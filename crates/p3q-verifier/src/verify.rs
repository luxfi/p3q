//! Generic STARK / FRI verification kernel.
//!
//! This is the audit-grade body. Each step is decomposed into a small
//! function with a single responsibility:
//!
//! 1. [`bind_transcript_through_commitments`] — replay Fiat-Shamir up
//!    to the trace+layer commits, capturing per-layer fold challenges.
//! 2. [`derive_query_indices`] — squeeze the query indices from the
//!    transcript after binding the final polynomial.
//! 3. [`authenticate_trace_query`] — verify the trace LDE Merkle
//!    opening at each query index.
//! 4. [`authenticate_and_fold`] — walk each FRI layer, checking the
//!    Merkle opening and that the folded value from the previous layer
//!    is consistent with the next layer's claimed eval.
//! 5. [`check_final_polynomial`] — assert the final folded value
//!    matches the explicit final polynomial evaluated at the surviving
//!    coset point.
//!
//! Together these are the full FRI low-degree test against a Merkle
//! commitment, replayed by Fiat-Shamir — no AIR-specific glue lives
//! here. AIR-specific verifiers (Z-Chain circuits, etc.) wrap this
//! kernel and add boundary / transition constraint checks.

use crate::domain::{fri_fold, horner, lde_generator, point_at_index};
use crate::transcript::VerifierTranscript;
use crate::wire::{ParsedProof, QueryOpening};
use p3q_core::{P3qError, ProofSystemId, Result};
use p3q_field::{Field, Goldilocks};
use p3q_merkle::BatchOpening;
use p3q_sha3::backend::Sha3Backend;

/// Result of replaying the transcript up to the query-derivation
/// phase: per-FRI-round fold challenge.
struct Bindings {
    /// Fold challenge for each FRI round; length = `num_fri_rounds`.
    fold_challenges: Vec<Goldilocks>,
}

/// Run the full generic STARK / FRI verification for the given parsed
/// proof under the given profile, binding `public_input` into the
/// transcript.
///
/// Uses the configured [`p3q_sha3::backend::default_backend`] (CPU on
/// audited builds; GPU when the verifier crate is built with
/// `--features gpu-sha3` and libluxgpu is dlopen-loadable at runtime).
/// Returns `Ok(())` only on full acceptance. Every failure mode maps
/// to a precise `P3qError` variant — the verifier never panics, never
/// `unwrap()`s, never silent-accepts.
pub fn verify_parsed(
    profile: ProofSystemId,
    parsed: &ParsedProof,
    public_input: &[u8],
) -> Result<()> {
    let backend = select_backend();
    verify_parsed_with_backend(profile, parsed, public_input, backend.as_ref())
}

/// Backend-explicit verification entry point. Production code uses
/// [`verify_parsed`] which picks the default backend; this variant is
/// exposed so callers (benchmarks, FFI shims, multi-tenant verifiers)
/// can pin a specific backend. Output is byte-identical regardless of
/// which `Sha3Backend` is supplied — the audited binding never depends
/// on the implementation choice.
pub fn verify_parsed_with_backend(
    profile: ProofSystemId,
    parsed: &ParsedProof,
    public_input: &[u8],
    backend: &dyn Sha3Backend,
) -> Result<()> {
    // ----- 0. Public-input binding -----
    if parsed.public_input.as_slice() != public_input {
        return Err(P3qError::StarkVerification(
            "public input does not match embedded value",
        ));
    }

    // ----- 1. Bind transcript through commits, capture fold randomness -----
    let bindings = bind_transcript_through_commitments(profile, parsed)?;

    // ----- 2. Re-derive query indices, check echoes -----
    let mut transcript = rebind_for_queries(profile, parsed)?;
    let log_lde = parsed.header.log_lde();
    for q in &parsed.queries {
        let derived = transcript.squeeze_query_index(log_lde)?;
        if derived != q.query_index {
            return Err(P3qError::Transcript("query index mismatch with transcript"));
        }
    }

    // ----- 3. Per-query wire-format invariants + batched Merkle auth -----
    //
    // All Merkle authentications across all queries are independent
    // (each only depends on `trace_root` or one `fri_layer_roots[i]`).
    // We batch them per-root so a future GPU cSHAKE backend gets a
    // single dispatch per root rather than O(N_queries * log N) serial
    // hashes. On the CPU backend this is equivalent to the serial path.
    check_query_invariants(parsed)?;
    authenticate_all_queries_batched(backend, parsed)?;

    // ----- 4-5. Per-query colinearity + final-poly checks -----
    //
    // Run AFTER Merkle authentication so we don't waste time on a
    // colinearity-rejection path for a tampered proof — the cheap fold
    // arithmetic is dwarfed by Merkle work anyway.
    let omega_lde = lde_generator(log_lde)?;
    for query in &parsed.queries {
        check_colinearity_and_final_poly(parsed, query, omega_lde, &bindings.fold_challenges)?;
    }

    Ok(())
}

/// Select the default `Sha3Backend`: CPU on audited builds; GPU when
/// the `gpu-sha3` feature is enabled AND libluxgpu is dlopen-loadable.
/// Either choice produces byte-identical verification output. The
/// backend is initialised once (lazily) per process via `OnceLock` —
/// dlopen + GPU context creation happens at first verify only, then
/// every subsequent verify reuses the same `Arc`.
fn select_backend() -> std::sync::Arc<dyn Sha3Backend> {
    use std::sync::OnceLock;
    static BACKEND: OnceLock<std::sync::Arc<dyn Sha3Backend>> = OnceLock::new();
    BACKEND
        .get_or_init(|| {
            #[cfg(feature = "gpu-sha3")]
            {
                if let Some(gpu) = p3q_gpu_sha3::try_load_default() {
                    return gpu;
                }
            }
            p3q_sha3::backend::default_backend()
        })
        .clone()
}

/// Per-query wire-format invariants. Extracted from the old
/// `verify_one_query` so the failure modes surface BEFORE we waste any
/// hash work — every malformed-encoding error returns here.
fn check_query_invariants(parsed: &ParsedProof) -> Result<()> {
    let log_lde = parsed.header.log_lde();
    let num_rounds = parsed.header.num_fri_rounds() as usize;
    if num_rounds == 0 {
        return Err(P3qError::FriVerification("zero fri rounds"));
    }
    let expected_layer_openings = num_rounds - 1;
    for query in &parsed.queries {
        if query.layers.len() != expected_layer_openings {
            return Err(P3qError::InvalidEncoding(
                "query layers count must equal num_rounds - 1",
            ));
        }
        if query.trace_auth.siblings.len() != log_lde as usize {
            return Err(P3qError::InvalidEncoding(
                "trace value auth path length mismatch",
            ));
        }
        if query.trace_conj_auth.siblings.len() != log_lde as usize {
            return Err(P3qError::InvalidEncoding(
                "trace conj auth path length mismatch",
            ));
        }
        for (commit_layer, layer) in query.layers.iter().enumerate() {
            let log_layer = log_lde - (commit_layer + 1) as u32;
            if layer.value_auth.siblings.len() != log_layer as usize {
                return Err(P3qError::InvalidEncoding(
                    "layer value auth path length mismatch with layer log-size",
                ));
            }
            if layer.sibling_auth.siblings.len() != log_layer as usize {
                return Err(P3qError::InvalidEncoding(
                    "layer sibling auth path length mismatch with layer log-size",
                ));
            }
        }
    }
    Ok(())
}

/// Authenticate every Merkle opening across every query in one
/// `verify_proof_batch` call per root. Returns `Err(P3qError::MerkleAuth)`
/// if any opening fails.
fn authenticate_all_queries_batched(backend: &dyn Sha3Backend, parsed: &ParsedProof) -> Result<()> {
    let log_lde = parsed.header.log_lde();
    let n_full = 1u32 << log_lde;
    let num_rounds = parsed.header.num_fri_rounds() as usize;

    // ----- Per-query payload bytes — stable storage for the openings -----
    // We materialise the `to_bytes()` slabs into one Vec per query so
    // `BatchOpening<'_>` can borrow them. Without this they'd be
    // temporaries dangling by the time we call into the merkle crate.
    let trace_bytes: Vec<Vec<u8>> = parsed
        .queries
        .iter()
        .map(|q| q.trace_value.to_bytes().to_vec())
        .collect();
    let trace_conj_bytes: Vec<Vec<u8>> = parsed
        .queries
        .iter()
        .map(|q| q.trace_conj_value.to_bytes().to_vec())
        .collect();

    // Trace root: 2 openings per query (value + sibling).
    let mut trace_openings: Vec<BatchOpening<'_>> = Vec::with_capacity(parsed.queries.len() * 2);
    for (i, q) in parsed.queries.iter().enumerate() {
        trace_openings.push(BatchOpening {
            leaf: &trace_bytes[i],
            index: q.query_index as usize,
            proof: &q.trace_auth,
        });
        let conj_index = (q.query_index ^ (n_full / 2)) as usize;
        trace_openings.push(BatchOpening {
            leaf: &trace_conj_bytes[i],
            index: conj_index,
            proof: &q.trace_conj_auth,
        });
    }
    p3q_merkle::verify_proof_batch(backend, &parsed.trace_root, &trace_openings)?;

    // FRI commit layers: 2 openings per query per layer.
    //
    // Pre-allocate per-layer byte storage outside the loop so the
    // `BatchOpening` borrows have a stable lifetime.
    for commit_layer in 1..num_rounds {
        let log_layer = log_lde - commit_layer as u32;
        let layer_mask = if log_layer == 32 {
            u64::MAX
        } else {
            (1u64 << log_layer) - 1
        };
        let n_layer = 1u32 << log_layer;
        let layer_root = &parsed.fri_layer_roots[commit_layer - 1];

        let value_bytes: Vec<Vec<u8>> = parsed
            .queries
            .iter()
            .map(|q| q.layers[commit_layer - 1].value.to_bytes().to_vec())
            .collect();
        let sibling_bytes: Vec<Vec<u8>> = parsed
            .queries
            .iter()
            .map(|q| q.layers[commit_layer - 1].sibling.to_bytes().to_vec())
            .collect();
        let mut openings: Vec<BatchOpening<'_>> = Vec::with_capacity(parsed.queries.len() * 2);
        for (i, q) in parsed.queries.iter().enumerate() {
            let value_index = ((q.query_index as u64) & layer_mask) as u32;
            let sibling_index = (value_index ^ (n_layer / 2)) as usize;
            openings.push(BatchOpening {
                leaf: &value_bytes[i],
                index: value_index as usize,
                proof: &q.layers[commit_layer - 1].value_auth,
            });
            openings.push(BatchOpening {
                leaf: &sibling_bytes[i],
                index: sibling_index,
                proof: &q.layers[commit_layer - 1].sibling_auth,
            });
        }
        p3q_merkle::verify_proof_batch(backend, layer_root, &openings)?;
    }

    Ok(())
}

/// Per-query colinearity + final-polynomial check. Same logic as the
/// FRI-fold half of the old `verify_one_query`, with the Merkle-auth
/// half removed (now batched up-front).
fn check_colinearity_and_final_poly(
    parsed: &ParsedProof,
    query: &QueryOpening,
    omega_lde: Goldilocks,
    fold_challenges: &[Goldilocks],
) -> Result<()> {
    let log_lde = parsed.header.log_lde();
    let num_rounds = parsed.header.num_fri_rounds() as usize;
    if fold_challenges.len() != num_rounds {
        return Err(P3qError::Transcript(
            "fold challenge count mismatch with num_rounds",
        ));
    }

    // First fold: trace -> layer 1.
    let x0 = point_at_index(omega_lde, query.query_index);
    let mut folded_carry = fri_fold(
        query.trace_value,
        query.trace_conj_value,
        x0,
        fold_challenges[0],
    )?;

    // Walk FRI commit layers 1..num_rounds-1.
    let mut current_omega = omega_lde * omega_lde;
    #[allow(clippy::needless_range_loop)]
    for commit_layer in 1..num_rounds {
        let log_layer = log_lde - commit_layer as u32;
        let layer = &query.layers[commit_layer - 1];
        let layer_mask = if log_layer == 32 {
            u64::MAX
        } else {
            (1u64 << log_layer) - 1
        };
        let value_index = ((query.query_index as u64) & layer_mask) as u32;
        if layer.value != folded_carry {
            return Err(P3qError::FriVerification(
                "layer value disagrees with previous fold",
            ));
        }
        let x = current_omega.pow(value_index as u64);
        folded_carry = fri_fold(layer.value, layer.sibling, x, fold_challenges[commit_layer])?;
        current_omega = current_omega * current_omega;
    }

    // Final polynomial check.
    let log_final = parsed.header.log_final_poly as u32;
    let final_mask = if log_final == 0 {
        0
    } else if log_final == 32 {
        u64::MAX
    } else {
        (1u64 << log_final) - 1
    };
    let final_index_u64 = (query.query_index as u64) & final_mask;
    if final_index_u64 >= parsed.final_poly.len() as u64 {
        return Err(P3qError::InvalidEncoding("final-poly index out of bounds"));
    }
    let final_x = current_omega.pow(final_index_u64);
    let expected = horner(&parsed.final_poly, final_x);
    if expected != folded_carry {
        return Err(P3qError::FriVerification(
            "final-poly evaluation disagrees with folded value",
        ));
    }
    Ok(())
}

/// Phase 1: replay all observations up to (but not including) the
/// final-polynomial absorption, and capture the per-layer fold
/// challenges sampled between consecutive layer-root absorptions.
fn bind_transcript_through_commitments(
    profile: ProofSystemId,
    parsed: &ParsedProof,
) -> Result<Bindings> {
    let mut transcript = VerifierTranscript::new(profile);
    let header_bytes = parsed.header.encode();
    transcript.observe_header(&header_bytes);
    transcript.observe_public_input(&parsed.public_input);
    transcript.observe_trace_root(&parsed.trace_root);

    let num_rounds = parsed.header.num_fri_rounds() as usize;
    if num_rounds == 0 {
        return Err(P3qError::FriVerification("zero fold rounds"));
    }

    // Layer-root count = num_rounds - 1 (the final polynomial is sent
    // explicitly, not committed). Fold-challenge count = num_rounds:
    // - the FIRST fold mixes the TRACE into layer 1, so it is sampled
    //   *after* trace commit, *before* layer-1 commit (or before the
    //   final poly if there's only one fold round).
    // - subsequent folds are sampled after each layer commit.
    if parsed.fri_layer_roots.len() + 1 != num_rounds {
        return Err(P3qError::InvalidEncoding(
            "fri layer root count mismatch with num_rounds",
        ));
    }

    let mut fold_challenges = Vec::with_capacity(num_rounds);
    // First fold sampled before observing any FRI-layer root (right
    // after the trace commit).
    fold_challenges.push(transcript.squeeze_field()?);
    for root in &parsed.fri_layer_roots {
        transcript.observe_fri_layer(root);
        fold_challenges.push(transcript.squeeze_field()?);
    }
    Ok(Bindings { fold_challenges })
}

/// Phase 2 helper: produce a fresh transcript identical to phase 1's
/// state right BEFORE query-index sampling, so we can re-derive the
/// per-query indices and compare to the echoed values.
///
/// (We do this in a second pass rather than threading the transcript
/// through phase 1 — keeps responsibilities clear, and the cost is
/// linear in proof size, dwarfed by Merkle work.)
fn rebind_for_queries(profile: ProofSystemId, parsed: &ParsedProof) -> Result<VerifierTranscript> {
    let mut transcript = VerifierTranscript::new(profile);
    let header_bytes = parsed.header.encode();
    transcript.observe_header(&header_bytes);
    transcript.observe_public_input(&parsed.public_input);
    transcript.observe_trace_root(&parsed.trace_root);
    // Re-derive the same fold challenges (we throw them away — the
    // bindings struct from phase 1 already captured them).
    let _ = transcript.squeeze_field()?;
    for root in &parsed.fri_layer_roots {
        transcript.observe_fri_layer(root);
        let _ = transcript.squeeze_field()?;
    }
    // Bind the final polynomial.
    let mut final_bytes = Vec::with_capacity(parsed.final_poly.len() * Goldilocks::BYTES);
    for v in &parsed.final_poly {
        final_bytes.extend_from_slice(&v.to_bytes());
    }
    transcript.observe_final_poly(&final_bytes);
    transcript.enter_query_phase();
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    // End-to-end verifier tests live in lib.rs (golden vector) — they
    // need the toy prover. The verify module itself contains only
    // small inline helpers, each tested via the integration path.

    use super::*;

    #[test]
    fn empty_proof_yields_invalid_encoding() {
        let res = crate::wire::parse(&[]);
        assert!(matches!(res, Err(P3qError::InvalidLength(_))));
    }
}
