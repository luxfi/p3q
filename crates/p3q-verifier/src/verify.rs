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
/// Returns `Ok(())` only on full acceptance. Every failure mode maps
/// to a precise `P3qError` variant — the verifier never panics, never
/// `unwrap()`s, never silent-accepts.
pub fn verify_parsed(
    profile: ProofSystemId,
    parsed: &ParsedProof,
    public_input: &[u8],
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

    // ----- 3-5. Per-query Merkle + FRI + final-poly checks -----
    let omega_lde = lde_generator(log_lde)?;
    for query in &parsed.queries {
        verify_one_query(parsed, query, omega_lde, &bindings.fold_challenges)?;
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

/// Verify one full query opening: trace pair + FRI layers + final
/// polynomial check.
///
/// The wire format encodes, per query, one trace pair `(value at q,
/// value at q ^ N/2)` authenticated against `trace_root`, then one
/// layer pair per FRI commit layer (layers 1..num_rounds-1 inclusive),
/// each authenticated against its layer root. The final layer
/// (`num_rounds`) is the explicit `final_poly` — we check the last
/// fold's output equals `horner(final_poly, x_final)`.
fn verify_one_query(
    parsed: &ParsedProof,
    query: &QueryOpening,
    omega_lde: Goldilocks,
    fold_challenges: &[Goldilocks],
) -> Result<()> {
    let log_lde = parsed.header.log_lde();
    let num_rounds = parsed.header.num_fri_rounds() as usize;
    if num_rounds == 0 {
        return Err(P3qError::FriVerification("zero fri rounds"));
    }

    // Cross-check the wire-format invariants we've already enforced in
    // parsing — defence in depth so a future refactor can't quietly
    // skew this without the verifier noticing.
    let expected_layer_openings = num_rounds - 1;
    if query.layers.len() != expected_layer_openings {
        return Err(P3qError::InvalidEncoding(
            "query layers count must equal num_rounds - 1",
        ));
    }
    if fold_challenges.len() != num_rounds {
        return Err(P3qError::Transcript(
            "fold challenge count mismatch with num_rounds",
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

    // ---- Trace pair authentication ----
    let n_full = 1u32 << log_lde;
    let conj_index = query.query_index ^ (n_full / 2);
    p3q_merkle::verify_proof(
        &parsed.trace_root,
        &query.trace_value.to_bytes(),
        query.query_index as usize,
        &query.trace_auth,
    )
    .map_err(|_| P3qError::MerkleAuth)?;
    p3q_merkle::verify_proof(
        &parsed.trace_root,
        &query.trace_conj_value.to_bytes(),
        conj_index as usize,
        &query.trace_conj_auth,
    )
    .map_err(|_| P3qError::MerkleAuth)?;

    // ---- First fold: trace -> layer 1 ----
    let x0 = point_at_index(omega_lde, query.query_index);
    let mut folded_carry = fri_fold(
        query.trace_value,
        query.trace_conj_value,
        x0,
        fold_challenges[0],
    )?;
    // `folded_carry` now is the expected eval of layer-1 at index q>>1.

    // ---- Walk FRI commit layers 1..num_rounds-1 ----
    //
    // Convention (matched in prover.rs):
    //
    //   layer_{i+1}[k] = fri_fold(layer_i[k], layer_i[k + N_i/2],
    //                              omega_i^k, r_i)   for k in 0..N_i/2.
    //
    // Each fold halves the domain by combining the FIRST and SECOND
    // halves of the array. The "fold bit" is therefore the HIGH bit
    // of the index in the previous layer; the "surviving index" in
    // the next layer is `prev_index & (N_i/2 - 1)`, i.e. the low
    // bits.
    //
    // For a transcript-derived LDE-domain query index `q in 0..N`:
    //   - layer 0 index = q
    //   - layer i index = q & ((1 << (log_lde - i)) - 1)
    //                   = the low (log_lde - i) bits of q.
    //
    // Wire encoding ships one LayerOpening per commit layer
    // (1..num_rounds-1) in `query.layers`; commit layer i corresponds
    // to `query.layers[i - 1]` and `parsed.fri_layer_roots[i - 1]`.
    let mut current_omega = omega_lde * omega_lde; // omega^(2) = layer-1 generator
                                                   // Index-based loop is intentional: `commit_layer` indexes into
                                                   // `query.layers`, `parsed.fri_layer_roots`, and `fold_challenges`,
                                                   // and is used in log-arithmetic on `log_layer`. An iterator chain
                                                   // would obscure the alignment between these four sequences.
    #[allow(clippy::needless_range_loop)]
    for commit_layer in 1..num_rounds {
        let log_layer = log_lde - commit_layer as u32;
        let layer = &query.layers[commit_layer - 1];
        let layer_root = &parsed.fri_layer_roots[commit_layer - 1];
        let layer_mask = if log_layer == 32 {
            u64::MAX
        } else {
            (1u64 << log_layer) - 1
        };
        let value_index_u64 = (query.query_index as u64) & layer_mask;
        debug_assert!(value_index_u64 < (1u64 << log_layer));
        let value_index = value_index_u64 as u32;
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
        let n_layer = 1u32 << log_layer;
        let sibling_index_in_layer = value_index ^ (n_layer / 2);
        // (a) authenticate value at value_index and sibling at sibling_index
        p3q_merkle::verify_proof(
            layer_root,
            &layer.value.to_bytes(),
            value_index as usize,
            &layer.value_auth,
        )
        .map_err(|_| P3qError::MerkleAuth)?;
        p3q_merkle::verify_proof(
            layer_root,
            &layer.sibling.to_bytes(),
            sibling_index_in_layer as usize,
            &layer.sibling_auth,
        )
        .map_err(|_| P3qError::MerkleAuth)?;
        // (b) colinearity with previous fold's output
        if layer.value != folded_carry {
            return Err(P3qError::FriVerification(
                "layer value disagrees with previous fold",
            ));
        }
        // (c) fold to next layer
        let x = current_omega.pow(value_index as u64);
        folded_carry = fri_fold(layer.value, layer.sibling, x, fold_challenges[commit_layer])?;
        current_omega = current_omega * current_omega; // square for next layer
    }
    // After this loop, current_omega is omega_lde^{2^num_rounds} — the
    // generator of the final polynomial's evaluation domain.

    // ---- Final polynomial check ----
    // After `num_rounds` folds the domain has log-size `log_final_poly`.
    // The surviving index is the low `log_final_poly` bits of q.
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
