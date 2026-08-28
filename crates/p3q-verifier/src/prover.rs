//! Minimal in-crate toy prover for golden-vector generation and round-
//! trip tests.
//!
//! This is **NOT** a production prover. It exists exclusively to:
//! - generate the golden test vector each profile asserts against,
//! - exercise the verifier on an honestly-constructed proof,
//! - serve as the executable companion to the wire format spec.
//!
//! Compiled only behind `#[cfg(any(test, feature = "prover"))]` so the
//! production verifier path does not pull in any proving codepaths.

#![cfg(any(test, feature = "prover"))]

use p3q_core::{P3qError, ProofSystemId, Result};
use p3q_field::{Field, Goldilocks};
use p3q_merkle::{Digest, MerkleTree};

use crate::domain::{fri_fold, horner, lde_generator, point_at_index, sibling_index};
use crate::transcript::VerifierTranscript;
use crate::wire::{Header, LayerOpening, ParsedProof, QueryOpening, FOLD_ARITY_LOG2};

/// Configuration for the toy prover. Mirrors the wire `Header` plus
/// secret coefficients of the toy polynomial.
pub struct ToyProverConfig {
    /// Polynomial degree bound (will produce a poly with exactly
    /// `2^log_degree_bound` coefficients, padded with zeros).
    pub log_degree_bound: u8,
    /// LDE blowup factor.
    pub log_blowup: u8,
    /// Number of FRI queries.
    pub num_queries: u8,
    /// Final layer log-size.
    pub log_final_poly: u8,
    /// Profile to bind into the transcript.
    pub profile: ProofSystemId,
    /// Public input — bound into the transcript.
    pub public_input: Vec<u8>,
    /// The polynomial we'll commit to, in coefficient form. Length
    /// must be exactly `2^log_degree_bound`.
    pub coeffs: Vec<Goldilocks>,
}

/// Produced toy proof: parsed (in-memory) plus serialized body bytes.
pub struct ToyProof {
    /// In-memory parsed form (same struct the verifier sees post-parse).
    pub parsed: ParsedProof,
    /// Serialized body bytes (i.e. the proof bytes WITHOUT the leading
    /// `ProofSystemId` byte). To get a full wire proof, prepend
    /// `cfg.profile.as_byte()`.
    pub body: Vec<u8>,
}

/// Prove the toy AIR: commit to a polynomial whose evaluations on the
/// LDE domain form a low-degree codeword.
pub fn prove(cfg: &ToyProverConfig) -> Result<ToyProof> {
    // ---- Validate config ----
    let n_trace = 1usize << cfg.log_degree_bound;
    if cfg.coeffs.len() != n_trace {
        return Err(P3qError::InvalidLength(
            "toy prover: coeffs len must equal 2^log_degree_bound",
        ));
    }
    let header = Header {
        log_degree_bound: cfg.log_degree_bound,
        log_blowup: cfg.log_blowup,
        log_arity: FOLD_ARITY_LOG2,
        num_queries: cfg.num_queries,
        log_final_poly: cfg.log_final_poly,
        public_input_len: u16::try_from(cfg.public_input.len())
            .map_err(|_| P3qError::InvalidLength("toy prover: public input too long"))?,
    };

    let log_lde = header.log_lde();
    let n_full = 1usize << log_lde;
    let omega = lde_generator(log_lde)?;

    // ---- Build LDE evaluations ----
    let mut trace_lde = Vec::with_capacity(n_full);
    for k in 0..n_full {
        let x = point_at_index(omega, k as u32);
        trace_lde.push(horner(&cfg.coeffs, x));
    }

    prove_word(cfg.profile, header, &cfg.public_input, trace_lde)
}

/// Commit to `trace_lde` and fold it honestly under `header`.
///
/// The word is arbitrary — nothing here requires it to be a low-degree
/// codeword, because nothing in FRI's *consistency* checks does either.
/// [`prove`] is this function preceded by an evaluation, and an
/// adversary is this function preceded by anything at all. Tests use
/// the difference to ask whether the verifier's degree claim is real:
/// every Merkle opening and every colinearity fold a proof from here
/// carries is genuine, so if such a proof verifies over a high-degree
/// word, the degree bound is not being enforced.
///
/// The header is NOT validated. An honest prover has no reason to mint
/// an inadmissible proof, but a test of the verifier's refusals needs
/// to, and so does an attacker.
pub fn prove_word(
    profile: ProofSystemId,
    header: Header,
    public_input: &[u8],
    trace_lde: Vec<Goldilocks>,
) -> Result<ToyProof> {
    let log_lde = header.log_lde();
    let n_full = 1usize << log_lde;
    if trace_lde.len() != n_full {
        return Err(P3qError::InvalidLength(
            "toy prover: trace len must equal 2^log_lde",
        ));
    }
    let omega = lde_generator(log_lde)?;

    // ---- Commit trace LDE ----
    let trace_leaves: Vec<Vec<u8>> = trace_lde.iter().map(|v| v.to_bytes()).collect();
    let trace_tree = MerkleTree::from_leaves(&trace_leaves)
        .map_err(|_| P3qError::InvalidLength("toy prover: trace tree build failed"))?;
    let trace_root = trace_tree.root();

    // ---- Replay transcript phase 1: header + pi + trace root ----
    let mut transcript = VerifierTranscript::new(profile);
    let header_bytes = header.encode();
    transcript.observe_header(&header_bytes);
    transcript.observe_public_input(public_input);
    transcript.observe_trace_root(&trace_root);
    let mut fold_challenges = Vec::with_capacity(header.num_fri_rounds() as usize);
    fold_challenges.push(transcript.squeeze_field()?);

    // ---- Compute and commit FRI layers ----
    let num_rounds = header.num_fri_rounds() as usize;
    let mut layers_evals: Vec<Vec<Goldilocks>> = Vec::with_capacity(num_rounds);
    layers_evals.push(trace_lde.clone()); // layer 0 = trace LDE

    let mut layer_omegas: Vec<Goldilocks> = Vec::with_capacity(num_rounds + 1);
    layer_omegas.push(omega);

    // For each fold round, produce the next layer's evaluations.
    for round in 0..num_rounds {
        let prev = &layers_evals[round];
        let log_prev = log_lde - round as u32;
        let half = (1usize << log_prev) / 2;
        let r = fold_challenges[round];
        let omega_prev = layer_omegas[round];
        let mut next = Vec::with_capacity(half);
        for k in 0..half {
            let a = prev[k];
            let b = prev[k + half];
            let x = point_at_index(omega_prev, k as u32);
            next.push(fri_fold(a, b, x, r)?);
        }
        layers_evals.push(next);
        layer_omegas.push(omega_prev * omega_prev);
        // After the round, commit the new layer (UNLESS it's the final
        // layer — that one is sent explicitly).
        let last_round = round + 1 == num_rounds;
        if !last_round {
            let leaves: Vec<Vec<u8>> = layers_evals[round + 1]
                .iter()
                .map(|v| v.to_bytes())
                .collect();
            let tree = MerkleTree::from_leaves(&leaves)
                .map_err(|_| P3qError::InvalidLength("toy prover: layer tree build failed"))?;
            transcript.observe_fri_layer(&tree.root());
            fold_challenges.push(transcript.squeeze_field()?);
        }
    }

    // ---- Build FRI layer roots + trees for opening ----
    // Index-based loop kept for clarity: we slice exactly layers
    // 1..num_rounds (skipping layer 0 = trace, which has its own
    // tree, and skipping the final layer, which is sent as
    // `final_poly`).
    let mut fri_layer_roots: Vec<Digest> = Vec::with_capacity(num_rounds - 1);
    let mut fri_layer_trees: Vec<MerkleTree> = Vec::with_capacity(num_rounds - 1);
    #[allow(clippy::needless_range_loop)]
    for round in 1..num_rounds {
        let leaves: Vec<Vec<u8>> = layers_evals[round].iter().map(|v| v.to_bytes()).collect();
        let tree = MerkleTree::from_leaves(&leaves)
            .map_err(|_| P3qError::InvalidLength("toy prover: layer tree build failed"))?;
        fri_layer_roots.push(tree.root());
        fri_layer_trees.push(tree);
    }

    // ---- Final polynomial (interpolate from final layer evals) ----
    // The FRI envelope says: final layer has size 2^log_final_poly.
    // The final layer evals are layers_evals[num_rounds]; its log-size
    // is log_lde - num_rounds = log_final_poly. We send these
    // evaluations in coefficient form. For simplicity we ship the
    // evaluations directly — the verifier interprets `final_poly` as
    // coefficients per the spec. To make that valid, the prover must
    // do an interpolation. We do it via inverse DFT on the layer's
    // multiplicative subgroup.
    let final_evals = &layers_evals[num_rounds];
    let omega_final = layer_omegas[num_rounds];
    let final_poly = inverse_dft_on_subgroup(final_evals, omega_final)?;

    // ---- Observe final poly + enter query phase ----
    let mut final_bytes = Vec::with_capacity(final_poly.len() * Goldilocks::BYTES);
    for v in &final_poly {
        final_bytes.extend_from_slice(&v.to_bytes());
    }
    transcript.observe_final_poly(&final_bytes);
    transcript.enter_query_phase();

    // ---- Sample query indices ----
    let mut queries = Vec::with_capacity(header.num_queries as usize);
    for _ in 0..header.num_queries {
        let q = transcript.squeeze_query_index(log_lde)?;
        let query = build_query_opening(
            q,
            &trace_lde,
            &trace_tree,
            &layers_evals,
            &fri_layer_trees,
            log_lde,
        )?;
        queries.push(query);
    }

    let parsed = ParsedProof {
        header,
        public_input: public_input.to_vec(),
        trace_root,
        fri_layer_roots,
        final_poly,
        queries,
    };

    let body = serialize(&parsed);
    Ok(ToyProof { parsed, body })
}

fn build_query_opening(
    q: u32,
    trace_lde: &[Goldilocks],
    trace_tree: &MerkleTree,
    layers_evals: &[Vec<Goldilocks>],
    fri_layer_trees: &[MerkleTree],
    log_lde: u32,
) -> Result<QueryOpening> {
    let trace_value = trace_lde[q as usize];
    let trace_auth = trace_tree.open(q as usize)?;
    let n_full = 1u32 << log_lde;
    let conj_index = q ^ (n_full / 2);
    let trace_conj_value = trace_lde[conj_index as usize];
    let trace_conj_auth = trace_tree.open(conj_index as usize)?;

    let num_rounds = layers_evals.len() - 1;
    let num_layer_openings = num_rounds.saturating_sub(1);
    let mut layers = Vec::with_capacity(num_layer_openings);
    // One opening per FRI commit layer 1..num_rounds-1 (the final
    // layer is sent explicitly as final_poly).
    //
    // Index convention (matches verify.rs): at commit layer i the
    // domain has log-size `log_layer = log_lde - i` and the surviving
    // index of `q` is the LOW `log_layer` bits of `q`.
    for commit_layer in 1..num_rounds {
        let log_layer = log_lde - commit_layer as u32;
        let layer_mask = (1u32 << log_layer).wrapping_sub(1);
        let value_index = q & layer_mask;
        let sibling_idx = sibling_index(value_index, log_layer);
        let value = layers_evals[commit_layer][value_index as usize];
        let sibling = layers_evals[commit_layer][sibling_idx as usize];
        let tree = &fri_layer_trees[commit_layer - 1];
        let value_auth = tree.open(value_index as usize)?;
        let sibling_auth = tree.open(sibling_idx as usize)?;
        layers.push(LayerOpening {
            value,
            sibling,
            value_auth,
            sibling_auth,
        });
    }

    Ok(QueryOpening {
        query_index: q,
        trace_value,
        trace_conj_value,
        trace_auth,
        trace_conj_auth,
        layers,
    })
}

/// Inverse DFT on a multiplicative subgroup of size `N = 2^k` with
/// generator `omega`. Naive O(N^2) — fine for tiny final polynomials.
fn inverse_dft_on_subgroup(evals: &[Goldilocks], omega: Goldilocks) -> Result<Vec<Goldilocks>> {
    let n = evals.len();
    if n == 0 {
        return Err(P3qError::InvalidLength("inverse_dft: empty evals"));
    }
    let n_inv = Goldilocks::from_u64(n as u64)
        .inverse()
        .ok_or(P3qError::FieldOutOfRange)?;
    let omega_inv = omega.inverse().ok_or(P3qError::FieldOutOfRange)?;
    let mut coeffs = Vec::with_capacity(n);
    for k in 0..n {
        let mut acc = Goldilocks::default();
        let mut wk = Goldilocks::one();
        let omega_inv_k = omega_inv.pow(k as u64);
        for v in evals.iter() {
            acc = acc + *v * wk;
            wk = wk * omega_inv_k;
        }
        coeffs.push(acc * n_inv);
    }
    Ok(coeffs)
}

/// Serialize a `ParsedProof` into the canonical wire format documented
/// in [`crate::wire`].
pub fn serialize(parsed: &ParsedProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&parsed.header.encode());
    out.extend_from_slice(&parsed.public_input);
    out.extend_from_slice(&parsed.trace_root);
    for root in &parsed.fri_layer_roots {
        out.extend_from_slice(root);
    }
    out.extend_from_slice(&(parsed.final_poly.len() as u16).to_be_bytes());
    for v in &parsed.final_poly {
        out.extend_from_slice(&v.to_bytes());
    }
    for q in &parsed.queries {
        out.extend_from_slice(&q.query_index.to_be_bytes());
        out.extend_from_slice(&q.trace_value.to_bytes());
        out.extend_from_slice(&q.trace_conj_value.to_bytes());
        out.push(q.trace_auth.siblings.len() as u8);
        for s in &q.trace_auth.siblings {
            out.extend_from_slice(s);
        }
        out.push(q.trace_conj_auth.siblings.len() as u8);
        for s in &q.trace_conj_auth.siblings {
            out.extend_from_slice(s);
        }
        for layer in &q.layers {
            out.extend_from_slice(&layer.value.to_bytes());
            out.extend_from_slice(&layer.sibling.to_bytes());
            out.push(layer.value_auth.siblings.len() as u8);
            for s in &layer.value_auth.siblings {
                out.extend_from_slice(s);
            }
            out.push(layer.sibling_auth.siblings.len() as u8);
            for s in &layer.sibling_auth.siblings {
                out.extend_from_slice(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_dft_roundtrip() {
        // Take a polynomial, evaluate on a subgroup, run inverse DFT,
        // and check we recover the coefficients.
        let coeffs: Vec<_> = (0u64..8).map(|i| Goldilocks::from_u64(i + 1)).collect();
        let omega = Goldilocks::two_adic_generator(3).unwrap();
        let evals: Vec<_> = (0..8u32)
            .map(|k| horner(&coeffs, omega.pow(k as u64)))
            .collect();
        let recovered = inverse_dft_on_subgroup(&evals, omega).unwrap();
        assert_eq!(recovered, coeffs);
    }
}
