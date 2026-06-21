//! Reusable FRI commit / prove / verify engine over a single codeword.
//!
//! This is the single FRI implementation used by the AIR DEEP-STARK
//! (`p3q-stark`). It proves that a committed evaluation vector is the
//! low-degree extension of a polynomial of degree `< 2^log_final_poly`
//! after `num_rounds = log_lde − log_final_poly` binary folds.
//!
//! Soundness depends on the fold challenges and query indices coming
//! from a Fiat-Shamir transcript that has *already absorbed* every
//! commitment the proof binds (trace root, quotient root, OOD values).
//! The engine therefore takes a `&mut dyn FriTranscript` from the
//! caller rather than owning one — the AIR layer threads one transcript
//! through the whole proof so the FRI randomness is bound to the AIR
//! commitments. Commit phase and query phase use the *same* transcript
//! state, replayed identically by prover and verifier.
//!
//! Indexing mirrors the audited generic walk in `p3q-verifier::verify`:
//! - committed-and-opened layers are `0 .. num_rounds` (layer 0 is the
//!   input codeword; layers `1..num_rounds−1` are committed here; layer
//!   `num_rounds` is the explicit final polynomial — NOT opened);
//! - so we open `num_rounds` layers each as `(value, sibling)`;
//! - fold challenge `i` folds opened-layer `i` into layer `i+1`;
//! - at layer `i` the surviving index is `query_index & (2^(log_lde−i)−1)`
//!   and the fold point is `omega_lde^{2^i · value_index}`.
//!
//! The fold formula `(a+b)/2 + r·(a−b)/(2x)` is invariant to swapping
//! `(a,b)` against `(value@x, value@−x)` provided `x` is the point of
//! `a`, so — exactly as the audited walk does — we always take
//! `a = value`, `x = omega_i^{value_index}` without case-splitting on
//! which half the index lands in.

use p3q_core::{P3qError, Result};
use p3q_field::{Field, Goldilocks};
use p3q_merkle::{verify_proof, Digest, MerkleProof, MerkleTree};

use crate::domain::{fri_fold, horner, inverse_dft_on_subgroup, lde_generator, point_at_index};

/// Transcript abstraction the FRI engine drives. Implemented by the AIR
/// layer over the project's cSHAKE256 challenger so FRI randomness is
/// bound to the AIR commitments. Kept minimal: observe a root, observe
/// the final poly, squeeze a fold challenge, squeeze a query index.
pub trait FriTranscript {
    /// Absorb a FRI-layer Merkle root.
    fn observe_fri_root(&mut self, root: &Digest);
    /// Absorb the explicit final polynomial (coefficient bytes).
    fn observe_fri_final(&mut self, coeffs: &[Goldilocks]);
    /// Squeeze a fold challenge in the field.
    fn squeeze_fold_challenge(&mut self) -> Result<Goldilocks>;
    /// Mark the start of the query phase (domain separation).
    fn enter_query_phase(&mut self);
    /// Squeeze a query index in `[0, 2^log_bound)`.
    fn squeeze_query_index(&mut self, log_bound: u32) -> Result<u32>;
}

/// One query's opening across all opened FRI layers (`0 .. num_rounds`):
/// at each layer, the value at the surviving index and its fold sibling,
/// each with a Merkle authentication path against that layer's root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriQuery {
    /// The query index in layer 0 (size `2^log_lde`).
    pub index: u32,
    /// Per opened layer `i ∈ [0, num_rounds)`: `(value, sibling)`.
    pub layer_values: Vec<(Goldilocks, Goldilocks)>,
    /// Per opened layer: Merkle path for `value`.
    pub value_auth: Vec<MerkleProof>,
    /// Per opened layer: Merkle path for `sibling`.
    pub sibling_auth: Vec<MerkleProof>,
}

/// A FRI low-degree proof produced by [`prove`] and checked by
/// [`verify`]. `layer_roots` holds the roots of layers
/// `1 .. num_rounds−1` (layer 0's root is supplied separately as
/// `codeword_root`; the final layer is the explicit `final_poly`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriProofData {
    /// Merkle roots of FRI layers `1 .. num_rounds−1`, length
    /// `num_rounds − 1`.
    pub layer_roots: Vec<Digest>,
    /// Final polynomial coefficients, length `2^log_final_poly`.
    pub final_poly: Vec<Goldilocks>,
    /// Query openings, length `num_queries`.
    pub queries: Vec<FriQuery>,
}

/// FRI shape, derived once and shared by prover/verifier.
///
/// Carries the *degree bound* of the layer-0 polynomial, not just the
/// LDE size — this is load-bearing for soundness. The final-polynomial
/// degree-bound check (see [`verify`]) rejects any proof whose final
/// polynomial has nonzero coefficients beyond the degree the codeword is
/// claimed to have, which is the ONLY thing that makes FRI reject a
/// high-degree (non-low-degree) codeword. Without it, an honest fold of
/// a random vector down to a size-`2^log_final_poly` final layer passes
/// vacuously (any `2^log_final_poly` values interpolate a degree
/// `< 2^log_final_poly` poly).
#[derive(Debug, Clone, Copy)]
pub struct FriShape {
    /// log2 of the upper bound on the layer-0 polynomial's degree.
    pub log_degree_bound: u32,
    /// log2 of the LDE blowup factor (`log_lde = log_degree_bound +
    /// log_blowup`).
    pub log_blowup: u32,
    /// log2 of the final-polynomial length (the size of the final
    /// folded layer's domain).
    pub log_final_poly: u32,
    /// Number of queries.
    pub num_queries: usize,
}

impl FriShape {
    /// log2 of the LDE domain size.
    #[inline]
    pub fn log_lde(&self) -> u32 {
        self.log_degree_bound + self.log_blowup
    }

    /// Total fold rounds (= number of opened layers).
    pub fn num_rounds(&self) -> usize {
        (self.log_lde() - self.log_final_poly) as usize
    }

    /// The degree bound the *final* polynomial must satisfy. Each binary
    /// fold halves the degree bound, so after `num_rounds` folds the
    /// surviving polynomial has degree
    /// `< 2^log_degree_bound / 2^num_rounds`. The final poly is sent with
    /// `2^log_final_poly` coefficient slots; everything at or above this
    /// bound MUST be zero, or the codeword was not low-degree.
    pub fn final_degree_bound(&self) -> usize {
        let nr = self.num_rounds() as u32;
        if nr >= self.log_degree_bound {
            1
        } else {
            1usize << (self.log_degree_bound - nr)
        }
    }
}

/// Commit one codeword layer to a Merkle tree over its LE field bytes.
fn commit_layer(evals: &[Goldilocks]) -> Result<MerkleTree> {
    let leaves: Vec<Vec<u8>> = evals.iter().map(|v| v.to_bytes()).collect();
    MerkleTree::from_leaves(&leaves)
}

/// Prove low-degreeness of `codeword` (the LDE of a polynomial). The
/// caller has already committed `codeword` (its tree is `codeword_tree`,
/// root observed into `transcript`). Returns the FRI proof.
pub fn prove(
    codeword: &[Goldilocks],
    codeword_tree: &MerkleTree,
    shape: FriShape,
    transcript: &mut dyn FriTranscript,
) -> Result<FriProofData> {
    let n = codeword.len();
    if n != (1usize << shape.log_lde()) {
        return Err(P3qError::InvalidLength(
            "fri prove: codeword len != 2^log_lde",
        ));
    }
    let num_rounds = shape.num_rounds();
    if num_rounds == 0 {
        return Err(P3qError::FriVerification("fri prove: zero rounds"));
    }

    // Layer 0 = input codeword (already committed by caller).
    let mut layers: Vec<Vec<Goldilocks>> = Vec::with_capacity(num_rounds + 1);
    layers.push(codeword.to_vec());
    let mut layer_trees: Vec<MerkleTree> = Vec::with_capacity(num_rounds);
    layer_trees.push(codeword_tree.clone());

    let mut omega = lde_generator(shape.log_lde())?;
    let mut omegas: Vec<Goldilocks> = vec![omega];

    // Interleave: challenge[round] is squeezed BEFORE committing the new
    // layer (it mixes layer `round` into layer `round+1`). After folding,
    // commit the new layer + observe its root — unless it is the final
    // layer (sent explicitly).
    let mut layer_roots: Vec<Digest> = Vec::with_capacity(num_rounds - 1);
    for round in 0..num_rounds {
        let r = transcript.squeeze_fold_challenge()?;
        let prev = &layers[round];
        let log_prev = shape.log_lde() - round as u32;
        let half = (1usize << log_prev) / 2;
        let omega_prev = omegas[round];
        let mut next = Vec::with_capacity(half);
        for k in 0..half {
            let a = prev[k];
            let b = prev[k + half];
            let x = point_at_index(omega_prev, k as u32);
            next.push(fri_fold(a, b, x, r)?);
        }
        layers.push(next);
        omega = omega_prev * omega_prev;
        omegas.push(omega);

        let last = round + 1 == num_rounds;
        if !last {
            let tree = commit_layer(&layers[round + 1])?;
            let root = tree.root();
            transcript.observe_fri_root(&root);
            layer_roots.push(root);
            layer_trees.push(tree);
        }
    }

    // Final polynomial: interpolate the final layer's evaluations.
    let final_evals = &layers[num_rounds];
    let omega_final = omegas[num_rounds];
    let final_poly = inverse_dft_on_subgroup(final_evals, omega_final)?;
    transcript.observe_fri_final(&final_poly);

    // Query phase: open layers 0 .. num_rounds (exclusive of final).
    transcript.enter_query_phase();
    let mut queries = Vec::with_capacity(shape.num_queries);
    for _ in 0..shape.num_queries {
        let q = transcript.squeeze_query_index(shape.log_lde())?;
        queries.push(open_query(q, &layers, &layer_trees, shape)?);
    }

    Ok(FriProofData {
        layer_roots,
        final_poly,
        queries,
    })
}

/// Build the per-layer openings for query index `q`. Opens layers
/// `0 .. num_rounds` (the final layer `num_rounds` is the explicit poly).
fn open_query(
    q: u32,
    layers: &[Vec<Goldilocks>],
    layer_trees: &[MerkleTree],
    shape: FriShape,
) -> Result<FriQuery> {
    let num_rounds = shape.num_rounds();
    let mut layer_values = Vec::with_capacity(num_rounds);
    let mut value_auth = Vec::with_capacity(num_rounds);
    let mut sibling_auth = Vec::with_capacity(num_rounds);
    for layer in 0..num_rounds {
        let log_layer = shape.log_lde() - layer as u32;
        let layer_mask = (1u32 << log_layer).wrapping_sub(1);
        let value_index = q & layer_mask;
        let half = 1u32 << (log_layer - 1);
        let sibling_idx = value_index ^ half;
        let evals = &layers[layer];
        let tree = &layer_trees[layer];
        layer_values.push((evals[value_index as usize], evals[sibling_idx as usize]));
        value_auth.push(tree.open(value_index as usize)?);
        sibling_auth.push(tree.open(sibling_idx as usize)?);
    }
    Ok(FriQuery {
        index: q,
        layer_values,
        value_auth,
        sibling_auth,
    })
}

/// Layer-0 echo of a verified query: the index and the codeword value /
/// sibling the FRI verifier authenticated. The AIR verifier uses these
/// to bind the DEEP codeword to the trace / quotient at the query point.
#[derive(Debug, Clone, Copy)]
pub struct FriQueryEcho {
    /// Layer-0 query index.
    pub index: u32,
    /// Authenticated layer-0 value (DEEP codeword at `omega_lde^index`).
    pub value: Goldilocks,
    /// Authenticated layer-0 sibling (at `omega_lde^{index ^ N/2}`).
    pub sibling: Goldilocks,
}

/// Verify a FRI proof. `codeword_root` is the Merkle root of layer 0,
/// already observed into `transcript` by the caller before this call.
/// Returns the per-query layer-0 echoes so the caller can bind the DEEP
/// codeword to its own trace/quotient openings.
pub fn verify(
    proof: &FriProofData,
    codeword_root: &Digest,
    shape: FriShape,
    transcript: &mut dyn FriTranscript,
) -> Result<Vec<FriQueryEcho>> {
    let num_rounds = shape.num_rounds();
    if num_rounds == 0 {
        return Err(P3qError::FriVerification("fri verify: zero rounds"));
    }
    if proof.layer_roots.len() != num_rounds - 1 {
        return Err(P3qError::InvalidEncoding(
            "fri verify: layer root count mismatch",
        ));
    }
    if proof.final_poly.len() != (1usize << shape.log_final_poly) {
        return Err(P3qError::InvalidEncoding(
            "fri verify: final poly length mismatch",
        ));
    }
    if proof.queries.len() != shape.num_queries {
        return Err(P3qError::InvalidEncoding(
            "fri verify: query count mismatch",
        ));
    }

    // ----- Final-polynomial degree-bound check (load-bearing) -----
    // The genuine final polynomial of a low-degree codeword has degree
    // `< final_degree_bound`. Every coefficient at or above that index
    // MUST be zero. This is the ONLY check that rejects a high-degree
    // (non-low-degree) codeword: an honest fold of any vector reaches a
    // self-consistent final layer, so the per-query fold checks alone
    // cannot enforce low-degree. Rejecting a final poly with nonzero
    // high coefficients is what closes that gap.
    let final_degree_bound = shape.final_degree_bound();
    for (i, c) in proof.final_poly.iter().enumerate() {
        if i >= final_degree_bound && *c != Goldilocks::zero() {
            return Err(P3qError::FriVerification(
                "fri verify: final poly exceeds degree bound (codeword not low-degree)",
            ));
        }
    }

    // Replay commit-phase transcript: squeeze each fold challenge,
    // interleaved with observing the committed layer roots, then the
    // final poly, then enter query phase.
    let mut fold_challenges = Vec::with_capacity(num_rounds);
    for round in 0..num_rounds {
        fold_challenges.push(transcript.squeeze_fold_challenge()?);
        let last = round + 1 == num_rounds;
        if !last {
            transcript.observe_fri_root(&proof.layer_roots[round]);
        }
    }
    transcript.observe_fri_final(&proof.final_poly);
    transcript.enter_query_phase();

    // Roots by opened-layer number: layer 0 = codeword root, layers 1..
    // = proof.layer_roots.
    let mut roots: Vec<Digest> = Vec::with_capacity(num_rounds);
    roots.push(*codeword_root);
    roots.extend_from_slice(&proof.layer_roots);

    let omega_lde = lde_generator(shape.log_lde())?;
    let mut echoes = Vec::with_capacity(shape.num_queries);
    for query in &proof.queries {
        let q = transcript.squeeze_query_index(shape.log_lde())?;
        if q != query.index {
            return Err(P3qError::Transcript("fri verify: query index mismatch"));
        }
        echoes.push(verify_one_query(
            query,
            &roots,
            &fold_challenges,
            &proof.final_poly,
            omega_lde,
            shape,
        )?);
    }
    Ok(echoes)
}

fn verify_one_query(
    query: &FriQuery,
    roots: &[Digest],
    fold_challenges: &[Goldilocks],
    final_poly: &[Goldilocks],
    omega_lde: Goldilocks,
    shape: FriShape,
) -> Result<FriQueryEcho> {
    let num_rounds = shape.num_rounds();
    if query.layer_values.len() != num_rounds
        || query.value_auth.len() != num_rounds
        || query.sibling_auth.len() != num_rounds
    {
        return Err(P3qError::InvalidEncoding(
            "fri verify: query shape mismatch",
        ));
    }
    if (query.index as u64) >= (1u64 << shape.log_lde()) {
        return Err(P3qError::InvalidEncoding(
            "fri verify: query index out of domain",
        ));
    }

    // Authenticate every opened layer's value + sibling, fold forward,
    // and check that the carry from layer i equals layer i+1's value.
    let mut omega = omega_lde;
    let mut carry: Option<Goldilocks> = None;
    let mut echo = None;

    for layer in 0..num_rounds {
        let log_layer = shape.log_lde() - layer as u32;
        let layer_mask = (1u32 << log_layer).wrapping_sub(1);
        let value_index = query.index & layer_mask;
        let half = 1u32 << (log_layer - 1);
        let sibling_idx = value_index ^ half;

        let (value, sibling) = query.layer_values[layer];
        verify_proof(
            &roots[layer],
            &value.to_bytes(),
            value_index as usize,
            &query.value_auth[layer],
        )?;
        verify_proof(
            &roots[layer],
            &sibling.to_bytes(),
            sibling_idx as usize,
            &query.sibling_auth[layer],
        )?;

        if let Some(c) = carry {
            if c != value {
                return Err(P3qError::FriVerification(
                    "fri verify: fold carry disagrees with layer value",
                ));
            }
        } else {
            echo = Some(FriQueryEcho {
                index: query.index,
                value,
                sibling,
            });
        }

        // Fold (value, sibling) into the next layer. Always a=value,
        // x=omega^value_index (fold formula is half-symmetric).
        let x = omega.pow(value_index as u64);
        carry = Some(fri_fold(value, sibling, x, fold_challenges[layer])?);
        omega = omega * omega;
    }

    // `carry` now lives in the final layer (size 2^log_final_poly), and
    // `omega` is the final-layer generator (omega_lde squared num_rounds
    // times). Check it equals the explicit final polynomial there.
    let final_value = carry.ok_or(P3qError::FriVerification("fri verify: no layers"))?;
    let log_final = shape.log_final_poly;
    let final_mask = if log_final == 0 {
        0
    } else {
        (1u64 << log_final) - 1
    };
    let final_index = (query.index as u64) & final_mask;
    let final_x = omega.pow(final_index);
    let expected = horner(final_poly, final_x);
    if expected != final_value {
        return Err(P3qError::FriVerification(
            "fri verify: final poly disagrees with folded value",
        ));
    }

    echo.ok_or(P3qError::FriVerification("fri verify: missing layer0 echo"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::dft_on_subgroup;
    use p3q_challenger::Challenger;
    use p3q_core::transcript::labels;

    /// Minimal in-test transcript over the cSHAKE256 challenger. Mirrors
    /// what the AIR layer will provide, isolated so we can unit-test the
    /// engine's round-trip without pulling in p3q-stark.
    struct TestTranscript {
        ch: Challenger,
    }
    impl TestTranscript {
        fn new() -> Self {
            Self {
                ch: Challenger::new(labels::ROOT),
            }
        }
        fn field(&mut self) -> Goldilocks {
            for _ in 0..32 {
                let b: [u8; 8] = self.ch.challenge_array();
                let raw = u64::from_le_bytes(b);
                if raw < p3q_field::goldilocks::P {
                    return Goldilocks::from_u64(raw);
                }
            }
            Goldilocks::zero()
        }
    }
    impl FriTranscript for TestTranscript {
        fn observe_fri_root(&mut self, root: &Digest) {
            self.ch.observe(root);
        }
        fn observe_fri_final(&mut self, coeffs: &[Goldilocks]) {
            for c in coeffs {
                self.ch.observe(&c.to_bytes());
            }
        }
        fn squeeze_fold_challenge(&mut self) -> Result<Goldilocks> {
            Ok(self.field())
        }
        fn enter_query_phase(&mut self) {
            self.ch.observe(b"query");
        }
        fn squeeze_query_index(&mut self, log_bound: u32) -> Result<u32> {
            let b: [u8; 8] = self.ch.challenge_array();
            let raw = u64::from_le_bytes(b);
            let mask = (1u64 << log_bound) - 1;
            Ok((raw & mask) as u32)
        }
    }

    fn make_shape(log_degree: u32, log_blowup: u32, log_final_poly: u32) -> FriShape {
        FriShape {
            log_degree_bound: log_degree,
            log_blowup,
            log_final_poly,
            num_queries: 16,
        }
    }

    fn make_codeword(shape: FriShape) -> Vec<Goldilocks> {
        // A genuine degree-`<2^log_degree_bound` polynomial, LDE-extended.
        let n_coeffs = 1usize << shape.log_degree_bound;
        let coeffs: Vec<_> = (0..n_coeffs)
            .map(|i| Goldilocks::from_u64(i as u64 + 1))
            .collect();
        let omega = lde_generator(shape.log_lde()).unwrap();
        dft_on_subgroup(&coeffs, omega, 1 << shape.log_lde())
    }

    #[test]
    fn low_degree_codeword_round_trips() {
        // deg < 16, lde 128, final layer 4 (final_degree_bound = 16/32
        // clamps to 1 -> constant; exercise log_final_poly=2 below too).
        let shape = make_shape(4, 3, 1);
        let codeword = make_codeword(shape);
        let tree = commit_layer(&codeword).unwrap();
        let root = tree.root();

        let mut pt = TestTranscript::new();
        pt.observe_fri_root(&root); // bind layer-0 root like the caller would
        let proof = prove(&codeword, &tree, shape, &mut pt).unwrap();

        let mut vt = TestTranscript::new();
        vt.observe_fri_root(&root);
        let echoes = verify(&proof, &root, shape, &mut vt).unwrap();
        assert_eq!(echoes.len(), shape.num_queries);
        for e in &echoes {
            assert_eq!(e.value, codeword[e.index as usize]);
        }
    }

    #[test]
    fn low_degree_round_trips_nontrivial_final() {
        // log_final_poly = 3 with deg-bound 6, blowup 3: final_degree_bound
        // = 2^(6 - (9-3)) = 2^0 = 1. Use deg-bound 8 so the post-fold
        // degree bound is >1 and the high-coeff-zero check is non-vacuous.
        // deg 256, lde 2048, final 8 -> num_rounds 8, final_degree_bound
        // = 2^(8-8)=1. To get >1 we need fewer rounds: raise log_final_poly.
        // deg-bound 8, blowup 3, log_final_poly 5: num_rounds = 11-5 = 6,
        // final_degree_bound = 2^(8-6) = 4.
        let shape = make_shape(8, 3, 5);
        assert_eq!(shape.final_degree_bound(), 4);
        let codeword = make_codeword(shape);
        let tree = commit_layer(&codeword).unwrap();
        let root = tree.root();
        let mut pt = TestTranscript::new();
        pt.observe_fri_root(&root);
        let proof = prove(&codeword, &tree, shape, &mut pt).unwrap();
        // The genuine final poly must vanish beyond degree 4.
        for (i, c) in proof.final_poly.iter().enumerate() {
            if i >= 4 {
                assert_eq!(*c, Goldilocks::zero(), "coeff {i} must be zero");
            }
        }
        let mut vt = TestTranscript::new();
        vt.observe_fri_root(&root);
        verify(&proof, &root, shape, &mut vt).unwrap();
    }

    #[test]
    fn high_degree_codeword_rejected() {
        // A random vector is NOT the LDE of a low-degree polynomial. The
        // honest prover folds it down to a full-rank final layer whose
        // interpolation has nonzero HIGH coefficients (beyond
        // final_degree_bound). The verifier's degree-bound check rejects.
        let shape = make_shape(4, 3, 3); // final_degree_bound = 2^(4-4)=1
        assert_eq!(shape.final_degree_bound(), 1);
        let mut s = 0x1234_5678_9abc_def0u64;
        let codeword: Vec<_> = (0..1usize << shape.log_lde())
            .map(|_| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                Goldilocks::from_u64(s % p3q_field::goldilocks::P)
            })
            .collect();
        let tree = commit_layer(&codeword).unwrap();
        let root = tree.root();
        let mut pt = TestTranscript::new();
        pt.observe_fri_root(&root);
        let proof = prove(&codeword, &tree, shape, &mut pt).unwrap();
        // The final poly should have nonzero coefficients beyond degree 1.
        let high_nonzero = proof.final_poly[1..]
            .iter()
            .any(|c| *c != Goldilocks::zero());
        assert!(
            high_nonzero,
            "random codeword should fold to high-degree final poly"
        );
        let mut vt = TestTranscript::new();
        vt.observe_fri_root(&root);
        let res = verify(&proof, &root, shape, &mut vt);
        assert!(res.is_err(), "high-degree codeword must reject");
    }

    #[test]
    fn cheating_final_poly_rejected() {
        // Take an honest proof and bump the final polynomial's constant
        // term: the queried folds no longer agree with it.
        let shape = make_shape(4, 3, 1);
        let codeword = make_codeword(shape);
        let tree = commit_layer(&codeword).unwrap();
        let root = tree.root();
        let mut pt = TestTranscript::new();
        pt.observe_fri_root(&root);
        let mut proof = prove(&codeword, &tree, shape, &mut pt).unwrap();
        proof.final_poly[0] = proof.final_poly[0] + Goldilocks::one();
        let mut vt = TestTranscript::new();
        vt.observe_fri_root(&root);
        assert!(
            verify(&proof, &root, shape, &mut vt).is_err(),
            "a final poly inconsistent with the folds must reject"
        );
    }

    #[test]
    fn wrong_codeword_root_rejected() {
        let shape = make_shape(4, 3, 1);
        let codeword = make_codeword(shape);
        let tree = commit_layer(&codeword).unwrap();
        let root = tree.root();
        let mut pt = TestTranscript::new();
        pt.observe_fri_root(&root);
        let proof = prove(&codeword, &tree, shape, &mut pt).unwrap();
        let mut wrong = root;
        wrong[0] ^= 0xff;
        let mut vt = TestTranscript::new();
        vt.observe_fri_root(&wrong);
        assert!(verify(&proof, &wrong, shape, &mut vt).is_err());
    }

    #[test]
    fn tampered_query_value_rejected() {
        let shape = make_shape(4, 3, 1);
        let codeword = make_codeword(shape);
        let tree = commit_layer(&codeword).unwrap();
        let root = tree.root();
        let mut pt = TestTranscript::new();
        pt.observe_fri_root(&root);
        let mut proof = prove(&codeword, &tree, shape, &mut pt).unwrap();
        proof.queries[0].layer_values[0].0 = proof.queries[0].layer_values[0].0 + Goldilocks::one();
        let mut vt = TestTranscript::new();
        vt.observe_fri_root(&root);
        assert!(verify(&proof, &root, shape, &mut vt).is_err());
    }
}
