//! AIR DEEP-STARK prover.
//!
//! Compiled only behind `#[cfg(any(test, feature = "prover"))]` so the
//! audited verifier crate never pulls in proving codepaths. This is a
//! **real** prover — it genuinely commits the trace and quotient,
//! enforces the constraint identity via the quotient, and binds
//! everything through OOD/DEEP + FRI. It is NOT optimised: DFTs are
//! naive `O(N²)`, which is fine for the trace sizes used in tests and
//! the initial Z-Chain circuits but MUST be replaced with radix-2 FFT
//! before large-scale (e.g. batched SLH-DSA) proving. The honest perf
//! status is recorded in `LLM.md`.

use p3q_core::{P3qError, Result};
use p3q_field::{Field, Goldilocks};
use p3q_fri::domain::{
    coset_dft, coset_idft, dft_on_subgroup, inverse_dft_on_subgroup, lde_generator,
};
use p3q_fri::engine::{self, FriQuery, FriShape, FriTranscript};
use p3q_merkle::MerkleTree;

use crate::air::Air;
use crate::proof::{AirProof, OodOpenings, QueryColumns};
use crate::prover_shared::{
    deep_degree_log_bound, eval_constraints, pick_log_blowup, pick_log_final_poly, z_h, NUM_QUERIES,
};
use crate::transcript::StarkTranscript;

/// Coset shift used for the quotient computation. The Goldilocks
/// generator `g = 7` lies in no proper smooth-order subgroup, so the
/// coset `7·D` is disjoint from the trace domain `H ⊆ D`; the vanishing
/// polynomial `Z_H` is therefore invertible everywhere on `7·D`, which
/// is exactly where the prover divides `C` by `Z_H`.
const COSET_SHIFT: Goldilocks = Goldilocks::from_u64(7);

/// An execution trace in column-major form: `columns[j]` is the length-
/// `num_rows` evaluation of column `j` over the trace domain `H`.
#[derive(Debug, Clone)]
pub struct Trace {
    /// `width` columns, each `num_rows` field elements.
    pub columns: Vec<Vec<Goldilocks>>,
}

impl Trace {
    /// Build a trace from column vectors. All columns must have equal,
    /// power-of-two length.
    pub fn new(columns: Vec<Vec<Goldilocks>>) -> Result<Self> {
        if columns.is_empty() {
            return Err(P3qError::InvalidLength("trace: zero columns"));
        }
        let n = columns[0].len();
        if !n.is_power_of_two() {
            return Err(P3qError::InvalidLength("trace: rows not a power of two"));
        }
        if columns.iter().any(|c| c.len() != n) {
            return Err(P3qError::InvalidLength("trace: ragged columns"));
        }
        Ok(Self { columns })
    }

    /// Number of rows.
    pub fn num_rows(&self) -> usize {
        self.columns[0].len()
    }

    /// Width (number of columns).
    pub fn width(&self) -> usize {
        self.columns.len()
    }
}

/// Commit a single codeword (column or quotient) over the LDE domain to
/// a Merkle tree (one leaf per evaluation).
fn commit_codeword(evals: &[Goldilocks]) -> Result<MerkleTree> {
    let leaves: Vec<Vec<u8>> = evals.iter().map(|v| v.to_bytes()).collect();
    MerkleTree::from_leaves(&leaves)
}

/// Commit the trace LDE row-major: leaf `i` is the concatenation of all
/// `w` column values at LDE row `i`. Binds all columns under one root.
fn commit_trace_rows(columns_lde: &[Vec<Goldilocks>], n_lde: usize) -> Result<MerkleTree> {
    let width = columns_lde.len();
    let mut leaves = Vec::with_capacity(n_lde);
    for i in 0..n_lde {
        let mut row = Vec::with_capacity(width * Goldilocks::BYTES);
        for col in columns_lde {
            row.extend_from_slice(&col[i].to_bytes());
        }
        leaves.push(row);
    }
    MerkleTree::from_leaves(&leaves)
}

/// Produce an AIR DEEP-STARK proof that `trace` satisfies `air`'s
/// constraints under `public_inputs`.
pub fn prove_air<A: Air>(air: &A, trace: &Trace, public_inputs: &[Goldilocks]) -> Result<AirProof> {
    // ---- 0. Shape / sanity ----
    if trace.width() != air.width() {
        return Err(P3qError::StarkVerification("trace width != air width"));
    }
    if trace.num_rows() != air.num_rows() {
        return Err(P3qError::StarkVerification("trace rows != air num_rows"));
    }
    if public_inputs.len() != air.num_public_inputs() {
        return Err(P3qError::StarkVerification(
            "public input count != air num_public_inputs",
        ));
    }
    // An AIR with no transition constraints certifies nothing; refuse to
    // produce a "proof of nothing" (mirrors the verifier's gate).
    if air.num_constraints() == 0 {
        return Err(P3qError::StarkVerification(
            "air declares zero constraints (a STARK with no constraints certifies nothing)",
        ));
    }
    let num_rows = trace.num_rows();
    let log_n = num_rows.trailing_zeros();
    // Blowup must be large enough that the quotient (degree up to
    // (constraint_degree − 1)·(num_rows − 1)) fits in the LDE: i.e.
    // 2^log_blowup ≥ constraint_degree. Round up to a power of two.
    let log_blowup = pick_log_blowup(air.constraint_degree());
    let log_lde = log_n + log_blowup;
    // Defensive shape bound (same invariant the verifier enforces): the
    // LDE log must keep the `1 << log_lde` shift well-defined and the
    // trace degree within the audited range, so no shift can overflow.
    if !(1..=20).contains(&log_n) {
        return Err(P3qError::StarkVerification(
            "trace log_rows out of range (must be 1..=20)",
        ));
    }
    if log_lde > 31 {
        return Err(P3qError::StarkVerification(
            "trace log_rows + log_blowup exceeds LDE shift bound",
        ));
    }
    let n_lde = 1usize << log_lde;

    let g_h = lde_generator(log_n)?; // trace-domain generator
    let omega = lde_generator(log_lde)?; // LDE-domain generator

    // ---- 1. Interpolate trace columns to coefficients, LDE-extend ----
    let mut trace_coeffs: Vec<Vec<Goldilocks>> = Vec::with_capacity(trace.width());
    let mut trace_lde: Vec<Vec<Goldilocks>> = Vec::with_capacity(trace.width());
    for col in &trace.columns {
        let coeffs = inverse_dft_on_subgroup(col, g_h)?;
        let lde = dft_on_subgroup(&coeffs, omega, n_lde);
        trace_coeffs.push(coeffs);
        trace_lde.push(lde);
    }

    // ---- 2. Commit trace, sample constraint challenges ----
    let trace_tree = commit_trace_rows(&trace_lde, n_lde)?;
    let trace_root = trace_tree.root();
    let mut transcript = StarkTranscript::new(public_inputs);
    transcript.observe_trace_root(&trace_root);
    let alphas = transcript.sample_constraint_challenges(air.num_constraints())?;

    // ---- 3. Build the quotient Q = C / Z_H on the coset 7·D ----
    //
    // Evaluate every trace column on the coset 7·D, evaluate the
    // constraints pointwise there (the "next" row at coset point
    // 7·omega^i is the trace at 7·omega^i · g_H — i.e. the column poly
    // evaluated at COSET_SHIFT·omega^i·(omega^blowup), since g_H =
    // omega^blowup), random-linear-combine with `alphas`, divide by
    // Z_H(7·omega^i) (nonzero on the coset), then interpolate the coset
    // evaluations back to the quotient's coefficients.
    let coset_trace: Vec<Vec<Goldilocks>> = trace_coeffs
        .iter()
        .map(|c| coset_dft(c, COSET_SHIFT, omega, n_lde))
        .collect();
    // Next-row stride on the LDE domain: g_H = omega^blowup, so the
    // "next" trace value at index i is the column poly at
    // coset_point · omega^blowup = coset value at index (i + blowup).
    let blowup = 1usize << log_blowup;
    let width = trace.width();
    let mut quotient_coset = Vec::with_capacity(n_lde);
    for i in 0..n_lde {
        let next_i = (i + blowup) % n_lde;
        let local: Vec<Goldilocks> = (0..width).map(|j| coset_trace[j][i]).collect();
        let next: Vec<Goldilocks> = (0..width).map(|j| coset_trace[j][next_i]).collect();
        let constraints = eval_constraints(air, &local, &next, public_inputs)?;
        // C(x) = Σ α_k · C_k(x)
        let mut c = Goldilocks::zero();
        for (a, ck) in alphas.iter().zip(constraints.iter()) {
            c = c + *a * *ck;
        }
        let x = COSET_SHIFT * omega.pow(i as u64);
        let zh = z_h(x, log_n);
        let zh_inv = zh.inverse().ok_or(P3qError::StarkVerification(
            "Z_H vanished on coset (impossible)",
        ))?;
        quotient_coset.push(c * zh_inv);
    }
    // Interpolate the quotient coset evaluations to coefficients, then
    // evaluate on the pure subgroup D for committing + DEEP.
    let quotient_coeffs = coset_idft(&quotient_coset, COSET_SHIFT, omega)?;
    // Soundness: the quotient must be a genuine low-degree polynomial.
    // If a constraint is violated on H, C does NOT vanish on H, so
    // C/Z_H is not a polynomial and the coset interpolation yields a
    // degree-(n_lde−1) result whose high coefficients are nonzero — FRI
    // will reject it downstream. We do not (and must not) "fix" that
    // here; the prover faithfully commits whatever the trace produces.
    let quotient_lde = dft_on_subgroup(&quotient_coeffs, omega, n_lde);
    let quotient_tree = commit_codeword(&quotient_lde)?;
    let quotient_root = quotient_tree.root();
    transcript.observe_quotient_root(&quotient_root);

    // ---- 4. OOD point ζ ∉ D; open T_j(ζ), T_j(gζ), Q(ζ) ----
    let zeta = sample_ood_not_in_domain(&mut transcript, omega, log_lde)?;
    let g_zeta = zeta * g_h;
    let trace_at_zeta: Vec<Goldilocks> = trace_coeffs.iter().map(|c| eval_poly(c, zeta)).collect();
    let trace_at_g_zeta: Vec<Goldilocks> =
        trace_coeffs.iter().map(|c| eval_poly(c, g_zeta)).collect();
    let quotient_at_zeta = eval_poly(&quotient_coeffs, zeta);
    transcript.observe_ood_values(&trace_at_zeta, &trace_at_g_zeta, quotient_at_zeta);

    // ---- 5. DEEP composition codeword on D ----
    let (gammas, gammas_shifted, gamma_q) = transcript.sample_deep_challenges(width)?;
    let deep_codeword = build_deep_codeword(
        &trace_lde,
        &quotient_lde,
        &trace_at_zeta,
        &trace_at_g_zeta,
        quotient_at_zeta,
        zeta,
        g_zeta,
        &gammas,
        &gammas_shifted,
        gamma_q,
        omega,
        n_lde,
    )?;

    // ---- 6. FRI low-degree proof of the DEEP codeword ----
    // The DEEP codeword has degree < num_rows (the trace/quotient DEEP
    // quotients each drop one degree from a degree-<num_rows poly... the
    // quotient itself can be up to degree (constraint_degree−1)·
    // (num_rows−1); the DEEP quotient (Q−Q(ζ))/(x−ζ) has degree one less
    // — so the DEEP codeword degree bound is the max of the trace and
    // quotient DEEP-quotient degrees). We size the FRI degree bound to
    // that maximum, rounded to a power of two.
    let log_deep_degree = deep_degree_log_bound(log_n, log_blowup, air.constraint_degree());
    let shape = FriShape {
        log_degree_bound: log_deep_degree,
        log_blowup: log_lde - log_deep_degree,
        log_final_poly: pick_log_final_poly(log_deep_degree),
        num_queries: NUM_QUERIES,
    };
    let deep_tree = commit_codeword(&deep_codeword)?;
    let deep_root = deep_tree.root();
    transcript.observe_fri_root(&deep_root);
    let fri = engine::prove(&deep_codeword, &deep_tree, shape, &mut transcript)?;

    // ---- 7. Per-query trace + quotient openings (aligned to fri.queries) ----
    let query_columns = build_query_columns(
        &fri.queries,
        &trace_lde,
        &trace_tree,
        &quotient_lde,
        &quotient_tree,
        log_lde,
    )?;

    // ---- 8. Boundary openings: one authenticated row per distinct
    //         boundary LDE index (row · blowup). ----
    let boundary_openings = build_boundary_openings(air, &trace_lde, &trace_tree, blowup, width)?;

    Ok(AirProof {
        log_trace_rows: log_n,
        log_blowup,
        trace_root,
        quotient_root,
        deep_root,
        ood: OodOpenings {
            trace_at_zeta,
            trace_at_g_zeta,
            quotient_at_zeta,
        },
        boundary_openings,
        fri,
        query_columns,
    })
}

/// Evaluate a coefficient polynomial at `x` (Horner).
fn eval_poly(coeffs: &[Goldilocks], x: Goldilocks) -> Goldilocks {
    let mut acc = Goldilocks::zero();
    for &c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// Resample the OOD point until it is not in the LDE domain `D` (so the
/// DEEP denominators `(x − ζ)` are nonzero on `D`). `ζ ∈ D` iff
/// `ζ^{N_lde} = 1`. The probability of landing in `D` is `N_lde/|F|`,
/// astronomically small, but we guard it.
fn sample_ood_not_in_domain(
    transcript: &mut StarkTranscript,
    _omega: Goldilocks,
    log_lde: u32,
) -> Result<Goldilocks> {
    for _ in 0..64 {
        let zeta = transcript.sample_ood_point()?;
        if zeta == Goldilocks::zero() {
            continue;
        }
        if zeta.pow(1u64 << log_lde) != Goldilocks::one() {
            return Ok(zeta);
        }
    }
    Err(P3qError::StarkVerification(
        "OOD sampling kept landing in the LDE domain (statistically impossible)",
    ))
}

/// Build the DEEP composition codeword on `D` (length `n_lde`).
///
/// `D_eep(x) = Σ_j γ_j·(T_j(x)−T_j(ζ))/(x−ζ)
///           + Σ_j γ'_j·(T_j(x)−T_j(gζ))/(x−gζ)
///           + γ_q·(Q(x)−Q(ζ))/(x−ζ)`
#[allow(clippy::too_many_arguments)]
fn build_deep_codeword(
    trace_lde: &[Vec<Goldilocks>],
    quotient_lde: &[Goldilocks],
    trace_at_zeta: &[Goldilocks],
    trace_at_g_zeta: &[Goldilocks],
    quotient_at_zeta: Goldilocks,
    zeta: Goldilocks,
    g_zeta: Goldilocks,
    gammas: &[Goldilocks],
    gammas_shifted: &[Goldilocks],
    gamma_q: Goldilocks,
    omega: Goldilocks,
    n_lde: usize,
) -> Result<Vec<Goldilocks>> {
    let width = trace_lde.len();
    let mut out = Vec::with_capacity(n_lde);
    for i in 0..n_lde {
        let x = omega.pow(i as u64);
        let denom_zeta = (x - zeta)
            .inverse()
            .ok_or(P3qError::StarkVerification("DEEP denom (x−ζ) zero"))?;
        let denom_g_zeta = (x - g_zeta)
            .inverse()
            .ok_or(P3qError::StarkVerification("DEEP denom (x−gζ) zero"))?;
        let mut acc = Goldilocks::zero();
        for j in 0..width {
            let tj = trace_lde[j][i];
            acc = acc + gammas[j] * (tj - trace_at_zeta[j]) * denom_zeta;
            acc = acc + gammas_shifted[j] * (tj - trace_at_g_zeta[j]) * denom_g_zeta;
        }
        acc = acc + gamma_q * (quotient_lde[i] - quotient_at_zeta) * denom_zeta;
        out.push(acc);
    }
    Ok(out)
}

/// Build authenticated boundary-row openings: for each distinct LDE
/// index `row·blowup` referenced by a boundary constraint, open the full
/// trace row once.
fn build_boundary_openings<A: Air>(
    air: &A,
    trace_lde: &[Vec<Goldilocks>],
    trace_tree: &MerkleTree,
    blowup: usize,
    width: usize,
) -> Result<Vec<crate::proof::BoundaryOpening>> {
    use std::collections::BTreeSet;
    let mut indices: BTreeSet<usize> = BTreeSet::new();
    for bc in air.boundary_constraints() {
        indices.insert(bc.row * blowup);
    }
    let mut out = Vec::with_capacity(indices.len());
    for idx in indices {
        let row: Vec<Goldilocks> = (0..width).map(|j| trace_lde[j][idx]).collect();
        out.push(crate::proof::BoundaryOpening {
            lde_index: idx as u32,
            row,
            auth: trace_tree.open(idx)?,
        });
    }
    Ok(out)
}

/// Build per-query trace + quotient openings aligned with `fri_queries`.
fn build_query_columns(
    fri_queries: &[FriQuery],
    trace_lde: &[Vec<Goldilocks>],
    trace_tree: &MerkleTree,
    quotient_lde: &[Goldilocks],
    quotient_tree: &MerkleTree,
    log_lde: u32,
) -> Result<Vec<QueryColumns>> {
    let width = trace_lde.len();
    let n_lde = 1u32 << log_lde;
    let half = n_lde / 2;
    let mut out = Vec::with_capacity(fri_queries.len());
    for q in fri_queries {
        let idx = q.index;
        let sib = idx ^ half;
        let trace_value: Vec<Goldilocks> = (0..width).map(|j| trace_lde[j][idx as usize]).collect();
        let trace_sibling: Vec<Goldilocks> =
            (0..width).map(|j| trace_lde[j][sib as usize]).collect();
        out.push(QueryColumns {
            index: idx,
            trace_value,
            trace_sibling,
            trace_auth: trace_tree.open(idx as usize)?,
            trace_sibling_auth: trace_tree.open(sib as usize)?,
            quotient_value: quotient_lde[idx as usize],
            quotient_sibling: quotient_lde[sib as usize],
            quotient_auth: quotient_tree.open(idx as usize)?,
            quotient_sibling_auth: quotient_tree.open(sib as usize)?,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{prove_air, Trace};
    use crate::air::{Air, AirBuilder};
    use crate::verifier::verify_air;
    use p3q_field::{Field, Goldilocks};

    /// Single column with the cyclic transition `next == local` (a constant
    /// column). It holds on every row INCLUDING the wrap-around row 7→0, so
    /// the constraint vanishes on all of `H` and `C/Z_H` is a genuine
    /// polynomial — a satisfying instance the verifier must accept.
    struct ConstantColumnAir;
    impl Air for ConstantColumnAir {
        fn width(&self) -> usize {
            1
        }
        fn num_rows(&self) -> usize {
            8
        }
        fn num_public_inputs(&self) -> usize {
            0
        }
        fn num_constraints(&self) -> usize {
            1
        }
        fn constraint_degree(&self) -> usize {
            1
        }
        fn eval<AB: AirBuilder>(&self, b: &mut AB) {
            let next = b.next(0);
            let local = b.local(0);
            b.assert_eq(next, local);
        }
    }

    /// End-to-end: a satisfying trace proves and verifies. Exercises the
    /// full machinery — trace LDE, quotient `C/Z_H`, OOD/DEEP, FRI, and the
    /// per-query Merkle openings. This is what makes the prover/verifier
    /// "real" rather than scaffold.
    #[test]
    fn deep_stark_round_trip_accepts_valid_trace() {
        let air = ConstantColumnAir;
        let col = vec![Goldilocks::from_u64(7); 8];
        let trace = Trace::new(vec![col]).expect("trace");
        let proof = prove_air(&air, &trace, &[]).expect("prove a satisfying trace");
        verify_air(&air, &proof, &[]).expect("verifier accepts a valid proof");
    }

    /// A trace that violates the constraint at one row makes `C` non-vanishing
    /// on `H`, so `C/Z_H` is NOT low-degree; the prover faithfully commits it
    /// and FRI's low-degree test rejects it (soundness). The verifier must
    /// reject (or the prover refuse) — never accept.
    #[test]
    fn deep_stark_rejects_tampered_trace() {
        let air = ConstantColumnAir;
        let mut col = vec![Goldilocks::from_u64(7); 8];
        col[3] = Goldilocks::from_u64(8); // break the constant column
        let trace = Trace::new(vec![col]).expect("trace");
        match prove_air(&air, &trace, &[]) {
            Ok(proof) => assert!(
                verify_air(&air, &proof, &[]).is_err(),
                "verifier MUST reject a tampered trace"
            ),
            Err(_) => { /* prover refused — also fail-closed */ }
        }
    }

    /// Public-input count mismatch fails closed.
    #[test]
    fn deep_stark_wrong_public_input_count_fails() {
        let air = ConstantColumnAir;
        let col = vec![Goldilocks::from_u64(7); 8];
        let trace = Trace::new(vec![col]).expect("trace");
        assert!(
            prove_air(&air, &trace, &[Goldilocks::one()]).is_err(),
            "prover rejects public-input count != num_public_inputs"
        );
    }

    // ---- Regression: F4 (fail-open zero-constraint AIR) ----

    /// An AIR that declares `num_constraints() == 0` and emits no
    /// constraint certifies nothing — a "proof of nothing". Both the
    /// prover and the verifier MUST refuse it with a typed error, never
    /// produce/accept a proof for arbitrary junk.
    struct NoConstraintAir;
    impl Air for NoConstraintAir {
        fn width(&self) -> usize {
            1
        }
        fn num_rows(&self) -> usize {
            8
        }
        fn num_public_inputs(&self) -> usize {
            0
        }
        fn num_constraints(&self) -> usize {
            0
        }
        fn constraint_degree(&self) -> usize {
            1
        }
        fn eval<AB: AirBuilder>(&self, _b: &mut AB) {}
    }

    #[test]
    fn f4_zero_constraint_air_is_refused_by_prover() {
        let air = NoConstraintAir;
        // Arbitrary junk trace; a zero-constraint AIR would otherwise
        // "prove" it.
        let col: Vec<Goldilocks> = (0..8)
            .map(|i| Goldilocks::from_u64(0xDEAD_0000 + i))
            .collect();
        let trace = Trace::new(vec![col]).expect("trace");
        assert!(
            prove_air(&air, &trace, &[]).is_err(),
            "prover MUST refuse a zero-constraint AIR (proof of nothing)"
        );
    }

    #[test]
    fn f4_zero_constraint_air_is_refused_by_verifier() {
        // The verifier must reject independently of the prover: even a
        // proof object that somehow reached it cannot certify a
        // zero-constraint AIR. We borrow a well-formed proof from a
        // 1-constraint AIR and present it against the zero-constraint AIR
        // — the verifier rejects on the constraint-count gate, panic-free.
        let real = ConstantColumnAir;
        let col = vec![Goldilocks::from_u64(7); 8];
        let trace = Trace::new(vec![col]).expect("trace");
        let proof = prove_air(&real, &trace, &[]).expect("prove a real AIR");
        let zero = NoConstraintAir;
        assert!(
            verify_air(&zero, &proof, &[]).is_err(),
            "verifier MUST reject against a zero-constraint AIR"
        );
    }

    // ---- Regression: F1 (remote-DoS via out-of-range shape) ----

    /// `log_blowup` and `log_trace_rows` are attacker-controlled fields of
    /// the proof. The verifier derives `log_lde = log_n + log_blowup` and
    /// shifts by it; an out-of-range value must yield a typed error BEFORE
    /// any shift, never a panic (the file is panic-free by contract).
    #[test]
    fn f1_oversized_log_blowup_returns_typed_error_no_panic() {
        let air = ConstantColumnAir;
        let col = vec![Goldilocks::from_u64(7); 8];
        let trace = Trace::new(vec![col]).expect("trace");
        let proof = prove_air(&air, &trace, &[]).expect("prove");
        // Values straddling and far beyond the u32 shift edge (log_lde ==
        // 32) — every one must REJECT and none may panic or accept.
        for bad in [
            6u32,
            25,
            28,
            29,
            30,
            31,
            40,
            60,
            64,
            100,
            u32::MAX - 2,
            u32::MAX,
        ] {
            let mut p = proof.clone();
            p.log_blowup = bad;
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                verify_air(&air, &p, &[])
            }));
            match res {
                Ok(Ok(())) => panic!("oversized log_blowup={bad} was ACCEPTED"),
                Ok(Err(_)) => { /* typed rejection — correct */ }
                Err(_) => panic!("verifier PANICKED on log_blowup={bad} (DoS)"),
            }
        }
    }

    #[test]
    fn f1_oversized_log_trace_rows_returns_typed_error_no_panic() {
        let air = ConstantColumnAir;
        let col = vec![Goldilocks::from_u64(7); 8];
        let trace = Trace::new(vec![col]).expect("trace");
        let proof = prove_air(&air, &trace, &[]).expect("prove");
        for bad in [0u32, 1, 2, 5, 21, 31, 40, 63, 64, u32::MAX] {
            let mut p = proof.clone();
            p.log_trace_rows = bad;
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                verify_air(&air, &p, &[])
            }));
            match res {
                Ok(v) => assert!(v.is_err(), "wrong log_trace_rows={bad} must reject"),
                Err(_) => panic!("verifier PANICKED on log_trace_rows={bad} (panic-free VIOLATED)"),
            }
        }
    }

    // ---- Regression: F3 (cyclic-transition contract) ----

    /// A *terminating* counter `next == local + 1` over rows `0,1,…,7`.
    /// The wrap-around pair (row 7 → row 0) gives `0 != 8`, so `C` does
    /// not vanish on all of `H`. The air.rs `eval` contract states every
    /// constraint must hold on the cyclic wrap-around too (there is no
    /// last-row mask), so this MUST be rejected — documenting that a
    /// non-cyclic recurrence cannot be written as a bare transition
    /// constraint.
    struct TerminatingCounterAir;
    impl Air for TerminatingCounterAir {
        fn width(&self) -> usize {
            1
        }
        fn num_rows(&self) -> usize {
            8
        }
        fn num_public_inputs(&self) -> usize {
            0
        }
        fn num_constraints(&self) -> usize {
            1
        }
        fn constraint_degree(&self) -> usize {
            1
        }
        fn eval<AB: AirBuilder>(&self, b: &mut AB) {
            let one = b.constant(Goldilocks::one());
            let next = b.next(0);
            let local = b.local(0);
            b.assert_eq(next, local + one);
        }
    }

    #[test]
    fn f3_cyclic_valid_air_proves_and_verifies() {
        // The constant column `next == local` holds on EVERY row including
        // the wrap-around — a genuinely cyclic transition. It must verify.
        let air = ConstantColumnAir;
        let col = vec![Goldilocks::from_u64(7); 8];
        let trace = Trace::new(vec![col]).expect("trace");
        let proof = prove_air(&air, &trace, &[]).expect("prove cyclic-valid trace");
        verify_air(&air, &proof, &[]).expect("verifier accepts a cyclic-valid trace");
    }

    #[test]
    fn f3_terminating_counter_is_rejected() {
        // The contract has NO last-row selector: the doc-following
        // terminating counter 0..7 must NOT prove+verify.
        let air = TerminatingCounterAir;
        let col: Vec<Goldilocks> = (0..8).map(Goldilocks::from_u64).collect();
        let trace = Trace::new(vec![col]).expect("trace");
        let accepted = match prove_air(&air, &trace, &[]) {
            Ok(p) => verify_air(&air, &p, &[]).is_ok(),
            Err(_) => false, // prover refused — also fail-closed
        };
        assert!(
            !accepted,
            "a terminating (non-cyclic) transition must be rejected (no last-row mask)"
        );
    }
}
