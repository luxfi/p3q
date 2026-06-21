//! AIR DEEP-STARK verifier. Panic-free by contract: every fault returns
//! a typed [`P3qError`]. Wraps the single FRI low-degree engine in
//! `p3q-fri` and adds the AIR-specific checks the engine does not know
//! about:
//!
//! 1. **Boundary constraints** — exact-point equality of the committed
//!    trace at fixed rows against the public statement.
//! 2. **Transition-constraint identity at ζ** — `Q(ζ)·Z_H(ζ) == Σ_k
//!    α_k·C_k(T(ζ), T(gζ))`, binding the committed quotient to the
//!    committed trace by Schwartz-Zippel.
//! 3. **DEEP / OOD binding** — at every FRI query, recompute the DEEP
//!    codeword value from the authenticated trace + quotient openings
//!    and check it equals the FRI layer-0 value the engine
//!    authenticated. This is what forces the OOD evaluations the prover
//!    opened to be the *genuine* evaluations of the committed
//!    polynomials.
//! 4. **Low-degree (FRI)** — delegated to the engine, including the
//!    final-poly degree-bound check that rejects a DEEP codeword that is
//!    not actually low-degree (which happens iff the OOD values are
//!    inconsistent, i.e. the trace violates a constraint).
//!
//! Together these reject any trace that does not satisfy the AIR.

use p3q_core::{P3qError, Result};
use p3q_field::{Field, Goldilocks};
use p3q_fri::domain::lde_generator;
use p3q_fri::engine::{self, FriShape, FriTranscript};
use p3q_merkle::{verify_proof, Digest};

use crate::air::Air;
use crate::proof::{AirProof, QueryColumns};
use crate::prover_shared::{deep_degree_log_bound, eval_constraints, pick_log_final_poly, z_h};
use crate::transcript::StarkTranscript;

/// Verify an AIR DEEP-STARK proof for `air` under `public_inputs`.
pub fn verify_air<A: Air>(air: &A, proof: &AirProof, public_inputs: &[Goldilocks]) -> Result<()> {
    // ---- 0. Shape / sanity ----
    if public_inputs.len() != air.num_public_inputs() {
        return Err(P3qError::StarkVerification(
            "public input count != air num_public_inputs",
        ));
    }
    let log_n = proof.log_trace_rows;
    if (1usize << log_n) != air.num_rows() {
        return Err(P3qError::StarkVerification(
            "proof trace rows != air num_rows",
        ));
    }
    let width = air.width();
    if proof.ood.trace_at_zeta.len() != width || proof.ood.trace_at_g_zeta.len() != width {
        return Err(P3qError::StarkVerification(
            "OOD trace vector width mismatch",
        ));
    }
    let log_blowup = proof.log_blowup;
    let log_lde = log_n + log_blowup;
    let n_lde = 1u32 << log_lde;
    let blowup = 1u32 << log_blowup;
    let g_h = lde_generator(log_n)?;
    let omega = lde_generator(log_lde)?;

    // ---- 1. Rebuild transcript through the commitments ----
    let mut transcript = StarkTranscript::new(public_inputs);
    transcript.observe_trace_root(&proof.trace_root);
    let alphas = transcript.sample_constraint_challenges(air.num_constraints())?;
    transcript.observe_quotient_root(&proof.quotient_root);

    // ζ ∉ D (resample exactly as the prover did).
    let zeta = sample_ood_not_in_domain(&mut transcript, log_lde)?;
    let g_zeta = zeta * g_h;
    transcript.observe_ood_values(
        &proof.ood.trace_at_zeta,
        &proof.ood.trace_at_g_zeta,
        proof.ood.quotient_at_zeta,
    );
    let (gammas, gammas_shifted, gamma_q) = transcript.sample_deep_challenges(width)?;

    // ---- 2. Boundary constraints: exact-point checks ----
    verify_boundary(air, proof, blowup, width)?;

    // ---- 3. Transition-constraint identity at ζ ----
    // Q(ζ)·Z_H(ζ) == Σ_k α_k · C_k(T(ζ), T(gζ))
    let constraints_at_zeta = eval_constraints(
        air,
        &proof.ood.trace_at_zeta,
        &proof.ood.trace_at_g_zeta,
        public_inputs,
    )?;
    let mut combined = Goldilocks::zero();
    for (a, ck) in alphas.iter().zip(constraints_at_zeta.iter()) {
        combined = combined + *a * *ck;
    }
    let zh_zeta = z_h(zeta, log_n);
    if proof.ood.quotient_at_zeta * zh_zeta != combined {
        return Err(P3qError::StarkVerification(
            "constraint identity at OOD point failed (trace violates a constraint)",
        ));
    }

    // ---- 4. FRI low-degree of the DEEP codeword ----
    let log_deep_degree = deep_degree_log_bound(log_n, log_blowup, air.constraint_degree());
    let shape = FriShape {
        log_degree_bound: log_deep_degree,
        log_blowup: log_lde - log_deep_degree,
        log_final_poly: pick_log_final_poly(log_deep_degree),
        num_queries: crate::prover_shared::NUM_QUERIES,
    };
    // The DEEP codeword root (FRI layer-0) is carried explicitly in the
    // proof, because the FRI engine treats layer-0's root as a value
    // supplied by the caller (it is not inside FriProofData). The prover
    // observed it into the transcript right before FRI; we replay that.
    let deep_root = proof.deep_root;
    transcript.observe_fri_root(&deep_root);
    let echoes = engine::verify(&proof.fri, &deep_root, shape, &mut transcript)?;

    // ---- 5. DEEP / OOD binding at every query ----
    if proof.query_columns.len() != echoes.len() {
        return Err(P3qError::StarkVerification(
            "query column count != FRI query count",
        ));
    }
    for (qc, echo) in proof.query_columns.iter().zip(echoes.iter()) {
        if qc.index != echo.index {
            return Err(P3qError::StarkVerification(
                "query column index != FRI echo index",
            ));
        }
        if qc.trace_value.len() != width || qc.trace_sibling.len() != width {
            return Err(P3qError::StarkVerification(
                "query column trace width mismatch",
            ));
        }
        // Authenticate the trace row + sibling row and the quotient
        // value + sibling against their committed roots.
        authenticate_query(qc, &proof.trace_root, &proof.quotient_root, n_lde, width)?;

        // Recompute DEEP codeword at the query index and its sibling,
        // then check they equal the FRI layer-0 echo values.
        let x = omega.pow(qc.index as u64);
        let deep_at_x = deep_value(
            &qc.trace_value,
            qc.quotient_value,
            &proof.ood.trace_at_zeta,
            &proof.ood.trace_at_g_zeta,
            proof.ood.quotient_at_zeta,
            zeta,
            g_zeta,
            &gammas,
            &gammas_shifted,
            gamma_q,
            x,
        )?;
        if deep_at_x != echo.value {
            return Err(P3qError::StarkVerification(
                "DEEP recomputation disagrees with FRI codeword (OOD binding broken)",
            ));
        }
        let sib_index = qc.index ^ (n_lde / 2);
        let x_sib = omega.pow(sib_index as u64);
        let deep_at_sib = deep_value(
            &qc.trace_sibling,
            qc.quotient_sibling,
            &proof.ood.trace_at_zeta,
            &proof.ood.trace_at_g_zeta,
            proof.ood.quotient_at_zeta,
            zeta,
            g_zeta,
            &gammas,
            &gammas_shifted,
            gamma_q,
            x_sib,
        )?;
        if deep_at_sib != echo.sibling {
            return Err(P3qError::StarkVerification(
                "DEEP recomputation (sibling) disagrees with FRI codeword",
            ));
        }
    }

    Ok(())
}

/// Verify boundary constraints by exact-point equality against the
/// authenticated trace rows.
fn verify_boundary<A: Air>(air: &A, proof: &AirProof, blowup: u32, width: usize) -> Result<()> {
    let bcs = air.boundary_constraints();
    if bcs.is_empty() {
        return Ok(());
    }
    // Index boundary openings by their LDE index for lookup.
    for opening in &proof.boundary_openings {
        if opening.row.len() != width {
            return Err(P3qError::StarkVerification(
                "boundary opening row width mismatch",
            ));
        }
        // Authenticate the row against the trace root (leaf = row bytes).
        let mut leaf = Vec::with_capacity(width * Goldilocks::BYTES);
        for v in &opening.row {
            leaf.extend_from_slice(&v.to_bytes());
        }
        verify_proof(
            &proof.trace_root,
            &leaf,
            opening.lde_index as usize,
            &opening.auth,
        )?;
    }
    // Every boundary constraint must be satisfied by a provided,
    // authenticated opening.
    for bc in &bcs {
        let lde_index = (bc.row as u32) * blowup;
        let opening = proof
            .boundary_openings
            .iter()
            .find(|o| o.lde_index == lde_index)
            .ok_or(P3qError::StarkVerification(
                "missing boundary opening for a declared boundary constraint",
            ))?;
        if bc.col >= width {
            return Err(P3qError::StarkVerification(
                "boundary constraint col out of range",
            ));
        }
        if opening.row[bc.col] != bc.value {
            return Err(P3qError::StarkVerification(
                "boundary constraint value mismatch",
            ));
        }
    }
    Ok(())
}

/// Authenticate one query's trace row, trace sibling row, quotient
/// value, and quotient sibling against the committed roots.
fn authenticate_query(
    qc: &QueryColumns,
    trace_root: &Digest,
    quotient_root: &Digest,
    n_lde: u32,
    width: usize,
) -> Result<()> {
    let sib = qc.index ^ (n_lde / 2);
    // Trace row leaf = concatenation of all column values at that row.
    let mut row_leaf = Vec::with_capacity(width * Goldilocks::BYTES);
    for v in &qc.trace_value {
        row_leaf.extend_from_slice(&v.to_bytes());
    }
    verify_proof(trace_root, &row_leaf, qc.index as usize, &qc.trace_auth)?;

    let mut sib_leaf = Vec::with_capacity(width * Goldilocks::BYTES);
    for v in &qc.trace_sibling {
        sib_leaf.extend_from_slice(&v.to_bytes());
    }
    verify_proof(trace_root, &sib_leaf, sib as usize, &qc.trace_sibling_auth)?;

    verify_proof(
        quotient_root,
        &qc.quotient_value.to_bytes(),
        qc.index as usize,
        &qc.quotient_auth,
    )?;
    verify_proof(
        quotient_root,
        &qc.quotient_sibling.to_bytes(),
        sib as usize,
        &qc.quotient_sibling_auth,
    )?;
    Ok(())
}

/// Recompute the DEEP codeword value at a single point `x` from the
/// (authenticated) trace + quotient values there and the OOD openings.
#[allow(clippy::too_many_arguments)]
fn deep_value(
    trace_at_x: &[Goldilocks],
    quotient_at_x: Goldilocks,
    trace_at_zeta: &[Goldilocks],
    trace_at_g_zeta: &[Goldilocks],
    quotient_at_zeta: Goldilocks,
    zeta: Goldilocks,
    g_zeta: Goldilocks,
    gammas: &[Goldilocks],
    gammas_shifted: &[Goldilocks],
    gamma_q: Goldilocks,
    x: Goldilocks,
) -> Result<Goldilocks> {
    let denom_zeta = (x - zeta).inverse().ok_or(P3qError::StarkVerification(
        "DEEP denom (x−ζ) zero at query",
    ))?;
    let denom_g_zeta = (x - g_zeta).inverse().ok_or(P3qError::StarkVerification(
        "DEEP denom (x−gζ) zero at query",
    ))?;
    let mut acc = Goldilocks::zero();
    for j in 0..trace_at_x.len() {
        acc = acc + gammas[j] * (trace_at_x[j] - trace_at_zeta[j]) * denom_zeta;
        acc = acc + gammas_shifted[j] * (trace_at_x[j] - trace_at_g_zeta[j]) * denom_g_zeta;
    }
    acc = acc + gamma_q * (quotient_at_x - quotient_at_zeta) * denom_zeta;
    Ok(acc)
}

/// Resample the OOD point until `ζ ∉ D` — identical to the prover.
fn sample_ood_not_in_domain(transcript: &mut StarkTranscript, log_lde: u32) -> Result<Goldilocks> {
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
