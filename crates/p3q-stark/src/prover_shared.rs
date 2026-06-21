//! Pure helpers shared by the AIR prover and verifier.
//!
//! These compile unconditionally (NOT behind `feature = "prover"`)
//! because the verifier needs them too: it evaluates the AIR's `eval` at
//! the OOD point and computes the trace-domain vanishing polynomial. The
//! split keeps the *proving-only* machinery (DFTs, commitment, DEEP
//! codeword construction) in `prover.rs` while the algebra both sides
//! must agree on lives here, defined once.

use p3q_core::{P3qError, Result};
use p3q_field::{Field, Goldilocks};

use crate::air::{Air, AirBuilder};

/// Number of FRI queries for the AIR STARK. 64 queries over an LDE of
/// rate ≤ 1/8 gives ≥ 100-bit soundness for the FRI proximity gap;
/// matches the generic verifier's posture.
pub const NUM_QUERIES: usize = 64;

/// Concrete `Goldilocks` builder that evaluates an `Air`'s `eval` at a
/// single (local, next) row pair, accumulating the constraint values.
/// One builder, two callers: the prover's per-LDE-row evaluation and the
/// verifier's single OOD-point evaluation.
struct RowEvaluator<'a> {
    local: &'a [Goldilocks],
    next: &'a [Goldilocks],
    public: &'a [Goldilocks],
    out: Vec<Goldilocks>,
}

impl AirBuilder for RowEvaluator<'_> {
    type Expr = Goldilocks;
    fn width(&self) -> usize {
        self.local.len()
    }
    fn local(&self, col: usize) -> Goldilocks {
        self.local[col]
    }
    fn next(&self, col: usize) -> Goldilocks {
        self.next[col]
    }
    fn public_input(&self, idx: usize) -> Goldilocks {
        self.public[idx]
    }
    fn constant(&self, c: Goldilocks) -> Goldilocks {
        c
    }
    fn assert_zero(&mut self, expr: Goldilocks) {
        self.out.push(expr);
    }
}

/// Evaluate the AIR's constraints at one row pair, returning the
/// constraint vector (length = `air.num_constraints()`). Rejects an AIR
/// whose `eval` emits a different number of constraints than it
/// declares — that mismatch would desync the prover's and verifier's
/// random-linear combinations.
pub fn eval_constraints<A: Air>(
    air: &A,
    local: &[Goldilocks],
    next: &[Goldilocks],
    public: &[Goldilocks],
) -> Result<Vec<Goldilocks>> {
    let mut b = RowEvaluator {
        local,
        next,
        public,
        out: Vec::with_capacity(air.num_constraints()),
    };
    air.eval(&mut b);
    if b.out.len() != air.num_constraints() {
        return Err(P3qError::StarkVerification(
            "air eval emitted a different constraint count than num_constraints()",
        ));
    }
    Ok(b.out)
}

/// Vanishing polynomial of the trace domain `H` (order `2^log_n`):
/// `Z_H(x) = x^{2^log_n} − 1`, which vanishes exactly on `H`.
pub fn z_h(x: Goldilocks, log_n: u32) -> Goldilocks {
    x.pow(1u64 << log_n) - Goldilocks::one()
}

/// log2 of the LDE blowup, chosen by the prover and re-derived by the
/// verifier from `constraint_degree`. See [`crate::prover`] for the
/// rationale: `max(3, ceil(log2(d−1)) + 1)` where `d = constraint_degree`.
pub fn pick_log_blowup(constraint_degree: usize) -> u32 {
    let mult = constraint_degree.saturating_sub(1).max(1);
    let mut ceil_log = 0u32;
    while (1usize << ceil_log) < mult {
        ceil_log += 1;
    }
    (ceil_log + 1).max(3)
}

/// log2 of the DEEP codeword's degree bound (power-of-two rounded up).
/// The trace DEEP-quotients have degree `< num_rows − 1`; the quotient
/// `Q = C/Z_H` has degree `< (d−1)·num_rows` and its DEEP-quotient one
/// less. The DEEP codeword degree bound is therefore
/// `num_rows · 2^ceil(log2(d−1))`, i.e. `log_n + ceil(log2(d−1))`,
/// clamped below the LDE size.
pub fn deep_degree_log_bound(log_n: u32, log_blowup: u32, constraint_degree: usize) -> u32 {
    let mult = constraint_degree.saturating_sub(1).max(1);
    let mut extra = 0u32;
    while (1usize << extra) < mult {
        extra += 1;
    }
    (log_n + extra).min(log_n + log_blowup - 1).max(1)
}

/// Pick the final-poly log-size: fold down to a constant (`log 0`) when
/// the degree bound is ≤ 2, else to 2 coefficients (`log 1`). Must be
/// `< log_degree_bound`.
pub fn pick_log_final_poly(log_degree_bound: u32) -> u32 {
    if log_degree_bound <= 1 {
        0
    } else {
        1
    }
}
