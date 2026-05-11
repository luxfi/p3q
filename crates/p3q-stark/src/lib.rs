// P3Q STARK arithmetisation. Defines AIR-style trace and constraint
// traits. No prover bodies here — those live behind a feature flag in
// downstream crates so the audited verifier crate never depends on
// proving-time codepaths.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! AIR trait surface plus the canonical `StarkProof` envelope.

use p3q_core::Result;
use p3q_field::Field;
use p3q_fri::FriProof;

/// An algebraic-intermediate-representation circuit. Concrete circuits
/// (e.g. Z-Chain epoch-transition) implement this trait.
pub trait Air<F: Field>: Send + Sync {
    /// Width of the execution trace (number of columns).
    fn width(&self) -> usize;

    /// Required number of trace rows; must be a power of two.
    fn num_rows(&self) -> usize;

    /// Number of independent constraint polynomials.
    fn num_constraints(&self) -> usize;
}

/// A STARK proof: trace-commit root, FRI low-degree proof, and the
/// out-of-domain openings the verifier needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkProof {
    /// Commitment to the execution-trace polynomial in canonical form.
    pub trace_root: [u8; 32],
    /// FRI sub-proof.
    pub fri: FriProof,
    /// Out-of-domain quotient openings.
    pub ood_openings: Vec<Vec<u8>>,
}

/// STARK prover. Bodies live in downstream crates behind feature flags;
/// the audit-gate verifier crate never compiles this trait's
/// implementations.
pub trait Prover<F: Field, A: Air<F>> {
    /// Produce a STARK proof for the given AIR and trace.
    fn prove(&self, air: &A, trace: &[F]) -> Result<StarkProof>;
}

/// STARK verifier. MUST be panic-free.
pub trait Verifier<F: Field, A: Air<F>> {
    /// Verify a STARK proof.
    fn verify(&self, air: &A, proof: &StarkProof) -> Result<()>;
}
