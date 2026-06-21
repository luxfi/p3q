// P3Q STARK arithmetisation. Defines the AIR constraint surface, the
// AIR DEEP-STARK proof envelope, and the prover/verifier that turn an
// `Air` + execution trace into a low-degree FRI proof of constraint
// satisfaction.
//
// Decomplected (Hickey):
//   - `air`      : what a circuit's constraints ARE (pure algebra).
//   - `prover`   : how to PRODUCE a proof (commit, compose, quotient,
//                  DEEP, FRI). Behind `feature = "prover"` so the
//                  audited verifier never links proving codepaths.
//   - `verifier` : how to CHECK a proof (FRI low-degree + OOD/DEEP
//                  binding + boundary checks). Panic-free.
//   - `proof`    : the wire envelope shared by both.
// The FRI fold math + low-degree engine live once in `p3q-fri`; this
// crate composes them. No KZG, no pairings — Goldilocks + SHA-3 only.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! AIR constraint surface + DEEP-ALI STARK over the strict-PQ
//! Goldilocks / cSHAKE256 / FRI stack.

pub mod air;
pub mod proof;
pub mod prover_shared;
pub mod transcript;
pub mod verifier;

#[cfg(any(test, feature = "prover"))]
pub mod prover;

pub use air::{Air, AirBuilder, BoundaryConstraint};
pub use proof::{AirProof, OodOpenings};
pub use verifier::verify_air;

#[cfg(any(test, feature = "prover"))]
pub use prover::{prove_air, Trace};

use p3q_core::Result;
use p3q_field::Goldilocks;
use p3q_fri::FriProof;

/// A STARK proof: trace-commit root, FRI low-degree proof, and the
/// out-of-domain openings the verifier needs.
///
/// Retained as the abstract envelope name used across the Lux stack.
/// The concrete strict-PQ realisation is [`AirProof`] (this struct is
/// the legacy abstract shape; new code uses [`AirProof`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkProof {
    /// Commitment to the execution-trace polynomial in canonical form.
    pub trace_root: [u8; 32],
    /// FRI sub-proof.
    pub fri: FriProof,
    /// Out-of-domain quotient openings.
    pub ood_openings: Vec<Vec<u8>>,
}

/// STARK prover trait. Bodies live behind feature flags so the
/// audit-gate verifier crate never compiles this trait's
/// implementations.
pub trait Prover<A: Air> {
    /// Produce a STARK proof for the given AIR and trace.
    fn prove(&self, air: &A, trace: &[Goldilocks]) -> Result<AirProof>;
}

/// STARK verifier trait. MUST be panic-free.
pub trait Verifier<A: Air> {
    /// Verify a STARK proof.
    fn verify(&self, air: &A, proof: &AirProof, public_inputs: &[Goldilocks]) -> Result<()>;
}
