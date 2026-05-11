// P3Q recursion. STARK-native only: no elliptic-curve wrappers, no
// pairing-based finalisers, no Groth16. Recursion is implemented as a
// STARK that verifies another STARK.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Recursion trait surface. A `RecursiveCircuit` consumes one or more
//! inner `StarkProof`s and emits a single outer proof that attests
//! their joint validity.

use p3q_core::Result;
use p3q_field::Field;
use p3q_stark::StarkProof;

/// A recursion circuit. Implementations verify a fixed-arity tuple of
/// inner STARK proofs inside an AIR; the outer proof is itself a
/// `StarkProof` produced by a regular STARK prover.
pub trait RecursiveCircuit<F: Field>: Send + Sync {
    /// Number of inner proofs this circuit composes.
    fn arity(&self) -> usize;

    /// Verify the recursion circuit's claim about the inner proofs.
    /// MUST be panic-free.
    fn verify_inner(&self, inner_proofs: &[StarkProof]) -> Result<()>;
}

/// A recursion folding parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoldParams {
    /// Number of proofs folded per outer round.
    pub fan_in: u32,
    /// Maximum recursion depth allowed by this circuit.
    pub max_depth: u32,
}

impl FoldParams {
    /// Production default: binary folding, depth 8.
    pub const DEFAULT: Self = Self {
        fan_in: 2,
        max_depth: 8,
    };
}
