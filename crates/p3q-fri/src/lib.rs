// P3Q FRI low-degree test. Strict-PQ profile: hash family is FIPS 202
// only (cSHAKE256 / KMAC256 / TupleHash256). No Poseidon, no BLAKE3.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! FRI commit-phase and query-phase trait surface. Concrete provers
//! and verifiers live behind these traits so the audit team reviews
//! one definition of "what FRI accepts".

use p3q_core::{P3qError, Result};
use p3q_field::Field;

/// FRI parameters: blowup factor, folding arity, number of queries,
/// final-polynomial degree bound. These are profile constants set at
/// circuit-build time; verifier reads them from the proof header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FriParams {
    /// log2 of evaluation-domain blowup factor.
    pub log_blowup: u32,
    /// log2 of folding arity per round.
    pub log_arity: u32,
    /// Number of random queries.
    pub num_queries: u32,
    /// log2 of the final-polynomial size accepted by the verifier.
    pub log_final_poly: u32,
}

impl FriParams {
    /// Reasonable default: blowup 8, arity 2, 64 queries, final poly
    /// degree bound 32.
    pub const DEFAULT: Self = Self {
        log_blowup: 3,
        log_arity: 1,
        num_queries: 64,
        log_final_poly: 5,
    };

    /// Validate parameter ranges; returns `P3qError::FriVerification`
    /// if any field is outside the audited bounds.
    pub fn validate(&self) -> Result<()> {
        if self.log_blowup == 0 || self.log_blowup > 5 {
            return Err(P3qError::FriVerification("log_blowup out of range"));
        }
        if self.log_arity == 0 || self.log_arity > 3 {
            return Err(P3qError::FriVerification("log_arity out of range"));
        }
        if self.num_queries == 0 || self.num_queries > 256 {
            return Err(P3qError::FriVerification("num_queries out of range"));
        }
        if self.log_final_poly > 10 {
            return Err(P3qError::FriVerification("log_final_poly out of range"));
        }
        Ok(())
    }
}

/// A FRI proof — opaque to consumers; the verifier knows how to walk
/// it under its profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FriProof {
    /// Commit-phase Merkle roots, one per fold.
    pub commit_roots: Vec<[u8; 32]>,
    /// Query openings.
    pub openings: Vec<Vec<u8>>,
    /// Final polynomial in coefficient form.
    pub final_poly: Vec<u8>,
}

/// FRI prover trait. Concrete implementations live behind feature
/// flags so the production verifier crate doesn't pull in any of the
/// proving-time codepath.
pub trait FriProver<F: Field> {
    /// Produce a FRI proof of low-degreeness for the given codeword.
    fn prove(&self, codeword: &[F], params: &FriParams) -> Result<FriProof>;
}

/// FRI verifier trait. Verifier paths MUST be panic-free.
pub trait FriVerifier<F: Field> {
    /// Verify a FRI proof for the given codeword commitment root.
    fn verify(
        &self,
        commit_root: &[u8; 32],
        proof: &FriProof,
        params: &FriParams,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_params_validate() {
        FriParams::DEFAULT.validate().expect("default must validate");
    }

    #[test]
    fn zero_queries_rejected() {
        let mut p = FriParams::DEFAULT;
        p.num_queries = 0;
        assert!(p.validate().is_err());
    }
}
