//! `register_validator` circuit.
//!
//! Public inputs: validator pubkey commitment, registration epoch,
//! validator-set root before and after. Witness: ML-DSA-65 signature
//! over (pubkey || epoch) and the Merkle insertion path.

use p3q_core::Result;
use p3q_field::Goldilocks;
use p3q_stark::Air;

use crate::{not_yet_audit_gated, Epoch, ValidatorId};

/// Public input + witness for the `register_validator` circuit.
#[derive(Debug, Clone)]
pub struct RegisterValidator {
    /// Validator pubkey commitment (cSHAKE256 of canonical ML-DSA-65 pk).
    pub validator: ValidatorId,
    /// Epoch in which registration occurs.
    pub epoch: Epoch,
    /// Validator-set Merkle root before insertion.
    pub set_root_pre: [u8; 32],
    /// Validator-set Merkle root after insertion.
    pub set_root_post: [u8; 32],
    /// ML-DSA-65 signature bytes over the canonical registration message.
    pub signature: Vec<u8>,
    /// Merkle insertion path bytes (leaf-to-root order).
    pub insertion_path: Vec<u8>,
}

impl RegisterValidator {
    /// Construct the AIR that enforces this circuit. The AIR body
    /// lands behind a feature flag once the v0.0.x audit gate passes;
    /// this entry point returns the typed circuit error so callers can
    /// surface a clean error instead of seeing a panic.
    pub fn build_air(&self) -> Result<RegisterValidatorAir> {
        Err(not_yet_audit_gated("register_validator"))
    }
}

/// AIR for `register_validator`. Body lands post-audit-gate.
#[derive(Debug, Clone, Copy)]
pub struct RegisterValidatorAir;

impl Air<Goldilocks> for RegisterValidatorAir {
    fn width(&self) -> usize {
        // 8 columns: pubkey words + signature accumulator + insertion lane.
        8
    }
    fn num_rows(&self) -> usize {
        // Power of two; signature recurrence + Merkle path verification.
        1024
    }
    fn num_constraints(&self) -> usize {
        16
    }
}
