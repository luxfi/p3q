//! `register_validator` circuit.
//!
//! Public inputs: validator pubkey commitment, registration epoch,
//! validator-set root before and after. Witness: ML-DSA-65 signature
//! over (pubkey || epoch) and the Merkle insertion path.

use p3q_core::Result;

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

/// AIR for `register_validator`. Typed placeholder only — it deliberately
/// carries **no** [`Air`](p3q_stark::Air) implementation until the
/// constraint system is written and audited, so it cannot be handed to
/// `prove_air`/`verify_air` (which require `A: Air`). `build_air` returns
/// the audit-gate error; this struct exists purely to name the eventual
/// circuit in the cross-crate type surface.
#[derive(Debug, Clone, Copy)]
pub struct RegisterValidatorAir;
