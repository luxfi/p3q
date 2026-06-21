//! `rotate_identity_key` circuit.
//!
//! Public inputs: validator id, old pubkey commitment, new pubkey
//! commitment, rotation epoch. Witness: ML-DSA-65 signature with the
//! OLD key over (new_pubkey || epoch || domain_sep), plus Merkle
//! update path.

use p3q_core::Result;

use crate::{not_yet_audit_gated, Epoch, ValidatorId};

/// Public input + witness for the `rotate_identity_key` circuit.
#[derive(Debug, Clone)]
pub struct RotateIdentityKey {
    /// Validator whose key is being rotated.
    pub validator: ValidatorId,
    /// Old pubkey commitment (must equal the current set entry).
    pub old_pubkey: [u8; 32],
    /// New pubkey commitment.
    pub new_pubkey: [u8; 32],
    /// Epoch in which rotation occurs.
    pub epoch: Epoch,
    /// ML-DSA-65 signature by the old key over the rotation message.
    pub signature: Vec<u8>,
    /// Merkle update path bytes.
    pub update_path: Vec<u8>,
}

impl RotateIdentityKey {
    /// Construct the AIR. Body lands post-audit-gate.
    pub fn build_air(&self) -> Result<RotateIdentityKeyAir> {
        Err(not_yet_audit_gated("rotate_identity_key"))
    }
}

/// AIR for `rotate_identity_key`. Typed placeholder only — no
/// [`Air`](p3q_stark::Air) implementation until the constraint system is
/// written and audited, so it cannot reach `prove_air`/`verify_air`.
/// `build_air` returns the audit-gate error.
#[derive(Debug, Clone, Copy)]
pub struct RotateIdentityKeyAir;
