//! `rotate_identity_key` circuit.
//!
//! Public inputs: validator id, old pubkey commitment, new pubkey
//! commitment, rotation epoch. Witness: ML-DSA-65 signature with the
//! OLD key over (new_pubkey || epoch || domain_sep), plus Merkle
//! update path.

use p3q_core::Result;
use p3q_field::Goldilocks;
use p3q_stark::Air;

use crate::{Epoch, ValidatorId, not_yet_audit_gated};

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

/// AIR for `rotate_identity_key`.
#[derive(Debug, Clone, Copy)]
pub struct RotateIdentityKeyAir;

impl Air<Goldilocks> for RotateIdentityKeyAir {
    fn width(&self) -> usize {
        8
    }
    fn num_rows(&self) -> usize {
        1024
    }
    fn num_constraints(&self) -> usize {
        16
    }
}
