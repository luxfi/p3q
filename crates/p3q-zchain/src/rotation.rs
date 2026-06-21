//! `rotate_identity_key` circuit.
//!
//! Public inputs: validator id, old pubkey commitment, new pubkey
//! commitment, rotation epoch. Witness: ML-DSA-65 signature with the
//! OLD key over (new_pubkey || epoch || domain_sep), plus Merkle
//! update path.

use p3q_core::Result;
use p3q_stark::{Air, AirBuilder};

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

/// AIR for `rotate_identity_key`.
#[derive(Debug, Clone, Copy)]
pub struct RotateIdentityKeyAir;

impl Air for RotateIdentityKeyAir {
    fn width(&self) -> usize {
        8
    }
    fn num_rows(&self) -> usize {
        1024
    }
    fn num_public_inputs(&self) -> usize {
        // Public-input field-element count is finalized with the AIR body.
        0
    }
    fn num_constraints(&self) -> usize {
        16
    }
    fn eval<AB: AirBuilder>(&self, _builder: &mut AB) {
        // Audit-gated: the constraint system lands post-audit. `build_air`
        // refuses construction until then; `eval` must never silently impose
        // zero constraints (a fail-OPEN), so it fails loudly if reached.
        unimplemented!("z-chain circuit AIR is audit-gated; see build_air");
    }
}
