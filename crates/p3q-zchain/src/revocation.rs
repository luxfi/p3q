//! `revoke_identity_key` circuit.
//!
//! Public inputs: validator id, revocation epoch, set-root pre/post.
//! Witness: ML-DSA-65 self-signed revocation note OR governance
//! signature, plus Merkle removal path.

use p3q_core::Result;
use p3q_stark::{Air, AirBuilder};

use crate::{not_yet_audit_gated, Epoch, ValidatorId};

/// Public input + witness for the `revoke_identity_key` circuit.
#[derive(Debug, Clone)]
pub struct RevokeIdentityKey {
    /// Validator being revoked.
    pub validator: ValidatorId,
    /// Revocation epoch.
    pub epoch: Epoch,
    /// Validator-set Merkle root before removal.
    pub set_root_pre: [u8; 32],
    /// Validator-set Merkle root after removal.
    pub set_root_post: [u8; 32],
    /// Revocation signature (self-revoke OR governance-revoke).
    pub signature: Vec<u8>,
    /// Merkle removal path bytes.
    pub removal_path: Vec<u8>,
}

impl RevokeIdentityKey {
    /// Construct the AIR. Body lands post-audit-gate.
    pub fn build_air(&self) -> Result<RevokeIdentityKeyAir> {
        Err(not_yet_audit_gated("revoke_identity_key"))
    }
}

/// AIR for `revoke_identity_key`.
#[derive(Debug, Clone, Copy)]
pub struct RevokeIdentityKeyAir;

impl Air for RevokeIdentityKeyAir {
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
