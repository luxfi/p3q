//! `revoke_identity_key` circuit.
//!
//! Public inputs: validator id, revocation epoch, set-root pre/post.
//! Witness: ML-DSA-65 self-signed revocation note OR governance
//! signature, plus Merkle removal path.

use p3q_core::Result;

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

/// AIR for `revoke_identity_key`. Typed placeholder only — no
/// [`Air`](p3q_stark::Air) implementation until the constraint system is
/// written and audited, so it cannot reach `prove_air`/`verify_air`.
/// `build_air` returns the audit-gate error.
#[derive(Debug, Clone, Copy)]
pub struct RevokeIdentityKeyAir;
