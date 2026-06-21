//! `commit_dkg_output` circuit.
//!
//! Public inputs: committee root, DKG output commitment. Witness:
//! Pulsar-M (HIP-0084) DKG transcript proving consistency between
//! committee shares and the published joint pubkey commitment.

use p3q_core::Result;

use crate::{not_yet_audit_gated, Epoch};

/// Public input + witness for the `commit_dkg_output` circuit.
#[derive(Debug, Clone)]
pub struct CommitDkgOutput {
    /// Epoch.
    pub epoch: Epoch,
    /// Committee root for this epoch.
    pub committee_root: [u8; 32],
    /// Joint DKG output commitment.
    pub dkg_commitment: [u8; 32],
    /// Pulsar-M DKG transcript bytes (HIP-0084).
    pub transcript: Vec<u8>,
}

impl CommitDkgOutput {
    /// Construct the AIR. Body lands post-audit-gate.
    pub fn build_air(&self) -> Result<CommitDkgOutputAir> {
        Err(not_yet_audit_gated("commit_dkg_output"))
    }
}

/// AIR for `commit_dkg_output`. Typed placeholder only — no
/// [`Air`](p3q_stark::Air) implementation until the constraint system is
/// written and audited, so it cannot reach `prove_air`/`verify_air`.
/// `build_air` returns the audit-gate error.
#[derive(Debug, Clone, Copy)]
pub struct CommitDkgOutputAir;
