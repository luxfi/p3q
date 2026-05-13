//! `commit_dkg_output` circuit.
//!
//! Public inputs: committee root, DKG output commitment. Witness:
//! Pulsar-M (HIP-0084) DKG transcript proving consistency between
//! committee shares and the published joint pubkey commitment.

use p3q_core::Result;
use p3q_field::Goldilocks;
use p3q_stark::Air;

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

/// AIR for `commit_dkg_output`.
#[derive(Debug, Clone, Copy)]
pub struct CommitDkgOutputAir;

impl Air<Goldilocks> for CommitDkgOutputAir {
    fn width(&self) -> usize {
        16
    }
    fn num_rows(&self) -> usize {
        4096
    }
    fn num_constraints(&self) -> usize {
        32
    }
}
