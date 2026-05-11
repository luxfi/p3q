//! `select_epoch_committee` circuit.
//!
//! Public inputs: validator-set root, epoch beacon, committee size,
//! claimed committee root. Witness: VRF outputs and the Merkle paths
//! for each selected validator.

use p3q_core::Result;
use p3q_field::Goldilocks;
use p3q_stark::Air;

use crate::{Epoch, not_yet_audit_gated};

/// Public input + witness for the `select_epoch_committee` circuit.
#[derive(Debug, Clone)]
pub struct SelectEpochCommittee {
    /// Epoch.
    pub epoch: Epoch,
    /// Validator-set Merkle root.
    pub set_root: [u8; 32],
    /// Epoch randomness beacon.
    pub beacon: [u8; 32],
    /// Committee size N (e.g. 64).
    pub committee_size: u32,
    /// Resulting committee Merkle root.
    pub committee_root: [u8; 32],
    /// Per-member VRF outputs and Merkle paths, concatenated.
    pub selection_witness: Vec<u8>,
}

impl SelectEpochCommittee {
    /// Construct the AIR. Body lands post-audit-gate.
    pub fn build_air(&self) -> Result<SelectEpochCommitteeAir> {
        Err(not_yet_audit_gated("select_epoch_committee"))
    }
}

/// AIR for `select_epoch_committee`.
#[derive(Debug, Clone, Copy)]
pub struct SelectEpochCommitteeAir;

impl Air<Goldilocks> for SelectEpochCommitteeAir {
    fn width(&self) -> usize {
        12
    }
    fn num_rows(&self) -> usize {
        4096
    }
    fn num_constraints(&self) -> usize {
        24
    }
}
