//! `select_epoch_committee` circuit.
//!
//! Public inputs: validator-set root, epoch beacon, committee size,
//! claimed committee root. Witness: VRF outputs and the Merkle paths
//! for each selected validator.

use p3q_core::Result;
use p3q_stark::{Air, AirBuilder};

use crate::{not_yet_audit_gated, Epoch};

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

impl Air for SelectEpochCommitteeAir {
    fn width(&self) -> usize {
        12
    }
    fn num_rows(&self) -> usize {
        4096
    }
    fn num_public_inputs(&self) -> usize {
        // Public-input field-element count is finalized with the AIR body.
        0
    }
    fn num_constraints(&self) -> usize {
        24
    }
    fn eval<AB: AirBuilder>(&self, _builder: &mut AB) {
        // Audit-gated: the constraint system lands post-audit. `build_air`
        // refuses construction until then; `eval` must never silently impose
        // zero constraints (a fail-OPEN), so it fails loudly if reached.
        unimplemented!("z-chain circuit AIR is audit-gated; see build_air");
    }
}
