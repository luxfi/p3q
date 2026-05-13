//! `produce_epoch_commitment` circuit.
//!
//! Folds the five preceding circuits into a single per-epoch
//! commitment posted to Z-Chain and referenced by Q-Chain (HIP-0079).

use p3q_core::Result;
use p3q_field::Goldilocks;
use p3q_stark::Air;

use crate::{not_yet_audit_gated, Epoch};

/// Public input + witness for the `produce_epoch_commitment` circuit.
#[derive(Debug, Clone)]
pub struct ProduceEpochCommitment {
    /// Epoch index this commitment is for.
    pub epoch: Epoch,
    /// Validator-set root at the end of this epoch.
    pub set_root: [u8; 32],
    /// Committee root selected for this epoch.
    pub committee_root: [u8; 32],
    /// DKG joint-pubkey commitment for this epoch.
    pub dkg_commitment: [u8; 32],
    /// Concatenated inner-proof bytes (registration / rotation /
    /// revocation / committee / DKG).
    pub inner_proofs: Vec<u8>,
    /// Final epoch commitment produced by the circuit.
    pub epoch_commitment: [u8; 32],
}

impl ProduceEpochCommitment {
    /// Construct the AIR. Body lands post-audit-gate.
    pub fn build_air(&self) -> Result<ProduceEpochCommitmentAir> {
        Err(not_yet_audit_gated("produce_epoch_commitment"))
    }
}

/// AIR for `produce_epoch_commitment`. This is a recursion circuit;
/// the body verifies each inner STARK proof inside its trace.
#[derive(Debug, Clone, Copy)]
pub struct ProduceEpochCommitmentAir;

impl Air<Goldilocks> for ProduceEpochCommitmentAir {
    fn width(&self) -> usize {
        24
    }
    fn num_rows(&self) -> usize {
        16384
    }
    fn num_constraints(&self) -> usize {
        48
    }
}
