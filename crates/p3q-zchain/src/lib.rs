// P3Q Z-Chain circuits. HIP-0078 epoch-proof AIRs:
//   - validator registration (ML-DSA-65 identity binding)
//   - identity-key rotation
//   - identity-key revocation
//   - epoch-committee selection (validator-set root + beacon)
//   - DKG output commitment (Pulsar-M HIP-0084 transcript)
//   - epoch-commitment production (folds all of the above)
//
// Downstream consumers (lux/consensus, lux/zchain) import the trait
// surface here and the verifier from p3q-verifier.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Z-Chain circuits. Each circuit is an AIR plus a witness type; the
//! prover-side body is implemented behind a feature flag in subsequent
//! v0.0.x releases. The public types here are the cross-crate import
//! surface for lux/consensus.

pub mod committee;
pub mod dkg;
pub mod epoch;
pub mod revocation;
pub mod registration;
pub mod rotation;

pub use committee::SelectEpochCommittee;
pub use dkg::CommitDkgOutput;
pub use epoch::ProduceEpochCommitment;
pub use registration::RegisterValidator;
pub use revocation::RevokeIdentityKey;
pub use rotation::RotateIdentityKey;

use p3q_core::P3qError;

/// Hash digest used to identify validators on Z-Chain (32 bytes,
/// produced by cSHAKE256 over the canonical pubkey encoding).
pub type ValidatorId = [u8; 32];

/// Z-Chain epoch index.
pub type Epoch = u64;

/// Shared error returned by every circuit's `build_air`.
fn not_yet_audit_gated(name: &'static str) -> P3qError {
    P3qError::Circuit(match name {
        "register_validator"        => "register_validator circuit body audit-gated",
        "rotate_identity_key"       => "rotate_identity_key circuit body audit-gated",
        "revoke_identity_key"       => "revoke_identity_key circuit body audit-gated",
        "select_epoch_committee"    => "select_epoch_committee circuit body audit-gated",
        "commit_dkg_output"         => "commit_dkg_output circuit body audit-gated",
        "produce_epoch_commitment"  => "produce_epoch_commitment circuit body audit-gated",
        _                           => "z-chain circuit body audit-gated",
    })
}
