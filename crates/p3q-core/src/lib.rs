// P3Q core — protocol types, error model, and traits shared by every
// strict-PQ crate. No cryptography lives here; this crate is pure
// definitions so downstream crates depend on a single source of truth.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! P3Q core — protocol types and trait surface for the strict-PQ
//! Plonky3 fork. Downstream crates depend only on this one for
//! cross-cutting names (`ProofSystemId`, `P3qError`, `TranscriptLabel`).

pub mod error;
pub mod profile;
pub mod proof;
pub mod transcript;

pub use error::P3qError;
pub use profile::ProofSystemId;
pub use proof::ProofBytes;
pub use transcript::TranscriptLabel;

/// Result alias used across every P3Q crate. Verifier paths must return
/// `P3qError` rather than panic.
pub type Result<T> = core::result::Result<T, P3qError>;
