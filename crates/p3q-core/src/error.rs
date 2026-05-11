//! Typed errors shared across every P3Q crate. The verifier path is
//! required to be panic-free; all failure modes flow through this enum.

use thiserror::Error;

/// Errors raised by any P3Q crate. The verifier path is required to map
/// every fault (length, decoding, arithmetic, transcript, Merkle, FRI)
/// onto exactly one of these variants and return — never panic.
#[derive(Debug, Error)]
pub enum P3qError {
    /// A length, offset, or count constraint was violated by the input.
    #[error("invalid input length: {0}")]
    InvalidLength(&'static str),

    /// A byte sequence did not decode into a well-formed protocol object.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),

    /// A Merkle authentication path did not reproduce the committed root.
    #[error("merkle authentication failed")]
    MerkleAuth,

    /// A FRI low-degree check rejected the queried codeword.
    #[error("fri verification failed: {0}")]
    FriVerification(&'static str),

    /// A STARK constraint or trace check rejected the proof.
    #[error("stark verification failed: {0}")]
    StarkVerification(&'static str),

    /// The Fiat-Shamir transcript was advanced inconsistently.
    #[error("transcript mismatch: {0}")]
    Transcript(&'static str),

    /// The advertised proof-system identifier does not match the verifier
    /// profile.
    #[error("unsupported proof-system id: 0x{0:02x}")]
    UnsupportedProfile(u8),

    /// An algebraic operation produced a value outside the field
    /// (typically from user input not yet reduced modulo p).
    #[error("field element out of range")]
    FieldOutOfRange,

    /// A Z-Chain circuit asserted a domain-specific invariant that did
    /// not hold (validator pubkey malformed, committee size wrong, etc).
    #[error("z-chain circuit invariant: {0}")]
    Circuit(&'static str),
}
