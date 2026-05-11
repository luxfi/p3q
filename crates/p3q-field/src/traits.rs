//! The `Field` trait. Minimum surface needed by FRI / Merkle / STARK
//! callers: addition, multiplication, inversion, zero / one, byte
//! serialization. Concrete fields (Goldilocks, binary extensions) live
//! in their own modules.

use core::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};

use p3q_core::P3qError;

/// A prime field used by P3Q. Implementations are required to be:
///
/// - constant-time on secret-derived inputs (verifier path),
/// - canonical: `to_bytes` followed by `from_bytes` round-trips, and
/// - reject non-canonical encodings of the same element.
pub trait Field:
    Copy
    + Clone
    + Debug
    + Default
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Send
    + Sync
{
    /// Byte width of the canonical encoding.
    const BYTES: usize;

    /// Additive identity.
    fn zero() -> Self;

    /// Multiplicative identity.
    fn one() -> Self;

    /// Multiplicative inverse. Returns `None` for zero.
    fn inverse(&self) -> Option<Self>;

    /// Square (one multiplication, no extra allocation in the common
    /// case; provided for clarity).
    fn square(&self) -> Self {
        *self * *self
    }

    /// Canonical little-endian encoding into a fixed-size byte buffer.
    fn to_bytes(&self) -> Vec<u8>;

    /// Decode a canonical little-endian byte string. Returns
    /// `P3qError::InvalidEncoding` for the wrong length and
    /// `P3qError::FieldOutOfRange` for an in-range-but-non-canonical
    /// representation.
    fn from_bytes(bytes: &[u8]) -> Result<Self, P3qError>;
}
