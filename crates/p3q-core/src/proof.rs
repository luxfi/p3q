//! Wire-level proof bytes. P3Q intentionally does not expose a typed
//! Proof struct at this layer; the verifier consumes a length-prefixed
//! byte string and parses it under its own profile.

/// Opaque wire-level proof bytes. The first byte is the
/// [`crate::ProofSystemId`]; the remainder is profile-defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBytes(Vec<u8>);

impl ProofBytes {
    /// Wrap a byte vector as a proof.
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consume into the underlying bytes.
    #[inline]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Total proof length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the proof has zero bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for ProofBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
