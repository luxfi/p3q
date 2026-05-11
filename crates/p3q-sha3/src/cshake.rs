//! cSHAKE256 — NIST SP 800-185 §3 customisable SHAKE.
//!
//! cSHAKE256(X, L, N, S) where:
//! - N = function-name string (left empty for plain SHAKE)
//! - S = customisation string (domain separation)
//! - L = output bit length
//!
//! When both N and S are empty, cSHAKE256 must reduce to SHAKE256 per
//! the standard. Domain encoding follows SP 800-185 §2.3.3.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256 as RawCShake256, CShake256Core};

/// cSHAKE256 hasher. Construct with a domain-separation `(name, customisation)`
/// pair; absorb bytes; finalize to a fixed or extendable output.
pub struct CShake256 {
    inner: RawCShake256,
}

impl CShake256 {
    /// Create a new cSHAKE256 instance.
    ///
    /// `name` (`N`) is the NIST-allocated function-name string. For most
    /// P3Q transcripts pass `b""`. `customisation` (`S`) is the
    /// per-call domain-separator chosen by the caller.
    pub fn new(name: &[u8], customisation: &[u8]) -> Self {
        let core = CShake256Core::new_with_function_name(name, customisation);
        Self {
            inner: RawCShake256::from_core(core),
        }
    }

    /// Absorb additional bytes into the sponge.
    pub fn absorb(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// Squeeze exactly `OUT` bytes of output and discard the hasher.
    pub fn finalize_array<const OUT: usize>(self) -> [u8; OUT] {
        let mut reader = self.inner.finalize_xof();
        let mut out = [0u8; OUT];
        reader.read(&mut out);
        out
    }

    /// Squeeze the configured `out_len` bytes into a fresh `Vec`.
    pub fn finalize_vec(self, out_len: usize) -> Vec<u8> {
        let mut reader = self.inner.finalize_xof();
        let mut out = vec![0u8; out_len];
        reader.read(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_customisation_distinct_output() {
        let mut a = CShake256::new(b"", b"p3q-domain-A");
        a.absorb(b"same input");
        let oa: [u8; 32] = a.finalize_array();

        let mut b = CShake256::new(b"", b"p3q-domain-B");
        b.absorb(b"same input");
        let ob: [u8; 32] = b.finalize_array();

        assert_ne!(oa, ob, "different customisation must give different output");
    }

    #[test]
    fn deterministic() {
        let mut a = CShake256::new(b"", b"S");
        a.absorb(b"x");
        let oa: [u8; 32] = a.finalize_array();

        let mut b = CShake256::new(b"", b"S");
        b.absorb(b"x");
        let ob: [u8; 32] = b.finalize_array();

        assert_eq!(oa, ob);
    }

    #[test]
    fn variable_output_length() {
        let mut h = CShake256::new(b"", b"len");
        h.absorb(b"x");
        let v = h.finalize_vec(64);
        assert_eq!(v.len(), 64);
    }
}
