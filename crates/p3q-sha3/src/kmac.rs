//! KMAC256 — NIST SP 800-185 §4 keyed message authentication.
//!
//! ```text
//! KMAC256(K, X, L, S) =
//!   cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L),
//!             L, "KMAC", S)
//! ```
//!
//! The function-name `N = "KMAC"` is fixed by the standard; the
//! customisation `S` is caller-chosen. Block rate for cSHAKE256 is
//! 136 bytes (1088 bits).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

/// cSHAKE256 rate in bytes (NIST FIPS 202).
const CSHAKE256_RATE: usize = 136;

/// KMAC256 keyed hash with a per-call customisation string.
pub struct Kmac256 {
    inner: CShake256,
    out_len: usize,
}

impl Kmac256 {
    /// Create a new KMAC256 instance with key `K` and customisation `S`.
    ///
    /// `out_len` is the byte length to be squeezed at finalisation; it
    /// is absorbed at finalise per SP 800-185 §4.3.
    pub fn new(key: &[u8], customisation: &[u8], out_len: usize) -> Self {
        let core = CShake256Core::new_with_function_name(b"KMAC", customisation);
        let mut inner = CShake256::from_core(core);
        // bytepad(encode_string(K), 136)
        let padded = bytepad(&encode_string(key), CSHAKE256_RATE);
        inner.update(&padded);
        Self { inner, out_len }
    }

    /// Absorb message bytes.
    pub fn absorb(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    /// Finalise into a `Vec` of exactly the configured length.
    pub fn finalize_vec(mut self) -> Vec<u8> {
        let l_bits = self.out_len as u64 * 8;
        let trailer = right_encode(l_bits);
        self.inner.update(&trailer);
        let mut reader = self.inner.finalize_xof();
        let mut out = vec![0u8; self.out_len];
        reader.read(&mut out);
        out
    }
}

/// SP 800-185 `left_encode(x)`: minimal big-endian byte string of x,
/// prefixed by its byte length.
fn left_encode(x: u64) -> Vec<u8> {
    if x == 0 {
        return vec![1, 0];
    }
    let mut buf = x.to_be_bytes().to_vec();
    while buf.first() == Some(&0) {
        buf.remove(0);
    }
    let n = buf.len() as u8;
    let mut out = Vec::with_capacity(1 + buf.len());
    out.push(n);
    out.extend_from_slice(&buf);
    out
}

/// SP 800-185 `right_encode(x)`: minimal big-endian byte string of x,
/// suffixed by its byte length.
fn right_encode(x: u64) -> Vec<u8> {
    if x == 0 {
        return vec![0, 1];
    }
    let mut buf = x.to_be_bytes().to_vec();
    while buf.first() == Some(&0) {
        buf.remove(0);
    }
    let n = buf.len() as u8;
    buf.push(n);
    buf
}

/// SP 800-185 `encode_string(S)` = left_encode(len_in_bits(S)) || S.
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode((s.len() as u64) * 8);
    out.extend_from_slice(s);
    out
}

/// SP 800-185 `bytepad(X, w)`: left_encode(w) || X || zero-pad to a
/// multiple of `w` bytes.
fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let prefix = left_encode(w as u64);
    let mut out = Vec::with_capacity(prefix.len() + x.len() + w);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(x);
    let pad = w - (out.len() % w);
    if pad != w {
        out.extend(core::iter::repeat(0u8).take(pad));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_keys_diverge() {
        let mut a = Kmac256::new(b"key-A", b"S", 32);
        a.absorb(b"msg");
        let oa = a.finalize_vec();

        let mut b = Kmac256::new(b"key-B", b"S", 32);
        b.absorb(b"msg");
        let ob = b.finalize_vec();

        assert_ne!(oa, ob);
        assert_eq!(oa.len(), 32);
    }

    #[test]
    fn deterministic_for_same_key() {
        let mut a = Kmac256::new(b"k", b"s", 32);
        a.absorb(b"m");
        let oa = a.finalize_vec();

        let mut b = Kmac256::new(b"k", b"s", 32);
        b.absorb(b"m");
        let ob = b.finalize_vec();

        assert_eq!(oa, ob);
    }

    #[test]
    fn customisation_separates() {
        let mut a = Kmac256::new(b"k", b"S1", 32);
        a.absorb(b"m");
        let oa = a.finalize_vec();

        let mut b = Kmac256::new(b"k", b"S2", 32);
        b.absorb(b"m");
        let ob = b.finalize_vec();

        assert_ne!(oa, ob);
    }

    #[test]
    fn left_encode_examples() {
        assert_eq!(left_encode(0), vec![1, 0]);
        assert_eq!(left_encode(1), vec![1, 1]);
        assert_eq!(left_encode(256), vec![2, 1, 0]);
    }

    #[test]
    fn right_encode_examples() {
        assert_eq!(right_encode(0), vec![0, 1]);
        assert_eq!(right_encode(256), vec![1, 0, 2]);
    }

    #[test]
    fn bytepad_to_multiple_of_w() {
        let pad = bytepad(b"abc", 8);
        assert_eq!(pad.len() % 8, 0);
        // left_encode(8) = [1,8], plus "abc" = 5 bytes, pad to 8 → 3 zero bytes
        assert!(pad.starts_with(&[1, 8, b'a', b'b', b'c']));
    }
}
