//! TupleHash256 — NIST SP 800-185 §5 unambiguous multi-string hash.
//!
//! TupleHash256 encodes its inputs as a tuple so the concatenations
//! `("ab","c")` and `("a","bc")` produce different outputs.
//!
//! This crate implements TupleHash256 over `cSHAKE256` by absorbing
//! each input prefixed with the SP 800-185 `encode_string` framing.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core};

/// TupleHash256 hasher; absorb a sequence of byte strings then finalise.
pub struct TupleHash256 {
    inner: CShake256,
    out_len: usize,
}

impl TupleHash256 {
    /// Create a new TupleHash256 with customisation string `S` and output
    /// length `out_len` (in bytes). Per the standard, the function name
    /// is `"TupleHash"` and the output length is absorbed at finalise.
    pub fn new(customisation: &[u8], out_len: usize) -> Self {
        let core = CShake256Core::new_with_function_name(b"TupleHash", customisation);
        Self {
            inner: CShake256::from_core(core),
            out_len,
        }
    }

    /// Absorb a single tuple element with SP 800-185 `encode_string` framing.
    pub fn absorb(&mut self, item: &[u8]) {
        let prefix = encode_string_prefix(item.len() as u64 * 8);
        self.inner.update(&prefix);
        self.inner.update(item);
    }

    /// Finalise into a `Vec` of `out_len` bytes, absorbing the
    /// `right_encode(out_len * 8)` trailer per SP 800-185 §5.3.
    pub fn finalize_vec(mut self) -> Vec<u8> {
        let trailer = right_encode(self.out_len as u64 * 8);
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
/// We return just the prefix; the caller appends the string itself.
fn encode_string_prefix(len_bits: u64) -> Vec<u8> {
    left_encode(len_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuple_separation_property() {
        // ("ab","c") vs ("a","bc") must give different outputs.
        let mut a = TupleHash256::new(b"S", 32);
        a.absorb(b"ab");
        a.absorb(b"c");
        let oa = a.finalize_vec();

        let mut b = TupleHash256::new(b"S", 32);
        b.absorb(b"a");
        b.absorb(b"bc");
        let ob = b.finalize_vec();

        assert_ne!(oa, ob);
    }

    #[test]
    fn deterministic() {
        let mut a = TupleHash256::new(b"S", 32);
        a.absorb(b"x");
        let oa = a.finalize_vec();

        let mut b = TupleHash256::new(b"S", 32);
        b.absorb(b"x");
        let ob = b.finalize_vec();

        assert_eq!(oa, ob);
    }

    #[test]
    fn left_encode_zero() {
        assert_eq!(left_encode(0), vec![1, 0]);
    }

    #[test]
    fn left_encode_one() {
        assert_eq!(left_encode(1), vec![1, 1]);
    }

    #[test]
    fn left_encode_256() {
        assert_eq!(left_encode(256), vec![2, 1, 0]);
    }

    #[test]
    fn right_encode_zero() {
        assert_eq!(right_encode(0), vec![0, 1]);
    }

    #[test]
    fn right_encode_256() {
        assert_eq!(right_encode(256), vec![1, 0, 2]);
    }
}
