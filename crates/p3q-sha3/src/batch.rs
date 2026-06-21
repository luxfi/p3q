//! Batched cSHAKE256 / TupleHash256 / KMAC256 over a [`Sha3Backend`].
//!
//! Each function builds the SP 800-185 framing on the CPU (the framing
//! is short and audit-locked) then dispatches the actual sponge work to
//! the configured backend via `cshake256_batch`. The backend may
//! parallelise across inputs (a future GPU cSHAKE batch) or process
//! them serially (CPU). Outputs are byte-identical either way.
//!
//! These batched functions are the canonical entry points used by
//! `p3q-merkle` and `p3q-verifier` when they have N independent hashes
//! to compute — fan-out happens here, not at the call sites.

use crate::backend::Sha3Backend;

/// cSHAKE256 rate in bytes (FIPS 202).
const CSHAKE256_RATE: usize = 136;

/// One batched cSHAKE256 input: customisation string + payload + per-
/// input squeeze length. The function-name `N` is fixed per call to
/// `cshake256_batch_fn` (typical use is `N = b""`).
#[derive(Debug, Clone)]
pub struct CShakeInput<'a> {
    /// SP 800-185 customisation string `S` (per-input).
    pub customisation: &'a [u8],
    /// Input payload `X` to absorb after the framing.
    pub payload: &'a [u8],
    /// Number of output bytes to squeeze.
    pub out_len: usize,
}

/// Compute cSHAKE256(payload, out_len, name=`name`, customisation=`S_i`)
/// for each input in `inputs`. Routes through the backend's native
/// `cshake256_batch` primitive (default CPU; potentially GPU when a
/// future libluxgpu exposes cSHAKE batch).
pub fn cshake256_batch(
    backend: &dyn Sha3Backend,
    name: &[u8],
    inputs: &[CShakeInput<'_>],
) -> Vec<Vec<u8>> {
    let customisations: Vec<&[u8]> = inputs.iter().map(|i| i.customisation).collect();
    let payloads: Vec<&[u8]> = inputs.iter().map(|i| i.payload).collect();
    let out_lens: Vec<usize> = inputs.iter().map(|i| i.out_len).collect();
    backend.cshake256_batch(name, &customisations, &payloads, &out_lens)
}

/// One batched TupleHash256 input.
#[derive(Debug, Clone)]
pub struct TupleInput<'a> {
    /// SP 800-185 customisation `S` (per-input).
    pub customisation: &'a [u8],
    /// Ordered tuple of byte strings to absorb with `encode_string` framing.
    pub items: &'a [&'a [u8]],
    /// Number of output bytes to squeeze.
    pub out_len: usize,
}

/// Compute TupleHash256 (SP 800-185 §5) for each input in `inputs`.
/// Returns one Vec per input. The function-name is fixed to `"TupleHash"`
/// per the standard. Dispatches through
/// [`Sha3Backend::tuple_hash256_batch`] — CPU streams items directly
/// into the stateful hasher; future GPU backends may override with a
/// native batch primitive.
pub fn tuple_hash256_batch(backend: &dyn Sha3Backend, inputs: &[TupleInput<'_>]) -> Vec<Vec<u8>> {
    let customisations: Vec<&[u8]> = inputs.iter().map(|i| i.customisation).collect();
    let items: Vec<&[&[u8]]> = inputs.iter().map(|i| i.items).collect();
    let out_lens: Vec<usize> = inputs.iter().map(|i| i.out_len).collect();
    backend.tuple_hash256_batch(&customisations, &items, &out_lens)
}

/// One batched KMAC256 input.
#[derive(Debug, Clone)]
pub struct KmacInput<'a> {
    /// MAC key `K` (per-input).
    pub key: &'a [u8],
    /// SP 800-185 customisation `S` (per-input).
    pub customisation: &'a [u8],
    /// Message payload `X` to absorb after the keyed prefix.
    pub message: &'a [u8],
    /// Number of output bytes to squeeze.
    pub out_len: usize,
}

/// Compute KMAC256 (SP 800-185 §4) for each input in `inputs`. Returns
/// one Vec per input. The function-name is fixed to `"KMAC"` per the
/// standard.
///
/// Implementation: KMAC256(K, X, L, S) = cSHAKE256(
///   bytepad(encode_string(K), 136) || X || right_encode(L),
///   L, "KMAC", S)
pub fn kmac256_batch(backend: &dyn Sha3Backend, inputs: &[KmacInput<'_>]) -> Vec<Vec<u8>> {
    let payloads: Vec<Vec<u8>> = inputs
        .iter()
        .map(|inp| {
            let mut buf = Vec::new();
            buf.extend_from_slice(&bytepad(&encode_string(inp.key), CSHAKE256_RATE));
            buf.extend_from_slice(inp.message);
            buf.extend_from_slice(&right_encode((inp.out_len as u64) * 8));
            buf
        })
        .collect();
    let payload_refs: Vec<&[u8]> = payloads.iter().map(|v| v.as_slice()).collect();
    let customisations: Vec<&[u8]> = inputs.iter().map(|i| i.customisation).collect();
    let out_lens: Vec<usize> = inputs.iter().map(|i| i.out_len).collect();
    backend.cshake256_batch(b"KMAC", &customisations, &payload_refs, &out_lens)
}

// ---- SP 800-185 framing — audit-locked, used by all three builders ----

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

/// SP 800-185 `encode_string(S)` = `left_encode(len_bits(S)) || S`.
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode((s.len() as u64) * 8);
    out.extend_from_slice(s);
    out
}

/// SP 800-185 `bytepad(X, w)` = `left_encode(w) || X || zero-pad to
/// multiple of w bytes`.
fn bytepad(x: &[u8], w: usize) -> Vec<u8> {
    let prefix = left_encode(w as u64);
    let mut out = Vec::with_capacity(prefix.len() + x.len() + w);
    out.extend_from_slice(&prefix);
    out.extend_from_slice(x);
    let pad = w - (out.len() % w);
    if pad != w {
        out.resize(out.len() + pad, 0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::CpuShake;
    use crate::{CShake256, Kmac256, TupleHash256};

    /// `cshake256_batch` must produce byte-identical output to the
    /// stateful `CShake256` wrapper for the same `(name, customisation,
    /// payload, out_len)`.
    #[test]
    fn cshake_batch_matches_stateful() {
        let backend = CpuShake;
        let inputs = vec![
            CShakeInput {
                customisation: b"p3q-S1",
                payload: b"hello world",
                out_len: 32,
            },
            CShakeInput {
                customisation: b"",
                payload: b"abc",
                out_len: 64,
            },
            CShakeInput {
                customisation: b"p3q-S2",
                payload: b"",
                out_len: 16,
            },
        ];
        let batched = cshake256_batch(&backend, b"", &inputs);
        for (i, inp) in inputs.iter().enumerate() {
            let mut h = CShake256::new(b"", inp.customisation);
            h.absorb(inp.payload);
            let expected = h.finalize_vec(inp.out_len);
            assert_eq!(batched[i], expected, "input {i} mismatch");
        }
    }

    /// `tuple_hash256_batch` must produce byte-identical output to the
    /// stateful `TupleHash256` wrapper.
    #[test]
    fn tuple_batch_matches_stateful() {
        let backend = CpuShake;
        let inputs = vec![
            TupleInput {
                customisation: b"p3q-tuple-A",
                items: &[b"alpha", b"beta"],
                out_len: 32,
            },
            TupleInput {
                customisation: b"",
                items: &[b"x", b"yz", b"abc"],
                out_len: 32,
            },
        ];
        let batched = tuple_hash256_batch(&backend, &inputs);
        for (i, inp) in inputs.iter().enumerate() {
            let mut h = TupleHash256::new(inp.customisation, inp.out_len);
            for item in inp.items {
                h.absorb(item);
            }
            let expected = h.finalize_vec();
            assert_eq!(batched[i], expected, "input {i} mismatch");
        }
    }

    /// `kmac256_batch` must produce byte-identical output to the
    /// stateful `Kmac256` wrapper.
    #[test]
    fn kmac_batch_matches_stateful() {
        let backend = CpuShake;
        let inputs = vec![
            KmacInput {
                key: b"k1",
                customisation: b"S1",
                message: b"m1",
                out_len: 32,
            },
            KmacInput {
                key: b"key-with-medium-length",
                customisation: b"",
                message: b"the quick brown fox jumps over the lazy dog",
                out_len: 32,
            },
        ];
        let batched = kmac256_batch(&backend, &inputs);
        for (i, inp) in inputs.iter().enumerate() {
            let mut h = Kmac256::new(inp.key, inp.customisation, inp.out_len);
            h.absorb(inp.message);
            let expected = h.finalize_vec();
            assert_eq!(batched[i], expected, "input {i} mismatch");
        }
    }
}
