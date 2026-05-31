//! Pluggable FIPS 202 / SP 800-185 hash backend.
//!
//! The trait is the boundary between *what* the audited primitives need
//! (`sha3_256_batch`, `shake256_batch`, `cshake256_batch`) and *who*
//! computes them (CPU or GPU). cSHAKE256 / KMAC256 / TupleHash256 are
//! built on top of `cshake256_batch` via the SP 800-185 framing in
//! [`crate::batch`].
//!
//! Decoupling design (per Hickey): the trait speaks only at the level
//! of "give me a batch of independent FIPS 202 / SP 800-185 sponge
//! results". The implementation is free to parallelise across inputs
//! (GPU) or compute them serially (CPU). The default impl of
//! `cshake256_batch` is provided — the GPU backend may override when
//! a future libluxgpu adds a cSHAKE batch primitive.
//!
//! Constant-time: every backend MUST be data-oblivious in the same way
//! the CPU `sha3` crate is. The verifier never feeds secret data
//! through these primitives anyway (everything is public proof
//! material), but the property is preserved on principle.

use crate::TupleHash256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake256, CShake256Core, Digest as _, Sha3_256, Shake256};
use std::sync::Arc;

// `sha3::Digest` and `sha3::digest::Update` both expose `update`, so we
// disambiguate explicitly at the call sites in `CpuShake`.

/// FIPS 202 SHA3-256 / SHAKE256 / cSHAKE256 batch primitives.
///
/// - `sha3_256_batch` — fixed 32-byte SHA3-256 digest per input
///   (FIPS 202, domain 0x06).
/// - `shake256_batch` — variable-length SHAKE256 squeeze per input
///   (FIPS 202, domain 0x1F).
/// - `cshake256_batch` — variable-length cSHAKE256 squeeze per input
///   (SP 800-185, domain 0x04 when `(name, customisation)` is non-empty;
///   degenerates to SHAKE256 when both are empty).
///
/// Outputs MUST be byte-identical to the CPU reference regardless of
/// backend (enforced by the `kat_parity` tests).
pub trait Sha3Backend: Send + Sync {
    /// Hash `inputs.len()` independent byte strings to 32-byte SHA3-256
    /// digests. Returns one digest per input, in input order.
    fn sha3_256_batch(&self, inputs: &[&[u8]]) -> Vec<[u8; 32]>;

    /// Squeeze `out_lens[i]` bytes from `SHAKE256(inputs[i])` for each
    /// `i`. Returns one Vec per input, in input order. `out_lens` MUST
    /// have the same length as `inputs`.
    fn shake256_batch(&self, inputs: &[&[u8]], out_lens: &[usize]) -> Vec<Vec<u8>>;

    /// Squeeze `out_lens[i]` bytes from
    /// `cSHAKE256(payloads[i], out_lens[i] * 8, name, customisations[i])`
    /// for each `i`. The function name `name` is shared across the
    /// batch (TupleHash256 always uses `name = b"TupleHash"`, KMAC256
    /// uses `name = b"KMAC"`).
    ///
    /// Default impl: invoke the CPU `sha3::CShake256` per input. Custom
    /// backends override only when they have a true cSHAKE batch
    /// primitive (libluxgpu 0.4 does NOT yet — its 0x1F-domain
    /// `lux_gpu_shake256_batch` is not byte-equivalent to cSHAKE's
    /// 0x04-domain output when `(name, customisation)` is non-empty).
    /// The default keeps callers unbreakable across backend versions.
    fn cshake256_batch(
        &self,
        name: &[u8],
        customisations: &[&[u8]],
        payloads: &[&[u8]],
        out_lens: &[usize],
    ) -> Vec<Vec<u8>> {
        cpu_cshake256_batch(name, customisations, payloads, out_lens)
    }

    /// Batched TupleHash256 with per-input ordered items. Default impl
    /// builds the SP 800-185 encoding once per input on the CPU, then
    /// delegates to `cshake256_batch`. The CPU backend overrides this
    /// to stream items directly into a stateful `TupleHash256` —
    /// equivalent output, ~5x faster (no per-input allocation storm).
    /// GPU backends inherit the default (cheap to override later when
    /// a native batched cSHAKE / TupleHash arrives in libluxgpu).
    fn tuple_hash256_batch(
        &self,
        customisations: &[&[u8]],
        items: &[&[&[u8]]],
        out_lens: &[usize],
    ) -> Vec<Vec<u8>> {
        debug_assert_eq!(customisations.len(), items.len());
        debug_assert_eq!(customisations.len(), out_lens.len());
        let payloads: Vec<Vec<u8>> = items
            .iter()
            .zip(out_lens.iter().copied())
            .map(|(its, n)| {
                let mut buf = Vec::new();
                for item in *its {
                    buf.extend_from_slice(&encode_string(item));
                }
                buf.extend_from_slice(&right_encode((n as u64) * 8));
                buf
            })
            .collect();
        let refs: Vec<&[u8]> = payloads.iter().map(|v| v.as_slice()).collect();
        self.cshake256_batch(b"TupleHash", customisations, &refs, out_lens)
    }

    /// Human-readable backend name, used in test logs and diagnostics.
    fn name(&self) -> &'static str;
}

// SP 800-185 framing helpers — duplicated here from `batch.rs` so the
// trait's default `tuple_hash256_batch` doesn't need to dip into the
// batch module (which depends on this trait). Audit-locked encoding.
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
fn encode_string(s: &[u8]) -> Vec<u8> {
    let mut out = left_encode((s.len() as u64) * 8);
    out.extend_from_slice(s);
    out
}

/// CPU reference for `cshake256_batch` — used by the default impl on
/// the trait and as the silent fallback for GPU backends that lack a
/// cSHAKE batch primitive.
pub fn cpu_cshake256_batch(
    name: &[u8],
    customisations: &[&[u8]],
    payloads: &[&[u8]],
    out_lens: &[usize],
) -> Vec<Vec<u8>> {
    debug_assert_eq!(customisations.len(), payloads.len());
    debug_assert_eq!(customisations.len(), out_lens.len());
    customisations
        .iter()
        .zip(payloads.iter())
        .zip(out_lens.iter().copied())
        .map(|((&s, &x), n)| {
            let core = CShake256Core::new_with_function_name(name, s);
            let mut h = CShake256::from_core(core);
            Update::update(&mut h, x);
            let mut reader = h.finalize_xof();
            let mut out = vec![0u8; n];
            reader.read(&mut out);
            out
        })
        .collect()
}

/// Pure-Rust CPU backend over the `sha3` crate (FIPS 202 reference).
/// Always available; the default backend selected by [`default_backend`]
/// when no GPU is wired in.
#[derive(Default, Debug, Clone, Copy)]
pub struct CpuShake;

impl Sha3Backend for CpuShake {
    fn sha3_256_batch(&self, inputs: &[&[u8]]) -> Vec<[u8; 32]> {
        inputs
            .iter()
            .map(|inp| {
                let mut h = Sha3_256::new();
                sha3::Digest::update(&mut h, inp);
                let out = h.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out);
                arr
            })
            .collect()
    }

    fn shake256_batch(&self, inputs: &[&[u8]], out_lens: &[usize]) -> Vec<Vec<u8>> {
        debug_assert_eq!(inputs.len(), out_lens.len());
        inputs
            .iter()
            .zip(out_lens.iter().copied())
            .map(|(inp, n)| {
                let mut h = Shake256::default();
                Update::update(&mut h, inp);
                let mut reader = h.finalize_xof();
                let mut out = vec![0u8; n];
                reader.read(&mut out);
                out
            })
            .collect()
    }

    /// Streaming override: avoid the per-input payload Vec allocations
    /// that the default impl uses. Constructs one `TupleHash256` per
    /// input, absorbs items in place, finalises. Byte-identical to the
    /// default; ~5x faster on hot Merkle paths.
    fn tuple_hash256_batch(
        &self,
        customisations: &[&[u8]],
        items: &[&[&[u8]]],
        out_lens: &[usize],
    ) -> Vec<Vec<u8>> {
        debug_assert_eq!(customisations.len(), items.len());
        debug_assert_eq!(customisations.len(), out_lens.len());
        customisations
            .iter()
            .zip(items.iter())
            .zip(out_lens.iter().copied())
            .map(|((&s, &its), n)| {
                let mut h = TupleHash256::new(s, n);
                for item in its {
                    h.absorb(item);
                }
                h.finalize_vec()
            })
            .collect()
    }

    fn name(&self) -> &'static str {
        "cpu-sha3"
    }
}

/// CPU-only default backend. Always available; never fails. Higher-
/// level crates (`p3q-verifier`) may shadow this with a GPU-aware
/// selector when their own `gpu-sha3` feature is enabled.
pub fn default_backend() -> Arc<dyn Sha3Backend> {
    Arc::new(CpuShake)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA3-256("") — FIPS 202 reference.
    const SHA3_256_EMPTY: [u8; 32] = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6,
        0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8,
        0x43, 0x4a,
    ];

    // SHA3-256("abc") — FIPS 202 reference.
    const SHA3_256_ABC: [u8; 32] = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];

    #[test]
    fn cpu_sha3_256_kat() {
        let out = CpuShake.sha3_256_batch(&[b"", b"abc"]);
        assert_eq!(out[0], SHA3_256_EMPTY);
        assert_eq!(out[1], SHA3_256_ABC);
    }

    #[test]
    fn cpu_shake256_length_independent() {
        // Squeezing 64 then 32 bytes from the same input: the first 32
        // bytes of the 64-byte squeeze must equal the 32-byte squeeze
        // (sponge invariant).
        let out = CpuShake.shake256_batch(&[b"abc", b"abc"], &[32, 64]);
        assert_eq!(out[0].len(), 32);
        assert_eq!(out[1].len(), 64);
        assert_eq!(out[0], out[1][..32]);
    }

    #[test]
    fn cpu_batch_matches_per_input() {
        let inputs: &[&[u8]] = &[b"", b"a", b"abc", b"the quick brown fox"];
        let batched = CpuShake.sha3_256_batch(inputs);
        for (i, &inp) in inputs.iter().enumerate() {
            let one = CpuShake.sha3_256_batch(&[inp]);
            assert_eq!(batched[i], one[0]);
        }
    }

    /// The default cSHAKE impl produces the same bytes as the stateful
    /// `CShake256` wrapper (which is the audited binding).
    #[test]
    fn cpu_cshake256_matches_stateful() {
        let out = CpuShake.cshake256_batch(
            b"",
            &[b"p3q-S1", b"", b"p3q-S2"],
            &[b"hello", b"abc", b""],
            &[32, 64, 16],
        );
        for (i, ((cust, payload), &n)) in [b"p3q-S1".as_slice(), b"", b"p3q-S2"]
            .iter()
            .zip([b"hello".as_slice(), b"abc", b""])
            .zip([32, 64, 16].iter())
            .enumerate()
        {
            let core = CShake256Core::new_with_function_name(b"", cust);
            let mut h = CShake256::from_core(core);
            Update::update(&mut h, payload);
            let mut reader = h.finalize_xof();
            let mut expected = vec![0u8; n];
            reader.read(&mut expected);
            assert_eq!(out[i], expected, "input {i} mismatch");
        }
    }
}
