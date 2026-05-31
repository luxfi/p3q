// =============================================================================
// p3q-c-abi - C ABI shim for the P3Q strict-PQ verifier
// =============================================================================
//
// Exposes a single entry point `p3q_verify` to non-Rust callers (luxcpp,
// multichain-cpp, cevm precompiles). The shim:
//
//   1. validates the raw pointer/length pairs,
//   2. forwards to `p3q_verifier::verify`,
//   3. converts `P3qError` into a stable integer status code,
//   4. catches every panic via `std::panic::catch_unwind` so a Rust
//      panic NEVER crosses the FFI boundary.
//
// The verifier body in p3q v0.0.1 is the upstream "not yet audit-gated"
// stub. When v0.1.0 lands the audited verifier the shim does not need
// to change: callers will automatically pick up the real verification
// behavior the next time they link.
// =============================================================================

//! C ABI shim for the P3Q strict-PQ verifier.
//!
//! Single entry point: [`p3q_verify`]. The shim catches all Rust
//! panics so they never cross the FFI boundary, and maps every
//! [`p3q_core::P3qError`] variant onto a stable integer status code
//! that's exported to C as a `P3Q_ERR_*` constant.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use p3q_core::{P3qError, ProofBytes};

// ---------------------------------------------------------------------------
// Status codes — exported into the C header by cbindgen.
// ---------------------------------------------------------------------------

/// Verification succeeded — the proof is accepted.
pub const P3Q_OK: i32 = 1;
/// Verification ran to completion and rejected the proof.
pub const P3Q_REJECTED: i32 = 0;
/// One of the input pointer / length pairs was malformed
/// (null pointer with non-zero length, etc).
pub const P3Q_ERR_NULL_PTR: i32 = -1;
/// The proof bytes did not decode into a well-formed protocol object.
pub const P3Q_ERR_PARSE: i32 = -2;
/// The proof's profile byte does not match a verifier the shim knows.
pub const P3Q_ERR_UNSUPPORTED_PROFILE: i32 = -3;
/// Merkle authentication failed.
pub const P3Q_ERR_MERKLE: i32 = -4;
/// FRI low-degree check failed.
pub const P3Q_ERR_FRI: i32 = -5;
/// STARK constraint check failed.
pub const P3Q_ERR_STARK: i32 = -6;
/// Fiat-Shamir transcript mismatch.
pub const P3Q_ERR_TRANSCRIPT: i32 = -7;
/// Field element out of range.
pub const P3Q_ERR_FIELD: i32 = -8;
/// Z-Chain circuit-level invariant failed.
pub const P3Q_ERR_CIRCUIT: i32 = -9;
/// A Rust panic was caught at the FFI boundary. This MUST be treated
/// as a verification failure by the caller.
pub const P3Q_ERR_PANIC: i32 = -99;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn map_err(e: P3qError) -> i32 {
    match e {
        P3qError::InvalidLength(_) | P3qError::InvalidEncoding(_) => P3Q_ERR_PARSE,
        P3qError::UnsupportedProfile(_) => P3Q_ERR_UNSUPPORTED_PROFILE,
        P3qError::MerkleAuth => P3Q_ERR_MERKLE,
        P3qError::FriVerification(_) => P3Q_ERR_FRI,
        P3qError::StarkVerification(_) => P3Q_ERR_STARK,
        P3qError::Transcript(_) => P3Q_ERR_TRANSCRIPT,
        P3qError::FieldOutOfRange => P3Q_ERR_FIELD,
        P3qError::Circuit(_) => P3Q_ERR_CIRCUIT,
    }
}

/// Reconstitute a `&[u8]` from a `(ptr, len)` pair. Treats `len == 0`
/// as an empty slice regardless of `ptr` so callers may pass a null
/// pointer with `len = 0` to signal "no public input".
///
/// # Safety
/// Caller must guarantee that for `len > 0`, `ptr` is non-null and
/// points to at least `len` initialized bytes of memory.
unsafe fn slice_from_raw<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Verify a P3Q proof.
///
/// `public_input` is the public-input bytes the verifier binds against
/// the Fiat-Shamir transcript. `proof` is the wire-level proof bytes
/// (first byte = `ProofSystemId`, rest = profile-defined).
///
/// Returns:
/// * `P3Q_OK` (1) - proof accepted
/// * `P3Q_REJECTED` (0) - proof rejected by the verifier
/// * negative value - error (see `P3Q_ERR_*` constants)
///
/// # Safety
/// Caller MUST ensure the `(public_input, public_input_len)` and
/// `(proof, proof_len)` pairs are valid `(ptr, len)` pairs: for any
/// non-zero `len`, the pointer must be non-null and point to at least
/// `len` initialized bytes. `len == 0` accepts a null pointer.
#[no_mangle]
pub unsafe extern "C" fn p3q_verify(
    public_input: *const u8,
    public_input_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let pi = match slice_from_raw(public_input, public_input_len) {
            Some(s) => s,
            None => return P3Q_ERR_NULL_PTR,
        };
        let proof_bytes = match slice_from_raw(proof, proof_len) {
            Some(s) => s,
            None => return P3Q_ERR_NULL_PTR,
        };
        let proof_obj = ProofBytes::new(proof_bytes.to_vec());
        match p3q_verifier::verify(pi, &proof_obj) {
            Ok(()) => P3Q_OK,
            Err(e) => map_err(e),
        }
    }));
    match result {
        Ok(code) => code,
        Err(_) => P3Q_ERR_PANIC,
    }
}

/// Return the on-wire byte for the P3Q-SHA3 profile (`0x10`). Useful
/// for callers that want to construct probe proofs in C without
/// hard-coding the magic number.
#[no_mangle]
pub extern "C" fn p3q_profile_sha3() -> u8 {
    p3q_core::ProofSystemId::Sha3.as_byte()
}

/// Return the on-wire byte for the P3Q-Keccak profile (`0x11`).
#[no_mangle]
pub extern "C" fn p3q_profile_keccak() -> u8 {
    p3q_core::ProofSystemId::Keccak.as_byte()
}

/// Semver string for the linked p3q-c-abi crate. Returns a static
/// nul-terminated UTF-8 string. The caller must NOT free this pointer.
#[no_mangle]
pub extern "C" fn p3q_version() -> *const core::ffi::c_char {
    // c"..." literals (since 1.77) end with an implicit \0.
    c"0.0.1".as_ptr()
}

// ---------------------------------------------------------------------------
// Tests — the C ABI is exercised in-process via raw `unsafe` calls.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_inputs_with_zero_len_are_legal() {
        // p3q_verify(NULL, 0, NULL, 0) must not crash; an empty proof
        // is REJECTED by the verifier (missing profile byte), which
        // maps to P3Q_ERR_PARSE — not a null-pointer error.
        let rc = unsafe { p3q_verify(std::ptr::null(), 0, std::ptr::null(), 0) };
        assert_eq!(rc, P3Q_ERR_PARSE, "got {rc}");
    }

    #[test]
    fn null_with_non_zero_len_is_null_ptr_error() {
        let rc = unsafe { p3q_verify(std::ptr::null(), 8, std::ptr::null(), 0) };
        assert_eq!(rc, P3Q_ERR_NULL_PTR, "got {rc}");
    }

    #[test]
    fn unknown_profile_is_unsupported() {
        let bad = [0xFFu8, 0x00, 0x00];
        let rc = unsafe { p3q_verify(std::ptr::null(), 0, bad.as_ptr(), bad.len()) };
        assert_eq!(rc, P3Q_ERR_UNSUPPORTED_PROFILE, "got {rc}");
    }

    #[test]
    fn sha3_profile_hits_audit_gate_stub() {
        // Profile byte 0x10 + a single body byte exercises the SHA-3
        // verifier path. Until the audited body lands in v0.1.0 this
        // returns StarkVerification ("not yet audit-gated"), which the
        // shim maps to P3Q_ERR_STARK. This is the contract: the FFI
        // works today; the verifier itself becomes real on the next
        // upstream release without any C ABI churn.
        let proof = [0x10u8, 0x01];
        let rc = unsafe { p3q_verify(std::ptr::null(), 0, proof.as_ptr(), proof.len()) };
        assert_eq!(rc, P3Q_ERR_STARK, "got {rc}");
    }

    #[test]
    fn keccak_profile_hits_audit_gate_stub() {
        let proof = [0x11u8, 0x01];
        let rc = unsafe { p3q_verify(std::ptr::null(), 0, proof.as_ptr(), proof.len()) };
        assert_eq!(rc, P3Q_ERR_STARK, "got {rc}");
    }

    #[test]
    fn empty_profile_body_is_parse_error() {
        // Just the profile byte, no body — verifier returns
        // InvalidLength("p3q-sha3 proof body is empty").
        let proof = [0x10u8];
        let rc = unsafe { p3q_verify(std::ptr::null(), 0, proof.as_ptr(), proof.len()) };
        assert_eq!(rc, P3Q_ERR_PARSE, "got {rc}");
    }

    #[test]
    fn profile_constants_match_core() {
        assert_eq!(p3q_profile_sha3(), 0x10);
        assert_eq!(p3q_profile_keccak(), 0x11);
    }

    #[test]
    fn version_is_null_terminated() {
        let p = p3q_version();
        assert!(!p.is_null());
        let s = unsafe { core::ffi::CStr::from_ptr(p) };
        assert_eq!(s.to_str().unwrap(), "0.0.1");
    }

    #[test]
    fn never_panics_on_random_bytes() {
        // Exercise every first byte 0x00..=0xFF with a small body.
        // Every call must return one of the documented status codes,
        // never panic.
        for b in 0u8..=0xFF {
            let proof = [b, 0x01, 0x02];
            let rc = unsafe { p3q_verify(std::ptr::null(), 0, proof.as_ptr(), proof.len()) };
            assert!(
                rc == P3Q_OK
                    || rc == P3Q_REJECTED
                    || rc == P3Q_ERR_PARSE
                    || rc == P3Q_ERR_UNSUPPORTED_PROFILE
                    || rc == P3Q_ERR_MERKLE
                    || rc == P3Q_ERR_FRI
                    || rc == P3Q_ERR_STARK
                    || rc == P3Q_ERR_TRANSCRIPT
                    || rc == P3Q_ERR_FIELD
                    || rc == P3Q_ERR_CIRCUIT,
                "byte 0x{b:02x} produced unknown rc={rc}"
            );
        }
    }
}
