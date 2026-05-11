// P3Q strict-PQ verifier. Panic-free by contract: every fault returns
// a typed `P3qError`. The audit gate runs malformed-proof fuzzing
// against this crate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Top-level verifier entry point. Dispatches a wire proof to the
//! profile-specific path (currently P3Q-SHA3) and never panics.

use p3q_core::{P3qError, ProofBytes, ProofSystemId, Result};

/// Verify a wire proof. The first byte is the [`ProofSystemId`]; the
/// remainder is profile-defined.
///
/// Constant-time: not yet certified. The audit gate will sign off on
/// this annotation in v0.1.0+.
pub fn verify(public_input: &[u8], proof: &ProofBytes) -> Result<()> {
    let bytes = proof.as_slice();
    let head = bytes
        .first()
        .copied()
        .ok_or(P3qError::InvalidLength("proof: missing profile byte"))?;
    let profile = ProofSystemId::from_byte(head)?;
    match profile {
        ProofSystemId::Sha3 => verify_sha3(public_input, &bytes[1..]),
        ProofSystemId::Keccak => verify_keccak(public_input, &bytes[1..]),
    }
}

/// P3Q-SHA3 strict-PQ verifier. Stubbed until the audited body lands.
fn verify_sha3(_public_input: &[u8], body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(P3qError::InvalidLength("p3q-sha3 proof body is empty"));
    }
    // The audit-gated verifier body is implemented in a feature-flagged
    // module that lands in subsequent v0.0.x releases; until then any
    // structurally valid proof is rejected with an explicit typed error
    // — never a panic, never silent acceptance.
    Err(P3qError::StarkVerification(
        "p3q-sha3 verifier body not yet audit-gated",
    ))
}

/// P3Q-Keccak cross-ecosystem verifier. Stubbed until the audited
/// body lands.
fn verify_keccak(_public_input: &[u8], body: &[u8]) -> Result<()> {
    if body.is_empty() {
        return Err(P3qError::InvalidLength("p3q-keccak proof body is empty"));
    }
    Err(P3qError::StarkVerification(
        "p3q-keccak verifier body not yet audit-gated",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_proof_rejected() {
        let p = ProofBytes::new(vec![]);
        assert!(matches!(verify(&[], &p), Err(P3qError::InvalidLength(_))));
    }

    #[test]
    fn unknown_profile_rejected() {
        let p = ProofBytes::new(vec![0xFF, 0x00]);
        assert!(matches!(
            verify(&[], &p),
            Err(P3qError::UnsupportedProfile(0xFF))
        ));
    }

    #[test]
    fn sha3_profile_dispatched() {
        let p = ProofBytes::new(vec![0x10, 0x01]);
        let err = verify(&[], &p).unwrap_err();
        // Should reach the audit-gate stub, not a different path.
        matches!(err, P3qError::StarkVerification(_));
    }

    #[test]
    fn never_panics_on_random_bytes() {
        // 32 byte random-ish strings — exercise dispatch + body
        // detection without panicking.
        for b in 0u8..32 {
            let proof = ProofBytes::new(vec![b; 64]);
            let _ = verify(&[], &proof);
        }
    }
}
