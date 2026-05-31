//! Typed Fiat-Shamir transcript used by the P3Q strict-PQ verifier.
//!
//! Wraps [`p3q_challenger::Challenger`] in a profile-aware façade so the
//! verifier never accidentally absorbs without a domain-separation
//! label. Every observation is prefixed with one of the constants
//! defined in [`labels`].
//!
//! Profile dispatch: the only thing that differs between the SHA-3 and
//! Keccak verifier profiles is the root customisation string, which is
//! threaded into the underlying cSHAKE256 instance.

use p3q_challenger::Challenger;
use p3q_core::{P3qError, ProofSystemId, Result};
use p3q_field::Goldilocks;

/// Domain-separation labels for each transcript observation.
///
/// These strings ARE part of the protocol — changing one is a hard fork
/// (proofs produced by an older prover become unverifiable). They are
/// pinned into the on-chain verifier ABI in `p3q-c-abi`.
pub mod labels {
    use p3q_core::TranscriptLabel;

    /// Root transcript label for the strict P3Q-SHA3 profile.
    pub const ROOT_SHA3: TranscriptLabel = TranscriptLabel("LUX-P3Q-V1-SHA3");
    /// Root transcript label for the cross-ecosystem P3Q-Keccak profile.
    pub const ROOT_KECCAK: TranscriptLabel = TranscriptLabel("LUX-P3Q-V1-KECCAK");

    /// Observation tag for the proof header.
    pub const HEADER: &[u8] = b"LUX-P3Q-V1-HEADER";
    /// Observation tag for the public-input bytes.
    pub const PUBLIC_INPUT: &[u8] = b"LUX-P3Q-V1-PUBLIC-INPUT";
    /// Observation tag for the trace LDE Merkle root.
    pub const TRACE_COMMIT: &[u8] = b"LUX-P3Q-V1-TRACE-COMMIT";
    /// Observation tag for each FRI layer's Merkle root.
    pub const FRI_COMMIT: &[u8] = b"LUX-P3Q-V1-FRI-COMMIT";
    /// Observation tag for the final polynomial.
    pub const FRI_FINAL: &[u8] = b"LUX-P3Q-V1-FRI-FINAL";
    /// Observation tag separating the query-derivation phase.
    pub const FRI_QUERY: &[u8] = b"LUX-P3Q-V1-FRI-QUERY";
}

/// Typed transcript. Constructed with the profile, then advanced by the
/// verifier in lock-step with the prover.
pub struct VerifierTranscript {
    inner: Challenger,
}

impl VerifierTranscript {
    /// Construct a fresh transcript for `profile`.
    pub fn new(profile: ProofSystemId) -> Self {
        let label = match profile {
            ProofSystemId::Sha3 => labels::ROOT_SHA3,
            ProofSystemId::Keccak => labels::ROOT_KECCAK,
        };
        Self {
            inner: Challenger::new(label),
        }
    }

    /// Observe an arbitrary tag + payload pair. The tag's length is
    /// absorbed first to make tag boundaries unambiguous.
    fn observe_tagged(&mut self, tag: &[u8], payload: &[u8]) {
        // tag length || tag || payload length || payload — no ambiguity.
        self.inner.observe(&(tag.len() as u32).to_be_bytes());
        self.inner.observe(tag);
        self.inner.observe(&(payload.len() as u32).to_be_bytes());
        self.inner.observe(payload);
    }

    /// Observe the proof header.
    pub fn observe_header(&mut self, header_bytes: &[u8]) {
        self.observe_tagged(labels::HEADER, header_bytes);
    }

    /// Observe the public-input bytes.
    pub fn observe_public_input(&mut self, pi: &[u8]) {
        self.observe_tagged(labels::PUBLIC_INPUT, pi);
    }

    /// Observe the trace LDE Merkle root.
    pub fn observe_trace_root(&mut self, root: &[u8; 32]) {
        self.observe_tagged(labels::TRACE_COMMIT, root);
    }

    /// Observe a single FRI-layer Merkle root.
    pub fn observe_fri_layer(&mut self, root: &[u8; 32]) {
        self.observe_tagged(labels::FRI_COMMIT, root);
    }

    /// Observe the final polynomial (after all folds).
    pub fn observe_final_poly(&mut self, encoded: &[u8]) {
        self.observe_tagged(labels::FRI_FINAL, encoded);
    }

    /// Mark the start of the query-derivation phase (no payload).
    pub fn enter_query_phase(&mut self) {
        self.observe_tagged(labels::FRI_QUERY, &[]);
    }

    /// Squeeze a Goldilocks field element by rejection sampling.
    ///
    /// The sponge produces 8-byte chunks; each chunk is interpreted as
    /// little-endian `u64`. If the chunk encodes a value `>= P` it is
    /// rejected and the next chunk is drawn. The rejection probability
    /// per chunk is `(2^64 - P) / 2^64 = (2^32 - 1) / 2^64 ≈ 2^-32`, so
    /// the loop terminates in ≈ 1 iteration almost surely. The verifier
    /// bound is `32` to guarantee termination under any input —
    /// transcript-derived randomness only.
    pub fn squeeze_field(&mut self) -> Result<Goldilocks> {
        for _ in 0..32 {
            let bytes: [u8; 8] = self.inner.challenge_array();
            let raw = u64::from_le_bytes(bytes);
            if raw < p3q_field::goldilocks::P {
                return Ok(Goldilocks::from_u64(raw));
            }
        }
        Err(P3qError::Transcript(
            "rejection-sampling for field element did not terminate",
        ))
    }

    /// Squeeze a `usize` query index uniformly in `[0, 1 << log_bound)`.
    ///
    /// Computes `chunk mod 2^log_bound` from a 64-bit squeezed value; for
    /// `log_bound <= 32` (current ceiling) this introduces no bias.
    pub fn squeeze_query_index(&mut self, log_bound: u32) -> Result<u32> {
        if log_bound == 0 {
            return Ok(0);
        }
        if log_bound > 32 {
            return Err(P3qError::Transcript("query index log_bound > 32"));
        }
        let bytes: [u8; 8] = self.inner.challenge_array();
        let raw = u64::from_le_bytes(bytes);
        let mask = (1u64 << log_bound) - 1;
        Ok((raw & mask) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_separates_root() {
        let mut a = VerifierTranscript::new(ProofSystemId::Sha3);
        let mut b = VerifierTranscript::new(ProofSystemId::Keccak);
        a.observe_header(b"hdr");
        b.observe_header(b"hdr");
        let oa = a.squeeze_field().unwrap();
        let ob = b.squeeze_field().unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn label_separates_observations() {
        // Same byte payload under different labels must produce
        // different challenges.
        let mut a = VerifierTranscript::new(ProofSystemId::Sha3);
        let mut b = VerifierTranscript::new(ProofSystemId::Sha3);
        a.observe_header(b"x");
        b.observe_public_input(b"x");
        let oa = a.squeeze_field().unwrap();
        let ob = b.squeeze_field().unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn replay_is_deterministic() {
        let mut a = VerifierTranscript::new(ProofSystemId::Sha3);
        let mut b = VerifierTranscript::new(ProofSystemId::Sha3);
        a.observe_header(b"hdr");
        a.observe_trace_root(&[0xABu8; 32]);
        b.observe_header(b"hdr");
        b.observe_trace_root(&[0xABu8; 32]);
        assert_eq!(a.squeeze_field().unwrap(), b.squeeze_field().unwrap());
    }

    #[test]
    fn query_index_in_range() {
        let mut t = VerifierTranscript::new(ProofSystemId::Sha3);
        t.observe_header(b"x");
        let q = t.squeeze_query_index(7).unwrap();
        assert!(q < 128);
    }

    #[test]
    fn squeeze_field_terminates() {
        // Functional: just ensure no panic across many draws.
        let mut t = VerifierTranscript::new(ProofSystemId::Sha3);
        for i in 0..256 {
            t.observe_header(&[i as u8]);
            let _ = t.squeeze_field().unwrap();
        }
    }
}
