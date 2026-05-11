// P3Q Fiat-Shamir challenger. Strict-PQ profile uses cSHAKE256 with
// per-transcript customisation strings; never SHA-256, never BLAKE3,
// never Poseidon.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Single-instance Fiat-Shamir transcript. Construct with a
//! domain-separation label, observe protocol messages, squeeze
//! challenges.

use p3q_core::TranscriptLabel;
use p3q_sha3::CShake256;

/// A Fiat-Shamir transcript over cSHAKE256. Each `observe` is
/// absorbed; each `challenge_bytes` finalises a fresh squeeze head
/// derived from the current state — without consuming the transcript.
pub struct Challenger {
    customisation: Vec<u8>,
    absorbed: Vec<u8>,
    counter: u64,
}

impl Challenger {
    /// New transcript with the given domain-separation label. The
    /// label is embedded as the cSHAKE256 customisation string.
    pub fn new(label: TranscriptLabel) -> Self {
        Self {
            customisation: label.as_bytes().to_vec(),
            absorbed: Vec::new(),
            counter: 0,
        }
    }

    /// Absorb protocol-message bytes into the transcript.
    pub fn observe(&mut self, bytes: &[u8]) {
        self.absorbed.extend_from_slice(bytes);
    }

    /// Squeeze `OUT` deterministic bytes from the current transcript.
    /// The internal counter is incremented so successive calls without
    /// intervening `observe` give distinct outputs.
    pub fn challenge_array<const OUT: usize>(&mut self) -> [u8; OUT] {
        let mut h = CShake256::new(b"", &self.customisation);
        h.absorb(&self.absorbed);
        h.absorb(&self.counter.to_le_bytes());
        self.counter += 1;
        h.finalize_array::<OUT>()
    }

    /// Squeeze `n` bytes into a fresh `Vec`.
    pub fn challenge_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut h = CShake256::new(b"", &self.customisation);
        h.absorb(&self.absorbed);
        h.absorb(&self.counter.to_le_bytes());
        self.counter += 1;
        h.finalize_vec(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3q_core::transcript::labels;

    #[test]
    fn different_observations_diverge() {
        let mut a = Challenger::new(labels::ROOT);
        a.observe(b"alpha");
        let oa: [u8; 32] = a.challenge_array();

        let mut b = Challenger::new(labels::ROOT);
        b.observe(b"beta");
        let ob: [u8; 32] = b.challenge_array();

        assert_ne!(oa, ob);
    }

    #[test]
    fn successive_challenges_diverge() {
        let mut t = Challenger::new(labels::ROOT);
        t.observe(b"x");
        let c0: [u8; 32] = t.challenge_array();
        let c1: [u8; 32] = t.challenge_array();
        assert_ne!(c0, c1);
    }

    #[test]
    fn deterministic_replay() {
        let mut a = Challenger::new(labels::ROOT);
        a.observe(b"x");
        let oa: [u8; 32] = a.challenge_array();

        let mut b = Challenger::new(labels::ROOT);
        b.observe(b"x");
        let ob: [u8; 32] = b.challenge_array();

        assert_eq!(oa, ob);
    }

    #[test]
    fn label_separates_transcripts() {
        let mut a = Challenger::new(labels::FRI_COMMIT);
        a.observe(b"x");
        let oa: [u8; 32] = a.challenge_array();

        let mut b = Challenger::new(labels::FRI_QUERY);
        b.observe(b"x");
        let ob: [u8; 32] = b.challenge_array();

        assert_ne!(oa, ob);
    }
}
