//! Fiat-Shamir transcript for the AIR DEEP-STARK.
//!
//! Wraps the project's cSHAKE256 [`p3q_challenger::Challenger`] with
//! domain-separated absorbs for every AIR-STARK message (trace root,
//! quotient root, OOD point, constraint-combination challenges, DEEP
//! challenges, FRI). It implements [`p3q_fri::engine::FriTranscript`] so
//! the single FRI engine threads through the *same* transcript state —
//! the FRI randomness is therefore bound to the AIR commitments, which
//! is required for soundness.
//!
//! Strict-PQ: cSHAKE256 only (same family as ML-DSA-65 / Pulsar). Every
//! observation is length-prefixed and label-tagged so independent
//! absorbs cannot collide.

use p3q_challenger::Challenger;
use p3q_core::{P3qError, Result, TranscriptLabel};
use p3q_field::{Field, Goldilocks};
use p3q_fri::engine::FriTranscript;
use p3q_merkle::Digest;

/// Domain-separation root label for the AIR DEEP-STARK transcript. This
/// string is part of the protocol; changing it is a hard fork.
pub const AIR_STARK_ROOT: TranscriptLabel = TranscriptLabel("LUX-P3Q-AIR-STARK-V1");

/// Tagged observation labels. Each absorb is prefixed with its label and
/// length so boundaries are unambiguous.
mod tag {
    pub const TRACE_COMMIT: &[u8] = b"air-trace-commit";
    pub const QUOTIENT_COMMIT: &[u8] = b"air-quotient-commit";
    pub const CONSTRAINT_ALPHA: &[u8] = b"air-constraint-alpha";
    pub const OOD_POINT: &[u8] = b"air-ood-point";
    pub const OOD_VALUES: &[u8] = b"air-ood-values";
    pub const DEEP_GAMMA: &[u8] = b"air-deep-gamma";
    pub const FRI_ROOT: &[u8] = b"air-fri-root";
    pub const FRI_FINAL: &[u8] = b"air-fri-final";
    pub const FRI_QUERY: &[u8] = b"air-fri-query";
}

/// The AIR-STARK Fiat-Shamir transcript.
pub struct StarkTranscript {
    inner: Challenger,
}

impl StarkTranscript {
    /// Fresh transcript bound to the AIR-STARK root label, with the
    /// circuit's public inputs absorbed first (so the whole proof is
    /// bound to the statement being proven).
    pub fn new(public_inputs: &[Goldilocks]) -> Self {
        let mut t = Self {
            inner: Challenger::new(AIR_STARK_ROOT),
        };
        t.observe_tagged(b"air-public-inputs", &fields_to_bytes(public_inputs));
        t
    }

    fn observe_tagged(&mut self, tag: &[u8], payload: &[u8]) {
        self.inner.observe(&(tag.len() as u32).to_be_bytes());
        self.inner.observe(tag);
        self.inner.observe(&(payload.len() as u32).to_be_bytes());
        self.inner.observe(payload);
    }

    /// Squeeze a Goldilocks element by rejection sampling (≈1 draw).
    fn squeeze_field(&mut self) -> Result<Goldilocks> {
        for _ in 0..32 {
            let b: [u8; 8] = self.inner.challenge_array();
            let raw = u64::from_le_bytes(b);
            if raw < p3q_field::goldilocks::P {
                return Ok(Goldilocks::from_u64(raw));
            }
        }
        Err(P3qError::Transcript(
            "air-stark: field rejection sampling did not terminate",
        ))
    }

    /// Observe the trace commitment root.
    pub fn observe_trace_root(&mut self, root: &Digest) {
        self.observe_tagged(tag::TRACE_COMMIT, root);
    }

    /// Observe the quotient commitment root.
    pub fn observe_quotient_root(&mut self, root: &Digest) {
        self.observe_tagged(tag::QUOTIENT_COMMIT, root);
    }

    /// Sample `count` constraint-combination challenges `α_0 .. α_{c−1}`.
    /// Drawn AFTER the trace commit, BEFORE the quotient commit.
    pub fn sample_constraint_challenges(&mut self, count: usize) -> Result<Vec<Goldilocks>> {
        self.observe_tagged(tag::CONSTRAINT_ALPHA, &(count as u32).to_be_bytes());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.squeeze_field()?);
        }
        Ok(out)
    }

    /// Sample the out-of-domain DEEP point `ζ`. Drawn AFTER the quotient
    /// commit. The caller rejects `ζ ∈ D` (probability ≈ N_lde/|F|,
    /// astronomically small) by resampling — see the prover/verifier.
    pub fn sample_ood_point(&mut self) -> Result<Goldilocks> {
        self.observe_tagged(tag::OOD_POINT, &[]);
        self.squeeze_field()
    }

    /// Observe the OOD opening values (so the DEEP challenges are bound
    /// to them).
    pub fn observe_ood_values(
        &mut self,
        trace_at_zeta: &[Goldilocks],
        trace_at_g_zeta: &[Goldilocks],
        quotient_at_zeta: Goldilocks,
    ) {
        let mut buf = fields_to_bytes(trace_at_zeta);
        buf.extend_from_slice(&fields_to_bytes(trace_at_g_zeta));
        buf.extend_from_slice(&quotient_at_zeta.to_bytes());
        self.observe_tagged(tag::OOD_VALUES, &buf);
    }

    /// Sample the DEEP combination challenges: one `γ_j` per column for
    /// the `(·−ζ)` quotients, one `γ'_j` per column for the `(·−gζ)`
    /// quotients, and one `γ_q` for the quotient term. Returned as
    /// `(gammas, gammas_shifted, gamma_q)`.
    #[allow(clippy::type_complexity)]
    pub fn sample_deep_challenges(
        &mut self,
        width: usize,
    ) -> Result<(Vec<Goldilocks>, Vec<Goldilocks>, Goldilocks)> {
        self.observe_tagged(tag::DEEP_GAMMA, &(width as u32).to_be_bytes());
        let mut gammas = Vec::with_capacity(width);
        for _ in 0..width {
            gammas.push(self.squeeze_field()?);
        }
        let mut gammas_shifted = Vec::with_capacity(width);
        for _ in 0..width {
            gammas_shifted.push(self.squeeze_field()?);
        }
        let gamma_q = self.squeeze_field()?;
        Ok((gammas, gammas_shifted, gamma_q))
    }
}

impl FriTranscript for StarkTranscript {
    fn observe_fri_root(&mut self, root: &Digest) {
        self.observe_tagged(tag::FRI_ROOT, root);
    }
    fn observe_fri_final(&mut self, coeffs: &[Goldilocks]) {
        self.observe_tagged(tag::FRI_FINAL, &fields_to_bytes(coeffs));
    }
    fn squeeze_fold_challenge(&mut self) -> Result<Goldilocks> {
        self.squeeze_field()
    }
    fn enter_query_phase(&mut self) {
        self.observe_tagged(tag::FRI_QUERY, &[]);
    }
    fn squeeze_query_index(&mut self, log_bound: u32) -> Result<u32> {
        if log_bound == 0 {
            return Ok(0);
        }
        if log_bound > 32 {
            return Err(P3qError::Transcript("air-stark: query log_bound > 32"));
        }
        let b: [u8; 8] = self.inner.challenge_array();
        let raw = u64::from_le_bytes(b);
        let mask = (1u64 << log_bound) - 1;
        Ok((raw & mask) as u32)
    }
}

/// Serialise field elements as concatenated canonical LE bytes.
fn fields_to_bytes(fields: &[Goldilocks]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * Goldilocks::BYTES);
    for f in fields {
        out.extend_from_slice(&f.to_bytes());
    }
    out
}
