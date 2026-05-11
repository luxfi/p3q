//! Transcript domain-separation labels. Every Fiat-Shamir absorb uses a
//! distinct constant label so independent transcripts cannot collide
//! even if they happen to absorb byte-identical content.

/// A short, ASCII, compile-time domain-separation label. Labels are
/// embedded into the cSHAKE256 customisation string when the profile is
/// P3Q-SHA3; for Keccak they are absorbed as length-prefixed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TranscriptLabel(pub &'static str);

impl TranscriptLabel {
    /// Borrow the label as a byte slice.
    #[inline]
    pub const fn as_bytes(self) -> &'static [u8] {
        self.0.as_bytes()
    }

    /// Length in bytes.
    #[inline]
    pub const fn len(self) -> usize {
        self.0.len()
    }

    /// True if the label is empty (forbidden by the protocol but
    /// representable for tests).
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

/// Standard transcript labels used by P3Q.
pub mod labels {
    use super::TranscriptLabel;

    /// Root domain separator for any P3Q transcript.
    pub const ROOT: TranscriptLabel = TranscriptLabel("p3q-v1");
    /// FRI commit-phase challenges.
    pub const FRI_COMMIT: TranscriptLabel = TranscriptLabel("p3q-fri-commit");
    /// FRI query-phase challenges.
    pub const FRI_QUERY: TranscriptLabel = TranscriptLabel("p3q-fri-query");
    /// STARK out-of-domain challenge.
    pub const STARK_OOD: TranscriptLabel = TranscriptLabel("p3q-stark-ood");
    /// Recursion folding challenge.
    pub const RECURSION_FOLD: TranscriptLabel = TranscriptLabel("p3q-rec-fold");
}
