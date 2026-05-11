//! P3Q profile identifiers. The wire-level byte is used to dispatch the
//! correct verifier; see README.md for the full table.

use crate::P3qError;

/// On-wire identifier of a P3Q proof profile.
///
/// `0x10` is the strict-PQ production default (P3Q-SHA3).
/// `0x11` is the Keccak-256 cross-ecosystem variant (P3Q-Keccak).
///
/// All other bytes are reserved; verifiers MUST reject them with
/// [`P3qError::UnsupportedProfile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProofSystemId {
    /// cSHAKE256 / KMAC256 / TupleHash256 — the Lux Z-Chain default.
    Sha3 = 0x10,
    /// Keccak-256 — Ethereum-adjacent cross-ecosystem variant.
    Keccak = 0x11,
}

impl ProofSystemId {
    /// On-wire byte for this profile.
    #[inline]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decode an on-wire byte into a profile. Returns
    /// `UnsupportedProfile` for any unrecognised byte.
    pub const fn from_byte(byte: u8) -> Result<Self, P3qError> {
        match byte {
            0x10 => Ok(Self::Sha3),
            0x11 => Ok(Self::Keccak),
            other => Err(P3qError::UnsupportedProfile(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for p in [ProofSystemId::Sha3, ProofSystemId::Keccak] {
            assert_eq!(ProofSystemId::from_byte(p.as_byte()).unwrap(), p);
        }
    }

    #[test]
    fn rejects_unknown() {
        assert!(matches!(
            ProofSystemId::from_byte(0xff),
            Err(P3qError::UnsupportedProfile(0xff))
        ));
    }
}
