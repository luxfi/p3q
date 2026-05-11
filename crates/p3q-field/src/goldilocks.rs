//! Goldilocks field: prime `p = 2^64 - 2^32 + 1`.
//!
//! This is the canonical small-field used by Plonky2/3-style STARK
//! arithmetisations: 64-bit elements, sparse modulus, fast reduction.
//! P3Q keeps the same field — only the hash family is swapped to
//! FIPS 202.

use core::ops::{Add, Mul, Neg, Sub};

use p3q_core::P3qError;

use crate::traits::Field;

/// Goldilocks prime: `2^64 - 2^32 + 1`.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// An element of the Goldilocks field, stored as a canonical `u64` in
/// `[0, P)`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Goldilocks(u64);

impl Goldilocks {
    /// Construct from a `u64`, reducing modulo `P`.
    #[inline]
    pub const fn from_u64(x: u64) -> Self {
        // const subtraction; the conditional is folded at compile time
        // when `x` is const.
        if x >= P {
            Self(x.wrapping_sub(P))
        } else {
            Self(x)
        }
    }

    /// Underlying canonical `u64`.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Reduce a 128-bit value modulo `P` using the Goldilocks identity
    /// `2^64 ≡ 2^32 - 1 = EPSILON (mod P)`.
    ///
    /// Algorithm (the canonical Plonky2-field reduction):
    ///
    /// Let `x = x_lo + x_hi * 2^64`, split `x_hi = x_hi_lo + x_hi_hi * 2^32`.
    /// Then `x = x_lo + (x_hi_lo + x_hi_hi * 2^32) * 2^64`.
    ///
    /// Using `2^64 ≡ EPSILON` and `2^96 = 2^32 * 2^64 ≡ 2^32 * EPSILON`,
    /// and noting that `2^32 * EPSILON = 2^64 - 2^32 ≡ EPSILON - 2^32 + 2^64
    /// ≡ -1 (mod P)` (since `2^32 ≡ 2^64 + 1 ≡ EPSILON + 1 ≡ 0 ... `), we
    /// get the much simpler form:
    ///
    /// `x ≡ x_lo - x_hi_hi + x_hi_lo * EPSILON (mod P)`.
    #[inline]
    fn reduce_u128(x: u128) -> Self {
        let x_lo = x as u64;
        let x_hi = (x >> 64) as u64;
        let x_hi_hi = x_hi >> 32;
        let x_hi_lo = x_hi & EPSILON;

        let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
        if borrow {
            // Underflow: r = x_lo - x_hi_hi + 2^64; reduce 2^64 ≡ EPSILON,
            // so subtract EPSILON to keep value ≡ correct mod P.
            t0 = t0.wrapping_sub(EPSILON);
        }
        // x_hi_lo < 2^32, EPSILON < 2^32, so the product fits in u64.
        let t1 = x_hi_lo * EPSILON;
        let (mut t2, carry) = t0.overflowing_add(t1);
        if carry {
            t2 = t2.wrapping_add(EPSILON);
        }
        if t2 >= P {
            t2 = t2.wrapping_sub(P);
        }
        Self(t2)
    }
}

/// `EPSILON = 2^32 - 1`; the value of `2^64 mod P`.
const EPSILON: u64 = (1u64 << 32) - 1;

impl Field for Goldilocks {
    const BYTES: usize = 8;

    #[inline]
    fn zero() -> Self {
        Self(0)
    }
    #[inline]
    fn one() -> Self {
        Self(1)
    }

    fn inverse(&self) -> Option<Self> {
        if self.0 == 0 {
            return None;
        }
        // Fermat's little theorem: a^(P-2) = a^-1 in F_P.
        // P - 2 = 0xFFFF_FFFF_0000_0001 - 2 = 0xFFFF_FFFF_FFFF_FFFF.
        // We exponentiate by P - 2 using a simple square-and-multiply.
        let mut base = *self;
        let exp: u64 = P - 2;
        let mut acc = Self::one();
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                acc = acc * base;
            }
            base = base.square();
            e >>= 1;
        }
        Some(acc)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, P3qError> {
        if bytes.len() != Self::BYTES {
            return Err(P3qError::InvalidEncoding("goldilocks element must be 8 bytes"));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(bytes);
        let raw = u64::from_le_bytes(buf);
        if raw >= P {
            return Err(P3qError::FieldOutOfRange);
        }
        Ok(Self(raw))
    }
}

impl Add for Goldilocks {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        let (s, c) = self.0.overflowing_add(rhs.0);
        // If we overflowed 2^64, subtract P which equals (2^64 - 2^32 + 1):
        // overflow contributes 2^64 ≡ 2^32 - 1 mod P.
        let mut out = s;
        if c {
            out = out.wrapping_sub(P);
        }
        if out >= P {
            out = out.wrapping_sub(P);
        }
        Self(out)
    }
}

impl Sub for Goldilocks {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        let (d, b) = self.0.overflowing_sub(rhs.0);
        let out = if b { d.wrapping_add(P) } else { d };
        Self(out)
    }
}

impl Neg for Goldilocks {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        if self.0 == 0 {
            self
        } else {
            Self(P - self.0)
        }
    }
}

impl Mul for Goldilocks {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        let prod = self.0 as u128 * rhs.0 as u128;
        Self::reduce_u128(prod)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_one() {
        let z = Goldilocks::zero();
        let o = Goldilocks::one();
        assert_eq!(z + o, o);
        assert_eq!(o * o, o);
        assert_eq!(-z, z);
    }

    #[test]
    fn inverse_roundtrip() {
        let a = Goldilocks::from_u64(123_456_789);
        let inv = a.inverse().expect("nonzero element has inverse");
        assert_eq!(a * inv, Goldilocks::one());
    }

    #[test]
    fn inverse_of_zero_is_none() {
        assert!(Goldilocks::zero().inverse().is_none());
    }

    #[test]
    fn bytes_roundtrip() {
        let a = Goldilocks::from_u64(0xDEAD_BEEF);
        let b = Goldilocks::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn non_canonical_bytes_rejected() {
        let bad = (P).to_le_bytes(); // exactly P is non-canonical
        assert!(matches!(
            Goldilocks::from_bytes(&bad),
            Err(P3qError::FieldOutOfRange)
        ));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(matches!(
            Goldilocks::from_bytes(&[0; 7]),
            Err(P3qError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn addition_mod_p() {
        // (P-1) + 1 == 0
        let a = Goldilocks::from_u64(P - 1);
        assert_eq!(a + Goldilocks::one(), Goldilocks::zero());
    }

    #[test]
    fn multiplication_mod_p() {
        // 2^32 * 2^32 = 2^64 ≡ 2^32 - 1
        let a = Goldilocks::from_u64(1u64 << 32);
        let want = Goldilocks::from_u64((1u64 << 32) - 1);
        assert_eq!(a * a, want);
    }

    /// Spot-check `reduce_u128` against the naive `u128 % P` for a
    /// fixed corpus of inputs that exercise carry / borrow paths.
    #[test]
    fn reduction_matches_naive_mod() {
        let inputs: &[u128] = &[
            0,
            1,
            P as u128 - 1,
            P as u128,
            P as u128 + 1,
            (1u128 << 64) - 1,
            (1u128 << 64),
            (1u128 << 96),
            (1u128 << 127),
            u128::MAX,
            (P as u128) * (P as u128 - 1),
            0xDEAD_BEEF_CAFE_BABE_1234_5678_9ABC_DEF0,
        ];
        for &x in inputs {
            let want = (x % P as u128) as u64;
            let got = Goldilocks::reduce_u128(x).0;
            assert_eq!(got, want, "reduce_u128({x:#034x}) = {got:#018x} but expected {want:#018x}");
        }
    }

    #[test]
    fn random_mul_matches_naive() {
        // Pseudo-random LCG; deterministic so the test is reproducible.
        let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
        for _ in 0..1024 {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let a = s % P;
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let b = s % P;
            let want = ((a as u128) * (b as u128) % (P as u128)) as u64;
            let got = (Goldilocks(a) * Goldilocks(b)).0;
            assert_eq!(got, want, "{a} * {b} mod P");
        }
    }
}
