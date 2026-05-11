// P3Q FIPS 202 / SP 800-185 hash primitives. Strict-PQ profile uses
// cSHAKE256, KMAC256 and TupleHash256 throughout — same hash family as
// ML-DSA-65 (FIPS 204) and Pulsar-M (HIP-0084).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! cSHAKE256 / KMAC256 / TupleHash256 wrappers. Domain separation is
//! enforced at construction; callers cannot accidentally collide
//! transcripts even if they absorb byte-identical content.

pub mod cshake;
pub mod kmac;
pub mod tuple;

pub use cshake::CShake256;
pub use kmac::Kmac256;
pub use tuple::TupleHash256;

/// Output size used across the P3Q strict-PQ profile: 32 bytes
/// (256-bit collision resistance against classical attackers; 128-bit
/// against quantum Grover).
pub const OUTPUT_BYTES: usize = 32;
