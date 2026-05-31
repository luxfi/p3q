// P3Q FIPS 202 / SP 800-185 hash primitives. Strict-PQ profile uses
// cSHAKE256, KMAC256 and TupleHash256 throughout — same hash family as
// ML-DSA-65 (FIPS 204) and Pulsar-M (HIP-0084).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! cSHAKE256 / KMAC256 / TupleHash256 wrappers. Domain separation is
//! enforced at construction; callers cannot accidentally collide
//! transcripts even if they absorb byte-identical content.
//!
//! Two flavours of API are exposed:
//!
//! - **Stateful** (`CShake256`, `TupleHash256`, `Kmac256`): incremental
//!   absorb / finalize for ad-hoc single-shot use. Always CPU.
//! - **Batched** (`cshake256_batch`, `tuple_hash256_batch`,
//!   `kmac256_batch`): take a slice of complete inputs and fan out to
//!   a [`backend::Sha3Backend`]. The default backend is CPU; with
//!   `--features gpu-sha3` (and libluxgpu available at runtime) the
//!   default flips to GPU SHAKE256 batch.

pub mod backend;
pub mod batch;
pub mod cshake;
pub mod kmac;
pub mod tuple;

pub use backend::{default_backend, CpuShake, Sha3Backend};
pub use batch::{cshake256_batch, kmac256_batch, tuple_hash256_batch};
pub use batch::{CShakeInput, KmacInput, TupleInput};
pub use cshake::CShake256;
pub use kmac::Kmac256;
pub use tuple::TupleHash256;

/// Output size used across the P3Q strict-PQ profile: 32 bytes
/// (256-bit collision resistance against classical attackers; 128-bit
/// against quantum Grover).
pub const OUTPUT_BYTES: usize = 32;
