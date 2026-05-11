// P3Q field primitives. Strict-PQ STARK profiles use small primes;
// Goldilocks (p = 2^64 - 2^32 + 1) is the production default.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! P3Q field crate: trait surface plus the Goldilocks concrete field.

pub mod goldilocks;
pub mod traits;

pub use goldilocks::Goldilocks;
pub use traits::Field;
