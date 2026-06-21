//! Evaluation-domain helpers for the generic FRI verifier.
//!
//! These are re-exported from [`p3q_fri::domain`] — there is exactly one
//! definition of the FRI fold formula and the LDE-domain math across the
//! workspace (DRY). The generic single-polynomial verifier in
//! [`crate::verify`] and the AIR DEEP-STARK in `p3q-stark` both call the
//! same functions. See the source module for the full conventions and
//! the fold-rule derivation.

pub use p3q_fri::domain::{fri_fold, horner, lde_generator, point_at_index};

// `sibling_index` is only used by the toy prover and tests; surface it
// under the same `cfg` gate so the production verifier build does not
// pull an unused symbol.
#[cfg(any(test, feature = "prover"))]
pub use p3q_fri::domain::sibling_index;
