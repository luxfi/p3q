//! The AIR DEEP-STARK proof envelope.
//!
//! Construction (DEEP-ALI, à la Winterfell / Plonky3, strict-PQ):
//!
//! 1. The prover commits the execution trace `T` (all `w` columns) as a
//!    row-major Merkle tree over the LDE domain `D` → `trace_root`.
//! 2. Fiat-Shamir yields constraint-combination challenges `α_k`. The
//!    prover forms the composition `C(x) = Σ_k α_k · C_k(T(x), T(gx))`
//!    (which vanishes on the trace domain `H` iff every constraint
//!    holds) and the quotient `Q(x) = C(x) / Z_H(x)`, committed over `D`
//!    → `quotient_root`.
//! 3. Fiat-Shamir yields an out-of-domain point `ζ ∉ D`. The prover
//!    opens `T_j(ζ)`, `T_j(gζ)` for every column `j` and `Q(ζ)`
//!    ([`OodOpenings`]). The verifier checks the *constraint identity at
//!    ζ* directly — `Q(ζ)·Z_H(ζ) == Σ_k α_k·C_k(T(ζ), T(gζ))` — which by
//!    Schwartz-Zippel binds the committed quotient to the trace.
//! 4. The prover forms the DEEP composition
//!    `D_eep(x) = Σ_j γ_j·(T_j(x)−T_j(ζ))/(x−ζ)
//!              + Σ_j γ'_j·(T_j(x)−T_j(gζ))/(x−gζ)
//!              + γ_q·(Q(x)−Q(ζ))/(x−ζ)`,
//!    a polynomial low-degree IFF the opened OOD values are the genuine
//!    evaluations of the committed `T`, `Q`. FRI proves `D_eep` is
//!    low-degree.
//! 5. At each FRI query index `q`, the proof carries the authenticated
//!    openings of every `T_j` and `Q` at `q` ([`QueryColumns`]) so the
//!    verifier recomputes `D_eep(ω^q)` and checks it equals the FRI
//!    layer-0 value it authenticated.
//!
//! The single FRI low-degree engine and the fold math live in `p3q-fri`;
//! this crate supplies the AIR-specific composition, quotient, OOD
//! binding, and DEEP recomputation.

use p3q_field::Goldilocks;
use p3q_fri::engine::FriProofData;
use p3q_merkle::{Digest, MerkleProof};

/// Out-of-domain (OOD) openings at the DEEP point `ζ`. These are the
/// claimed evaluations the verifier binds via the constraint identity
/// and the DEEP composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OodOpenings {
    /// `T_j(ζ)` for each trace column `j` (length = width).
    pub trace_at_zeta: Vec<Goldilocks>,
    /// `T_j(g·ζ)` for each trace column `j` (length = width).
    pub trace_at_g_zeta: Vec<Goldilocks>,
    /// `Q(ζ)` — the quotient polynomial at `ζ`.
    pub quotient_at_zeta: Goldilocks,
}

/// Per-FRI-query authenticated openings of the trace and quotient
/// codewords at the query index `q` and its fold-sibling index. These
/// let the verifier recompute the DEEP codeword value at both points and
/// cross-check against the FRI layer-0 echo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryColumns {
    /// Layer-0 query index `q`.
    pub index: u32,
    /// `T_j(ω^q)` for each column `j`.
    pub trace_value: Vec<Goldilocks>,
    /// `T_j(ω^{q ^ N/2})` for each column `j` (the FRI fold sibling).
    pub trace_sibling: Vec<Goldilocks>,
    /// Merkle path authenticating the row `q` of the trace tree.
    pub trace_auth: MerkleProof,
    /// Merkle path authenticating the row `q ^ N/2` of the trace tree.
    pub trace_sibling_auth: MerkleProof,
    /// `Q(ω^q)`.
    pub quotient_value: Goldilocks,
    /// `Q(ω^{q ^ N/2})`.
    pub quotient_sibling: Goldilocks,
    /// Merkle path authenticating `Q(ω^q)`.
    pub quotient_auth: MerkleProof,
    /// Merkle path authenticating `Q(ω^{q ^ N/2})`.
    pub quotient_sibling_auth: MerkleProof,
}

/// An authenticated opening of one trace cell at a fixed boundary row.
/// Pins `trace[col](row) == value` directly against the committed trace,
/// at the exact LDE index `row · blowup`. Exact-point equality — sound
/// without Schwartz-Zippel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryOpening {
    /// LDE row index (`= trace_row · blowup`) that was opened.
    pub lde_index: u32,
    /// The full trace row (all `w` columns) at `lde_index`.
    pub row: Vec<Goldilocks>,
    /// Merkle path authenticating the row against `trace_root`.
    pub auth: MerkleProof,
}

/// A complete AIR DEEP-STARK proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AirProof {
    /// log2 of the trace length (trace domain `H` size).
    pub log_trace_rows: u32,
    /// log2 of the LDE blowup factor.
    pub log_blowup: u32,
    /// Row-major Merkle commitment to the trace LDE.
    pub trace_root: Digest,
    /// Merkle commitment to the quotient LDE.
    pub quotient_root: Digest,
    /// Merkle commitment to the DEEP composition codeword (the FRI
    /// layer-0 root). Carried explicitly so the verifier can replay the
    /// transcript: the FRI engine treats layer-0's root as a value
    /// supplied by the caller, so it is not inside [`FriProofData`].
    pub deep_root: Digest,
    /// OOD openings at `ζ` (transition-constraint binding).
    pub ood: OodOpenings,
    /// Authenticated boundary-row openings, one per distinct boundary
    /// LDE row (deduplicated). Exact-point boundary-constraint binding.
    pub boundary_openings: Vec<BoundaryOpening>,
    /// FRI low-degree proof of the DEEP composition codeword.
    pub fri: FriProofData,
    /// Per-query trace + quotient openings, aligned with `fri.queries`.
    pub query_columns: Vec<QueryColumns>,
}
