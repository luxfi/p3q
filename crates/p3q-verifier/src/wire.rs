//! Wire format for P3Q strict-PQ STARK proofs.
//!
//! The body bytes (after the leading `ProofSystemId`) follow a single
//! canonical layout regardless of profile (`SHA3` vs `Keccak`). The
//! profile byte only changes the transcript domain separation; the
//! envelope structure is identical.
//!
//! ```text
//! BODY:
//!   HEADER (10 bytes, big-endian):
//!     version             u8  (= 0x01, anything else is rejected)
//!     log_degree_bound    u8  (1..=20)  log2 of upper bound on poly degree
//!     log_blowup          u8  (1..=5)
//!     log_arity           u8  (== 1 in v1; binary folding only)
//!     num_queries         u8  (1..=64)
//!     log_final_poly      u8  (0..=10)  log_blowup <= log_final_poly < log_degree_bound
//!     flags               u8  (reserved, must be 0)
//!     reserved            u8  (must be 0)
//!     public_input_len    u16 BE
//!   PUBLIC_INPUT          public_input_len bytes (echoed; must match caller's pi)
//!   TRACE_ROOT            32 bytes
//!   FRI_LAYER_ROOTS       (num_layers - 1) * 32 bytes
//!                         num_layers = log_degree_bound + log_blowup - log_final_poly
//!   FINAL_POLY_LEN        u16 BE (must equal 2^log_final_poly)
//!   FINAL_POLY            FINAL_POLY_LEN * 8 bytes  (Goldilocks LE)
//!   QUERY_OPENINGS        num_queries * <see [`QueryOpening`]>
//! ```
//!
//! Per-query opening layout:
//! ```text
//!   query_index           u32 BE  (re-derived from transcript; verifier compares)
//!   trace_value           8 bytes
//!   trace_path_len        u8
//!   trace_path            trace_path_len * 32 bytes
//!   per layer (num_layers - 1 times):
//!     layer_value         8 bytes
//!     layer_sibling       8 bytes              // arity = 2 => 1 sibling
//!     layer_path_len      u8
//!     layer_path          layer_path_len * 32 bytes
//! ```
//!
//! Every length, range and well-formedness check happens here, BEFORE
//! any cryptographic work — the verifier rejects ill-formed proofs in
//! O(parse) time without touching the transcript. The soundness floor
//! ([`MIN_SOUNDNESS_BITS`]) is checked earlier still, off the ten
//! header bytes, before a single query opening is allocated.

use p3q_core::{P3qError, Result};
use p3q_field::{Field, Goldilocks};
use p3q_merkle::{Digest, MerkleProof};

/// Wire-format version emitted by this crate.
pub const WIRE_VERSION: u8 = 0x01;

/// Fixed binary folding arity. Wider arities are reserved for v2.
pub const FOLD_ARITY_LOG2: u8 = 1;

/// Header byte width.
pub const HEADER_LEN: usize = 10;

/// Query-phase soundness a proof must carry to be admissible, in bits.
///
/// FRI's query phase repeats an independent consistency check `q =
/// num_queries` times against a codeword of rate `ρ = 2^-log_blowup`.
/// A prover committed to a word `δ`-far from the code survives one
/// query with probability `1 - δ`, so the query-phase soundness error
/// is `(1 - δ)^q`, and how large `δ` may be is exactly what the
/// proximity theorem in force allows:
///
/// | proximity bound                      | max δ                | error       | bits per query |
/// |--------------------------------------|----------------------|-------------|----------------|
/// | unique decoding (BBHR18)             | `(1-ρ)/2`            | `((1+ρ)/2)^q` | 0.42 … 0.96  |
/// | Johnson, provable (BCIKS20 Thm 8.3)  | `1-√ρ-√ρ/2m`         | `(√ρ(1+1/2m))^q` | ≈ b/2     |
/// | capacity, conjectured (ethSTARK 5.6) | `1-ρ`                | `ρ^q`       | b              |
///
/// This constant is stated in the **capacity** metric, where one query
/// buys exactly `log_blowup` bits, so admissibility is the integer
/// predicate `log_blowup * num_queries >= MIN_SOUNDNESS_BITS` — no
/// floating point, no table, identical on every platform, which is
/// what a consensus rule needs. Under the provable Johnson bound the
/// same parameters deliver about half as much (128 capacity bits ≈ 61
/// provable bits at `log_blowup = 2, num_queries = 64`).
///
/// 128 rather than the common 100: `num_queries` is capped at 64 by
/// the wire, so the reachable settings are `log_blowup ∈ {2,3,4,5}`
/// with `num_queries ≥ {64,43,32,26}` — every blowup but rate-1/2
/// stays usable, and rate-1/2 cannot reach 128 bits under *any* of the
/// three bounds with 64 queries, so excluding it costs nothing real.
/// Raising a consensus floor later invalidates proofs already minted
/// under it, so it is set once, high, before anything is deployed.
///
/// This bounds the QUERY phase only. The commit phase is bounded by
/// the proximity-gap term, which scales as `N²/|F|` for domain size
/// `N` and challenge field `F`; challenges here are drawn from the
/// Goldilocks BASE field (`|F| < 2^64`), which caps commit-phase
/// soundness at `64 - 2*log_lde` bits before constants — about 18 bits
/// at `log_lde = 16`. No number of queries moves that; only a wider
/// challenge field does.
pub const MIN_SOUNDNESS_BITS: u32 = 128;

/// Decoded header. Every field is bounds-checked in [`Header::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// log2 of upper bound on degree of the committed polynomial.
    pub log_degree_bound: u8,
    /// log2 of evaluation-domain blowup factor.
    pub log_blowup: u8,
    /// log2 of FRI folding arity (must be 1 in v1).
    pub log_arity: u8,
    /// Number of random FRI queries.
    pub num_queries: u8,
    /// log2 of the final-polynomial layer size.
    pub log_final_poly: u8,
    /// Public-input length echoed for transcript binding.
    pub public_input_len: u16,
}

impl Header {
    /// Bits of query-phase soundness these parameters deliver, in the
    /// capacity metric one query buys `log_blowup` bits. See
    /// [`MIN_SOUNDNESS_BITS`] for the three proximity regimes and why
    /// this is the one the floor is stated in.
    ///
    /// Widest value is `5 * 64 = 320`, so the product never overflows.
    #[inline]
    pub const fn soundness_bits(&self) -> u32 {
        self.log_blowup as u32 * self.num_queries as u32
    }

    /// How many coefficients the FRI degree ladder leaves alive in
    /// `final_poly`.
    ///
    /// Layer 0 claims degree `< 2^log_degree_bound` over a domain of
    /// `2^log_lde` points. Each fold halves domain AND degree bound, so
    /// after `num_fri_rounds = log_lde - log_final_poly` folds the
    /// surviving bound is
    ///
    /// ```text
    /// 2^(log_degree_bound - num_fri_rounds) = 2^(log_final_poly - log_blowup)
    /// ```
    ///
    /// The final layer is sent as `2^log_final_poly` coefficients —
    /// `2^log_blowup` times more room than the ladder permits. Every
    /// coefficient past this count MUST be zero; that gap is the
    /// degree bound, and it is the only place the claim
    /// "`log_degree_bound`" is enforced at all.
    ///
    /// Saturating so an unchecked header cannot underflow; on an
    /// admissible header (`log_final_poly >= log_blowup`) it is exact.
    #[inline]
    pub const fn final_poly_terms(&self) -> usize {
        1usize << self.log_final_poly.saturating_sub(self.log_blowup)
    }

    /// The one admissibility predicate: every constraint on the header
    /// VALUES, in one place, so each entry point into the verifier asks
    /// the same question. [`decode`](Self::decode) calls it for proofs
    /// arriving over the wire; the kernel calls it for `Header` values
    /// built in memory. Neither owns a copy of the policy.
    ///
    /// This is not a range check. A range check asks of each field
    /// alone "is this byte encodable", and its job is to make parsing
    /// total; every field here already passes one. This asks of the
    /// TUPLE "do these parameters describe a sound instance", and its
    /// job is to make acceptance mean something. The two are different
    /// shapes: `(log_blowup=1, num_queries=64)` and
    /// `(log_blowup=5, num_queries=1)` sit inside every range and
    /// neither is admissible, because the admissible set is bounded by
    /// `log_blowup * num_queries`, a hyperbola, and no box contains
    /// exactly the region above a hyperbola.
    pub fn check_admissible(&self) -> Result<()> {
        if !(1..=20).contains(&self.log_degree_bound) {
            return Err(P3qError::InvalidEncoding(
                "header: log_degree_bound out of range",
            ));
        }
        if !(1..=5).contains(&self.log_blowup) {
            return Err(P3qError::InvalidEncoding("header: log_blowup out of range"));
        }
        if self.log_arity != FOLD_ARITY_LOG2 {
            return Err(P3qError::InvalidEncoding(
                "header: log_arity must be 1 (binary fold only in v1)",
            ));
        }
        if !(1..=64).contains(&self.num_queries) {
            return Err(P3qError::InvalidEncoding(
                "header: num_queries out of range",
            ));
        }
        if self.log_final_poly > 10 {
            return Err(P3qError::InvalidEncoding(
                "header: log_final_poly out of range",
            ));
        }
        // Folding must terminate strictly before the final layer.
        if self.log_final_poly >= self.log_degree_bound {
            return Err(P3qError::InvalidEncoding(
                "header: log_final_poly >= log_degree_bound",
            ));
        }
        // ...and must not run PAST degree 1: after `num_fri_rounds`
        // folds the surviving degree bound is
        // `2^(log_final_poly - log_blowup)`, which is a whole
        // coefficient only while `log_final_poly >= log_blowup`. Below
        // that the ladder claims "degree < 1", i.e. the final
        // polynomial is identically zero — a claim no honest prover
        // with a non-zero trace can make, so the configuration is
        // degenerate rather than merely wasteful.
        if self.log_final_poly < self.log_blowup {
            return Err(P3qError::InvalidEncoding(
                "header: log_final_poly < log_blowup (folds past degree 1)",
            ));
        }
        if self.soundness_bits() < MIN_SOUNDNESS_BITS {
            return Err(P3qError::InvalidEncoding(
                "header: parameters below the soundness floor",
            ));
        }
        Ok(())
    }

    /// Decode 10 bytes into a header. The two reserved bytes are facts
    /// about the ENCODING and are checked here; every constraint on the
    /// decoded values comes from [`check_admissible`](Self::check_admissible),
    /// so a `Header` returned from this function is admissible.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            return Err(P3qError::InvalidLength("header: short"));
        }
        if buf[0] != WIRE_VERSION {
            return Err(P3qError::InvalidEncoding("header: wrong version"));
        }
        if buf[6] != 0 {
            return Err(P3qError::InvalidEncoding(
                "header: reserved flags must be 0",
            ));
        }
        if buf[7] != 0 {
            return Err(P3qError::InvalidEncoding("header: reserved byte must be 0"));
        }
        let header = Self {
            log_degree_bound: buf[1],
            log_blowup: buf[2],
            log_arity: buf[3],
            num_queries: buf[4],
            log_final_poly: buf[5],
            public_input_len: u16::from_be_bytes([buf[8], buf[9]]),
        };
        header.check_admissible()?;
        Ok(header)
    }

    /// log2 of the LDE domain size.
    #[inline]
    pub fn log_lde(&self) -> u32 {
        self.log_degree_bound as u32 + self.log_blowup as u32
    }

    /// Total number of FRI folding rounds (= number of layer roots
    /// committed). The final polynomial is the value after this many
    /// folds; it is not Merkle-committed.
    #[inline]
    pub fn num_fri_rounds(&self) -> u32 {
        self.log_lde() - self.log_final_poly as u32
    }

    /// Encode the header back to bytes (used by the toy prover and by
    /// transcript binding in the verifier).
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let pi_len = self.public_input_len.to_be_bytes();
        [
            WIRE_VERSION,
            self.log_degree_bound,
            self.log_blowup,
            self.log_arity,
            self.num_queries,
            self.log_final_poly,
            0,
            0,
            pi_len[0],
            pi_len[1],
        ]
    }
}

/// A query opening over one FRI commit layer (layer i in
/// `1..num_rounds`).
///
/// `value` is the codeword evaluation at the layer's queried index,
/// authenticated against `fri_layer_roots[i-1]` via `value_auth`.
/// `sibling` is the codeword evaluation at the FRI-fold-natural
/// sibling index `value_index ^ (N_i / 2)` — also authenticated against
/// the same root via `sibling_auth`. The verifier folds the pair using
/// the round challenge `r_i` to obtain the expected evaluation in the
/// next layer.
///
/// We carry TWO independent auth paths rather than a single "pair"
/// path because the FRI-fold sibling and the leaf-level sibling are
/// different indices: under our wire layout, the codeword evaluations
/// are stored in natural order, so `value_index` and
/// `value_index ^ (N/2)` are sibling subtrees at the ROOT of the
/// Merkle tree — not leaf-level siblings. A v2 wire could switch to a
/// bit-reverse leaf permutation and collapse to one auth path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerOpening {
    /// Goldilocks element at the queried index in this layer.
    pub value: Goldilocks,
    /// Sibling element (binary folding => one sibling per round).
    pub sibling: Goldilocks,
    /// Merkle authentication path for `value`.
    pub value_auth: MerkleProof,
    /// Merkle authentication path for `sibling`.
    pub sibling_auth: MerkleProof,
}

/// One full query opening: the trace pair + every FRI-layer pair.
///
/// Wire layout:
/// ```text
/// query_index           u32 BE
/// trace_value           8 bytes  // eval at q
/// trace_conj_value      8 bytes  // eval at q ^ (N/2)
/// trace_value_auth_len  u8       // == log_lde
/// trace_value_auth_path log_lde * 32 bytes
/// trace_conj_auth_len   u8       // == log_lde
/// trace_conj_auth_path  log_lde * 32 bytes
/// per FRI commit layer i in 1..num_rounds:
///   layer_value         8 bytes  // eval at q >> i
///   layer_sibling       8 bytes  // eval at (q >> i) ^ (N_i / 2)
///   layer_value_auth_len    u8   // == log_lde - i
///   layer_value_auth_path   (log_lde - i) * 32 bytes
///   layer_sibling_auth_len  u8   // == log_lde - i
///   layer_sibling_auth_path (log_lde - i) * 32 bytes
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOpening {
    /// Index this opening was sampled at (echoed from the proof; the
    /// verifier re-derives it from the transcript and rejects on
    /// mismatch).
    pub query_index: u32,
    /// Goldilocks trace value at `query_index`.
    pub trace_value: Goldilocks,
    /// Trace value at the FRI-fold conjugate index
    /// `query_index ^ (N/2)`.
    pub trace_conj_value: Goldilocks,
    /// Merkle authentication path for `trace_value` against
    /// `trace_root`.
    pub trace_auth: MerkleProof,
    /// Merkle authentication path for `trace_conj_value` against
    /// `trace_root`.
    pub trace_conj_auth: MerkleProof,
    /// One opening per FRI commit layer (i.e. layers 1..num_rounds);
    /// length = `num_rounds - 1`. The final layer is sent as the
    /// explicit `final_poly` so it has no per-query opening.
    pub layers: Vec<LayerOpening>,
}

/// Top-level decoded proof. Once a `ParsedProof` exists, every
/// length / encoding / range check has already passed — the verifier
/// only needs to do cryptographic work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProof {
    /// Header (bounds-checked).
    pub header: Header,
    /// Public-input bytes embedded in the proof (echoed by caller for
    /// transcript binding).
    pub public_input: Vec<u8>,
    /// Trace LDE commitment root.
    pub trace_root: Digest,
    /// FRI layer commitment roots, length = `num_fri_rounds - 1`.
    /// The final layer is the explicit polynomial, not a Merkle root.
    pub fri_layer_roots: Vec<Digest>,
    /// Final polynomial in evaluation form, length `2^log_final_poly`.
    /// (Coefficient form is equivalent — we treat it as evaluations on
    /// the final layer's coset.)
    pub final_poly: Vec<Goldilocks>,
    /// Per-query openings, length `num_queries`.
    pub queries: Vec<QueryOpening>,
}

/// Cursor for sequential byte parsing with explicit error variants.
struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .off
            .checked_add(n)
            .ok_or(P3qError::InvalidLength("cursor: offset overflow"))?;
        if end > self.buf.len() {
            return Err(P3qError::InvalidLength("cursor: short read"));
        }
        let slice = &self.buf[self.off..end];
        self.off = end;
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.read(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }

    fn read_digest(&mut self) -> Result<Digest> {
        self.read_array::<32>()
    }

    fn read_field(&mut self) -> Result<Goldilocks> {
        let bytes = self.read(Goldilocks::BYTES)?;
        Goldilocks::from_bytes(bytes)
    }

    fn read_merkle_path(&mut self, max_len: usize) -> Result<MerkleProof> {
        let len = self.read_u8()? as usize;
        if len > max_len {
            return Err(P3qError::InvalidEncoding(
                "merkle path: length exceeds domain log",
            ));
        }
        let mut siblings = Vec::with_capacity(len);
        for _ in 0..len {
            siblings.push(self.read_digest()?);
        }
        Ok(MerkleProof { siblings })
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.off)
    }
}

/// Parse a proof body into a [`ParsedProof`]. Every length / range
/// check is enforced before returning.
pub fn parse(body: &[u8]) -> Result<ParsedProof> {
    let mut cur = Cursor::new(body);

    // ---- Header ----
    let header_bytes = cur.read(HEADER_LEN)?;
    let header = Header::decode(header_bytes)?;

    // ---- Public input ----
    let public_input = cur.read(header.public_input_len as usize)?.to_vec();

    // ---- Trace root ----
    let trace_root = cur.read_digest()?;

    // ---- FRI layer roots ----
    let num_rounds = header.num_fri_rounds();
    if num_rounds == 0 {
        return Err(P3qError::InvalidEncoding(
            "header: zero FRI rounds (degenerate)",
        ));
    }
    let num_layer_roots = (num_rounds - 1) as usize;
    let mut fri_layer_roots = Vec::with_capacity(num_layer_roots);
    for _ in 0..num_layer_roots {
        fri_layer_roots.push(cur.read_digest()?);
    }

    // ---- Final polynomial ----
    let expected_final = 1usize << header.log_final_poly;
    let final_len = cur.read_u16_be()? as usize;
    if final_len != expected_final {
        return Err(P3qError::InvalidEncoding(
            "final polynomial: length mismatch",
        ));
    }
    let mut final_poly = Vec::with_capacity(final_len);
    for _ in 0..final_len {
        final_poly.push(cur.read_field()?);
    }

    // ---- Per-query openings ----
    let log_lde = header.log_lde() as usize;
    let num_layer_openings = num_rounds as usize - 1; // final layer is sent as final_poly
    let mut queries = Vec::with_capacity(header.num_queries as usize);
    for _ in 0..header.num_queries {
        let query_index = cur.read_u32_be()?;
        if (query_index as u64) >= (1u64 << log_lde) {
            return Err(P3qError::InvalidEncoding("query: index out of LDE domain"));
        }
        let trace_value = cur.read_field()?;
        let trace_conj_value = cur.read_field()?;
        let trace_auth = cur.read_merkle_path(log_lde)?;
        if trace_auth.siblings.len() != log_lde {
            return Err(P3qError::InvalidEncoding(
                "query: trace auth path length must equal log(LDE)",
            ));
        }
        let trace_conj_auth = cur.read_merkle_path(log_lde)?;
        if trace_conj_auth.siblings.len() != log_lde {
            return Err(P3qError::InvalidEncoding(
                "query: trace conj auth path length must equal log(LDE)",
            ));
        }
        let mut layers = Vec::with_capacity(num_layer_openings);
        // layer_idx in 0..num_layer_openings corresponds to FRI commit
        // layer (layer_idx + 1) in the verifier — the layer that lives
        // in the (layer_idx + 1)-th committed Merkle tree.
        //
        // At layer (layer_idx + 1), the domain has log-size
        // `log_lde - (layer_idx + 1)`, so each auth path has that depth.
        for layer_idx in 0..num_layer_openings {
            let value = cur.read_field()?;
            let sibling = cur.read_field()?;
            let expected_depth = log_lde - (layer_idx + 1);
            let value_auth = cur.read_merkle_path(expected_depth)?;
            if value_auth.siblings.len() != expected_depth {
                return Err(P3qError::InvalidEncoding(
                    "query: layer value auth path length mismatch",
                ));
            }
            let sibling_auth = cur.read_merkle_path(expected_depth)?;
            if sibling_auth.siblings.len() != expected_depth {
                return Err(P3qError::InvalidEncoding(
                    "query: layer sibling auth path length mismatch",
                ));
            }
            layers.push(LayerOpening {
                value,
                sibling,
                value_auth,
                sibling_auth,
            });
        }
        queries.push(QueryOpening {
            query_index,
            trace_value,
            trace_conj_value,
            trace_auth,
            trace_conj_auth,
            layers,
        });
    }

    if cur.remaining() != 0 {
        return Err(P3qError::InvalidEncoding(
            "trailing bytes after final query",
        ));
    }

    Ok(ParsedProof {
        header,
        public_input,
        trace_root,
        fri_layer_roots,
        final_poly,
        queries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cheapest admissible header: exactly `MIN_SOUNDNESS_BITS`,
    /// and `log_blowup <= log_final_poly < log_degree_bound`.
    fn good_header() -> Header {
        Header {
            log_degree_bound: 3,
            log_blowup: 2,
            log_arity: 1,
            num_queries: 64,
            log_final_poly: 2,
            public_input_len: 4,
        }
    }

    #[test]
    fn header_round_trip() {
        let h = good_header();
        let b = h.encode();
        let h2 = Header::decode(&b).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn header_rejects_wrong_version() {
        let mut b = good_header().encode();
        b[0] = 0x02;
        assert!(matches!(
            Header::decode(&b),
            Err(P3qError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn header_rejects_non_binary_arity() {
        let mut b = good_header().encode();
        b[3] = 2;
        assert!(matches!(
            Header::decode(&b),
            Err(P3qError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn header_rejects_final_geq_degree() {
        let mut b = good_header().encode();
        b[5] = b[1]; // log_final_poly == log_degree_bound
        assert!(matches!(
            Header::decode(&b),
            Err(P3qError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn header_rejects_reserved_nonzero() {
        let mut b = good_header().encode();
        b[6] = 1; // flags
        assert!(matches!(
            Header::decode(&b),
            Err(P3qError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn header_rejects_short_buf() {
        assert!(matches!(
            Header::decode(&[0u8; 4]),
            Err(P3qError::InvalidLength(_))
        ));
    }

    /// The floor decides the whole `(log_blowup, num_queries)` grid,
    /// and decides it by the PRODUCT. Every point in the range is
    /// admissible exactly when `log_blowup * num_queries >=
    /// MIN_SOUNDNESS_BITS` — so this pins the boundary at every blowup
    /// at once: one query below the line refuses, one query on it
    /// accepts. A per-field minimum would fail here, because the
    /// admissible region is not a box.
    #[test]
    fn floor_is_a_product_not_a_box() {
        for log_blowup in 1u8..=5 {
            let mut seen_boundary = false;
            for num_queries in 1u8..=64 {
                let h = Header {
                    log_degree_bound: log_blowup + 1,
                    log_blowup,
                    log_arity: FOLD_ARITY_LOG2,
                    num_queries,
                    log_final_poly: log_blowup,
                    public_input_len: 0,
                };
                let bits = log_blowup as u32 * num_queries as u32;
                assert_eq!(h.soundness_bits(), bits);
                let want = bits >= MIN_SOUNDNESS_BITS;
                assert_eq!(
                    h.check_admissible().is_ok(),
                    want,
                    "log_blowup={log_blowup} num_queries={num_queries} ({bits} bits)"
                );
                // Round-tripping through the wire must not change the
                // verdict: the floor is not an in-memory-only rule.
                assert_eq!(Header::decode(&h.encode()).is_ok(), want);
                if want && !seen_boundary {
                    seen_boundary = true;
                    assert!(
                        num_queries == 1 || {
                            let below = log_blowup as u32 * (num_queries - 1) as u32;
                            below < MIN_SOUNDNESS_BITS
                        },
                        "boundary is not tight at log_blowup={log_blowup}"
                    );
                }
            }
            // Rate 1/2 cannot reach the floor with 64 queries under any
            // proximity bound, so it must be unreachable entirely.
            if log_blowup == 1 {
                assert!(!seen_boundary, "log_blowup=1 must be unreachable");
            } else {
                assert!(seen_boundary, "log_blowup={log_blowup} must be reachable");
            }
        }
    }

    /// The degree ladder must not run past degree 1: after
    /// `num_fri_rounds` folds the surviving bound is
    /// `2^(log_final_poly - log_blowup)`, so `log_final_poly` below
    /// `log_blowup` claims the final polynomial is identically zero.
    #[test]
    fn header_rejects_folding_past_degree_one() {
        let mut h = good_header();
        h.log_final_poly = h.log_blowup - 1;
        assert!(matches!(
            h.check_admissible(),
            Err(P3qError::InvalidEncoding(_))
        ));
        assert!(matches!(
            Header::decode(&h.encode()),
            Err(P3qError::InvalidEncoding(_))
        ));
    }

    /// `final_poly_terms` is the ladder's arithmetic, so it must agree
    /// with walking the ladder one fold at a time.
    #[test]
    fn final_poly_terms_matches_the_ladder() {
        for log_blowup in 2u8..=5 {
            for log_final_poly in log_blowup..=10 {
                for log_degree_bound in (log_final_poly + 1)..=12 {
                    let h = Header {
                        log_degree_bound,
                        log_blowup,
                        log_arity: FOLD_ARITY_LOG2,
                        num_queries: 64,
                        log_final_poly,
                        public_input_len: 0,
                    };
                    // Halve the degree bound once per fold round.
                    let mut bound = 1u64 << log_degree_bound;
                    for _ in 0..h.num_fri_rounds() {
                        bound /= 2;
                    }
                    assert_eq!(h.final_poly_terms() as u64, bound.max(1));
                    assert!(h.final_poly_terms() <= 1usize << log_final_poly);
                }
            }
        }
    }

    #[test]
    fn parse_rejects_truncated_body() {
        // Just the header — no trace root, public input, etc.
        let h = good_header().encode();
        assert!(matches!(parse(&h), Err(P3qError::InvalidLength(_))));
    }
}
