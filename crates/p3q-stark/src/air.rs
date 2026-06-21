//! AIR constraint-evaluation surface.
//!
//! This is the API everything downstream needs: the Plonky3 /
//! Winterfell-style symbolic constraint hook. An [`Air`] implementation
//! describes its transition and boundary constraints *once*, in terms of
//! an abstract [`AirBuilder`]; the prover and the verifier each supply a
//! different builder so the *same* `eval` body serves both:
//!
//! - The **prover** evaluates `eval` at every row of the low-degree
//!   extension (builder expression type = [`Goldilocks`]). The
//!   accumulated constraint values become the numerator of the quotient
//!   polynomial.
//! - The **verifier** evaluates `eval` at a single out-of-domain (OOD)
//!   point `ζ` drawn from the transcript, using the trace values the
//!   prover opened there, and checks the algebraic identity
//!   `quotient(ζ) · Z_H(ζ) == Σ αⁱ · Cᵢ(ζ)` (DEEP-ALI binding).
//!
//! Decomplected (Hickey): the constraint *definition* (this trait) is a
//! distinct concern from *evaluating a codeword's low-degreeness* (the
//! FRI kernel in `p3q-verifier`) and from *policy* (which circuit is
//! allowed). An `Air` knows only its own algebra. It never touches
//! Merkle trees, transcripts, or FRI.
//!
//! Strict-PQ: Goldilocks field + SHA-3 hash family only. No curve
//! arithmetic, no pairing-friendly extension fields.

use core::ops::{Add, Mul, Sub};

use p3q_field::Goldilocks;

/// A row pair presented to [`Air::eval`]: the trace cells of the current
/// row (`local`) and the next row (`next`), plus the circuit's public
/// inputs.
///
/// The constraint author reads cells by column index. Out-of-bounds
/// access is a circuit bug (the AIR declares its own `width()` /
/// `num_public_inputs()`); accessors panic only in debug builds via
/// `debug_assert`, and the prover/verifier glue guarantees the slices
/// are correctly sized before `eval` ever runs, so the production path
/// is panic-free.
///
/// `Expr` is the abstract expression type the builder works over. For
/// every builder in this crate `Expr = Goldilocks` (concrete
/// evaluation), but the trait is generic so a future symbolic
/// degree-tracking builder can slot in without touching any `Air`.
pub trait AirBuilder {
    /// The expression / value type constraints are built from.
    type Expr: Clone
        + Add<Output = Self::Expr>
        + Sub<Output = Self::Expr>
        + Mul<Output = Self::Expr>;

    /// Number of trace columns (matches the owning [`Air::width`]).
    fn width(&self) -> usize;

    /// Current-row cell at column `col`.
    fn local(&self, col: usize) -> Self::Expr;

    /// Next-row cell at column `col`. On the trace domain `H` this is the
    /// value one trace-domain step ahead (i.e. `T(g · x)`). The step is
    /// **cyclic**: the `next` of the last row (index `num_rows − 1`) is
    /// the *first* row (index `0`), because `g^{num_rows} = 1`. A
    /// constraint relating `local` and `next` is therefore evaluated on
    /// the wrap-around pair `(row n−1, row 0)` exactly like every other
    /// row — see [`Air::eval`] for the contract this imposes.
    fn next(&self, col: usize) -> Self::Expr;

    /// Public input at index `idx` (matches [`Air::num_public_inputs`]).
    fn public_input(&self, idx: usize) -> Self::Expr;

    /// Lift a field constant into the expression type.
    fn constant(&self, c: Goldilocks) -> Self::Expr;

    /// Assert that `expr` is zero on every row where the constraint
    /// applies. The builder *accumulates* these into its constraint
    /// vector (prover) or random-linear-combination (verifier). Calling
    /// this is how an `Air` states "this polynomial identity must hold".
    fn assert_zero(&mut self, expr: Self::Expr);

    /// Convenience: assert `a == b` (i.e. `a - b == 0`).
    fn assert_eq(&mut self, a: Self::Expr, b: Self::Expr) {
        self.assert_zero(a - b);
    }
}

/// An algebraic-intermediate-representation circuit.
///
/// An `Air` is fully described by three numbers (`width`, `num_rows`,
/// `num_public_inputs`) plus its [`Air::eval`] body. Everything else —
/// committing the trace, building the quotient, running FRI, OOD binding
/// — is generic machinery in the prover/verifier that consumes `eval`.
///
/// The constraint count [`Air::num_constraints`] MUST equal the number
/// of `assert_zero` calls `eval` makes per row (it is the length of the
/// random challenge vector the verifier draws to combine constraints).
/// A mismatch is caught by the prover/verifier glue, not silently
/// accepted.
pub trait Air: Send + Sync {
    /// Width of the execution trace (number of columns).
    fn width(&self) -> usize;

    /// Number of trace rows; MUST be a power of two (FRI / FFT domain).
    fn num_rows(&self) -> usize;

    /// Number of public-input field elements bound into the proof and
    /// available to `eval` via [`AirBuilder::public_input`].
    fn num_public_inputs(&self) -> usize;

    /// Number of independent constraint polynomials emitted per row by
    /// [`eval`](Air::eval) (i.e. the count of `assert_zero` calls). This
    /// fixes the length of the constraint-combination challenge vector.
    fn num_constraints(&self) -> usize;

    /// Highest total degree (in the trace columns) of any single
    /// constraint expression emitted by [`eval`](Air::eval). Governs the
    /// quotient degree and therefore the blowup the prover must use:
    /// the composition polynomial has degree `≤ (constraint_degree − 1)
    /// · (num_rows − 1)` after dividing by the degree-`num_rows`
    /// vanishing polynomial `Z_H`. A linear constraint (e.g. a copy) has
    /// degree 1; a single multiplication of two trace cells has degree
    /// 2.
    ///
    /// Returns the *maximum* constraint degree; the default of 3 is a
    /// safe upper bound for the simple AIRs in this crate (the
    /// Fibonacci AIR is degree 2, the Keccak χ step is degree 2). An
    /// `Air` with higher-degree constraints MUST override this.
    fn constraint_degree(&self) -> usize {
        3
    }

    /// Emit the circuit's constraints into `builder`. Called once per
    /// row by the prover (over the LDE) and once at the OOD point by the
    /// verifier. The body must be *pure*: deterministic in `builder`'s
    /// row/public-input accessors, with no interior mutability or side
    /// effects beyond `assert_zero` / `assert_eq`.
    ///
    /// **Cyclic contract — read this before writing a recurrence.** Every
    /// constraint emitted here MUST hold on *all* rows of the trace
    /// domain `H`, **including the cyclic wrap-around row**: the prover
    /// divides the combined constraint polynomial by the full vanishing
    /// polynomial `Z_H(x) = x^{num_rows} − 1`, which vanishes on *every*
    /// row of `H`. There is **no last-row selector** and no "all rows
    /// except the last" masking — the `next` of the last row is the first
    /// row (`g^{num_rows} = 1`; see [`AirBuilder::next`]), and a
    /// transition constraint is checked on that `(row n−1, row 0)` pair
    /// too. Consequently a *terminating* (non-cyclic) recurrence — e.g. a
    /// counter `next == local + 1` whose last value does not wrap back to
    /// the first — MUST NOT be written as a bare transition constraint:
    /// it does not vanish on the wrap-around row, so `C / Z_H` is not a
    /// polynomial and FRI rejects the proof (completeness loss, not a
    /// soundness hole). Express a terminating computation by making the
    /// trace genuinely cyclic (pad/wrap the columns so the recurrence
    /// closes) or by pinning its endpoints with
    /// [`boundary_constraints`](Air::boundary_constraints), never by
    /// assuming a phantom last-row exemption.
    ///
    /// Boundary constraints (fixed values at specific rows) are NOT
    /// expressed here — they are exact-point checks the verifier runs
    /// directly against authenticated trace openings. See
    /// [`BoundaryConstraint`].
    fn eval<AB: AirBuilder>(&self, builder: &mut AB);

    /// Boundary constraints: trace cell `(row, col)` must equal a fixed
    /// field value. These pin the input/output of the computation to the
    /// public statement and are checked by the verifier directly against
    /// the Merkle-authenticated trace evaluations (no quotient needed —
    /// an exact equality at a known domain index, sound without
    /// Schwartz-Zippel).
    ///
    /// Default: no boundary constraints. Most real AIRs override this.
    fn boundary_constraints(&self) -> Vec<BoundaryConstraint> {
        Vec::new()
    }
}

/// A single boundary constraint: `trace[row][col] == value`.
///
/// `row` is an index into the *trace* domain `H` (size `num_rows`), not
/// the LDE domain. The prover/verifier translate it to the LDE index by
/// the fixed stride `blowup = N_lde / num_rows`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryConstraint {
    /// Trace-domain row index in `[0, num_rows)`.
    pub row: usize,
    /// Column index in `[0, width)`.
    pub col: usize,
    /// Required field value at `(row, col)`.
    pub value: Goldilocks,
}

impl BoundaryConstraint {
    /// Construct a boundary constraint `trace[row][col] == value`.
    pub const fn new(row: usize, col: usize, value: Goldilocks) -> Self {
        Self { row, col, value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3q_field::Field;

    /// A concrete builder over `Goldilocks` for unit-testing `eval`
    /// bodies in isolation: feed it two rows + public inputs, run
    /// `eval`, and inspect the accumulated constraint values. This is
    /// exactly the prover's per-row builder, minus the quotient
    /// bookkeeping.
    struct EvalBuilder {
        local: Vec<Goldilocks>,
        next: Vec<Goldilocks>,
        public: Vec<Goldilocks>,
        out: Vec<Goldilocks>,
    }

    impl AirBuilder for EvalBuilder {
        type Expr = Goldilocks;
        fn width(&self) -> usize {
            self.local.len()
        }
        fn local(&self, col: usize) -> Goldilocks {
            self.local[col]
        }
        fn next(&self, col: usize) -> Goldilocks {
            self.next[col]
        }
        fn public_input(&self, idx: usize) -> Goldilocks {
            self.public[idx]
        }
        fn constant(&self, c: Goldilocks) -> Goldilocks {
            c
        }
        fn assert_zero(&mut self, expr: Goldilocks) {
            self.out.push(expr);
        }
    }

    /// Toy AIR: a single column `c`, constraint `next == local + 1`
    /// (a counter). One transition constraint.
    struct CounterAir;
    impl Air for CounterAir {
        fn width(&self) -> usize {
            1
        }
        fn num_rows(&self) -> usize {
            8
        }
        fn num_public_inputs(&self) -> usize {
            0
        }
        fn num_constraints(&self) -> usize {
            1
        }
        fn constraint_degree(&self) -> usize {
            1
        }
        fn eval<AB: AirBuilder>(&self, b: &mut AB) {
            let one = b.constant(Goldilocks::one());
            let next = b.next(0);
            let local = b.local(0);
            // next - (local + 1) == 0
            b.assert_eq(next, local + one);
        }
    }

    #[test]
    fn counter_constraint_satisfied_is_zero() {
        let air = CounterAir;
        let mut bld = EvalBuilder {
            local: vec![Goldilocks::from_u64(5)],
            next: vec![Goldilocks::from_u64(6)],
            public: vec![],
            out: vec![],
        };
        air.eval(&mut bld);
        assert_eq!(bld.out.len(), air.num_constraints());
        assert_eq!(bld.out[0], Goldilocks::zero(), "satisfied -> 0");
    }

    #[test]
    fn counter_constraint_violated_is_nonzero() {
        let air = CounterAir;
        let mut bld = EvalBuilder {
            local: vec![Goldilocks::from_u64(5)],
            next: vec![Goldilocks::from_u64(99)], // wrong successor
            public: vec![],
            out: vec![],
        };
        air.eval(&mut bld);
        assert_ne!(bld.out[0], Goldilocks::zero(), "violated -> nonzero");
    }

    #[test]
    fn boundary_constraint_default_empty() {
        assert!(CounterAir.boundary_constraints().is_empty());
    }
}
