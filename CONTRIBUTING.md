# Contributing to P3Q

## What we accept

P3Q is a strict-PQ profile and fork of Plonky3 for Lux Z-Chain
(HIP-0078). Until the audit gate passes, contributions that align with
the **strict subset** are highest priority:

1. **cSHAKE256 / KMAC256 / TupleHash256 implementations** of the
   Plonky3 Merkle / FRI / Fiat-Shamir primitives.
2. **Z-Chain circuits** in `crates/p3q-zchain/` — validator
   registration, DKG transcript verification, revocation, committee
   selection, epoch transition.
3. **Verifier-totality fuzzing** — every malformed proof returns a
   typed error; no panics.
4. **Constant-time analysis** of any verifier path that touches
   secret-derived state.
5. **Cross-implementation drift detection** — KATs in `vectors/`
   compared against an independent implementation.
6. **Audit-prep** — code clarity, comment density on cryptographic
   invariants, test coverage gates.

## What we don't accept

Until after the production audit:

- New polynomial-IOP modes outside STARK / FRI.
- Pairing-based wrappers (KZG, Groth16, PLONK/KZG) for "cheaper
  classical verification". P3Q's whole point is no classical fallback.
- Elliptic-curve recursion stacks. P3Q recursion is STARK-native only.
- BLAKE3 / Poseidon / Monolith / Rescue hash families. Strict-PQ profile
  is FIPS 202 / SP 800-185 only.
- Optimisations before the encoding freeze.

## Process

1. **Open an issue first.** Discuss the change before implementing.
2. **One concern per PR.** Don't bundle a Merkle change with a
   verifier change.
3. **CI gate must pass.** `cargo build`, `cargo test`,
   `cargo clippy -- -D warnings`, `scripts/lint_forbidden.sh`.
4. **Sign your commits.** Real name in `Signed-off-by`.
5. **Patent disclosures** attach to commits per Apache 2.0 §3.

## Coding standards

- Rust 1.79+, stable only. No `nightly` features.
- `unsafe_code = "deny"` workspace-wide. Audited subset.
- Every public function in `p3q-verifier` has a constant-time
  annotation (yes / no / not-applicable + rationale).
- No `panic!()` inside the verifier path — return typed errors via
  `thiserror`.
- No `unwrap()` / `expect()` on user-controlled input.

## License

By contributing you agree to dual MIT / Apache-2.0 licensing and the
patent grant in Apache 2.0 §3.
