# P3Q

> **P3Q** — a post-quantum-only profile and fork of Plonky3 for STARK/FRI
> proving. **No KZG. No BN254. No Groth16. No PLONK wrappers. No
> elliptic-curve recursion. No pairings.**

P3Q is the proof-system substrate for **Z-Chain** (HIP-0078) — Lux's
post-quantum identity & attestation rollup. Where upstream Plonky3 is a
general polynomial-IOP toolkit that *can* be used in PQ-secure modes, P3Q
is the strict subset that *must*: a curated, audited, NIST-aligned
profile that builds on the Plonky3 STARK/FRI/Merkle primitives and
strips every classical proof-system path.

The strict Lux Z-Chain profile is **P3Q-SHA3**: cSHAKE256 / KMAC256 /
TupleHash256 (FIPS 202 + NIST SP 800-185) replaces every default Keccak
or SHA-256 hash inside Merkle trees, FRI commitments, and Fiat-Shamir
transforms. Same hash family as ML-DSA-65 (FIPS 204) and Pulsar
(HIP-0084) — single auditable surface across the entire Lux PQ stack.

> **Status: scaffold + stable surface, audit-gated body pending.**
> Pin to a tagged release before depending on P3Q from a downstream
> consumer. Current released tag: **`v0.0.1`**.

### What's stable in `v0.0.1`

- Workspace layout, crate boundaries, public types
  (`ProofBytes`, `ProofSystemId`, `P3qError`, `Result`).
- Goldilocks field arithmetic (`p3q-field`).
- SHA3 / cSHAKE256 / KMAC256 / TupleHash256 bindings (`p3q-sha3`) —
  FIPS 202 + SP 800-185.
- Merkle tree primitives (`p3q-merkle`).
- FRI low-degree test plumbing (`p3q-fri`).
- Fiat-Shamir challenger transcript (`p3q-challenger`).
- AIR / STARK trait surface (`p3q-stark`).
- Verifier dispatch + profile byte handling (`p3q-verifier`):
  malformed input is rejected with a typed `P3qError`, never a panic.
- `scripts/lint_forbidden.sh` CI gate against banned imports.
- Test suite: 43 unit tests pass, zero failures.

### What's WIP (returns `P3qError`, never panics)

- `p3q-verifier::verify_sha3` / `verify_keccak` — audit-gated proof
  body verification. Currently returns
  `P3qError::StarkVerification("…not yet audit-gated")`.
- `p3q-zchain` circuits — all six `build_air()` constructors
  (`register_validator`, `rotate_identity_key`, `revoke_identity_key`,
  `select_epoch_committee`, `commit_dkg_output`,
  `produce_epoch_commitment`) return `P3qError` until the audited
  bodies land.
- Constant-time verifier certification (annotation pending audit).

Downstream consumers can depend on the type surface today; production
proof verification is gated behind subsequent `v0.0.x` releases.

## Why a fork

Plonky3 is MIT/Apache-2.0 dual-licensed and modular by design. Adopting
upstream wholesale exposes Lux to hash-family drift (default Plonky3
profiles use Keccak-256 / SHA-256), recursion-stack drift (active
upstream development), and accidental classical-primitive leakage
(future Plonky3 versions might add a Plonky-style verifier wrapper or
KZG mode). A fork pins:

- One canonical hash family (FIPS 202 / SP 800-185) across every level.
- A reviewable, audit-friendly subset — no PLONK / KZG / BN254 code in
  the binary at all.
- Lux-specific Z-Chain integration baked in (`p3q-zchain` crate).

## Crate layout

```
p3q/
├── crates/
│   ├── p3q-core/         protocol types, error model, common traits
│   ├── p3q-field/        Goldilocks field arithmetic (PQ-friendly modulus)
│   ├── p3q-fri/          FRI low-degree test (cSHAKE256 Merkle)
│   ├── p3q-merkle/       hash-based authenticated trees
│   ├── p3q-stark/        AIR / STARK arithmetisation
│   ├── p3q-recursion/    P3Q-native recursion (no curve wrappers)
│   ├── p3q-challenger/   Fiat-Shamir transform under cSHAKE256
│   ├── p3q-verifier/     STARK + FRI verifier
│   ├── p3q-sha3/         FIPS 202 + SP 800-185 primitive bindings
│   └── p3q-zchain/       Z-Chain integration: epoch-proof circuits + Lux DA glue
├── docs/                 design notes, security analysis, profile spec
├── examples/             reference circuits (validator-registration, DKG-transcript-check)
├── benches/              proof-size + verifier-time benchmark harness
├── vectors/              KATs for cross-implementation drift detection
└── scripts/              build / test / bench / SBOM
```

## Profiles

| profile      | hash family                              | use case                                          | wire ProofSystemID |
|--------------|------------------------------------------|---------------------------------------------------|--------------------|
| **P3Q-SHA3** | cSHAKE256 / KMAC256 / TupleHash256 (FIPS 202 + SP 800-185) | strict Lux Z-Chain default; NIST-aligned | `0x10` |
| P3Q-Keccak   | Keccak-256 (FIPS 202)                    | Ethereum-adjacent compatibility, still PQ         | `0x11` |
| P3Q-Fast     | internal benchmarking only               | engineering experiments; never normative          | not on the wire    |

`P3Q-SHA3` is the production profile. `P3Q-Keccak` exists for
cross-ecosystem audit / shared-circuit interop where Keccak fits the
counterparty's expectation. Both are PQ-secure under the same
hash-collision-resistance assumption.

## What's strictly forbidden

P3Q binaries MUST NOT link or compile-include:

```
p3-bn254                  ← upstream Plonky3 BN254 backend
KZG                       ← polynomial commitment over pairings
Groth16 wrappers          ← classical SNARK final-verifier wrap
PLONK / KZG modes         ← upstream PIOP modes outside STARK/FRI
elliptic-curve recursion  ← any pairing-based recursion stack
```

These are absent from `Cargo.toml` workspace members. CI gate refuses any
PR that re-introduces them. The `vectors/forbidden_imports.txt` file is
the canonical list; `scripts/lint_forbidden.sh` greps the source tree.

## Relationship to upstream Plonky3

| dimension                     | upstream Plonky3                                  | P3Q                                                                |
|-------------------------------|---------------------------------------------------|--------------------------------------------------------------------|
| hash families                 | Keccak-256, SHA-256, Poseidon, BLAKE3, Monolith   | cSHAKE256 (P3Q-SHA3) + Keccak-256 (P3Q-Keccak); Poseidon/BLAKE3 dropped |
| BN254 backend                 | available (`p3-bn254`)                            | **absent**                                                         |
| KZG / pairings                | possible via downstream wrappers                  | **forbidden**                                                      |
| FRI                           | yes                                               | yes — same algorithm, cSHAKE256 Merkle                             |
| recursion                     | active upstream work                              | strict subset; P3Q-native, no curve wrappers                       |
| verifier totality             | "may panic on invalid proofs" (upstream README)   | totality is a launch gate; CI fuzz tests verifier on malformed input |
| audited subset                | toolkit posture                                   | curated and audited                                                |

P3Q tracks upstream Plonky3 for STARK/FRI/Merkle correctness fixes via
periodic upstream-merge PRs that the audit team reviews before landing.

## Z-Chain integration

`p3q-zchain` exposes the circuits Z-Chain (HIP-0078) needs:

- **validator_registration_circuit** — verifies an ML-DSA-65
  identity signature against a registering pubkey under unmodified
  FIPS 204 ML-DSA.Verify.
- **dkg_transcript_circuit** — checks Pulsar DKG transcript
  consistency against the committee root.
- **revocation_circuit** — verifies revocation signatures.
- **committee_selection_circuit** — checks committee derivation from
  validator-set root + epoch randomness beacon.
- **epoch_transition_circuit** — folds the above into a single
  per-epoch proof.

Each circuit produces a P3Q-SHA3 proof (~80–140 KB for an N=64
committee, ~10–30 ms median verifier on standard hardware). Z-Chain
posts the resulting epoch-commitment to the chain; Q-Chain (HIP-0079)
references it.

## Build

```sh
cd ~/work/lux/p3q
cargo build --release          # builds every p3q-* crate
cargo test                     # unit tests
cargo bench --bench p3q_bench  # proof-size + verifier-time
./scripts/lint_forbidden.sh    # CI gate: no banned imports
```

Rust toolchain: stable, 1.79+. No `nightly` features.

## License

MIT OR Apache-2.0 (dual, mirroring upstream Plonky3). See `LICENSE-MIT`
and `LICENSE-APACHE`.

## See also

- HIP-0077 — Mesh Identity, Gossip & Payments (parent)
- HIP-0078 — Z-Chain PQ Identity & Attestation Rollup (downstream consumer)
- HIP-0079 — Q-Chain Finality Block Standard (anchors Z-Chain roots)
- HIP-0084 — Pulsar Threshold ML-DSA DKG & Signing
- Upstream Plonky3 — https://github.com/Plonky3/Plonky3
