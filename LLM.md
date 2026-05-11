# P3Q -- Agent Knowledge Base

**Repository**: github.com/luxfi/p3q
**Latest Tag**: v0.0.1
**crates.io**: 10 crates published
**Status**: Under construction (workspace scaffolded; cSHAKE256 substitution + Z-Chain integration in flight)

## Purpose (one-liner)

Post-quantum-only profile and fork of Plonky3 for STARK/FRI proving on
Lux Z-Chain. **No KZG. No BN254. No Groth16. No PLONK wrappers. No
elliptic-curve recursion. No pairings.**

P3Q is the proof-system substrate for **Z-Chain** (HIP-0078 / LP-168).
Where upstream Plonky3 is a general polynomial-IOP toolkit that *can* be
PQ-secure, P3Q is the strict subset that *must*: a curated, audited,
NIST-aligned profile that builds on the Plonky3 STARK/FRI/Merkle
primitives and strips every classical proof-system path.

The strict Lux Z-Chain profile is **P3Q-SHA3**: cSHAKE256 / KMAC256 /
TupleHash256 (FIPS 202 + NIST SP 800-185) replaces every default Keccak
or SHA-256 hash inside Merkle trees, FRI commitments, and Fiat-Shamir
transforms. Same hash family as ML-DSA-65 (FIPS 204) and Pulsar-M
(HIP-0084) — single auditable surface across the entire Lux PQ stack.

## Canonical profile + scheme constants

- Hash: cSHAKE256 / KMAC256 / TupleHash256 (SP 800-185).
- Field: Goldilocks (PQ-friendly modulus).
- Proof system: STARK + FRI (no KZG, no pairings).
- Recursion: P3Q-native (no curve wrappers, no Plonky-style verifier
  inside the circuit).

## Recent significant commits

| SHA | Tag | Impact |
|-----|-----|--------|
| `82d0b5f` | v0.0.1 | Populate strict-PQ Plonky3 fork workspace; 10 crates published on crates.io |

## Active versions

- Repo: `v0.0.1` (workspace scaffold tag). Next: `v0.0.2` when cSHAKE256
  Merkle substitution lands.
- crates.io: 10 crates under `p3q-*` namespace.

## Crate layout

```
crates/
  p3q-core/         protocol types, error model, common traits
  p3q-field/        Goldilocks field arithmetic
  p3q-fri/          FRI low-degree test (cSHAKE256 Merkle)
  p3q-merkle/       hash-based authenticated trees
  p3q-stark/        AIR / STARK arithmetisation
  p3q-recursion/    P3Q-native recursion (no curve wrappers)
  p3q-challenger/   Fiat-Shamir transform under cSHAKE256
  p3q-zchain/       Lux Z-Chain integration
```

## Cross-repo dependencies

- Consumed by:
  - `luxfi/consensus/protocol/zchain` (HIP-0078 §4 backend) — once the
    cSHAKE256 substitution lands, the Z-Chain `ProofBackendID` will pin
    a P3Q profile and the registry roots will commit P3Q proofs.
- Pinned hash family aligned with:
  - `luxfi/crypto/pq/mldsa/mldsa65` (FIPS 204 uses SHAKE128/256)
  - `luxfi/pulsar-m` (cSHAKE / KMAC profile)

## Where to look for X

- Workspace manifest: `Cargo.toml`
- Goldilocks field: `crates/p3q-field/`
- cSHAKE256 Fiat-Shamir transcript: `crates/p3q-challenger/`
- Z-Chain integration crate: `crates/p3q-zchain/`
- Vectors: `vectors/`

## Open follow-ups

- cSHAKE256 Merkle / Fiat-Shamir substitution: in flight.
- Z-Chain `ProofBackendID` byte assignment: pending workspace
  completion; will land in `luxfi/consensus/config/security_profile.go`
  registry once P3Q tags a release.
- crates.io patch-bumps only (`v0.0.1` → `v0.0.2`); 10 published crates
  must move in lockstep.

## Rules

1. Patch-bump only; never bump minor/major without explicit approval.
2. No KZG, no BN254, no Groth16, no PLONK, no pairings, no
   elliptic-curve recursion — these are the line in the sand. Anything
   that pulls a curve dependency is a no-merge.
3. Hash family is fixed: cSHAKE256 / KMAC256 / TupleHash256. Any
   alternate default (Keccak-256, SHA-256, Poseidon) requires a new
   profile ID, not a swap.
