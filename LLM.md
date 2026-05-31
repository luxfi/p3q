# P3Q -- Agent Knowledge Base

**Repository**: github.com/luxfi/p3q
**Latest Tag**: v0.0.1 (next: v0.1.0 with real verifier body)
**crates.io**: 10 crates published
**Status**: Generic STARK / FRI verifier body LANDED in p3q-verifier; toy-AIR golden vector verifies under both SHA3 and Keccak profiles; AIR-specific Z-Chain circuit verifiers still scaffolded

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
| (this) | (untagged) | **`Sha3Backend` trait + libluxgpu 0.4 FFI**. New crate `p3q-gpu-sha3` (the ONLY `unsafe`-allowed crate alongside `p3q-c-abi`) dlopens libluxgpu.{dylib,so} and exposes `lux_gpu_sha3_256_batch` / `lux_gpu_shake256_batch` via a `GpuShake: Sha3Backend` impl. Trait lives in `p3q-sha3::backend`; `CpuShake` is the audited reference. KAT parity (FIPS 202) enforced by `p3q-gpu-sha3` tests on every CI run. `p3q-merkle::verify_proof_batch(backend, root, openings)` fans out per-query Merkle authentications level-by-level; verifier collects every opening across every query and dispatches one `verify_proof_batch` per Merkle root (trace + each FRI layer). Wired into `verify_parsed` behind `p3q-verifier --features gpu-sha3`; transparent CPU fallback when dlopen fails, GPU context creation fails, libluxgpu lacks symbols, or libluxgpu panics inside FFI (`catch_unwind` boundary). Field-order load-bearing in `GpuShake`: `gpu` MUST drop before `lib` to avoid use-after-free on the destroy fn-ptr at shutdown. Audited transcript binding UNCHANGED — `GpuShake::cshake256_batch` routes through CPU because libluxgpu 0.4 has SHAKE256 (0x1F domain) only, not cSHAKE256 (0x04 domain), and cSHAKE outputs are not byte-equivalent to SHAKE outputs with prepended framing. When libluxgpu adds a cSHAKE batch primitive, the override drops in `p3q-gpu-sha3` with zero verifier-side change. Bench: toy-AIR `verifier_wall_clock` 1017 us/iter CPU-only vs 1016 us/iter `--features gpu-sha3` (within noise; GPU only meaningfully accelerates once cSHAKE batch lands). |
| `c68eeaa` | (untagged) | Audit-grade generic STARK / FRI verifier body in `p3q-verifier`: wire format v1, cSHAKE256 Fiat-Shamir transcript with profile-keyed root, dual-auth-path Merkle openings, binary FRI fold; toy prover behind `feature="prover"`; golden vectors persisted in `vectors/`; verify wall-clock ~1 ms toy AIR; `cargo test`/`cargo clippy --all-targets -- -D warnings` clean |
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
  p3q-merkle/       hash-based authenticated trees + verify_proof_batch
  p3q-stark/        AIR / STARK arithmetisation
  p3q-recursion/    P3Q-native recursion (no curve wrappers)
  p3q-challenger/   Fiat-Shamir transform under cSHAKE256
  p3q-sha3/         FIPS 202 / SP 800-185 primitives + Sha3Backend trait
                    + cshake256/tuple/kmac batch fns (CPU streaming impl)
  p3q-gpu-sha3/     libluxgpu 0.4 SHA3-256 / SHAKE256 FFI (dlopen),
                    GpuShake: Sha3Backend impl, transparent CPU fallback.
                    THE second `unsafe`-allowed crate (with p3q-c-abi).
  p3q-zchain/       Lux Z-Chain integration
  p3q-c-abi/        C ABI shim for non-Rust callers
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
- `Sha3Backend` trait + CPU impl: `crates/p3q-sha3/src/backend.rs`
- Batched cshake/tuple/kmac fns: `crates/p3q-sha3/src/batch.rs`
- libluxgpu FFI + `GpuShake`: `crates/p3q-gpu-sha3/src/lib.rs`
- Batched Merkle verify: `crates/p3q-merkle/src/lib.rs::verify_proof_batch`
- Verifier backend dispatch: `crates/p3q-verifier/src/verify.rs::select_backend`
- Z-Chain integration crate: `crates/p3q-zchain/`
- Vectors: `vectors/`

## Open follow-ups

- cSHAKE256 Merkle / Fiat-Shamir substitution: LANDED in `p3q-verifier`
  (transcript root labels `LUX-P3Q-V1-SHA3` / `LUX-P3Q-V1-KECCAK`,
  per-observation tags `LUX-P3Q-V1-{HEADER,PUBLIC-INPUT,TRACE-COMMIT,
  FRI-COMMIT,FRI-FINAL,FRI-QUERY}`).
- AIR-specific verifiers (boundary + transition constraint checks):
  pending. `p3q-zchain` circuit scaffolding still returns
  `Circuit("... audit-gated")`; circuits land in v0.2.x by wrapping
  the generic kernel.
- Bit-reverse leaf permutation (v2): would collapse the per-query
  dual auth paths into single paths. Current v1 wire ships two paths
  per layer pair for simplicity at ~2x byte cost; still ~30 KB for the
  toy AIR which is fine.
- Constant-time annotation review: kernel uses only Goldilocks ops and
  cSHAKE256 (both CT by construction). Branch on echoed query-index
  mismatch is a public-time decision (transcript-derived comparison),
  acceptable.
- Z-Chain `ProofBackendID` byte assignment: pending workspace
  completion; will land in `luxfi/consensus/config/security_profile.go`
  registry once P3Q tags a release.
- crates.io patch-bumps only (`v0.0.1` → `v0.0.2`); 10 published crates
  must move in lockstep. Verifier body landing supports a minor bump
  to v0.1.0.
- GPU cSHAKE256 batch in libluxgpu: when libluxgpu adds a native
  `lux_gpu_cshake256_batch` (0x04 padding domain, per-input
  customisation string), override `GpuShake::cshake256_batch` to
  dispatch through it. The verifier wiring is already in place — only
  the `p3q-gpu-sha3` impl changes.

## Rules

1. Patch-bump only; never bump minor/major without explicit approval.
2. No KZG, no BN254, no Groth16, no PLONK, no pairings, no
   elliptic-curve recursion — these are the line in the sand. Anything
   that pulls a curve dependency is a no-merge.
3. Hash family is fixed: cSHAKE256 / KMAC256 / TupleHash256. Any
   alternate default (Keccak-256, SHA-256, Poseidon) requires a new
   profile ID, not a swap.
