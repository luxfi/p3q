# `@luxfi/p3q-evm`

EVM verifier surface (Solidity) for the P3Q strict-PQ proof system.

This package is part of the [`luxfi/p3q`](https://github.com/luxfi/p3q)
workspace. The Rust verifier crate (`crates/p3q-verifier`) is the source
of truth for proof verification logic; this package is the on-chain
Solidity surface that EVM consumers (bridges, anchors, gateways) wire
into their strict-PQ slots.

## Versioning

Pinned to the parent Rust workspace version (see `Cargo.toml`):

| Component      | Version |
| -------------- | ------- |
| `Cargo.toml`   | `0.0.1` |
| `package.json` | `0.0.1` |

Patch-bumps only until the audit clears. Never major-bump.

## Surface

- `IP3QVerifier` — typed verifier interface (`verify`, `policyId`, and
  the `AuditGatedReject` event).
- `P3QVerifierStub` — audit-gated default body. `verify` ALWAYS rejects.
  `policyId()` returns the canonical PQ proof policy id
  (`keccak256("ProofPolicySTARKFRISHA3PQ")`) so the
  `StrictPQProfileGate` admits the stub in the strict-PQ slot. The audit
  gate is enforced inside `verify`, not via policy mismatch.

## Audit gating

The real STARK/FRI/SHA-3 verifier body is audit-gated. Until the audit
clears, `P3QVerifierStub` is the canonical body and rejects every proof.
Do NOT replace the stub with a permissive verifier without an audit
attestation against the matching `p3q-verifier` Rust release.

The stub returns `false` (rather than reverting with a custom error) so
that consumer contracts can surface their own caller-owned error
(e.g. `BridgeV2` reverts with `P3QProofRejected`). The
`AuditGatedReject` log is the off-chain signal that a deployment still
holds the stub.

## Consumers

- [`luxfi/teleport`](https://github.com/luxfi/teleport) — `BridgeV2`
  P3Q proof slot.
- [`luxfi/node`](https://github.com/luxfi/node) — `quasar/contract`
  strict-PQ profile gate (mirrors `policyId` discriminants).

Downstream packages MUST import this surface — they MUST NOT redefine
`IP3QVerifier` locally.

## Build

```sh
forge build
```

(Requires [Foundry](https://getfoundry.sh/). The package has no
JavaScript or TypeScript sources; it is pure Solidity.)
