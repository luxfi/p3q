# Security policy

## Reporting vulnerabilities

Email **security@lux.network** encrypted with the team key at
`https://lux.network/security/key.asc`. Public disclosure happens after
a fix lands and downstream consumers (Lux Z-Chain, anything depending
on `luxfi/p3q`) have had a 14-day private window.

## In-scope

- Soundness gaps in any P3Q-shipped circuit (validator-registration,
  DKG-transcript-check, revocation, committee-selection,
  epoch-transition).
- FRI / Merkle / Fiat-Shamir parameter weakness vs the claimed
  conjectured-security target (≥ 128-bit classical, ≥ NIST PQ Cat 3).
- Hash-suite drift: any code path that calls a non-FIPS-202 hash inside
  a strict-PQ profile.
- Verifier-totality bugs: malformed proofs that panic, hang, or
  produce undefined behaviour (per upstream Plonky3 README, the
  upstream verifier "may panic on certain invalid proofs"; P3Q
  refuses panics as a launch gate).
- Constant-time gaps in any verifier code touching secret-derived state.

## Forbidden imports — automatic CVE

Any PR that adds a dependency on classical-only primitives — `bn254`,
`KZG`, Groth16, PLONK/KZG modes, pairing-based recursion — is
automatically a security regression. CI rejects via
`scripts/lint_forbidden.sh`. Disclosing a bypass of that gate is
in-scope under this policy.

## Out-of-scope

- Performance / efficiency reports (file an issue).
- Issues exclusively in upstream Plonky3 — file there.
- Issues in downstream consumers (Z-Chain VM, Lux DA layer) — file in
  those repos.

## CVE assignment

P3Q maintainers will request CVEs for in-scope vulnerabilities prior to
public disclosure.
