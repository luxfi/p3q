// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

/// @title IP3QVerifier
/// @notice Typed EVM verifier surface for P3Q STARK/FRI proofs.
/// @dev    P3Q is the strict-PQ proof system specified in
///         `~/work/lux/papers/pq/pq.tex` §profile-table and implemented
///         by the Rust workspace at `github.com/luxfi/p3q`. The on-chain
///         verifier slot under `PROFILE_QUASAR_STRICT_PQ` MUST hold a
///         contract whose `policyId()` returns the canonical PQ proof
///         policy id (`keccak256("ProofPolicySTARKFRISHA3PQ")`).
///
///         Verifier bodies (the real STARK/FRI verification) are
///         audit-gated and live in the Rust crate `p3q-verifier` (and
///         eventually a generated Solidity verifier). Until that audit
///         lands, the canonical implementation shipped with this
///         package is `P3QVerifierStub`, which is profile-compatible
///         (correct `policyId`) but rejects every proof and emits
///         `AuditGatedReject`. Consumers (bridges, anchors) wire the
///         stub by default and swap in the real verifier via their
///         normal admin path once the audit ships.
///
///         The interface intentionally mirrors `IVerifier` from
///         `luxfi/node/quasar/contract`: `policyId()` is the discriminant
///         that the `StrictPQProfileGate` consumes to admit / refuse a
///         verifier in a given profile slot. `verify` is NOT view here
///         because the audit-gated stub needs to emit a log on every
///         attempted verification; production STARK verifiers MAY
///         implement `verify` as a pure / view precompile call.
///
///         This package is the single source of truth for the P3Q EVM
///         verifier types. Downstream consumers (`luxfi/teleport`,
///         `luxfi/node`, etc.) MUST import from here; redefining the
///         interface locally is a versioning bug.
interface IP3QVerifier {
    /// @notice Audit-gate signal. Emitted by `P3QVerifierStub` (and any
    ///         other pre-audit body) on every `verify` attempt so that
    ///         off-chain observers can detect deployments that have not
    ///         yet swapped in the real verifier.
    /// @param  publicInputsHash The keccak256 commitment to the public
    ///         inputs of the rejected proof.
    event AuditGatedReject(bytes32 indexed publicInputsHash);

    /// @notice Verify `proof` against `publicInputsHash`. Returns true
    ///         iff the proof is valid for the given public inputs.
    /// @dev    Non-view to permit `AuditGatedReject` emission in the
    ///         audit-gated stub. Production verifiers MAY be view.
    /// @param  proof              Encoded STARK/FRI proof bytes.
    /// @param  publicInputsHash   keccak256 commitment to public inputs.
    /// @return ok                 True iff the proof verifies.
    function verify(bytes calldata proof, bytes32 publicInputsHash)
        external
        returns (bool ok);

    /// @notice Returns the ProofPolicy id this verifier implements.
    ///         For P3Q this MUST be
    ///         `keccak256("ProofPolicySTARKFRISHA3PQ")`. The strict-PQ
    ///         profile gate uses this discriminant to admit / refuse
    ///         the verifier in the ZK-claim and P3Q proof slots.
    /// @dev    Declared `view` (not `pure`) so production verifiers MAY
    ///         derive policy from storage if needed; the canonical
    ///         stub implements it as `pure` returning the constant.
    function policyId() external view returns (bytes32);
}
