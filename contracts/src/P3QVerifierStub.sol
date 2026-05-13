// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import "./IP3QVerifier.sol";

/// @title P3QVerifierStub
/// @notice Audit-gated canonical implementation of `IP3QVerifier`.
///         `verify` ALWAYS rejects: it emits `AuditGatedReject` and
///         returns `false`. Callers that `require(verify(...))` will
///         therefore revert on every proof.
/// @dev    This stub is the audit-gated default. The real verifier
///         ships in this same package once the Rust verifier bodies
///         in `crates/p3q-verifier` complete formal audit. Do NOT
///         replace this with a permissive verifier without an audit
///         attestation.
///
///         Why "return false + emit event" instead of "revert with
///         custom error"? Two reasons:
///
///         1. Callers (e.g. `BridgeV2.claimWithProof`) wrap the
///            verifier call in `require(p3qVerifier.verify(...))` so
///            they can surface a stable, caller-owned error
///            (`P3QProofRejected`) rather than leaking the verifier
///            implementation's revert reason. Reverting from the
///            stub would replace that with a verifier-implementation
///            error and break the caller's error surface contract.
///
///         2. `AuditGatedReject` is emitted as a log so off-chain
///            indexers can detect "stub still in slot" deployments
///            even when the parent transaction reverts (logs are
///            still observable in revert traces, but emitting before
///            return keeps semantics identical to the production
///            verifier where `verify` would emit a result event).
///
///         The `policyId()` is the canonical PQ proof policy id
///         (`keccak256("ProofPolicySTARKFRISHA3PQ")`) so the
///         `StrictPQProfileGate` admits the stub in the strict-PQ
///         slot. The audit gate is enforced by `verify`'s rejection,
///         not by policy mismatch.
contract P3QVerifierStub is IP3QVerifier {
    /// @inheritdoc IP3QVerifier
    function policyId() external pure override returns (bytes32) {
        return keccak256("ProofPolicySTARKFRISHA3PQ");
    }

    /// @inheritdoc IP3QVerifier
    /// @dev Stub: emits the audit gate event and returns false. Every
    ///      call rejects; callers that `require(verify(...))` revert.
    function verify(bytes calldata, bytes32 publicInputsHash)
        external
        override
        returns (bool)
    {
        emit AuditGatedReject(publicInputsHash);
        return false;
    }
}
