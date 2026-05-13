// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

// @luxfi/p3q-evm — re-exports.
//
// Single source of truth for the P3Q EVM verifier surface. Downstream
// consumers import from `@luxfi/p3q-evm/src/IP3QVerifier.sol` and
// `@luxfi/p3q-evm/src/P3QVerifierStub.sol`. This file exists to make
// the npm `main` entry resolvable for tooling that walks package.json.

import "./IP3QVerifier.sol";
import "./P3QVerifierStub.sol";
