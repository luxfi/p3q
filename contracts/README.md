# `@luxfi/p3q-evm`

EVM verifier surface (Solidity) for [P3Q](https://github.com/luxfi/p3q),
the strict-PQ STARK/FRI/SHA-3 proof system for Lux Z-Chain.

See [`src/README.md`](src/README.md) for the detailed package surface and
audit-gating notes.

## Install

```sh
npm install @luxfi/p3q-evm
# or
pnpm add @luxfi/p3q-evm
```

In Solidity:

```solidity
import "@luxfi/p3q-evm/src/IP3QVerifier.sol";
import "@luxfi/p3q-evm/src/P3QVerifierStub.sol";
```

## Build (standalone)

```sh
forge build
```

## License

MIT OR Apache-2.0 (matches the parent Rust workspace).
