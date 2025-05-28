# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0]

### Fixed

- Added two new utils, `add0x` and `remove0x` to add/remove `0x` prefix to/from the hexadecimal string. ([#112](https://github.com/MetaMask/toprf-secure-backup/pull/112))
- Added `cancellation` logic to the `timeoutPromise` after the `Promise.race` in `Some` function. ([#110](https://github.com/MetaMask/toprf-secure-backup/pull/110))

## [0.2.0]

### Fixed

- fix: allow Some function to succeed with truthy values ([#107](https://github.com/MetaMask/toprf-secure-backup.git/pull/107))
- Test/auth network utils ([#94](https://github.com/MetaMask/toprf-secure-backup.git/pull/94))
- refactor: Improve response handling logic for commitIdToken and authenticateUser ([#89](https://github.com/MetaMask/toprf-secure-backup.git/pull/89))

## [0.1.0]

### Added

- First release of `@metamask/auth-network-utils`
  - Add functions for parsing results from web3auth network. eg: `some`, `thresholdSame`, `kCombinations`
  - Add helper functions to convert `snake case` keys to `camelcase` keys and vice versa
  - Add helper functions converting `ecies` params from hex to buffer and vice versa
  - Add helper function to format BN public key to SEC1 hex format
  - Add class to define `Point` on elliptic curve
  - Add class to define `Share`
  - Add class to define `Polynomial`
  - Add function to run lagrange interpolation on a array of scalar BNs and nodeIndexes
  - Add common Cryptographic utilities and classes that will be useful in other packages

[Unreleased]: https://github.com/MetaMask/toprf-secure-backup.git/compare/@metamask/auth-network-utils@0.3.0...HEAD
[0.3.0]: https://github.com/MetaMask/toprf-secure-backup.git/compare/@metamask/auth-network-utils@0.2.0...@metamask/auth-network-utils@0.3.0
[0.2.0]: https://github.com/MetaMask/toprf-secure-backup.git/compare/@metamask/auth-network-utils@0.1.0...@metamask/auth-network-utils@0.2.0
[0.1.0]: https://github.com/MetaMask/toprf-secure-backup.git/releases/tag/@metamask/auth-network-utils@0.1.0
