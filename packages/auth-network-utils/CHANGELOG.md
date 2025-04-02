# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `@metamask/auth-network-utils` package
  - Add functions for parsing results from web3auth network. eg: `some`, `thresholdSame`, `kCombinations`.
  - Add helper functions to convert `snake case` keys to `camelcase` keys and vice versa.
  - Add helper functions converting `ecies` params from hex to buffer and vice versa.
  - Add helper function to format BN public key to SEC1 hex format.
  - Add class to define `Point` on elliptic curve.
  - Add class to define `Share`.
  - Add class to define `Polynomial`.
  - Add function to run lagrange interpolation on a array of scalar BNs and nodeIndexes.
  - Add common Cryptographic utilities and classes that will be useful in other packages.

[Unreleased]: https://github.com/MetaMask/toprf-secret-backup/
