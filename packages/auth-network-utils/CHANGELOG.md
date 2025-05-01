# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Uncategorized

- Revert "Release/0.1.0" ([#100](https://github.com/MetaMask/toprf-secure-backup.git/pull/100))
- Release/0.1.0 ([#99](https://github.com/MetaMask/toprf-secure-backup.git/pull/99))
- Revert "Release 0.1.0" ([#97](https://github.com/MetaMask/toprf-secure-backup.git/pull/97))
- Release 0.1.0 ([#95](https://github.com/MetaMask/toprf-secure-backup.git/pull/95))
- Refactor: Rename verifier/verifierId to authConnectionId/userId ([#93](https://github.com/MetaMask/toprf-secure-backup.git/pull/93))
- update eccrypto to use padding in encryption ([#86](https://github.com/MetaMask/toprf-secure-backup.git/pull/86))
- feat: enhance safeStringify to accept options and add preserveKeyOrder utility function
- refactor: move TOPRFError and related types to a new errors.ts file for better organization
- refactor: update error handling in SomeError class and introduce RateLimitErrorData type
- feat: add JSON-RPC error handling utilities and improve request filtering logic
- Merge remote-tracking branch 'origin/main' into feat/get-pub-key
- kCombinations: convert to generator function
- fixup filterCompletedRequests
- cleanup / dedicate function for mergeEndpointsWithAuthTokens
- replace pubKeyToSec1 by uint8ArrayToHex
- add dedicated function for filtering completed requests
- fix: update noble/\* libs to latest
- fix: fix/update noble/\* sdks to align with metamask/core
- fix: removed 'ethereum-cryptography' and replaced with 'noble/hashes', 'noble/curves'
- Merge remote-tracking branch 'origin/feat/key-recovery' into feat/metadata
- added 100% test coverage for reset rate limits
- Merge remote-tracking branch 'origin/feat/key-recovery' into feat/metadata
- cleanup
- Merge remote-tracking branch 'origin/feat/key-recovery' into feat/metadata
- utils: simplify Some function
- fix private key format / reduce usage of elliptic
- simplify utils
- Merge remote-tracking branch 'origin/main' into feat/import-shares
- disable coverage check for auth-network-utils
- disable coverage check for auth-network-utils
- adjust coverageThreshold for auth-network-utils
- minor tsconfig cleanup
- merge with authenticate
- fix jrpc req error handling
- lint
- Merge branch 'feat/authenticate' into feat/import-shares
- increased test coverage
- Merge remote-tracking branch 'origin/feat/key-recovery' into feat/metadata
- fix: explicit prototype in Custom Error classes
- build fixed
- store shares test fixed
- Merge branch 'feat/authenticate' into feat/import-shares
- fix review comments
- Merge branch 'fix/base-setup' into feat/authenticate
- update package name
- update package name
- Merge branch 'feat/authenticate' into feat/import-shares
- linter fixed
- added function to commit id token and authenticate user's id token
- chore: Add dependencies for `@noble/curves` and `@noble/hashes`
- update change log
- update change log
- fixed base config, package name and auth utils linter
- fix: tsconfig build ([#17](https://github.com/MetaMask/toprf-secure-backup.git/pull/17))
- fix promise length check in 'some' function
- Merge remote-tracking branch 'origin/feat/key-recovery' into feat/metadata
- fix: tsconfig build
- wip: toprf eval api added
- Merge remote-tracking branch 'origin/feat/import-shares' into feat/metadata
- test: updated tests
- create encKey function added in main class
- merged with latest import shares and jsdoc fixes
- store shares api integration added
- upgrade: jest to v0.29
- add tests
- update all interfaces to camel case
- store share api handler added and casing middleware added
- jrpc request type and updatEncKey function renamed to changeEncKey
- Merge branch 'main' into feat/jwt-login
- Merge branch 'main' into feat/authenticate
- commitment request function added
- added jsdoc to getSecp256K1Curve function
- removed unused imports
- fixed lagrangeInterpolation test
- lint fixed
- remove dead code
- lint fixed
- fixed build
- added tests for common, keys and lagrange utils
- added auth-network-utils functions
- initial setup
- new package added

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

[Unreleased]: https://github.com/MetaMask/toprf-secure-backup.git/
