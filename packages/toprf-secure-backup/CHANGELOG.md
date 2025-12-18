# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `EncAccountDataType` enum for categorizing secret data (e.g., `PrimarySrp`, `ImportedSrp`, `ImportedPrivateKey`). ([#157](https://github.com/MetaMask/toprf-secure-backup/pull/157))
- Add optional `dataType`, `itemId`, and `createdAt` fields to secret data items. ([#157](https://github.com/MetaMask/toprf-secure-backup/pull/157))
- Add `updateSecretDataItem` and `batchUpdateSecretDataItems` methods to `ToprfSecureBackup` to update fields for existing items. ([#157](https://github.com/MetaMask/toprf-secure-backup/pull/157))

### Changed

- **Breaking**: `fetchAllSecretDataItems` now returns `FetchedSecretDataItem[]` instead of `Uint8Array[]`, including `data`, `itemId`, `dataType`, and `createdAt` fields. ([#157](https://github.com/MetaMask/toprf-secure-backup/pull/157))
- **Breaking**: `batchAddSecretDataItems` parameter `secretData` changed from `Uint8Array[]` to `{ data: Uint8Array, itemId?: string, dataType?: EncAccountDataType }[]`. ([#157](https://github.com/MetaMask/toprf-secure-backup/pull/157))
- `addSecretDataItem` now accepts optional `itemId` and `dataType` parameters. ([#157](https://github.com/MetaMask/toprf-secure-backup/pull/157))

## [0.11.0]

### Added

- added `getNodeDetails` method to `ToprfSecureBackup` class. ([#155](https://github.com/MetaMask/toprf-secure-backup/pull/155))
  - we can use this method to fetch the node details required for the other public requests.

## [0.10.1]

### Changed

- removed node-details fetch call from the constructor. ([#153](https://github.com/MetaMask/toprf-secure-backup/pull/153))
  - we should not start calling to the external endpoints until user gives consent.

## [0.10.0]

### Added

- feat: Extend auth token error handling to `fetchAuthPubKey` and `resetRateLimits` ([#150](https://github.com/MetaMask/toprf-secure-backup/pull/150))

## [0.9.0]

### Added

- feat: Add auth token error handling (expired and invalid) to TOPRF eval request in `recoverTOPRFSeed` ([#147](https://github.com/MetaMask/toprf-secure-backup/pull/147))

## [0.8.0]

### Changed

- chore: dep updates ([#143](https://github.com/MetaMask/toprf-secure-backup/pull/143))
- Updated: @metamask/create-release-branch ([#144](https://github.com/MetaMask/toprf-secure-backup/pull/144))

## [0.7.1]

### Changed

- Changed `fetchAuthPubKey` response to return a object with both `authPubkey` and `KeyIndex`.([#138]https://github.com/MetaMask/toprf-secure-backup/pull/138)

## [0.7.0]

### Changed

- Replaced `couldNotFetchPassword` error with `maxKeyChainLengthExceeded` in `recoverPwEncKey` function.([#136]https://github.com/MetaMask/toprf-secure-backup/pull/136)

## [0.6.0]

### Added

- **Breaking**: Add `fetchMetadataAccessCreds` function option in `ToprfSecureBackup` class constructor.([#134]https://github.com/MetaMask/toprf-secure-backup/pull/134)
  - This function should be used to inject metadata access token for calling metadata apis.

### Changed

- Changed timestamp format from seconds to milliseconds in reset rate limit requests to minimize nonce collision. ([#133](https://github.com/MetaMask/toprf-secure-backup/pull/133))

## [0.5.0]

### Added

- Add optional `pregeneratedOprfKey` param to `changeEncKey` function in `ToprfSecureBackup` class to allow using pre-generated oprf key while changing enc key. ([#129](https://github.com/MetaMask/toprf-secure-backup/pull/129))
  - Either one of `pregeneratedOprfKey` or `newPassword` is required in `changeEncKey`function.
  - `newPassword` is optional param now as well.

### Changed

- Changed `newPassword` param from required to optional in `changeEncKey` function. ([#129](https://github.com/MetaMask/toprf-secure-backup/pull/129))

## [0.4.0]

### Changed

- Changed `recoverPassword` to `recoverPwEncKey`. ([#125](https://github.com/MetaMask/toprf-secure-backup/pull/125))
  - Recovering password encryption key instead of password. No longer storing passwords.
  - Separated password encryption key from encryption key.
- Updated security documentation with best practices for handling sensitive data. ([#122](https://github.com/MetaMask/toprf-secure-backup/pull/122))
- Did Immediate cleanup of sensitive data (session keys, password bytes, seeds) with try-finally patterns to ensure cleanup on exceptions. ([#122](https://github.com/MetaMask/toprf-secure-backup/pull/122))

## [0.3.2]

### Fixed

- Fixed `RateLimit` error parsing on TOPRFEvalRequest. ([#120](https://github.com/MetaMask/toprf-secure-backup/pull/120))

## [0.3.1]

### Fixed

- Fixed usage of `groupedAuthConnectionId` in `ToprfSecureBackup.fetchAuthPubKey` for grouped connection use case. ([#117](https://github.com/MetaMask/toprf-secure-backup/pull/117))

## [0.3.0]

### Changed

- **Breaking**: updated implementation of aggregate(single id) verifier authentication. ([#112](https://github.com/MetaMask/toprf-secure-backup/pull/112))
  - Updated `AuthenticateParams` type to align with the web3auth docs
  - Updated `ToprfSecureBackup.authenticate` method to align with the updated params
  - Computed `hashedIdToken` in the SDK instead of getting from the method params
- **Breaking**: added optional method params, `groupedAuthConnectionId` to methods in `ToprfSecureBackup` class. ([#115](https://github.com/MetaMask/toprf-secure-backup/pull/115))
  - For the use with aggregate (single id) verifier, the value must be provided in the new param, groupedAuthConnectionId

## [0.2.0]

### Added

- Add optional `keyDeriver` parameter to `ToprfSecureBackup` constructor. ([#104](https://github.com/MetaMask/toprf-secure-backup/pull/104))

### Changed

- **Breaking**: `createLocalKey` is now an asynchronous function that returns a Promise. ([#104](https://github.com/MetaMask/toprf-secure-backup/pull/104))

### Fixed

- Rename InvalidAuthTokens, prioritize expired check in parsing. ([#92](https://github.com/MetaMask/toprf-secure-backup/pull/92))

- Improve response handling logic for commitIdToken and authenticateUser. ([#89](https://github.com/MetaMask/toprf-secure-backup/pull/89))

- Allow override of node details in ToprfSecureBackup. ([#103](https://github.com/MetaMask/toprf-secure-backup/pull/103))

## [0.1.0]

### Added

- First release of `@metamask/toprf-secure-backup` package
  - Add `authenticate` function to verify id token with nodes.
  - Add `createLocalKey` function to create encryption and auth key pair locally.
  - Add `persistLocalKey` function to persist locally created encryption key share in nodes.
  - Add `createAndPersistEncKey` function to create and persist encryption key share in nodes.
  - Add `recoverEncKey` function to recover encryption key using password.
  - Add `changeEncKey` function to change encryption key, this function is used for switching to a new password.
  - Add `addSecretDataItem` function to store secret data in metadata storage, encrypted with enc key.
  - Add `batchAddSecretDataItems` function to array of store secret data in metadata storage, encrypted with enc key.
  - Add `fetchAllSecretDataItems` function to fetch all secret data items from metadata storage associated with a enc key.
  - Add `fetchAuthPubKey` function to fetch current auth public key associated with user's password, helps to check if user password is changed.
  - Add `recoverPassword` function to recover a older password corresponding to provided target auth public key, user can use this function only if they have access to latest password. This function is useful for password syncing across devices.

[Unreleased]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.11.0...HEAD
[0.11.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.10.1...@metamask/toprf-secure-backup@0.11.0
[0.10.1]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.10.0...@metamask/toprf-secure-backup@0.10.1
[0.10.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.9.0...@metamask/toprf-secure-backup@0.10.0
[0.9.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.8.0...@metamask/toprf-secure-backup@0.9.0
[0.8.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.7.1...@metamask/toprf-secure-backup@0.8.0
[0.7.1]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.7.0...@metamask/toprf-secure-backup@0.7.1
[0.7.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.6.0...@metamask/toprf-secure-backup@0.7.0
[0.6.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.5.0...@metamask/toprf-secure-backup@0.6.0
[0.5.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.4.0...@metamask/toprf-secure-backup@0.5.0
[0.4.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.3.2...@metamask/toprf-secure-backup@0.4.0
[0.3.2]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.3.1...@metamask/toprf-secure-backup@0.3.2
[0.3.1]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.3.0...@metamask/toprf-secure-backup@0.3.1
[0.3.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.2.0...@metamask/toprf-secure-backup@0.3.0
[0.2.0]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.1.0...@metamask/toprf-secure-backup@0.2.0
[0.1.0]: https://github.com/MetaMask/toprf-secure-backup/releases/tag/@metamask/toprf-secure-backup@0.1.0
