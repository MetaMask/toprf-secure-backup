# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/MetaMask/toprf-secure-backup/compare/@metamask/toprf-secure-backup@0.1.0...HEAD
[0.1.0]: https://github.com/MetaMask/toprf-secure-backup/releases/tag/@metamask/toprf-secure-backup@0.1.0
