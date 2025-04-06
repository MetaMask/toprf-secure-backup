# `toprf-secure-backup-sdk`

This monorepo implements the SRP Backup feature for the MetaMask Wallet.

## Contributing

See the [Contributor Guide](./docs/contributing.md) for help on:

- Setting up your development environment
- Working with the monorepo
- Testing changes in clients
- Issuing new releases
- Creating a new package

## Installation/Usage

```bash
yarn
yarn build
yarn test
```

Each package in this repository has its own README where you can find installation and usage instructions. See `packages/` for more.

## Packages

<!-- start package list -->

- [`@metamask/auth-network-utils`](packages/auth-network-utils)
- [`@metamask/toprf-secure-backup`](packages/toprf-secure-backup)

<!-- end package list -->

<!-- start dependency graph -->

```mermaid
%%{ init: { 'flowchart': { 'curve': 'bumpX' } } }%%
graph LR;
linkStyle default opacity:0.5
  auth_network_utils(["@metamask/auth-network-utils"]);
  toprf_secure_backup(["@metamask/toprf-secure-backup"]);
  toprf_secure_backup --> auth_network_utils;
```

<!-- end dependency graph -->

(This section may be regenerated at any time by running `yarn update-readme-content`.)
