import base, { createConfig } from '@metamask/eslint-config';
import jest from '@metamask/eslint-config-jest';
import nodejs from '@metamask/eslint-config-nodejs';
import typescript from '@metamask/eslint-config-typescript';

const NODE_LTS_VERSION = 22;

const config = createConfig([
  ...base,
  {
    ignores: [
      '**/dist/**',
      '**/docs/**',
      '**/coverage/**',
      'merged-packages/**',
      '.yarn/**',
      'scripts/create-package/package-template/**',
      'yarn.config.cjs',
      '.pnp.*',
    ],
  },
  {
    rules: {
      // TODO: Lint violations for these rules already exist.
      // Please handle these violations so that we do not need to do this.
      'id-denylist': 'warn',
      'id-length': 'warn',
      'no-restricted-globals': 'warn',
      'import-x/no-named-as-default-member': 'warn',
      'import-x/no-unassigned-import': 'warn',
      'import-x/order': 'warn',
    },
  },
  {
    files: [
      '**/*.{js,cjs,mjs}',
      '**/*.test.{js,ts}',
      '**/tests/**/*.{js,ts}',
      'scripts/*.ts',
      'scripts/create-package/**/*.ts',
    ],
    extends: [nodejs],
    rules: {
      // TODO: Lint violations for these rules already exist.
      // Please handle these violations so that we do not need to do this.
      'n/no-sync': 'warn',
    },
  },
  {
    files: ['**/*.test.{js,ts}', '**/tests/**/*.{js,ts}'],
    extends: [jest],
    rules: {
      // We sometimes find conditionals to be useful, especially when mocking
      // functions.
      // Consider disabling this rule in `@metamask/eslint-config`.
      'jest/no-conditional-in-test': 'off',
    },
    settings: {
      node: {
        version: `^${NODE_LTS_VERSION}`,
      },
    },
  },
  {
    files: ['**/*.{js,cjs,mjs}'],
    languageOptions: {
      sourceType: 'script',
      ecmaVersion: 2020,
    },
  },
  {
    files: ['**/*.ts'],
    extends: [typescript],
    languageOptions: {
      parserOptions: {
        tsconfigRootDir: import.meta.dirname,
        project: './tsconfig.json',
        projectService: {
          allowDefaultProject: ['./scripts/*.ts'],
        },
      },
    },
    rules: {
      // We sometimes use enums as substitutes for strings.
      // Consider disabling this rule in `@metamask/eslint-config`.
      '@typescript-eslint/no-unsafe-enum-comparison': 'off',

      // TODO: Lint violations for these rules already exist.
      // Please handle these violations so that we do not need to do this.
      '@typescript-eslint/explicit-function-return-type': 'warn',
      '@typescript-eslint/naming-convention': 'warn',
      '@typescript-eslint/prefer-nullish-coalescing': 'warn',
      '@typescript-eslint/prefer-optional-chain': 'warn',
      '@typescript-eslint/prefer-reduce-type-parameter': 'warn',
      '@typescript-eslint/promise-function-async': 'warn',
    },
  },
  {
    files: ['tests/setupAfterEnv/matchers.ts'],
    languageOptions: {
      sourceType: 'script',
    },
  },
  // This should really be in `@metamask/eslint-config-typescript`
  {
    files: ['**/*.d.ts'],
    rules: {
      '@typescript-eslint/naming-convention': 'warn',
      'import-x/unambiguous': 'off',
    },
  },
  {
    files: ['scripts/*.ts'],
    rules: {
      // Scripts may be self-executable and thus have hashbangs.
      'n/hashbang': 'off',
    },
  },
  {
    files: ['**/jest.environment.js'],
    rules: {
      // These files run under Node, and thus `require(...)` is expected.
      'n/global-require': 'off',
    },
  },
  {
    files: ['**/*.mjs'],
    languageOptions: {
      sourceType: 'module',
    },
  },
]);

export default config;
