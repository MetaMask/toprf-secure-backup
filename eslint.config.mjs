import base, { createConfig } from '@metamask/eslint-config';
import jest from '@metamask/eslint-config-jest';
import nodejs from '@metamask/eslint-config-nodejs';
import typescript from '@metamask/eslint-config-typescript';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const NODE_LTS_VERSION = 22;
const configDirName = dirname(fileURLToPath(import.meta.url));

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
      'no-restricted-globals': 'off',
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
    settings: {
      node: {
        version: `^${NODE_LTS_VERSION}`,
      },
    },
    languageOptions: {
      parserOptions: {
        tsconfigRootDir: configDirName,
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
      // This is taken directly from @metamask/eslint-config-typescript@12.1.0
      '@typescript-eslint/naming-convention': [
        'warn',
        // We have to disable the default selector for our objectLiteralProperty
        // filter to work.
        // {
        //   selector: 'default',
        //   format: ['camelCase'],
        //   leadingUnderscore: 'allow',
        //   trailingUnderscore: 'forbid',
        // },
        {
          selector: 'enumMember',
          format: ['PascalCase'],
        },
        {
          selector: 'interface',
          format: ['PascalCase'],
          custom: {
            regex: '^I[A-Z]',
            match: false,
          },
        },
        {
          selector: 'objectLiteralProperty',
          format: null, // no format requirements for numeric keys
          filter: {
            regex: '^[0-9]+$',
            match: true,
          },
        },
        // This option is modified by the addition of a filter.
        {
          selector: 'objectLiteralProperty',
          format: ['camelCase', 'PascalCase', 'UPPER_CASE'],
          filter: {
            // Match RPC method names like foo_bar, foo_barBaz, etc., and metamask.io
            regex: '(^[a-z]+_[a-z]+[a-zA-Z0-9]*)|metamask\\.io$',
            match: false,
          },
        },

        {
          selector: 'typeLike',
          format: ['PascalCase'],
        },
        {
          selector: 'typeParameter',
          format: ['PascalCase'],
          custom: {
            regex: '^.{3,}',
            match: true,
          },
        },
        {
          selector: 'variable',
          format: ['camelCase', 'UPPER_CASE', 'PascalCase'],
          leadingUnderscore: 'allow',
        },
        {
          selector: 'parameter',
          format: ['camelCase', 'PascalCase'],
          leadingUnderscore: 'allow',
        },
        {
          selector: [
            'classProperty',
            'objectLiteralProperty',
            'typeProperty',
            'classMethod',
            'objectLiteralMethod',
            'typeMethod',
            'accessor',
            'enumMember',
          ],
          format: null,
          modifiers: ['requiresQuotes'],
        },
      ],
      '@typescript-eslint/prefer-nullish-coalescing': 'warn',
      '@typescript-eslint/prefer-optional-chain': 'warn',
      '@typescript-eslint/prefer-reduce-type-parameter': 'warn',
      '@typescript-eslint/promise-function-async': 'warn',
      'jsdoc/require-jsdoc': [
        'error',
        {
          require: {
            FunctionDeclaration: true,
            MethodDefinition: true,
            ClassDeclaration: true,
            ArrowFunctionExpression: true,
            FunctionExpression: true,
          },
        },
      ],
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
