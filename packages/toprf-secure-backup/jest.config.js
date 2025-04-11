/*
 * For a detailed explanation regarding each configuration property and type check, visit:
 * https://jestjs.io/docs/configuration
 */

const merge = require('deepmerge');
const path = require('path');

const baseConfig = require('../../jest.config.packages');

const displayName = path.basename(__dirname);

module.exports = merge(baseConfig, {
  // The display name when running multiple projects
  displayName,

  // Setup files to run before tests
  setupFiles: ['./tests/setup.ts'],

  // An object that configures minimum threshold enforcement for coverage results
  coverageThreshold: {
    global: {
      statements: 100,
      branches: 100,
      functions: 100,
      lines: 100,
    },
    './src/toprfEvalRequest.ts': {
      statements: 100,
      branches: 92.3,
      functions: 100,
      lines: 100,
    },
    './src/toprfSecureBackup.ts': {
      statements: 97.97,
      branches: 93.75,
      functions: 100,
      lines: 97.97,
    },
  },
});
