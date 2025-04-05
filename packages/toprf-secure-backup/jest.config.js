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
      branches: 80,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './src/toprfEvalRequest.ts': {
      statements: 90,
      branches: 50,
      functions: 90,
      lines: 90,
    },
    './src/toprfSecureBackup.ts': {
      statements: 90,
      branches: 70,
      functions: 90,
      lines: 90,
    },
  },
});
