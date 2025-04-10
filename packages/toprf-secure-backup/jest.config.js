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
      statements: 95,
      branches: 63.63,
      functions: 100,
      lines: 94.82,
    },
    './src/toprfSecureBackup.ts': {
      statements: 98.78,
      branches: 83.33,
      functions: 100,
      lines: 98.78,
    },
  },
});
