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
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
    './src/resetRateLimits.ts': {
      statements: 86.04,
      branches: 41.66,
      functions: 100,
      lines: 84.61,
    },
    './src/toprfEvalRequest.ts': {
      statements: 91.17,
      branches: 55.55,
      functions: 100,
      lines: 90.62,
    },
    './src/toprfSecureBackup.ts': {
      statements: 96.36,
      branches: 75,
      functions: 90,
      lines: 96.36,
    },
  },
});
