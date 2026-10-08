/**
 * Jest configuration for SecureWork Verify backend tests.
 */

module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  // Increase timeout for DB operations
  testTimeout: 15000,
  // Run setup before all test suites
  globalSetup: './tests/setup.js',
  // Run teardown after all test suites
  globalTeardown: './tests/teardown.js',
  // maxWorkers:1 forces single-process execution (equivalent to --runInBand).
  // Required on Windows when the project path contains spaces
  // (e.g. "Camera Roll/OneDrive/Documents") — Jest worker IPC channels
  // fail silently when path quoting is inconsistent across worker forks.
  // This does NOT change test behavior or results.
  maxWorkers: 1,
};
