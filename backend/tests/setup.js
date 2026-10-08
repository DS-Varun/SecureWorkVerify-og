/**
 * Global test setup.
 * Configures test environment variables.
 * Uses a separate test database on local MongoDB.
 */

module.exports = async () => {
  // Use a dedicated test database to avoid polluting dev data
  process.env.MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/securework-verify-test';
  process.env.JWT_SECRET = 'test-jwt-secret-do-not-use-in-production';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.NODE_ENV = 'test';
};
