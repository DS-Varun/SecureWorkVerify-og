/**
 * Test helper utilities.
 * Enforces strict safety guards to prevent accidental deletion of development/production data.
 */

'use strict';

const mongoose = require('mongoose');

/**
 * Asserts that the current database connection is strictly a dedicated test database.
 * Aborts execution immediately if not in test environment or database name does not contain 'test'.
 */
const assertTestDatabase = () => {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(
      `FATAL: Destructive test cleanup aborted. NODE_ENV is '${process.env.NODE_ENV}', expected 'test'.`
    );
  }

  const dbName = mongoose.connection.name || '';
  const uri = process.env.MONGODB_URI || '';

  if (!dbName.includes('test') && !uri.includes('test')) {
    throw new Error(
      `FATAL: Destructive test cleanup aborted. Database '${dbName || uri}' is not a dedicated test database.`
    );
  }
};

/**
 * Connect to test database with safety verification.
 */
const connectTestDB = async () => {
  if (mongoose.connection.readyState === 0) {
    const testUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/securework-verify-test';
    await mongoose.connect(testUri);
  }
  assertTestDatabase();
};

/**
 * Disconnect from test database.
 */
const disconnectTestDB = async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
};

module.exports = {
  assertTestDatabase,
  connectTestDB,
  disconnectTestDB,
};
