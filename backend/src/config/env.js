/**
 * Environment configuration.
 * Validates required environment variables on startup.
 * Crashes early with a clear message if any are missing.
 */

const dotenv = require('dotenv');
const path = require('path');

// Load .env from backend root
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const requiredVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'JWT_EXPIRES_IN',
];

const missing = requiredVars.filter((key) => !process.env[key]);

if (missing.length > 0 && process.env.NODE_ENV !== 'test') {
  console.error(
    `\n❌ Missing required environment variables:\n${missing.map((v) => `   - ${v}`).join('\n')}\n`
  );
  console.error('Copy backend/.env.example to backend/.env and fill in the values.\n');
  process.exit(1);
}

const config = {
  port: parseInt(process.env.PORT, 10) || 5000,
  nodeEnv: process.env.NODE_ENV || 'development',
  mongodbUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/securework-verify-test',
  jwtSecret: process.env.JWT_SECRET || 'test-secret',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '24h',
  corsOrigin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  keyStoragePath: process.env.KEY_STORAGE_PATH || './keys',
  documentStoragePath: process.env.DOCUMENT_STORAGE_PATH || './uploads',
  maxFileSizeMb: parseInt(process.env.MAX_FILE_SIZE_MB, 10) || 10,
};

module.exports = config;
