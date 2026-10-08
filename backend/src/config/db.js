/**
 * MongoDB connection using Mongoose.
 */

const mongoose = require('mongoose');
const config = require('./env');

/**
 * Connect to MongoDB.
 * @returns {Promise<void>}
 */
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(config.mongodbUri);
    console.log(`✅ MongoDB connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`❌ MongoDB connection error: ${error.message}`);
    process.exit(1);
  }
};

/**
 * Disconnect from MongoDB.
 * @returns {Promise<void>}
 */
const disconnectDB = async () => {
  await mongoose.disconnect();
};

module.exports = { connectDB, disconnectDB };
