/**
 * Health check controller.
 * Returns API status, database status, and server timestamp.
 */

const mongoose = require('mongoose');
const { success } = require('../utils/apiResponse');

/**
 * GET /api/health
 */
const getHealth = async (req, res) => {
  const dbStates = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting',
  };

  const dbState = mongoose.connection.readyState;

  return success(res, {
    api: 'operational',
    database: dbStates[dbState] || 'unknown',
    timestamp: new Date().toISOString(),
  }, 'Health check passed');
};

module.exports = { getHealth };
