/**
 * JWT authentication middleware.
 * Verifies the Bearer token and attaches the user to req.user.
 */

const jwt = require('jsonwebtoken');
const config = require('../config/env');
const { User } = require('../models/User');
const { error: errorResponse } = require('../utils/apiResponse');

/**
 * Authenticate the request using JWT.
 * Expects header: Authorization: Bearer <token>
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return errorResponse(res, 'Authentication required. No token provided.', 401);
    }

    const token = authHeader.split(' ')[1];

    // Verify token
    const decoded = jwt.verify(token, config.jwtSecret);

    // Find user and confirm they are active
    const user = await User.findById(decoded.userId);

    if (!user) {
      return errorResponse(res, 'User not found. Token may be invalid.', 401);
    }

    if (!user.isActive) {
      return errorResponse(res, 'Account is deactivated.', 403);
    }

    // Attach user to request
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError') {
      return errorResponse(res, 'Invalid token.', 401);
    }
    if (err.name === 'TokenExpiredError') {
      return errorResponse(res, 'Token expired.', 401);
    }
    next(err);
  }
};

module.exports = { authenticate };
