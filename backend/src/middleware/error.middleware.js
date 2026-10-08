/**
 * Centralized error handling middleware.
 * Must be registered after all routes.
 */

const multer = require('multer');
const config = require('../config/env');
const { error: errorResponse } = require('../utils/apiResponse');

/**
 * Handle 404 - Route not found.
 */
const notFound = (req, res, next) => {
  return errorResponse(res, `Route not found: ${req.method} ${req.originalUrl}`, 404);
};

/**
 * Global error handler.
 * Catches all errors passed via next(err).
 */
// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  if (config.nodeEnv !== 'test') {
    console.error(`❌ Error: ${err.message}`);
  }

  // Multer file upload errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return errorResponse(
        res,
        `File too large. Maximum allowed size is ${config.maxFileSizeMb} MB.`,
        413
      );
    }
    return errorResponse(res, `File upload error: ${err.message}`, 400);
  }

  // Custom MIME type rejection (thrown by upload middleware fileFilter)
  if (err.code === 'UNSUPPORTED_FILE_TYPE') {
    return errorResponse(res, err.message, 415);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((e) => e.message);
    return errorResponse(res, 'Validation failed', 400, messages);
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return errorResponse(res, `Duplicate value for field: ${field}`, 409);
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return errorResponse(res, 'Invalid token', 401);
  }
  if (err.name === 'TokenExpiredError') {
    return errorResponse(res, 'Token expired', 401);
  }

  // Default
  const statusCode = err.statusCode || 500;
  const message =
    config.nodeEnv === 'production'
      ? 'Internal Server Error'
      : err.message || 'Internal Server Error';

  return errorResponse(res, message, statusCode);
};

module.exports = { notFound, errorHandler };
