/**
 * Standardized API response helpers.
 * All API responses follow a consistent format.
 */

/**
 * Send a success response.
 * @param {import('express').Response} res
 * @param {*} data - Response payload
 * @param {string} [message='Success'] - Human-readable message
 * @param {number} [statusCode=200] - HTTP status code
 */
const success = (res, data = null, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({
    success: true,
    message,
    data,
  });
};

/**
 * Send an error response.
 * @param {import('express').Response} res
 * @param {string} message - Error description
 * @param {number} [statusCode=500] - HTTP status code
 * @param {*} [errors=null] - Validation errors or additional details
 */
const error = (res, message = 'Internal Server Error', statusCode = 500, errors = null) => {
  const response = {
    success: false,
    error: {
      message,
      ...(errors && { details: errors }),
    },
  };
  return res.status(statusCode).json(response);
};

module.exports = { success, error };
