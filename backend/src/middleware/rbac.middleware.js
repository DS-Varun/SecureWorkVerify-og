/**
 * Role-Based Access Control middleware.
 * Must be used AFTER authenticate middleware.
 */

const { error: errorResponse } = require('../utils/apiResponse');

/**
 * Factory function that returns middleware to check if the user has
 * one of the allowed roles.
 * @param {...string} allowedRoles - Roles permitted to access the route
 * @returns {Function} Express middleware
 *
 * @example
 * router.get('/admin-only', authenticate, authorize('ADMIN'), handler);
 * router.get('/multi', authenticate, authorize('ADMIN', 'AUDITOR'), handler);
 */
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return errorResponse(res, 'Authentication required.', 401);
    }

    if (!allowedRoles.includes(req.user.role)) {
      return errorResponse(
        res,
        `Access denied. Required role(s): ${allowedRoles.join(', ')}`,
        403
      );
    }

    next();
  };
};

module.exports = { authorize };
