/**
 * Auth controller.
 * Handles HTTP request/response for authentication endpoints.
 */

const authService = require('../services/auth.service');
const { success, error: errorResponse } = require('../utils/apiResponse');

/**
 * POST /api/auth/register
 */
const register = async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body;
    const { user, token } = await authService.register({ name, email, password, role });

    return success(
      res,
      { user, token },
      'User registered successfully',
      201
    );
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/auth/login
 */
const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const { user, token } = await authService.login({ email, password });

    return success(
      res,
      { user, token },
      'Login successful'
    );
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/auth/me
 * Returns the currently authenticated user's profile.
 */
const getMe = async (req, res, next) => {
  try {
    return success(res, { user: req.user }, 'User profile retrieved');
  } catch (err) {
    next(err);
  }
};

module.exports = { register, login, getMe };
