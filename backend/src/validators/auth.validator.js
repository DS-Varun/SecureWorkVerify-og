/**
 * Validation rules for authentication endpoints.
 * Uses express-validator.
 *
 * SECURITY: Registration does NOT accept a role field.
 * Public registration always creates a USER. Privileged roles are
 * assigned only by ADMIN via separate promotion endpoints.
 */

const { body, validationResult } = require('express-validator');
const { error: errorResponse } = require('../utils/apiResponse');

/**
 * Middleware to check validation results.
 * Returns 400 with details if validation fails.
 */
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages = errors.array().map((err) => err.msg);
    return errorResponse(res, 'Validation failed', 400, messages);
  }
  next();
};

/**
 * Registration validation rules.
 * Role is intentionally not accepted — always set to USER server-side.
 */
const registerRules = [
  body('name')
    .trim()
    .notEmpty().withMessage('Name is required')
    .isLength({ min: 2, max: 100 }).withMessage('Name must be 2-100 characters'),

  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Must be a valid email')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[0-9]/).withMessage('Password must contain at least one number'),

  validate,
];

/**
 * Login validation rules.
 */
const loginRules = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Must be a valid email')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required'),

  validate,
];

module.exports = { registerRules, loginRules, validate };
