/**
 * Validation schemas for Verification endpoints.
 * Uses express-validator consistent with existing validators.
 */

'use strict';

const { param, query, validationResult } = require('express-validator');
const { error: errorResponse } = require('../utils/apiResponse');
const { VERIFICATION_RESULTS } = require('../models/Verification');

// ─── validate middleware ───────────────────────────────────────────────────────

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages = errors.array().map((err) => err.msg);
    return errorResponse(res, 'Validation failed', 400, messages);
  }
  next();
};

// ─── Verification ID param ────────────────────────────────────────────────────

const validateVerificationId = [
  param('id')
    .notEmpty()
    .withMessage('id param is required')
    .isMongoId()
    .withMessage('id must be a valid MongoDB ObjectId'),
  validate,
];

// ─── List verifications query filters ─────────────────────────────────────────

const listVerificationsQuery = [
  query('result')
    .optional()
    .isIn(VERIFICATION_RESULTS)
    .withMessage(`result must be one of: ${VERIFICATION_RESULTS.join(', ')}`),

  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('limit must be between 1 and 100'),

  validate,
];

module.exports = {
  validateVerificationId,
  listVerificationsQuery,
  validate,
};
