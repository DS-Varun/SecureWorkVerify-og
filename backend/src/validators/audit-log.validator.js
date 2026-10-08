/**
 * Audit log validators (M6).
 *
 * AUDITOR and ADMIN read-only access — no create/update/delete validators.
 * Validates query parameters for listing and filtering audit entries.
 */

'use strict';

const { query, param, validationResult } = require('express-validator');
const { AUDIT_ACTIONS, AUDIT_TARGET_TYPES } = require('../models/AuditLog');
const { error: errorResponse } = require('../utils/apiResponse');

/**
 * Shared handler that checks validation results and returns 400 on failure.
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return errorResponse(
      res,
      'Validation failed',
      400,
      errors.array().map((e) => ({ field: e.path, message: e.msg }))
    );
  }
  next();
};

/**
 * GET /api/audit-logs
 * Query params: page, limit, action, targetType, targetId, startDate, endDate
 */
const listAuditLogsQuery = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('limit must be between 1 and 100'),

  query('action')
    .optional()
    .isIn(AUDIT_ACTIONS)
    .withMessage(`action must be one of: ${AUDIT_ACTIONS.join(', ')}`),

  query('targetType')
    .optional()
    .isIn(AUDIT_TARGET_TYPES)
    .withMessage(`targetType must be one of: ${AUDIT_TARGET_TYPES.join(', ')}`),

  query('targetId')
    .optional()
    .isMongoId()
    .withMessage('targetId must be a valid MongoDB ObjectId'),

  query('performedBy')
    .optional()
    .isMongoId()
    .withMessage('performedBy must be a valid MongoDB ObjectId'),

  query('startDate')
    .optional()
    .isISO8601()
    .withMessage('startDate must be a valid ISO 8601 date'),

  query('endDate')
    .optional()
    .isISO8601()
    .withMessage('endDate must be a valid ISO 8601 date'),

  handleValidationErrors,
];

/**
 * Validate :id param for credential timeline.
 */
const validateTimelineId = [
  param('id')
    .isMongoId()
    .withMessage('Credential ID must be a valid MongoDB ObjectId'),

  handleValidationErrors,
];

module.exports = {
  listAuditLogsQuery,
  validateTimelineId,
};
