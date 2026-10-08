/**
 * Validation schemas for Credential endpoints.
 * Uses the same express-validator pattern as organization.validator.js.
 */

'use strict';

const { body, param, query, validationResult } = require('express-validator');
const { error: errorResponse } = require('../utils/apiResponse');
const { CREDENTIAL_TYPES, CREDENTIAL_STATUSES } = require('../models/Credential');

// ─── validate middleware ───────────────────────────────────────────────────────

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages = errors.array().map((err) => err.msg);
    return errorResponse(res, 'Validation failed', 400, messages);
  }
  next();
};

// ─── Issue credential ─────────────────────────────────────────────────────────

const validateIssueCredential = [
  body('recipientId')
    .notEmpty()
    .withMessage('recipientId is required')
    .isMongoId()
    .withMessage('recipientId must be a valid MongoDB ObjectId'),

  body('credentialType')
    .notEmpty()
    .withMessage('credentialType is required')
    .isIn(CREDENTIAL_TYPES)
    .withMessage(`credentialType must be one of: ${CREDENTIAL_TYPES.join(', ')}`),

  body('title')
    .trim()
    .notEmpty()
    .withMessage('title is required')
    .isLength({ min: 2, max: 200 })
    .withMessage('title must be between 2 and 200 characters'),

  body('description')
    .optional({ nullable: true, checkFalsy: true })
    .isString()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('description cannot exceed 2000 characters'),

  body('expiresAt')
    .optional({ nullable: true, checkFalsy: true })
    .isISO8601()
    .withMessage('expiresAt must be a valid ISO 8601 date')
    .toDate()
    .custom((value) => {
      if (value && value <= new Date()) {
        throw new Error('expiresAt must be in the future');
      }
      return true;
    }),

  body('representationType')
    .optional()
    .isIn(['ORIGINAL_DIGITAL_FILE', 'PDF', 'IMAGE', 'SCAN', 'SCREENSHOT', 'OTHER'])
    .withMessage('Invalid representationType'),

  validate,
];

// ─── Credential ID param ──────────────────────────────────────────────────────

const validateCredentialId = [
  param('id')
    .notEmpty()
    .withMessage('id param is required')
    .isMongoId()
    .withMessage('id must be a valid MongoDB ObjectId'),
  validate,
];

// ─── List credentials query ───────────────────────────────────────────────────

const listCredentialsQuery = [
  query('status')
    .optional()
    .isIn(CREDENTIAL_STATUSES)
    .withMessage(`status must be one of: ${CREDENTIAL_STATUSES.join(', ')}`),
  validate,
];

// ─── Add version ──────────────────────────────────────────────────────────────

const validateAddVersion = [
  param('id')
    .notEmpty()
    .withMessage('id param is required')
    .isMongoId()
    .withMessage('id must be a valid MongoDB ObjectId'),

  body('changeReason')
    .trim()
    .notEmpty()
    .withMessage('changeReason is required')
    .isLength({ min: 3, max: 500 })
    .withMessage('changeReason must be between 3 and 500 characters'),

  body('representationType')
    .optional()
    .isIn(['ORIGINAL_DIGITAL_FILE', 'PDF', 'IMAGE', 'SCAN', 'SCREENSHOT', 'OTHER'])
    .withMessage('Invalid representationType'),

  validate,
];

// ─── Revoke credential ────────────────────────────────────────────────────────

const validateRevokeCredential = [
  param('id')
    .notEmpty()
    .withMessage('id param is required')
    .isMongoId()
    .withMessage('id must be a valid MongoDB ObjectId'),

  body('reason')
    .trim()
    .notEmpty()
    .withMessage('reason is required')
    .isLength({ min: 3, max: 500 })
    .withMessage('reason must be between 3 and 500 characters'),

  validate,
];

module.exports = {
  validateIssueCredential,
  validateCredentialId,
  listCredentialsQuery,
  validateAddVersion,
  validateRevokeCredential,
  validate,
};
