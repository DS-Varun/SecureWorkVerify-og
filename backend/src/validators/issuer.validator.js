/**
 * Validation schemas for Issuer endpoints.
 * Uses the same express-validator pattern as organization.validator.js.
 */

'use strict';

const { body, param, query, validationResult } = require('express-validator');
const { error: errorResponse } = require('../utils/apiResponse');
const { ISSUER_STATUSES } = require('../models/Issuer');

// ─── validate middleware ───────────────────────────────────────────────────────

const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const messages = errors.array().map((err) => err.msg);
    return errorResponse(res, 'Validation failed', 400, messages);
  }
  next();
};

// ─── Register Issuer ──────────────────────────────────────────────────────────

const validateRegisterIssuer = [
  body('organizationId')
    .notEmpty()
    .withMessage('organizationId is required')
    .isMongoId()
    .withMessage('organizationId must be a valid MongoDB ObjectId'),

  body('authorizationEvidence')
    .optional()
    .isObject()
    .withMessage('authorizationEvidence must be an object'),

  body('authorizationEvidence.invitationLetter')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('invitationLetter cannot exceed 2000 characters'),

  body('authorizationEvidence.institutionalEmail')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('institutionalEmail must be a valid email address'),

  body('authorizationEvidence.additionalNotes')
    .optional()
    .isString()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('additionalNotes cannot exceed 2000 characters'),

  validate,
];

// ─── Issuer ID param ──────────────────────────────────────────────────────────

const validateIssuerId = [
  param('id')
    .notEmpty()
    .withMessage('id param is required')
    .isMongoId()
    .withMessage('id must be a valid MongoDB ObjectId'),
  validate,
];

// ─── Issuer Key ID param ──────────────────────────────────────────────────────

const validateIssuerKeyId = [
  param('id')
    .notEmpty()
    .withMessage('id param is required')
    .isMongoId()
    .withMessage('id must be a valid MongoDB ObjectId'),
  validate,
];

// ─── List issuers query filters ────────────────────────────────────────────────

const listIssuersQuery = [
  query('status')
    .optional()
    .isIn(ISSUER_STATUSES)
    .withMessage(`status must be one of: ${ISSUER_STATUSES.join(', ')}`),

  query('organizationId')
    .optional()
    .isMongoId()
    .withMessage('organizationId must be a valid MongoDB ObjectId'),

  validate,
];

// ─── Suspend/Revoke/Compromise reason ─────────────────────────────────────────

const validateStatusChangeReason = [
  body('reason')
    .notEmpty()
    .withMessage('reason is required')
    .isString()
    .withMessage('reason must be a string')
    .trim()
    .isLength({ min: 3, max: 500 })
    .withMessage('reason must be between 3 and 500 characters'),
  validate,
];

module.exports = {
  validateRegisterIssuer,
  validateIssuerId,
  validateIssuerKeyId,
  listIssuersQuery,
  validateStatusChangeReason,
  validate,
};
