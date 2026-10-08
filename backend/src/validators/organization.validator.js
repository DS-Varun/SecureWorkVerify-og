/**
 * Validation rules for organization endpoints.
 * Uses express-validator.
 */

'use strict';

const { body, param, query, validationResult } = require('express-validator');
const { error: errorResponse } = require('../utils/apiResponse');
const {
  ORG_TYPES,
  ORG_VERIFICATION_STATUSES,
  ORG_STATUSES,
} = require('../models/Organization');

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
 * Validates MongoDB ObjectId in URL params.
 */
const paramIdRule = [
  param('id')
    .isMongoId()
    .withMessage('Invalid organization ID format'),
  validate,
];

/**
 * Organization creation validation rules.
 */
const createOrgRules = [
  body('name')
    .trim()
    .notEmpty().withMessage('Organization name is required')
    .isLength({ min: 2, max: 200 }).withMessage('Organization name must be 2-200 characters'),

  body('type')
    .trim()
    .notEmpty().withMessage('Organization type is required')
    .isIn(ORG_TYPES).withMessage(`Organization type must be one of: ${ORG_TYPES.join(', ')}`),

  body('officialDomain')
    .optional({ nullable: true, checkFalsy: true })
    .trim()
    .isLength({ max: 253 }).withMessage('Official domain cannot exceed 253 characters'),

  body('description')
    .optional({ nullable: true, checkFalsy: true })
    .trim()
    .isLength({ max: 1000 }).withMessage('Description cannot exceed 1000 characters'),

  validate,
];

/**
 * Organization verification validation rules.
 * Requires verificationMethod 'ADMIN_REVIEW' and evidence with notes and reference.
 */
const verifyOrgRules = [
  body('verificationMethod')
    .optional()
    .equals('ADMIN_REVIEW')
    .withMessage("In v1, only 'ADMIN_REVIEW' verification method is supported"),

  body('evidence')
    .notEmpty().withMessage('Verification evidence object is required')
    .isObject().withMessage('Verification evidence must be an object'),

  body('evidence.notes')
    .trim()
    .notEmpty().withMessage('Verification evidence notes are required')
    .isLength({ min: 5, max: 2000 }).withMessage('Verification evidence notes must be 5-2000 characters'),

  body('evidence.reference')
    .trim()
    .notEmpty().withMessage('Verification evidence reference or document ID is required')
    .isLength({ min: 2, max: 200 }).withMessage('Verification reference must be 2-200 characters'),

  validate,
];

/**
 * Organization suspension validation rules.
 */
const suspendOrgRules = [
  body('reason')
    .trim()
    .notEmpty().withMessage('Suspension reason is required')
    .isLength({ min: 3, max: 500 }).withMessage('Suspension reason must be 3-500 characters'),

  validate,
];

/**
 * Organization revocation validation rules.
 */
const revokeOrgRules = [
  body('reason')
    .trim()
    .notEmpty().withMessage('Revocation reason is required')
    .isLength({ min: 3, max: 500 }).withMessage('Revocation reason must be 3-500 characters'),

  validate,
];

/**
 * Query filter validation rules.
 */
const listOrgQueryRules = [
  query('organizationVerificationStatus')
    .optional()
    .isIn(ORG_VERIFICATION_STATUSES)
    .withMessage(`organizationVerificationStatus must be one of: ${ORG_VERIFICATION_STATUSES.join(', ')}`),

  query('status')
    .optional()
    .isIn(ORG_STATUSES)
    .withMessage(`status must be one of: ${ORG_STATUSES.join(', ')}`),

  query('type')
    .optional()
    .isIn(ORG_TYPES)
    .withMessage(`type must be one of: ${ORG_TYPES.join(', ')}`),

  validate,
];

module.exports = {
  paramIdRule,
  createOrgRules,
  verifyOrgRules,
  suspendOrgRules,
  revokeOrgRules,
  listOrgQueryRules,
  validate,
};
