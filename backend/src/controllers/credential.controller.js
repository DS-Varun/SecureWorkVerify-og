/**
 * Credential controller.
 * Handles HTTP request/response for credential issuance, listing, retrieval,
 * versioning, and revocation endpoints.
 *
 * SECURITY:
 * - Private keys are never touched or returned here.
 * - RBAC and role scoping are enforced at route and service levels.
 */

'use strict';

const credentialService = require('../services/credential.service');
const { success, error: errorResponse } = require('../utils/apiResponse');

/**
 * POST /api/credentials/issue
 * Issue a new signed credential (ISSUER only, must be ACTIVE).
 */
const issue = async (req, res, next) => {
  try {
    if (!req.file) {
      return errorResponse(res, 'Document file is required (field name: document)', 400);
    }

    const {
      recipientId,
      credentialType,
      title,
      description,
      expiresAt,
      representationType,
    } = req.body;

    const result = await credentialService.issueCredential({
      issuingUserId: req.user._id,
      recipientId,
      credentialType,
      title,
      description,
      expiresAt,
      fileBuffer: req.file.buffer,
      originalFilename: req.file.originalname,
      mimeType: req.file.mimetype,
      fileSize: req.file.size,
      representationType,
    });

    return success(res, result, 'Credential issued successfully', 201);
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/credentials
 * List credentials with role-based scoping (ADMIN, ISSUER, HR, USER).
 */
const list = async (req, res, next) => {
  try {
    const { status, page, limit } = req.query;
    const result = await credentialService.listCredentials({
      user: req.user,
      status,
      page,
      limit,
    });

    return success(res, result, 'Credentials retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/credentials/:id
 * Get single credential details (scoped by role).
 */
const getById = async (req, res, next) => {
  try {
    const credential = await credentialService.getCredential({
      credentialId: req.params.id,
      user: req.user,
    });

    return success(res, { credential }, 'Credential retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/credentials/:id/versions
 * Get all versions of a credential (scoped by role).
 */
const getVersions = async (req, res, next) => {
  try {
    const versions = await credentialService.getCredentialVersions({
      credentialId: req.params.id,
      user: req.user,
    });

    return success(res, { versions }, 'Credential versions retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/credentials/:id/versions
 * Create a new version of an existing credential (ISSUER only).
 */
const addVersion = async (req, res, next) => {
  try {
    if (!req.file) {
      return errorResponse(res, 'Document file is required (field name: document)', 400);
    }

    const { changeReason, representationType } = req.body;

    const result = await credentialService.addCredentialVersion({
      credentialId: req.params.id,
      issuingUserId: req.user._id,
      fileBuffer: req.file.buffer,
      originalFilename: req.file.originalname,
      mimeType: req.file.mimetype,
      fileSize: req.file.size,
      changeReason,
      representationType,
    });

    return success(res, result, 'Credential version created successfully', 201);
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/credentials/:id/revoke
 * Revoke a credential (ISSUER only — own credentials).
 */
const revoke = async (req, res, next) => {
  try {
    const { reason } = req.body;
    const credential = await credentialService.revokeCredential({
      credentialId: req.params.id,
      issuingUserId: req.user._id,
      reason,
    });

    return success(res, { credential }, 'Credential revoked successfully');
  } catch (err) {
    next(err);
  }
};

module.exports = {
  issue,
  list,
  getById,
  getVersions,
  addVersion,
  revoke,
};
