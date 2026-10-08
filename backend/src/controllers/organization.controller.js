/**
 * Organization controller.
 * Handles HTTP request/response for organization management and trust lifecycle endpoints.
 */

'use strict';

const organizationService = require('../services/organization.service');
const { success } = require('../utils/apiResponse');

/**
 * POST /api/organizations
 * Create a new organization (ADMIN only).
 */
const create = async (req, res, next) => {
  try {
    const { name, type, officialDomain, description } = req.body;
    const organization = await organizationService.createOrganization({
      name,
      type,
      officialDomain,
      description,
      createdBy: req.user._id,
    });

    return success(
      res,
      { organization },
      'Organization created successfully',
      201
    );
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/organizations
 * List organizations with pagination and filtering.
 */
const list = async (req, res, next) => {
  try {
    const { organizationVerificationStatus, status, type, page, limit } = req.query;
    const result = await organizationService.listOrganizations({
      organizationVerificationStatus,
      status,
      type,
      page,
      limit,
    });

    return success(res, result, 'Organizations retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/organizations/:id
 * Get single organization by ID with full verification event history.
 */
const getById = async (req, res, next) => {
  try {
    const organization = await organizationService.getOrganization(req.params.id);
    return success(res, { organization }, 'Organization retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * POST /api/organizations/:id/verify
 * Establish organization trust via ADMIN_REVIEW (ADMIN only).
 */
const verify = async (req, res, next) => {
  try {
    const { verificationMethod, evidence } = req.body;
    const organization = await organizationService.verifyOrganization({
      orgId: req.params.id,
      adminUserId: req.user._id,
      verificationMethod: verificationMethod || 'ADMIN_REVIEW',
      evidence,
    });

    return success(
      res,
      { organization },
      'Organization verified successfully'
    );
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/organizations/:id/suspend
 * Temporarily suspend organization trust (ADMIN only).
 */
const suspend = async (req, res, next) => {
  try {
    const { reason } = req.body;
    const organization = await organizationService.suspendOrganization({
      orgId: req.params.id,
      adminUserId: req.user._id,
      reason,
    });

    return success(
      res,
      { organization },
      'Organization suspended successfully'
    );
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/organizations/:id/revoke
 * Permanently revoke organization trust (ADMIN only).
 */
const revoke = async (req, res, next) => {
  try {
    const { reason } = req.body;
    const organization = await organizationService.revokeOrganization({
      orgId: req.params.id,
      adminUserId: req.user._id,
      reason,
    });

    return success(
      res,
      { organization },
      'Organization revoked successfully'
    );
  } catch (err) {
    next(err);
  }
};

module.exports = {
  create,
  list,
  getById,
  verify,
  suspend,
  revoke,
};
