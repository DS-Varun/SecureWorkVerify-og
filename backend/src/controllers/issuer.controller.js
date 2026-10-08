/**
 * Issuer controller.
 * Handles HTTP request/response for issuer and issuer-key lifecycle endpoints.
 *
 * SECURITY:
 * - Private key bytes are NEVER returned in any response here.
 * - privateKeyReference field is excluded from Mongoose queries (select: false).
 * - issuerKey responses only expose: _id, issuerId, keyId, algorithm, publicKey, status, timestamps.
 */

'use strict';

const issuerService = require('../services/issuer.service');
const { success } = require('../utils/apiResponse');

// ─── IssuerKey safe projection ────────────────────────────────────────────────

/**
 * Strip sensitive fields from an IssuerKey document before sending to client.
 * Never returns privateKeyReference.
 * @param {Object} key - IssuerKey mongoose document or plain object
 * @returns {Object} Safe key object
 */
const safeKeyResponse = (key) => {
  const obj = key.toObject ? key.toObject() : { ...key };
  delete obj.privateKeyReference;
  delete obj.__v;
  return obj;
};

// ─── Issuer Endpoints ─────────────────────────────────────────────────────────

/**
 * POST /api/issuers/register
 * Register an issuer profile for the authenticated ISSUER-role user.
 * Status starts PENDING.
 */
const register = async (req, res, next) => {
  try {
    const { organizationId, authorizationEvidence } = req.body;
    const issuer = await issuerService.registerIssuer({
      userId: req.user._id,
      organizationId,
      authorizationEvidence,
    });

    return success(res, { issuer }, 'Issuer registration submitted. Awaiting ADMIN approval.', 201);
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/issuers/me
 * Get the authenticated ISSUER-role user's own issuer profile.
 */
const getMyProfile = async (req, res, next) => {
  try {
    const issuer = await issuerService.getMyIssuerProfile(req.user._id);
    return success(res, { issuer }, 'Issuer profile retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/issuers
 * List all issuers (ADMIN only) with pagination and status filtering.
 */
const list = async (req, res, next) => {
  try {
    const { status, organizationId, page, limit } = req.query;
    const result = await issuerService.listIssuers({ status, organizationId, page, limit });
    return success(res, result, 'Issuers retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/issuers/:id
 * Get a single issuer by ID (ADMIN only).
 */
const getById = async (req, res, next) => {
  try {
    const issuer = await issuerService.getIssuer(req.params.id);
    return success(res, { issuer }, 'Issuer retrieved successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/issuers/:id/approve
 * Approve a PENDING issuer, generate Ed25519 keypair (ADMIN only).
 */
const approve = async (req, res, next) => {
  try {
    const { issuer, issuerKey } = await issuerService.approveIssuer({
      issuerId: req.params.id,
      adminUserId: req.user._id,
    });

    // Never return privateKeyReference
    return success(
      res,
      {
        issuer,
        issuerKey: safeKeyResponse(issuerKey),
      },
      'Issuer approved. Ed25519 keypair generated.'
    );
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/issuers/:id/suspend
 * Suspend an ACTIVE issuer (ADMIN only).
 */
const suspend = async (req, res, next) => {
  try {
    const { reason } = req.body;
    const issuer = await issuerService.suspendIssuer({
      issuerId: req.params.id,
      adminUserId: req.user._id,
      reason,
    });
    return success(res, { issuer }, 'Issuer suspended successfully');
  } catch (err) {
    next(err);
  }
};

/**
 * PATCH /api/issuers/:id/revoke
 * Permanently revoke an issuer and retire the active private key (ADMIN only).
 */
const revoke = async (req, res, next) => {
  try {
    const { reason } = req.body;
    const issuer = await issuerService.revokeIssuer({
      issuerId: req.params.id,
      adminUserId: req.user._id,
      reason,
    });
    return success(res, { issuer }, 'Issuer revoked. Active signing key retired.');
  } catch (err) {
    next(err);
  }
};

// ─── IssuerKey Endpoints ──────────────────────────────────────────────────────

/**
 * PATCH /api/issuer-keys/:id/compromise
 * Mark an IssuerKey as COMPROMISED — stops new signing, preserves historical record (ADMIN only).
 */
const markKeyCompromised = async (req, res, next) => {
  try {
    const { reason } = req.body;
    const issuerKey = await issuerService.markKeyCompromised({
      issuerKeyId: req.params.id,
      adminUserId: req.user._id,
      reason,
    });

    // Never return privateKeyReference
    return success(
      res,
      { issuerKey: safeKeyResponse(issuerKey) },
      'Issuer key marked as COMPROMISED. New signing with this key has been stopped.'
    );
  } catch (err) {
    next(err);
  }
};

module.exports = {
  register,
  getMyProfile,
  list,
  getById,
  approve,
  suspend,
  revoke,
  markKeyCompromised,
};
