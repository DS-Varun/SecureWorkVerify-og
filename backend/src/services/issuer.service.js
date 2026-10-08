/**
 * Issuer service.
 *
 * Handles all business logic for the Issuer and IssuerKey lifecycles.
 *
 * KEY SECURITY RULES (PROJECT_RULES §7, §8, §20):
 * - Private key bytes are NEVER stored in MongoDB.
 * - Private key bytes are NEVER returned in any response or log.
 * - loadPrivateKey() is called only transiently during signing, not here.
 * - retirePrivateKey() is used instead of deletePrivateKey() on revocation.
 * - publicKey is preserved permanently in MongoDB even after key revocation.
 *
 * TRUST RULES (PROJECT_RULES §6):
 * - Organization must be VERIFIED before an issuer can register under it.
 * - Only ADMIN can approve, suspend, or revoke.
 * - ACTIVE issuer status is required before signing.
 * - Revocation does NOT retroactively invalidate historical credentials.
 */

'use strict';

const path = require('path');
const { Issuer } = require('../models/Issuer');
const { IssuerKey } = require('../models/IssuerKey');
const { Organization } = require('../models/Organization');
const cryptoService = require('./crypto.service');
const keystoreService = require('./keystore.service');
const auditService = require('./audit.service');

// ─── Helper ────────────────────────────────────────────────────────────────────

const appError = (message, statusCode) => {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
};

// ─── Register ─────────────────────────────────────────────────────────────────

/**
 * Register an issuer profile for a user with ISSUER role.
 * The profile starts in PENDING status pending ADMIN approval.
 *
 * @param {Object} params
 * @param {ObjectId} params.userId - The user requesting issuer status
 * @param {string} params.organizationId - Organization this issuer represents
 * @param {Object} [params.authorizationEvidence] - Supporting evidence
 * @returns {Promise<Object>} Created Issuer document
 */
const registerIssuer = async ({ userId, organizationId, authorizationEvidence = {} }) => {
  // Check for duplicate (one profile per user)
  const existing = await Issuer.findOne({ userId });
  if (existing) {
    throw appError('An issuer profile already exists for this user account', 409);
  }

  // Organization must exist and be VERIFIED (PROJECT_RULES §6)
  const org = await Organization.findById(organizationId).lean();
  if (!org) {
    throw appError('Organization not found', 404);
  }
  if (org.organizationVerificationStatus !== 'VERIFIED') {
    throw appError(
      'Issuer registration is only allowed for VERIFIED organizations. ' +
        `This organization is '${org.organizationVerificationStatus}'.`,
      409
    );
  }

  const issuer = await Issuer.create({
    userId,
    organizationId,
    authorizationEvidence,
    status: 'PENDING',
  });

  await auditService.log({
    action: 'ISSUER_AUTHORIZATION_SUBMITTED',
    performedBy: userId,
    targetType: 'ISSUER',
    targetId: issuer._id,
    metadata: {
      organizationId: issuer.organizationId,
      status: 'PENDING',
    },
  });

  return issuer;
};

// ─── List ──────────────────────────────────────────────────────────────────────

/**
 * List all issuers (ADMIN view) with optional filters.
 *
 * @param {Object} [options]
 * @param {string} [options.status]
 * @param {string} [options.organizationId]
 * @param {number} [options.page=1]
 * @param {number} [options.limit=20]
 * @returns {Promise<Object>} { issuers, total, page, limit }
 */
const listIssuers = async ({ status, organizationId, page = 1, limit = 20 } = {}) => {
  const filter = {};
  if (status) filter.status = status;
  if (organizationId) filter.organizationId = organizationId;

  const safePage = Math.max(1, parseInt(page, 10) || 1);
  const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
  const skip = (safePage - 1) * safeLimit;

  const [issuers, total] = await Promise.all([
    Issuer.find(filter)
      .populate('userId', 'name email role')
      .populate('organizationId', 'name organizationCode type organizationVerificationStatus')
      .populate('approvedBy', 'name email')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit)
      .lean(),
    Issuer.countDocuments(filter),
  ]);

  return { issuers, total, page: safePage, limit: safeLimit };
};

// ─── Get One ───────────────────────────────────────────────────────────────────

/**
 * Get a single issuer by its _id.
 *
 * @param {string} issuerId
 * @returns {Promise<Object>} Issuer document (populated)
 */
const getIssuer = async (issuerId) => {
  const issuer = await Issuer.findById(issuerId)
    .populate('userId', 'name email role')
    .populate('organizationId', 'name organizationCode type organizationVerificationStatus')
    .populate('approvedBy', 'name email');

  if (!issuer) throw appError('Issuer not found', 404);
  return issuer;
};

/**
 * Get the issuer profile for the current authenticated user.
 *
 * @param {ObjectId} userId
 * @returns {Promise<Object>} Issuer document (populated)
 */
const getMyIssuerProfile = async (userId) => {
  const issuer = await Issuer.findOne({ userId })
    .populate('userId', 'name email role')
    .populate('organizationId', 'name organizationCode type organizationVerificationStatus')
    .populate('approvedBy', 'name email');

  if (!issuer) throw appError('No issuer profile found for this user', 404);
  return issuer;
};

// ─── Approve ──────────────────────────────────────────────────────────────────

/**
 * Approve a PENDING issuer.
 * Generates an Ed25519 keypair on approval.
 * Saves the private key to the filesystem via keystore.service.
 * Saves the public key to MongoDB via IssuerKey model.
 *
 * SECURITY: private key bytes are never stored in MongoDB or returned in the response.
 *
 * @param {Object} params
 * @param {string} params.issuerId
 * @param {ObjectId} params.adminUserId
 * @returns {Promise<Object>} { issuer, issuerKey }
 */
const approveIssuer = async ({ issuerId, adminUserId }) => {
  const issuer = await Issuer.findById(issuerId);
  if (!issuer) throw appError('Issuer not found', 404);

  if (issuer.status !== 'PENDING') {
    throw appError(
      `Cannot approve an issuer with status '${issuer.status}'. Only PENDING issuers can be approved.`,
      409
    );
  }

  // Generate Ed25519 keypair (tweetnacl)
  const { publicKey, privateKey } = cryptoService.generateKeyPair();

  // Save private key to filesystem — returns the path reference string
  const privateKeyRef = keystoreService.savePrivateKey(String(issuer._id), privateKey);

  // Derive the keyId (filename) from the path reference
  const keyId = path.basename(privateKeyRef);

  const now = new Date();

  // Create IssuerKey record — public key in MongoDB, private key reference is a path string
  const issuerKey = await IssuerKey.create({
    issuerId: issuer._id,
    keyId,
    algorithm: 'Ed25519',
    publicKey,
    privateKeyReference: privateKeyRef, // path reference only — no key bytes
    status: 'ACTIVE',
    activatedAt: now,
  });

  // Update issuer status
  issuer.status = 'ACTIVE';
  issuer.approvedBy = adminUserId;
  issuer.approvedAt = now;
  await issuer.save();

  // Audit: two entries — issuer approval + key creation
  await auditService.log({
    action: 'ISSUER_APPROVED',
    performedBy: adminUserId,
    targetType: 'ISSUER',
    targetId: issuer._id,
    metadata: {
      previousStatus: 'PENDING',
      newStatus: 'ACTIVE',
      organizationId: issuer.organizationId,
      issuerKeyId: issuerKey._id,
    },
  });

  await auditService.log({
    action: 'ISSUER_KEY_CREATED',
    performedBy: adminUserId,
    targetType: 'ISSUER_KEY',
    targetId: issuerKey._id,
    metadata: {
      issuerId: issuer._id,
      algorithm: 'Ed25519',
      keyId,
      // publicKey included in audit — this is correct (public half is not secret)
      publicKey,
    },
  });

  return { issuer, issuerKey };
};

// ─── Suspend ──────────────────────────────────────────────────────────────────

/**
 * Suspend an ACTIVE issuer.
 *
 * @param {Object} params
 * @param {string} params.issuerId
 * @param {ObjectId} params.adminUserId
 * @param {string} params.reason
 * @returns {Promise<Object>} Updated issuer
 */
const suspendIssuer = async ({ issuerId, adminUserId, reason }) => {
  const cleanReason = reason ? String(reason).trim() : '';
  if (!cleanReason || cleanReason.length < 3) {
    throw appError('A suspension reason is required (minimum 3 characters)', 400);
  }

  const issuer = await Issuer.findById(issuerId);
  if (!issuer) throw appError('Issuer not found', 404);

  if (issuer.status === 'REVOKED') {
    throw appError('A revoked issuer cannot be suspended', 409);
  }
  if (issuer.status === 'SUSPENDED') {
    throw appError('Issuer is already suspended', 409);
  }

  const previousStatus = issuer.status;

  issuer.status = 'SUSPENDED';
  issuer.suspendedAt = new Date();
  issuer.suspensionReason = cleanReason;
  await issuer.save();

  await auditService.log({
    action: 'ISSUER_SUSPENDED',
    performedBy: adminUserId,
    targetType: 'ISSUER',
    targetId: issuer._id,
    metadata: {
      previousStatus,
      newStatus: 'SUSPENDED',
      reason: cleanReason,
      organizationId: issuer.organizationId,
    },
  });

  return issuer;
};

// ─── Revoke ───────────────────────────────────────────────────────────────────

/**
 * Permanently revoke an issuer.
 *
 * KEY RETIREMENT (PROJECT_RULES §7, M1 Decision):
 * - The active private key is MOVED to keys/retired/ (not deleted).
 * - The public key REMAINS in MongoDB permanently.
 * - Historical credentials remain verifiable.
 * - The key CANNOT be used for new signing after this call.
 *
 * @param {Object} params
 * @param {string} params.issuerId
 * @param {ObjectId} params.adminUserId
 * @param {string} params.reason
 * @returns {Promise<Object>} Updated issuer
 */
const revokeIssuer = async ({ issuerId, adminUserId, reason }) => {
  const cleanReason = reason ? String(reason).trim() : '';
  if (!cleanReason || cleanReason.length < 3) {
    throw appError('A revocation reason is required (minimum 3 characters)', 400);
  }

  const issuer = await Issuer.findById(issuerId);
  if (!issuer) throw appError('Issuer not found', 404);

  if (issuer.status === 'REVOKED') {
    throw appError('Issuer is already revoked', 409);
  }

  const previousStatus = issuer.status;
  const now = new Date();

  // Find and retire the ACTIVE key (if it exists)
  const activeKey = await IssuerKey.findOne({ issuerId: issuer._id, status: 'ACTIVE' });

  if (activeKey) {
    // Move key file to retired/ directory (PROJECT_RULES §7 — retire, not delete)
    keystoreService.retirePrivateKey(String(issuer._id));

    activeKey.status = 'REVOKED';
    activeKey.revokedAt = now;
    activeKey.statusReason = `Issuer revoked: ${cleanReason}`;
    await activeKey.save();

    await auditService.log({
      action: 'ISSUER_KEY_REVOKED',
      performedBy: adminUserId,
      targetType: 'ISSUER_KEY',
      targetId: activeKey._id,
      metadata: {
        issuerId: issuer._id,
        keyId: activeKey.keyId,
        reason: cleanReason,
        // publicKey preserved in MongoDB — not deleted
      },
    });
  }

  issuer.status = 'REVOKED';
  issuer.revokedAt = now;
  issuer.revokedReason = cleanReason;
  await issuer.save();

  await auditService.log({
    action: 'ISSUER_REVOKED',
    performedBy: adminUserId,
    targetType: 'ISSUER',
    targetId: issuer._id,
    metadata: {
      previousStatus,
      newStatus: 'REVOKED',
      reason: cleanReason,
      organizationId: issuer.organizationId,
    },
  });

  return issuer;
};

// ─── Key Compromise ───────────────────────────────────────────────────────────

/**
 * Mark an IssuerKey as COMPROMISED (PROJECT_RULES §7, M5 Decision).
 *
 * Called when a private key is suspected stolen/leaked.
 * Immediately stops all new signing with that key.
 * Does NOT automatically invalidate historical credentials.
 * The public key is preserved for historical signature verification.
 *
 * @param {Object} params
 * @param {string} params.issuerKeyId
 * @param {ObjectId} params.adminUserId
 * @param {string} params.reason
 * @returns {Promise<Object>} Updated IssuerKey
 */
const markKeyCompromised = async ({ issuerKeyId, adminUserId, reason }) => {
  const cleanReason = reason ? String(reason).trim() : '';
  if (!cleanReason || cleanReason.length < 3) {
    throw appError('A compromise reason is required (minimum 3 characters)', 400);
  }

  const key = await IssuerKey.findById(issuerKeyId);
  if (!key) throw appError('Issuer key not found', 404);

  if (key.status === 'COMPROMISED') {
    throw appError('Key is already marked as compromised', 409);
  }
  if (key.status === 'REVOKED') {
    throw appError('Key is already revoked', 409);
  }

  const now = new Date();

  // Retire the private key immediately — stop new signing
  keystoreService.retirePrivateKey(String(key.issuerId));

  key.status = 'COMPROMISED';
  key.compromisedAt = now;
  key.statusReason = cleanReason;
  await key.save();

  await auditService.log({
    action: 'ISSUER_KEY_COMPROMISED',
    performedBy: adminUserId,
    targetType: 'ISSUER_KEY',
    targetId: key._id,
    metadata: {
      issuerId: key.issuerId,
      keyId: key.keyId,
      reason: cleanReason,
      compromisedAt: now.toISOString(),
      // publicKey NOT deleted — needed for verifying past signatures
    },
  });

  return key;
};

module.exports = {
  registerIssuer,
  listIssuers,
  getIssuer,
  getMyIssuerProfile,
  approveIssuer,
  suspendIssuer,
  revokeIssuer,
  markKeyCompromised,
};
