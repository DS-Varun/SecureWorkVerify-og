/**
 * Organization service.
 *
 * Handles all business logic for organization CRUD and trust-lifecycle management.
 *
 * TRUST RULES (PROJECT_RULES §4):
 * - Organization existence does NOT equal trust.
 * - An organization starts PENDING.
 * - Only an ADMIN can create an organization.
 * - Only an ADMIN can verify, suspend, or revoke an organization.
 * - officialDomain is informational only in v1; domain ownership is not verified.
 * - Do not fabricate verification — ADMIN_REVIEW means an admin has manually reviewed.
 * - A SUSPENDED or REVOKED organization is never treated as trusted.
 * - All status transitions are logged to the embedded verificationEvents array
 *   AND to the hash-chained AuditLog. Historical evidence is never overwritten or deleted.
 * - Revoking an organization does NOT delete the organization record.
 */

'use strict';

const crypto = require('crypto');
const { Organization } = require('../models/Organization');
const auditService = require('./audit.service');

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Throw a structured application error.
 * @param {string} message
 * @param {number} statusCode
 */
const appError = (message, statusCode) => {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
};

/**
 * Generate a unique public organization code (format: ORG-XXXXXXXX).
 * @returns {Promise<string>}
 */
const generateOrganizationCode = async () => {
  let attempts = 0;
  while (attempts < 10) {
    const randomHex = crypto.randomBytes(4).toString('hex').toUpperCase();
    const candidateCode = `ORG-${randomHex}`;
    const exists = await Organization.findOne({ organizationCode: candidateCode }).lean();
    if (!exists) {
      return candidateCode;
    }
    attempts++;
  }
  throw appError('Failed to generate a unique organization code. Please try again.', 500);
};

// ─── Create ───────────────────────────────────────────────────────────────────

/**
 * Create a new organization.
 * SECURITY: Only an ADMIN can create an organization (enforced at route and service layer).
 *
 * @param {Object} params
 * @param {string} params.name
 * @param {string} params.type
 * @param {string} [params.officialDomain]
 * @param {string} [params.description]
 * @param {ObjectId} params.createdBy - User._id of the creating ADMIN
 * @returns {Promise<Object>} Created organization document
 */
const createOrganization = async ({
  name,
  type,
  officialDomain,
  description,
  createdBy,
}) => {
  // Prevent accidental duplicate names (case-insensitive)
  const existing = await Organization.findOne({
    name: { $regex: new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') },
  });
  if (existing) {
    throw appError('An organization with this name already exists', 409);
  }

  const organizationCode = await generateOrganizationCode();

  const org = await Organization.create({
    organizationCode,
    name,
    type,
    officialDomain: officialDomain ? officialDomain.toLowerCase().trim() : undefined,
    description: description ? description.trim() : undefined,
    createdBy,
    organizationVerificationStatus: 'PENDING',
    domainVerificationStatus: 'UNVERIFIED',
    status: 'ACTIVE',
  });

  // Audit event
  await auditService.log({
    action: 'ORGANIZATION_CREATED',
    performedBy: createdBy,
    targetType: 'ORGANIZATION',
    targetId: org._id,
    metadata: {
      organizationCode: org.organizationCode,
      name: org.name,
      type: org.type,
      officialDomain: org.officialDomain || null,
    },
  });

  return org;
};

// ─── List ─────────────────────────────────────────────────────────────────────

/**
 * List organizations with optional filters.
 * Accessible to authenticated users (ADMIN, AUDITOR, USER, ISSUER, HR).
 *
 * @param {Object} options
 * @param {string} [options.organizationVerificationStatus] - Filter by verification status
 * @param {string} [options.status] - Filter by record status
 * @param {string} [options.type] - Filter by org type
 * @param {number} [options.page=1]
 * @param {number} [options.limit=20]
 * @returns {Promise<Object>} { organizations, total, page, limit }
 */
const listOrganizations = async ({
  organizationVerificationStatus,
  status,
  type,
  page = 1,
  limit = 20,
} = {}) => {
  const filter = {};
  if (organizationVerificationStatus) filter.organizationVerificationStatus = organizationVerificationStatus;
  if (status) filter.status = status;
  if (type) filter.type = type;

  const safePage = Math.max(1, parseInt(page, 10) || 1);
  const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
  const skip = (safePage - 1) * safeLimit;

  const [organizations, total] = await Promise.all([
    Organization.find(filter)
      .select('-verificationEvents') // Omit embedded event log from list view
      .populate('createdBy', 'name email role')
      .populate('lastActionBy', 'name email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit)
      .lean(),
    Organization.countDocuments(filter),
  ]);

  return { organizations, total, page: safePage, limit: safeLimit };
};

// ─── Get One ──────────────────────────────────────────────────────────────────

/**
 * Get a single organization by ID, including full verification event history.
 *
 * @param {string} id - Organization._id
 * @returns {Promise<Object>} Organization document
 */
const getOrganization = async (id) => {
  const org = await Organization.findById(id)
    .populate('createdBy', 'name email role')
    .populate('lastActionBy', 'name email role')
    .populate('verificationEvents.performedBy', 'name email role');

  if (!org) {
    throw appError('Organization not found', 404);
  }

  return org;
};

// ─── Verify ───────────────────────────────────────────────────────────────────

/**
 * ADMIN_REVIEW verification: ADMIN marks an organization as VERIFIED.
 *
 * Requirements:
 * - verificationMethod must be 'ADMIN_REVIEW' for v1
 * - evidence must contain meaningful notes and reference
 * - Cannot verify a REVOKED organization
 * - Cannot verify an already VERIFIED organization
 *
 * @param {Object} params
 * @param {string} params.orgId
 * @param {ObjectId} params.adminUserId - Must be ADMIN role
 * @param {string} params.verificationMethod - Must be 'ADMIN_REVIEW' for v1
 * @param {Object} params.evidence - Must contain notes and reference
 * @returns {Promise<Object>} Updated organization document
 */
const verifyOrganization = async ({
  orgId,
  adminUserId,
  verificationMethod = 'ADMIN_REVIEW',
  evidence = {},
}) => {
  if (verificationMethod !== 'ADMIN_REVIEW') {
    throw appError(
      `Verification method '${verificationMethod}' is not supported in v1. Only 'ADMIN_REVIEW' is implemented.`,
      400
    );
  }

  if (!evidence || typeof evidence !== 'object') {
    throw appError('Verification evidence is required', 400);
  }

  const notes = evidence.notes ? String(evidence.notes).trim() : '';
  const reference = evidence.reference ? String(evidence.reference).trim() : '';

  if (!notes || notes.length < 5) {
    throw appError('Verification evidence notes are required (minimum 5 characters)', 400);
  }

  if (!reference || reference.length < 2) {
    throw appError('Verification evidence reference/document ID is required', 400);
  }

  const org = await Organization.findById(orgId);
  if (!org) throw appError('Organization not found', 404);

  if (org.status === 'REVOKED' || org.organizationVerificationStatus === 'REVOKED') {
    throw appError('A revoked organization cannot be verified', 409);
  }

  const previousStatus = org.organizationVerificationStatus;

  if (previousStatus === 'VERIFIED') {
    throw appError('Organization is already verified', 409);
  }

  org.organizationVerificationStatus = 'VERIFIED';
  org.status = 'ACTIVE';
  org.lastActionBy = adminUserId;
  org.lastActionAt = new Date();

  // Append to the immutable verification event log
  org.verificationEvents.push({
    fromStatus: previousStatus,
    toStatus: 'VERIFIED',
    method: 'ADMIN_REVIEW',
    performedBy: adminUserId,
    notes,
    evidence: {
      notes,
      reference,
      ...(evidence.additionalDetails ? { additionalDetails: evidence.additionalDetails } : {}),
    },
  });

  await org.save();

  // Hash-chained audit entry
  await auditService.log({
    action: 'ORGANIZATION_VERIFIED',
    performedBy: adminUserId,
    targetType: 'ORGANIZATION',
    targetId: org._id,
    metadata: {
      organizationCode: org.organizationCode,
      previousStatus,
      newStatus: 'VERIFIED',
      method: 'ADMIN_REVIEW',
      notes,
      reference,
    },
  });

  return org;
};

// ─── Suspend ──────────────────────────────────────────────────────────────────

/**
 * Suspend an organization (temporarily remove trust).
 * Only ADMIN can suspend. A suspended org is not trusted.
 *
 * @param {Object} params
 * @param {string} params.orgId
 * @param {ObjectId} params.adminUserId
 * @param {string} params.reason - Required; must document why
 * @returns {Promise<Object>} Updated organization document
 */
const suspendOrganization = async ({ orgId, adminUserId, reason }) => {
  const cleanReason = reason ? String(reason).trim() : '';
  if (!cleanReason || cleanReason.length < 3) {
    throw appError('A suspension reason is required (minimum 3 characters)', 400);
  }

  const org = await Organization.findById(orgId);
  if (!org) throw appError('Organization not found', 404);

  if (org.status === 'REVOKED' || org.organizationVerificationStatus === 'REVOKED') {
    throw appError('A revoked organization cannot be suspended', 409);
  }

  if (org.status === 'SUSPENDED' && org.organizationVerificationStatus === 'SUSPENDED') {
    throw appError('Organization is already suspended', 409);
  }

  const previousVerificationStatus = org.organizationVerificationStatus;
  const previousStatus = org.status;

  org.status = 'SUSPENDED';
  org.organizationVerificationStatus = 'SUSPENDED';
  org.suspendedAt = new Date();
  org.suspendedReason = cleanReason;
  org.lastActionBy = adminUserId;
  org.lastActionAt = new Date();

  org.verificationEvents.push({
    fromStatus: previousVerificationStatus,
    toStatus: 'SUSPENDED',
    method: 'ADMIN_REVIEW',
    performedBy: adminUserId,
    notes: cleanReason,
    evidence: { reason: cleanReason },
  });

  await org.save();

  await auditService.log({
    action: 'ORGANIZATION_SUSPENDED',
    performedBy: adminUserId,
    targetType: 'ORGANIZATION',
    targetId: org._id,
    metadata: {
      organizationCode: org.organizationCode,
      previousStatus,
      previousVerificationStatus,
      reason: cleanReason,
    },
  });

  return org;
};

// ─── Revoke ───────────────────────────────────────────────────────────────────

/**
 * Revoke an organization (permanently remove trust).
 * Only ADMIN can revoke. Revocation is permanent.
 *
 * IMPORTANT: Revocation does NOT delete the organization or retroactively invalidate
 * historical credentials. Historical verification evidence remains auditable.
 *
 * @param {Object} params
 * @param {string} params.orgId
 * @param {ObjectId} params.adminUserId
 * @param {string} params.reason - Required
 * @returns {Promise<Object>} Updated organization document
 */
const revokeOrganization = async ({ orgId, adminUserId, reason }) => {
  const cleanReason = reason ? String(reason).trim() : '';
  if (!cleanReason || cleanReason.length < 3) {
    throw appError('A revocation reason is required (minimum 3 characters)', 400);
  }

  const org = await Organization.findById(orgId);
  if (!org) throw appError('Organization not found', 404);

  if (org.status === 'REVOKED' || org.organizationVerificationStatus === 'REVOKED') {
    throw appError('Organization is already revoked', 409);
  }

  const previousVerificationStatus = org.organizationVerificationStatus;
  const previousStatus = org.status;

  org.status = 'REVOKED';
  org.organizationVerificationStatus = 'REVOKED';
  org.revokedAt = new Date();
  org.revokedReason = cleanReason;
  org.lastActionBy = adminUserId;
  org.lastActionAt = new Date();

  org.verificationEvents.push({
    fromStatus: previousVerificationStatus,
    toStatus: 'REVOKED',
    method: 'ADMIN_REVIEW',
    performedBy: adminUserId,
    notes: cleanReason,
    evidence: { reason: cleanReason },
  });

  await org.save();

  await auditService.log({
    action: 'ORGANIZATION_REVOKED',
    performedBy: adminUserId,
    targetType: 'ORGANIZATION',
    targetId: org._id,
    metadata: {
      organizationCode: org.organizationCode,
      previousStatus,
      previousVerificationStatus,
      reason: cleanReason,
    },
  });

  return org;
};

module.exports = {
  createOrganization,
  listOrganizations,
  getOrganization,
  verifyOrganization,
  suspendOrganization,
  revokeOrganization,
};
