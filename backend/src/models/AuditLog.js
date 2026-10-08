/**
 * AuditLog model — hash-chained, append-only with strict sequence numbers.
 *
 * Every security-sensitive operation creates a hash-chained audit record.
 * The hash chain and sequence numbers enable detection of record tampering,
 * insertion, or deletion.
 *
 * IMPORTANT LIMITATIONS (documented, not hidden):
 * - The hash chain detects modification of records and gaps in sequence numbers,
 *   but does not prevent deletion of the entire database by someone with direct
 *   unrestricted MongoDB/DBA access.
 * - Do NOT claim this log is immutable against a privileged DBA.
 * - This is a known v1 limitation (PROJECT_RULES §15).
 *
 * Hash chain formula:
 *   currentHash = SHA-256(
 *     sequenceNumber +
 *     action +
 *     performedBy +
 *     targetType +
 *     targetId +
 *     canonicalStringify(metadata) +
 *     createdAt (ISO string) +
 *     previousHash
 *   )
 *
 * Genesis previousHash = SHA-256("GENESIS_SECUREWORK_VERIFY")
 */

'use strict';

const mongoose = require('mongoose');
const crypto = require('crypto');
const { canonicalStringify } = require('../utils/canonicalJson');

// ─── Enums ────────────────────────────────────────────────────────────────────

const AUDIT_ACTIONS = [
  // Auth
  'USER_CREATED',
  'LOGIN_SUCCESS',
  'LOGIN_FAILED',
  // Organizations
  'ORGANIZATION_CREATED',
  'ORGANIZATION_VERIFICATION_SUBMITTED',
  'ORGANIZATION_VERIFIED',
  'ORGANIZATION_SUSPENDED',
  'ORGANIZATION_REVOKED',
  // Trusted sources (future M8)
  'TRUSTED_SOURCE_REGISTERED',
  'TRUSTED_SOURCE_VERIFIED',
  'TRUSTED_SOURCE_SUSPENDED',
  // Issuers (future M2+)
  'ISSUER_AUTHORIZATION_SUBMITTED',
  'ISSUER_APPROVED',
  'ISSUER_SUSPENDED',
  'ISSUER_REVOKED',
  // Issuer keys (future M2+)
  'ISSUER_KEY_CREATED',
  'ISSUER_KEY_ROTATED',
  'ISSUER_KEY_COMPROMISED',
  'ISSUER_KEY_REVOKED',
  // Documents & credentials (future M3+)
  'DOCUMENT_UPLOADED',
  'CREDENTIAL_ISSUED',
  'CREDENTIAL_VERSION_CREATED',
  'CREDENTIAL_SUPERSEDED',
  'CREDENTIAL_REVOKED',
  // Verifications (future M4+)
  'VERIFICATION_PERFORMED',
  'VERIFICATION_EVIDENCE_CREATED',
  'OFFICIAL_SOURCE_CHECKED',
  // Audit
  'AUDIT_CHECKPOINT_CREATED',
];

const AUDIT_TARGET_TYPES = [
  'USER',
  'ORGANIZATION',
  'ISSUER',
  'ISSUER_KEY',
  'CREDENTIAL',
  'CREDENTIAL_VERSION',
  'DOCUMENT',
  'VERIFICATION',
  'TRUSTED_SOURCE',
  'AUDIT_CHECKPOINT',
];

// ─── Schema ───────────────────────────────────────────────────────────────────

const auditLogSchema = new mongoose.Schema(
  {
    sequenceNumber: {
      type: Number,
      required: [true, 'sequenceNumber is required'],
      unique: true,
      immutable: true,
      min: 1,
    },

    action: {
      type: String,
      enum: {
        values: AUDIT_ACTIONS,
        message: 'Invalid audit action',
      },
      required: [true, 'Audit action is required'],
      immutable: true,
    },

    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'performedBy is required'],
      immutable: true,
    },

    targetType: {
      type: String,
      enum: {
        values: AUDIT_TARGET_TYPES,
        message: 'Invalid audit target type',
      },
      required: [true, 'targetType is required'],
      immutable: true,
    },

    targetId: {
      type: mongoose.Schema.Types.ObjectId,
      required: [true, 'targetId is required'],
      immutable: true,
    },

    // Action-specific payload. Stored for full audit trail.
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
      immutable: true,
    },

    // SHA-256 of the previous entry's currentHash
    // Genesis entry: SHA-256("GENESIS_SECUREWORK_VERIFY")
    previousHash: {
      type: String,
      required: [true, 'previousHash is required'],
      immutable: true,
    },

    // SHA-256 of all fields combined deterministically
    currentHash: {
      type: String,
      required: [true, 'currentHash is required'],
      immutable: true,
    },

    // Append-only: managed manually, no updatedAt
    createdAt: {
      type: Date,
      default: Date.now,
      immutable: true,
    },
  },
  {
    // Disable automatic timestamps — we manage createdAt manually and
    // intentionally have NO updatedAt (append-only).
    timestamps: false,
  }
);

// ─── Indexes ──────────────────────────────────────────────────────────────────

auditLogSchema.index({ createdAt: 1 });
auditLogSchema.index({ performedBy: 1 });
auditLogSchema.index({ targetType: 1, targetId: 1 });
auditLogSchema.index({ action: 1 });

// ─── Static helpers ───────────────────────────────────────────────────────────

/**
 * Compute the genesis previous hash.
 * Used for the very first audit log entry (sequenceNumber = 1).
 */
auditLogSchema.statics.genesisHash = function () {
  return crypto
    .createHash('sha256')
    .update('GENESIS_SECUREWORK_VERIFY')
    .digest('hex');
};

/**
 * Compute the currentHash for an entry.
 *
 * Formula:
 *   SHA256(
 *     sequenceNumber +
 *     action +
 *     performedBy +
 *     targetType +
 *     targetId +
 *     canonicalMetadata +
 *     createdAt +
 *     previousHash
 *   )
 *
 * @param {Object} params
 * @param {number} params.sequenceNumber
 * @param {string} params.action
 * @param {string|ObjectId} params.performedBy
 * @param {string} params.targetType
 * @param {string|ObjectId} params.targetId
 * @param {Object} params.metadata
 * @param {string} params.previousHash
 * @param {string} params.createdAt - ISO string
 * @returns {string} hex SHA-256
 */
auditLogSchema.statics.computeHash = function ({
  sequenceNumber,
  action,
  performedBy,
  targetType,
  targetId,
  metadata = {},
  previousHash,
  createdAt,
}) {
  const canonicalMetadata = canonicalStringify(metadata);
  const payload =
    String(sequenceNumber) +
    String(action) +
    String(performedBy) +
    String(targetType) +
    String(targetId) +
    canonicalMetadata +
    String(createdAt) +
    String(previousHash);

  return crypto.createHash('sha256').update(payload).digest('hex');
};

// ─── Model ────────────────────────────────────────────────────────────────────

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = { AuditLog, AUDIT_ACTIONS, AUDIT_TARGET_TYPES };
