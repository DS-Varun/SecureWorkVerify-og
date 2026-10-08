/**
 * Organization model.
 *
 * An organization is a legal or institutional entity (university, company,
 * government body, certification body, institution, etc.) that can sponsor issuers.
 *
 * TRUST RULES (PROJECT_RULES §4):
 * - Organization existence does NOT equal trust.
 * - An organization starts PENDING.
 * - Only ADMIN can establish organization trust (ADMIN_REVIEW method for v1).
 * - officialDomain is informational only; domain ownership is not verified in v1.
 * - A SUSPENDED or REVOKED organization must not be treated as trusted.
 * - Historical verification evidence remains permanently auditable.
 * - Revoking an organization does NOT retroactively invalidate historical credentials.
 */

'use strict';

const mongoose = require('mongoose');

// ─── Enums ────────────────────────────────────────────────────────────────────

const ORG_TYPES = [
  'UNIVERSITY',
  'COMPANY',
  'CERTIFICATION_BODY',
  'GOVERNMENT',
  'INSTITUTION',
  'OTHER',
];

const ORG_VERIFICATION_STATUSES = [
  'PENDING',    // Newly created — not yet reviewed
  'VERIFIED',   // Admin has verified the organization
  'SUSPENDED',  // Temporarily not trusted
  'REVOKED',    // Permanently not trusted
];

// Zero-cost verification methods available in v1.
// DOMAIN_OWNERSHIP, OFFICIAL_REGISTRY, INSTITUTIONAL_CONTACT are future.
const VERIFICATION_METHODS = [
  'ADMIN_REVIEW',           // Admin manually reviews and approves — implemented in v1
  'DOMAIN_OWNERSHIP',       // Future: verify org controls the declared domain
  'OFFICIAL_REGISTRY',      // Future: check official business/institution registry
  'INSTITUTIONAL_CONTACT',  // Future: contact institution via known channel
  'OTHER',
];

const ORG_STATUSES = [
  'ACTIVE',     // Organization record is active (does not imply VERIFIED trust)
  'SUSPENDED',  // Organization record is suspended
  'REVOKED',    // Organization record is revoked
];

// ─── Sub-schema: Verification Event ──────────────────────────────────────────

/**
 * Records each trust-status transition for auditable history.
 * Historical events are never deleted or overwritten.
 */
const verificationEventSchema = new mongoose.Schema(
  {
    fromStatus: {
      type: String,
      enum: ORG_VERIFICATION_STATUSES,
    },
    toStatus: {
      type: String,
      enum: ORG_VERIFICATION_STATUSES,
      required: true,
    },
    method: {
      type: String,
      enum: VERIFICATION_METHODS,
      required: true,
    },
    performedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    notes: {
      type: String,
      trim: true,
      maxlength: [2000, 'Notes cannot exceed 2000 characters'],
    },
    evidence: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    performedAt: {
      type: Date,
      default: Date.now,
      immutable: true,
    },
  },
  { _id: true }
);

// ─── Organization Schema ──────────────────────────────────────────────────────

const organizationSchema = new mongoose.Schema(
  {
    /**
     * Unique, immutable public organization identifier.
     * Format: ORG-XXXXXXXX (server-generated).
     */
    organizationCode: {
      type: String,
      required: [true, 'Organization code is required'],
      unique: true,
      uppercase: true,
      trim: true,
      immutable: true,
      match: [/^ORG-[A-Z0-9]{8}$/, 'Organization code must match format ORG-XXXXXXXX'],
    },

    name: {
      type: String,
      required: [true, 'Organization name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [200, 'Name cannot exceed 200 characters'],
    },

    type: {
      type: String,
      enum: {
        values: ORG_TYPES,
        message: 'Organization type must be one of: ' + ORG_TYPES.join(', '),
      },
      required: [true, 'Organization type is required'],
    },

    /**
     * The official domain of the organization (informational in v1).
     * Domain ownership is NOT verified in v1; this field is for reference only.
     * Do not treat possession of this field as proof of domain control.
     */
    officialDomain: {
      type: String,
      trim: true,
      lowercase: true,
      maxlength: [253, 'Domain cannot exceed 253 characters'],
    },

    /**
     * Optional description of the organization.
     */
    description: {
      type: String,
      trim: true,
      maxlength: [1000, 'Description cannot exceed 1000 characters'],
    },

    /**
     * Canonical trust status. Starts PENDING.
     * Only ADMIN can change this to VERIFIED, SUSPENDED, or REVOKED.
     */
    organizationVerificationStatus: {
      type: String,
      enum: {
        values: ORG_VERIFICATION_STATUSES,
        message:
          'Organization verification status must be one of: ' +
          ORG_VERIFICATION_STATUSES.join(', '),
      },
      default: 'PENDING',
    },

    /**
     * Domain ownership verification status — informational in v1.
     * Not used in trust decisions until domain verification is implemented.
     */
    domainVerificationStatus: {
      type: String,
      enum: ['UNVERIFIED', 'VERIFIED', 'FAILED'],
      default: 'UNVERIFIED',
    },

    /**
     * Record lifecycle status. Separate from organizationVerificationStatus.
     * ACTIVE does NOT mean trusted — check isTrusted() or organizationVerificationStatus.
     */
    status: {
      type: String,
      enum: {
        values: ORG_STATUSES,
        message: 'Status must be one of: ' + ORG_STATUSES.join(', '),
      },
      default: 'ACTIVE',
    },

    // Who created this record (ADMIN)
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },

    // Who last verified / suspended / revoked
    lastActionBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },

    lastActionAt: {
      type: Date,
    },

    /**
     * Append-only verification event log.
     * Records every trust-status transition for auditable history.
     * These events are never deleted or overwritten.
     */
    verificationEvents: {
      type: [verificationEventSchema],
      default: [],
    },

    // Suspension / revocation metadata
    suspendedAt: { type: Date },
    suspendedReason: { type: String, trim: true, maxlength: 500 },
    revokedAt: { type: Date },
    revokedReason: { type: String, trim: true, maxlength: 500 },
  },
  {
    timestamps: true, // createdAt, updatedAt
  }
);

// ─── Indexes ─────────────────────────────────────────────────────────────────

organizationSchema.index({ name: 1 });
organizationSchema.index({ organizationVerificationStatus: 1 });
organizationSchema.index({ status: 1 });
organizationSchema.index({ createdBy: 1 });

// ─── Instance Methods ─────────────────────────────────────────────────────────

/**
 * Returns true only if the organization is both record-ACTIVE and VERIFIED.
 * Use this when deciding whether an org can sponsor issuers.
 */
organizationSchema.methods.isTrusted = function () {
  return this.status === 'ACTIVE' && this.organizationVerificationStatus === 'VERIFIED';
};

/**
 * Returns a public-safe representation (strips internal Mongoose __v).
 */
organizationSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.__v;
  return obj;
};

// ─── Model ────────────────────────────────────────────────────────────────────

const Organization = mongoose.model('Organization', organizationSchema);

module.exports = {
  Organization,
  ORG_TYPES,
  ORG_VERIFICATION_STATUSES,
  VERIFICATION_METHODS,
  ORG_STATUSES,
};
