/**
 * Issuer model.
 *
 * An Issuer is a user authorized to sign credentials on behalf of an organization.
 * Issuer status requires a separate explicit authorization — organization trust alone
 * does NOT confer issuer status (PROJECT_RULES §6).
 *
 * Lifecycle: PENDING → ACTIVE → SUSPENDED | REVOKED
 *
 * Key rules (PROJECT_RULES §6):
 * - An issuer with status !== ACTIVE MUST NOT sign credentials.
 * - authorizationEvidence is preserved permanently.
 * - Revocation does not retroactively invalidate historical credentials.
 * - userId is unique: one issuer profile per user account.
 */

'use strict';

const mongoose = require('mongoose');

const ISSUER_STATUSES = ['PENDING', 'ACTIVE', 'SUSPENDED', 'REVOKED'];

const issuerSchema = new mongoose.Schema(
  {
    /**
     * The user account that is the issuer.
     * Unique constraint: a user can hold at most one issuer profile.
     */
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'userId is required'],
      unique: true,
      immutable: true,
    },

    /**
     * The organization this issuer represents.
     * Must be VERIFIED at the time of registration.
     */
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      required: [true, 'organizationId is required'],
      immutable: true,
    },

    /**
     * Evidence that justified the issuer authorization request.
     * Preserved permanently — never overwritten or deleted.
     */
    authorizationEvidence: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    /**
     * Current lifecycle status.
     */
    status: {
      type: String,
      enum: {
        values: ISSUER_STATUSES,
        message: 'Invalid issuer status',
      },
      default: 'PENDING',
      required: [true, 'status is required'],
    },

    /**
     * Admin who approved this issuer (null until approved).
     */
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },

    approvedAt: {
      type: Date,
      default: null,
    },

    suspendedAt: {
      type: Date,
      default: null,
    },

    suspensionReason: {
      type: String,
      trim: true,
      maxlength: [500, 'Suspension reason cannot exceed 500 characters'],
      default: null,
    },

    revokedAt: {
      type: Date,
      default: null,
    },

    revokedReason: {
      type: String,
      trim: true,
      maxlength: [500, 'Revocation reason cannot exceed 500 characters'],
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// ─── Indexes ──────────────────────────────────────────────────────────────────

issuerSchema.index({ organizationId: 1 });
issuerSchema.index({ status: 1 });
issuerSchema.index({ userId: 1, status: 1 });

// ─── Model ────────────────────────────────────────────────────────────────────

const Issuer = mongoose.model('Issuer', issuerSchema);

module.exports = { Issuer, ISSUER_STATUSES };
