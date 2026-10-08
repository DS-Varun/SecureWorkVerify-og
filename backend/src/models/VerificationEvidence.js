/**
 * VerificationEvidence model (PROJECT_RULES §10, §18).
 *
 * Represents granular evidence produced by individual checks in the verification engine.
 * Evidence records are persistent, independently inspectable, and referenced by Verification documents.
 *
 * SECURITY:
 * - Private keys are NEVER stored or referenced here.
 */

'use strict';

const mongoose = require('mongoose');

const EVIDENCE_TYPES = [
  'OFFICIAL_DOCUMENT',
  'OFFICIAL_RECORD',
  'DIGITAL_SIGNATURE',
  'HASH_MATCH',
  'ISSUER_STATUS',
  'CREDENTIAL_STATUS',
  'DOMAIN_VERIFICATION',
  'MANUAL_REVIEW',
];

const EVIDENCE_STATUSES = [
  'VALID',
  'INVALID',
  'SUSPICIOUS',
  'INCONCLUSIVE',
  'NOT_APPLICABLE',
];

const verificationEvidenceSchema = new mongoose.Schema(
  {
    /**
     * Reference to the parent verification execution.
     */
    verificationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Verification',
      required: [true, 'verificationId is required'],
      index: true,
    },

    /**
     * Categorical evidence type per PROJECT_RULES §10.
     */
    evidenceType: {
      type: String,
      enum: {
        values: EVIDENCE_TYPES,
        message: 'Invalid evidenceType',
      },
      required: [true, 'evidenceType is required'],
    },

    /**
     * Reference to TrustedSource if applicable.
     */
    sourceId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'TrustedSource',
      default: null,
    },

    /**
     * Source URL if applicable.
     */
    sourceUrl: {
      type: String,
      default: null,
    },

    /**
     * External or internal credential identifier.
     */
    credentialIdentifier: {
      type: String,
      default: null,
    },

    /**
     * When evidence was retrieved or evaluated.
     */
    retrievedAt: {
      type: Date,
      default: Date.now,
      required: true,
    },

    /**
     * SHA-256 hash of submitted document evaluated.
     */
    documentHash: {
      type: String,
      default: null,
    },

    /**
     * Expected SHA-256 hash from trusted record.
     */
    expectedDocumentHash: {
      type: String,
      default: null,
    },

    /**
     * SHA-256 hash of source response if applicable.
     */
    responseHash: {
      type: String,
      default: null,
    },

    /**
     * Whether a cryptographic signature was present.
     */
    signaturePresent: {
      type: Boolean,
      default: false,
    },

    /**
     * Result of digital signature verification.
     */
    signatureValid: {
      type: Boolean,
      default: null,
    },

    /**
     * Human-readable summary of source response or check result.
     */
    sourceResponseSummary: {
      type: String,
      trim: true,
      maxlength: [2000, 'sourceResponseSummary cannot exceed 2000 characters'],
      default: null,
    },

    /**
     * Evaluation status of this evidence item.
     */
    evidenceStatus: {
      type: String,
      enum: {
        values: EVIDENCE_STATUSES,
        message: 'Invalid evidenceStatus',
      },
      default: 'VALID',
      required: true,
    },

    /**
     * Detailed metadata for this evidence check.
     */
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

// ─── Indexes ──────────────────────────────────────────────────────────────────
verificationEvidenceSchema.index({ verificationId: 1, evidenceType: 1 });

const VerificationEvidence = mongoose.model(
  'VerificationEvidence',
  verificationEvidenceSchema
);

module.exports = {
  VerificationEvidence,
  EVIDENCE_TYPES,
  EVIDENCE_STATUSES,
};
