/**
 * Verification model (PROJECT_RULES §11, §12, §13, §19).
 *
 * Represents an immutable, persistent verification execution record.
 * Each document verification attempt creates a new Verification document
 * linked to granular VerificationEvidence records and hash-chained audit events.
 *
 * SECURITY:
 * - Private keys are NEVER stored or returned here.
 * - Historical verification records are NEVER overwritten or deleted.
 */

'use strict';

const mongoose = require('mongoose');

const VERIFICATION_RESULTS = [
  'VERIFIED',
  'SOURCE_VERIFIED',
  'SOURCE_FOUND',
  'ALTERED',
  'NOT_FOUND',
  'CREDENTIAL_REVOKED',
  'CREDENTIAL_EXPIRED',
  'ISSUER_SUSPENDED',
  'ISSUER_REVOKED',
  'SIGNATURE_INVALID',
  'KEY_COMPROMISED',
  'MANUAL_REVIEW',
  'UNSUPPORTED_SOURCE',
];

const TRUST_LEVELS = [
  'LEVEL_0_UNKNOWN',
  'LEVEL_1_SOURCE_FOUND',
  'LEVEL_2_SOURCE_VERIFIED',
  'LEVEL_3_INTEGRITY_VERIFIED',
  'LEVEL_4_SIGNATURE_VERIFIED',
  'LEVEL_5_CURRENTLY_VALID',
];

const VERIFICATION_MODES = [
  'CREDENTIAL',
  'OFFICIAL_SOURCE',
  'MANUAL_REVIEW',
];

const verificationSchema = new mongoose.Schema(
  {
    /**
     * User who executed the verification request.
     */
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'verifiedBy is required'],
      index: true,
    },

    /**
     * Verification mode.
     */
    verificationMode: {
      type: String,
      enum: {
        values: VERIFICATION_MODES,
        message: 'Invalid verificationMode',
      },
      default: 'CREDENTIAL',
      required: true,
    },

    /**
     * Reference to submitted document if persisted.
     */
    submittedDocumentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Document',
      default: null,
    },

    /**
     * SHA-256 hash of the submitted document.
     */
    uploadedDocumentHash: {
      type: String,
      required: [true, 'uploadedDocumentHash is required'],
      index: true,
    },

    /**
     * Matched Credential reference (if found).
     */
    credentialId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Credential',
      default: null,
      index: true,
    },

    /**
     * Specific matched version if versioned.
     */
    credentialVersionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CredentialVersion',
      default: null,
    },

    /**
     * Organization associated with the credential/issuer.
     */
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      default: null,
      index: true,
    },

    /**
     * Issuer who signed the credential.
     */
    issuerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Issuer',
      default: null,
    },

    /**
     * Specific signing key used.
     */
    issuerKeyId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'IssuerKey',
      default: null,
    },

    /**
     * 13 categorical verification states (PROJECT_RULES §11).
     */
    result: {
      type: String,
      enum: {
        values: VERIFICATION_RESULTS,
        message: 'Invalid verification result',
      },
      required: [true, 'result is required'],
      index: true,
    },

    /**
     * Categorical trust level (PROJECT_RULES §12).
     */
    trustLevel: {
      type: String,
      enum: {
        values: TRUST_LEVELS,
        message: 'Invalid trustLevel',
      },
      required: [true, 'trustLevel is required'],
      index: true,
    },

    /**
     * Independent check summaries for UI and debugging.
     */
    integrityCheck: {
      passed: { type: Boolean, default: false },
      documentHash: { type: String, default: null },
      expectedHash: { type: String, default: null },
    },

    signatureCheck: {
      passed: { type: Boolean, default: false },
      algorithm: { type: String, default: 'Ed25519' },
      signature: { type: String, default: null },
      publicKey: { type: String, default: null },
    },

    issuerTrustCheck: {
      passed: { type: Boolean, default: false },
      issuerStatus: { type: String, default: null },
      keyStatus: { type: String, default: null },
    },

    organizationTrustCheck: {
      passed: { type: Boolean, default: false },
      organizationVerificationStatus: { type: String, default: null },
      organizationStatus: { type: String, default: null },
    },

    credentialStatusCheck: {
      passed: { type: Boolean, default: false },
      credentialStatus: { type: String, default: null },
      isExpired: { type: Boolean, default: false },
      expiresAt: { type: Date, default: null },
    },

    /**
     * Granular evidence references.
     */
    evidenceIds: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'VerificationEvidence',
      },
    ],

    /**
     * Human-readable explanation of why the final result was produced.
     */
    explanation: {
      type: String,
      trim: true,
      maxlength: [2000, 'explanation cannot exceed 2000 characters'],
      default: '',
    },

    /**
     * Warnings encountered during verification.
     */
    warnings: [
      {
        type: String,
        trim: true,
      },
    ],

    /**
     * Additional structured metadata.
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
verificationSchema.index({ verifiedBy: 1, createdAt: -1 });
verificationSchema.index({ result: 1, createdAt: -1 });

const Verification = mongoose.model('Verification', verificationSchema);

module.exports = {
  Verification,
  VERIFICATION_RESULTS,
  TRUST_LEVELS,
  VERIFICATION_MODES,
};
