/**
 * CredentialVersion model.
 *
 * Tracks the version history of credentials.
 * Each issuance creates a new CredentialVersion record.
 *
 * Rules (PROJECT_RULES §9, §20):
 * - Versions are NEVER deleted.
 * - All fields except `status` are immutable.
 * - issuerKeyId records which key was used for this specific version.
 *   This is critical: after key rotation, earlier versions still reference
 *   the original key so verification can use the correct public key.
 * - The Credential.currentVersionId field points to the most recent version.
 * - Old versions remain queryable for auditability.
 * - status transitions: ACTIVE → SUPERSEDED (when a new version is created)
 */

'use strict';

const mongoose = require('mongoose');

const CREDENTIAL_VERSION_STATUSES = ['ACTIVE', 'SUPERSEDED'];

const credentialVersionSchema = new mongoose.Schema(
  {
    /**
     * The parent credential this version belongs to.
     */
    credentialId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Credential',
      required: [true, 'credentialId is required'],
      immutable: true,
    },

    /**
     * Sequential version number within this credential (1-based).
     */
    versionNumber: {
      type: Number,
      required: [true, 'versionNumber is required'],
      min: [1, 'versionNumber must be at least 1'],
      immutable: true,
    },

    /**
     * The document backing this version.
     */
    documentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Document',
      required: [true, 'documentId is required'],
      immutable: true,
    },

    /**
     * SHA-256 hash of the document at this version (hex).
     */
    documentHash: {
      type: String,
      required: [true, 'documentHash is required'],
      match: [/^[a-f0-9]{64}$/, 'documentHash must be a 64-character hex string'],
      immutable: true,
    },

    /**
     * Ed25519 signature of documentHash (base64).
     */
    signature: {
      type: String,
      required: [true, 'signature is required'],
      immutable: true,
    },

    /**
     * Which issuer key was used to sign this version.
     * Required for key-rotation-safe historical verification.
     */
    issuerKeyId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'IssuerKey',
      required: [true, 'issuerKeyId is required'],
      immutable: true,
    },

    /**
     * When this version was issued. Server-supplied.
     */
    issuedAt: {
      type: Date,
      required: [true, 'issuedAt is required'],
      immutable: true,
    },

    /**
     * Null for v1 (first version). Points to the version this supersedes.
     */
    supersedesVersionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CredentialVersion',
      default: null,
      immutable: true,
    },

    /**
     * Reason for creating a new version (why was the document corrected?).
     * Null for initial issuance.
     */
    changeReason: {
      type: String,
      trim: true,
      maxlength: [500, 'Change reason cannot exceed 500 characters'],
      default: null,
    },

    /**
     * Version status.
     * ACTIVE = current version. SUPERSEDED = replaced by a newer version.
     */
    status: {
      type: String,
      enum: {
        values: CREDENTIAL_VERSION_STATUSES,
        message: 'Invalid credential version status',
      },
      default: 'ACTIVE',
      required: [true, 'status is required'],
    },

    /**
     * Timestamp of this version record. No updatedAt (append-only by convention).
     */
    createdAt: {
      type: Date,
      default: Date.now,
      immutable: true,
    },
  },
  {
    // No automatic timestamps: createdAt is manual + immutable; no updatedAt.
    timestamps: false,
  }
);

// ─── Compound unique index: one version number per credential ──────────────────

credentialVersionSchema.index({ credentialId: 1, versionNumber: 1 }, { unique: true });
credentialVersionSchema.index({ credentialId: 1 });
credentialVersionSchema.index({ documentHash: 1 });

// ─── Model ────────────────────────────────────────────────────────────────────

const CredentialVersion = mongoose.model('CredentialVersion', credentialVersionSchema);

module.exports = { CredentialVersion, CREDENTIAL_VERSION_STATUSES };
