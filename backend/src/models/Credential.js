/**
 * Credential model.
 *
 * A credential is a signed attestation that links a document to a recipient,
 * backed by an authorized issuer's Ed25519 signature.
 *
 * Key rules (PROJECT_RULES §9, §19, §20):
 * - documentHash is the SHA-256 of the backing document (denormalized for lookup speed).
 * - signature is the Ed25519 signature of documentHash, signed by the issuer key.
 * - issuerKeyId records which specific key signed this credential.
 * - currentVersionId points to the most recent CredentialVersion.
 * - REVOKED is NOT FAKE. A revoked credential was authentic at issuance.
 * - EXPIRED is NOT FAKE. An expired credential was authentic during its validity period.
 * - Historical credentials are never deleted.
 */

'use strict';

const mongoose = require('mongoose');

const CREDENTIAL_TYPES = [
  'DEGREE',
  'CERTIFICATE',
  'EMPLOYMENT_LETTER',
  'LICENSE',
  'OTHER',
];

const CREDENTIAL_STATUSES = ['ACTIVE', 'REVOKED', 'EXPIRED'];

const credentialSchema = new mongoose.Schema(
  {
    /**
     * The document backing this credential.
     */
    documentId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Document',
      required: [true, 'documentId is required'],
      immutable: true,
    },

    /**
     * The issuer who created this credential.
     */
    issuerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Issuer',
      required: [true, 'issuerId is required'],
      immutable: true,
    },

    /**
     * The specific IssuerKey that signed this credential.
     * Stored per-credential so key rotation does not break historical verification.
     */
    issuerKeyId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'IssuerKey',
      required: [true, 'issuerKeyId is required'],
      immutable: true,
    },

    /**
     * The user who receives/holds this credential.
     */
    recipientId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'recipientId is required'],
      immutable: true,
    },

    /**
     * The organization associated with this credential.
     */
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      required: [true, 'organizationId is required'],
      immutable: true,
    },

    credentialType: {
      type: String,
      enum: {
        values: CREDENTIAL_TYPES,
        message: 'Invalid credential type',
      },
      required: [true, 'credentialType is required'],
    },

    title: {
      type: String,
      required: [true, 'title is required'],
      trim: true,
      minlength: [2, 'Title must be at least 2 characters'],
      maxlength: [200, 'Title cannot exceed 200 characters'],
    },

    description: {
      type: String,
      trim: true,
      maxlength: [2000, 'Description cannot exceed 2000 characters'],
      default: null,
    },

    /**
     * SHA-256 hash of the document (hex).
     * Denormalized from Document for fast hash-based lookup during verification.
     * Immutable — the credential is tied to this specific document hash.
     */
    documentHash: {
      type: String,
      required: [true, 'documentHash is required'],
      match: [/^[a-f0-9]{64}$/, 'documentHash must be a 64-character hex string'],
      immutable: true,
    },

    /**
     * Ed25519 signature of documentHash (base64).
     * Signed by the private key corresponding to issuerKeyId.
     * Immutable — signature is fixed at issuance.
     */
    signature: {
      type: String,
      required: [true, 'signature is required'],
      immutable: true,
    },

    /**
     * Points to the most recent CredentialVersion record.
     * Updated when a new version is published.
     */
    currentVersionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'CredentialVersion',
      default: null,
    },

    status: {
      type: String,
      enum: {
        values: CREDENTIAL_STATUSES,
        message: 'Invalid credential status',
      },
      default: 'ACTIVE',
      required: [true, 'status is required'],
    },

    /**
     * When the credential was formally issued.
     * Server-supplied; NOT claimed as a cryptographically trusted timestamp.
     */
    issuedAt: {
      type: Date,
      required: [true, 'issuedAt is required'],
    },

    /**
     * Optional expiry date. Null means no expiry.
     */
    expiresAt: {
      type: Date,
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

// documentHash lookup is the critical path for verification
credentialSchema.index({ documentHash: 1 });
credentialSchema.index({ issuerId: 1 });
credentialSchema.index({ recipientId: 1 });
credentialSchema.index({ organizationId: 1 });
credentialSchema.index({ status: 1 });

// ─── Model ────────────────────────────────────────────────────────────────────

const Credential = mongoose.model('Credential', credentialSchema);

module.exports = { Credential, CREDENTIAL_TYPES, CREDENTIAL_STATUSES };
