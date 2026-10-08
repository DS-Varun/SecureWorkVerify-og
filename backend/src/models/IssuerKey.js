/**
 * IssuerKey model.
 *
 * Keys are a first-class entity separate from the Issuer record (PROJECT_RULES §7).
 *
 * SECURITY rules (non-negotiable):
 * - publicKey is stored in MongoDB (base64) — this is correct and expected.
 * - privateKeyReference is a FILESYSTEM PATH STRING only — key bytes NEVER in MongoDB.
 * - publicKey is NEVER deleted — historical signatures remain verifiable forever.
 * - On revocation or compromise: status changes; privateKeyReference field stays
 *   (it references a retired file, not an active key).
 * - loadPrivateKey(issuerId) in keystore.service.js ONLY reads from the active dir.
 *
 * Key status lifecycle:
 * ACTIVE → RETIRED    (normal revocation/rotation)
 * ACTIVE → COMPROMISED (key suspected stolen; stop signing immediately)
 * ACTIVE → REVOKED    (issuer revoked)
 */

'use strict';

const mongoose = require('mongoose');

const ISSUER_KEY_STATUSES = ['ACTIVE', 'RETIRED', 'COMPROMISED', 'REVOKED'];

const issuerKeySchema = new mongoose.Schema(
  {
    /**
     * The issuer this key belongs to.
     */
    issuerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Issuer',
      required: [true, 'issuerId is required'],
      immutable: true,
    },

    /**
     * Filename reference for the private key.
     * Pattern: issuer_<mongoId>.key
     * This is a path reference ONLY — key bytes are never stored here.
     */
    keyId: {
      type: String,
      required: [true, 'keyId is required'],
      immutable: true,
      trim: true,
    },

    /**
     * Cryptographic algorithm. Always "Ed25519" in v1.
     */
    algorithm: {
      type: String,
      required: [true, 'algorithm is required'],
      default: 'Ed25519',
      immutable: true,
    },

    /**
     * Public key in base64 encoding.
     * PERMANENTLY stored in MongoDB — NEVER deleted.
     * Required for verifying previously signed credentials.
     */
    publicKey: {
      type: String,
      required: [true, 'publicKey is required'],
      immutable: true, // public key never changes for a given key record
    },

    /**
     * Filesystem path reference to the private key file.
     * Contains a path string (e.g., /path/to/keys/issuer_<id>.key).
     * KEY BYTES ARE NEVER STORED HERE.
     * After retirement: points to the retired/ subdirectory path.
     *
     * This field has select: false so it is excluded from default API responses.
     * The controller MUST NOT manually include this in response payloads.
     */
    privateKeyReference: {
      type: String,
      required: [true, 'privateKeyReference is required'],
      select: false, // excluded from default query results for safety
    },

    /**
     * Current key status.
     */
    status: {
      type: String,
      enum: {
        values: ISSUER_KEY_STATUSES,
        message: 'Invalid issuer key status',
      },
      default: 'ACTIVE',
      required: [true, 'status is required'],
    },

    activatedAt: {
      type: Date,
      default: null,
    },

    retiredAt: {
      type: Date,
      default: null,
    },

    compromisedAt: {
      type: Date,
      default: null,
    },

    revokedAt: {
      type: Date,
      default: null,
    },

    /**
     * Reason for status change (suspension, revocation, compromise).
     */
    statusReason: {
      type: String,
      trim: true,
      maxlength: [1000, 'Status reason cannot exceed 1000 characters'],
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// ─── Indexes ──────────────────────────────────────────────────────────────────

issuerKeySchema.index({ issuerId: 1 });
issuerKeySchema.index({ status: 1 });

// ─── Model ────────────────────────────────────────────────────────────────────

const IssuerKey = mongoose.model('IssuerKey', issuerKeySchema);

module.exports = { IssuerKey, ISSUER_KEY_STATUSES };
