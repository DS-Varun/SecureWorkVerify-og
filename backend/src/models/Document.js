/**
 * Document model.
 *
 * Represents a physical file stored in the document storage system.
 * Each credential is backed by exactly one document.
 *
 * IMPORTANT (PROJECT_RULES §18, §19):
 * - sha256Hash proves byte-level identity only — NOT authenticity.
 * - representationType records what kind of file was uploaded.
 * - canonicalizationStatus records whether any normalization was applied.
 * - In v1: exact original file bytes are required for verification.
 *   Screenshots/scans produce different hashes and MUST NOT yield VERIFIED.
 *
 * Storage (PROJECT_RULES §2, M3 Decision):
 * - storagePath: relative path from DOCUMENT_STORAGE_PATH (local filesystem in v1)
 * - storageUrl: null for local filesystem; populated for cloud storage adapters
 */

'use strict';

const mongoose = require('mongoose');

const DOCUMENT_MIME_TYPES = ['application/pdf', 'image/png', 'image/jpeg'];

const DOCUMENT_REPRESENTATION_TYPES = [
  'ORIGINAL_DIGITAL_FILE',
  'PDF',
  'IMAGE',
  'SCAN',
  'SCREENSHOT',
  'OTHER',
];

const documentSchema = new mongoose.Schema(
  {
    /**
     * Original filename as provided by the uploader (sanitized, not trusted for path).
     */
    originalFilename: {
      type: String,
      required: [true, 'originalFilename is required'],
      trim: true,
      maxlength: [500, 'Filename cannot exceed 500 characters'],
    },

    /**
     * MIME type of the uploaded file.
     * Validated by upload.middleware.js before reaching this model.
     */
    mimeType: {
      type: String,
      required: [true, 'mimeType is required'],
      enum: {
        values: DOCUMENT_MIME_TYPES,
        message: 'Unsupported MIME type',
      },
    },

    /**
     * File size in bytes. Max 10 MB enforced by upload middleware.
     */
    fileSize: {
      type: Number,
      required: [true, 'fileSize is required'],
      min: [1, 'fileSize must be positive'],
      max: [10 * 1024 * 1024, 'fileSize cannot exceed 10 MB'],
    },

    /**
     * Path to the stored file, relative to DOCUMENT_STORAGE_PATH.
     * For local storage: e.g., "doc_<id>.pdf"
     * For cloud storage: the bucket key / storage path.
     */
    storagePath: {
      type: String,
      required: [true, 'storagePath is required'],
      trim: true,
    },

    /**
     * Download URL for the document.
     * Null for local filesystem storage in v1.
     * Populated for cloud storage adapters (Firebase, S3, GCS).
     */
    storageUrl: {
      type: String,
      default: null,
      trim: true,
    },

    /**
     * SHA-256 hash of the exact file bytes (hex string, lowercase).
     * Immutable — never changed after initial save.
     *
     * Proves byte-level identity only. Does NOT prove authenticity.
     */
    sha256Hash: {
      type: String,
      required: [true, 'sha256Hash is required'],
      match: [/^[a-f0-9]{64}$/, 'sha256Hash must be a 64-character hex string'],
      immutable: true,
    },

    /**
     * Hash algorithm identifier. Always "sha256" in v1.
     */
    hashAlgorithm: {
      type: String,
      required: [true, 'hashAlgorithm is required'],
      default: 'sha256',
      immutable: true,
    },

    /**
     * User who uploaded this document.
     */
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'uploadedBy is required'],
      immutable: true,
    },

    /**
     * What type of document representation was uploaded.
     * Affects the verification result: scans/screenshots cannot yield VERIFIED.
     */
    representationType: {
      type: String,
      enum: {
        values: DOCUMENT_REPRESENTATION_TYPES,
        message: 'Invalid document representation type',
      },
      default: 'ORIGINAL_DIGITAL_FILE',
    },

    /**
     * Canonicalization status — was any normalization applied to the file before hashing?
     * "NONE" means the file was hashed as-is (expected for v1).
     */
    canonicalizationStatus: {
      type: String,
      default: 'NONE',
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// ─── Indexes ──────────────────────────────────────────────────────────────────

documentSchema.index({ sha256Hash: 1 }); // Hash lookup during verification
documentSchema.index({ uploadedBy: 1 });

// ─── Model ────────────────────────────────────────────────────────────────────

const Document = mongoose.model('Document', documentSchema);

module.exports = { Document, DOCUMENT_MIME_TYPES, DOCUMENT_REPRESENTATION_TYPES };
