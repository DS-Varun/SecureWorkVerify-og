/**
 * File upload middleware.
 *
 * Configures multer for credential document uploads.
 *
 * Rules (PROJECT_RULES §18):
 * - Allowed MIME types: application/pdf, image/png, image/jpeg
 * - Max file size: configurable via MAX_FILE_SIZE_MB env (default: 10 MB)
 * - Storage: memory (buffer in-process for SHA-256 hashing before writing to disk)
 *
 * SECURITY:
 * - File type is validated server-side by MIME type, not by file extension.
 * - A rejected file type results in a 415 response via error.middleware.js.
 * - Private key material MUST NEVER be passed through this middleware.
 */

'use strict';

const multer = require('multer');
const config = require('../config/env');

const ALLOWED_MIME_TYPES = [
  'application/pdf',
  'image/png',
  'image/jpeg',
];

/**
 * Multer fileFilter — rejects disallowed MIME types with a structured error.
 * @param {Object} req
 * @param {Object} file
 * @param {Function} cb
 */
const fileFilter = (req, file, cb) => {
  if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
    cb(null, true);
  } else {
    const err = new Error(
      `Unsupported file type: '${file.mimetype}'. Allowed types: PDF, PNG, JPEG.`
    );
    err.code = 'UNSUPPORTED_FILE_TYPE';
    cb(err, false);
  }
};

/**
 * Multer instance:
 * - Memory storage (buffer stays in memory for hashing)
 * - File size limit from config (in bytes)
 * - MIME type allowlist via fileFilter
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxFileSizeMb * 1024 * 1024, // bytes
    files: 1,
  },
  fileFilter,
});

/**
 * Single-file upload middleware for credential documents.
 * Field name: 'document'
 * Use as: router.post('/issue', authenticate, uploadDocument, controller)
 */
const uploadDocument = upload.single('document');

module.exports = { uploadDocument, ALLOWED_MIME_TYPES };
