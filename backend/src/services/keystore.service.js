/**
 * Key store service — Ed25519 private key filesystem management.
 *
 * This is the ONLY module allowed to read or write private key files.
 * Private key bytes MUST NEVER appear in MongoDB, API responses, or logs.
 *
 * Key lifecycle (PROJECT_RULES §7):
 * - savePrivateKey(issuerId, base64)  → writes to  keys/issuer_<id>.key
 * - loadPrivateKey(issuerId)          → reads from  keys/issuer_<id>.key  (ACTIVE only)
 * - retirePrivateKey(issuerId)        → moves to    keys/retired/issuer_<id>.key
 *                                       (inaccessible for new signing; preserved for audit)
 *
 * Key compromise (PROJECT_RULES §7):
 * - When a key is compromised, retirePrivateKey() is called immediately.
 * - The historical public key remains in MongoDB for verifying past signatures.
 * - Historical signatures remain valid for verification purposes.
 * - The ADMIN/human must determine whether credentials signed before the compromise
 *   are still trustworthy, based on timestamps.
 *
 * SECURITY rules enforced here:
 * - Files are written with mode 0o600 (owner read/write only).
 * - loadPrivateKey() ONLY reads from the active directory — NOT from retired/.
 * - If the key file is missing or in retired/, loadPrivateKey() throws.
 * - No private key bytes appear in error messages or logs.
 * - Path traversal: issuerId is validated to be a MongoDB ObjectId string.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const config = require('../config/env');

// ─── Path helpers ─────────────────────────────────────────────────────────────

const MONGO_ID_REGEX = /^[a-f0-9]{24}$/i;

/**
 * Validate issuerId to prevent path traversal.
 * @param {string} issuerId
 */
const validateIssuerId = (issuerId) => {
  const id = String(issuerId);
  if (!MONGO_ID_REGEX.test(id)) {
    throw new Error('Invalid issuerId format — must be a 24-character hex MongoDB ObjectId');
  }
  return id;
};

/**
 * Resolve the base keys directory (absolute path).
 * Relative paths are resolved from the backend process working directory.
 */
const getKeysDir = () => {
  const rawPath = config.keyStoragePath || './keys';
  return path.isAbsolute(rawPath)
    ? rawPath
    : path.resolve(process.cwd(), rawPath);
};

/**
 * Resolve the retired keys subdirectory.
 */
const getRetiredDir = () => path.join(getKeysDir(), 'retired');

/**
 * Resolve the active key file path for a given issuerId.
 * @param {string} issuerId
 * @returns {string} Absolute path to key file
 */
const activeKeyPath = (issuerId) =>
  path.join(getKeysDir(), `issuer_${validateIssuerId(issuerId)}.key`);

/**
 * Resolve the retired key file path.
 * @param {string} issuerId
 * @returns {string} Absolute path to retired key file
 */
const retiredKeyPath = (issuerId) =>
  path.join(getRetiredDir(), `issuer_${validateIssuerId(issuerId)}.key`);

// ─── Directory initialisation ─────────────────────────────────────────────────

/**
 * Ensure key storage directories exist.
 * Safe to call multiple times (idempotent).
 */
const ensureDirectories = () => {
  fs.mkdirSync(getKeysDir(), { recursive: true });
  fs.mkdirSync(getRetiredDir(), { recursive: true });
};

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Save a private key to the active keys directory.
 *
 * SECURITY: File permissions set to 0o600 (owner read/write only).
 * Called ONLY during issuer approval when a new keypair is generated.
 *
 * @param {string} issuerId - MongoDB ObjectId as string
 * @param {string} privateKeyBase64 - Ed25519 secret key (64 bytes) as base64
 * @returns {string} The filesystem path where the key was saved (path reference only)
 */
const savePrivateKey = (issuerId, privateKeyBase64) => {
  if (!privateKeyBase64 || typeof privateKeyBase64 !== 'string') {
    throw new Error('savePrivateKey: privateKeyBase64 must be a non-empty string');
  }

  ensureDirectories();

  const filePath = activeKeyPath(issuerId);

  // Write with restricted permissions: owner read/write only
  fs.writeFileSync(filePath, privateKeyBase64, { encoding: 'utf8', mode: 0o600 });

  // Return path reference (not the key bytes)
  return filePath;
};

/**
 * Load a private key for signing.
 *
 * SECURITY:
 * - ONLY reads from the active keys directory.
 * - Throws if the key is retired/compromised (in retired/ dir) or missing.
 * - The returned string MUST NOT be stored in MongoDB, returned in API responses, or logged.
 *
 * @param {string} issuerId - MongoDB ObjectId as string
 * @returns {string} Ed25519 secret key as base64 string
 * @throws If key is not found in the active directory
 */
const loadPrivateKey = (issuerId) => {
  const filePath = activeKeyPath(issuerId);

  if (!fs.existsSync(filePath)) {
    // Check if it was retired — give a specific error without exposing path details
    const rPath = retiredKeyPath(issuerId);
    if (fs.existsSync(rPath)) {
      throw new Error('Private key is retired and cannot be used for new signing operations.');
    }
    throw new Error('Private key not found. The issuer may not be active or approved.');
  }

  const keyBase64 = fs.readFileSync(filePath, { encoding: 'utf8' }).trim();

  if (!keyBase64) {
    throw new Error('Private key file is empty or corrupted.');
  }

  return keyBase64;
};

/**
 * Retire a private key — moves it from the active directory to keys/retired/.
 *
 * Called when:
 * - An issuer is revoked (PROJECT_RULES §7: "private key becomes unusable")
 * - A key is marked as compromised (PROJECT_RULES §7: stop new signing immediately)
 *
 * IMPORTANT (PROJECT_RULES §7, §20):
 * - The key file is MOVED, not deleted.
 * - The public key remains in MongoDB permanently.
 * - Historical signatures remain verifiable.
 * - The retired file is NOT accessible via loadPrivateKey().
 *
 * Idempotent: if the key is already retired, this is a no-op.
 *
 * @param {string} issuerId - MongoDB ObjectId as string
 * @returns {string} The retired file path (for audit metadata)
 */
const retirePrivateKey = (issuerId) => {
  ensureDirectories();

  const srcPath = activeKeyPath(issuerId);
  const dstPath = retiredKeyPath(issuerId);

  if (!fs.existsSync(srcPath)) {
    // Already retired or never existed — idempotent
    return dstPath;
  }

  fs.renameSync(srcPath, dstPath);
  return dstPath;
};

/**
 * Check whether an active key file exists (without reading its contents).
 *
 * @param {string} issuerId
 * @returns {boolean}
 */
const activeKeyExists = (issuerId) => {
  try {
    return fs.existsSync(activeKeyPath(issuerId));
  } catch {
    return false;
  }
};

module.exports = {
  savePrivateKey,
  loadPrivateKey,
  retirePrivateKey,
  activeKeyExists,
  ensureDirectories,
  // Exported for tests only — not for general use
  _getKeysDir: getKeysDir,
  _getRetiredDir: getRetiredDir,
};
