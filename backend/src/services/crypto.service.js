/**
 * Cryptographic service.
 *
 * Provides:
 * - Ed25519 keypair generation (tweetnacl)
 * - Ed25519 sign / verify (tweetnacl)
 * - SHA-256 document hashing (Node.js built-in crypto)
 *
 * SECURITY (PROJECT_RULES §8, §20):
 * - All operations are server-side ONLY.
 * - Private key bytes are NEVER returned from public-facing APIs.
 * - Private key bytes are NEVER stored in MongoDB.
 * - This module receives and returns base64 strings for key material;
 *   conversion to/from Uint8Array is internal only.
 * - The caller (keystore.service.js) is responsible for persisting private keys
 *   to the filesystem.
 */

'use strict';

const crypto = require('crypto');
const nacl = require('tweetnacl');

// ─── SHA-256 Hashing ──────────────────────────────────────────────────────────

/**
 * Compute the SHA-256 hash of a file buffer.
 * Returns the hex string (lowercase).
 *
 * IMPORTANT: This proves byte-level identity of two files only.
 * It does NOT prove authenticity of the document content.
 *
 * @param {Buffer} buffer - Raw file bytes
 * @returns {string} SHA-256 hex string
 */
const hashDocument = (buffer) => {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('hashDocument requires a Buffer');
  }
  return crypto.createHash('sha256').update(buffer).digest('hex');
};

// ─── Ed25519 Operations ───────────────────────────────────────────────────────

/**
 * Generate a new Ed25519 keypair.
 *
 * Returns BOTH keys as base64 strings.
 * The CALLER must immediately pass privateKeyBase64 to keystore.service.js
 * for secure filesystem storage and MUST NOT store it anywhere else.
 *
 * @returns {{ publicKey: string, privateKey: string }} Both keys as base64
 */
const generateKeyPair = () => {
  const keyPair = nacl.sign.keyPair();
  return {
    publicKey: Buffer.from(keyPair.publicKey).toString('base64'),
    // WARNING: privateKey is the full 64-byte Ed25519 secret key (seed + public).
    // It must be stored securely on the filesystem — never in MongoDB or logs.
    privateKey: Buffer.from(keyPair.secretKey).toString('base64'),
  };
};

/**
 * Sign a document hash using an Ed25519 private key.
 *
 * @param {string} documentHashHex - SHA-256 hex string of the document
 * @param {string} privateKeyBase64 - Ed25519 secret key (64 bytes) as base64
 * @returns {string} Detached Ed25519 signature as base64
 */
const sign = (documentHashHex, privateKeyBase64) => {
  if (!documentHashHex || typeof documentHashHex !== 'string') {
    throw new Error('sign: documentHashHex must be a non-empty string');
  }
  if (!privateKeyBase64 || typeof privateKeyBase64 !== 'string') {
    throw new Error('sign: privateKeyBase64 must be a non-empty string');
  }

  // Convert hex to bytes for signing
  const messageBytes = Buffer.from(documentHashHex, 'hex');
  const privateKeyBytes = Buffer.from(privateKeyBase64, 'base64');

  if (privateKeyBytes.length !== 64) {
    throw new Error('sign: invalid Ed25519 private key length (expected 64 bytes)');
  }

  const signatureBytes = nacl.sign.detached(messageBytes, privateKeyBytes);
  return Buffer.from(signatureBytes).toString('base64');
};

/**
 * Verify an Ed25519 signature against a document hash and public key.
 *
 * @param {string} documentHashHex - SHA-256 hex string
 * @param {string} signatureBase64 - Detached Ed25519 signature as base64
 * @param {string} publicKeyBase64 - Ed25519 public key (32 bytes) as base64
 * @returns {boolean} true if signature is valid, false otherwise
 */
const verify = (documentHashHex, signatureBase64, publicKeyBase64) => {
  try {
    const messageBytes = Buffer.from(documentHashHex, 'hex');
    const signatureBytes = Buffer.from(signatureBase64, 'base64');
    const publicKeyBytes = Buffer.from(publicKeyBase64, 'base64');

    if (publicKeyBytes.length !== 32) {
      return false;
    }
    if (signatureBytes.length !== 64) {
      return false;
    }

    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch {
    // Any parsing error = invalid signature
    return false;
  }
};

module.exports = { hashDocument, generateKeyPair, sign, verify };
