/**
 * Credential service.
 *
 * Handles credential issuance, versioning, revocation, and role-scoped listing.
 *
 * SECURITY rules:
 * - Only ACTIVE issuers may sign credentials (PROJECT_RULES §6).
 * - Private key is loaded TRANSIENTLY for signing only — not stored, not returned.
 * - After signing, the private key variable goes out of scope immediately.
 * - documentHash + signature are stored for verification.
 * - HR users can only see credentials from their own organizationId (M2 Decision A).
 * - AUDITOR has no access to credential management (M4 Decision).
 *
 * DOCUMENT STORAGE:
 * - Files are stored under DOCUMENT_STORAGE_PATH (env-configurable).
 * - Storage filenames are deterministic: doc_<documentId>.<ext>
 * - In v1: local filesystem only. Future: adapter pattern for cloud storage.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { Credential } = require('../models/Credential');
const { CredentialVersion } = require('../models/CredentialVersion');
const { Document } = require('../models/Document');
const { Issuer } = require('../models/Issuer');
const { IssuerKey } = require('../models/IssuerKey');
const cryptoService = require('./crypto.service');
const keystoreService = require('./keystore.service');
const auditService = require('./audit.service');
const config = require('../config/env');

// ─── Helper ────────────────────────────────────────────────────────────────────

const appError = (message, statusCode) => {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
};

// ─── Document Storage ─────────────────────────────────────────────────────────

/**
 * Resolve the configured document storage directory (absolute path).
 */
const getDocumentStorageDir = () => {
  const rawPath = config.documentStoragePath || './uploads';
  const absPath = path.isAbsolute(rawPath)
    ? rawPath
    : path.resolve(process.cwd(), rawPath);
  fs.mkdirSync(absPath, { recursive: true });
  return absPath;
};

/**
 * Derive file extension from MIME type.
 * @param {string} mimeType
 * @returns {string} e.g., ".pdf", ".png", ".jpg"
 */
const mimeToExt = (mimeType) => {
  const map = {
    'application/pdf': '.pdf',
    'image/png': '.png',
    'image/jpeg': '.jpg',
  };
  return map[mimeType] || '.bin';
};



/**
 * Issue a new credential.
 *
 * Flow:
 * 1. Verify issuer is ACTIVE and belongs to request user.
 * 2. Load active IssuerKey.
 * 3. Hash document buffer (SHA-256).
 * 4. Load private key (TRANSIENTLY — never stored).
 * 5. Sign documentHash with Ed25519.
 * 6. Save document file to storage.
 * 7. Create Document record.
 * 8. Create Credential record.
 * 9. Create CredentialVersion v1 record.
 * 10. Update Credential.currentVersionId.
 * 11. Audit log.
 *
 * @param {Object} params
 * @param {ObjectId} params.issuingUserId - req.user._id (must have role ISSUER)
 * @param {string} params.recipientId
 * @param {string} params.credentialType
 * @param {string} params.title
 * @param {string} [params.description]
 * @param {Date|string} [params.expiresAt]
 * @param {Buffer} params.fileBuffer - from multer memoryStorage
 * @param {string} params.originalFilename
 * @param {string} params.mimeType
 * @param {string} params.fileSize
 * @param {string} [params.representationType]
 * @returns {Promise<Object>} { credential, credentialVersion, document }
 */
const issueCredential = async ({
  issuingUserId,
  recipientId,
  credentialType,
  title,
  description,
  expiresAt,
  fileBuffer,
  originalFilename,
  mimeType,
  fileSize,
  representationType = 'ORIGINAL_DIGITAL_FILE',
}) => {
  // 1. Verify issuer is ACTIVE
  const issuer = await Issuer.findOne({ userId: issuingUserId });
  if (!issuer) throw appError('No issuer profile found for this user', 403);
  if (issuer.status !== 'ACTIVE') {
    throw appError(
      `Issuer is not authorized to sign credentials. Current status: '${issuer.status}'.`,
      403
    );
  }

  // 2. Load ACTIVE IssuerKey for this issuer
  const issuerKey = await IssuerKey.findOne({ issuerId: issuer._id, status: 'ACTIVE' });
  if (!issuerKey) {
    throw appError('No active signing key found for this issuer. Contact an administrator.', 403);
  }

  // 3. Hash document (SHA-256)
  const documentHash = cryptoService.hashDocument(fileBuffer);

  // 4. Load private key TRANSIENTLY (never stored after this scope)
  let signature;
  try {
    const privateKeyBase64 = keystoreService.loadPrivateKey(String(issuer._id));
    // 5. Sign the document hash
    signature = cryptoService.sign(documentHash, privateKeyBase64);
    // privateKeyBase64 goes out of scope here — no further reference
  } catch (keyErr) {
    throw appError(`Signing failed: ${keyErr.message}`, 500);
  }

  const now = new Date();
  const issuedAt = now;

  // 6. Save file to storage — create a temporary ObjectId-like placeholder
  //    We need the documentId for the filename, so we use a pre-allocated mongoose ObjectId.
  const mongoose = require('mongoose');
  const documentId = new mongoose.Types.ObjectId();

  // 6. Save file to document storage (uses documentId as filename base)
  const storageDir = getDocumentStorageDir();
  const ext = mimeToExt(mimeType);
  const filename = `doc_${String(documentId)}${ext}`;
  const filePath = path.join(storageDir, filename);
  fs.writeFileSync(filePath, fileBuffer);

  // 7. Create Document record
  const document = await Document.create({
    _id: documentId,
    originalFilename,
    mimeType,
    fileSize,
    storagePath: filename,
    storageUrl: null,
    sha256Hash: documentHash,
    hashAlgorithm: 'sha256',
    uploadedBy: issuingUserId,
    representationType,
    canonicalizationStatus: 'NONE',
  });

  // 8. Create Credential record
  const credential = await Credential.create({
    documentId: document._id,
    issuerId: issuer._id,
    issuerKeyId: issuerKey._id,
    recipientId,
    organizationId: issuer.organizationId,
    credentialType,
    title,
    description: description || null,
    documentHash,
    signature,
    status: 'ACTIVE',
    issuedAt,
    expiresAt: expiresAt || null,
  });

  // 9. Create CredentialVersion v1
  const credentialVersion = await CredentialVersion.create({
    credentialId: credential._id,
    versionNumber: 1,
    documentId: document._id,
    documentHash,
    signature,
    issuerKeyId: issuerKey._id,
    issuedAt,
    supersedesVersionId: null,
    changeReason: null,
    status: 'ACTIVE',
    createdAt: now,
  });

  // 10. Update currentVersionId
  credential.currentVersionId = credentialVersion._id;
  await credential.save();

  // 11. Audit
  await auditService.log({
    action: 'DOCUMENT_UPLOADED',
    performedBy: issuingUserId,
    targetType: 'DOCUMENT',
    targetId: document._id,
    metadata: {
      originalFilename,
      mimeType,
      fileSize,
      sha256Hash: documentHash,
      representationType,
    },
  });

  await auditService.log({
    action: 'CREDENTIAL_ISSUED',
    performedBy: issuingUserId,
    targetType: 'CREDENTIAL',
    targetId: credential._id,
    metadata: {
      issuerId: issuer._id,
      issuerKeyId: issuerKey._id,
      organizationId: issuer.organizationId,
      recipientId,
      credentialType,
      title,
      documentHash,
    },
  });

  await auditService.log({
    action: 'CREDENTIAL_VERSION_CREATED',
    performedBy: issuingUserId,
    targetType: 'CREDENTIAL_VERSION',
    targetId: credentialVersion._id,
    metadata: {
      credentialId: credential._id,
      versionNumber: 1,
      issuerKeyId: issuerKey._id,
    },
  });

  return { credential, credentialVersion, document };
};

// ─── Role-Scoped Credential Listing ──────────────────────────────────────────

/**
 * Build a query filter based on the requester's role.
 *
 * - ADMIN:  all credentials
 * - ISSUER: only credentials they issued
 * - HR:     only credentials from their organization (if organizationId set)
 * - USER:   only their own credentials (recipientId)
 * - AUDITOR: no access (caller must check before calling this)
 *
 * @param {Object} user - req.user
 * @returns {Object} Mongoose filter
 */
const buildCredentialFilter = (user) => {
  switch (user.role) {
    case 'ADMIN':
      return {};

    case 'ISSUER': {
      // ISSUER can see credentials they issued
      // We can't directly filter by userId here without a lookup;
      // the caller should pass issuerId from issuer profile.
      // We return a marker for the service to resolve.
      return { _byIssuerUserId: user._id };
    }

    case 'HR': {
      if (!user.organizationId) {
        throw appError(
          'HR user has no organizationId assigned. Contact an administrator.',
          403
        );
      }
      return { organizationId: user.organizationId };
    }

    case 'USER':
      return { recipientId: user._id };

    default:
      throw appError('Access denied', 403);
  }
};

/**
 * List credentials with role-based scoping.
 *
 * @param {Object} params
 * @param {Object} params.user - req.user
 * @param {string} [params.status]
 * @param {number} [params.page]
 * @param {number} [params.limit]
 * @returns {Promise<Object>} { credentials, total, page, limit }
 */
const listCredentials = async ({ user, status, page = 1, limit = 20 }) => {
  let filter = buildCredentialFilter(user);

  // If ISSUER, resolve their issuerId first
  if (filter._byIssuerUserId) {
    const issuerProfile = await Issuer.findOne({ userId: filter._byIssuerUserId }).lean();
    if (!issuerProfile) {
      return { credentials: [], total: 0, page: 1, limit: 20 };
    }
    filter = { issuerId: issuerProfile._id };
  }

  if (status) filter.status = status;

  const safePage = Math.max(1, parseInt(page, 10) || 1);
  const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
  const skip = (safePage - 1) * safeLimit;

  const [credentials, total] = await Promise.all([
    Credential.find(filter)
      .populate('documentId', 'originalFilename mimeType fileSize sha256Hash representationType')
      .populate('issuerId', 'status organizationId')
      .populate('issuerKeyId', 'algorithm publicKey status')
      .populate('recipientId', 'name email')
      .populate('organizationId', 'name organizationCode type')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit)
      .lean(),
    Credential.countDocuments(filter),
  ]);

  return { credentials, total, page: safePage, limit: safeLimit };
};

// ─── Get Single Credential ────────────────────────────────────────────────────

/**
 * Get a single credential by ID with role-based access check.
 *
 * @param {Object} params
 * @param {string} params.credentialId
 * @param {Object} params.user - req.user
 * @returns {Promise<Object>} Credential document
 */
const getCredential = async ({ credentialId, user }) => {
  const credential = await Credential.findById(credentialId)
    .populate('documentId', 'originalFilename mimeType fileSize sha256Hash representationType')
    .populate('issuerId', 'status organizationId')
    .populate('issuerKeyId', 'algorithm publicKey status')
    .populate('recipientId', 'name email')
    .populate('organizationId', 'name organizationCode type')
    .lean();

  if (!credential) throw appError('Credential not found', 404);

  // Access check
  const canAccess = (() => {
    switch (user.role) {
      case 'ADMIN': return true;
      case 'USER': return String(credential.recipientId?._id || credential.recipientId) === String(user._id);
      case 'HR': return user.organizationId && String(credential.organizationId?._id || credential.organizationId) === String(user.organizationId);
      case 'ISSUER': {
        // Need issuerId for the issuer user
        return true; // resolved below via issuer profile
      }
      default: return false;
    }
  })();

  if (user.role === 'ISSUER') {
    const issuerProfile = await Issuer.findOne({ userId: user._id }).lean();
    if (!issuerProfile || String(credential.issuerId?._id || credential.issuerId) !== String(issuerProfile._id)) {
      throw appError('Access denied', 403);
    }
    return credential;
  }

  if (!canAccess) throw appError('Access denied', 403);
  return credential;
};

// ─── Credential Versions ──────────────────────────────────────────────────────

/**
 * Get all versions of a credential.
 *
 * @param {Object} params
 * @param {string} params.credentialId
 * @param {Object} params.user
 * @returns {Promise<Array>} CredentialVersion documents
 */
const getCredentialVersions = async ({ credentialId, user }) => {
  // Access check via getCredential (reuses the same logic)
  await getCredential({ credentialId, user });

  const versions = await CredentialVersion.find({ credentialId })
    .populate('documentId', 'originalFilename mimeType sha256Hash')
    .populate('issuerKeyId', 'algorithm publicKey status')
    .sort({ versionNumber: 1 })
    .lean();

  return versions;
};

/**
 * Create a new credential version (correction/superseding).
 *
 * @param {Object} params
 * @param {string} params.credentialId
 * @param {ObjectId} params.issuingUserId
 * @param {Buffer} params.fileBuffer
 * @param {string} params.originalFilename
 * @param {string} params.mimeType
 * @param {number} params.fileSize
 * @param {string} params.changeReason
 * @param {string} [params.representationType]
 */
const addCredentialVersion = async ({
  credentialId,
  issuingUserId,
  fileBuffer,
  originalFilename,
  mimeType,
  fileSize,
  changeReason,
  representationType = 'ORIGINAL_DIGITAL_FILE',
}) => {
  // Verify issuer
  const issuer = await Issuer.findOne({ userId: issuingUserId });
  if (!issuer) throw appError('No issuer profile found for this user', 403);
  if (issuer.status !== 'ACTIVE') {
    throw appError(`Issuer is not authorized to create new versions. Status: '${issuer.status}'.`, 403);
  }

  // Verify credential belongs to this issuer
  const credential = await Credential.findById(credentialId);
  if (!credential) throw appError('Credential not found', 404);
  if (String(credential.issuerId) !== String(issuer._id)) {
    throw appError('Access denied: you did not issue this credential', 403);
  }
  if (credential.status === 'REVOKED') {
    throw appError('Cannot create a new version for a revoked credential', 409);
  }

  // Load ACTIVE key
  const issuerKey = await IssuerKey.findOne({ issuerId: issuer._id, status: 'ACTIVE' });
  if (!issuerKey) {
    throw appError('No active signing key found for this issuer.', 403);
  }

  // Hash and sign new document
  const documentHash = cryptoService.hashDocument(fileBuffer);
  let signature;
  try {
    const privateKeyBase64 = keystoreService.loadPrivateKey(String(issuer._id));
    signature = cryptoService.sign(documentHash, privateKeyBase64);
  } catch (keyErr) {
    throw appError(`Signing failed: ${keyErr.message}`, 500);
  }

  const now = new Date();

  // Determine new version number
  const lastVersion = await CredentialVersion.findOne({ credentialId })
    .sort({ versionNumber: -1 });
  const nextVersionNumber = (lastVersion ? lastVersion.versionNumber : 0) + 1;
  const prevVersionId = lastVersion ? lastVersion._id : null;

  // Save new document file
  const mongoose = require('mongoose');
  const documentId = new mongoose.Types.ObjectId();
  const storageDir = getDocumentStorageDir();
  const ext = mimeToExt(mimeType);
  const filename = `doc_${String(documentId)}${ext}`;
  const filePath = path.join(storageDir, filename);
  fs.writeFileSync(filePath, fileBuffer);

  const document = await Document.create({
    _id: documentId,
    originalFilename,
    mimeType,
    fileSize,
    storagePath: filename,
    storageUrl: null,
    sha256Hash: documentHash,
    hashAlgorithm: 'sha256',
    uploadedBy: issuingUserId,
    representationType,
    canonicalizationStatus: 'NONE',
  });

  // Supersede the previous version
  if (lastVersion) {
    lastVersion.status = 'SUPERSEDED';
    await lastVersion.save();
  }

  // Create new version
  const newVersion = await CredentialVersion.create({
    credentialId: credential._id,
    versionNumber: nextVersionNumber,
    documentId: document._id,
    documentHash,
    signature,
    issuerKeyId: issuerKey._id,
    issuedAt: now,
    supersedesVersionId: prevVersionId,
    changeReason: changeReason || null,
    status: 'ACTIVE',
    createdAt: now,
  });

  // Update credential pointer
  credential.currentVersionId = newVersion._id;
  await credential.save();

  // Audit
  await auditService.log({
    action: 'DOCUMENT_UPLOADED',
    performedBy: issuingUserId,
    targetType: 'DOCUMENT',
    targetId: document._id,
    metadata: { originalFilename, mimeType, fileSize, sha256Hash: documentHash, representationType },
  });

  await auditService.log({
    action: 'CREDENTIAL_SUPERSEDED',
    performedBy: issuingUserId,
    targetType: 'CREDENTIAL',
    targetId: credential._id,
    metadata: {
      previousVersionId: prevVersionId,
      newVersionId: newVersion._id,
      newVersionNumber: nextVersionNumber,
    },
  });

  await auditService.log({
    action: 'CREDENTIAL_VERSION_CREATED',
    performedBy: issuingUserId,
    targetType: 'CREDENTIAL_VERSION',
    targetId: newVersion._id,
    metadata: {
      credentialId: credential._id,
      versionNumber: nextVersionNumber,
      issuerKeyId: issuerKey._id,
      changeReason,
    },
  });

  return { credential, credentialVersion: newVersion, document };
};

// ─── Revoke Credential ────────────────────────────────────────────────────────

/**
 * Revoke a credential (ISSUER — own credentials only).
 *
 * REVOKED is NOT FAKE (PROJECT_RULES §11, §20).
 * The credential record is preserved permanently.
 *
 * @param {Object} params
 * @param {string} params.credentialId
 * @param {ObjectId} params.issuingUserId
 * @param {string} params.reason
 * @returns {Promise<Object>} Updated credential
 */
const revokeCredential = async ({ credentialId, issuingUserId, reason }) => {
  const cleanReason = reason ? String(reason).trim() : '';
  if (!cleanReason || cleanReason.length < 3) {
    throw appError('A revocation reason is required (minimum 3 characters)', 400);
  }

  const issuer = await Issuer.findOne({ userId: issuingUserId });
  if (!issuer) throw appError('No issuer profile found for this user', 403);
  if (issuer.status !== 'ACTIVE') {
    throw appError(`Issuer is not authorized to revoke credentials. Status: '${issuer.status}'.`, 403);
  }

  const credential = await Credential.findById(credentialId);
  if (!credential) throw appError('Credential not found', 404);
  if (String(credential.issuerId) !== String(issuer._id)) {
    throw appError('Access denied: you did not issue this credential', 403);
  }
  if (credential.status === 'REVOKED') {
    throw appError('Credential is already revoked', 409);
  }

  credential.status = 'REVOKED';
  credential.revokedAt = new Date();
  credential.revokedReason = cleanReason;
  await credential.save();

  await auditService.log({
    action: 'CREDENTIAL_REVOKED',
    performedBy: issuingUserId,
    targetType: 'CREDENTIAL',
    targetId: credential._id,
    metadata: {
      reason: cleanReason,
      issuerId: issuer._id,
    },
  });

  return credential;
};

module.exports = {
  issueCredential,
  listCredentials,
  getCredential,
  getCredentialVersions,
  addCredentialVersion,
  revokeCredential,
};
