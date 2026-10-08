/**
 * Verification service.
 *
 * Implements the deterministic 4-part independent verification engine (PROJECT_RULES §10–14):
 * 1. Document Integrity (SHA-256 hash comparison)
 * 2. Digital Signature (Ed25519 verification against historical public key)
 * 3. Issuer Authorization & Key Trust (Issuer status, Key compromise status)
 * 4. Credential Validity & Organization Trust (Active, Revoked, Expired, Org Verified)
 *
 * CRITICAL SEMANTIC RULES:
 * - A revoked credential is NOT fake -> CREDENTIAL_REVOKED
 * - An expired credential is NOT fake -> CREDENTIAL_EXPIRED
 * - A compromised key -> KEY_COMPROMISED
 * - Private keys are NEVER used or accessed during verification (public keys only).
 */

'use strict';

const mongoose = require('mongoose');
const { Verification, VERIFICATION_RESULTS, TRUST_LEVELS } = require('../models/Verification');
const { VerificationEvidence } = require('../models/VerificationEvidence');
const { Credential } = require('../models/Credential');
const { CredentialVersion } = require('../models/CredentialVersion');
const { Issuer } = require('../models/Issuer');
const { IssuerKey } = require('../models/IssuerKey');
const { Organization } = require('../models/Organization');
const cryptoService = require('./crypto.service');
const auditService = require('./audit.service');

// ─── Helper ────────────────────────────────────────────────────────────────────

const appError = (message, statusCode) => {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
};

// ─── Verification Engine ───────────────────────────────────────────────────────

/**
 * Execute document verification.
 *
 * @param {Object} params
 * @param {Buffer} params.fileBuffer - Raw uploaded document bytes
 * @param {Object} params.verifiedByUser - User performing verification (req.user)
 * @param {string} [params.originalFilename]
 * @param {string} [params.mimeType]
 * @returns {Promise<Object>} Verification document with populated evidence and details
 */
const verifyDocument = async ({
  fileBuffer,
  verifiedByUser,
  originalFilename = null,
  mimeType = null,
}) => {
  if (!Buffer.isBuffer(fileBuffer)) {
    throw appError('Document file buffer is required for verification', 400);
  }

  const verificationId = new mongoose.Types.ObjectId();
  const uploadedDocumentHash = cryptoService.hashDocument(fileBuffer);
  const evidenceRecords = [];
  const warnings = [];

  // ─── Step 1: Look up matching Credential or Version by Hash ───────────────
  let credential = await Credential.findOne({ documentHash: uploadedDocumentHash });
  let matchedVersion = null;

  if (!credential) {
    // Check if the hash matches a specific historical CredentialVersion
    matchedVersion = await CredentialVersion.findOne({ documentHash: uploadedDocumentHash });
    if (matchedVersion) {
      credential = await Credential.findById(matchedVersion.credentialId);
    }
  } else if (credential.currentVersionId) {
    matchedVersion = await CredentialVersion.findById(credential.currentVersionId);
  }

  // ─── Case A: Document Hash Not Found ────────────────────────────────────────
  if (!credential) {
    const hashEvidence = new VerificationEvidence({
      verificationId,
      evidenceType: 'HASH_MATCH',
      documentHash: uploadedDocumentHash,
      expectedDocumentHash: null,
      evidenceStatus: 'INVALID',
      sourceResponseSummary: 'No credential found matching the uploaded document hash.',
      details: {
        checkedAt: new Date(),
        originalFilename,
        mimeType,
      },
    });
    await hashEvidence.save();
    evidenceRecords.push(hashEvidence);

    const verification = await Verification.create({
      _id: verificationId,
      verifiedBy: verifiedByUser._id,
      verificationMode: 'CREDENTIAL',
      uploadedDocumentHash,
      credentialId: null,
      credentialVersionId: null,
      organizationId: null,
      issuerId: null,
      issuerKeyId: null,
      result: 'NOT_FOUND',
      trustLevel: 'LEVEL_0_UNKNOWN',
      integrityCheck: {
        passed: false,
        documentHash: uploadedDocumentHash,
        expectedHash: null,
      },
      signatureCheck: {
        passed: false,
        algorithm: 'Ed25519',
        signature: null,
        publicKey: null,
      },
      issuerTrustCheck: {
        passed: false,
        issuerStatus: null,
        keyStatus: null,
      },
      organizationTrustCheck: {
        passed: false,
        organizationVerificationStatus: null,
        organizationStatus: null,
      },
      credentialStatusCheck: {
        passed: false,
        credentialStatus: null,
        isExpired: false,
        expiresAt: null,
      },
      evidenceIds: [hashEvidence._id],
      explanation: 'No matching credential found in the system for the submitted document hash.',
      warnings: ['Document does not match any registered credential hash.'],
      details: { uploadedDocumentHash },
    });

    // Audit logs
    await auditService.log({
      action: 'VERIFICATION_EVIDENCE_CREATED',
      performedBy: verifiedByUser._id,
      targetType: 'VERIFICATION',
      targetId: verification._id,
      metadata: { evidenceType: 'HASH_MATCH', evidenceId: hashEvidence._id },
    });

    await auditService.log({
      action: 'VERIFICATION_PERFORMED',
      performedBy: verifiedByUser._id,
      targetType: 'VERIFICATION',
      targetId: verification._id,
      metadata: {
        result: 'NOT_FOUND',
        trustLevel: 'LEVEL_0_UNKNOWN',
        uploadedDocumentHash,
      },
    });

    return verification;
  }

  // ─── Case B: Credential Found — Perform Independent Checks ─────────────────
  const expectedHash = matchedVersion?.documentHash || credential.documentHash;
  const signature = matchedVersion?.signature || credential.signature;
  const keyIdToLookup = matchedVersion?.issuerKeyId || credential.issuerKeyId;

  // 1. Fetch Issuer, Key, and Organization
  const [issuer, issuerKey, organization] = await Promise.all([
    Issuer.findById(credential.issuerId),
    IssuerKey.findById(keyIdToLookup),
    Organization.findById(credential.organizationId || (await Issuer.findById(credential.issuerId))?.organizationId),
  ]);

  // 2. Check 1: Document Hash Integrity
  const hashMatch = (uploadedDocumentHash === expectedHash);
  const hashEvidence = new VerificationEvidence({
    verificationId,
    evidenceType: 'HASH_MATCH',
    documentHash: uploadedDocumentHash,
    expectedDocumentHash: expectedHash,
    evidenceStatus: hashMatch ? 'VALID' : 'INVALID',
    sourceResponseSummary: hashMatch
      ? 'Document SHA-256 hash matches the trusted credential original.'
      : 'Document hash mismatch against expected trusted credential hash.',
    details: {
      matchedVersionNumber: matchedVersion?.versionNumber || 1,
      expectedHash,
      uploadedDocumentHash,
    },
  });
  await hashEvidence.save();
  evidenceRecords.push(hashEvidence);

  // 3. Check 2: Digital Signature Verification (Ed25519)
  let sigValid = false;
  const publicKey = issuerKey ? issuerKey.publicKey : null;

  if (signature && publicKey && expectedHash) {
    sigValid = cryptoService.verify(expectedHash, signature, publicKey);
  }

  const sigEvidence = new VerificationEvidence({
    verificationId,
    evidenceType: 'DIGITAL_SIGNATURE',
    documentHash: expectedHash,
    signaturePresent: !!signature,
    signatureValid: sigValid,
    evidenceStatus: sigValid ? 'VALID' : 'INVALID',
    sourceResponseSummary: sigValid
      ? 'Ed25519 cryptographic signature is valid and matches the issuer public key.'
      : 'Ed25519 digital signature validation failed against the issuer public key.',
    details: {
      algorithm: issuerKey?.algorithm || 'Ed25519',
      issuerKeyId: issuerKey?._id,
      publicKey: publicKey ? `${publicKey.substring(0, 16)}...` : null,
    },
  });
  await sigEvidence.save();
  evidenceRecords.push(sigEvidence);

  // 4. Check 3: Organization Trust
  const orgVerificationStatus = organization ? organization.organizationVerificationStatus : 'UNKNOWN';
  const orgStatus = organization ? organization.status : 'UNKNOWN';
  const orgTrusted = (organization && orgVerificationStatus === 'VERIFIED' && orgStatus === 'ACTIVE');

  const orgEvidence = new VerificationEvidence({
    verificationId,
    evidenceType: 'DOMAIN_VERIFICATION',
    sourceResponseSummary: orgTrusted
      ? `Organization '${organization.name}' is VERIFIED and ACTIVE.`
      : `Organization verification status is '${orgVerificationStatus}', status is '${orgStatus}'.`,
    evidenceStatus: orgTrusted ? 'VALID' : 'INVALID',
    details: {
      organizationId: organization?._id,
      organizationName: organization?.name,
      organizationCode: organization?.organizationCode,
      organizationVerificationStatus: orgVerificationStatus,
      status: orgStatus,
    },
  });
  await orgEvidence.save();
  evidenceRecords.push(orgEvidence);

  // 5. Check 4: Issuer Status
  const issuerStatus = issuer ? issuer.status : 'UNKNOWN';
  const issuerActive = (issuer && issuerStatus === 'ACTIVE');

  const issuerEvidence = new VerificationEvidence({
    verificationId,
    evidenceType: 'ISSUER_STATUS',
    sourceResponseSummary: issuerActive
      ? 'Issuer is authorized and in ACTIVE status.'
      : `Issuer status is '${issuerStatus}'.`,
    evidenceStatus: issuerActive ? 'VALID' : 'INVALID',
    details: {
      issuerId: issuer?._id,
      status: issuerStatus,
    },
  });
  await issuerEvidence.save();
  evidenceRecords.push(issuerEvidence);

  // 6. Check 5: Signing Key Trust (Compromised / Active / Retired)
  const keyStatus = issuerKey ? issuerKey.status : 'UNKNOWN';
  const keyCompromised = (issuerKey && keyStatus === 'COMPROMISED');

  // 7. Check 6: Credential Status & Expiry
  const credStatus = credential.status;
  const isRevoked = (credStatus === 'REVOKED');
  const now = new Date();
  const isExpired = !!(credential.expiresAt && new Date(credential.expiresAt) <= now);

  const credEvidence = new VerificationEvidence({
    verificationId,
    evidenceType: 'CREDENTIAL_STATUS',
    sourceResponseSummary: isRevoked
      ? `Credential is REVOKED (Reason: ${credential.revokedReason || 'Not specified'}).`
      : isExpired
      ? `Credential EXPIRED on ${credential.expiresAt.toISOString()}.`
      : 'Credential is ACTIVE and within valid date range.',
    evidenceStatus: (!isRevoked && !isExpired && credStatus === 'ACTIVE') ? 'VALID' : 'INVALID',
    details: {
      credentialStatus: credStatus,
      isRevoked,
      revokedReason: credential.revokedReason,
      revokedAt: credential.revokedAt,
      expiresAt: credential.expiresAt,
      isExpired,
    },
  });
  await credEvidence.save();
  evidenceRecords.push(credEvidence);

  // ─── Determine Authoritative Verification Result & Trust Level ───────────────
  let result;
  let trustLevel;
  let explanation;

  if (!hashMatch) {
    result = 'ALTERED';
    trustLevel = 'LEVEL_0_UNKNOWN';
    explanation = 'Document content does not match the registered credential original.';
    warnings.push('File hash does not match expected credential hash.');
  } else if (!sigValid) {
    result = 'SIGNATURE_INVALID';
    trustLevel = 'LEVEL_3_INTEGRITY_VERIFIED';
    explanation = 'Document hash matched, but cryptographic signature validation failed against the issuer public key.';
    warnings.push('Digital signature is invalid.');
  } else if (keyCompromised) {
    result = 'KEY_COMPROMISED';
    trustLevel = 'LEVEL_3_INTEGRITY_VERIFIED';
    explanation = 'The issuer key used to sign this credential was marked as COMPROMISED. Manual review required.';
    warnings.push('Issuer signing key is marked COMPROMISED.');
  } else if (issuerStatus === 'REVOKED') {
    result = 'ISSUER_REVOKED';
    trustLevel = 'LEVEL_4_SIGNATURE_VERIFIED';
    explanation = 'Document integrity and signature were verified, but the signing issuer authorization has been REVOKED.';
    warnings.push('Issuer authorization has been revoked.');
  } else if (issuerStatus === 'SUSPENDED') {
    result = 'ISSUER_SUSPENDED';
    trustLevel = 'LEVEL_4_SIGNATURE_VERIFIED';
    explanation = 'Document integrity and signature were verified, but the signing issuer is currently SUSPENDED.';
    warnings.push('Issuer is currently suspended.');
  } else if (isRevoked) {
    result = 'CREDENTIAL_REVOKED';
    trustLevel = 'LEVEL_4_SIGNATURE_VERIFIED';
    explanation = `The credential is authentic and signature is valid, but the credential was REVOKED by the issuer. Reason: ${credential.revokedReason || 'Not specified'}. (Authentic but revoked — NOT fake).`;
    warnings.push('Credential has been revoked by the issuing institution.');
  } else if (isExpired) {
    result = 'CREDENTIAL_EXPIRED';
    trustLevel = 'LEVEL_4_SIGNATURE_VERIFIED';
    explanation = `The credential is authentic and signature is valid, but its validity period ended on ${credential.expiresAt.toISOString()}. (Authentic but expired — NOT fake).`;
    warnings.push('Credential validity period has expired.');
  } else if (!orgTrusted) {
    result = 'MANUAL_REVIEW';
    trustLevel = 'LEVEL_4_SIGNATURE_VERIFIED';
    explanation = 'Document integrity and signature were verified, but the issuing organization trust is not active or verified. Human review is required.';
    warnings.push(`Issuing organization verification status is '${orgVerificationStatus}'.`);
  } else {
    result = 'VERIFIED';
    trustLevel = 'LEVEL_5_CURRENTLY_VALID';
    explanation = 'All checks passed: organization is verified, issuer is authorized and active, digital signature is cryptographically valid, and credential is active and within valid date range.';
  }

  // ─── Create Verification Document ───────────────────────────────────────────
  const verification = await Verification.create({
    _id: verificationId,
    verifiedBy: verifiedByUser._id,
    verificationMode: 'CREDENTIAL',
    uploadedDocumentHash,
    credentialId: credential._id,
    credentialVersionId: matchedVersion?._id || credential.currentVersionId || null,
    organizationId: organization?._id || credential.organizationId || null,
    issuerId: issuer?._id || credential.issuerId || null,
    issuerKeyId: issuerKey?._id || credential.issuerKeyId || null,
    result,
    trustLevel,
    integrityCheck: {
      passed: hashMatch,
      documentHash: uploadedDocumentHash,
      expectedHash,
    },
    signatureCheck: {
      passed: sigValid,
      algorithm: issuerKey?.algorithm || 'Ed25519',
      signature: signature ? `${signature.substring(0, 16)}...` : null,
      publicKey: publicKey ? `${publicKey.substring(0, 16)}...` : null,
    },
    issuerTrustCheck: {
      passed: issuerActive,
      issuerStatus,
      keyStatus,
    },
    organizationTrustCheck: {
      passed: orgTrusted,
      organizationVerificationStatus: orgVerificationStatus,
      organizationStatus: orgStatus,
    },
    credentialStatusCheck: {
      passed: (!isRevoked && !isExpired && credStatus === 'ACTIVE'),
      credentialStatus: credStatus,
      isExpired,
      expiresAt: credential.expiresAt || null,
    },
    evidenceIds: evidenceRecords.map((e) => e._id),
    explanation,
    warnings,
    details: {
      credentialType: credential.credentialType,
      title: credential.title,
      recipientId: credential.recipientId,
      versionNumber: matchedVersion?.versionNumber || 1,
    },
  });

  // ─── Audit Logging ──────────────────────────────────────────────────────────
  for (const ev of evidenceRecords) {
    await auditService.log({
      action: 'VERIFICATION_EVIDENCE_CREATED',
      performedBy: verifiedByUser._id,
      targetType: 'VERIFICATION',
      targetId: verification._id,
      metadata: {
        evidenceId: ev._id,
        evidenceType: ev.evidenceType,
        evidenceStatus: ev.evidenceStatus,
      },
    });
  }

  await auditService.log({
    action: 'VERIFICATION_PERFORMED',
    performedBy: verifiedByUser._id,
    targetType: 'VERIFICATION',
    targetId: verification._id,
    metadata: {
      result,
      trustLevel,
      credentialId: credential._id,
      uploadedDocumentHash,
    },
  });

  return verification;
};

// ─── Role-Scoped Listing ───────────────────────────────────────────────────────

/**
 * List verification history with role-based scoping.
 *
 * Scoping rules (PROJECT_RULES §24):
 * - USER: only their own verifications (verifiedBy === user._id)
 * - HR: only their own verifications (verifiedBy === user._id)
 * - ADMIN: all verifications
 * - AUDITOR: all verifications
 *
 * @param {Object} params
 * @param {Object} params.user - req.user
 * @param {string} [params.result]
 * @param {number} [params.page]
 * @param {number} [params.limit]
 * @returns {Promise<Object>} { verifications, total, page, limit }
 */
const listVerifications = async ({ user, result, page = 1, limit = 20 }) => {
  const filter = {};

  if (user.role === 'USER' || user.role === 'HR') {
    filter.verifiedBy = user._id;
  } else if (user.role !== 'ADMIN' && user.role !== 'AUDITOR') {
    throw appError('Access denied', 403);
  }

  if (result) {
    if (!VERIFICATION_RESULTS.includes(result)) {
      throw appError(`Invalid result filter: ${result}`, 400);
    }
    filter.result = result;
  }

  const safePage = Math.max(1, parseInt(page, 10) || 1);
  const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
  const skip = (safePage - 1) * safeLimit;

  const [verifications, total] = await Promise.all([
    Verification.find(filter)
      .populate('credentialId', 'title credentialType status')
      .populate('organizationId', 'name organizationCode type')
      .populate('issuerId', 'status')
      .populate('verifiedBy', 'name email role')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(safeLimit)
      .lean(),
    Verification.countDocuments(filter),
  ]);

  return { verifications, total, page: safePage, limit: safeLimit };
};

// ─── Single Verification Retrieval ─────────────────────────────────────────────

/**
 * Get a single verification record by ID with role-based access check.
 *
 * @param {Object} params
 * @param {string} params.verificationId
 * @param {Object} params.user - req.user
 * @returns {Promise<Object>} Verification document
 */
const getVerification = async ({ verificationId, user }) => {
  const verification = await Verification.findById(verificationId)
    .populate('credentialId', 'title credentialType documentHash status issuedAt expiresAt')
    .populate('organizationId', 'name organizationCode type organizationVerificationStatus')
    .populate('issuerId', 'status')
    .populate('verifiedBy', 'name email role')
    .populate('evidenceIds')
    .lean();

  if (!verification) {
    throw appError('Verification record not found', 404);
  }

  // Role scoping
  if (user.role === 'USER' || user.role === 'HR') {
    const verifiedById = verification.verifiedBy?._id || verification.verifiedBy;
    if (String(verifiedById) !== String(user._id)) {
      throw appError('Access denied', 403);
    }
  } else if (user.role !== 'ADMIN' && user.role !== 'AUDITOR') {
    throw appError('Access denied', 403);
  }

  return verification;
};

// ─── Evidence Trail Retrieval ──────────────────────────────────────────────────

/**
 * Get all granular VerificationEvidence records for a given verification.
 *
 * @param {Object} params
 * @param {string} params.verificationId
 * @param {Object} params.user - req.user
 * @returns {Promise<Array>} List of VerificationEvidence records
 */
const getVerificationEvidence = async ({ verificationId, user }) => {
  // Check permission via getVerification first
  await getVerification({ verificationId, user });

  const evidenceList = await VerificationEvidence.find({ verificationId })
    .sort({ retrievedAt: 1 })
    .lean();

  return evidenceList;
};

module.exports = {
  verifyDocument,
  listVerifications,
  getVerification,
  getVerificationEvidence,
};
