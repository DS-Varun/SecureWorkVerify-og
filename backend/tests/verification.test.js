/**
 * Document Verification Engine & Evidence Trail tests.
 *
 * Tests cover:
 * - Deterministic 4-part independent verification engine
 * - Exact 13 categorical states and 6 trust levels
 * - Exact original document verification -> VERIFIED (LEVEL_5_CURRENTLY_VALID)
 * - Altered document / unknown hash -> NOT_FOUND (LEVEL_0_UNKNOWN)
 * - Revoked credential -> CREDENTIAL_REVOKED (authentic but revoked, NOT fake)
 * - Expired credential -> CREDENTIAL_EXPIRED (authentic but expired, NOT fake)
 * - Suspended issuer -> ISSUER_SUSPENDED
 * - Revoked issuer -> ISSUER_REVOKED
 * - Compromised signing key -> KEY_COMPROMISED
 * - Manipulated signature -> SIGNATURE_INVALID
 * - Verification details and granular evidence trail inspection
 * - Role-based scoping (USER, HR, ADMIN, AUDITOR)
 * - Audit logging (VERIFICATION_PERFORMED, VERIFICATION_EVIDENCE_CREATED)
 * - Audit hash-chain verification
 */

'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const app = require('../src/app');
const { User } = require('../src/models/User');
const { Organization } = require('../src/models/Organization');
const { Issuer } = require('../src/models/Issuer');
const { IssuerKey } = require('../src/models/IssuerKey');
const { Document } = require('../src/models/Document');
const { Credential } = require('../src/models/Credential');
const { CredentialVersion } = require('../src/models/CredentialVersion');
const { Verification } = require('../src/models/Verification');
const { VerificationEvidence } = require('../src/models/VerificationEvidence');
const { AuditLog } = require('../src/models/AuditLog');
const { generateToken } = require('../src/services/auth.service');
const issuerService = require('../src/services/issuer.service');
const credentialService = require('../src/services/credential.service');
const auditService = require('../src/services/audit.service');
const { assertTestDatabase } = require('./testHelper');

describe('Document Verification Engine & Evidence Trail', () => {
  let adminUser, hrUser, normalUser, otherUser, issuerUser, auditorUser;
  let adminToken, hrToken, userToken, otherUserToken, issuerToken, auditorToken;
  let verifiedOrg;
  let issuerProfile, issuerKeyDoc;
  let validCredential, validCredentialDoc;
  let verificationIdForDetail;

  const validPdfBytes = Buffer.from('%PDF-1.4 official genuine diploma document for verification');
  const alteredPdfBytes = Buffer.from('%PDF-1.4 forged altered tampered document bytes');

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    assertTestDatabase();

    // Clean up collections
    await User.deleteMany({});
    await Organization.deleteMany({});
    await Issuer.deleteMany({});
    await IssuerKey.deleteMany({});
    await Document.deleteMany({});
    await Credential.deleteMany({});
    await CredentialVersion.deleteMany({});
    await Verification.deleteMany({});
    await VerificationEvidence.deleteMany({});
    await AuditLog.deleteMany({});

    // Create Organization
    verifiedOrg = await Organization.create({
      name: 'Oxford University',
      organizationCode: 'ORG-OXFD0001',
      type: 'UNIVERSITY',
      organizationVerificationStatus: 'VERIFIED',
      status: 'ACTIVE',
      createdBy: new mongoose.Types.ObjectId(),
    });

    // Create Users
    adminUser = await User.create({
      name: 'Admin Verifier',
      email: 'admin_v@oxford.edu',
      passwordHash: 'Password123',
      role: 'ADMIN',
    });

    hrUser = await User.create({
      name: 'HR Verifier',
      email: 'hr_v@company.com',
      passwordHash: 'Password123',
      role: 'HR',
      organizationId: verifiedOrg._id,
    });

    normalUser = await User.create({
      name: 'Student Verifier',
      email: 'student_v@example.com',
      passwordHash: 'Password123',
      role: 'USER',
    });

    otherUser = await User.create({
      name: 'Other Student',
      email: 'other_v@example.com',
      passwordHash: 'Password123',
      role: 'USER',
    });

    issuerUser = await User.create({
      name: 'Dean Issuer',
      email: 'dean_v@oxford.edu',
      passwordHash: 'Password123',
      role: 'ISSUER',
      organizationId: verifiedOrg._id,
    });

    auditorUser = await User.create({
      name: 'Auditor Verifier',
      email: 'auditor_v@audit.org',
      passwordHash: 'Password123',
      role: 'AUDITOR',
    });

    adminToken = generateToken(adminUser);
    hrToken = generateToken(hrUser);
    userToken = generateToken(normalUser);
    otherUserToken = generateToken(otherUser);
    issuerToken = generateToken(issuerUser);
    auditorToken = generateToken(auditorUser);

    // Register and approve issuer
    issuerProfile = await issuerService.registerIssuer({
      userId: issuerUser._id,
      organizationId: verifiedOrg._id,
    });
    const approved = await issuerService.approveIssuer({
      issuerId: issuerProfile._id,
      adminUserId: adminUser._id,
    });
    issuerKeyDoc = approved.issuerKey;

    // Issue a genuine test credential
    const issued = await credentialService.issueCredential({
      issuingUserId: issuerUser._id,
      recipientId: normalUser._id,
      credentialType: 'DEGREE',
      title: 'Master of Science in Cryptography',
      description: 'First Class Honours with Distinction',
      fileBuffer: validPdfBytes,
      originalFilename: 'oxford_diploma.pdf',
      mimeType: 'application/pdf',
      fileSize: validPdfBytes.length,
    });

    validCredential = issued.credential;
    validCredentialDoc = issued.document;
  });

  afterAll(async () => {
    assertTestDatabase();
    await User.deleteMany({});
    await Organization.deleteMany({});
    await Issuer.deleteMany({});
    await IssuerKey.deleteMany({});
    await Document.deleteMany({});
    await Credential.deleteMany({});
    await CredentialVersion.deleteMany({});
    await Verification.deleteMany({});
    await VerificationEvidence.deleteMany({});
    await AuditLog.deleteMany({});

    // Clean up created files in keys and uploads
    const keysDir = path.resolve(process.cwd(), 'keys');
    if (fs.existsSync(keysDir)) {
      const files = fs.readdirSync(keysDir);
      for (const file of files) {
        if (file.endsWith('.key')) {
          fs.unlinkSync(path.join(keysDir, file));
        }
      }
      const retiredDir = path.join(keysDir, 'retired');
      if (fs.existsSync(retiredDir)) {
        const retiredFiles = fs.readdirSync(retiredDir);
        for (const file of retiredFiles) {
          if (file.endsWith('.key')) {
            fs.unlinkSync(path.join(retiredDir, file));
          }
        }
      }
    }

    const uploadsDir = path.resolve(process.cwd(), 'uploads');
    if (fs.existsSync(uploadsDir)) {
      const uploadFiles = fs.readdirSync(uploadsDir);
      for (const file of uploadFiles) {
        if (file.startsWith('doc_')) {
          fs.unlinkSync(path.join(uploadsDir, file));
        }
      }
    }

    await mongoose.disconnect();
  });

  // ─── 1. Valid Document Verification ──────────────────────────────────────────

  describe('1. Valid Document Verification (VERIFIED, Level 5)', () => {
    it('verifies exact genuine document -> VERIFIED, LEVEL_5_CURRENTLY_VALID', async () => {
      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', validPdfBytes, 'submitted_diploma.pdf');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const v = res.body.data.verification;
      expect(v).toBeDefined();
      expect(v.result).toBe('VERIFIED');
      expect(v.trustLevel).toBe('LEVEL_5_CURRENTLY_VALID');
      expect(v.integrityCheck.passed).toBe(true);
      expect(v.signatureCheck.passed).toBe(true);
      expect(v.issuerTrustCheck.passed).toBe(true);
      expect(v.organizationTrustCheck.passed).toBe(true);
      expect(v.credentialStatusCheck.passed).toBe(true);
      expect(v.evidenceIds.length).toBeGreaterThanOrEqual(4);

      verificationIdForDetail = v._id;
    });

    it('allows a regular USER to verify an authentic document', async () => {
      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${userToken}`)
        .attach('document', validPdfBytes, 'my_diploma.pdf');

      expect(res.status).toBe(200);
      expect(res.body.data.verification.result).toBe('VERIFIED');
      expect(res.body.data.verification.trustLevel).toBe('LEVEL_5_CURRENTLY_VALID');
    });
  });

  // ─── 2. Altered Document Verification ────────────────────────────────────────

  describe('2. Altered Document Verification (NOT_FOUND, Level 0)', () => {
    it('returns NOT_FOUND when uploaded document bytes do not match any credential', async () => {
      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', alteredPdfBytes, 'fake_diploma.pdf');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const v = res.body.data.verification;
      expect(v.result).toBe('NOT_FOUND');
      expect(v.trustLevel).toBe('LEVEL_0_UNKNOWN');
      expect(v.integrityCheck.passed).toBe(false);
      expect(v.credentialId).toBeNull();
    });
  });

  // ─── 3. Revoked Credential Verification ──────────────────────────────────────

  describe('3. Revoked Credential (CREDENTIAL_REVOKED, Level 4)', () => {
    it('returns CREDENTIAL_REVOKED for a revoked credential (distinguished from fake)', async () => {
      // Issue a separate credential and revoke it
      const tempPdfBytes = Buffer.from('%PDF-1.4 degree to be revoked for academic misconduct');
      const issued = await credentialService.issueCredential({
        issuingUserId: issuerUser._id,
        recipientId: normalUser._id,
        credentialType: 'DEGREE',
        title: 'BSc in Chemistry',
        fileBuffer: tempPdfBytes,
        originalFilename: 'chem_degree.pdf',
        mimeType: 'application/pdf',
        fileSize: tempPdfBytes.length,
      });

      await credentialService.revokeCredential({
        credentialId: issued.credential._id,
        issuingUserId: issuerUser._id,
        reason: 'Plagiarism proven in final dissertation',
      });

      // Verify the revoked document
      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', tempPdfBytes, 'chem_degree.pdf');

      expect(res.status).toBe(200);
      const v = res.body.data.verification;
      expect(v.result).toBe('CREDENTIAL_REVOKED');
      expect(v.trustLevel).toBe('LEVEL_4_SIGNATURE_VERIFIED');
      expect(v.integrityCheck.passed).toBe(true);
      expect(v.signatureCheck.passed).toBe(true);
      expect(v.credentialStatusCheck.passed).toBe(false);
      expect(v.explanation).toMatch(/REVOKED/i);
    });
  });

  // ─── 4. Expired Credential Verification ──────────────────────────────────────

  describe('4. Expired Credential (CREDENTIAL_EXPIRED, Level 4)', () => {
    it('returns CREDENTIAL_EXPIRED for an expired credential (distinguished from fake)', async () => {
      const expPdfBytes = Buffer.from('%PDF-1.4 temporary driving license valid for 30 days');
      const issued = await credentialService.issueCredential({
        issuingUserId: issuerUser._id,
        recipientId: normalUser._id,
        credentialType: 'LICENSE',
        title: 'Temporary Research Permit',
        fileBuffer: expPdfBytes,
        originalFilename: 'permit.pdf',
        mimeType: 'application/pdf',
        fileSize: expPdfBytes.length,
      });

      // Set expiresAt to the past
      await Credential.findByIdAndUpdate(issued.credential._id, {
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000), // yesterday
      });

      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', expPdfBytes, 'permit.pdf');

      expect(res.status).toBe(200);
      const v = res.body.data.verification;
      expect(v.result).toBe('CREDENTIAL_EXPIRED');
      expect(v.trustLevel).toBe('LEVEL_4_SIGNATURE_VERIFIED');
      expect(v.integrityCheck.passed).toBe(true);
      expect(v.signatureCheck.passed).toBe(true);
      expect(v.credentialStatusCheck.passed).toBe(false);
      expect(v.credentialStatusCheck.isExpired).toBe(true);
    });
  });

  // ─── 5. Suspended Issuer Verification ────────────────────────────────────────

  describe('5. Suspended Issuer (ISSUER_SUSPENDED)', () => {
    it('returns ISSUER_SUSPENDED when signing issuer is in SUSPENDED status', async () => {
      const suspPdfBytes = Buffer.from('%PDF-1.4 issued by issuer about to be suspended');
      const issued = await credentialService.issueCredential({
        issuingUserId: issuerUser._id,
        recipientId: normalUser._id,
        credentialType: 'CERTIFICATE',
        title: 'Course Certificate',
        fileBuffer: suspPdfBytes,
        originalFilename: 'cert.pdf',
        mimeType: 'application/pdf',
        fileSize: suspPdfBytes.length,
      });

      // Suspend issuer
      await Issuer.findByIdAndUpdate(issuerProfile._id, {
        status: 'SUSPENDED',
      });

      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', suspPdfBytes, 'cert.pdf');

      expect(res.status).toBe(200);
      const v = res.body.data.verification;
      expect(v.result).toBe('ISSUER_SUSPENDED');
      expect(v.trustLevel).toBe('LEVEL_4_SIGNATURE_VERIFIED');
      expect(v.issuerTrustCheck.passed).toBe(false);

      // Restore issuer to ACTIVE for subsequent tests
      await Issuer.findByIdAndUpdate(issuerProfile._id, { status: 'ACTIVE' });
    });
  });

  // ─── 6. Revoked Issuer Verification ──────────────────────────────────────────

  describe('6. Revoked Issuer (ISSUER_REVOKED)', () => {
    it('returns ISSUER_REVOKED when signing issuer is permanently REVOKED', async () => {
      // Create a second issuer, issue a credential, then revoke that issuer
      const tempIssuerUser = await User.create({
        name: 'Departed Professor',
        email: 'prof_v@oxford.edu',
        passwordHash: 'Password123',
        role: 'ISSUER',
        organizationId: verifiedOrg._id,
      });

      const tempIssuerProfile = await issuerService.registerIssuer({
        userId: tempIssuerUser._id,
        organizationId: verifiedOrg._id,
      });
      await issuerService.approveIssuer({
        issuerId: tempIssuerProfile._id,
        adminUserId: adminUser._id,
      });

      const revIssuerPdfBytes = Buffer.from('%PDF-1.4 issued by professor who is revoked later');
      await credentialService.issueCredential({
        issuingUserId: tempIssuerUser._id,
        recipientId: normalUser._id,
        credentialType: 'CERTIFICATE',
        title: 'Lab Training Certificate',
        fileBuffer: revIssuerPdfBytes,
        originalFilename: 'lab_cert.pdf',
        mimeType: 'application/pdf',
        fileSize: revIssuerPdfBytes.length,
      });

      // Revoke the issuer
      await issuerService.revokeIssuer({
        issuerId: tempIssuerProfile._id,
        adminUserId: adminUser._id,
        reason: 'Professor left university',
      });

      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', revIssuerPdfBytes, 'lab_cert.pdf');

      expect(res.status).toBe(200);
      const v = res.body.data.verification;
      expect(v.result).toBe('ISSUER_REVOKED');
      expect(v.trustLevel).toBe('LEVEL_4_SIGNATURE_VERIFIED');
    });
  });

  // ─── 7. Compromised Key Verification ─────────────────────────────────────────

  describe('7. Compromised Key (KEY_COMPROMISED)', () => {
    it('returns KEY_COMPROMISED when signing key is marked COMPROMISED', async () => {
      const compKeyPdfBytes = Buffer.from('%PDF-1.4 signed with key that gets compromised');
      const issued = await credentialService.issueCredential({
        issuingUserId: issuerUser._id,
        recipientId: normalUser._id,
        credentialType: 'DEGREE',
        title: 'Degree with Compromised Key',
        fileBuffer: compKeyPdfBytes,
        originalFilename: 'comp_key.pdf',
        mimeType: 'application/pdf',
        fileSize: compKeyPdfBytes.length,
      });

      // Mark the key as COMPROMISED
      await IssuerKey.findByIdAndUpdate(issued.credential.issuerKeyId, {
        status: 'COMPROMISED',
      });

      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', compKeyPdfBytes, 'comp_key.pdf');

      expect(res.status).toBe(200);
      const v = res.body.data.verification;
      expect(v.result).toBe('KEY_COMPROMISED');
      expect(v.trustLevel).toBe('LEVEL_3_INTEGRITY_VERIFIED');
      expect(v.issuerTrustCheck.keyStatus).toBe('COMPROMISED');

      // Restore key to ACTIVE for other tests
      await IssuerKey.findByIdAndUpdate(issued.credential.issuerKeyId, {
        status: 'ACTIVE',
      });
    });
  });

  // ─── 8. Invalid Signature Verification ───────────────────────────────────────

  describe('8. Invalid Signature (SIGNATURE_INVALID)', () => {
    it('returns SIGNATURE_INVALID when digital signature has been manipulated', async () => {
      const corruptSigPdfBytes = Buffer.from('%PDF-1.4 document with forged signature in DB');
      const issued = await credentialService.issueCredential({
        issuingUserId: issuerUser._id,
        recipientId: normalUser._id,
        credentialType: 'DEGREE',
        title: 'Degree with Corrupt Signature',
        fileBuffer: corruptSigPdfBytes,
        originalFilename: 'corrupt_sig.pdf',
        mimeType: 'application/pdf',
        fileSize: corruptSigPdfBytes.length,
      });

      // Corrupt the signature in MongoDB (simulate forgery bypassing schema immutability)
      const fakeSig = Buffer.alloc(64, 0xaa).toString('base64');
      await Credential.collection.updateOne(
        { _id: issued.credential._id },
        { $set: { signature: fakeSig } }
      );
      await CredentialVersion.collection.updateOne(
        { _id: issued.credentialVersion._id },
        { $set: { signature: fakeSig } }
      );

      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${hrToken}`)
        .attach('document', corruptSigPdfBytes, 'corrupt_sig.pdf');

      expect(res.status).toBe(200);
      const v = res.body.data.verification;
      expect(v.result).toBe('SIGNATURE_INVALID');
      expect(v.trustLevel).toBe('LEVEL_3_INTEGRITY_VERIFIED');
      expect(v.signatureCheck.passed).toBe(false);
    });
  });

  // ─── 9 & 10. Detail & Evidence Trail Retrieval ───────────────────────────────

  describe('9 & 10. Verification Detail and Evidence Trail Retrieval', () => {
    it('GET /api/verifications/:id returns full verification record details', async () => {
      const res = await request(app)
        .get(`/api/verifications/${verificationIdForDetail}`)
        .set('Authorization', `Bearer ${hrToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.verification).toBeDefined();
      expect(res.body.data.verification._id.toString()).toBe(verificationIdForDetail.toString());
      expect(res.body.data.verification.result).toBe('VERIFIED');
    });

    it('GET /api/verifications/:id/evidence returns complete evidence trail items', async () => {
      const res = await request(app)
        .get(`/api/verifications/${verificationIdForDetail}/evidence`)
        .set('Authorization', `Bearer ${hrToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data.evidence)).toBe(true);
      expect(res.body.data.evidence.length).toBeGreaterThanOrEqual(4);

      const types = res.body.data.evidence.map((e) => e.evidenceType);
      expect(types).toContain('HASH_MATCH');
      expect(types).toContain('DIGITAL_SIGNATURE');
      expect(types).toContain('DOMAIN_VERIFICATION');
      expect(types).toContain('ISSUER_STATUS');
    });
  });

  // ─── 11, 12, 13, 14, 15. Role Scoping & RBAC ────────────────────────────────

  describe('11–15. Role Scoping & RBAC Enforcement', () => {
    it('USER can see only their own verifications', async () => {
      const res = await request(app)
        .get('/api/verifications')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.data.verifications)).toBe(true);
      for (const item of res.body.data.verifications) {
        const verifierId = item.verifiedBy?._id || item.verifiedBy;
        expect(verifierId.toString()).toBe(normalUser._id.toString());
      }
    });

    it('USER cannot view another user verification detail with 403', async () => {
      // verificationIdForDetail was executed by hrUser, so otherUser should receive 403
      const res = await request(app)
        .get(`/api/verifications/${verificationIdForDetail}`)
        .set('Authorization', `Bearer ${otherUserToken}`);

      expect(res.status).toBe(403);
    });

    it('ADMIN can view all verifications across all users', async () => {
      const res = await request(app)
        .get('/api/verifications')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.total).toBeGreaterThanOrEqual(3);
    });

    it('AUDITOR can view all verifications across all users', async () => {
      const res = await request(app)
        .get('/api/verifications')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.total).toBeGreaterThanOrEqual(3);
    });

    it('rejects ISSUER role from submitting verifications with 403', async () => {
      const res = await request(app)
        .post('/api/verifications/verify')
        .set('Authorization', `Bearer ${issuerToken}`)
        .attach('document', validPdfBytes, 'diploma.pdf');

      expect(res.status).toBe(403);
    });

    it('rejects unauthenticated verification requests with 401', async () => {
      const res = await request(app)
        .post('/api/verifications/verify')
        .attach('document', validPdfBytes, 'diploma.pdf');

      expect(res.status).toBe(401);
    });
  });

  // ─── 16 & 17. Audit Events & Hash Chain ──────────────────────────────────────

  describe('16 & 17. Audit Events & Hash-Chain Verification', () => {
    it('creates VERIFICATION_PERFORMED and VERIFICATION_EVIDENCE_CREATED audit logs', async () => {
      const logs = await AuditLog.find({
        action: { $in: ['VERIFICATION_PERFORMED', 'VERIFICATION_EVIDENCE_CREATED'] },
      });

      expect(logs.length).toBeGreaterThanOrEqual(5);
      for (const log of logs) {
        expect(log.currentHash).toBeDefined();
        expect(log.previousHash).toBeDefined();
        expect(log.sequenceNumber).toBeGreaterThanOrEqual(1);
      }
    });

    it('preserves a completely valid cryptographic hash chain across the entire audit log', async () => {
      const chainValidation = await auditService.verifyChain();
      expect(chainValidation.valid).toBe(true);
      expect(chainValidation.count).toBeGreaterThanOrEqual(10);
    });
  });
});
