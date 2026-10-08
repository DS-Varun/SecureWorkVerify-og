/**
 * Credential Issuance, Scoping, Versioning, and Revocation tests.
 *
 * Tests cover:
 * - Credential issuance by an ACTIVE ISSUER with multipart document upload (PDF/PNG)
 * - Cryptographic SHA-256 document hashing and Ed25519 signature creation
 * - Creation of Document, Credential (ACTIVE), and CredentialVersion (v1)
 * - Role-scoped listing (ADMIN, ISSUER, HR with organizationId, USER recipient, AUDITOR denied)
 * - Role-scoped credential retrieval and version inspection
 * - Credential versioning (POST /:id/versions) with version superseding (v1 -> SUPERSEDED, v2 -> ACTIVE)
 * - Credential revocation (PATCH /:id/revoke) with permanent record retention (REVOKED is NOT FAKE)
 * - Prevention of issuing by non-active issuers or non-ISSUER roles
 * - File type validation (rejection of unsupported MIME types with 415)
 * - Audit log creation and hash chain integrity
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
const { AuditLog } = require('../src/models/AuditLog');
const { generateToken } = require('../src/services/auth.service');
const issuerService = require('../src/services/issuer.service');
const { assertTestDatabase } = require('./testHelper');

describe('Credential Lifecycle & RBAC', () => {
  let adminUser, hrUser1, hrUser2, activeIssuerUser, pendingIssuerUser, recipientUser1, recipientUser2, auditorUser;
  let adminToken, hrToken1, hrToken2, activeIssuerToken, pendingIssuerToken, recipientToken1, recipientToken2, auditorToken;
  let org1, org2;
  let activeIssuer, pendingIssuer;
  let issuedCredentialId;

  // Sample PDF dummy bytes for test uploads
  const samplePdfBuffer = Buffer.from('%PDF-1.4 sample content for credential testing');
  const samplePngBuffer = Buffer.from('\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRsample png');
  const sampleTxtBuffer = Buffer.from('Unsupported plain text file');

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
    await AuditLog.deleteMany({});

    // Create Organizations
    org1 = await Organization.create({
      name: 'Harvard University',
      organizationCode: 'ORG-HARV0001',
      type: 'UNIVERSITY',
      organizationVerificationStatus: 'VERIFIED',
      status: 'ACTIVE',
      createdBy: new mongoose.Types.ObjectId(),
    });

    org2 = await Organization.create({
      name: 'Tech Corp Inc',
      organizationCode: 'ORG-TECH0001',
      type: 'COMPANY',
      organizationVerificationStatus: 'VERIFIED',
      status: 'ACTIVE',
      createdBy: new mongoose.Types.ObjectId(),
    });

    // Create Users
    adminUser = await User.create({
      name: 'Admin User',
      email: 'admin_cred@example.com',
      passwordHash: 'Password123',
      role: 'ADMIN',
    });

    hrUser1 = await User.create({
      name: 'HR User Org 1',
      email: 'hr1@harvard.edu',
      passwordHash: 'Password123',
      role: 'HR',
      organizationId: org1._id,
    });

    hrUser2 = await User.create({
      name: 'HR User Org 2',
      email: 'hr2@techcorp.com',
      passwordHash: 'Password123',
      role: 'HR',
      organizationId: org2._id,
    });

    activeIssuerUser = await User.create({
      name: 'Active Issuer',
      email: 'active_issuer@harvard.edu',
      passwordHash: 'Password123',
      role: 'ISSUER',
      organizationId: org1._id,
    });

    pendingIssuerUser = await User.create({
      name: 'Pending Issuer',
      email: 'pending_issuer@harvard.edu',
      passwordHash: 'Password123',
      role: 'ISSUER',
      organizationId: org1._id,
    });

    recipientUser1 = await User.create({
      name: 'Recipient One',
      email: 'recipient1@example.com',
      passwordHash: 'Password123',
      role: 'USER',
    });

    recipientUser2 = await User.create({
      name: 'Recipient Two',
      email: 'recipient2@example.com',
      passwordHash: 'Password123',
      role: 'USER',
    });

    auditorUser = await User.create({
      name: 'Auditor User',
      email: 'auditor_cred@example.com',
      passwordHash: 'Password123',
      role: 'AUDITOR',
    });

    adminToken = generateToken(adminUser);
    hrToken1 = generateToken(hrUser1);
    hrToken2 = generateToken(hrUser2);
    activeIssuerToken = generateToken(activeIssuerUser);
    pendingIssuerToken = generateToken(pendingIssuerUser);
    recipientToken1 = generateToken(recipientUser1);
    recipientToken2 = generateToken(recipientUser2);
    auditorToken = generateToken(auditorUser);

    // Setup Active Issuer profile & approve with keypair
    activeIssuer = await issuerService.registerIssuer({
      userId: activeIssuerUser._id,
      organizationId: org1._id,
    });
    await issuerService.approveIssuer({
      issuerId: activeIssuer._id,
      adminUserId: adminUser._id,
    });

    // Setup Pending Issuer profile (unapproved)
    pendingIssuer = await issuerService.registerIssuer({
      userId: pendingIssuerUser._id,
      organizationId: org1._id,
    });
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

  // ─── 1. Credential Issuance ──────────────────────────────────────────────────

  describe('POST /api/credentials/issue (Issuance & Signing)', () => {
    it('allows an ACTIVE ISSUER to issue a signed credential with a PDF document', async () => {
      const res = await request(app)
        .post('/api/credentials/issue')
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .field('recipientId', recipientUser1._id.toString())
        .field('credentialType', 'DEGREE')
        .field('title', 'Bachelor of Science in Computer Science')
        .field('description', 'Graduated with Magna Cum Laude honors')
        .field('representationType', 'ORIGINAL_DIGITAL_FILE')
        .attach('document', samplePdfBuffer, 'diploma.pdf');

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.credential).toBeDefined();
      expect(res.body.data.credential.status).toBe('ACTIVE');
      expect(res.body.data.credential.documentHash).toBeDefined();
      expect(res.body.data.credential.signature).toBeDefined();
      expect(res.body.data.credentialVersion).toBeDefined();
      expect(res.body.data.credentialVersion.versionNumber).toBe(1);
      expect(res.body.data.document).toBeDefined();
      expect(res.body.data.document.mimeType).toBe('application/pdf');

      issuedCredentialId = res.body.data.credential._id;

      // Verify file exists on disk
      const docStorageDir = path.resolve(process.cwd(), 'uploads');
      const savedFiles = fs.readdirSync(docStorageDir);
      expect(savedFiles.some((f) => f.includes(res.body.data.document._id))).toBe(true);
    });

    it('rejects issuance when document file is missing with 400', async () => {
      const res = await request(app)
        .post('/api/credentials/issue')
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .field('recipientId', recipientUser1._id.toString())
        .field('credentialType', 'DEGREE')
        .field('title', 'Test Certificate');

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/document file is required/i);
    });

    it('rejects unsupported file type (e.g. text/plain) with 415', async () => {
      const res = await request(app)
        .post('/api/credentials/issue')
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .field('recipientId', recipientUser1._id.toString())
        .field('credentialType', 'DEGREE')
        .field('title', 'Test Diploma')
        .attach('document', sampleTxtBuffer, 'notes.txt');

      expect(res.status).toBe(415);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/unsupported file type/i);
    });

    it('rejects issuance by a PENDING issuer with 403', async () => {
      const res = await request(app)
        .post('/api/credentials/issue')
        .set('Authorization', `Bearer ${pendingIssuerToken}`)
        .field('recipientId', recipientUser1._id.toString())
        .field('credentialType', 'DEGREE')
        .field('title', 'Test Diploma')
        .attach('document', samplePdfBuffer, 'diploma.pdf');

      expect(res.status).toBe(403);
      expect(res.body.error.message).toMatch(/not authorized/i);
    });

    it('rejects issuance by non-ISSUER roles (USER, HR, ADMIN, AUDITOR) with 403', async () => {
      for (const token of [recipientToken1, hrToken1, adminToken, auditorToken]) {
        const res = await request(app)
          .post('/api/credentials/issue')
          .set('Authorization', `Bearer ${token}`)
          .field('recipientId', recipientUser1._id.toString())
          .field('credentialType', 'DEGREE')
          .field('title', 'Test')
          .attach('document', samplePdfBuffer, 'test.pdf');

        expect(res.status).toBe(403);
      }
    });
  });

  // ─── 2. Role-Scoped Listing ──────────────────────────────────────────────────

  describe('GET /api/credentials (Role-Scoped Listing)', () => {
    it('allows ADMIN to list all credentials across all organizations', async () => {
      const res = await request(app)
        .get('/api/credentials')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data.credentials)).toBe(true);
      expect(res.body.data.total).toBeGreaterThanOrEqual(1);
    });

    it('allows ISSUER to see credentials they issued', async () => {
      const res = await request(app)
        .get('/api/credentials')
        .set('Authorization', `Bearer ${activeIssuerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.credentials.length).toBeGreaterThanOrEqual(1);
    });

    it('allows HR to see credentials from their own organizationId', async () => {
      const res = await request(app)
        .get('/api/credentials')
        .set('Authorization', `Bearer ${hrToken1}`);

      expect(res.status).toBe(200);
      expect(res.body.data.credentials.length).toBeGreaterThanOrEqual(1);

      // HR from Org 2 should see 0 credentials
      const res2 = await request(app)
        .get('/api/credentials')
        .set('Authorization', `Bearer ${hrToken2}`);

      expect(res2.status).toBe(200);
      expect(res2.body.data.credentials.length).toBe(0);
    });

    it('allows recipient USER to see only their own credentials', async () => {
      const res = await request(app)
        .get('/api/credentials')
        .set('Authorization', `Bearer ${recipientToken1}`);

      expect(res.status).toBe(200);
      expect(res.body.data.credentials.length).toBeGreaterThanOrEqual(1);

      // Other user should see 0
      const res2 = await request(app)
        .get('/api/credentials')
        .set('Authorization', `Bearer ${recipientToken2}`);

      expect(res2.status).toBe(200);
      expect(res2.body.data.credentials.length).toBe(0);
    });

    it('rejects AUDITOR role from credential listing with 403', async () => {
      const res = await request(app)
        .get('/api/credentials')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(403);
    });
  });

  // ─── 3. Credential Retrieval & Versions ──────────────────────────────────────

  describe('GET /api/credentials/:id & /versions (Detail & Version History)', () => {
    it('allows recipient to retrieve credential details', async () => {
      const res = await request(app)
        .get(`/api/credentials/${issuedCredentialId}`)
        .set('Authorization', `Bearer ${recipientToken1}`);

      expect(res.status).toBe(200);
      expect(res.body.data.credential._id.toString()).toBe(issuedCredentialId.toString());
      expect(res.body.data.credential.title).toBe('Bachelor of Science in Computer Science');
    });

    it('rejects another unrelated USER from viewing with 403', async () => {
      const res = await request(app)
        .get(`/api/credentials/${issuedCredentialId}`)
        .set('Authorization', `Bearer ${recipientToken2}`);

      expect(res.status).toBe(403);
    });

    it('allows inspecting credential version history', async () => {
      const res = await request(app)
        .get(`/api/credentials/${issuedCredentialId}/versions`)
        .set('Authorization', `Bearer ${recipientToken1}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.data.versions)).toBe(true);
      expect(res.body.data.versions.length).toBe(1);
      expect(res.body.data.versions[0].versionNumber).toBe(1);
      expect(res.body.data.versions[0].status).toBe('ACTIVE');
    });
  });

  // ─── 4. Credential Versioning ────────────────────────────────────────────────

  describe('POST /api/credentials/:id/versions (Superseding Version)', () => {
    it('allows ISSUER to add a new version with an updated document', async () => {
      const res = await request(app)
        .post(`/api/credentials/${issuedCredentialId}/versions`)
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .field('changeReason', 'Corrected spelling of recipient middle name on official certificate')
        .attach('document', samplePngBuffer, 'diploma_v2.png');

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.credentialVersion.versionNumber).toBe(2);
      expect(res.body.data.credentialVersion.status).toBe('ACTIVE');
      expect(res.body.data.credentialVersion.changeReason).toBe(
        'Corrected spelling of recipient middle name on official certificate'
      );

      // Verify v1 is now SUPERSEDED
      const versionsRes = await request(app)
        .get(`/api/credentials/${issuedCredentialId}/versions`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(versionsRes.body.data.versions.length).toBe(2);
      const v1 = versionsRes.body.data.versions.find((v) => v.versionNumber === 1);
      const v2 = versionsRes.body.data.versions.find((v) => v.versionNumber === 2);

      expect(v1.status).toBe('SUPERSEDED');
      expect(v2.status).toBe('ACTIVE');
      expect(v2.supersedesVersionId.toString()).toBe(v1._id.toString());
    });

    it('rejects adding a version without a changeReason with 400', async () => {
      const res = await request(app)
        .post(`/api/credentials/${issuedCredentialId}/versions`)
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .attach('document', samplePngBuffer, 'diploma_v3.png');

      expect(res.status).toBe(400);
    });

    it('rejects non-issuing user from adding versions with 403', async () => {
      const res = await request(app)
        .post(`/api/credentials/${issuedCredentialId}/versions`)
        .set('Authorization', `Bearer ${recipientToken1}`)
        .field('changeReason', 'Unauthorized attempt')
        .attach('document', samplePngBuffer, 'fake.png');

      expect(res.status).toBe(403);
    });
  });

  // ─── 5. Credential Revocation ────────────────────────────────────────────────

  describe('PATCH /api/credentials/:id/revoke (Revocation)', () => {
    it('allows ISSUER to revoke their credential with mandatory reason', async () => {
      const res = await request(app)
        .patch(`/api/credentials/${issuedCredentialId}/revoke`)
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .send({ reason: 'Degree revoked due to academic integrity violation' });

      expect(res.status).toBe(200);
      expect(res.body.data.credential.status).toBe('REVOKED');
      expect(res.body.data.credential.revokedReason).toBe(
        'Degree revoked due to academic integrity violation'
      );
      expect(res.body.data.credential.revokedAt).toBeDefined();

      // SECURITY CRITICAL: The credential record MUST NOT be deleted (REVOKED is NOT FAKE)
      const credInDb = await Credential.findById(issuedCredentialId);
      expect(credInDb).not.toBeNull();
      expect(credInDb.status).toBe('REVOKED');
    });

    it('rejects revoking an already REVOKED credential with 409', async () => {
      const res = await request(app)
        .patch(`/api/credentials/${issuedCredentialId}/revoke`)
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .send({ reason: 'Duplicate revocation attempt' });

      expect(res.status).toBe(409);
    });

    it('rejects adding new versions to a REVOKED credential with 409', async () => {
      const res = await request(app)
        .post(`/api/credentials/${issuedCredentialId}/versions`)
        .set('Authorization', `Bearer ${activeIssuerToken}`)
        .field('changeReason', 'Attempting version on revoked credential')
        .attach('document', samplePdfBuffer, 'test.pdf');

      expect(res.status).toBe(409);
    });
  });

  // ─── 6. Audit Logging Verification ───────────────────────────────────────────

  describe('Audit Logging for Credential Lifecycle', () => {
    it('logs hash-chained audit events for document upload, issuance, versioning, and revocation', async () => {
      const logs = await AuditLog.find({
        action: {
          $in: [
            'DOCUMENT_UPLOADED',
            'CREDENTIAL_ISSUED',
            'CREDENTIAL_VERSION_CREATED',
            'CREDENTIAL_SUPERSEDED',
            'CREDENTIAL_REVOKED',
          ],
        },
      });

      expect(logs.length).toBeGreaterThanOrEqual(5);
      for (const log of logs) {
        expect(log.currentHash).toBeDefined();
        expect(log.previousHash).toBeDefined();
        expect(log.sequenceNumber).toBeGreaterThanOrEqual(1);
      }
    });
  });
});
