/**
 * Issuer & IssuerKey Lifecycle and RBAC tests.
 *
 * Tests cover:
 * - ISSUER role self-registration of issuer profile for a VERIFIED organization
 * - Rejection of registration for non-existent or unverified organizations
 * - Duplicate registration prevention
 * - RBAC enforcement (ADMIN, ISSUER, HR, USER, AUDITOR)
 * - Issuer profile retrieval (/api/issuers/me)
 * - ADMIN listing and detail endpoints (/api/issuers, /api/issuers/:id)
 * - ADMIN approval, Ed25519 keypair generation, and filesystem keystore isolation
 * - Private key exclusion from API responses (security rule)
 * - Issuer suspension and revocation with mandatory reasons
 * - Key compromise endpoint (/api/issuer-keys/:id/compromise)
 * - Historical public key preservation on revocation and compromise
 * - Audit logging for all lifecycle transitions
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
const { AuditLog } = require('../src/models/AuditLog');
const { generateToken } = require('../src/services/auth.service');
const keystoreService = require('../src/services/keystore.service');
const { assertTestDatabase } = require('./testHelper');

describe('Issuer & IssuerKey Lifecycle and RBAC', () => {
  let adminUser, hrUser, issuerUser, issuerUser2, normalUser, auditorUser;
  let adminToken, hrToken, issuerToken, issuerToken2, userToken, auditorToken;
  let verifiedOrg, pendingOrg;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    assertTestDatabase();

    // Clean up test data
    await User.deleteMany({});
    await Organization.deleteMany({});
    await Issuer.deleteMany({});
    await IssuerKey.deleteMany({});
    await AuditLog.deleteMany({});

    // Create test users
    adminUser = await User.create({
      name: 'Admin User',
      email: 'admin@example.com',
      passwordHash: 'Password123',
      role: 'ADMIN',
    });

    hrUser = await User.create({
      name: 'HR User',
      email: 'hr@example.com',
      passwordHash: 'Password123',
      role: 'HR',
    });

    issuerUser = await User.create({
      name: 'Issuer User 1',
      email: 'issuer1@example.com',
      passwordHash: 'Password123',
      role: 'ISSUER',
    });

    issuerUser2 = await User.create({
      name: 'Issuer User 2',
      email: 'issuer2@example.com',
      passwordHash: 'Password123',
      role: 'ISSUER',
    });

    normalUser = await User.create({
      name: 'Regular User',
      email: 'user@example.com',
      passwordHash: 'Password123',
      role: 'USER',
    });

    auditorUser = await User.create({
      name: 'Auditor User',
      email: 'auditor@example.com',
      passwordHash: 'Password123',
      role: 'AUDITOR',
    });

    adminToken = generateToken(adminUser);
    hrToken = generateToken(hrUser);
    issuerToken = generateToken(issuerUser);
    issuerToken2 = generateToken(issuerUser2);
    userToken = generateToken(normalUser);
    auditorToken = generateToken(auditorUser);

    // Create organizations: one VERIFIED, one PENDING
    verifiedOrg = await Organization.create({
      name: 'MIT University',
      organizationCode: 'ORG-MIT00001',
      type: 'UNIVERSITY',
      organizationVerificationStatus: 'VERIFIED',
      status: 'ACTIVE',
      createdBy: adminUser._id,
      verifiedBy: adminUser._id,
      verifiedAt: new Date(),
    });

    pendingOrg = await Organization.create({
      name: 'Pending Org',
      organizationCode: 'ORG-PEN00001',
      type: 'COMPANY',
      organizationVerificationStatus: 'PENDING',
      status: 'ACTIVE',
      createdBy: adminUser._id,
    });
  });

  afterAll(async () => {
    assertTestDatabase();
    await User.deleteMany({});
    await Organization.deleteMany({});
    await Issuer.deleteMany({});
    await IssuerKey.deleteMany({});
    await AuditLog.deleteMany({});

    // Clean up created key files
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

    await mongoose.disconnect();
  });

  // ─── 1. Registration ─────────────────────────────────────────────────────────

  describe('POST /api/issuers/register (Registration & RBAC)', () => {
    it('allows an ISSUER user to register a profile under a VERIFIED organization', async () => {
      const res = await request(app)
        .post('/api/issuers/register')
        .set('Authorization', `Bearer ${issuerToken}`)
        .send({
          organizationId: verifiedOrg._id,
          authorizationEvidence: {
            institutionalEmail: 'issuer@mit.edu',
            invitationLetter: 'Official appointment letter ref #1234',
          },
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.issuer).toBeDefined();
      expect(res.body.data.issuer.status).toBe('PENDING');
      expect(res.body.data.issuer.userId.toString()).toBe(issuerUser._id.toString());
      expect(res.body.data.issuer.organizationId.toString()).toBe(verifiedOrg._id.toString());
    });

    it('rejects registration under a non-verified (PENDING) organization with 409', async () => {
      const res = await request(app)
        .post('/api/issuers/register')
        .set('Authorization', `Bearer ${issuerToken2}`)
        .send({
          organizationId: pendingOrg._id,
        });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/VERIFIED organizations/i);
    });

    it('rejects duplicate registration for the same user with 409', async () => {
      const res = await request(app)
        .post('/api/issuers/register')
        .set('Authorization', `Bearer ${issuerToken}`)
        .send({
          organizationId: verifiedOrg._id,
        });

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/already exists/i);
    });

    it('rejects registration by non-ISSUER roles (USER, HR, ADMIN, AUDITOR) with 403', async () => {
      for (const token of [userToken, hrToken, adminToken, auditorToken]) {
        const res = await request(app)
          .post('/api/issuers/register')
          .set('Authorization', `Bearer ${token}`)
          .send({
            organizationId: verifiedOrg._id,
          });

        expect(res.status).toBe(403);
      }
    });

    it('rejects unauthenticated registration with 401', async () => {
      const res = await request(app)
        .post('/api/issuers/register')
        .send({
          organizationId: verifiedOrg._id,
        });

      expect(res.status).toBe(401);
    });
  });

  // ─── 2. Profile Retrieval (/me) ──────────────────────────────────────────────

  describe('GET /api/issuers/me (Own Profile)', () => {
    it('allows an ISSUER to view their own profile', async () => {
      const res = await request(app)
        .get('/api/issuers/me')
        .set('Authorization', `Bearer ${issuerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.issuer).toBeDefined();
      const profileUserId = res.body.data.issuer.userId._id
        ? res.body.data.issuer.userId._id.toString()
        : res.body.data.issuer.userId.toString();
      expect(profileUserId).toBe(issuerUser._id.toString());
    });

    it('returns 404 if the ISSUER user has not registered an issuer profile yet', async () => {
      const res = await request(app)
        .get('/api/issuers/me')
        .set('Authorization', `Bearer ${issuerToken2}`);

      expect(res.status).toBe(404);
      expect(res.body.error.message).toMatch(/no issuer profile/i);
    });

    it('rejects non-ISSUER roles with 403', async () => {
      const res = await request(app)
        .get('/api/issuers/me')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(403);
    });
  });

  // ─── 3. Listing & Detail (ADMIN only) ────────────────────────────────────────

  describe('GET /api/issuers & GET /api/issuers/:id (ADMIN Access)', () => {
    it('allows ADMIN to list all issuers', async () => {
      const res = await request(app)
        .get('/api/issuers')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(Array.isArray(res.body.data.issuers)).toBe(true);
      expect(res.body.data.total).toBeGreaterThanOrEqual(1);
    });

    it('allows ADMIN to get a single issuer by ID', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });
      const res = await request(app)
        .get(`/api/issuers/${issuer._id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.issuer._id.toString()).toBe(issuer._id.toString());
    });

    it('rejects non-ADMIN users from listing issuers with 403', async () => {
      for (const token of [issuerToken, hrToken, userToken, auditorToken]) {
        const res = await request(app)
          .get('/api/issuers')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(403);
      }
    });
  });

  // ─── 4. Approval & Key Generation ────────────────────────────────────────────

  describe('PATCH /api/issuers/:id/approve (Approval & Keystore)', () => {
    it('allows ADMIN to approve a PENDING issuer, creating an ACTIVE Ed25519 key', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });

      const res = await request(app)
        .patch(`/api/issuers/${issuer._id}/approve`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.issuer.status).toBe('ACTIVE');
      expect(res.body.data.issuerKey).toBeDefined();
      expect(res.body.data.issuerKey.algorithm).toBe('Ed25519');
      expect(res.body.data.issuerKey.publicKey).toBeDefined();
      expect(res.body.data.issuerKey.status).toBe('ACTIVE');

      // SECURITY CRITICAL: privateKeyReference must NOT be returned in API response
      expect(res.body.data.issuerKey.privateKeyReference).toBeUndefined();

      // Verify key file exists on filesystem
      const keyFile = path.resolve(process.cwd(), 'keys', `issuer_${issuer._id}.key`);
      expect(fs.existsSync(keyFile)).toBe(true);

      // Verify key loads successfully via keystore service
      const privateKey = keystoreService.loadPrivateKey(String(issuer._id));
      expect(typeof privateKey).toBe('string');
      expect(privateKey.length).toBeGreaterThan(0);
    });

    it('rejects approving an already ACTIVE issuer with 409', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });

      const res = await request(app)
        .patch(`/api/issuers/${issuer._id}/approve`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(409);
      expect(res.body.error.message).toMatch(/cannot approve/i);
    });

    it('rejects approval by non-ADMIN roles with 403', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });

      const res = await request(app)
        .patch(`/api/issuers/${issuer._id}/approve`)
        .set('Authorization', `Bearer ${issuerToken}`);

      expect(res.status).toBe(403);
    });
  });

  // ─── 5. Suspension & Revocation ──────────────────────────────────────────────

  describe('PATCH /api/issuers/:id/suspend & revoke (Lifecycle Transitions)', () => {
    it('allows ADMIN to suspend an ACTIVE issuer with mandatory reason', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });

      const res = await request(app)
        .patch(`/api/issuers/${issuer._id}/suspend`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Investigation into unauthorized credential issue request' });

      expect(res.status).toBe(200);
      expect(res.body.data.issuer.status).toBe('SUSPENDED');
      expect(res.body.data.issuer.suspensionReason).toBe(
        'Investigation into unauthorized credential issue request'
      );
    });

    it('rejects suspension without a reason with 400', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });

      const res = await request(app)
        .patch(`/api/issuers/${issuer._id}/suspend`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
    });

    it('allows ADMIN to revoke an issuer, retiring their active private key', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });

      const res = await request(app)
        .patch(`/api/issuers/${issuer._id}/revoke`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Issuer departed the institution permanently' });

      expect(res.status).toBe(200);
      expect(res.body.data.issuer.status).toBe('REVOKED');
      expect(res.body.data.issuer.revokedReason).toBe(
        'Issuer departed the institution permanently'
      );

      // Verify active key file is no longer in active keys/ directory
      const activeKeyFile = path.resolve(process.cwd(), 'keys', `issuer_${issuer._id}.key`);
      expect(fs.existsSync(activeKeyFile)).toBe(false);

      // Verify key was moved to retired/ directory
      const retiredKeyFile = path.resolve(
        process.cwd(),
        'keys',
        'retired',
        `issuer_${issuer._id}.key`
      );
      expect(fs.existsSync(retiredKeyFile)).toBe(true);

      // Verify historical public key is preserved in MongoDB
      const issuerKey = await IssuerKey.findOne({ issuerId: issuer._id });
      expect(issuerKey).not.toBeNull();
      expect(issuerKey.status).toBe('REVOKED');
      expect(issuerKey.publicKey).toBeDefined();
    });

    it('rejects transitions on an already REVOKED issuer with 409', async () => {
      const issuer = await Issuer.findOne({ userId: issuerUser._id });

      const res = await request(app)
        .patch(`/api/issuers/${issuer._id}/suspend`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Attempting to suspend revoked issuer' });

      expect(res.status).toBe(409);
    });
  });

  // ─── 6. Key Compromise Endpoint ──────────────────────────────────────────────

  describe('PATCH /api/issuer-keys/:id/compromise (Key Compromise Handling)', () => {
    it('allows ADMIN to mark an IssuerKey as COMPROMISED', async () => {
      // First, create and approve another issuer to test key compromise
      await User.create({
        name: 'Issuer User 3',
        email: 'issuer3@example.com',
        passwordHash: 'Password123',
        role: 'ISSUER',
      });
      const user3 = await User.findOne({ email: 'issuer3@example.com' });
      const user3Token = generateToken(user3);

      await request(app)
        .post('/api/issuers/register')
        .set('Authorization', `Bearer ${user3Token}`)
        .send({ organizationId: verifiedOrg._id });

      const issuer3 = await Issuer.findOne({ userId: user3._id });
      const approveRes = await request(app)
        .patch(`/api/issuers/${issuer3._id}/approve`)
        .set('Authorization', `Bearer ${adminToken}`);

      const keyId = approveRes.body.data.issuerKey._id;

      // Mark the key as compromised
      const compRes = await request(app)
        .patch(`/api/issuer-keys/${keyId}/compromise`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Private key suspected exposed on developer workstation' });

      expect(compRes.status).toBe(200);
      expect(compRes.body.success).toBe(true);
      expect(compRes.body.data.issuerKey.status).toBe('COMPROMISED');
      expect(compRes.body.data.issuerKey.publicKey).toBeDefined();
      expect(compRes.body.data.issuerKey.privateKeyReference).toBeUndefined();

      // Key must be moved to retired
      const retiredFile = path.resolve(
        process.cwd(),
        'keys',
        'retired',
        `issuer_${issuer3._id}.key`
      );
      expect(fs.existsSync(retiredFile)).toBe(true);
    });

    it('rejects compromise by non-ADMIN roles with 403', async () => {
      const anyKey = await IssuerKey.findOne();
      const res = await request(app)
        .patch(`/api/issuer-keys/${anyKey._id}/compromise`)
        .set('Authorization', `Bearer ${issuerToken}`)
        .send({ reason: 'Unauthorized compromise attempt' });

      expect(res.status).toBe(403);
    });
  });

  // ─── 7. Audit Log Verification ───────────────────────────────────────────────

  describe('Audit Logging Verification', () => {
    it('records hash-chained audit logs for all issuer lifecycle events', async () => {
      const logs = await AuditLog.find({
        action: {
          $in: [
            'ISSUER_AUTHORIZATION_SUBMITTED',
            'ISSUER_APPROVED',
            'ISSUER_SUSPENDED',
            'ISSUER_REVOKED',
            'ISSUER_KEY_CREATED',
            'ISSUER_KEY_COMPROMISED',
          ],
        },
      });

      expect(logs.length).toBeGreaterThanOrEqual(4);
      for (const log of logs) {
        expect(log.currentHash).toBeDefined();
        expect(log.previousHash).toBeDefined();
        expect(log.sequenceNumber).toBeGreaterThanOrEqual(1);
      }
    });
  });
});
