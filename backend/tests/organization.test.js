/**
 * Organization endpoint and trust lifecycle tests.
 *
 * Tests cover:
 * - ADMIN-only creation of organizations
 * - Role-Based Access Control (ADMIN, USER, HR, ISSUER, AUDITOR)
 * - Organization code auto-generation (format: ORG-XXXXXXXX)
 * - Validation & duplicate name prevention
 * - Organization types (including INSTITUTION)
 * - Verification lifecycle: PENDING -> VERIFIED -> SUSPENDED -> REVOKED
 * - Re-verification of suspended organizations (SUSPENDED -> VERIFIED)
 * - Rejection of invalid transitions (e.g. verifying or suspending a revoked org)
 * - Mandatory verification evidence (notes, reference)
 * - Mandatory suspension/revocation reasons
 * - Preservation of historical verification events
 * - Database safety guards
 */

'use strict';

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const { User } = require('../src/models/User');
const { Organization } = require('../src/models/Organization');
const { AuditLog } = require('../src/models/AuditLog');
const { generateToken } = require('../src/services/auth.service');
const { assertTestDatabase } = require('./testHelper');

describe('Organization Trust Lifecycle & RBAC', () => {
  let adminUser, hrUser, issuerUser, normalUser, auditorUser;
  let adminToken, hrToken, issuerToken, userToken, auditorToken;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    assertTestDatabase();

    // Clean up test data
    await User.deleteMany({});
    await Organization.deleteMany({});
    await AuditLog.deleteMany({});

    // Create test users for every role
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
      name: 'Issuer User',
      email: 'issuer@example.com',
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
    userToken = generateToken(normalUser);
    auditorToken = generateToken(auditorUser);
  });

  afterAll(async () => {
    assertTestDatabase();
    await User.deleteMany({});
    await Organization.deleteMany({});
    await AuditLog.deleteMany({});
    await mongoose.disconnect();
  });

  // ─── 1. Creation & RBAC ───────────────────────────────────────────────────

  describe('POST /api/organizations (Creation & RBAC)', () => {
    const validOrgData = {
      name: 'Stanford University',
      type: 'UNIVERSITY',
      officialDomain: 'stanford.edu',
      description: 'Private research university',
    };

    it('should allow ADMIN to create an organization', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validOrgData);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.organization).toBeDefined();

      const org = res.body.data.organization;
      expect(org.name).toBe(validOrgData.name);
      expect(org.type).toBe('UNIVERSITY');
      expect(org.officialDomain).toBe('stanford.edu');
      expect(org.organizationVerificationStatus).toBe('PENDING');
      expect(org.status).toBe('ACTIVE');

      // Check organizationCode format: ORG-XXXXXXXX
      expect(org.organizationCode).toBeDefined();
      expect(org.organizationCode).toMatch(/^ORG-[A-Z0-9]{8}$/);
    });

    it('should reject organization creation by USER role (403)', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ name: 'User Org', type: 'COMPANY' });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject organization creation by HR role (403)', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${hrToken}`)
        .send({ name: 'HR Org', type: 'COMPANY' });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject organization creation by ISSUER role (403)', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${issuerToken}`)
        .send({ name: 'Issuer Org', type: 'COMPANY' });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject organization creation by AUDITOR role (403)', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send({ name: 'Auditor Org', type: 'COMPANY' });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
    });

    it('should reject unauthenticated creation (401)', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .send({ name: 'Anon Org', type: 'COMPANY' });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject duplicate organization names (409)', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${adminToken}`)
        .send(validOrgData);

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/already exists/i);
    });

    it('should accept INSTITUTION as a valid organization type', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'World Health Institution',
          type: 'INSTITUTION',
          officialDomain: 'whi.int',
        });

      expect(res.status).toBe(201);
      expect(res.body.data.organization.type).toBe('INSTITUTION');
    });

    it('should reject invalid organization types (400)', async () => {
      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          name: 'Bad Type Org',
          type: 'INVALID_TYPE',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ─── 2. Listing & Reading ─────────────────────────────────────────────────

  describe('GET /api/organizations (Listing & Reading)', () => {
    it('should allow all authenticated roles to list organizations', async () => {
      const tokens = [adminToken, hrToken, issuerToken, userToken, auditorToken];

      for (const token of tokens) {
        const res = await request(app)
          .get('/api/organizations')
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(Array.isArray(res.body.data.organizations)).toBe(true);
        expect(res.body.data.total).toBeGreaterThanOrEqual(2);
      }
    });

    it('should filter organizations by type', async () => {
      const res = await request(app)
        .get('/api/organizations?type=INSTITUTION')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.organizations.every((o) => o.type === 'INSTITUTION')).toBe(true);
    });

    it('should filter organizations by organizationVerificationStatus', async () => {
      const res = await request(app)
        .get('/api/organizations?organizationVerificationStatus=PENDING')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(
        res.body.data.organizations.every((o) => o.organizationVerificationStatus === 'PENDING')
      ).toBe(true);
    });

    it('should return a single organization by ID with verification history', async () => {
      const listRes = await request(app)
        .get('/api/organizations')
        .set('Authorization', `Bearer ${userToken}`);

      const orgId = listRes.body.data.organizations[0]._id;

      const res = await request(app)
        .get(`/api/organizations/${orgId}`)
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.organization._id).toBe(orgId);
      expect(Array.isArray(res.body.data.organization.verificationEvents)).toBe(true);
    });

    it('should return 400 for invalid MongoDB ObjectId format', async () => {
      const res = await request(app)
        .get('/api/organizations/invalid-id-format')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(400);
    });

    it('should return 404 for non-existent organization ID', async () => {
      const nonExistentId = new mongoose.Types.ObjectId();
      const res = await request(app)
        .get(`/api/organizations/${nonExistentId}`)
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(404);
    });
  });

  // ─── 3. Trust Establishment (Verification) ────────────────────────────────

  describe('POST /api/organizations/:id/verify (Trust Establishment)', () => {
    let testOrg;

    const crypto = require('crypto');
    beforeEach(async () => {
      const uniqueSuffix = crypto.randomBytes(4).toString('hex').toUpperCase();
      testOrg = await Organization.create({
        organizationCode: `ORG-${uniqueSuffix}`,
        name: `Test Org ${Date.now()}`,
        type: 'COMPANY',
        createdBy: adminUser._id,
        organizationVerificationStatus: 'PENDING',
        status: 'ACTIVE',
      });
    });

    it('should allow ADMIN to verify organization with valid evidence', async () => {
      const res = await request(app)
        .post(`/api/organizations/${testOrg._id}/verify`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          verificationMethod: 'ADMIN_REVIEW',
          evidence: {
            notes: 'Verified institutional charter and official tax registration.',
            reference: 'GOV-TAX-DOC-98765',
          },
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const org = res.body.data.organization;
      expect(org.organizationVerificationStatus).toBe('VERIFIED');
      expect(org.status).toBe('ACTIVE');

      // Check verification event was appended
      expect(org.verificationEvents.length).toBe(1);
      expect(org.verificationEvents[0].fromStatus).toBe('PENDING');
      expect(org.verificationEvents[0].toStatus).toBe('VERIFIED');
      expect(org.verificationEvents[0].method).toBe('ADMIN_REVIEW');
      expect(org.verificationEvents[0].notes).toBe(
        'Verified institutional charter and official tax registration.'
      );
      expect(org.verificationEvents[0].evidence.reference).toBe('GOV-TAX-DOC-98765');

      // Verify isTrusted() on model
      const updatedOrg = await Organization.findById(testOrg._id);
      expect(updatedOrg.isTrusted()).toBe(true);
    });

    it('should reject verification without required evidence notes/reference (400)', async () => {
      const res = await request(app)
        .post(`/api/organizations/${testOrg._id}/verify`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          verificationMethod: 'ADMIN_REVIEW',
          evidence: {}, // Missing notes and reference
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject verification by non-ADMIN roles (403)', async () => {
      const nonAdminTokens = [userToken, hrToken, issuerToken, auditorToken];

      for (const token of nonAdminTokens) {
        const res = await request(app)
          .post(`/api/organizations/${testOrg._id}/verify`)
          .set('Authorization', `Bearer ${token}`)
          .send({
            verificationMethod: 'ADMIN_REVIEW',
            evidence: {
              notes: 'Attempted review notes here.',
              reference: 'REF-12345',
            },
          });

        expect(res.status).toBe(403);
      }
    });

    it('should reject verifying an already VERIFIED organization (409)', async () => {
      // First verify
      await request(app)
        .post(`/api/organizations/${testOrg._id}/verify`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          verificationMethod: 'ADMIN_REVIEW',
          evidence: {
            notes: 'First verification review notes.',
            reference: 'REF-FIRST',
          },
        });

      // Second verify attempt
      const res = await request(app)
        .post(`/api/organizations/${testOrg._id}/verify`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          verificationMethod: 'ADMIN_REVIEW',
          evidence: {
            notes: 'Second verification review notes.',
            reference: 'REF-SECOND',
          },
        });

      expect(res.status).toBe(409);
      expect(res.body.error.message).toMatch(/already verified/i);
    });
  });

  // ─── 4. Suspension Lifecycle ──────────────────────────────────────────────

  describe('PATCH /api/organizations/:id/suspend (Suspension)', () => {
    let verifiedOrg;

    beforeEach(async () => {
      verifiedOrg = await Organization.create({
        organizationCode: `ORG-${Date.now().toString(16).toUpperCase().padStart(8, '0').slice(-8)}`,
        name: `Verified Org ${Date.now()}`,
        type: 'COMPANY',
        createdBy: adminUser._id,
        organizationVerificationStatus: 'VERIFIED',
        status: 'ACTIVE',
      });
    });

    it('should allow ADMIN to suspend organization with required reason', async () => {
      const res = await request(app)
        .patch(`/api/organizations/${verifiedOrg._id}/suspend`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          reason: 'Temporary investigation into corporate registration status.',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const org = res.body.data.organization;
      expect(org.organizationVerificationStatus).toBe('SUSPENDED');
      expect(org.status).toBe('SUSPENDED');
      expect(org.suspendedReason).toBe(
        'Temporary investigation into corporate registration status.'
      );

      // Check model isTrusted() returns false
      const updatedOrg = await Organization.findById(verifiedOrg._id);
      expect(updatedOrg.isTrusted()).toBe(false);
    });

    it('should reject suspension without reason (400)', async () => {
      const res = await request(app)
        .patch(`/api/organizations/${verifiedOrg._id}/suspend`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
    });

    it('should reject suspension by non-ADMIN roles (403)', async () => {
      const res = await request(app)
        .patch(`/api/organizations/${verifiedOrg._id}/suspend`)
        .set('Authorization', `Bearer ${hrToken}`)
        .send({ reason: 'HR attempting suspension' });

      expect(res.status).toBe(403);
    });

    it('should allow ADMIN to re-verify a SUSPENDED organization', async () => {
      // Suspend first
      await request(app)
        .patch(`/api/organizations/${verifiedOrg._id}/suspend`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Temporary suspension.' });

      // Re-verify
      const res = await request(app)
        .post(`/api/organizations/${verifiedOrg._id}/verify`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          verificationMethod: 'ADMIN_REVIEW',
          evidence: {
            notes: 'Investigation concluded with clear findings. Re-instated trust.',
            reference: 'INVESTIGATION-CLEAR-2026',
          },
        });

      expect(res.status).toBe(200);
      expect(res.body.data.organization.organizationVerificationStatus).toBe('VERIFIED');
      expect(res.body.data.organization.status).toBe('ACTIVE');

      // Check full event log preserves both transitions
      const orgWithEvents = await Organization.findById(verifiedOrg._id);
      expect(orgWithEvents.verificationEvents.length).toBe(2);
      expect(orgWithEvents.verificationEvents[0].toStatus).toBe('SUSPENDED');
      expect(orgWithEvents.verificationEvents[1].toStatus).toBe('VERIFIED');
    });
  });

  // ─── 5. Revocation Lifecycle ──────────────────────────────────────────────

  describe('PATCH /api/organizations/:id/revoke (Revocation)', () => {
    let activeOrg;

    beforeEach(async () => {
      activeOrg = await Organization.create({
        organizationCode: `ORG-${Date.now().toString(16).toUpperCase().padStart(8, '0').slice(-8)}`,
        name: `Active Org For Revocation ${Date.now()}`,
        type: 'COMPANY',
        createdBy: adminUser._id,
        organizationVerificationStatus: 'VERIFIED',
        status: 'ACTIVE',
      });
    });

    it('should allow ADMIN to permanently revoke an organization with reason', async () => {
      const res = await request(app)
        .patch(`/api/organizations/${activeOrg._id}/revoke`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          reason: 'Entity dissolved per official court proceedings.',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const org = res.body.data.organization;
      expect(org.organizationVerificationStatus).toBe('REVOKED');
      expect(org.status).toBe('REVOKED');
      expect(org.revokedReason).toBe('Entity dissolved per official court proceedings.');

      const dbOrg = await Organization.findById(activeOrg._id);
      expect(dbOrg.isTrusted()).toBe(false);
    });

    it('should reject revocation without reason (400)', async () => {
      const res = await request(app)
        .patch(`/api/organizations/${activeOrg._id}/revoke`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
    });

    it('should reject revocation by non-ADMIN roles (403)', async () => {
      const res = await request(app)
        .patch(`/api/organizations/${activeOrg._id}/revoke`)
        .set('Authorization', `Bearer ${userToken}`)
        .send({ reason: 'User attempting revocation' });

      expect(res.status).toBe(403);
    });

    it('should prevent verifying a REVOKED organization (409)', async () => {
      // Revoke
      await request(app)
        .patch(`/api/organizations/${activeOrg._id}/revoke`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Permanent shutdown.' });

      // Attempt to verify revoked org
      const res = await request(app)
        .post(`/api/organizations/${activeOrg._id}/verify`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({
          verificationMethod: 'ADMIN_REVIEW',
          evidence: {
            notes: 'Attempting to verify revoked entity.',
            reference: 'REF-FAIL',
          },
        });

      expect(res.status).toBe(409);
      expect(res.body.error.message).toMatch(/revoked/i);
    });

    it('should prevent suspending a REVOKED organization (409)', async () => {
      // Revoke
      await request(app)
        .patch(`/api/organizations/${activeOrg._id}/revoke`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Permanent shutdown.' });

      // Attempt to suspend revoked org
      const res = await request(app)
        .patch(`/api/organizations/${activeOrg._id}/suspend`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ reason: 'Attempting to suspend revoked entity.' });

      expect(res.status).toBe(409);
      expect(res.body.error.message).toMatch(/revoked/i);
    });
  });
});
