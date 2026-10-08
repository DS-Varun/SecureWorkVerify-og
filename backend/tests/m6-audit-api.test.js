/**
 * M6 — Auditor API & Lifecycle Timeline integration tests.
 *
 * Tests cover:
 * 1. AUDITOR can access audit logs
 * 2. Unauthenticated access is rejected (401)
 * 3. Unauthorized roles are rejected (403) per PROJECT_RULES §24
 * 4. AUDITOR is read-only (no POST/PUT/PATCH/DELETE on audit endpoints)
 * 5. Pagination works
 * 6. Supported filters work (action, targetType, date range)
 * 7. Credential timeline works
 * 8. Timeline is chronological
 * 9. Valid audit chain passes
 * 10. Tampered chain is detected
 * 11. Sensitive information is not exposed
 */

'use strict';

const mongoose = require('mongoose');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { AuditLog } = require('../src/models/AuditLog');
const { User } = require('../src/models/User');
const auditService = require('../src/services/audit.service');
const { assertTestDatabase } = require('./testHelper');

// ─── Helpers ──────────────────────────────────────────────────────────────────

const JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-do-not-use-in-production';

const generateToken = (user) => {
  return jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
};

// ─── Test Suite ───────────────────────────────────────────────────────────────

describe('M6 — Auditor API & Lifecycle Timeline', () => {
  let adminUser, auditorUser, regularUser, issuerUser, hrUser;
  let adminToken, auditorToken, userToken, issuerToken, hrToken;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/securework-verify-test');
    assertTestDatabase();
  });

  afterAll(async () => {
    assertTestDatabase();
    await User.deleteMany({});
    await AuditLog.deleteMany({});
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await AuditLog.deleteMany({});

    // Create test users with all roles
    adminUser = await User.create({
      name: 'Admin User',
      email: 'admin@test.com',
      passwordHash: 'Password123!',
      role: 'ADMIN',
    });

    auditorUser = await User.create({
      name: 'Auditor User',
      email: 'auditor@test.com',
      passwordHash: 'Password123!',
      role: 'AUDITOR',
    });

    regularUser = await User.create({
      name: 'Regular User',
      email: 'user@test.com',
      passwordHash: 'Password123!',
      role: 'USER',
    });

    issuerUser = await User.create({
      name: 'Issuer User',
      email: 'issuer@test.com',
      passwordHash: 'Password123!',
      role: 'ISSUER',
    });

    hrUser = await User.create({
      name: 'HR User',
      email: 'hr@test.com',
      passwordHash: 'Password123!',
      role: 'HR',
    });

    adminToken = generateToken(adminUser);
    auditorToken = generateToken(auditorUser);
    userToken = generateToken(regularUser);
    issuerToken = generateToken(issuerUser);
    hrToken = generateToken(hrUser);
  });

  // ─── Helper to create sample audit entries ──────────────────────────────────

  const createSampleEntries = async (count = 5) => {
    const entries = [];
    const actions = [
      'ORGANIZATION_CREATED',
      'ISSUER_APPROVED',
      'CREDENTIAL_ISSUED',
      'VERIFICATION_PERFORMED',
      'CREDENTIAL_REVOKED',
    ];

    for (let i = 0; i < count; i++) {
      const entry = await auditService.log({
        action: actions[i % actions.length],
        performedBy: adminUser._id,
        targetType: i < 2 ? 'ORGANIZATION' : 'CREDENTIAL',
        targetId: new mongoose.Types.ObjectId(),
        metadata: { step: i, note: `Sample event ${i}` },
      });
      entries.push(entry);
    }
    return entries;
  };

  // ─── 1. AUDITOR can access audit logs ───────────────────────────────────────

  describe('GET /api/audit-logs', () => {
    it('1. AUDITOR can access audit logs', async () => {
      await createSampleEntries(3);

      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.entries).toHaveLength(3);
      expect(res.body.data.total).toBe(3);
    });

    it('1b. ADMIN can also access audit logs', async () => {
      await createSampleEntries(2);

      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.entries).toHaveLength(2);
    });
  });

  // ─── 2. Unauthenticated access is rejected ─────────────────────────────────

  describe('Authentication enforcement', () => {
    it('2. unauthenticated access to audit logs returns 401', async () => {
      const res = await request(app).get('/api/audit-logs');
      expect(res.status).toBe(401);
    });

    it('2b. unauthenticated access to validate returns 401', async () => {
      const res = await request(app).get('/api/audit-logs/validate');
      expect(res.status).toBe(401);
    });
  });

  // ─── 3. Unauthorized roles are rejected ─────────────────────────────────────

  describe('Authorization enforcement', () => {
    it('3a. USER role cannot access audit logs (403)', async () => {
      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
    });

    it('3b. ISSUER role cannot access audit logs (403)', async () => {
      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${issuerToken}`);
      expect(res.status).toBe(403);
    });

    it('3c. HR role cannot access audit logs (403)', async () => {
      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${hrToken}`);
      expect(res.status).toBe(403);
    });

    it('3d. USER cannot access validate (403)', async () => {
      const res = await request(app)
        .get('/api/audit-logs/validate')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(403);
    });
  });

  // ─── 4. AUDITOR is read-only ────────────────────────────────────────────────

  describe('AUDITOR read-only enforcement', () => {
    it('4a. POST to /api/audit-logs returns 404 (no route)', async () => {
      const res = await request(app)
        .post('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send({ action: 'ORGANIZATION_CREATED' });
      expect(res.status).toBe(404);
    });

    it('4b. PUT to /api/audit-logs returns 404 (no route)', async () => {
      const res = await request(app)
        .put('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send({});
      expect(res.status).toBe(404);
    });

    it('4c. DELETE to /api/audit-logs returns 404 (no route)', async () => {
      const res = await request(app)
        .delete('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`);
      expect(res.status).toBe(404);
    });

    it('4d. PATCH to /api/audit-logs returns 404 (no route)', async () => {
      const res = await request(app)
        .patch('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`)
        .send({});
      expect(res.status).toBe(404);
    });
  });

  // ─── 5. Pagination works ────────────────────────────────────────────────────

  describe('Pagination', () => {
    it('5a. pagination returns correct page and limit', async () => {
      await createSampleEntries(5);

      const res = await request(app)
        .get('/api/audit-logs?page=1&limit=2')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.entries).toHaveLength(2);
      expect(res.body.data.total).toBe(5);
      expect(res.body.data.page).toBe(1);
      expect(res.body.data.limit).toBe(2);
      expect(res.body.data.totalPages).toBe(3);
    });

    it('5b. page 2 returns next set', async () => {
      await createSampleEntries(5);

      const res = await request(app)
        .get('/api/audit-logs?page=2&limit=2')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.entries).toHaveLength(2);
      expect(res.body.data.page).toBe(2);
    });

    it('5c. default pagination values work', async () => {
      await createSampleEntries(3);

      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.page).toBe(1);
      expect(res.body.data.limit).toBe(20);
    });
  });

  // ─── 6. Supported filters work ─────────────────────────────────────────────

  describe('Filters', () => {
    it('6a. filter by action works', async () => {
      await createSampleEntries(5);

      const res = await request(app)
        .get('/api/audit-logs?action=ORGANIZATION_CREATED')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      res.body.data.entries.forEach((entry) => {
        expect(entry.action).toBe('ORGANIZATION_CREATED');
      });
    });

    it('6b. filter by targetType works', async () => {
      await createSampleEntries(5);

      const res = await request(app)
        .get('/api/audit-logs?targetType=CREDENTIAL')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      res.body.data.entries.forEach((entry) => {
        expect(entry.targetType).toBe('CREDENTIAL');
      });
    });

    it('6c. invalid action returns 400', async () => {
      const res = await request(app)
        .get('/api/audit-logs?action=INVALID_ACTION')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(400);
    });
  });

  // ─── 7 & 8. Timeline works and is chronological ────────────────────────────

  describe('GET /api/credentials/:id/timeline', () => {
    it('7. credential timeline returns audit events', async () => {
      const credentialId = new mongoose.Types.ObjectId();

      // Create audit entries targeting the credential
      await auditService.log({
        action: 'CREDENTIAL_ISSUED',
        performedBy: adminUser._id,
        targetType: 'CREDENTIAL',
        targetId: credentialId,
        metadata: { title: 'Test Credential' },
      });

      await auditService.log({
        action: 'CREDENTIAL_REVOKED',
        performedBy: adminUser._id,
        targetType: 'CREDENTIAL',
        targetId: credentialId,
        metadata: { reason: 'Testing revocation' },
      });

      const res = await request(app)
        .get(`/api/credentials/${credentialId}/timeline`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.timeline).toHaveLength(2);
      expect(res.body.data.credentialId).toBe(String(credentialId));
    });

    it('8. timeline events are in chronological order', async () => {
      const credentialId = new mongoose.Types.ObjectId();

      await auditService.log({
        action: 'CREDENTIAL_ISSUED',
        performedBy: adminUser._id,
        targetType: 'CREDENTIAL',
        targetId: credentialId,
        metadata: { step: 'first' },
      });

      await auditService.log({
        action: 'CREDENTIAL_REVOKED',
        performedBy: adminUser._id,
        targetType: 'CREDENTIAL',
        targetId: credentialId,
        metadata: { step: 'second' },
      });

      const res = await request(app)
        .get(`/api/credentials/${credentialId}/timeline`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      const timeline = res.body.data.timeline;
      expect(timeline.length).toBeGreaterThanOrEqual(2);

      // Verify chronological order (sequenceNumber ascending)
      for (let i = 1; i < timeline.length; i++) {
        expect(timeline[i].sequenceNumber).toBeGreaterThan(timeline[i - 1].sequenceNumber);
      }
    });

    it('7b. timeline for non-existent credential returns empty', async () => {
      const fakeId = new mongoose.Types.ObjectId();

      const res = await request(app)
        .get(`/api/credentials/${fakeId}/timeline`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.timeline).toHaveLength(0);
    });

    it('7c. unauthenticated access to timeline returns 401', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const res = await request(app).get(`/api/credentials/${fakeId}/timeline`);
      expect(res.status).toBe(401);
    });
  });

  // ─── 9. Valid audit chain passes ────────────────────────────────────────────

  describe('GET /api/audit-logs/validate', () => {
    it('9. valid chain returns valid: true', async () => {
      await createSampleEntries(5);

      const res = await request(app)
        .get('/api/audit-logs/validate')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.valid).toBe(true);
      expect(res.body.data.count).toBe(5);
    });

    it('9b. empty chain returns valid: true with count 0', async () => {
      const res = await request(app)
        .get('/api/audit-logs/validate')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.valid).toBe(true);
      expect(res.body.data.count).toBe(0);
    });
  });

  // ─── 10. Tampered chain is detected ─────────────────────────────────────────

  describe('Tamper detection via validate', () => {
    it('10. tampered entry is detected through validate endpoint', async () => {
      await createSampleEntries(3);

      // Directly tamper with sequence 2 in MongoDB
      await AuditLog.collection.updateOne(
        { sequenceNumber: 2 },
        { $set: { 'metadata.note': 'TAMPERED' } }
      );

      const res = await request(app)
        .get('/api/audit-logs/validate')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.data.valid).toBe(false);
      expect(res.body.data.error).toBeDefined();
      expect(res.body.data.brokenAt).toBeDefined();
    });
  });

  // ─── 11. Sensitive information is not exposed ───────────────────────────────

  describe('Data exposure checks', () => {
    it('11a. audit log entries do not expose user password hashes', async () => {
      await createSampleEntries(2);

      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      const entries = res.body.data.entries;
      entries.forEach((entry) => {
        if (entry.performedBy && typeof entry.performedBy === 'object') {
          expect(entry.performedBy.passwordHash).toBeUndefined();
          expect(entry.performedBy.password).toBeUndefined();
        }
      });
    });

    it('11b. audit entries include sequence and hash fields for auditor inspection', async () => {
      await createSampleEntries(1);

      const res = await request(app)
        .get('/api/audit-logs')
        .set('Authorization', `Bearer ${auditorToken}`);

      expect(res.status).toBe(200);
      const entry = res.body.data.entries[0];
      expect(entry.sequenceNumber).toBeDefined();
      expect(entry.currentHash).toBeDefined();
      expect(entry.previousHash).toBeDefined();
      expect(entry.action).toBeDefined();
    });
  });
});
