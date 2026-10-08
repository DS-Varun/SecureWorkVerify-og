/**
 * Authentication endpoint tests.
 *
 * Tests cover:
 * - Registration success
 * - Duplicate registration prevention
 * - Login success
 * - Incorrect password
 * - Invalid JWT
 * - Missing JWT
 * - GET /api/auth/me
 */

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');
const { User } = require('../src/models/User');

// Test user data.
// NOTE: role is NOT sent in registration — the server always assigns USER.
const testUser = {
  name: 'Test User',
  email: 'test@example.com',
  password: 'TestPass123',
};

let authToken;

const { assertTestDatabase } = require('./testHelper');

describe('Auth Endpoints', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    assertTestDatabase();
  });

  afterAll(async () => {
    // Clean up test data with safety verification
    assertTestDatabase();
    await User.deleteMany({});
    await mongoose.disconnect();
  });

  // ─── Registration ──────────────────────────────────────

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('token');
      expect(res.body.data).toHaveProperty('user');
      expect(res.body.data.user).toHaveProperty('name', testUser.name);
      expect(res.body.data.user).toHaveProperty('email', testUser.email.toLowerCase());
      // Server always assigns USER regardless of input
      expect(res.body.data.user).toHaveProperty('role', 'USER');
      expect(res.body.data.user).toHaveProperty('isActive', true);

      // passwordHash must NEVER be in the response
      expect(res.body.data.user).not.toHaveProperty('passwordHash');

      // Save token for later tests
      authToken = res.body.data.token;
    });

    it('should reject duplicate email registration', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);

      expect(res.status).toBe(409);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/already registered/i);
    });

    it('should reject registration with missing fields', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ email: 'incomplete@example.com' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject registration with invalid email', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ ...testUser, email: 'not-an-email' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should reject registration with weak password', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({ ...testUser, email: 'weak@example.com', password: '123' });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });

    it('should register as USER even if an unknown role is sent', async () => {
      // Role is ignored entirely at registration — server always assigns USER
      const res = await request(app)
        .post('/api/auth/register')
        .send({ ...testUser, email: 'badrole@example.com', role: 'SUPERADMIN' });

      expect(res.status).toBe(201);
      expect(res.body.data.user.role).toBe('USER');
    });

    it('should normalize email to lowercase', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          ...testUser,
          email: 'UpperCase@Example.COM',
          password: 'ValidPass123',
        });

      expect(res.status).toBe(201);
      expect(res.body.data.user.email).toBe('uppercase@example.com');
      // Role is always USER regardless of what caller sends
      expect(res.body.data.user.role).toBe('USER');
    });

    it('should always register as USER even if a privileged role is sent', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Would-be Admin',
          email: 'sneaky@example.com',
          password: 'ValidPass123',
          role: 'ADMIN', // attacker tries to self-assign ADMIN
        });

      // Registration should succeed but role must always be USER
      expect(res.status).toBe(201);
      expect(res.body.data.user.role).toBe('USER');
    });
  });

  // ─── Login ─────────────────────────────────────────────

  describe('POST /api/auth/login', () => {
    it('should login with correct credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('token');
      expect(res.body.data).toHaveProperty('user');
      expect(res.body.data.user).not.toHaveProperty('passwordHash');

      // Update token for subsequent tests
      authToken = res.body.data.token;
    });

    it('should reject login with incorrect password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword123',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/invalid/i);
    });

    it('should reject login with non-existent email', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nobody@example.com',
          password: 'SomePassword123',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });

    it('should reject login with missing fields', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: testUser.email });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
    });
  });

  // ─── GET /api/auth/me ──────────────────────────────────

  describe('GET /api/auth/me', () => {
    it('should return the authenticated user profile', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${authToken}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user).toHaveProperty('name', testUser.name);
      expect(res.body.data.user).toHaveProperty('email', testUser.email.toLowerCase());
      expect(res.body.data.user).toHaveProperty('role', 'USER');
      expect(res.body.data.user).not.toHaveProperty('passwordHash');
    });

    it('should reject request with missing JWT', async () => {
      const res = await request(app)
        .get('/api/auth/me');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/no token/i);
    });

    it('should reject request with invalid JWT', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalid.token.here');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.error.message).toMatch(/invalid/i);
    });

    it('should reject request with malformed Authorization header', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'NotBearer sometoken');

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
    });
  });

  // ─── 404 Handling ──────────────────────────────────────

  describe('Unknown routes', () => {
    it('should return 404 for unknown routes', async () => {
      const res = await request(app).get('/api/nonexistent');

      expect(res.status).toBe(404);
      expect(res.body.success).toBe(false);
    });
  });
});
