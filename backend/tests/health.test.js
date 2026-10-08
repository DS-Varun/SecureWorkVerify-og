/**
 * Health endpoint and database connection tests.
 */

const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../src/app');

describe('Health & Database', () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
  });

  afterAll(async () => {
    await mongoose.disconnect();
  });

  describe('GET /api/health', () => {
    it('should return health status with API status, database status, and timestamp', async () => {
      const res = await request(app).get('/api/health');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data).toHaveProperty('api', 'operational');
      expect(res.body.data).toHaveProperty('database', 'connected');
      expect(res.body.data).toHaveProperty('timestamp');

      // Verify timestamp is a valid ISO string
      const timestamp = new Date(res.body.data.timestamp);
      expect(timestamp.toISOString()).toBe(res.body.data.timestamp);
    });
  });

  describe('Database connection', () => {
    it('should be connected to MongoDB', () => {
      // readyState: 0=disconnected, 1=connected, 2=connecting, 3=disconnecting
      expect(mongoose.connection.readyState).toBe(1);
    });
  });
});
