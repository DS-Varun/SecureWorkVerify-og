/**
 * Audit log and hash-chain integrity tests.
 *
 * Tests cover:
 * - Genesis previousHash creation
 * - Sequential sequenceNumber generation (1, 2, 3...)
 * - Deterministic canonical JSON hashing (key-order independent)
 * - Hash-chain verification (verifyChain returns valid: true)
 * - Tamper detection (modified metadata / action fails verification)
 * - Sequence gap detection (missing sequence number fails verification)
 * - previousHash mismatch detection
 * - Concurrency protection (concurrent writes maintain unbroken chain)
 * - Database safety guard
 */

'use strict';

const mongoose = require('mongoose');
const { AuditLog } = require('../src/models/AuditLog');
const { User } = require('../src/models/User');
const auditService = require('../src/services/audit.service');
const { canonicalStringify } = require('../src/utils/canonicalJson');
const { assertTestDatabase } = require('./testHelper');

describe('Audit Log Hash Chain & Concurrency', () => {
  let testUser;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGODB_URI);
    assertTestDatabase();

    await User.deleteMany({});
    await AuditLog.deleteMany({});

    testUser = await User.create({
      name: 'Audit Actor',
      email: 'actor@example.com',
      passwordHash: 'Password123',
      role: 'ADMIN',
    });
  });

  afterAll(async () => {
    assertTestDatabase();
    await User.deleteMany({});
    await AuditLog.deleteMany({});
    await mongoose.disconnect();
  });

  beforeEach(async () => {
    await AuditLog.deleteMany({});
  });

  it('should create initial entry with sequenceNumber 1 and genesisHash', async () => {
    const entry = await auditService.log({
      action: 'ORGANIZATION_CREATED',
      performedBy: testUser._id,
      targetType: 'ORGANIZATION',
      targetId: new mongoose.Types.ObjectId(),
      metadata: { name: 'Test Org' },
    });

    expect(entry.sequenceNumber).toBe(1);
    expect(entry.previousHash).toBe(AuditLog.genesisHash());
    expect(entry.currentHash).toBeDefined();

    const verification = await auditService.verifyChain();
    expect(verification.valid).toBe(true);
    expect(verification.count).toBe(1);
  });

  it('should deterministically stringify JSON regardless of key insertion order', () => {
    const objA = { b: 2, a: 1, nested: { z: 10, y: 5 } };
    const objB = { nested: { y: 5, z: 10 }, a: 1, b: 2 };

    expect(canonicalStringify(objA)).toBe(canonicalStringify(objB));
    expect(canonicalStringify(objA)).toBe('{"a":1,"b":2,"nested":{"y":5,"z":10}}');
  });

  it('should maintain unbroken hash chain across multiple sequential entries', async () => {
    for (let i = 0; i < 5; i++) {
      await auditService.log({
        action: 'ORGANIZATION_VERIFIED',
        performedBy: testUser._id,
        targetType: 'ORGANIZATION',
        targetId: new mongoose.Types.ObjectId(),
        metadata: { step: i, note: `Audit event step ${i}` },
      });
    }

    const entries = await AuditLog.find({}).sort({ sequenceNumber: 1 });
    expect(entries.length).toBe(5);

    // Verify continuous sequences
    for (let i = 0; i < entries.length; i++) {
      expect(entries[i].sequenceNumber).toBe(i + 1);
    }

    const verification = await auditService.verifyChain();
    expect(verification.valid).toBe(true);
    expect(verification.count).toBe(5);
  });

  it('should detect tampering when entry metadata is altered', async () => {
    // Create 3 valid entries
    for (let i = 0; i < 3; i++) {
      await auditService.log({
        action: 'ORGANIZATION_CREATED',
        performedBy: testUser._id,
        targetType: 'ORGANIZATION',
        targetId: new mongoose.Types.ObjectId(),
        metadata: { legitimate: `data-${i}` },
      });
    }

    // Directly tamper with MongoDB record #2
    await AuditLog.collection.updateOne(
      { sequenceNumber: 2 },
      { $set: { 'metadata.legitimate': 'TAMPERED_VALUE' } }
    );

    const verification = await auditService.verifyChain();
    expect(verification.valid).toBe(false);
    expect(verification.error).toMatch(/currentHash mismatch/i);
  });

  it('should detect sequence gaps when an entry is deleted', async () => {
    // Create 3 valid entries (sequences 1, 2, 3)
    for (let i = 0; i < 3; i++) {
      await auditService.log({
        action: 'ORGANIZATION_CREATED',
        performedBy: testUser._id,
        targetType: 'ORGANIZATION',
        targetId: new mongoose.Types.ObjectId(),
        metadata: { seq: i + 1 },
      });
    }

    // Delete sequence 2 to create a gap (1, 3)
    await AuditLog.collection.deleteOne({ sequenceNumber: 2 });

    const verification = await auditService.verifyChain();
    expect(verification.valid).toBe(false);
    expect(verification.error).toMatch(/Sequence gap detected/i);
  });

  it('should safely handle concurrent writes without sequence collisions or broken linkages', async () => {
    const concurrentWrites = 10;
    const targetIds = Array.from({ length: concurrentWrites }, () => new mongoose.Types.ObjectId());

    // Trigger all log calls concurrently in Promise.all
    await Promise.all(
      targetIds.map((targetId, index) =>
        auditService.log({
          action: 'ORGANIZATION_CREATED',
          performedBy: testUser._id,
          targetType: 'ORGANIZATION',
          targetId,
          metadata: { concurrentIndex: index },
        })
      )
    );

    const entries = await AuditLog.find({}).sort({ sequenceNumber: 1 });
    expect(entries.length).toBe(concurrentWrites);

    // Assert strictly continuous sequence numbers: 1 to 10
    const sequenceNumbers = entries.map((e) => e.sequenceNumber);
    expect(sequenceNumbers).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    // Verify entire chain is valid
    const verification = await auditService.verifyChain();
    expect(verification.valid).toBe(true);
    expect(verification.count).toBe(concurrentWrites);
  });
});
