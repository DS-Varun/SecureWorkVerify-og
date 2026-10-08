/**
 * Audit service — hash-chained append-only audit log writer.
 *
 * Requirements:
 * - Deterministic SHA-256 hash chaining covering all critical audit fields
 * - Strict, continuous sequence numbering (1, 2, 3...)
 * - In-process serialization mutex to prevent concurrency races during sequence/hash generation
 * - Complete integrity verification via verifyChain()
 * - Audit failures throw errors rather than silently swallowing
 *
 * ARCHITECTURAL LIMITATION (v1):
 * In-process serialization protects concurrent writes within this single Node.js application process.
 * A future multi-instance / distributed deployment would require database-level coordination/transactions
 * or a dedicated sequencing worker.
 */

'use strict';

const { AuditLog } = require('../models/AuditLog');

// ─── In-Process Serialization Mutex ──────────────────────────────────────────

/**
 * Sequential promise queue to serialize audit log writes in-process.
 */
let writeQueue = Promise.resolve();

/**
 * Executes an async task exclusively within the serialization queue.
 * @param {Function} task
 * @returns {Promise<*>}
 */
const enqueueWrite = (task) => {
  const next = writeQueue.then(task, task);
  // Keep queue alive even if a previous task failed
  writeQueue = next.catch(() => {});
  return next;
};

// ─── Core Audit Functions ─────────────────────────────────────────────────────

/**
 * Fetch the latest audit log entry (by sequenceNumber).
 * @returns {Promise<Object|null>}
 */
const getLastEntry = async () => {
  return AuditLog.findOne({}, { sequenceNumber: 1, currentHash: 1 })
    .sort({ sequenceNumber: -1 })
    .lean();
};

/**
 * Write a new hash-chained audit log entry.
 * Serialized via in-process write queue to prevent concurrency race conditions.
 *
 * @param {Object} params
 * @param {string} params.action        - Enum from AUDIT_ACTIONS
 * @param {ObjectId|string} params.performedBy - User who triggered the action
 * @param {string} params.targetType    - Enum from AUDIT_TARGET_TYPES
 * @param {ObjectId|string} params.targetId   - ID of the affected entity
 * @param {Object} [params.metadata={}] - Action-specific context
 * @returns {Promise<Object>} Created AuditLog document
 */
const log = async ({
  action,
  performedBy,
  targetType,
  targetId,
  metadata = {},
}) => {
  return enqueueWrite(async () => {
    const lastEntry = await getLastEntry();

    const sequenceNumber = lastEntry ? lastEntry.sequenceNumber + 1 : 1;
    const previousHash = lastEntry ? lastEntry.currentHash : AuditLog.genesisHash();

    const now = new Date();
    const createdAtIso = now.toISOString();

    const currentHash = AuditLog.computeHash({
      sequenceNumber,
      action,
      performedBy,
      targetType,
      targetId,
      metadata,
      previousHash,
      createdAt: createdAtIso,
    });

    const entry = await AuditLog.create({
      sequenceNumber,
      action,
      performedBy,
      targetType,
      targetId,
      metadata,
      previousHash,
      currentHash,
      createdAt: now,
    });

    return entry;
  });
};

/**
 * Verify the hash chain integrity from the beginning.
 *
 * Checks:
 * 1. Sequence numbers are strictly continuous (1, 2, 3... without gaps)
 * 2. previousHash linkages are valid (entry 1 uses genesisHash, entry N uses entry N-1's currentHash)
 * 3. Recomputed currentHash matches entry's stored hash
 *
 * @returns {Promise<Object>} { valid: boolean, count: number, error?: string, brokenAt?: ObjectId, index?: number }
 */
const verifyChain = async () => {
  // MUST sort by sequenceNumber ascending
  const entries = await AuditLog.find({}).sort({ sequenceNumber: 1 }).lean();

  if (entries.length === 0) {
    return { valid: true, count: 0 };
  }

  let expectedPreviousHash = AuditLog.genesisHash();
  let expectedSeq = 1;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    // 1. Check continuous sequence numbers
    if (entry.sequenceNumber !== expectedSeq) {
      return {
        valid: false,
        count: entries.length,
        brokenAt: entry._id,
        index: i,
        error: `Sequence gap detected: expected sequenceNumber ${expectedSeq}, but found ${entry.sequenceNumber}`,
      };
    }

    // 2. Check previousHash linkage
    if (entry.previousHash !== expectedPreviousHash) {
      return {
        valid: false,
        count: entries.length,
        brokenAt: entry._id,
        index: i,
        error: `previousHash mismatch at sequence ${entry.sequenceNumber}: expected ${expectedPreviousHash}, got ${entry.previousHash}`,
      };
    }

    // 3. Recompute currentHash
    const createdAtIso = new Date(entry.createdAt).toISOString();
    const recomputedHash = AuditLog.computeHash({
      sequenceNumber: entry.sequenceNumber,
      action: entry.action,
      performedBy: entry.performedBy,
      targetType: entry.targetType,
      targetId: entry.targetId,
      metadata: entry.metadata || {},
      previousHash: entry.previousHash,
      createdAt: createdAtIso,
    });

    if (recomputedHash !== entry.currentHash) {
      return {
        valid: false,
        count: entries.length,
        brokenAt: entry._id,
        index: i,
        error: `currentHash mismatch at sequence ${entry.sequenceNumber} (entry data altered or tampered)`,
      };
    }

    expectedPreviousHash = entry.currentHash;
    expectedSeq++;
  }

  return { valid: true, count: entries.length };
};

module.exports = {
  log,
  verifyChain,
  getLastEntry,
};
