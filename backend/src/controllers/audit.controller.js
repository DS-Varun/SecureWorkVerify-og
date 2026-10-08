/**
 * Audit log controller (M6).
 *
 * READ-ONLY controller for ADMIN and AUDITOR roles.
 * Provides:
 * - Paginated/filterable listing of audit log entries
 * - Hash-chain integrity validation
 * - Credential lifecycle timeline (uses existing audit log entries)
 *
 * SECURITY:
 * - AUDITOR must NOT create, update, or delete audit records.
 * - AUDITOR must NOT alter sequence numbers, previousHash, currentHash, or metadata.
 * - Only read/validation operations are exposed.
 * - All endpoints require authentication + ADMIN or AUDITOR role.
 */

'use strict';

const { AuditLog } = require('../models/AuditLog');
const auditService = require('../services/audit.service');
const { success, error: errorResponse } = require('../utils/apiResponse');

/**
 * GET /api/audit-logs
 * List audit log entries with pagination and filtering.
 *
 * Query params:
 *   page       - page number (default 1)
 *   limit      - items per page (default 20, max 100)
 *   action     - filter by audit action enum
 *   targetType - filter by target type enum
 *   targetId   - filter by specific target ObjectId
 *   performedBy - filter by user ObjectId
 *   startDate  - filter entries >= this ISO date
 *   endDate    - filter entries <= this ISO date
 */
const list = async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 20,
      action,
      targetType,
      targetId,
      performedBy,
      startDate,
      endDate,
    } = req.query;

    const filter = {};

    if (action) filter.action = action;
    if (targetType) filter.targetType = targetType;
    if (targetId) filter.targetId = targetId;
    if (performedBy) filter.performedBy = performedBy;

    // Date range filter
    if (startDate || endDate) {
      filter.createdAt = {};
      if (startDate) filter.createdAt.$gte = new Date(startDate);
      if (endDate) filter.createdAt.$lte = new Date(endDate);
    }

    const safePage = Math.max(1, parseInt(page, 10) || 1);
    const safeLimit = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const skip = (safePage - 1) * safeLimit;

    const [entries, total] = await Promise.all([
      AuditLog.find(filter)
        .populate('performedBy', 'name email role')
        .sort({ sequenceNumber: -1 })
        .skip(skip)
        .limit(safeLimit)
        .lean(),
      AuditLog.countDocuments(filter),
    ]);

    return success(
      res,
      {
        entries,
        total,
        page: safePage,
        limit: safeLimit,
        totalPages: Math.ceil(total / safeLimit),
      },
      'Audit logs retrieved successfully'
    );
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/audit-logs/validate
 * Validate the entire audit hash chain.
 *
 * Returns:
 *   valid    - boolean
 *   count    - total entries checked
 *   error    - description if chain is broken (optional)
 *   brokenAt - ObjectId of the broken entry (optional)
 *   index    - index of the broken entry (optional)
 *
 * NOTE: This is read-only. The chain is NEVER modified or repaired.
 */
const validate = async (req, res, next) => {
  try {
    const result = await auditService.verifyChain();
    return success(res, result, result.valid ? 'Audit chain is valid' : 'Audit chain integrity failure detected');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/credentials/:id/timeline
 * Get lifecycle timeline for a specific credential using existing audit log entries.
 *
 * Returns all audit events where targetId matches the credential (or its related entities).
 * Does NOT create any new audit records.
 * Ordered chronologically (oldest first).
 *
 * Relevant audit actions for a credential timeline:
 * - CREDENTIAL_ISSUED
 * - CREDENTIAL_VERSION_CREATED
 * - CREDENTIAL_SUPERSEDED
 * - CREDENTIAL_REVOKED
 * - VERIFICATION_PERFORMED (where targetId matches)
 * - DOCUMENT_UPLOADED (linked through credential metadata)
 */
const credentialTimeline = async (req, res, next) => {
  try {
    const credentialId = req.params.id;

    // Find all audit entries whose targetId is this credential
    // or which reference this credential in their metadata.
    const directEntries = await AuditLog.find({
      targetId: credentialId,
      targetType: { $in: ['CREDENTIAL', 'CREDENTIAL_VERSION'] },
    })
      .populate('performedBy', 'name email role')
      .sort({ sequenceNumber: 1 })
      .lean();

    // Also find verification events that reference this credential in metadata
    const verificationEntries = await AuditLog.find({
      action: 'VERIFICATION_PERFORMED',
      'metadata.credentialId': credentialId,
    })
      .populate('performedBy', 'name email role')
      .sort({ sequenceNumber: 1 })
      .lean();

    // Merge and sort chronologically by sequenceNumber (unique, no duplicates)
    const seenIds = new Set(directEntries.map((e) => String(e._id)));
    const merged = [...directEntries];
    for (const entry of verificationEntries) {
      if (!seenIds.has(String(entry._id))) {
        merged.push(entry);
      }
    }
    merged.sort((a, b) => a.sequenceNumber - b.sequenceNumber);

    return success(
      res,
      {
        credentialId,
        timeline: merged,
        count: merged.length,
      },
      'Credential timeline retrieved successfully'
    );
  } catch (err) {
    next(err);
  }
};

module.exports = {
  list,
  validate,
  credentialTimeline,
};
