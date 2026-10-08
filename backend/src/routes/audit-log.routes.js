/**
 * Audit log routes (M6 — PROJECT_RULES §24).
 *
 * REST Contract:
 * - GET /api/audit-logs            → ADMIN, AUDITOR (paginated, filterable)
 * - GET /api/audit-logs/validate   → ADMIN, AUDITOR (chain integrity check)
 *
 * SECURITY:
 * - All endpoints require authentication (JWT).
 * - Only ADMIN and AUDITOR roles are authorized.
 * - AUDITOR is READ-ONLY — no create/update/delete endpoints exist.
 * - No public audit endpoints.
 */

'use strict';

const express = require('express');
const router = express.Router();
const auditController = require('../controllers/audit.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/rbac.middleware');
const { listAuditLogsQuery } = require('../validators/audit-log.validator');

// GET /api/audit-logs (ADMIN, AUDITOR — paginated, filterable, read-only)
router.get(
  '/',
  authenticate,
  authorize('ADMIN', 'AUDITOR'),
  listAuditLogsQuery,
  auditController.list
);

// GET /api/audit-logs/validate (ADMIN, AUDITOR — chain integrity validation, read-only)
router.get(
  '/validate',
  authenticate,
  authorize('ADMIN', 'AUDITOR'),
  auditController.validate
);

module.exports = router;
