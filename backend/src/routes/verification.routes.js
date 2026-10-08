/**
 * Verification routes (PROJECT_RULES §24).
 * Verify endpoint is rate limited: max 30 requests / 15 min per IP (M7).
 *
 * REST Contract:
 * - POST   /api/verifications/verify        → HR, USER (upload document for verification)
 * - GET    /api/verifications               → HR, USER, ADMIN, AUDITOR (role-scoped history)
 * - GET    /api/verifications/:id          → HR, USER, ADMIN, AUDITOR (role-scoped details)
 * - GET    /api/verifications/:id/evidence → HR, USER, ADMIN, AUDITOR (evidence trail)
 */

'use strict';

const express = require('express');
const router = express.Router();
const verificationController = require('../controllers/verification.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/rbac.middleware');
const { uploadDocument } = require('../middleware/upload.middleware');
const { verifyLimiter } = require('../middleware/rateLimiter.middleware');
const {
  validateVerificationId,
  listVerificationsQuery,
} = require('../validators/verification.validator');

// POST /api/verifications/verify (HR, USER — rate limited)
router.post(
  '/verify',
  authenticate,
  authorize('HR', 'USER'),
  verifyLimiter,
  uploadDocument,
  verificationController.verify
);

// GET /api/verifications (HR, USER, ADMIN, AUDITOR — role-scoped)
router.get(
  '/',
  authenticate,
  authorize('HR', 'USER', 'ADMIN', 'AUDITOR'),
  listVerificationsQuery,
  verificationController.list
);

// GET /api/verifications/:id (HR, USER, ADMIN, AUDITOR — role-scoped)
router.get(
  '/:id',
  authenticate,
  authorize('HR', 'USER', 'ADMIN', 'AUDITOR'),
  validateVerificationId,
  verificationController.getById
);

// GET /api/verifications/:id/evidence (HR, USER, ADMIN, AUDITOR — role-scoped)
router.get(
  '/:id/evidence',
  authenticate,
  authorize('HR', 'USER', 'ADMIN', 'AUDITOR'),
  validateVerificationId,
  verificationController.getEvidence
);

module.exports = router;
