/**
 * Credential routes (PROJECT_RULES §24).
 *
 * REST Contract:
 * - POST   /api/credentials/issue         → ISSUER (must be ACTIVE)
 * - GET    /api/credentials               → ADMIN, ISSUER, HR, USER (role-scoped)
 * - GET    /api/credentials/:id          → ADMIN, ISSUER, HR, USER (role-scoped)
 * - GET    /api/credentials/:id/versions → ADMIN, ISSUER, HR, USER (role-scoped)
 * - POST   /api/credentials/:id/versions → ISSUER (own credential only)
 * - PATCH  /api/credentials/:id/revoke   → ISSUER (own credential only)
 * - GET    /api/credentials/:id/timeline → ADMIN, ISSUER, HR, USER (role-scoped) [M6]
 */

'use strict';

const express = require('express');
const router = express.Router();
const credentialController = require('../controllers/credential.controller');
const auditController = require('../controllers/audit.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/rbac.middleware');
const { uploadDocument } = require('../middleware/upload.middleware');
const {
  validateIssueCredential,
  validateCredentialId,
  listCredentialsQuery,
  validateAddVersion,
  validateRevokeCredential,
} = require('../validators/credential.validator');

// POST /api/credentials/issue (ISSUER only)
router.post(
  '/issue',
  authenticate,
  authorize('ISSUER'),
  uploadDocument,
  validateIssueCredential,
  credentialController.issue
);

// GET /api/credentials (ADMIN, ISSUER, HR, USER — role-scoped)
router.get(
  '/',
  authenticate,
  authorize('ADMIN', 'ISSUER', 'HR', 'USER'),
  listCredentialsQuery,
  credentialController.list
);

// GET /api/credentials/:id (ADMIN, ISSUER, HR, USER — role-scoped)
router.get(
  '/:id',
  authenticate,
  authorize('ADMIN', 'ISSUER', 'HR', 'USER'),
  validateCredentialId,
  credentialController.getById
);

// GET /api/credentials/:id/versions (ADMIN, ISSUER, HR, USER — role-scoped)
router.get(
  '/:id/versions',
  authenticate,
  authorize('ADMIN', 'ISSUER', 'HR', 'USER'),
  validateCredentialId,
  credentialController.getVersions
);

// POST /api/credentials/:id/versions (ISSUER only)
router.post(
  '/:id/versions',
  authenticate,
  authorize('ISSUER'),
  uploadDocument,
  validateAddVersion,
  credentialController.addVersion
);

// PATCH /api/credentials/:id/revoke (ISSUER only)
router.patch(
  '/:id/revoke',
  authenticate,
  authorize('ISSUER'),
  validateRevokeCredential,
  credentialController.revoke
);

// GET /api/credentials/:id/timeline (ADMIN, ISSUER, HR, USER — role-scoped) [M6]
router.get(
  '/:id/timeline',
  authenticate,
  authorize('ADMIN', 'ISSUER', 'HR', 'USER'),
  validateCredentialId,
  auditController.credentialTimeline
);

module.exports = router;

