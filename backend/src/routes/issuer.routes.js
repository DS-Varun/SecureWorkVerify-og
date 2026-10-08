/**
 * Issuer routes (PROJECT_RULES §24).
 *
 * POST   /api/issuers/register          → authenticate + authorize(ISSUER)
 * GET    /api/issuers/me                → authenticate + authorize(ISSUER)
 * GET    /api/issuers                   → authenticate + authorize(ADMIN)
 * GET    /api/issuers/:id              → authenticate + authorize(ADMIN)
 * PATCH  /api/issuers/:id/approve      → authenticate + authorize(ADMIN)
 * PATCH  /api/issuers/:id/suspend      → authenticate + authorize(ADMIN)
 * PATCH  /api/issuers/:id/revoke       → authenticate + authorize(ADMIN)
 */

'use strict';

const express = require('express');
const router = express.Router();
const issuerController = require('../controllers/issuer.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/rbac.middleware');
const {
  validateRegisterIssuer,
  validateIssuerId,
  listIssuersQuery,
  validateStatusChangeReason,
} = require('../validators/issuer.validator');

// POST /api/issuers/register  (ISSUER-role user registers their issuer profile)
router.post(
  '/register',
  authenticate,
  authorize('ISSUER'),
  validateRegisterIssuer,
  issuerController.register
);

// GET /api/issuers/me  (ISSUER: view own profile)
// NOTE: /me must appear BEFORE /:id to prevent "me" matching a param
router.get(
  '/me',
  authenticate,
  authorize('ISSUER'),
  issuerController.getMyProfile
);

// GET /api/issuers  (ADMIN: list all issuers)
router.get(
  '/',
  authenticate,
  authorize('ADMIN'),
  listIssuersQuery,
  issuerController.list
);

// GET /api/issuers/:id  (ADMIN: get single issuer)
router.get(
  '/:id',
  authenticate,
  authorize('ADMIN'),
  validateIssuerId,
  issuerController.getById
);

// PATCH /api/issuers/:id/approve  (ADMIN: approve + generate keypair)
router.patch(
  '/:id/approve',
  authenticate,
  authorize('ADMIN'),
  validateIssuerId,
  issuerController.approve
);

// PATCH /api/issuers/:id/suspend  (ADMIN)
router.patch(
  '/:id/suspend',
  authenticate,
  authorize('ADMIN'),
  validateIssuerId,
  validateStatusChangeReason,
  issuerController.suspend
);

// PATCH /api/issuers/:id/revoke  (ADMIN)
router.patch(
  '/:id/revoke',
  authenticate,
  authorize('ADMIN'),
  validateIssuerId,
  validateStatusChangeReason,
  issuerController.revoke
);

module.exports = router;
