/**
 * Organization routes.
 *
 * REST Contract (PROJECT_RULES §4 & Milestone 2 specs):
 * - POST  /api/organizations             (ADMIN only)
 * - GET   /api/organizations             (Authenticated)
 * - GET   /api/organizations/:id         (Authenticated)
 * - POST  /api/organizations/:id/verify  (ADMIN only)
 * - PATCH /api/organizations/:id/suspend (ADMIN only)
 * - PATCH /api/organizations/:id/revoke  (ADMIN only)
 */

'use strict';

const express = require('express');
const router = express.Router();
const organizationController = require('../controllers/organization.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/rbac.middleware');
const {
  paramIdRule,
  createOrgRules,
  verifyOrgRules,
  suspendOrgRules,
  revokeOrgRules,
  listOrgQueryRules,
} = require('../validators/organization.validator');

// POST /api/organizations (ADMIN only)
router.post(
  '/',
  authenticate,
  authorize('ADMIN'),
  createOrgRules,
  organizationController.create
);

// GET /api/organizations (All authenticated users)
router.get(
  '/',
  authenticate,
  listOrgQueryRules,
  organizationController.list
);

// GET /api/organizations/:id (All authenticated users)
router.get(
  '/:id',
  authenticate,
  paramIdRule,
  organizationController.getById
);

// POST /api/organizations/:id/verify (ADMIN only)
router.post(
  '/:id/verify',
  authenticate,
  authorize('ADMIN'),
  paramIdRule,
  verifyOrgRules,
  organizationController.verify
);

// PATCH /api/organizations/:id/suspend (ADMIN only)
router.patch(
  '/:id/suspend',
  authenticate,
  authorize('ADMIN'),
  paramIdRule,
  suspendOrgRules,
  organizationController.suspend
);

// PATCH /api/organizations/:id/revoke (ADMIN only)
router.patch(
  '/:id/revoke',
  authenticate,
  authorize('ADMIN'),
  paramIdRule,
  revokeOrgRules,
  organizationController.revoke
);

module.exports = router;
