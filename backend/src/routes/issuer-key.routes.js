/**
 * Issuer key routes (PROJECT_RULES §24).
 *
 * PATCH  /api/issuer-keys/:id/compromise  → authenticate + authorize(ADMIN)
 */

'use strict';

const express = require('express');
const router = express.Router();
const issuerController = require('../controllers/issuer.controller');
const { authenticate } = require('../middleware/auth.middleware');
const { authorize } = require('../middleware/rbac.middleware');
const {
  validateIssuerKeyId,
  validateStatusChangeReason,
} = require('../validators/issuer.validator');

// PATCH /api/issuer-keys/:id/compromise (ADMIN only)
router.patch(
  '/:id/compromise',
  authenticate,
  authorize('ADMIN'),
  validateIssuerKeyId,
  validateStatusChangeReason,
  issuerController.markKeyCompromised
);

module.exports = router;
