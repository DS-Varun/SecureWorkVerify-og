/**
 * Authentication routes.
 * Rate limited: max 10 requests / 15 min per IP (M7).
 */

const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { registerRules, loginRules } = require('../validators/auth.validator');
const { authenticate } = require('../middleware/auth.middleware');
const { authLimiter } = require('../middleware/rateLimiter.middleware');

// POST /api/auth/register (rate limited)
router.post('/register', authLimiter, registerRules, authController.register);

// POST /api/auth/login (rate limited)
router.post('/login', authLimiter, loginRules, authController.login);

// GET /api/auth/me (protected)
router.get('/me', authenticate, authController.getMe);

module.exports = router;

