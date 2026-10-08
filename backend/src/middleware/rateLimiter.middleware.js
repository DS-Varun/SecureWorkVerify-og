/**
 * Rate limiting middleware (M7 — Security Hardening).
 *
 * Two distinct limiters as specified in implementation_plan.md:
 *
 * 1. authLimiter  — /api/auth/* endpoints (login, register)
 *    Max 10 requests per 15-minute window per IP.
 *    Prevents brute-force login and registration spam.
 *
 * 2. verifyLimiter — /api/verifications/verify endpoint
 *    Max 30 requests per 15-minute window per IP.
 *    Prevents verification abuse / DoS.
 *
 * Both return standard API error format on limit exceeded.
 */

'use strict';

const rateLimit = require('express-rate-limit');

/**
 * Auth rate limiter — 10 requests / 15 min per IP.
 * Applied to: POST /api/auth/register, POST /api/auth/login
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  standardHeaders: true,  // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false,   // Disable the `X-RateLimit-*` headers
  message: {
    success: false,
    error: {
      message: 'Too many requests. Please try again after 15 minutes.',
      code: 'RATE_LIMIT_EXCEEDED',
    },
  },
  // Skip rate limiting in test environment
  skip: () => process.env.NODE_ENV === 'test',
});

/**
 * Verification rate limiter — 30 requests / 15 min per IP.
 * Applied to: POST /api/verifications/verify
 */
const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'Too many verification requests. Please try again after 15 minutes.',
      code: 'RATE_LIMIT_EXCEEDED',
    },
  },
  skip: () => process.env.NODE_ENV === 'test',
});

/**
 * General API rate limiter — 100 requests / 15 min per IP.
 * Applied globally as a safety net against abuse.
 */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      message: 'Too many requests. Please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
    },
  },
  skip: () => process.env.NODE_ENV === 'test',
});

module.exports = { authLimiter, verifyLimiter, generalLimiter };
