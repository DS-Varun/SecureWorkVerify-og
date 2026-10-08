/**
 * Authentication service.
 * Handles user registration, login, and token generation.
 *
 * SECURITY: Public registration ALWAYS creates a USER.
 * Privileged roles (ADMIN, ISSUER, HR, AUDITOR) must be assigned by an ADMIN
 * through separate promotion endpoints. The registration endpoint ignores any
 * caller-supplied role and always sets role = 'USER'.
 */

const jwt = require('jsonwebtoken');
const config = require('../config/env');
const { User, PUBLIC_REGISTRATION_ROLE } = require('../models/User');

/**
 * Generate a JWT for a user.
 * @param {Object} user - User document
 * @returns {string} JWT token
 */
const generateToken = (user) => {
  return jwt.sign(
    {
      userId: user._id,
      role: user.role,
    },
    config.jwtSecret,
    {
      expiresIn: config.jwtExpiresIn,
    }
  );
};

/**
 * Register a new user.
 * @param {Object} params
 * @param {string} params.name
 * @param {string} params.email
 * @param {string} params.password
 * @returns {Promise<{user: Object, token: string}>}
 */
const register = async ({ name, email, password }) => {
  // Check for existing user
  const existingUser = await User.findOne({ email: email.toLowerCase() });
  if (existingUser) {
    const err = new Error('Email already registered');
    err.statusCode = 409;
    throw err;
  }

  // SECURITY: Always create USER — never accept caller-supplied role.
  // Privileged roles are assigned by ADMIN only via separate endpoints.
  const user = await User.create({
    name,
    email: email.toLowerCase(),
    passwordHash: password,
    role: PUBLIC_REGISTRATION_ROLE,
  });

  const token = generateToken(user);

  return { user, token };
};

/**
 * Login a user.
 * @param {Object} params
 * @param {string} params.email
 * @param {string} params.password
 * @returns {Promise<{user: Object, token: string}>}
 */
const login = async ({ email, password }) => {
  // Find user WITH passwordHash (not selected by default)
  const user = await User.findOne({ email: email.toLowerCase() }).select('+passwordHash');

  if (!user) {
    const err = new Error('Invalid email or password');
    err.statusCode = 401;
    throw err;
  }

  if (!user.isActive) {
    const err = new Error('Account is deactivated');
    err.statusCode = 403;
    throw err;
  }

  // Compare password
  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    const err = new Error('Invalid email or password');
    err.statusCode = 401;
    throw err;
  }

  const token = generateToken(user);

  return { user, token };
};

module.exports = { register, login, generateToken };
