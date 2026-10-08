/**
 * Express application setup.
 * Configures middleware, routes, and error handling.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const config = require('./config/env');
const { notFound, errorHandler } = require('./middleware/error.middleware');
const { generalLimiter } = require('./middleware/rateLimiter.middleware');

// Import routes
const authRoutes = require('./routes/auth.routes');
const healthRoutes = require('./routes/health.routes');
const organizationRoutes = require('./routes/organization.routes');
const issuerRoutes = require('./routes/issuer.routes');
const issuerKeyRoutes = require('./routes/issuer-key.routes');
const credentialRoutes = require('./routes/credential.routes');
const verificationRoutes = require('./routes/verification.routes');
const auditLogRoutes = require('./routes/audit-log.routes');

const app = express();

// ---------------------
// Security middleware
// ---------------------
app.use(helmet());
app.use(generalLimiter);

// ---------------------
// CORS
// ---------------------
app.use(
  cors({
    origin: config.corsOrigin,
    credentials: true,
  })
);

// ---------------------
// Body parsing
// ---------------------
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ---------------------
// Request logging
// ---------------------
if (config.nodeEnv !== 'test') {
  app.use(morgan('dev'));
}

// ---------------------
// API Routes
// ---------------------
app.use('/api/health', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/organizations', organizationRoutes);
app.use('/api/issuers', issuerRoutes);
app.use('/api/issuer-keys', issuerKeyRoutes);
app.use('/api/credentials', credentialRoutes);
app.use('/api/verifications', verificationRoutes);
app.use('/api/audit-logs', auditLogRoutes);

// ---------------------
// Error handling
// ---------------------
app.use(notFound);
app.use(errorHandler);

module.exports = app;
