# SecureWork Verify — Local Development Setup Guide

> Step-by-step guide to get SecureWork Verify running on your local machine.

---

## Prerequisites

| Requirement | Version | Check command |
|---|---|---|
| Node.js | 18+ (LTS recommended) | `node --version` |
| npm | 9+ | `npm --version` |
| MongoDB | 7.x | `mongosh --eval "db.version()"` |
| Git | Any recent | `git --version` |

### Install MongoDB locally

**Windows:** Download from [mongodb.com/try/download/community](https://www.mongodb.com/try/download/community) and install as a Windows service.

**macOS:** `brew install mongodb-community && brew services start mongodb-community`

**Linux:** Follow the [official MongoDB installation guide](https://www.mongodb.com/docs/manual/installation/).

Verify MongoDB is running:
```bash
mongosh --eval "db.version()"
```

---

## Step 1: Clone the repository

```bash
git clone <repository-url>
cd crypto
```

---

## Step 2: Backend setup

```bash
cd backend

# Install dependencies
npm install
```

---

## Step 3: Configure environment variables

```bash
# Copy the example environment file
cp .env.example .env
```

Edit `backend/.env` and set your values:

| Variable | Description | Default |
|---|---|---|
| `PORT` | Server port | `5000` |
| `NODE_ENV` | Environment | `development` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/securework-verify` |
| `JWT_SECRET` | **CHANGE THIS** — secret for JWT signing | *(required)* |
| `JWT_EXPIRES_IN` | JWT token expiration | `24h` |
| `CORS_ORIGIN` | Frontend origin URL | `http://localhost:5173` |
| `KEY_STORAGE_PATH` | Path for Ed25519 private keys | `./keys` |
| `DOCUMENT_STORAGE_PATH` | Path for uploaded documents | `./uploads` |
| `MAX_FILE_SIZE_MB` | Max upload file size | `10` |

> ⚠️ **Security:** Always change `JWT_SECRET` from the example value. In production, use a cryptographically random string (minimum 64 characters).

---

## Step 4: Seed the admin user

The admin user is the only way to manage organizations, issuers, and roles. It cannot be created through the API.

Set the seed credentials in `.env`:
```
ADMIN_NAME=System Admin
ADMIN_EMAIL=admin@securework.local
ADMIN_PASSWORD=Admin@123456
```

Then run:
```bash
npm run seed
```

Expected output:
```
✅ Admin user created: admin@securework.local
```

---

## Step 5: Start the backend

```bash
# Development mode (auto-restart on changes)
npm run dev

# Production mode
npm start
```

The API is now available at **http://localhost:5000**.

---

## Step 6: Verify the server

```bash
curl http://localhost:5000/api/health
```

Expected response:
```json
{
  "success": true,
  "message": "Health check passed",
  "data": {
    "api": "operational",
    "database": "connected",
    "timestamp": "2026-08-30T06:00:00.000Z"
  }
}
```

---

## Step 7: Run tests

Tests require a running MongoDB instance. They use a dedicated test database (`securework-verify-test`) that is cleaned automatically.

```bash
# Run all tests
npm test

# Run with verbose output
npm run test:verbose

# Run a specific test file
npm test -- tests/auth.test.js
```

---

## Common Workflows

### Register → Login → Use API

```bash
# 1. Register a new user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "email": "user@test.com", "password": "Password123!"}'

# 2. Login and get JWT token
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@test.com", "password": "Password123!"}'
# → Copy the token from the response

# 3. Use the token for authenticated requests
curl http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer <your-token-here>"
```

### Admin: Create Organization → Approve Issuer → Issue Credential

```bash
# Login as admin
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@securework.local", "password": "Admin@123456"}'

# Create organization
curl -X POST http://localhost:5000/api/organizations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{"name": "ABC University", "type": "EDUCATIONAL", "domain": "abc.edu"}'
```

---

## Troubleshooting

### Server won't start — missing environment variables
```
❌ Missing required environment variables:
   - MONGODB_URI
   - JWT_SECRET
```
**Fix:** Copy `.env.example` to `.env` and fill in all required values.

### MongoDB connection refused
```
MongoServerError: connect ECONNREFUSED 127.0.0.1:27017
```
**Fix:** Ensure MongoDB is installed and running. On Windows, check Services for `MongoDB Server`.

### Rate limit exceeded (429)
```json
{"success": false, "error": {"message": "Too many requests..."}}
```
**Fix:** Wait 15 minutes, or restart the server to reset rate limit counters in development.

### Tests fail — database not a test database
```
FATAL: Destructive test cleanup aborted. Database is not a dedicated test database.
```
**Fix:** Ensure your test `MONGODB_URI` contains "test" in the database name. The test setup defaults to `securework-verify-test`.

---

## Directory Structure

```
crypto/
├── backend/
│   ├── keys/               # Ed25519 private keys (dev only, gitignored)
│   ├── uploads/            # Uploaded documents (dev only, gitignored)
│   ├── scripts/seed.js     # Admin user seed script
│   ├── src/
│   │   ├── config/         # Environment configuration
│   │   ├── controllers/    # Route handlers
│   │   ├── middleware/     # Auth, RBAC, rate limiting, error handling
│   │   ├── models/         # Mongoose schemas (User, Organization, Issuer, etc.)
│   │   ├── routes/         # Express route definitions
│   │   ├── services/       # Business logic layer
│   │   ├── utils/          # Helpers (API response, canonical JSON)
│   │   ├── validators/     # Input validation (express-validator)
│   │   └── app.js          # Express app setup
│   ├── tests/              # Jest + Supertest integration tests
│   ├── server.js           # Entry point
│   ├── jest.config.js      # Test configuration
│   ├── .env.example        # Environment template
│   └── package.json
├── frontend/               # React frontend (Vite)
├── docs/                   # Documentation
├── PROJECT_RULES.md        # Canonical project rules
├── SETUP.md                # ← You are here
└── README.md               # Project overview
```

---

## Security Notes

- **Passwords:** Hashed with bcrypt (12 salt rounds). Plaintext never stored.
- **JWT:** Stored in client-side storage. Production should use httpOnly cookies.
- **Private keys:** Stored on local filesystem in development. Production must use KMS/HSM.
- **Rate limiting:** Auth endpoints (10/15min), verification (30/15min), global (100/15min).
- **Audit log:** Hash-chained, append-only. Detects tampering and deletions within the chain.
- **CORS:** Restricted to configured frontend origin.
- **Helmet:** Security headers (CSP, HSTS, X-Frame-Options, etc.) enabled by default.

---

*Last updated: 2026-09-21*
