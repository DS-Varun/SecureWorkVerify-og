# SecureWork Verify

A document-credential verification platform that prevents fraudulent or tampered document submissions in workplaces.

Trusted organizations issue digitally signed credentials. HR teams and users verify submitted documents against stored cryptographic hashes and digital signatures — without blockchain.

---

## Architecture Overview

```
┌──────────────┐       HTTPS + JWT       ┌──────────────────────┐
│   Frontend   │ ◄─────────────────────► │      Backend         │
│   (React)    │                         │  (Node.js + Express) │
└──────────────┘                         └──────────┬───────────┘
                                                    │
                                 ┌──────────────────┼──────────────────┐
                                 ▼                  ▼                  ▼
                          ┌────────────┐    ┌──────────────┐   ┌─────────────┐
                          │  MongoDB   │    │   Document   │   │  Key Store  │
                          │ (Database) │    │   Storage    │   │ (File-sys)  │
                          └────────────┘    └──────────────┘   └─────────────┘
```

| Layer          | Technology                                  |
|----------------|---------------------------------------------|
| Frontend       | React (JavaScript) via Vite                 |
| Backend        | Node.js + Express.js                        |
| Database       | MongoDB via Mongoose                        |
| Authentication | JWT + bcrypt                                |
| Crypto         | SHA-256 hashing + Ed25519 digital signatures|
| Audit          | Hash-chained append-only log in MongoDB     |

### Roles

| Role     | Description                                          | Self-registrable? |
|----------|------------------------------------------------------|-------------------|
| ADMIN    | Platform administrator. Manages orgs, issuers, users.| No — seeded only  |
| ISSUER   | Issues digitally signed credentials.                 | No — promoted      |
| HR       | Verifies user-submitted documents.                   | No — promoted      |
| USER     | Default registration role. Document holder.          | **Yes**            |
| AUDITOR  | Read-only reviewer of hash-chained audit logs.       | No — promoted      |

### Core Workflow

**Issuing:** Issuer uploads document → SHA-256 hash → Ed25519 signature → credential stored with audit trail.

**Verifying:** HR/User uploads document → hash compared → signature verified → issuer status checked → trust level computed → evidence breakdown returned.

**Auditing:** Every security-sensitive operation → hash-chained, sequence-numbered audit record → tamper detection via chain validation.

---

## Quick Start

See [SETUP.md](SETUP.md) for detailed step-by-step instructions.

```bash
cd backend
npm install
cp .env.example .env    # Edit with your values
npm run seed            # Create admin user
npm run dev             # Start development server
```

API available at **http://localhost:5000**.

---

## API Endpoints

### Health
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/health` | No | Health check |

### Authentication
| Method | Endpoint | Auth | Rate Limit | Description |
|--------|----------|------|------------|-------------|
| POST | `/api/auth/register` | No | 10/15min | Register new user |
| POST | `/api/auth/login` | No | 10/15min | Login, receive JWT |
| GET | `/api/auth/me` | JWT | — | Get authenticated profile |

### Organizations
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/organizations` | ADMIN | Create organization |
| GET | `/api/organizations` | ADMIN | List organizations |
| GET | `/api/organizations/:id` | ADMIN | Get organization details |
| PATCH | `/api/organizations/:id/verify` | ADMIN | Submit verification |
| PATCH | `/api/organizations/:id/approve` | ADMIN | Approve organization |
| PATCH | `/api/organizations/:id/suspend` | ADMIN | Suspend organization |
| PATCH | `/api/organizations/:id/revoke` | ADMIN | Revoke organization |

### Issuers
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/issuers` | ADMIN | Create issuer |
| GET | `/api/issuers` | ADMIN | List issuers |
| GET | `/api/issuers/:id` | ADMIN | Get issuer details |
| PATCH | `/api/issuers/:id/approve` | ADMIN | Approve issuer |
| PATCH | `/api/issuers/:id/suspend` | ADMIN | Suspend issuer |
| PATCH | `/api/issuers/:id/revoke` | ADMIN | Revoke issuer |

### Issuer Keys
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/issuer-keys/:issuerId/generate` | ADMIN | Generate Ed25519 keypair |
| GET | `/api/issuer-keys/:issuerId` | ADMIN, ISSUER | Get public key info |

### Credentials
| Method | Endpoint | Auth | Rate Limit | Description |
|--------|----------|------|------------|-------------|
| POST | `/api/credentials/issue` | ISSUER | — | Issue signed credential |
| GET | `/api/credentials` | Role-scoped | — | List credentials |
| GET | `/api/credentials/:id` | Role-scoped | — | Get credential details |
| GET | `/api/credentials/:id/versions` | Role-scoped | — | Get credential versions |
| POST | `/api/credentials/:id/versions` | ISSUER | — | Add new version |
| PATCH | `/api/credentials/:id/revoke` | ISSUER | — | Revoke credential |
| GET | `/api/credentials/:id/timeline` | Role-scoped | — | Lifecycle timeline (M6) |

### Verifications
| Method | Endpoint | Auth | Rate Limit | Description |
|--------|----------|------|------------|-------------|
| POST | `/api/verifications/verify` | HR, USER | 30/15min | Verify document |
| GET | `/api/verifications` | Role-scoped | — | Verification history |
| GET | `/api/verifications/:id` | Role-scoped | — | Verification details |
| GET | `/api/verifications/:id/evidence` | Role-scoped | — | Evidence trail |

### Audit Logs (M6)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/audit-logs` | ADMIN, AUDITOR | Paginated, filterable audit log |
| GET | `/api/audit-logs/validate` | ADMIN, AUDITOR | Hash-chain integrity validation |

---

## Running Tests

```bash
cd backend

# Run all tests
npm test

# Run with verbose output
npm run test:verbose
```

Tests require a running MongoDB instance. They use a dedicated test database (`securework-verify-test`).

---

## Security Features (M7)

- **Rate limiting:** Auth (10/15min), verification (30/15min), global (100/15min)
- **Helmet:** Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- **CORS:** Restricted to configured frontend origin
- **Input validation:** express-validator on every endpoint
- **Password security:** bcrypt with 12 salt rounds, never exposed in API responses
- **JWT:** Configurable expiration, validated on every protected route
- **Error handling:** Standardized error responses, no stack traces in production
- **Audit chain:** SHA-256 hash-chained, sequence-numbered, tamper-detectable

---

## Project Structure

```
crypto/
├── backend/
│   ├── keys/               # Ed25519 private keys (gitignored)
│   ├── uploads/            # Uploaded documents (gitignored)
│   ├── scripts/seed.js     # Admin user seed script
│   ├── src/
│   │   ├── config/         # Environment configuration
│   │   ├── controllers/    # Route handlers (auth, org, issuer, credential, verification, audit)
│   │   ├── middleware/     # Auth, RBAC, rate limiting, file upload, error handling
│   │   ├── models/         # Mongoose schemas
│   │   ├── routes/         # Express route definitions
│   │   ├── services/       # Business logic layer
│   │   ├── utils/          # Helpers (API response, canonical JSON)
│   │   ├── validators/     # Input validation
│   │   └── app.js          # Express app setup
│   ├── tests/              # Jest + Supertest integration tests
│   ├── server.js           # Entry point
│   └── package.json
├── frontend/               # React frontend (Vite)
├── docs/                   # Documentation
├── PROJECT_RULES.md        # Canonical project rules
├── SETUP.md                # Local development setup guide
└── README.md               # ← You are here
```

---

## License

This project is for educational purposes.
# SecureWorkVerify-og
