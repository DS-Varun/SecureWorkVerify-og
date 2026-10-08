# SecureWork Verify — Viva Preparation

All questions and answers are based strictly on the actual implementation.

---

## Project Basics

**Q: What is SecureWork Verify?**  
A: It is a digital document credential verification platform. Organizations issue digitally signed credentials, and anyone (HR, students, institutions) can verify whether a submitted document is genuine, tampered, revoked, or expired. It uses SHA-256 hashing and Ed25519 digital signatures — without blockchain.

**Q: What problem does it solve?**  
A: In workplaces and academic institutions, people sometimes submit fake or tampered certificates. Traditional verification methods require calling the issuing institution manually. SecureWork Verify automates this by checking cryptographic proofs — so verification is instant and tamper-proof.

**Q: Is this blockchain-based?**  
A: No. There is no blockchain. We use standard public-key cryptography: SHA-256 for document hashing and Ed25519 for digital signatures. The trust is rooted in the issuer's key pair and the organization's verified status.

**Q: What technologies does the project use?**  
A: Backend: Node.js + Express.js + MongoDB + Mongoose. Frontend: React + Vite. Authentication: JWT + bcryptjs. Cryptography: Node.js crypto (SHA-256) + tweetnacl (Ed25519). Testing: Jest + Supertest.

---

## Architecture

**Q: Describe the system architecture.**  
A: Three-layer architecture: React frontend communicates via JWT-authenticated REST API to the Express backend. The backend stores data in MongoDB (credentials, users, audit logs), stores uploaded documents on the filesystem, and stores Ed25519 private keys on a protected filesystem path. There is no external dependency that requires payment.

**Q: What are the main backend layers?**  
A: Controllers handle HTTP requests and responses. Services contain all business logic (crypto, verification engine, audit chaining). Models define MongoDB schemas. Middleware handles authentication, authorization, rate limiting, file upload, and error handling.

**Q: What is the key store?**  
A: The key store is the server-side filesystem directory (backend/keys/). When ADMIN approves an issuer, an Ed25519 keypair is generated. The public key is stored in MongoDB. The private key is stored only on the filesystem — it is never written to MongoDB and never returned by the API.

---

## Frontend

**Q: What does the frontend do?**  
A: It is a React single-page application that lets users log in, register, verify documents (drag-drop upload), view verification history, see evidence trails, manage credentials, and view audit logs. Navigation and access are role-aware — different roles see different menus and pages.

**Q: How does the frontend authenticate?**  
A: After login, the backend returns a JWT token. The frontend stores it in localStorage and attaches it as `Authorization: Bearer <token>` on every API call. If the server returns 401, the frontend clears the token and redirects to login.

**Q: Does the frontend have access to private keys?**  
A: No. Private keys are stored only on the server filesystem. The frontend never receives or stores any private key material.

---

## Backend

**Q: How is the backend structured?**  
A: Entry point: server.js → connects MongoDB → starts Express. App: src/app.js → middleware (helmet, cors, rate limit, express-validator) → routes → controllers → services. All business logic lives in services/.

**Q: How does file upload work?**  
A: multer middleware accepts PDF, PNG, and JPEG files up to 10 MB. The field name is `document`. The file buffer is passed to the verification or credential issuance service — the raw bytes never touch the route handler.

---

## Database

**Q: What database does the project use?**  
A: MongoDB (NoSQL, document-oriented). Connected via Mongoose ODM.

**Q: What are the main collections?**  
A: Users, Organizations, Issuers, IssuerKeys, Documents, Credentials, CredentialVersions, Verifications, VerificationEvidence, AuditLogs.

**Q: How are tests isolated from the development database?**  
A: The test setup.js configures `process.env.MONGODB_URI` to use `mongodb://localhost:27017/securework-verify-test`. The testHelper.js asserts the connection is to a database with "test" in its name before any destructive cleanup operation.

---

## Authentication

**Q: How does user registration work?**  
A: POST /api/auth/register accepts name, email, password. The role field is ignored — the server always assigns USER. The password is hashed with bcryptjs (12 salt rounds) before storing. The passwordHash field has `select: false` in Mongoose so it is never returned.

**Q: How does JWT work in this project?**  
A: After login, the server signs a JWT containing userId and role using the JWT_SECRET. The token expires in JWT_EXPIRES_IN (default 24h). Every protected route uses an auth middleware that verifies the token and attaches req.user.

**Q: Why bcrypt with 12 rounds?**  
A: bcrypt is designed to be slow — making brute-force attacks computationally expensive. 12 rounds provides a good balance between security and performance (~300ms per hash on typical hardware).

---

## RBAC

**Q: What are the five roles?**  
A: ADMIN, ISSUER, HR, USER, AUDITOR.

**Q: Who can register as what role?**  
A: Public registration always creates USER. ADMIN, ISSUER, HR, and AUDITOR are privileged roles — they can only be assigned by an ADMIN after the user is registered.

**Q: What can an AUDITOR do?**  
A: An AUDITOR has read-only access to audit logs (GET /api/audit-logs, GET /api/audit-logs/validate) and can view verification records. An AUDITOR cannot create, modify, or delete anything. Attempting to POST/PATCH/DELETE on audit endpoints returns 403.

**Q: What can a USER do?**  
A: A USER can verify documents (POST /api/verifications/verify) and view their own verification history. They cannot see other users' verifications.

---

## SHA-256

**Q: What is SHA-256 and why do you use it?**  
A: SHA-256 (Secure Hash Algorithm 256-bit) is a one-way cryptographic hash function. We use it to compute a fixed-length fingerprint of a document. If even one byte in the document changes, the hash changes completely. We compare the hash of the uploaded file against the stored hash to detect tampering.

**Q: How is SHA-256 computed in your project?**  
A: `crypto.createHash('sha256').update(fileBuffer).digest('hex')` — the Node.js built-in `crypto` module computes a 64-character lowercase hex string from the raw file bytes.

**Q: Does SHA-256 alone prove authenticity?**  
A: No. SHA-256 proves identity (same bytes = same hash), not authenticity (who created it). A forger who copies the original document bytes would get the same hash. Authenticity requires the Ed25519 signature — only the genuine issuer who holds the private key can produce a valid signature.

**Q: What happens when a document is modified?**  
A: The SHA-256 hash of the modified file will not match the stored expected hash. The verification result becomes ALTERED with trust level LEVEL_0_UNKNOWN.

---

## Ed25519

**Q: What is Ed25519 and why did you choose it?**  
A: Ed25519 is an elliptic curve digital signature algorithm using the Edwards curve. We chose it because: it generates short (64-byte) signatures, has excellent security properties, is fast, and is available in tweetnacl (a well-audited JavaScript library). It is the modern recommended alternative to RSA for signatures.

**Q: How does Ed25519 signing work in your project?**  
A: When a credential is issued: the SHA-256 hash of the document (as hex) is converted to bytes, then `nacl.sign.detached(messageBytes, secretKeyBytes)` produces a 64-byte signature. The signature is stored in base64 alongside the credential.

**Q: How does Ed25519 verification work?**  
A: During document verification: `nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes)` returns true or false. If true, we know the holder of the private key signed exactly these document bytes.

**Q: Where are private keys stored?**  
A: Only on the server filesystem (`backend/keys/`). They are never written to MongoDB. They are never returned by any API endpoint. Only the keystore.service.js reads them during issuance.

---

## Key Lifecycle

**Q: What is the issuer key lifecycle?**  
A: ACTIVE (key is valid for signing) → RETIRED (issuer was suspended or revoked, key still exists for verification) → COMPROMISED (key was reported compromised).

**Q: What happens when a key is COMPROMISED?**  
A: Any verification against a credential signed by that key returns KEY_COMPROMISED with trust level LEVEL_3_INTEGRITY_VERIFIED. The signature may still be mathematically valid, but the key can no longer be trusted.

**Q: Why keep historical public keys?**  
A: So we can verify signatures on credentials that were issued before a key was rotated, suspended, or compromised. Verification looks up the specific IssuerKey that was active at the time of issuance.

---

## Digital Signatures

**Q: What does the Ed25519 signature prove?**  
A: It proves that the holder of the private key (the authorized issuer) signed the exact SHA-256 hash of this document. If the hash is correct AND the signature verifies against the issuer's historical public key, we know the document is genuine and was authorized by that issuer.

**Q: Can the signature be faked?**  
A: No. Without the private key, it is computationally infeasible to produce a valid Ed25519 signature. This is the security guarantee of asymmetric cryptography.

---

## Verification Engine

**Q: How does the verification process work?**  
A: 4 independent checks are run:
1. SHA-256 hash of uploaded file vs stored expected hash
2. Ed25519 signature verification using historical public key
3. Issuer status (ACTIVE? SUSPENDED? REVOKED?) + key status (COMPROMISED?)
4. Credential status (ACTIVE? REVOKED? EXPIRED?) + organization trust (VERIFIED, ACTIVE?)

The result and trust level are determined by which check fails first, in priority order.

**Q: Why are CREDENTIAL_REVOKED and CREDENTIAL_EXPIRED not "FAKE"?**  
A: Because the document is still cryptographically authentic — the hash matches and the signature is valid. The credential was legitimately issued but has since been administratively revoked or has passed its expiry date. These are different from ALTERED or SIGNATURE_INVALID.

**Q: What is trust level?**  
A: A categorical score from LEVEL_0_UNKNOWN to LEVEL_5_CURRENTLY_VALID. It indicates how far through the verification pipeline the document passed before a failure was detected (or it passed completely).

---

## Audit Hash Chain

**Q: What is the audit hash chain?**  
A: Every security-sensitive operation creates an AuditLog entry. Each entry contains a `currentHash` computed as SHA-256 of all its fields plus the previous entry's hash (`previousHash`). This creates a chain where any modification to a past entry breaks all subsequent hashes.

**Q: What is the genesis hash?**  
A: The first audit entry uses `SHA-256("GENESIS_SECUREWORK_VERIFY")` as its `previousHash`. This is a deterministic starting point that ties the chain to this specific application.

**Q: How do you detect tampering?**  
A: The verifyChain() function reads all entries in sequence order and:
1. Checks there are no gaps in sequence numbers
2. Checks each entry's previousHash matches the prior entry's currentHash
3. Recomputes each entry's currentHash and compares it to the stored value

**Q: What are the limitations of the audit chain?**  
A: A MongoDB DBA with direct database access can delete records — the chain cannot prevent this. It only detects modification or deletion through the API. A multi-instance deployment would need database-level coordination for sequence numbers.

---

## MongoDB

**Q: What MongoDB collections does the project use?**  
A: Users, Organizations, Issuers, IssuerKeys, Documents, Credentials, CredentialVersions, Verifications, VerificationEvidence, AuditLogs.

**Q: Why MongoDB and not SQL?**  
A: The credential, verification, and audit data has variable schemas (metadata fields, evidence details). MongoDB's flexible document model handles this well. The Mongoose ODM provides schema validation where needed.

---

## API

**Q: What HTTP status codes does your API use?**  
A: 200 (success), 201 (created), 400 (bad request / validation), 401 (unauthenticated), 403 (forbidden), 404 (not found), 409 (conflict — duplicate, wrong state), 415 (unsupported media type), 429 (rate limit exceeded), 500 (server error).

**Q: What is the API response format?**  
A: Always `{success: true, data: {...}}` for success, and `{success: false, error: {message: "..."}}` for errors. Stack traces are never included in production error responses.

---

## Security

**Q: How is the application secured?**  
A: JWT authentication, bcrypt passwords (12 rounds), RBAC middleware, Helmet security headers, CORS restriction, rate limiting, input validation, standardized errors (no information leakage), private keys never in DB or API, audit hash chain.

**Q: What is Helmet?**  
A: An npm package that sets HTTP security headers: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, removes X-Powered-By.

**Q: What is rate limiting?**  
A: express-rate-limit middleware restricts auth endpoints to 10 requests per 15 minutes, verification to 30 per 15 minutes, and global endpoints to 100 per 15 minutes per IP. Prevents brute-force attacks.

---

## Testing

**Q: What testing framework is used?**  
A: Jest as the test runner, Supertest for HTTP integration tests.

**Q: What is the test count?**  
A: 157 tests across 9 suites. All pass. Zero failures, zero skipped.

**Q: What do the tests cover?**  
A: Auth (register/login/JWT), organizations (CRUD/trust lifecycle/RBAC), issuers (lifecycle/key generation), credentials (issuance/versioning/revocation), verification engine (all 13 result states), audit hash chain (chaining, concurrency, tamper detection), M6 auditor API, M7 security headers and hardening, and health endpoint.

**Q: Why is maxWorkers: 1 in jest.config.js?**  
A: Jest spawns multiple child processes for parallel test execution. On Windows when the project path contains spaces, the inter-process communication (IPC) channel fails silently. `maxWorkers: 1` forces all tests to run in the main process, which is equivalent to `--runInBand`. It does not affect test correctness.

---

## Limitations

**Q: What are the known limitations?**  
A: Audit chain cannot prevent DBA deletion; single-process serialization doesn't scale to multiple instances; private keys are on filesystem not HSM; no email verification; no JWT refresh tokens; no official source API integrations.

---

## Future Scope

**Q: What would you add in a production version?**  
A: Cloud KMS for private keys (AWS KMS, GCP Cloud HSM), official source API integrations (university/government registrars), distributed audit coordination, email verification, JWT refresh tokens, webhook notifications, admin analytics dashboard, mobile app.
