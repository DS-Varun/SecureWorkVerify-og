# SecureWork Verify — My Role and Contribution

This document explains what each part of the project does and how to articulate
your contribution during a viva or presentation.

---

## Project Summary in One Sentence

SecureWork Verify is a full-stack credential verification platform that uses
SHA-256 document hashing and Ed25519 digital signatures to allow trusted
organizations to issue authenticated credentials, and allow anyone to verify
whether a submitted document is genuine, altered, revoked, or expired.

---

## What You Built

### Backend (M1–M7)

**M1 — Authentication and RBAC**

You designed and implemented the authentication layer. This includes:
- User registration that always assigns the USER role (prevents privilege escalation)
- bcryptjs password hashing with 12 salt rounds
- JWT-based stateless authentication
- Role-based access control middleware (`requireRole(...)`)
- Rate limiting on auth endpoints to prevent brute-force attacks
- The initial ADMIN seed script

Why this was non-trivial: the RBAC middleware had to correctly scope data responses by role (e.g. a USER can only see their own verifications, not everyone else's), not just gate access at the route level.

---

**M2 — Organizations and Trust**

You built the organization trust lifecycle:
- Create → Pending → Verified → Suspended → Revoked
- Verification requires evidence notes and a reference (not just a click)
- Status transitions are guarded — cannot verify a revoked org, cannot suspend a pending org, etc.
- Full audit trail per transition

Why this matters: the entire verification trust chain depends on the organization status. A credential issued by an issuer from a non-verified organization results in MANUAL_REVIEW, not VERIFIED.

---

**M3 — Issuers, Issuer Keys, Credentials and Versioning**

This is the most technically involved backend module:

- Issuer registration under verified organizations
- ADMIN approval auto-generates an Ed25519 keypair using tweetnacl
- Public key stored in MongoDB (IssuerKey document)
- Private key stored ONLY on the filesystem (backend/keys/) — never in the database
- Credential issuance: compute SHA-256 of the uploaded file, sign the hash with the issuer's private key, store the hash + signature + public key reference
- Credential versioning: each revised version has its own hash and signature; historical versions are preserved for verification of old documents
- Revocation: a credential can be revoked with a mandatory reason; REVOKED credentials produce CREDENTIAL_REVOKED (authentic but revoked), not ALTERED or NOT_FOUND

Key design decision: private keys never touch MongoDB. The keystore service reads the private key from disk only during signing, and immediately discards the reference. Verification uses only the public key.

---

**M4 — Verification Engine and Evidence**

The core intellectual contribution of the project:

- 4 independent checks executed per verification:
  1. SHA-256 hash integrity
  2. Ed25519 signature verification (using historical public key)
  3. Issuer trust (active status, key compromise)
  4. Credential status (active/revoked/expired) and organization trust
- 13 categorical result states with precise semantic meaning
- 6 trust levels mapping to how far through the pipeline the document passed
- Per-verification VerificationEvidence records (one per check)
- Hash chain audit entry written after every verification

The non-trivial part: correctly ordering the priority of failures. For example, ALTERED (hash mismatch) must be caught before checking the signature (you cannot verify a signature of a modified document). KEY_COMPROMISED must produce a different result than ISSUER_SUSPENDED even though both have LEVEL_4 trust.

---

**M6 — Auditor API and Lifecycle Timeline**

- Paginated, filterable audit log endpoint for ADMIN and AUDITOR roles
- Hash chain integrity validation endpoint
- Credential lifecycle timeline endpoint that aggregates events from AuditLog
- AUDITOR role is strictly read-only — all write attempts return 403

---

**M7 — Security Hardening**

- Helmet configuration with Content-Security-Policy, HSTS, X-Frame-Options
- Global CORS restriction to configured frontend origin
- Rate limiting on three tiers
- Standardized error response format — no stack traces, no internal paths in production responses
- 400 for malformed JSON and validation failures
- 404 for unknown routes
- Role escalation tests verify that registering as ADMIN or AUDITOR is blocked at the API level

---

### Audit Hash Chain

The audit chain is a cryptographic mechanism that links every audit entry:
- `currentHash = SHA-256(all fields + previousHash)`
- Genesis uses a fixed domain constant
- Any modification to a past entry breaks all subsequent hashes
- A separate service (verifyChain) can detect gaps, broken linkages, and hash mismatches
- An in-process write queue serializes concurrent audit writes

This is not a standard off-the-shelf component — you designed and implemented it from scratch using the Node.js crypto module.

---

### Frontend (M5)

You built a full React 19 + React Router 7 single-page application:
- Role-aware routing and navigation
- JWT session management (AuthContext)
- Document verification with drag-drop file upload
- Evidence trail display showing each of the 4 checks
- All 13 verification states rendered with semantic explanations
- Credential management pages (issue, list, revoke, timeline)
- Organization and issuer management
- Audit log viewer with chain validation

---

## How to Talk About It in a Viva

### On the core idea

"The fundamental problem is that credentials like certificates and degree documents are easy to forge or tamper with. My system solves this by having trusted issuers register a cryptographic fingerprint of each document — a SHA-256 hash — and sign it with their private Ed25519 key. Anyone can then verify a submitted document by recomputing its hash, checking the signature with the public key, and checking the issuer and organization trust status."

### On SHA-256

"I use SHA-256 from Node.js's built-in crypto module. It produces a 64-character hex fingerprint of any file. If even one bit of the file changes, the hash changes completely. When a document is verified, we compute the hash of the uploaded file and compare it to the stored hash. If they differ, the result is ALTERED."

### On Ed25519

"I use Ed25519 digital signatures via the tweetnacl library. When an issuer issues a credential, the system uses their private key to sign the SHA-256 hash. This signature is stored alongside the credential. During verification, we use only the public key to verify the signature — the private key never leaves the server filesystem."

### On the audit chain

"Every security-sensitive operation creates an audit log entry. Each entry's hash depends on all its fields AND the previous entry's hash, forming a chain. If anyone modifies a past entry, that entry's hash will no longer match what the next entry expects as its previousHash. My verifyChain function re-reads all entries and recomputes every hash to detect any tampering."

### On RBAC

"There are five roles: ADMIN, ISSUER, HR, USER, and AUDITOR. Registration always creates a USER. Privileged roles must be assigned by an ADMIN. Each route uses a requireRole middleware that returns 403 if the authenticated user's role isn't in the allowed list."

### On verification results

"The system has 13 categorical result states. The key semantic insight is that CREDENTIAL_REVOKED and CREDENTIAL_EXPIRED are different from ALTERED. A revoked credential was genuinely issued — the signature is valid — but the organization chose to revoke it. That's different from a forged or tampered document."

### On the test suite

"I have 157 integration tests across 9 test suites using Jest and Supertest. The tests cover every role's access permissions, every trust lifecycle transition, the verification engine with multiple scenarios including tampered documents, revoked credentials, compromised keys, suspended issuers, and the audit hash chain including concurrency and tampering detection."

---

## Questions You Might Struggle With — Prepare These

**"What if the private key is compromised?"**  
The ADMIN can mark the issuerKey as COMPROMISED via the API. Any verification using that key will then return KEY_COMPROMISED, alerting the verifier to seek manual confirmation. The key cannot be deleted — only marked to prevent trusting credentials signed by it.

**"Couldn't someone just copy the original file?"**  
Yes — but to forge a credential, the attacker would need both the original file bytes (for the correct hash) AND a valid Ed25519 signature. Without the issuer's private key, they cannot produce a valid signature. The system would return SIGNATURE_INVALID.

**"What stops someone from registering as ADMIN?"**  
The registration endpoint always assigns USER regardless of what role is sent in the request body. The test suite explicitly verifies this — any attempt to register as ADMIN or AUDITOR still results in a USER account.

**"Is your audit log truly immutable?"**  
Not absolutely — a MongoDB DBA with direct database access could delete or truncate records. This is a documented limitation. What the hash chain provides is tamper detection through the application layer: any modification, insertion, or deletion of individual records is detectable by the verifyChain function.
