# PROJECT_RULES.md — SecureWork Verify

> **Authority:** This file is the canonical rule set for the SecureWork Verify project.
> It is derived from `implementation_plan.md` (approved, v1) and
> `SecureWork_Verify_Trust_Model_v2.md` (trust model, supersedes conflicting parts of the plan).
> **No rule in this file invents new architecture. No new dependency is added.**
> When this file conflicts with older notes, this file wins.
> When this file conflicts with a future user instruction, the user instruction wins.

---

## 1. Project Purpose

SecureWork Verify is a document-credential verification platform that prevents fraudulent or
tampered document submissions in workplaces, institutions, and hiring processes.

Trusted organizations issue digitally signed credentials.
HR teams and users verify submitted documents against stored cryptographic hashes and digital
signatures — **without blockchain**.

The system distinguishes five separate facts that must each be independently verified:

1. **Integrity** — Is the submitted file byte-for-byte identical to the trusted original?
2. **Issuer authenticity** — Was the document signed by an authorized key from an authorized issuer?
3. **Institutional trust** — Is the organization/source itself trusted?
4. **Current validity** — Has the credential been revoked or expired?
5. **Evidence strength** — What evidence supports the verification result, and how strong is it?

> A SHA-256 hash proves only that two byte sequences are identical.
> It does NOT prove a document is genuine.
> A digital signature links a document hash to an issuer key.
> The trustworthiness of that key comes from the issuer approval process.

---

## 2. Technology Stack

| Layer | Technology | Notes |
|---|---|---|
| Frontend | React 18+ (JavaScript) via Vite | Not yet scaffolded |
| Backend | Node.js 18+ / Express 4.x | In development — `backend/` |
| Database | MongoDB 7.x via Mongoose 8.x | Single instance for v1 |
| File storage | **Local filesystem (default)** | `backend/keys/` for private keys; document storage adapter-switchable |
| Auth | JWT (`jsonwebtoken`) + `bcryptjs` | 24h expiry, configurable |
| Crypto | Node.js built-in `crypto` (SHA-256) + `tweetnacl` (Ed25519) | Server-side only |
| Audit | SHA-256 hash-chained append-only log in MongoDB | No delete/update operations |

### Zero-cost local-first requirement

The system MUST be fully functional with no paid external services in development:

- MongoDB runs locally (`mongodb://localhost:27017/securework-verify`)
- Private keys stored on local filesystem (`backend/keys/`, gitignored)
- Document files stored on local filesystem OR Firebase Storage (optional adapter)
- No mandatory cloud subscription required to run locally

Optional infrastructure adapters (future, non-breaking):
- KMS / HSM / Secrets Manager for private key storage (production swap)
- Firebase Storage / S3 / GCS for document storage (storage adapter abstraction)
- RFC 3161 timestamp authority (future trusted timestamping)
- External audit anchoring (future external checkpoint)

**No paid service may be a hard runtime dependency for local development.**

---

## 3. Roles

| Role | Description | Self-registrable? |
|---|---|---|
| ADMIN | Platform administrator. Manages orgs, issuers, trusted sources. | No — seeded only |
| ISSUER | Issues digitally signed credentials on behalf of an organization. | No — promoted by admin |
| HR | Verifies documents submitted by users in their organization. | No — promoted by admin |
| USER | Default public registration role. Document holder, job applicant, student, employee, etc. | **Yes — only this role** |
| AUDITOR | Read-only reviewer of hash-chained audit logs. | No — promoted by admin |

### Role assignment rules

- Public registration (`POST /api/auth/register`) MUST always create a `USER`.
- The registration endpoint MUST NOT accept a caller-supplied `role` field for privileged roles.
- Privileged roles (`ADMIN`, `ISSUER`, `HR`, `AUDITOR`) MUST only be assigned by an `ADMIN`
  through separate promotion endpoints — never through self-registration.
- The seed script creates the first `ADMIN` from environment variables (`ADMIN_EMAIL`,
  `ADMIN_PASSWORD`, `ADMIN_NAME`). This is the only path to the first admin account.

> **Terminology note:** `EMPLOYEE` (from earlier drafts) has been permanently replaced by `USER`
> across all models, routes, and documentation. Do not re-introduce `EMPLOYEE`.

---

## 4. Organization Trust Model

An organization is a legal or institutional entity (university, company, government body, etc.)
that can sponsor issuers.

### Organization fields (required)

```
_id
name
type                           // UNIVERSITY | COMPANY | CERTIFICATION_BODY | GOVERNMENT | OTHER
officialDomain
domainVerificationStatus
organizationVerificationStatus // PENDING | VERIFIED | SUSPENDED | REVOKED
verificationMethods[]          // ADMIN_REVIEW | DOMAIN_OWNERSHIP | OFFICIAL_REGISTRY |
                               //   INSTITUTIONAL_CONTACT | OTHER
verifiedAt
verifiedBy
status
createdBy
createdAt
updatedAt
```

### Organization trust rules

- Only `ADMIN` can create organizations.
- An organization starts `PENDING` and requires admin verification before issuers can be approved under it.
- Domain ownership verification establishes that the org controls the domain — it does NOT prove
  that every document on that domain is authentic.
- An inactive/revoked organization does NOT retroactively invalidate historical credentials.
  Historical credentials remain verifiable with appropriate status labels.

---

## 5. TrustedSource

A `TrustedSource` is an external official source (website, portal, API, repository) associated
with a verified organization that may be used as a secondary verification channel.

### TrustedSource fields

```
_id
organizationId
name
sourceType          // OFFICIAL_WEBSITE | VERIFICATION_PORTAL | API | DOCUMENT_REPOSITORY | OTHER
baseUrl
verificationEndpoint
domain
verificationStatus
verificationMethod
verificationToken
lastCheckedAt
status              // PENDING | ACTIVE | SUSPENDED | REVOKED
createdBy
verifiedBy
verifiedAt
createdAt
updatedAt
```

### TrustedSource rules

- Arbitrary user-supplied URLs MUST NOT automatically become trusted sources.
- A source MUST belong to an approved organization.
- `ADMIN` must approve a source before it can be used in verification.
- Domain ownership verification may be used as supporting evidence, not as sole proof.
- Every official-source retrieval MUST record exactly what evidence was obtained.
- Official-source verification is a separate verification mode — it does NOT replace cryptographic verification.

---

## 6. Issuer Authorization

An organization being trusted does NOT automatically make any of its users an issuer.
Issuer status requires a separate explicit authorization.

### Issuer lifecycle

```
USER
  -> submits issuer registration request
PENDING
  -> ADMIN review + authorization
ACTIVE
  -> (if needed)
SUSPENDED -> REVOKED
```

### Issuer fields (required)

```
_id
userId
organizationId
authorizationEvidence  // object: org invitation, admin approval, institutional email, etc.
status                 // PENDING | ACTIVE | SUSPENDED | REVOKED
approvedBy
approvedAt
suspendedAt
suspensionReason
revokedAt
revokedReason
createdAt
updatedAt
```

### Issuer trust rules

- An issuer with `status !== ACTIVE` MUST NOT be allowed to sign new credentials.
- The system MUST preserve the evidence that justified issuer approval (`authorizationEvidence`).
- An issuer being `REVOKED` does NOT retroactively make historical signed credentials fake.
  Historical credentials remain verifiable with appropriate status in the verification response.

---

## 7. IssuerKey Lifecycle

Keys are a first-class entity separate from the Issuer record.

### IssuerKey fields

```
_id
issuerId
keyId                  // filename reference: issuer_<mongoId>.key
algorithm              // always "Ed25519"
publicKey              // base64 — stored in MongoDB
privateKeyReference    // filesystem path reference only — key bytes never in MongoDB
status                 // ACTIVE | RETIRED | COMPROMISED | REVOKED
createdAt
activatedAt
retiredAt
compromisedAt
revokedAt
statusReason
```

### Key lifecycle rules

- Private keys MUST be stored on the filesystem (dev) or KMS (prod) — never in MongoDB.
- Private key bytes MUST NEVER be returned in any API response.
- Private key bytes MUST NEVER be sent to the frontend.
- Public keys MUST be preserved permanently — historical public keys are NEVER deleted.
  They are needed to verify previously signed credentials.
- When an issuer is revoked, the private key becomes unusable for new signing
  (achieved by changing `IssuerKey.status`, not by deleting the key file).
- Historical credential versions store the `issuerKeyId` used to sign them,
  so that key rotation does not break historical verification.

### Key compromise

If a private key is suspected stolen:

```
IssuerKey: ACTIVE -> COMPROMISED
```

Immediately:
- Stop all new signing with that key.
- Require `ADMIN` review.
- Preserve the public key and all historical signatures.
- Record the compromise timestamp.
- Audit the event (`ISSUER_KEY_COMPROMISED`).

**Do NOT automatically invalidate all historical credentials signed by a compromised key.**
The verification response MUST expose the key status, the signing timestamp, and the credential
timestamp, and let the human reviewer assess whether the credential predates the compromise.

---

## 8. Cryptographic Rules

| Operation | Algorithm | Location | Notes |
|---|---|---|---|
| Password hashing | bcrypt (12 rounds) | Server only | Never stored in plaintext |
| Document hashing | SHA-256 | Server only | Hex string output |
| Document signing | Ed25519 (tweetnacl) | Server only — reads key from filesystem | Never on client |
| Signature verification | Ed25519 (tweetnacl) | Server only — reads public key from MongoDB | Never on client |
| Audit hash chain | SHA-256 | Server only | Every audited event |

### SHA-256 rules

- A SHA-256 hash proves only byte-level identity of two files.
- The system MUST NOT claim a document is genuine based solely on a hash match.
- A hash match against a trusted credential record establishes integrity; authenticity requires
  a valid issuer signature and full lifecycle checks.
- For v1: exact original file bytes are required for cryptographic verification.
  Screenshots/scans of a document produce different hashes and MUST NOT yield `VERIFIED`.

### Ed25519 rules

- All Ed25519 operations are server-side only.
- Client-side SHA-256 (via `js-sha256`) is for display preview only — not for verification decisions.
- Keypairs are generated on issuer approval (`ACTIVE` status transition).
- One keypair per issuer per key lifecycle period.

---

## 9. CredentialVersion

Credentials have a version history to support legitimate document corrections.

### CredentialVersion fields

```
_id
credentialId
versionNumber
documentId
documentHash        // SHA-256 hex of the document at this version
signature           // Ed25519 signature of documentHash, base64
issuerKeyId         // which key signed this version
issuedAt
supersedesVersionId // nullable — links to previous version
changeReason
status
createdAt
```

### Versioning rules

- Each credential tracks its `currentVersionId`.
- Old versions remain permanently in the database for auditability.
- The system distinguishes between:
  - `ALTERED` — hash mismatch against a trusted original with no published new version
  - `LEGITIMATE_NEW_VERSION` — issuer explicitly published a corrected version
- Versions are never deleted.

---

## 10. VerificationEvidence

Every verification result must be backed by recorded evidence.

### VerificationEvidence fields

```
_id
verificationId
evidenceType         // OFFICIAL_DOCUMENT | OFFICIAL_RECORD | DIGITAL_SIGNATURE |
                     //   HASH_MATCH | ISSUER_STATUS | CREDENTIAL_STATUS |
                     //   DOMAIN_VERIFICATION | MANUAL_REVIEW
sourceId             // nullable — TrustedSource reference
sourceUrl            // nullable
credentialIdentifier
retrievedAt
documentHash
responseHash
signaturePresent
signatureValid
sourceResponseSummary
evidenceStatus
```

### Evidence rules

- Every `Verification` record MUST reference its evidence via `evidenceIds[]`.
- The frontend MUST display the evidence items — not merely a single badge.
- AI/ML outputs, if used in future, are supplementary evidence items only.
  They MUST NOT produce `VERIFIED` alone; they are `MANUAL_REVIEW` evidence at best.
- OCR outputs are evidence-extraction aids only — they do NOT constitute cryptographic proof.
  OCR results, if used, must be recorded as `MANUAL_REVIEW` evidence.

---

## 11. Verification Result States

Replace any simple boolean `verified` field with these categorical states:

| State | Meaning |
|---|---|
| `VERIFIED` | All checks pass: trusted org, authorized active issuer, valid key, hash match, valid signature, active non-expired credential |
| `SOURCE_VERIFIED` | A trusted official source confirms the record; no cryptographic signature from the source |
| `SOURCE_FOUND` | A matching record found on official/trusted source; insufficient evidence for full verification |
| `ALTERED` | A trusted original exists; submitted file hashes differ |
| `NOT_FOUND` | No trusted credential or source record found |
| `CREDENTIAL_REVOKED` | Credential was authentic but issuer has revoked it |
| `CREDENTIAL_EXPIRED` | Credential is authentic but validity period has ended |
| `ISSUER_SUSPENDED` | Issuer is temporarily not authorized |
| `ISSUER_REVOKED` | Issuer is permanently not authorized |
| `SIGNATURE_INVALID` | Document/hash does not validate against issuer public key |
| `KEY_COMPROMISED` | Issuer key is marked compromised; policy-aware result required |
| `MANUAL_REVIEW` | Evidence insufficient, conflicting, or requires human decision |
| `UNSUPPORTED_SOURCE` | Supplied source cannot be safely or reliably verified |

### Revocation and expiry semantics

- `REVOKED` is NOT `FAKE`. A revoked credential was authentic at issuance.
- `EXPIRED` is NOT `FAKE`. An expired credential was authentic during its validity period.
- The UI MUST preserve this distinction (e.g., "Authentic but revoked", "Authentic but expired").

---

## 12. Trust Levels

Do NOT use arbitrary numerical percentage scores (e.g., "95% genuine").
Use categorical evidence levels:

| Level | Name | Meaning |
|---|---|---|
| 0 | `LEVEL_0_UNKNOWN` | No evidence obtained |
| 1 | `LEVEL_1_SOURCE_FOUND` | Official source exists or a matching record was found |
| 2 | `LEVEL_2_SOURCE_VERIFIED` | Trusted institution/source confirms the record |
| 3 | `LEVEL_3_INTEGRITY_VERIFIED` | Document hash matches the trusted original |
| 4 | `LEVEL_4_SIGNATURE_VERIFIED` | Issuer signature validates |
| 5 | `LEVEL_5_CURRENTLY_VALID` | Signature + integrity + issuer + lifecycle checks all pass |

A credential issued within the system by an active, approved issuer should reach Level 5
(`VERIFIED`) when all checks pass.

---

## 13. Verification Decision Engine

Checks MUST be evaluated independently.

The four facts that must all be independently checked:

```
Organization is legitimate
        NOT EQUAL TO
User is an authorized issuer
        NOT EQUAL TO
Issuer key is currently trusted
        NOT EQUAL TO
Credential is currently valid
```

All four must pass for `VERIFIED`.
Failure of any one produces a specific non-`VERIFIED` result, not a generic failure.

### Decision examples

```
organizationTrusted=true, issuerActive=true, hashMatch=true,
signatureValid=false, credentialActive=true
-> SIGNATURE_INVALID (not VERIFIED)

organizationTrusted=true, hashMatch=true, signatureValid=true,
credentialRevoked=true
-> CREDENTIAL_REVOKED (not VERIFIED, not FAKE)

officialSourceFound=true, signatureAvailable=false
-> SOURCE_VERIFIED or SOURCE_FOUND (not VERIFIED)
```

---

## 14. Official-Source Verification

Official-source verification is a separate mode from cryptographic credential verification.

Supported source types:
- `OFFICIAL_VERIFICATION_PORTAL`
- `OFFICIAL_API`
- `OFFICIAL_DOCUMENT_REPOSITORY`

### SSRF Protection (mandatory when official-source retrieval is implemented)

- Only allow pre-approved `TrustedSource` records — never arbitrary URLs.
- Allowlist domains from the `TrustedSource` record.
- Resolve DNS safely; reject all of:
  - `localhost` / loopback
  - Private IP ranges (RFC 1918)
  - Link-local addresses
  - Cloud metadata IPs (e.g., 169.254.169.254)
- Restrict redirects to approved domains only.
- Restrict protocols to HTTPS only.
- Enforce connection timeout, response timeout, and maximum response size.
- Validate response content type; reject executable content.
- Log every retrieval attempt in the audit log (`OFFICIAL_SOURCE_CHECKED`).

### Correct API pattern for source verification

```json
{
  "trustedSourceId": "SOURCE_ID",
  "credentialIdentifier": "ABC2026CS123",
  "document": "<multipart file>"
}
```

The backend MUST reject any endpoint that accepts arbitrary external URLs for fetching.

---

## 15. Hash-Chained Audit Logs

Every security-sensitive operation creates a hash-chained, append-only audit record.

### AuditLog fields

```
_id
action          // see action list below
performedBy     // User ObjectId
targetType      // USER | ORGANIZATION | ISSUER | ISSUER_KEY | CREDENTIAL |
                //   CREDENTIAL_VERSION | DOCUMENT | VERIFICATION |
                //   TRUSTED_SOURCE | AUDIT_CHECKPOINT
targetId
metadata        // action-specific data object
previousHash    // SHA-256 of previous entry's currentHash
currentHash     // SHA-256(action + targetId + JSON(metadata) + previousHash + timestamp)
createdAt       // no updatedAt — append-only
```

### Hash chain rules

- No update or delete operations on `AuditLog`. The Mongoose schema has no `updatedAt`.
- Genesis entry: `previousHash = SHA-256("GENESIS_SECUREWORK_VERIFY")`
- Chain validation recomputes every `currentHash` and verifies the `previousHash` linkage.
- **Known limitation (v1):** The hash chain detects modification but does not prevent deletion
  by someone with direct MongoDB access. This MUST be documented; do not claim MongoDB audit
  logs are immutable against a privileged DBA.

### Audited actions (complete list)

```
USER_CREATED
LOGIN_SUCCESS
LOGIN_FAILED
ORGANIZATION_CREATED
ORGANIZATION_VERIFICATION_SUBMITTED
ORGANIZATION_VERIFIED
ORGANIZATION_SUSPENDED
TRUSTED_SOURCE_REGISTERED
TRUSTED_SOURCE_VERIFIED
TRUSTED_SOURCE_SUSPENDED
ISSUER_AUTHORIZATION_SUBMITTED
ISSUER_APPROVED
ISSUER_SUSPENDED
ISSUER_REVOKED
ISSUER_KEY_CREATED
ISSUER_KEY_ROTATED
ISSUER_KEY_COMPROMISED
ISSUER_KEY_REVOKED
DOCUMENT_UPLOADED
CREDENTIAL_ISSUED
CREDENTIAL_VERSION_CREATED
CREDENTIAL_SUPERSEDED
CREDENTIAL_REVOKED
VERIFICATION_PERFORMED
VERIFICATION_EVIDENCE_CREATED
OFFICIAL_SOURCE_CHECKED
AUDIT_CHECKPOINT_CREATED
```

---

## 16. Audit Checkpoints

### AuditCheckpoint fields

```
_id
sequenceStart
sequenceEnd
chainHeadHash
createdAt
externalAnchorType   // nullable in v1
externalReference    // nullable in v1
```

### Checkpoint rules

- Internal checkpoints are created periodically to preserve chain-head hashes.
- v1: internal checkpoints only. External anchoring (blockchain, timestamp authority) is
  documented as a future enhancement.
- Do NOT claim that checkpoints make the audit log immutable.

---

## 17. Manual Verification Rules

- `MANUAL_REVIEW` is a valid, first-class verification result — not an error state.
- It is produced when evidence is insufficient, conflicting, or requires human judgment.
- Screenshots/scans of a document produce different hashes from the original digital file.
  They MUST NOT produce `VERIFIED`. They MUST produce `MANUAL_REVIEW` or `NOT_FOUND`.
- Visually identical PDFs with different metadata produce different hashes. This MUST produce
  `NOT_EXACT_FILE_MATCH` or `MANUAL_REVIEW`, not `FAKE`/`ALTERED`.
- OCR/visual similarity features are future scope — not v1.
- AI/ML outputs, if ever added, are supplementary evidence only. They may elevate a
  `MANUAL_REVIEW` result with supporting information; they cannot produce `VERIFIED` alone.

---

## 18. Document Representation Policy

### Document fields (required)

```
_id
originalFilename
mimeType              // application/pdf | image/png | image/jpeg
fileSize              // max 10 MB
storagePath
storageUrl
sha256Hash
hashAlgorithm         // "sha256"
uploadedBy
representationType    // ORIGINAL_DIGITAL_FILE | PDF | IMAGE | SCAN | SCREENSHOT | OTHER
canonicalizationStatus
createdAt
updatedAt
```

### File type restrictions

- Allowed: PDF, PNG, JPG/JPEG only
- Maximum file size: 10 MB (enforced by multer; configurable via env)
- Memory storage (file buffer stays in memory for hashing before upload)

### Timestamp labeling

For v1, store `issuedAt`, `signedAt`, and `recordedAt` as server-supplied timestamps.
Do NOT claim independent trusted timestamping unless an RFC 3161 or equivalent authority
is actually integrated.

---

## 19. What the System Can and Cannot Claim

### The system CAN claim:

- Exact file integrity (hash match against stored trusted credential)
- Valid digital signature from an authorized issuer key
- Authorized issuer relationship
- Current credential status (active, revoked, expired)
- Trusted source confirmation (where a TrustedSource is configured)
- Evidence-backed verification result with full evidence trail

### The system CANNOT claim:

- That a random document is genuine based only on a hash
- That a website is trustworthy based only on HTTPS or domain ownership
- That a person is who they claim to be
- That a document is currently valid without a lifecycle check
- That a screenshot or scan is the exact original digital file
- That a MongoDB audit log is immutable against a privileged DBA
- Independent trusted timestamping (unless a timestamp authority is integrated)

---

## 20. Hard Prohibitions (Non-Negotiable)

### Architecture prohibitions

| Rule | Reason |
|---|---|
| No blockchain | Architecture decision — excluded from v1 |
| No mandatory paid services | Zero-cost local-first requirement |
| No AI/ML as primary verification | AI/ML is supplementary evidence only |
| No OCR as proof | OCR is evidence extraction, not cryptographic proof |
| No fabricated government/API verification | Only real, approved TrustedSources |
| No arbitrary URL fetching | SSRF risk; only approved TrustedSource IDs accepted |
| No microservices | Monolithic backend for v1 |
| No multiple databases | Single MongoDB instance |
| No zero-knowledge proofs | Over-engineering for v1 |

### Security prohibitions

| Rule | Description |
|---|---|
| No private keys in MongoDB | Private key bytes must never be stored in any MongoDB document |
| No private keys in API responses | No endpoint may return private key material |
| No private keys in Git | `backend/keys/*.key` must always be gitignored |
| No secrets in Git | `.env` files must always be gitignored; use `.env.example` |
| No privileged self-registration | Public registration always creates `USER` only |
| No hash-only VERIFIED | Hash match alone is insufficient for VERIFIED result |
| No deleting historical public keys | Public keys are permanently preserved |
| No deleting historical credential versions | All versions permanently auditable |
| No deleting audit log entries | AuditLog is append-only; no update or delete |
| No treating revoked as fake | REVOKED is NOT FAKE; distinction must be preserved in UI |
| No treating expired as fake | EXPIRED is NOT FAKE; distinction must be preserved in UI |
| No claiming immutable audit log | Hash chain detects modification; DBA deletion is a known limitation |
| No undocumented assumed timestamping | Server timestamps must be labeled as server-supplied |

---

## 21. Data Model Summary

All entities that must exist as MongoDB models (may be embedded where practical in early
milestones, but must remain conceptually separate):

| Model | Milestone introduced | Notes |
|---|---|---|
| `User` | 1 | Roles: ADMIN, ISSUER, HR, USER, AUDITOR |
| `Organization` | 2 | Trust status, verification methods |
| `TrustedSource` | 8 | Admin-approved external sources only |
| `Issuer` | 2 | Authorization evidence required |
| `IssuerKey` | 2 | Key lifecycle; public key preserved on revocation |
| `Document` | 3 | Representative type, hash algorithm recorded |
| `Credential` | 3 | References currentVersionId |
| `CredentialVersion` | 3 | Version history; issuerKeyId per version |
| `Verification` | 4 | Evidence-based result; full check breakdown |
| `VerificationEvidence` | 4 | Per-item evidence records |
| `AuditLog` | 5 | Append-only hash chain |
| `AuditCheckpoint` | 5 | Periodic chain snapshots |

---

## 22. Directory Structure

```
crypto/
+-- frontend/                     # React + Vite (not yet scaffolded)
+-- backend/                      # Node.js + Express
|   +-- keys/                     # Ed25519 private keys — GITIGNORED
|   |   +-- .gitkeep
|   +-- scripts/
|   |   +-- seed.js               # Creates initial ADMIN user
|   +-- src/
|   |   +-- config/
|   |   |   +-- db.js
|   |   |   +-- env.js            # Crashes on startup if required vars missing
|   |   |   +-- firebase.js       # Optional — only if Firebase Storage used
|   |   +-- models/               # Mongoose schemas (see section 21)
|   |   +-- controllers/
|   |   +-- routes/
|   |   +-- services/             # All business logic; crypto operations here only
|   |   +-- middleware/
|   |   |   +-- auth.middleware.js
|   |   |   +-- rbac.middleware.js
|   |   |   +-- upload.middleware.js
|   |   |   +-- error.middleware.js
|   |   +-- validators/
|   |   +-- utils/
|   |       +-- apiResponse.js
|   +-- tests/
|   +-- .env                      # GITIGNORED
|   +-- .env.example              # Committed — documents all required vars
|   +-- server.js
+-- docs/
+-- .gitignore
+-- README.md
+-- implementation_plan.md
+-- SecureWork_Verify_Trust_Model_v2.md
+-- PROJECT_RULES.md              # This file
```

---

## 23. Environment Variables

All required variables that MUST be present at startup:

| Variable | Description | Dev default |
|---|---|---|
| `PORT` | Server port | `5000` |
| `NODE_ENV` | `development` / `production` / `test` | `development` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/securework-verify` |
| `JWT_SECRET` | JWT signing secret | (required — no default) |
| `JWT_EXPIRES_IN` | JWT expiry | `24h` |
| `CORS_ORIGIN` | Allowed frontend origin | `http://localhost:5173` |
| `KEY_STORAGE_PATH` | Filesystem path for Ed25519 private keys | `./keys` |
| `ADMIN_NAME` | Seed admin name | `System Admin` |
| `ADMIN_EMAIL` | Seed admin email | (required for seed) |
| `ADMIN_PASSWORD` | Seed admin password | (required for seed) |

Firebase Storage variables are required only if Firebase Storage is used as the document
storage adapter. They are optional for local-only operation.

---

## 24. API Surface (Approved)

### Authentication
```
POST   /api/auth/register      creates USER only
POST   /api/auth/login         returns JWT
GET    /api/auth/me            authenticated user profile
```

### Organizations
```
POST   /api/organizations                    ADMIN
GET    /api/organizations                    all authenticated
GET    /api/organizations/:id               all authenticated
POST   /api/organizations/:id/verify        ADMIN
PATCH  /api/organizations/:id/suspend       ADMIN
```

### Trusted Sources
```
POST   /api/trusted-sources                        ADMIN
GET    /api/trusted-sources                        ADMIN
GET    /api/trusted-sources/:id                   ADMIN
PATCH  /api/trusted-sources/:id/approve           ADMIN
PATCH  /api/trusted-sources/:id/suspend           ADMIN
POST   /api/trusted-sources/:id/verify-domain     ADMIN
```

### Issuers
```
POST   /api/issuers/register                ISSUER (own profile registration)
GET    /api/issuers/me                      ISSUER
GET    /api/issuers                         ADMIN
PATCH  /api/issuers/:id/approve             ADMIN
PATCH  /api/issuers/:id/suspend             ADMIN
PATCH  /api/issuers/:id/revoke              ADMIN
POST   /api/issuers/:id/rotate-key          ADMIN
PATCH  /api/issuer-keys/:id/compromise      ADMIN
```

### Credentials
```
POST   /api/credentials/issue               ISSUER (must be ACTIVE)
GET    /api/credentials                     scoped by role
GET    /api/credentials/:id                scoped by role
GET    /api/credentials/:id/versions       scoped by role
POST   /api/credentials/:id/versions       ISSUER
PATCH  /api/credentials/:id/revoke         ISSUER (own credentials)
GET    /api/credentials/:id/timeline       scoped by role
```

### Verifications
```
POST   /api/verifications/verify            HR, USER
POST   /api/verifications/verify-source     HR, USER (trustedSourceId only — no arbitrary URL)
GET    /api/verifications                   scoped by role
GET    /api/verifications/:id              scoped by role
GET    /api/verifications/:id/evidence     scoped by role
```

### Audit
```
GET    /api/audit-logs            ADMIN, AUDITOR (paginated, filterable)
GET    /api/audit-logs/validate   ADMIN, AUDITOR
```

### Health
```
GET    /api/health   public
```

---

## 25. Frontend Result Display Rules

The frontend MUST never show only a green badge.
Every verification result must show the evidence breakdown:

```
VERIFICATION RESULT
-----------------------------------
[OK] Document integrity    - Hash matches trusted credential
[OK] Digital signature     - Signature valid
[OK] Issuer               - ABC University - Authorized
[OK] Issuer status        - ACTIVE
[OK] Credential status    - ACTIVE
[OK] Expiration           - Not expired

TRUST LEVEL: 5 / 5
FINAL RESULT: VERIFIED
```

For non-cryptographic source results:

```
SOURCE FOUND

[OK] Official source
[OK] Matching credential record

[--] Digital signature unavailable

Result: SOURCE FOUND / NOT CRYPTOGRAPHICALLY VERIFIED
```

---

## 26. Definition of "Trusted"

> A trusted entity is not trusted because the system says it is trusted.
> It is trusted because the system has recorded verifiable evidence establishing
> the basis of that trust.

This is the central design principle for the entire project.

---

*Last updated: 2026-08-30*
*Derived from: `implementation_plan.md` (v1, approved) + `SecureWork_Verify_Trust_Model_v2.md`*
