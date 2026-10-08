# SecureWork Verify — Algorithms and Technical Explanation

This document explains every algorithm and cryptographic mechanism used in the project,
grounded in the actual source code.

---

## 1. SHA-256 — Document Integrity Hashing

### What it is
SHA-256 (Secure Hash Algorithm, 256-bit output) is a one-way cryptographic hash function from the SHA-2 family, standardized by NIST (FIPS 180-4).

### Properties
- Deterministic: same input always produces same output
- Fixed output length: always 256 bits (64 hex characters)
- One-way: computationally infeasible to reverse
- Avalanche effect: a single bit change in input changes ~50% of output bits
- Collision resistant: computationally infeasible to find two inputs with the same hash

### Implementation in this project

**File:** `backend/src/services/crypto.service.js`

```javascript
const hashDocument = (buffer) => {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('hashDocument requires a Buffer');
  }
  return crypto.createHash('sha256').update(buffer).digest('hex');
};
```

- Uses Node.js built-in `crypto` module — no third-party library
- Input: raw file bytes as a Node.js Buffer
- Output: 64-character lowercase hex string
- Called on: every document upload (issuance) and every verification attempt

### What it proves and what it does NOT prove
- **Proves:** byte-level identity — if hash matches, the file content is identical
- **Does NOT prove:** authenticity — a forger who obtains a copy of the exact file would produce the same hash
- Authenticity requires the Ed25519 signature (Section 2)

### Vulnerability awareness
- SHA-256 is a known-hash function — if an attacker obtains the exact original document bytes, they can verify the hash, but they cannot produce a valid Ed25519 signature without the private key

---

## 2. Ed25519 — Digital Signature Scheme

### What it is
Ed25519 is a digital signature algorithm using the Edwards-curve Digital Signature Algorithm (EdDSA) on the twisted Edwards curve Curve25519. It was introduced by Bernstein et al. (2011).

### Properties
- Short signatures: 64 bytes (512 bits)
- Short keys: 32-byte public key, 64-byte secret key (seed + public)
- Fast: optimized for software implementation
- Security: 128-bit security level (equivalent to RSA-3072)
- Deterministic: same key + same message → always same signature (no randomness required during signing)
- No side-channel vulnerabilities from timing attacks (constant-time implementation in tweetnacl)

### Library
**tweetnacl** (npm package `tweetnacl`) — a port of NaCl cryptography by Bernstein, Lange, and Schwabe. Pure JavaScript, no native bindings, well-audited.

### Implementation in this project

**File:** `backend/src/services/crypto.service.js`

**Key Generation:**
```javascript
const generateKeyPair = () => {
  const keyPair = nacl.sign.keyPair();
  return {
    publicKey: Buffer.from(keyPair.publicKey).toString('base64'),
    privateKey: Buffer.from(keyPair.secretKey).toString('base64'),
  };
};
```
- `nacl.sign.keyPair()` generates a 32-byte public key and 64-byte secret key
- Both returned as base64 strings
- Caller (keystore.service.js) must immediately persist the private key to the filesystem
- Private key is NEVER stored in MongoDB

**Signing:**
```javascript
const sign = (documentHashHex, privateKeyBase64) => {
  const messageBytes = Buffer.from(documentHashHex, 'hex');
  const privateKeyBytes = Buffer.from(privateKeyBase64, 'base64');
  const signatureBytes = nacl.sign.detached(messageBytes, privateKeyBytes);
  return Buffer.from(signatureBytes).toString('base64');
};
```
- Message signed: the SHA-256 hex string of the document, converted to bytes
- `nacl.sign.detached()` returns a 64-byte signature
- Returned as base64 string for storage

**Verification:**
```javascript
const verify = (documentHashHex, signatureBase64, publicKeyBase64) => {
  try {
    const messageBytes = Buffer.from(documentHashHex, 'hex');
    const signatureBytes = Buffer.from(signatureBase64, 'base64');
    const publicKeyBytes = Buffer.from(publicKeyBase64, 'base64');
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch {
    return false;
  }
};
```
- Any parsing failure returns false (not an exception)
- `nacl.sign.detached.verify()` returns boolean
- Uses the PUBLIC key only — private key is never loaded during verification

### Why Ed25519 over RSA?
| Property | Ed25519 | RSA-2048 |
|---|---|---|
| Public key size | 32 bytes | 256 bytes |
| Signature size | 64 bytes | 256 bytes |
| Security level | 128-bit | 112-bit |
| Signing speed | Very fast | Slower |
| Timing attacks | Resistant | Requires careful implementation |
| Key generation | Very fast | Slow |

---

## 3. SHA-256 Audit Hash Chain

### What it is
The audit hash chain links every audit log entry cryptographically, so that any modification to a past entry (or insertion/deletion of entries) is detectable.

### Design
- Every security operation creates an AuditLog document
- Each entry stores:
  - `sequenceNumber`: strictly incrementing from 1
  - `previousHash`: the `currentHash` of the preceding entry
  - `currentHash`: SHA-256 of all this entry's fields combined

### Hash formula

**File:** `backend/src/models/AuditLog.js`

```javascript
const payload =
  String(sequenceNumber) +
  String(action) +
  String(performedBy) +
  String(targetType) +
  String(targetId) +
  canonicalStringify(metadata) +
  String(createdAt) +   // ISO 8601 string
  String(previousHash);

currentHash = SHA-256(payload)
```

### Genesis hash
The very first entry uses:
```javascript
previousHash = SHA-256("GENESIS_SECUREWORK_VERIFY")
```
This is a domain-specific constant that anchors the chain to this application.

### Canonical JSON
Metadata is serialized using `canonicalStringify` which recursively sorts object keys alphabetically. This ensures the same object always produces the same string regardless of key insertion order.

**File:** `backend/src/utils/canonicalJson.js`

### Chain verification algorithm

**File:** `backend/src/services/audit.service.js` — `verifyChain()`

```
1. Fetch all entries sorted by sequenceNumber ASC
2. expectedPreviousHash = SHA-256("GENESIS_SECUREWORK_VERIFY")
3. expectedSeq = 1
4. For each entry:
   a. Check: entry.sequenceNumber === expectedSeq (no gaps)
   b. Check: entry.previousHash === expectedPreviousHash (correct linkage)
   c. Recompute currentHash using stored fields
   d. Check: recomputedHash === entry.currentHash (not tampered)
   e. Advance: expectedPreviousHash = entry.currentHash; expectedSeq++
5. If all pass: chain is valid
```

### Concurrency protection
The audit service uses an in-process promise queue (serialization mutex) to prevent race conditions where two concurrent operations could read the same `lastEntry` and generate duplicate sequence numbers.

```javascript
let writeQueue = Promise.resolve();
const enqueueWrite = (task) => {
  const next = writeQueue.then(task, task);
  writeQueue = next.catch(() => {});
  return next;
};
```

All `log()` calls go through `enqueueWrite()`. The queue ensures the next write begins only after the previous one has fetched the last entry and stored the new entry.

### Limitations
- Detects tampering via application-layer reads
- A MongoDB DBA with direct database access can delete the entire collection
- Single-process queue doesn't scale to multi-instance deployments

---

## 4. bcrypt — Password Hashing

### What it is
bcrypt is a password hashing algorithm designed by Niels Provos and David Mazières (1999). It incorporates a salt and a cost factor, making brute-force attacks computationally expensive.

### Properties
- Slow by design: increasing cost factor doubles computation time
- Salted: unique random salt per password (prevents rainbow tables)
- Cost factor: 12 rounds used in this project (~300ms hash time)
- Maximum password length: 72 bytes (bcrypt limitation)

### Implementation

**File:** `backend/src/models/User.js`

```javascript
userSchema.pre('save', async function (next) {
  if (!this.isModified('passwordHash')) return next();
  const salt = await bcrypt.genSalt(12);
  this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
  next();
});
```

- Library: `bcryptjs` (pure JavaScript bcrypt)
- The `passwordHash` field name stores the raw password before the hook, then replaces it with the bcrypt hash
- The `select: false` schema option ensures passwordHash is never returned in queries

**Comparison:**
```javascript
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};
```

---

## 5. JWT — Stateless Authentication

### What it is
JSON Web Tokens (JWT, RFC 7519) are a compact, URL-safe means of representing claims between two parties. They consist of header.payload.signature.

### Structure
```
Header: { "alg": "HS256", "typ": "JWT" }
Payload: { "userId": "...", "role": "USER", "iat": ..., "exp": ... }
Signature: HMAC-SHA256(base64(header) + "." + base64(payload), secret)
```

### Implementation

**File:** `backend/src/services/auth.service.js`

On login, after password verification:
```javascript
const token = jwt.sign(
  { userId: user._id, role: user.role },
  process.env.JWT_SECRET,
  { expiresIn: process.env.JWT_EXPIRES_IN }
);
```

Auth middleware verifies on every protected route:
```javascript
const decoded = jwt.verify(token, process.env.JWT_SECRET);
req.user = await User.findById(decoded.userId);
```

### Properties
- Stateless: no session store needed
- Self-contained: role and userId in payload
- Expiry: enforced by exp claim
- No refresh token: sessions expire and user must log in again

---

## 6. RBAC — Role-Based Access Control

### Roles and permissions matrix

| Action | ADMIN | ISSUER | HR | USER | AUDITOR |
|---|---|---|---|---|---|
| Register (POST /auth/register) | — | — | — | Always USER | — |
| Create organization | Yes | No | No | No | No |
| Approve/suspend/revoke org | Yes | No | No | No | No |
| Register issuer profile | No | Yes | No | No | No |
| Approve/suspend/revoke issuer | Yes | No | No | No | No |
| Generate Ed25519 keypair | Yes | No | No | No | No |
| Issue credential | No | Yes (own) | No | No | No |
| List credentials | All (scoped) | Own issued | Own org | Own received | No |
| Verify document | No | No | Yes | Yes | No |
| View audit logs | Yes | No | No | No | Yes |
| Validate audit chain | Yes | No | No | No | Yes |

### Implementation

**File:** `backend/src/middleware/auth.js`

```javascript
const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return next(createError('Access denied', 403));
  }
  next();
};
```

Each route uses e.g. `requireRole('ADMIN')` or `requireRole('HR', 'USER')`.

---

## 7. Credential Versioning

### Why versioning?
Organizations may issue updated versions of a credential (e.g. revised degree classification, corrected date). Each version has its own document hash and Ed25519 signature, enabling verification of any historical version.

### Implementation

When a new version is created:
1. The old credential status is updated to indicate supersession
2. A new CredentialVersion document is created with:
   - The new document hash and signature
   - The issuerKeyId active at that time
   - The changeReason and version number
3. The credential's `currentVersionId` is updated

During verification, if the uploaded document hash matches a historical CredentialVersion (not the current version), the verification proceeds using the historical version's signature and key.

---

## 8. Verification Algorithm (Full Walkthrough)

### Step 0: Hash the uploaded file
```
uploadedHash = SHA-256(fileBuffer)
```

### Step 1: Credential lookup
```
Find Credential where documentHash == uploadedHash
If not found: Find CredentialVersion where documentHash == uploadedHash → load parent Credential
If still not found: result = NOT_FOUND, trustLevel = LEVEL_0_UNKNOWN → stop
```

### Step 2: Load context
```
issuer = Issuer.findById(credential.issuerId)
issuerKey = IssuerKey.findById(matchedVersion?.issuerKeyId || credential.issuerKeyId)
organization = Organization.findById(credential.organizationId || issuer.organizationId)
```

### Step 3: Hash integrity check
```
hashMatch = (uploadedHash === expectedHash)
```
Evidence saved: HASH_MATCH

### Step 4: Ed25519 signature check
```
sigValid = nacl.sign.detached.verify(hashBytes, sigBytes, pubKeyBytes)
```
Evidence saved: DIGITAL_SIGNATURE

### Step 5: Organization trust check
```
orgTrusted = (org.organizationVerificationStatus === 'VERIFIED' && org.status === 'ACTIVE')
```
Evidence saved: DOMAIN_VERIFICATION

### Step 6: Issuer status check
```
issuerActive = (issuer.status === 'ACTIVE')
```
Evidence saved: ISSUER_STATUS

### Step 7: Key and credential status checks
```
keyCompromised = (issuerKey.status === 'COMPROMISED')
isRevoked = (credential.status === 'REVOKED')
isExpired = (credential.expiresAt && new Date(credential.expiresAt) <= now)
```
Evidence saved: CREDENTIAL_STATUS

### Step 8: Determine authoritative result (priority order)
```
if (!hashMatch)            → ALTERED         LEVEL_0_UNKNOWN
elif (!sigValid)           → SIGNATURE_INVALID LEVEL_3_INTEGRITY_VERIFIED
elif (keyCompromised)      → KEY_COMPROMISED  LEVEL_3_INTEGRITY_VERIFIED
elif (issuer REVOKED)      → ISSUER_REVOKED   LEVEL_4_SIGNATURE_VERIFIED
elif (issuer SUSPENDED)    → ISSUER_SUSPENDED  LEVEL_4_SIGNATURE_VERIFIED
elif (isRevoked)           → CREDENTIAL_REVOKED LEVEL_4_SIGNATURE_VERIFIED
elif (isExpired)           → CREDENTIAL_EXPIRED LEVEL_4_SIGNATURE_VERIFIED
elif (!orgTrusted)         → MANUAL_REVIEW    LEVEL_4_SIGNATURE_VERIFIED
else                       → VERIFIED         LEVEL_5_CURRENTLY_VALID
```

### Step 9: Persist and audit
- Create Verification document in MongoDB
- Create per-step evidence records
- Write audit log entries for each evidence and the final result

---

## 9. Audit Concurrency Test

The audit concurrency test (`tests/audit.test.js`) fires 20 concurrent `auditService.log()` calls and then verifies:
- All 20 sequence numbers are unique and form a gap-free sequence
- The hash chain is unbroken
- No two entries share a sequence number

This validates the in-process serialization mutex.

---

## 10. Security Headers (Helmet)

| Header | Value | Protection |
|---|---|---|
| Content-Security-Policy | default-src 'self' | XSS mitigation |
| Strict-Transport-Security | max-age=15552000 | Forces HTTPS |
| X-Content-Type-Options | nosniff | MIME sniffing |
| X-Frame-Options | SAMEORIGIN | Clickjacking |
| X-Powered-By | (removed) | Hides tech stack |

---

## 11. Rate Limiting

Implemented via `express-rate-limit`:

| Scope | Limit | Window | Purpose |
|---|---|---|---|
| Auth routes | 10 requests | 15 minutes | Prevents brute-force login |
| Verification | 30 requests | 15 minutes | Prevents hash lookup abuse |
| Global | 100 requests | 15 minutes | General denial-of-service mitigation |

---

## 12. File Upload Security

- `multer` middleware validates MIME type: only `application/pdf`, `image/png`, `image/jpeg` accepted
- 415 Unsupported Media Type for other file types
- Maximum file size: 10 MB (configurable via MAX_FILE_SIZE_MB)
- Files stored in `backend/uploads/` (gitignored)
- Only the file buffer is used for hashing — file contents are not executed or interpreted
