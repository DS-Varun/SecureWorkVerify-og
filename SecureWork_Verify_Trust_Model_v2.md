# SecureWork Verify — Trust Model Implementation Specification
## Version 2 — Trust-Aware Architecture

> Purpose: Extend the approved SecureWork Verify architecture so that every verification result is based on explicit trust evidence.
> This document supersedes conflicting parts of implementation_plan.md where noted.
> Blockchain remains excluded from v1.

---

# 1. Core principle

The system MUST distinguish:

1. **Integrity** — Is the submitted file exactly the same as the trusted file?
2. **Issuer authenticity** — Was the document signed by an authorized issuer?
3. **Institutional trust** — Is the organization/source itself trusted?
4. **Current validity** — Has the credential been revoked or expired?
5. **Evidence strength** — What evidence supports the verification result?

The system MUST NOT treat a hash as proof that a document is genuine.

A SHA-256 hash proves only that two byte sequences are identical.

A digital signature links a document hash to an issuer key.

The trustworthiness of that issuer key comes from the trusted organization/issuer approval process.

---

# 2. Terminology change

Replace EMPLOYEE everywhere with USER.

Roles:

- ADMIN
- ISSUER
- HR
- USER
- AUDITOR

USER is the default public registration role.

Public registration MUST NOT accept a caller-selected privileged role.

USER may be a student, employee, unemployed person, job applicant, certificate holder, or any other document holder.

---

# 3. Trust levels

Do NOT use a single boolean `verified`.

Use evidence-based verification states.

## Primary verification results

- VERIFIED
- SOURCE_VERIFIED
- SOURCE_FOUND
- ALTERED
- NOT_FOUND
- CREDENTIAL_REVOKED
- CREDENTIAL_EXPIRED
- ISSUER_SUSPENDED
- ISSUER_REVOKED
- SIGNATURE_INVALID
- KEY_COMPROMISED
- MANUAL_REVIEW
- UNSUPPORTED_SOURCE

## Meaning

### VERIFIED
All required cryptographic and lifecycle checks pass:

- trusted organization
- authorized active issuer
- valid issuer signature
- document hash matches signed hash
- credential is active
- credential is not expired/revoked

### SOURCE_VERIFIED
A trusted official source confirms the credential/document record, but no cryptographic signature is available from the source.

### SOURCE_FOUND
A matching document was found on an official/trusted source, but the source does not provide enough evidence for cryptographic verification.

### ALTERED
A trusted original exists and the submitted representation is expected to be the exact same digital file, but hashes differ.

### NOT_FOUND
No trusted credential or source record was found.

### CREDENTIAL_REVOKED
The credential is authentic or was previously valid, but the issuer has revoked it.

### CREDENTIAL_EXPIRED
The credential is authentic but its validity period has ended.

### ISSUER_SUSPENDED / ISSUER_REVOKED
The issuer is not currently authorized.

### SIGNATURE_INVALID
The document/hash does not validate against the issuer's public key.

### KEY_COMPROMISED
The issuer key has been marked compromised and the verification policy requires rejection/warning.

### MANUAL_REVIEW
Evidence is insufficient, conflicting, or requires human review.

### UNSUPPORTED_SOURCE
The supplied source cannot be safely or reliably verified.

---

# 4. New trust entities

Add these MongoDB models:

1. Organization
2. TrustedSource
3. Issuer
4. IssuerKey
5. Credential
6. CredentialVersion
7. Document
8. Verification
9. VerificationEvidence
10. AuditLog
11. AuditCheckpoint

The first implementation may keep IssuerKey and CredentialVersion embedded where practical, but the conceptual entities MUST remain separate.

---

# 5. Organization trust model

Organization fields:

```text
_id
name
type
officialDomain
domainVerificationStatus
organizationVerificationStatus
verificationMethods[]
verifiedAt
verifiedBy
status
createdBy
createdAt
updatedAt
```

Organization verification status:

- PENDING
- VERIFIED
- SUSPENDED
- REVOKED

Verification methods:

- ADMIN_REVIEW
- DOMAIN_OWNERSHIP
- OFFICIAL_REGISTRY
- INSTITUTIONAL_CONTACT
- OTHER

IMPORTANT:

Domain ownership alone does NOT prove that every document hosted on the domain is authentic.

It only establishes that the organization controls the domain.

---

# 6. TrustedSource model

Create:

```text
TrustedSource
```

Fields:

```text
_id
organizationId
name
sourceType
baseUrl
verificationEndpoint
domain
verificationStatus
verificationMethod
verificationToken
lastCheckedAt
status
createdBy
verifiedBy
verifiedAt
createdAt
updatedAt
```

sourceType:

- OFFICIAL_WEBSITE
- VERIFICATION_PORTAL
- API
- DOCUMENT_REPOSITORY
- OTHER

status:

- PENDING
- ACTIVE
- SUSPENDED
- REVOKED

Rules:

- Arbitrary user URLs MUST NOT automatically become trusted.
- A source must belong to an approved organization.
- ADMIN must approve a source before it can be used as a trust source.
- Domain ownership verification may be used as evidence.
- Official-source verification MUST record exactly what evidence was obtained.

---

# 7. Issuer trust

An organization being trusted does NOT automatically make every user an issuer.

Issuer registration:

```text
USER
  ↓
issuer registration request
  ↓
PENDING
  ↓
ADMIN / organization authorization
  ↓
ACTIVE
```

Issuer fields:

```text
_id
userId
organizationId
authorizationEvidence
status
approvedBy
approvedAt
suspendedAt
suspensionReason
revokedAt
revokedReason
createdAt
updatedAt
```

authorizationEvidence may contain:

- organization invitation
- admin approval
- institutional email verification
- employee/issuer identifier
- manual verification notes

The system MUST preserve the evidence that justified issuer approval.

---

# 8. Issuer key lifecycle

DO NOT delete historical public keys or cryptographic evidence when an issuer is revoked.

Previous plan's "delete private key on revocation" rule is superseded.

Instead:

```text
ACTIVE
  ↓
SUSPENDED
  ↓
REVOKED
```

The signing key becomes unusable for new issuance when issuer/key is suspended, revoked, or compromised.

Historical public keys remain available for verifying historical credentials.

Private key handling:

- development: protected file-system storage
- production: KMS/HSM/secrets manager
- API never exposes private keys
- private key never enters MongoDB
- private key is never returned to frontend

---

# 9. IssuerKey model

Create a key lifecycle record:

```text
IssuerKey
-------------------------
_id
issuerId
keyId
algorithm = Ed25519
publicKey
privateKeyReference
status
createdAt
activatedAt
retiredAt
compromisedAt
revokedAt
statusReason
```

status:

- ACTIVE
- RETIRED
- COMPROMISED
- REVOKED

A credential MUST store the `issuerKeyId` used to sign it.

This is necessary because an issuer may rotate keys.

---

# 10. Key compromise

If a private key is suspected/stolen:

```text
IssuerKey
ACTIVE
   ↓
COMPROMISED
```

Immediately:

- stop new signing
- require ADMIN review
- preserve public key
- preserve historical signatures
- record compromise time
- audit the event

New credentials MUST NOT be signed using a compromised key.

Historical credentials require a policy-aware result.

Do NOT automatically call all historical credentials fake.

The verification response must say that the key is compromised and expose the signing/credential timestamps.

---

# 11. Credential model changes

Credential MUST include:

```text
_id
credentialNumber
credentialType
title
description

issuerId
issuerKeyId
organizationId
recipientId

currentVersionId

status
issuedAt
expiresAt
revokedAt
revokedReason

createdAt
updatedAt
```

status:

- ACTIVE
- REVOKED
- EXPIRED
- SUPERSEDED

A credential must never rely only on a hash to determine current validity.

---

# 12. CredentialVersion model

Create version history.

```text
CredentialVersion
-------------------------
_id
credentialId
versionNumber
documentId
documentHash
signature
issuerKeyId
issuedAt
supersedesVersionId
changeReason
status
createdAt
```

This solves legitimate document corrections.

Example:

```text
Version 1
   ↓ corrected
Version 2
   ↓
Version 3
```

Old versions remain auditable.

The system can distinguish:

```text
ALTERED
```

from:

```text
LEGITIMATE_NEW_VERSION
```

when the issuer has explicitly published a new version.

---

# 13. Document model

Document fields:

```text
_id
originalFilename
mimeType
fileSize
storagePath
storageUrl
sha256Hash
hashAlgorithm
uploadedBy
representationType
canonicalizationStatus
createdAt
updatedAt
```

representationType:

- ORIGINAL_DIGITAL_FILE
- PDF
- IMAGE
- SCAN
- SCREENSHOT
- OTHER

IMPORTANT:

For v1, exact cryptographic verification uses the complete file bytes.

Therefore:

```text
same content but different PDF metadata
```

may produce different hashes.

Do NOT silently normalize PDFs in v1.

If two visually identical PDFs have different hashes, return:

```text
NOT_EXACT_FILE_MATCH
```

or:

```text
MANUAL_REVIEW
```

rather than automatically calling the file fake.

---

# 14. Screenshot and scan policy

A screenshot/scan is NOT an exact digital copy of the original.

Therefore:

```text
Original signed PDF
       ↓
Screenshot
       ↓
different bytes
```

MUST NOT produce `VERIFIED` through exact hash matching.

For v1:

- exact original file → cryptographic verification
- screenshot/scan → MANUAL_REVIEW or NOT_FOUND
- OCR/visual similarity → future feature, not v1

This prevents the system from making unsupported authenticity claims.

---

# 15. Trusted timestamp model

`issuedAt` in MongoDB is not by itself a cryptographic timestamp.

For v1:

Store:

```text
issuedAt
signedAt
recordedAt
```

and clearly label them as server/issuer timestamps.

Do NOT claim independent trusted timestamping.

Future enhancement:

- RFC 3161 timestamp authority
- external timestamp service
- external audit anchoring

Blockchain is still not required.

---

# 16. Official-source verification

This is a separate verification mode.

Supported source types:

```text
OFFICIAL_VERIFICATION_PORTAL
OFFICIAL_API
OFFICIAL_DOCUMENT_REPOSITORY
```

Workflow:

```text
USER
 ↓
submit document + credential identifier/source reference
 ↓
trusted source selected
 ↓
secure source adapter
 ↓
retrieve official record/document
 ↓
record evidence
 ↓
compare available evidence
 ↓
produce evidence-based result
```

Do NOT build generic arbitrary URL downloading.

---

# 17. SSRF protection

When official-source retrieval is implemented:

- only allow pre-approved TrustedSource records
- allowlist domains
- resolve DNS safely
- reject localhost
- reject private IP ranges
- reject loopback
- reject link-local
- reject cloud metadata IPs
- restrict redirects to approved domains
- restrict protocols to HTTPS
- enforce connection timeout
- enforce response timeout
- enforce maximum response size
- validate content type
- reject executable content
- log every retrieval attempt

Never trust:

```text
POST /verify
{
  "url": "http://..."
}
```

as an arbitrary fetch instruction.

---

# 18. Official-source evidence

Create `VerificationEvidence`:

```text
_id
verificationId
evidenceType
sourceId
sourceUrl
credentialIdentifier
retrievedAt
documentHash
responseHash
signaturePresent
signatureValid
sourceResponseSummary
evidenceStatus
```

evidenceType:

- OFFICIAL_DOCUMENT
- OFFICIAL_RECORD
- DIGITAL_SIGNATURE
- HASH_MATCH
- ISSUER_STATUS
- CREDENTIAL_STATUS
- DOMAIN_VERIFICATION
- MANUAL_REVIEW

This allows the UI to explain WHY a result was produced.

---

# 19. Verification model

Replace the old Verification result list with:

```text
_id
verifiedBy
verificationMode
submittedDocumentId
uploadedDocumentHash
credentialId
organizationId
issuerId

result
trustLevel

integrityCheck
signatureCheck
issuerTrustCheck
sourceCheck
credentialStatusCheck
timestampCheck

evidenceIds[]

explanation
warnings[]

createdAt
```

verificationMode:

- CREDENTIAL
- OFFICIAL_SOURCE
- MANUAL_REVIEW

---

# 20. Trust score / trust level

Do not create an arbitrary numerical "95% genuine" score.

Instead use categorical evidence levels:

```text
LEVEL_0_UNKNOWN

LEVEL_1_SOURCE_FOUND
Official source exists or matching record found.

LEVEL_2_SOURCE_VERIFIED
Trusted institution/source confirms record.

LEVEL_3_INTEGRITY_VERIFIED
Document hash matches trusted original.

LEVEL_4_SIGNATURE_VERIFIED
Issuer signature validates.

LEVEL_5_CURRENTLY_VALID
Signature + integrity + issuer + lifecycle checks all pass.
```

`VERIFIED` should normally correspond to Level 5 for credentials issued by our system.

---

# 21. Verification decision engine

The engine must evaluate checks independently.

Example:

```text
organizationTrusted = true
sourceTrusted = true
hashMatch = true
signatureValid = false
issuerActive = true
credentialActive = true
```

Result:

```text
SIGNATURE_INVALID
```

NOT:

```text
VERIFIED
```

Another:

```text
organizationTrusted = true
hashMatch = true
signatureValid = true
credentialRevoked = true
```

Result:

```text
CREDENTIAL_REVOKED
```

Another:

```text
officialSourceFound = true
signatureAvailable = false
```

Result:

```text
SOURCE_VERIFIED
```

or `SOURCE_FOUND`, depending on the strength of the source response.

---

# 22. Verification response format

Example:

```json
{
  "success": true,
  "data": {
    "result": "VERIFIED",
    "trustLevel": 5,
    "message": "Document authenticity and current credential validity verified.",
    "checks": {
      "organizationTrusted": true,
      "issuerAuthorized": true,
      "issuerActive": true,
      "documentHashMatch": true,
      "signatureValid": true,
      "credentialActive": true,
      "credentialExpired": false,
      "credentialRevoked": false
    },
    "evidence": [
      {
        "type": "DIGITAL_SIGNATURE",
        "status": "VALID"
      },
      {
        "type": "HASH_MATCH",
        "status": "MATCH"
      },
      {
        "type": "ISSUER_STATUS",
        "status": "ACTIVE"
      }
    ]
  }
}
```

The frontend MUST display the evidence, not merely a green "Verified" badge.

---

# 23. Organization website compromise

Never use:

```text
HTTPS + official domain = genuine document
```

Instead:

```text
Official domain
      ↓
trusted source
      ↓
official record
      ↓
cryptographic proof if available
```

If the official source has no cryptographic signature:

```text
SOURCE_FOUND / SOURCE_VERIFIED
```

depending on the evidence.

Do not claim cryptographic authenticity.

---

# 24. Issuer authorization model

Separate these facts:

```text
Organization is legitimate
        ≠
User is an authorized issuer
        ≠
Issuer key is currently trusted
        ≠
Credential is currently valid
```

All four must be independently checked.

---

# 25. Revocation model

A credential may be:

```text
AUTHENTIC + REVOKED
```

This is NOT the same as:

```text
FAKE
```

UI:

```text
AUTHENTIC BUT REVOKED
```

Similarly:

```text
AUTHENTIC + EXPIRED
```

should display:

```text
AUTHENTIC BUT EXPIRED
```

The verification API must preserve this distinction.

---

# 26. Institution shutdown

If an organization becomes inactive:

```text
Organization = INACTIVE
```

historical credentials remain verifiable.

Result may become:

```text
VERIFIED — ISSUER INACTIVE
```

if the cryptographic evidence remains valid.

Do not retroactively mark historical credentials as fake solely because the institution closed.

---

# 27. Audit log additions

Add audit actions:

```text
ORGANIZATION_VERIFICATION_SUBMITTED
ORGANIZATION_VERIFIED
ORGANIZATION_SUSPENDED
TRUSTED_SOURCE_REGISTERED
TRUSTED_SOURCE_VERIFIED
TRUSTED_SOURCE_SUSPENDED
ISSUER_AUTHORIZATION_SUBMITTED
ISSUER_KEY_CREATED
ISSUER_KEY_ROTATED
ISSUER_KEY_COMPROMISED
ISSUER_KEY_REVOKED
CREDENTIAL_VERSION_CREATED
CREDENTIAL_SUPERSEDED
OFFICIAL_SOURCE_CHECKED
VERIFICATION_EVIDENCE_CREATED
AUDIT_CHECKPOINT_CREATED
```

Existing audit actions remain.

---

# 28. Audit checkpoints

The existing hash chain detects modification of records but does not independently prevent database deletion.

Add periodic:

```text
AuditCheckpoint
-------------------------
_id
sequenceStart
sequenceEnd
chainHeadHash
createdAt
externalAnchorType
externalReference
```

For v1:

- create internal checkpoints
- preserve chain-head hashes
- document external anchoring as a future enhancement

Do not pretend this makes MongoDB tamper-proof.

---

# 29. Database relationships

```text
USER
 ├── owns/uses → DOCUMENT
 ├── performs → VERIFICATION
 ├── performs → AUDIT_LOG
 └── has → ISSUER (optional)

ORGANIZATION
 ├── has → ISSUER
 └── has → TRUSTED_SOURCE

ISSUER
 ├── belongs to → ORGANIZATION
 ├── has → ISSUER_KEY
 └── issues → CREDENTIAL

ISSUER_KEY
 └── signs → CREDENTIAL_VERSION

CREDENTIAL
 ├── belongs to → ORGANIZATION
 ├── issued by → ISSUER
 ├── received by → USER
 └── has many → CREDENTIAL_VERSION

CREDENTIAL_VERSION
 └── references → DOCUMENT

VERIFICATION
 ├── performed by → USER
 ├── may match → CREDENTIAL
 └── has → VERIFICATION_EVIDENCE

TRUSTED_SOURCE
 └── belongs to → ORGANIZATION
```

---

# 30. Updated RBAC

| Capability | ADMIN | ISSUER | HR | USER | AUDITOR |
|---|---:|---:|---:|---:|---:|
| Register | ✓ | ✓ | ✓ | ✓ | ✓ |
| Login | ✓ | ✓ | ✓ | ✓ | ✓ |
| Create organization | ✓ | — | — | — | — |
| Verify organization | ✓ | — | — | — | — |
| Register trusted source | ✓ | — | — | — | — |
| Approve trusted source | ✓ | — | — | — | — |
| Register issuer request | — | ✓ | — | — | — |
| Approve issuer | ✓ | — | — | — | — |
| Suspend/revoke issuer | ✓ | — | — | — | — |
| Issue credential | — | ✓ | — | — | — |
| Revoke credential | — | ✓ | — | — | — |
| Verify credential | — | — | ✓ | ✓ | — |
| Verify official source | — | — | ✓ | ✓ | — |
| View own verification history | — | — | ✓ | ✓ | — |
| View audit logs | ✓ | — | — | — | ✓ |
| Validate audit chain | ✓ | — | — | — | ✓ |

---

# 31. API additions

## Organization trust

```http
POST /api/organizations
GET /api/organizations
GET /api/organizations/:id
POST /api/organizations/:id/verify
PATCH /api/organizations/:id/suspend
```

## Trusted sources

```http
POST /api/trusted-sources
GET /api/trusted-sources
GET /api/trusted-sources/:id
PATCH /api/trusted-sources/:id/approve
PATCH /api/trusted-sources/:id/suspend
POST /api/trusted-sources/:id/verify-domain
```

## Issuer

```http
POST /api/issuers/register
GET /api/issuers/me
GET /api/issuers
PATCH /api/issuers/:id/approve
PATCH /api/issuers/:id/suspend
PATCH /api/issuers/:id/revoke
POST /api/issuers/:id/rotate-key
PATCH /api/issuer-keys/:id/compromise
```

## Credentials

```http
POST /api/credentials/issue
GET /api/credentials
GET /api/credentials/:id
GET /api/credentials/:id/versions
POST /api/credentials/:id/versions
PATCH /api/credentials/:id/revoke
```

## Verification

```http
POST /api/verifications/verify
POST /api/verifications/verify-source
GET /api/verifications
GET /api/verifications/:id
GET /api/verifications/:id/evidence
```

`verify-source` MUST accept only a registered TrustedSource ID, not an arbitrary URL.

---

# 32. Verification-source API request

Correct:

```json
{
  "trustedSourceId": "SOURCE_ID",
  "credentialIdentifier": "ABC2026CS123",
  "document": "<multipart file>"
}
```

Incorrect:

```json
{
  "url": "https://random-site.com/file.pdf"
}
```

The backend MUST reject arbitrary external URLs.

---

# 33. Frontend result design

Never show only:

```text
✓ VERIFIED
```

Show:

```text
VERIFICATION RESULT
────────────────────────

✓ Document integrity
  Hash matches trusted credential

✓ Digital signature
  Signature valid

✓ Issuer
  ABC University — Authorized

✓ Issuer status
  ACTIVE

✓ Credential status
  ACTIVE

✓ Expiration
  Not expired

TRUST LEVEL: 5 / 5

FINAL RESULT:
VERIFIED
```

For a source-only result:

```text
SOURCE FOUND

✓ Official source
✓ Matching credential record

— Digital signature unavailable

Result:
SOURCE FOUND / NOT CRYPTOGRAPHICALLY VERIFIED
```

---

# 34. Milestone changes

## Milestone 1
Only change terminology:

EMPLOYEE → USER

Implement secure role assignment.

## Milestone 2
Add:

- organization trust status
- issuer authorization evidence
- issuer key lifecycle
- public key preservation

## Milestone 3
Add:

- CredentialVersion
- issuerKeyId
- signed credential
- document integrity

## Milestone 4
Replace simple VERIFIED/NOT_FOUND logic with the evidence-based verification engine.

## Milestone 5
Audit all trust decisions and evidence creation.

## Milestone 6
Implement:

- credential versions
- revocation
- expiration
- issuer/key suspension
- key compromise

## Milestone 7
Implement security hardening and prepare official-source adapters.

## Milestone 8 — Official Source Verification
New milestone after core system works:

- TrustedSource
- domain verification
- official verification portal adapters
- secure retrieval
- SSRF protection
- evidence collection
- SOURCE_FOUND / SOURCE_VERIFIED states

Do NOT implement generic web crawling.

---

# 35. What the system can and cannot claim

The system CAN claim:

- exact file integrity
- valid digital signature
- authorized issuer relationship
- current credential status
- trusted source confirmation
- evidence-backed verification result

The system CANNOT claim merely from a hash:

- that a random document is genuine
- that a website is trustworthy
- that a person is who they claim to be
- that a document is currently valid
- that a screenshot is an exact original

This distinction must appear in project documentation.

---

# 36. Final trust chain

The final architecture is:

```text
                    TRUST FOUNDATION
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
       TRUSTED ORGANIZATION        TRUSTED SOURCE
             │                           │
             ▼                           ▼
      AUTHORIZED ISSUER          OFFICIAL RECORD
             │
             ▼
        ISSUER KEY
             │
             ▼
       DIGITAL SIGNATURE
             │
             ▼
      CREDENTIAL VERSION
             │
             ▼
        DOCUMENT HASH
             │
             │
       ──────┼────────
             │
             ▼
      USER SUBMITTED FILE
             │
             ▼
         SHA-256 HASH
             │
             ▼
       EVIDENCE ENGINE
             │
       ┌─────┼─────┐
       ▼     ▼     ▼
   Integrity  Signature  Lifecycle
       │        │          │
       └────────┼──────────┘
                ▼
         TRUST DECISION
                │
     ┌──────────┼───────────┐
     ▼          ▼           ▼
 VERIFIED   SOURCE FOUND   MANUAL REVIEW
```

---

# 37. Non-negotiable security rules

1. Never trust a hash by itself.
2. Never trust an arbitrary URL.
3. Never allow public users to create trusted organizations.
4. Never allow public users to create active issuers.
5. Never allow public users to select ADMIN/ISSUER/HR/AUDITOR during registration.
6. Never delete historical public keys.
7. Never delete historical credential versions.
8. Never mark an unsigned source document as cryptographically verified.
9. Never treat revoked as fake.
10. Never treat expired as fake.
11. Never treat a changed screenshot as an exact original.
12. Never expose private keys.
13. Never claim independent timestamping unless an independent timestamp authority is actually used.
14. Never claim MongoDB audit logs are immutable against a privileged database administrator.
15. Every verification result must contain evidence explaining why it was produced.

---

# 38. Definition of "trusted"

For this project:

> A trusted entity is not trusted because the system says it is trusted. It is trusted because the system has recorded verifiable evidence establishing the basis of that trust.

This is the central design principle for the entire project.
