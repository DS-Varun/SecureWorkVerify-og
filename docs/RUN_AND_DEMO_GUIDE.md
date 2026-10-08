# SecureWork Verify — Run and Demo Guide

A step-by-step guide to set up and demonstrate SecureWork Verify locally.

---

## Prerequisites

| Requirement | Version | Check |
|---|---|---|
| Node.js | 18 or higher | `node --version` |
| npm | 8 or higher | `npm --version` |
| MongoDB | 6 or higher, running on port 27017 | `mongod --version` |

MongoDB must be running before starting the backend.

---

## Step 1 — Start MongoDB

On Windows (if installed as a service):

```
The MongoDB service is typically already running.
To check: Services panel → MongoDB → Status: Running
Or: sc query MongoDB
```

On Windows (manual):

```cmd
"C:\Program Files\MongoDB\Server\6.0\bin\mongod.exe" --dbpath "C:\data\db"
```

---

## Step 2 — Backend Setup

```cmd
cd backend
npm install
copy .env.example .env
```

Edit `.env` and set:

```
MONGODB_URI=mongodb://localhost:27017/securework-verify
JWT_SECRET=your-strong-secret-key-here
JWT_EXPIRES_IN=24h
PORT=5000
CORS_ORIGIN=http://localhost:5173
NODE_ENV=development
```

Create the initial ADMIN user:

```cmd
npm run seed
```

The seed script prints the ADMIN email and password to the console.
**Save these credentials — you need them for the demo.**

Start the backend:

```cmd
npm run dev
```

Backend runs at: **http://localhost:5000**

Test it: open http://localhost:5000/api/health in a browser — you should see:
```json
{"success": true, "data": {"api": "operational", "database": "connected"}}
```

---

## Step 3 — Frontend Setup

Open a second terminal:

```cmd
cd frontend
npm install
npm run dev
```

Frontend runs at: **http://localhost:5173**

Open **http://localhost:5173** in your browser.

---

## Step 4 — Environment Variables Reference

| Variable | Required | Default | Purpose |
|---|---|---|---|
| MONGODB_URI | Yes | — | MongoDB connection string |
| JWT_SECRET | Yes | — | JWT signing secret (keep private) |
| JWT_EXPIRES_IN | Yes | 24h | JWT session duration |
| PORT | No | 5000 | Backend HTTP port |
| CORS_ORIGIN | No | http://localhost:5173 | Allowed frontend origin |
| NODE_ENV | No | development | Runtime environment |
| KEY_STORAGE_PATH | No | ./keys | Ed25519 private key storage path |
| DOCUMENT_STORAGE_PATH | No | ./uploads | Uploaded file storage path |
| MAX_FILE_SIZE_MB | No | 10 | Maximum upload size |

---

## Step 5 — Run Tests

```cmd
cd backend
npm test
```

Expected result:
```
Test Suites: 9 passed, 9 total
Tests:       157 passed, 157 total
Time:        ~120 s
```

---

## Demo Sequence

### Part A — Login and Dashboard

1. Open http://localhost:5173
2. Click **Login**
3. Enter the ADMIN credentials from the seed output
4. You will see the ADMIN dashboard with action cards:
   - Manage Organizations
   - Manage Issuers
   - View Audit Logs
   - Verify Document

---

### Part B — Create Organization

1. From the ADMIN dashboard, click **Organizations**
2. Click **Create Organization**
3. Fill in:
   - Name: `Oxford University`
   - Code: `ORG-OXF001`
   - Type: `UNIVERSITY`
4. Click **Create**
5. The organization shows with status PENDING
6. Click **Verify** and enter:
   - Notes: `Verified via official university website`
   - Reference: `oxf.ac.uk/about`
7. Status becomes VERIFIED

---

### Part C — Register and Promote an Issuer

1. Open a new browser tab or incognito window
2. Go to http://localhost:5173/register
3. Register a new account:
   - Name: `Dr. Alice Smith`
   - Email: `alice@oxford.ac.uk`
   - Password: `Issuer@123`
4. Note: the account is created as USER role
5. Back in the ADMIN account, go to Users (or via API) and promote alice to ISSUER role
   (assign organizationId = Oxford University)
6. Login as alice
7. Go to **Register as Issuer** — register a profile under Oxford University
8. Back in ADMIN account: Issuers → **Approve** alice's profile
   - This auto-generates an Ed25519 keypair
   - Public key stored in DB; private key on filesystem only

---

### Part D — Issue a Credential

1. Login as alice (ISSUER)
2. Go to **Issue Credential**
3. Upload a PDF file (e.g., a diploma)
4. Fill in:
   - Credential Type: DEGREE
   - Title: `Bachelor of Computer Science`
   - Recipient name, organization: Oxford University
5. Click **Issue**
6. The system:
   - Computes SHA-256 of the PDF
   - Signs the hash with alice's Ed25519 private key
   - Stores the credential with hash + signature in MongoDB

**Save a copy of the original PDF — you'll need it for verification.**

---

### Part E — Verify the Genuine Document

1. Login as any USER account (or the same ADMIN)
2. Go to **Verify Document**
3. Drag-drop or select the **original PDF** (the same file issued)
4. Click **Verify**
5. Expected result: **VERIFIED — LEVEL_5_CURRENTLY_VALID**
6. Expand the **Evidence Trail** to see:
   - HASH_MATCH: VALID
   - DIGITAL_SIGNATURE: VALID (Ed25519)
   - ISSUER_STATUS: VALID (ACTIVE)
   - ORGANIZATION: VALID (VERIFIED, ACTIVE)
   - CREDENTIAL_STATUS: VALID (ACTIVE)

---

### Part F — Demonstrate a Tampered Document

1. Make a copy of the original PDF
2. Open the copy in a text editor or hex editor and change even one character
3. Save the modified file
4. Go to **Verify Document**
5. Upload the **modified file**
6. Expected result: **ALTERED — LEVEL_0_UNKNOWN**
7. Explanation shown: "Document content does not match the registered credential original."
8. Evidence trail shows HASH_MATCH: INVALID

This demonstrates SHA-256 tamper detection.

---

### Part G — Demonstrate Credential Revocation

1. Login as alice (ISSUER)
2. Go to **Credentials** → find the issued credential
3. Click **Revoke Credential**
4. Enter reason: `Student requested revocation`
5. Go back to **Verify Document** and upload the original PDF again
6. Expected result: **CREDENTIAL_REVOKED — LEVEL_4_SIGNATURE_VERIFIED**
7. Note the explanation: "The credential is authentic and signature is valid, but the credential was REVOKED"
8. This demonstrates the distinction — REVOKED ≠ FAKE

---

### Part H — View Audit Log

1. Login as ADMIN
2. Go to **Audit Logs**
3. You will see all security events with:
   - Sequence numbers (1, 2, 3...)
   - Actions (CREDENTIAL_ISSUED, VERIFICATION_PERFORMED, etc.)
   - Performed by user
   - Timestamp
4. Click **Validate Chain** button
5. Expected: "Chain valid — N entries verified"

---

### Part I — Demonstrate Other States

**NOT_FOUND:**
- Create any random PDF file that was never registered
- Upload it for verification
- Result: NOT_FOUND

**KEY_COMPROMISED:**
1. ADMIN → Issuers → Issuer Keys → Mark Key as COMPROMISED
2. Upload the original credential PDF again
3. Result: KEY_COMPROMISED (even though hash and signature are technically valid)

**ISSUER_SUSPENDED:**
1. ADMIN → Issuers → Suspend alice (with reason)
2. Upload original PDF
3. Result: ISSUER_SUSPENDED

---

## Useful API Endpoints for Demonstration

| Endpoint | Auth | What It Shows |
|---|---|---|
| GET /api/health | No | System operational status |
| POST /api/auth/register | No | User registration (always USER role) |
| POST /api/auth/login | No | JWT authentication |
| POST /api/verifications/verify | JWT (HR/USER) | Document verification engine |
| GET /api/audit-logs/validate | JWT (ADMIN/AUDITOR) | Hash-chain integrity |
| GET /api/credentials/:id/timeline | JWT | Credential lifecycle |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Backend won't start | Check MongoDB is running; check .env values |
| Tests hang | maxWorkers:1 is in jest.config.js — if changed, revert it |
| "No credential found" on verify | Ensure you are uploading the exact same file that was used during issuance |
| CORS error in browser | Confirm CORS_ORIGIN in .env matches the frontend URL (http://localhost:5173) |
| Seed fails | ADMIN may already exist; check MongoDB or drop the test DB |
