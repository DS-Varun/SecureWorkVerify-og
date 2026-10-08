/**
 * Demo lifecycle bootstrap seed.
 *
 * Creates ONE complete local demonstration lifecycle:
 *   ADMIN → VERIFIED ORG → ISSUER USER → ISSUER PROFILE → APPROVED
 *   → ACTIVE Ed25519 KEY → DEMO CREDENTIAL (v1) → USER VERIFIER
 *
 * SAFETY:
 *   - Requires DEMO_SEED_ALLOWED=true environment variable.
 *   - Refuses to run if the database name looks like a production database.
 *   - Does NOT delete or reset any collection.
 *   - Does NOT modify any src/ production file.
 *
 * IDEMPOTENT:
 *   Running multiple times will reuse existing records and NOT create duplicates.
 *
 * Usage (Windows):
 *   set DEMO_SEED_ALLOWED=true && npm run seed:demo
 *
 * Usage (cross-platform, already set in env):
 *   DEMO_SEED_ALLOWED=true npm run seed:demo
 */

'use strict';

// ─── Load env FIRST (populates process.env from .env) ─────────────────────────
require('../src/config/env');

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const { connectDB, disconnectDB } = require('../src/config/db');
const mongoose = require('mongoose');

const { User }         = require('../src/models/User');
const { Organization } = require('../src/models/Organization');
const { Issuer }       = require('../src/models/Issuer');
const { IssuerKey }    = require('../src/models/IssuerKey');
const { Credential }   = require('../src/models/Credential');

const issuerService     = require('../src/services/issuer.service');
const credentialService = require('../src/services/credential.service');
const keystoreService   = require('../src/services/keystore.service');

// ─── Demo Identities (deterministic, development-only) ────────────────────────

const DEMO = {
  admin: {
    name:     'SecureWork Demo Admin',
    email:    'demo.admin@securework.local',
    password: 'DemoAdmin@123',
    role:     'ADMIN',
  },
  issuer: {
    name:     'SecureWork Demo Issuer',
    email:    'demo.issuer@securework.local',
    password: 'DemoIssuer@123',
    role:     'ISSUER',
  },
  user: {
    name:     'SecureWork Demo User',
    email:    'demo.user@securework.local',
    password: 'DemoUser@123',
    role:     'USER',
  },
  org: {
    // organizationCode must match /^ORG-[A-Z0-9]{8}$/
    // Using a deterministic 8-char alphanumeric code for the demo org.
    organizationCode: 'ORG-DEMORGSW',
    name:  'SecureWork Demo University',
    type:  'UNIVERSITY',
    officialDomain: 'demo.securework.local',
    description:    'Development-only demo organization — not for production use.',
  },
  credential: {
    type:             'CERTIFICATE',
    title:            'SecureWork Demo Certificate',
    description:      'Development-only demo credential — not for production use.',
    originalFilename: 'securework-demo-credential.pdf',
    mimeType:         'application/pdf',
  },
};

// ─── Deterministic demo PDF bytes ─────────────────────────────────────────────
// This content is FIXED — the same bytes are used every run and saved to disk.
// Do NOT change this string after the first seed run, or verification will break.

const DEMO_PDF_CONTENT =
  '%PDF-1.4\n' +
  '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n' +
  '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n' +
  '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n' +
  '   /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n' +
  '4 0 obj\n<< /Length 120 >>\nstream\n' +
  'BT\n/F1 18 Tf\n72 720 Td\n' +
  '(SecureWork Demo Certificate) Tj\n' +
  '0 -30 Td /F1 12 Tf\n' +
  '(This is a development-only demo credential.) Tj\n' +
  'ET\nendstream\nendobj\n' +
  '5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n' +
  'xref\n0 6\n0000000000 65535 f\n0000000009 00000 n\n0000000068 00000 n\n' +
  '0000000125 00000 n\n0000000306 00000 n\n0000000486 00000 n\n' +
  'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n558\n%%EOF\n' +
  '% SECUREWORK-DEMO-SEED-V1\n';

const DEMO_PDF_BUFFER = Buffer.from(DEMO_PDF_CONTENT, 'utf8');

// ─── Derived path for the saved demo PDF ──────────────────────────────────────

const DEMO_DIR      = path.resolve(__dirname, '../demo');
const DEMO_PDF_PATH = path.join(DEMO_DIR, DEMO.credential.originalFilename);

// ─── Safety guard ─────────────────────────────────────────────────────────────

const PRODUCTION_DB_PATTERNS = [
  'prod', 'production', 'live', 'securework-verify\b',
];

/**
 * Abort the script with a red message and exit code 1.
 */
const abort = (msg) => {
  console.error(`\n❌ DEMO SEED ABORTED: ${msg}\n`);
  process.exit(1);
};

const checkSafetyGuards = () => {
  // 1. Require explicit opt-in flag
  if (process.env.DEMO_SEED_ALLOWED !== 'true') {
    abort(
      'DEMO_SEED_ALLOWED is not set to "true".\n\n' +
      '   To run the demo seed on Windows:\n' +
      '     set DEMO_SEED_ALLOWED=true && npm run seed:demo\n\n' +
      '   This guard prevents accidental execution against a real database.'
    );
  }

  // 2. Check database name
  const uri = process.env.MONGODB_URI || '';
  const dbName = uri.split('/').pop().split('?')[0].toLowerCase();

  const looksLikeProduction = PRODUCTION_DB_PATTERNS.some((pat) =>
    dbName.match(new RegExp(pat, 'i'))
  );

  if (looksLikeProduction) {
    abort(
      `The configured database name "${dbName}" looks like a production database.\n` +
      '   Set MONGODB_URI to a local development database before running this script.'
    );
  }

  console.log(`🔒 Safety check passed. Database: "${dbName || '(from env)'}"`);
};

// ─── Idempotent user creation ──────────────────────────────────────────────────

/**
 * Find or create a user with the given email + role.
 * Uses User.create() which triggers the pre-save bcrypt hook.
 * Does NOT go through the auth HTTP endpoint.
 */
const findOrCreateUser = async ({ name, email, password, role }) => {
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) {
    console.log(`   ↩  User already exists: ${email} [${existing.role}]`);
    return { user: existing, created: false };
  }

  const user = await User.create({
    name,
    email: email.toLowerCase(),
    passwordHash: password, // pre-save hook hashes this
    role,
    isActive: true,
  });

  console.log(`   ✅ Created user: ${email} [${role}]`);
  return { user, created: true };
};

// ─── Idempotent organization creation ─────────────────────────────────────────

/**
 * Find or create the demo organization.
 * Uses Organization.create() directly (same pattern as all test fixtures).
 * Creates it in VERIFIED state — acceptable for a demo seed (see test patterns).
 */
const findOrCreateOrg = async (adminUser) => {
  const existing = await Organization.findOne({ organizationCode: DEMO.org.organizationCode });
  if (existing) {
    console.log(`   ↩  Organization already exists: ${existing.name} [${existing._id}]`);
    return { org: existing, created: false };
  }

  const org = await Organization.create({
    organizationCode:             DEMO.org.organizationCode,
    name:                         DEMO.org.name,
    type:                         DEMO.org.type,
    officialDomain:               DEMO.org.officialDomain,
    description:                  DEMO.org.description,
    organizationVerificationStatus: 'VERIFIED',
    status:                       'ACTIVE',
    createdBy:                    adminUser._id,
    lastActionBy:                 adminUser._id,
    lastActionAt:                 new Date(),
    verificationEvents: [
      {
        fromStatus:  'PENDING',
        toStatus:    'VERIFIED',
        method:      'ADMIN_REVIEW',
        performedBy: adminUser._id,
        notes:       'Demo organization — auto-verified by demo seed script.',
        evidence:    { source: 'seed.demo.js' },
        performedAt: new Date(),
      },
    ],
  });

  console.log(`   ✅ Created organization: ${org.name} [${org._id}]`);
  return { org, created: true };
};

// ─── Idempotent issuer profile creation and approval ──────────────────────────

/**
 * Find or create the issuer profile and ensure it is ACTIVE with an ACTIVE key.
 * Uses issuerService.registerIssuer() and issuerService.approveIssuer() — the real service layer.
 */
const findOrProvisionIssuer = async ({ issuerUser, org, adminUser }) => {
  // Check for existing issuer profile
  let issuerProfile = await Issuer.findOne({ userId: issuerUser._id });
  let issuerKey     = null;
  let profileCreated = false;
  let approved       = false;

  if (!issuerProfile) {
    // Register via the real service
    issuerProfile = await issuerService.registerIssuer({
      userId:               issuerUser._id,
      organizationId:       org._id,
      authorizationEvidence: {
        source:      'seed.demo.js',
        description: 'Demo seed auto-registration',
      },
    });
    profileCreated = true;
    console.log(`   ✅ Issuer profile created: [${issuerProfile._id}] status=PENDING`);
  } else {
    console.log(`   ↩  Issuer profile already exists: [${issuerProfile._id}] status=${issuerProfile.status}`);
  }

  // Approve if still PENDING — this generates the Ed25519 keypair
  if (issuerProfile.status === 'PENDING') {
    const result = await issuerService.approveIssuer({
      issuerId:    issuerProfile._id,
      adminUserId: adminUser._id,
    });
    issuerProfile = result.issuer;
    issuerKey     = result.issuerKey;
    approved      = true;
    console.log(`   ✅ Issuer approved. ACTIVE. Key: [${issuerKey._id}]`);
  } else if (issuerProfile.status === 'ACTIVE') {
    // Find existing active key
    issuerKey = await IssuerKey.findOne({ issuerId: issuerProfile._id, status: 'ACTIVE' });
    if (!issuerKey) {
      abort(
        `Issuer [${issuerProfile._id}] is ACTIVE but has no ACTIVE IssuerKey in MongoDB.\n` +
        '   The key may have been compromised or manually removed.\n' +
        '   Resolve this manually before re-running seed:demo.'
      );
    }
    console.log(`   ↩  Issuer already ACTIVE. Key: [${issuerKey._id}]`);
  } else {
    abort(
      `Issuer [${issuerProfile._id}] has status "${issuerProfile.status}".\n` +
      '   The demo seed can only work with PENDING or ACTIVE issuers.\n' +
      '   Resolve this manually (revoke, re-register) before re-running.'
    );
  }

  // Confirm private key file exists in keystore
  const keyFileExists = keystoreService.activeKeyExists(String(issuerProfile._id));
  if (!keyFileExists) {
    abort(
      `ACTIVE IssuerKey [${issuerKey._id}] exists in MongoDB but the private key file is missing.\n` +
      `   Expected: keys/issuer_${issuerProfile._id}.key\n` +
      '   The key may have been manually deleted. The credential cannot be signed without it.'
    );
  }

  return { issuerProfile, issuerKey, profileCreated, approved };
};

// ─── Save demo PDF to backend/demo/ ──────────────────────────────────────────

/**
 * Write the deterministic demo PDF to backend/demo/ if not already present.
 * Does NOT overwrite if the file already exists, to preserve byte identity.
 */
const ensureDemoPdfOnDisk = () => {
  fs.mkdirSync(DEMO_DIR, { recursive: true });

  if (fs.existsSync(DEMO_PDF_PATH)) {
    // Verify the existing file matches — if it differs, warn but do not overwrite
    const existing = fs.readFileSync(DEMO_PDF_PATH);
    if (!existing.equals(DEMO_PDF_BUFFER)) {
      console.warn(
        `   ⚠️  WARNING: ${DEMO_PDF_PATH} already exists but its bytes differ from the seed buffer.\n` +
        '      The file was NOT overwritten. If you need to re-issue the credential,\n' +
        '      delete the file manually and run seed:demo again.'
      );
      return { written: false, mismatch: true };
    }
    console.log(`   ↩  Demo PDF already exists and matches: ${DEMO_PDF_PATH}`);
    return { written: false, mismatch: false };
  }

  fs.writeFileSync(DEMO_PDF_PATH, DEMO_PDF_BUFFER);
  console.log(`   ✅ Demo PDF written: ${DEMO_PDF_PATH}`);
  return { written: true, mismatch: false };
};

// ─── Idempotent credential creation ───────────────────────────────────────────

/**
 * Find or issue the demo credential.
 * Uses credentialService.issueCredential() — the real service layer.
 * Idempotency: checks for an existing credential by (issuerId + title + recipientId).
 */
const findOrIssueCredential = async ({ issuerUser, issuerProfile, recipientUser }) => {
  // Look for an existing demo credential for this issuer+recipient+title
  const existing = await Credential.findOne({
    issuerId:  issuerProfile._id,
    recipientId: recipientUser._id,
    title:     DEMO.credential.title,
  }).lean();

  if (existing) {
    console.log(
      `   ↩  Demo credential already exists: [${existing._id}] status=${existing.status}`
    );
    return {
      credential:        existing,
      credentialVersion: null, // already exists, we'll look it up separately
      document:          null,
      created:           false,
    };
  }

  // Issue via the real service — this: hashes the PDF, signs it, writes uploads/doc_*.pdf,
  // creates Document + Credential + CredentialVersion v1 + 3 audit log entries.
  const result = await credentialService.issueCredential({
    issuingUserId:    issuerUser._id,
    recipientId:      recipientUser._id,
    credentialType:   DEMO.credential.type,
    title:            DEMO.credential.title,
    description:      DEMO.credential.description,
    fileBuffer:       DEMO_PDF_BUFFER,
    originalFilename: DEMO.credential.originalFilename,
    mimeType:         DEMO.credential.mimeType,
    fileSize:         DEMO_PDF_BUFFER.length,
  });

  console.log(
    `   ✅ Credential issued: [${result.credential._id}]\n` +
    `      Version 1: [${result.credentialVersion._id}]\n` +
    `      Document:  [${result.document._id}]`
  );

  return { ...result, created: true };
};

// ─── Summary printer ──────────────────────────────────────────────────────────

const printSummary = ({ adminUser, issuerUser, recipientUser, org, issuerProfile, issuerKey, credential, credentialVersion }) => {
  const docHash = crypto.createHash('sha256').update(DEMO_PDF_BUFFER).digest('hex');

  const cvId     = credentialVersion ? credentialVersion._id : '(already existed — see DB)';
  const cvStatus = credentialVersion ? credentialVersion.status : '(check DB for current version)';
  const cvNum    = credentialVersion ? credentialVersion.versionNumber : 1;

  console.log(`
╔══════════════════════════════════════════════════════════════════╗
║                    DEMO SEED COMPLETE                            ║
╠══════════════════════════════════════════════════════════════════╣
║  Admin:              ${adminUser.email.padEnd(44)}║
║  Issuer:             ${issuerUser.email.padEnd(44)}║
║  Verifier:           ${recipientUser.email.padEnd(44)}║
╠══════════════════════════════════════════════════════════════════╣
║  Organization:  ${org.name.substring(0, 49).padEnd(49)}║
║    ID:          ${String(org._id).padEnd(49)}║
╠══════════════════════════════════════════════════════════════════╣
║  Issuer Profile:${' '.repeat(49)}║
║    ID:          ${String(issuerProfile._id).padEnd(49)}║
║    Status:      ${String(issuerProfile.status).padEnd(49)}║
╠══════════════════════════════════════════════════════════════════╣
║  Issuer Key:    ${' '.repeat(49)}║
║    ID:          ${String(issuerKey._id).padEnd(49)}║
║    Status:      ${String(issuerKey.status).padEnd(49)}║
╠══════════════════════════════════════════════════════════════════╣
║  Credential:    ${' '.repeat(49)}║
║    ID:          ${String(credential._id).padEnd(49)}║
║    Status:      ${String(credential.status).padEnd(49)}║
╠══════════════════════════════════════════════════════════════════╣
║  Credential Version:${' '.repeat(45)}║
║    ID:          ${String(cvId).substring(0, 49).padEnd(49)}║
║    Version:     ${String(cvNum).padEnd(49)}║
║    Status:      ${String(cvStatus).padEnd(49)}║
╠══════════════════════════════════════════════════════════════════╣
║  Demo document:${' '.repeat(50)}║`);
  // Split long path across 2 lines if needed
  const pathStr = DEMO_PDF_PATH;
  const pathLine1 = pathStr.substring(0, 49);
  const pathLine2 = pathStr.substring(49, 98);
  console.log(`║    ${pathLine1.padEnd(62)}║`);
  if (pathLine2) console.log(`║    ${pathLine2.padEnd(62)}║`);
  console.log(`╠══════════════════════════════════════════════════════════════════╣`);
  console.log(`║  Document SHA-256:${' '.repeat(47)}║`);
  console.log(`║    ${docHash.padEnd(62)}║`);
  console.log(`╚══════════════════════════════════════════════════════════════════╝`);

  console.log(`
📋 DEMO LOGIN CREDENTIALS (development only — NOT for production):
   Admin:    ${DEMO.admin.email}   /  ${DEMO.admin.password}
   Issuer:   ${DEMO.issuer.email}  /  ${DEMO.issuer.password}
   Verifier: ${DEMO.user.email}    /  ${DEMO.user.password}

📄 To test VERIFIED / LEVEL_5_CURRENTLY_VALID:
   Upload this exact file through the normal USER verification UI/API:
   ${DEMO_PDF_PATH}

🚀 Re-run command (Windows):
   set DEMO_SEED_ALLOWED=true && npm run seed:demo
`);
};

// ─── Main ─────────────────────────────────────────────────────────────────────

const main = async () => {
  // Step 0: Safety guards — must pass before ANY database operation
  checkSafetyGuards();

  console.log('\n🌱 Starting demo seed...\n');

  await connectDB();

  try {
    // Step 1: ADMIN user
    console.log('👤 [1/6] ADMIN user...');
    const { user: adminUser } = await findOrCreateUser(DEMO.admin);

    // Step 2: ISSUER user
    console.log('👤 [2/6] ISSUER user...');
    const { user: issuerUser } = await findOrCreateUser(DEMO.issuer);

    // Step 3: USER (verifier)
    console.log('👤 [3/6] USER (verifier)...');
    const { user: recipientUser } = await findOrCreateUser(DEMO.user);

    // Step 4: VERIFIED organization
    console.log('🏛  [4/6] Organization...');
    const { org } = await findOrCreateOrg(adminUser);

    // Step 5: Issuer profile + approval + key generation
    console.log('🔑 [5/6] Issuer profile + approval...');
    const { issuerProfile, issuerKey } = await findOrProvisionIssuer({
      issuerUser,
      org,
      adminUser,
    });

    // Step 6: Demo PDF + credential
    console.log('📄 [6/6] Demo PDF + credential...');

    // Always ensure the PDF is on disk (idempotent write)
    ensureDemoPdfOnDisk();

    const { credential, credentialVersion } = await findOrIssueCredential({
      issuerUser,
      issuerProfile,
      recipientUser,
    });

    // Fetch fresh credential for accurate status display
    const freshCredential = await Credential.findById(credential._id).lean();

    console.log('\n');
    printSummary({
      adminUser,
      issuerUser,
      recipientUser,
      org,
      issuerProfile,
      issuerKey,
      credential:        freshCredential,
      credentialVersion,
    });

    await disconnectDB();
    process.exit(0);

  } catch (err) {
    console.error('\n❌ Demo seed failed:');
    console.error('   Message:', err.message);
    if (err.stack) {
      console.error('   Stack:', err.stack.split('\n').slice(1, 4).join('\n           '));
    }
    await disconnectDB();
    process.exit(1);
  }
};

main();
