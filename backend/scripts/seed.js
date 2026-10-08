/**
 * Seed script — creates the initial ADMIN user.
 * Run with: npm run seed
 *
 * Reads ADMIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD from environment.
 */

const config = require('../src/config/env');
const { connectDB, disconnectDB } = require('../src/config/db');
const { User } = require('../src/models/User');

const seed = async () => {
  const name = process.env.ADMIN_NAME || 'System Admin';
  const email = (process.env.ADMIN_EMAIL || 'admin@securework.local').toLowerCase();
  const password = process.env.ADMIN_PASSWORD;

  if (!password) {
    console.error('❌ ADMIN_PASSWORD environment variable is required.');
    process.exit(1);
  }

  try {
    await connectDB();

    // Check if admin already exists
    const existing = await User.findOne({ email });
    if (existing) {
      console.log(`ℹ️  Admin user already exists: ${email}`);
      await disconnectDB();
      return;
    }

    // Create admin
    const admin = await User.create({
      name,
      email,
      passwordHash: password, // pre-save hook will hash it
      role: 'ADMIN',
      isActive: true,
    });

    console.log(`✅ Admin user created:`);
    console.log(`   Name:  ${admin.name}`);
    console.log(`   Email: ${admin.email}`);
    console.log(`   Role:  ${admin.role}`);

    await disconnectDB();
  } catch (error) {
    console.error('❌ Seed failed:', error.message);
    await disconnectDB();
    process.exit(1);
  }
};

seed();
