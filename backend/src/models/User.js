/**
 * User model.
 * Stores authentication credentials and role information.
 * passwordHash is NEVER returned in queries by default.
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const ROLES = ['ADMIN', 'ISSUER', 'HR', 'USER', 'AUDITOR'];

// Roles that public registration is NOT allowed to self-assign
const PRIVILEGED_ROLES = ['ADMIN', 'ISSUER', 'HR', 'AUDITOR'];

// The only role assignable via public registration
const PUBLIC_REGISTRATION_ROLE = 'USER';

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      minlength: [2, 'Name must be at least 2 characters'],
      maxlength: [100, 'Name cannot exceed 100 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email'],
    },
    passwordHash: {
      type: String,
      required: [true, 'Password is required'],
      select: false, // Never returned by default
    },
    role: {
      type: String,
      enum: {
        values: ROLES,
        message: 'Role must be one of: ' + ROLES.join(', '),
      },
      required: [true, 'Role is required'],
    },
    isActive: {
      type: Boolean,
      default: true,
    },

    /**
     * Optional organization membership.
     * Set by ADMIN when promoting a user to HR or ISSUER role.
     * Used for HR credential scoping (PROJECT_RULES §3, M3 Decision A).
     * NULL for ADMIN, AUDITOR, and unaffiliated USER accounts.
     */
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      default: null,
    },
  },
  {
    timestamps: true, // createdAt, updatedAt
  }
);

/**
 * Hash password before saving.
 */
userSchema.pre('save', async function (next) {
  if (!this.isModified('passwordHash')) return next();
  const salt = await bcrypt.genSalt(12);
  this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
  next();
});

/**
 * Compare a candidate password against the stored hash.
 * @param {string} candidatePassword
 * @returns {Promise<boolean>}
 */
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

/**
 * Remove sensitive fields when converting to JSON.
 */
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  delete obj.__v;
  return obj;
};

const User = mongoose.model('User', userSchema);

module.exports = { User, ROLES, PRIVILEGED_ROLES, PUBLIC_REGISTRATION_ROLE };
