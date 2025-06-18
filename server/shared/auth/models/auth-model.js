// server/shared/auth/models/auth-model.js
/**
 * @file Authentication Model
 * @description Comprehensive authentication model with advanced features
 * @version 3.0.0
 */

const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const config = require('../../config/config');
const constants = require('../../config/constants');

/**
 * Authentication Schema
 */
const authSchema = new mongoose.Schema({
  // User reference
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  
  // Authentication methods
  authMethods: {
    local: {
      email: {
        type: String,
        lowercase: true,
        trim: true,
        sparse: true,
        index: true
      },
      password: String,
      passwordHistory: [{
        hash: String,
        changedAt: Date
      }],
      isVerified: {
        type: Boolean,
        default: false
      },
      verificationToken: String,
      verificationExpiry: Date
    },
    
    oauth: {
      google: {
        id: String,
        email: String,
        displayName: String,
        picture: String,
        refreshToken: String,
        accessToken: String,
        tokenExpiry: Date
      },
      github: {
        id: String,
        username: String,
        email: String,
        avatar: String,
        accessToken: String
      },
      linkedin: {
        id: String,
        email: String,
        firstName: String,
        lastName: String,
        picture: String,
        accessToken: String,
        tokenExpiry: Date
      }
    },
    
    passkey: {
      credentials: [{
        credentialId: {
          type: String,
          required: true,
          unique: true
        },
        publicKey: {
          type: Buffer,
          required: true
        },
        counter: {
          type: Number,
          default: 0
        },
        deviceType: String,
        transports: [String],
        createdAt: {
          type: Date,
          default: Date.now
        },
        lastUsedAt: Date,
        name: String
      }],
      challenges: [{
        challenge: String,
        createdAt: Date,
        expiresAt: Date,
        used: {
          type: Boolean,
          default: false
        }
      }]
    },
    
    saml: {
      nameId: String,
      nameIdFormat: String,
      sessionIndex: String,
      attributes: mongoose.Schema.Types.Mixed
    },
    
    organizationSSO: {
      provider: String,
      identifier: String,
      attributes: mongoose.Schema.Types.Mixed,
      lastSyncedAt: Date
    }
  },
  
  // Multi-factor authentication
  mfa: {
    enabled: {
      type: Boolean,
      default: false
    },
    methods: [{
      type: {
        type: String,
        enum: constants.AUTH.MFA_METHOD_TYPES_ENUM,
        required: true
      },
      enabled: {
        type: Boolean,
        default: true
      },
      isPrimary: {
        type: Boolean,
        default: false
      },
      config: {
        // TOTP specific
        totpSecret: String,
        
        // SMS specific
        phoneNumber: String,
        phoneVerified: Boolean,
        
        // Email specific
        email: String,
        emailVerified: Boolean,
        
        // Backup codes
        codes: [{
          code: String,
          used: Boolean,
          usedAt: Date
        }],
        
        // Push notification
        devices: [{
          deviceId: String,
          deviceName: String,
          platform: String,
          pushToken: String,
          addedAt: Date
        }],
        
        // Biometric
        biometricId: String,
        biometricType: String
      },
      setupAt: Date,
      lastUsedAt: Date,
      verificationAttempts: {
        type: Number,
        default: 0
      }
    }]
  },
  
  // Sessions management
  sessions: [{
    sessionId: {
      type: String,
      required: true,
      unique: true
    },
    deviceInfo: {
      userAgent: String,
      platform: String,
      browser: String,
      version: String,
      os: String,
      device: String
    },
    location: {
      ip: String,
      country: String,
      region: String,
      city: String,
      timezone: String,
      coordinates: {
        latitude: Number,
        longitude: Number
      }
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    lastActivityAt: {
      type: Date,
      default: Date.now
    },
    expiresAt: Date,
    isActive: {
      type: Boolean,
      default: true
    },
    revokedAt: Date,
    revokedReason: String
  }],
  
  // Security settings
  security: {
    passwordPolicy: {
      minLength: {
        type: Number,
        default: 12
      },
      requireUppercase: {
        type: Boolean,
        default: true
      },
      requireLowercase: {
        type: Boolean,
        default: true
      },
      requireNumbers: {
        type: Boolean,
        default: true
      },
      requireSpecialChars: {
        type: Boolean,
        default: true
      },
      preventReuse: {
        type: Number,
        default: 5
      },
      expiryDays: Number
    },
    
    loginAttempts: {
      count: {
        type: Number,
        default: 0
      },
      lastAttempt: Date,
      lockedUntil: Date
    },
    
    passwordReset: {
      token: String,
      tokenExpiry: Date,
      requestedAt: Date,
      requestedFrom: {
        ip: String,
        userAgent: String
      }
    },
    
    accountRecovery: {
      questions: [{
        question: String,
        answerHash: String
      }],
      recoveryEmail: String,
      recoveryPhone: String,
      backupCodes: [{
        code: String,
        used: Boolean,
        usedAt: Date
      }]
    },
    
    trustedDevices: [{
      deviceId: String,
      deviceFingerprint: String,
      trustToken: String,
      trustedAt: Date,
      lastSeenAt: Date,
      name: String
    }],
    
    suspiciousActivity: [{
      type: {
        type: String,
        enum: constants.AUTH.SUSPICIOUS_ACTIVITY_TYPES_ENUM
      },
      detectedAt: Date,
      details: mongoose.Schema.Types.Mixed,
      resolved: Boolean,
      resolvedAt: Date,
      action: String
    }]
  },
  
  // Consent and compliance
  consent: {
    termsOfService: {
      accepted: Boolean,
      version: String,
      acceptedAt: Date,
      ip: String
    },
    privacyPolicy: {
      accepted: Boolean,
      version: String,
      acceptedAt: Date,
      ip: String
    },
    dataProcessing: {
      marketing: Boolean,
      analytics: Boolean,
      thirdPartySharing: Boolean,
      consentedAt: Date
    },
    cookieConsent: {
      necessary: {
        type: Boolean,
        default: true
      },
      functional: Boolean,
      analytics: Boolean,
      marketing: Boolean,
      consentedAt: Date
    }
  },
  
  // Activity tracking
  activity: {
    lastLogin: Date,
    lastLogout: Date,
    lastPasswordChange: Date,
    lastProfileUpdate: Date,
    loginCount: {
      type: Number,
      default: 0
    },
    
    loginHistory: [{
      timestamp: Date,
      ip: String,
      userAgent: String,
      location: {
        country: String,
        city: String
      },
      method: String,
      success: Boolean,
      mfaUsed: Boolean
    }],
    
    securityEvents: [{
      event: String,
      timestamp: Date,
      ip: String,
      details: mongoose.Schema.Types.Mixed
    }]
  },
  
  // Metadata
  metadata: {
    createdBy: {
      userId: mongoose.Schema.Types.ObjectId,
      method: String
    },
    lastModifiedBy: {
      userId: mongoose.Schema.Types.ObjectId,
      action: String
    },
    source: {
      type: String,
      enum: constants.AUTH.SOURCE_TYPES_ENUM
    },
    migratedFrom: String,
    customFields: mongoose.Schema.Types.Mixed
  }
}, {
  timestamps: true,
  collection: 'authentications'
});

// Indexes
authSchema.index({ 'authMethods.local.email': 1 });
authSchema.index({ 'authMethods.oauth.google.id': 1 });
authSchema.index({ 'authMethods.oauth.github.id': 1 });
authSchema.index({ 'authMethods.oauth.linkedin.id': 1 });
authSchema.index({ 'authMethods.passkey.credentials.credentialId': 1 });
authSchema.index({ 'sessions.sessionId': 1 });
authSchema.index({ 'security.passwordReset.token': 1 });
authSchema.index({ 'activity.lastLogin': -1 });
authSchema.index({ createdAt: -1 });

// Virtual for active sessions count
authSchema.virtual('activeSessionsCount').get(function() {
  return this.sessions.filter(session => 
    session.isActive && (!session.expiresAt || session.expiresAt > new Date())
  ).length;
});

// Virtual for MFA enabled check
authSchema.virtual('isMfaEnabled').get(function() {
  return this.mfa.enabled && this.mfa.methods.some(method => method.enabled);
});

/**
 * Instance Methods
 */

// Verify password
authSchema.methods.verifyPassword = async function(password) {
  if (!this.authMethods.local.password) {
    return false;
  }
  return bcrypt.compare(password, this.authMethods.local.password);
};

// Set password with history check
authSchema.methods.setPassword = async function(password) {
  // Check password history
  const historyLimit = this.security.passwordPolicy.preventReuse || 5;
  const recentPasswords = this.authMethods.local.passwordHistory.slice(-historyLimit);
  
  for (const oldPassword of recentPasswords) {
    const isReused = await bcrypt.compare(password, oldPassword.hash);
    if (isReused) {
      throw new Error('Password has been used recently');
    }
  }
  
  // Hash new password with corrected configuration reference
  const saltRounds = config.auth.saltRounds || 10; // Fixed: use saltRounds instead of bcryptRounds
  const hash = await bcrypt.hash(password, saltRounds);
  
  // Update password and history
  this.authMethods.local.password = hash;
  this.authMethods.local.passwordHistory.push({
    hash,
    changedAt: new Date()
  });
  
  // Limit history size
  if (this.authMethods.local.passwordHistory.length > historyLimit + 5) {
    this.authMethods.local.passwordHistory = this.authMethods.local.passwordHistory.slice(-historyLimit);
  }
  
  this.activity.lastPasswordChange = new Date();
};

// Generate verification token
authSchema.methods.generateVerificationToken = function() {
  const token = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  
  this.authMethods.local.verificationToken = hashedToken;
  this.authMethods.local.verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
  
  return token;
};

// Verify email token
authSchema.methods.verifyEmailToken = function(token) {
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  
  if (this.authMethods.local.verificationToken !== hashedToken) {
    return false;
  }
  
  if (this.authMethods.local.verificationExpiry < new Date()) {
    return false;
  }
  
  this.authMethods.local.isVerified = true;
  this.authMethods.local.verificationToken = undefined;
  this.authMethods.local.verificationExpiry = undefined;
  
  return true;
};

// Generate password reset token
authSchema.methods.generatePasswordResetToken = function() {
  const token = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  
  this.security.passwordReset = {
    token: hashedToken,
    tokenExpiry: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
    requestedAt: new Date()
  };
  
  return token;
};

// Add login attempt
authSchema.methods.addLoginAttempt = function(success = false) {
  if (success) {
    this.security.loginAttempts.count = 0;
    this.security.loginAttempts.lockedUntil = undefined;
  } else {
    this.security.loginAttempts.count += 1;
    this.security.loginAttempts.lastAttempt = new Date();
    
    // Lock account after max attempts
    if (this.security.loginAttempts.count >= config.security.maxLoginAttempts) {
      this.security.loginAttempts.lockedUntil = new Date(
        Date.now() + config.security.lockoutDuration
      );
    }
  }
};

// Check if account is locked
authSchema.methods.isLocked = function() {
  return !!(this.security.loginAttempts.lockedUntil && 
            this.security.loginAttempts.lockedUntil > new Date());
};

// Add session
authSchema.methods.addSession = function(sessionData) {
  // Remove expired sessions
  this.sessions = this.sessions.filter(session => 
    !session.expiresAt || session.expiresAt > new Date()
  );
  
  // Add new session
  const session = {
    sessionId: crypto.randomBytes(32).toString('hex'),
    ...sessionData,
    createdAt: new Date(),
    lastActivityAt: new Date(),
    isActive: true
  };
  
  this.sessions.push(session);
  this.activity.lastLogin = new Date();
  this.activity.loginCount += 1;
  
  return session;
};

// Revoke session
authSchema.methods.revokeSession = function(sessionId, reason) {
  const session = this.sessions.find(s => s.sessionId === sessionId);
  if (session) {
    session.isActive = false;
    session.revokedAt = new Date();
    session.revokedReason = reason;
  }
};

// Update session activity
authSchema.methods.updateSessionActivity = function(sessionId) {
  const session = this.sessions.find(s => s.sessionId === sessionId);
  if (session && session.isActive) {
    session.lastActivityAt = new Date();
  }
};

// Add MFA method
authSchema.methods.addMfaMethod = function(method, config) {
  const existingMethod = this.mfa.methods.find(m => m.type === method);
  
  if (existingMethod) {
    existingMethod.config = { ...existingMethod.config, ...config };
    existingMethod.enabled = true;
  } else {
    this.mfa.methods.push({
      type: method,
      enabled: true,
      config,
      setupAt: new Date()
    });
  }
  
  if (!this.mfa.enabled && this.mfa.methods.length > 0) {
    this.mfa.enabled = true;
  }
};

// Generate backup codes
authSchema.methods.generateBackupCodes = function(count = 10) {
  const codes = [];
  
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push({
      code: crypto.createHash('sha256').update(code).digest('hex'),
      used: false
    });
  }
  
  const backupMethod = this.mfa.methods.find(m => m.type === 'backup_codes');
  if (backupMethod) {
    backupMethod.config.codes = codes;
  } else {
    this.addMfaMethod('backup_codes', { codes });
  }
  
  // Return unhashed codes for user
  return codes.map((_, i) => 
    crypto.randomBytes(4).toString('hex').toUpperCase()
  );
};

// Add trusted device
authSchema.methods.addTrustedDevice = function(deviceInfo) {
  const device = {
    deviceId: crypto.randomBytes(16).toString('hex'),
    trustToken: crypto.randomBytes(32).toString('hex'),
    trustedAt: new Date(),
    lastSeenAt: new Date(),
    ...deviceInfo
  };
  
  this.security.trustedDevices.push(device);
  
  // Limit to 10 devices
  if (this.security.trustedDevices.length > 10) {
    this.security.trustedDevices = this.security.trustedDevices
      .sort((a, b) => b.lastSeenAt - a.lastSeenAt)
      .slice(0, 10);
  }
  
  return device;
};

// Record suspicious activity
authSchema.methods.recordSuspiciousActivity = function(type, details) {
  this.security.suspiciousActivity.push({
    type,
    detectedAt: new Date(),
    details,
    resolved: false
  });
  
  // Trigger security alert if needed
  if (this.security.suspiciousActivity.filter(a => !a.resolved).length >= 3) {
    // This would trigger security notifications
    this.markModified('security.suspiciousActivity');
  }
};

// Accept consent
authSchema.methods.acceptConsent = function(type, version, ip) {
  const consentData = {
    accepted: true,
    version,
    acceptedAt: new Date(),
    ip
  };
  
  switch (type) {
    case 'terms':
      this.consent.termsOfService = consentData;
      break;
    case 'privacy':
      this.consent.privacyPolicy = consentData;
      break;
    case 'cookies':
      this.consent.cookieConsent = {
        ...this.consent.cookieConsent,
        consentedAt: new Date()
      };
      break;
  }
};

/**
 * Static Methods
 */

// Find by email across auth methods
authSchema.statics.findByEmail = async function(email) {
  return this.findOne({
    $or: [
      { 'authMethods.local.email': email.toLowerCase() },
      { 'authMethods.oauth.google.email': email },
      { 'authMethods.oauth.github.email': email },
      { 'authMethods.oauth.linkedin.email': email }
    ]
  });
};

// Find by OAuth provider
authSchema.statics.findByOAuthProvider = async function(provider, providerId) {
  const query = {};
  query[`authMethods.oauth.${provider}.id`] = providerId;
  return this.findOne(query);
};

// Find by passkey credential
authSchema.statics.findByPasskeyCredential = async function(credentialId) {
  return this.findOne({
    'authMethods.passkey.credentials.credentialId': credentialId
  });
};

// Find by session
authSchema.statics.findBySession = async function(sessionId) {
  return this.findOne({
    'sessions.sessionId': sessionId,
    'sessions.isActive': true
  });
};

// Find by password reset token
authSchema.statics.findByPasswordResetToken = async function(token) {
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  
  return this.findOne({
    'security.passwordReset.token': hashedToken,
    'security.passwordReset.tokenExpiry': { $gt: new Date() }
  });
};

// Clean up expired data
authSchema.statics.cleanupExpiredData = async function() {
  const now = new Date();
  
  // Remove expired sessions
  await this.updateMany(
    {},
    {
      $pull: {
        sessions: {
          $or: [
            { expiresAt: { $lt: now } },
            { isActive: false, revokedAt: { $lt: new Date(now - 30 * 24 * 60 * 60 * 1000) } }
          ]
        },
        'authMethods.passkey.challenges': {
          expiresAt: { $lt: now }
        }
      }
    }
  );
  
  // Clear expired password reset tokens
  await this.updateMany(
    { 'security.passwordReset.tokenExpiry': { $lt: now } },
    { $unset: { 'security.passwordReset': 1 } }
  );
};

// Get authentication statistics
authSchema.statics.getAuthStats = async function(userId) {
  const auth = await this.findOne({ userId });
  if (!auth) return null;
  
  return {
    authMethods: {
      local: !!auth.authMethods.local.password,
      google: !!auth.authMethods.oauth.google.id,
      github: !!auth.authMethods.oauth.github.id,
      linkedin: !!auth.authMethods.oauth.linkedin.id,
      passkey: auth.authMethods.passkey.credentials.length > 0,
      sso: !!auth.authMethods.organizationSSO.provider
    },
    mfa: {
      enabled: auth.mfa.enabled,
      methods: auth.mfa.methods.map(m => ({
        type: m.type,
        enabled: m.enabled,
        setupAt: m.setupAt
      }))
    },
    security: {
      lastPasswordChange: auth.activity.lastPasswordChange,
      activeSessions: auth.activeSessionsCount,
      trustedDevices: auth.security.trustedDevices.length,
      suspiciousActivities: auth.security.suspiciousActivity.filter(a => !a.resolved).length
    },
    activity: {
      lastLogin: auth.activity.lastLogin,
      loginCount: auth.activity.loginCount,
      recentLogins: auth.activity.loginHistory.slice(-5)
    }
  };
};

// Pre-save middleware
authSchema.pre('save', async function(next) {
  // Clean up old login history
  if (this.activity.loginHistory.length > 100) {
    this.activity.loginHistory = this.activity.loginHistory.slice(-50);
  }
  
  // Clean up old security events
  if (this.activity.securityEvents.length > 100) {
    this.activity.securityEvents = this.activity.securityEvents.slice(-50);
  }
  
  next();
});

// Create model
const Auth = mongoose.model('Auth', authSchema);

module.exports = Auth;