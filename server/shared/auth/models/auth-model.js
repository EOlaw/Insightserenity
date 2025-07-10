// server/shared/auth/models/auth-model.js
/**
 * @file Authentication Model - Complete Fixed Version
 * @description Comprehensive authentication model with resolved passkey constraints
 * @version 3.1.0
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const TwoFactorService = require('../services/two-factor-service');

const config = require('../../config/config');
const constants = require('../../config/constants');
const logger = require('../../utils/logger');

/**
 * Authentication Schema - Complete Fixed Version
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
        sparse: true
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
    
    // FIXED: Passkey schema without conflicting constraints
    passkey: {
      credentials: [{
        credentialId: {
          type: String
          // Removed required and unique constraints to prevent conflicts
        },
        publicKey: {
          type: Buffer
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
        totpSecret: mongoose.Schema.Types.Mixed,
        
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
    }],
    pendingSetup: {
      method: {
        type: String,
        enum: ['totp', 'sms', 'email', 'backup_codes']
      },
      secret: mongoose.Schema.Types.Mixed, // For encrypted TOTP secrets
      setupToken: String,
      expiresAt: Date,
      phoneNumber: String, // For SMS setup
      email: String, // For email setup
      verificationCode: String, // For SMS/Email verification codes
      codes: [{
        code: String,
        used: Boolean,
        usedAt: Date,
        generatedAt: Date
      }],
      attemptsRemaining: { type: Number, default: 3 } // ADD THIS LINE
    },
    activeChallenge: {
      method: {
        type: String,
        enum: ['sms', 'email']
      },
      code: String, // Hashed verification code
      expiresAt: Date,
      attemptsRemaining: { type: Number, default: 3 },
      createdAt: { type: Date, default: Date.now }
    }
  },
  
  // Sessions management
  sessions: [{
    sessionId: {
      type: String,
      required: true
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

// FIXED: Proper index definitions with sparse indexes for optional unique fields
authSchema.index({ 'authMethods.local.email': 1 }, { sparse: true });
authSchema.index({ 'authMethods.oauth.google.id': 1 }, { sparse: true });
authSchema.index({ 'authMethods.oauth.github.id': 1 }, { sparse: true });
authSchema.index({ 'authMethods.oauth.linkedin.id': 1 }, { sparse: true });

// FIXED: Sparse unique index for passkey credentials
authSchema.index(
  { 'authMethods.passkey.credentials.credentialId': 1 }, 
  { 
    unique: true, 
    sparse: true,
    name: 'passkey_credential_id_unique_sparse'
  }
);

authSchema.index({ 'sessions.sessionId': 1 }, { sparse: true });
authSchema.index({ 'security.passwordReset.token': 1 }, { sparse: true });
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
  
  // Hash new password
  const saltRounds = config.auth.saltRounds || 10;
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
    if (this.security.loginAttempts.count >= (config.security?.maxLoginAttempts || 5)) {
      this.security.loginAttempts.lockedUntil = new Date(
        Date.now() + (config.security?.lockoutDuration || 900000) // 15 minutes default
      );
    }
  }
};

// Reset login attempts
authSchema.methods.resetLoginAttempts = function() {
  this.security.loginAttempts.count = 0;
  this.security.loginAttempts.lockedUntil = undefined;
  this.security.loginAttempts.lastAttempt = undefined;
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
  const plainCodes = [];
  
  for (let i = 0; i < count; i++) {
    const plainCode = crypto.randomBytes(4).toString('hex').toUpperCase();
    const hashedCode = crypto.createHash('sha256').update(plainCode).digest('hex');
    
    codes.push({
      code: hashedCode,
      used: false
    });
    plainCodes.push(plainCode);
  }
  
  const backupMethod = this.mfa.methods.find(m => m.type === 'backup_codes');
  if (backupMethod) {
    backupMethod.config.codes = codes;
  } else {
    this.addMfaMethod('backup_codes', { codes });
  }
  
  return plainCodes;
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

/**
 * Get MFA methods for user (enhanced status)
 * @param {string} userId - User ID
 * @returns {Promise<Object>} MFA methods and availability
 */
authSchema.statics.getMfaMethods = async function(userId) {
  try {
    const status = await this.get2FAStatus(userId);
    
    return {
      enabled: status.enabled,
      available: ['totp', 'sms', 'backup_codes'],
      configured: status.methods || [],
      primary: status.method,
      backupCodesRemaining: status.backupCodesRemaining || 0,
      recommendations: {
        setupTOTP: !status.enabled || status.method !== 'totp',
        setupSMS: !status.enabled || status.method !== 'sms',
        generateBackupCodes: !status.enabled || status.backupCodesRemaining < 3
      }
    };
  } catch (error) {
    logger.error('Get MFA methods failed', { error, userId });
    return { enabled: false, available: [], configured: [] };
  }
};

/**
 * Bridge method to verify 2FA code - connects middleware to TwoFactorService
 * @param {string} userId - User ID
 * @param {string} code - 2FA code to verify
 * @returns {Promise<boolean>} Verification result
 */
authSchema.statics.verify2FACode = async function(userId, code) {
  try {
    const auth = await this.findOne({ userId }).populate('userId');
    if (!auth || !auth.isMfaEnabled) {
      return false;
    }

    // Create a bridge user object that TwoFactorService expects
    const bridgeUser = createBridgeUser(auth);
    
    // Delegate to TwoFactorService
    return await TwoFactorService.verifyToken(userId, code);
  } catch (error) {
    logger.error('2FA verification failed in AuthModel', { error, userId });
    return false;
  }
};

/**
 * Setup TOTP for user
 * @param {string} userId - User ID
 * @returns {Promise<Object>} Setup data including QR code
 */
authSchema.statics.setup2FA = async function(userId, method = 'totp') {
  try {
    const auth = await this.findOne({ userId }).populate('userId');
    if (!auth) {
      throw new Error('User authentication record not found');
    }

    const bridgeUser = createBridgeUser(auth);
    
    let setupResult;
    switch (method) {
      case 'totp':
        setupResult = await TwoFactorService.setupTOTP(bridgeUser);
        break;
      case 'sms':
        const phoneNumber = auth.mfa.pendingSetup?.phoneNumber;
        if (!phoneNumber) {
          throw new Error('Phone number required for SMS setup');
        }
        setupResult = await TwoFactorService.setupSMS(bridgeUser, phoneNumber);
        break;
      default:
        throw new Error(`Unsupported 2FA method: ${method}`);
    }

    // Store pending setup in AuthModel format
    auth.mfa.pendingSetup = {
      method,
      secret: setupResult.tempId, // Store tempId for TOTP
      setupToken: setupResult.tempId,
      expiresAt: new Date(Date.now() + 3600000), // 1 hour
      attemptsRemaining: 3
    };

    await auth.save();
    return setupResult;
  } catch (error) {
    logger.error('2FA setup failed in AuthModel', { error, userId });
    throw error;
  }
};

/**
 * Enable 2FA for user after verification
 * @param {string} userId - User ID
 * @param {string} code - Verification code
 * @param {string} method - 2FA method
 * @returns {Promise<Object>} Enable result
 */
authSchema.statics.enable2FA = async function(userId, code, method = 'totp') {
  try {
    const auth = await this.findOne({ userId }).populate('userId');
    if (!auth || !auth.mfa.pendingSetup) {
      throw new Error('No pending 2FA setup found');
    }

    const bridgeUser = createBridgeUser(auth);
    const tempId = auth.mfa.pendingSetup.setupToken;
    
    let enableResult;
    switch (method) {
      case 'totp':
        enableResult = await TwoFactorService.enableTOTP(bridgeUser, tempId, code);
        break;
      case 'sms':
        const phoneNumber = auth.mfa.pendingSetup.phoneNumber;
        enableResult = await TwoFactorService.enableSMS(bridgeUser, phoneNumber, code);
        break;
      default:
        throw new Error(`Unsupported 2FA method: ${method}`);
    }

    // Update AuthModel with enabled 2FA
    auth.mfa.enabled = true;
    
    // Add or update the method
    const existingMethodIndex = auth.mfa.methods.findIndex(m => m.type === method);
    const methodConfig = {
      type: method,
      enabled: true,
      isPrimary: auth.mfa.methods.length === 0, // First method is primary
      config: {},
      setupAt: new Date(),
      verificationAttempts: 0
    };

    if (method === 'totp') {
      // The TwoFactorService has stored the secret in the user.security format
      // We need to extract it and store in our format
      methodConfig.config.totpSecret = bridgeUser.security?.totpSecret;
    } else if (method === 'sms') {
      methodConfig.config.phoneNumber = auth.mfa.pendingSetup.phoneNumber;
      methodConfig.config.phoneVerified = true;
    }

    // Store backup codes in our format
    if (enableResult.backupCodes) {
      methodConfig.config.codes = enableResult.backupCodes.map(code => ({
        code: crypto.createHash('sha256').update(code).digest('hex'),
        used: false,
        usedAt: null
      }));
    }

    if (existingMethodIndex >= 0) {
      auth.mfa.methods[existingMethodIndex] = methodConfig;
    } else {
      auth.mfa.methods.push(methodConfig);
    }

    // Clear pending setup
    auth.mfa.pendingSetup = undefined;

    await auth.save();
    return enableResult;
  } catch (error) {
    logger.error('2FA enable failed in AuthModel', { error, userId });
    throw error;
  }
};

/**
 * Disable 2FA for user
 * @param {string} userId - User ID
 * @param {string} password - User password for verification
 * @returns {Promise<Object>} Disable result
 */
authSchema.statics.disable2FA = async function(userId, password) {
  try {
    const auth = await this.findOne({ userId }).populate('userId');
    if (!auth) {
      throw new Error('User authentication record not found');
    }

    const bridgeUser = createBridgeUser(auth);
    
    // Delegate to TwoFactorService for password verification and logging
    const disableResult = await TwoFactorService.disable2FA(bridgeUser, password);

    // Update AuthModel
    auth.mfa.enabled = false;
    auth.mfa.methods = [];
    auth.mfa.pendingSetup = undefined;
    auth.mfa.activeChallenge = undefined;

    await auth.save();
    return disableResult;
  } catch (error) {
    logger.error('2FA disable failed in AuthModel', { error, userId });
    throw error;
  }
};

/**
 * Get 2FA status for user
 * @param {string} userId - User ID
 * @returns {Promise<Object>} 2FA status
 */
authSchema.statics.get2FAStatus = async function(userId) {
  try {
    const auth = await this.findOne({ userId });
    if (!auth) {
      return { enabled: false };
    }

    const primaryMethod = auth.mfa.methods.find(m => m.isPrimary && m.enabled);
    const backupMethod = auth.mfa.methods.find(m => m.type === 'backup_codes');
    
    const status = {
      enabled: auth.mfa.enabled,
      method: primaryMethod?.type || null,
      methods: auth.mfa.methods.map(m => ({
        type: m.type,
        enabled: m.enabled,
        isPrimary: m.isPrimary,
        setupAt: m.setupAt
      })),
      backupCodesRemaining: 0,
      phoneNumberMasked: null,
      enabledAt: primaryMethod?.setupAt || null
    };

    // Count remaining backup codes
    if (backupMethod?.config?.codes) {
      status.backupCodesRemaining = backupMethod.config.codes.filter(c => !c.used).length;
    }

    // Mask phone number if SMS is enabled
    const smsMethod = auth.mfa.methods.find(m => m.type === 'sms' && m.enabled);
    if (smsMethod?.config?.phoneNumber) {
      const phoneNumber = smsMethod.config.phoneNumber;
      status.phoneNumberMasked = phoneNumber.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2');
    }

    return status;
  } catch (error) {
    logger.error('Get 2FA status failed', { error, userId });
    return { enabled: false };
  }
};

/**
 * Generate new backup codes
 * @param {string} userId - User ID
 * @param {string} password - User password for verification
 * @returns {Promise<Object>} New backup codes
 */
authSchema.statics.regenerateBackupCodes = async function(userId, password) {
  try {
    const auth = await this.findOne({ userId }).populate('userId');
    if (!auth || !auth.mfa.enabled) {
      throw new Error('2FA not enabled for user');
    }

    const bridgeUser = createBridgeUser(auth);
    const result = await TwoFactorService.regenerateBackupCodes(bridgeUser, password);

    // Update backup codes in AuthModel
    const backupMethod = auth.mfa.methods.find(m => m.type === 'backup_codes');
    if (backupMethod) {
      backupMethod.config.codes = result.backupCodes.map(code => ({
        code: crypto.createHash('sha256').update(code).digest('hex'),
        used: false,
        usedAt: null
      }));
    } else {
      auth.mfa.methods.push({
        type: 'backup_codes',
        enabled: true,
        isPrimary: false,
        config: {
          codes: result.backupCodes.map(code => ({
            code: crypto.createHash('sha256').update(code).digest('hex'),
            used: false,
            usedAt: null
          }))
        },
        setupAt: new Date(),
        verificationAttempts: 0
      });
    }

    await auth.save();
    return result;
  } catch (error) {
    logger.error('Backup code regeneration failed', { error, userId });
    throw error;
  }
};

/**
 * Send SMS code for login
 * @param {string} userId - User ID
 * @returns {Promise<Object>} Send result
 */
authSchema.statics.sendSMSCode = async function(userId) {
  try {
    const auth = await this.findOne({ userId }).populate('userId');
    if (!auth) {
      throw new Error('User authentication record not found');
    }

    const smsMethod = auth.mfa.methods.find(m => m.type === 'sms' && m.enabled);
    if (!smsMethod) {
      throw new Error('SMS 2FA not enabled for user');
    }

    const bridgeUser = createBridgeUser(auth);
    return await TwoFactorService.sendSMSCode(bridgeUser);
  } catch (error) {
    logger.error('SMS code send failed', { error, userId });
    throw error;
  }
};

/**
 * Helper function to create bridge user object for TwoFactorService
 * @param {Object} auth - AuthModel document
 * @returns {Object} Bridge user object
 */
function createBridgeUser(auth) {
  const user = auth.userId || auth.toObject().userId;
  const totpMethod = auth.mfa.methods?.find(m => m.type === 'totp' && m.enabled);
  const smsMethod = auth.mfa.methods?.find(m => m.type === 'sms' && m.enabled);
  const backupMethod = auth.mfa.methods?.find(m => m.type === 'backup_codes');

  // Create a bridge object that matches what TwoFactorService expects
  const bridgeUser = {
    _id: auth.userId._id || auth.userId,
    email: user.email,
    security: {
      twoFactorEnabled: auth.mfa.enabled,
      twoFactorMethod: auth.mfa.methods.find(m => m.isPrimary)?.type || null,
      twoFactorEnabledAt: auth.mfa.methods.find(m => m.isPrimary)?.setupAt || null
    }
  };

  // Add TOTP secret if available
  if (totpMethod?.config?.totpSecret) {
    bridgeUser.security.totpSecret = totpMethod.config.totpSecret;
  }

  // Add phone number if available
  if (smsMethod?.config?.phoneNumber) {
    bridgeUser.security.phoneNumber = smsMethod.config.phoneNumber;
  }

  // Add backup codes if available
  if (backupMethod?.config?.codes) {
    bridgeUser.security.backupCodes = backupMethod.config.codes.map(c => ({
      code: c.code,
      used: c.used,
      usedAt: c.usedAt
    }));
  }

  // Add save method that updates the auth document
  bridgeUser.save = async function() {
    // Update the original auth document with any changes made by TwoFactorService
    
    // Update TOTP secret
    if (this.security.totpSecret && totpMethod) {
      totpMethod.config.totpSecret = this.security.totpSecret;
    }

    // Update backup codes
    if (this.security.backupCodes && backupMethod) {
      backupMethod.config.codes = this.security.backupCodes.map(c => ({
        code: c.code,
        used: c.used,
        usedAt: c.usedAt
      }));
    }

    // Update 2FA status
    auth.mfa.enabled = this.security.twoFactorEnabled;
    if (this.security.twoFactorEnabledAt) {
      const primaryMethod = auth.mfa.methods.find(m => m.isPrimary);
      if (primaryMethod) {
        primaryMethod.setupAt = this.security.twoFactorEnabledAt;
      }
    }

    return await auth.save();
  };

  return bridgeUser;
}



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

// Find by verification token
authSchema.statics.findByVerificationToken = async function(token) {
  const hashedToken = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');
  
  return this.findOne({
    'authMethods.local.verificationToken': hashedToken,
    'authMethods.local.verificationExpiry': { $gt: new Date() }
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
  
  // Clear expired verification tokens
  await this.updateMany(
    { 'authMethods.local.verificationExpiry': { $lt: now } },
    { 
      $unset: { 
        'authMethods.local.verificationToken': 1,
        'authMethods.local.verificationExpiry': 1
      } 
    }
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

// Validate password strength
authSchema.statics.validatePasswordStrength = function(password) {
  const policy = {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true
  };
  
  const errors = [];
  
  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters long`);
  }
  
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (policy.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    valid: errors.length === 0,
    errors,
    strength: this.calculatePasswordStrength(password)
  };
};

// Calculate password strength
authSchema.statics.calculatePasswordStrength = function(password) {
  let score = 0;
  
  // Length
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  
  // Character variety
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
  
  // Patterns
  if (!/(.)\1{2,}/.test(password)) score += 1; // No repeated characters
  if (!/123|abc|qwe/i.test(password)) score += 1; // No sequential patterns
  
  const strength = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'];
  return {
    score: Math.min(score, 5),
    level: strength[Math.min(score, 5)]
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