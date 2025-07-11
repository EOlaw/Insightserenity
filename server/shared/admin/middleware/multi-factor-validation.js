/**
 * @file Multi-Factor Validation Middleware
 * @description Multi-factor authentication validation for administrative operations
 * @version 1.0.0
 */

const crypto = require('crypto');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { MFAError, AuthenticationError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../../audit/services/audit-service');
const AdminAuditLogger = require('./admin-audit-logging');
const Auth = require('../../../auth/models/auth-model');
const EncryptionService = require('../../../security/services/encryption-service');
const { CacheService } = require('../../../services/cache-service');
const config = require('../../../config/config');

/**
 * Multi-Factor Validator Class
 * @class MultiFactorValidator
 */
class MultiFactorValidator {
  /**
   * Initialize MFA configurations
   */
  static initialize() {
    this.cache = new CacheService('admin:mfa');
    this.encryptionService = new EncryptionService();
    
    // MFA configuration
    this.mfaConfig = {
      issuer: config.auth.twoFactor.issuer || 'InsightSerenity Admin',
      window: config.auth.twoFactor.window || 2,
      backupCodesCount: config.auth.twoFactor.backupCodesCount || 8,
      codeExpiry: 300000, // 5 minutes
      maxAttempts: 3,
      lockoutDuration: 1800000, // 30 minutes
      requireForCriticalOps: true
    };
    
    // Supported MFA methods
    this.supportedMethods = {
      totp: { name: 'Authenticator App', priority: 1 },
      sms: { name: 'SMS Code', priority: 2 },
      email: { name: 'Email Code', priority: 3 },
      backup: { name: 'Backup Code', priority: 4 },
      hardware: { name: 'Hardware Token', priority: 5 },
      biometric: { name: 'Biometric', priority: 6 }
    };
    
    // Critical operations requiring MFA
    this.criticalOperations = [
      'user_deletion',
      'role_elevation',
      'system_config_change',
      'bulk_operations',
      'security_settings',
      'billing_changes',
      'api_key_generation',
      'emergency_access'
    ];
    
    // Track MFA attempts
    this.attemptTracking = new Map();
    this.pendingChallenges = new Map();
  }

  /**
   * Create MFA validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  static validate(options = {}) {
    const {
      required = true,
      methods = ['totp', 'sms', 'email', 'backup'],
      operation = null,
      allowRemembered = true,
      rememberDuration = 86400000 // 24 hours
    } = options;

    return async (req, res, next) => {
      try {
        // Check if MFA is required
        if (!required && !this.isOperationCritical(operation)) {
          return next();
        }

        // Check if user has MFA enabled
        const authRecord = await Auth.findOne({ userId: req.user._id });
        if (!authRecord?.security?.twoFactorEnabled) {
          if (required) {
            return res.status(403).json({
              success: false,
              error: 'Multi-factor authentication is required for admin access',
              data: {
                setupUrl: '/api/admin/mfa/setup',
                methods: this.getAvailableMethods(methods)
              }
            });
          }
          return next();
        }

        // Check if already verified in this session
        if (req.adminAuth?.mfaVerified) {
          const verifiedAt = req.adminAuth.mfaVerifiedAt || 0;
          const age = Date.now() - verifiedAt;
          
          // Re-verify for critical operations after 1 hour
          if (this.isOperationCritical(operation) && age > 3600000) {
            return this.challengeMFA(req, res, {
              methods,
              operation,
              reason: 'critical_operation_reverification'
            });
          }
          
          return next();
        }

        // Check for remembered device
        if (allowRemembered && await this.isDeviceRemembered(req.user._id, req)) {
          req.adminAuth.mfaVerified = true;
          req.adminAuth.mfaMethod = 'remembered_device';
          return next();
        }

        // Initiate MFA challenge
        return this.challengeMFA(req, res, { methods, operation });
      } catch (error) {
        logger.error('MFA validation error', {
          error: error.message,
          userId: req.user?._id
        });
        next(error);
      }
    };
  }

  /**
   * Challenge user for MFA
   * @param {Object} req - Express request
   * @param {Object} res - Express response
   * @param {Object} options - Challenge options
   */
  static async challengeMFA(req, res, options) {
    const challengeId = crypto.randomUUID();
    const challenge = {
      id: challengeId,
      userId: req.user._id,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.mfaConfig.codeExpiry),
      methods: options.methods,
      operation: options.operation,
      attempts: 0,
      completed: false
    };

    // Store challenge
    this.pendingChallenges.set(challengeId, challenge);
    await this.cache.set(`challenge:${challengeId}`, challenge, 300); // 5 minutes

    // Get available methods for user
    const authRecord = await Auth.findOne({ userId: req.user._id });
    const userMethods = this.getUserMFAMethods(authRecord);

    // Send appropriate codes
    const sentMethods = [];
    for (const method of userMethods) {
      if (options.methods.includes(method.type)) {
        if (method.type === 'sms' || method.type === 'email') {
          await this.sendVerificationCode(req.user, method, challengeId);
          sentMethods.push(method.type);
        }
      }
    }

    // Log challenge initiation
    await AdminAuditLogger.logAdminEvent({
      eventType: 'admin_mfa_challenge_initiated',
      userId: req.user._id,
      targetType: 'mfa',
      operation: 'challenge',
      metadata: {
        challengeId,
        methods: userMethods.map(m => m.type),
        operation: options.operation,
        reason: options.reason
      }
    });

    return res.status(403).json({
      success: false,
      error: 'Multi-factor authentication required',
      data: {
        challengeId,
        methods: userMethods,
        sentTo: sentMethods,
        expiresIn: this.mfaConfig.codeExpiry / 1000,
        verifyUrl: '/api/admin/mfa/verify'
      }
    });
  }

  /**
   * Verify MFA code
   * @param {string} challengeId - Challenge ID
   * @param {string} code - Verification code
   * @param {string} method - MFA method
   * @param {Object} req - Express request
   * @returns {Object} Verification result
   */
  static async verifyMFA(challengeId, code, method, req) {
    try {
      // Get challenge
      const challenge = this.pendingChallenges.get(challengeId) || 
                       await this.cache.get(`challenge:${challengeId}`);
      
      if (!challenge) {
        throw new MFAError('Invalid or expired MFA challenge');
      }

      // Check expiry
      if (new Date(challenge.expiresAt) < new Date()) {
        this.pendingChallenges.delete(challengeId);
        throw new MFAError('MFA challenge expired');
      }

      // Check attempts
      challenge.attempts++;
      if (challenge.attempts > this.mfaConfig.maxAttempts) {
        await this.handleMaxAttempts(challenge, req);
        throw new MFAError('Maximum MFA attempts exceeded');
      }

      // Update challenge
      await this.cache.set(`challenge:${challengeId}`, challenge, 300);

      // Get auth record
      const authRecord = await Auth.findOne({ userId: challenge.userId });
      if (!authRecord) {
        throw new AuthenticationError('Authentication record not found');
      }

      // Verify based on method
      let verified = false;
      let consumedBackupCode = null;

      switch (method) {
        case 'totp':
          verified = this.verifyTOTP(code, authRecord.security.twoFactorSecret);
          break;
          
        case 'sms':
        case 'email':
          verified = await this.verifyTemporaryCode(challengeId, code, method);
          break;
          
        case 'backup':
          const backupResult = await this.verifyBackupCode(code, authRecord);
          verified = backupResult.verified;
          consumedBackupCode = backupResult.code;
          break;
          
        case 'hardware':
          verified = await this.verifyHardwareToken(code, authRecord);
          break;
          
        default:
          throw new MFAError(`Unsupported MFA method: ${method}`);
      }

      if (!verified) {
        await this.logFailedAttempt(challenge, method, req);
        throw new MFAError('Invalid verification code');
      }

      // Mark challenge as completed
      challenge.completed = true;
      challenge.completedAt = new Date();
      challenge.method = method;
      
      // Clean up
      this.pendingChallenges.delete(challengeId);
      await this.cache.delete(`challenge:${challengeId}`);

      // Update backup codes if used
      if (consumedBackupCode) {
        authRecord.security.backupCodes = authRecord.security.backupCodes.filter(
          bc => bc.code !== consumedBackupCode
        );
        await authRecord.save();
      }

      // Log successful verification
      await AdminAuditLogger.logAdminEvent({
        eventType: 'admin_mfa_verified',
        userId: challenge.userId,
        targetType: 'mfa',
        operation: 'verify',
        metadata: {
          challengeId,
          method,
          operation: challenge.operation,
          attempts: challenge.attempts
        }
      });

      return {
        verified: true,
        userId: challenge.userId,
        method,
        timestamp: new Date()
      };
    } catch (error) {
      logger.error('MFA verification error', {
        error: error.message,
        challengeId,
        method
      });
      throw error;
    }
  }

  /**
   * Setup MFA for admin user
   * @param {string} userId - User ID
   * @param {string} method - MFA method
   * @param {Object} data - Setup data
   * @returns {Object} Setup result
   */
  static async setupMFA(userId, method, data = {}) {
    try {
      const authRecord = await Auth.findOne({ userId });
      if (!authRecord) {
        throw new AuthenticationError('Authentication record not found');
      }

      let setupResult = {};

      switch (method) {
        case 'totp':
          setupResult = await this.setupTOTP(authRecord);
          break;
          
        case 'sms':
          setupResult = await this.setupSMS(authRecord, data.phoneNumber);
          break;
          
        case 'email':
          setupResult = await this.setupEmail(authRecord, data.email);
          break;
          
        case 'hardware':
          setupResult = await this.setupHardwareToken(authRecord, data);
          break;
          
        default:
          throw new MFAError(`Unsupported MFA method: ${method}`);
      }

      // Generate backup codes if first MFA method
      if (!authRecord.security.twoFactorEnabled) {
        setupResult.backupCodes = await this.generateBackupCodes(authRecord);
      }

      // Enable MFA
      authRecord.security.twoFactorEnabled = true;
      authRecord.security.twoFactorMethods = authRecord.security.twoFactorMethods || [];
      
      if (!authRecord.security.twoFactorMethods.find(m => m.type === method)) {
        authRecord.security.twoFactorMethods.push({
          type: method,
          enabled: true,
          addedAt: new Date(),
          ...setupResult.methodData
        });
      }

      await authRecord.save();

      // Log setup
      await AdminAuditLogger.logAdminEvent({
        eventType: 'admin_mfa_setup',
        userId,
        targetType: 'mfa',
        operation: 'setup',
        metadata: {
          method,
          firstMethod: setupResult.backupCodes ? true : false
        }
      });

      return setupResult;
    } catch (error) {
      logger.error('MFA setup error', {
        error: error.message,
        userId,
        method
      });
      throw error;
    }
  }

  /**
   * Setup TOTP authentication
   * @param {Object} authRecord - Auth record
   * @returns {Object} Setup data
   */
  static async setupTOTP(authRecord) {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(
      authRecord.userId.email,
      this.mfaConfig.issuer,
      secret
    );

    authRecord.security.twoFactorSecret = this.encryptionService.encryptField(secret, 'mfa_secret');

    const qrCode = await QRCode.toDataURL(otpauth);

    return {
      method: 'totp',
      secret: secret,
      qrCode: qrCode,
      manualEntry: {
        issuer: this.mfaConfig.issuer,
        account: authRecord.userId.email,
        secret: secret
      },
      methodData: {
        configured: true
      }
    };
  }

  /**
   * Setup SMS authentication
   * @param {Object} authRecord - Auth record
   * @param {string} phoneNumber - Phone number
   * @returns {Object} Setup data
   */
  static async setupSMS(authRecord, phoneNumber) {
    if (!phoneNumber || !/^\+\d{10,15}$/.test(phoneNumber)) {
      throw new MFAError('Valid phone number required (+1234567890)');
    }

    // Send verification code to confirm number
    const verificationCode = this.generateNumericCode(6);
    const hashedCode = this.encryptionService.hash(verificationCode);

    // Store verification temporarily
    await this.cache.set(`sms_verify:${authRecord.userId}`, {
      phoneNumber,
      code: hashedCode,
      expiresAt: new Date(Date.now() + 600000) // 10 minutes
    }, 600);

    // TODO: Send SMS via SMS service
    logger.info('SMS verification code generated', {
      userId: authRecord.userId,
      phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*')
    });

    return {
      method: 'sms',
      phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*'),
      verificationRequired: true,
      verificationCode: config.app.env === 'development' ? verificationCode : undefined,
      methodData: {
        phoneNumber: this.encryptionService.encryptField(phoneNumber, 'phone_number'),
        verified: false
      }
    };
  }

  /**
   * Setup email authentication
   * @param {Object} authRecord - Auth record
   * @param {string} email - Email address
   * @returns {Object} Setup data
   */
  static async setupEmail(authRecord, email) {
    const userEmail = email || authRecord.userId.email;
    
    if (!userEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(userEmail)) {
      throw new MFAError('Valid email address required');
    }

    return {
      method: 'email',
      email: userEmail,
      methodData: {
        email: userEmail,
        verified: true
      }
    };
  }

  /**
   * Generate backup codes
   * @param {Object} authRecord - Auth record
   * @returns {Array} Backup codes
   */
  static async generateBackupCodes(authRecord) {
    const codes = [];
    const hashedCodes = [];

    for (let i = 0; i < this.mfaConfig.backupCodesCount; i++) {
      const code = this.generateBackupCode();
      codes.push(code);
      hashedCodes.push({
        code: this.encryptionService.hash(code),
        used: false,
        createdAt: new Date()
      });
    }

    authRecord.security.backupCodes = hashedCodes;

    return codes;
  }

  /**
   * Verify TOTP code
   * @param {string} token - TOTP token
   * @param {string} encryptedSecret - Encrypted secret
   * @returns {boolean} Verification result
   */
  static verifyTOTP(token, encryptedSecret) {
    try {
      const secret = this.encryptionService.decryptField(encryptedSecret);
      return authenticator.verify({
        token,
        secret,
        window: this.mfaConfig.window
      });
    } catch (error) {
      logger.error('TOTP verification error', { error: error.message });
      return false;
    }
  }

  /**
   * Verify temporary code (SMS/Email)
   * @param {string} challengeId - Challenge ID
   * @param {string} code - Verification code
   * @param {string} method - Method type
   * @returns {boolean} Verification result
   */
  static async verifyTemporaryCode(challengeId, code, method) {
    const codeKey = `mfa_code:${challengeId}:${method}`;
    const storedData = await this.cache.get(codeKey);

    if (!storedData) {
      return false;
    }

    const isValid = this.encryptionService.verifySignature(code, storedData.hashedCode);
    
    if (isValid) {
      await this.cache.delete(codeKey);
    }

    return isValid;
  }

  /**
   * Verify backup code
   * @param {string} code - Backup code
   * @param {Object} authRecord - Auth record
   * @returns {Object} Verification result
   */
  static async verifyBackupCode(code, authRecord) {
    const backupCodes = authRecord.security.backupCodes || [];
    
    for (const backupCode of backupCodes) {
      if (!backupCode.used && this.encryptionService.verifySignature(code, backupCode.code)) {
        backupCode.used = true;
        backupCode.usedAt = new Date();
        return { verified: true, code: backupCode.code };
      }
    }

    return { verified: false };
  }

  /**
   * Send verification code
   * @param {Object} user - User object
   * @param {Object} method - MFA method
   * @param {string} challengeId - Challenge ID
   */
  static async sendVerificationCode(user, method, challengeId) {
    const code = this.generateNumericCode(6);
    const hashedCode = this.encryptionService.sign(code);

    // Store code
    await this.cache.set(`mfa_code:${challengeId}:${method.type}`, {
      hashedCode,
      attempts: 0,
      expiresAt: new Date(Date.now() + this.mfaConfig.codeExpiry)
    }, 300);

    // Send based on method
    if (method.type === 'sms') {
      // TODO: Send SMS
      logger.info('MFA SMS code generated', {
        userId: user._id,
        challengeId,
        code: config.app.env === 'development' ? code : undefined
      });
    } else if (method.type === 'email') {
      // TODO: Send email
      logger.info('MFA email code generated', {
        userId: user._id,
        challengeId,
        code: config.app.env === 'development' ? code : undefined
      });
    }
  }

  /**
   * Check if device is remembered
   * @param {string} userId - User ID
   * @param {Object} req - Express request
   * @returns {boolean} Is remembered
   */
  static async isDeviceRemembered(userId, req) {
    const deviceId = req.cookies?.adminDeviceId;
    if (!deviceId) return false;

    const rememberedKey = `remembered:${userId}:${deviceId}`;
    const remembered = await this.cache.get(rememberedKey);

    if (remembered && remembered.expiresAt > new Date()) {
      // Verify device fingerprint
      const currentFingerprint = this.generateDeviceFingerprint(req);
      return remembered.fingerprint === currentFingerprint;
    }

    return false;
  }

  /**
   * Remember device
   * @param {string} userId - User ID
   * @param {Object} req - Express request
   * @param {Object} res - Express response
   * @param {number} duration - Remember duration
   */
  static async rememberDevice(userId, req, res, duration = 2592000000) { // 30 days
    const deviceId = crypto.randomUUID();
    const fingerprint = this.generateDeviceFingerprint(req);

    const remembered = {
      deviceId,
      userId,
      fingerprint,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + duration),
      device: {
        userAgent: req.get('user-agent'),
        ip: req.ip
      }
    };

    await this.cache.set(`remembered:${userId}:${deviceId}`, remembered, duration / 1000);

    // Set secure cookie
    res.cookie('adminDeviceId', deviceId, {
      httpOnly: true,
      secure: config.security.ssl.enabled,
      sameSite: 'strict',
      maxAge: duration
    });

    await AdminAuditLogger.logAdminEvent({
      eventType: 'admin_device_remembered',
      userId,
      targetType: 'device',
      operation: 'remember',
      metadata: {
        deviceId,
        duration,
        device: remembered.device
      }
    });
  }

  /**
   * Helper methods
   */

  static isOperationCritical(operation) {
    return operation && this.criticalOperations.includes(operation);
  }

  static getUserMFAMethods(authRecord) {
    const methods = [];
    
    if (authRecord.security.twoFactorMethods) {
      authRecord.security.twoFactorMethods
        .filter(m => m.enabled)
        .forEach(m => {
          methods.push({
            type: m.type,
            name: this.supportedMethods[m.type]?.name || m.type,
            configured: true
          });
        });
    }

    // Always include backup codes if available
    if (authRecord.security.backupCodes?.some(c => !c.used)) {
      methods.push({
        type: 'backup',
        name: 'Backup Code',
        configured: true
      });
    }

    return methods.sort((a, b) => 
      (this.supportedMethods[a.type]?.priority || 99) - 
      (this.supportedMethods[b.type]?.priority || 99)
    );
  }

  static generateNumericCode(length = 6) {
    let code = '';
    for (let i = 0; i < length; i++) {
      code += Math.floor(Math.random() * 10);
    }
    return code;
  }

  static generateBackupCode() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let code = '';
    for (let i = 0; i < 8; i++) {
      if (i === 4) code += '-';
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    return code;
  }

  static generateDeviceFingerprint(req) {
    const components = [
      req.get('user-agent'),
      req.get('accept-language'),
      req.get('accept-encoding')
    ];
    
    return crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');
  }

  static async handleMaxAttempts(challenge, req) {
    const lockKey = `mfa_lock:${challenge.userId}`;
    await this.cache.set(lockKey, {
      lockedAt: new Date(),
      unlockedAt: new Date(Date.now() + this.mfaConfig.lockoutDuration),
      reason: 'max_mfa_attempts',
      challengeId: challenge.id
    }, this.mfaConfig.lockoutDuration / 1000);

    await AuditService.log({
      type: 'admin_mfa_lockout',
      action: 'lockout',
      category: 'security',
      result: 'locked',
      severity: 'high',
      userId: challenge.userId,
      metadata: {
        challengeId: challenge.id,
        attempts: challenge.attempts,
        lockoutDuration: this.mfaConfig.lockoutDuration,
        ip: req.ip
      }
    });
  }

  static async logFailedAttempt(challenge, method, req) {
    await AdminAuditLogger.logAdminEvent({
      eventType: 'admin_mfa_failed',
      userId: challenge.userId,
      targetType: 'mfa',
      operation: 'verify',
      metadata: {
        challengeId: challenge.id,
        method,
        attempt: challenge.attempts,
        maxAttempts: this.mfaConfig.maxAttempts,
        ip: req.ip
      }
    });
  }

  /**
   * Disable MFA method
   * @param {string} userId - User ID
   * @param {string} method - MFA method
   * @param {string} reason - Disable reason
   */
  static async disableMFAMethod(userId, method, reason) {
    try {
      const authRecord = await Auth.findOne({ userId });
      if (!authRecord) {
        throw new AuthenticationError('Authentication record not found');
      }

      const methodIndex = authRecord.security.twoFactorMethods?.findIndex(m => m.type === method);
      if (methodIndex === -1) {
        throw new MFAError('MFA method not found');
      }

      // Don't allow disabling last method
      const activeMethods = authRecord.security.twoFactorMethods.filter(m => m.enabled);
      if (activeMethods.length === 1 && activeMethods[0].type === method) {
        throw new MFAError('Cannot disable last MFA method');
      }

      authRecord.security.twoFactorMethods[methodIndex].enabled = false;
      authRecord.security.twoFactorMethods[methodIndex].disabledAt = new Date();
      authRecord.security.twoFactorMethods[methodIndex].disableReason = reason;

      await authRecord.save();

      await AdminAuditLogger.logAdminEvent({
        eventType: 'admin_mfa_disabled',
        userId,
        targetType: 'mfa',
        operation: 'disable',
        metadata: {
          method,
          reason
        }
      });

      return { success: true };
    } catch (error) {
      logger.error('Failed to disable MFA method', {
        error: error.message,
        userId,
        method
      });
      throw error;
    }
  }

  /**
   * Get MFA statistics
   * @returns {Object} Statistics
   */
  static getStatistics() {
    return {
      pendingChallenges: this.pendingChallenges.size,
      activeAttempts: this.attemptTracking.size,
      supportedMethods: Object.keys(this.supportedMethods).length
    };
  }

  /**
   * Clean up expired data
   */
  static cleanup() {
    const now = Date.now();

    // Clean expired challenges
    for (const [id, challenge] of this.pendingChallenges.entries()) {
      if (new Date(challenge.expiresAt).getTime() < now) {
        this.pendingChallenges.delete(id);
      }
    }

    // Clean old attempt tracking
    for (const [key, data] of this.attemptTracking.entries()) {
      if (data.lastAttempt && (now - data.lastAttempt) > 86400000) { // 24 hours
        this.attemptTracking.delete(key);
      }
    }
  }
}

// Initialize on module load
MultiFactorValidator.initialize();

// Schedule periodic cleanup
setInterval(() => {
  MultiFactorValidator.cleanup();
}, 3600000); // Every hour

module.exports = MultiFactorValidator;