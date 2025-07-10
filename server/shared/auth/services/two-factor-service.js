// server/shared/auth/services/two-factor-service.js
// Description: Two-Factor Authentication Service for managing TOTP, SMS, and backup codes
/**
 * @file Two-Factor Authentication Service
 * @description Multi-factor authentication service supporting TOTP, SMS, and backup codes with Redis storage
 * @version 3.1.0
 */

const crypto = require('crypto');
const qrcode = require('qrcode');
const speakeasy = require('speakeasy');

const config = require('../../config/config');
const AuthModel = require('../models/auth-model');
const AuditService = require('../../security/services/audit-service');
const EncryptionService = require('../../security/services/encryption-service');
const { AppError, ValidationError, AuthenticationError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

// Conditionally require Redis if enabled
let redis = null;
if (config.redis?.enabled) {
  try {
    redis = require('../../config/redis'); // Adjust path as needed
    logger.info('Redis enabled for TwoFactorService storage');
  } catch (error) {
    logger.warn('Redis configuration not found, using in-memory fallback', { error: error.message });
  }
} else {
  logger.info('Redis disabled, using in-memory storage for TwoFactorService');
}

/**
 * Two-Factor Authentication Service Class
 * @class TwoFactorService
 */
class TwoFactorService {
  constructor() {
    this.appName = config.app?.name || config.server?.name || 'InsightSerenity';
    this.backupCodeCount = config.auth?.twoFactor?.backupCodesCount || 10;
    this.backupCodeLength = 8;
    this.totpWindow = config.auth?.twoFactor?.window || 2;
    this.smsCodeLength = config.sms?.mfa?.codeLength || 6;
    this.smsCodeExpiry = config.sms?.mfa?.codeExpiry || 10 * 60 * 1000; // 10 minutes
  }
  
  /**
   * Setup TOTP for user - Updated for AuthModel integration
   * @param {Object} user - User document (can be bridge user from AuthModel)
   * @returns {Promise<Object>} Setup data
   */
  async setupTOTP(user) {
    try {
      // Support both direct user and bridge user formats
      const email = user.email || user.authMethods?.local?.email || 'user@example.com';
      const userId = user._id || user.userId;

      if (config.app.env === 'development') {
        logger.info('🔐 TOTP Setup Started', {
          userId,
          email,
          appName: this.appName
        });
      }

      // Generate secret
      const secret = speakeasy.generateSecret({
        name: `${this.appName} (${email})`,
        issuer: this.appName,
        length: 32
      });
      
      // Generate QR code
      const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);
      
      // Store encrypted secret temporarily
      const tempSecret = {
        secret: EncryptionService.encryptField(secret.base32, 'totp_secret'),
        tempId: EncryptionService.generateToken(16),
        userId: userId,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000) // 1 hour
      };
      
      // Store in cache or temporary collection
      await this.storeTempSecret(tempSecret);

      // Enhanced development logging
      if (config.app.env === 'development') {
        logger.info('🔑 TOTP Secret Generated (Development Only)', {
          userId,
          secret: secret.base32,
          tempId: tempSecret.tempId,
          qrCodeLength: qrCodeDataUrl.length,
          expiresAt: tempSecret.expiresAt,
          otpauthUrl: secret.otpauth_url
        });
        
        logger.info('📱 QR Code Data Available', {
          userId,
          qrCodePrefix: qrCodeDataUrl.substring(0, 50) + '...',
          fullLength: qrCodeDataUrl.length
        });
      }
      
      // Log setup initiation
      await AuditService.log({
        type: '2fa_setup_initiated',
        action: 'setup_2fa',
        category: 'security',
        result: 'success',
        userId: userId,
        metadata: {
          method: 'totp'
        }
      });
      
      return {
        tempId: tempSecret.tempId,
        qrCode: qrCodeDataUrl,
        secret: secret.base32,
        manualEntryKey: secret.base32.match(/.{1,4}/g).join(' '),
        backupCodes: await this.generateBackupCodes()
      };
    } catch (error) {
      logger.error('TOTP setup failed', { error, userId: user._id || user.userId });
      throw new AppError('Failed to setup two-factor authentication', 500, '2FA_SETUP_ERROR');
    }
  }
  
  /**
   * Enable TOTP for user - Updated for AuthModel integration
   * @param {Object} user - User document
   * @param {string} tempId - Temporary secret ID
   * @param {string} token - TOTP token to verify
   * @returns {Promise<Object>} Enable result
   */
  async enableTOTP(user, tempId, token) {
    try {
      // Retrieve temporary secret
      const tempSecret = await this.retrieveTempSecret(tempId);
      const userId = user._id || user.userId;
      
      if (!tempSecret || tempSecret.userId.toString() !== userId.toString()) {
        throw new ValidationError('Invalid or expired setup session');
      }
      
      // Decrypt secret
      const secret = EncryptionService.decryptField(tempSecret.secret);
      
      // Verify token
      const isValid = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: this.totpWindow
      });
      
      if (!isValid) {
        throw new ValidationError('Invalid verification code');
      }
      
      // Update user security settings in the format expected
      if (!user.security) {
        user.security = {};
      }
      
      user.security.twoFactorEnabled = true;
      user.security.twoFactorMethod = 'totp';
      user.security.totpSecret = EncryptionService.encryptField(secret, 'totp_secret');
      user.security.twoFactorEnabledAt = new Date();
      
      // Generate backup codes
      const backupCodes = await this.generateBackupCodes();
      user.security.backupCodes = await this.encryptBackupCodes(backupCodes);
      
      // Save using the bridge user's save method or direct save
      if (typeof user.save === 'function') {
        await user.save();
      }
      
      // Clean up temporary secret
      await this.deleteTempSecret(tempId);
      
      // Log successful enablement
      await AuditService.log({
        type: '2fa_enabled',
        action: 'enable_2fa',
        category: 'security',
        result: 'success',
        severity: 'high',
        userId: userId,
        metadata: {
          method: 'totp'
        }
      });
      
      return {
        success: true,
        backupCodes,
        message: 'Two-factor authentication has been enabled'
      };
    } catch (error) {
      logger.error('TOTP enable failed', { error, userId: user._id || user.userId });
      throw error;
    }
  }
  
  /**
   * Verify token - Enhanced to work with AuthModel structure
   * @param {string} userId - User ID
   * @param {string} token - TOTP token
   * @returns {Promise<boolean>} Verification result
   */
  async verifyToken(userId, token) {
    try {
      if (config.app.env === 'development') {
        logger.info('🔍 2FA Token Verification', {
          userId,
          tokenLength: token.length,
          tokenMasked: '***' + token.slice(-3),
          timestamp: new Date().toISOString()
        });
      }

      // Try to get user from AuthModel first, then fallback to User model
      let user;
      try {
        const auth = await AuthModel.findOne({ userId }).populate('userId');
        if (auth && auth.mfa.enabled) {
          user = this.createUserFromAuth(auth);
        }
      } catch (error) {
        // Fallback to User model if AuthModel doesn't work
        const User = require('../../users/models/user-model');
        user = await User.findById(userId).select('+security');
      }
      
      if (!user || !this.isUserMfaEnabled(user)) {
        if (config.app.env === 'development') {
          logger.warn('🚫 2FA Not Enabled', { userId, userFound: !!user });
        }
        return false;
      }
      
      // Check if it's a backup code
      if (token.length === this.backupCodeLength && /^\d+$/.test(token)) {
        const result = this.verifyBackupCode(user, token);
        if (config.app.env === 'development') {
          logger.info('🔐 Backup Code Verification', { userId, result });
        }
        return result;
      }
      
      // Verify based on method
      const method = this.getUserMfaMethod(user);
      let result = false;
      switch (method) {
        case 'totp':
          result = await this.verifyTOTP(user, token);
          break;
        case 'sms':
          result = await this.verifySMSCode(user, token);
          break;
        default:
          result = false;
      }
      if (config.app.env === 'development') {
        logger.info('✅ 2FA Verification Result', {
          userId,
          method,
          result,
          timestamp: new Date().toISOString()
        });
      }
      
      return result;
    } catch (error) {
      logger.error('Token verification failed', { error, userId });
      return false;
    }
  }
  
  /**
   * Verify TOTP token - Enhanced for both user formats
   * @param {Object} user - User document
   * @param {string} token - TOTP token
   * @returns {Promise<boolean>} Verification result
   */
  async verifyTOTP(user, token) {
    try {
      const totpSecret = this.getUserTotpSecret(user);
      if (!totpSecret) {
        return false;
      }
      
      // Decrypt secret
      const secret = EncryptionService.decryptField(totpSecret);
      
      // Verify token
      const isValid = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: this.totpWindow
      });
      
      if (isValid) {
        // Log successful verification
        await AuditService.log({
          type: '2fa_verification_success',
          action: 'verify_2fa',
          category: 'authentication',
          result: 'success',
          userId: user._id || user.userId,
          metadata: {
            method: 'totp'
          }
        });
      }
      
      return isValid;
    } catch (error) {
      logger.error('TOTP verification error', { error, userId: user._id || user.userId });
      return false;
    }
  }
  
  /**
   * Verify backup code - Enhanced for both user formats
   * @param {Object} user - User document
   * @param {string} code - Backup code
   * @returns {Promise<boolean>} Verification result
   */
  async verifyBackupCode(user, code) {
    try {
      const backupCodes = this.getUserBackupCodes(user);
      if (!backupCodes || backupCodes.length === 0) {
        return false;
      }
      
      // Find and verify code
      for (let i = 0; i < backupCodes.length; i++) {
        const backupCode = backupCodes[i];
        
        if (backupCode.used) {
          continue;
        }
        
        const decryptedCode = EncryptionService.decryptField(backupCode.code);
        
        if (decryptedCode === code) {
          // Mark as used
          backupCodes[i].used = true;
          backupCodes[i].usedAt = new Date();
          
          // Save using appropriate method
          if (typeof user.save === 'function') {
            await user.save();
          }
          
          // Log backup code usage
          await AuditService.log({
            type: '2fa_backup_code_used',
            action: 'use_backup_code',
            category: 'security',
            result: 'success',
            severity: 'medium',
            userId: user._id || user.userId,
            metadata: {
              remainingCodes: backupCodes.filter(c => !c.used).length
            }
          });
          
          return true;
        }
      }
      
      return false;
    } catch (error) {
      logger.error('Backup code verification error', { error, userId: user._id || user.userId });
      return false;
    }
  }
  
  /**
   * Disable two-factor authentication - Updated for AuthModel integration
   * @param {Object} user - User document
   * @param {string} password - User password for verification
   * @returns {Promise<Object>} Disable result
   */
  async disable2FA(user, password) {
    try {
      // Verify password using AuthModel method
      const isValid = await user.verifyPassword(password);
      
      if (!isValid) {
        throw new AuthenticationError('Invalid password');
      }
      
      // Clear 2FA settings in bridge user format
      if (user.security) {
        user.security.twoFactorEnabled = false;
        user.security.twoFactorMethod = null;
        user.security.totpSecret = null;
        user.security.backupCodes = [];
        user.security.phoneNumber = null;
        user.security.twoFactorDisabledAt = new Date();
      }
      
      // Save using appropriate method
      if (typeof user.save === 'function') {
        await user.save();
      }
      
      // Log disablement
      await AuditService.log({
        type: '2fa_disabled',
        action: 'disable_2fa',
        category: 'security',
        result: 'success',
        severity: 'high',
        userId: user._id || user.userId
      });
      
      return {
        success: true,
        message: 'Two-factor authentication has been disabled'
      };
    } catch (error) {
      logger.error('2FA disable failed', { error, userId: user._id || user.userId });
      throw error;
    }
  }
  
  /**
   * Setup SMS-based 2FA
   * @param {Object} user - User document
   * @param {string} phoneNumber - Phone number
   * @returns {Promise<Object>} Setup result
   */
  async setupSMS(user, phoneNumber) {
    try {
      const userId = user._id || user.userId;
    
      if (config.app.env === 'development') {
        logger.info('📱 SMS Setup Started', {
          userId,
          phoneNumber: phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2')
        });
      }

      // // Validate phone number format using basic regex since config constants might not be available
      // const phoneRegex = /^\+?[1-9]\d{1,14}$/;
      // if (!phoneRegex.test(phoneNumber.replace(/[\s\-\(\)]/g, ''))) {
      //   throw new ValidationError('Invalid phone number format');
      // }
      
      // Generate and send verification code
      const verificationCode = this.generateSMSCode();
      
      // Store verification session
      const session = {
        userId: user._id || user.userId,
        phoneNumber,
        code: EncryptionService.hash(verificationCode),
        expiresAt: new Date(Date.now() + this.smsCodeExpiry),
        attempts: 0
      };
      
      await this.storeSMSSession(session);
      
      // Send SMS (integrate with SMS service)
      await this.sendSMS(phoneNumber, `Your ${this.appName} verification code is: ${verificationCode}`);

      // Enhanced development logging
      if (config.app.env === 'development') {
        logger.info('📲 SMS Verification Code (Development Only)', {
          userId,
          phoneNumber: phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2'),
          verificationCode: verificationCode,
          tempId: session.tempId,
          expiresAt: session.expiresAt,
          message: `Your ${this.appName} verification code is: ${verificationCode}`
        });
      }
      
      // Log setup initiation
      await AuditService.log({
        type: '2fa_setup_initiated',
        action: 'setup_2fa',
        category: 'security',
        result: 'success',
        userId: userId,
        metadata: { method: 'sms' }
      });
      
      return {
        success: true,
        message: 'Verification code sent to your phone',
        tempId: session.tempId,
        expiresIn: this.smsCodeExpiry / 1000,
        phoneNumberMasked: phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2')
      };
    } catch (error) {
      logger.error('SMS 2FA setup failed', { error, userId: user._id || user.userId });
      throw error;
    }
  }
  
  /**
   * Enable SMS-based 2FA
   * @param {Object} user - User document
   * @param {string} phoneNumber - Phone number
   * @param {string} code - Verification code
   * @returns {Promise<Object>} Enable result
   */
  async enableSMS(user, phoneNumber, code) {
    try {
      const userId = user._id || user.userId;
      
      // Verify SMS code
      const session = await this.retrieveSMSSession(userId, phoneNumber);
      
      if (!session) {
        throw new ValidationError('Verification session expired');
      }
      
      // Check attempts
      if (session.attempts >= 3) {
        throw new ValidationError('Too many failed attempts');
      }
      
      // Verify code
      const isValid = EncryptionService.verifySignature(code, session.code);
      
      if (!isValid) {
        session.attempts++;
        await this.updateSMSSession(session);
        throw new ValidationError('Invalid verification code');
      }
      
      // Enable SMS 2FA
      if (!user.security) {
        user.security = {};
      }
      
      user.security.twoFactorEnabled = true;
      user.security.twoFactorMethod = 'sms';
      user.security.phoneNumber = EncryptionService.encryptField(phoneNumber, 'phone_number');
      user.security.twoFactorEnabledAt = new Date();
      
      // Generate backup codes
      const backupCodes = await this.generateBackupCodes();
      user.security.backupCodes = await this.encryptBackupCodes(backupCodes);
      
      // Save using appropriate method
      if (typeof user.save === 'function') {
        await user.save();
      }
      
      // Clean up session
      await this.deleteSMSSession(userId, phoneNumber);
      
      // Log enablement
      await AuditService.log({
        type: '2fa_enabled',
        action: 'enable_2fa',
        category: 'security',
        result: 'success',
        severity: 'high',
        userId: userId,
        metadata: {
          method: 'sms'
        }
      });
      
      return {
        success: true,
        backupCodes,
        message: 'SMS two-factor authentication has been enabled'
      };
    } catch (error) {
      logger.error('SMS 2FA enable failed', { error, userId: user._id || user.userId });
      throw error;
    }
  }
  
  /**
   * Send SMS code for verification
   * @param {Object} user - User document
   * @returns {Promise<Object>} Send result
   */
  async sendSMSCode(user) {
    try {
      if (!user.security?.phoneNumber) {
        throw new AppError('Phone number not configured', 400, 'PHONE_NOT_CONFIGURED');
      }
      
      // Decrypt phone number
      const phoneNumber = EncryptionService.decryptField(user.security.phoneNumber);
      
      // Generate code
      const code = this.generateSMSCode();
      
      // Store code session
      const session = {
        userId: user._id || user.userId,
        code: EncryptionService.hash(code),
        expiresAt: new Date(Date.now() + this.smsCodeExpiry),
        attempts: 0
      };
      
      await this.storeSMSCodeSession(session);
      
      // Send SMS
      await this.sendSMS(phoneNumber, `Your ${this.appName} login code is: ${code}`);
      
      return {
        success: true,
        message: 'Verification code sent'
      };
    } catch (error) {
      logger.error('SMS code send failed', { error, userId: user._id || user.userId });
      throw error;
    }
  }
  
  /**
   * Verify SMS code
   * @param {Object} user - User document
   * @param {string} code - SMS code
   * @returns {Promise<boolean>} Verification result
   */
  async verifySMSCode(user, code) {
    try {
      const userId = user._id || user.userId;
      const session = await this.retrieveSMSCodeSession(userId);
      
      if (!session || new Date() > session.expiresAt) {
        return false;
      }
      
      // Check attempts
      if (session.attempts >= 3) {
        return false;
      }
      
      // Verify code
      const isValid = EncryptionService.verifySignature(code, session.code);
      
      if (!isValid) {
        session.attempts++;
        await this.updateSMSCodeSession(session);
        return false;
      }
      
      // Clean up session
      await this.deleteSMSCodeSession(userId);
      
      // Log successful verification
      await AuditService.log({
        type: '2fa_verification_success',
        action: 'verify_2fa',
        category: 'authentication',
        result: 'success',
        userId: userId,
        metadata: {
          method: 'sms'
        }
      });
      
      return true;
    } catch (error) {
      logger.error('SMS code verification error', { error, userId: user._id || user.userId });
      return false;
    }
  }
  
  /**
   * Generate SMS verification code
   * @returns {string} Verification code
   */
  generateSMSCode() {
    return Array.from({ length: this.smsCodeLength }, () =>
      crypto.randomInt(0, 10)
    ).join('');
  }
  
  /**
   * Generate backup codes
   * @returns {Promise<Array>} Backup codes
   */
  async generateBackupCodes() {
    const codes = [];
    
    for (let i = 0; i < this.backupCodeCount; i++) {
      const code = Array.from({ length: this.backupCodeLength }, () =>
        crypto.randomInt(0, 10)
      ).join('');
      codes.push(code);
    }
    
    return codes;
  }
  
  /**
   * Encrypt backup codes for storage
   * @param {Array} codes - Backup codes
   * @returns {Promise<Array>} Encrypted codes
   */
  async encryptBackupCodes(codes) {
    return codes.map(code => ({
      code: EncryptionService.encryptField(code, 'backup_code'),
      used: false,
      usedAt: null
    }));
  }
  
  /**
   * Regenerate backup codes
   * @param {Object} user - User document
   * @param {string} password - User password for verification
   * @returns {Promise<Object>} New backup codes
   */
  async regenerateBackupCodes(user, password) {
    try {
      // Verify password using appropriate method
      let isValid;
      if (typeof user.verifyPassword === 'function') {
        isValid = await user.verifyPassword(password);
      } else {
        // Fallback password verification
        const PasswordService = require('./password-service');
        isValid = await PasswordService.verifyPassword(password, user.password);
      }
      
      if (!isValid) {
        throw new AuthenticationError('Invalid password');
      }
      
      // Generate new codes
      const newCodes = await this.generateBackupCodes();
      
      if (!user.security) {
        user.security = {};
      }
      
      user.security.backupCodes = await this.encryptBackupCodes(newCodes);
      
      // Save using appropriate method
      if (typeof user.save === 'function') {
        await user.save();
      }
      
      // Log regeneration
      await AuditService.log({
        type: '2fa_backup_codes_regenerated',
        action: 'regenerate_backup_codes',
        category: 'security',
        result: 'success',
        severity: 'medium',
        userId: user._id || user.userId
      });
      
      return {
        success: true,
        backupCodes: newCodes,
        message: 'Backup codes have been regenerated'
      };
    } catch (error) {
      logger.error('Backup code regeneration failed', { error, userId: user._id || user.userId });
      throw error;
    }
  }
  
  /**
   * Get 2FA status for user
   * @param {Object} user - User document
   * @returns {Object} 2FA status
   */
  get2FAStatus(user) {
    const status = {
      enabled: user.security?.twoFactorEnabled || false,
      method: user.security?.twoFactorMethod || null,
      backupCodesRemaining: 0,
      phoneNumberMasked: null,
      enabledAt: user.security?.twoFactorEnabledAt || null
    };
    
    if (status.enabled) {
      // Count remaining backup codes
      if (user.security?.backupCodes) {
        status.backupCodesRemaining = user.security.backupCodes.filter(c => !c.used).length;
      }
      
      // Mask phone number
      if (user.security?.phoneNumber) {
        try {
          const phoneNumber = EncryptionService.decryptField(user.security.phoneNumber);
          status.phoneNumberMasked = phoneNumber.replace(/(\d{3})\d{4}(\d{4})/, '$1****$2');
        } catch (error) {
          logger.error('Failed to mask phone number', { error });
        }
      }
    }
    
    return status;
  }
  
  // Helper methods to work with different user formats
  
  /**
   * Create user object from AuthModel document
   * @param {Object} auth - AuthModel document
   * @returns {Object} User object compatible with TwoFactorService
   */
  createUserFromAuth(auth) {
    const user = {
      _id: auth.userId._id || auth.userId,
      email: auth.userId.email,
      security: {
        twoFactorEnabled: auth.mfa.enabled,
        twoFactorMethod: null,
        backupCodes: []
      },
      verifyPassword: async (password) => {
        return await auth.verifyPassword(password);
      },
      save: async () => {
        return await auth.save();
      }
    };
    
    // Find primary method
    const primaryMethod = auth.mfa.methods.find(m => m.isPrimary && m.enabled);
    if (primaryMethod) {
      user.security.twoFactorMethod = primaryMethod.type;
      user.security.twoFactorEnabledAt = primaryMethod.setupAt;
      
      if (primaryMethod.type === 'totp' && primaryMethod.config.totpSecret) {
        user.security.totpSecret = primaryMethod.config.totpSecret;
      }
      
      if (primaryMethod.type === 'sms' && primaryMethod.config.phoneNumber) {
        user.security.phoneNumber = primaryMethod.config.phoneNumber;
      }
    }
    
    // Add backup codes
    const backupMethod = auth.mfa.methods.find(m => m.type === 'backup_codes');
    if (backupMethod && backupMethod.config.codes) {
      user.security.backupCodes = backupMethod.config.codes;
    }
    
    return user;
  }
  
  /**
   * Check if user has MFA enabled (works with both formats)
   * @param {Object} user - User document
   * @returns {boolean} MFA enabled status
   */
  isUserMfaEnabled(user) {
    return user.security?.twoFactorEnabled || user.mfa?.enabled || false;
  }
  
  /**
   * Get user's MFA method (works with both formats)
   * @param {Object} user - User document
   * @returns {string|null} MFA method
   */
  getUserMfaMethod(user) {
    if (user.security?.twoFactorMethod) {
      return user.security.twoFactorMethod;
    }
    
    if (user.mfa?.methods) {
      const primaryMethod = user.mfa.methods.find(m => m.isPrimary && m.enabled);
      return primaryMethod?.type || null;
    }
    
    return null;
  }
  
  /**
   * Get user's TOTP secret (works with both formats)
   * @param {Object} user - User document
   * @returns {string|null} TOTP secret
   */
  getUserTotpSecret(user) {
    if (user.security?.totpSecret) {
      return user.security.totpSecret;
    }
    
    if (user.mfa?.methods) {
      const totpMethod = user.mfa.methods.find(m => m.type === 'totp' && m.enabled);
      return totpMethod?.config?.totpSecret || null;
    }
    
    return null;
  }
  
  /**
   * Get user's backup codes (works with both formats)
   * @param {Object} user - User document
   * @returns {Array} Backup codes
   */
  getUserBackupCodes(user) {
    if (user.security?.backupCodes) {
      return user.security.backupCodes;
    }
    
    if (user.mfa?.methods) {
      const backupMethod = user.mfa.methods.find(m => m.type === 'backup_codes');
      return backupMethod?.config?.codes || [];
    }
    
    return [];
  }
  
  // =======================
  // REDIS STORAGE METHODS
  // =======================
  
  /**
   * Store temporary secret in Redis with fallback
   * @param {Object} secret - Secret data
   */
  async storeTempSecret(secret) {
    try {
      if (!redis) {
        // Fallback to in-memory storage for development
        logger.warn('Redis not available, using in-memory storage for temp secrets');
        if (!global.tempSecrets) global.tempSecrets = new Map();
        global.tempSecrets.set(secret.tempId, secret);
        return;
      }

      const key = `2fa:temp:${secret.tempId}`;
      const ttl = Math.floor((secret.expiresAt - new Date()) / 1000); // TTL in seconds
      
      await redis.setex(key, ttl, JSON.stringify(secret));
      logger.debug('Temporary secret stored in Redis', { tempId: secret.tempId, ttl });
    } catch (error) {
      logger.error('Failed to store temporary secret', { error, tempId: secret.tempId });
      throw new AppError('Failed to store temporary secret', 500);
    }
  }

  /**
   * Retrieve temporary secret from Redis with fallback
   * @param {string} tempId - Temporary ID
   * @returns {Promise<Object>} Secret data
   */
  async retrieveTempSecret(tempId) {
    try {
      if (!redis) {
        // Fallback to in-memory storage for development
        if (!global.tempSecrets) return null;
        const secret = global.tempSecrets.get(tempId);
        if (secret && secret.expiresAt > new Date()) {
          return secret;
        }
        global.tempSecrets.delete(tempId);
        return null;
      }

      const key = `2fa:temp:${tempId}`;
      const data = await redis.get(key);
      
      if (!data) {
        logger.debug('Temporary secret not found or expired', { tempId });
        return null;
      }
      
      const secret = JSON.parse(data);
      
      // Convert date strings back to Date objects
      secret.createdAt = new Date(secret.createdAt);
      secret.expiresAt = new Date(secret.expiresAt);
      
      // Check if expired (additional safety check)
      if (secret.expiresAt < new Date()) {
        await this.deleteTempSecret(tempId);
        return null;
      }
      
      logger.debug('Temporary secret retrieved from Redis', { tempId });
      return secret;
    } catch (error) {
      logger.error('Failed to retrieve temporary secret', { error, tempId });
      return null;
    }
  }

  /**
   * Delete temporary secret from Redis with fallback
   * @param {string} tempId - Temporary ID
   */
  async deleteTempSecret(tempId) {
    try {
      if (!redis) {
        // Fallback to in-memory storage for development
        if (global.tempSecrets) {
          global.tempSecrets.delete(tempId);
        }
        return;
      }

      const key = `2fa:temp:${tempId}`;
      await redis.del(key);
      logger.debug('Temporary secret deleted from Redis', { tempId });
    } catch (error) {
      logger.error('Failed to delete temporary secret', { error, tempId });
      // Don't throw error for cleanup operations
    }
  }

  /**
   * Store SMS session in Redis with fallback
   * @param {Object} session - Session data
   */
  async storeSMSSession(session) {
    try {
      if (!redis) {
        logger.warn('Redis not available, using in-memory storage for SMS sessions');
        if (!global.smsSessions) global.smsSessions = new Map();
        const key = `${session.userId}:${session.phoneNumber}`;
        global.smsSessions.set(key, session);
        return;
      }

      const key = `2fa:sms:${session.userId}:${session.phoneNumber}`;
      const ttl = Math.floor((session.expiresAt - new Date()) / 1000);
      
      await redis.setex(key, ttl, JSON.stringify(session));
      logger.debug('SMS session stored in Redis', { userId: session.userId });
    } catch (error) {
      logger.error('Failed to store SMS session', { error, userId: session.userId });
      throw new AppError('Failed to store SMS session', 500);
    }
  }

  /**
   * Retrieve SMS session from Redis with fallback
   * @param {string} userId - User ID
   * @param {string} phoneNumber - Phone number
   * @returns {Promise<Object>} Session data
   */
  async retrieveSMSSession(userId, phoneNumber) {
    try {
      if (!redis) {
        if (!global.smsSessions) return null;
        const key = `${userId}:${phoneNumber}`;
        const session = global.smsSessions.get(key);
        if (session && session.expiresAt > new Date()) {
          return session;
        }
        global.smsSessions.delete(key);
        return null;
      }

      const key = `2fa:sms:${userId}:${phoneNumber}`;
      const data = await redis.get(key);
      
      if (!data) {
        return null;
      }
      
      const session = JSON.parse(data);
      session.expiresAt = new Date(session.expiresAt);
      
      if (session.expiresAt < new Date()) {
        await this.deleteSMSSession(userId, phoneNumber);
        return null;
      }
      
      return session;
    } catch (error) {
      logger.error('Failed to retrieve SMS session', { error, userId });
      return null;
    }
  }

  /**
   * Update SMS session in Redis with fallback
   * @param {Object} session - Session data
   */
  async updateSMSSession(session) {
    try {
      if (!redis) {
        if (global.smsSessions) {
          const key = `${session.userId}:${session.phoneNumber}`;
          global.smsSessions.set(key, session);
        }
        return;
      }

      const key = `2fa:sms:${session.userId}:${session.phoneNumber}`;
      const ttl = Math.floor((session.expiresAt - new Date()) / 1000);
      
      if (ttl > 0) {
        await redis.setex(key, ttl, JSON.stringify(session));
        logger.debug('SMS session updated in Redis', { userId: session.userId });
      }
    } catch (error) {
      logger.error('Failed to update SMS session', { error, userId: session.userId });
    }
  }

  /**
   * Delete SMS session from Redis with fallback
   * @param {string} userId - User ID
   * @param {string} phoneNumber - Phone number
   */
  async deleteSMSSession(userId, phoneNumber) {
    try {
      if (!redis) {
        if (global.smsSessions) {
          const key = `${userId}:${phoneNumber}`;
          global.smsSessions.delete(key);
        }
        return;
      }

      const key = `2fa:sms:${userId}:${phoneNumber}`;
      await redis.del(key);
      logger.debug('SMS session deleted from Redis', { userId });
    } catch (error) {
      logger.error('Failed to delete SMS session', { error, userId });
    }
  }

  /**
   * Store SMS code session in Redis with fallback
   * @param {Object} session - Session data
   */
  async storeSMSCodeSession(session) {
    try {
      if (!redis) {
        logger.warn('Redis not available, using in-memory storage for SMS code sessions');
        if (!global.smsCodeSessions) global.smsCodeSessions = new Map();
        global.smsCodeSessions.set(session.userId.toString(), session);
        return;
      }

      const key = `2fa:sms_code:${session.userId}`;
      const ttl = Math.floor((session.expiresAt - new Date()) / 1000);
      
      await redis.setex(key, ttl, JSON.stringify(session));
      logger.debug('SMS code session stored in Redis', { userId: session.userId });
    } catch (error) {
      logger.error('Failed to store SMS code session', { error, userId: session.userId });
      throw new AppError('Failed to store SMS code session', 500);
    }
  }

  /**
   * Retrieve SMS code session from Redis with fallback
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Session data
   */
  async retrieveSMSCodeSession(userId) {
    try {
      if (!redis) {
        if (!global.smsCodeSessions) return null;
        const session = global.smsCodeSessions.get(userId.toString());
        if (session && session.expiresAt > new Date()) {
          return session;
        }
        global.smsCodeSessions.delete(userId.toString());
        return null;
      }

      const key = `2fa:sms_code:${userId}`;
      const data = await redis.get(key);
      
      if (!data) {
        return null;
      }
      
      const session = JSON.parse(data);
      session.expiresAt = new Date(session.expiresAt);
      
      if (session.expiresAt < new Date()) {
        await this.deleteSMSCodeSession(userId);
        return null;
      }
      
      return session;
    } catch (error) {
      logger.error('Failed to retrieve SMS code session', { error, userId });
      return null;
    }
  }

  /**
   * Update SMS code session in Redis with fallback
   * @param {Object} session - Session data
   */
  async updateSMSCodeSession(session) {
    try {
      if (!redis) {
        if (global.smsCodeSessions) {
          global.smsCodeSessions.set(session.userId.toString(), session);
        }
        return;
      }

      const key = `2fa:sms_code:${session.userId}`;
      const ttl = Math.floor((session.expiresAt - new Date()) / 1000);
      
      if (ttl > 0) {
        await redis.setex(key, ttl, JSON.stringify(session));
        logger.debug('SMS code session updated in Redis', { userId: session.userId });
      }
    } catch (error) {
      logger.error('Failed to update SMS code session', { error, userId: session.userId });
    }
  }

  /**
   * Delete SMS code session from Redis with fallback
   * @param {string} userId - User ID
   */
  async deleteSMSCodeSession(userId) {
    try {
      if (!redis) {
        if (global.smsCodeSessions) {
          global.smsCodeSessions.delete(userId.toString());
        }
        return;
      }

      const key = `2fa:sms_code:${userId}`;
      await redis.del(key);
      logger.debug('SMS code session deleted from Redis', { userId });
    } catch (error) {
      logger.error('Failed to delete SMS code session', { error, userId });
    }
  }

  // =======================
  // SMS SENDING METHODS
  // =======================

  /**
   * Send SMS message - Enhanced with configuration support and fallbacks
   * @param {string} phoneNumber - Phone number
   * @param {string} message - Message content
   */
  async sendSMS(phoneNumber, message) {
    try {
      // Check if SMS is enabled
      if (!config.sms?.enabled) {
        logger.info('SMS sending disabled in configuration', { 
          phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*'), 
          messageLength: message.length 
        });
        
        // In development, log the message instead of sending
        if (config.app.env === 'development') {
          logger.info('SMS Message (Development Mode)', {
            phoneNumber: phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2'),
            message: message
          });
          return;
        }
        
        throw new AppError('SMS service is not configured', 500);
      }

      // Get SMS provider configuration
      const provider = config.sms.provider || 'twilio';
      
      switch (provider) {
        case 'twilio':
          await this.sendTwilioSMS(phoneNumber, message);
          break;
        case 'sns':
          await this.sendSNSSMS(phoneNumber, message);
          break;
        default:
          logger.warn('SMS sent via placeholder implementation', { 
            phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*'), 
            messageLength: message.length,
            provider 
          });
      }
    } catch (error) {
      logger.error('SMS sending failed', { 
        error: error.message, 
        phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*') 
      });
      throw new AppError('Failed to send SMS', 500);
    }
  }

  /**
   * Send SMS via Twilio (if configured)
   * @param {string} phoneNumber - Phone number
   * @param {string} message - Message content
   */
  async sendTwilioSMS(phoneNumber, message) {
    if (!config.sms.twilio?.accountSid || !config.sms.twilio?.authToken) {
      throw new AppError('Twilio SMS not configured', 500);
    }
    
    // This would integrate with actual Twilio SDK
    // const twilio = require('twilio');
    // const client = twilio(config.sms.twilio.accountSid, config.sms.twilio.authToken);
    // await client.messages.create({
    //   body: message,
    //   from: config.sms.twilio.phoneNumber,
    //   to: phoneNumber
    // });
    
    logger.info('Twilio SMS placeholder called', { 
      phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*'),
      messageLength: message.length 
    });
  }

  /**
   * Send SMS via AWS SNS (if configured)
   * @param {string} phoneNumber - Phone number
   * @param {string} message - Message content
   */
  async sendSNSSMS(phoneNumber, message) {
    if (!config.sms.sns?.accessKeyId || !config.sms.sns?.secretAccessKey) {
      throw new AppError('AWS SNS SMS not configured', 500);
    }
    
    // This would integrate with AWS SDK
    // const AWS = require('aws-sdk');
    // const sns = new AWS.SNS({
    //   accessKeyId: config.sms.sns.accessKeyId,
    //   secretAccessKey: config.sms.sns.secretAccessKey,
    //   region: config.sms.sns.region
    // });
    // await sns.publish({
    //   Message: message,
    //   PhoneNumber: phoneNumber
    // }).promise();
    
    logger.info('AWS SNS SMS placeholder called', { 
      phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*'),
      messageLength: message.length 
    });
  }
}

// Create and export singleton instance
module.exports = new TwoFactorService();