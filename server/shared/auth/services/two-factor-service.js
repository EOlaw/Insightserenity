// server/shared/auth/services/two-factor-service.js
// Description: Two-Factor Authentication Service for managing TOTP, SMS, and backup codes
/**
 * @file Two-Factor Authentication Service
 * @description Multi-factor authentication service supporting TOTP, SMS, and backup codes
 * @version 3.0.0
 */

const crypto = require('crypto');

const qrcode = require('qrcode');
const speakeasy = require('speakeasy');

const config = require('../../config');
const AuditService = require('../../security/services/audit-service');
const EncryptionService = require('../../security/services/encryption-service');
const { AppError, ValidationError, AuthenticationError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

/**
 * Two-Factor Authentication Service Class
 * @class TwoFactorService
 */
class TwoFactorService {
  constructor() {
    this.appName = config.server.appName || 'InsightSerenity';
    this.backupCodeCount = 10;
    this.backupCodeLength = 8;
    this.totpWindow = 2; // Allow 2 time steps before/after
    this.smsCodeLength = 6;
    this.smsCodeExpiry = 10 * 60 * 1000; // 10 minutes
  }
  
  /**
   * Setup TOTP for user
   * @param {Object} user - User document
   * @returns {Promise<Object>} Setup data
   */
  async setupTOTP(user) {
    try {
      // Generate secret
      const secret = speakeasy.generateSecret({
        name: `${this.appName} (${user.email})`,
        issuer: this.appName,
        length: 32
      });
      
      // Generate QR code
      const qrCodeDataUrl = await qrcode.toDataURL(secret.otpauth_url);
      
      // Store encrypted secret temporarily
      const tempSecret = {
        secret: EncryptionService.encryptField(secret.base32, 'totp_secret'),
        tempId: EncryptionService.generateToken(16),
        userId: user._id,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000) // 1 hour
      };
      
      // Store in cache or temporary collection
      await this.storeTempSecret(tempSecret);
      
      // Log setup initiation
      await AuditService.log({
        type: '2fa_setup_initiated',
        action: 'setup_2fa',
        category: 'security',
        result: 'success',
        userId: user._id,
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
      logger.error('TOTP setup failed', { error, userId: user._id });
      throw new AppError('Failed to setup two-factor authentication', 500, '2FA_SETUP_ERROR');
    }
  }
  
  /**
   * Enable TOTP for user
   * @param {Object} user - User document
   * @param {string} tempId - Temporary secret ID
   * @param {string} token - TOTP token to verify
   * @returns {Promise<Object>} Enable result
   */
  async enableTOTP(user, tempId, token) {
    try {
      // Retrieve temporary secret
      const tempSecret = await this.retrieveTempSecret(tempId);
      
      if (!tempSecret || tempSecret.userId.toString() !== user._id.toString()) {
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
      
      // Update user security settings
      if (!user.security) {
        user.security = {};
      }
      
      user.security.twoFactorEnabled = true;
      user.security.twoFactorMethod = 'totp';
      user.security.totpSecret = EncryptionService.encryptField(secret, 'totp_secret');
      user.security.twoFactorEnabledAt = new Date();
      
      // Save backup codes
      const backupCodes = await this.generateBackupCodes();
      user.security.backupCodes = await this.encryptBackupCodes(backupCodes);
      
      await user.save();
      
      // Clean up temporary secret
      await this.deleteTempSecret(tempId);
      
      // Log successful enablement
      await AuditService.log({
        type: '2fa_enabled',
        action: 'enable_2fa',
        category: 'security',
        result: 'success',
        severity: 'high',
        userId: user._id,
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
      logger.error('TOTP enable failed', { error, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Disable two-factor authentication
   * @param {Object} user - User document
   * @param {string} password - User password for verification
   * @returns {Promise<Object>} Disable result
   */
  async disable2FA(user, password) {
    try {
      // Verify password
      const PasswordService = require('./password-service');
      const isValid = await PasswordService.verifyPassword(password, user.password);
      
      if (!isValid) {
        throw new AuthenticationError('Invalid password');
      }
      
      // Disable 2FA
      user.security.twoFactorEnabled = false;
      user.security.twoFactorMethod = null;
      user.security.totpSecret = null;
      user.security.backupCodes = [];
      user.security.phoneNumber = null;
      user.security.twoFactorDisabledAt = new Date();
      
      await user.save();
      
      // Log disablement
      await AuditService.log({
        type: '2fa_disabled',
        action: 'disable_2fa',
        category: 'security',
        result: 'success',
        severity: 'high',
        userId: user._id
      });
      
      return {
        success: true,
        message: 'Two-factor authentication has been disabled'
      };
    } catch (error) {
      logger.error('2FA disable failed', { error, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Verify TOTP token
   * @param {string} userId - User ID
   * @param {string} token - TOTP token
   * @returns {Promise<boolean>} Verification result
   */
  async verifyToken(userId, token) {
    try {
      // Get user
      const User = require('../../users/models/user-model');
      const user = await User.findById(userId).select('+security');
      
      if (!user || !user.security?.twoFactorEnabled) {
        return false;
      }
      
      // Check if it's a backup code
      if (token.length === this.backupCodeLength && /^\d+$/.test(token)) {
        return this.verifyBackupCode(user, token);
      }
      
      // Verify based on method
      switch (user.security.twoFactorMethod) {
        case 'totp':
          return this.verifyTOTP(user, token);
        case 'sms':
          return this.verifySMSCode(user, token);
        default:
          return false;
      }
    } catch (error) {
      logger.error('Token verification failed', { error, userId });
      return false;
    }
  }
  
  /**
   * Verify TOTP token
   * @param {Object} user - User document
   * @param {string} token - TOTP token
   * @returns {Promise<boolean>} Verification result
   */
  async verifyTOTP(user, token) {
    try {
      if (!user.security?.totpSecret) {
        return false;
      }
      
      // Decrypt secret
      const secret = EncryptionService.decryptField(user.security.totpSecret);
      
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
          userId: user._id,
          metadata: {
            method: 'totp'
          }
        });
      }
      
      return isValid;
    } catch (error) {
      logger.error('TOTP verification error', { error, userId: user._id });
      return false;
    }
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
   * Verify backup code
   * @param {Object} user - User document
   * @param {string} code - Backup code
   * @returns {Promise<boolean>} Verification result
   */
  async verifyBackupCode(user, code) {
    try {
      if (!user.security?.backupCodes || user.security.backupCodes.length === 0) {
        return false;
      }
      
      // Find and verify code
      for (let i = 0; i < user.security.backupCodes.length; i++) {
        const backupCode = user.security.backupCodes[i];
        
        if (backupCode.used) {
          continue;
        }
        
        const decryptedCode = EncryptionService.decryptField(backupCode.code);
        
        if (decryptedCode === code) {
          // Mark as used
          user.security.backupCodes[i].used = true;
          user.security.backupCodes[i].usedAt = new Date();
          
          await user.save();
          
          // Log backup code usage
          await AuditService.log({
            type: '2fa_backup_code_used',
            action: 'use_backup_code',
            category: 'security',
            result: 'success',
            severity: 'medium',
            userId: user._id,
            metadata: {
              remainingCodes: user.security.backupCodes.filter(c => !c.used).length
            }
          });
          
          return true;
        }
      }
      
      return false;
    } catch (error) {
      logger.error('Backup code verification error', { error, userId: user._id });
      return false;
    }
  }
  
  /**
   * Regenerate backup codes
   * @param {Object} user - User document
   * @param {string} password - User password for verification
   * @returns {Promise<Object>} New backup codes
   */
  async regenerateBackupCodes(user, password) {
    try {
      // Verify password
      const PasswordService = require('./password-service');
      const isValid = await PasswordService.verifyPassword(password, user.password);
      
      if (!isValid) {
        throw new AuthenticationError('Invalid password');
      }
      
      // Generate new codes
      const newCodes = await this.generateBackupCodes();
      user.security.backupCodes = await this.encryptBackupCodes(newCodes);
      
      await user.save();
      
      // Log regeneration
      await AuditService.log({
        type: '2fa_backup_codes_regenerated',
        action: 'regenerate_backup_codes',
        category: 'security',
        result: 'success',
        severity: 'medium',
        userId: user._id
      });
      
      return {
        success: true,
        backupCodes: newCodes,
        message: 'Backup codes have been regenerated'
      };
    } catch (error) {
      logger.error('Backup code regeneration failed', { error, userId: user._id });
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
      // Validate phone number
      if (!config.constants.REGEX.PHONE.test(phoneNumber)) {
        throw new ValidationError('Invalid phone number format');
      }
      
      // Generate and send verification code
      const verificationCode = await this.generateSMSCode();
      
      // Store verification session
      const session = {
        userId: user._id,
        phoneNumber,
        code: EncryptionService.hash(verificationCode),
        expiresAt: new Date(Date.now() + this.smsCodeExpiry),
        attempts: 0
      };
      
      await this.storeSMSSession(session);
      
      // Send SMS (integrate with SMS service)
      await this.sendSMS(phoneNumber, `Your ${this.appName} verification code is: ${verificationCode}`);
      
      return {
        success: true,
        message: 'Verification code sent to your phone'
      };
    } catch (error) {
      logger.error('SMS 2FA setup failed', { error, userId: user._id });
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
      // Verify SMS code
      const session = await this.retrieveSMSSession(user._id, phoneNumber);
      
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
      user.security.twoFactorEnabled = true;
      user.security.twoFactorMethod = 'sms';
      user.security.phoneNumber = EncryptionService.encryptField(phoneNumber, 'phone_number');
      user.security.twoFactorEnabledAt = new Date();
      
      // Generate backup codes
      const backupCodes = await this.generateBackupCodes();
      user.security.backupCodes = await this.encryptBackupCodes(backupCodes);
      
      await user.save();
      
      // Clean up session
      await this.deleteSMSSession(user._id, phoneNumber);
      
      // Log enablement
      await AuditService.log({
        type: '2fa_enabled',
        action: 'enable_2fa',
        category: 'security',
        result: 'success',
        severity: 'high',
        userId: user._id,
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
      logger.error('SMS 2FA enable failed', { error, userId: user._id });
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
      const code = await this.generateSMSCode();
      
      // Store code session
      const session = {
        userId: user._id,
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
      logger.error('SMS code send failed', { error, userId: user._id });
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
      const session = await this.retrieveSMSCodeSession(user._id);
      
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
      await this.deleteSMSCodeSession(user._id);
      
      // Log successful verification
      await AuditService.log({
        type: '2fa_verification_success',
        action: 'verify_2fa',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        metadata: {
          method: 'sms'
        }
      });
      
      return true;
    } catch (error) {
      logger.error('SMS code verification error', { error, userId: user._id });
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
  
  /**
   * Store temporary secret (implementation depends on storage choice)
   * @param {Object} secret - Secret data
   */
  async storeTempSecret(secret) {
    // This would store in Redis or temporary collection
    // Placeholder implementation
    logger.debug('Storing temporary secret', { tempId: secret.tempId });
  }
  
  /**
   * Retrieve temporary secret
   * @param {string} tempId - Temporary ID
   * @returns {Promise<Object>} Secret data
   */
  async retrieveTempSecret(tempId) {
    // This would retrieve from Redis or temporary collection
    // Placeholder implementation
    logger.debug('Retrieving temporary secret', { tempId });
    return null;
  }
  
  /**
   * Delete temporary secret
   * @param {string} tempId - Temporary ID
   */
  async deleteTempSecret(tempId) {
    // This would delete from Redis or temporary collection
    // Placeholder implementation
    logger.debug('Deleting temporary secret', { tempId });
  }
  
  /**
   * Store SMS session
   * @param {Object} session - Session data
   */
  async storeSMSSession(session) {
    // This would store in Redis or temporary collection
    // Placeholder implementation
    logger.debug('Storing SMS session', { userId: session.userId });
  }
  
  /**
   * Retrieve SMS session
   * @param {string} userId - User ID
   * @param {string} phoneNumber - Phone number
   * @returns {Promise<Object>} Session data
   */
  async retrieveSMSSession(userId, phoneNumber) {
    // This would retrieve from Redis or temporary collection
    // Placeholder implementation
    logger.debug('Retrieving SMS session', { userId });
    return null;
  }
  
  /**
   * Update SMS session
   * @param {Object} session - Session data
   */
  async updateSMSSession(session) {
    // This would update in Redis or temporary collection
    // Placeholder implementation
    logger.debug('Updating SMS session', { userId: session.userId });
  }
  
  /**
   * Delete SMS session
   * @param {string} userId - User ID
   * @param {string} phoneNumber - Phone number
   */
  async deleteSMSSession(userId, phoneNumber) {
    // This would delete from Redis or temporary collection
    // Placeholder implementation
    logger.debug('Deleting SMS session', { userId });
  }
  
  /**
   * Store SMS code session
   * @param {Object} session - Session data
   */
  async storeSMSCodeSession(session) {
    // This would store in Redis or temporary collection
    // Placeholder implementation
    logger.debug('Storing SMS code session', { userId: session.userId });
  }
  
  /**
   * Retrieve SMS code session
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Session data
   */
  async retrieveSMSCodeSession(userId) {
    // This would retrieve from Redis or temporary collection
    // Placeholder implementation
    logger.debug('Retrieving SMS code session', { userId });
    return null;
  }
  
  /**
   * Update SMS code session
   * @param {Object} session - Session data
   */
  async updateSMSCodeSession(session) {
    // This would update in Redis or temporary collection
    // Placeholder implementation
    logger.debug('Updating SMS code session', { userId: session.userId });
  }
  
  /**
   * Delete SMS code session
   * @param {string} userId - User ID
   */
  async deleteSMSCodeSession(userId) {
    // This would delete from Redis or temporary collection
    // Placeholder implementation
    logger.debug('Deleting SMS code session', { userId });
  }
  
  /**
   * Send SMS message
   * @param {string} phoneNumber - Phone number
   * @param {string} message - Message content
   */
  async sendSMS(phoneNumber, message) {
    // This would integrate with SMS service (Twilio, etc.)
    // Placeholder implementation
    logger.info('Sending SMS', { phoneNumber: phoneNumber.replace(/\d(?=\d{4})/g, '*'), messageLength: message.length });
  }
}

// Create and export singleton instance
module.exports = new TwoFactorService();