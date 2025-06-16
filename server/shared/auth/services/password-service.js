// server/shared/auth/services/password-service.js
/**
 * @file Password Service
 * @description Password management and validation service
 * @version 3.0.0
 */

const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const zxcvbn = require('zxcvbn');

const config = require('../../config');
const EncryptionService = require('../../security/services/encryption-service');
const { ValidationError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

/**
 * Password Service Class
 * @class PasswordService
 */
class PasswordService {
  constructor() {
    this.saltRounds = config.auth.bcryptRounds || 10;
    this.minLength = config.security.password.minLength || 8;
    this.maxLength = config.security.password.maxLength || 128;
    this.requireUppercase = config.security.password.requireUppercase;
    this.requireLowercase = config.security.password.requireLowercase;
    this.requireNumber = config.security.password.requireNumber;
    this.requireSpecial = config.security.password.requireSpecial;
    this.specialChars = config.security.password.specialChars || '@$!%*?&';
    this.historyCount = config.security.password.historyCount || 5;
    this.expiryDays = config.security.password.expiryDays || 90;
    
    // Common weak passwords
    this.commonPasswords = new Set([
      'password', '12345678', '123456789', 'qwerty', 'abc123',
      'password123', 'admin', 'letmein', 'welcome', 'monkey',
      '1234567890', 'password1', 'qwerty123', 'welcome123'
    ]);
    
    // Password patterns to block
    this.blockedPatterns = [
      /^(.)\1+$/, // All same character
      /^(012|123|234|345|456|567|678|789|890)+$/, // Sequential numbers
      /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i, // Sequential letters
      /^(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)+$/i // Keyboard patterns
    ];
  }
  
  /**
   * Hash password
   * @param {string} password - Plain text password
   * @returns {Promise<string>} Hashed password
   */
  async hashPassword(password) {
    try {
      const salt = await bcrypt.genSalt(this.saltRounds);
      return bcrypt.hash(password, salt);
    } catch (error) {
      logger.error('Password hashing failed', { error });
      throw new Error('Failed to hash password');
    }
  }
  
  /**
   * Verify password
   * @param {string} plainPassword - Plain text password
   * @param {string} hashedPassword - Hashed password
   * @returns {Promise<boolean>} Verification result
   */
  async verifyPassword(plainPassword, hashedPassword) {
    try {
      return bcrypt.compare(plainPassword, hashedPassword);
    } catch (error) {
      logger.error('Password verification failed', { error });
      return false;
    }
  }
  
  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @param {Object} userContext - User context for additional validation
   * @returns {Promise<Object>} Validation result
   */
  async validatePassword(password, userContext = {}) {
    const errors = [];
    const warnings = [];
    
    // Length validation
    if (password.length < this.minLength) {
      errors.push(`Password must be at least ${this.minLength} characters long`);
    }
    
    if (password.length > this.maxLength) {
      errors.push(`Password must not exceed ${this.maxLength} characters`);
    }
    
    // Character requirements
    if (this.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (this.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (this.requireNumber && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (this.requireSpecial && !new RegExp(`[${this.specialChars}]`).test(password)) {
      errors.push(`Password must contain at least one special character (${this.specialChars})`);
    }
    
    // Check common passwords
    if (this.commonPasswords.has(password.toLowerCase())) {
      errors.push('This password is too common. Please choose a more unique password');
    }
    
    // Check patterns
    for (const pattern of this.blockedPatterns) {
      if (pattern.test(password)) {
        errors.push('Password contains predictable patterns. Please choose a more complex password');
        break;
      }
    }
    
    // Context-based validation
    if (userContext) {
      // Check if password contains user info
      const userInfo = [
        userContext.email?.split('@')[0],
        userContext.firstName,
        userContext.lastName,
        userContext.username
      ].filter(Boolean).map(s => s.toLowerCase());
      
      const lowerPassword = password.toLowerCase();
      for (const info of userInfo) {
        if (info && lowerPassword.includes(info)) {
          errors.push('Password cannot contain personal information');
          break;
        }
      }
    }
    
    // Calculate password strength
    const strength = this.calculateStrength(password);
    
    if (strength.score < 2) {
      warnings.push('Password is weak. Consider using a stronger password');
    }
    
    // Check for errors
    if (errors.length > 0) {
      throw new ValidationError('Password validation failed', errors.map(message => ({
        field: 'password',
        message
      })));
    }
    
    return {
      valid: true,
      strength,
      warnings
    };
  }
  
  /**
   * Calculate password strength
   * @param {string} password - Password to analyze
   * @returns {Object} Strength analysis
   */
  calculateStrength(password) {
    const result = zxcvbn(password);
    
    return {
      score: result.score, // 0-4
      guesses: result.guesses,
      guessesLog10: result.guesses_log10,
      crackTime: {
        online: result.crack_times_display.online_throttling_100_per_hour,
        offline: result.crack_times_display.offline_slow_hashing_1e4_per_second
      },
      feedback: {
        warning: result.feedback.warning,
        suggestions: result.feedback.suggestions
      },
      scoreText: ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][result.score]
    };
  }
  
  /**
   * Generate secure password
   * @param {Object} options - Generation options
   * @returns {string} Generated password
   */
  generatePassword(options = {}) {
    const {
      length = 16,
      includeUppercase = true,
      includeLowercase = true,
      includeNumbers = true,
      includeSpecial = true,
      excludeAmbiguous = true,
      excludeSimilar = true
    } = options;
    
    let charset = '';
    
    if (includeLowercase) {
      charset += excludeAmbiguous ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    }
    
    if (includeUppercase) {
      charset += excludeAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }
    
    if (includeNumbers) {
      charset += excludeAmbiguous ? '23456789' : '0123456789';
    }
    
    if (includeSpecial) {
      charset += excludeSimilar ? '@#$%^&*' : '@$!%*?&';
    }
    
    if (!charset) {
      throw new Error('At least one character type must be included');
    }
    
    // Generate password
    let password = '';
    const randomBytes = crypto.randomBytes(length);
    
    for (let i = 0; i < length; i++) {
      password += charset[randomBytes[i] % charset.length];
    }
    
    // Ensure all required character types are present
    const requirements = [];
    if (includeUppercase && !/[A-Z]/.test(password)) {
      requirements.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    }
    if (includeLowercase && !/[a-z]/.test(password)) {
      requirements.push('abcdefghijklmnopqrstuvwxyz');
    }
    if (includeNumbers && !/\d/.test(password)) {
      requirements.push('0123456789');
    }
    if (includeSpecial && !/[@$!%*?&]/.test(password)) {
      requirements.push('@$!%*?&');
    }
    
    // Replace random characters with required types
    for (let i = 0; i < requirements.length; i++) {
      const position = crypto.randomInt(0, length);
      const charSet = requirements[i];
      password = password.substring(0, position) + 
                charSet[crypto.randomInt(0, charSet.length)] + 
                password.substring(position + 1);
    }
    
    return password;
  }
  
  /**
   * Generate passphrase
   * @param {Object} options - Generation options
   * @returns {string} Generated passphrase
   */
  generatePassphrase(options = {}) {
    const {
      wordCount = 4,
      separator = '-',
      capitalize = true,
      includeNumber = true
    } = options;
    
    // Word list (simplified - in production, use a comprehensive word list)
    const words = [
      'correct', 'horse', 'battery', 'staple', 'cloud', 'dragon',
      'phoenix', 'wizard', 'mountain', 'river', 'forest', 'ocean',
      'thunder', 'lightning', 'shadow', 'crystal', 'mirror', 'silver',
      'golden', 'ancient', 'modern', 'future', 'cosmic', 'stellar'
    ];
    
    const selectedWords = [];
    for (let i = 0; i < wordCount; i++) {
      const word = words[crypto.randomInt(0, words.length)];
      selectedWords.push(capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word);
    }
    
    let passphrase = selectedWords.join(separator);
    
    if (includeNumber) {
      passphrase += separator + crypto.randomInt(100, 999);
    }
    
    return passphrase;
  }
  
  /**
   * Check password history
   * @param {Object} user - User document
   * @param {string} newPassword - New password to check
   * @returns {Promise<boolean>} Is password reused
   */
  async checkPasswordHistory(user, newPassword) {
    if (!user.security?.passwordHistory || user.security.passwordHistory.length === 0) {
      return false;
    }
    
    // Check against password history
    for (const historicalPassword of user.security.passwordHistory) {
      const isMatch = await this.verifyPassword(newPassword, historicalPassword.hash);
      if (isMatch) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Add password to history
   * @param {Object} user - User document
   * @param {string} password - Password to add
   * @returns {Promise<void>}
   */
  async addToPasswordHistory(user, password) {
    if (!user.security) {
      user.security = {};
    }
    
    if (!user.security.passwordHistory) {
      user.security.passwordHistory = [];
    }
    
    // Hash password for history
    const hash = await this.hashPassword(password);
    
    // Add to history
    user.security.passwordHistory.unshift({
      hash,
      changedAt: new Date()
    });
    
    // Keep only the configured number of passwords
    if (user.security.passwordHistory.length > this.historyCount) {
      user.security.passwordHistory = user.security.passwordHistory.slice(0, this.historyCount);
    }
  }
  
  /**
   * Check if password has expired
   * @param {Object} user - User document
   * @returns {boolean} Is expired
   */
  isPasswordExpired(user) {
    if (!this.expiryDays || this.expiryDays <= 0) {
      return false;
    }
    
    if (!user.security?.passwordChangedAt) {
      return true;
    }
    
    const daysSinceChange = Math.floor(
      (Date.now() - new Date(user.security.passwordChangedAt).getTime()) / 
      (1000 * 60 * 60 * 24)
    );
    
    return daysSinceChange >= this.expiryDays;
  }
  
  /**
   * Get password expiry info
   * @param {Object} user - User document
   * @returns {Object} Expiry information
   */
  getPasswordExpiryInfo(user) {
    if (!this.expiryDays || this.expiryDays <= 0) {
      return {
        expiryEnabled: false,
        isExpired: false,
        daysUntilExpiry: null,
        expiryDate: null
      };
    }
    
    const passwordChangedAt = user.security?.passwordChangedAt || user.createdAt;
    const daysSinceChange = Math.floor(
      (Date.now() - new Date(passwordChangedAt).getTime()) / 
      (1000 * 60 * 60 * 24)
    );
    
    const daysUntilExpiry = this.expiryDays - daysSinceChange;
    const expiryDate = new Date(passwordChangedAt);
    expiryDate.setDate(expiryDate.getDate() + this.expiryDays);
    
    return {
      expiryEnabled: true,
      isExpired: daysUntilExpiry <= 0,
      daysUntilExpiry: Math.max(0, daysUntilExpiry),
      expiryDate,
      requiresChange: user.security?.requirePasswordChange || false
    };
  }
  
  /**
   * Generate password reset code
   * @param {number} length - Code length
   * @returns {Object} Code and hash
   */
  generateResetCode(length = 6) {
    const code = Array.from({ length }, () => 
      crypto.randomInt(0, 10)
    ).join('');
    
    const hash = EncryptionService.hash(code);
    
    return {
      code,
      hash,
      expiresAt: new Date(Date.now() + 3600000) // 1 hour
    };
  }
  
  /**
   * Verify reset code
   * @param {string} code - Reset code
   * @param {string} hash - Stored hash
   * @returns {boolean} Is valid
   */
  verifyResetCode(code, hash) {
    const codeHash = EncryptionService.hash(code);
    return crypto.timingSafeEqual(
      Buffer.from(hash),
      Buffer.from(codeHash)
    );
  }
  
  /**
   * Mask password for logging
   * @param {string} password - Password to mask
   * @returns {string} Masked password
   */
  maskPassword(password) {
    if (!password) return '';
    return '*'.repeat(password.length);
  }
  
  /**
   * Create password validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  createValidationMiddleware(options = {}) {
    const {
      field = 'password',
      required = true,
      checkStrength = true
    } = options;
    
    return async (req, res, next) => {
      try {
        const password = req.body[field];
        
        if (!password && required) {
          return res.status(400).json({
            success: false,
            error: {
              message: 'Password is required',
              field
            }
          });
        }
        
        if (password) {
          const validation = await this.validatePassword(password, {
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            username: req.body.username
          });
          
          if (checkStrength && validation.strength.score < 2) {
            return res.status(400).json({
              success: false,
              error: {
                message: 'Password is too weak',
                field,
                strength: validation.strength
              }
            });
          }
          
          // Attach validation result to request
          req.passwordValidation = validation;
        }
        
        next();
      } catch (error) {
        if (error instanceof ValidationError) {
          return res.status(400).json({
            success: false,
            error: {
              message: error.message,
              errors: error.errors
            }
          });
        }
        
        next(error);
      }
    };
  }
}

// Create and export singleton instance
module.exports = new PasswordService();