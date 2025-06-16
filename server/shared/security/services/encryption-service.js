// server/shared/security/services/encryption-service.js
/**
 * @file Encryption Service
 * @description Comprehensive encryption and security utilities
 * @version 3.0.0
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const config = require('../../config');
const logger = require('../../utils/logger');
const { AppError } = require('../../utils/app-error');

/**
 * Encryption Service Class
 * @class EncryptionService
 */
class EncryptionService {
  constructor() {
    this.algorithm = config.security.encryption.algorithm || 'aes-256-gcm';
    this.keyLength = config.security.encryption.keyLength || 32;
    this.ivLength = config.security.encryption.ivLength || 16;
    this.tagLength = config.security.encryption.tagLength || 16;
    this.saltLength = config.security.encryption.saltLength || 64;
    this.iterations = config.security.encryption.iterations || 100000;
    this.digest = 'sha256';
    
    // Initialize master key from environment
    this.masterKey = this.initializeMasterKey();
    
    // Cache for derived keys
    this.keyCache = new Map();
  }
  
  /**
   * Initialize master encryption key
   * @returns {Buffer} Master key
   */
  initializeMasterKey() {
    const masterKeyHex = process.env.ENCRYPTION_MASTER_KEY;
    
    if (!masterKeyHex) {
      if (config.isProduction) {
        throw new Error('ENCRYPTION_MASTER_KEY is required in production');
      }
      logger.warn('Using default encryption key - NOT FOR PRODUCTION USE');
      return crypto.randomBytes(this.keyLength);
    }
    
    const key = Buffer.from(masterKeyHex, 'hex');
    
    if (key.length !== this.keyLength) {
      throw new Error(`Master key must be ${this.keyLength} bytes`);
    }
    
    return key;
  }
  
  /**
   * Generate random bytes
   * @param {number} length - Number of bytes
   * @returns {Buffer} Random bytes
   */
  generateRandomBytes(length) {
    return crypto.randomBytes(length);
  }
  
  /**
   * Generate random string
   * @param {number} length - String length
   * @param {string} charset - Character set
   * @returns {string} Random string
   */
  generateRandomString(length = 32, charset = 'alphanumeric') {
    const charsets = {
      alphanumeric: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
      alphabetic: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
      numeric: '0123456789',
      hex: '0123456789abcdef',
      base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    };
    
    const chars = charsets[charset] || charsets.alphanumeric;
    const bytes = crypto.randomBytes(length);
    const result = new Array(length);
    
    for (let i = 0; i < length; i++) {
      result[i] = chars[bytes[i] % chars.length];
    }
    
    return result.join('');
  }
  
  /**
   * Generate secure token
   * @param {number} bytes - Token size in bytes
   * @returns {string} URL-safe token
   */
  generateToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('base64url');
  }
  
  /**
   * Hash data using SHA256
   * @param {string|Buffer} data - Data to hash
   * @param {string} encoding - Output encoding
   * @returns {string} Hash
   */
  hash(data, encoding = 'hex') {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest(encoding);
  }
  
  /**
   * Hash data with HMAC
   * @param {string|Buffer} data - Data to hash
   * @param {string|Buffer} key - HMAC key
   * @param {string} encoding - Output encoding
   * @returns {string} HMAC
   */
  hmac(data, key, encoding = 'hex') {
    return crypto
      .createHmac('sha256', key)
      .update(data)
      .digest(encoding);
  }
  
  /**
   * Derive encryption key from password
   * @param {string} password - Password
   * @param {Buffer} salt - Salt
   * @param {string} context - Key context
   * @returns {Buffer} Derived key
   */
  deriveKey(password, salt, context = 'encryption') {
    const cacheKey = `${password}:${salt.toString('hex')}:${context}`;
    
    // Check cache
    if (this.keyCache.has(cacheKey)) {
      return this.keyCache.get(cacheKey);
    }
    
    // Derive key
    const key = crypto.pbkdf2Sync(
      password,
      Buffer.concat([salt, Buffer.from(context)]),
      this.iterations,
      this.keyLength,
      this.digest
    );
    
    // Cache key (with size limit)
    if (this.keyCache.size > 100) {
      const firstKey = this.keyCache.keys().next().value;
      this.keyCache.delete(firstKey);
    }
    this.keyCache.set(cacheKey, key);
    
    return key;
  }
  
  /**
   * Encrypt data
   * @param {string|Buffer|Object} data - Data to encrypt
   * @param {Buffer} key - Encryption key (optional)
   * @returns {Object} Encrypted data with metadata
   */
  encrypt(data, key = null) {
    try {
      // Prepare data
      let plaintext;
      if (typeof data === 'object') {
        plaintext = JSON.stringify(data);
      } else if (Buffer.isBuffer(data)) {
        plaintext = data;
      } else {
        plaintext = String(data);
      }
      
      // Use provided key or master key
      const encryptionKey = key || this.masterKey;
      
      // Generate IV and salt
      const iv = this.generateRandomBytes(this.ivLength);
      const salt = this.generateRandomBytes(this.saltLength);
      
      // Create cipher
      const cipher = crypto.createCipheriv(this.algorithm, encryptionKey, iv);
      
      // Encrypt data
      const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
      ]);
      
      // Get auth tag for GCM mode
      const authTag = cipher.getAuthTag();
      
      // Combine encrypted data
      const combined = Buffer.concat([
        salt,
        iv,
        authTag,
        encrypted
      ]);
      
      return {
        encrypted: combined.toString('base64'),
        algorithm: this.algorithm,
        keyDerivation: 'pbkdf2'
      };
    } catch (error) {
      logger.error('Encryption error', { error: error.message });
      throw new AppError('Encryption failed', 500, 'ENCRYPTION_ERROR');
    }
  }
  
  /**
   * Decrypt data
   * @param {string} encryptedData - Base64 encoded encrypted data
   * @param {Buffer} key - Decryption key (optional)
   * @returns {string|Object} Decrypted data
   */
  decrypt(encryptedData, key = null) {
    try {
      // Decode from base64
      const combined = Buffer.from(encryptedData, 'base64');
      
      // Extract components
      const salt = combined.slice(0, this.saltLength);
      const iv = combined.slice(this.saltLength, this.saltLength + this.ivLength);
      const authTag = combined.slice(
        this.saltLength + this.ivLength,
        this.saltLength + this.ivLength + this.tagLength
      );
      const encrypted = combined.slice(this.saltLength + this.ivLength + this.tagLength);
      
      // Use provided key or master key
      const decryptionKey = key || this.masterKey;
      
      // Create decipher
      const decipher = crypto.createDecipheriv(this.algorithm, decryptionKey, iv);
      decipher.setAuthTag(authTag);
      
      // Decrypt data
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]).toString('utf8');
      
      // Try to parse as JSON
      try {
        return JSON.parse(decrypted);
      } catch {
        return decrypted;
      }
    } catch (error) {
      logger.error('Decryption error', { error: error.message });
      throw new AppError('Decryption failed', 500, 'DECRYPTION_ERROR');
    }
  }
  
  /**
   * Encrypt field value for database storage
   * @param {any} value - Value to encrypt
   * @param {string} fieldName - Field name for context
   * @returns {string} Encrypted value
   */
  encryptField(value, fieldName) {
    if (value === null || value === undefined) {
      return value;
    }
    
    const context = `field:${fieldName}`;
    const salt = this.generateRandomBytes(16);
    const key = this.deriveKey(this.masterKey.toString('hex'), salt, context);
    
    const encrypted = this.encrypt(value, key);
    
    return JSON.stringify({
      ...encrypted,
      salt: salt.toString('base64'),
      field: fieldName
    });
  }
  
  /**
   * Decrypt field value from database
   * @param {string} encryptedValue - Encrypted value
   * @returns {any} Decrypted value
   */
  decryptField(encryptedValue) {
    if (!encryptedValue || typeof encryptedValue !== 'string') {
      return encryptedValue;
    }
    
    try {
      const parsed = JSON.parse(encryptedValue);
      
      if (!parsed.encrypted || !parsed.salt || !parsed.field) {
        return encryptedValue;
      }
      
      const salt = Buffer.from(parsed.salt, 'base64');
      const context = `field:${parsed.field}`;
      const key = this.deriveKey(this.masterKey.toString('hex'), salt, context);
      
      return this.decrypt(parsed.encrypted, key);
    } catch {
      return encryptedValue;
    }
  }
  
  /**
   * Hash password
   * @param {string} password - Plain text password
   * @returns {Promise<string>} Hashed password
   */
  async hashPassword(password) {
    const rounds = config.auth.bcryptRounds || 10;
    return bcrypt.hash(password, rounds);
  }
  
  /**
   * Verify password
   * @param {string} password - Plain text password
   * @param {string} hash - Password hash
   * @returns {Promise<boolean>} Verification result
   */
  async verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
  }
  
  /**
   * Generate OTP (One-Time Password)
   * @param {number} length - OTP length
   * @param {Object} options - OTP options
   * @returns {Object} OTP and metadata
   */
  generateOTP(length = 6, options = {}) {
    const {
      numeric = true,
      expiryMinutes = 10,
      purpose = 'verification'
    } = options;
    
    let otp;
    if (numeric) {
      otp = Array.from({ length }, () => 
        Math.floor(Math.random() * 10)
      ).join('');
    } else {
      otp = this.generateRandomString(length, 'alphanumeric');
    }
    
    const hash = this.hash(`${otp}:${purpose}`);
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
    
    return {
      otp,
      hash,
      expiresAt,
      purpose
    };
  }
  
  /**
   * Verify OTP
   * @param {string} otp - OTP to verify
   * @param {string} hash - OTP hash
   * @param {string} purpose - OTP purpose
   * @returns {boolean} Verification result
   */
  verifyOTP(otp, hash, purpose = 'verification') {
    const expectedHash = this.hash(`${otp}:${purpose}`);
    return crypto.timingSafeEqual(
      Buffer.from(hash),
      Buffer.from(expectedHash)
    );
  }
  
  /**
   * Sign data with HMAC
   * @param {any} data - Data to sign
   * @param {string} secret - Signing secret
   * @returns {string} Signature
   */
  sign(data, secret = null) {
    const signingKey = secret || this.masterKey.toString('hex');
    const payload = typeof data === 'object' ? JSON.stringify(data) : String(data);
    
    return this.hmac(payload, signingKey);
  }
  
  /**
   * Verify signature
   * @param {any} data - Data to verify
   * @param {string} signature - Signature to verify
   * @param {string} secret - Signing secret
   * @returns {boolean} Verification result
   */
  verifySignature(data, signature, secret = null) {
    const expectedSignature = this.sign(data, secret);
    
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }
  
  /**
   * Encrypt sensitive data for logging
   * @param {any} data - Data to sanitize
   * @param {Array} sensitiveFields - Fields to encrypt
   * @returns {any} Sanitized data
   */
  sanitizeForLogging(data, sensitiveFields = []) {
    if (!data || typeof data !== 'object') {
      return data;
    }
    
    const defaultSensitiveFields = [
      'password', 'token', 'secret', 'key', 'apiKey',
      'creditCard', 'ssn', 'bankAccount', 'pin'
    ];
    
    const fields = [...defaultSensitiveFields, ...sensitiveFields];
    const sanitized = { ...data };
    
    const sanitizeObject = (obj) => {
      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        
        if (fields.some(field => lowerKey.includes(field.toLowerCase()))) {
          obj[key] = '[REDACTED]';
        } else if (value && typeof value === 'object') {
          sanitizeObject(value);
        }
      }
    };
    
    sanitizeObject(sanitized);
    return sanitized;
  }
  
  /**
   * Generate secure filename
   * @param {string} originalName - Original filename
   * @returns {string} Secure filename
   */
  generateSecureFilename(originalName) {
    const ext = originalName.split('.').pop();
    const timestamp = Date.now();
    const random = this.generateRandomString(8);
    
    return `${timestamp}_${random}.${ext}`;
  }
  
  /**
   * Create encrypted backup
   * @param {any} data - Data to backup
   * @param {string} backupKey - Backup encryption key
   * @returns {Object} Encrypted backup
   */
  createEncryptedBackup(data, backupKey) {
    const timestamp = new Date().toISOString();
    const checksum = this.hash(JSON.stringify(data));
    
    const backup = {
      version: '1.0',
      timestamp,
      checksum,
      data
    };
    
    const encrypted = this.encrypt(backup, Buffer.from(backupKey, 'hex'));
    
    return {
      ...encrypted,
      metadata: {
        timestamp,
        checksum,
        version: '1.0'
      }
    };
  }
  
  /**
   * Restore encrypted backup
   * @param {Object} encryptedBackup - Encrypted backup
   * @param {string} backupKey - Backup decryption key
   * @returns {any} Restored data
   */
  restoreEncryptedBackup(encryptedBackup, backupKey) {
    const decrypted = this.decrypt(
      encryptedBackup.encrypted,
      Buffer.from(backupKey, 'hex')
    );
    
    // Verify checksum
    const checksum = this.hash(JSON.stringify(decrypted.data));
    
    if (checksum !== decrypted.checksum) {
      throw new AppError('Backup integrity check failed', 400, 'BACKUP_CORRUPTED');
    }
    
    return decrypted.data;
  }
}

// Create and export singleton instance
module.exports = new EncryptionService();