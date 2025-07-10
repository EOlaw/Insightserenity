// server/shared/auth/services/password-service.js
/**
 * @file Enhanced Password Service
 * @description Enterprise-grade password management and validation service with advanced security features
 * @version 4.0.0
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const zxcvbn = require('zxcvbn');

const config = require('../../config/config');
const AuditService = require('../../security/services/audit-service');
const EncryptionService = require('../../security/services/encryption-service');
const { AppError, ValidationError, AuthenticationError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

// Conditionally require Redis for rate limiting and caching
let redis = null;
if (config.redis?.enabled) {
  try {
    redis = require('../../config/redis');
    logger.info('Redis enabled for PasswordService rate limiting and caching');
  } catch (error) {
    logger.warn('Redis configuration not found, using in-memory fallback for password service', { error: error.message });
  }
}

/**
 * Enhanced Password Service Class with Enterprise Features
 * @class PasswordService
 */
class PasswordService {
  constructor() {
    // Configuration from config with comprehensive fallbacks
    this.config = {
      saltRounds: config.auth?.saltRounds || 12,
      minLength: config.auth?.passwordPolicy?.minLength || 12,
      maxLength: config.auth?.passwordPolicy?.maxLength || 128,
      requireUppercase: config.auth?.passwordPolicy?.requireUppercase ?? true,
      requireLowercase: config.auth?.passwordPolicy?.requireLowercase ?? true,
      requireNumbers: config.auth?.passwordPolicy?.requireNumbers ?? true,
      requireSpecialChars: config.auth?.passwordPolicy?.requireSpecialChars ?? true,
      preventReuse: config.auth?.passwordPolicy?.preventReuse || 5,
      maxAge: config.auth?.passwordPolicy?.maxAge || 7776000000, // 90 days
      expiryWarningDays: 7, // Warning period before expiry
      
      // Advanced security settings
      maxFailedAttempts: 5,
      lockoutDuration: 15 * 60 * 1000, // 15 minutes
      complexityChecking: true,
      breachChecking: config.app.env === 'production',
      entropyMinimum: 40, // bits of entropy
      
      // Rate limiting
      rateLimit: {
        enabled: true,
        maxAttempts: 10,
        windowMs: 15 * 60 * 1000, // 15 minutes
        blockDuration: 60 * 60 * 1000 // 1 hour
      }
    };
    
    // Enhanced character sets
    this.charSets = {
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      numbers: '0123456789',
      special: '!@#$%^&*()_+-=[]{}|;:,.<>?',
      ambiguous: 'il1Lo0O',
      similar: 'il1Lo0O'
    };
    
    // Comprehensive list of common weak passwords
    this.commonPasswords = new Set([
      'password', '12345678', '123456789', '1234567890', 'qwerty', 'abc123',
      'password123', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
      'password1', 'qwerty123', 'welcome123', 'admin123', 'root123',
      'changeme', 'default', 'guest', 'test123', 'user123', 'pass123',
      'secret', 'master', 'super', 'login', 'access', 'system',
      'service', 'temp123', 'demo123', 'sample123', 'trial123'
    ]);
    
    // Enhanced blocked patterns
    this.blockedPatterns = [
      { pattern: /^(.)\1+$/, message: 'Cannot use repeated characters' },
      { pattern: /^(012|123|234|345|456|567|678|789|890)+$/i, message: 'Cannot use sequential numbers' },
      { pattern: /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i, message: 'Cannot use sequential letters' },
      { pattern: /^(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)+$/i, message: 'Cannot use keyboard patterns' },
      { pattern: /^(19|20)\d{2}$/, message: 'Cannot use year as password' },
      { pattern: /^(january|february|march|april|may|june|july|august|september|october|november|december)\d*$/i, message: 'Cannot use month names' },
      { pattern: /^(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\d*$/i, message: 'Cannot use day names' }
    ];
    
    // Dictionary words to check against (simplified - in production, use comprehensive lists)
    this.commonWords = new Set([
      'company', 'business', 'office', 'work', 'home', 'family',
      'love', 'life', 'happy', 'birthday', 'christmas', 'holiday'
    ]);
    
    // Security breach indicators
    this.breachIndicators = new Map(); // In production, integrate with HaveIBeenPwned API
    
    // In-memory stores for rate limiting when Redis is not available
    if (!redis) {
      this.rateLimitStore = new Map();
      this.validationCache = new Map();
    }
  }
  
  /**
   * Enhanced password hashing with timing attack protection
   * @param {string} password - Plain text password
   * @param {Object} options - Hashing options
   * @returns {Promise<string>} Hashed password with metadata
   */
  async hashPassword(password, options = {}) {
    try {
      const startTime = Date.now();
      
      // Input validation
      if (!password || typeof password !== 'string') {
        throw new ValidationError('Invalid password input');
      }
      
      if (password.length > this.config.maxLength) {
        throw new ValidationError(`Password exceeds maximum length of ${this.config.maxLength} characters`);
      }
      
      // Generate salt with configurable rounds
      const saltRounds = options.saltRounds || this.config.saltRounds;
      const salt = await bcrypt.genSalt(saltRounds);
      
      // Hash password
      const hash = await bcrypt.hash(password, salt);
      
      // Timing attack protection - ensure minimum processing time
      const processingTime = Date.now() - startTime;
      if (processingTime < 100) {
        await new Promise(resolve => setTimeout(resolve, 100 - processingTime));
      }
      
      // Log password change event
      logger.info('Password hashed successfully', {
        saltRounds,
        processingTime: Date.now() - startTime,
        passwordLength: password.length
      });
      
      return hash;
    } catch (error) {
      logger.error('Password hashing failed', { 
        error: error.message,
        stack: error.stack,
        passwordLength: password?.length || 0
      });
      
      if (error instanceof ValidationError) {
        throw error;
      }
      
      throw new AppError('Failed to hash password', 500, 'PASSWORD_HASH_ERROR');
    }
  }
  
  /**
   * Enhanced password verification with rate limiting and audit logging
   * @param {string} plainPassword - Plain text password
   * @param {string} hashedPassword - Hashed password
   * @param {Object} context - Verification context
   * @returns {Promise<boolean>} Verification result
   */
  async verifyPassword(plainPassword, hashedPassword, context = {}) {
    const startTime = Date.now();
    
    try {
      // Input validation
      if (!plainPassword || !hashedPassword) {
        return false;
      }
      
      // Rate limiting check
      if (context.userId) {
        await this.checkRateLimit(context.userId, 'password_verification');
      }
      
      // Perform verification with timing attack protection
      const isValid = await bcrypt.compare(plainPassword, hashedPassword);
      
      // Ensure minimum processing time for timing attack protection
      const processingTime = Date.now() - startTime;
      if (processingTime < 100) {
        await new Promise(resolve => setTimeout(resolve, 100 - processingTime));
      }
      
      // Audit logging
      if (context.userId) {
        await AuditService.log({
          type: isValid ? 'password_verification_success' : 'password_verification_failed',
          action: 'verify_password',
          category: 'authentication',
          result: isValid ? 'success' : 'failure',
          userId: context.userId,
          metadata: {
            ip: context.ip,
            userAgent: context.userAgent,
            processingTime: Date.now() - startTime
          }
        });
        
        // Update rate limiting
        if (!isValid) {
          await this.recordFailedAttempt(context.userId, 'password_verification');
        }
      }
      
      return isValid;
    } catch (error) {
      logger.error('Password verification failed', { 
        error: error.message,
        context,
        processingTime: Date.now() - startTime
      });
      
      // Always return false on error to prevent information leakage
      return false;
    }
  }
  
  /**
   * Comprehensive password validation with advanced security checks
   * @param {string} password - Password to validate
   * @param {Object} userContext - User context for additional validation
   * @param {Object} options - Validation options
   * @returns {Promise<Object>} Comprehensive validation result
   */
  async validatePassword(password, userContext = {}, options = {}) {
    const validationId = crypto.randomUUID();
    const startTime = Date.now();
    
    try {
      logger.debug('Starting password validation', { validationId, passwordLength: password?.length || 0 });
      
      // Input validation
      if (!password) {
        throw new ValidationError('Password is required');
      }
      
      if (typeof password !== 'string') {
        throw new ValidationError('Password must be a string');
      }
      
      // Check cache for repeated validations
      const cacheKey = this.generateValidationCacheKey(password, userContext);
      if (!options.skipCache) {
        const cachedResult = await this.getCachedValidation(cacheKey);
        if (cachedResult) {
          logger.debug('Using cached validation result', { validationId });
          return cachedResult;
        }
      }
      
      const errors = [];
      const warnings = [];
      const suggestions = [];
      
      // Basic length validation
      if (password.length < this.config.minLength) {
        errors.push({
          code: 'LENGTH_TOO_SHORT',
          message: `Password must be at least ${this.config.minLength} characters long`,
          severity: 'error'
        });
      }
      
      if (password.length > this.config.maxLength) {
        errors.push({
          code: 'LENGTH_TOO_LONG',
          message: `Password must not exceed ${this.config.maxLength} characters`,
          severity: 'error'
        });
      }
      
      // Character requirement validation
      const characterChecks = this.performCharacterValidation(password);
      errors.push(...characterChecks.errors);
      warnings.push(...characterChecks.warnings);
      suggestions.push(...characterChecks.suggestions);
      
      // Common password check
      if (this.commonPasswords.has(password.toLowerCase())) {
        errors.push({
          code: 'COMMON_PASSWORD',
          message: 'This password is too common. Please choose a more unique password',
          severity: 'error'
        });
      }
      
      // Pattern validation
      const patternCheck = this.checkBlockedPatterns(password);
      if (patternCheck.blocked) {
        errors.push({
          code: 'BLOCKED_PATTERN',
          message: patternCheck.message,
          severity: 'error'
        });
      }
      
      // Dictionary word check
      const dictionaryCheck = this.checkDictionaryWords(password);
      if (dictionaryCheck.hasWords) {
        warnings.push({
          code: 'DICTIONARY_WORDS',
          message: 'Password contains common dictionary words',
          severity: 'warning'
        });
        suggestions.push('Consider using uncommon words or adding numbers and symbols');
      }
      
      // Context-based validation
      const contextCheck = await this.validateAgainstUserContext(password, userContext);
      errors.push(...contextCheck.errors);
      warnings.push(...contextCheck.warnings);
      
      // Entropy calculation
      const entropyCheck = this.calculatePasswordEntropy(password);
      if (entropyCheck.entropy < this.config.entropyMinimum) {
        warnings.push({
          code: 'LOW_ENTROPY',
          message: `Password entropy is ${entropyCheck.entropy.toFixed(1)} bits, recommended minimum is ${this.config.entropyMinimum}`,
          severity: 'warning'
        });
        suggestions.push('Add more character variety to increase password strength');
      }
      
      // Advanced strength analysis using zxcvbn
      const strengthAnalysis = this.performStrengthAnalysis(password, userContext);
      
      // Breach checking (if enabled)
      let breachCheck = { breached: false, breachCount: 0 };
      if (this.config.breachChecking) {
        breachCheck = await this.checkPasswordBreach(password);
        if (breachCheck.breached) {
          errors.push({
            code: 'KNOWN_BREACH',
            message: `This password has been found in ${breachCheck.breachCount} data breaches`,
            severity: 'error'
          });
        }
      }
      
      // Compile validation result
      const validationResult = {
        valid: errors.length === 0,
        validationId,
        password: {
          length: password.length,
          entropy: entropyCheck.entropy,
          characterSets: entropyCheck.characterSets
        },
        strength: strengthAnalysis,
        security: {
          breached: breachCheck.breached,
          breachCount: breachCheck.breachCount,
          entropy: entropyCheck.entropy,
          riskLevel: this.calculateRiskLevel(errors, warnings, strengthAnalysis)
        },
        validation: {
          errors: errors,
          warnings: warnings,
          suggestions: suggestions,
          score: this.calculateValidationScore(errors, warnings, strengthAnalysis),
          processingTime: Date.now() - startTime
        },
        compliance: {
          meetsPolicy: errors.length === 0,
          policyVersion: '1.0',
          lastChecked: new Date().toISOString()
        }
      };
      
      // Cache result if valid
      if (validationResult.valid && !options.skipCache) {
        await this.cacheValidationResult(cacheKey, validationResult);
      }
      
      // Log validation completion
      logger.debug('Password validation completed', {
        validationId,
        valid: validationResult.valid,
        errorCount: errors.length,
        warningCount: warnings.length,
        processingTime: validationResult.validation.processingTime
      });
      
      return validationResult;
      
    } catch (error) {
      logger.error('Password validation failed', {
        error: error.message,
        validationId,
        processingTime: Date.now() - startTime
      });
      
      if (error instanceof ValidationError) {
        throw error;
      }
      
      throw new AppError('Password validation failed', 500, 'VALIDATION_ERROR');
    }
  }
  
  /**
   * Perform character requirement validation
   * @param {string} password - Password to check
   * @returns {Object} Character validation results
   */
  performCharacterValidation(password) {
    const errors = [];
    const warnings = [];
    const suggestions = [];
    
    const hasLowercase = /[a-z]/.test(password);
    const hasUppercase = /[A-Z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password);
    
    if (this.config.requireLowercase && !hasLowercase) {
      errors.push({
        code: 'MISSING_LOWERCASE',
        message: 'Password must contain at least one lowercase letter',
        severity: 'error'
      });
    }
    
    if (this.config.requireUppercase && !hasUppercase) {
      errors.push({
        code: 'MISSING_UPPERCASE',
        message: 'Password must contain at least one uppercase letter',
        severity: 'error'
      });
    }
    
    if (this.config.requireNumbers && !hasNumbers) {
      errors.push({
        code: 'MISSING_NUMBERS',
        message: 'Password must contain at least one number',
        severity: 'error'
      });
    }
    
    if (this.config.requireSpecialChars && !hasSpecial) {
      errors.push({
        code: 'MISSING_SPECIAL',
        message: 'Password must contain at least one special character',
        severity: 'error'
      });
    }
    
    // Character variety suggestions
    const characterTypes = [hasLowercase, hasUppercase, hasNumbers, hasSpecial].filter(Boolean).length;
    if (characterTypes < 3) {
      suggestions.push('Use a mix of uppercase, lowercase, numbers, and special characters');
    }
    
    return { errors, warnings, suggestions };
  }
  
  /**
   * Check for blocked patterns
   * @param {string} password - Password to check
   * @returns {Object} Pattern check result
   */
  checkBlockedPatterns(password) {
    for (const { pattern, message } of this.blockedPatterns) {
      if (pattern.test(password)) {
        return { blocked: true, message };
      }
    }
    return { blocked: false };
  }
  
  /**
   * Check for dictionary words
   * @param {string} password - Password to check
   * @returns {Object} Dictionary check result
   */
  checkDictionaryWords(password) {
    const lowerPassword = password.toLowerCase();
    const foundWords = [];
    
    for (const word of this.commonWords) {
      if (lowerPassword.includes(word)) {
        foundWords.push(word);
      }
    }
    
    return {
      hasWords: foundWords.length > 0,
      words: foundWords
    };
  }
  
  /**
   * Validate password against user context
   * @param {string} password - Password to validate
   * @param {Object} userContext - User information
   * @returns {Promise<Object>} Context validation results
   */
  async validateAgainstUserContext(password, userContext) {
    const errors = [];
    const warnings = [];
    
    if (!userContext || typeof userContext !== 'object') {
      return { errors, warnings };
    }
    
    const lowerPassword = password.toLowerCase();
    
    // Check email
    if (userContext.email) {
      const emailParts = userContext.email.toLowerCase().split('@');
      const username = emailParts[0];
      const domain = emailParts[1]?.split('.')[0];
      
      if (username && username.length > 2 && lowerPassword.includes(username)) {
        errors.push({
          code: 'CONTAINS_EMAIL',
          message: 'Password cannot contain parts of your email address',
          severity: 'error'
        });
      }
      
      if (domain && domain.length > 2 && lowerPassword.includes(domain)) {
        warnings.push({
          code: 'CONTAINS_DOMAIN',
          message: 'Password contains your email domain',
          severity: 'warning'
        });
      }
    }
    
    // Check personal information
    const personalInfo = [
      { value: userContext.firstName, type: 'first name' },
      { value: userContext.lastName, type: 'last name' },
      { value: userContext.username, type: 'username' },
      { value: userContext.displayName, type: 'display name' }
    ];
    
    for (const { value, type } of personalInfo) {
      if (value && typeof value === 'string' && value.length > 2) {
        if (lowerPassword.includes(value.toLowerCase())) {
          errors.push({
            code: 'CONTAINS_PERSONAL_INFO',
            message: `Password cannot contain your ${type}`,
            severity: 'error'
          });
        }
      }
    }
    
    // Check organization information
    if (userContext.organizationName && userContext.organizationName.length > 3) {
      if (lowerPassword.includes(userContext.organizationName.toLowerCase())) {
        warnings.push({
          code: 'CONTAINS_ORGANIZATION',
          message: 'Password contains organization name',
          severity: 'warning'
        });
      }
    }
    
    return { errors, warnings };
  }
  
  /**
   * Calculate password entropy
   * @param {string} password - Password to analyze
   * @returns {Object} Entropy analysis
   */
  calculatePasswordEntropy(password) {
    let charsetSize = 0;
    const characterSets = {
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /\d/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password),
      extended: /[^\w\s!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)
    };
    
    if (characterSets.lowercase) charsetSize += 26;
    if (characterSets.uppercase) charsetSize += 26;
    if (characterSets.numbers) charsetSize += 10;
    if (characterSets.special) charsetSize += 32;
    if (characterSets.extended) charsetSize += 20;
    
    const entropy = password.length * Math.log2(charsetSize);
    
    return {
      entropy: Math.round(entropy * 10) / 10,
      charsetSize,
      characterSets,
      length: password.length
    };
  }
  
  /**
   * Perform strength analysis using zxcvbn
   * @param {string} password - Password to analyze
   * @param {Object} userContext - User context for personalized analysis
   * @returns {Object} Strength analysis
   */
  performStrengthAnalysis(password, userContext = {}) {
    try {
      // Build user inputs for zxcvbn
      const userInputs = [];
      if (userContext.email) userInputs.push(userContext.email, userContext.email.split('@')[0]);
      if (userContext.firstName) userInputs.push(userContext.firstName);
      if (userContext.lastName) userInputs.push(userContext.lastName);
      if (userContext.username) userInputs.push(userContext.username);
      if (userContext.organizationName) userInputs.push(userContext.organizationName);
      
      const result = zxcvbn(password, userInputs);
      
      return {
        score: result.score, // 0-4
        scoreText: ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'][result.score],
        guesses: result.guesses,
        guessesLog10: result.guesses_log10,
        crackTime: {
          onlineThrottling: result.crack_times_display.online_throttling_100_per_hour,
          onlineNoThrottling: result.crack_times_display.online_no_throttling_10_per_second,
          offlineSlowHashing: result.crack_times_display.offline_slow_hashing_1e4_per_second,
          offlineFastHashing: result.crack_times_display.offline_fast_hashing_1e10_per_second
        },
        feedback: {
          warning: result.feedback.warning || '',
          suggestions: result.feedback.suggestions || []
        },
        pattern: result.sequence.map(seq => ({
          pattern: seq.pattern,
          token: seq.token,
          matched_word: seq.matched_word,
          rank: seq.rank
        }))
      };
    } catch (error) {
      logger.error('Strength analysis failed', { error: error.message });
      
      // Fallback simple scoring
      return {
        score: 1,
        scoreText: 'Unknown',
        guesses: 1000000,
        guessesLog10: 6,
        crackTime: {
          onlineThrottling: 'unknown',
          onlineNoThrottling: 'unknown',
          offlineSlowHashing: 'unknown',
          offlineFastHashing: 'unknown'
        },
        feedback: {
          warning: 'Unable to analyze password strength',
          suggestions: ['Use a strong, unique password']
        },
        pattern: []
      };
    }
  }
  
  /**
   * Check if password has been compromised in data breaches
   * @param {string} password - Password to check
   * @returns {Promise<Object>} Breach check result
   */
  async checkPasswordBreach(password) {
    try {
      // In production, integrate with HaveIBeenPwned API
      // For now, return placeholder result
      
      // Hash password for checking (SHA-1 for HIBP compatibility)
      const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);
      
      // Check local breach cache first
      if (this.breachIndicators.has(hash)) {
        const breachData = this.breachIndicators.get(hash);
        return {
          breached: true,
          breachCount: breachData.count,
          lastSeen: breachData.lastSeen
        };
      }
      
      // In production, make API call to HaveIBeenPwned
      // const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      // if (response.ok) {
      //   const data = await response.text();
      //   const lines = data.split('\n');
      //   for (const line of lines) {
      //     const [hashSuffix, count] = line.split(':');
      //     if (hashSuffix === suffix) {
      //       return { breached: true, breachCount: parseInt(count, 10) };
      //     }
      //   }
      // }
      
      return { breached: false, breachCount: 0 };
    } catch (error) {
      logger.error('Breach check failed', { error: error.message });
      return { breached: false, breachCount: 0 };
    }
  }
  
  /**
   * Calculate risk level based on validation results
   * @param {Array} errors - Validation errors
   * @param {Array} warnings - Validation warnings
   * @param {Object} strengthAnalysis - Strength analysis
   * @returns {string} Risk level
   */
  calculateRiskLevel(errors, warnings, strengthAnalysis) {
    if (errors.length > 0) return 'high';
    if (strengthAnalysis.score <= 1) return 'high';
    if (strengthAnalysis.score === 2 || warnings.length > 2) return 'medium';
    if (strengthAnalysis.score === 3 || warnings.length > 0) return 'low';
    return 'minimal';
  }
  
  /**
   * Calculate validation score
   * @param {Array} errors - Validation errors
   * @param {Array} warnings - Validation warnings
   * @param {Object} strengthAnalysis - Strength analysis
   * @returns {number} Validation score (0-100)
   */
  calculateValidationScore(errors, warnings, strengthAnalysis) {
    if (errors.length > 0) return 0;
    
    let score = strengthAnalysis.score * 20; // Base score from strength (0-80)
    score -= warnings.length * 5; // Reduce for warnings
    score = Math.max(0, Math.min(100, score)); // Clamp to 0-100
    
    return score;
  }
  
  /**
   * Generate secure password with comprehensive options
   * @param {Object} options - Generation options
   * @returns {Promise<Object>} Generated password with metadata
   */
  async generatePassword(options = {}) {
    try {
      const settings = {
        length: options.length || 16,
        includeUppercase: options.includeUppercase ?? true,
        includeLowercase: options.includeLowercase ?? true,
        includeNumbers: options.includeNumbers ?? true,
        includeSpecial: options.includeSpecial ?? true,
        excludeAmbiguous: options.excludeAmbiguous ?? true,
        excludeSimilar: options.excludeSimilar ?? true,
        minUppercase: options.minUppercase || 1,
        minLowercase: options.minLowercase || 1,
        minNumbers: options.minNumbers || 1,
        minSpecial: options.minSpecial || 1,
        maxRepeating: options.maxRepeating || 2,
        ensureComplexity: options.ensureComplexity ?? true
      };
      
      // Validate settings
      if (settings.length < 8 || settings.length > 128) {
        throw new ValidationError('Password length must be between 8 and 128 characters');
      }
      
      // Build character set
      let charset = '';
      if (settings.includeLowercase) {
        charset += settings.excludeAmbiguous ? 
          this.charSets.lowercase.replace(/[il]/g, '') : 
          this.charSets.lowercase;
      }
      if (settings.includeUppercase) {
        charset += settings.excludeAmbiguous ? 
          this.charSets.uppercase.replace(/[IL]/g, '') : 
          this.charSets.uppercase;
      }
      if (settings.includeNumbers) {
        charset += settings.excludeAmbiguous ? 
          this.charSets.numbers.replace(/[10]/g, '') : 
          this.charSets.numbers;
      }
      if (settings.includeSpecial) {
        charset += this.charSets.special;
      }
      
      if (!charset) {
        throw new ValidationError('At least one character type must be included');
      }
      
      let attempts = 0;
      let password = '';
      
      // Generate password with requirements checking
      do {
        password = '';
        const randomBytes = crypto.randomBytes(settings.length * 2); // Extra bytes for filtering
        let byteIndex = 0;
        
        while (password.length < settings.length && byteIndex < randomBytes.length) {
          const char = charset[randomBytes[byteIndex] % charset.length];
          
          // Check for repeating characters
          if (settings.maxRepeating > 0) {
            const lastChars = password.slice(-settings.maxRepeating);
            if (lastChars.length === settings.maxRepeating && lastChars.every(c => c === char)) {
              byteIndex++;
              continue;
            }
          }
          
          password += char;
          byteIndex++;
        }
        
        attempts++;
        
        // Check if password meets minimum requirements
        if (settings.ensureComplexity && !this.meetsMinimumRequirements(password, settings)) {
          if (attempts < 10) {
            continue; // Try again
          } else {
            // Force requirements by replacing characters
            password = this.enforceRequirements(password, settings);
          }
        }
        
        break;
      } while (attempts < 10);
      
      // Validate generated password
      const validation = await this.validatePassword(password, {}, { skipCache: true });
      
      // Calculate entropy
      const entropy = this.calculatePasswordEntropy(password);
      
      return {
        password,
        metadata: {
          length: password.length,
          entropy: entropy.entropy,
          charset: charset.length,
          strength: validation.strength.score,
          settings,
          attempts,
          generatedAt: new Date().toISOString()
        },
        validation: validation.valid,
        warnings: validation.validation?.warnings || []
      };
    } catch (error) {
      logger.error('Password generation failed', { error: error.message, options });
      throw error;
    }
  }
  
  /**
   * Check if password meets minimum requirements
   * @param {string} password - Password to check
   * @param {Object} settings - Requirements settings
   * @returns {boolean} Meets requirements
   */
  meetsMinimumRequirements(password, settings) {
    const counts = {
      uppercase: (password.match(/[A-Z]/g) || []).length,
      lowercase: (password.match(/[a-z]/g) || []).length,
      numbers: (password.match(/\d/g) || []).length,
      special: (password.match(/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/g) || []).length
    };
    
    return counts.uppercase >= settings.minUppercase &&
           counts.lowercase >= settings.minLowercase &&
           counts.numbers >= settings.minNumbers &&
           counts.special >= settings.minSpecial;
  }
  
  /**
   * Enforce minimum requirements by replacing characters
   * @param {string} password - Password to modify
   * @param {Object} settings - Requirements settings
   * @returns {string} Modified password
   */
  enforceRequirements(password, settings) {
    const chars = password.split('');
    const requirements = [
      { type: 'uppercase', chars: this.charSets.uppercase, min: settings.minUppercase },
      { type: 'lowercase', chars: this.charSets.lowercase, min: settings.minLowercase },
      { type: 'numbers', chars: this.charSets.numbers, min: settings.minNumbers },
      { type: 'special', chars: this.charSets.special, min: settings.minSpecial }
    ];
    
    let position = 0;
    for (const req of requirements) {
      for (let i = 0; i < req.min && position < chars.length; i++) {
        const randomChar = req.chars[crypto.randomInt(0, req.chars.length)];
        chars[position] = randomChar;
        position++;
      }
    }
    
    return chars.join('');
  }
  
  /**
   * Rate limiting check
   * @param {string} identifier - User or IP identifier
   * @param {string} action - Action type
   * @returns {Promise<boolean>} Is rate limited
   */
  async checkRateLimit(identifier, action) {
    if (!this.config.rateLimit.enabled) {
      return false;
    }
    
    const key = `rate_limit:${action}:${identifier}`;
    const now = Date.now();
    
    try {
      if (redis) {
        const attempts = await redis.get(key);
        if (attempts && parseInt(attempts) >= this.config.rateLimit.maxAttempts) {
          throw new AppError('Rate limit exceeded', 429, 'RATE_LIMIT_EXCEEDED');
        }
      } else {
        // Fallback to in-memory storage
        if (!this.rateLimitStore.has(key)) {
          this.rateLimitStore.set(key, { count: 0, resetTime: now + this.config.rateLimit.windowMs });
        }
        
        const data = this.rateLimitStore.get(key);
        if (now > data.resetTime) {
          data.count = 0;
          data.resetTime = now + this.config.rateLimit.windowMs;
        }
        
        if (data.count >= this.config.rateLimit.maxAttempts) {
          throw new AppError('Rate limit exceeded', 429, 'RATE_LIMIT_EXCEEDED');
        }
      }
      
      return false;
    } catch (error) {
      if (error.code === 'RATE_LIMIT_EXCEEDED') {
        throw error;
      }
      logger.error('Rate limit check failed', { error: error.message });
      return false;
    }
  }
  
  /**
   * Record failed attempt for rate limiting
   * @param {string} identifier - User or IP identifier
   * @param {string} action - Action type
   */
  async recordFailedAttempt(identifier, action) {
    if (!this.config.rateLimit.enabled) {
      return;
    }
    
    const key = `rate_limit:${action}:${identifier}`;
    
    try {
      if (redis) {
        await redis.multi()
          .incr(key)
          .expire(key, Math.floor(this.config.rateLimit.windowMs / 1000))
          .exec();
      } else {
        // Fallback to in-memory storage
        const now = Date.now();
        if (!this.rateLimitStore.has(key)) {
          this.rateLimitStore.set(key, { count: 0, resetTime: now + this.config.rateLimit.windowMs });
        }
        
        const data = this.rateLimitStore.get(key);
        if (now > data.resetTime) {
          data.count = 1;
          data.resetTime = now + this.config.rateLimit.windowMs;
        } else {
          data.count++;
        }
      }
    } catch (error) {
      logger.error('Failed to record rate limit attempt', { error: error.message });
    }
  }
  
  /**
   * Generate cache key for validation results
   * @param {string} password - Password
   * @param {Object} userContext - User context
   * @returns {string} Cache key
   */
  generateValidationCacheKey(password, userContext) {
    const contextHash = crypto.createHash('sha256')
      .update(JSON.stringify(userContext))
      .digest('hex')
      .substring(0, 16);
    
    const passwordHash = crypto.createHash('sha256')
      .update(password)
      .digest('hex')
      .substring(0, 16);
    
    return `password_validation:${passwordHash}:${contextHash}`;
  }
  
  /**
   * Get cached validation result
   * @param {string} cacheKey - Cache key
   * @returns {Promise<Object|null>} Cached result
   */
  async getCachedValidation(cacheKey) {
    try {
      if (redis) {
        const cached = await redis.get(cacheKey);
        return cached ? JSON.parse(cached) : null;
      } else {
        const cached = this.validationCache.get(cacheKey);
        if (cached && cached.expiresAt > Date.now()) {
          return cached.result;
        } else if (cached) {
          this.validationCache.delete(cacheKey);
        }
        return null;
      }
    } catch (error) {
      logger.error('Failed to get cached validation', { error: error.message });
      return null;
    }
  }
  
  /**
   * Cache validation result
   * @param {string} cacheKey - Cache key
   * @param {Object} result - Validation result
   */
  async cacheValidationResult(cacheKey, result) {
    try {
      const ttl = 300; // 5 minutes
      
      if (redis) {
        await redis.setex(cacheKey, ttl, JSON.stringify(result));
      } else {
        this.validationCache.set(cacheKey, {
          result,
          expiresAt: Date.now() + (ttl * 1000)
        });
        
        // Clean up expired entries periodically
        if (this.validationCache.size > 1000) {
          const now = Date.now();
          for (const [key, value] of this.validationCache.entries()) {
            if (value.expiresAt < now) {
              this.validationCache.delete(key);
            }
          }
        }
      }
    } catch (error) {
      logger.error('Failed to cache validation result', { error: error.message });
    }
  }
  
  /**
   * Enhanced password history checking with AuthModel integration
   * @param {Object} user - User document (AuthModel format)
   * @param {string} newPassword - New password to check
   * @returns {Promise<Object>} History check result
   */
  async checkPasswordHistory(user, newPassword) {
    try {
      // Support both direct user and AuthModel formats
      let passwordHistory = [];
      
      if (user.authMethods?.local?.passwordHistory) {
        // AuthModel format
        passwordHistory = user.authMethods.local.passwordHistory;
      } else if (user.security?.passwordHistory) {
        // Direct user format
        passwordHistory = user.security.passwordHistory;
      }
      
      if (!passwordHistory || passwordHistory.length === 0) {
        return { isReused: false, matchedIndex: -1 };
      }
      
      // Check against configured number of previous passwords
      const historyLimit = this.config.preventReuse;
      const recentPasswords = passwordHistory.slice(0, historyLimit);
      
      for (let i = 0; i < recentPasswords.length; i++) {
        const historicalPassword = recentPasswords[i];
        const isMatch = await this.verifyPassword(newPassword, historicalPassword.hash || historicalPassword);
        
        if (isMatch) {
          return {
            isReused: true,
            matchedIndex: i,
            matchedDate: historicalPassword.changedAt,
            historyLength: passwordHistory.length
          };
        }
      }
      
      return { isReused: false, matchedIndex: -1, historyLength: passwordHistory.length };
    } catch (error) {
      logger.error('Password history check failed', { error: error.message });
      return { isReused: false, matchedIndex: -1, error: error.message };
    }
  }
  
  /**
   * Create comprehensive password validation middleware
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  createValidationMiddleware(options = {}) {
    const {
      field = 'password',
      required = true,
      minStrength = 2,
      checkHistory = false,
      customValidation = null
    } = options;
    
    return async (req, res, next) => {
      try {
        const password = req.body[field];
        
        if (!password && required) {
          return res.status(400).json({
            success: false,
            error: {
              code: 'PASSWORD_REQUIRED',
              message: 'Password is required',
              field
            }
          });
        }
        
        if (password) {
          // Build user context from request
          const userContext = {
            email: req.body.email || req.user?.email,
            firstName: req.body.firstName || req.user?.firstName,
            lastName: req.body.lastName || req.user?.lastName,
            username: req.body.username || req.user?.username,
            organizationName: req.user?.organization?.name
          };
          
          // Perform validation
          const validation = await this.validatePassword(password, userContext);
          
          if (!validation.valid) {
            return res.status(400).json({
              success: false,
              error: {
                code: 'PASSWORD_VALIDATION_FAILED',
                message: 'Password does not meet security requirements',
                field,
                validation: validation.validation
              }
            });
          }
          
          // Check minimum strength requirement
          if (validation.strength.score < minStrength) {
            return res.status(400).json({
              success: false,
              error: {
                code: 'PASSWORD_TOO_WEAK',
                message: `Password strength score ${validation.strength.score} is below minimum required ${minStrength}`,
                field,
                strength: validation.strength
              }
            });
          }
          
          // Check password history if requested
          if (checkHistory && req.user) {
            const historyCheck = await this.checkPasswordHistory(req.user, password);
            if (historyCheck.isReused) {
              return res.status(400).json({
                success: false,
                error: {
                  code: 'PASSWORD_RECENTLY_USED',
                  message: 'This password has been used recently. Please choose a different password.',
                  field,
                  historyCheck
                }
              });
            }
          }
          
          // Run custom validation if provided
          if (customValidation && typeof customValidation === 'function') {
            const customResult = await customValidation(password, req);
            if (!customResult.valid) {
              return res.status(400).json({
                success: false,
                error: {
                  code: 'CUSTOM_VALIDATION_FAILED',
                  message: customResult.message || 'Password failed custom validation',
                  field,
                  details: customResult.details
                }
              });
            }
          }
          
          // Attach validation result to request for use in route handlers
          req.passwordValidation = validation;
        }
        
        next();
      } catch (error) {
        logger.error('Password validation middleware error', { error: error.message });
        
        if (error instanceof ValidationError || error instanceof AppError) {
          return res.status(error.statusCode || 400).json({
            success: false,
            error: {
              code: error.code || 'VALIDATION_ERROR',
              message: error.message,
              field
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