// /server/shared/utils/validation/custom-validators.js

/**
 * @file Custom Validation Functions
 * @description Custom validators for complex business logic validation
 * @version 1.0.0
 */

const validator = require('validator');
const moment = require('moment-timezone');
const constants = require('../../config/constants');
const logger = require('../logger');

/**
 * Custom validator functions
 */
const customValidators = {
  /**
   * Validate email with additional business rules
   * @param {string} email - Email to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateEmail(email, options = {}) {
    const result = {
      valid: false,
      message: null,
      normalized: null
    };
    
    if (!email) {
      result.message = 'Email is required';
      return result;
    }
    
    // Basic validation
    if (!validator.isEmail(email)) {
      result.message = 'Invalid email format';
      return result;
    }
    
    // Normalize email
    const normalized = validator.normalizeEmail(email, {
      gmail_remove_dots: true,
      gmail_remove_subaddress: true,
      outlookdotcom_remove_subaddress: true,
      yahoo_remove_subaddress: true,
      icloud_remove_subaddress: true
    });
    
    // Check blacklisted domains
    const blacklistedDomains = options.blacklistedDomains || [
      'tempmail.com', 'throwaway.email', 'guerrillamail.com',
      'mailinator.com', '10minutemail.com', 'trashmail.com'
    ];
    
    const domain = email.split('@')[1].toLowerCase();
    if (blacklistedDomains.includes(domain)) {
      result.message = 'Email domain not allowed';
      return result;
    }
    
    // Check whitelisted domains (if specified)
    if (options.whitelistedDomains && options.whitelistedDomains.length > 0) {
      if (!options.whitelistedDomains.includes(domain)) {
        result.message = 'Email domain not in whitelist';
        return result;
      }
    }
    
    result.valid = true;
    result.normalized = normalized;
    return result;
  },
  
  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result with strength score
   */
  validatePasswordStrength(password, options = {}) {
    const result = {
      valid: false,
      score: 0,
      strength: 'weak',
      suggestions: []
    };
    
    if (!password) {
      result.message = 'Password is required';
      return result;
    }
    
    // Length check
    const minLength = options.minLength || constants.AUTH.PASSWORD.MIN_LENGTH;
    const maxLength = options.maxLength || constants.AUTH.PASSWORD.MAX_LENGTH;
    
    if (password.length < minLength) {
      result.suggestions.push(`Password must be at least ${minLength} characters`);
    } else if (password.length > maxLength) {
      result.message = `Password must not exceed ${maxLength} characters`;
      return result;
    } else {
      result.score += 20;
    }
    
    // Character type checks
    const checks = {
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /\d/.test(password),
      special: /[@$!%*?&#^()_+=\-{}\[\]:;"'<>,.?\/\\|`~]/.test(password)
    };
    
    if (checks.lowercase) result.score += 15;
    else result.suggestions.push('Add lowercase letters');
    
    if (checks.uppercase) result.score += 15;
    else result.suggestions.push('Add uppercase letters');
    
    if (checks.numbers) result.score += 15;
    else result.suggestions.push('Add numbers');
    
    if (checks.special) result.score += 15;
    else result.suggestions.push('Add special characters');
    
    // Length bonus
    if (password.length >= 12) result.score += 10;
    if (password.length >= 16) result.score += 10;
    
    // Pattern checks (deductions)
    if (/(.)\1{2,}/.test(password)) {
      result.score -= 10;
      result.suggestions.push('Avoid repeated characters');
    }
    
    if (/^[0-9]+$/.test(password)) {
      result.score -= 20;
      result.suggestions.push('Don\'t use only numbers');
    }
    
    if (/^[a-zA-Z]+$/.test(password)) {
      result.score -= 20;
      result.suggestions.push('Don\'t use only letters');
    }
    
    // Common patterns
    const commonPatterns = [
      /^123/, /^abc/i, /^qwerty/i, /password/i, /admin/i,
      /letmein/i, /welcome/i, /monkey/i, /dragon/i, /baseball/i
    ];
    
    for (const pattern of commonPatterns) {
      if (pattern.test(password)) {
        result.score -= 30;
        result.suggestions.push('Avoid common password patterns');
        break;
      }
    }
    
    // Determine strength
    result.score = Math.max(0, Math.min(100, result.score));
    
    if (result.score >= 80) {
      result.strength = 'strong';
      result.valid = true;
    } else if (result.score >= 60) {
      result.strength = 'moderate';
      result.valid = options.allowModerate !== false;
    } else if (result.score >= 40) {
      result.strength = 'fair';
      result.valid = false;
    } else {
      result.strength = 'weak';
      result.valid = false;
    }
    
    if (!result.valid && !result.message) {
      result.message = 'Password is too weak';
    }
    
    return result;
  },
  
  /**
   * Validate phone number with international support
   * @param {string} phone - Phone number to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validatePhoneNumber(phone, options = {}) {
    const result = {
      valid: false,
      formatted: null,
      country: null
    };
    
    if (!phone) {
      result.message = 'Phone number is required';
      return result;
    }
    
    // Remove common formatting characters
    const cleaned = phone.replace(/[\s\-\(\)\.]/g, '');
    
    // Check if it matches international format
    if (!constants.REGEX.PHONE.test(cleaned)) {
      result.message = 'Invalid phone number format';
      return result;
    }
    
    // Country-specific validation
    if (options.country) {
      const countryValidators = {
        US: /^(\+1)?[2-9]\d{2}[2-9]\d{6}$/,
        UK: /^(\+44)?[1-9]\d{9,10}$/,
        CA: /^(\+1)?[2-9]\d{2}[2-9]\d{6}$/,
        AU: /^(\+61)?4\d{8}$/,
        IN: /^(\+91)?[6-9]\d{9}$/
      };
      
      const countryValidator = countryValidators[options.country];
      if (countryValidator && !countryValidator.test(cleaned)) {
        result.message = `Invalid phone number for ${options.country}`;
        return result;
      }
      
      result.country = options.country;
    }
    
    result.valid = true;
    result.formatted = cleaned;
    
    // Format based on country
    if (result.country === 'US' || result.country === 'CA') {
      const match = cleaned.match(/^(\+1)?(\d{3})(\d{3})(\d{4})$/);
      if (match) {
        result.formatted = `+1 (${match[2]}) ${match[3]}-${match[4]}`;
      }
    }
    
    return result;
  },
  
  /**
   * Validate URL with additional checks
   * @param {string} url - URL to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateUrl(url, options = {}) {
    const result = {
      valid: false,
      normalized: null,
      protocol: null,
      domain: null
    };
    
    if (!url) {
      result.message = 'URL is required';
      return result;
    }
    
    // Basic URL validation
    const urlOptions = {
      protocols: options.protocols || ['http', 'https'],
      require_protocol: options.requireProtocol !== false,
      require_host: true,
      require_valid_protocol: true,
      allow_underscores: false,
      allow_trailing_dot: false,
      allow_protocol_relative_urls: false
    };
    
    if (!validator.isURL(url, urlOptions)) {
      result.message = 'Invalid URL format';
      return result;
    }
    
    try {
      const urlObj = new URL(url);
      
      // Extract components
      result.protocol = urlObj.protocol.replace(':', '');
      result.domain = urlObj.hostname;
      
      // Check blacklisted domains
      if (options.blacklistedDomains) {
        if (options.blacklistedDomains.includes(result.domain)) {
          result.message = 'Domain not allowed';
          return result;
        }
      }
      
      // Check whitelisted domains
      if (options.whitelistedDomains && options.whitelistedDomains.length > 0) {
        if (!options.whitelistedDomains.includes(result.domain)) {
          result.message = 'Domain not in whitelist';
          return result;
        }
      }
      
      // Normalize URL
      result.normalized = urlObj.href;
      
      // Remove trailing slash for consistency
      if (options.removeTrailingSlash && result.normalized.endsWith('/')) {
        result.normalized = result.normalized.slice(0, -1);
      }
      
      result.valid = true;
    } catch (error) {
      result.message = 'Invalid URL';
    }
    
    return result;
  },
  
  /**
   * Validate date with business rules
   * @param {string|Date} date - Date to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateDate(date, options = {}) {
    const result = {
      valid: false,
      parsed: null,
      formatted: null
    };
    
    if (!date) {
      result.message = 'Date is required';
      return result;
    }
    
    // Parse date
    const parsed = moment(date);
    if (!parsed.isValid()) {
      result.message = 'Invalid date format';
      return result;
    }
    
    // Check if date is in the past
    if (options.allowPast === false && parsed.isBefore(moment())) {
      result.message = 'Date cannot be in the past';
      return result;
    }
    
    // Check if date is in the future
    if (options.allowFuture === false && parsed.isAfter(moment())) {
      result.message = 'Date cannot be in the future';
      return result;
    }
    
    // Check minimum date
    if (options.minDate) {
      const minDate = moment(options.minDate);
      if (parsed.isBefore(minDate)) {
        result.message = `Date must be after ${minDate.format('YYYY-MM-DD')}`;
        return result;
      }
    }
    
    // Check maximum date
    if (options.maxDate) {
      const maxDate = moment(options.maxDate);
      if (parsed.isAfter(maxDate)) {
        result.message = `Date must be before ${maxDate.format('YYYY-MM-DD')}`;
        return result;
      }
    }
    
    // Check business days only
    if (options.businessDaysOnly) {
      const dayOfWeek = parsed.day();
      if (dayOfWeek === 0 || dayOfWeek === 6) {
        result.message = 'Date must be a business day (Monday-Friday)';
        return result;
      }
    }
    
    // Check working hours
    if (options.workingHoursOnly) {
      const hour = parsed.hour();
      const startHour = options.workingHoursStart || 9;
      const endHour = options.workingHoursEnd || 17;
      
      if (hour < startHour || hour >= endHour) {
        result.message = `Date must be within working hours (${startHour}:00-${endHour}:00)`;
        return result;
      }
    }
    
    result.valid = true;
    result.parsed = parsed.toDate();
    result.formatted = parsed.format(options.format || 'YYYY-MM-DD');
    
    if (options.timezone) {
      result.timezone = options.timezone;
      result.formatted = parsed.tz(options.timezone).format(options.format || 'YYYY-MM-DD HH:mm:ss z');
    }
    
    return result;
  },
  
  /**
   * Validate file upload
   * @param {Object} file - File object to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateFile(file, options = {}) {
    const result = {
      valid: false,
      fileType: null,
      extension: null
    };
    
    if (!file) {
      result.message = 'File is required';
      return result;
    }
    
    // Check file size
    const maxSize = options.maxSize || constants.FILE_UPLOAD.MAX_SIZE.DEFAULT;
    if (file.size > maxSize) {
      result.message = `File size exceeds maximum allowed size of ${maxSize / 1048576}MB`;
      return result;
    }
    
    // Extract extension
    const filename = file.originalname || file.name || '';
    const lastDot = filename.lastIndexOf('.');
    const extension = lastDot !== -1 ? filename.substring(lastDot).toLowerCase() : '';
    
    // Check allowed extensions
    if (options.allowedExtensions) {
      if (!options.allowedExtensions.includes(extension)) {
        result.message = `File type ${extension} not allowed`;
        return result;
      }
    }
    
    // Check MIME type
    if (options.allowedMimeTypes) {
      if (!options.allowedMimeTypes.includes(file.mimetype)) {
        result.message = `File type ${file.mimetype} not allowed`;
        return result;
      }
    }
    
    // Validate image dimensions
    if (options.imageValidation && file.mimetype.startsWith('image/')) {
      // This would require additional image processing library
      // Placeholder for image dimension validation
    }
    
    result.valid = true;
    result.fileType = file.mimetype;
    result.extension = extension;
    
    return result;
  },
  
  /**
   * Validate credit card number
   * @param {string} cardNumber - Card number to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateCreditCard(cardNumber, options = {}) {
    const result = {
      valid: false,
      type: null,
      masked: null
    };
    
    if (!cardNumber) {
      result.message = 'Card number is required';
      return result;
    }
    
    // Remove spaces and dashes
    const cleaned = cardNumber.replace(/[\s-]/g, '');
    
    // Check if it's a valid credit card number
    if (!validator.isCreditCard(cleaned)) {
      result.message = 'Invalid credit card number';
      return result;
    }
    
    // Detect card type
    const cardPatterns = {
      visa: /^4[0-9]{12}(?:[0-9]{3})?$/,
      mastercard: /^5[1-5][0-9]{14}$/,
      amex: /^3[47][0-9]{13}$/,
      discover: /^6(?:011|5[0-9]{2})[0-9]{12}$/,
      diners: /^3(?:0[0-5]|[68][0-9])[0-9]{11}$/,
      jcb: /^(?:2131|1800|35\d{3})\d{11}$/
    };
    
    for (const [type, pattern] of Object.entries(cardPatterns)) {
      if (pattern.test(cleaned)) {
        result.type = type;
        break;
      }
    }
    
    // Check allowed card types
    if (options.allowedTypes && result.type) {
      if (!options.allowedTypes.includes(result.type)) {
        result.message = `Card type ${result.type} not accepted`;
        return result;
      }
    }
    
    // Mask card number
    result.masked = cleaned.slice(0, 6) + '*'.repeat(cleaned.length - 10) + cleaned.slice(-4);
    result.valid = true;
    
    return result;
  },
  
  /**
   * Validate organization slug
   * @param {string} slug - Slug to validate
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validateSlug(slug, options = {}) {
    const result = {
      valid: false,
      normalized: null
    };
    
    if (!slug) {
      result.message = 'Slug is required';
      return result;
    }
    
    // Check format
    if (!constants.REGEX.SLUG.test(slug)) {
      result.message = 'Slug must contain only lowercase letters, numbers, and hyphens';
      return result;
    }
    
    // Check length
    const minLength = options.minLength || 3;
    const maxLength = options.maxLength || 50;
    
    if (slug.length < minLength) {
      result.message = `Slug must be at least ${minLength} characters`;
      return result;
    }
    
    if (slug.length > maxLength) {
      result.message = `Slug must not exceed ${maxLength} characters`;
      return result;
    }
    
    // Check reserved slugs
    const reservedSlugs = options.reservedSlugs || [
      'admin', 'api', 'app', 'www', 'mail', 'ftp', 'blog',
      'help', 'support', 'docs', 'status', 'about', 'contact',
      'privacy', 'terms', 'login', 'register', 'dashboard'
    ];
    
    if (reservedSlugs.includes(slug)) {
      result.message = 'This slug is reserved';
      return result;
    }
    
    // Check for consecutive hyphens
    if (/--/.test(slug)) {
      result.message = 'Slug cannot contain consecutive hyphens';
      return result;
    }
    
    // Check start and end
    if (slug.startsWith('-') || slug.endsWith('-')) {
      result.message = 'Slug cannot start or end with a hyphen';
      return result;
    }
    
    result.valid = true;
    result.normalized = slug.toLowerCase();
    
    return result;
  }
};

/**
 * Express middleware validator
 */
const createValidator = (validationRules) => {
  return async (req, res, next) => {
    const errors = [];
    
    for (const [field, rules] of Object.entries(validationRules)) {
      const value = req.body[field] || req.query[field] || req.params[field];
      
      for (const rule of rules) {
        const result = await rule(value, req);
        
        if (!result.valid) {
          errors.push({
            field,
            message: result.message,
            value
          });
          break;
        }
      }
    }
    
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        error: {
          message: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: errors
        }
      });
    }
    
    next();
  };
};

module.exports = {
  ...customValidators,
  createValidator
};