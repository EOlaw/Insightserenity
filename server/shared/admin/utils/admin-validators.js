/**
 * @file Admin Validators Utilities
 * @description Validation utilities for administrative operations with comprehensive rule sets
 * @version 1.0.0
 */

const validator = require('validator');
const moment = require('moment');
const AdminLogger = require('./admin-logger');
const AdminPermissions = require('./admin-permissions');
const config = require('../../../config/config');

/**
 * Admin Validators Class
 * @class AdminValidators
 */
class AdminValidators {
  /**
   * Initialize validator configurations
   */
  static initialize() {
    // Validation rules
    this.rules = {
      // String validations
      string: {
        minLength: 1,
        maxLength: 1000,
        allowedCharacters: /^[\w\s\-.,!?@#$%^&*()+=\[\]{}:;"'<>\/\\|`~]+$/,
        noScriptTags: /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
        noSqlInjection: /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/gi
      },

      // Numeric validations
      number: {
        minValue: -999999999,
        maxValue: 999999999,
        precision: 2
      },

      // Date validations
      date: {
        minDate: '1900-01-01',
        maxDate: '2100-12-31',
        formats: ['YYYY-MM-DD', 'YYYY-MM-DD HH:mm:ss', 'ISO8601']
      },

      // Email validations
      email: {
        maxLength: 254,
        domainWhitelist: [],
        domainBlacklist: ['tempmail.com', 'throwaway.email', 'guerrillamail.com']
      },

      // Password validations
      password: {
        minLength: config.auth.passwordPolicy.minLength || 12,
        maxLength: config.auth.passwordPolicy.maxLength || 128,
        requireUppercase: config.auth.passwordPolicy.requireUppercase,
        requireLowercase: config.auth.passwordPolicy.requireLowercase,
        requireNumbers: config.auth.passwordPolicy.requireNumbers,
        requireSpecialChars: config.auth.passwordPolicy.requireSpecialChars,
        commonPasswords: ['password', '12345678', 'qwerty', 'admin', 'letmein']
      },

      // ID validations
      id: {
        mongoId: /^[0-9a-fA-F]{24}$/,
        uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
        customId: /^[a-zA-Z0-9_-]{1,64}$/
      },

      // File validations
      file: {
        maxSize: 10 * 1024 * 1024, // 10MB
        allowedMimeTypes: [
          'image/jpeg',
          'image/png',
          'image/gif',
          'image/webp',
          'application/pdf',
          'application/zip',
          'text/csv',
          'application/vnd.ms-excel',
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        ],
        dangerousExtensions: ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.app', '.dmg'],
        maxFilenameLength: 255
      },

      // URL validations
      url: {
        protocols: ['http', 'https'],
        maxLength: 2048,
        requireTLD: true
      },

      // Phone validations
      phone: {
        formats: [
          /^\+\d{1,3}\d{4,14}$/, // International format
          /^\(\d{3}\)\s?\d{3}-?\d{4}$/, // US format
          /^\d{3}-\d{3}-\d{4}$/ // Alternative US format
        ]
      }
    };

    // Business rule validators
    this.businessRules = {
      user: {
        minAge: 18,
        maxAge: 120,
        reservedUsernames: ['admin', 'root', 'system', 'support', 'test'],
        maxOrganizations: 10,
        maxRoles: 5
      },

      organization: {
        minNameLength: 3,
        maxNameLength: 100,
        maxUsers: 1000,
        maxProjects: 500,
        subdomainPattern: /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/
      },

      billing: {
        minAmount: 0.01,
        maxAmount: 999999.99,
        supportedCurrencies: ['USD', 'EUR', 'GBP', 'CAD', 'AUD'],
        maxRefundDays: 180
      },

      system: {
        maxBatchSize: 1000,
        maxExportRecords: 50000,
        maintenanceWindowHours: [0, 1, 2, 3, 4, 5], // 12 AM - 6 AM
        maxConcurrentJobs: 10
      }
    };

    // Custom validators
    this.customValidators = new Map();
    this.registerDefaultValidators();
  }

  /**
   * Register default custom validators
   */
  static registerDefaultValidators() {
    // Admin session validator
    this.registerValidator('adminSession', (value, context) => {
      if (!value.sessionId || !value.userId) {
        return { valid: false, error: 'Session ID and User ID are required' };
      }

      if (!this.validateId(value.sessionId, 'custom')) {
        return { valid: false, error: 'Invalid session ID format' };
      }

      if (!this.validateId(value.userId, 'mongo')) {
        return { valid: false, error: 'Invalid user ID format' };
      }

      return { valid: true };
    });

    // Permission validator
    this.registerValidator('permission', (value) => {
      const validation = AdminPermissions.validatePermissionName(value);
      return validation.valid ? { valid: true } : { valid: false, error: validation.errors[0] };
    });

    // Cron expression validator
    this.registerValidator('cronExpression', (value) => {
      const cronPattern = /^(\*|([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])|\*\/([0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])) (\*|([0-9]|1[0-9]|2[0-3])|\*\/([0-9]|1[0-9]|2[0-3])) (\*|([1-9]|1[0-9]|2[0-9]|3[0-1])|\*\/([1-9]|1[0-9]|2[0-9]|3[0-1])) (\*|([1-9]|1[0-2])|\*\/([1-9]|1[0-2])) (\*|([0-6])|\*\/([0-6]))$/;
      
      if (!cronPattern.test(value)) {
        return { valid: false, error: 'Invalid cron expression format' };
      }

      return { valid: true };
    });

    // IP address validator
    this.registerValidator('ipAddress', (value) => {
      if (!validator.isIP(value)) {
        return { valid: false, error: 'Invalid IP address format' };
      }

      // Check for reserved IPs
      const reserved = ['0.0.0.0', '255.255.255.255'];
      if (reserved.includes(value)) {
        return { valid: false, error: 'Reserved IP address not allowed' };
      }

      return { valid: true };
    });

    // Organization subdomain validator
    this.registerValidator('subdomain', (value) => {
      if (!this.businessRules.organization.subdomainPattern.test(value)) {
        return { valid: false, error: 'Invalid subdomain format' };
      }

      const reserved = ['www', 'admin', 'api', 'app', 'mail', 'ftp', 'blog', 'shop'];
      if (reserved.includes(value.toLowerCase())) {
        return { valid: false, error: 'Reserved subdomain not allowed' };
      }

      return { valid: true };
    });
  }

  /**
   * Validate input against schema
   * @param {Object} data - Data to validate
   * @param {Object} schema - Validation schema
   * @returns {Object} Validation result
   */
  static validate(data, schema) {
    const errors = [];
    const validated = {};

    for (const [field, rules] of Object.entries(schema)) {
      const value = data[field];
      const fieldValidation = this.validateField(field, value, rules);

      if (!fieldValidation.valid) {
        errors.push(...fieldValidation.errors);
      } else {
        validated[field] = fieldValidation.value;
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      data: validated
    };
  }

  /**
   * Validate single field
   * @param {string} field - Field name
   * @param {any} value - Field value
   * @param {Object} rules - Validation rules
   * @returns {Object} Validation result
   */
  static validateField(field, value, rules) {
    const errors = [];
    let processedValue = value;

    // Check required
    if (rules.required && (value === undefined || value === null || value === '')) {
      errors.push({ field, message: `${field} is required` });
      return { valid: false, errors };
    }

    // Skip validation if not required and empty
    if (!rules.required && (value === undefined || value === null || value === '')) {
      return { valid: true, value: value };
    }

    // Apply sanitization if specified
    if (rules.sanitize) {
      processedValue = this.sanitizeValue(processedValue, rules.sanitize);
    }

    // Type validation
    if (rules.type) {
      const typeValidation = this.validateType(processedValue, rules.type);
      if (!typeValidation.valid) {
        errors.push({ field, message: typeValidation.error });
      }
    }

    // String validations
    if (rules.type === 'string') {
      const stringValidation = this.validateString(processedValue, rules);
      if (!stringValidation.valid) {
        errors.push({ field, message: stringValidation.error });
      }
    }

    // Number validations
    if (rules.type === 'number') {
      const numberValidation = this.validateNumber(processedValue, rules);
      if (!numberValidation.valid) {
        errors.push({ field, message: numberValidation.error });
      }
    }

    // Date validations
    if (rules.type === 'date') {
      const dateValidation = this.validateDate(processedValue, rules);
      if (!dateValidation.valid) {
        errors.push({ field, message: dateValidation.error });
      }
    }

    // Email validation
    if (rules.type === 'email') {
      const emailValidation = this.validateEmail(processedValue);
      if (!emailValidation.valid) {
        errors.push({ field, message: emailValidation.error });
      }
    }

    // URL validation
    if (rules.type === 'url') {
      const urlValidation = this.validateURL(processedValue);
      if (!urlValidation.valid) {
        errors.push({ field, message: urlValidation.error });
      }
    }

    // Array validation
    if (rules.type === 'array') {
      const arrayValidation = this.validateArray(processedValue, rules);
      if (!arrayValidation.valid) {
        errors.push({ field, message: arrayValidation.error });
      }
    }

    // Object validation
    if (rules.type === 'object' && rules.schema) {
      const objectValidation = this.validate(processedValue, rules.schema);
      if (!objectValidation.valid) {
        objectValidation.errors.forEach(error => {
          errors.push({ field: `${field}.${error.field}`, message: error.message });
        });
      }
    }

    // Custom validation
    if (rules.validate) {
      const customValidation = rules.validate(processedValue, data);
      if (!customValidation.valid) {
        errors.push({ field, message: customValidation.error });
      }
    }

    // Enum validation
    if (rules.enum && !rules.enum.includes(processedValue)) {
      errors.push({ field, message: `${field} must be one of: ${rules.enum.join(', ')}` });
    }

    // Pattern validation
    if (rules.pattern && !rules.pattern.test(processedValue)) {
      errors.push({ field, message: `${field} does not match required pattern` });
    }

    return {
      valid: errors.length === 0,
      errors,
      value: processedValue
    };
  }

  /**
   * Validate data type
   * @param {any} value - Value to validate
   * @param {string} expectedType - Expected type
   * @returns {Object} Validation result
   */
  static validateType(value, expectedType) {
    const actualType = Array.isArray(value) ? 'array' : typeof value;

    if (actualType !== expectedType) {
      return { valid: false, error: `Expected ${expectedType} but got ${actualType}` };
    }

    return { valid: true };
  }

  /**
   * Validate string
   * @param {string} value - String value
   * @param {Object} rules - Validation rules
   * @returns {Object} Validation result
   */
  static validateString(value, rules) {
    // Length validation
    if (rules.minLength && value.length < rules.minLength) {
      return { valid: false, error: `Minimum length is ${rules.minLength}` };
    }

    if (rules.maxLength && value.length > rules.maxLength) {
      return { valid: false, error: `Maximum length is ${rules.maxLength}` };
    }

    // Script tag detection
    if (this.rules.string.noScriptTags.test(value)) {
      return { valid: false, error: 'Script tags are not allowed' };
    }

    // SQL injection detection
    if (rules.noSqlInjection !== false && this.rules.string.noSqlInjection.test(value)) {
      return { valid: false, error: 'Potential SQL injection detected' };
    }

    return { valid: true };
  }

  /**
   * Validate number
   * @param {number} value - Number value
   * @param {Object} rules - Validation rules
   * @returns {Object} Validation result
   */
  static validateNumber(value, rules) {
    const num = Number(value);

    if (isNaN(num)) {
      return { valid: false, error: 'Invalid number' };
    }

    if (rules.min !== undefined && num < rules.min) {
      return { valid: false, error: `Minimum value is ${rules.min}` };
    }

    if (rules.max !== undefined && num > rules.max) {
      return { valid: false, error: `Maximum value is ${rules.max}` };
    }

    if (rules.integer && !Number.isInteger(num)) {
      return { valid: false, error: 'Must be an integer' };
    }

    if (rules.positive && num <= 0) {
      return { valid: false, error: 'Must be a positive number' };
    }

    return { valid: true };
  }

  /**
   * Validate date
   * @param {string|Date} value - Date value
   * @param {Object} rules - Validation rules
   * @returns {Object} Validation result
   */
  static validateDate(value, rules) {
    const date = moment(value);

    if (!date.isValid()) {
      return { valid: false, error: 'Invalid date format' };
    }

    if (rules.min && date.isBefore(moment(rules.min))) {
      return { valid: false, error: `Date must be after ${rules.min}` };
    }

    if (rules.max && date.isAfter(moment(rules.max))) {
      return { valid: false, error: `Date must be before ${rules.max}` };
    }

    if (rules.future && !date.isAfter(moment())) {
      return { valid: false, error: 'Date must be in the future' };
    }

    if (rules.past && !date.isBefore(moment())) {
      return { valid: false, error: 'Date must be in the past' };
    }

    return { valid: true };
  }

  /**
   * Validate email
   * @param {string} email - Email address
   * @returns {Object} Validation result
   */
  static validateEmail(email) {
    if (!validator.isEmail(email)) {
      return { valid: false, error: 'Invalid email format' };
    }

    const domain = email.split('@')[1];

    // Check blacklisted domains
    if (this.rules.email.domainBlacklist.includes(domain)) {
      return { valid: false, error: 'Email domain is not allowed' };
    }

    // Check whitelisted domains if configured
    if (this.rules.email.domainWhitelist.length > 0 && !this.rules.email.domainWhitelist.includes(domain)) {
      return { valid: false, error: 'Email domain is not in whitelist' };
    }

    return { valid: true };
  }

  /**
   * Validate URL
   * @param {string} url - URL to validate
   * @returns {Object} Validation result
   */
  static validateURL(url) {
    if (!validator.isURL(url, {
      protocols: this.rules.url.protocols,
      require_protocol: true,
      require_valid_protocol: true,
      require_tld: this.rules.url.requireTLD
    })) {
      return { valid: false, error: 'Invalid URL format' };
    }

    if (url.length > this.rules.url.maxLength) {
      return { valid: false, error: `URL exceeds maximum length of ${this.rules.url.maxLength}` };
    }

    return { valid: true };
  }

  /**
   * Validate array
   * @param {Array} value - Array value
   * @param {Object} rules - Validation rules
   * @returns {Object} Validation result
   */
  static validateArray(value, rules) {
    if (!Array.isArray(value)) {
      return { valid: false, error: 'Value must be an array' };
    }

    if (rules.minItems && value.length < rules.minItems) {
      return { valid: false, error: `Array must have at least ${rules.minItems} items` };
    }

    if (rules.maxItems && value.length > rules.maxItems) {
      return { valid: false, error: `Array must have at most ${rules.maxItems} items` };
    }

    if (rules.unique) {
      const uniqueValues = new Set(value);
      if (uniqueValues.size !== value.length) {
        return { valid: false, error: 'Array must contain unique values' };
      }
    }

    return { valid: true };
  }

  /**
   * Validate ID
   * @param {string} id - ID to validate
   * @param {string} type - ID type (mongo, uuid, custom)
   * @returns {boolean} Is valid
   */
  static validateId(id, type = 'mongo') {
    switch (type) {
      case 'mongo':
        return this.rules.id.mongoId.test(id);
      case 'uuid':
        return this.rules.id.uuid.test(id);
      case 'custom':
        return this.rules.id.customId.test(id);
      default:
        return false;
    }
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} Validation result
   */
  static validatePassword(password) {
    const errors = [];
    const rules = this.rules.password;

    if (password.length < rules.minLength) {
      errors.push(`Password must be at least ${rules.minLength} characters`);
    }

    if (password.length > rules.maxLength) {
      errors.push(`Password must be at most ${rules.maxLength} characters`);
    }

    if (rules.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (rules.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (rules.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (rules.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    // Check common passwords
    if (rules.commonPasswords.some(common => password.toLowerCase().includes(common))) {
      errors.push('Password is too common');
    }

    return {
      valid: errors.length === 0,
      errors,
      strength: this.calculatePasswordStrength(password)
    };
  }

  /**
   * Calculate password strength
   * @param {string} password - Password
   * @returns {Object} Strength assessment
   */
  static calculatePasswordStrength(password) {
    let strength = 0;
    const checks = {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /\d/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
      noRepeating: !/(.)\1{2,}/.test(password),
      noSequential: !/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password)
    };

    Object.values(checks).forEach(passed => {
      if (passed) strength++;
    });

    const percentage = (strength / Object.keys(checks).length) * 100;

    return {
      score: strength,
      percentage,
      level: percentage >= 80 ? 'strong' : percentage >= 60 ? 'medium' : 'weak',
      checks
    };
  }

  /**
   * Validate file upload
   * @param {Object} file - File object
   * @returns {Object} Validation result
   */
  static validateFileUpload(file) {
    const errors = [];

    // Check file size
    if (file.size > this.rules.file.maxSize) {
      errors.push(`File size exceeds maximum of ${this.rules.file.maxSize / 1024 / 1024}MB`);
    }

    // Check MIME type
    if (!this.rules.file.allowedMimeTypes.includes(file.mimetype)) {
      errors.push('File type not allowed');
    }

    // Check filename
    if (file.name.length > this.rules.file.maxFilenameLength) {
      errors.push(`Filename exceeds maximum length of ${this.rules.file.maxFilenameLength}`);
    }

    // Check dangerous extensions
    const extension = file.name.substring(file.name.lastIndexOf('.'));
    if (this.rules.file.dangerousExtensions.includes(extension.toLowerCase())) {
      errors.push('File extension not allowed for security reasons');
    }

    // Validate filename characters
    if (!/^[\w\-. ]+$/.test(file.name)) {
      errors.push('Filename contains invalid characters');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Validate phone number
   * @param {string} phone - Phone number
   * @returns {Object} Validation result
   */
  static validatePhone(phone) {
    const isValid = this.rules.phone.formats.some(pattern => pattern.test(phone));

    return {
      valid: isValid,
      error: isValid ? null : 'Invalid phone number format'
    };
  }

  /**
   * Sanitize value
   * @param {any} value - Value to sanitize
   * @param {Object} options - Sanitization options
   * @returns {any} Sanitized value
   */
  static sanitizeValue(value, options) {
    if (typeof value !== 'string') return value;

    let sanitized = value;

    // Trim whitespace
    if (options.trim !== false) {
      sanitized = sanitized.trim();
    }

    // Convert case
    if (options.lowercase) {
      sanitized = sanitized.toLowerCase();
    } else if (options.uppercase) {
      sanitized = sanitized.toUpperCase();
    }

    // Remove HTML tags
    if (options.stripTags) {
      sanitized = validator.stripLow(validator.escape(sanitized));
    }

    // Normalize whitespace
    if (options.normalizeWhitespace) {
      sanitized = sanitized.replace(/\s+/g, ' ');
    }

    return sanitized;
  }

  /**
   * Register custom validator
   * @param {string} name - Validator name
   * @param {Function} validator - Validator function
   */
  static registerValidator(name, validator) {
    this.customValidators.set(name, validator);
  }

  /**
   * Get custom validator
   * @param {string} name - Validator name
   * @returns {Function} Validator function
   */
  static getValidator(name) {
    return this.customValidators.get(name);
  }

  /**
   * Validate business rules
   * @param {string} entity - Entity type
   * @param {Object} data - Data to validate
   * @returns {Object} Validation result
   */
  static validateBusinessRules(entity, data) {
    const rules = this.businessRules[entity];
    if (!rules) {
      return { valid: true };
    }

    const errors = [];

    switch (entity) {
      case 'user':
        if (data.age && (data.age < rules.minAge || data.age > rules.maxAge)) {
          errors.push(`Age must be between ${rules.minAge} and ${rules.maxAge}`);
        }
        if (data.username && rules.reservedUsernames.includes(data.username.toLowerCase())) {
          errors.push('Username is reserved');
        }
        break;

      case 'organization':
        if (data.name && (data.name.length < rules.minNameLength || data.name.length > rules.maxNameLength)) {
          errors.push(`Organization name must be between ${rules.minNameLength} and ${rules.maxNameLength} characters`);
        }
        if (data.subdomain && !rules.subdomainPattern.test(data.subdomain)) {
          errors.push('Invalid subdomain format');
        }
        break;

      case 'billing':
        if (data.amount && (data.amount < rules.minAmount || data.amount > rules.maxAmount)) {
          errors.push(`Amount must be between ${rules.minAmount} and ${rules.maxAmount}`);
        }
        if (data.currency && !rules.supportedCurrencies.includes(data.currency)) {
          errors.push(`Currency must be one of: ${rules.supportedCurrencies.join(', ')}`);
        }
        break;
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Create validation schema
   * @param {Object} definition - Schema definition
   * @returns {Object} Validation schema
   */
  static createSchema(definition) {
    const schema = {};

    Object.entries(definition).forEach(([field, config]) => {
      if (typeof config === 'string') {
        // Simple type definition
        schema[field] = { type: config, required: true };
      } else {
        // Full configuration
        schema[field] = config;
      }
    });

    return schema;
  }

  /**
   * Validate pagination parameters
   * @param {Object} params - Pagination parameters
   * @returns {Object} Validation result
   */
  static validatePagination(params) {
    const defaults = {
      page: 1,
      limit: 20,
      maxLimit: 100
    };

    const validated = {
      page: parseInt(params.page) || defaults.page,
      limit: parseInt(params.limit) || defaults.limit
    };

    const errors = [];

    if (validated.page < 1) {
      errors.push('Page must be greater than 0');
    }

    if (validated.limit < 1) {
      errors.push('Limit must be greater than 0');
    }

    if (validated.limit > defaults.maxLimit) {
      errors.push(`Limit cannot exceed ${defaults.maxLimit}`);
    }

    return {
      valid: errors.length === 0,
      errors,
      data: validated
    };
  }

  /**
   * Validate sort parameters
   * @param {string} sort - Sort parameter
   * @param {Array} allowedFields - Allowed sort fields
   * @returns {Object} Validation result
   */
  static validateSort(sort, allowedFields) {
    if (!sort) {
      return { valid: true, data: {} };
    }

    const sortObj = {};
    const errors = [];
    const parts = sort.split(',');

    parts.forEach(part => {
      const field = part.startsWith('-') ? part.substring(1) : part;
      const order = part.startsWith('-') ? -1 : 1;

      if (!allowedFields.includes(field)) {
        errors.push(`Cannot sort by field: ${field}`);
      } else {
        sortObj[field] = order;
      }
    });

    return {
      valid: errors.length === 0,
      errors,
      data: sortObj
    };
  }

  /**
   * Validate filter parameters
   * @param {Object} filters - Filter parameters
   * @param {Object} allowedFilters - Allowed filters configuration
   * @returns {Object} Validation result
   */
  static validateFilters(filters, allowedFilters) {
    const validated = {};
    const errors = [];

    Object.entries(filters).forEach(([key, value]) => {
      if (!allowedFilters[key]) {
        errors.push(`Filter not allowed: ${key}`);
        return;
      }

      const filterConfig = allowedFilters[key];
      const validation = this.validateField(key, value, filterConfig);

      if (!validation.valid) {
        errors.push(...validation.errors.map(e => e.message));
      } else {
        validated[key] = validation.value;
      }
    });

    return {
      valid: errors.length === 0,
      errors,
      data: validated
    };
  }

  /**
   * Log validation error
   * @param {string} operation - Operation name
   * @param {Object} errors - Validation errors
   * @param {Object} context - Context
   */
  static logValidationError(operation, errors, context = {}) {
    AdminLogger.warning('Validation failed', {
      operation,
      errors,
      context,
      category: 'validation'
    });
  }
}

// Initialize on module load
AdminValidators.initialize();

module.exports = AdminValidators;