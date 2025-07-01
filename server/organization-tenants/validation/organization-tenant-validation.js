/**
 * @file Organization Tenant Validation
 * @description Request validation schemas for organization tenant management
 * @version 1.0.0
 */

const { body, param, query, validationResult } = require('express-validator');
const { ValidationError, ErrorFactory } = require('../../shared/utils/app-error');
const { TENANT_CONSTANTS } = require('../constants/tenant-constants');

/**
 * Validation middleware to check validation results
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const formattedErrors = errors.array().map(error => ({
      field: error.param,
      message: error.msg,
      value: error.value
    }));
    
    throw new ValidationError('Validation failed', formattedErrors);
  }
  
  next();
};

/**
 * Validate tenant creation
 */
const validateTenantCreate = [
  // Basic Information
  body('name')
    .trim()
    .notEmpty().withMessage('Organization name is required')
    .isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-&.,]+$/).withMessage('Name contains invalid characters'),
    
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters'),
    
  body('tenantCode')
    .optional()
    .trim()
    .toUpperCase()
    .matches(/^[A-Z0-9]{3,10}$/).withMessage('Tenant code must be 3-10 uppercase alphanumeric characters'),
    
  // Contact Information
  body('contactEmail')
    .trim()
    .notEmpty().withMessage('Contact email is required')
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail(),
    
  body('contactPhone')
    .optional()
    .trim()
    .matches(/^\+?[1-9]\d{1,14}$/).withMessage('Invalid phone number format'),
    
  body('website')
    .optional()
    .trim()
    .isURL({ protocols: ['http', 'https'] }).withMessage('Invalid website URL'),
    
  // Business Information
  body('businessType')
    .optional()
    .isIn(TENANT_CONSTANTS.BUSINESS_TYPES).withMessage('Invalid business type'),
    
  body('industry')
    .optional()
    .isIn(TENANT_CONSTANTS.INDUSTRIES).withMessage('Invalid industry'),
    
  body('size')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.COMPANY_SIZES)).withMessage('Invalid company size'),
    
  // Subscription
  body('subscription.plan')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.SUBSCRIPTION_PLANS)).withMessage('Invalid subscription plan'),
    
  // Database Strategy
  body('database.strategy')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.DATABASE_STRATEGIES)).withMessage('Invalid database strategy'),
    
  // Compliance
  body('compliance.dataLocation')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.DATA_LOCATIONS)).withMessage('Invalid data location'),
    
  handleValidationErrors
];

/**
 * Validate tenant update
 */
const validateTenantUpdate = [
  param('id')
    .isMongoId().withMessage('Invalid tenant ID'),
    
  // Basic Information (all optional for updates)
  body('name')
    .optional()
    .trim()
    .isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-&.,]+$/).withMessage('Name contains invalid characters'),
    
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters'),
    
  // Contact Information
  body('contactEmail')
    .optional()
    .trim()
    .isEmail().withMessage('Invalid email format')
    .normalizeEmail(),
    
  body('contactPhone')
    .optional()
    .trim()
    .matches(/^\+?[1-9]\d{1,14}$/).withMessage('Invalid phone number format'),
    
  body('website')
    .optional()
    .trim()
    .isURL({ protocols: ['http', 'https'] }).withMessage('Invalid website URL'),
    
  // Business Information
  body('businessType')
    .optional()
    .isIn(TENANT_CONSTANTS.BUSINESS_TYPES).withMessage('Invalid business type'),
    
  body('industry')
    .optional()
    .isIn(TENANT_CONSTANTS.INDUSTRIES).withMessage('Invalid industry'),
    
  body('size')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.COMPANY_SIZES)).withMessage('Invalid company size'),
    
  // Status (restricted field)
  body('status')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.TENANT_STATUS)).withMessage('Invalid status')
    .custom((value, { req }) => {
      // Only platform admins can change status
      if (!req.user.roles.includes('admin') && !req.user.roles.includes('super_admin')) {
        throw new ValidationError('Only platform administrators can change tenant status');
      }
      return true;
    }),
    
  // Prevent updating immutable fields
  body(['tenantId', 'tenantCode', 'owner', 'createdAt', 'createdBy'])
    .custom((value) => {
      if (value !== undefined) {
        throw new ValidationError('This field cannot be updated');
      }
      return true;
    }),
    
  handleValidationErrors
];

/**
 * Validate subscription update
 */
const validateSubscriptionUpdate = [
  param('id')
    .isMongoId().withMessage('Invalid tenant ID'),
    
  body('plan')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.SUBSCRIPTION_PLANS)).withMessage('Invalid subscription plan'),
    
  body('status')
    .optional()
    .isIn(Object.values(TENANT_CONSTANTS.SUBSCRIPTION_STATUS)).withMessage('Invalid subscription status'),
    
  body('autoRenew')
    .optional()
    .isBoolean().withMessage('Auto-renew must be a boolean value'),
    
  body('endDate')
    .optional()
    .isISO8601().withMessage('Invalid date format')
    .custom((value) => {
      if (new Date(value) <= new Date()) {
        throw new ValidationError('End date must be in the future');
      }
      return true;
    }),
    
  body('customTerms')
    .optional()
    .isObject().withMessage('Custom terms must be an object'),
    
  handleValidationErrors
];

/**
 * Validate domain addition
 */
const validateDomainAdd = [
  param('id')
    .isMongoId().withMessage('Invalid tenant ID'),
    
  body('domain')
    .trim()
    .notEmpty().withMessage('Domain is required')
    .toLowerCase()
    .matches(/^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/).withMessage('Invalid domain format')
    .custom((value) => {
      // Check for reserved domains
      const reservedDomains = ['localhost', 'example.com', 'test.com'];
      if (reservedDomains.includes(value)) {
        throw new ValidationError('This domain is reserved and cannot be used');
      }
      return true;
    }),
    
  handleValidationErrors
];

/**
 * Validate security settings
 */
const validateSecuritySettings = [
  body('enforceIPWhitelist')
    .optional()
    .isBoolean().withMessage('Enforce IP whitelist must be a boolean'),
    
  body('ipWhitelist')
    .optional()
    .isArray().withMessage('IP whitelist must be an array')
    .custom((value) => {
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      const invalidIPs = value.filter(ip => !ipRegex.test(ip));
      if (invalidIPs.length > 0) {
        throw new ValidationError(`Invalid IP addresses: ${invalidIPs.join(', ')}`);
      }
      return true;
    }),
    
  body('enforce2FA')
    .optional()
    .isBoolean().withMessage('Enforce 2FA must be a boolean'),
    
  body('passwordPolicy.minLength')
    .optional()
    .isInt({ min: 6, max: 32 }).withMessage('Password minimum length must be between 6 and 32'),
    
  body('passwordPolicy.requireUppercase')
    .optional()
    .isBoolean().withMessage('Require uppercase must be a boolean'),
    
  body('passwordPolicy.requireLowercase')
    .optional()
    .isBoolean().withMessage('Require lowercase must be a boolean'),
    
  body('passwordPolicy.requireNumbers')
    .optional()
    .isBoolean().withMessage('Require numbers must be a boolean'),
    
  body('passwordPolicy.requireSpecialChars')
    .optional()
    .isBoolean().withMessage('Require special chars must be a boolean'),
    
  body('passwordPolicy.expiryDays')
    .optional()
    .isInt({ min: 0, max: 365 }).withMessage('Password expiry days must be between 0 and 365'),
    
  body('sessionTimeout')
    .optional()
    .isInt({ min: 300, max: 86400 }).withMessage('Session timeout must be between 300 and 86400 seconds'),
    
  body('maxLoginAttempts')
    .optional()
    .isInt({ min: 3, max: 10 }).withMessage('Max login attempts must be between 3 and 10'),
    
  handleValidationErrors
];

/**
 * Validate resource limits
 */
const validateResourceLimits = [
  param('id')
    .isMongoId().withMessage('Invalid tenant ID'),
    
  body('users.max')
    .optional()
    .isInt({ min: -1 }).withMessage('User limit must be -1 (unlimited) or a positive number'),
    
  body('storage.maxGB')
    .optional()
    .isInt({ min: -1 }).withMessage('Storage limit must be -1 (unlimited) or a positive number'),
    
  body('apiCalls.maxPerMonth')
    .optional()
    .isInt({ min: -1 }).withMessage('API call limit must be -1 (unlimited) or a positive number'),
    
  body('projects.max')
    .optional()
    .isInt({ min: -1 }).withMessage('Project limit must be -1 (unlimited) or a positive number'),
    
  body('customDomains.max')
    .optional()
    .isInt({ min: 0 }).withMessage('Custom domain limit must be 0 or a positive number'),
    
  handleValidationErrors
];

/**
 * Validate search query
 */
const validateSearchQuery = [
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    
  query('sort')
    .optional()
    .matches(/^-?(name|createdAt|updatedAt|status|size)$/).withMessage('Invalid sort field'),
    
  query('status')
    .optional()
    .custom((value) => {
      const statuses = Array.isArray(value) ? value : [value];
      const validStatuses = Object.values(TENANT_CONSTANTS.TENANT_STATUS);
      const invalidStatuses = statuses.filter(s => !validStatuses.includes(s));
      if (invalidStatuses.length > 0) {
        throw new ValidationError(`Invalid status values: ${invalidStatuses.join(', ')}`);
      }
      return true;
    }),
    
  query('plan')
    .optional()
    .custom((value) => {
      const plans = Array.isArray(value) ? value : [value];
      const validPlans = Object.values(TENANT_CONSTANTS.SUBSCRIPTION_PLANS);
      const invalidPlans = plans.filter(p => !validPlans.includes(p));
      if (invalidPlans.length > 0) {
        throw new ValidationError(`Invalid plan values: ${invalidPlans.join(', ')}`);
      }
      return true;
    }),
    
  query('industry')
    .optional()
    .custom((value) => {
      const industries = Array.isArray(value) ? value : [value];
      const invalidIndustries = industries.filter(i => !TENANT_CONSTANTS.INDUSTRIES.includes(i));
      if (invalidIndustries.length > 0) {
        throw new ValidationError(`Invalid industry values: ${invalidIndustries.join(', ')}`);
      }
      return true;
    }),
    
  query('size')
    .optional()
    .custom((value) => {
      const sizes = Array.isArray(value) ? value : [value];
      const validSizes = Object.values(TENANT_CONSTANTS.COMPANY_SIZES);
      const invalidSizes = sizes.filter(s => !validSizes.includes(s));
      if (invalidSizes.length > 0) {
        throw new ValidationError(`Invalid size values: ${invalidSizes.join(', ')}`);
      }
      return true;
    }),
    
  query('createdAfter')
    .optional()
    .isISO8601().withMessage('Invalid date format for createdAfter'),
    
  query('createdBefore')
    .optional()
    .isISO8601().withMessage('Invalid date format for createdBefore'),
    
  query('search')
    .optional()
    .trim()
    .isLength({ min: 2 }).withMessage('Search term must be at least 2 characters'),
    
  handleValidationErrors
];

/**
 * Custom validation functions
 */

/**
 * Validate branding colors configuration
 * @param {Object} colors - Color configuration object
 * @returns {boolean} Returns true if valid
 * @throws {ValidationError} If validation fails
 */
const validateBrandingColors = (colors) => {
  const colorRegex = /^#[0-9A-F]{6}$/i;
  const colorFields = ['primary', 'secondary', 'accent', 'background', 'text'];
  
  for (const field of colorFields) {
    if (colors[field] && !colorRegex.test(colors[field])) {
      throw new ValidationError(`Invalid color format for ${field}. Use hex format (e.g., #FFFFFF)`);
    }
  }
  
  return true;
};

/**
 * Validate feature flags configuration
 * @param {Object} features - Feature flags object
 * @returns {boolean} Returns true if valid
 * @throws {ValidationError} If validation fails
 */
const validateFeatureFlags = (features) => {
  const validFeatures = Object.values(TENANT_CONSTANTS.FEATURES);
  const providedFeatures = Object.keys(features);
  
  const invalidFeatures = providedFeatures.filter(f => !validFeatures.includes(f));
  if (invalidFeatures.length > 0) {
    throw new ValidationError(`Invalid features: ${invalidFeatures.join(', ')}`);
  }
  
  // Verify all feature values are boolean
  for (const [feature, value] of Object.entries(features)) {
    if (typeof value !== 'boolean') {
      throw new ValidationError(`Feature ${feature} must have a boolean value`);
    }
  }
  
  return true;
};

/**
 * Validate webhook configuration settings
 * @param {Object} webhook - Webhook configuration object
 * @returns {boolean} Returns true if valid
 * @throws {ValidationError} If validation fails
 */
const validateWebhookConfig = (webhook) => {
  if (!webhook.enabled) return true;
  
  if (!webhook.url) {
    throw new ValidationError('Webhook URL is required when webhooks are enabled');
  }
  
  try {
    new URL(webhook.url);
  } catch (error) {
    throw new ValidationError('Invalid webhook URL format');
  }
  
  if (!webhook.secret || webhook.secret.length < 16) {
    throw new ValidationError('Webhook secret must be at least 16 characters');
  }
  
  if (webhook.events && webhook.events.length > 0) {
    const validEvents = Object.values(TENANT_CONSTANTS.WEBHOOK_EVENTS);
    const invalidEvents = webhook.events.filter(e => !validEvents.includes(e));
    if (invalidEvents.length > 0) {
      throw new ValidationError(`Invalid webhook events: ${invalidEvents.join(', ')}`);
    }
  }
  
  return true;
};

/**
 * Validate tenant branding configuration
 * @param {Object} branding - Branding configuration object
 * @returns {boolean} Returns true if valid
 * @throws {ValidationError} If validation fails
 */
const validateBrandingConfig = (branding) => {
  if (branding.colors) {
    validateBrandingColors(branding.colors);
  }
  
  if (branding.logo && branding.logo.url) {
    try {
      new URL(branding.logo.url);
    } catch (error) {
      throw new ValidationError('Invalid logo URL format');
    }
  }
  
  if (branding.favicon && branding.favicon.url) {
    try {
      new URL(branding.favicon.url);
    } catch (error) {
      throw new ValidationError('Invalid favicon URL format');
    }
  }
  
  return true;
};

/**
 * Validate resource usage limits
 * @param {Object} limits - Resource limits object
 * @param {Object} currentUsage - Current resource usage
 * @returns {boolean} Returns true if valid
 * @throws {ValidationError} If validation fails
 */
const validateResourceUsage = (limits, currentUsage) => {
  const resourceTypes = ['users', 'storage', 'apiCalls', 'projects'];
  
  for (const resourceType of resourceTypes) {
    const limit = limits[resourceType]?.max;
    const usage = currentUsage[resourceType]?.current || 0;
    
    if (limit !== -1 && limit > 0 && usage > limit) {
      throw new ValidationError(`${resourceType} usage (${usage}) exceeds limit (${limit})`);
    }
  }
  
  return true;
};

module.exports = {
  validateTenantCreate,
  validateTenantUpdate,
  validateSubscriptionUpdate,
  validateDomainAdd,
  validateSecuritySettings,
  validateResourceLimits,
  validateSearchQuery,
  handleValidationErrors,
  // Export custom validators for use in other modules
  validateBrandingColors,
  validateFeatureFlags,
  validateWebhookConfig,
  validateBrandingConfig,
  validateResourceUsage
};