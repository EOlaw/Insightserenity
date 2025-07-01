/**
 * @file Organization Validation Middleware
 * @description Validation middleware for organization-related routes
 * @version 1.0.0
 */

const { body, param, query, validationResult } = require('express-validator');
const { AppError } = require('../../../shared/utils/app-error');

/**
 * Validation error handler
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(error => ({
      field: error.param,
      message: error.msg,
      value: error.value
    }));
    
    return next(new AppError('Validation error', 400, {
      errors: errorMessages
    }));
  }
  
  next();
};

/**
 * Validate organization creation
 */
const validateOrganizationCreate = [
  body('name')
    .trim()
    .notEmpty().withMessage('Organization name is required')
    .isLength({ min: 2, max: 100 }).withMessage('Organization name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-&.,]+$/).withMessage('Organization name contains invalid characters'),
  
  body('displayName')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Display name cannot exceed 100 characters'),
  
  body('legalName')
    .optional()
    .trim()
    .isLength({ max: 200 }).withMessage('Legal name cannot exceed 200 characters'),
  
  body('businessInfo.registrationNumber')
    .optional()
    .trim()
    .matches(/^[A-Z0-9\-\/]+$/i).withMessage('Invalid registration number format'),
  
  body('businessInfo.taxId')
    .optional()
    .trim()
    .matches(/^[A-Z0-9\-]+$/i).withMessage('Invalid tax ID format'),
  
  body('businessInfo.businessType')
    .optional()
    .isIn(['sole_proprietorship', 'partnership', 'llc', 'corporation', 'nonprofit', 'other'])
    .withMessage('Invalid business type'),
  
  body('headquarters.email')
    .optional()
    .trim()
    .normalizeEmail()
    .isEmail().withMessage('Invalid email format')
    .isLength({ max: 255 }).withMessage('Email cannot exceed 255 characters'),
  
  body('headquarters.phone')
    .optional()
    .trim()
    .matches(/^[\d\s\-+()]+$/).withMessage('Invalid phone number format'),
  
  body('headquarters.timezone')
    .optional()
    .trim()
    .isIn(Intl.supportedValuesOf('timeZone')).withMessage('Invalid timezone'),
  
  body('platformConfig.tier')
    .optional()
    .isIn(['starter', 'growth', 'professional', 'enterprise', 'custom'])
    .withMessage('Invalid tier'),
  
  body('domains.subdomain')
    .optional()
    .trim()
    .toLowerCase()
    .matches(/^[a-z0-9-]+$/).withMessage('Subdomain can only contain lowercase letters, numbers, and hyphens')
    .isLength({ min: 3, max: 63 }).withMessage('Subdomain must be between 3 and 63 characters')
    .custom(value => {
      const reserved = ['www', 'api', 'admin', 'app', 'mail', 'ftp', 'blog', 'shop', 'support'];
      return !reserved.includes(value);
    }).withMessage('This subdomain is reserved'),
  
  handleValidationErrors
];

/**
 * Validate organization update
 */
const validateOrganizationUpdate = [
  body('name')
    .optional()
    .trim()
    .notEmpty().withMessage('Organization name cannot be empty')
    .isLength({ min: 2, max: 100 }).withMessage('Organization name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z0-9\s\-&.,]+$/).withMessage('Organization name contains invalid characters'),
  
  body('displayName')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Display name cannot exceed 100 characters'),
  
  body('legalName')
    .optional()
    .trim()
    .isLength({ max: 200 }).withMessage('Legal name cannot exceed 200 characters'),
  
  body('businessInfo')
    .optional()
    .isObject().withMessage('Business info must be an object'),
  
  body('headquarters')
    .optional()
    .isObject().withMessage('Headquarters must be an object'),
  
  body('headquarters.email')
    .optional()
    .trim()
    .normalizeEmail()
    .isEmail().withMessage('Invalid email format'),
  
  body('branding.colors.primary')
    .optional()
    .matches(/^#[0-9A-F]{6}$/i).withMessage('Invalid hex color format'),
  
  body('security.twoFactorRequired')
    .optional()
    .isBoolean().withMessage('Two-factor required must be a boolean'),
  
  body('security.ipWhitelist')
    .optional()
    .isArray().withMessage('IP whitelist must be an array')
    .custom(value => {
      return value.every(ip => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip));
    }).withMessage('Invalid IP address format in whitelist'),
  
  body('preferences.defaultLanguage')
    .optional()
    .isLength({ min: 2, max: 5 }).withMessage('Invalid language code'),
  
  body('preferences.currency')
    .optional()
    .isLength({ min: 3, max: 3 }).withMessage('Currency must be a 3-letter code')
    .isUppercase().withMessage('Currency must be uppercase'),
  
  handleValidationErrors
];

/**
 * Validate subscription update
 */
const validateSubscriptionUpdate = [
  body('plan.id')
    .notEmpty().withMessage('Plan ID is required')
    .isIn(['starter', 'growth', 'professional', 'enterprise', 'custom'])
    .withMessage('Invalid plan ID'),
  
  body('plan.name')
    .optional()
    .trim()
    .notEmpty().withMessage('Plan name cannot be empty'),
  
  body('plan.interval')
    .optional()
    .isIn(['monthly', 'yearly']).withMessage('Invalid billing interval'),
  
  body('plan.amount')
    .optional()
    .isFloat({ min: 0 }).withMessage('Amount must be a positive number'),
  
  body('plan.currency')
    .optional()
    .isLength({ min: 3, max: 3 }).withMessage('Currency must be a 3-letter code')
    .isUppercase().withMessage('Currency must be uppercase'),
  
  body('paymentMethod.type')
    .optional()
    .isIn(['card', 'bank_account', 'paypal']).withMessage('Invalid payment method type'),
  
  body('billingCycle')
    .optional()
    .isIn(['monthly', 'quarterly', 'annual']).withMessage('Invalid billing cycle'),
  
  handleValidationErrors
];

/**
 * Validate team member
 */
const validateTeamMember = [
  body('email')
    .trim()
    .normalizeEmail()
    .notEmpty().withMessage('Email is required')
    .isEmail().withMessage('Invalid email format')
    .isLength({ max: 255 }).withMessage('Email cannot exceed 255 characters'),
  
  body('role')
    .optional()
    .isIn(['owner', 'admin', 'member', 'developer', 'analyst', 'manager', 'viewer', 'guest'])
    .withMessage('Invalid role'),
  
  body('department')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Department cannot exceed 100 characters'),
  
  body('title')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Title cannot exceed 100 characters'),
  
  body('permissions')
    .optional()
    .isArray().withMessage('Permissions must be an array')
    .custom(value => {
      const validPermissions = [
        'read', 'write', 'delete', 'manage_team', 'manage_settings', 
        'manage_billing', 'view_analytics', 'export_data'
      ];
      return value.every(perm => validPermissions.includes(perm));
    }).withMessage('Invalid permission in array'),
  
  handleValidationErrors
];

/**
 * Validate domain
 */
const validateDomain = [
  body('domain')
    .trim()
    .toLowerCase()
    .notEmpty().withMessage('Domain is required')
    .matches(/^([a-z0-9-]+\.)+[a-z]{2,}$/).withMessage('Invalid domain format')
    .isLength({ max: 253 }).withMessage('Domain cannot exceed 253 characters')
    .custom(value => {
      // Check for prohibited domains
      const prohibited = ['localhost', '127.0.0.1', '0.0.0.0'];
      return !prohibited.includes(value);
    }).withMessage('This domain is not allowed'),
  
  body('isPrimary')
    .optional()
    .isBoolean().withMessage('isPrimary must be a boolean'),
  
  body('sslEnabled')
    .optional()
    .isBoolean().withMessage('sslEnabled must be a boolean'),
  
  handleValidationErrors
];

/**
 * Validate invitation acceptance
 */
const validateInvitationAccept = [
  body('token')
    .trim()
    .notEmpty().withMessage('Invitation token is required')
    .isLength({ min: 32, max: 128 }).withMessage('Invalid token length')
    .matches(/^[a-zA-Z0-9]+$/).withMessage('Invalid token format'),
  
  body('acceptTerms')
    .optional()
    .isBoolean().withMessage('acceptTerms must be a boolean')
    .custom(value => value === true).withMessage('You must accept the terms'),
  
  handleValidationErrors
];

/**
 * Validate organization ID parameter
 */
const validateOrganizationId = [
  param('id')
    .notEmpty().withMessage('Organization ID is required')
    .isMongoId().withMessage('Invalid organization ID format'),
  
  handleValidationErrors
];

/**
 * Validate member ID parameter
 */
const validateMemberId = [
  param('memberId')
    .notEmpty().withMessage('Member ID is required')
    .isMongoId().withMessage('Invalid member ID format'),
  
  handleValidationErrors
];

/**
 * Validate query parameters for listing
 */
const validateListQuery = [
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
  
  query('sort')
    .optional()
    .matches(/^-?(name|createdAt|updatedAt)$/).withMessage('Invalid sort field'),
  
  query('includeInactive')
    .optional()
    .isBoolean().withMessage('includeInactive must be a boolean'),
  
  query('search')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Search term cannot exceed 100 characters')
    .escape(),
  
  handleValidationErrors
];

/**
 * Validate security settings
 */
const validateSecuritySettings = [
  body('twoFactorRequired')
    .optional()
    .isBoolean().withMessage('twoFactorRequired must be a boolean'),
  
  body('ipWhitelist')
    .optional()
    .isArray().withMessage('IP whitelist must be an array')
    .custom(value => {
      return value.every(ip => /^(\d{1,3}\.){3}\d{1,3}$/.test(ip));
    }).withMessage('Invalid IP address format in whitelist'),
  
  body('passwordPolicy')
    .optional()
    .isObject().withMessage('Password policy must be an object'),
  
  body('passwordPolicy.minLength')
    .optional()
    .isInt({ min: 8, max: 128 }).withMessage('Password minimum length must be between 8 and 128'),
  
  body('passwordPolicy.requireUppercase')
    .optional()
    .isBoolean().withMessage('requireUppercase must be a boolean'),
  
  body('passwordPolicy.requireNumbers')
    .optional()
    .isBoolean().withMessage('requireNumbers must be a boolean'),
  
  body('passwordPolicy.requireSpecialChars')
    .optional()
    .isBoolean().withMessage('requireSpecialChars must be a boolean'),
  
  body('sessionTimeout')
    .optional()
    .isInt({ min: 300, max: 86400 }).withMessage('Session timeout must be between 5 minutes and 24 hours (in seconds)'),
  
  body('dataRetentionDays')
    .optional()
    .isInt({ min: 30, max: 3650 }).withMessage('Data retention must be between 30 days and 10 years'),
  
  handleValidationErrors
];

module.exports = {
  validateOrganizationCreate,
  validateOrganizationUpdate,
  validateSubscriptionUpdate,
  validateTeamMember,
  validateDomain,
  validateInvitationAccept,
  validateOrganizationId,
  validateMemberId,
  validateListQuery,
  validateSecuritySettings,
  handleValidationErrors
};