/**
 * @file Common Admin Validation
 * @description Common validation schemas and utilities for administrative operations
 * @version 1.0.0
 */

const { body, param, query, header } = require('express-validator');
const AdminPermissions = require('../utils/admin-permissions');
const AdminValidators = require('../utils/admin-validators');
const config = require('../../../config/config');

/**
 * Common validation patterns
 */
const patterns = {
  adminSessionId: /^ADM-[A-Z0-9]{16}$/,
  adminActionId: /^ACT-[0-9]{13}-[A-Z0-9]{8}$/,
  auditLogId: /^AUD-[0-9]{8}-[A-Z0-9]{12}$/,
  backupId: /^BAK-[0-9]{8}-[A-Z0-9]{8}$/,
  reportId: /^RPT-[A-Z]{3}-[0-9]{8}-[A-Z0-9]{6}$/
};

/**
 * Common parameter validations
 */
const commonParams = {
  // MongoDB ObjectId validation
  objectId: (fieldName = 'id') => 
    param(fieldName)
      .isMongoId()
      .withMessage(`Invalid ${fieldName} format`),

  // Pagination parameters
  pagination: [
    query('page')
      .optional()
      .isInt({ min: 1, max: 10000 })
      .withMessage('Page must be between 1 and 10,000')
      .toInt(),

    query('limit')
      .optional()
      .isInt({ min: 1, max: 1000 })
      .withMessage('Limit must be between 1 and 1,000')
      .toInt(),

    query('offset')
      .optional()
      .isInt({ min: 0 })
      .withMessage('Offset must be a positive integer')
      .toInt()
  ],

  // Sorting parameters
  sorting: [
    query('sortBy')
      .optional()
      .matches(/^[a-zA-Z_]+$/)
      .withMessage('Sort field must contain only letters and underscores')
      .custom((value, { req }) => {
        const allowedFields = req.allowedSortFields || [
          'createdAt', 'updatedAt', 'name', 'email', 'status',
          'role', 'lastActive', 'priority'
        ];
        return allowedFields.includes(value);
      })
      .withMessage('Invalid sort field'),

    query('sortOrder')
      .optional()
      .isIn(['asc', 'desc', 'ASC', 'DESC'])
      .withMessage('Sort order must be asc or desc')
      .toLowerCase()
  ],

  // Date range parameters
  dateRange: [
    query('startDate')
      .optional()
      .isISO8601()
      .withMessage('Start date must be valid ISO 8601 date')
      .custom((value, { req }) => {
        if (req.query.endDate) {
          return new Date(value) <= new Date(req.query.endDate);
        }
        return true;
      })
      .withMessage('Start date must be before or equal to end date'),

    query('endDate')
      .optional()
      .isISO8601()
      .withMessage('End date must be valid ISO 8601 date')
      .custom((value) => {
        return new Date(value) <= new Date();
      })
      .withMessage('End date cannot be in the future')
  ]
};

/**
 * Admin authentication validation
 */
const adminAuthSchema = [
  header('x-admin-token')
    .optional()
    .matches(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/)
    .withMessage('Invalid admin token format'),

  header('x-admin-session')
    .optional()
    .matches(patterns.adminSessionId)
    .withMessage('Invalid admin session ID format'),

  header('x-mfa-token')
    .optional()
    .matches(/^[0-9]{6}$/)
    .withMessage('MFA token must be 6 digits')
];

/**
 * Admin user management validation
 */
const userManagementSchema = {
  // Create admin user
  createAdmin: [
    body('email')
      .isEmail()
      .withMessage('Valid email is required')
      .normalizeEmail()
      .custom(async (email) => {
        return AdminValidators.validateEmail(email).valid;
      })
      .withMessage('Email format is invalid'),

    body('username')
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be between 3 and 30 characters')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),

    body('password')
      .isLength({ min: 12 })
      .withMessage('Password must be at least 12 characters')
      .custom((password) => {
        const strength = AdminValidators.validatePasswordStrength(password);
        return strength.level !== 'weak';
      })
      .withMessage('Password is too weak'),

    body('role')
      .isIn(['admin', 'super_admin', 'support_admin', 'billing_admin', 'security_admin'])
      .withMessage('Invalid admin role'),

    body('permissions')
      .optional()
      .isArray()
      .withMessage('Permissions must be an array')
      .custom((permissions) => {
        return permissions.every(perm => 
          AdminPermissions.validatePermissionName(perm).valid
        );
      })
      .withMessage('Invalid permissions specified'),

    body('requireMFA')
      .optional()
      .isBoolean()
      .withMessage('Require MFA must be boolean')
      .toBoolean()
  ],

  // Update admin user
  updateAdmin: [
    commonParams.objectId('userId'),

    body('email')
      .optional()
      .isEmail()
      .withMessage('Valid email is required')
      .normalizeEmail(),

    body('username')
      .optional()
      .trim()
      .isLength({ min: 3, max: 30 })
      .withMessage('Username must be between 3 and 30 characters')
      .matches(/^[a-zA-Z0-9_-]+$/)
      .withMessage('Username can only contain letters, numbers, underscores, and hyphens'),

    body('status')
      .optional()
      .isIn(['active', 'suspended', 'locked', 'pending'])
      .withMessage('Invalid status'),

    body('role')
      .optional()
      .isIn(['admin', 'super_admin', 'support_admin', 'billing_admin', 'security_admin'])
      .withMessage('Invalid admin role')
      .custom((role, { req }) => {
        // Check if user can assign this role
        const userRole = req.user?.role;
        if (role === 'super_admin' && userRole !== 'super_admin') {
          return false;
        }
        return true;
      })
      .withMessage('Insufficient permissions to assign this role'),

    body('permissions')
      .optional()
      .isArray()
      .withMessage('Permissions must be an array')
  ],

  // Admin action validation
  adminAction: [
    body('action')
      .notEmpty()
      .withMessage('Action is required')
      .isLength({ max: 100 })
      .withMessage('Action name too long'),

    body('target')
      .notEmpty()
      .withMessage('Target is required')
      .isObject()
      .withMessage('Target must be an object'),

    body('target.type')
      .notEmpty()
      .withMessage('Target type is required')
      .isIn(['user', 'organization', 'system', 'billing', 'security'])
      .withMessage('Invalid target type'),

    body('target.id')
      .notEmpty()
      .withMessage('Target ID is required'),

    body('reason')
      .optional()
      .trim()
      .isLength({ min: 10, max: 1000 })
      .withMessage('Reason must be between 10 and 1000 characters'),

    body('metadata')
      .optional()
      .isObject()
      .withMessage('Metadata must be an object')
  ]
};

/**
 * System configuration validation
 */
const systemConfigSchema = {
  // Update system configuration
  updateConfig: [
    body('category')
      .notEmpty()
      .withMessage('Configuration category is required')
      .isIn(['general', 'security', 'billing', 'email', 'integrations', 'features'])
      .withMessage('Invalid configuration category'),

    body('settings')
      .notEmpty()
      .withMessage('Settings are required')
      .isObject()
      .withMessage('Settings must be an object'),

    body('settings.*')
      .custom((value, { path }) => {
        // Validate based on the setting path
        const settingKey = path.split('.').pop();
        
        // Add specific validations for known settings
        const validators = {
          maxLoginAttempts: (val) => Number.isInteger(val) && val >= 3 && val <= 10,
          sessionTimeout: (val) => Number.isInteger(val) && val >= 300 && val <= 86400,
          passwordExpiry: (val) => Number.isInteger(val) && val >= 0 && val <= 365,
          maintenanceMode: (val) => typeof val === 'boolean',
          allowedDomains: (val) => Array.isArray(val) && val.every(d => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d))
        };

        if (validators[settingKey]) {
          return validators[settingKey](value);
        }

        return true;
      })
      .withMessage('Invalid setting value'),

    body('applyImmediately')
      .optional()
      .isBoolean()
      .withMessage('Apply immediately must be boolean')
      .toBoolean()
  ],

  // Maintenance mode
  maintenanceMode: [
    body('enabled')
      .isBoolean()
      .withMessage('Enabled must be boolean')
      .toBoolean(),

    body('message')
      .optional()
      .trim()
      .isLength({ max: 500 })
      .withMessage('Message cannot exceed 500 characters'),

    body('allowedIPs')
      .optional()
      .isArray()
      .withMessage('Allowed IPs must be an array')
      .custom((ips) => {
        return ips.every(ip => /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip));
      })
      .withMessage('Invalid IP address format'),

    body('estimatedDuration')
      .optional()
      .isInt({ min: 1, max: 1440 })
      .withMessage('Duration must be between 1 and 1440 minutes')
  ]
};

/**
 * Search and filter validation
 */
const searchFilterSchema = [
  query('search')
    .optional()
    .trim()
    .isLength({ max: 200 })
    .withMessage('Search query too long')
    .custom((value) => {
      // Prevent SQL injection patterns
      const dangerousPatterns = [
        /(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/i,
        /(--|\/\*|\*\/|;|'|")/
      ];
      return !dangerousPatterns.some(pattern => pattern.test(value));
    })
    .withMessage('Search query contains invalid characters'),

  query('filters')
    .optional()
    .custom((value) => {
      try {
        if (typeof value === 'string') {
          JSON.parse(value);
        }
        return true;
      } catch {
        return false;
      }
    })
    .withMessage('Filters must be valid JSON'),

  query('fields')
    .optional()
    .matches(/^[a-zA-Z,_]+$/)
    .withMessage('Fields must contain only letters, commas, and underscores')
];

/**
 * Admin report validation
 */
const adminReportSchema = [
  body('reportType')
    .notEmpty()
    .withMessage('Report type is required')
    .isIn([
      'user_activity', 'system_health', 'security_audit',
      'billing_summary', 'performance_metrics', 'compliance_report',
      'error_logs', 'api_usage', 'custom'
    ])
    .withMessage('Invalid report type'),

  body('parameters')
    .optional()
    .isObject()
    .withMessage('Parameters must be an object'),

  body('schedule')
    .optional()
    .isObject()
    .withMessage('Schedule must be an object'),

  body('schedule.frequency')
    .optional()
    .isIn(['once', 'daily', 'weekly', 'monthly', 'quarterly'])
    .withMessage('Invalid schedule frequency'),

  body('recipients')
    .optional()
    .isArray()
    .withMessage('Recipients must be an array')
    .custom((recipients) => {
      return recipients.every(r => AdminValidators.validateEmail(r).valid);
    })
    .withMessage('Invalid recipient email addresses')
];

/**
 * Helper function to combine validations
 */
const combineValidations = (...validations) => {
  return validations.flat();
};

/**
 * Custom validation middleware
 */
const customValidation = (validator) => {
  return (req, res, next) => {
    const result = validator(req);
    if (!result.valid) {
      return res.status(400).json({
        success: false,
        errors: result.errors
      });
    }
    next();
  };
};

module.exports = {
  patterns,
  commonParams,
  adminAuthSchema,
  userManagementSchema,
  systemConfigSchema,
  searchFilterSchema,
  adminReportSchema,
  combineValidations,
  customValidation
};