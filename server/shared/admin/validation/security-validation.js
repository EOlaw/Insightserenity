/**
 * @file Security Validation
 * @description Validation schemas for security-related administrative operations
 * @version 1.0.0
 */

const { body, param, query, header } = require('express-validator');
const AdminValidators = require('../utils/admin-validators');
const AdminSecurityConfig = require('../config/admin-security-config');
const config = require('../../../config/config');

/**
 * Security patterns and rules
 */
const securityPatterns = {
  ipAddress: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  ipv6Address: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
  apiKey: /^[A-Za-z0-9+/]{40,}={0,2}$/,
  sessionToken: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/,
  totpCode: /^[0-9]{6}$/,
  backupCode: /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/
};

/**
 * Multi-factor authentication validation
 */
const mfaValidationSchema = {
  // Setup MFA
  setupMFA: [
    body('method')
      .notEmpty().withMessage('MFA method is required')
      .isIn(['totp', 'sms', 'email', 'hardware', 'biometric'])
      .withMessage('Invalid MFA method'),

    body('phoneNumber')
      .optional()
      .custom((value, { req }) => {
        if (req.body.method === 'sms') {
          return AdminValidators.validatePhone(value).valid;
        }
        return true;
      })
      .withMessage('Valid phone number required for SMS MFA'),

    body('email')
      .optional()
      .custom((value, { req }) => {
        if (req.body.method === 'email') {
          return AdminValidators.validateEmail(value).valid;
        }
        return true;
      })
      .withMessage('Valid email required for email MFA')
  ],

  // Verify MFA
  verifyMFA: [
    body('code')
      .notEmpty().withMessage('MFA code is required')
      .custom((value, { req }) => {
        const method = req.body.method || req.user?.mfaMethod;
        
        if (method === 'totp' || method === 'sms' || method === 'email') {
          return securityPatterns.totpCode.test(value);
        }
        
        if (method === 'backup') {
          return securityPatterns.backupCode.test(value);
        }
        
        return true;
      })
      .withMessage('Invalid MFA code format'),

    body('trustDevice')
      .optional()
      .isBoolean().withMessage('Trust device must be boolean')
      .toBoolean(),

    body('deviceName')
      .optional()
      .trim()
      .isLength({ max: 100 })
      .withMessage('Device name too long')
      .custom((value, { req }) => {
        return req.body.trustDevice ? value && value.length > 0 : true;
      })
      .withMessage('Device name required when trusting device')
  ],

  // Backup codes
  backupCodes: [
    body('regenerate')
      .optional()
      .isBoolean().withMessage('Regenerate must be boolean')
      .toBoolean(),

    body('verifyCode')
      .optional()
      .matches(securityPatterns.backupCode)
      .withMessage('Invalid backup code format')
  ]
};

/**
 * Access control validation
 */
const accessControlSchema = {
  // IP whitelist/blacklist
  ipRestriction: [
    body('action')
      .notEmpty().withMessage('Action is required')
      .isIn(['whitelist', 'blacklist', 'remove'])
      .withMessage('Invalid IP restriction action'),

    body('ipAddresses')
      .isArray({ min: 1, max: 100 })
      .withMessage('IP addresses must be an array with 1-100 items'),

    body('ipAddresses.*')
      .custom((value) => {
        // Support both IPv4 and IPv6
        return securityPatterns.ipAddress.test(value) || 
               securityPatterns.ipv6Address.test(value) ||
               // CIDR notation
               /^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/.test(value);
      })
      .withMessage('Invalid IP address format'),

    body('description')
      .optional()
      .trim()
      .isLength({ max: 200 })
      .withMessage('Description cannot exceed 200 characters'),

    body('expiresAt')
      .optional()
      .isISO8601()
      .withMessage('Expiry must be valid ISO date')
      .custom((value) => new Date(value) > new Date())
      .withMessage('Expiry date must be in the future')
  ],

  // API key management
  apiKeyManagement: [
    body('name')
      .trim()
      .notEmpty().withMessage('API key name is required')
      .isLength({ min: 3, max: 100 })
      .withMessage('Name must be between 3 and 100 characters')
      .matches(/^[a-zA-Z0-9\s_-]+$/)
      .withMessage('Name contains invalid characters'),

    body('permissions')
      .isArray().withMessage('Permissions must be an array')
      .notEmpty().withMessage('At least one permission is required'),

    body('permissions.*')
      .isString()
      .custom((permission) => {
        // Validate against allowed API permissions
        const allowedPermissions = [
          'read:users', 'write:users', 'delete:users',
          'read:organizations', 'write:organizations',
          'read:billing', 'write:billing',
          'read:reports', 'generate:reports',
          'read:audit', 'admin:all'
        ];
        return allowedPermissions.includes(permission);
      })
      .withMessage('Invalid API permission'),

    body('expiresIn')
      .optional()
      .isIn(['30d', '90d', '180d', '1y', 'never'])
      .withMessage('Invalid expiry duration'),

    body('ipRestrictions')
      .optional()
      .isArray()
      .withMessage('IP restrictions must be an array'),

    body('rateLimits')
      .optional()
      .isObject()
      .withMessage('Rate limits must be an object'),

    body('rateLimits.requests')
      .optional()
      .isInt({ min: 10, max: 10000 })
      .withMessage('Request limit must be between 10 and 10,000'),

    body('rateLimits.window')
      .optional()
      .isIn(['minute', 'hour', 'day'])
      .withMessage('Invalid rate limit window')
  ],

  // Session management
  sessionManagement: [
    body('action')
      .notEmpty().withMessage('Action is required')
      .isIn(['terminate', 'terminate_all', 'extend', 'lock'])
      .withMessage('Invalid session action'),

    body('sessionIds')
      .optional()
      .isArray()
      .withMessage('Session IDs must be an array')
      .custom((value, { req }) => {
        if (req.body.action === 'terminate' && (!value || value.length === 0)) {
          return false;
        }
        return true;
      })
      .withMessage('Session IDs required for terminate action'),

    body('sessionIds.*')
      .matches(/^[A-Za-z0-9_-]{20,}$/)
      .withMessage('Invalid session ID format'),

    body('reason')
      .optional()
      .trim()
      .isLength({ min: 10, max: 500 })
      .withMessage('Reason must be between 10 and 500 characters'),

    body('excludeCurrent')
      .optional()
      .isBoolean()
      .withMessage('Exclude current must be boolean')
      .toBoolean()
  ]
};

/**
 * Security policy validation
 */
const securityPolicySchema = {
  // Password policy
  passwordPolicy: [
    body('minLength')
      .optional()
      .isInt({ min: 8, max: 128 })
      .withMessage('Minimum length must be between 8 and 128'),

    body('requireUppercase')
      .optional()
      .isBoolean()
      .withMessage('Require uppercase must be boolean')
      .toBoolean(),

    body('requireLowercase')
      .optional()
      .isBoolean()
      .withMessage('Require lowercase must be boolean')
      .toBoolean(),

    body('requireNumbers')
      .optional()
      .isBoolean()
      .withMessage('Require numbers must be boolean')
      .toBoolean(),

    body('requireSpecialChars')
      .optional()
      .isBoolean()
      .withMessage('Require special chars must be boolean')
      .toBoolean(),

    body('preventReuse')
      .optional()
      .isInt({ min: 0, max: 24 })
      .withMessage('Prevent reuse must be between 0 and 24'),

    body('expiryDays')
      .optional()
      .isInt({ min: 0, max: 365 })
      .withMessage('Expiry days must be between 0 and 365'),

    body('lockoutAttempts')
      .optional()
      .isInt({ min: 3, max: 10 })
      .withMessage('Lockout attempts must be between 3 and 10'),

    body('lockoutDuration')
      .optional()
      .isInt({ min: 5, max: 1440 })
      .withMessage('Lockout duration must be between 5 and 1440 minutes')
  ],

  // Session policy
  sessionPolicy: [
    body('sessionTimeout')
      .optional()
      .isInt({ min: 5, max: 1440 })
      .withMessage('Session timeout must be between 5 and 1440 minutes'),

    body('absoluteTimeout')
      .optional()
      .isInt({ min: 60, max: 10080 })
      .withMessage('Absolute timeout must be between 60 and 10,080 minutes'),

    body('concurrentSessions')
      .optional()
      .isInt({ min: 1, max: 10 })
      .withMessage('Concurrent sessions must be between 1 and 10'),

    body('requireReauthentication')
      .optional()
      .isArray()
      .withMessage('Require reauthentication must be an array'),

    body('requireReauthentication.*')
      .isIn([
        'billing_changes', 'security_changes', 'user_deletion',
        'api_key_generation', 'export_data', 'role_changes'
      ])
      .withMessage('Invalid reauthentication requirement')
  ],

  // Security headers
  securityHeaders: [
    body('csp')
      .optional()
      .isObject()
      .withMessage('CSP must be an object'),

    body('hsts')
      .optional()
      .isObject()
      .withMessage('HSTS must be an object'),

    body('hsts.maxAge')
      .optional()
      .isInt({ min: 0, max: 63072000 })
      .withMessage('HSTS max age must be between 0 and 63,072,000 seconds'),

    body('hsts.includeSubDomains')
      .optional()
      .isBoolean()
      .withMessage('Include subdomains must be boolean')
      .toBoolean(),

    body('frameOptions')
      .optional()
      .isIn(['DENY', 'SAMEORIGIN'])
      .withMessage('Invalid frame options value'),

    body('contentTypeOptions')
      .optional()
      .isBoolean()
      .withMessage('Content type options must be boolean')
      .toBoolean()
  ]
};

/**
 * Audit and compliance validation
 */
const auditComplianceSchema = {
  // Audit log query
  auditLogQuery: [
    query('startDate')
      .optional()
      .isISO8601()
      .withMessage('Start date must be valid ISO date'),

    query('endDate')
      .optional()
      .isISO8601()
      .withMessage('End date must be valid ISO date'),

    query('actions')
      .optional()
      .custom((value) => {
        if (typeof value === 'string') {
          return value.split(',').every(a => /^[a-zA-Z_]+$/.test(a));
        }
        return Array.isArray(value);
      })
      .withMessage('Invalid actions format'),

    query('actors')
      .optional()
      .custom((value) => {
        if (typeof value === 'string') {
          const actors = value.split(',');
          return actors.every(a => /^[0-9a-fA-F]{24}$/.test(a));
        }
        return true;
      })
      .withMessage('Invalid actor IDs'),

    query('severity')
      .optional()
      .isIn(['low', 'medium', 'high', 'critical'])
      .withMessage('Invalid severity level'),

    query('includeSystem')
      .optional()
      .isBoolean()
      .withMessage('Include system must be boolean')
      .toBoolean()
  ],

  // Compliance report
  complianceReport: [
    body('framework')
      .notEmpty().withMessage('Compliance framework is required')
      .isIn(['SOC2', 'ISO27001', 'GDPR', 'HIPAA', 'PCI-DSS', 'CCPA'])
      .withMessage('Invalid compliance framework'),

    body('scope')
      .optional()
      .isArray()
      .withMessage('Scope must be an array'),

    body('scope.*')
      .isIn([
        'access_control', 'data_protection', 'incident_response',
        'business_continuity', 'vendor_management', 'physical_security',
        'network_security', 'application_security', 'all'
      ])
      .withMessage('Invalid scope item'),

    body('format')
      .optional()
      .isIn(['summary', 'detailed', 'evidence'])
      .withMessage('Invalid report format'),

    body('includeRecommendations')
      .optional()
      .isBoolean()
      .withMessage('Include recommendations must be boolean')
      .toBoolean()
  ]
};

/**
 * Threat detection validation
 */
const threatDetectionSchema = {
  // Threat rule configuration
  threatRule: [
    body('name')
      .trim()
      .notEmpty().withMessage('Rule name is required')
      .isLength({ min: 3, max: 100 })
      .withMessage('Name must be between 3 and 100 characters'),

    body('type')
      .notEmpty().withMessage('Rule type is required')
      .isIn([
        'brute_force', 'suspicious_activity', 'data_exfiltration',
        'privilege_escalation', 'anomalous_behavior', 'custom'
      ])
      .withMessage('Invalid rule type'),

    body('conditions')
      .isArray({ min: 1 })
      .withMessage('At least one condition is required'),

    body('conditions.*.field')
      .notEmpty()
      .withMessage('Condition field is required'),

    body('conditions.*.operator')
      .isIn(['equals', 'contains', 'greater_than', 'less_than', 'matches', 'in'])
      .withMessage('Invalid condition operator'),

    body('conditions.*.value')
      .notEmpty()
      .withMessage('Condition value is required'),

    body('actions')
      .isArray({ min: 1 })
      .withMessage('At least one action is required'),

    body('actions.*')
      .isIn([
        'alert', 'block', 'lockout', 'require_mfa',
        'terminate_session', 'notify_admin', 'log'
      ])
      .withMessage('Invalid action'),

    body('severity')
      .notEmpty().withMessage('Severity is required')
      .isIn(['low', 'medium', 'high', 'critical'])
      .withMessage('Invalid severity level'),

    body('enabled')
      .optional()
      .isBoolean()
      .withMessage('Enabled must be boolean')
      .toBoolean()
  ],

  // Security incident
  securityIncident: [
    body('type')
      .notEmpty().withMessage('Incident type is required')
      .isIn([
        'unauthorized_access', 'data_breach', 'malware',
        'phishing', 'ddos', 'insider_threat', 'other'
      ])
      .withMessage('Invalid incident type'),

    body('severity')
      .notEmpty().withMessage('Severity is required')
      .isIn(['low', 'medium', 'high', 'critical'])
      .withMessage('Invalid severity'),

    body('description')
      .trim()
      .notEmpty().withMessage('Description is required')
      .isLength({ min: 20, max: 5000 })
      .withMessage('Description must be between 20 and 5000 characters'),

    body('affectedSystems')
      .isArray()
      .withMessage('Affected systems must be an array'),

    body('affectedUsers')
      .optional()
      .isArray()
      .withMessage('Affected users must be an array'),

    body('containmentActions')
      .optional()
      .isArray()
      .withMessage('Containment actions must be an array'),

    body('evidenceFiles')
      .optional()
      .isArray({ max: 10 })
      .withMessage('Maximum 10 evidence files allowed')
  ]
};

/**
 * Emergency access validation
 */
const emergencyAccessSchema = [
  body('reason')
    .trim()
    .notEmpty().withMessage('Reason is required for emergency access')
    .isLength({ min: 50, max: 1000 })
    .withMessage('Reason must be between 50 and 1000 characters'),

  body('accessLevel')
    .notEmpty().withMessage('Access level is required')
    .isIn(['read_only', 'full_admin', 'specific_permissions'])
    .withMessage('Invalid access level'),

  body('permissions')
    .optional()
    .custom((value, { req }) => {
      if (req.body.accessLevel === 'specific_permissions') {
        return Array.isArray(value) && value.length > 0;
      }
      return true;
    })
    .withMessage('Permissions required for specific permissions access level'),

  body('duration')
    .notEmpty().withMessage('Duration is required')
    .isInt({ min: 15, max: 480 })
    .withMessage('Duration must be between 15 and 480 minutes'),

  body('approvers')
    .isArray({ min: 2 })
    .withMessage('At least 2 approvers required for emergency access'),

  body('approvers.*')
    .isMongoId()
    .withMessage('Invalid approver ID'),

  body('notificationEmails')
    .isArray({ min: 1 })
    .withMessage('At least one notification email required'),

  body('notificationEmails.*')
    .isEmail()
    .withMessage('Invalid notification email')
];

module.exports = {
  mfaValidationSchema,
  accessControlSchema,
  securityPolicySchema,
  auditComplianceSchema,
  threatDetectionSchema,
  emergencyAccessSchema,
  securityPatterns
};