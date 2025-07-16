// server/admin/user-management/validation/user-management-validation.js
/**
 * @file User Management Validation
 * @description Validation schemas and rules for user management operations
 * @version 1.0.0
 */

const Joi = require('joi');
const moment = require('moment-timezone');

// Utilities
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const ValidationHelpers = require('../../../shared/utils/validation-helpers');

// Constants
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Common validation schemas
 */
const commonSchemas = {
  // MongoDB ObjectId
  objectId: Joi.string()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .messages({
      'string.pattern.base': 'Invalid ID format'
    }),

  // Email
  email: Joi.string()
    .email()
    .lowercase()
    .trim()
    .max(255)
    .messages({
      'string.email': 'Invalid email format',
      'string.max': 'Email cannot exceed 255 characters'
    }),

  // Password
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .messages({
      'string.min': 'Password must be at least 8 characters long',
      'string.max': 'Password cannot exceed 128 characters',
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    }),

  // Phone number
  phone: Joi.string()
    .pattern(/^\+?[1-9]\d{1,14}$/)
    .messages({
      'string.pattern.base': 'Invalid phone number format (E.164 format required)'
    }),

  // Profile fields
  profile: Joi.object({
    firstName: Joi.string().trim().max(50).pattern(/^[a-zA-Z\s'-]+$/).messages({
      'string.max': 'First name cannot exceed 50 characters',
      'string.pattern.base': 'First name can only contain letters, spaces, hyphens, and apostrophes'
    }),
    lastName: Joi.string().trim().max(50).pattern(/^[a-zA-Z\s'-]+$/).messages({
      'string.max': 'Last name cannot exceed 50 characters',
      'string.pattern.base': 'Last name can only contain letters, spaces, hyphens, and apostrophes'
    }),
    displayName: Joi.string().trim().max(100),
    avatar: Joi.string().uri().max(500),
    bio: Joi.string().max(500),
    dateOfBirth: Joi.date().max('now').min('1900-01-01'),
    gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say'),
    timezone: Joi.string().custom((value, helpers) => {
      if (!moment.tz.zone(value)) {
        return helpers.error('any.invalid');
      }
      return value;
    }).messages({
      'any.invalid': 'Invalid timezone'
    }),
    language: Joi.string().pattern(/^[a-z]{2}(-[A-Z]{2})?$/),
    country: Joi.string().length(2).uppercase()
  }),

  // Pagination
  pagination: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(AdminLimits.PAGINATION.MAX_LIMIT).default(20),
    sortBy: Joi.string(),
    sortOrder: Joi.string().valid('asc', 'desc').default('desc')
  })
};

/**
 * Get users query validation schema
 */
const getUsersQuerySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  search: Joi.string().max(100).trim(),
  status: Joi.string().valid('active', 'inactive', 'suspended', 'locked', 'deleted'),
  role: commonSchemas.objectId,
  organization: commonSchemas.objectId,
  verified: Joi.boolean(),
  hasSubscription: Joi.boolean(),
  createdFrom: Joi.date().iso(),
  createdTo: Joi.date().iso().when('createdFrom', {
    is: Joi.exist(),
    then: Joi.date().greater(Joi.ref('createdFrom'))
  }),
  lastActiveFrom: Joi.date().iso(),
  lastActiveTo: Joi.date().iso().when('lastActiveFrom', {
    is: Joi.exist(),
    then: Joi.date().greater(Joi.ref('lastActiveFrom'))
  }),
  sortBy: Joi.string().valid(
    'createdAt', 'lastActiveAt', 'email', 'firstName', 'lastName', 'status'
  ).default('createdAt'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  includeDeleted: Joi.boolean().default(false),
  exportFormat: Joi.string().valid('csv', 'xlsx', 'json')
}).messages({
  'date.greater': 'End date must be after start date'
});

/**
 * Create user validation schema
 */
const createUserSchema = Joi.object({
  email: commonSchemas.email.required(),
  password: commonSchemas.password.required(),
  profile: commonSchemas.profile.required(),
  role: commonSchemas.objectId.required(),
  organization: commonSchemas.objectId,
  permissions: Joi.array().items(Joi.object({
    resource: Joi.string().required(),
    actions: Joi.array().items(Joi.string()).min(1).required()
  })),
  sendWelcomeEmail: Joi.boolean().default(true),
  requirePasswordChange: Joi.boolean().default(false),
  skipEmailVerification: Joi.boolean().default(false),
  settings: Joi.object({
    notifications: Joi.object({
      email: Joi.boolean(),
      sms: Joi.boolean(),
      push: Joi.boolean()
    }),
    preferences: Joi.object()
  }),
  metadata: Joi.object()
}).custom((value, helpers) => {
  // Ensure at least first name or last name is provided
  if (!value.profile.firstName && !value.profile.lastName) {
    return helpers.error('custom.nameRequired');
  }
  return value;
}).messages({
  'custom.nameRequired': 'At least first name or last name is required'
});

/**
 * Update user validation schema
 */
const updateUserSchema = Joi.object({
  email: commonSchemas.email,
  status: Joi.string().valid('active', 'suspended', 'locked'),
  role: Joi.object({
    primary: commonSchemas.objectId,
    secondary: Joi.array().items(commonSchemas.objectId)
  }),
  organization: commonSchemas.objectId,
  permissions: Joi.object({
    custom: Joi.array().items(Joi.object({
      resource: Joi.string().required(),
      actions: Joi.array().items(Joi.string()).min(1).required()
    }))
  }),
  profile: commonSchemas.profile,
  settings: Joi.object({
    notifications: Joi.object({
      email: Joi.boolean(),
      sms: Joi.boolean(),
      push: Joi.boolean()
    }),
    preferences: Joi.object(),
    privacy: Joi.object()
  }),
  security: Joi.object({
    requireMFA: Joi.boolean(),
    requirePasswordChange: Joi.boolean(),
    allowedIPs: Joi.array().items(
      Joi.string().ip({ version: ['ipv4', 'ipv6'] })
    ),
    sessionTimeout: Joi.number().min(300).max(86400)
  })
}).min(1).messages({
  'object.min': 'At least one field must be provided for update'
});

/**
 * Delete user validation schema
 */
const deleteUserSchema = Joi.object({
  hardDelete: Joi.boolean().default(false),
  reason: Joi.string().min(10).max(1000).required().messages({
    'string.min': 'Deletion reason must be at least 10 characters',
    'any.required': 'Deletion reason is required'
  }),
  anonymizeData: Joi.boolean().default(true),
  transferOwnership: commonSchemas.objectId,
  backupData: Joi.boolean().default(true),
  notifyUser: Joi.boolean().default(false),
  scheduleDeletion: Joi.date().iso().min('now').max(
    moment().add(90, 'days').toDate()
  )
});

/**
 * Reset password validation schema
 */
const resetPasswordSchema = Joi.object({
  newPassword: commonSchemas.password,
  generateRandom: Joi.boolean().default(true),
  requireChange: Joi.boolean().default(true),
  notifyUser: Joi.boolean().default(true),
  reason: Joi.string().min(5).max(500).required().messages({
    'string.min': 'Password reset reason must be at least 5 characters',
    'any.required': 'Password reset reason is required'
  }),
  expireSessions: Joi.boolean().default(true)
}).custom((value, helpers) => {
  // If not generating random, new password is required
  if (!value.generateRandom && !value.newPassword) {
    return helpers.error('custom.passwordRequired');
  }
  // If generating random, new password should not be provided
  if (value.generateRandom && value.newPassword) {
    return helpers.error('custom.passwordConflict');
  }
  return value;
}).messages({
  'custom.passwordRequired': 'New password is required when not generating random password',
  'custom.passwordConflict': 'Cannot provide new password when generating random password'
});

/**
 * Toggle suspension validation schema
 */
const toggleSuspensionSchema = Joi.object({
  action: Joi.string().valid('suspend', 'unsuspend').required(),
  reason: Joi.string().min(10).max(1000).required().messages({
    'string.min': 'Suspension reason must be at least 10 characters',
    'any.required': 'Suspension reason is required'
  }),
  duration: Joi.when('action', {
    is: 'suspend',
    then: Joi.number().integer().min(1).max(365).messages({
      'number.min': 'Suspension duration must be at least 1 day',
      'number.max': 'Suspension duration cannot exceed 365 days'
    }),
    otherwise: Joi.forbidden()
  }),
  notifyUser: Joi.boolean().default(true),
  restrictionLevel: Joi.when('action', {
    is: 'suspend',
    then: Joi.string().valid('full', 'read_only', 'api_only').default('full'),
    otherwise: Joi.forbidden()
  })
});

/**
 * Force logout validation schema
 */
const forceLogoutSchema = Joi.object({
  reason: Joi.string().max(500).default('Forced logout by administrator'),
  notifyUser: Joi.boolean().default(false),
  includeAllDevices: Joi.boolean().default(true)
});

/**
 * User activity query validation schema
 */
const userActivityQuerySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  startDate: Joi.date().iso(),
  endDate: Joi.date().iso().when('startDate', {
    is: Joi.exist(),
    then: Joi.date().greater(Joi.ref('startDate'))
  }),
  activityType: Joi.string().valid(
    'login', 'logout', 'profile_update', 'password_change',
    'settings_change', 'api_access', 'data_export', 'security_event'
  ),
  ipAddress: Joi.string().ip({ version: ['ipv4', 'ipv6'] }),
  deviceType: Joi.string().valid('desktop', 'mobile', 'tablet', 'api')
});

/**
 * User sessions query validation schema
 */
const userSessionsQuerySchema = Joi.object({
  includeInactive: Joi.boolean().default(false),
  limit: Joi.number().integer().min(1).max(50).default(10),
  deviceType: Joi.string().valid('desktop', 'mobile', 'tablet', 'api'),
  sortBy: Joi.string().valid('createdAt', 'lastActivityAt').default('lastActivityAt'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

/**
 * Update permissions validation schema
 */
const updatePermissionsSchema = Joi.object({
  permissions: Joi.array().items(Joi.object({
    resource: Joi.string().required().pattern(/^[a-z_]+(\.[a-z_]+)*$/),
    actions: Joi.array().items(
      Joi.string().valid('create', 'read', 'update', 'delete', 'manage', '*')
    ).min(1).unique().required(),
    conditions: Joi.object(),
    expiresAt: Joi.date().iso().min('now')
  })).min(1).unique((a, b) => a.resource === b.resource).required()
}).messages({
  'array.unique': 'Duplicate resource permissions are not allowed'
});

/**
 * Send password reset email validation schema
 */
const sendPasswordResetEmailSchema = Joi.object({
  customMessage: Joi.string().max(1000),
  expiryHours: Joi.number().min(1).max(72).default(24),
  requireMFA: Joi.boolean().default(false)
});

/**
 * Verify email validation schema
 */
const verifyEmailSchema = Joi.object({
  reason: Joi.string().max(500),
  notifyUser: Joi.boolean().default(true),
  skipTokenValidation: Joi.boolean().default(true)
});

/**
 * Audit logs query validation schema
 */
const auditLogsQuerySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  startDate: Joi.date().iso(),
  endDate: Joi.date().iso().when('startDate', {
    is: Joi.exist(),
    then: Joi.date().greater(Joi.ref('startDate'))
  }),
  action: Joi.string(),
  severity: Joi.string().valid('low', 'medium', 'high', 'critical'),
  category: Joi.string().valid(
    'authentication', 'authorization', 'user_management',
    'data_access', 'configuration', 'security'
  ),
  ipAddress: Joi.string().ip({ version: ['ipv4', 'ipv6'] }),
  success: Joi.boolean()
});

/**
 * Custom validators for complex validations
 */
const customValidators = {
  /**
   * Validate user status transition
   * @param {string} currentStatus - Current user status
   * @param {string} newStatus - New user status
   * @returns {Object} Validation result
   */
  validateStatusTransition: (currentStatus, newStatus) => {
    const validTransitions = {
      active: ['suspended', 'locked', 'inactive'],
      inactive: ['active', 'suspended', 'locked'],
      suspended: ['active', 'locked'],
      locked: ['active'],
      deleted: [] // Cannot transition from deleted
    };

    const allowed = validTransitions[currentStatus] || [];
    
    return {
      valid: allowed.includes(newStatus),
      error: !allowed.includes(newStatus) ? 
        `Cannot transition from ${currentStatus} to ${newStatus}` : null
    };
  },

  /**
   * Validate role assignment
   * @param {Object} adminUser - Admin user performing the assignment
   * @param {Object} targetRole - Role being assigned
   * @returns {Object} Validation result
   */
  validateRoleAssignment: (adminUser, targetRole) => {
    // Check role hierarchy
    if (targetRole.level >= adminUser.role?.level) {
      return {
        valid: false,
        error: 'Cannot assign role with equal or higher level than your own'
      };
    }

    // Check restricted roles
    const restrictedRoles = ['super_admin', 'system_admin'];
    if (restrictedRoles.includes(targetRole.name) && 
        adminUser.role?.name !== 'super_admin') {
      return {
        valid: false,
        error: 'Insufficient permissions to assign this role'
      };
    }

    return { valid: true };
  },

  /**
   * Validate permission assignment
   * @param {Array} permissions - Permissions to assign
   * @param {Object} adminUser - Admin user performing the assignment
   * @returns {Object} Validation result
   */
  validatePermissionAssignment: (permissions, adminUser) => {
    const errors = [];
    const adminPermissions = adminUser.permissions || [];

    permissions.forEach(permission => {
      // Check if admin has the permission they're trying to assign
      const hasPermission = adminPermissions.some(p => 
        p.resource === permission.resource && 
        permission.actions.every(action => p.actions.includes(action))
      );

      if (!hasPermission) {
        errors.push(`Cannot assign permission: ${permission.resource}`);
      }

      // Check for restricted permissions
      const restrictedResources = ['system', 'super_admin'];
      if (restrictedResources.some(r => permission.resource.startsWith(r))) {
        errors.push(`Cannot assign restricted permission: ${permission.resource}`);
      }
    });

    return {
      valid: errors.length === 0,
      errors
    };
  },

  /**
   * Validate user data consistency
   * @param {Object} userData - User data to validate
   * @returns {Object} Validation result
   */
  validateUserDataConsistency: (userData) => {
    const warnings = [];

    // Check email and username consistency
    if (userData.email && userData.username) {
      if (userData.email.split('@')[0] !== userData.username) {
        warnings.push('Email prefix does not match username');
      }
    }

    // Check profile completeness
    if (userData.profile) {
      const requiredFields = ['firstName', 'lastName'];
      const missingFields = requiredFields.filter(field => !userData.profile[field]);
      
      if (missingFields.length > 0) {
        warnings.push(`Incomplete profile: missing ${missingFields.join(', ')}`);
      }
    }

    // Check organization and role consistency
    if (userData.organization && userData.role) {
      // Add organization-specific role validation here
    }

    return {
      valid: true, // Warnings don't invalidate, just inform
      warnings
    };
  }
};

/**
 * Validation middleware factory
 * @param {Object} schema - Joi schema to validate against
 * @param {string} source - Source of data ('body', 'query', 'params')
 * @returns {Function} Express middleware function
 */
const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req[source], {
      abortEarly: false,
      stripUnknown: true,
      convert: true
    });

    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        type: detail.type
      }));

      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request data',
          details: errors
        }
      });
    }

    // Replace source data with validated and sanitized value
    req[source] = value;
    next();
  };
};

// Export schemas and validators
module.exports = {
  schemas: {
    getUsersQuery: getUsersQuerySchema,
    createUser: createUserSchema,
    updateUser: updateUserSchema,
    deleteUser: deleteUserSchema,
    resetPassword: resetPasswordSchema,
    toggleSuspension: toggleSuspensionSchema,
    forceLogout: forceLogoutSchema,
    userActivityQuery: userActivityQuerySchema,
    userSessionsQuery: userSessionsQuerySchema,
    updatePermissions: updatePermissionsSchema,
    sendPasswordResetEmail: sendPasswordResetEmailSchema,
    verifyEmail: verifyEmailSchema,
    auditLogsQuery: auditLogsQuerySchema
  },
  validators: customValidators,
  middleware: {
    validateGetUsers: validate(getUsersQuerySchema, 'query'),
    validateCreateUser: validate(createUserSchema, 'body'),
    validateUpdateUser: validate(updateUserSchema, 'body'),
    validateDeleteUser: validate(deleteUserSchema, 'body'),
    validateResetPassword: validate(resetPasswordSchema, 'body'),
    validateToggleSuspension: validate(toggleSuspensionSchema, 'body'),
    validateForceLogout: validate(forceLogoutSchema, 'body'),
    validateUserActivity: validate(userActivityQuerySchema, 'query'),
    validateUserSessions: validate(userSessionsQuerySchema, 'query'),
    validateUpdatePermissions: validate(updatePermissionsSchema, 'body'),
    validateSendPasswordResetEmail: validate(sendPasswordResetEmailSchema, 'body'),
    validateVerifyEmail: validate(verifyEmailSchema, 'body'),
    validateAuditLogs: validate(auditLogsQuerySchema, 'query')
  }
};