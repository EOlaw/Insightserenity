// server/admin/user-management/validation/bulk-operations-validation.js
/**
 * @file Bulk Operations Validation
 * @description Validation schemas and rules for bulk user operations
 * @version 1.0.0
 */

const Joi = require('joi');
const moment = require('moment');

// Utilities
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const ValidationHelpers = require('../../../shared/utils/validation-helpers');

// Constants
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Base schemas for common fields
 */
const baseSchemas = {
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

  // User IDs array
  userIds: Joi.array()
    .items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/))
    .min(1)
    .unique()
    .messages({
      'array.min': 'At least one user ID is required',
      'array.unique': 'Duplicate user IDs are not allowed'
    }),

  // Filter object
  filters: Joi.object({
    status: Joi.string().valid('active', 'inactive', 'suspended', 'locked', 'deleted'),
    role: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
    organization: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
    verified: Joi.boolean(),
    hasSubscription: Joi.boolean(),
    createdAfter: Joi.date().iso(),
    createdBefore: Joi.date().iso(),
    lastActiveAfter: Joi.date().iso(),
    lastActiveBefore: Joi.date().iso(),
    search: Joi.string().max(100),
    tags: Joi.array().items(Joi.string()),
    customFields: Joi.object()
  }).min(1).messages({
    'object.min': 'At least one filter criterion is required'
  })
};

/**
 * Bulk import validation schema
 */
const bulkImportSchema = Joi.object({
  fileData: Joi.object({
    originalName: Joi.string().required(),
    mimetype: Joi.string().valid(
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ).required(),
    size: Joi.number().max(AdminLimits.FILE_UPLOAD.MAX_IMPORT_SIZE).required(),
    content: Joi.string().required()
  }).required().messages({
    'any.required': 'Import file data is required',
    'string.valid': 'Invalid file type. Only CSV and Excel files are allowed',
    'number.max': `File size cannot exceed ${AdminLimits.FILE_UPLOAD.MAX_IMPORT_SIZE / 1024 / 1024}MB`
  }),

  mappings: Joi.object({
    email: Joi.string().required(),
    firstName: Joi.string(),
    lastName: Joi.string(),
    role: Joi.string(),
    organization: Joi.string(),
    phone: Joi.string(),
    customFields: Joi.object()
  }).required().messages({
    'any.required': 'Field mappings are required',
    'object.base': 'Mappings must be an object'
  }),

  options: Joi.object({
    sendWelcomeEmails: Joi.boolean().default(true),
    skipExisting: Joi.boolean().default(true),
    validateOnly: Joi.boolean().default(false),
    defaultRole: baseSchemas.objectId,
    defaultOrganization: baseSchemas.objectId,
    generatePasswords: Joi.boolean().default(true),
    requirePasswordChange: Joi.boolean().default(true),
    passwordLength: Joi.number().min(8).max(32).default(12),
    notificationTemplate: Joi.string(),
    importTags: Joi.array().items(Joi.string()),
    customDefaults: Joi.object()
  }).default({})
}).custom((value, helpers) => {
  // Validate date field mappings
  const dateFields = ['dateOfBirth', 'joinDate', 'customDates'];
  Object.entries(value.mappings).forEach(([key, mappedField]) => {
    if (dateFields.includes(key) && value.options.dateFormat) {
      // Validate date format
      if (!moment(new Date(), value.options.dateFormat, true).isValid()) {
        return helpers.error('custom.invalidDateFormat', { field: key });
      }
    }
  });
  return value;
}).messages({
  'custom.invalidDateFormat': 'Invalid date format for field {#field}'
});

/**
 * Bulk update validation schema
 */
const bulkUpdateSchema = Joi.object({
  userIds: baseSchemas.userIds
    .max(AdminLimits.BULK_OPERATIONS.MAX_UPDATE_USERS)
    .messages({
      'array.max': `Cannot update more than ${AdminLimits.BULK_OPERATIONS.MAX_UPDATE_USERS} users at once`
    }),
  
  filters: baseSchemas.filters,

  updates: Joi.object({
    status: Joi.string().valid('active', 'suspended', 'locked'),
    role: baseSchemas.objectId,
    organization: baseSchemas.objectId,
    requirePasswordChange: Joi.boolean(),
    requireMFA: Joi.boolean(),
    tags: Joi.object({
      add: Joi.array().items(Joi.string()),
      remove: Joi.array().items(Joi.string())
    }),
    customFields: Joi.object(),
    settings: Joi.object({
      notifications: Joi.object(),
      preferences: Joi.object()
    })
  }).min(1).required().messages({
    'object.min': 'At least one update field is required',
    'any.required': 'Updates object is required'
  }),

  options: Joi.object({
    validateOnly: Joi.boolean().default(false),
    notifyUsers: Joi.boolean().default(false),
    skipProtectedAccounts: Joi.boolean().default(true),
    auditReason: Joi.string().min(10).max(500),
    scheduledAt: Joi.date().iso().min('now'),
    batchSize: Joi.number().min(10).max(1000).default(100)
  }).default({})
}).xor('userIds', 'filters').messages({
  'object.xor': 'Either userIds or filters must be provided, but not both'
});

/**
 * Bulk delete validation schema
 */
const bulkDeleteSchema = Joi.object({
  userIds: baseSchemas.userIds
    .max(AdminLimits.BULK_OPERATIONS.MAX_DELETE_USERS)
    .messages({
      'array.max': `Cannot delete more than ${AdminLimits.BULK_OPERATIONS.MAX_DELETE_USERS} users at once`
    }),
  
  filters: baseSchemas.filters,

  options: Joi.object({
    hardDelete: Joi.boolean().default(false),
    reason: Joi.string().min(20).max(1000).required().messages({
      'string.min': 'Deletion reason must be at least 20 characters',
      'any.required': 'Deletion reason is required'
    }),
    skipProtectedAccounts: Joi.boolean().default(true),
    validateOnly: Joi.boolean().default(false),
    anonymizeData: Joi.boolean().default(true),
    transferOwnership: baseSchemas.objectId,
    backupData: Joi.boolean().default(true),
    notifyUsers: Joi.boolean().default(false),
    gracePeriodDays: Joi.number().min(0).max(30).default(0)
  }).required()
}).xor('userIds', 'filters').custom((value, helpers) => {
  // Validate transfer ownership is not in deletion list
  if (value.options.transferOwnership && value.userIds) {
    if (value.userIds.includes(value.options.transferOwnership)) {
      return helpers.error('custom.transferOwnershipConflict');
    }
  }
  return value;
}).messages({
  'object.xor': 'Either userIds or filters must be provided, but not both',
  'custom.transferOwnershipConflict': 'Transfer ownership target cannot be in deletion list'
});

/**
 * Bulk export validation schema
 */
const bulkExportSchema = Joi.object({
  filters: baseSchemas.filters.default({}),

  fields: Joi.array().items(
    Joi.string().valid(
      // Basic fields
      'id', 'email', 'firstName', 'lastName', 'fullName',
      'status', 'role', 'organization', 'createdAt', 'lastActiveAt',
      // Extended fields
      'phone', 'avatar', 'timezone', 'language', 'country',
      'emailVerified', 'mfaEnabled', 'lastLoginAt', 'loginCount',
      // Subscription fields
      'subscriptionStatus', 'subscriptionPlan', 'subscriptionExpiry',
      // Custom fields
      'tags', 'customFields', 'metadata'
    )
  ).min(1).default(['id', 'email', 'firstName', 'lastName', 'status', 'role', 'createdAt']),

  format: Joi.string().valid('csv', 'xlsx', 'json').default('csv'),

  options: Joi.object({
    includeDeleted: Joi.boolean().default(false),
    includeSensitive: Joi.boolean().default(false),
    dateFormat: Joi.string().default('YYYY-MM-DD'),
    timezone: Joi.string().default('UTC'),
    chunkSize: Joi.number().min(100).max(10000).default(5000),
    compression: Joi.boolean().default(false),
    asyncExport: Joi.boolean().default(false),
    encryptFile: Joi.boolean().default(false),
    password: Joi.when('encryptFile', {
      is: true,
      then: Joi.string().min(8).required(),
      otherwise: Joi.forbidden()
    })
  }).default({})
}).custom((value, helpers) => {
  // Validate sensitive fields permission
  const sensitiveFields = ['phone', 'customFields', 'metadata'];
  if (!value.options.includeSensitive) {
    const requestedSensitive = value.fields.filter(f => sensitiveFields.includes(f));
    if (requestedSensitive.length > 0) {
      return helpers.error('custom.sensitiveFieldsRestricted', { 
        fields: requestedSensitive.join(', ') 
      });
    }
  }
  return value;
}).messages({
  'custom.sensitiveFieldsRestricted': 'Sensitive fields ({#fields}) require includeSensitive option'
});

/**
 * Bulk email validation schema
 */
const bulkEmailSchema = Joi.object({
  userIds: baseSchemas.userIds
    .max(AdminLimits.BULK_OPERATIONS.MAX_EMAIL_RECIPIENTS)
    .messages({
      'array.max': `Cannot send emails to more than ${AdminLimits.BULK_OPERATIONS.MAX_EMAIL_RECIPIENTS} users at once`
    }),
  
  filters: baseSchemas.filters,

  emailTemplate: Joi.object({
    subject: Joi.string().min(5).max(200).required().messages({
      'string.min': 'Email subject must be at least 5 characters',
      'string.max': 'Email subject cannot exceed 200 characters',
      'any.required': 'Email subject is required'
    }),
    content: Joi.string().min(10).max(50000).required().messages({
      'string.min': 'Email content must be at least 10 characters',
      'string.max': 'Email content cannot exceed 50,000 characters',
      'any.required': 'Email content is required'
    }),
    contentType: Joi.string().valid('text', 'html').default('html'),
    templateId: Joi.string(),
    variables: Joi.object(),
    attachments: Joi.array().items(Joi.object({
      filename: Joi.string().required(),
      path: Joi.string(),
      content: Joi.string(),
      contentType: Joi.string()
    })).max(5)
  }).required(),

  customData: Joi.object().default({}),

  options: Joi.object({
    scheduleAt: Joi.date().iso().min('now').max(
      moment().add(90, 'days').toDate()
    ).messages({
      'date.min': 'Schedule date must be in the future',
      'date.max': 'Cannot schedule emails more than 90 days in advance'
    }),
    batchDelay: Joi.number().min(100).max(10000).default(1000),
    trackOpens: Joi.boolean().default(true),
    trackClicks: Joi.boolean().default(true),
    validateOnly: Joi.boolean().default(false),
    testRecipients: Joi.array().items(baseSchemas.email).max(5),
    replyTo: baseSchemas.email,
    fromName: Joi.string().max(100),
    unsubscribeUrl: Joi.string().uri(),
    priority: Joi.string().valid('low', 'normal', 'high').default('normal')
  }).default({})
}).xor('userIds', 'filters').messages({
  'object.xor': 'Either userIds or filters must be provided, but not both'
});

/**
 * Operation status query validation schema
 */
const operationStatusSchema = Joi.object({
  operationId: Joi.string()
    .uuid()
    .required()
    .messages({
      'string.guid': 'Invalid operation ID format',
      'any.required': 'Operation ID is required'
    })
});

/**
 * Operation history query validation schema
 */
const operationHistorySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  type: Joi.string().valid(
    'import', 'update', 'delete', 'export', 'email',
    'role_assign', 'org_assign', 'status_change', 'password_reset'
  ),
  status: Joi.string().valid(
    'pending', 'processing', 'completed', 'failed', 'cancelled', 'scheduled'
  ),
  startDate: Joi.date().iso(),
  endDate: Joi.date().iso().when('startDate', {
    is: Joi.exist(),
    then: Joi.date().greater(Joi.ref('startDate'))
  }),
  sortBy: Joi.string().valid(
    'createdAt', 'completedAt', 'totalRecords', 'successfulRecords'
  ).default('createdAt'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

/**
 * Bulk role assignment validation schema
 */
const bulkRoleAssignmentSchema = Joi.object({
  userIds: baseSchemas.userIds,
  filters: baseSchemas.filters,
  roleId: baseSchemas.objectId.required().messages({
    'any.required': 'Role ID is required'
  }),
  notifyUsers: Joi.boolean().default(true),
  effectiveDate: Joi.date().iso().min('now'),
  reason: Joi.string().min(10).max(500)
}).xor('userIds', 'filters');

/**
 * Bulk organization assignment validation schema
 */
const bulkOrganizationAssignmentSchema = Joi.object({
  userIds: baseSchemas.userIds,
  filters: baseSchemas.filters,
  organizationId: baseSchemas.objectId.required().messages({
    'any.required': 'Organization ID is required'
  }),
  removeFromCurrent: Joi.boolean().default(false),
  notifyUsers: Joi.boolean().default(true),
  transferData: Joi.boolean().default(false),
  reason: Joi.string().min(10).max(500)
}).xor('userIds', 'filters');

/**
 * Bulk password reset validation schema
 */
const bulkPasswordResetSchema = Joi.object({
  userIds: baseSchemas.userIds,
  filters: baseSchemas.filters,
  reason: Joi.string().min(10).max(500).required().messages({
    'string.min': 'Password reset reason must be at least 10 characters',
    'any.required': 'Password reset reason is required'
  }),
  options: Joi.object({
    generateRandom: Joi.boolean().default(true),
    passwordLength: Joi.number().min(8).max(32).default(12),
    requireChange: Joi.boolean().default(true),
    notifyUsers: Joi.boolean().default(true),
    expireCurrentSessions: Joi.boolean().default(true),
    customPassword: Joi.when('generateRandom', {
      is: false,
      then: Joi.string().min(8).max(128).required(),
      otherwise: Joi.forbidden()
    })
  }).default({})
}).xor('userIds', 'filters');

/**
 * Custom validation functions
 */
const customValidators = {
  /**
   * Validate import file content
   * @param {Object} fileData - File data object
   * @returns {Object} Validation result
   */
  validateImportFile: (fileData) => {
    const errors = [];
    
    // Check file size
    if (fileData.size > AdminLimits.FILE_UPLOAD.MAX_IMPORT_SIZE) {
      errors.push(`File size exceeds maximum limit of ${AdminLimits.FILE_UPLOAD.MAX_IMPORT_SIZE / 1024 / 1024}MB`);
    }

    // Validate CSV content if applicable
    if (fileData.mimetype === 'text/csv') {
      const lines = fileData.content.split('\n');
      if (lines.length < 2) {
        errors.push('CSV file must contain at least a header row and one data row');
      }

      // Check for BOM
      if (fileData.content.charCodeAt(0) === 0xFEFF) {
        errors.push('CSV file contains BOM character which may cause parsing issues');
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  },

  /**
   * Validate bulk operation limits
   * @param {string} operationType - Type of operation
   * @param {number} count - Number of records
   * @returns {Object} Validation result
   */
  validateOperationLimits: (operationType, count) => {
    const limits = {
      import: AdminLimits.BULK_OPERATIONS.MAX_IMPORT_USERS,
      update: AdminLimits.BULK_OPERATIONS.MAX_UPDATE_USERS,
      delete: AdminLimits.BULK_OPERATIONS.MAX_DELETE_USERS,
      export: AdminLimits.BULK_OPERATIONS.MAX_EXPORT_USERS,
      email: AdminLimits.BULK_OPERATIONS.MAX_EMAIL_RECIPIENTS
    };

    const limit = limits[operationType] || AdminLimits.BULK_OPERATIONS.MAX_DEFAULT_USERS;

    return {
      valid: count <= limit,
      limit,
      error: count > limit ? `Operation exceeds maximum limit of ${limit} records` : null
    };
  },

  /**
   * Validate filter safety
   * @param {Object} filters - Filter object
   * @returns {Object} Validation result
   */
  validateFilterSafety: (filters) => {
    const warnings = [];

    // Check for potentially dangerous filters
    if (filters.status === 'deleted' && !filters.organization) {
      warnings.push('Filtering deleted users without organization constraint may return large dataset');
    }

    if (!filters.createdAfter && !filters.lastActiveAfter && Object.keys(filters).length < 2) {
      warnings.push('Broad filters may result in large dataset. Consider adding more constraints.');
    }

    return {
      safe: warnings.length === 0,
      warnings
    };
  }
};

/**
 * Validation middleware factory
 * @param {Object} schema - Joi schema to validate against
 * @returns {Function} Express middleware function
 */
const validateBulkOperation = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
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

    // Replace request body with validated and sanitized value
    req.body = value;
    next();
  };
};

// Export schemas and validators
module.exports = {
  schemas: {
    bulkImport: bulkImportSchema,
    bulkUpdate: bulkUpdateSchema,
    bulkDelete: bulkDeleteSchema,
    bulkExport: bulkExportSchema,
    bulkEmail: bulkEmailSchema,
    operationStatus: operationStatusSchema,
    operationHistory: operationHistorySchema,
    bulkRoleAssignment: bulkRoleAssignmentSchema,
    bulkOrganizationAssignment: bulkOrganizationAssignmentSchema,
    bulkPasswordReset: bulkPasswordResetSchema
  },
  validators: {
    ...customValidators
  },
  middleware: {
    validateBulkImport: validateBulkOperation(bulkImportSchema),
    validateBulkUpdate: validateBulkOperation(bulkUpdateSchema),
    validateBulkDelete: validateBulkOperation(bulkDeleteSchema),
    validateBulkExport: validateBulkOperation(bulkExportSchema),
    validateBulkEmail: validateBulkOperation(bulkEmailSchema),
    validateBulkRoleAssignment: validateBulkOperation(bulkRoleAssignmentSchema),
    validateBulkOrganizationAssignment: validateBulkOperation(bulkOrganizationAssignmentSchema),
    validateBulkPasswordReset: validateBulkOperation(bulkPasswordResetSchema)
  }
};