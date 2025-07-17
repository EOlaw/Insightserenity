// server/admin/organization-management/validation/organization-management-validation.js
/**
 * @file Organization Management Validation
 * @description Validation schemas for organization management operations
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');

// Constants
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');
const constants = require('../../../shared/config/constants');

// Custom validation helpers
const customValidators = {
  objectId: (value, helpers) => {
    if (!mongoose.isValidObjectId(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  phoneNumber: (value, helpers) => {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    if (!phoneRegex.test(value)) {
      return helpers.error('string.pattern.base');
    }
    return value;
  },
  
  timezone: (value, helpers) => {
    const validTimezones = Intl.supportedValuesOf('timeZone');
    if (!validTimezones.includes(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  url: (value, helpers) => {
    try {
      new URL(value);
      return value;
    } catch {
      return helpers.error('string.uri');
    }
  }
};

/**
 * Organization creation validation schema
 */
const validateOrganizationCreate = (data) => {
  const schema = Joi.object({
    // Basic Information
    name: Joi.string()
      .min(2)
      .max(100)
      .trim()
      .required()
      .messages({
        'string.min': 'Organization name must be at least 2 characters',
        'string.max': 'Organization name cannot exceed 100 characters',
        'any.required': 'Organization name is required'
      }),
    
    displayName: Joi.string()
      .min(2)
      .max(100)
      .trim()
      .optional(),
    
    description: Joi.string()
      .max(500)
      .trim()
      .optional()
      .allow(''),
    
    slug: Joi.string()
      .lowercase()
      .trim()
      .pattern(/^[a-z0-9-]+$/)
      .optional()
      .messages({
        'string.pattern.base': 'Slug can only contain lowercase letters, numbers, and hyphens'
      }),
    
    // Owner Information
    ownerId: Joi.string()
      .custom(customValidators.objectId)
      .required()
      .messages({
        'any.invalid': 'Invalid owner ID format',
        'any.required': 'Owner ID is required'
      }),
    
    // Business Information
    businessInfo: Joi.object({
      type: Joi.string()
        .valid(...Object.values(TENANT_CONSTANTS.BUSINESS_TYPES))
        .default('startup'),
      
      industry: Joi.string()
        .valid(...Object.values(TENANT_CONSTANTS.INDUSTRIES))
        .optional(),
      
      size: Joi.string()
        .valid(...Object.values(TENANT_CONSTANTS.COMPANY_SIZES))
        .default('small'),
      
      foundedYear: Joi.number()
        .integer()
        .min(1800)
        .max(new Date().getFullYear())
        .optional(),
      
      registrationNumber: Joi.string()
        .max(50)
        .optional(),
      
      taxId: Joi.string()
        .max(50)
        .optional()
    }).optional(),
    
    // Contact Information
    headquarters: Joi.object({
      address: Joi.object({
        street: Joi.string().max(200).optional(),
        city: Joi.string().max(100).optional(),
        state: Joi.string().max(100).optional(),
        postalCode: Joi.string().max(20).optional(),
        country: Joi.string().length(2).uppercase().required()
      }).optional(),
      
      phone: Joi.string()
        .custom(customValidators.phoneNumber)
        .optional()
        .messages({
          'string.pattern.base': 'Please provide a valid phone number'
        }),
      
      email: Joi.string()
        .email()
        .lowercase()
        .required()
        .messages({
          'string.email': 'Please provide a valid email address',
          'any.required': 'Contact email is required'
        }),
      
      timezone: Joi.string()
        .custom(customValidators.timezone)
        .default('UTC')
        .messages({
          'any.invalid': 'Invalid timezone'
        })
    }).required(),
    
    // Platform Configuration
    platformConfig: Joi.object({
      tier: Joi.string()
        .valid('starter', 'growth', 'professional', 'enterprise')
        .default('starter'),
      
      features: Joi.object().pattern(
        Joi.string(),
        Joi.boolean()
      ).optional(),
      
      modules: Joi.object().pattern(
        Joi.string(),
        Joi.boolean()
      ).optional()
    }).optional(),
    
    // Subscription Configuration
    subscription: Joi.object({
      plan: Joi.object({
        id: Joi.string().required(),
        name: Joi.string().required(),
        interval: Joi.string().valid('monthly', 'yearly').default('monthly')
      }).optional(),
      
      status: Joi.string()
        .valid(...Object.values(constants.BILLING.SUBSCRIPTION_STATUS))
        .default('trial'),
      
      trialDays: Joi.number()
        .integer()
        .min(0)
        .max(90)
        .default(14)
    }).optional(),
    
    // Domain Configuration
    domains: Joi.object({
      subdomain: Joi.string()
        .lowercase()
        .pattern(/^[a-z0-9-]+$/)
        .optional()
        .messages({
          'string.pattern.base': 'Subdomain can only contain lowercase letters, numbers, and hyphens'
        }),
      
      customDomains: Joi.array().items(
        Joi.string().custom(customValidators.url)
      ).optional()
    }).optional(),
    
    // Initial Settings
    settings: Joi.object({
      branding: Joi.object({
        primaryColor: Joi.string().pattern(/^#[0-9A-F]{6}$/i).optional(),
        logo: Joi.string().uri().optional(),
        favicon: Joi.string().uri().optional()
      }).optional(),
      
      locale: Joi.string().default('en'),
      
      dateFormat: Joi.string().default('MM/DD/YYYY'),
      
      currency: Joi.string()
        .length(3)
        .uppercase()
        .default('USD')
    }).optional(),
    
    // Initial Resource Limits
    limits: Joi.object({
      users: Joi.number().integer().min(-1).default(-1),
      storage: Joi.number().min(-1).default(-1),
      apiCallsPerMonth: Joi.number().integer().min(-1).default(-1),
      projects: Joi.number().integer().min(-1).default(-1),
      customDomains: Joi.number().integer().min(0).default(1)
    }).optional(),
    
    // Metadata
    metadata: Joi.object().pattern(
      Joi.string(),
      Joi.any()
    ).optional(),
    
    // Admin Creation Options
    autoVerify: Joi.boolean().default(false),
    skipNotifications: Joi.boolean().default(false),
    setupInfrastructure: Joi.boolean().default(true),
    initialAdmins: Joi.array().items(
      Joi.string().custom(customValidators.objectId)
    ).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization update validation schema
 */
const validateOrganizationUpdate = (data) => {
  const schema = Joi.object({
    // Basic Information (all optional for updates)
    name: Joi.string()
      .min(2)
      .max(100)
      .trim()
      .optional(),
    
    displayName: Joi.string()
      .min(2)
      .max(100)
      .trim()
      .optional(),
    
    description: Joi.string()
      .max(500)
      .trim()
      .optional()
      .allow(''),
    
    // Business Information
    businessInfo: Joi.object({
      type: Joi.string()
        .valid(...Object.values(TENANT_CONSTANTS.BUSINESS_TYPES))
        .optional(),
      
      industry: Joi.string()
        .valid(...Object.values(TENANT_CONSTANTS.INDUSTRIES))
        .optional(),
      
      size: Joi.string()
        .valid(...Object.values(TENANT_CONSTANTS.COMPANY_SIZES))
        .optional(),
      
      foundedYear: Joi.number()
        .integer()
        .min(1800)
        .max(new Date().getFullYear())
        .optional(),
      
      registrationNumber: Joi.string()
        .max(50)
        .optional(),
      
      taxId: Joi.string()
        .max(50)
        .optional()
    }).optional(),
    
    // Contact Information
    headquarters: Joi.object({
      address: Joi.object({
        street: Joi.string().max(200).optional(),
        city: Joi.string().max(100).optional(),
        state: Joi.string().max(100).optional(),
        postalCode: Joi.string().max(20).optional(),
        country: Joi.string().length(2).uppercase().optional()
      }).optional(),
      
      phone: Joi.string()
        .custom(customValidators.phoneNumber)
        .optional(),
      
      email: Joi.string()
        .email()
        .lowercase()
        .optional(),
      
      timezone: Joi.string()
        .custom(customValidators.timezone)
        .optional()
    }).optional(),
    
    // Platform Configuration
    platformConfig: Joi.object({
      features: Joi.object().pattern(
        Joi.string(),
        Joi.boolean()
      ).optional(),
      
      modules: Joi.object().pattern(
        Joi.string(),
        Joi.boolean()
      ).optional()
    }).optional(),
    
    // Settings
    settings: Joi.object({
      branding: Joi.object({
        primaryColor: Joi.string().pattern(/^#[0-9A-F]{6}$/i).optional(),
        logo: Joi.string().uri().optional(),
        favicon: Joi.string().uri().optional()
      }).optional(),
      
      locale: Joi.string().optional(),
      dateFormat: Joi.string().optional(),
      currency: Joi.string().length(3).uppercase().optional()
    }).optional(),
    
    // Resource Limits (requires special permission)
    limits: Joi.object({
      users: Joi.number().integer().min(-1).optional(),
      storage: Joi.number().min(-1).optional(),
      apiCallsPerMonth: Joi.number().integer().min(-1).optional(),
      projects: Joi.number().integer().min(-1).optional(),
      customDomains: Joi.number().integer().min(0).optional()
    }).optional(),
    
    // Status Changes (requires special permission)
    status: Joi.object({
      active: Joi.boolean().optional(),
      verified: Joi.boolean().optional(),
      locked: Joi.boolean().optional()
    }).optional(),
    
    // Metadata
    metadata: Joi.object().pattern(
      Joi.string(),
      Joi.any()
    ).optional(),
    
    // Update Options
    validateLimits: Joi.boolean().default(true),
    skipNotifications: Joi.boolean().default(false)
  }).min(1); // At least one field must be updated
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization suspension validation schema
 */
const validateSuspension = (data) => {
  const schema = Joi.object({
    reason: Joi.object({
      description: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Suspension reason must be at least 10 characters',
          'string.max': 'Suspension reason cannot exceed 500 characters',
          'any.required': 'Suspension reason is required'
        }),
      
      category: Joi.string()
        .valid(
          'payment_issue',
          'policy_violation',
          'security_concern',
          'legal_requirement',
          'administrative',
          'other'
        )
        .required(),
      
      details: Joi.string()
        .max(1000)
        .optional(),
      
      expectedDuration: Joi.string()
        .valid('temporary', 'indefinite', 'pending_resolution')
        .default('indefinite'),
      
      autoLiftDate: Joi.date()
        .greater('now')
        .optional()
        .when('expectedDuration', {
          is: 'temporary',
          then: Joi.required()
        }),
      
      notes: Joi.string()
        .max(2000)
        .optional()
    }).required(),
    
    // Suspension Options
    maintainSessions: Joi.boolean().default(false),
    skipNotifications: Joi.boolean().default(false),
    notifyUsers: Joi.boolean().default(true),
    preserveData: Joi.boolean().default(true)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Ownership transfer validation schema
 */
const validateOwnershipTransfer = (data) => {
  const schema = Joi.object({
    newOwnerId: Joi.string()
      .custom(customValidators.objectId)
      .required()
      .messages({
        'any.invalid': 'Invalid new owner ID format',
        'any.required': 'New owner ID is required'
      }),
    
    reason: Joi.string()
      .min(10)
      .max(500)
      .required()
      .messages({
        'string.min': 'Transfer reason must be at least 10 characters',
        'any.required': 'Transfer reason is required'
      }),
    
    // Transfer Options
    transferAdminRights: Joi.boolean().default(true),
    transferBillingOwnership: Joi.boolean().default(true),
    keepPreviousOwnerAsAdmin: Joi.boolean().default(true),
    notifyAllAdmins: Joi.boolean().default(true),
    skipNotifications: Joi.boolean().default(false),
    validateNewOwner: Joi.boolean().default(true),
    
    // Additional Information
    notes: Joi.string().max(1000).optional(),
    effectiveDate: Joi.date().optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Bulk operation validation schema
 */
const validateBulkOperation = (data) => {
  const schema = Joi.object({
    organizationIds: Joi.array()
      .items(Joi.string().custom(customValidators.objectId))
      .min(1)
      .max(200)
      .required()
      .messages({
        'array.min': 'At least one organization ID is required',
        'array.max': 'Maximum 200 organizations can be processed at once',
        'any.required': 'Organization IDs are required'
      }),
    
    operation: Joi.string()
      .valid('suspend', 'activate', 'delete', 'update', 'export')
      .required(),
    
    // Operation-specific data
    reason: Joi.when('operation', {
      is: Joi.valid('suspend', 'delete'),
      then: Joi.object({
        description: Joi.string().min(10).max(500).required(),
        category: Joi.string().required()
      }).required(),
      otherwise: Joi.optional()
    }),
    
    updates: Joi.when('operation', {
      is: 'update',
      then: Joi.object().required(),
      otherwise: Joi.forbidden()
    }),
    
    // Bulk Options
    skipFailures: Joi.boolean().default(false),
    skipNotifications: Joi.boolean().default(false),
    batchSize: Joi.number().integer().min(1).max(50).default(10),
    delayBetweenBatches: Joi.number().integer().min(0).max(5000).default(100),
    
    // Safety Options
    confirmationCode: Joi.when('operation', {
      is: 'delete',
      then: Joi.string().required(),
      otherwise: Joi.optional()
    }),
    
    dryRun: Joi.boolean().default(false)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization search validation schema
 */
const validateOrganizationSearch = (data) => {
  const schema = Joi.object({
    query: Joi.string()
      .min(2)
      .max(100)
      .required()
      .messages({
        'string.min': 'Search query must be at least 2 characters',
        'any.required': 'Search query is required'
      }),
    
    fields: Joi.array()
      .items(Joi.string().valid(
        'name',
        'displayName',
        'email',
        'tenantCode',
        'description',
        'ownerName',
        'ownerEmail'
      ))
      .default(['name', 'email', 'tenantCode']),
    
    filters: Joi.object({
      status: Joi.string().valid('active', 'inactive', 'suspended', 'all').optional(),
      plan: Joi.string().optional(),
      industry: Joi.string().optional(),
      country: Joi.string().length(2).uppercase().optional(),
      createdAfter: Joi.date().optional(),
      createdBefore: Joi.date().optional()
    }).optional(),
    
    fuzzy: Joi.boolean().default(true),
    limit: Joi.number().integer().min(1).max(100).default(20),
    includeDeleted: Joi.boolean().default(false)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization import validation schema
 */
const validateOrganizationImport = (data) => {
  const schema = Joi.object({
    format: Joi.string()
      .valid('csv', 'json', 'excel')
      .default('csv'),
    
    mapping: Joi.object({
      name: Joi.string().required(),
      email: Joi.string().required(),
      owner: Joi.string().optional(),
      plan: Joi.string().optional(),
      country: Joi.string().optional()
    }).when('format', {
      is: 'csv',
      then: Joi.required()
    }),
    
    options: Joi.object({
      validateOnly: Joi.boolean().default(false),
      updateExisting: Joi.boolean().default(false),
      skipErrors: Joi.boolean().default(false),
      defaultPlan: Joi.string().default('starter'),
      defaultCountry: Joi.string().length(2).uppercase().default('US'),
      sendWelcomeEmails: Joi.boolean().default(false),
      assignToAdmin: Joi.string().custom(customValidators.objectId).optional()
    }).optional(),
    
    batchSize: Joi.number().integer().min(1).max(100).default(10)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization export validation schema
 */
const validateOrganizationExport = (data) => {
  const schema = Joi.object({
    format: Joi.string()
      .valid('csv', 'json', 'excel', 'pdf')
      .default('csv'),
    
    fields: Joi.array()
      .items(Joi.string())
      .min(1)
      .optional(),
    
    filters: Joi.object({
      status: Joi.string().optional(),
      plan: Joi.string().optional(),
      createdFrom: Joi.date().optional(),
      createdTo: Joi.date().optional(),
      industry: Joi.string().optional(),
      country: Joi.string().optional()
    }).optional(),
    
    includeRelated: Joi.boolean().default(false),
    includeSensitive: Joi.boolean().default(false),
    
    options: Joi.object({
      timezone: Joi.string().default('UTC'),
      dateFormat: Joi.string().default('YYYY-MM-DD'),
      includHeaders: Joi.boolean().default(true),
      compress: Joi.boolean().default(false)
    }).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization clone validation schema
 */
const validateOrganizationClone = (data) => {
  const schema = Joi.object({
    name: Joi.string()
      .min(2)
      .max(100)
      .required()
      .messages({
        'any.required': 'New organization name is required'
      }),
    
    options: Joi.object({
      cloneData: Joi.boolean().default(false),
      cloneUsers: Joi.boolean().default(false),
      cloneConfiguration: Joi.boolean().default(true),
      cloneIntegrations: Joi.boolean().default(false),
      cloneBilling: Joi.boolean().default(false),
      
      dataOptions: Joi.when('cloneData', {
        is: true,
        then: Joi.object({
          projects: Joi.boolean().default(true),
          tasks: Joi.boolean().default(true),
          documents: Joi.boolean().default(false),
          excludeArchived: Joi.boolean().default(true)
        }).optional()
      }),
      
      userOptions: Joi.when('cloneUsers', {
        is: true,
        then: Joi.object({
          includeInactive: Joi.boolean().default(false),
          resetPasswords: Joi.boolean().default(true),
          notifyUsers: Joi.boolean().default(true)
        }).optional()
      })
    }).optional(),
    
    newOwnerId: Joi.string()
      .custom(customValidators.objectId)
      .optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization merge validation schema
 */
const validateOrganizationMerge = (data) => {
  const schema = Joi.object({
    sourceId: Joi.string()
      .custom(customValidators.objectId)
      .required()
      .messages({
        'any.required': 'Source organization ID is required'
      }),
    
    targetId: Joi.string()
      .custom(customValidators.objectId)
      .required()
      .invalid(Joi.ref('sourceId'))
      .messages({
        'any.required': 'Target organization ID is required',
        'any.invalid': 'Source and target organizations must be different'
      }),
    
    mergeOptions: Joi.object({
      mergeUsers: Joi.boolean().default(true),
      mergeData: Joi.boolean().default(true),
      mergeSubscriptions: Joi.boolean().default(false),
      keepSource: Joi.boolean().default(false),
      
      conflictResolution: Joi.object({
        users: Joi.string().valid('keep_target', 'keep_source', 'merge_both').default('keep_target'),
        data: Joi.string().valid('keep_target', 'keep_source', 'merge_both').default('merge_both'),
        settings: Joi.string().valid('keep_target', 'keep_source', 'merge_custom').default('keep_target')
      }).optional(),
      
      userMergeStrategy: Joi.when('mergeUsers', {
        is: true,
        then: Joi.object({
          deduplicateByEmail: Joi.boolean().default(true),
          preserveRoles: Joi.string().valid('highest', 'target', 'source').default('highest'),
          notifyAffectedUsers: Joi.boolean().default(true)
        }).optional()
      })
    }).required(),
    
    confirmation: Joi.object({
      sourceOrganizationName: Joi.string().required(),
      targetOrganizationName: Joi.string().required(),
      acknowledgeDataLoss: Joi.boolean().valid(true).required()
    }).required()
  });
  
  return schema.validate(data, { abortEarly: false });
};

module.exports = {
  validateOrganizationCreate,
  validateOrganizationUpdate,
  validateSuspension,
  validateOwnershipTransfer,
  validateBulkOperation,
  validateOrganizationSearch,
  validateOrganizationImport,
  validateOrganizationExport,
  validateOrganizationClone,
  validateOrganizationMerge
};