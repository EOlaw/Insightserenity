// server/admin/organization-management/validation/tenant-validation.js
/**
 * @file Tenant Validation
 * @description Validation schemas for tenant management operations
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');

// Constants
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');

// Custom validators
const customValidators = {
  objectId: (value, helpers) => {
    if (!mongoose.isValidObjectId(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  tenantId: (value, helpers) => {
    const tenantIdPattern = /^[a-zA-Z0-9_-]+$/;
    if (!tenantIdPattern.test(value)) {
      return helpers.error('string.pattern.base');
    }
    return value;
  },
  
  tenantCode: (value, helpers) => {
    const tenantCodePattern = /^[A-Z0-9]{3,10}$/;
    if (!tenantCodePattern.test(value)) {
      return helpers.error('string.pattern.base');
    }
    return value;
  },
  
  ipAddress: (value, helpers) => {
    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    
    if (!ipv4Pattern.test(value) && !ipv6Pattern.test(value)) {
      return helpers.error('string.pattern.base');
    }
    return value;
  },
  
  connectionString: (value, helpers) => {
    try {
      // Basic validation for MongoDB connection string
      if (!value.startsWith('mongodb://') && !value.startsWith('mongodb+srv://')) {
        throw new Error('Invalid connection string format');
      }
      return value;
    } catch {
      return helpers.error('any.invalid');
    }
  }
};

/**
 * Tenant configuration update validation
 */
const validateTenantConfigUpdate = (data) => {
  const schema = Joi.object({
    // Settings
    settings: Joi.object({
      name: Joi.string().min(2).max(100).optional(),
      locale: Joi.string().optional(),
      timezone: Joi.string().optional(),
      dateFormat: Joi.string().optional(),
      currency: Joi.string().length(3).uppercase().optional(),
      
      branding: Joi.object({
        primaryColor: Joi.string().pattern(/^#[0-9A-F]{6}$/i).optional(),
        secondaryColor: Joi.string().pattern(/^#[0-9A-F]{6}$/i).optional(),
        logo: Joi.string().uri().optional(),
        favicon: Joi.string().uri().optional(),
        customCSS: Joi.string().max(50000).optional()
      }).optional(),
      
      emailSettings: Joi.object({
        fromName: Joi.string().max(100).optional(),
        fromEmail: Joi.string().email().optional(),
        replyTo: Joi.string().email().optional(),
        footer: Joi.string().max(500).optional()
      }).optional(),
      
      dataLocation: Joi.string()
        .valid(...TENANT_CONSTANTS.DATA_LOCATIONS)
        .optional()
    }).optional(),
    
    // Features
    features: Joi.object().pattern(
      Joi.string(),
      Joi.boolean()
    ).optional(),
    
    // Integrations
    integrations: Joi.array().items(
      Joi.object({
        type: Joi.string().required(),
        enabled: Joi.boolean().required(),
        config: Joi.object().optional(),
        credentials: Joi.object().optional()
      })
    ).optional(),
    
    // Security Settings
    security: Joi.object({
      mfaRequired: Joi.boolean().optional(),
      mfaType: Joi.string().valid('totp', 'sms', 'email', 'all').optional(),
      
      passwordPolicy: Joi.object({
        minLength: Joi.number().min(8).max(128).optional(),
        requireUppercase: Joi.boolean().optional(),
        requireLowercase: Joi.boolean().optional(),
        requireNumbers: Joi.boolean().optional(),
        requireSpecialChars: Joi.boolean().optional(),
        expirationDays: Joi.number().min(0).max(365).optional(),
        preventReuse: Joi.number().min(0).max(24).optional()
      }).optional(),
      
      ipWhitelistEnabled: Joi.boolean().optional(),
      ipWhitelist: Joi.array().items(
        Joi.string().custom(customValidators.ipAddress)
      ).optional(),
      
      sessionTimeout: Joi.number().min(300000).max(86400000).optional(), // 5 min to 24 hours
      
      dataEncryption: Joi.object({
        enabled: Joi.boolean().optional(),
        algorithm: Joi.string().valid('AES-256-GCM', 'AES-256-CBC').optional()
      }).optional()
    }).optional(),
    
    // Customization
    customization: Joi.object({
      loginPage: Joi.object({
        backgroundImage: Joi.string().uri().optional(),
        welcomeMessage: Joi.string().max(200).optional(),
        customHTML: Joi.string().max(10000).optional()
      }).optional(),
      
      emailTemplates: Joi.object().pattern(
        Joi.string(),
        Joi.object({
          subject: Joi.string().max(200).optional(),
          body: Joi.string().max(50000).optional(),
          variables: Joi.array().items(Joi.string()).optional()
        })
      ).optional(),
      
      customFields: Joi.array().items(
        Joi.object({
          name: Joi.string().required(),
          type: Joi.string().valid('text', 'number', 'date', 'boolean', 'select').required(),
          label: Joi.string().required(),
          required: Joi.boolean().optional(),
          options: Joi.array().items(Joi.string()).when('type', {
            is: 'select',
            then: Joi.required()
          })
        })
      ).optional()
    }).optional(),
    
    // Validation Options
    validateChanges: Joi.boolean().default(true),
    applyImmediately: Joi.boolean().default(false),
    notifyUsers: Joi.boolean().default(true)
  }).min(1);
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Resource limits validation
 */
const validateResourceLimits = (data) => {
  const schema = Joi.object({
    users: Joi.number()
      .integer()
      .min(-1) // -1 means unlimited
      .optional()
      .messages({
        'number.min': 'User limit must be -1 (unlimited) or a positive number'
      }),
    
    storage: Joi.number()
      .min(-1) // -1 means unlimited
      .optional()
      .messages({
        'number.min': 'Storage limit must be -1 (unlimited) or a positive number'
      }),
    
    apiCalls: Joi.number()
      .integer()
      .min(-1)
      .optional()
      .messages({
        'number.min': 'API call limit must be -1 (unlimited) or a positive number'
      }),
    
    projects: Joi.number()
      .integer()
      .min(-1)
      .optional(),
    
    customDomains: Joi.number()
      .integer()
      .min(0)
      .optional(),
    
    bandwidth: Joi.number()
      .min(-1)
      .optional(),
    
    // Additional limits
    emailsPerMonth: Joi.number()
      .integer()
      .min(-1)
      .optional(),
    
    smsPerMonth: Joi.number()
      .integer()
      .min(-1)
      .optional(),
    
    // Limit metadata
    reason: Joi.string()
      .min(10)
      .max(500)
      .required()
      .messages({
        'string.min': 'Reason must be at least 10 characters',
        'any.required': 'Reason for limit change is required'
      }),
    
    expiresAt: Joi.date()
      .greater('now')
      .optional()
      .messages({
        'date.greater': 'Expiration date must be in the future'
      }),
    
    // Options
    enforceImmediately: Joi.boolean().default(false),
    skipNotifications: Joi.boolean().default(false),
    allowOverage: Joi.boolean().default(false)
  }).min(2); // At least one limit + reason
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Migration configuration validation
 */
const validateMigrationConfig = (data) => {
  const schema = Joi.object({
    type: Joi.string()
      .valid('infrastructure', 'data', 'full')
      .required()
      .messages({
        'any.required': 'Migration type is required'
      }),
    
    // Target configuration
    targetDatabase: Joi.string()
      .valid(...Object.values(TENANT_CONSTANTS.DATABASE_STRATEGIES))
      .when('type', {
        is: Joi.valid('infrastructure', 'full'),
        then: Joi.required()
      }),
    
    targetServer: Joi.string()
      .when('targetDatabase', {
        is: 'dedicated',
        then: Joi.required()
      }),
    
    targetRegion: Joi.string()
      .valid(...TENANT_CONSTANTS.DATA_LOCATIONS)
      .optional(),
    
    // Migration strategy
    strategy: Joi.string()
      .valid('incremental', 'full', 'selective')
      .default('incremental'),
    
    // Data selection (for selective migration)
    dataSelection: Joi.when('strategy', {
      is: 'selective',
      then: Joi.object({
        collections: Joi.array().items(Joi.string()).required(),
        dateRange: Joi.object({
          from: Joi.date().optional(),
          to: Joi.date().optional()
        }).optional(),
        excludeArchived: Joi.boolean().default(true)
      }).required()
    }),
    
    // Migration options
    requiresMaintenance: Joi.boolean().default(true),
    
    maintenanceWindow: Joi.when('requiresMaintenance', {
      is: true,
      then: Joi.object({
        start: Joi.date().greater('now').required(),
        duration: Joi.number().min(30).max(480).required() // 30 min to 8 hours
      }).required()
    }),
    
    // Validation and safety
    validateData: Joi.boolean().default(true),
    createBackup: Joi.boolean().default(true),
    rollbackOnError: Joi.boolean().default(true),
    
    // Performance options
    batchSize: Joi.number().integer().min(100).max(10000).default(1000),
    parallelWorkers: Joi.number().integer().min(1).max(10).default(3),
    
    // Notifications
    notifyUsers: Joi.boolean().default(true),
    notificationMessage: Joi.string().max(500).optional(),
    
    // Schedule options
    scheduleAt: Joi.date().greater('now').optional(),
    dryRun: Joi.boolean().default(false)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Maintenance mode configuration validation
 */
const validateMaintenanceConfig = (data) => {
  const schema = Joi.object({
    enabled: Joi.boolean().required(),
    
    config: Joi.when('enabled', {
      is: true,
      then: Joi.object({
        reason: Joi.string()
          .min(10)
          .max(200)
          .required()
          .messages({
            'string.min': 'Maintenance reason must be at least 10 characters',
            'any.required': 'Maintenance reason is required'
          }),
        
        estimatedDuration: Joi.number()
          .min(1)
          .max(1440) // Max 24 hours
          .required()
          .messages({
            'any.required': 'Estimated duration is required',
            'number.max': 'Maintenance duration cannot exceed 24 hours'
          }),
        
        allowedIPs: Joi.array()
          .items(Joi.string().custom(customValidators.ipAddress))
          .optional()
          .messages({
            'string.pattern.base': 'Invalid IP address format'
          }),
        
        customMessage: Joi.string()
          .max(500)
          .optional(),
        
        notifyUsers: Joi.boolean().default(true),
        
        notificationChannels: Joi.array()
          .items(Joi.string().valid('email', 'sms', 'in-app'))
          .default(['email', 'in-app']),
        
        autoEnd: Joi.boolean().default(false),
        
        autoEndAt: Joi.when('autoEnd', {
          is: true,
          then: Joi.date().greater('now').required()
        })
      }).required(),
      
      otherwise: Joi.forbidden()
    })
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Tenant reset validation
 */
const validateTenantReset = (data) => {
  const schema = Joi.object({
    confirmation: Joi.string()
      .required()
      .messages({
        'any.required': 'Confirmation code is required'
      }),
    
    resetUsers: Joi.boolean().default(false),
    resetData: Joi.boolean().default(true),
    resetConfiguration: Joi.boolean().default(false),
    resetLogs: Joi.boolean().default(false),
    
    // Data reset options
    dataTypes: Joi.when('resetData', {
      is: true,
      then: Joi.array()
        .items(Joi.string().valid(
          'projects',
          'tasks',
          'documents',
          'invoices',
          'payments',
          'analytics',
          'all'
        ))
        .min(1)
        .required()
    }),
    
    // User reset options
    userOptions: Joi.when('resetUsers', {
      is: true,
      then: Joi.object({
        keepOwner: Joi.boolean().default(true),
        keepAdmins: Joi.boolean().default(false),
        resetPasswords: Joi.boolean().default(true),
        clearSessions: Joi.boolean().default(true)
      }).optional()
    }),
    
    // Safety options
    createBackup: Joi.boolean().default(true),
    
    backupOptions: Joi.when('createBackup', {
      is: true,
      then: Joi.object({
        includeFiles: Joi.boolean().default(true),
        compress: Joi.boolean().default(true),
        encrypt: Joi.boolean().default(true),
        retentionDays: Joi.number().integer().min(7).max(365).default(30)
      }).optional()
    }),
    
    // Reset metadata
    reason: Joi.string()
      .min(20)
      .max(500)
      .required()
      .messages({
        'string.min': 'Reset reason must be at least 20 characters',
        'any.required': 'Reset reason is required'
      }),
    
    requestedBy: Joi.string().max(200).optional(),
    
    // Final confirmation
    acknowledgeDataLoss: Joi.boolean()
      .valid(true)
      .required()
      .messages({
        'any.only': 'You must acknowledge potential data loss',
        'any.required': 'Data loss acknowledgment is required'
      })
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Clone configuration validation
 */
const validateCloneConfig = (data) => {
  const schema = Joi.object({
    sourceTenantId: Joi.string()
      .custom(customValidators.tenantId)
      .required()
      .messages({
        'any.required': 'Source tenant ID is required',
        'string.pattern.base': 'Invalid source tenant ID format'
      }),
    
    targetTenantId: Joi.string()
      .custom(customValidators.tenantId)
      .required()
      .invalid(Joi.ref('sourceTenantId'))
      .messages({
        'any.required': 'Target tenant ID is required',
        'string.pattern.base': 'Invalid target tenant ID format',
        'any.invalid': 'Source and target tenants must be different'
      }),
    
    config: Joi.object({
      includeSettings: Joi.boolean().default(true),
      includeFeatures: Joi.boolean().default(true),
      includeIntegrations: Joi.boolean().default(false),
      includeSecurity: Joi.boolean().default(false),
      includeCustomization: Joi.boolean().default(true),
      includeResourceLimits: Joi.boolean().default(false),
      
      // Integration options
      integrationOptions: Joi.when('includeIntegrations', {
        is: true,
        then: Joi.object({
          includeCredentials: Joi.boolean().default(false),
          resetApiKeys: Joi.boolean().default(true),
          verifyEndpoints: Joi.boolean().default(true)
        }).optional()
      }),
      
      // Security options
      securityOptions: Joi.when('includeSecurity', {
        is: true,
        then: Joi.object({
          resetMfaSettings: Joi.boolean().default(true),
          clearIpWhitelist: Joi.boolean().default(false),
          regenerateEncryptionKeys: Joi.boolean().default(true)
        }).optional()
      })
    }).required(),
    
    // Clone options
    overwriteExisting: Joi.boolean().default(false),
    backupTarget: Joi.boolean().default(true),
    validateCompatibility: Joi.boolean().default(true)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Bulk tenant update validation
 */
const validateBulkTenantUpdate = (data) => {
  const schema = Joi.object({
    tenantIds: Joi.array()
      .items(Joi.string().custom(customValidators.tenantId))
      .min(1)
      .max(100)
      .required()
      .messages({
        'array.min': 'At least one tenant ID is required',
        'array.max': 'Maximum 100 tenants can be updated at once'
      }),
    
    updates: Joi.object({
      settings: Joi.object().optional(),
      features: Joi.object().optional(),
      security: Joi.object().optional(),
      resourceLimits: Joi.object().optional()
    }).min(1).required(),
    
    // Update options
    skipFailures: Joi.boolean().default(false),
    validateEach: Joi.boolean().default(true),
    applyInBatches: Joi.boolean().default(true),
    batchSize: Joi.number().integer().min(1).max(20).default(10),
    
    // Notification options
    notifyUsers: Joi.boolean().default(true),
    notificationTemplate: Joi.string().optional(),
    
    // Safety options
    dryRun: Joi.boolean().default(false),
    createBackups: Joi.boolean().default(false)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Tenant backup configuration validation
 */
const validateTenantBackupConfig = (data) => {
  const schema = Joi.object({
    type: Joi.string()
      .valid('full', 'incremental', 'selective')
      .default('full'),
    
    // Backup content
    includeDatabase: Joi.boolean().default(true),
    includeFiles: Joi.boolean().default(true),
    includeConfiguration: Joi.boolean().default(true),
    includeLogs: Joi.boolean().default(false),
    
    // Selective backup options
    selectiveOptions: Joi.when('type', {
      is: 'selective',
      then: Joi.object({
        collections: Joi.array().items(Joi.string()).optional(),
        dateRange: Joi.object({
          from: Joi.date().optional(),
          to: Joi.date().default('now')
        }).optional(),
        fileTypes: Joi.array().items(Joi.string()).optional()
      }).optional()
    }),
    
    // Backup options
    compress: Joi.boolean().default(true),
    
    compressionLevel: Joi.when('compress', {
      is: true,
      then: Joi.number().integer().min(1).max(9).default(6)
    }),
    
    encrypt: Joi.boolean().default(true),
    
    encryptionOptions: Joi.when('encrypt', {
      is: true,
      then: Joi.object({
        algorithm: Joi.string().valid('AES-256-GCM', 'AES-256-CBC').default('AES-256-GCM'),
        generateNewKey: Joi.boolean().default(false)
      }).optional()
    }),
    
    // Storage options
    storageLocation: Joi.string()
      .valid('local', 's3', 'azure', 'gcs')
      .default('s3'),
    
    storageOptions: Joi.object({
      bucket: Joi.string().when('$storageLocation', {
        is: Joi.valid('s3', 'gcs'),
        then: Joi.required()
      }),
      container: Joi.string().when('$storageLocation', {
        is: 'azure',
        then: Joi.required()
      }),
      path: Joi.string().optional(),
      region: Joi.string().optional()
    }).optional(),
    
    // Retention
    retentionDays: Joi.number()
      .integer()
      .min(1)
      .max(3650) // 10 years
      .default(30),
    
    // Metadata
    description: Joi.string().max(500).optional(),
    tags: Joi.array().items(Joi.string()).max(10).optional(),
    
    // Schedule options
    schedule: Joi.object({
      frequency: Joi.string().valid('daily', 'weekly', 'monthly').required(),
      time: Joi.string().pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).required(), // HH:MM format
      dayOfWeek: Joi.number().integer().min(0).max(6).when('frequency', {
        is: 'weekly',
        then: Joi.required()
      }),
      dayOfMonth: Joi.number().integer().min(1).max(31).when('frequency', {
        is: 'monthly',
        then: Joi.required()
      })
    }).optional()
  }).custom((value, helpers) => {
    // Additional validation for storage options
    if (value.storageLocation !== 'local' && !value.storageOptions) {
      return helpers.error('any.required', { 
        message: 'Storage options are required for non-local storage' 
      });
    }
    return value;
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Tenant restore validation
 */
const validateTenantRestore = (data) => {
  const schema = Joi.object({
    backupId: Joi.string()
      .custom(customValidators.objectId)
      .required()
      .messages({
        'any.required': 'Backup ID is required'
      }),
    
    // Restore options
    restoreData: Joi.boolean().default(true),
    restoreConfiguration: Joi.boolean().default(true),
    restoreUsers: Joi.boolean().default(false),
    restoreFiles: Joi.boolean().default(true),
    
    // Selective restore
    selectiveRestore: Joi.object({
      collections: Joi.array().items(Joi.string()).optional(),
      configSections: Joi.array().items(
        Joi.string().valid('settings', 'features', 'security', 'integrations')
      ).optional(),
      dateRange: Joi.object({
        from: Joi.date().optional(),
        to: Joi.date().optional()
      }).optional()
    }).optional(),
    
    // Conflict resolution
    conflictResolution: Joi.string()
      .valid('overwrite', 'skip', 'merge')
      .default('overwrite'),
    
    mergeStrategy: Joi.when('conflictResolution', {
      is: 'merge',
      then: Joi.object({
        data: Joi.string().valid('newer_wins', 'older_wins', 'manual').default('newer_wins'),
        configuration: Joi.string().valid('backup', 'current', 'manual').default('backup')
      }).required()
    }),
    
    // Safety options
    createNewBackup: Joi.boolean().default(true),
    validateIntegrity: Joi.boolean().default(true),
    testRestore: Joi.boolean().default(false),
    
    // Confirmation
    confirmation: Joi.object({
      backupDate: Joi.date().required(),
      tenantCode: Joi.string().custom(customValidators.tenantCode).required(),
      acknowledgeDataChange: Joi.boolean().valid(true).required()
    }).required()
  });
  
  return schema.validate(data, { abortEarly: false });
};

module.exports = {
  validateTenantConfigUpdate,
  validateResourceLimits,
  validateMigrationConfig,
  validateMaintenanceConfig,
  validateTenantReset,
  validateCloneConfig,
  validateBulkTenantUpdate,
  validateTenantBackupConfig,
  validateTenantRestore
};