// server/admin/super-admin/validation/system-settings-validation.js
/**
 * @file System Settings Validation
 * @description Validation schemas for system configuration and settings management
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');

// Shared validation utilities
const { objectId, email, url } = require('../../../shared/validation/common-validators');

// Constants
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Custom validators for system settings
 */
const customValidators = {
  /**
   * Validate setting key format
   */
  settingKey: () => Joi.string()
    .pattern(/^[a-zA-Z][a-zA-Z0-9._-]*[a-zA-Z0-9]$/)
    .min(3)
    .max(100)
    .messages({
      'string.pattern.base': 'Setting key must start with a letter and contain only letters, numbers, dots, underscores, and hyphens',
      'string.min': 'Setting key must be at least 3 characters',
      'string.max': 'Setting key cannot exceed 100 characters'
    }),

  /**
   * Validate setting value based on type
   */
  settingValue: (valueType) => {
    switch (valueType) {
      case 'string':
        return Joi.string().max(5000);
      case 'number':
        return Joi.number();
      case 'boolean':
        return Joi.boolean();
      case 'json':
        return Joi.object();
      case 'array':
        return Joi.array();
      case 'date':
        return Joi.date();
      case 'encrypted':
        return Joi.string().max(1000);
      default:
        return Joi.any();
    }
  },

  /**
   * Validate feature flag key
   */
  featureFlagKey: () => Joi.string()
    .pattern(/^[A-Z][A-Z0-9_]*$/)
    .min(3)
    .max(50)
    .messages({
      'string.pattern.base': 'Feature flag key must be uppercase with underscores',
      'string.min': 'Feature flag key must be at least 3 characters',
      'string.max': 'Feature flag key cannot exceed 50 characters'
    })
};

/**
 * System Settings Validation Schemas
 */
const SystemSettingsValidation = {
  /**
   * Update setting validation
   */
  updateSetting: {
    params: Joi.object({
      settingKey: customValidators.settingKey().required()
    }),
    
    body: Joi.object({
      value: Joi.any()
        .required()
        .messages({
          'any.required': 'Setting value is required'
        }),
      
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Update reason must be at least 10 characters',
          'any.required': 'Update reason is required for audit purposes'
        }),
      
      effectiveDate: Joi.date()
        .min('now')
        .default(() => new Date()),
      
      testMode: Joi.boolean()
        .default(false),
      
      acknowledgeImpact: Joi.boolean()
        .when('$requiresAcknowledgment', {
          is: true,
          then: Joi.required().valid(true),
          otherwise: Joi.optional()
        })
    })
  },

  /**
   * Bulk update settings validation
   */
  bulkUpdateSettings: {
    body: Joi.object({
      updates: Joi.array()
        .items(Joi.object({
          key: customValidators.settingKey().required(),
          value: Joi.any().required()
        }))
        .min(1)
        .max(AdminLimits.BULK_OPERATIONS.MAX_SETTINGS)
        .unique('key')
        .required()
        .messages({
          'array.min': 'At least one setting update is required',
          'array.max': `Cannot update more than ${AdminLimits.BULK_OPERATIONS.MAX_SETTINGS} settings at once`,
          'any.required': 'Updates array is required'
        }),
      
      options: Joi.object({
        reason: Joi.string()
          .min(20)
          .max(1000)
          .required()
          .messages({
            'string.min': 'Bulk update reason must be at least 20 characters',
            'any.required': 'Reason is required for bulk updates'
          }),
        
        testMode: Joi.boolean()
          .default(false),
        
        stopOnError: Joi.boolean()
          .default(true),
        
        createBackup: Joi.boolean()
          .default(true),
        
        validateDependencies: Joi.boolean()
          .default(true)
      }).required()
    })
  },

  /**
   * Reset setting validation
   */
  resetSetting: {
    params: Joi.object({
      settingKey: customValidators.settingKey().required()
    }),
    
    body: Joi.object({
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Reset reason must be at least 10 characters',
          'any.required': 'Reset reason is required'
        }),
      
      notifyServices: Joi.boolean()
        .default(true)
    })
  },

  /**
   * Create feature flag validation
   */
  createFeatureFlag: {
    body: Joi.object({
      key: customValidators.featureFlagKey()
        .required()
        .messages({
          'any.required': 'Feature flag key is required'
        }),
      
      displayName: Joi.string()
        .min(3)
        .max(100)
        .required(),
      
      description: Joi.string()
        .min(10)
        .max(500)
        .required(),
      
      type: Joi.string()
        .valid('boolean', 'percentage', 'variant', 'permission')
        .default('boolean'),
      
      defaultValue: Joi.when('type', {
        switch: [
          {
            is: 'boolean',
            then: Joi.boolean().required()
          },
          {
            is: 'percentage',
            then: Joi.number().min(0).max(100).required()
          },
          {
            is: 'variant',
            then: Joi.string().required()
          },
          {
            is: 'permission',
            then: Joi.array().items(Joi.string()).required()
          }
        ]
      }),
      
      environments: Joi.object({
        development: Joi.object({
          enabled: Joi.boolean().default(true),
          value: Joi.any(),
          rolloutPercentage: Joi.number().min(0).max(100),
          targetGroups: Joi.array().items(Joi.string())
        }),
        staging: Joi.object({
          enabled: Joi.boolean().default(false),
          value: Joi.any(),
          rolloutPercentage: Joi.number().min(0).max(100),
          targetGroups: Joi.array().items(Joi.string())
        }),
        production: Joi.object({
          enabled: Joi.boolean().default(false),
          value: Joi.any(),
          rolloutPercentage: Joi.number().min(0).max(100),
          targetGroups: Joi.array().items(Joi.string())
        })
      }).default({}),
      
      metadata: Joi.object({
        jiraTicket: Joi.string(),
        owner: email(),
        team: Joi.string(),
        category: Joi.string()
      }).default({})
    })
  },

  /**
   * Update feature flag validation
   */
  updateFeatureFlag: {
    params: Joi.object({
      flagKey: customValidators.featureFlagKey().required()
    }),
    
    body: Joi.object({
      environment: Joi.string()
        .valid('development', 'staging', 'production')
        .default('production'),
      
      enabled: Joi.boolean(),
      
      rolloutPercentage: Joi.number()
        .min(0)
        .max(100),
      
      targetGroups: Joi.array()
        .items(Joi.string())
        .max(100),
      
      value: Joi.any()
        .when('enabled', {
          is: true,
          then: Joi.optional(),
          otherwise: Joi.forbidden()
        }),
      
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Update reason must be at least 10 characters',
          'any.required': 'Update reason is required for feature flag changes'
        }),
      
      scheduledActivation: Joi.date()
        .min('now')
        .when('enabled', {
          is: true,
          then: Joi.optional(),
          otherwise: Joi.forbidden()
        })
    })
  },

  /**
   * Import configuration validation
   */
  importConfiguration: {
    body: Joi.object({
      data: Joi.alternatives()
        .try(
          Joi.string(), // Encrypted or JSON string
          Joi.object()  // Parsed configuration object
        )
        .required()
        .messages({
          'any.required': 'Configuration data is required'
        }),
      
      options: Joi.object({
        encrypted: Joi.boolean()
          .default(false),
        
        merge: Joi.boolean()
          .default(true),
        
        overwrite: Joi.boolean()
          .default(false)
          .when('merge', {
            is: true,
            then: Joi.valid(false)
          }),
        
        testMode: Joi.boolean()
          .default(true),
        
        categories: Joi.array()
          .items(Joi.string().valid(
            'core',
            'security',
            'authentication',
            'performance',
            'features',
            'billing',
            'notifications',
            'integrations',
            'api',
            'ui'
          ))
          .unique(),
        
        includeSettings: Joi.boolean()
          .default(true),
        
        includeFeatureFlags: Joi.boolean()
          .default(true),
        
        includeTemplates: Joi.boolean()
          .default(true),
        
        backupFirst: Joi.boolean()
          .default(true)
      }).default({})
    })
  },

  /**
   * Apply template validation
   */
  applyTemplate: {
    params: Joi.object({
      templateId: objectId().required()
    }),
    
    body: Joi.object({
      environment: Joi.string()
        .valid('development', 'staging', 'production')
        .required()
        .messages({
          'any.required': 'Target environment is required'
        }),
      
      testMode: Joi.boolean()
        .default(false),
      
      overrides: Joi.object()
        .max(50)
        .default({}),
      
      skipValidation: Joi.boolean()
        .default(false),
      
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
    })
  },

  /**
   * Create backup validation
   */
  createBackup: {
    body: Joi.object({
      name: Joi.string()
        .pattern(/^[a-zA-Z0-9-_\s]+$/)
        .min(3)
        .max(100)
        .required()
        .messages({
          'string.pattern.base': 'Backup name can only contain letters, numbers, hyphens, underscores, and spaces',
          'any.required': 'Backup name is required'
        }),
      
      description: Joi.string()
        .min(10)
        .max(500),
      
      categories: Joi.array()
        .items(Joi.string())
        .unique()
        .default(['all']),
      
      includeAuditLogs: Joi.boolean()
        .default(false),
      
      compress: Joi.boolean()
        .default(true),
      
      encrypt: Joi.boolean()
        .default(true),
      
      retention: Joi.object({
        days: Joi.number()
          .integer()
          .min(1)
          .max(365)
          .default(30),
        
        permanent: Joi.boolean()
          .default(false)
      }).default({})
    })
  },

  /**
   * Restore backup validation
   */
  restoreBackup: {
    body: Joi.object({
      backupId: objectId()
        .required()
        .messages({
          'any.required': 'Backup ID is required'
        }),
      
      testMode: Joi.boolean()
        .default(true),
      
      categories: Joi.array()
        .items(Joi.string())
        .unique(),
      
      skipValidation: Joi.boolean()
        .default(false),
      
      createRestorePoint: Joi.boolean()
        .default(true),
      
      reason: Joi.string()
        .min(20)
        .max(1000)
        .required()
        .messages({
          'string.min': 'Restore reason must be at least 20 characters',
          'any.required': 'Detailed reason is required for configuration restore'
        }),
      
      confirmationCode: Joi.string()
        .length(6)
        .pattern(/^\d{6}$/)
        .when('testMode', {
          is: false,
          then: Joi.required(),
          otherwise: Joi.optional()
        })
    })
  },

  /**
   * Export configuration validation
   */
  exportConfiguration: {
    query: Joi.object({
      includeSettings: Joi.string()
        .valid('true', 'false')
        .default('true'),
      
      includeFeatureFlags: Joi.string()
        .valid('true', 'false')
        .default('true'),
      
      includeTemplates: Joi.string()
        .valid('true', 'false')
        .default('true'),
      
      format: Joi.string()
        .valid('json', 'yaml', 'xml')
        .default('json'),
      
      encrypt: Joi.string()
        .valid('true', 'false')
        .default('true'),
      
      categories: Joi.string()
        .pattern(/^[a-zA-Z,]+$/),
      
      download: Joi.string()
        .valid('true', 'false')
        .default('false')
    })
  },

  /**
   * Search settings validation
   */
  searchSettings: {
    query: Joi.object({
      query: Joi.string()
        .min(2)
        .max(100)
        .required()
        .messages({
          'string.min': 'Search query must be at least 2 characters',
          'any.required': 'Search query is required'
        }),
      
      categories: Joi.string()
        .pattern(/^[a-zA-Z,]+$/),
      
      valueTypes: Joi.string()
        .pattern(/^[a-zA-Z,]+$/),
      
      includeDefaults: Joi.boolean()
        .default(false),
      
      includeHidden: Joi.boolean()
        .default(false),
      
      page: Joi.number()
        .integer()
        .min(1)
        .default(1),
      
      limit: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .default(20)
    })
  },

  /**
   * Setting history query
   */
  settingHistory: {
    params: Joi.object({
      settingKey: customValidators.settingKey().required()
    }),
    
    query: Joi.object({
      limit: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .default(20),
      
      startDate: Joi.date()
        .max('now'),
      
      endDate: Joi.date()
        .min(Joi.ref('startDate'))
        .max('now')
        .when('startDate', {
          is: Joi.exist(),
          otherwise: Joi.optional()
        }),
      
      includeValues: Joi.boolean()
        .default(true),
      
      includeMetadata: Joi.boolean()
        .default(false)
    })
  },

  /**
   * Validate configuration
   */
  validateConfiguration: {
    body: Joi.object({
      settings: Joi.object()
        .min(1)
        .required()
        .messages({
          'object.min': 'At least one setting must be provided',
          'any.required': 'Settings object is required'
        }),
      
      checkDependencies: Joi.boolean()
        .default(true),
      
      checkConflicts: Joi.boolean()
        .default(true),
      
      checkCompatibility: Joi.boolean()
        .default(true),
      
      targetEnvironment: Joi.string()
        .valid('development', 'staging', 'production')
        .default('production')
    })
  },

  /**
   * Configuration template creation
   */
  createTemplate: {
    body: Joi.object({
      name: Joi.string()
        .min(3)
        .max(100)
        .required(),
      
      description: Joi.string()
        .min(10)
        .max(500)
        .required(),
      
      category: Joi.string()
        .valid(
          'security',
          'performance',
          'development',
          'production',
          'compliance',
          'custom'
        )
        .required(),
      
      environments: Joi.array()
        .items(Joi.string().valid('development', 'staging', 'production'))
        .min(1)
        .unique()
        .required(),
      
      settings: Joi.object()
        .min(1)
        .required(),
      
      featureFlags: Joi.object()
        .default({}),
      
      priority: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .default(50),
      
      active: Joi.boolean()
        .default(true),
      
      metadata: Joi.object({
        author: Joi.string(),
        version: Joi.string(),
        tags: Joi.array().items(Joi.string()).max(10),
        notes: Joi.string().max(1000)
      }).default({})
    })
  }
};

module.exports = SystemSettingsValidation;