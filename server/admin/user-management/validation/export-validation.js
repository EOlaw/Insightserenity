// server/admin/user-management/validation/export-validation.js
/**
 * @file Export Validation
 * @description Validation schemas and rules for user data export and reporting operations
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
 * Base export schemas
 */
const exportSchemas = {
  // Export format
  exportFormat: Joi.string().valid('csv', 'xlsx', 'json', 'pdf', 'xml').default('csv'),

  // Date format
  dateFormat: Joi.string().valid(
    'YYYY-MM-DD',
    'DD/MM/YYYY',
    'MM/DD/YYYY',
    'YYYY-MM-DD HH:mm:ss',
    'ISO8601',
    'Unix'
  ).default('YYYY-MM-DD'),

  // Timezone
  timezone: Joi.string().custom((value, helpers) => {
    if (!moment.tz.zone(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  }).default('UTC').messages({
    'any.invalid': 'Invalid timezone'
  }),

  // Field selection
  fieldSelection: Joi.array().items(Joi.string()).min(1).unique(),

  // Export options
  exportOptions: Joi.object({
    compression: Joi.boolean().default(false),
    encryption: Joi.boolean().default(false),
    password: Joi.when('encryption', {
      is: true,
      then: Joi.string().min(8).max(128).required(),
      otherwise: Joi.forbidden()
    }),
    splitFiles: Joi.boolean().default(false),
    maxRecordsPerFile: Joi.when('splitFiles', {
      is: true,
      then: Joi.number().integer().min(100).max(100000).default(10000),
      otherwise: Joi.forbidden()
    }),
    includeHeaders: Joi.boolean().default(true),
    includeMetadata: Joi.boolean().default(false),
    customFileName: Joi.string().max(255).pattern(/^[a-zA-Z0-9-_]+$/),
    expiryHours: Joi.number().integer().min(1).max(168).default(24)
  })
};

/**
 * User data export schema
 */
const userDataExportSchema = Joi.object({
  filters: Joi.object({
    userIds: Joi.array().items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/)).unique(),
    status: Joi.array().items(Joi.string().valid('active', 'inactive', 'suspended', 'locked', 'deleted')),
    role: Joi.array().items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/)),
    organization: Joi.array().items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/)),
    createdAfter: Joi.date().iso(),
    createdBefore: Joi.date().iso(),
    lastActiveAfter: Joi.date().iso(),
    lastActiveBefore: Joi.date().iso(),
    verified: Joi.boolean(),
    hasSubscription: Joi.boolean(),
    tags: Joi.array().items(Joi.string()),
    customFields: Joi.object()
  }).default({}),

  fields: Joi.object({
    basic: Joi.array().items(Joi.string().valid(
      'id', 'email', 'username', 'status', 'createdAt', 'updatedAt'
    )),
    profile: Joi.array().items(Joi.string().valid(
      'firstName', 'lastName', 'displayName', 'avatar', 'bio',
      'dateOfBirth', 'gender', 'phone', 'timezone', 'language', 'country'
    )),
    organization: Joi.array().items(Joi.string().valid(
      'organizationId', 'organizationName', 'organizationRole', 'department'
    )),
    authentication: Joi.array().items(Joi.string().valid(
      'lastLoginAt', 'loginCount', 'emailVerified', 'mfaEnabled', 'lastPasswordChange'
    )),
    subscription: Joi.array().items(Joi.string().valid(
      'plan', 'status', 'startDate', 'endDate', 'billingCycle', 'amount'
    )),
    activity: Joi.array().items(Joi.string().valid(
      'lastActiveAt', 'totalSessions', 'averageSessionDuration', 'totalActions'
    )),
    custom: Joi.array().items(Joi.string())
  }).default({
    basic: ['id', 'email', 'status', 'createdAt']
  }),

  format: exportSchemas.exportFormat,
  dateFormat: exportSchemas.dateFormat,
  timezone: exportSchemas.timezone,
  
  options: exportSchemas.exportOptions.keys({
    includeSensitive: Joi.boolean().default(false),
    includeDeleted: Joi.boolean().default(false),
    anonymize: Joi.boolean().default(false),
    anonymizationRules: Joi.when('anonymize', {
      is: true,
      then: Joi.object({
        email: Joi.string().valid('hash', 'mask', 'remove').default('mask'),
        phone: Joi.string().valid('hash', 'mask', 'remove').default('mask'),
        name: Joi.string().valid('initials', 'remove').default('initials'),
        customFields: Joi.array().items(Joi.string())
      }),
      otherwise: Joi.forbidden()
    }),
    dataRetentionCompliant: Joi.boolean().default(true)
  }),

  delivery: Joi.object({
    method: Joi.string().valid('download', 'email', 's3', 'sftp').default('download'),
    email: Joi.when('method', {
      is: 'email',
      then: Joi.string().email().required(),
      otherwise: Joi.forbidden()
    }),
    s3Config: Joi.when('method', {
      is: 's3',
      then: Joi.object({
        bucket: Joi.string().required(),
        key: Joi.string().required(),
        region: Joi.string().required()
      }).required(),
      otherwise: Joi.forbidden()
    }),
    sftpConfig: Joi.when('method', {
      is: 'sftp',
      then: Joi.object({
        host: Joi.string().required(),
        port: Joi.number().integer().default(22),
        username: Joi.string().required(),
        password: Joi.string(),
        privateKey: Joi.string(),
        path: Joi.string().required()
      }).xor('password', 'privateKey').required(),
      otherwise: Joi.forbidden()
    })
  }).default({ method: 'download' })
}).custom((value, helpers) => {
  // Validate date ranges
  if (value.filters.createdAfter && value.filters.createdBefore) {
    if (new Date(value.filters.createdAfter) >= new Date(value.filters.createdBefore)) {
      return helpers.error('custom.invalidDateRange', { field: 'created' });
    }
  }
  
  if (value.filters.lastActiveAfter && value.filters.lastActiveBefore) {
    if (new Date(value.filters.lastActiveAfter) >= new Date(value.filters.lastActiveBefore)) {
      return helpers.error('custom.invalidDateRange', { field: 'lastActive' });
    }
  }

  // Validate field selection
  const allFields = Object.values(value.fields).flat();
  if (allFields.length === 0) {
    return helpers.error('custom.noFieldsSelected');
  }

  // Check for sensitive fields without permission
  const sensitiveFields = ['dateOfBirth', 'phone', 'customFields'];
  const requestedSensitive = allFields.filter(f => sensitiveFields.includes(f));
  
  if (requestedSensitive.length > 0 && !value.options.includeSensitive) {
    return helpers.error('custom.sensitiveFieldsRestricted', {
      fields: requestedSensitive.join(', ')
    });
  }

  return value;
}).messages({
  'custom.invalidDateRange': '{#field} date range is invalid',
  'custom.noFieldsSelected': 'At least one field must be selected for export',
  'custom.sensitiveFieldsRestricted': 'Sensitive fields ({#fields}) require includeSensitive option'
});

/**
 * Analytics export schema
 */
const analyticsExportSchema = Joi.object({
  reportType: Joi.string().valid(
    'user_growth',
    'user_engagement',
    'user_retention',
    'user_demographics',
    'lifecycle_analysis',
    'behavior_patterns',
    'risk_assessment',
    'custom'
  ).required(),

  dateRange: Joi.object({
    startDate: Joi.date().iso().required(),
    endDate: Joi.date().iso().greater(Joi.ref('startDate')).required(),
    granularity: Joi.string().valid('hour', 'day', 'week', 'month', 'quarter', 'year')
  }).required(),

  metrics: Joi.array().items(Joi.string().valid(
    // Growth metrics
    'new_users', 'total_users', 'active_users', 'growth_rate',
    // Engagement metrics
    'dau', 'wau', 'mau', 'stickiness', 'session_duration', 'actions_per_user',
    // Retention metrics
    'retention_rate', 'churn_rate', 'lifetime_value', 'cohort_retention',
    // Revenue metrics
    'mrr', 'arr', 'arpu', 'conversion_rate',
    // Custom metrics
    'custom'
  )).min(1).required(),

  dimensions: Joi.array().items(Joi.string().valid(
    'organization', 'role', 'plan', 'country', 'source', 'device', 'lifecycle_stage'
  )),

  filters: Joi.object({
    organizations: Joi.array().items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/)),
    roles: Joi.array().items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/)),
    plans: Joi.array().items(Joi.string()),
    countries: Joi.array().items(Joi.string().length(2).uppercase()),
    lifecycleStages: Joi.array().items(Joi.string()),
    customFilters: Joi.object()
  }),

  format: exportSchemas.exportFormat,
  
  options: exportSchemas.exportOptions.keys({
    includeRawData: Joi.boolean().default(false),
    includeCharts: Joi.boolean().default(true),
    chartFormat: Joi.when('includeCharts', {
      is: true,
      then: Joi.string().valid('png', 'svg', 'base64').default('png'),
      otherwise: Joi.forbidden()
    }),
    aggregationMethod: Joi.string().valid('sum', 'average', 'median', 'count').default('sum'),
    fillMissingData: Joi.boolean().default(true),
    confidence: Joi.number().min(0.5).max(0.99).default(0.95)
  })
}).custom((value, helpers) => {
  // Validate date range limits based on granularity
  const daysDiff = moment(value.dateRange.endDate).diff(moment(value.dateRange.startDate), 'days');
  
  const limits = {
    hour: 7,
    day: 90,
    week: 365,
    month: 730,
    quarter: 1825,
    year: 3650
  };
  
  const limit = limits[value.dateRange.granularity];
  if (limit && daysDiff > limit) {
    return helpers.error('custom.dateRangeExceedsLimit', {
      granularity: value.dateRange.granularity,
      limit
    });
  }

  // Validate metric compatibility
  if (value.reportType === 'user_retention' && !value.metrics.includes('retention_rate')) {
    value.metrics.push('retention_rate');
  }

  return value;
}).messages({
  'custom.dateRangeExceedsLimit': 'Date range exceeds {#limit} days limit for {#granularity} granularity'
});

/**
 * Report generation schema
 */
const reportGenerationSchema = Joi.object({
  name: Joi.string().trim().min(3).max(255).required(),
  description: Joi.string().max(1000),
  type: Joi.string().valid(
    'executive_summary',
    'detailed_analysis',
    'compliance_report',
    'audit_report',
    'custom_template'
  ).required(),

  sections: Joi.array().items(Joi.string().valid(
    'overview',
    'key_metrics',
    'user_growth',
    'user_engagement',
    'user_retention',
    'demographics',
    'behavior_analysis',
    'risk_assessment',
    'recommendations',
    'appendix'
  )).min(1).required(),

  data: Joi.object({
    includeHistorical: Joi.boolean().default(true),
    historicalPeriods: Joi.when('includeHistorical', {
      is: true,
      then: Joi.number().integer().min(1).max(12).default(3),
      otherwise: Joi.forbidden()
    }),
    includeForecasts: Joi.boolean().default(false),
    forecastPeriods: Joi.when('includeForecasts', {
      is: true,
      then: Joi.number().integer().min(1).max(6).default(3),
      otherwise: Joi.forbidden()
    }),
    dataSources: Joi.array().items(Joi.string().valid(
      'users', 'activities', 'sessions', 'subscriptions', 'audit_logs'
    )).min(1)
  }).required(),

  format: Joi.string().valid('pdf', 'html', 'docx', 'pptx').default('pdf'),
  
  template: Joi.object({
    id: Joi.string(),
    customization: Joi.object({
      logo: Joi.string().uri(),
      primaryColor: Joi.string().pattern(/^#[0-9A-F]{6}$/i),
      includeWatermark: Joi.boolean(),
      footerText: Joi.string().max(200)
    })
  }),

  schedule: Joi.object({
    frequency: Joi.string().valid('once', 'daily', 'weekly', 'monthly', 'quarterly').required(),
    time: Joi.when('frequency', {
      is: Joi.not('once'),
      then: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/).required(),
      otherwise: Joi.forbidden()
    }),
    dayOfWeek: Joi.when('frequency', {
      is: 'weekly',
      then: Joi.number().integer().min(0).max(6).required(),
      otherwise: Joi.forbidden()
    }),
    dayOfMonth: Joi.when('frequency', {
      is: 'monthly',
      then: Joi.number().integer().min(1).max(31).required(),
      otherwise: Joi.forbidden()
    }),
    timezone: exportSchemas.timezone,
    endDate: Joi.when('frequency', {
      is: Joi.not('once'),
      then: Joi.date().iso().min('now'),
      otherwise: Joi.forbidden()
    })
  }),

  distribution: Joi.object({
    recipients: Joi.array().items(Joi.object({
      email: Joi.string().email().required(),
      name: Joi.string().max(100),
      role: Joi.string().valid('viewer', 'editor')
    })).min(1).max(50).required(),
    cc: Joi.array().items(Joi.string().email()).max(10),
    deliveryMethod: Joi.string().valid('email', 'secure_link', 'api').default('email'),
    accessControl: Joi.object({
      requireAuthentication: Joi.boolean().default(true),
      expiryDays: Joi.number().integer().min(1).max(90).default(7),
      downloadLimit: Joi.number().integer().min(1).max(100),
      ipWhitelist: Joi.array().items(Joi.string().ip({ version: ['ipv4', 'ipv6'] }))
    })
  }).required()
});

/**
 * Data compliance export schema
 */
const complianceExportSchema = Joi.object({
  purpose: Joi.string().valid(
    'gdpr_request',
    'ccpa_request',
    'data_audit',
    'legal_hold',
    'regulatory_compliance',
    'internal_audit'
  ).required(),

  requestDetails: Joi.object({
    requestId: Joi.string().required(),
    requestorEmail: Joi.string().email().required(),
    deadline: Joi.date().iso().min('now').required(),
    legalBasis: Joi.string().max(500)
  }).required(),

  scope: Joi.object({
    userIds: Joi.array().items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/)).min(1).unique(),
    dataCategories: Joi.array().items(Joi.string().valid(
      'personal_info',
      'contact_info',
      'authentication',
      'activities',
      'preferences',
      'communications',
      'financial',
      'technical',
      'all'
    )).min(1).required(),
    dateRange: Joi.object({
      startDate: Joi.date().iso(),
      endDate: Joi.date().iso().greater(Joi.ref('startDate'))
    }),
    includeDeleted: Joi.boolean().default(true),
    includeArchived: Joi.boolean().default(true)
  }).required(),

  format: Joi.string().valid('json', 'xml', 'csv', 'pdf').default('json'),
  
  processing: Joi.object({
    anonymization: Joi.object({
      method: Joi.string().valid('none', 'pseudonymization', 'full').default('none'),
      retainKeys: Joi.when('method', {
        is: Joi.not('none'),
        then: Joi.boolean().default(true),
        otherwise: Joi.forbidden()
      })
    }),
    encryption: Joi.object({
      enabled: Joi.boolean().default(true),
      method: Joi.string().valid('AES-256', 'PGP').default('AES-256'),
      publicKey: Joi.when('method', {
        is: 'PGP',
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      })
    }),
    certification: Joi.object({
      includeDigitalSignature: Joi.boolean().default(true),
      includeTimestamp: Joi.boolean().default(true),
      includeAuditTrail: Joi.boolean().default(true)
    })
  }).required(),

  retention: Joi.object({
    deleteAfterDelivery: Joi.boolean().default(true),
    retentionDays: Joi.when('deleteAfterDelivery', {
      is: false,
      then: Joi.number().integer().min(1).max(90).required(),
      otherwise: Joi.forbidden()
    })
  }).required()
});

/**
 * Custom export validators
 */
const exportValidators = {
  /**
   * Validate export size limits
   * @param {Object} filters - Export filters
   * @param {string} format - Export format
   * @returns {Object} Validation result
   */
  validateExportSize: async (filters, format) => {
    // Estimate record count based on filters
    const estimatedCount = await estimateExportSize(filters);
    
    const limits = {
      csv: AdminLimits.EXPORT.MAX_CSV_RECORDS,
      xlsx: AdminLimits.EXPORT.MAX_EXCEL_RECORDS,
      json: AdminLimits.EXPORT.MAX_JSON_RECORDS,
      pdf: AdminLimits.EXPORT.MAX_PDF_PAGES
    };
    
    const limit = limits[format] || AdminLimits.EXPORT.MAX_DEFAULT_RECORDS;
    
    return {
      valid: estimatedCount <= limit,
      estimatedCount,
      limit,
      error: estimatedCount > limit ? 
        `Export size (${estimatedCount}) exceeds limit (${limit}) for ${format} format` : null
    };
  },

  /**
   * Validate field permissions
   * @param {Array} fields - Requested fields
   * @param {Object} permissions - User permissions
   * @returns {Object} Validation result
   */
  validateFieldPermissions: (fields, permissions) => {
    const restrictedFields = {
      'auth.password': 'view_passwords',
      'auth.twoFactor': 'view_2fa',
      'payment.cards': 'view_payment_info',
      'security.apiKeys': 'view_api_keys'
    };
    
    const unauthorized = [];
    
    fields.forEach(field => {
      const requiredPermission = restrictedFields[field];
      if (requiredPermission && !permissions.includes(requiredPermission)) {
        unauthorized.push({
          field,
          requiredPermission
        });
      }
    });
    
    return {
      valid: unauthorized.length === 0,
      unauthorized
    };
  },

  /**
   * Validate compliance requirements
   * @param {Object} exportConfig - Export configuration
   * @param {string} regulation - Compliance regulation
   * @returns {Object} Validation result
   */
  validateComplianceRequirements: (exportConfig, regulation) => {
    const requirements = {
      gdpr: {
        maxProcessingDays: 30,
        requiredFormats: ['json', 'xml'],
        encryption: true,
        auditTrail: true
      },
      ccpa: {
        maxProcessingDays: 45,
        requiredFormats: ['json', 'csv'],
        encryption: true,
        verification: true
      },
      hipaa: {
        maxProcessingDays: 30,
        requiredFormats: ['json'],
        encryption: true,
        accessLogging: true,
        minimumDataSet: true
      }
    };
    
    const reqs = requirements[regulation];
    if (!reqs) {
      return { valid: true };
    }
    
    const violations = [];
    
    if (!reqs.requiredFormats.includes(exportConfig.format)) {
      violations.push(`Format must be one of: ${reqs.requiredFormats.join(', ')}`);
    }
    
    if (reqs.encryption && !exportConfig.processing?.encryption?.enabled) {
      violations.push('Encryption is required');
    }
    
    if (reqs.auditTrail && !exportConfig.processing?.certification?.includeAuditTrail) {
      violations.push('Audit trail is required');
    }
    
    return {
      valid: violations.length === 0,
      violations
    };
  }
};

/**
 * Helper function to estimate export size
 * @param {Object} filters - Export filters
 * @returns {Promise<number>} Estimated record count
 */
async function estimateExportSize(filters) {
  // This would typically query the database with filters
  // For now, return a mock estimate
  return 1000;
}

/**
 * Validation middleware factory
 * @param {Object} schema - Joi schema to validate against
 * @param {string} source - Source of data ('body', 'query', 'params')
 * @returns {Function} Express middleware function
 */
const validateExport = (schema, source = 'body') => {
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
          message: 'Invalid export configuration',
          details: errors
        }
      });
    }

    req[source] = value;
    next();
  };
};

// Export schemas and validators
module.exports = {
  schemas: {
    userDataExport: userDataExportSchema,
    analyticsExport: analyticsExportSchema,
    reportGeneration: reportGenerationSchema,
    complianceExport: complianceExportSchema
  },
  validators: exportValidators,
  middleware: {
    validateUserDataExport: validateExport(userDataExportSchema),
    validateAnalyticsExport: validateExport(analyticsExportSchema),
    validateReportGeneration: validateExport(reportGenerationSchema),
    validateComplianceExport: validateExport(complianceExportSchema)
  }
};