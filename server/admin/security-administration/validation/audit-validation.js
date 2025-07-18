// server/admin/security-administration/validation/audit-validation.js
/**
 * @file Audit Validation Schema
 * @description Validation schemas for audit management operations
 * @version 1.0.0
 */

const Joi = require('joi');

/**
 * Audit Validation Schemas
 */
const AuditValidation = {
  /**
   * Search audit logs validation
   */
  searchLogs: {
    query: Joi.object({
      query: Joi.string().max(500),
      eventType: Joi.string().max(100),
      severity: Joi.string().valid('low', 'medium', 'high', 'critical'),
      userId: Joi.string(),
      organizationId: Joi.string(),
      dateFrom: Joi.date().iso(),
      dateTo: Joi.date().iso().when('dateFrom', {
        is: Joi.exist(),
        then: Joi.date().greater(Joi.ref('dateFrom'))
      }),
      ipAddress: Joi.string().ip(),
      userAgent: Joi.string().max(500),
      category: Joi.string().max(100),
      riskScore: Joi.object({
        min: Joi.number().min(0).max(100),
        max: Joi.number().min(0).max(100).greater(Joi.ref('min'))
      }),
      compliance: Joi.object({
        standard: Joi.string().valid('gdpr', 'hipaa', 'pci', 'sox', 'iso27001'),
        compliant: Joi.boolean()
      }),
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(50),
      sort: Joi.string().pattern(/^-?[a-zA-Z_]+$/).default('-timestamp'),
      includeRelated: Joi.boolean().default(false),
      decrypt: Joi.boolean().default(false)
    })
  },

  /**
   * Get audit details validation
   */
  getDetails: {
    params: Joi.object({
      auditId: Joi.string().required()
    }),
    query: Joi.object({
      includeRelated: Joi.boolean().default(false),
      includeCompliance: Joi.boolean().default(true),
      decrypt: Joi.boolean().default(false)
    })
  },

  /**
   * Export audit logs validation
   */
  exportLogs: {
    body: Joi.object({
      format: Joi.string().valid('json', 'csv', 'pdf', 'excel').default('csv'),
      query: Joi.string().max(500),
      filters: Joi.object({
        eventType: Joi.array().items(Joi.string()),
        severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
        dateFrom: Joi.date().iso().required(),
        dateTo: Joi.date().iso().greater(Joi.ref('dateFrom')).required(),
        userId: Joi.array().items(Joi.string()),
        organizationId: Joi.array().items(Joi.string()),
        category: Joi.array().items(Joi.string()),
        compliance: Joi.object({
          standard: Joi.string(),
          compliant: Joi.boolean()
        })
      }).required(),
      columns: Joi.array().items(Joi.string()).min(1),
      includeMetadata: Joi.boolean().default(true),
      compress: Joi.boolean().default(false),
      encrypt: Joi.boolean().default(false),
      encryptionPassword: Joi.when('encrypt', {
        is: true,
        then: Joi.string().min(8).required(),
        otherwise: Joi.forbidden()
      }),
      notificationEmail: Joi.string().email()
    })
  },

  /**
   * Configure audit retention validation
   */
  configureRetention: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'delete').required(),
      policyId: Joi.when('action', {
        is: Joi.valid('update', 'delete'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      policy: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          name: Joi.string().min(3).max(100).required(),
          description: Joi.string().max(500),
          retentionDays: Joi.number().integer().min(1).max(2555).required(),
          complianceStandard: Joi.string().valid('gdpr', 'hipaa', 'pci', 'sox', 'custom'),
          filters: Joi.object({
            eventTypes: Joi.array().items(Joi.string()),
            severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
            categories: Joi.array().items(Joi.string())
          }),
          archiveEnabled: Joi.boolean().default(false),
          archiveLocation: Joi.when('archiveEnabled', {
            is: true,
            then: Joi.string().required(),
            otherwise: Joi.forbidden()
          }),
          compressionEnabled: Joi.boolean().default(true),
          encryptionEnabled: Joi.boolean().default(true),
          legalHold: Joi.boolean().default(false)
        }).required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Configure audit alerts validation
   */
  configureAlerts: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'delete', 'test').required(),
      alertId: Joi.when('action', {
        is: Joi.valid('update', 'delete', 'test'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      alert: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          name: Joi.string().min(3).max(100).required(),
          description: Joi.string().max(500),
          enabled: Joi.boolean().default(true),
          conditions: Joi.array().items(Joi.object({
            field: Joi.string().required(),
            operator: Joi.string().valid('equals', 'contains', 'gt', 'lt', 'between', 'in').required(),
            value: Joi.alternatives().try(Joi.string(), Joi.number(), Joi.array(), Joi.boolean()),
            aggregation: Joi.object({
              function: Joi.string().valid('count', 'sum', 'avg', 'min', 'max'),
              timeWindow: Joi.number().integer().min(60000),
              threshold: Joi.number()
            })
          })).min(1).required(),
          actions: Joi.array().items(Joi.object({
            type: Joi.string().valid('email', 'sms', 'webhook', 'slack', 'pagerduty').required(),
            recipients: Joi.when('type', {
              is: Joi.valid('email', 'sms'),
              then: Joi.array().items(Joi.string()).min(1).required(),
              otherwise: Joi.forbidden()
            }),
            webhookUrl: Joi.when('type', {
              is: 'webhook',
              then: Joi.string().uri().required(),
              otherwise: Joi.forbidden()
            }),
            channelId: Joi.when('type', {
              is: 'slack',
              then: Joi.string().required(),
              otherwise: Joi.forbidden()
            }),
            serviceKey: Joi.when('type', {
              is: 'pagerduty',
              then: Joi.string().required(),
              otherwise: Joi.forbidden()
            }),
            template: Joi.string().max(2000)
          })).min(1).required(),
          cooldownPeriod: Joi.number().integer().min(60000).default(300000),
          priority: Joi.string().valid('low', 'medium', 'high', 'critical').default('medium')
        }).required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Archive audit logs validation
   */
  archiveLogs: {
    body: Joi.object({
      dateFrom: Joi.date().iso().required(),
      dateTo: Joi.date().iso().greater(Joi.ref('dateFrom')).required(),
      filters: Joi.object({
        eventTypes: Joi.array().items(Joi.string()),
        severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
        organizationIds: Joi.array().items(Joi.string())
      }),
      destination: Joi.string().valid('s3', 'azure', 'gcp', 'local').required(),
      compress: Joi.boolean().default(true),
      encrypt: Joi.boolean().default(true),
      deleteAfterArchive: Joi.boolean().default(false),
      notificationEmail: Joi.string().email()
    })
  },

  /**
   * Audit statistics validation
   */
  getStatistics: {
    query: Joi.object({
      timeRange: Joi.string().pattern(/^\d+[hdwm]$/).default('7d'),
      groupBy: Joi.string().valid('hour', 'day', 'week', 'month').default('day'),
      metrics: Joi.array().items(
        Joi.string().valid('total', 'byType', 'bySeverity', 'byUser', 'byOrganization', 'trends')
      ).default(['total', 'byType', 'bySeverity'])
    })
  },

  /**
   * Manage compliance mappings validation
   */
  manageComplianceMappings: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'delete').required(),
      standard: Joi.string().valid('gdpr', 'hipaa', 'pci', 'sox', 'iso27001', 'custom').required(),
      eventTypes: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.array().items(Joi.string()).min(1).required(),
        otherwise: Joi.forbidden()
      }),
      requirements: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.array().items(Joi.object({
          id: Joi.string().required(),
          description: Joi.string().required(),
          category: Joi.string()
        })),
        otherwise: Joi.forbidden()
      }),
      controls: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.array().items(Joi.object({
          id: Joi.string().required(),
          description: Joi.string().required(),
          type: Joi.string().valid('preventive', 'detective', 'corrective')
        })),
        otherwise: Joi.forbidden()
      }),
      description: Joi.string().max(1000)
    })
  },

  /**
   * Generate compliance report validation
   */
  generateComplianceReport: {
    body: Joi.object({
      standard: Joi.string().valid('gdpr', 'hipaa', 'pci', 'sox', 'iso27001', 'all').required(),
      dateFrom: Joi.date().iso(),
      dateTo: Joi.date().iso().when('dateFrom', {
        is: Joi.exist(),
        then: Joi.date().greater(Joi.ref('dateFrom'))
      }),
      scope: Joi.string().valid('organization', 'platform', 'specific').default('organization'),
      organizationIds: Joi.when('scope', {
        is: 'specific',
        then: Joi.array().items(Joi.string()).min(1).required(),
        otherwise: Joi.forbidden()
      }),
      format: Joi.string().valid('summary', 'detailed', 'evidence').default('detailed'),
      includeEvidence: Joi.boolean().default(true),
      includeGaps: Joi.boolean().default(true),
      includeRecommendations: Joi.boolean().default(true)
    })
  },

  /**
   * Analyze audit patterns validation
   */
  analyzePatterns: {
    body: Joi.object({
      analysisType: Joi.string().valid('user_behavior', 'security_threats', 'compliance_gaps', 'anomaly_detection').required(),
      timeRange: Joi.object({
        from: Joi.date().iso().required(),
        to: Joi.date().iso().greater(Joi.ref('from')).required()
      }).required(),
      userId: Joi.string(),
      organizationId: Joi.string(),
      eventTypes: Joi.array().items(Joi.string()),
      sensitivity: Joi.string().valid('low', 'medium', 'high').default('medium'),
      includeRecommendations: Joi.boolean().default(true)
    })
  }
};

module.exports = AuditValidation;