// server/admin/security-administration/validation/security-validation.js
/**
 * @file Security Validation Schema
 * @description Validation schemas for security management operations
 * @version 1.0.0
 */

const Joi = require('joi');

/**
 * Security Validation Schemas
 */
const SecurityValidation = {
  /**
   * Security overview query validation
   */
  getOverview: {
    query: Joi.object({
      timeRange: Joi.string().pattern(/^\d+[hdwm]$/).default('7d'),
      includeMetrics: Joi.boolean().default(true),
      includeThreats: Joi.boolean().default(true),
      includeVulnerabilities: Joi.boolean().default(true),
      includeCompliance: Joi.boolean().default(true)
    })
  },

  /**
   * Update security settings validation
   */
  updateSettings: {
    body: Joi.object({
      passwordPolicy: Joi.object({
        minLength: Joi.number().integer().min(8).max(128),
        maxLength: Joi.number().integer().min(12).max(256),
        requireUppercase: Joi.boolean(),
        requireLowercase: Joi.boolean(),
        requireNumbers: Joi.boolean(),
        requireSpecialChars: Joi.boolean(),
        preventReuse: Joi.number().integer().min(0).max(24),
        maxAge: Joi.number().integer().min(0),
        complexityScore: Joi.number().min(0).max(100)
      }),
      sessionPolicy: Joi.object({
        sessionTimeout: Joi.number().integer().min(300000),
        idleTimeout: Joi.number().integer().min(60000),
        maxConcurrentSessions: Joi.number().integer().min(1).max(10),
        requireReauth: Joi.boolean(),
        rememberMeDuration: Joi.number().integer().min(0)
      }),
      mfaPolicy: Joi.object({
        required: Joi.boolean(),
        methods: Joi.array().items(Joi.string().valid('totp', 'sms', 'email', 'backup')),
        gracePeriod: Joi.number().integer().min(0),
        rememberDevice: Joi.boolean(),
        deviceTrustDuration: Joi.number().integer().min(0)
      }),
      accessControl: Joi.object({
        ipWhitelisting: Joi.boolean(),
        ipBlacklisting: Joi.boolean(),
        geoBlocking: Joi.boolean(),
        blockedCountries: Joi.array().items(Joi.string().length(2)),
        allowedCountries: Joi.array().items(Joi.string().length(2)),
        rateLimit: Joi.object({
          enabled: Joi.boolean(),
          maxRequests: Joi.number().integer().min(1),
          windowMs: Joi.number().integer().min(1000)
        })
      }),
      encryptionSettings: Joi.object({
        algorithm: Joi.string().valid('aes-256-gcm', 'aes-256-cbc', 'chacha20-poly1305'),
        keyRotationEnabled: Joi.boolean(),
        keyRotationInterval: Joi.number().integer().min(86400000),
        enforceHttps: Joi.boolean(),
        hsts: Joi.object({
          enabled: Joi.boolean(),
          maxAge: Joi.number().integer().min(0),
          includeSubDomains: Joi.boolean(),
          preload: Joi.boolean()
        })
      }),
      auditSettings: Joi.object({
        enabled: Joi.boolean(),
        retentionDays: Joi.number().integer().min(1).max(2555),
        logLevel: Joi.string().valid('minimal', 'standard', 'detailed', 'verbose'),
        logSensitiveData: Joi.boolean(),
        complianceMode: Joi.string().valid('none', 'gdpr', 'hipaa', 'pci', 'sox', 'all')
      })
    }).min(1)
  },

  /**
   * Security policies validation
   */
  managePolicy: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'delete', 'enable', 'disable').required(),
      policyId: Joi.when('action', {
        is: Joi.valid('update', 'delete', 'enable', 'disable'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      policy: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          name: Joi.string().min(3).max(100).required(),
          description: Joi.string().max(500),
          type: Joi.string().valid('access', 'password', 'session', 'data', 'network').required(),
          rules: Joi.array().items(Joi.object({
            condition: Joi.string().required(),
            action: Joi.string().required(),
            parameters: Joi.object()
          })).min(1),
          scope: Joi.string().valid('global', 'organization', 'user', 'role'),
          targetIds: Joi.array().items(Joi.string()),
          priority: Joi.number().integer().min(0).max(100),
          enabled: Joi.boolean().default(true),
          enforcement: Joi.string().valid('block', 'warn', 'audit'),
          expiresAt: Joi.date().iso().greater('now')
        }).required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * IP management validation
   */
  manageIpList: {
    body: Joi.object({
      action: Joi.string().valid('add', 'remove', 'update').required(),
      listType: Joi.string().valid('whitelist', 'blacklist').required(),
      entries: Joi.array().items(Joi.object({
        ip: Joi.alternatives().try(
          Joi.string().ip({ version: ['ipv4'] }),
          Joi.string().pattern(/^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/), // CIDR
          Joi.string().ip({ version: ['ipv6'] })
        ).required(),
        description: Joi.string().max(200),
        expiresAt: Joi.date().iso().greater('now'),
        tags: Joi.array().items(Joi.string().max(50))
      })).min(1).max(100).required(),
      reason: Joi.string().max(500).required()
    })
  },

  /**
   * Threat detection configuration
   */
  configureThreatDetection: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'delete', 'test').required(),
      ruleId: Joi.when('action', {
        is: Joi.valid('update', 'delete', 'test'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      rule: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          name: Joi.string().min(3).max(100).required(),
          description: Joi.string().max(500),
          type: Joi.string().valid('bruteforce', 'injection', 'anomaly', 'malware', 'dos').required(),
          severity: Joi.string().valid('low', 'medium', 'high', 'critical').required(),
          conditions: Joi.array().items(Joi.object({
            field: Joi.string().required(),
            operator: Joi.string().valid('equals', 'contains', 'regex', 'gt', 'lt', 'between').required(),
            value: Joi.alternatives().try(Joi.string(), Joi.number(), Joi.array()),
            timeWindow: Joi.number().integer().min(1000)
          })).min(1),
          actions: Joi.array().items(Joi.object({
            type: Joi.string().valid('block', 'alert', 'log', 'captcha', 'rateLimit').required(),
            parameters: Joi.object()
          })).min(1),
          enabled: Joi.boolean().default(true),
          testMode: Joi.boolean().default(false)
        }).required(),
        otherwise: Joi.forbidden()
      }),
      testData: Joi.when('action', {
        is: 'test',
        then: Joi.object().required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Security scan validation
   */
  performScan: {
    body: Joi.object({
      scanType: Joi.string().valid('full', 'vulnerability', 'compliance', 'access', 'configuration').default('full'),
      targets: Joi.array().items(Joi.string().valid('system', 'network', 'applications', 'data', 'users')).default(['system']),
      deep: Joi.boolean().default(false),
      schedule: Joi.alternatives().try(
        Joi.boolean().valid(false),
        Joi.object({
          frequency: Joi.string().valid('once', 'daily', 'weekly', 'monthly').required(),
          time: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
          dayOfWeek: Joi.when('frequency', {
            is: 'weekly',
            then: Joi.number().integer().min(0).max(6),
            otherwise: Joi.forbidden()
          }),
          dayOfMonth: Joi.when('frequency', {
            is: 'monthly',
            then: Joi.number().integer().min(1).max(31),
            otherwise: Joi.forbidden()
          })
        })
      ).default(false)
    })
  },

  /**
   * Incident response validation
   */
  manageIncident: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'close', 'escalate').required(),
      incidentId: Joi.when('action', {
        is: Joi.valid('update', 'close', 'escalate'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      incident: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          title: Joi.string().min(5).max(200).required(),
          description: Joi.string().max(2000).required(),
          type: Joi.string().valid('breach', 'attack', 'vulnerability', 'policy', 'other').required(),
          severity: Joi.string().valid('low', 'medium', 'high', 'critical').required(),
          affectedSystems: Joi.array().items(Joi.string()).min(1),
          affectedUsers: Joi.array().items(Joi.string()),
          evidence: Joi.array().items(Joi.object({
            type: Joi.string().required(),
            data: Joi.string().required(),
            timestamp: Joi.date().iso()
          })),
          containmentActions: Joi.array().items(Joi.string()),
          status: Joi.string().valid('open', 'investigating', 'contained', 'resolved', 'closed')
        }).required(),
        otherwise: Joi.forbidden()
      }),
      escalationReason: Joi.when('action', {
        is: 'escalate',
        then: Joi.string().max(500).required(),
        otherwise: Joi.forbidden()
      }),
      resolution: Joi.when('action', {
        is: 'close',
        then: Joi.object({
          summary: Joi.string().max(1000).required(),
          rootCause: Joi.string().max(2000),
          lessonsLearned: Joi.array().items(Joi.string()),
          preventiveMeasures: Joi.array().items(Joi.string())
        }).required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Generate security report validation
   */
  generateReport: {
    body: Joi.object({
      reportType: Joi.string().valid('overview', 'vulnerability', 'compliance', 'incident', 'audit').required(),
      dateFrom: Joi.date().iso().required(),
      dateTo: Joi.date().iso().greater(Joi.ref('dateFrom')).required(),
      format: Joi.string().valid('summary', 'detailed', 'executive').default('detailed'),
      includeGraphs: Joi.boolean().default(true),
      includeRecommendations: Joi.boolean().default(true),
      filters: Joi.object({
        severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
        categories: Joi.array().items(Joi.string()),
        organizationIds: Joi.array().items(Joi.string()),
        userIds: Joi.array().items(Joi.string())
      })
    })
  }
};

module.exports = SecurityValidation;