// server/admin/security-administration/validation/threat-management-validation.js
/**
 * @file Threat Management Validation Schema
 * @description Validation schemas for threat management operations
 * @version 1.0.0
 */

const Joi = require('joi');

/**
 * Threat Management Validation Schemas
 */
const ThreatManagementValidation = {
  /**
   * Get threat overview validation
   */
  getOverview: {
    query: Joi.object({
      timeRange: Joi.string().pattern(/^\d+[hdwm]$/).default('24h'),
      includeMitigated: Joi.boolean().default(false),
      severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
      threatTypes: Joi.array().items(Joi.string().valid('malware', 'phishing', 'bruteforce', 'injection', 'dos', 'insider', 'other'))
    })
  },

  /**
   * Search threats validation
   */
  searchThreats: {
    query: Joi.object({
      query: Joi.string().max(500),
      status: Joi.array().items(Joi.string().valid('active', 'mitigated', 'investigating', 'false-positive')),
      severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
      type: Joi.array().items(Joi.string()),
      source: Joi.string(),
      targetType: Joi.string().valid('user', 'system', 'network', 'data'),
      dateFrom: Joi.date().iso(),
      dateTo: Joi.date().iso().when('dateFrom', {
        is: Joi.exist(),
        then: Joi.date().greater(Joi.ref('dateFrom'))
      }),
      organizationId: Joi.string(),
      affectedUsers: Joi.array().items(Joi.string()),
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(50),
      sort: Joi.string().pattern(/^-?[a-zA-Z_]+$/).default('-detectedAt')
    })
  },

  /**
   * Manage threat validation
   */
  manageThreat: {
    body: Joi.object({
      action: Joi.string().valid('acknowledge', 'investigate', 'mitigate', 'resolve', 'escalate', 'false-positive').required(),
      threatId: Joi.string().required(),
      investigation: Joi.when('action', {
        is: Joi.valid('investigate', 'mitigate', 'resolve'),
        then: Joi.object({
          findings: Joi.string().max(5000).required(),
          evidence: Joi.array().items(Joi.object({
            type: Joi.string().valid('log', 'screenshot', 'network-capture', 'file', 'other').required(),
            description: Joi.string().required(),
            url: Joi.string().uri(),
            hash: Joi.string(),
            timestamp: Joi.date().iso()
          })),
          affectedSystems: Joi.array().items(Joi.object({
            type: Joi.string().required(),
            identifier: Joi.string().required(),
            impact: Joi.string().valid('none', 'minimal', 'moderate', 'severe', 'critical')
          })),
          indicators: Joi.array().items(Joi.object({
            type: Joi.string().valid('ip', 'domain', 'url', 'hash', 'email', 'pattern').required(),
            value: Joi.string().required(),
            confidence: Joi.number().min(0).max(100)
          }))
        }),
        otherwise: Joi.forbidden()
      }),
      mitigation: Joi.when('action', {
        is: 'mitigate',
        then: Joi.object({
          strategy: Joi.string().valid('block', 'isolate', 'patch', 'remove', 'monitor').required(),
          actions: Joi.array().items(Joi.object({
            type: Joi.string().required(),
            target: Joi.string().required(),
            status: Joi.string().valid('pending', 'in-progress', 'completed', 'failed'),
            completedAt: Joi.date().iso()
          })).min(1).required(),
          effectiveness: Joi.string().valid('full', 'partial', 'temporary'),
          duration: Joi.when('effectiveness', {
            is: 'temporary',
            then: Joi.number().integer().min(1).required(),
            otherwise: Joi.forbidden()
          })
        }).required(),
        otherwise: Joi.forbidden()
      }),
      resolution: Joi.when('action', {
        is: 'resolve',
        then: Joi.object({
          summary: Joi.string().max(2000).required(),
          rootCause: Joi.string().max(3000).required(),
          impact: Joi.object({
            users: Joi.number().integer().min(0),
            systems: Joi.number().integer().min(0),
            dataCompromised: Joi.boolean(),
            financialLoss: Joi.number().min(0),
            reputationalDamage: Joi.string().valid('none', 'minimal', 'moderate', 'severe')
          }),
          lessonsLearned: Joi.array().items(Joi.string()),
          preventiveMeasures: Joi.array().items(Joi.string()).min(1).required()
        }).required(),
        otherwise: Joi.forbidden()
      }),
      escalation: Joi.when('action', {
        is: 'escalate',
        then: Joi.object({
          to: Joi.string().valid('security-team', 'management', 'external-soc', 'law-enforcement').required(),
          reason: Joi.string().max(1000).required(),
          urgency: Joi.string().valid('normal', 'high', 'critical').required(),
          contactInfo: Joi.object({
            name: Joi.string(),
            email: Joi.string().email(),
            phone: Joi.string()
          })
        }).required(),
        otherwise: Joi.forbidden()
      }),
      notes: Joi.string().max(2000)
    })
  },

  /**
   * Manage threat rule validation
   */
  manageThreatRule: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'delete', 'enable', 'disable', 'test').required(),
      ruleId: Joi.when('action', {
        is: Joi.valid('update', 'delete', 'enable', 'disable', 'test'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      rule: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          name: Joi.string().min(3).max(100).required(),
          description: Joi.string().max(500),
          type: Joi.string().valid('signature', 'behavioral', 'anomaly', 'correlation', 'custom').required(),
          severity: Joi.string().valid('low', 'medium', 'high', 'critical').required(),
          category: Joi.string().required(),
          detection: Joi.object({
            method: Joi.string().valid('pattern', 'threshold', 'machine-learning', 'heuristic').required(),
            patterns: Joi.when('method', {
              is: 'pattern',
              then: Joi.array().items(Joi.object({
                type: Joi.string().valid('regex', 'exact', 'contains', 'wildcard').required(),
                value: Joi.string().required(),
                field: Joi.string().required(),
                caseSensitive: Joi.boolean().default(false)
              })).min(1).required(),
              otherwise: Joi.forbidden()
            }),
            threshold: Joi.when('method', {
              is: 'threshold',
              then: Joi.object({
                metric: Joi.string().required(),
                operator: Joi.string().valid('gt', 'gte', 'lt', 'lte', 'eq', 'ne').required(),
                value: Joi.number().required(),
                timeWindow: Joi.number().integer().min(60000).required(),
                aggregation: Joi.string().valid('count', 'sum', 'avg', 'min', 'max')
              }).required(),
              otherwise: Joi.forbidden()
            }),
            model: Joi.when('method', {
              is: 'machine-learning',
              then: Joi.object({
                algorithm: Joi.string().required(),
                features: Joi.array().items(Joi.string()).min(1).required(),
                threshold: Joi.number().min(0).max(1).required()
              }).required(),
              otherwise: Joi.forbidden()
            })
          }).required(),
          response: Joi.object({
            actions: Joi.array().items(Joi.object({
              type: Joi.string().valid('alert', 'block', 'quarantine', 'log', 'script').required(),
              priority: Joi.number().integer().min(1).max(10),
              parameters: Joi.object()
            })).min(1).required(),
            autoMitigate: Joi.boolean().default(false),
            notificationChannels: Joi.array().items(Joi.string())
          }).required(),
          conditions: Joi.object({
            enabled: Joi.boolean().default(true),
            schedule: Joi.object({
              active: Joi.boolean().default(false),
              times: Joi.array().items(Joi.object({
                days: Joi.array().items(Joi.number().integer().min(0).max(6)),
                startTime: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/),
                endTime: Joi.string().pattern(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/)
              }))
            }),
            excludePatterns: Joi.array().items(Joi.string()),
            targetScope: Joi.object({
              include: Joi.array().items(Joi.string()),
              exclude: Joi.array().items(Joi.string())
            })
          }),
          testing: Joi.object({
            enabled: Joi.boolean().default(false),
            sampleRate: Joi.number().min(0).max(100),
            logOnly: Joi.boolean().default(true)
          })
        }).required(),
        otherwise: Joi.forbidden()
      }),
      testData: Joi.when('action', {
        is: 'test',
        then: Joi.object({
          input: Joi.object().required(),
          expectedResult: Joi.object({
            shouldTrigger: Joi.boolean().required(),
            severity: Joi.string(),
            score: Joi.number()
          })
        }).required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Investigate threat validation
   */
  investigateThreat: {
    params: Joi.object({
      threatId: Joi.string().required()
    }),
    query: Joi.object({
      deep: Joi.boolean().default(false),
      includeContext: Joi.boolean().default(true),
      timeframeBefore: Joi.number().integer().min(60000).default(3600000),
      timeframeAfter: Joi.number().integer().min(60000).default(1800000)
    })
  },

  /**
   * Threat intelligence feed validation
   */
  manageThreatIntelligence: {
    body: Joi.object({
      action: Joi.string().valid('subscribe', 'unsubscribe', 'update', 'test').required(),
      feedId: Joi.string().required(),
      configuration: Joi.when('action', {
        is: Joi.valid('subscribe', 'update'),
        then: Joi.object({
          url: Joi.string().uri(),
          apiKey: Joi.string(),
          format: Joi.string().valid('stix', 'taxii', 'json', 'csv').required(),
          updateFrequency: Joi.number().integer().min(300000).default(3600000),
          filters: Joi.object({
            types: Joi.array().items(Joi.string()),
            severity: Joi.array().items(Joi.string()),
            confidence: Joi.number().min(0).max(100),
            tags: Joi.array().items(Joi.string())
          }),
          mapping: Joi.object({
            indicator: Joi.string(),
            type: Joi.string(),
            severity: Joi.string(),
            confidence: Joi.string()
          })
        }),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Generate threat report validation
   */
  generateThreatReport: {
    body: Joi.object({
      reportType: Joi.string().valid('incident', 'trending', 'intelligence', 'executive').required(),
      timeRange: Joi.object({
        from: Joi.date().iso().required(),
        to: Joi.date().iso().greater(Joi.ref('from')).required()
      }).required(),
      filters: Joi.object({
        severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
        status: Joi.array().items(Joi.string()),
        types: Joi.array().items(Joi.string()),
        organizationIds: Joi.array().items(Joi.string())
      }),
      includeMetrics: Joi.boolean().default(true),
      includeRecommendations: Joi.boolean().default(true),
      format: Joi.string().valid('pdf', 'json', 'csv').default('pdf'),
      recipients: Joi.array().items(Joi.string().email())
    })
  }
};

module.exports = ThreatManagementValidation;