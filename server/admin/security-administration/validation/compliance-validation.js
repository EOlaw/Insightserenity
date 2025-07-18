// server/admin/security-administration/validation/compliance-validation.js
/**
 * @file Compliance Validation Schema
 * @description Validation schemas for compliance management operations
 * @version 1.0.0
 */

const Joi = require('joi');

/**
 * Compliance Validation Schemas
 */
const ComplianceValidation = {
  /**
   * Get compliance standards validation
   */
  getStandards: {
    query: Joi.object({
      active: Joi.boolean(),
      search: Joi.string().max(100),
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(50).default(20),
      sort: Joi.string().pattern(/^-?[a-zA-Z_]+$/).default('name')
    })
  },

  /**
   * Manage compliance standard validation
   */
  manageStandard: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'delete', 'activate', 'deactivate').required(),
      standardId: Joi.when('action', {
        is: Joi.valid('update', 'delete', 'activate', 'deactivate'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      standard: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          name: Joi.string().min(3).max(100).required(),
          code: Joi.string().alphanum().uppercase().min(2).max(20).required(),
          description: Joi.string().max(1000).required(),
          version: Joi.string().max(20),
          category: Joi.string().valid('privacy', 'security', 'financial', 'healthcare', 'general').required(),
          requirements: Joi.array().items(Joi.object({
            id: Joi.string().required(),
            title: Joi.string().required(),
            description: Joi.string().required(),
            category: Joi.string().required(),
            priority: Joi.string().valid('critical', 'high', 'medium', 'low').required(),
            controls: Joi.array().items(Joi.string())
          })).min(1).required(),
          controls: Joi.array().items(Joi.object({
            id: Joi.string().required(),
            title: Joi.string().required(),
            description: Joi.string().required(),
            type: Joi.string().valid('preventive', 'detective', 'corrective', 'compensating').required(),
            category: Joi.string().required(),
            implementation: Joi.string(),
            evidence: Joi.array().items(Joi.string())
          })).min(1).required(),
          metadata: Joi.object({
            authority: Joi.string(),
            effectiveDate: Joi.date().iso(),
            lastReviewDate: Joi.date().iso(),
            nextReviewDate: Joi.date().iso(),
            references: Joi.array().items(Joi.string().uri()),
            industries: Joi.array().items(Joi.string()),
            jurisdictions: Joi.array().items(Joi.string())
          }),
          active: Joi.boolean().default(true)
        }).required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Perform compliance assessment validation
   */
  performAssessment: {
    body: Joi.object({
      standardId: Joi.string().required(),
      organizationId: Joi.string().required(),
      scope: Joi.string().valid('full', 'partial', 'specific').default('full'),
      specificAreas: Joi.when('scope', {
        is: 'specific',
        then: Joi.array().items(Joi.string()).min(1).required(),
        otherwise: Joi.forbidden()
      }),
      controlResponses: Joi.object().pattern(
        Joi.string(),
        Joi.object({
          status: Joi.string().valid('compliant', 'non-compliant', 'partial', 'not-applicable').required(),
          evidence: Joi.array().items(Joi.object({
            type: Joi.string().valid('document', 'screenshot', 'log', 'report', 'other').required(),
            url: Joi.string().uri(),
            description: Joi.string().required(),
            uploadedAt: Joi.date().iso()
          })),
          notes: Joi.string().max(2000),
          compensatingControls: Joi.array().items(Joi.string()),
          remediationPlan: Joi.when('status', {
            is: Joi.valid('non-compliant', 'partial'),
            then: Joi.object({
              description: Joi.string().required(),
              targetDate: Joi.date().iso().greater('now').required(),
              assignedTo: Joi.string(),
              estimatedCost: Joi.number().min(0)
            }),
            otherwise: Joi.forbidden()
          })
        })
      ).min(1).required(),
      assessor: Joi.object({
        name: Joi.string().required(),
        role: Joi.string(),
        qualifications: Joi.array().items(Joi.string())
      }),
      notes: Joi.string().max(5000)
    })
  },

  /**
   * Get compliance assessments validation
   */
  getAssessments: {
    query: Joi.object({
      standardId: Joi.string(),
      organizationId: Joi.string(),
      status: Joi.string().valid('draft', 'in-progress', 'completed', 'expired'),
      dateFrom: Joi.date().iso(),
      dateTo: Joi.date().iso().when('dateFrom', {
        is: Joi.exist(),
        then: Joi.date().greater(Joi.ref('dateFrom'))
      }),
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(50).default(20),
      sort: Joi.string().pattern(/^-?[a-zA-Z_]+$/).default('-completionDate')
    })
  },

  /**
   * Get assessment details validation
   */
  getAssessmentDetails: {
    params: Joi.object({
      assessmentId: Joi.string().required()
    }),
    query: Joi.object({
      includeEvidence: Joi.boolean().default(true),
      includeGaps: Joi.boolean().default(true)
    })
  },

  /**
   * Manage compliance gap validation
   */
  manageGap: {
    body: Joi.object({
      action: Joi.string().valid('update', 'resolve', 'extend', 'escalate').required(),
      gapId: Joi.string().required(),
      status: Joi.when('action', {
        is: 'update',
        then: Joi.string().valid('open', 'in-progress', 'pending-verification', 'resolved', 'accepted-risk'),
        otherwise: Joi.forbidden()
      }),
      remediationPlan: Joi.when('action', {
        is: Joi.valid('update', 'extend'),
        then: Joi.object({
          description: Joi.string().max(2000),
          steps: Joi.array().items(Joi.object({
            description: Joi.string().required(),
            targetDate: Joi.date().iso(),
            status: Joi.string().valid('pending', 'in-progress', 'completed'),
            assignedTo: Joi.string()
          })),
          targetDate: Joi.date().iso().greater('now'),
          estimatedCost: Joi.number().min(0),
          resources: Joi.array().items(Joi.string())
        }),
        otherwise: Joi.forbidden()
      }),
      evidence: Joi.when('action', {
        is: 'resolve',
        then: Joi.array().items(Joi.object({
          type: Joi.string().required(),
          url: Joi.string().uri(),
          description: Joi.string().required()
        })).min(1).required(),
        otherwise: Joi.forbidden()
      }),
      extensionReason: Joi.when('action', {
        is: 'extend',
        then: Joi.string().max(1000).required(),
        otherwise: Joi.forbidden()
      }),
      escalationReason: Joi.when('action', {
        is: 'escalate',
        then: Joi.string().max(1000).required(),
        otherwise: Joi.forbidden()
      }),
      assignedTo: Joi.string(),
      notes: Joi.string().max(2000)
    })
  },

  /**
   * Schedule compliance activities validation
   */
  scheduleActivity: {
    body: Joi.object({
      action: Joi.string().valid('create', 'update', 'cancel').required(),
      scheduleId: Joi.when('action', {
        is: Joi.valid('update', 'cancel'),
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      schedule: Joi.when('action', {
        is: Joi.valid('create', 'update'),
        then: Joi.object({
          type: Joi.string().valid('assessment', 'audit', 'review', 'training').required(),
          standardId: Joi.string().required(),
          organizationId: Joi.string(),
          frequency: Joi.string().valid('once', 'monthly', 'quarterly', 'semi-annual', 'annual').required(),
          startDate: Joi.date().iso().greater('now').required(),
          endDate: Joi.when('frequency', {
            is: 'once',
            then: Joi.forbidden(),
            otherwise: Joi.date().iso().greater(Joi.ref('startDate'))
          }),
          assignedTo: Joi.array().items(Joi.string()).min(1),
          notifications: Joi.object({
            enabled: Joi.boolean().default(true),
            daysBefore: Joi.array().items(Joi.number().integer().min(1).max(90)).default([7, 1]),
            recipients: Joi.array().items(Joi.string().email())
          }),
          description: Joi.string().max(1000),
          scope: Joi.object({
            areas: Joi.array().items(Joi.string()),
            excludeAreas: Joi.array().items(Joi.string())
          })
        }).required(),
        otherwise: Joi.forbidden()
      }),
      cancellationReason: Joi.when('action', {
        is: 'cancel',
        then: Joi.string().max(500).required(),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Generate compliance report validation
   */
  generateReport: {
    body: Joi.object({
      reportType: Joi.string().valid('assessment', 'gap-analysis', 'remediation', 'executive', 'detailed').required(),
      standardIds: Joi.array().items(Joi.string()).min(1).required(),
      organizationIds: Joi.array().items(Joi.string()),
      dateFrom: Joi.date().iso(),
      dateTo: Joi.date().iso().when('dateFrom', {
        is: Joi.exist(),
        then: Joi.date().greater(Joi.ref('dateFrom'))
      }),
      includeEvidence: Joi.boolean().default(false),
      includeRemediation: Joi.boolean().default(true),
      includeMetrics: Joi.boolean().default(true),
      format: Joi.string().valid('pdf', 'excel', 'word', 'json').default('pdf'),
      language: Joi.string().default('en'),
      customization: Joi.object({
        logo: Joi.string().uri(),
        primaryColor: Joi.string().pattern(/^#[0-9A-F]{6}$/i),
        includeExecutiveSummary: Joi.boolean().default(true),
        includeAppendix: Joi.boolean().default(true)
      })
    })
  },

  /**
   * Compliance dashboard data validation
   */
  getDashboard: {
    query: Joi.object({
      organizationId: Joi.string(),
      timeRange: Joi.string().pattern(/^\d+[hdwm]$/).default('30d'),
      metrics: Joi.array().items(
        Joi.string().valid('overallScore', 'byStandard', 'gaps', 'remediations', 'trends', 'upcoming')
      ).default(['overallScore', 'byStandard', 'gaps'])
    })
  }
};

module.exports = ComplianceValidation;