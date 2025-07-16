// server/admin/user-management/validation/lifecycle-validation.js
/**
 * @file Lifecycle Validation
 * @description Validation schemas and rules for account lifecycle management
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
 * Common lifecycle schemas
 */
const lifecycleSchemas = {
  // Lifecycle stage
  lifecycleStage: Joi.string().valid(
    'onboarding',
    'active',
    'inactive',
    'at_risk',
    'churned',
    'reactivated',
    'suspended',
    'deleted'
  ),

  // Date range
  dateRange: Joi.object({
    startDate: Joi.date().iso().required(),
    endDate: Joi.date().iso().greater(Joi.ref('startDate')).required()
  }).messages({
    'date.greater': 'End date must be after start date'
  }),

  // Reason field
  reason: Joi.string().trim().min(10).max(1000).messages({
    'string.min': 'Reason must be at least {#limit} characters',
    'string.max': 'Reason cannot exceed {#limit} characters'
  }),

  // Notification options
  notificationOptions: Joi.object({
    notifyUser: Joi.boolean().default(true),
    notificationTemplate: Joi.string(),
    customMessage: Joi.string().max(1000),
    channels: Joi.array().items(
      Joi.string().valid('email', 'sms', 'push', 'in_app')
    ).default(['email'])
  })
};

/**
 * Lifecycle overview query validation schema
 */
const lifecycleOverviewQuerySchema = Joi.object({
  timeRange: Joi.string().valid(
    'last24h', 'last7d', 'last30d', 'last90d', 'last365d', 'custom'
  ).default('last30d'),
  startDate: Joi.when('timeRange', {
    is: 'custom',
    then: Joi.date().iso().required(),
    otherwise: Joi.forbidden()
  }),
  endDate: Joi.when('timeRange', {
    is: 'custom',
    then: Joi.date().iso().greater(Joi.ref('startDate')).required(),
    otherwise: Joi.forbidden()
  }),
  organizationId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
  skipCache: Joi.boolean().default(false)
});

/**
 * Lifecycle policies configuration schema
 */
const lifecyclePoliciesSchema = Joi.object({
  organizationId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
  policies: Joi.object({
    inactivityWarning: Joi.number().integer().min(1).max(365),
    inactivitySuspension: Joi.number().integer().min(1).max(730),
    inactivityDeletion: Joi.number().integer().min(30).max(1825),
    trialExpiration: Joi.number().integer().min(1).max(90),
    passwordExpiration: Joi.number().integer().min(0).max(365),
    sessionTimeout: Joi.number().integer().min(1).max(720),
    dataRetention: Joi.number().integer().min(365).max(3650),
    gracePeriods: Joi.object({
      suspension: Joi.number().integer().min(1).max(30),
      deletion: Joi.number().integer().min(7).max(90),
      reactivation: Joi.number().integer().min(1).max(365)
    }),
    automationRules: Joi.object({
      enableInactivityWarnings: Joi.boolean(),
      enableAutoSuspension: Joi.boolean(),
      enableAutoDeletion: Joi.boolean(),
      enableTrialReminders: Joi.boolean(),
      enablePasswordExpiryNotices: Joi.boolean()
    }),
    notifications: Joi.object({
      warningIntervals: Joi.array().items(Joi.number().integer()).min(1).max(5),
      reminderFrequency: Joi.string().valid('daily', 'weekly', 'monthly'),
      includeAdmins: Joi.boolean()
    })
  }).min(1).required(),
  applyToExisting: Joi.boolean().default(false),
  effectiveDate: Joi.date().iso().min('now').default(() => new Date()),
  testMode: Joi.boolean().default(false)
}).custom((value, helpers) => {
  const policies = value.policies;
  
  // Validate policy relationships
  if (policies.inactivityWarning && policies.inactivitySuspension) {
    if (policies.inactivityWarning >= policies.inactivitySuspension) {
      return helpers.error('custom.warningAfterSuspension');
    }
  }
  
  if (policies.inactivitySuspension && policies.inactivityDeletion) {
    if (policies.inactivitySuspension >= policies.inactivityDeletion) {
      return helpers.error('custom.suspensionAfterDeletion');
    }
  }
  
  return value;
}).messages({
  'custom.warningAfterSuspension': 'Inactivity warning must occur before suspension',
  'custom.suspensionAfterDeletion': 'Inactivity suspension must occur before deletion'
});

/**
 * Account lifecycle transition schema
 */
const lifecycleTransitionSchema = Joi.object({
  targetStage: lifecycleSchemas.lifecycleStage.required(),
  reason: lifecycleSchemas.reason.required(),
  automated: Joi.boolean().default(false),
  notifyUser: Joi.boolean().default(true),
  metadata: Joi.object({
    triggeredBy: Joi.string(),
    relatedTicket: Joi.string(),
    notes: Joi.string().max(2000)
  }),
  effectiveDate: Joi.date().iso().min('now').default(() => new Date()),
  transitionActions: Joi.array().items(
    Joi.string().valid(
      'terminate_sessions',
      'revoke_api_keys',
      'cancel_subscriptions',
      'transfer_ownership',
      'backup_data',
      'notify_team'
    )
  )
}).custom((value, helpers) => {
  // Validate stage-specific requirements
  if (value.targetStage === 'deleted') {
    if (!value.metadata?.notes) {
      return helpers.error('custom.deletionNotesRequired');
    }
  }
  
  if (value.targetStage === 'suspended' && !value.reason) {
    return helpers.error('custom.suspensionReasonRequired');
  }
  
  return value;
}).messages({
  'custom.deletionNotesRequired': 'Detailed notes are required for deletion',
  'custom.suspensionReasonRequired': 'Suspension reason is required'
});

/**
 * Account reactivation schema
 */
const accountReactivationSchema = Joi.object({
  reason: lifecycleSchemas.reason.required(),
  resetPassword: Joi.boolean().default(false),
  extendTrial: Joi.boolean().default(false),
  trialDays: Joi.when('extendTrial', {
    is: true,
    then: Joi.number().integer().min(1).max(90).required(),
    otherwise: Joi.forbidden()
  }),
  offerIncentive: Joi.boolean().default(false),
  incentiveDetails: Joi.when('offerIncentive', {
    is: true,
    then: Joi.object({
      type: Joi.string().valid('discount', 'credit', 'free_period', 'upgrade').required(),
      percentage: Joi.when('type', {
        is: 'discount',
        then: Joi.number().min(1).max(100).required(),
        otherwise: Joi.forbidden()
      }),
      amount: Joi.when('type', {
        is: 'credit',
        then: Joi.number().positive().required(),
        otherwise: Joi.forbidden()
      }),
      days: Joi.when('type', {
        is: 'free_period',
        then: Joi.number().integer().min(1).max(365).required(),
        otherwise: Joi.forbidden()
      }),
      targetPlan: Joi.when('type', {
        is: 'upgrade',
        then: Joi.string().required(),
        otherwise: Joi.forbidden()
      }),
      validUntil: Joi.date().iso().min('now').required(),
      conditions: Joi.string().max(500)
    }).required(),
    otherwise: Joi.forbidden()
  }),
  notifyUser: Joi.boolean().default(true),
  restoreData: Joi.boolean().default(true),
  clearSuspensionHistory: Joi.boolean().default(false)
});

/**
 * Scheduled deletion schema
 */
const scheduledDeletionSchema = Joi.object({
  userIds: Joi.array()
    .items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/))
    .min(1)
    .max(AdminLimits.LIFECYCLE.MAX_SCHEDULED_DELETIONS)
    .unique(),
  filters: Joi.object({
    status: Joi.array().items(Joi.string().valid('inactive', 'suspended', 'churned')),
    lastActiveBefor: Joi.date().iso(),
    createdBefore: Joi.date().iso(),
    noLoginSince: Joi.date().iso(),
    organization: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
    excludeTags: Joi.array().items(Joi.string())
  }),
  deletionDate: Joi.date()
    .iso()
    .min(moment().add(7, 'days').toDate())
    .max(moment().add(365, 'days').toDate())
    .required()
    .messages({
      'date.min': 'Deletion must be scheduled at least 7 days in the future',
      'date.max': 'Deletion cannot be scheduled more than 1 year in advance'
    }),
  deletionType: Joi.string().valid('soft', 'hard').default('soft'),
  reason: lifecycleSchemas.reason.min(20).required(),
  notifyUsers: Joi.boolean().default(true),
  notificationLeadTime: Joi.number().integer().min(1).max(90).default(30),
  requireConfirmation: Joi.boolean().default(true),
  backupBeforeDeletion: Joi.boolean().default(true)
}).xor('userIds', 'filters').messages({
  'object.xor': 'Either userIds or filters must be provided, but not both'
});

/**
 * Lifecycle automation rule schema
 */
const lifecycleAutomationRuleSchema = Joi.object({
  name: Joi.string().trim().min(3).max(100).required(),
  description: Joi.string().max(500),
  trigger: Joi.object({
    type: Joi.string().valid('time_based', 'event_based', 'condition_based', 'manual').required(),
    schedule: Joi.when('type', {
      is: 'time_based',
      then: Joi.object({
        frequency: Joi.string().valid('once', 'hourly', 'daily', 'weekly', 'monthly').required(),
        time: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/),
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
        timezone: Joi.string().default('UTC')
      }).required(),
      otherwise: Joi.forbidden()
    }),
    event: Joi.when('type', {
      is: 'event_based',
      then: Joi.string().valid(
        'user_created',
        'user_activated',
        'user_deactivated',
        'subscription_expired',
        'payment_failed',
        'login_after_inactivity',
        'profile_completed'
      ).required(),
      otherwise: Joi.forbidden()
    }),
    conditions: Joi.when('type', {
      is: 'condition_based',
      then: Joi.array().items(Joi.object({
        field: Joi.string().required(),
        operator: Joi.string().valid(
          'equals', 'not_equals', 'greater_than', 'less_than',
          'contains', 'not_contains', 'in', 'not_in', 'exists', 'not_exists'
        ).required(),
        value: Joi.any(),
        dataType: Joi.string().valid('string', 'number', 'boolean', 'date', 'array')
      })).min(1).required(),
      otherwise: Joi.forbidden()
    })
  }).required(),
  conditions: Joi.array().items(Joi.object({
    field: Joi.string().required(),
    operator: Joi.string().valid(
      'equals', 'not_equals', 'greater_than', 'less_than',
      'contains', 'not_contains', 'in', 'not_in'
    ).required(),
    value: Joi.any().required(),
    combineWith: Joi.string().valid('AND', 'OR').default('AND')
  })).max(AdminLimits.LIFECYCLE.MAX_CONDITIONS_PER_RULE),
  actions: Joi.array().items(Joi.object({
    type: Joi.string().valid(
      'send_email',
      'send_notification',
      'change_status',
      'change_lifecycle_stage',
      'add_tag',
      'remove_tag',
      'trigger_webhook',
      'create_task',
      'update_field',
      'execute_script'
    ).required(),
    config: Joi.object().required(),
    delay: Joi.number().integer().min(0).max(86400) // max 24 hours delay
  })).min(1).max(AdminLimits.LIFECYCLE.MAX_ACTIONS_PER_RULE).required(),
  organizationId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
  isActive: Joi.boolean().default(true),
  priority: Joi.number().integer().min(1).max(100).default(50),
  tags: Joi.array().items(Joi.string()),
  restrictions: Joi.object({
    maxExecutionsPerUser: Joi.number().integer().min(1),
    cooldownPeriod: Joi.number().integer().min(60), // seconds
    excludeUserTags: Joi.array().items(Joi.string()),
    onlyUserTags: Joi.array().items(Joi.string())
  })
});

/**
 * Retention analysis query schema
 */
const retentionAnalysisQuerySchema = Joi.object({
  startDate: Joi.date().iso().max('now').required(),
  endDate: Joi.date().iso().greater(Joi.ref('startDate')).max('now').required(),
  cohortSize: Joi.string().valid('day', 'week', 'month', 'quarter').default('month'),
  segmentBy: Joi.string().valid(
    'lifecycle_stage', 'organization', 'plan', 'acquisition_source'
  ),
  includeChurnPrediction: Joi.boolean().default(true),
  minCohortSize: Joi.number().integer().min(1).default(10),
  excludeTestUsers: Joi.boolean().default(true)
}).custom((value, helpers) => {
  const daysDiff = moment(value.endDate).diff(moment(value.startDate), 'days');
  
  // Validate date range based on cohort size
  if (value.cohortSize === 'day' && daysDiff > 90) {
    return helpers.error('custom.dailyCohortLimit');
  }
  
  if (value.cohortSize === 'week' && daysDiff > 365) {
    return helpers.error('custom.weeklyCohortLimit');
  }
  
  return value;
}).messages({
  'custom.dailyCohortLimit': 'Daily cohort analysis limited to 90 days',
  'custom.weeklyCohortLimit': 'Weekly cohort analysis limited to 1 year'
});

/**
 * At-risk accounts query schema
 */
const atRiskAccountsQuerySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  riskThreshold: Joi.number().min(0).max(1).default(0.5),
  riskFactors: Joi.array().items(
    Joi.string().valid(
      'low_activity',
      'decreased_usage',
      'failed_payments',
      'support_tickets',
      'negative_feedback',
      'competitor_research',
      'expired_trial',
      'incomplete_onboarding'
    )
  ),
  organizationId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
  sortBy: Joi.string().valid(
    'riskScore', 'lastActiveAt', 'createdAt', 'lifetimeValue'
  ).default('riskScore'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
  includeRecommendations: Joi.boolean().default(true)
});

/**
 * Lifecycle events query schema
 */
const lifecycleEventsQuerySchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  userId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
  eventTypes: Joi.array().items(
    Joi.string().valid(
      'stage_transition',
      'reactivation',
      'suspension',
      'deletion_scheduled',
      'deletion_cancelled',
      'policy_applied',
      'automation_triggered'
    )
  ),
  startDate: Joi.date().iso(),
  endDate: Joi.date().iso().when('startDate', {
    is: Joi.exist(),
    then: Joi.date().greater(Joi.ref('startDate'))
  }),
  severity: Joi.string().valid('low', 'medium', 'high', 'critical'),
  automated: Joi.boolean(),
  sortBy: Joi.string().valid('timestamp', 'severity', 'eventType').default('timestamp'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc')
});

/**
 * Lifecycle action execution schema
 */
const lifecycleActionExecutionSchema = Joi.object({
  action: Joi.string().valid(
    'send_inactivity_warning',
    'apply_retention_campaign',
    'trigger_reactivation_sequence',
    'process_scheduled_deletions',
    'update_lifecycle_stages',
    'generate_at_risk_report'
  ).required(),
  userIds: Joi.array()
    .items(Joi.string().pattern(/^[0-9a-fA-F]{24}$/))
    .min(1)
    .unique(),
  filters: Joi.object({
    lifecycleStage: lifecycleSchemas.lifecycleStage,
    daysInStage: Joi.object({
      min: Joi.number().integer().min(0),
      max: Joi.number().integer().greater(Joi.ref('min'))
    }),
    riskScore: Joi.object({
      min: Joi.number().min(0).max(1),
      max: Joi.number().min(0).max(1).greater(Joi.ref('min'))
    })
  }),
  reason: lifecycleSchemas.reason.required(),
  parameters: Joi.object(),
  scheduleAt: Joi.date().iso().min('now'),
  testMode: Joi.boolean().default(false)
}).xor('userIds', 'filters');

/**
 * Custom validators for lifecycle operations
 */
const lifecycleValidators = {
  /**
   * Validate lifecycle stage transition
   * @param {string} currentStage - Current lifecycle stage
   * @param {string} targetStage - Target lifecycle stage
   * @returns {Object} Validation result
   */
  validateStageTransition: (currentStage, targetStage) => {
    const validTransitions = {
      onboarding: ['active', 'inactive', 'churned'],
      active: ['inactive', 'at_risk', 'suspended', 'deleted'],
      inactive: ['active', 'at_risk', 'churned', 'deleted'],
      at_risk: ['active', 'inactive', 'churned', 'reactivated'],
      churned: ['reactivated', 'deleted'],
      reactivated: ['active', 'inactive', 'at_risk'],
      suspended: ['active', 'deleted'],
      deleted: [] // No transitions from deleted
    };

    const allowed = validTransitions[currentStage] || [];
    
    return {
      valid: allowed.includes(targetStage),
      error: !allowed.includes(targetStage) ? 
        `Invalid transition from ${currentStage} to ${targetStage}` : null,
      allowedTransitions: allowed
    };
  },

  /**
   * Validate automation rule consistency
   * @param {Object} rule - Automation rule object
   * @returns {Object} Validation result
   */
  validateAutomationRule: (rule) => {
    const errors = [];
    
    // Check trigger and action compatibility
    if (rule.trigger.type === 'event_based' && rule.trigger.event === 'user_created') {
      const invalidActions = rule.actions.filter(a => 
        ['change_lifecycle_stage', 'send_inactivity_warning'].includes(a.type)
      );
      
      if (invalidActions.length > 0) {
        errors.push('Invalid actions for user_created event');
      }
    }
    
    // Check action dependencies
    const hasStatusChange = rule.actions.some(a => a.type === 'change_status');
    const hasStageChange = rule.actions.some(a => a.type === 'change_lifecycle_stage');
    
    if (hasStatusChange && hasStageChange) {
      errors.push('Cannot change both status and lifecycle stage in same rule');
    }
    
    // Validate action order
    const emailIndex = rule.actions.findIndex(a => a.type === 'send_email');
    const deleteIndex = rule.actions.findIndex(a => 
      a.type === 'change_status' && a.config.status === 'deleted'
    );
    
    if (emailIndex > -1 && deleteIndex > -1 && deleteIndex < emailIndex) {
      errors.push('Cannot send email after deletion action');
    }
    
    return {
      valid: errors.length === 0,
      errors
    };
  },

  /**
   * Validate retention policy consistency
   * @param {Object} policies - Lifecycle policies
   * @returns {Object} Validation result
   */
  validateRetentionPolicies: (policies) => {
    const warnings = [];
    
    // Check for aggressive policies
    if (policies.inactivityWarning && policies.inactivityWarning < 30) {
      warnings.push('Inactivity warning period is very short (< 30 days)');
    }
    
    if (policies.dataRetention && policies.dataRetention < 730) {
      warnings.push('Data retention period may not meet regulatory requirements');
    }
    
    // Check for conflicting policies
    if (policies.trialExpiration && policies.gracePeriods?.reactivation) {
      if (policies.trialExpiration > policies.gracePeriods.reactivation) {
        warnings.push('Trial expiration exceeds reactivation grace period');
      }
    }
    
    return {
      valid: true, // Warnings don't invalidate
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
const validateLifecycle = (schema, source = 'body') => {
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

    req[source] = value;
    next();
  };
};

// Export schemas and validators
module.exports = {
  schemas: {
    lifecycleOverviewQuery: lifecycleOverviewQuerySchema,
    lifecyclePolicies: lifecyclePoliciesSchema,
    lifecycleTransition: lifecycleTransitionSchema,
    accountReactivation: accountReactivationSchema,
    scheduledDeletion: scheduledDeletionSchema,
    lifecycleAutomationRule: lifecycleAutomationRuleSchema,
    retentionAnalysisQuery: retentionAnalysisQuerySchema,
    atRiskAccountsQuery: atRiskAccountsQuerySchema,
    lifecycleEventsQuery: lifecycleEventsQuerySchema,
    lifecycleActionExecution: lifecycleActionExecutionSchema
  },
  validators: lifecycleValidators,
  middleware: {
    validateLifecycleOverview: validateLifecycle(lifecycleOverviewQuerySchema, 'query'),
    validateLifecyclePolicies: validateLifecycle(lifecyclePoliciesSchema),
    validateLifecycleTransition: validateLifecycle(lifecycleTransitionSchema),
    validateAccountReactivation: validateLifecycle(accountReactivationSchema),
    validateScheduledDeletion: validateLifecycle(scheduledDeletionSchema),
    validateAutomationRule: validateLifecycle(lifecycleAutomationRuleSchema),
    validateRetentionAnalysis: validateLifecycle(retentionAnalysisQuerySchema, 'query'),
    validateAtRiskAccounts: validateLifecycle(atRiskAccountsQuerySchema, 'query'),
    validateLifecycleEvents: validateLifecycle(lifecycleEventsQuerySchema, 'query'),
    validateLifecycleAction: validateLifecycle(lifecycleActionExecutionSchema)
  }
};