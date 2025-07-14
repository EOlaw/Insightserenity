// server/admin/super-admin/validation/emergency-access-validation.js
/**
 * @file Emergency Access Validation
 * @description Validation schemas for emergency access and critical operations
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');

// Shared validation utilities
const { objectId, email, ipAddress } = require('../../../shared/validation/common-validators');

// Constants
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Custom validators for emergency access
 */
const customValidators = {
  /**
   * Validate emergency code format
   */
  emergencyCode: () => Joi.string()
    .pattern(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/)
    .messages({
      'string.pattern.base': 'Invalid emergency code format. Expected: XXXX-XXXX-XXXX-XXXX'
    }),

  /**
   * Validate bypass type
   */
  bypassType: () => Joi.string()
    .valid(
      'AUTHENTICATION',
      'AUTHORIZATION',
      'RATE_LIMITING',
      'SECURITY_CHECKS',
      'SYSTEM_LOCKS',
      'FULL_OVERRIDE'
    ),

  /**
   * Validate access type
   */
  accessType: () => Joi.string()
    .valid(
      'BYPASS_AUTH',
      'OVERRIDE_PERMISSIONS',
      'UNLOCK_SYSTEM',
      'DISABLE_SECURITY',
      'FULL_ACCESS',
      'DATA_RECOVERY',
      'SYSTEM_RESTORE'
    )
};

/**
 * Emergency Access Validation Schemas
 */
const EmergencyAccessValidation = {
  /**
   * Request emergency access validation
   */
  requestAccess: {
    body: Joi.object({
      accessType: customValidators.accessType()
        .required()
        .messages({
          'any.required': 'Emergency access type is required',
          'any.only': 'Invalid emergency access type'
        }),
      
      reason: Joi.string()
        .min(30)
        .max(1000)
        .required()
        .messages({
          'string.min': 'Reason must be at least 30 characters for emergency access',
          'string.max': 'Reason cannot exceed 1000 characters',
          'any.required': 'Detailed reason is required for emergency access'
        }),
      
      duration: Joi.number()
        .integer()
        .min(300) // 5 minutes
        .max(AdminLimits.EMERGENCY_ACCESS.MAX_DURATION)
        .default(3600)
        .messages({
          'number.min': 'Duration must be at least 5 minutes',
          'number.max': `Duration cannot exceed ${AdminLimits.EMERGENCY_ACCESS.MAX_DURATION / 3600} hours`
        }),
      
      scope: Joi.object({
        systems: Joi.array()
          .items(Joi.string().valid(
            'authentication',
            'authorization',
            'database',
            'api',
            'frontend',
            'billing',
            'notifications'
          ))
          .unique()
          .default([]),
        
        operations: Joi.array()
          .items(Joi.string())
          .max(50)
          .default([]),
        
        dataAccess: Joi.array()
          .items(Joi.string())
          .max(20)
          .default([]),
        
        restrictions: Joi.array()
          .items(Joi.string())
          .max(10)
          .default([])
      }).default({}),
      
      urgencyLevel: Joi.string()
        .valid('low', 'medium', 'high', 'critical')
        .default('high'),
      
      affectedSystems: Joi.array()
        .items(Joi.string())
        .max(20)
        .default([]),
      
      requireDualAuth: Joi.boolean()
        .when('accessType', {
          is: Joi.valid('FULL_ACCESS', 'SYSTEM_RESTORE'),
          then: Joi.valid(true),
          otherwise: Joi.optional()
        })
        .default(true),
      
      ticketReference: Joi.string()
        .pattern(/^[A-Z]{2,4}-\d{4,8}$/),
      
      externalAuthorization: Joi.object({
        authorizedBy: email(),
        authorizationCode: Joi.string(),
        expiresAt: Joi.date().min('now')
      }).and('authorizedBy', 'authorizationCode', 'expiresAt')
    })
  },

  /**
   * Activate emergency access validation
   */
  activateAccess: {
    params: Joi.object({
      requestId: Joi.string()
        .uuid()
        .required()
    }),
    
    body: Joi.object({
      primaryCode: customValidators.emergencyCode()
        .required()
        .messages({
          'any.required': 'Primary authentication code is required'
        }),
      
      secondaryCode: customValidators.emergencyCode()
        .when('$requireDualAuth', {
          is: true,
          then: Joi.required(),
          otherwise: Joi.optional()
        })
        .messages({
          'any.required': 'Secondary authentication code is required for dual authentication'
        }),
      
      confirmRisks: Joi.boolean()
        .valid(true)
        .required()
        .messages({
          'any.required': 'You must confirm understanding of the risks',
          'any.only': 'Risk confirmation must be explicitly true'
        })
    })
  },

  /**
   * Revoke emergency access validation
   */
  revokeAccess: {
    params: Joi.object({
      requestId: Joi.string()
        .uuid()
        .required()
    }),
    
    body: Joi.object({
      reason: Joi.string()
        .min(20)
        .max(500)
        .required()
        .messages({
          'string.min': 'Revocation reason must be at least 20 characters',
          'any.required': 'Revocation reason is required'
        }),
      
      immediate: Joi.boolean()
        .default(true),
      
      notifyAffectedUsers: Joi.boolean()
        .default(true)
    })
  },

  /**
   * Break glass access validation
   */
  breakGlass: {
    body: Joi.object({
      reason: Joi.string()
        .min(50)
        .max(2000)
        .required()
        .messages({
          'string.min': 'Break glass reason must be at least 50 characters',
          'any.required': 'Detailed reason is required for break glass access'
        }),
      
      systems: Joi.array()
        .items(Joi.string().valid(
          'all',
          'authentication',
          'authorization',
          'database',
          'api',
          'configuration',
          'billing'
        ))
        .min(1)
        .unique()
        .default(['all']),
      
      duration: Joi.number()
        .integer()
        .min(300) // 5 minutes
        .max(3600) // 1 hour max for break glass
        .default(3600)
        .messages({
          'number.max': 'Break glass access cannot exceed 1 hour'
        }),
      
      notificationList: Joi.array()
        .items(email())
        .max(10)
        .default([]),
      
      videoAuthToken: Joi.string()
        .when('$requireVideoAuth', {
          is: true,
          then: Joi.required(),
          otherwise: Joi.optional()
        }),
      
      acknowledgeIrreversible: Joi.boolean()
        .valid(true)
        .required()
        .messages({
          'any.required': 'You must acknowledge that some actions may be irreversible',
          'any.only': 'Acknowledgment must be explicitly true'
        })
    })
  },

  /**
   * System bypass validation
   */
  systemBypass: {
    body: Joi.object({
      bypassType: customValidators.bypassType()
        .required()
        .messages({
          'any.required': 'Bypass type is required',
          'any.only': 'Invalid bypass type'
        }),
      
      targets: Joi.array()
        .items(Joi.object({
          type: Joi.string()
            .valid('user', 'api', 'service', 'endpoint')
            .required(),
          id: Joi.string().required(),
          scope: Joi.string()
        }))
        .min(1)
        .max(50)
        .required()
        .messages({
          'array.min': 'At least one target is required',
          'array.max': 'Cannot bypass more than 50 targets at once'
        }),
      
      duration: Joi.number()
        .integer()
        .min(60) // 1 minute
        .max(1800) // 30 minutes
        .required(),
      
      reason: Joi.string()
        .min(20)
        .max(500)
        .required(),
      
      restrictions: Joi.array()
        .items(Joi.string())
        .default([]),
      
      notifyTargets: Joi.boolean()
        .default(false)
    })
  },

  /**
   * Unlock resources validation
   */
  unlockResources: {
    body: Joi.object({
      resourceType: Joi.string()
        .valid(
          'user_account',
          'organization',
          'api_endpoint',
          'database_table',
          'system_feature',
          'configuration'
        )
        .required()
        .messages({
          'any.required': 'Resource type is required',
          'any.only': 'Invalid resource type'
        }),
      
      resourceIds: Joi.array()
        .items(Joi.string())
        .min(1)
        .max(100)
        .unique()
        .required()
        .messages({
          'array.min': 'At least one resource ID is required',
          'array.max': 'Cannot unlock more than 100 resources at once'
        }),
      
      reason: Joi.string()
        .min(15)
        .max(500)
        .required(),
      
      notifyAffected: Joi.boolean()
        .default(true),
      
      clearFlags: Joi.array()
        .items(Joi.string().valid(
          'locked',
          'suspended',
          'rate_limited',
          'security_hold',
          'failed_attempts'
        ))
        .default(['locked'])
    })
  },

  /**
   * Test emergency procedures validation
   */
  testProcedures: {
    body: Joi.object({
      procedureType: Joi.string()
        .valid(
          'access_request',
          'dual_auth',
          'break_glass',
          'system_bypass',
          'recovery',
          'notification'
        )
        .required(),
      
      testScenario: Joi.string()
        .valid(
          'happy_path',
          'auth_failure',
          'timeout',
          'concurrent_access',
          'system_failure'
        )
        .required(),
      
      dryRun: Joi.boolean()
        .default(true),
      
      parameters: Joi.object()
        .default({}),
      
      notifyTeam: Joi.boolean()
        .default(false)
    })
  },

  /**
   * Configure emergency contacts validation
   */
  configureContacts: {
    body: Joi.object({
      contacts: Joi.array()
        .items(Joi.object({
          name: Joi.string()
            .min(2)
            .max(100)
            .required(),
          
          role: Joi.string()
            .valid(
              'primary',
              'secondary',
              'security_team',
              'management',
              'technical'
            )
            .required(),
          
          email: email()
            .required(),
          
          phone: Joi.string()
            .pattern(/^\+?[1-9]\d{1,14}$/),
          
          availability: Joi.object({
            timezone: Joi.string().required(),
            hours: Joi.object({
              start: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/),
              end: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/)
            }),
            days: Joi.array()
              .items(Joi.number().integer().min(0).max(6))
          }),
          
          notificationPreferences: Joi.object({
            email: Joi.boolean().default(true),
            sms: Joi.boolean().default(false),
            phone: Joi.boolean().default(false),
            slack: Joi.boolean().default(false)
          }).default({})
        }))
        .min(2)
        .max(20)
        .required()
        .messages({
          'array.min': 'At least 2 emergency contacts are required',
          'array.max': 'Cannot configure more than 20 emergency contacts'
        }),
      
      escalationChain: Joi.array()
        .items(Joi.object({
          level: Joi.number()
            .integer()
            .min(1)
            .max(5)
            .required(),
          
          contacts: Joi.array()
            .items(Joi.string())
            .min(1)
            .required(),
          
          waitTime: Joi.number()
            .integer()
            .min(60) // 1 minute
            .max(1800) // 30 minutes
            .required()
        }))
        .min(1)
        .max(5)
        .required(),
      
      notificationSettings: Joi.object({
        alertAllOnCritical: Joi.boolean().default(true),
        requireAcknowledgment: Joi.boolean().default(true),
        retryAttempts: Joi.number().integer().min(1).max(5).default(3),
        retryInterval: Joi.number().integer().min(30).max(300).default(60)
      }).default({})
    })
  },

  /**
   * Generate emergency report validation
   */
  generateReport: {
    body: Joi.object({
      reportType: Joi.string()
        .valid(
          'access_log',
          'incident_summary',
          'audit_trail',
          'impact_assessment',
          'compliance_report'
        )
        .required(),
      
      dateRange: Joi.object({
        startDate: Joi.date()
          .max('now')
          .required(),
        endDate: Joi.date()
          .min(Joi.ref('startDate'))
          .max('now')
          .required()
      }).required(),
      
      filters: Joi.object({
        accessTypes: Joi.array().items(customValidators.accessType()),
        urgencyLevels: Joi.array().items(Joi.string()),
        adminUsers: Joi.array().items(objectId()),
        statuses: Joi.array().items(Joi.string())
      }).default({}),
      
      includeRecommendations: Joi.boolean()
        .default(true),
      
      format: Joi.string()
        .valid('pdf', 'html', 'json')
        .default('pdf'),
      
      recipients: Joi.array()
        .items(email())
        .max(10)
        .default([])
    })
  },

  /**
   * Review emergency request validation
   */
  reviewRequest: {
    params: Joi.object({
      requestId: Joi.string()
        .uuid()
        .required()
    }),
    
    body: Joi.object({
      decision: Joi.string()
        .valid('approve', 'reject', 'require_more_info')
        .required()
        .messages({
          'any.required': 'Review decision is required',
          'any.only': 'Decision must be approve, reject, or require_more_info'
        }),
      
      comments: Joi.string()
        .min(10)
        .max(1000)
        .required()
        .messages({
          'string.min': 'Review comments must be at least 10 characters',
          'any.required': 'Review comments are required'
        }),
      
      conditions: Joi.when('decision', {
        is: 'approve',
        then: Joi.object({
          reducedDuration: Joi.number()
            .integer()
            .min(300),
          
          additionalRestrictions: Joi.array()
            .items(Joi.string())
            .max(10),
          
          requireVideoAuth: Joi.boolean(),
          
          notificationList: Joi.array()
            .items(email())
            .max(5)
        }),
        otherwise: Joi.forbidden()
      })
    })
  },

  /**
   * Update emergency protocol validation
   */
  updateProtocol: {
    params: Joi.object({
      protocolId: objectId().required()
    }),
    
    body: Joi.object({
      name: Joi.string()
        .min(3)
        .max(100),
      
      description: Joi.string()
        .min(10)
        .max(1000),
      
      triggers: Joi.array()
        .items(Joi.object({
          type: Joi.string().required(),
          condition: Joi.string().required(),
          threshold: Joi.any()
        }))
        .min(1),
      
      actions: Joi.array()
        .items(Joi.object({
          type: Joi.string().required(),
          parameters: Joi.object(),
          order: Joi.number().integer().min(1)
        }))
        .min(1),
      
      notifications: Joi.object({
        recipients: Joi.array().items(Joi.string()),
        channels: Joi.array().items(Joi.string()),
        template: Joi.string()
      }),
      
      active: Joi.boolean(),
      
      testSchedule: Joi.object({
        frequency: Joi.string().valid('weekly', 'monthly', 'quarterly'),
        nextTest: Joi.date().min('now')
      })
    }).min(1)
  },

  /**
   * Simulate emergency scenario validation
   */
  simulateScenario: {
    body: Joi.object({
      scenario: Joi.string()
        .valid(
          'database_failure',
          'authentication_breach',
          'mass_lockout',
          'data_corruption',
          'service_outage',
          'security_incident'
        )
        .required(),
      
      parameters: Joi.object({
        severity: Joi.string()
          .valid('low', 'medium', 'high', 'critical')
          .default('high'),
        
        affectedSystems: Joi.array()
          .items(Joi.string())
          .default(['all']),
        
        duration: Joi.number()
          .integer()
          .min(300)
          .max(7200)
          .default(1800),
        
        userImpact: Joi.number()
          .integer()
          .min(0)
          .max(100)
          .default(50)
      }).default({}),
      
      recordResults: Joi.boolean()
        .default(true),
      
      notifyParticipants: Joi.boolean()
        .default(false)
    })
  },

  /**
   * Execute recovery validation
   */
  executeRecovery: {
    body: Joi.object({
      recoveryType: Joi.string()
        .valid(
          'data_restore',
          'configuration_rollback',
          'service_restart',
          'cache_clear',
          'session_reset',
          'full_system_restore'
        )
        .required(),
      
      targetSystems: Joi.array()
        .items(Joi.string())
        .min(1)
        .required(),
      
      backupId: objectId()
        .when('recoveryType', {
          is: Joi.valid('data_restore', 'full_system_restore'),
          then: Joi.required(),
          otherwise: Joi.optional()
        }),
      
      verificationRequired: Joi.boolean()
        .default(true),
      
      rollbackOnFailure: Joi.boolean()
        .default(true),
      
      maintenanceWindow: Joi.object({
        start: Joi.date().min('now'),
        duration: Joi.number().integer().min(300).max(14400)
      }),
      
      confirmationCode: Joi.string()
        .length(6)
        .pattern(/^\d{6}$/)
        .when('recoveryType', {
          is: 'full_system_restore',
          then: Joi.required(),
          otherwise: Joi.optional()
        })
    })
  }
};

module.exports = EmergencyAccessValidation;