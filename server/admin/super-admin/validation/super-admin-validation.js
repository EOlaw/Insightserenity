// server/admin/super-admin/validation/super-admin-validation.js
/**
 * @file Super Admin Validation
 * @description Validation schemas for super administrator operations
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');

// Shared validation utilities
const { 
  objectId, 
  email, 
  password,
  phoneNumber,
  url,
  ipAddress 
} = require('../../../shared/validation/common-validators');

// Constants
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Super Admin Validation Schemas
 */
const SuperAdminValidation = {
  /**
   * User impersonation validation
   */
  impersonateUser: {
    body: Joi.object({
      userId: objectId().required()
        .messages({
          'any.required': 'User ID is required for impersonation',
          'string.pattern.base': 'Invalid user ID format'
        }),
      
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Reason must be at least 10 characters',
          'string.max': 'Reason cannot exceed 500 characters',
          'any.required': 'Detailed reason is required for impersonation'
        }),
      
      duration: Joi.number()
        .integer()
        .min(60)
        .max(AdminLimits.IMPERSONATION.MAX_DURATION)
        .default(3600)
        .messages({
          'number.min': 'Duration must be at least 60 seconds',
          'number.max': `Duration cannot exceed ${AdminLimits.IMPERSONATION.MAX_DURATION} seconds`
        }),
      
      restrictions: Joi.array()
        .items(Joi.string().valid(
          'no_notification',
          'read_only',
          'no_billing',
          'no_settings',
          'no_admin_functions'
        ))
        .unique()
        .max(5)
        .default([]),
      
      requireMFA: Joi.boolean()
        .default(true),
      
      notifyUser: Joi.boolean()
        .default(true),
      
      ticketId: Joi.string()
        .pattern(/^[A-Z]{2,4}-\d{4,8}$/)
        .messages({
          'string.pattern.base': 'Invalid ticket ID format'
        }),
      
      authorized: Joi.boolean()
        .when('ticketId', {
          is: Joi.exist(),
          then: Joi.required(),
          otherwise: Joi.forbidden()
        })
    })
  },

  /**
   * Emergency action validation
   */
  emergencyAction: {
    body: Joi.object({
      action: Joi.string()
        .valid(
          'EMERGENCY_SHUTDOWN',
          'DISABLE_ALL_LOGINS',
          'FORCE_LOGOUT_ALL',
          'ENABLE_MAINTENANCE_MODE',
          'EMERGENCY_BACKUP',
          'LOCK_DATABASE'
        )
        .required()
        .messages({
          'any.required': 'Emergency action type is required',
          'any.only': 'Invalid emergency action type'
        }),
      
      reason: Joi.string()
        .min(20)
        .max(1000)
        .required()
        .messages({
          'string.min': 'Reason must be at least 20 characters',
          'any.required': 'Detailed reason is required for emergency action'
        }),
      
      scope: Joi.string()
        .valid('system', 'application', 'database', 'network')
        .default('system'),
      
      duration: Joi.number()
        .integer()
        .min(0)
        .max(86400) // 24 hours
        .when('action', {
          is: Joi.valid('EMERGENCY_SHUTDOWN', 'ENABLE_MAINTENANCE_MODE'),
          then: Joi.required(),
          otherwise: Joi.optional()
        }),
      
      parameters: Joi.object({
        excludeAdmins: Joi.boolean().default(true),
        allowedIPs: Joi.array()
          .items(ipAddress())
          .max(20),
        message: Joi.string().max(500),
        readOnly: Joi.boolean(),
        gracePeriod: Joi.number().integer().min(0).max(3600)
      }).default({}),
      
      requireConfirmation: Joi.boolean()
        .default(true),
      
      confirmationCode: Joi.string()
        .length(6)
        .pattern(/^\d{6}$/)
        .when('requireConfirmation', {
          is: true,
          then: Joi.optional(),
          otherwise: Joi.forbidden()
        })
    })
  },

  /**
   * System configuration modification
   */
  modifyConfiguration: {
    body: Joi.object({
      category: Joi.string()
        .valid(
          'security',
          'authentication',
          'performance',
          'features',
          'billing',
          'notifications',
          'maintenance',
          'api_limits'
        )
        .required()
        .messages({
          'any.required': 'Configuration category is required',
          'any.only': 'Invalid configuration category'
        }),
      
      settings: Joi.object()
        .min(1)
        .max(50)
        .required()
        .messages({
          'object.min': 'At least one setting must be provided',
          'object.max': 'Cannot modify more than 50 settings at once',
          'any.required': 'Settings object is required'
        }),
      
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Reason must be at least 10 characters',
          'any.required': 'Reason is required for configuration changes'
        }),
      
      effectiveDate: Joi.date()
        .min('now')
        .max(Joi.ref('$now', { adjust: (value) => value + 30 * 24 * 60 * 60 * 1000 }))
        .default(() => new Date()),
      
      testMode: Joi.boolean()
        .default(false),
      
      acknowledgeImpact: Joi.boolean()
        .when('$impactLevel', {
          is: 'critical',
          then: Joi.required().valid(true),
          otherwise: Joi.optional()
        })
    })
  },

  /**
   * Generate system report
   */
  generateReport: {
    body: Joi.object({
      reportType: Joi.string()
        .valid(
          'system_overview',
          'security_audit',
          'performance_analysis',
          'user_analytics',
          'financial_summary',
          'compliance_report',
          'incident_report'
        )
        .required()
        .messages({
          'any.required': 'Report type is required',
          'any.only': 'Invalid report type'
        }),
      
      dateRange: Joi.object({
        startDate: Joi.date()
          .max('now')
          .required(),
        endDate: Joi.date()
          .min(Joi.ref('startDate'))
          .max('now')
          .required()
      }).required(),
      
      format: Joi.string()
        .valid('pdf', 'excel', 'csv', 'json')
        .default('pdf'),
      
      includeCharts: Joi.boolean()
        .default(true)
        .when('format', {
          is: Joi.valid('csv', 'json'),
          then: Joi.valid(false)
        }),
      
      recipients: Joi.array()
        .items(email())
        .max(10)
        .default([]),
      
      includeMetrics: Joi.array()
        .items(Joi.string())
        .when('reportType', {
          is: 'custom',
          then: Joi.required(),
          otherwise: Joi.optional()
        }),
      
      filters: Joi.object({
        organizations: Joi.array().items(objectId()),
        users: Joi.array().items(objectId()),
        severity: Joi.array().items(Joi.string().valid('low', 'medium', 'high', 'critical')),
        status: Joi.array().items(Joi.string())
      }).default({})
    })
  },

  /**
   * System maintenance scheduling
   */
  systemMaintenance: {
    body: Joi.object({
      maintenanceType: Joi.string()
        .valid(
          'routine',
          'emergency',
          'upgrade',
          'security_patch',
          'database_optimization',
          'backup_restore'
        )
        .required(),
      
      scheduledAt: Joi.date()
        .min('now')
        .required()
        .messages({
          'date.min': 'Maintenance must be scheduled in the future',
          'any.required': 'Scheduled time is required'
        }),
      
      duration: Joi.number()
        .integer()
        .min(300) // 5 minutes
        .max(28800) // 8 hours
        .required()
        .messages({
          'number.min': 'Maintenance duration must be at least 5 minutes',
          'number.max': 'Maintenance duration cannot exceed 8 hours'
        }),
      
      notification: Joi.object({
        sendAt: Joi.array()
          .items(Joi.number().integer().min(0))
          .default([86400, 3600, 900]), // 24h, 1h, 15m before
        
        customMessage: Joi.string()
          .max(1000),
        
        channels: Joi.array()
          .items(Joi.string().valid('email', 'sms', 'in-app', 'webhook'))
          .min(1)
          .default(['email', 'in-app'])
      }).default({}),
      
      tasks: Joi.array()
        .items(Joi.object({
          name: Joi.string().required(),
          order: Joi.number().integer().min(1),
          estimatedDuration: Joi.number().integer().min(60),
          critical: Joi.boolean().default(false)
        }))
        .min(1)
        .max(20)
        .required(),
      
      rollbackPlan: Joi.string()
        .min(50)
        .max(2000)
        .when('maintenanceType', {
          is: Joi.valid('upgrade', 'security_patch'),
          then: Joi.required()
        })
    })
  },

  /**
   * Broadcast notification
   */
  broadcastNotification: {
    body: Joi.object({
      type: Joi.string()
        .valid(
          'announcement',
          'maintenance',
          'security_alert',
          'feature_update',
          'policy_change',
          'outage'
        )
        .required(),
      
      title: Joi.string()
        .min(5)
        .max(100)
        .required()
        .messages({
          'string.min': 'Title must be at least 5 characters',
          'string.max': 'Title cannot exceed 100 characters'
        }),
      
      message: Joi.string()
        .min(10)
        .max(2000)
        .required()
        .messages({
          'string.min': 'Message must be at least 10 characters',
          'string.max': 'Message cannot exceed 2000 characters'
        }),
      
      targetAudience: Joi.object({
        type: Joi.string()
          .valid('all', 'organizations', 'users', 'admins', 'custom')
          .required(),
        
        filters: Joi.when('type', {
          is: 'custom',
          then: Joi.object({
            organizationIds: Joi.array().items(objectId()),
            userIds: Joi.array().items(objectId()),
            roles: Joi.array().items(Joi.string()),
            plans: Joi.array().items(Joi.string()),
            regions: Joi.array().items(Joi.string())
          }).or('organizationIds', 'userIds', 'roles', 'plans', 'regions'),
          otherwise: Joi.forbidden()
        })
      }).required(),
      
      priority: Joi.string()
        .valid('low', 'medium', 'high', 'urgent')
        .default('medium'),
      
      channels: Joi.array()
        .items(Joi.string().valid('in-app', 'email', 'sms', 'push'))
        .min(1)
        .default(['in-app', 'email']),
      
      scheduledAt: Joi.date()
        .min('now'),
      
      expiresAt: Joi.date()
        .min(Joi.ref('scheduledAt'))
        .when('type', {
          is: 'announcement',
          then: Joi.optional(),
          otherwise: Joi.forbidden()
        }),
      
      actionButton: Joi.object({
        text: Joi.string().max(50).required(),
        url: url().required(),
        style: Joi.string().valid('primary', 'secondary', 'danger').default('primary')
      })
    })
  },

  /**
   * Export system data
   */
  exportData: {
    body: Joi.object({
      dataTypes: Joi.array()
        .items(Joi.string().valid(
          'users',
          'organizations',
          'roles',
          'permissions',
          'audit_logs',
          'configurations',
          'subscriptions',
          'analytics'
        ))
        .min(1)
        .unique()
        .required()
        .messages({
          'array.min': 'At least one data type must be selected',
          'any.required': 'Data types are required'
        }),
      
      format: Joi.string()
        .valid('json', 'csv', 'excel', 'sql')
        .default('json'),
      
      dateRange: Joi.object({
        startDate: Joi.date()
          .max('now'),
        endDate: Joi.date()
          .min(Joi.ref('startDate'))
          .max('now')
      }).when('dataTypes', {
        is: Joi.array().items(Joi.valid('audit_logs', 'analytics')).min(1),
        then: Joi.required()
      }),
      
      includeMetadata: Joi.boolean()
        .default(true),
      
      compress: Joi.boolean()
        .default(true),
      
      encryption: Joi.object({
        enabled: Joi.boolean().default(true),
        password: Joi.string()
          .min(12)
          .when('enabled', {
            is: true,
            then: Joi.required()
          })
      }).default({ enabled: true }),
      
      filters: Joi.object({
        status: Joi.array().items(Joi.string()),
        roles: Joi.array().items(Joi.string()),
        organizations: Joi.array().items(objectId())
      }).default({})
    })
  },

  /**
   * Platform analytics query
   */
  platformAnalytics: {
    query: Joi.object({
      metric: Joi.string()
        .pattern(/^[a-zA-Z0-9,_]+$/)
        .default('all'),
      
      period: Joi.string()
        .pattern(/^(\d+)(h|d|w|m|y)$/)
        .default('30d')
        .messages({
          'string.pattern.base': 'Invalid period format. Use format like 30d, 1w, 3m'
        }),
      
      groupBy: Joi.string()
        .valid('hour', 'day', 'week', 'month')
        .default('day'),
      
      includeProjections: Joi.string()
        .valid('true', 'false')
        .default('false')
    })
  },

  /**
   * Search system entities
   */
  searchEntities: {
    query: Joi.object({
      query: Joi.string()
        .min(2)
        .max(100)
        .required()
        .messages({
          'string.min': 'Search query must be at least 2 characters',
          'any.required': 'Search query is required'
        }),
      
      types: Joi.string()
        .pattern(/^[a-zA-Z,_]+$/)
        .default('users,organizations,roles'),
      
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
   * User search parameters
   */
  userSearch: {
    query: Joi.object({
      search: Joi.string()
        .min(2)
        .max(100),
      
      role: Joi.string(),
      
      status: Joi.string()
        .valid('active', 'inactive', 'suspended', 'deleted'),
      
      organization: objectId(),
      
      createdAfter: Joi.date(),
      
      createdBefore: Joi.date()
        .when('createdAfter', {
          is: Joi.exist(),
          then: Joi.date().greater(Joi.ref('createdAfter'))
        }),
      
      hasActiveSessions: Joi.boolean(),
      
      page: Joi.number()
        .integer()
        .min(1)
        .default(1),
      
      limit: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .default(20),
      
      sortBy: Joi.string()
        .valid('createdAt', 'lastActiveAt', 'email', 'role')
        .default('createdAt'),
      
      sortOrder: Joi.string()
        .valid('asc', 'desc')
        .default('desc')
    })
  }
};

module.exports = SuperAdminValidation;