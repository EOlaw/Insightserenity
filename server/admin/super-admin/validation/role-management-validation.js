// server/admin/super-admin/validation/role-management-validation.js
/**
 * @file Role Management Validation
 * @description Validation schemas for role and permission management operations
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');

// Shared validation utilities
const { objectId, email } = require('../../../shared/validation/common-validators');

// Constants
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * Custom validators for role management
 */
const customValidators = {
  /**
   * Validate role name format
   */
  roleName: () => Joi.string()
    .pattern(/^[a-z0-9_]+$/)
    .min(3)
    .max(50)
    .messages({
      'string.pattern.base': 'Role name must contain only lowercase letters, numbers, and underscores',
      'string.min': 'Role name must be at least 3 characters',
      'string.max': 'Role name cannot exceed 50 characters'
    }),

  /**
   * Validate permission format
   */
  permission: () => Joi.string()
    .pattern(/^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*(\.\*)?$/)
    .messages({
      'string.pattern.base': 'Invalid permission format. Use format: resource.action or resource.*'
    }),

  /**
   * Validate permission object
   */
  permissionObject: () => Joi.object({
    resource: Joi.string()
      .pattern(/^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$/)
      .required(),
    actions: Joi.array()
      .items(Joi.string().pattern(/^[a-zA-Z0-9_]+$/))
      .min(1)
      .unique()
      .required(),
    conditions: Joi.object(),
    metadata: Joi.object()
  })
};

/**
 * Role Management Validation Schemas
 */
const RoleManagementValidation = {
  /**
   * Create role validation
   */
  createRole: {
    body: Joi.object({
      name: customValidators.roleName()
        .required()
        .messages({
          'any.required': 'Role name is required'
        }),
      
      displayName: Joi.string()
        .min(3)
        .max(100)
        .messages({
          'string.min': 'Display name must be at least 3 characters',
          'string.max': 'Display name cannot exceed 100 characters'
        }),
      
      description: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Description must be at least 10 characters',
          'string.max': 'Description cannot exceed 500 characters',
          'any.required': 'Role description is required'
        }),
      
      category: Joi.string()
        .valid('system', 'organization', 'custom', 'integration')
        .default('custom'),
      
      permissions: Joi.array()
        .items(Joi.alternatives().try(
          objectId(), // Permission ID
          customValidators.permission() // Permission string
        ))
        .unique()
        .max(200)
        .default([])
        .messages({
          'array.max': 'Cannot assign more than 200 permissions to a role'
        }),
      
      inheritFrom: objectId()
        .messages({
          'string.pattern.base': 'Invalid parent role ID'
        }),
      
      priority: Joi.number()
        .integer()
        .min(1)
        .max(1000)
        .default(100),
      
      constraints: Joi.object({
        maxUsers: Joi.number()
          .integer()
          .min(0)
          .max(10000),
        
        requireMFA: Joi.boolean()
          .default(false),
        
        requireEmailVerification: Joi.boolean()
          .default(true),
        
        ipWhitelist: Joi.array()
          .items(Joi.string().ip())
          .max(50),
        
        timeRestrictions: Joi.object({
          timezone: Joi.string(),
          allowedHours: Joi.object({
            start: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/),
            end: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/)
          }),
          allowedDays: Joi.array()
            .items(Joi.number().integer().min(0).max(6))
        }),
        
        geographicRestrictions: Joi.object({
          allowedCountries: Joi.array()
            .items(Joi.string().length(2).uppercase()),
          blockedCountries: Joi.array()
            .items(Joi.string().length(2).uppercase())
        }).xor('allowedCountries', 'blockedCountries')
      }).default({}),
      
      metadata: Joi.object()
        .max(20)
        .default({})
    })
  },

  /**
   * Update role validation
   */
  updateRole: {
    params: Joi.object({
      roleId: Joi.alternatives().try(
        objectId(),
        customValidators.roleName()
      ).required()
    }),
    
    body: Joi.object({
      displayName: Joi.string()
        .min(3)
        .max(100),
      
      description: Joi.string()
        .min(10)
        .max(500),
      
      permissions: Joi.array()
        .items(Joi.alternatives().try(
          objectId(),
          customValidators.permission()
        ))
        .unique()
        .max(200),
      
      priority: Joi.number()
        .integer()
        .min(1)
        .max(1000),
      
      constraints: Joi.object({
        maxUsers: Joi.number()
          .integer()
          .min(0)
          .max(10000),
        
        requireMFA: Joi.boolean(),
        
        requireEmailVerification: Joi.boolean(),
        
        ipWhitelist: Joi.array()
          .items(Joi.string().ip())
          .max(50),
        
        timeRestrictions: Joi.object({
          timezone: Joi.string(),
          allowedHours: Joi.object({
            start: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/),
            end: Joi.string().pattern(/^([01]\d|2[0-3]):([0-5]\d)$/)
          }),
          allowedDays: Joi.array()
            .items(Joi.number().integer().min(0).max(6))
        }),
        
        geographicRestrictions: Joi.object({
          allowedCountries: Joi.array()
            .items(Joi.string().length(2).uppercase()),
          blockedCountries: Joi.array()
            .items(Joi.string().length(2).uppercase())
        }).xor('allowedCountries', 'blockedCountries')
      }),
      
      metadata: Joi.object()
        .max(20),
      
      isActive: Joi.boolean()
    }).min(1)
      .messages({
        'object.min': 'At least one field must be provided for update'
      })
  },

  /**
   * Delete role validation
   */
  deleteRole: {
    params: Joi.object({
      roleId: Joi.alternatives().try(
        objectId(),
        customValidators.roleName()
      ).required()
    }),
    
    body: Joi.object({
      reassignTo: Joi.alternatives().try(
        objectId(),
        customValidators.roleName()
      ).messages({
        'alternatives.match': 'Reassign target must be a valid role ID or name'
      }),
      
      force: Joi.boolean()
        .default(false),
      
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Deletion reason must be at least 10 characters',
          'any.required': 'Deletion reason is required'
        })
    })
  },

  /**
   * Clone role validation
   */
  cloneRole: {
    params: Joi.object({
      roleId: Joi.alternatives().try(
        objectId(),
        customValidators.roleName()
      ).required()
    }),
    
    body: Joi.object({
      name: customValidators.roleName()
        .required()
        .messages({
          'any.required': 'New role name is required for cloning'
        }),
      
      displayName: Joi.string()
        .min(3)
        .max(100),
      
      description: Joi.string()
        .min(10)
        .max(500),
      
      modifyPermissions: Joi.object({
        add: Joi.array()
          .items(Joi.alternatives().try(
            objectId(),
            customValidators.permission()
          ))
          .unique()
          .max(50),
        
        remove: Joi.array()
          .items(Joi.alternatives().try(
            objectId(),
            customValidators.permission()
          ))
          .unique()
          .max(50)
      }).default({})
    })
  },

  /**
   * Bulk assign role validation
   */
  bulkAssignRole: {
    params: Joi.object({
      roleId: Joi.alternatives().try(
        objectId(),
        customValidators.roleName()
      ).required()
    }),
    
    body: Joi.object({
      userIds: Joi.array()
        .items(objectId())
        .min(1)
        .max(AdminLimits.BULK_OPERATIONS.MAX_USERS)
        .unique()
        .required()
        .messages({
          'array.min': 'At least one user ID is required',
          'array.max': `Cannot assign role to more than ${AdminLimits.BULK_OPERATIONS.MAX_USERS} users at once`,
          'any.required': 'User IDs array is required'
        }),
      
      notifyUsers: Joi.boolean()
        .default(true),
      
      reason: Joi.string()
        .min(10)
        .max(500)
        .required()
        .messages({
          'string.min': 'Assignment reason must be at least 10 characters',
          'any.required': 'Assignment reason is required'
        }),
      
      effectiveDate: Joi.date()
        .min('now')
        .default(() => new Date()),
      
      expiryDate: Joi.date()
        .greater(Joi.ref('effectiveDate'))
        .messages({
          'date.greater': 'Expiry date must be after effective date'
        })
    })
  },

  /**
   * Update role permissions validation
   */
  updatePermissions: {
    params: Joi.object({
      roleId: Joi.alternatives().try(
        objectId(),
        customValidators.roleName()
      ).required()
    }),
    
    body: Joi.object({
      permissions: Joi.array()
        .items(Joi.alternatives().try(
          objectId(),
          customValidators.permission()
        ))
        .min(1)
        .max(200)
        .unique()
        .required()
        .messages({
          'array.min': 'At least one permission is required',
          'array.max': 'Cannot assign more than 200 permissions',
          'any.required': 'Permissions array is required'
        }),
      
      operation: Joi.string()
        .valid('replace', 'add', 'remove')
        .default('replace')
        .messages({
          'any.only': 'Operation must be replace, add, or remove'
        })
    })
  },

  /**
   * Create permission validation
   */
  createPermission: {
    body: Joi.object({
      resource: Joi.string()
        .pattern(/^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$/)
        .required()
        .messages({
          'string.pattern.base': 'Invalid resource format. Use dot notation like module.submodule',
          'any.required': 'Resource is required'
        }),
      
      actions: Joi.array()
        .items(Joi.string().pattern(/^[a-zA-Z0-9_]+$/))
        .min(1)
        .max(20)
        .unique()
        .required()
        .messages({
          'array.min': 'At least one action is required',
          'array.max': 'Cannot define more than 20 actions',
          'any.required': 'Actions array is required'
        }),
      
      displayName: Joi.string()
        .min(3)
        .max(100)
        .required(),
      
      description: Joi.string()
        .min(10)
        .max(500)
        .required(),
      
      category: Joi.string()
        .valid('system', 'user', 'content', 'billing', 'api', 'custom')
        .default('custom'),
      
      riskLevel: Joi.string()
        .valid('low', 'medium', 'high', 'critical')
        .default('low'),
      
      requiresMFA: Joi.boolean()
        .default(false)
        .when('riskLevel', {
          is: Joi.valid('high', 'critical'),
          then: Joi.valid(true)
        }),
      
      metadata: Joi.object()
        .max(10)
        .default({})
    })
  },

  /**
   * Merge roles validation
   */
  mergeRoles: {
    body: Joi.object({
      sourceRoles: Joi.array()
        .items(Joi.alternatives().try(
          objectId(),
          customValidators.roleName()
        ))
        .min(2)
        .max(5)
        .unique()
        .required()
        .messages({
          'array.min': 'At least 2 source roles are required',
          'array.max': 'Cannot merge more than 5 roles at once',
          'any.required': 'Source roles array is required'
        }),
      
      targetRole: Joi.alternatives()
        .try(
          objectId(),
          customValidators.roleName(),
          Joi.object({
            name: customValidators.roleName().required(),
            displayName: Joi.string().min(3).max(100).required(),
            description: Joi.string().min(10).max(500).required()
          })
        )
        .required()
        .messages({
          'any.required': 'Target role is required'
        }),
      
      mergeOptions: Joi.object({
        combinePermissions: Joi.boolean().default(true),
        keepHighestPriority: Joi.boolean().default(true),
        mergeConstraints: Joi.string()
          .valid('strict', 'permissive')
          .default('strict'),
        deleteSourceRoles: Joi.boolean().default(false),
        reassignUsers: Joi.boolean().default(true)
      }).default({})
    })
  },

  /**
   * Import roles validation
   */
  importRoles: {
    body: Joi.object({
      data: Joi.alternatives()
        .try(
          Joi.string(), // JSON string
          Joi.object(), // Parsed object
          Joi.binary()  // File upload
        )
        .required()
        .messages({
          'any.required': 'Import data is required'
        }),
      
      options: Joi.object({
        mode: Joi.string()
          .valid('create', 'update', 'upsert')
          .default('create'),
        
        skipExisting: Joi.boolean()
          .default(true)
          .when('mode', {
            is: 'create',
            then: Joi.valid(true)
          }),
        
        updatePermissions: Joi.boolean()
          .default(false),
        
        validateOnly: Joi.boolean()
          .default(false),
        
        mapping: Joi.object({
          nameField: Joi.string().default('name'),
          displayNameField: Joi.string().default('displayName'),
          permissionsField: Joi.string().default('permissions')
        })
      }).default({})
    })
  },

  /**
   * Role search parameters
   */
  searchRoles: {
    query: Joi.object({
      search: Joi.string()
        .min(2)
        .max(100),
      
      category: Joi.string()
        .valid('system', 'organization', 'custom', 'integration'),
      
      includeSystem: Joi.string()
        .valid('true', 'false')
        .default('true'),
      
      includeCustom: Joi.string()
        .valid('true', 'false')
        .default('true'),
      
      hasPermission: customValidators.permission(),
      
      minUsers: Joi.number()
        .integer()
        .min(0),
      
      maxUsers: Joi.number()
        .integer()
        .min(0)
        .when('minUsers', {
          is: Joi.exist(),
          then: Joi.number().greater(Joi.ref('minUsers'))
        }),
      
      isActive: Joi.boolean(),
      
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
        .valid('name', 'priority', 'userCount', 'createdAt', 'updatedAt')
        .default('priority'),
      
      sortOrder: Joi.string()
        .valid('asc', 'desc')
        .default('asc')
    })
  },

  /**
   * Permission search parameters
   */
  searchPermissions: {
    query: Joi.object({
      search: Joi.string()
        .min(2)
        .max(100),
      
      resource: Joi.string()
        .pattern(/^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$/),
      
      category: Joi.string()
        .valid('system', 'user', 'content', 'billing', 'api', 'custom'),
      
      riskLevel: Joi.string()
        .valid('low', 'medium', 'high', 'critical'),
      
      requiresMFA: Joi.boolean(),
      
      page: Joi.number()
        .integer()
        .min(1)
        .default(1),
      
      limit: Joi.number()
        .integer()
        .min(1)
        .max(100)
        .default(50)
    })
  }
};

module.exports = RoleManagementValidation;