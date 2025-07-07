// // server/shared/auth/middleware/permission-middleware.js
// /**
//  * @file Permission Middleware
//  * @description Advanced permission and access control middleware
//  * @version 3.0.0
//  */

// const config = require('../../config');
// const { asyncHandler } = require('../../utils/async-handler');
// const logger = require('../../utils/logger');
// const ResponseHandler = require('../../utils/response-handler');

// /**
//  * Permission Middleware Class
//  * @class PermissionMiddleware
//  */
// class PermissionMiddleware {
//   /**
//    * Initialize permission system
//    */
//   static initialize() {
//     // Define permission hierarchy
//     this.permissionHierarchy = {
//       // System permissions
//       'system.*': ['system.read', 'system.write', 'system.delete', 'system.admin'],
//       'system.admin': ['system.read', 'system.write', 'system.delete'],
//       'system.write': ['system.read'],
      
//       // User permissions
//       'user.*': ['user.read', 'user.write', 'user.delete', 'user.admin'],
//       'user.admin': ['user.read', 'user.write', 'user.delete'],
//       'user.write': ['user.read'],
      
//       // Organization permissions
//       'organization.*': ['organization.read', 'organization.write', 'organization.delete', 'organization.admin'],
//       'organization.admin': ['organization.read', 'organization.write', 'organization.delete', 'organization.members.manage'],
//       'organization.write': ['organization.read'],
      
//       // Project permissions
//       'project.*': ['project.read', 'project.write', 'project.delete', 'project.admin'],
//       'project.admin': ['project.read', 'project.write', 'project.delete', 'project.members.manage'],
//       'project.write': ['project.read'],
      
//       // Billing permissions
//       'billing.*': ['billing.read', 'billing.write', 'billing.admin'],
//       'billing.admin': ['billing.read', 'billing.write', 'billing.refund'],
//       'billing.write': ['billing.read'],
      
//       // Recruitment permissions
//       'recruitment.*': ['recruitment.read', 'recruitment.write', 'recruitment.admin'],
//       'recruitment.admin': ['recruitment.read', 'recruitment.write', 'recruitment.delete'],
//       'recruitment.write': ['recruitment.read']
//     };
    
//     // Role-based permissions
//     this.rolePermissions = {
//       // Platform roles
//       super_admin: ['*'],
//       platform_admin: [
//         'system.read', 'system.write',
//         'user.*', 'organization.*', 'billing.*'
//       ],
//       support_agent: [
//         'user.read', 'organization.read', 'billing.read',
//         'project.read', 'recruitment.read'
//       ],
      
//       // Core business roles
//       partner: [
//         'organization.admin', 'project.admin', 'billing.admin',
//         'user.admin', 'recruitment.admin'
//       ],
//       director: [
//         'organization.write', 'project.admin', 'billing.read',
//         'user.write', 'recruitment.write'
//       ],
//       manager: [
//         'project.admin', 'user.write', 'billing.read'
//       ],
//       consultant: [
//         'project.write', 'user.read', 'billing.read'
//       ],
//       junior_consultant: [
//         'project.read', 'user.read'
//       ],
      
//       // Organization roles
//       org_owner: [
//         'organization.admin', 'project.admin', 'billing.admin',
//         'user.admin'
//       ],
//       org_admin: [
//         'organization.write', 'project.admin', 'user.write'
//       ],
//       org_member: [
//         'organization.read', 'project.write', 'user.read'
//       ],
      
//       // Recruitment roles
//       recruitment_admin: [
//         'recruitment.admin', 'user.write'
//       ],
//       recruiter: [
//         'recruitment.write', 'user.read'
//       ],
//       hiring_manager: [
//         'recruitment.read', 'recruitment.approve'
//       ],
//       candidate: [
//         'recruitment.apply', 'user.read.own'
//       ],
      
//       // Client roles
//       client: [
//         'organization.create', 'organization.read', 'organization.update.own',
//         'project.read', 'billing.read', 'user.read.own'
//       ],
//       prospect: [
//         'organization.read', 'user.read.own'
//       ]
//     };
//   }
  
//   /**
//    * Check if user has permission
//    * @param {Object} user - User object
//    * @param {string} permission - Required permission
//    * @returns {boolean} Has permission
//    */
//   static hasPermission(user, permission) {
//     if (!user) return false;
    
//     // Super admin has all permissions
//     if (user.role?.primary === 'super_admin') return true;
    
//     // Check direct permissions
//     const userPermissions = user.permissions || [];
//     if (userPermissions.includes('*') || userPermissions.includes(permission)) {
//       return true;
//     }
    
//     // Check role-based permissions
//     const rolePermissions = this.rolePermissions[user.role?.primary] || [];
//     if (rolePermissions.includes('*') || rolePermissions.includes(permission)) {
//       return true;
//     }
    
//     // Check permission hierarchy
//     for (const perm of userPermissions.concat(rolePermissions)) {
//       if (this.permissionHierarchy[perm]?.includes(permission)) {
//         return true;
//       }
//     }
    
//     return false;
//   }
  
//   /**
//    * Require specific permissions
//    * @param {string|Array} permissions - Required permissions
//    * @param {Object} options - Middleware options
//    * @returns {Function} Express middleware
//    */
//   static require(permissions, options = {}) {
//     const {
//       checkAll = false,
//       customCheck = null,
//       errorMessage = 'Insufficient permissions'
//     } = options;
    
//     const permissionArray = Array.isArray(permissions) ? permissions : [permissions];
    
//     return asyncHandler(async (req, res, next) => {
//       if (!req.user) {
//         return ResponseHandler.unauthorized(res, 'Authentication required');
//       }
      
//       // Custom permission check
//       if (customCheck) {
//         const allowed = await customCheck(req.user, req);
//         if (!allowed) {
//           return ResponseHandler.forbidden(res, errorMessage, 'CUSTOM_CHECK_FAILED');
//         }
//         return next();
//       }
      
//       // Standard permission check
//       let hasAccess;
//       if (checkAll) {
//         hasAccess = permissionArray.every(perm => this.hasPermission(req.user, perm));
//       } else {
//         hasAccess = permissionArray.some(perm => this.hasPermission(req.user, perm));
//       }
      
//       if (!hasAccess) {
//         logger.warn('Permission denied', {
//           userId: req.user._id,
//           required: permissionArray,
//           userPermissions: req.user.permissions,
//           userRole: req.user.role?.primary
//         });
        
//         return ResponseHandler.forbidden(res, errorMessage, 'INSUFFICIENT_PERMISSIONS');
//       }
      
//       next();
//     });
//   }
  
//   /**
//    * Check resource-based permissions
//    * @param {Function} getResource - Function to retrieve resource
//    * @param {string} permission - Required permission
//    * @param {Object} options - Middleware options
//    * @returns {Function} Express middleware
//    */
//   static requireForResource(getResource, permission, options = {}) {
//     const {
//       ownerField = 'owner',
//       organizationField = 'organizationId',
//       checkOrganizationAccess = true
//     } = options;
    
//     return asyncHandler(async (req, res, next) => {
//       if (!req.user) {
//         return ResponseHandler.unauthorized(res, 'Authentication required');
//       }
      
//       // Get resource
//       const resource = await getResource(req);
//       if (!resource) {
//         return ResponseHandler.notFound(res, 'Resource');
//       }
      
//       // Check global permission
//       if (this.hasPermission(req.user, permission)) {
//         req.resource = resource;
//         return next();
//       }
      
//       // Check ownership
//       const ownerId = resource[ownerField]?.toString();
//       if (ownerId === req.user._id.toString()) {
//         req.resource = resource;
//         return next();
//       }
      
//       // Check organization access
//       if (checkOrganizationAccess && resource[organizationField]) {
//         const hasOrgAccess = await this.checkOrganizationPermission(
//           req.user,
//           resource[organizationField],
//           permission
//         );
        
//         if (hasOrgAccess) {
//           req.resource = resource;
//           return next();
//         }
//       }
      
//       return ResponseHandler.forbidden(res, 'Access denied to this resource');
//     });
//   }
  
//   /**
//    * Dynamic permission check
//    * @param {Function} permissionResolver - Function to resolve required permissions
//    * @returns {Function} Express middleware
//    */
//   static dynamic(permissionResolver) {
//     return asyncHandler(async (req, res, next) => {
//       if (!req.user) {
//         return ResponseHandler.unauthorized(res, 'Authentication required');
//       }
      
//       // Resolve required permissions
//       const requiredPermissions = await permissionResolver(req);
      
//       if (!requiredPermissions || requiredPermissions.length === 0) {
//         return next();
//       }
      
//       // Check permissions
//       const hasAccess = Array.isArray(requiredPermissions)
//         ? requiredPermissions.some(perm => this.hasPermission(req.user, perm))
//         : this.hasPermission(req.user, requiredPermissions);
      
//       if (!hasAccess) {
//         return ResponseHandler.forbidden(res, 'Dynamic permission check failed');
//       }
      
//       next();
//     });
//   }
  
//   /**
//    * Scope-based permission check
//    * @param {string} scope - Required scope
//    * @param {Object} options - Middleware options
//    * @returns {Function} Express middleware
//    */
//   static requireScope(scope, options = {}) {
//     const {
//       scopeField = 'scopes',
//       allowSubScopes = true
//     } = options;
    
//     return (req, res, next) => {
//       if (!req.user) {
//         return ResponseHandler.unauthorized(res, 'Authentication required');
//       }
      
//       const userScopes = req.user[scopeField] || req.token?.[scopeField] || [];
      
//       // Direct scope match
//       if (userScopes.includes(scope) || userScopes.includes('*')) {
//         return next();
//       }
      
//       // Sub-scope match
//       if (allowSubScopes) {
//         const scopeParts = scope.split('.');
//         for (let i = scopeParts.length - 1; i > 0; i--) {
//           const parentScope = scopeParts.slice(0, i).join('.') + '.*';
//           if (userScopes.includes(parentScope)) {
//             return next();
//           }
//         }
//       }
      
//       return ResponseHandler.forbidden(res, `Missing required scope: ${scope}`, 'INSUFFICIENT_SCOPE');
//     };
//   }
  
//   /**
//    * Time-based permission check
//    * @param {string} permission - Required permission
//    * @param {Object} timeConstraints - Time constraints
//    * @returns {Function} Express middleware
//    */
//   static requireWithTimeConstraint(permission, timeConstraints = {}) {
//     const {
//       allowedDays = [0, 1, 2, 3, 4, 5, 6], // All days
//       allowedHours = { start: 0, end: 24 }, // All hours
//       timezone = 'UTC'
//     } = timeConstraints;
    
//     return (req, res, next) => {
//       if (!req.user) {
//         return ResponseHandler.unauthorized(res, 'Authentication required');
//       }
      
//       // Check base permission
//       if (!this.hasPermission(req.user, permission)) {
//         return ResponseHandler.forbidden(res, 'Insufficient permissions');
//       }
      
//       // Check time constraints
//       const now = new Date();
//       const day = now.getUTCDay();
//       const hour = now.getUTCHours();
      
//       if (!allowedDays.includes(day)) {
//         return ResponseHandler.forbidden(res, 'Access not allowed on this day', 'TIME_CONSTRAINT');
//       }
      
//       if (hour < allowedHours.start || hour >= allowedHours.end) {
//         return ResponseHandler.forbidden(res, 'Access not allowed at this time', 'TIME_CONSTRAINT');
//       }
      
//       next();
//     };
//   }
  
//   /**
//    * Check organization permission
//    * @param {Object} user - User object
//    * @param {string} organizationId - Organization ID
//    * @param {string} permission - Required permission
//    * @returns {Promise<boolean>} Has permission
//    */
//   static async checkOrganizationPermission(user, organizationId, permission) {
//     // This would check user's role within the organization
//     // Simplified implementation
//     return user.organization?.organizations?.includes(organizationId);
//   }
  
//   /**
//    * Grant temporary permission
//    * @param {string} userId - User ID
//    * @param {string} permission - Permission to grant
//    * @param {number} duration - Duration in milliseconds
//    * @returns {Promise<string>} Grant ID
//    */
//   static async grantTemporary(userId, permission, duration) {
//     const grantId = require('crypto').randomBytes(16).toString('hex');
//     const expiresAt = new Date(Date.now() + duration);
    
//     // Store temporary grant (would use Redis in production)
//     // Simplified for this example
    
//     logger.info('Temporary permission granted', {
//       userId,
//       permission,
//       grantId,
//       expiresAt
//     });
    
//     return grantId;
//   }
  
//   /**
//    * Create permission builder
//    * @returns {Object} Permission builder
//    */
//   static createBuilder() {
//     return {
//       permissions: [],
      
//       add(permission) {
//         this.permissions.push(permission);
//         return this;
//       },
      
//       addMultiple(permissions) {
//         this.permissions.push(...permissions);
//         return this;
//       },
      
//       addForRole(role) {
//         const rolePerms = PermissionMiddleware.rolePermissions[role] || [];
//         this.permissions.push(...rolePerms);
//         return this;
//       },
      
//       build() {
//         return [...new Set(this.permissions)];
//       }
//     };
//   }
// }

// // Initialize permission system
// PermissionMiddleware.initialize();

// module.exports = PermissionMiddleware;




// server/shared/auth/middleware/permission-middleware.js
/**
 * @file Permission Middleware
 * @description Advanced permission and access control middleware with proper business logic
 * @version 3.1.0
 */

const config = require('../../config/config');
const { asyncHandler } = require('../../utils/async-handler');
const logger = require('../../utils/logger');
const ResponseHandler = require('../../utils/response-handler');

/**
 * Permission Middleware Class
 * @class PermissionMiddleware
 */
class PermissionMiddleware {
  /**
   * Initialize permission system
   */
  static initialize() {
    // Define permission hierarchy with proper business logic
    this.permissionHierarchy = {
      // System permissions
      'system.*': ['system.read', 'system.write', 'system.delete', 'system.admin', 'system.maintenance'],
      'system.admin': ['system.read', 'system.write', 'system.delete', 'system.maintenance'],
      'system.write': ['system.read'],
      
      // User permissions
      'user.*': ['user.read', 'user.write', 'user.delete', 'user.admin', 'user.impersonate'],
      'user.admin': ['user.read', 'user.write', 'user.delete', 'user.bulk.update'],
      'user.write': ['user.read'],
      
      // Organization permissions - Enhanced hierarchy
      'organization.*': [
        'organization.read', 'organization.write', 'organization.delete', 'organization.admin',
        'organization.create', 'organization.update.own', 'organization.members.manage',
        'organization.billing.manage', 'organization.settings.manage', 'organization.suspend'
      ],
      'organization.admin': [
        'organization.read', 'organization.write', 'organization.members.manage', 
        'organization.settings.manage', 'organization.billing.manage'
      ],
      'organization.write': ['organization.read', 'organization.update.own'],
      'organization.create': ['organization.read'], // Creating implies ability to read
      
      // Project permissions
      'project.*': ['project.read', 'project.write', 'project.delete', 'project.admin', 'project.members.manage'],
      'project.admin': ['project.read', 'project.write', 'project.delete', 'project.members.manage'],
      'project.write': ['project.read'],
      
      // Billing permissions
      'billing.*': ['billing.read', 'billing.write', 'billing.admin', 'billing.refund', 'billing.export'],
      'billing.admin': ['billing.read', 'billing.write', 'billing.refund', 'billing.export'],
      'billing.write': ['billing.read'],
      
      // Recruitment permissions
      'recruitment.*': ['recruitment.read', 'recruitment.write', 'recruitment.admin', 'recruitment.delete'],
      'recruitment.admin': ['recruitment.read', 'recruitment.write', 'recruitment.delete'],
      'recruitment.write': ['recruitment.read']
    };
    
    // Role-based permissions with proper business separation
    this.rolePermissions = {
      // Platform roles (Internal system administration)
      super_admin: ['*'],
      platform_admin: [
        'system.read', 'system.write', 'system.maintenance',
        'user.*', 'organization.*', 'billing.*', 'recruitment.*'
      ],
      support_agent: [
        'user.read', 'organization.read', 'billing.read',
        'project.read', 'recruitment.read'
      ],
      content_manager: [
        'user.read', 'organization.read', 'project.read',
        'system.content.manage'
      ],
      
      // Core business roles (Internal consultancy staff)
      partner: [
        'organization.admin', 'project.admin', 'billing.admin',
        'user.admin', 'recruitment.admin', 'system.read'
      ],
      director: [
        'organization.admin', 'project.admin', 'billing.read',
        'user.write', 'recruitment.write', 'system.read'
      ],
      senior_manager: [
        'organization.write', 'project.admin', 'billing.read',
        'user.write', 'recruitment.write'
      ],
      manager: [
        'project.admin', 'user.write', 'billing.read',
        'organization.read'
      ],
      senior_consultant: [
        'project.write', 'user.read', 'billing.read',
        'organization.read'
      ],
      consultant: [
        'project.write', 'user.read', 'organization.read'
      ],
      junior_consultant: [
        'project.read', 'user.read.own', 'organization.read'
      ],
      
      // Organization roles (Within hosted organizations)
      org_owner: [
        'organization.admin', 'project.admin', 'billing.admin',
        'user.admin'
      ],
      org_admin: [
        'organization.write', 'project.admin', 'user.write',
        'organization.members.manage', 'organization.settings.manage'
      ],
      org_manager: [
        'organization.read', 'project.admin', 'user.write'
      ],
      org_member: [
        'organization.read', 'project.write', 'user.read'
      ],
      org_viewer: [
        'organization.read', 'project.read', 'user.read.own'
      ],
      
      // Recruitment roles
      recruitment_admin: [
        'recruitment.admin', 'user.write', 'organization.read'
      ],
      recruitment_partner: [
        'recruitment.write', 'user.read', 'organization.read',
        'billing.read'
      ],
      recruiter: [
        'recruitment.write', 'user.read'
      ],
      hiring_manager: [
        'recruitment.read', 'recruitment.approve', 'user.read'
      ],
      candidate: [
        'recruitment.apply', 'user.read.own'
      ],
      
      // External client roles (Paying customers)
      client: [
        'organization.create', 'organization.read', 'organization.update.own',
        'project.read', 'billing.read', 'user.read.own',
        'organization.trial.start' // Allows starting trials
      ],
      
      // External prospect roles (Pre-sales leads - HIGHLY RESTRICTED)
      prospect: [
        'user.read.own', // Can only view their own profile
        'organization.read.public', // Can view public org info (pricing, features)
        'project.read.public' // Can view public project templates/examples
      ]
    };
    
    // Define role categories for business logic
    this.roleCategories = {
      platform: ['super_admin', 'platform_admin', 'support_agent', 'content_manager'],
      internal: ['partner', 'director', 'senior_manager', 'manager', 'senior_consultant', 'consultant', 'junior_consultant'],
      organization: ['org_owner', 'org_admin', 'org_manager', 'org_member', 'org_viewer'],
      recruitment: ['recruitment_admin', 'recruitment_partner', 'recruiter', 'hiring_manager', 'candidate'],
      external: ['client', 'prospect']
    };
    
    // Define restricted operations that require elevated access
    this.restrictedOperations = {
      organization_creation: ['client', 'org_owner', 'platform_admin', 'super_admin'],
      user_management: ['platform_admin', 'super_admin', 'partner', 'director'],
      billing_management: ['platform_admin', 'super_admin', 'partner', 'director', 'org_owner'],
      system_administration: ['super_admin', 'platform_admin']
    };
  }
  
  /**
   * Check if user has permission
   * @param {Object} user - User object
   * @param {string} permission - Required permission
   * @returns {boolean} Has permission
   */
  static hasPermission(user, permission) {
    if (!user) return false;
    
    // Super admin has all permissions
    if (user.role?.primary === 'super_admin') return true;
    
    // Check direct permissions
    const userPermissions = user.permissions || [];
    if (userPermissions.includes('*') || userPermissions.includes(permission)) {
      return true;
    }
    
    // Check role-based permissions
    const rolePermissions = this.rolePermissions[user.role?.primary] || [];
    if (rolePermissions.includes('*') || rolePermissions.includes(permission)) {
      return true;
    }
    
    // Check permission hierarchy
    for (const perm of userPermissions.concat(rolePermissions)) {
      if (this.permissionHierarchy[perm]?.includes(permission)) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Check if user can perform restricted operation
   * @param {Object} user - User object
   * @param {string} operation - Operation name
   * @returns {boolean} Can perform operation
   */
  static canPerformOperation(user, operation) {
    if (!user || !user.role?.primary) return false;
    
    const allowedRoles = this.restrictedOperations[operation];
    if (!allowedRoles) return false;
    
    return allowedRoles.includes(user.role.primary);
  }
  
  /**
   * Get user role category
   * @param {Object} user - User object
   * @returns {string|null} Role category
   */
  static getUserRoleCategory(user) {
    if (!user || !user.role?.primary) return null;
    
    for (const [category, roles] of Object.entries(this.roleCategories)) {
      if (roles.includes(user.role.primary)) {
        return category;
      }
    }
    
    return null;
  }
  
  /**
   * Check if role can be assigned publicly
   * @param {string} role - Role to check
   * @returns {boolean} Can be assigned publicly
   */
  static isPubliclyAssignableRole(role) {
    const publicRoles = ['prospect']; // Only prospects can be created through public registration
    return publicRoles.includes(role);
  }
  
  /**
   * Require specific permissions
   * @param {string|Array} permissions - Required permissions
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  static require(permissions, options = {}) {
    const {
      checkAll = false,
      customCheck = null,
      errorMessage = 'Insufficient permissions',
      operation = null
    } = options;
    
    const permissionArray = Array.isArray(permissions) ? permissions : [permissions];
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
      }
      
      // Check restricted operation if specified
      if (operation && !this.canPerformOperation(req.user, operation)) {
        logger.warn('Restricted operation attempted', {
          userId: req.user._id,
          userRole: req.user.role?.primary,
          operation,
          ip: req.ip
        });
        return ResponseHandler.forbidden(res, `Operation '${operation}' requires elevated privileges`, 'RESTRICTED_OPERATION');
      }
      
      // Custom permission check
      if (customCheck) {
        const allowed = await customCheck(req.user, req);
        if (!allowed) {
          return ResponseHandler.forbidden(res, errorMessage, 'CUSTOM_CHECK_FAILED');
        }
        return next();
      }
      
      // Standard permission check
      let hasAccess;
      if (checkAll) {
        hasAccess = permissionArray.every(perm => this.hasPermission(req.user, perm));
      } else {
        hasAccess = permissionArray.some(perm => this.hasPermission(req.user, perm));
      }
      
      if (!hasAccess) {
        logger.warn('Permission denied', {
          userId: req.user._id,
          required: permissionArray,
          userPermissions: req.user.permissions,
          userRole: req.user.role?.primary,
          userCategory: this.getUserRoleCategory(req.user)
        });
        
        return ResponseHandler.forbidden(res, errorMessage, 'INSUFFICIENT_PERMISSIONS');
      }
      
      next();
    });
  }
  
  /**
   * Require organization creation permission with business logic
   * @returns {Function} Express middleware
   */
  static requireOrganizationCreation() {
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
      }
      
      // Check if user can perform organization creation
      if (!this.canPerformOperation(req.user, 'organization_creation')) {
        logger.warn('Organization creation attempted by unauthorized role', {
          userId: req.user._id,
          userRole: req.user.role?.primary,
          userCategory: this.getUserRoleCategory(req.user),
          ip: req.ip
        });
        
        const userCategory = this.getUserRoleCategory(req.user);
        let message = 'Insufficient permissions to create organization';
        
        if (userCategory === 'external' && req.user.role?.primary === 'prospect') {
          message = 'Prospects must upgrade to client status to create organizations. Please contact sales to upgrade your account.';
        }
        
        return ResponseHandler.forbidden(res, message, 'ORGANIZATION_CREATION_DENIED');
      }
      
      next();
    });
  }
  
  /**
   * Check role assignment permissions
   * @param {string} targetRole - Role being assigned
   * @param {Object} context - Assignment context
   * @returns {Function} Express middleware
   */
  static requireRoleAssignment(targetRole, context = {}) {
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
      }
      
      const {
        isPublicRegistration = false,
        requiresVerification = false,
        isInternalOnboarding = false
      } = context;
      
      // Public registration restrictions
      if (isPublicRegistration && !this.isPubliclyAssignableRole(targetRole)) {
        logger.warn('Attempt to assign elevated role through public registration', {
          targetRole,
          userId: req.user._id,
          ip: req.ip
        });
        return ResponseHandler.forbidden(res, 'Role cannot be assigned through public registration', 'INVALID_PUBLIC_ROLE');
      }
      
      // Internal role restrictions
      const internalRoles = this.roleCategories.internal;
      if (internalRoles.includes(targetRole) && !isInternalOnboarding) {
        return ResponseHandler.forbidden(res, 'Internal roles require administrator approval', 'INTERNAL_ROLE_RESTRICTED');
      }
      
      // Client role restrictions
      if (targetRole === 'client' && !requiresVerification) {
        return ResponseHandler.forbidden(res, 'Client role requires business verification', 'CLIENT_VERIFICATION_REQUIRED');
      }
      
      next();
    });
  }
  
  /**
   * Check resource-based permissions
   * @param {Function} getResource - Function to retrieve resource
   * @param {string} permission - Required permission
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  static requireForResource(getResource, permission, options = {}) {
    const {
      ownerField = 'owner',
      organizationField = 'organizationId',
      checkOrganizationAccess = true
    } = options;
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
      }
      
      // Get resource
      const resource = await getResource(req);
      if (!resource) {
        return ResponseHandler.notFound(res, 'Resource');
      }
      
      // Check global permission
      if (this.hasPermission(req.user, permission)) {
        req.resource = resource;
        return next();
      }
      
      // Check ownership
      const ownerId = resource[ownerField]?.toString();
      if (ownerId === req.user._id.toString()) {
        req.resource = resource;
        return next();
      }
      
      // Check organization access
      if (checkOrganizationAccess && resource[organizationField]) {
        const hasOrgAccess = await this.checkOrganizationPermission(
          req.user,
          resource[organizationField],
          permission
        );
        
        if (hasOrgAccess) {
          req.resource = resource;
          return next();
        }
      }
      
      return ResponseHandler.forbidden(res, 'Access denied to this resource');
    });
  }
  
  /**
   * Dynamic permission check
   * @param {Function} permissionResolver - Function to resolve required permissions
   * @returns {Function} Express middleware
   */
  static dynamic(permissionResolver) {
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
      }
      
      // Resolve required permissions
      const requiredPermissions = await permissionResolver(req);
      
      if (!requiredPermissions || requiredPermissions.length === 0) {
        return next();
      }
      
      // Check permissions
      const hasAccess = Array.isArray(requiredPermissions)
        ? requiredPermissions.some(perm => this.hasPermission(req.user, perm))
        : this.hasPermission(req.user, requiredPermissions);
      
      if (!hasAccess) {
        return ResponseHandler.forbidden(res, 'Dynamic permission check failed');
      }
      
      next();
    });
  }
  
  /**
   * Check organization permission
   * @param {Object} user - User object
   * @param {string} organizationId - Organization ID
   * @param {string} permission - Required permission
   * @returns {Promise<boolean>} Has permission
   */
  static async checkOrganizationPermission(user, organizationId, permission) {
    // Check if user belongs to organization
    const belongsToOrg = user.organization?.organizations?.includes(organizationId);
    if (!belongsToOrg) return false;
    
    // Get user role in organization
    const orgMembership = user.organizations?.find(
      org => org.organizationId?.toString() === organizationId
    );
    
    if (!orgMembership) return false;
    
    // Check role permissions within organization
    const rolePermissions = this.rolePermissions[orgMembership.role] || [];
    return rolePermissions.includes(permission) || rolePermissions.includes('*');
  }
  
  /**
   * Create permission builder
   * @returns {Object} Permission builder
   */
  static createBuilder() {
    return {
      permissions: [],
      
      add(permission) {
        this.permissions.push(permission);
        return this;
      },
      
      addMultiple(permissions) {
        this.permissions.push(...permissions);
        return this;
      },
      
      addForRole(role) {
        const rolePerms = PermissionMiddleware.rolePermissions[role] || [];
        this.permissions.push(...rolePerms);
        return this;
      },
      
      addForOperation(operation) {
        const allowedRoles = PermissionMiddleware.restrictedOperations[operation] || [];
        allowedRoles.forEach(role => {
          const rolePerms = PermissionMiddleware.rolePermissions[role] || [];
          this.permissions.push(...rolePerms);
        });
        return this;
      },
      
      build() {
        return [...new Set(this.permissions)];
      }
    };
  }
}

// Initialize permission system
PermissionMiddleware.initialize();

module.exports = PermissionMiddleware;