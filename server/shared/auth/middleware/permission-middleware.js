// server/shared/auth/middleware/permission-middleware.js
/**
 * @file Permission Middleware
 * @description Advanced permission and access control middleware
 * @version 3.0.0
 */

const config = require('../../config');
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
    // Define permission hierarchy
    this.permissionHierarchy = {
      // System permissions
      'system.*': ['system.read', 'system.write', 'system.delete', 'system.admin'],
      'system.admin': ['system.read', 'system.write', 'system.delete'],
      'system.write': ['system.read'],
      
      // User permissions
      'user.*': ['user.read', 'user.write', 'user.delete', 'user.admin'],
      'user.admin': ['user.read', 'user.write', 'user.delete'],
      'user.write': ['user.read'],
      
      // Organization permissions
      'organization.*': ['organization.read', 'organization.write', 'organization.delete', 'organization.admin'],
      'organization.admin': ['organization.read', 'organization.write', 'organization.delete', 'organization.members.manage'],
      'organization.write': ['organization.read'],
      
      // Project permissions
      'project.*': ['project.read', 'project.write', 'project.delete', 'project.admin'],
      'project.admin': ['project.read', 'project.write', 'project.delete', 'project.members.manage'],
      'project.write': ['project.read'],
      
      // Billing permissions
      'billing.*': ['billing.read', 'billing.write', 'billing.admin'],
      'billing.admin': ['billing.read', 'billing.write', 'billing.refund'],
      'billing.write': ['billing.read'],
      
      // Recruitment permissions
      'recruitment.*': ['recruitment.read', 'recruitment.write', 'recruitment.admin'],
      'recruitment.admin': ['recruitment.read', 'recruitment.write', 'recruitment.delete'],
      'recruitment.write': ['recruitment.read']
    };
    
    // Role-based permissions
    this.rolePermissions = {
      // Platform roles
      super_admin: ['*'],
      platform_admin: [
        'system.read', 'system.write',
        'user.*', 'organization.*', 'billing.*'
      ],
      support_agent: [
        'user.read', 'organization.read', 'billing.read',
        'project.read', 'recruitment.read'
      ],
      
      // Core business roles
      partner: [
        'organization.admin', 'project.admin', 'billing.admin',
        'user.admin', 'recruitment.admin'
      ],
      director: [
        'organization.write', 'project.admin', 'billing.read',
        'user.write', 'recruitment.write'
      ],
      manager: [
        'project.admin', 'user.write', 'billing.read'
      ],
      consultant: [
        'project.write', 'user.read', 'billing.read'
      ],
      junior_consultant: [
        'project.read', 'user.read'
      ],
      
      // Organization roles
      org_owner: [
        'organization.admin', 'project.admin', 'billing.admin',
        'user.admin'
      ],
      org_admin: [
        'organization.write', 'project.admin', 'user.write'
      ],
      org_member: [
        'organization.read', 'project.write', 'user.read'
      ],
      
      // Recruitment roles
      recruitment_admin: [
        'recruitment.admin', 'user.write'
      ],
      recruiter: [
        'recruitment.write', 'user.read'
      ],
      hiring_manager: [
        'recruitment.read', 'recruitment.approve'
      ],
      candidate: [
        'recruitment.apply', 'user.read.own'
      ],
      
      // Client roles
      client: [
        'project.read', 'billing.read', 'user.read.own'
      ],
      prospect: [
        'organization.read', 'user.read.own'
      ]
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
   * Require specific permissions
   * @param {string|Array} permissions - Required permissions
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  static require(permissions, options = {}) {
    const {
      checkAll = false,
      customCheck = null,
      errorMessage = 'Insufficient permissions'
    } = options;
    
    const permissionArray = Array.isArray(permissions) ? permissions : [permissions];
    
    return asyncHandler(async (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
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
          userRole: req.user.role?.primary
        });
        
        return ResponseHandler.forbidden(res, errorMessage, 'INSUFFICIENT_PERMISSIONS');
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
   * Scope-based permission check
   * @param {string} scope - Required scope
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  static requireScope(scope, options = {}) {
    const {
      scopeField = 'scopes',
      allowSubScopes = true
    } = options;
    
    return (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
      }
      
      const userScopes = req.user[scopeField] || req.token?.[scopeField] || [];
      
      // Direct scope match
      if (userScopes.includes(scope) || userScopes.includes('*')) {
        return next();
      }
      
      // Sub-scope match
      if (allowSubScopes) {
        const scopeParts = scope.split('.');
        for (let i = scopeParts.length - 1; i > 0; i--) {
          const parentScope = scopeParts.slice(0, i).join('.') + '.*';
          if (userScopes.includes(parentScope)) {
            return next();
          }
        }
      }
      
      return ResponseHandler.forbidden(res, `Missing required scope: ${scope}`, 'INSUFFICIENT_SCOPE');
    };
  }
  
  /**
   * Time-based permission check
   * @param {string} permission - Required permission
   * @param {Object} timeConstraints - Time constraints
   * @returns {Function} Express middleware
   */
  static requireWithTimeConstraint(permission, timeConstraints = {}) {
    const {
      allowedDays = [0, 1, 2, 3, 4, 5, 6], // All days
      allowedHours = { start: 0, end: 24 }, // All hours
      timezone = 'UTC'
    } = timeConstraints;
    
    return (req, res, next) => {
      if (!req.user) {
        return ResponseHandler.unauthorized(res, 'Authentication required');
      }
      
      // Check base permission
      if (!this.hasPermission(req.user, permission)) {
        return ResponseHandler.forbidden(res, 'Insufficient permissions');
      }
      
      // Check time constraints
      const now = new Date();
      const day = now.getUTCDay();
      const hour = now.getUTCHours();
      
      if (!allowedDays.includes(day)) {
        return ResponseHandler.forbidden(res, 'Access not allowed on this day', 'TIME_CONSTRAINT');
      }
      
      if (hour < allowedHours.start || hour >= allowedHours.end) {
        return ResponseHandler.forbidden(res, 'Access not allowed at this time', 'TIME_CONSTRAINT');
      }
      
      next();
    };
  }
  
  /**
   * Check organization permission
   * @param {Object} user - User object
   * @param {string} organizationId - Organization ID
   * @param {string} permission - Required permission
   * @returns {Promise<boolean>} Has permission
   */
  static async checkOrganizationPermission(user, organizationId, permission) {
    // This would check user's role within the organization
    // Simplified implementation
    return user.organization?.organizations?.includes(organizationId);
  }
  
  /**
   * Grant temporary permission
   * @param {string} userId - User ID
   * @param {string} permission - Permission to grant
   * @param {number} duration - Duration in milliseconds
   * @returns {Promise<string>} Grant ID
   */
  static async grantTemporary(userId, permission, duration) {
    const grantId = require('crypto').randomBytes(16).toString('hex');
    const expiresAt = new Date(Date.now() + duration);
    
    // Store temporary grant (would use Redis in production)
    // Simplified for this example
    
    logger.info('Temporary permission granted', {
      userId,
      permission,
      grantId,
      expiresAt
    });
    
    return grantId;
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
      
      build() {
        return [...new Set(this.permissions)];
      }
    };
  }
}

// Initialize permission system
PermissionMiddleware.initialize();

module.exports = PermissionMiddleware;