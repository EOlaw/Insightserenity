/**
 * @file Admin Authorization Middleware
 * @description Enhanced authorization middleware for administrative operations with granular permission controls
 * @version 1.0.0
 */

const { AuthorizationError, AppError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../../audit/services/audit-service');
const PermissionMiddleware = require('../../middleware/auth/permission-middleware');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');

/**
 * Admin Authorization Middleware Class
 * @class AdminAuthorizationMiddleware
 */
class AdminAuthorizationMiddleware {
  /**
   * Initialize admin permission hierarchy
   */
  static initialize() {
    // Define admin-specific permission hierarchy
    this.adminPermissionHierarchy = {
      // Super Admin - Complete system control
      'admin.super.*': [
        'admin.super.system', 'admin.super.platform', 'admin.super.security',
        'admin.super.billing', 'admin.super.emergency', 'admin.super.audit',
        'admin.super.impersonate', 'admin.super.maintenance'
      ],
      
      // Platform Admin - Platform-wide operations
      'admin.platform.*': [
        'admin.platform.organizations', 'admin.platform.users', 'admin.platform.billing',
        'admin.platform.analytics', 'admin.platform.settings', 'admin.platform.support'
      ],
      'admin.platform.organizations': [
        'admin.platform.organizations.create', 'admin.platform.organizations.update',
        'admin.platform.organizations.delete', 'admin.platform.organizations.suspend',
        'admin.platform.organizations.billing'
      ],
      
      // Organization Admin - Organization-specific control
      'admin.organization.*': [
        'admin.organization.settings', 'admin.organization.users', 'admin.organization.billing',
        'admin.organization.projects', 'admin.organization.reports', 'admin.organization.audit'
      ],
      'admin.organization.users': [
        'admin.organization.users.create', 'admin.organization.users.update',
        'admin.organization.users.delete', 'admin.organization.users.roles'
      ],
      
      // Security Admin - Security and compliance
      'admin.security.*': [
        'admin.security.audit', 'admin.security.compliance', 'admin.security.threats',
        'admin.security.access', 'admin.security.monitoring', 'admin.security.forensics'
      ],
      
      // System Admin - System operations
      'admin.system.*': [
        'admin.system.config', 'admin.system.maintenance', 'admin.system.monitoring',
        'admin.system.backup', 'admin.system.logs', 'admin.system.integrations'
      ]
    };

    // Define role to permission mappings
    this.adminRolePermissions = {
      super_admin: ['admin.super.*', 'admin.platform.*', 'admin.security.*', 'admin.system.*'],
      platform_admin: ['admin.platform.*', 'admin.organization.*'],
      organization_admin: ['admin.organization.*'],
      security_admin: ['admin.security.*', 'admin.organization.audit'],
      system_admin: ['admin.system.*', 'admin.platform.monitoring']
    };

    // Define sensitive operations requiring additional verification
    this.sensitiveOperations = [
      'admin.super.emergency',
      'admin.super.impersonate',
      'admin.platform.organizations.delete',
      'admin.security.forensics',
      'admin.system.config',
      'admin.system.backup'
    ];
  }

  /**
   * Check if user has admin permission
   * @param {Object} user - User object
   * @param {string} permission - Required permission
   * @returns {boolean} Has permission
   */
  static hasAdminPermission(user, permission) {
    if (!user || !permission) return false;

    const userRole = user.role?.primary;
    const rolePermissions = this.adminRolePermissions[userRole] || [];

    // Check direct permission match
    if (rolePermissions.includes(permission)) return true;

    // Check wildcard permissions
    for (const rolePermission of rolePermissions) {
      if (rolePermission.endsWith('*')) {
        const permissionBase = rolePermission.slice(0, -1);
        if (permission.startsWith(permissionBase)) return true;
      }
    }

    // Check permission hierarchy
    for (const [parent, children] of Object.entries(this.adminPermissionHierarchy)) {
      if (rolePermissions.includes(parent) && children.includes(permission)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Require specific admin permissions
   * @param {...string} permissions - Required permissions (OR logic)
   * @returns {Function} Express middleware
   */
  static requireAdminPermission(...permissions) {
    return async (req, res, next) => {
      try {
        if (!req.adminAuth || !req.user) {
          throw new AuthorizationError('Admin authentication required');
        }

        // Super admin bypass (with audit)
        if (req.user.role?.primary === 'super_admin') {
          await AuditService.log({
            type: 'admin_permission_bypass',
            action: 'authorize',
            category: 'authorization',
            result: 'success',
            userId: req.user._id,
            target: {
              type: 'permission',
              id: permissions.join(',')
            },
            metadata: {
              reason: 'super_admin_bypass',
              endpoint: req.originalUrl,
              method: req.method
            }
          });
          return next();
        }

        // Check if user has any of the required permissions
        const hasPermission = permissions.some(permission => 
          this.hasAdminPermission(req.user, permission)
        );

        if (!hasPermission) {
          await AuditService.log({
            type: 'admin_permission_denied',
            action: 'authorize',
            category: 'authorization',
            result: 'blocked',
            severity: 'high',
            userId: req.user._id,
            target: {
              type: 'permission',
              id: permissions.join(',')
            },
            metadata: {
              userRole: req.user.role?.primary,
              requiredPermissions: permissions,
              endpoint: req.originalUrl,
              method: req.method,
              ip: req.ip
            }
          });

          throw new AuthorizationError(
            `Admin permission required: ${permissions.join(' or ')}`
          );
        }

        // Check if sensitive operation requires elevated auth
        const isSensitive = permissions.some(p => this.sensitiveOperations.includes(p));
        if (isSensitive && !req.adminAuth.elevatedPrivileges) {
          return res.status(402).json({
            success: false,
            error: 'Elevated authentication required for sensitive operation',
            data: {
              permissions,
              authUrl: '/api/admin/auth/elevate'
            }
          });
        }

        // Set permission context
        req.adminPermissions = {
          required: permissions,
          granted: permissions.filter(p => this.hasAdminPermission(req.user, p)),
          isSensitive
        };

        await AuditService.log({
          type: 'admin_permission_granted',
          action: 'authorize',
          category: 'authorization',
          result: 'success',
          userId: req.user._id,
          target: {
            type: 'permission',
            id: permissions.join(',')
          },
          metadata: {
            grantedPermissions: req.adminPermissions.granted,
            endpoint: req.originalUrl,
            method: req.method,
            elevated: req.adminAuth.elevatedPrivileges
          }
        });

        next();
      } catch (error) {
        next(error);
      }
    };
  }

  /**
   * Restrict to specific admin roles
   * @param {...string} roles - Allowed admin roles
   * @returns {Function} Express middleware
   */
  static restrictToAdminRole(...roles) {
    return async (req, res, next) => {
      try {
        if (!req.adminAuth || !req.user) {
          throw new AuthorizationError('Admin authentication required');
        }

        const userRole = req.user.role?.primary;
        
        if (!roles.includes(userRole)) {
          await AuditService.log({
            type: 'admin_role_denied',
            action: 'authorize',
            category: 'authorization',
            result: 'blocked',
            severity: 'medium',
            userId: req.user._id,
            metadata: {
              userRole,
              requiredRoles: roles,
              endpoint: req.originalUrl
            }
          });

          throw new AuthorizationError(
            `Admin role required: ${roles.join(' or ')}`
          );
        }

        next();
      } catch (error) {
        next(error);
      }
    };
  }

  /**
   * Check organization admin access
   * @param {Object} options - Access options
   * @returns {Function} Express middleware
   */
  static requireOrganizationAdminAccess(options = {}) {
    const {
      paramName = 'organizationId',
      allowPlatformAdmin = true,
      requireOwnership = false
    } = options;

    return async (req, res, next) => {
      try {
        const organizationId = req.params[paramName] || req.body.organizationId;
        
        if (!organizationId) {
          throw new AppError('Organization ID required', 400);
        }

        // Platform admins have access to all organizations
        if (allowPlatformAdmin && ['super_admin', 'platform_admin'].includes(req.user.role?.primary)) {
          req.organizationAccess = {
            level: 'platform',
            organizationId
          };
          return next();
        }

        // Load organization
        const organization = await HostedOrganization.findById(organizationId)
          .populate('tenantRef');

        if (!organization) {
          throw new AppError('Organization not found', 404);
        }

        // Check if user is organization admin
        const membership = organization.team.members.find(
          m => m.userId.toString() === req.user._id.toString()
        );

        if (!membership || !['owner', 'admin'].includes(membership.role)) {
          throw new AuthorizationError('Organization admin access required');
        }

        // Check ownership if required
        if (requireOwnership && membership.role !== 'owner') {
          throw new AuthorizationError('Organization ownership required');
        }

        // Set organization context
        req.organization = organization;
        req.organizationId = organization._id;
        req.organizationAccess = {
          level: 'organization',
          role: membership.role,
          organizationId: organization._id
        };

        await AuditService.log({
          type: 'admin_organization_access',
          action: 'authorize',
          category: 'authorization',
          result: 'success',
          userId: req.user._id,
          organizationId: organization._id,
          metadata: {
            accessLevel: req.organizationAccess.level,
            memberRole: membership.role,
            endpoint: req.originalUrl
          }
        });

        next();
      } catch (error) {
        await AuditService.log({
          type: 'admin_organization_access_denied',
          action: 'authorize',
          category: 'authorization',
          result: 'blocked',
          severity: 'medium',
          userId: req.user?._id,
          metadata: {
            error: error.message,
            organizationId,
            endpoint: req.originalUrl
          }
        });

        next(error);
      }
    };
  }

  /**
   * Verify resource access in admin context
   * @param {Object} options - Resource options
   * @returns {Function} Express middleware
   */
  static verifyAdminResourceAccess(options = {}) {
    const {
      resourceType,
      loadResource,
      ownerField = 'owner',
      organizationField = 'organization'
    } = options;

    return async (req, res, next) => {
      try {
        const resourceId = req.params.id || req.params.resourceId;
        
        if (!resourceId) {
          throw new AppError('Resource ID required', 400);
        }

        // Load resource
        const resource = await loadResource(resourceId);
        
        if (!resource) {
          throw new AppError(`${resourceType} not found`, 404);
        }

        // Platform admins have full access
        if (['super_admin', 'platform_admin'].includes(req.user.role?.primary)) {
          req.resource = resource;
          req.resourceAccess = { level: 'platform' };
          return next();
        }

        // Check organization context
        const resourceOrgId = resource[organizationField]?.toString();
        if (resourceOrgId) {
          // Verify user has admin access to the resource's organization
          const userOrgs = req.user.organizations || [];
          const hasOrgAccess = userOrgs.some(org => 
            org.organizationId.toString() === resourceOrgId &&
            ['owner', 'admin'].includes(org.role)
          );

          if (!hasOrgAccess) {
            throw new AuthorizationError('Admin access to resource organization required');
          }
        }

        // Check direct ownership
        const resourceOwnerId = resource[ownerField]?.toString();
        if (resourceOwnerId === req.user._id.toString()) {
          req.resourceAccess = { level: 'owner' };
        } else {
          req.resourceAccess = { level: 'organization' };
        }

        req.resource = resource;

        await AuditService.log({
          type: 'admin_resource_access',
          action: 'authorize',
          category: 'authorization',
          result: 'success',
          userId: req.user._id,
          target: {
            type: resourceType,
            id: resourceId
          },
          metadata: {
            accessLevel: req.resourceAccess.level,
            endpoint: req.originalUrl
          }
        });

        next();
      } catch (error) {
        next(error);
      }
    };
  }

  /**
   * Rate limit admin operations
   * @param {Object} options - Rate limit options
   * @returns {Function} Express middleware
   */
  static adminRateLimit(options = {}) {
    const {
      windowMs = 900000, // 15 minutes
      max = 100,
      keyGenerator = (req) => `admin:${req.user?._id || req.ip}`,
      skipSuccessfulRequests = false
    } = options;

    // Store for rate limit tracking
    const rateLimitStore = new Map();

    return async (req, res, next) => {
      const key = keyGenerator(req);
      const now = Date.now();
      const windowStart = now - windowMs;

      // Get or create rate limit entry
      let entry = rateLimitStore.get(key);
      if (!entry) {
        entry = { requests: [], blocked: false };
        rateLimitStore.set(key, entry);
      }

      // Clean old requests
      entry.requests = entry.requests.filter(timestamp => timestamp > windowStart);

      // Check if blocked
      if (entry.blocked && entry.blockedUntil > now) {
        await AuditService.log({
          type: 'admin_rate_limit_blocked',
          action: 'rate_limit',
          category: 'security',
          result: 'blocked',
          severity: 'high',
          userId: req.user?._id,
          metadata: {
            key,
            requests: entry.requests.length,
            limit: max,
            endpoint: req.originalUrl
          }
        });

        return res.status(429).json({
          success: false,
          error: 'Too many admin requests',
          retryAfter: Math.ceil((entry.blockedUntil - now) / 1000)
        });
      }

      // Check rate limit
      if (entry.requests.length >= max) {
        entry.blocked = true;
        entry.blockedUntil = now + windowMs;

        await AuditService.log({
          type: 'admin_rate_limit_exceeded',
          action: 'rate_limit',
          category: 'security',
          result: 'blocked',
          severity: 'high',
          userId: req.user?._id,
          metadata: {
            key,
            requests: entry.requests.length,
            limit: max,
            blockedUntil: entry.blockedUntil,
            endpoint: req.originalUrl
          }
        });

        return res.status(429).json({
          success: false,
          error: 'Admin rate limit exceeded',
          retryAfter: Math.ceil(windowMs / 1000)
        });
      }

      // Track request
      entry.requests.push(now);

      // Clean up old entries periodically
      if (Math.random() < 0.01) {
        for (const [k, v] of rateLimitStore.entries()) {
          if (v.requests.length === 0 && (!v.blocked || v.blockedUntil < now)) {
            rateLimitStore.delete(k);
          }
        }
      }

      next();
    };
  }
}

// Initialize on module load
AdminAuthorizationMiddleware.initialize();

module.exports = AdminAuthorizationMiddleware;