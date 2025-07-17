// server/admin/organization-management/middleware/organization-access.js
/**
 * @file Organization Access Middleware
 * @description Middleware for controlling access to organization management features
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Models
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const User = require('../../../shared/users/models/user-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Services
const PermissionService = require('../../../shared/users/services/permission-service');
const CacheService = require('../../../shared/utils/cache-service');

// Utilities
const { AppError, ForbiddenError, NotFoundError, UnauthorizedError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminRoles = require('../../../shared/admin/constants/admin-roles');

// Configuration
const config = require('../../../config');

/**
 * Organization Access Middleware Class
 * @class OrganizationAccessMiddleware
 */
class OrganizationAccessMiddleware {
  constructor() {
    this.cache = new CacheService();
    this.cachePrefix = 'org-access';
    this.cacheTTL = 300; // 5 minutes
  }

  /**
   * Check if admin has access to organization
   * @param {Object} options - Access options
   * @returns {Function} Middleware function
   */
  checkOrganizationAccess(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const organizationId = req.params.organizationId || req.params.id || req.body.organizationId;
        
        if (!adminUser || !adminUser._id) {
          throw new UnauthorizedError('Authentication required');
        }
        
        if (!organizationId) {
          throw new AppError('Organization ID is required', 400);
        }
        
        if (!mongoose.isValidObjectId(organizationId)) {
          throw new AppError('Invalid organization ID', 400);
        }
        
        // Check cache first
        const cacheKey = `${this.cachePrefix}:${adminUser._id}:${organizationId}`;
        const cachedAccess = await this.cache.get(cacheKey);
        
        if (cachedAccess && !options.skipCache) {
          req.organizationAccess = cachedAccess;
          return next();
        }
        
        // Get organization
        const organization = await HostedOrganization.findById(organizationId)
          .select('_id name status subscription tenantRef')
          .lean();
        
        if (!organization) {
          throw new NotFoundError('Organization not found');
        }
        
        // Check admin access level
        const accessLevel = await this._determineAccessLevel(adminUser, organization, options);
        
        if (!accessLevel.hasAccess) {
          throw new ForbiddenError(accessLevel.reason || 'Insufficient permissions to access this organization');
        }
        
        // Store access information
        const accessInfo = {
          organizationId,
          organizationName: organization.name,
          accessLevel: accessLevel.level,
          permissions: accessLevel.permissions,
          restrictions: accessLevel.restrictions
        };
        
        req.organizationAccess = accessInfo;
        
        // Cache the access info
        await this.cache.set(cacheKey, accessInfo, this.cacheTTL);
        
        // Log access
        await this._logAccess(adminUser, organization, 'organization_accessed');
        
        next();
      } catch (error) {
        logger.error('Organization access check failed:', error);
        next(error);
      }
    };
  }

  /**
   * Check if admin can modify organization
   * @param {Object} options - Modification options
   * @returns {Function} Middleware function
   */
  checkModificationPermission(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const organizationId = req.params.organizationId || req.params.id;
        const operation = options.operation || this._getOperationFromRoute(req);
        
        if (!adminUser || !adminUser._id) {
          throw new UnauthorizedError('Authentication required');
        }
        
        if (!organizationId || !mongoose.isValidObjectId(organizationId)) {
          throw new AppError('Valid organization ID is required', 400);
        }
        
        // Get organization with additional details for modification checks
        const organization = await HostedOrganization.findById(organizationId)
          .populate('tenantRef', 'status subscription')
          .lean();
        
        if (!organization) {
          throw new NotFoundError('Organization not found');
        }
        
        // Check modification permission
        const canModify = await this._checkModificationPermission(
          adminUser,
          organization,
          operation,
          options
        );
        
        if (!canModify.allowed) {
          throw new ForbiddenError(canModify.reason || 'Insufficient permissions to modify this organization');
        }
        
        // Store modification context
        req.modificationContext = {
          organizationId,
          operation,
          restrictions: canModify.restrictions,
          requiresApproval: canModify.requiresApproval,
          validationRules: canModify.validationRules
        };
        
        // Log modification attempt
        await this._logAccess(adminUser, organization, `modification_attempted_${operation}`);
        
        next();
      } catch (error) {
        logger.error('Organization modification check failed:', error);
        next(error);
      }
    };
  }

  /**
   * Check bulk operation permissions
   * @param {Object} options - Bulk operation options
   * @returns {Function} Middleware function
   */
  checkBulkOperationPermission(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const organizationIds = req.body.organizationIds || [];
        const operation = options.operation || req.body.operation;
        
        if (!adminUser || !adminUser._id) {
          throw new UnauthorizedError('Authentication required');
        }
        
        if (!Array.isArray(organizationIds) || organizationIds.length === 0) {
          throw new AppError('Organization IDs array is required', 400);
        }
        
        // Check bulk operation permission
        const bulkPermission = await PermissionService.checkPermission(
          adminUser._id,
          AdminPermissions.ORGANIZATION_MANAGEMENT.BULK_OPERATIONS
        );
        
        if (!bulkPermission) {
          throw new ForbiddenError('Insufficient permissions for bulk operations');
        }
        
        // Validate all organization IDs
        const invalidIds = organizationIds.filter(id => !mongoose.isValidObjectId(id));
        if (invalidIds.length > 0) {
          throw new AppError(`Invalid organization IDs: ${invalidIds.join(', ')}`, 400);
        }
        
        // Check operation limits
        const limits = this._getBulkOperationLimits(adminUser, operation);
        if (organizationIds.length > limits.maxOrganizations) {
          throw new AppError(
            `Bulk operation limit exceeded. Maximum allowed: ${limits.maxOrganizations}`,
            400
          );
        }
        
        // Verify access to all organizations
        const accessChecks = await Promise.all(
          organizationIds.map(async (orgId) => {
            const org = await HostedOrganization.findById(orgId)
              .select('_id name status')
              .lean();
            
            if (!org) {
              return { orgId, hasAccess: false, reason: 'Organization not found' };
            }
            
            const access = await this._determineAccessLevel(adminUser, org, options);
            return {
              orgId,
              hasAccess: access.hasAccess,
              reason: access.reason
            };
          })
        );
        
        const inaccessibleOrgs = accessChecks.filter(check => !check.hasAccess);
        
        if (inaccessibleOrgs.length > 0 && !options.skipInaccessible) {
          throw new ForbiddenError(
            `No access to organizations: ${inaccessibleOrgs.map(o => o.orgId).join(', ')}`
          );
        }
        
        // Store bulk operation context
        req.bulkOperationContext = {
          operation,
          totalOrganizations: organizationIds.length,
          accessibleOrganizations: accessChecks.filter(c => c.hasAccess).map(c => c.orgId),
          inaccessibleOrganizations: inaccessibleOrgs,
          limits
        };
        
        next();
      } catch (error) {
        logger.error('Bulk operation permission check failed:', error);
        next(error);
      }
    };
  }

  /**
   * Validate organization status for operations
   * @param {Object} options - Status validation options
   * @returns {Function} Middleware function
   */
  validateOrganizationStatus(options = {}) {
    return async (req, res, next) => {
      try {
        const organizationId = req.params.organizationId || req.params.id;
        const requiredStatuses = options.requiredStatuses || ['active'];
        const forbiddenStatuses = options.forbiddenStatuses || [];
        
        if (!organizationId || !mongoose.isValidObjectId(organizationId)) {
          throw new AppError('Valid organization ID is required', 400);
        }
        
        const organization = await HostedOrganization.findById(organizationId)
          .select('status')
          .lean();
        
        if (!organization) {
          throw new NotFoundError('Organization not found');
        }
        
        // Check required statuses
        if (requiredStatuses.length > 0) {
          const hasRequiredStatus = requiredStatuses.some(status => {
            if (status === 'active') return organization.status.active;
            if (status === 'verified') return organization.status.verified;
            if (status === 'suspended') return organization.status.suspended;
            return false;
          });
          
          if (!hasRequiredStatus) {
            throw new AppError(
              `Organization must have one of the following statuses: ${requiredStatuses.join(', ')}`,
              400
            );
          }
        }
        
        // Check forbidden statuses
        if (forbiddenStatuses.length > 0) {
          const hasForbiddenStatus = forbiddenStatuses.some(status => {
            if (status === 'suspended') return organization.status.suspended;
            if (status === 'deleted') return organization.status.deleted;
            return false;
          });
          
          if (hasForbiddenStatus) {
            throw new AppError(
              `Operation not allowed for organizations with status: ${forbiddenStatuses.join(', ')}`,
              400
            );
          }
        }
        
        req.organizationStatus = organization.status;
        next();
      } catch (error) {
        logger.error('Organization status validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Check organization plan restrictions
   * @param {Object} options - Plan restriction options
   * @returns {Function} Middleware function
   */
  checkPlanRestrictions(options = {}) {
    return async (req, res, next) => {
      try {
        const organizationId = req.params.organizationId || req.params.id;
        const requiredPlans = options.requiredPlans || [];
        const minimumPlan = options.minimumPlan;
        
        if (!organizationId || !mongoose.isValidObjectId(organizationId)) {
          throw new AppError('Valid organization ID is required', 400);
        }
        
        const organization = await HostedOrganization.findById(organizationId)
          .select('subscription')
          .lean();
        
        if (!organization) {
          throw new NotFoundError('Organization not found');
        }
        
        const currentPlan = organization.subscription?.plan?.id || 'free';
        
        // Check required plans
        if (requiredPlans.length > 0 && !requiredPlans.includes(currentPlan)) {
          throw new AppError(
            `This operation requires one of the following plans: ${requiredPlans.join(', ')}`,
            403
          );
        }
        
        // Check minimum plan
        if (minimumPlan) {
          const planHierarchy = ['free', 'starter', 'growth', 'professional', 'enterprise'];
          const currentPlanIndex = planHierarchy.indexOf(currentPlan);
          const minimumPlanIndex = planHierarchy.indexOf(minimumPlan);
          
          if (currentPlanIndex < minimumPlanIndex) {
            throw new AppError(
              `This operation requires at least ${minimumPlan} plan`,
              403
            );
          }
        }
        
        req.organizationPlan = currentPlan;
        next();
      } catch (error) {
        logger.error('Plan restriction check failed:', error);
        next(error);
      }
    };
  }

  // Private helper methods

  async _determineAccessLevel(adminUser, organization, options) {
    // Super admin has full access
    if (adminUser.role?.type === AdminRoles.TYPES.SUPER_ADMIN) {
      return {
        hasAccess: true,
        level: 'full',
        permissions: ['*'],
        restrictions: []
      };
    }
    
    // Platform admin has access to non-enterprise organizations
    if (adminUser.role?.type === AdminRoles.TYPES.PLATFORM_ADMIN) {
      if (organization.subscription?.plan?.id === 'enterprise' && !options.allowEnterpriseAccess) {
        return {
          hasAccess: false,
          reason: 'Platform admins cannot access enterprise organizations'
        };
      }
      
      return {
        hasAccess: true,
        level: 'standard',
        permissions: Object.values(AdminPermissions.ORGANIZATION_MANAGEMENT),
        restrictions: ['no_billing_overrides', 'no_infrastructure_changes']
      };
    }
    
    // Support admin has limited access
    if (adminUser.role?.type === AdminRoles.TYPES.SUPPORT_ADMIN) {
      return {
        hasAccess: true,
        level: 'limited',
        permissions: [
          AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS,
          AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS
        ],
        restrictions: ['read_only', 'no_sensitive_data']
      };
    }
    
    // Check custom permissions
    const hasCustomAccess = await PermissionService.checkPermission(
      adminUser._id,
      AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS
    );
    
    if (hasCustomAccess) {
      return {
        hasAccess: true,
        level: 'custom',
        permissions: await this._getAdminPermissions(adminUser),
        restrictions: ['based_on_assigned_permissions']
      };
    }
    
    return {
      hasAccess: false,
      reason: 'No permission to access organization management'
    };
  }

  async _checkModificationPermission(adminUser, organization, operation, options) {
    // Define operation permissions mapping
    const operationPermissions = {
      update: AdminPermissions.ORGANIZATION_MANAGEMENT.UPDATE_ORGANIZATION,
      suspend: AdminPermissions.ORGANIZATION_MANAGEMENT.SUSPEND_ORGANIZATION,
      delete: AdminPermissions.ORGANIZATION_MANAGEMENT.DELETE_ORGANIZATION,
      transfer: AdminPermissions.ORGANIZATION_MANAGEMENT.TRANSFER_OWNERSHIP,
      billing: AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_SUBSCRIPTIONS
    };
    
    const requiredPermission = operationPermissions[operation];
    if (!requiredPermission) {
      return { allowed: false, reason: 'Unknown operation' };
    }
    
    // Check permission
    const hasPermission = await PermissionService.checkPermission(
      adminUser._id,
      requiredPermission
    );
    
    if (!hasPermission) {
      return { allowed: false, reason: 'Insufficient permissions for this operation' };
    }
    
    // Additional checks based on operation
    const restrictions = [];
    let requiresApproval = false;
    
    // Check for protected organizations
    if (organization.metadata?.protected && adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
      return { allowed: false, reason: 'This organization is protected' };
    }
    
    // Deletion restrictions
    if (operation === 'delete') {
      if (organization.subscription?.status === 'active' && !options.forceDelete) {
        restrictions.push('must_cancel_subscription_first');
      }
      if (adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
        requiresApproval = true;
      }
    }
    
    // Billing restrictions
    if (operation === 'billing') {
      if (organization.subscription?.plan?.id === 'enterprise' && 
          adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
        restrictions.push('enterprise_billing_requires_super_admin');
      }
    }
    
    return {
      allowed: true,
      restrictions,
      requiresApproval,
      validationRules: this._getOperationValidationRules(operation)
    };
  }

  _getOperationFromRoute(req) {
    const method = req.method.toLowerCase();
    const path = req.route?.path || req.path;
    
    if (method === 'put' || method === 'patch') return 'update';
    if (method === 'delete') return 'delete';
    if (path.includes('suspend')) return 'suspend';
    if (path.includes('transfer')) return 'transfer';
    if (path.includes('billing') || path.includes('subscription')) return 'billing';
    
    return 'unknown';
  }

  _getBulkOperationLimits(adminUser, operation) {
    const baseLimits = {
      maxOrganizations: 50,
      maxConcurrent: 10,
      timeout: 300000 // 5 minutes
    };
    
    // Super admins get higher limits
    if (adminUser.role?.type === AdminRoles.TYPES.SUPER_ADMIN) {
      baseLimits.maxOrganizations = 200;
      baseLimits.maxConcurrent = 20;
    }
    
    // Destructive operations have lower limits
    if (['delete', 'suspend'].includes(operation)) {
      baseLimits.maxOrganizations = Math.floor(baseLimits.maxOrganizations / 2);
    }
    
    return baseLimits;
  }

  _getOperationValidationRules(operation) {
    const rules = {
      update: ['validate_data_types', 'check_field_permissions'],
      suspend: ['require_reason', 'validate_suspension_duration'],
      delete: ['require_confirmation', 'check_data_retention_policy'],
      transfer: ['validate_new_owner', 'check_ownership_history'],
      billing: ['validate_payment_data', 'check_refund_limits']
    };
    
    return rules[operation] || [];
  }

  async _getAdminPermissions(adminUser) {
    // Get all permissions for the admin user
    const user = await User.findById(adminUser._id)
      .populate('role')
      .lean();
    
    if (!user || !user.role) {
      return [];
    }
    
    return user.role.permissions || [];
  }

  async _logAccess(adminUser, organization, action) {
    try {
      const logEntry = new AdminActionLog({
        adminId: adminUser._id,
        action,
        category: 'organization_access',
        targetType: 'organization',
        targetId: organization._id,
        targetName: organization.name,
        metadata: {
          organizationStatus: organization.status,
          subscriptionPlan: organization.subscription?.plan?.id
        },
        ipAddress: adminUser.lastLoginIP,
        userAgent: adminUser.lastUserAgent
      });
      
      await logEntry.save();
    } catch (error) {
      logger.error('Failed to log organization access:', error);
      // Don't throw - logging failure shouldn't block the operation
    }
  }
}

module.exports = new OrganizationAccessMiddleware();