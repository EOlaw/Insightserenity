// server/admin/user-management/middleware/user-management-auth.js
/**
 * @file User Management Auth Middleware
 * @description Authentication and authorization middleware specific to user management operations
 * @version 1.0.0
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Models
const User = require('../../../shared/users/models/user-model');
const AdminSession = require('../../../shared/admin/models/admin-session-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');

// Services
const PermissionService = require('../../../shared/users/services/permission-service');
const CacheService = require('../../../shared/utils/cache-service');
const IPService = require('../../../shared/utils/ip-service');

// Utilities
const { AppError, UnauthorizedError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminRoles = require('../../../shared/admin/constants/admin-roles');

// Configuration
const config = require('../../../config');

/**
 * Verify user management permissions
 * @param {string|Array} requiredPermissions - Required permission(s)
 * @returns {Function} Middleware function
 */
const requireUserManagementPermission = (requiredPermissions) => {
  return async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Convert to array if single permission
      const permissions = Array.isArray(requiredPermissions) ? 
        requiredPermissions : [requiredPermissions];

      // Check if admin has any of the required permissions
      const hasPermission = await checkUserManagementPermissions(adminUser, permissions);

      if (!hasPermission) {
        // Log unauthorized access attempt
        await logUnauthorizedAccess(adminUser, req.path, permissions);

        throw new ForbiddenError(
          'Insufficient permissions for user management operation'
        );
      }

      // Store granted permission in request
      req.grantedPermission = await getHighestPermission(adminUser, permissions);

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Verify target user access permissions
 * Ensures admin can perform operations on specific users
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const verifyTargetUserAccess = async (req, res, next) => {
  try {
    const adminUser = req.adminUser;
    const targetUserId = req.params.userId || req.body.userId;

    if (!targetUserId) {
      return next();
    }

    // Validate user ID format
    if (!AdminHelpers.isValidObjectId(targetUserId)) {
      throw new AppError('Invalid user ID format', 400);
    }

    // Load target user
    const targetUser = await User.findById(targetUserId)
      .select('role organization status security')
      .populate('role.primary', 'name level')
      .lean();

    if (!targetUser) {
      throw new AppError('Target user not found', 404);
    }

    // Check access restrictions
    const canAccess = await canAccessTargetUser(adminUser, targetUser);

    if (!canAccess.allowed) {
      await logTargetUserAccessDenied(adminUser, targetUser, canAccess.reason);
      throw new ForbiddenError(canAccess.reason || 'Access to target user denied');
    }

    // Store target user info in request
    req.targetUser = targetUser;
    req.targetUserAccess = canAccess;

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Verify organization scope for user operations
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const verifyOrganizationScope = async (req, res, next) => {
  try {
    const adminUser = req.adminUser;
    const { organizationId } = req.query || req.body || req.params;

    // Skip if no organization specified or admin has global access
    if (!organizationId || await hasGlobalAccess(adminUser)) {
      return next();
    }

    // Validate organization ID format
    if (!AdminHelpers.isValidObjectId(organizationId)) {
      throw new AppError('Invalid organization ID format', 400);
    }

    // Check if admin has access to the organization
    const hasOrgAccess = await checkOrganizationAccess(adminUser, organizationId);

    if (!hasOrgAccess) {
      await logOrganizationAccessDenied(adminUser, organizationId);
      throw new ForbiddenError('Access to specified organization denied');
    }

    // Store organization scope in request
    req.organizationScope = organizationId;

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Require elevated privileges for sensitive operations
 * @param {Object} options - Elevation options
 * @returns {Function} Middleware function
 */
const requireElevatedPrivileges = (options = {}) => {
  return async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      const {
        requireMFA = true,
        requireRecentAuth = true,
        maxAuthAge = 900000, // 15 minutes
        requirePasswordConfirmation = false
      } = options;

      // Check MFA requirement
      if (requireMFA && !adminUser.auth?.mfaVerified) {
        throw new UnauthorizedError('Multi-factor authentication required for this operation');
      }

      // Check recent authentication
      if (requireRecentAuth) {
        const lastAuthTime = new Date(adminUser.lastAuthenticatedAt || 0);
        const authAge = Date.now() - lastAuthTime.getTime();

        if (authAge > maxAuthAge) {
          throw new UnauthorizedError('Recent authentication required. Please re-authenticate.');
        }
      }

      // Check password confirmation if required
      if (requirePasswordConfirmation && !req.body.passwordConfirmation) {
        throw new UnauthorizedError('Password confirmation required for this operation');
      }

      if (requirePasswordConfirmation && req.body.passwordConfirmation) {
        const isValid = await AdminHelpers.verifyPassword(
          req.body.passwordConfirmation,
          adminUser.auth.password
        );

        if (!isValid) {
          await logFailedPasswordConfirmation(adminUser, req.path);
          throw new UnauthorizedError('Invalid password confirmation');
        }
      }

      // Mark session as elevated
      req.elevatedPrivileges = true;
      req.elevationTime = new Date();

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Validate sensitive data access
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateSensitiveDataAccess = async (req, res, next) => {
  try {
    const adminUser = req.adminUser;
    const requestedFields = extractRequestedFields(req);
    const sensitiveFields = getSensitiveUserFields();

    // Check if any sensitive fields are being accessed
    const accessingSensitive = requestedFields.some(field => 
      sensitiveFields.includes(field)
    );

    if (!accessingSensitive) {
      return next();
    }

    // Verify permission for sensitive data
    const hasPermission = await checkUserManagementPermissions(
      adminUser,
      [AdminPermissions.USER_MANAGEMENT.VIEW_SENSITIVE]
    );

    if (!hasPermission) {
      // Log sensitive data access attempt
      await logSensitiveDataAccessAttempt(adminUser, requestedFields);

      // Filter out sensitive fields from response
      req.filterSensitiveFields = true;
      req.sensitiveFieldsToFilter = sensitiveFields;
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Track user management actions
 * @param {string} action - Action being performed
 * @returns {Function} Middleware function
 */
const trackUserManagementAction = (action) => {
  return async (req, res, next) => {
    const startTime = Date.now();
    const actionId = crypto.randomUUID();

    // Store action info in request
    req.actionTracking = {
      id: actionId,
      action,
      startTime
    };

    // Store original end function
    const originalEnd = res.end;

    // Override end function to capture completion
    res.end = function(...args) {
      // Call original end
      originalEnd.apply(res, args);

      // Track action completion asynchronously
      setImmediate(async () => {
        try {
          const duration = Date.now() - startTime;
          const success = res.statusCode < 400;

          await AdminActionLog.create({
            actionId,
            adminUserId: req.adminUser.id,
            action: `USER_MANAGEMENT_${action.toUpperCase()}`,
            category: 'USER_MANAGEMENT',
            targetUserId: req.params.userId || req.targetUser?.id,
            requestPath: req.path,
            requestMethod: req.method,
            statusCode: res.statusCode,
            success,
            duration,
            metadata: {
              ip: req.ip,
              userAgent: req.get('user-agent'),
              organizationScope: req.organizationScope,
              elevatedPrivileges: req.elevatedPrivileges
            }
          });

          // Update metrics
          await updateUserManagementMetrics(req.adminUser.id, action, {
            success,
            duration
          });
        } catch (error) {
          logger.error('Failed to track user management action', {
            error: error.message,
            actionId,
            adminId: req.adminUser.id
          });
        }
      });
    };

    next();
  };
};

/**
 * Validate cross-organization operations
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateCrossOrganizationOperation = async (req, res, next) => {
  try {
    const adminUser = req.adminUser;
    const sourceOrgId = req.body.sourceOrganization;
    const targetOrgId = req.body.targetOrganization;

    // Skip if not a cross-org operation
    if (!sourceOrgId || !targetOrgId || sourceOrgId === targetOrgId) {
      return next();
    }

    // Check permission for cross-org operations
    const hasPermission = await checkUserManagementPermissions(
      adminUser,
      [AdminPermissions.USER_MANAGEMENT.CROSS_ORG_OPERATIONS]
    );

    if (!hasPermission) {
      throw new ForbiddenError('Cross-organization operations not permitted');
    }

    // Verify access to both organizations
    const [sourceAccess, targetAccess] = await Promise.all([
      checkOrganizationAccess(adminUser, sourceOrgId),
      checkOrganizationAccess(adminUser, targetOrgId)
    ]);

    if (!sourceAccess || !targetAccess) {
      throw new ForbiddenError('Access denied to one or more organizations');
    }

    // Mark as cross-org operation
    req.isCrossOrgOperation = true;
    req.crossOrgDetails = {
      source: sourceOrgId,
      target: targetOrgId
    };

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Helper function to check user management permissions
 * @param {Object} adminUser - Admin user
 * @param {Array} permissions - Required permissions
 * @returns {Promise<boolean>} Has permission
 */
async function checkUserManagementPermissions(adminUser, permissions) {
  // Super admins have all permissions
  if (adminUser.role?.primary === AdminRoles.SUPER_ADMIN) {
    return true;
  }

  // Check cached permissions
  const cacheKey = `user_mgmt_perms:${adminUser.id}`;
  const cached = await CacheService.get(cacheKey);

  if (cached) {
    return permissions.some(perm => cached.includes(perm));
  }

  // Get all user management permissions
  const userPermissions = await PermissionService.getUserPermissions(adminUser.id);
  const userMgmtPermissions = userPermissions.filter(perm => 
    perm.startsWith('user_management.')
  );

  // Cache for 5 minutes
  await CacheService.set(cacheKey, userMgmtPermissions, 300);

  // Check if has any required permission
  return permissions.some(requiredPerm => {
    // Direct permission match
    if (userMgmtPermissions.includes(requiredPerm)) {
      return true;
    }

    // Wildcard permission check
    const permParts = requiredPerm.split('.');
    for (let i = permParts.length - 1; i > 0; i--) {
      const wildcardPerm = permParts.slice(0, i).join('.') + '.*';
      if (userMgmtPermissions.includes(wildcardPerm)) {
        return true;
      }
    }

    return false;
  });
}

/**
 * Helper function to check if admin can access target user
 * @param {Object} adminUser - Admin user
 * @param {Object} targetUser - Target user
 * @returns {Promise<Object>} Access decision
 */
async function canAccessTargetUser(adminUser, targetUser) {
  // Cannot modify super admins unless you are one
  if (targetUser.role?.primary?.name === AdminRoles.SUPER_ADMIN && 
      adminUser.role?.primary !== AdminRoles.SUPER_ADMIN) {
    return {
      allowed: false,
      reason: 'Cannot modify super administrator accounts'
    };
  }

  // Check if target user is protected
  if (targetUser.security?.protectedAccount) {
    const canAccessProtected = await checkUserManagementPermissions(
      adminUser,
      [AdminPermissions.USER_MANAGEMENT.ACCESS_PROTECTED]
    );

    if (!canAccessProtected) {
      return {
        allowed: false,
        reason: 'Cannot access protected user accounts'
      };
    }
  }

  // Check organization scope
  if (adminUser.organization?.restrictToOrg && 
      targetUser.organization?.current !== adminUser.organization.current) {
    return {
      allowed: false,
      reason: 'Can only manage users within your organization'
    };
  }

  // Check role hierarchy
  if (targetUser.role?.primary?.level !== undefined && 
      adminUser.role?.primary?.level !== undefined) {
    if (targetUser.role.primary.level >= adminUser.role.primary.level) {
      return {
        allowed: false,
        reason: 'Cannot manage users with equal or higher role level'
      };
    }
  }

  return {
    allowed: true,
    permissions: await getTargetUserPermissions(adminUser, targetUser)
  };
}

/**
 * Helper function to check organization access
 * @param {Object} adminUser - Admin user
 * @param {string} organizationId - Organization ID
 * @returns {Promise<boolean>} Has access
 */
async function checkOrganizationAccess(adminUser, organizationId) {
  // Global access admins can access any organization
  if (await hasGlobalAccess(adminUser)) {
    return true;
  }

  // Check if admin belongs to the organization
  if (adminUser.organization?.current?.toString() === organizationId) {
    return true;
  }

  // Check if admin has multi-org access
  if (adminUser.organization?.accessible?.includes(organizationId)) {
    return true;
  }

  // Check specific organization permissions
  const orgPermission = `organization.${organizationId}.manage_users`;
  return await checkUserManagementPermissions(adminUser, [orgPermission]);
}

/**
 * Helper function to check if admin has global access
 * @param {Object} adminUser - Admin user
 * @returns {Promise<boolean>} Has global access
 */
async function hasGlobalAccess(adminUser) {
  return adminUser.role?.primary === AdminRoles.SUPER_ADMIN ||
         await checkUserManagementPermissions(adminUser, [AdminPermissions.USER_MANAGEMENT.GLOBAL_ACCESS]);
}

/**
 * Helper function to get highest permission level
 * @param {Object} adminUser - Admin user
 * @param {Array} permissions - Permission list
 * @returns {Promise<string>} Highest permission
 */
async function getHighestPermission(adminUser, permissions) {
  // Permission hierarchy
  const hierarchy = {
    [AdminPermissions.USER_MANAGEMENT.FULL_ACCESS]: 100,
    [AdminPermissions.USER_MANAGEMENT.DELETE]: 90,
    [AdminPermissions.USER_MANAGEMENT.CREATE]: 80,
    [AdminPermissions.USER_MANAGEMENT.UPDATE]: 70,
    [AdminPermissions.USER_MANAGEMENT.VIEW]: 50
  };

  let highestPermission = null;
  let highestLevel = 0;

  for (const permission of permissions) {
    const hasPermission = await checkUserManagementPermissions(adminUser, [permission]);
    const level = hierarchy[permission] || 0;

    if (hasPermission && level > highestLevel) {
      highestLevel = level;
      highestPermission = permission;
    }
  }

  return highestPermission;
}

/**
 * Helper function to extract requested fields from request
 * @param {Object} req - Express request object
 * @returns {Array} Requested fields
 */
function extractRequestedFields(req) {
  const fields = [];

  // From query parameters
  if (req.query.fields) {
    fields.push(...req.query.fields.split(',').map(f => f.trim()));
  }

  // From body
  if (req.body.fields && Array.isArray(req.body.fields)) {
    fields.push(...req.body.fields);
  }

  // From select parameter
  if (req.query.select) {
    fields.push(...req.query.select.split(' ').map(f => f.trim()));
  }

  return [...new Set(fields)]; // Remove duplicates
}

/**
 * Helper function to get sensitive user fields
 * @returns {Array} Sensitive field names
 */
function getSensitiveUserFields() {
  return [
    'auth.password',
    'auth.twoFactor.secret',
    'auth.passwordResetToken',
    'auth.emailVerificationToken',
    'security.encryptionKeys',
    'security.apiKeys',
    'payment.cards',
    'payment.bankAccounts',
    'personalInfo.ssn',
    'personalInfo.dob',
    'personalInfo.governmentId'
  ];
}

/**
 * Helper function to log unauthorized access attempt
 * @param {Object} adminUser - Admin user
 * @param {string} path - Request path
 * @param {Array} permissions - Required permissions
 */
async function logUnauthorizedAccess(adminUser, path, permissions) {
  await AuditLog.create({
    userId: adminUser.id,
    action: AdminEvents.USER_MANAGEMENT.UNAUTHORIZED_ACCESS,
    category: 'SECURITY',
    severity: 'WARNING',
    details: {
      path,
      requiredPermissions: permissions,
      adminRole: adminUser.role?.primary
    },
    metadata: {
      ip: adminUser.lastLoginIP,
      timestamp: new Date()
    }
  });
}

/**
 * Helper function to log target user access denied
 * @param {Object} adminUser - Admin user
 * @param {Object} targetUser - Target user
 * @param {string} reason - Denial reason
 */
async function logTargetUserAccessDenied(adminUser, targetUser, reason) {
  await AuditLog.create({
    userId: adminUser.id,
    action: AdminEvents.USER_MANAGEMENT.TARGET_USER_ACCESS_DENIED,
    category: 'SECURITY',
    severity: 'WARNING',
    targetUserId: targetUser._id,
    details: {
      reason,
      targetUserRole: targetUser.role?.primary?.name,
      targetUserOrg: targetUser.organization?.current
    },
    metadata: {
      ip: adminUser.lastLoginIP,
      timestamp: new Date()
    }
  });
}

/**
 * Helper function to update user management metrics
 * @param {string} adminId - Admin ID
 * @param {string} action - Action performed
 * @param {Object} metrics - Metrics data
 */
async function updateUserManagementMetrics(adminId, action, metrics) {
  const MetricsService = require('../../../shared/utils/metrics-service');
  
  await MetricsService.recordMetric('user_management_action', {
    adminId,
    action,
    success: metrics.success,
    duration: metrics.duration
  });
}

// Export middleware functions
module.exports = {
  requireUserManagementPermission,
  verifyTargetUserAccess,
  verifyOrganizationScope,
  requireElevatedPrivileges,
  validateSensitiveDataAccess,
  trackUserManagementAction,
  validateCrossOrganizationOperation
};