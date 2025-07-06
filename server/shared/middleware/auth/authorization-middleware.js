/**
 * @file Authorization Middleware - Fixed
 * @description Role-based access control middleware with organization loading
 * @version 1.1.0
 */

const { AuthorizationError, AppError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

// Import the HostedOrganization model
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');

/**
 * Helper function to load organization from route parameter
 * @param {Object} req - Express request object
 * @returns {Promise<Object>} - Organization document
 */
const loadOrganizationFromParam = async (req) => {
  const organizationId = req.params.id;
  
  if (!organizationId) {
    throw new AppError('Organization ID is required', 400);
  }

  logger.debug('Loading organization from route parameter', {
    organizationId,
    userId: req.user?._id
  });

  // Load organization with tenant reference (don't use .lean() to preserve methods)
  const organization = await HostedOrganization.findById(organizationId)
    .populate('tenantRef')
    .exec();

  if (!organization) {
    throw new AppError('Organization not found', 404);
  }

  // Check if organization is active
  if (!organization.status.active) {
    throw new AppError('Organization is not active', 403);
  }

  // Check if tenant is active
  if (organization.tenantRef && organization.tenantRef.status === 'suspended') {
    throw new AppError('Organization is suspended', 403);
  }

  return organization;
};

/**
 * Restrict access to specific roles
 * @param {...string} roles - Allowed roles
 * @returns {Function} - Express middleware
 */
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AuthorizationError('Authentication required'));
    }
    
    const userRole = req.user.role?.primary || req.user.role;
    
    if (!roles.includes(userRole)) {
      logger.warn('Access denied - insufficient role', {
        userId: req.user._id,
        userRole,
        requiredRoles: roles,
        path: req.originalUrl
      });
      
      return next(new AuthorizationError(
        `This action requires one of the following roles: ${roles.join(', ')}`
      ));
    }
    
    next();
  };
};

/**
 * Check if user has organization context
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkOrganizationContext = (req, res, next) => {
  if (!req.organization) {
    return next(new AppError('Organization context required', 400));
  }
  
  // Ensure user belongs to the organization
  const belongsToOrg = req.user.organizations?.some(
    org => org.organizationId.toString() === req.organization._id.toString()
  );
  
  if (!belongsToOrg && !['admin', 'super_admin'].includes(req.user.role?.primary)) {
    return next(new AuthorizationError('Access denied to this organization'));
  }
  
  next();
};

/**
 * Require organization owner role
 * FIXED: Now loads organization if not present
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireOrganizationOwner = async (req, res, next) => {
  try {
    // Load organization if not already present
    if (!req.organization) {
      req.organization = await loadOrganizationFromParam(req);
      req.organizationId = req.organization._id;
      
      // Also set tenant context if available
      if (req.organization.tenantRef) {
        req.tenant = req.organization.tenantRef;
        req.tenantId = req.organization.tenantId;
      }
    }

    const isOwner = req.organization.team.owner.toString() === req.user._id.toString();
    const isSystemAdmin = ['admin', 'super_admin'].includes(req.user.role?.primary);
    
    if (!isOwner && !isSystemAdmin) {
      return next(new AuthorizationError('Only organization owner can perform this action'));
    }
    
    next();
  } catch (error) {
    logger.error('Failed to check organization owner permission', {
      error: error.message,
      userId: req.user._id,
      organizationId: req.params.id
    });
    next(error);
  }
};

/**
 * Require organization admin role
 * FIXED: Now loads organization if not present
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireOrganizationAdmin = async (req, res, next) => {
  try {
    // Load organization if not already present
    if (!req.organization) {
      req.organization = await loadOrganizationFromParam(req);
      req.organizationId = req.organization._id;
      
      // Also set tenant context if available
      if (req.organization.tenantRef) {
        req.tenant = req.organization.tenantRef;
        req.tenantId = req.organization.tenantId;
      }
    }

    // Check if user is owner
    const isOwner = req.organization.team.owner.toString() === req.user._id.toString();
    
    // Check if user is admin
    const isAdmin = req.organization.team?.admins?.some(
      admin => admin.user.toString() === req.user._id.toString()
    );
    
    // Check if system admin
    const isSystemAdmin = ['admin', 'super_admin'].includes(req.user.role?.primary);
    
    if (!isOwner && !isAdmin && !isSystemAdmin) {
      return next(new AuthorizationError('Organization admin privileges required'));
    }
    
    next();
  } catch (error) {
    logger.error('Failed to check organization admin permission', {
      error: error.message,
      userId: req.user._id,
      organizationId: req.params.id
    });
    next(error);
  }
};

/**
 * Require organization member role
 * FIXED: Now loads organization if not present
 * Checks if user is a member of the organization (includes owner, admin, and regular members)
 * Handles both populated and unpopulated object references
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireOrganizationMember = async (req, res, next) => {
  try {
    // Load organization if not already present
    if (!req.organization) {
      req.organization = await loadOrganizationFromParam(req);
      req.organizationId = req.organization._id;
      
      // Also set tenant context if available
      if (req.organization.tenantRef) {
        req.tenant = req.organization.tenantRef;
        req.tenantId = req.organization.tenantId;
      }
    }

    if (!req.user) {
      return next(new AuthorizationError('Authentication required'));
    }
    
    // System admins always have access
    if (['admin', 'super_admin'].includes(req.user.role?.primary)) {
      logger.debug('System admin access granted', {
        userId: req.user._id,
        userRole: req.user.role?.primary,
        organizationId: req.organization._id
      });
      return next();
    }
    
    // Use the static helper method for membership checking
    const isMember = HostedOrganization.checkMembership(req.organization, req.user._id);
    
    // Alternative check through user's organizations array
    const belongsToOrg = req.user.organizations?.some(
      org => org.organizationId?.toString() === req.organization._id.toString()
    );
    
    // Debug logging to help troubleshoot authorization issues
    logger.debug('Organization member check details', {
      userId: req.user._id.toString(),
      userRole: req.user.role,
      organizationId: req.organization._id.toString(),
      checks: {
        isMember,
        belongsToOrg
      }
    });
    
    if (!isMember && !belongsToOrg) {
      logger.warn('User attempted to access organization without membership', {
        userId: req.user._id,
        organizationId: req.organization._id
      });
      return next(new AuthorizationError('You are not a member of this organization'));
    }
    
    // Set additional context
    const userRole = HostedOrganization.getUserRole(req.organization, req.user._id);
    req.organizationRole = userRole;
    req.userOrganizationPermissions = []; // You can expand this based on role
    
    logger.debug('Organization member access granted', {
      userId: req.user._id,
      organizationId: req.organization._id,
      assignedRole: req.organizationRole,
      permissions: req.userOrganizationPermissions
    });
    
    next();
  } catch (error) {
    logger.error('Failed to check organization member permission', {
      error: error.message,
      userId: req.user._id,
      organizationId: req.params.id
    });
    next(error);
  }
};

/**
 * Check specific permission for organization member
 * @param {string} permission - Required permission
 * @returns {Function} - Express middleware
 */
const requireOrganizationPermission = (permission) => {
  return async (req, res, next) => {
    try {
      // Load organization if not already present
      if (!req.organization) {
        req.organization = await loadOrganizationFromParam(req);
        req.organizationId = req.organization._id;
      }
      
      // System admins bypass permission checks
      if (['admin', 'super_admin'].includes(req.user.role?.primary)) {
        return next();
      }
      
      // Find user's membership in organization
      const membership = req.user.organizations?.find(
        org => org.organizationId.toString() === req.organization._id.toString()
      );
      
      if (!membership) {
        return next(new AuthorizationError('Not a member of this organization'));
      }
      
      // Check role-based permissions
      const rolePermissions = {
        owner: ['*'], // All permissions
        admin: ['read', 'write', 'delete', 'manage_team', 'manage_settings'],
        manager: ['read', 'write', 'manage_team'],
        member: ['read', 'write'],
        viewer: ['read'],
        guest: ['read']
      };
      
      const userPermissions = rolePermissions[membership.role] || [];
      
      if (!userPermissions.includes('*') && !userPermissions.includes(permission)) {
        return next(new AuthorizationError(
          `Permission denied. Required: ${permission}`
        ));
      }
      
      next();
    } catch (error) {
      logger.error('Failed to check organization permission', {
        error: error.message,
        userId: req.user._id,
        permission
      });
      next(error);
    }
  };
};

/**
 * Check resource ownership
 * @param {string} resourceField - Field containing owner ID
 * @returns {Function} - Express middleware
 */
const requireResourceOwnership = (resourceField = 'owner') => {
  return (req, res, next) => {
    const resource = req.resource || req.body;
    
    if (!resource) {
      return next(new AppError('Resource not found', 404));
    }
    
    const ownerId = resource[resourceField]?.toString() || resource[resourceField];
    const userId = req.user._id.toString();
    
    if (ownerId !== userId && !['admin', 'super_admin'].includes(req.user.role?.primary)) {
      return next(new AuthorizationError('Access denied - not resource owner'));
    }
    
    next();
  };
};

/**
 * Role-based rate limiting
 * @param {Object} limits - Rate limits per role
 * @returns {Function} - Express middleware
 */
const roleBasedRateLimit = (limits) => {
  return (req, res, next) => {
    const userRole = req.user?.role?.primary || req.user?.role || 'guest';
    const limit = limits[userRole] || limits.default || 100;
    
    // Implement rate limiting logic here
    // For now, just pass through
    next();
  };
};

/**
 * API key validation
 */
const checkApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return next(new AppError('API key required', 401));
  }
  
  // Validate API key logic here
  // For now, just pass through
  next();
};

/**
 * Check feature access based on subscription
 * @param {string} feature - Required feature
 * @returns {Function} - Express middleware
 */
const requireFeature = (feature) => {
  return async (req, res, next) => {
    try {
      // Load organization if not already present
      if (!req.organization) {
        req.organization = await loadOrganizationFromParam(req);
      }
      
      const hasFeature = req.organization.platformConfig?.features?.get(feature);
      
      if (!hasFeature) {
        return next(new AppError(
          `This feature (${feature}) is not available in your current plan`,
          402 // Payment Required
        ));
      }
      
      next();
    } catch (error) {
      logger.error('Failed to check feature access', {
        error: error.message,
        feature
      });
      next(error);
    }
  };
};

/**
 * IP whitelist check
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkIpWhitelist = async (req, res, next) => {
  try {
    // Load organization if not already present
    if (!req.organization) {
      req.organization = await loadOrganizationFromParam(req);
    }
    
    if (!req.organization?.security?.ipWhitelist?.length) {
      return next();
    }
    
    const clientIp = req.ip || req.connection.remoteAddress;
    const whitelist = req.organization.security.ipWhitelist;
    
    if (!whitelist.includes(clientIp)) {
      logger.warn('Access denied - IP not whitelisted', {
        clientIp,
        organizationId: req.organization._id,
        userId: req.user?._id
      });
      
      return next(new AuthorizationError('Access denied from this IP address'));
    }
    
    next();
  } catch (error) {
    logger.error('Failed to check IP whitelist', {
      error: error.message
    });
    next(error);
  }
};

module.exports = {
  restrictTo,
  checkOrganizationContext,
  requireOrganizationOwner,
  requireOrganizationAdmin,
  requireOrganizationMember,
  requireOrganizationPermission,
  requireResourceOwnership,
  roleBasedRateLimit,
  checkApiKey,
  requireFeature,
  checkIpWhitelist
};