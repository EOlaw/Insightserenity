/**
 * @file Authorization Middleware
 * @description Role-based access control middleware
 * @version 1.0.0
 */

const { AuthorizationError, AppError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

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
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireOrganizationOwner = (req, res, next) => {
  if (!req.organization) {
    return next(new AppError('Organization context required', 400));
  }
  
  const isOwner = req.organization.owner.toString() === req.user._id.toString();
  const isSystemAdmin = ['admin', 'super_admin'].includes(req.user.role?.primary);
  
  if (!isOwner && !isSystemAdmin) {
    return next(new AuthorizationError('Only organization owner can perform this action'));
  }
  
  next();
};

/**
 * Require organization admin role
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireOrganizationAdmin = (req, res, next) => {
  if (!req.organization) {
    return next(new AppError('Organization context required', 400));
  }
  
  // Check if user is owner
  const isOwner = req.organization.owner.toString() === req.user._id.toString();
  
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
};

/**
 * Require organization member role
 * Checks if user is a member of the organization (includes owner, admin, and regular members)
 * Handles both populated and unpopulated object references
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireOrganizationMember = (req, res, next) => {
  if (!req.organization) {
    return next(new AppError('Organization context required', 400));
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
  
  // Extract owner ID - handle both populated and unpopulated owner references
  const ownerId = req.organization.team?.owner?._id || req.organization.team?.owner;
  const isOwner = ownerId?.toString() === req.user._id.toString();
  
  // Extract admin IDs - handle both populated and unpopulated admin references
  const isAdmin = req.organization.team?.admins?.some(admin => {
    const adminUserId = admin.user?._id || admin.user;
    return adminUserId?.toString() === req.user._id.toString();
  });
  
  // Extract member IDs - handle both populated and unpopulated member references
  const isMember = req.organization.team?.members?.some(member => {
    const memberUserId = member.user?._id || member.user;
    return memberUserId?.toString() === req.user._id.toString();
  });
  
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
      isOwner,
      isAdmin,
      isMember,
      belongsToOrg
    },
    organizationData: {
      ownerId: ownerId?.toString(),
      isOwnerPopulated: typeof req.organization.team?.owner === 'object' && !!req.organization.team?.owner?._id,
      adminCount: req.organization.team?.admins?.length || 0,
      memberCount: req.organization.team?.members?.length || 0,
      adminIds: req.organization.team?.admins?.map(admin => {
        const adminUserId = admin.user?._id || admin.user;
        return adminUserId?.toString();
      }).filter(Boolean) || [],
      memberIds: req.organization.team?.members?.map(member => {
        const memberUserId = member.user?._id || member.user;
        return memberUserId?.toString();
      }).filter(Boolean) || []
    },
    userData: {
      userOrgCount: req.user.organizations?.length || 0,
      userOrganizations: req.user.organizations?.map(org => ({
        orgId: org.organizationId?.toString(),
        role: org.role,
        active: org.active
      })) || []
    }
  });
  
  // Check if user has any form of access to the organization
  if (!isOwner && !isAdmin && !isMember && !belongsToOrg) {
    logger.warn('Access denied - not a member of organization', {
      userId: req.user._id,
      organizationId: req.organization._id,
      path: req.originalUrl,
      attemptedAccess: {
        ownerCheck: `${ownerId?.toString()} === ${req.user._id.toString()} = ${isOwner}`,
        adminCheck: `Found ${req.organization.team?.admins?.length || 0} admins`,
        memberCheck: `Found ${req.organization.team?.members?.length || 0} members`,
        userOrgCheck: `User has ${req.user.organizations?.length || 0} organization memberships`
      }
    });
    
    return next(new AuthorizationError('You must be a member of this organization to access this resource'));
  }
  
  // Set user's role in the organization for downstream middleware and handlers
  if (isOwner) {
    req.organizationRole = 'owner';
    req.userOrganizationPermissions = ['*']; // All permissions
  } else if (isAdmin) {
    req.organizationRole = 'admin';
    req.userOrganizationPermissions = ['read', 'write', 'delete', 'manage_team', 'manage_settings'];
  } else if (isMember) {
    // Find the specific member record to get their role and permissions
    const memberRecord = req.organization.team?.members?.find(member => {
      const memberUserId = member.user?._id || member.user;
      return memberUserId?.toString() === req.user._id.toString();
    });
    
    req.organizationRole = memberRecord?.role || 'member';
    req.userOrganizationPermissions = memberRecord?.permissions || ['read', 'write'];
  } else {
    // User belongs through organizations array but not in team structure
    const orgMembership = req.user.organizations?.find(
      org => org.organizationId?.toString() === req.organization._id.toString()
    );
    
    req.organizationRole = orgMembership?.role || 'member';
    req.userOrganizationPermissions = ['read', 'write']; // Default permissions
  }
  
  logger.debug('Organization access granted', {
    userId: req.user._id,
    organizationId: req.organization._id,
    assignedRole: req.organizationRole,
    permissions: req.userOrganizationPermissions
  });
  
  next();
};

/**
 * Check specific permission for organization member
 * @param {string} permission - Required permission
 * @returns {Function} - Express middleware
 */
const requireOrganizationPermission = (permission) => {
  return (req, res, next) => {
    if (!req.organization) {
      return next(new AppError('Organization context required', 400));
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
      return next(new AuthorizationError('You can only modify your own resources'));
    }
    
    next();
  };
};

/**
 * Rate limit by user role
 * Different limits for different roles
 * @param {Object} limits - Role-based rate limits
 * @returns {Function} - Express middleware
 */
const roleBasedRateLimit = (limits = {}) => {
  const defaultLimits = {
    guest: 10,
    member: 100,
    admin: 1000,
    super_admin: 10000
  };
  
  const roleLimits = { ...defaultLimits, ...limits };
  
  return (req, res, next) => {
    const userRole = req.user?.role?.primary || 'guest';
    req.rateLimit = roleLimits[userRole] || roleLimits.guest;
    next();
  };
};

/**
 * Check API key authentication
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  if (!apiKey) {
    return next(new AuthenticationError('API key required'));
  }
  
  try {
    // Validate API key (implement your API key validation logic)
    const keyData = await validateApiKey(apiKey);
    
    if (!keyData.valid) {
      return next(new AuthenticationError('Invalid API key'));
    }
    
    // Add API key data to request
    req.apiKey = keyData;
    req.organization = keyData.organization;
    
    next();
  } catch (error) {
    logger.error('API key validation error', {
      error: error.message,
      apiKey: apiKey.substring(0, 8) + '...'
    });
    next(new AuthenticationError('API key validation failed'));
  }
};

/**
 * Validate API key (placeholder - implement your logic)
 * @param {string} apiKey - API key to validate
 * @returns {Promise<Object>} - Validation result
 */
async function validateApiKey(apiKey) {
  // This is a placeholder - implement your actual API key validation
  // Check against database, cache, etc.
  return {
    valid: true,
    organization: null,
    permissions: []
  };
}

/**
 * Check feature access based on subscription
 * @param {string} feature - Required feature
 * @returns {Function} - Express middleware
 */
const requireFeature = (feature) => {
  return (req, res, next) => {
    if (!req.organization) {
      return next(new AppError('Organization context required', 400));
    }
    
    const hasFeature = req.organization.platformConfig?.features?.get(feature);
    
    if (!hasFeature) {
      return next(new AppError(
        `This feature (${feature}) is not available in your current plan`,
        402 // Payment Required
      ));
    }
    
    next();
  };
};

/**
 * IP whitelist check
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkIpWhitelist = (req, res, next) => {
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