/**
 * @file Tenant Context Middleware
 * @description Middleware for managing multi-tenant context and access control
 * @version 1.0.0
 */

const HostedOrganization = require('../../hosted-organizations/organizations/models/organization-model');
const OrganizationTenantService = require('../services/organization-tenant-service');
const { AppError } = require('../../shared/utils/app-error');
const logger = require('../../shared/utils/logger');
const { TENANT_CONSTANTS } = require('../constants/tenant-constants');

/**
 * Detect tenant context from various sources
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const detectTenantContext = async (req, res, next) => {
  try {
    let tenantId = null;
    let tenantCode = null;
    let tenant = null;

    // 1. Check custom headers
    if (req.headers['x-tenant-id']) {
      tenantId = req.headers['x-tenant-id'];
      logger.debug('Tenant ID detected from header', { tenantId });
    } else if (req.headers['x-tenant-code']) {
      tenantCode = req.headers['x-tenant-code'];
      logger.debug('Tenant code detected from header', { tenantCode });
    }

    // 2. Check subdomain
    if (!tenantId && !tenantCode) {
      const host = req.get('host');
      const subdomain = host.split('.')[0];
      
      // Skip if it's a reserved subdomain
      const reservedSubdomains = ['www', 'api', 'admin', 'app', 'staging', 'dev'];
      if (!reservedSubdomains.includes(subdomain) && subdomain !== host) {
        tenantCode = subdomain.toUpperCase();
        logger.debug('Tenant code detected from subdomain', { tenantCode, host });
      }
    }

    // 3. Check custom domain
    if (!tenantId && !tenantCode) {
      const domain = req.get('host');
      tenant = await OrganizationTenantService.getTenantByDomain(domain);
      if (tenant) {
        tenantId = tenant._id.toString();
        logger.debug('Tenant detected from custom domain', { domain, tenantId });
      }
    }

    // 4. Check query parameters (lowest priority)
    if (!tenantId && !tenantCode && !tenant) {
      if (req.query.tenantId) {
        tenantId = req.query.tenantId;
        logger.debug('Tenant ID detected from query parameter', { tenantId });
      } else if (req.query.tenantCode) {
        tenantCode = req.query.tenantCode;
        logger.debug('Tenant code detected from query parameter', { tenantCode });
      }
    }

    // 5. Check user's default tenant
    if (!tenantId && !tenantCode && !tenant && req.user) {
      if (req.user.defaultTenantId) {
        tenantId = req.user.defaultTenantId;
        logger.debug('Tenant ID detected from user default', { tenantId, userId: req.user._id });
      }
    }

    // Fetch tenant if we have ID or code
    if (!tenant) {
      if (tenantId) {
        try {
          tenant = await OrganizationTenantService.getTenantById(tenantId);
        } catch (error) {
          logger.warn('Failed to fetch tenant by ID', { tenantId, error: error.message });
        }
      } else if (tenantCode) {
        try {
          tenant = await OrganizationTenantService.getTenantByCode(tenantCode);
        } catch (error) {
          logger.warn('Failed to fetch tenant by code', { tenantCode, error: error.message });
        }
      }
    }

    // Attach tenant context to request
    if (tenant) {
      req.tenant = tenant;
      req.tenantId = tenant._id.toString();
      req.tenantCode = tenant.tenantCode;
      
      // Add tenant context to response headers
      res.setHeader('X-Tenant-ID', req.tenantId);
      res.setHeader('X-Tenant-Code', req.tenantCode);
      
      logger.debug('Tenant context established', {
        tenantId: req.tenantId,
        tenantCode: req.tenantCode,
        userId: req.user?._id
      });
    }

    next();

  } catch (error) {
    logger.error('Error detecting tenant context', { error });
    next(error);
  }
};

/**
 * Require tenant context and establish organization context
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireTenantContext = async (req, res, next) => {
  if (!req.tenant || !req.tenantId) {
    logger.warn('Tenant context required but not found', {
      userId: req.user?._id,
      path: req.path
    });
    
    return next(new AppError('Tenant context is required for this operation', 400));
  }

  // Verify tenant is active
  if (req.tenant.status !== TENANT_CONSTANTS.TENANT_STATUS.ACTIVE) {
    logger.warn('Attempt to access inactive tenant', {
      tenantId: req.tenantId,
      status: req.tenant.status,
      userId: req.user?._id
    });
    
    if (req.tenant.status === TENANT_CONSTANTS.TENANT_STATUS.SUSPENDED) {
      return next(new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_SUSPENDED, 403));
    } else if (req.tenant.status === TENANT_CONSTANTS.TENANT_STATUS.TERMINATED) {
      return next(new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_TERMINATED, 403));
    } else {
      return next(new AppError('Tenant is not active', 403));
    }
  }

  // NEW: Establish organization context from tenant
  try {
    // Look for organization that references this tenant
    // Ensure we get a full Mongoose document with methods, not a lean object
    const organization = await HostedOrganization.findOne({ tenantRef: req.tenant._id })
      .populate('team.owner team.admins.user team.members.user'); // Add population if needed
  
    
    if (organization) {
      req.organization = organization;
      req.organizationId = organization._id;
      
      logger.debug('Organization context established from tenant', {
        tenantId: req.tenantId,
        organizationId: organization._id,
        organizationName: organization.name,
        hasIsMemberMethod: typeof organization.isMember === 'function' // Verify method exists
      });
    } else {
      logger.warn('Organization not found for tenant', {
        tenantId: req.tenantId,
        tenantObjectId: req.tenant._id
      });
    }
  } catch (error) {
    logger.error('Error establishing organization context from tenant', {
      tenantId: req.tenantId,
      error: error.message
    });
    // Continue without organization context rather than failing the request
  }

  next();
};

/**
 * Validate tenant access
 * Ensures user has access to the requested tenant
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateTenantAccess = async (req, res, next) => {
  try {
    const requestedTenantId = req.params.id || req.tenantId;
    
    if (!requestedTenantId) {
      return next(new AppError('Tenant ID is required', 400));
    }

    // Platform admins have access to all tenants
    if (req.user.roles.includes('admin') || req.user.roles.includes('super_admin')) {
      logger.debug('Platform admin access granted', {
        userId: req.user._id,
        tenantId: requestedTenantId
      });
      return next();
    }

    // Fetch tenant if not already in context
    let tenant = req.tenant;
    if (!tenant || tenant._id.toString() !== requestedTenantId) {
      try {
        tenant = await OrganizationTenantService.getTenantById(requestedTenantId);
      } catch (error) {
        return next(new AppError('Tenant not found', 404));
      }
    }

    // Check if user is owner
    if (tenant.owner.toString() === req.user._id.toString()) {
      req.userTenantRole = 'owner';
      return next();
    }

    // Check if user is admin
    if (tenant.admins.some(adminId => adminId.toString() === req.user._id.toString())) {
      req.userTenantRole = 'admin';
      return next();
    }

    // Check if user is a member (would need to implement member tracking)
    // This is a placeholder - you'd need to implement actual member checking
    // based on your business logic
    
    logger.warn('User does not have access to tenant', {
      userId: req.user._id,
      tenantId: requestedTenantId
    });
    
    return next(new AppError('Access denied to this tenant', 403));

  } catch (error) {
    logger.error('Error validating tenant access', { error });
    next(error);
  }
};

/**
 * Require tenant owner role
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireTenantOwner = async (req, res, next) => {
  try {
    // Platform admins can perform owner actions
    if (req.user.roles.includes('admin') || req.user.roles.includes('super_admin')) {
      return next();
    }

    const tenantId = req.params.id || req.tenantId;
    if (!tenantId) {
      return next(new AppError('Tenant context is required', 400));
    }

    // Get tenant if not in context
    let tenant = req.tenant;
    if (!tenant || tenant._id.toString() !== tenantId) {
      tenant = await OrganizationTenantService.getTenantById(tenantId);
    }

    // Check if user is owner
    if (tenant.owner.toString() !== req.user._id.toString()) {
      logger.warn('Non-owner attempted owner action', {
        userId: req.user._id,
        tenantId,
        ownerId: tenant.owner
      });
      
      return next(new AppError('Only the tenant owner can perform this action', 403));
    }

    next();

  } catch (error) {
    logger.error('Error checking tenant owner', { error });
    next(error);
  }
};

/**
 * Require tenant admin role
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requireTenantAdmin = async (req, res, next) => {
  try {
    // Platform admins can perform admin actions
    if (req.user.roles.includes('admin') || req.user.roles.includes('super_admin')) {
      return next();
    }

    const tenantId = req.params.id || req.tenantId;
    if (!tenantId) {
      return next(new AppError('Tenant context is required', 400));
    }

    // Get tenant if not in context
    let tenant = req.tenant;
    if (!tenant || tenant._id.toString() !== tenantId) {
      tenant = await OrganizationTenantService.getTenantById(tenantId);
    }

    // Check if user is owner or admin
    const isOwner = tenant.owner.toString() === req.user._id.toString();
    const isAdmin = tenant.admins.some(adminId => adminId.toString() === req.user._id.toString());

    if (!isOwner && !isAdmin) {
      logger.warn('Non-admin attempted admin action', {
        userId: req.user._id,
        tenantId
      });
      
      return next(new AppError('Admin privileges required for this action', 403));
    }

    next();

  } catch (error) {
    logger.error('Error checking tenant admin', { error });
    next(error);
  }
};

/**
 * Require platform admin role
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const requirePlatformAdmin = (req, res, next) => {
  if (!req.user.roles.includes('admin') && !req.user.roles.includes('super_admin')) {
    logger.warn('Non-platform admin attempted platform admin action', {
      userId: req.user._id,
      roles: req.user.roles
    });
    
    return next(new AppError('Platform administrator privileges required', 403));
  }

  next();
};

/**
 * Check tenant feature availability
 * @param {string|array} features - Required features
 * @returns {Function} Middleware function
 */
const requireTenantFeature = (features) => {
  const requiredFeatures = Array.isArray(features) ? features : [features];
  
  return async (req, res, next) => {
    try {
      if (!req.tenant) {
        return next(new AppError('Tenant context is required', 400));
      }

      // Check each required feature
      const missingFeatures = requiredFeatures.filter(feature => !req.tenant.hasFeature(feature));
      
      if (missingFeatures.length > 0) {
        logger.warn('Tenant missing required features', {
          tenantId: req.tenantId,
          requiredFeatures,
          missingFeatures
        });
        
        return next(new AppError(
          `This feature requires: ${missingFeatures.join(', ')}. Please upgrade your plan.`,
          403
        ));
      }

      next();

    } catch (error) {
      logger.error('Error checking tenant features', { error });
      next(error);
    }
  };
};

/**
 * Check tenant resource limits
 * @param {string} resource - Resource type to check
 * @returns {Function} Middleware function
 */
const checkResourceLimit = (resource) => {
  return async (req, res, next) => {
    try {
      if (!req.tenant) {
        return next(new AppError('Tenant context is required', 400));
      }

      if (req.tenant.hasReachedLimit(resource)) {
        logger.warn('Tenant resource limit reached', {
          tenantId: req.tenantId,
          resource,
          current: req.tenant.resourceLimits[resource].current,
          max: req.tenant.resourceLimits[resource].max
        });
        
        return next(new AppError(
          `You have reached your ${resource} limit. Please upgrade your plan to continue.`,
          403
        ));
      }

      next();

    } catch (error) {
      logger.error('Error checking resource limit', { error });
      next(error);
    }
  };
};

/**
 * Track resource usage
 * @param {string} resource - Resource type
 * @param {number} amount - Amount to track (default: 1)
 * @returns {Function} Middleware function
 */
const trackResourceUsage = (resource, amount = 1) => {
  return async (req, res, next) => {
    try {
      if (!req.tenant) {
        return next(new AppError('Tenant context is required', 400));
      }

      // Track usage after successful response
      res.on('finish', async () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            await req.tenant.updateResourceUsage(resource, amount);
            logger.debug('Resource usage tracked', {
              tenantId: req.tenantId,
              resource,
              amount
            });
          } catch (error) {
            logger.error('Failed to track resource usage', {
              error,
              tenantId: req.tenantId,
              resource
            });
          }
        }
      });

      next();

    } catch (error) {
      logger.error('Error in resource tracking middleware', { error });
      next(error);
    }
  };
};

/**
 * Inject tenant database connection
 * For tenants using dedicated database strategy
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const injectTenantDatabase = async (req, res, next) => {
  try {
    if (!req.tenant) {
      return next(new AppError('Tenant context is required', 400));
    }

    if (req.tenant.database.strategy === TENANT_CONSTANTS.DATABASE_STRATEGIES.DEDICATED) {
      // Implementation would depend on your database architecture
      // This is a placeholder for the concept
      
      // const tenantDb = await DatabaseManager.getTenantConnection(req.tenant);
      // req.tenantDb = tenantDb;
      
      logger.debug('Tenant database connection established', {
        tenantId: req.tenantId,
        strategy: req.tenant.database.strategy
      });
    }

    next();

  } catch (error) {
    logger.error('Error injecting tenant database', { error });
    next(error);
  }
};

module.exports = {
  detectTenantContext,
  requireTenantContext,
  validateTenantAccess,
  requireTenantOwner,
  requireTenantAdmin,
  requirePlatformAdmin,
  requireTenantFeature,
  checkResourceLimit,
  trackResourceUsage,
  injectTenantDatabase
};