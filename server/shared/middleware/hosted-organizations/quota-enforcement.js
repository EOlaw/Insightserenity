/**
 * @file Quota Enforcement Middleware
 * @description Middleware for enforcing resource quotas in hosted organizations
 * @version 1.0.0
 */

const logger = require('../../utils/logger');
const { AppError } = require('../../utils/app-error');
const OrganizationTenantService = require('../../../organization-tenants/services/organization-tenant-service');
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');

/**
 * Enforce quotas for various resources
 * @param {Object} options - Quota enforcement options
 * @param {string} options.resource - Resource type to check
 * @param {number} options.increment - Amount to increment usage by (default: 1)
 * @param {boolean} options.strict - Whether to strictly enforce limits (default: true)
 * @returns {Function} Express middleware function
 */
const enforceQuotas = (options = {}) => {
  const {
    resource = 'api_calls',
    increment = 1,
    strict = true
  } = options;

  return async (req, res, next) => {
    try {
      // Skip quota enforcement for certain conditions
      if (shouldSkipQuotaCheck(req, resource)) {
        return next();
      }

      // Ensure tenant context exists
      if (!req.tenant) {
        logger.warn('Quota enforcement requires tenant context', {
          resource,
          path: req.path,
          method: req.method,
          userId: req.user?._id
        });
        return next();
      }

      const tenant = req.tenant;

      // Check if tenant has unlimited access (enterprise plans, etc.)
      if (hasUnlimitedAccess(tenant, resource)) {
        logger.debug('Unlimited access granted', {
          tenantId: tenant._id,
          resource,
          plan: tenant.subscription?.plan
        });
        return next();
      }

      // Get current usage and limits
      const usage = await getCurrentUsage(tenant, resource);
      const limit = getResourceLimit(tenant, resource);

      if (limit === null || limit === undefined) {
        logger.warn('No limit defined for resource', {
          tenantId: tenant._id,
          resource,
          plan: tenant.subscription?.plan
        });
        return next();
      }

      // Check if adding the increment would exceed the limit
      const projectedUsage = usage + increment;
      
      if (projectedUsage > limit) {
        logger.warn('Quota exceeded', {
          tenantId: tenant._id,
          resource,
          currentUsage: usage,
          limit,
          increment,
          projectedUsage,
          plan: tenant.subscription?.plan,
          path: req.path,
          method: req.method,
          userId: req.user?._id
        });

        if (strict) {
          const error = new AppError('Resource quota exceeded', 429);
          error.type = 'QuotaExceeded';
          error.quota = {
            resource,
            limit,
            current: usage,
            increment,
            projected: projectedUsage
          };
          error.usage = usage;
          return next(error);
        } else {
          // Soft enforcement - log warning but allow request
          logger.warn('Quota soft limit exceeded - allowing request', {
            tenantId: tenant._id,
            resource,
            usage,
            limit
          });
        }
      }

      // Store usage info for tracking middleware
      req.quotaCheck = {
        resource,
        usage,
        limit,
        increment,
        withinLimits: projectedUsage <= limit
      };

      next();

    } catch (error) {
      logger.error('Quota enforcement error', {
        error: error.message,
        stack: error.stack,
        resource,
        tenantId: req.tenant?._id,
        path: req.path,
        method: req.method
      });
      
      // On error, allow request to proceed to avoid blocking legitimate traffic
      next();
    }
  };
};

/**
 * Check if quota enforcement should be skipped
 * @param {Object} req - Express request object
 * @param {string} resource - Resource type
 * @returns {boolean} Whether to skip quota check
 */
function shouldSkipQuotaCheck(req, resource) {
  // Skip for health checks and internal routes
  const skipPaths = ['/health', '/ping', '/metrics', '/admin'];
  if (skipPaths.some(path => req.path.startsWith(path))) {
    return true;
  }

  // Skip for platform admin users
  if (req.user?.roles?.includes('super_admin') || req.user?.roles?.includes('admin')) {
    return true;
  }

  // Skip for GET requests on certain resources
  if (req.method === 'GET' && ['storage', 'bandwidth'].includes(resource)) {
    return true;
  }

  return false;
}

/**
 * Check if tenant has unlimited access for a resource
 * @param {Object} tenant - Tenant object
 * @param {string} resource - Resource type
 * @returns {boolean} Whether tenant has unlimited access
 */
function hasUnlimitedAccess(tenant, resource) {
  // Enterprise plans typically have unlimited access
  const unlimitedPlans = ['enterprise', 'enterprise_plus', 'unlimited'];
  
  if (unlimitedPlans.includes(tenant.subscription?.plan)) {
    return true;
  }

  // Check for specific unlimited resources
  const resourceLimits = tenant.resourceLimits?.[resource];
  if (resourceLimits && resourceLimits.unlimited === true) {
    return true;
  }

  return false;
}

/**
 * Get current usage for a resource
 * @param {Object} tenant - Tenant object
 * @param {string} resource - Resource type
 * @returns {Promise<number>} Current usage
 */
async function getCurrentUsage(tenant, resource) {
  try {
    // Get usage from tenant service
    const usage = await OrganizationTenantService.getTenantUsage(tenant._id);
    
    switch (resource) {
      case 'api_calls':
        return usage.apiCalls?.current || 0;
      case 'storage':
        return usage.storage?.current || 0;
      case 'bandwidth':
        return usage.bandwidth?.current || 0;
      case 'users':
        return usage.users?.current || 0;
      case 'organizations':
        return usage.organizations?.current || 0;
      case 'integrations':
        return usage.integrations?.current || 0;
      default:
        return usage[resource]?.current || 0;
    }
  } catch (error) {
    logger.error('Error getting current usage', {
      error: error.message,
      tenantId: tenant._id,
      resource
    });
    return 0;
  }
}

/**
 * Get resource limit for tenant
 * @param {Object} tenant - Tenant object
 * @param {string} resource - Resource type
 * @returns {number|null} Resource limit or null if unlimited
 */
function getResourceLimit(tenant, resource) {
  // Check tenant-specific limits first
  const resourceLimits = tenant.resourceLimits?.[resource];
  if (resourceLimits) {
    if (resourceLimits.unlimited) {
      return null;
    }
    return resourceLimits.limit;
  }

  // Fall back to plan-based limits
  const planLimits = getPlanLimits(tenant.subscription?.plan);
  return planLimits[resource] || null;
}

/**
 * Get default limits for a subscription plan
 * @param {string} plan - Subscription plan
 * @returns {Object} Plan limits
 */
function getPlanLimits(plan) {
  const defaultLimits = {
    starter: {
      api_calls: 10000,
      storage: 1024 * 1024 * 1024, // 1GB
      bandwidth: 10 * 1024 * 1024 * 1024, // 10GB
      users: 5,
      organizations: 1,
      integrations: 3
    },
    professional: {
      api_calls: 100000,
      storage: 10 * 1024 * 1024 * 1024, // 10GB
      bandwidth: 100 * 1024 * 1024 * 1024, // 100GB
      users: 25,
      organizations: 5,
      integrations: 10
    },
    business: {
      api_calls: 500000,
      storage: 50 * 1024 * 1024 * 1024, // 50GB
      bandwidth: 500 * 1024 * 1024 * 1024, // 500GB
      users: 100,
      organizations: 20,
      integrations: 25
    },
    enterprise: {
      api_calls: null, // Unlimited
      storage: null,
      bandwidth: null,
      users: null,
      organizations: null,
      integrations: null
    }
  };

  return defaultLimits[plan] || defaultLimits.starter;
}

/**
 * Create resource-specific quota middleware
 * @param {string} resource - Resource type
 * @param {Object} options - Additional options
 * @returns {Function} Express middleware function
 */
const createResourceQuotaMiddleware = (resource, options = {}) => {
  return enforceQuotas({ resource, ...options });
};

// Pre-configured middleware for common resources
const enforceAPIQuotas = createResourceQuotaMiddleware('api_calls');
const enforceStorageQuotas = createResourceQuotaMiddleware('storage');
const enforceUserQuotas = createResourceQuotaMiddleware('users');
const enforceIntegrationQuotas = createResourceQuotaMiddleware('integrations');

module.exports = {
  enforceQuotas,
  createResourceQuotaMiddleware,
  enforceAPIQuotas,
  enforceStorageQuotas,
  enforceUserQuotas,
  enforceIntegrationQuotas,
  shouldSkipQuotaCheck,
  hasUnlimitedAccess,
  getCurrentUsage,
  getResourceLimit,
  getPlanLimits
};