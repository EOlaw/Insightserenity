/**
 * @file Organization Rate Limiter Middleware
 * @description Middleware for implementing organization-specific rate limiting in hosted organizations
 * @version 1.0.0
 */

const logger = require('../../utils/logger');
const { AppError } = require('../../utils/app-error');
const { createRateLimitMiddleware } = require('../../utils/rate-limiter');

/**
 * Create organization-specific rate limiter
 * @param {Object} options - Rate limiting options
 * @param {number} options.points - Number of requests allowed
 * @param {number} options.duration - Time window in seconds
 * @param {number} options.blockDuration - Block duration in seconds after limit exceeded
 * @param {string} options.keyGenerator - Strategy for generating rate limit keys
 * @param {Object} options.planLimits - Plan-specific rate limits
 * @param {boolean} options.skipSuccessfulRequests - Whether to skip successful requests
 * @param {boolean} options.skipFailedRequests - Whether to skip failed requests
 * @returns {Function} Express middleware function
 */
const organizationRateLimiter = (options = {}) => {
  const defaultOptions = {
    points: 1000, // Default: 1000 requests
    duration: 3600, // Default: per hour
    blockDuration: 3600, // Default: block for 1 hour
    keyGenerator: 'tenant', // Default: rate limit by tenant
    planLimits: {
      starter: { points: 500, duration: 3600 },
      professional: { points: 2000, duration: 3600 },
      business: { points: 5000, duration: 3600 },
      enterprise: { points: 20000, duration: 3600 }
    },
    skipSuccessfulRequests: false,
    skipFailedRequests: true
  };

  const config = { ...defaultOptions, ...options };

  return async (req, res, next) => {
    try {
      // Skip rate limiting for certain conditions
      if (shouldSkipRateLimit(req)) {
        return next();
      }

      // Generate rate limit key
      const rateLimitKey = generateRateLimitKey(req, config.keyGenerator);
      
      if (!rateLimitKey) {
        logger.debug('No rate limit key generated, skipping rate limiting', {
          path: req.path,
          method: req.method,
          keyGenerator: config.keyGenerator
        });
        return next();
      }

      // Get plan-specific limits
      const planLimits = getPlanSpecificLimits(req, config);
      
      // Create dynamic rate limiter with plan-specific settings
      const rateLimiter = createRateLimitMiddleware(`org_${rateLimitKey}`, {
        points: planLimits.points,
        duration: planLimits.duration,
        blockDuration: config.blockDuration,
        skipSuccessfulRequests: config.skipSuccessfulRequests,
        skipFailedRequests: config.skipFailedRequests,
        keyGenerator: () => rateLimitKey, // Use our custom key
        onLimitReached: (req, res, options) => {
          handleRateLimitExceeded(req, res, options, planLimits);
        }
      });

      // Apply rate limiting
      rateLimiter(req, res, next);

    } catch (error) {
      logger.error('Organization rate limiter error', {
        error: error.message,
        stack: error.stack,
        path: req.path,
        method: req.method,
        tenantId: req.tenant?._id
      });
      
      // On error, allow request to proceed
      next();
    }
  };
};

/**
 * Generate rate limit key based on strategy
 * @param {Object} req - Express request object
 * @param {string} strategy - Key generation strategy
 * @returns {string|null} Rate limit key
 */
function generateRateLimitKey(req, strategy) {
  switch (strategy) {
    case 'tenant':
      return req.tenant?._id || req.tenantId;
    
    case 'organization':
      return req.organizationId || req.tenant?.organizationId;
    
    case 'user':
      return req.user?._id;
    
    case 'tenant_user':
      const tenantId = req.tenant?._id || req.tenantId;
      const userId = req.user?._id;
      return tenantId && userId ? `${tenantId}:${userId}` : null;
    
    case 'ip':
      return req.ip || req.connection.remoteAddress;
    
    case 'tenant_ip':
      const tenant = req.tenant?._id || req.tenantId;
      const ip = req.ip || req.connection.remoteAddress;
      return tenant && ip ? `${tenant}:${ip}` : null;
    
    default:
      logger.warn('Unknown rate limit key strategy', { strategy });
      return req.tenant?._id || req.tenantId;
  }
}

/**
 * Get plan-specific rate limits
 * @param {Object} req - Express request object
 * @param {Object} config - Rate limiter configuration
 * @returns {Object} Plan-specific limits
 */
function getPlanSpecificLimits(req, config) {
  const defaultLimits = {
    points: config.points,
    duration: config.duration
  };

  // Get tenant plan
  const plan = req.tenant?.subscription?.plan || 'starter';
  
  // Return plan-specific limits or defaults
  return config.planLimits[plan] || defaultLimits;
}

/**
 * Handle rate limit exceeded
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Object} options - Rate limit options
 * @param {Object} planLimits - Plan-specific limits
 */
function handleRateLimitExceeded(req, res, options, planLimits) {
  const tenantId = req.tenant?._id || req.tenantId;
  const plan = req.tenant?.subscription?.plan || 'starter';
  
  logger.warn('Organization rate limit exceeded', {
    tenantId,
    organizationId: req.organizationId,
    plan,
    path: req.path,
    method: req.method,
    userId: req.user?._id,
    limits: planLimits,
    currentUsage: options.totalUsage,
    resetTime: options.resetTime
  });

  // Calculate retry after time
  const retryAfter = Math.round((options.resetTime - Date.now()) / 1000) || 1;

  // Set rate limit headers
  res.set({
    'X-RateLimit-Limit': planLimits.points,
    'X-RateLimit-Remaining': Math.max(0, planLimits.points - options.totalUsage),
    'X-RateLimit-Reset': new Date(options.resetTime).toISOString(),
    'Retry-After': retryAfter
  });

  // Create error response
  const error = new AppError('Rate limit exceeded for organization', 429);
  error.type = 'RateLimitExceeded';
  error.rateLimit = {
    limit: planLimits.points,
    remaining: Math.max(0, planLimits.points - options.totalUsage),
    resetTime: options.resetTime,
    retryAfter,
    plan,
    upgradeUrl: '/billing/upgrade'
  };

  res.status(429).json({
    status: 'error',
    type: 'rate_limit_exceeded',
    message: `Rate limit exceeded. Your ${plan} plan allows ${planLimits.points} requests per ${Math.round(planLimits.duration / 60)} minutes.`,
    code: 'RATE_LIMIT_EXCEEDED',
    rateLimit: error.rateLimit,
    upgradeUrl: '/billing/upgrade'
  });
}

/**
 * Check if rate limiting should be skipped
 * @param {Object} req - Express request object
 * @returns {boolean} Whether to skip rate limiting
 */
function shouldSkipRateLimit(req) {
  // Skip for health checks and internal routes
  const skipPaths = ['/health', '/ping', '/metrics'];
  if (skipPaths.some(path => req.path.startsWith(path))) {
    return true;
  }

  // Skip for platform admin users
  if (req.user?.roles?.includes('super_admin') || req.user?.roles?.includes('admin')) {
    return true;
  }

  // Skip for OPTIONS requests
  if (req.method === 'OPTIONS') {
    return true;
  }

  return false;
}

/**
 * Create endpoint-specific rate limiters
 */

// General API rate limiter
const generalAPIRateLimiter = organizationRateLimiter({
  points: 1000,
  duration: 3600, // 1 hour
  keyGenerator: 'tenant',
  planLimits: {
    starter: { points: 500, duration: 3600 },
    professional: { points: 2000, duration: 3600 },
    business: { points: 5000, duration: 3600 },
    enterprise: { points: 20000, duration: 3600 }
  }
});

// Sensitive operations rate limiter (lower limits)
const sensitiveOperationsRateLimiter = organizationRateLimiter({
  points: 50,
  duration: 3600, // 1 hour
  blockDuration: 3600, // 1 hour block
  keyGenerator: 'tenant_user',
  planLimits: {
    starter: { points: 20, duration: 3600 },
    professional: { points: 50, duration: 3600 },
    business: { points: 100, duration: 3600 },
    enterprise: { points: 200, duration: 3600 }
  }
});

// Organization creation rate limiter (very strict)
const organizationCreationRateLimiter = organizationRateLimiter({
  points: 5,
  duration: 86400, // 24 hours
  blockDuration: 86400, // 24 hour block
  keyGenerator: 'user',
  planLimits: {
    starter: { points: 1, duration: 86400 },
    professional: { points: 3, duration: 86400 },
    business: { points: 5, duration: 86400 },
    enterprise: { points: 10, duration: 86400 }
  }
});

// File upload rate limiter
const fileUploadRateLimiter = organizationRateLimiter({
  points: 100,
  duration: 3600, // 1 hour
  keyGenerator: 'tenant',
  planLimits: {
    starter: { points: 50, duration: 3600 },
    professional: { points: 200, duration: 3600 },
    business: { points: 500, duration: 3600 },
    enterprise: { points: 1000, duration: 3600 }
  }
});

// Export rate limiter (data exports are resource intensive)
const exportRateLimiter = organizationRateLimiter({
  points: 10,
  duration: 3600, // 1 hour
  blockDuration: 3600,
  keyGenerator: 'tenant',
  planLimits: {
    starter: { points: 2, duration: 3600 },
    professional: { points: 10, duration: 3600 },
    business: { points: 20, duration: 3600 },
    enterprise: { points: 50, duration: 3600 }
  }
});

module.exports = {
  organizationRateLimiter,
  generalAPIRateLimiter,
  sensitiveOperationsRateLimiter,
  organizationCreationRateLimiter,
  fileUploadRateLimiter,
  exportRateLimiter,
  generateRateLimitKey,
  getPlanSpecificLimits,
  shouldSkipRateLimit
};