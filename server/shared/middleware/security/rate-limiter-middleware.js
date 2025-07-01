/**
 * @file Rate Limiter Middleware
 * @description Express middleware wrappers for rate limiting functionality
 * @version 1.0.0
 */

const { 
  createRateLimitMiddleware,
  rateLimiters,
  rateLimiterFactory 
} = require('../../utils/rate-limiter');
const logger = require('../../utils/logger');

/**
 * Organization-specific rate limiter
 * Provides standard rate limiting for organization endpoints
 */
const organizationLimiter = createRateLimitMiddleware('organization_general', {
  points: 100, // 100 requests
  duration: 900, // Per 15 minutes (in seconds)
  blockDuration: 900 // Block for 15 minutes
});

/**
 * Sensitive operations rate limiter
 * Stricter rate limiting for sensitive actions like deletions, security changes
 */
const sensitiveOperationLimiter = createRateLimitMiddleware('sensitive_ops', {
  points: 10, // 10 operations
  duration: 900, // Per 15 minutes (in seconds)
  blockDuration: 1800 // Block for 30 minutes
});

/**
 * Authentication rate limiter
 * Rate limiting for authentication endpoints
 */
const authLimiter = createRateLimitMiddleware('auth_general', rateLimiters.auth.login);

/**
 * Registration rate limiter
 * Rate limiting for user registration
 */
const registrationLimiter = createRateLimitMiddleware('auth_register', rateLimiters.auth.register);

/**
 * API general rate limiter
 * Standard rate limiting for general API endpoints
 */
const apiLimiter = createRateLimitMiddleware('api_general', rateLimiters.api.general);

/**
 * File upload rate limiter
 * Rate limiting for file upload endpoints
 */
const uploadLimiter = createRateLimitMiddleware('file_upload', rateLimiters.upload.general);

/**
 * Create custom rate limiter with organization-aware limits
 * Adjusts rate limits based on organization subscription tier
 */
const createOrganizationRateLimiter = (baseConfig = {}) => {
  return async (req, res, next) => {
    try {
      // Get organization tier from request context
      const orgTier = req.organization?.subscription?.tier || 'starter';
      const userId = req.user?.id;
      const organizationId = req.organizationId || req.params.id;

      // Determine rate limit based on organization tier
      const tierLimits = {
        starter: { points: 100, duration: 3600 },
        growth: { points: 500, duration: 3600 },
        professional: { points: 2000, duration: 3600 },
        enterprise: { points: 10000, duration: 3600 }
      };

      const limits = { ...tierLimits[orgTier], ...baseConfig };
      const limiterName = `org_${organizationId}_${orgTier}`;

      // Create organization-specific rate limiter
      const middleware = createRateLimitMiddleware(limiterName, limits);
      
      return middleware(req, res, next);
    } catch (error) {
      logger.error('Organization rate limiter error', {
        error: error.message,
        organizationId: req.organizationId,
        userId: req.user?.id
      });
      
      // Fall back to default rate limiting
      return apiLimiter(req, res, next);
    }
  };
};

/**
 * Create progressive rate limiter
 * Increases rate limits for users with good behavior history
 */
const createProgressiveRateLimiter = (baseConfig = {}) => {
  return async (req, res, next) => {
    try {
      const userId = req.user?.id;
      
      if (!userId) {
        // Use IP-based limiting for unauthenticated users
        const middleware = createRateLimitMiddleware('progressive_anonymous', baseConfig);
        return middleware(req, res, next);
      }

      // Create user-specific progressive limiter
      const limiterName = `progressive_user_${userId}`;
      const middleware = createRateLimitMiddleware(limiterName, {
        ...baseConfig,
        // Progressive enhancement based on user behavior could be added here
        keyPrefix: `progressive_${userId}`
      });

      return middleware(req, res, next);
    } catch (error) {
      logger.error('Progressive rate limiter error', {
        error: error.message,
        userId: req.user?.id
      });
      
      // Fall back to standard rate limiting
      const fallbackMiddleware = createRateLimitMiddleware('progressive_fallback', baseConfig);
      return fallbackMiddleware(req, res, next);
    }
  };
};

/**
 * Create burst rate limiter
 * Allows short bursts of activity followed by cooling periods
 */
const createBurstRateLimiter = (options = {}) => {
  const {
    burstPoints = 20,
    burstDuration = 60, // 1 minute
    sustainedPoints = 100,
    sustainedDuration = 3600, // 1 hour
    cooldownMultiplier = 2
  } = options;

  return async (req, res, next) => {
    try {
      const key = req.user?.id || req.ip;
      
      // Check burst limiter first
      const burstLimiter = rateLimiterFactory.getLimiter(`burst_${key}`, {
        points: burstPoints,
        duration: burstDuration,
        blockDuration: burstDuration * cooldownMultiplier
      });

      // Check sustained limiter
      const sustainedLimiter = rateLimiterFactory.getLimiter(`sustained_${key}`, {
        points: sustainedPoints,
        duration: sustainedDuration,
        blockDuration: sustainedDuration
      });

      try {
        await burstLimiter.consume(key);
        await sustainedLimiter.consume(key);
        next();
      } catch (rateLimiterRes) {
        // Rate limit exceeded
        const retryAfter = Math.round(rateLimiterRes.msBeforeNext / 1000) || 60;
        
        res.set({
          'Retry-After': retryAfter,
          'X-RateLimit-Limit': rateLimiterRes.totalPoints,
          'X-RateLimit-Remaining': rateLimiterRes.remainingPoints || 0,
          'X-RateLimit-Reset': new Date(Date.now() + rateLimiterRes.msBeforeNext).toISOString(),
        });

        logger.warn('Burst rate limit exceeded', {
          key: rateLimiterRes.key,
          totalPoints: rateLimiterRes.totalPoints,
          consumedPoints: rateLimiterRes.consumedPoints,
          url: req.originalUrl
        });

        return res.status(429).json({
          status: 'error',
          message: 'Rate limit exceeded. Please slow down your requests.',
          retryAfter
        });
      }
    } catch (error) {
      logger.error('Burst rate limiter error', {
        error: error.message,
        url: req.originalUrl
      });
      next(); // Continue without rate limiting on error
    }
  };
};

/**
 * Create endpoint-specific rate limiter
 * Provides different limits for different endpoint patterns
 */
const createEndpointRateLimiter = (endpointLimits = {}) => {
  return (req, res, next) => {
    try {
      // Match endpoint pattern to determine appropriate limits
      const endpoint = req.route?.path || req.path;
      const method = req.method;
      const key = `${method}:${endpoint}`;

      // Find matching endpoint configuration
      let config = endpointLimits[key] || 
                   endpointLimits[endpoint] || 
                   endpointLimits.default || 
                   rateLimiters.api.general;

      // Create endpoint-specific limiter
      const limiterName = `endpoint_${method}_${endpoint.replace(/[^\w]/g, '_')}`;
      const middleware = createRateLimitMiddleware(limiterName, config);

      return middleware(req, res, next);
    } catch (error) {
      logger.error('Endpoint rate limiter error', {
        error: error.message,
        endpoint: req.path,
        method: req.method
      });
      
      // Fall back to API limiter
      return apiLimiter(req, res, next);
    }
  };
};

/**
 * Skip rate limiting middleware
 * Conditionally skips rate limiting based on conditions
 */
const skipRateLimiting = (condition) => {
  return (req, res, next) => {
    if (condition(req)) {
      // Skip rate limiting
      return next();
    }
    
    // Apply default rate limiting
    return apiLimiter(req, res, next);
  };
};

/**
 * Rate limit bypass for admin users
 * Allows admin users to bypass rate limiting
 */
const adminBypass = (req, res, next) => {
  const userRole = req.user?.role?.primary;
  
  if (['super_admin', 'admin'].includes(userRole)) {
    logger.debug('Rate limiting bypassed for admin user', {
      userId: req.user.id,
      role: userRole,
      url: req.originalUrl
    });
    return next();
  }
  
  return apiLimiter(req, res, next);
};

module.exports = {
  // Pre-configured limiters
  organizationLimiter,
  sensitiveOperationLimiter,
  authLimiter,
  registrationLimiter,
  apiLimiter,
  uploadLimiter,
  
  // Dynamic limiter creators
  createOrganizationRateLimiter,
  createProgressiveRateLimiter,
  createBurstRateLimiter,
  createEndpointRateLimiter,
  
  // Utility middleware
  skipRateLimiting,
  adminBypass,
  
  // Direct access to core functionality
  createRateLimitMiddleware,
  rateLimiters,
  rateLimiterFactory
};