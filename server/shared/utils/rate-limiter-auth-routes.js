/**
 * @file Rate Limiter Adapter for Auth Routes
 * @description Adapter to bridge auth-routes.js expectations with existing rate limiter
 * @version 3.0.0
 */

const {
  createRateLimitMiddleware,
  rateLimiters,
  rateLimiterFactory
} = require('./rate-limiter');
const logger = require('./logger');

/**
 * Rate limiter configurations for auth endpoints
 * Maps auth route types to rate limiter options
 */
const AUTH_RATE_LIMITS = {
  register: {
    points: 5,
    duration: 900, // 15 minutes in seconds
    blockDuration: 900,
    keyPrefix: 'auth_register'
  },
  login: {
    points: 10,
    duration: 900, // 15 minutes in seconds
    blockDuration: 900,
    keyPrefix: 'auth_login'
  },
  logout: {
    points: 20,
    duration: 900,
    blockDuration: 300,
    keyPrefix: 'auth_logout'
  },
  'forgot-password': {
    points: 3,
    duration: 3600, // 1 hour in seconds
    blockDuration: 3600,
    keyPrefix: 'auth_forgot_password'
  },
  'reset-password': {
    points: 5,
    duration: 3600,
    blockDuration: 1800,
    keyPrefix: 'auth_reset_password'
  },
  'verify-email': {
    points: 10,
    duration: 3600,
    blockDuration: 300,
    keyPrefix: 'auth_verify_email'
  },
  'resend-verification': {
    points: 3,
    duration: 3600,
    blockDuration: 1800,
    keyPrefix: 'auth_resend_verification'
  },
  'change-password': {
    points: 5,
    duration: 900,
    blockDuration: 1800,
    keyPrefix: 'auth_change_password'
  },
  '2fa-verify': {
    points: 5,
    duration: 300, // 5 minutes
    blockDuration: 900,
    keyPrefix: 'auth_2fa_verify'
  },
  'api-login': {
    points: 50,
    duration: 900,
    blockDuration: 600,
    keyPrefix: 'auth_api_login'
  }
};

/**
 * Convert express-rate-limit style options to rate-limiter-flexible options
 * @param {Object} options - Express rate limit options
 * @returns {Object} - Rate limiter flexible options
 */
const convertOptions = (options) => {
  const converted = {};
  
  if (options.max) {
    converted.points = options.max;
  }
  
  if (options.windowMs) {
    converted.duration = Math.floor(options.windowMs / 1000); // Convert ms to seconds
  }
  
  if (options.blockDuration) {
    converted.blockDuration = Math.floor(options.blockDuration / 1000);
  } else if (options.windowMs) {
    converted.blockDuration = Math.floor(options.windowMs / 1000);
  }
  
  return converted;
};

/**
 * Main rate limiter function compatible with auth-routes.js
 * @param {string} type - Type of rate limiting (register, login, etc.)
 * @param {Object} options - Rate limiting options in express-rate-limit format
 * @returns {Function} - Express middleware
 */
const rateLimiter = (type, options = {}) => {
  try {
    // Get default configuration for this auth type
    const defaultConfig = AUTH_RATE_LIMITS[type] || AUTH_RATE_LIMITS.login;
    
    // Convert express-rate-limit options to rate-limiter-flexible format
    const convertedOptions = convertOptions(options);
    
    // Merge default config with provided options
    const finalOptions = {
      ...defaultConfig,
      ...convertedOptions
    };

    // Ensure keyPrefix is set
    if (!finalOptions.keyPrefix) {
      finalOptions.keyPrefix = `auth_${type}`;
    }

    logger.debug('Creating rate limiter middleware', {
      type,
      options: finalOptions,
      originalOptions: options
    });

    // Create and return the middleware using existing infrastructure
    return createRateLimitMiddleware(`auth_${type}`, finalOptions);
    
  } catch (error) {
    logger.error('Failed to create rate limiter middleware', {
      type,
      options,
      error: error.message,
      stack: error.stack
    });
    
    // Return a pass-through middleware on error to avoid breaking auth
    return (req, res, next) => {
      logger.warn('Rate limiter fallback - allowing request without limiting', {
        type,
        endpoint: req.originalUrl,
        method: req.method,
        ip: req.ip
      });
      next();
    };
  }
};

/**
 * Enhanced rate limiter with additional features for auth endpoints
 * @param {string} type - Type of rate limiting
 * @param {Object} options - Enhanced options
 * @returns {Function} - Express middleware
 */
const enhancedRateLimiter = (type, options = {}) => {
  const baseMiddleware = rateLimiter(type, options);
  
  return async (req, res, next) => {
    // Add custom headers for auth endpoints
    res.set('X-Auth-Rate-Limit-Type', type);
    
    // Log rate limiting attempts for security monitoring
    logger.debug('Auth rate limit check', {
      type,
      endpoint: req.originalUrl,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: req.user?._id,
      timestamp: new Date().toISOString()
    });
    
    return baseMiddleware(req, res, next);
  };
};

/**
 * Create progressive rate limiter for auth endpoints
 * Adjusts limits based on user behavior
 * @param {string} type - Type of rate limiting
 * @param {Object} options - Rate limiting options
 * @returns {Function} - Express middleware
 */
const progressiveAuthRateLimiter = (type, options = {}) => {
  const baseConfig = AUTH_RATE_LIMITS[type] || AUTH_RATE_LIMITS.login;
  const finalOptions = { ...baseConfig, ...convertOptions(options) };
  
  return async (req, res, next) => {
    try {
      // Generate key based on IP and user if available
      let key = req.ip;
      if (req.user && req.user._id) {
        key = `user_${req.user._id}`;
      }
      
      // Check for previous failed attempts
      const limiter = rateLimiterFactory.getLimiter(`progressive_auth_${type}`, {
        ...finalOptions,
        keyPrefix: `progressive_auth_${type}`
      });
      
      await limiter.consume(key);
      
      // Add success headers
      const limiterRes = await limiter.get(key);
      if (limiterRes) {
        res.set({
          'X-Auth-RateLimit-Limit': finalOptions.points,
          'X-Auth-RateLimit-Remaining': limiterRes.remainingPoints || 0,
          'X-Auth-RateLimit-Reset': new Date(Date.now() + limiterRes.msBeforeNext).toISOString(),
          'X-Auth-RateLimit-Type': type
        });
      }
      
      next();
    } catch (rateLimiterRes) {
      // Rate limit exceeded
      const retryAfter = Math.round(rateLimiterRes.msBeforeNext / 1000) || 60;
      
      res.set({
        'Retry-After': retryAfter,
        'X-Auth-RateLimit-Limit': rateLimiterRes.totalPoints,
        'X-Auth-RateLimit-Remaining': rateLimiterRes.remainingPoints || 0,
        'X-Auth-RateLimit-Reset': new Date(Date.now() + rateLimiterRes.msBeforeNext).toISOString(),
        'X-Auth-RateLimit-Type': type
      });

      logger.warn('Auth rate limit exceeded', {
        type,
        key: rateLimiterRes.key,
        totalPoints: rateLimiterRes.totalPoints,
        consumedPoints: rateLimiterRes.consumedPoints,
        remainingPoints: rateLimiterRes.remainingPoints || 0,
        msBeforeNext: rateLimiterRes.msBeforeNext,
        endpoint: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('user-agent')
      });

      return res.status(429).json({
        status: 'error',
        message: 'Too many authentication attempts. Please try again later.',
        code: 'AUTH_RATE_LIMIT_EXCEEDED',
        type: type,
        retryAfter: retryAfter,
        timestamp: new Date().toISOString()
      });
    }
  };
};

/**
 * Get rate limit status for a key
 * @param {string} type - Rate limit type
 * @param {string} key - Rate limit key
 * @returns {Promise<Object>} - Rate limit status
 */
const getRateLimitStatus = async (type, key) => {
  try {
    const limiter = rateLimiterFactory.getLimiter(`auth_${type}`);
    const status = await limiter.get(key);
    
    return {
      type,
      key,
      points: limiter.points,
      remainingPoints: status?.remainingPoints || limiter.points,
      msBeforeNext: status?.msBeforeNext || 0,
      resetAt: status ? new Date(Date.now() + status.msBeforeNext) : null
    };
  } catch (error) {
    logger.error('Failed to get rate limit status', { type, key, error: error.message });
    return null;
  }
};

/**
 * Reset rate limit for a key
 * @param {string} type - Rate limit type
 * @param {string} key - Rate limit key
 * @returns {Promise<boolean>} - Success status
 */
const resetRateLimit = async (type, key) => {
  try {
    const limiter = rateLimiterFactory.getLimiter(`auth_${type}`);
    await limiter.delete(key);
    
    logger.info('Rate limit reset', { type, key });
    return true;
  } catch (error) {
    logger.error('Failed to reset rate limit', { type, key, error: error.message });
    return false;
  }
};

module.exports = {
  rateLimiter,
  enhancedRateLimiter,
  progressiveAuthRateLimiter,
  getRateLimitStatus,
  resetRateLimit,
  AUTH_RATE_LIMITS,
  
  // For backward compatibility
  default: rateLimiter
};