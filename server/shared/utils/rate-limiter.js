// /server/shared/utils/rate-limiter.js

const { RateLimiterRedis, RateLimiterMemory } = require('rate-limiter-flexible');

const redis = require('../config/redis');

const { AppError } = require('./app-error');
const logger = require('./logger');

/**
 * Rate limiter factory for different use cases
 */
class RateLimiterFactory {
  constructor() {
    this.limiters = new Map();
    this.redisClient = redis;
  }

  /**
   * Get or create a rate limiter instance
   */
  getLimiter(name, options = {}) {
    if (this.limiters.has(name)) {
      return this.limiters.get(name);
    }

    const limiter = this.createLimiter(name, options);
    this.limiters.set(name, limiter);
    return limiter;
  }

  /**
   * Create a new rate limiter based on configuration
   */
  createLimiter(name, options) {
    const defaultOptions = {
      keyPrefix: `rate_limit_${name}`,
      points: 100, // Number of requests
      duration: 900, // Per 15 minutes
      blockDuration: 900, // Block for 15 minutes
      execEvenly: false,
    };

    const limiterOptions = { ...defaultOptions, ...options };

    try {
      if (this.redisClient && this.redisClient.status === 'ready') {
        return new RateLimiterRedis({
          storeClient: this.redisClient,
          ...limiterOptions,
        });
      }
    } catch (error) {
      logger.warn(`Failed to create Redis rate limiter for ${name}, falling back to memory:`, error);
    }

    // Fallback to memory-based rate limiting
    return new RateLimiterMemory(limiterOptions);
  }
}

const rateLimiterFactory = new RateLimiterFactory();

/**
 * Pre-configured rate limiters for different scenarios
 */
const rateLimiters = {
  // General API rate limiting
  api: {
    general: { points: 100, duration: 60 }, // 100 requests per minute
    strict: { points: 20, duration: 60 }, // 20 requests per minute
    relaxed: { points: 500, duration: 60 }, // 500 requests per minute
  },

  // Authentication endpoints
  auth: {
    login: { points: 5, duration: 900, blockDuration: 900 }, // 5 attempts per 15 minutes
    register: { points: 3, duration: 3600, blockDuration: 3600 }, // 3 per hour
    passwordReset: { points: 3, duration: 3600, blockDuration: 3600 }, // 3 per hour
    twoFactor: { points: 5, duration: 300, blockDuration: 900 }, // 5 per 5 minutes
  },

  // Organization-specific limits
  organization: {
    standard: { points: 1000, duration: 3600 }, // 1000 per hour
    premium: { points: 5000, duration: 3600 }, // 5000 per hour
    enterprise: { points: 10000, duration: 3600 }, // 10000 per hour
  },

  // Recruitment API limits
  recruitment: {
    jobSearch: { points: 100, duration: 60 }, // 100 searches per minute
    applicationSubmit: { points: 10, duration: 3600 }, // 10 applications per hour
    candidateSearch: { points: 50, duration: 300 }, // 50 searches per 5 minutes
  },

  // File upload limits
  upload: {
    general: { points: 10, duration: 3600 }, // 10 uploads per hour
    resume: { points: 5, duration: 3600 }, // 5 resume uploads per hour
    bulk: { points: 2, duration: 3600 }, // 2 bulk uploads per hour
  },

  // Email sending limits
  email: {
    transactional: { points: 100, duration: 3600 }, // 100 per hour
    bulk: { points: 10, duration: 86400 }, // 10 bulk emails per day
    notification: { points: 50, duration: 3600 }, // 50 notifications per hour
  },
};

/**
 * Express middleware for rate limiting
 */
const createRateLimitMiddleware = (limiterName, options = {}) => {
  return async (req, res, next) => {
    try {
      const limiter = rateLimiterFactory.getLimiter(limiterName, options);
      
      // Generate key based on IP, user ID, or API key
      let key = req.ip;
      if (req.user && req.user._id) {
        key = `user_${req.user._id}`;
      } else if (req.apiKey && req.apiKey._id) {
        key = `api_${req.apiKey._id}`;
      }

      await limiter.consume(key);
      
      // Add rate limit headers
      const limiterRes = await limiter.get(key);
      if (limiterRes) {
        res.set({
          'X-RateLimit-Limit': limiter.points,
          'X-RateLimit-Remaining': limiterRes.remainingPoints || 0,
          'X-RateLimit-Reset': new Date(Date.now() + limiterRes.msBeforeNext).toISOString(),
        });
      }
      
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

      logger.warn(`Rate limit exceeded for ${limiterName}:`, {
        key: rateLimiterRes.key,
        totalPoints: rateLimiterRes.totalPoints,
        consumedPoints: rateLimiterRes.consumedPoints,
      });

      return next(new AppError('Too many requests, please try again later', 429));
    }
  };
};

/**
 * Dynamic rate limiting based on user plan or organization tier
 */
const createDynamicRateLimiter = (getOptionsCallback) => {
  return async (req, res, next) => {
    try {
      const options = await getOptionsCallback(req);
      const middleware = createRateLimitMiddleware(`dynamic_${req.user?.plan || 'default'}`, options);
      return middleware(req, res, next);
    } catch (error) {
      logger.error('Dynamic rate limiter error:', error);
      next();
    }
  };
};

/**
 * Sliding window rate limiter for more accurate limiting
 */
const createSlidingWindowLimiter = (name, options = {}) => {
  const defaultOptions = {
    points: 100,
    duration: 60,
    execEvenly: true, // Spread requests evenly
  };

  return createRateLimitMiddleware(`sliding_${name}`, { ...defaultOptions, ...options });
};

/**
 * Distributed rate limiting for microservices
 */
class DistributedRateLimiter {
  constructor(serviceName, options = {}) {
    this.serviceName = serviceName;
    this.options = {
      points: 1000,
      duration: 60,
      keyPrefix: `dist_limit_${serviceName}`,
      ...options,
    };
    this.limiter = rateLimiterFactory.getLimiter(`dist_${serviceName}`, this.options);
  }

  async consume(key, points = 1) {
    try {
      const result = await this.limiter.consume(key, points);
      return {
        allowed: true,
        remaining: result.remainingPoints,
        resetAt: new Date(Date.now() + result.msBeforeNext),
      };
    } catch (rateLimiterRes) {
      return {
        allowed: false,
        remaining: rateLimiterRes.remainingPoints || 0,
        resetAt: new Date(Date.now() + rateLimiterRes.msBeforeNext),
        retryAfter: Math.round(rateLimiterRes.msBeforeNext / 1000),
      };
    }
  }

  async reset(key) {
    return this.limiter.delete(key);
  }

  async get(key) {
    return this.limiter.get(key);
  }
}

/**
 * Rate limit by custom criteria (e.g., endpoint, method, user role)
 */
const createCustomRateLimiter = (keyGenerator, optionsGenerator) => {
  return async (req, res, next) => {
    try {
      const key = await keyGenerator(req);
      const options = await optionsGenerator(req);
      
      const limiterName = `custom_${key}`;
      const limiter = rateLimiterFactory.getLimiter(limiterName, options);
      
      await limiter.consume(key);
      next();
    } catch (rateLimiterRes) {
      const retryAfter = Math.round(rateLimiterRes.msBeforeNext / 1000) || 60;
      res.set('Retry-After', retryAfter);
      return next(new AppError('Rate limit exceeded', 429));
    }
  };
};

/**
 * Progressive rate limiting - increases limits for good behavior
 */
class ProgressiveRateLimiter {
  constructor(baseLimiter, options = {}) {
    this.baseLimiter = baseLimiter;
    this.options = {
      goodBehaviorPoints: 1,
      maxMultiplier: 3,
      decayDuration: 86400, // 24 hours
      ...options,
    };
    this.reputationStore = new Map();
  }

  async consume(key, points = 1) {
    const reputation = this.getReputation(key);
    const multiplier = Math.min(1 + reputation * 0.1, this.options.maxMultiplier);
    
    const adjustedLimiter = {
      ...this.baseLimiter,
      points: Math.floor(this.baseLimiter.points * multiplier),
    };

    const limiter = rateLimiterFactory.getLimiter(`progressive_${key}`, adjustedLimiter);
    
    try {
      await limiter.consume(key, points);
      this.improveReputation(key);
      return { allowed: true, multiplier };
    } catch (error) {
      this.degradeReputation(key);
      throw error;
    }
  }

  getReputation(key) {
    const data = this.reputationStore.get(key);
    if (!data) return 0;
    
    const age = Date.now() - data.lastUpdate;
    if (age > this.options.decayDuration * 1000) {
      this.reputationStore.delete(key);
      return 0;
    }
    
    return data.score;
  }

  improveReputation(key) {
    const current = this.reputationStore.get(key) || { score: 0, lastUpdate: Date.now() };
    current.score = Math.min(current.score + this.options.goodBehaviorPoints, 30);
    current.lastUpdate = Date.now();
    this.reputationStore.set(key, current);
  }

  degradeReputation(key) {
    const current = this.reputationStore.get(key) || { score: 0, lastUpdate: Date.now() };
    current.score = Math.max(current.score - this.options.goodBehaviorPoints * 2, -10);
    current.lastUpdate = Date.now();
    this.reputationStore.set(key, current);
  }
}

/**
 * Cleanup function to remove expired rate limit entries
 */
const cleanupExpiredEntries = async () => {
  try {
    const limiters = Array.from(rateLimiterFactory.limiters.values());
    for (const limiter of limiters) {
      if (limiter instanceof RateLimiterRedis) {
        // Redis handles expiration automatically
        continue;
      }
      // For memory-based limiters, we could implement manual cleanup if needed
    }
  } catch (error) {
    logger.error('Rate limiter cleanup error:', error);
  }
};

// Schedule cleanup every hour
setInterval(cleanupExpiredEntries, 3600000);

module.exports = {
  rateLimiterFactory,
  rateLimiters,
  createRateLimitMiddleware,
  createDynamicRateLimiter,
  createSlidingWindowLimiter,
  createCustomRateLimiter,
  DistributedRateLimiter,
  ProgressiveRateLimiter,
  
  // Pre-configured middleware
  limitAuthEndpoints: createRateLimitMiddleware('auth_login', rateLimiters.auth.login),
  limitApiEndpoints: createRateLimitMiddleware('api_general', rateLimiters.api.general),
  limitFileUploads: createRateLimitMiddleware('upload_general', rateLimiters.upload.general),
  limitRecruitmentApi: createRateLimitMiddleware('recruitment_api', rateLimiters.recruitment.jobSearch),
};