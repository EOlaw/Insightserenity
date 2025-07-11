/**
 * @file Admin Rate Limiting Middleware
 * @description Advanced rate limiting for administrative operations with adaptive thresholds
 * @version 1.0.0
 */

const crypto = require('crypto');
const { RateLimitError, AppError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../../audit/services/audit-service');
const AdminAuditLogger = require('./admin-audit-logging');
const config = require('../../../config/config');
const { CacheService } = require('../../../services/cache-service');

/**
 * Admin Rate Limiter Class
 * @class AdminRateLimiter
 */
class AdminRateLimiter {
  /**
   * Initialize rate limiting configurations
   */
  static initialize() {
    this.cache = new CacheService('admin:ratelimit');
    
    // Default rate limits by operation type
    this.defaultLimits = {
      // Authentication operations
      login: { windowMs: 900000, max: 5, blockDuration: 3600000 },
      mfa: { windowMs: 300000, max: 3, blockDuration: 1800000 },
      passwordReset: { windowMs: 3600000, max: 3, blockDuration: 7200000 },
      
      // Read operations
      read: { windowMs: 60000, max: 100, blockDuration: 300000 },
      list: { windowMs: 60000, max: 50, blockDuration: 300000 },
      export: { windowMs: 3600000, max: 10, blockDuration: 3600000 },
      
      // Write operations
      create: { windowMs: 60000, max: 20, blockDuration: 600000 },
      update: { windowMs: 60000, max: 30, blockDuration: 600000 },
      delete: { windowMs: 60000, max: 10, blockDuration: 1800000 },
      
      // Bulk operations
      bulkCreate: { windowMs: 3600000, max: 5, blockDuration: 7200000 },
      bulkUpdate: { windowMs: 3600000, max: 5, blockDuration: 7200000 },
      bulkDelete: { windowMs: 86400000, max: 2, blockDuration: 86400000 },
      
      // System operations
      systemConfig: { windowMs: 3600000, max: 10, blockDuration: 3600000 },
      maintenance: { windowMs: 86400000, max: 3, blockDuration: 86400000 },
      emergency: { windowMs: 3600000, max: 1, blockDuration: 7200000 },
      
      // Default fallback
      default: { windowMs: 60000, max: 60, blockDuration: 600000 }
    };
    
    // Role-based multipliers
    this.roleMultipliers = {
      super_admin: 2.0,
      platform_admin: 1.5,
      organization_admin: 1.2,
      security_admin: 1.3,
      admin: 1.0
    };
    
    // Adaptive thresholds
    this.adaptiveConfig = {
      enabled: true,
      increaseThreshold: 0.8, // Increase limit at 80% usage
      decreaseThreshold: 0.3, // Decrease limit at 30% usage
      adjustmentFactor: 0.2,   // Adjust by 20%
      minLimit: 5,
      maxLimit: 1000
    };
    
    // Track usage patterns
    this.usagePatterns = new Map();
    this.blockedEntities = new Map();
  }

  /**
   * Create rate limiter middleware
   * @param {string|Object} options - Operation type or options
   * @returns {Function} Express middleware
   */
  static limit(options = {}) {
    // Handle string parameter for operation type
    if (typeof options === 'string') {
      options = { operation: options };
    }
    
    const {
      operation = 'default',
      keyGenerator = this.defaultKeyGenerator,
      skipSuccessfulRequests = false,
      skipFailedRequests = false,
      customLimits = {},
      bypassRoles = [],
      enableAdaptive = true
    } = options;
    
    return async (req, res, next) => {
      try {
        // Generate rate limit key
        const key = keyGenerator(req);
        
        // Check if user role bypasses rate limiting
        if (req.user && bypassRoles.includes(req.user.role?.primary)) {
          logger.debug('Admin rate limit bypassed', {
            userId: req.user._id,
            role: req.user.role?.primary,
            operation
          });
          return next();
        }
        
        // Check if entity is blocked
        if (this.isBlocked(key)) {
          const blockInfo = this.blockedEntities.get(key);
          throw new RateLimitError(
            'Too many requests. Access temporarily blocked.',
            429,
            { retryAfter: Math.ceil((blockInfo.unblockAt - Date.now()) / 1000) }
          );
        }
        
        // Get rate limit configuration
        const limits = this.getRateLimits(operation, req.user, customLimits);
        
        // Get current usage
        const usage = await this.getUsage(key, limits.windowMs);
        
        // Check if limit exceeded
        if (usage.count >= limits.max) {
          await this.handleLimitExceeded(key, operation, limits, req);
          throw new RateLimitError(
            `Rate limit exceeded for ${operation} operations`,
            429,
            { 
              limit: limits.max,
              window: limits.windowMs / 1000,
              retryAfter: Math.ceil((usage.resetAt - Date.now()) / 1000)
            }
          );
        }
        
        // Track request
        const shouldTrack = () => {
          if (skipSuccessfulRequests || skipFailedRequests) {
            const originalSend = res.send;
            const originalJson = res.json;
            
            res.send = function(data) {
              const success = res.statusCode >= 200 && res.statusCode < 400;
              if (!((success && skipSuccessfulRequests) || (!success && skipFailedRequests))) {
                AdminRateLimiter.incrementUsage(key, limits.windowMs, operation);
              }
              return originalSend.apply(res, arguments);
            };
            
            res.json = function(data) {
              const success = res.statusCode >= 200 && res.statusCode < 400;
              if (!((success && skipSuccessfulRequests) || (!success && skipFailedRequests))) {
                AdminRateLimiter.incrementUsage(key, limits.windowMs, operation);
              }
              return originalJson.apply(res, arguments);
            };
          } else {
            await this.incrementUsage(key, limits.windowMs, operation);
          }
        };
        
        shouldTrack();
        
        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', limits.max);
        res.setHeader('X-RateLimit-Remaining', Math.max(0, limits.max - usage.count - 1));
        res.setHeader('X-RateLimit-Reset', new Date(usage.resetAt).toISOString());
        res.setHeader('X-RateLimit-Window', `${limits.windowMs / 1000}s`);
        
        // Apply adaptive rate limiting
        if (enableAdaptive && this.adaptiveConfig.enabled) {
          await this.updateAdaptiveThresholds(key, operation, usage, limits);
        }
        
        // Set rate limit info in request
        req.rateLimit = {
          key,
          operation,
          limit: limits.max,
          remaining: Math.max(0, limits.max - usage.count - 1),
          resetAt: usage.resetAt,
          usage: usage.count
        };
        
        next();
      } catch (error) {
        if (error instanceof RateLimitError) {
          // Log rate limit violation
          await AdminAuditLogger.logAdminEvent({
            eventType: 'admin_rate_limit_exceeded',
            userId: req.user?._id,
            targetType: 'rate_limit',
            operation,
            metadata: {
              key: options.keyGenerator ? 'custom' : this.defaultKeyGenerator(req),
              endpoint: req.originalUrl,
              method: req.method
            }
          });
        }
        next(error);
      }
    };
  }

  /**
   * Default key generator
   * @param {Object} req - Express request
   * @returns {string} Rate limit key
   */
  static defaultKeyGenerator(req) {
    if (req.user) {
      return `user:${req.user._id}`;
    }
    return `ip:${req.ip}`;
  }

  /**
   * Get rate limits for operation
   * @param {string} operation - Operation type
   * @param {Object} user - User object
   * @param {Object} customLimits - Custom limits
   * @returns {Object} Rate limits
   */
  static getRateLimits(operation, user, customLimits = {}) {
    // Start with default limits
    let limits = { ...this.defaultLimits[operation] || this.defaultLimits.default };
    
    // Apply custom limits
    if (customLimits[operation]) {
      limits = { ...limits, ...customLimits[operation] };
    }
    
    // Apply role-based multipliers
    if (user?.role?.primary) {
      const multiplier = this.roleMultipliers[user.role.primary] || 1.0;
      limits.max = Math.ceil(limits.max * multiplier);
    }
    
    // Check for adaptive adjustments
    const adaptiveKey = `adaptive:${operation}`;
    const adaptiveAdjustment = this.usagePatterns.get(adaptiveKey);
    if (adaptiveAdjustment) {
      limits.max = Math.max(
        this.adaptiveConfig.minLimit,
        Math.min(this.adaptiveConfig.maxLimit, adaptiveAdjustment.adjustedLimit)
      );
    }
    
    return limits;
  }

  /**
   * Get current usage for key
   * @param {string} key - Rate limit key
   * @param {number} windowMs - Window in milliseconds
   * @returns {Object} Usage data
   */
  static async getUsage(key, windowMs) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    // Get usage data from cache
    const cacheKey = `usage:${key}`;
    let usage = await this.cache.get(cacheKey);
    
    if (!usage) {
      usage = {
        requests: [],
        count: 0,
        firstRequest: now,
        resetAt: now + windowMs
      };
    }
    
    // Filter requests within window
    usage.requests = usage.requests.filter(timestamp => timestamp > windowStart);
    usage.count = usage.requests.length;
    usage.resetAt = usage.requests.length > 0 
      ? usage.requests[0] + windowMs 
      : now + windowMs;
    
    return usage;
  }

  /**
   * Increment usage counter
   * @param {string} key - Rate limit key
   * @param {number} windowMs - Window in milliseconds
   * @param {string} operation - Operation type
   */
  static async incrementUsage(key, windowMs, operation) {
    const now = Date.now();
    const cacheKey = `usage:${key}`;
    
    // Get current usage
    let usage = await this.cache.get(cacheKey) || {
      requests: [],
      count: 0,
      firstRequest: now,
      operations: {}
    };
    
    // Add new request
    usage.requests.push(now);
    usage.count = usage.requests.length;
    usage.lastRequest = now;
    
    // Track operations
    usage.operations[operation] = (usage.operations[operation] || 0) + 1;
    
    // Save to cache with TTL
    await this.cache.set(cacheKey, usage, windowMs / 1000);
    
    // Update usage patterns
    this.updateUsagePattern(key, operation, usage);
  }

  /**
   * Check if entity is blocked
   * @param {string} key - Entity key
   * @returns {boolean} Is blocked
   */
  static isBlocked(key) {
    const blockInfo = this.blockedEntities.get(key);
    
    if (!blockInfo) return false;
    
    // Check if block has expired
    if (blockInfo.unblockAt < Date.now()) {
      this.blockedEntities.delete(key);
      return false;
    }
    
    return true;
  }

  /**
   * Block entity
   * @param {string} key - Entity key
   * @param {number} duration - Block duration
   * @param {string} reason - Block reason
   */
  static async blockEntity(key, duration, reason) {
    const blockInfo = {
      blockedAt: Date.now(),
      unblockAt: Date.now() + duration,
      reason,
      violations: 1
    };
    
    // Check for existing block
    const existing = this.blockedEntities.get(key);
    if (existing) {
      blockInfo.violations = existing.violations + 1;
      // Extend block duration for repeat offenders
      blockInfo.unblockAt = Date.now() + (duration * blockInfo.violations);
    }
    
    this.blockedEntities.set(key, blockInfo);
    
    // Schedule unblock
    setTimeout(() => {
      this.blockedEntities.delete(key);
    }, blockInfo.unblockAt - Date.now());
    
    // Log block event
    await AuditService.log({
      type: 'admin_rate_limit_block',
      action: 'block',
      category: 'security',
      result: 'blocked',
      severity: 'high',
      metadata: {
        key,
        reason,
        duration,
        violations: blockInfo.violations,
        unblockAt: new Date(blockInfo.unblockAt)
      }
    });
  }

  /**
   * Handle rate limit exceeded
   * @param {string} key - Rate limit key
   * @param {string} operation - Operation type
   * @param {Object} limits - Rate limits
   * @param {Object} req - Express request
   */
  static async handleLimitExceeded(key, operation, limits, req) {
    // Check if should block
    const violationKey = `violations:${key}`;
    const violations = (this.usagePatterns.get(violationKey) || 0) + 1;
    this.usagePatterns.set(violationKey, violations);
    
    if (violations >= 3) {
      await this.blockEntity(key, limits.blockDuration, `Repeated rate limit violations for ${operation}`);
    }
    
    // Log violation
    await AdminAuditLogger.logAdminEvent({
      eventType: 'admin_rate_limit_violation',
      userId: req.user?._id,
      targetType: 'rate_limit',
      operation,
      metadata: {
        key,
        limit: limits.max,
        window: limits.windowMs,
        violations,
        endpoint: req.originalUrl,
        blocked: violations >= 3
      }
    });
  }

  /**
   * Update usage patterns
   * @param {string} key - Entity key
   * @param {string} operation - Operation type
   * @param {Object} usage - Usage data
   */
  static updateUsagePattern(key, operation, usage) {
    const patternKey = `pattern:${key}:${operation}`;
    const pattern = this.usagePatterns.get(patternKey) || {
      totalRequests: 0,
      windows: [],
      averageUsage: 0
    };
    
    pattern.totalRequests++;
    pattern.lastUpdate = Date.now();
    
    // Track window usage
    pattern.windows.push({
      timestamp: Date.now(),
      count: usage.count,
      operations: usage.operations
    });
    
    // Keep only recent windows (last 24 hours)
    const dayAgo = Date.now() - 86400000;
    pattern.windows = pattern.windows.filter(w => w.timestamp > dayAgo);
    
    // Calculate average usage
    if (pattern.windows.length > 0) {
      pattern.averageUsage = pattern.windows.reduce((sum, w) => sum + w.count, 0) / pattern.windows.length;
    }
    
    this.usagePatterns.set(patternKey, pattern);
  }

  /**
   * Update adaptive thresholds
   * @param {string} key - Entity key
   * @param {string} operation - Operation type
   * @param {Object} usage - Current usage
   * @param {Object} limits - Current limits
   */
  static async updateAdaptiveThresholds(key, operation, usage, limits) {
    const adaptiveKey = `adaptive:${operation}`;
    const adaptive = this.usagePatterns.get(adaptiveKey) || {
      adjustedLimit: limits.max,
      adjustmentHistory: []
    };
    
    const usageRatio = usage.count / limits.max;
    
    // Check if adjustment needed
    if (usageRatio >= this.adaptiveConfig.increaseThreshold) {
      // Increase limit
      const newLimit = Math.min(
        this.adaptiveConfig.maxLimit,
        Math.ceil(limits.max * (1 + this.adaptiveConfig.adjustmentFactor))
      );
      
      if (newLimit !== adaptive.adjustedLimit) {
        adaptive.adjustedLimit = newLimit;
        adaptive.adjustmentHistory.push({
          timestamp: Date.now(),
          action: 'increase',
          from: limits.max,
          to: newLimit,
          usageRatio
        });
        
        logger.info('Admin rate limit increased adaptively', {
          operation,
          from: limits.max,
          to: newLimit,
          usageRatio
        });
      }
    } else if (usageRatio <= this.adaptiveConfig.decreaseThreshold && adaptive.adjustmentHistory.length > 0) {
      // Decrease limit
      const newLimit = Math.max(
        this.adaptiveConfig.minLimit,
        Math.ceil(limits.max * (1 - this.adaptiveConfig.adjustmentFactor))
      );
      
      if (newLimit !== adaptive.adjustedLimit) {
        adaptive.adjustedLimit = newLimit;
        adaptive.adjustmentHistory.push({
          timestamp: Date.now(),
          action: 'decrease',
          from: limits.max,
          to: newLimit,
          usageRatio
        });
        
        logger.info('Admin rate limit decreased adaptively', {
          operation,
          from: limits.max,
          to: newLimit,
          usageRatio
        });
      }
    }
    
    // Keep only recent history
    adaptive.adjustmentHistory = adaptive.adjustmentHistory.slice(-10);
    
    this.usagePatterns.set(adaptiveKey, adaptive);
  }

  /**
   * Create custom rate limiter for specific scenarios
   * @param {Object} config - Rate limiter configuration
   * @returns {Function} Express middleware
   */
  static custom(config) {
    const {
      windowMs,
      max,
      message = 'Too many requests',
      keyGenerator,
      onLimitReached,
      skipOptions = {}
    } = config;
    
    return async (req, res, next) => {
      try {
        const key = keyGenerator ? keyGenerator(req) : this.defaultKeyGenerator(req);
        const usage = await this.getUsage(key, windowMs);
        
        if (usage.count >= max) {
          if (onLimitReached) {
            await onLimitReached(req, res, { key, usage, limit: max });
          }
          
          throw new RateLimitError(message, 429, {
            limit: max,
            window: windowMs / 1000,
            retryAfter: Math.ceil((usage.resetAt - Date.now()) / 1000)
          });
        }
        
        // Track request based on skip options
        const shouldSkip = () => {
          if (skipOptions.condition) {
            return skipOptions.condition(req, res);
          }
          return false;
        };
        
        if (!shouldSkip()) {
          await this.incrementUsage(key, windowMs, 'custom');
        }
        
        next();
      } catch (error) {
        next(error);
      }
    };
  }

  /**
   * Reset rate limits for entity
   * @param {string} key - Entity key
   */
  static async reset(key) {
    const cacheKey = `usage:${key}`;
    await this.cache.delete(cacheKey);
    
    // Remove from blocked entities
    this.blockedEntities.delete(key);
    
    // Clear violations
    const violationKey = `violations:${key}`;
    this.usagePatterns.delete(violationKey);
    
    logger.info('Admin rate limits reset', { key });
  }

  /**
   * Get rate limit statistics
   * @returns {Object} Statistics
   */
  static async getStatistics() {
    const stats = {
      blockedEntities: this.blockedEntities.size,
      activePatterns: this.usagePatterns.size,
      adaptiveAdjustments: [],
      topOperations: {},
      recentViolations: []
    };
    
    // Collect adaptive adjustments
    for (const [key, value] of this.usagePatterns.entries()) {
      if (key.startsWith('adaptive:')) {
        stats.adaptiveAdjustments.push({
          operation: key.replace('adaptive:', ''),
          currentLimit: value.adjustedLimit,
          adjustmentCount: value.adjustmentHistory?.length || 0
        });
      }
    }
    
    // Collect top operations
    for (const [key, value] of this.usagePatterns.entries()) {
      if (key.startsWith('pattern:')) {
        const operation = key.split(':')[2];
        stats.topOperations[operation] = (stats.topOperations[operation] || 0) + value.totalRequests;
      }
    }
    
    return stats;
  }

  /**
   * Clean up old data
   */
  static cleanup() {
    const now = Date.now();
    const maxAge = 86400000; // 24 hours
    
    // Clean usage patterns
    for (const [key, value] of this.usagePatterns.entries()) {
      if (value.lastUpdate && (now - value.lastUpdate) > maxAge) {
        this.usagePatterns.delete(key);
      }
    }
    
    // Clean expired blocks
    for (const [key, value] of this.blockedEntities.entries()) {
      if (value.unblockAt < now) {
        this.blockedEntities.delete(key);
      }
    }
  }
}

// Initialize on module load
AdminRateLimiter.initialize();

// Schedule periodic cleanup
setInterval(() => {
  AdminRateLimiter.cleanup();
}, 3600000); // Every hour

module.exports = AdminRateLimiter;