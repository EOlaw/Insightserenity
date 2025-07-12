/**
 * @file Admin Cache Service
 * @description Specialized caching service for administrative operations with performance optimization and cache management
 * @version 1.0.0
 */

const Redis = require('redis');
const crypto = require('crypto');

const AdminBaseService = require('./admin-base-service');
const config = require('../../../shared/config/config');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { CacheService } = require('../../../shared/services/cache-service');

// Import admin models
const AdminActionLog = require('../models/admin-action-log-model');
const AdminSession = require('../models/admin-session-model');
const AdminPreference = require('../models/admin-preference-model');
const AdminNotification = require('../models/admin-notification-model');

/**
 * Admin Cache Service Class
 * Provides specialized caching functionality for administrative operations
 */
class AdminCacheService extends AdminBaseService {
  constructor() {
    super('AdminCacheService');
    
    this.cacheConfig = {
      redis: {
        host: config.redis?.host || 'localhost',
        port: config.redis?.port || 6379,
        password: config.redis?.password,
        db: config.redis?.adminDb || 2,
        keyPrefix: 'admin:',
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: 3
      },
      defaultTTL: config.cache?.defaultTTL || 3600, // 1 hour
      maxMemoryPolicy: 'allkeys-lru',
      compression: config.cache?.compression || true,
      encryption: config.cache?.encryption || false
    };
    
    this.cacheStrategies = {
      WRITE_THROUGH: 'write_through',
      WRITE_BEHIND: 'write_behind',
      CACHE_ASIDE: 'cache_aside',
      REFRESH_AHEAD: 'refresh_ahead'
    };
    
    this.cacheNamespaces = {
      SESSIONS: 'sessions',
      PERMISSIONS: 'permissions',
      PREFERENCES: 'preferences',
      NOTIFICATIONS: 'notifications',
      ANALYTICS: 'analytics',
      CONFIGURATIONS: 'config',
      RATE_LIMITS: 'rate_limits',
      AUDIT_LOGS: 'audit_logs'
    };
    
    this.initializeCacheService();
  }
  
  /**
   * Initialize cache service
   * @private
   */
  async initializeCacheService() {
    try {
      // Initialize Redis client
      await this.initializeRedisClient();
      
      // Initialize cache namespaces
      this.initializeCacheNamespaces();
      
      // Set up cache monitoring
      this.setupCacheMonitoring();
      
      // Initialize cache warming
      await this.warmupCache();
      
      logger.info('Admin cache service initialized', {
        redis: `${this.cacheConfig.redis.host}:${this.cacheConfig.redis.port}`,
        namespaces: Object.keys(this.cacheNamespaces).length
      });
      
    } catch (error) {
      logger.error('Failed to initialize cache service', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Initialize Redis client
   * @private
   */
  async initializeRedisClient() {
    this.redisClient = Redis.createClient(this.cacheConfig.redis);
    
    this.redisClient.on('error', (error) => {
      logger.error('Redis client error', { error: error.message });
      this.emit('cache:error', error);
    });
    
    this.redisClient.on('connect', () => {
      logger.info('Redis client connected');
      this.emit('cache:connected');
    });
    
    this.redisClient.on('disconnect', () => {
      logger.warn('Redis client disconnected');
      this.emit('cache:disconnected');
    });
    
    await this.redisClient.connect();
  }
  
  /**
   * Initialize cache namespaces
   * @private
   */
  initializeCacheNamespaces() {
    this.caches = {};
    
    for (const [name, namespace] of Object.entries(this.cacheNamespaces)) {
      this.caches[name] = new CacheService(namespace, {
        redis: this.redisClient,
        defaultTTL: this.cacheConfig.defaultTTL,
        compression: this.cacheConfig.compression,
        encryption: this.cacheConfig.encryption
      });
    }
  }
  
  /**
   * Cache admin session data
   * @param {Object} context - Operation context
   * @param {string} sessionId - Session ID
   * @param {Object} sessionData - Session data to cache
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} Success status
   */
  async cacheSession(context, sessionId, sessionData, ttl = null) {
    return this.executeOperation('cache.session.set', async () => {
      const cacheKey = this.generateSessionKey(sessionId);
      const cacheTTL = ttl || this.getSessionCacheTTL(sessionData);
      
      // Prepare session data for caching
      const cacheData = this.prepareCacheData(sessionData, {
        sanitize: true,
        compress: true
      });
      
      await this.caches.SESSIONS.set(cacheKey, cacheData, { ttl: cacheTTL });
      
      // Also cache user session list
      await this.updateUserSessionCache(sessionData.userId, sessionId, 'add');
      
      logger.debug('Session cached successfully', {
        sessionId,
        userId: sessionData.userId,
        ttl: cacheTTL
      });
      
      return true;
      
    }, context);
  }
  
  /**
   * Get cached session data
   * @param {Object} context - Operation context
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object|null>} Cached session data
   */
  async getCachedSession(context, sessionId) {
    return this.executeOperation('cache.session.get', async () => {
      const cacheKey = this.generateSessionKey(sessionId);
      const cachedData = await this.caches.SESSIONS.get(cacheKey);
      
      if (cachedData) {
        // Validate cached session data
        if (this.isSessionCacheValid(cachedData)) {
          logger.debug('Session cache hit', { sessionId });
          return this.prepareCacheData(cachedData, { decompress: true });
        } else {
          // Invalid cache, remove it
          await this.invalidateSession(context, sessionId);
          logger.debug('Invalid session cache removed', { sessionId });
        }
      }
      
      logger.debug('Session cache miss', { sessionId });
      return null;
      
    }, context);
  }
  
  /**
   * Cache user permissions
   * @param {Object} context - Operation context
   * @param {string} userId - User ID
   * @param {Array} permissions - User permissions
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} Success status
   */
  async cacheUserPermissions(context, userId, permissions, ttl = 1800) {
    return this.executeOperation('cache.permissions.set', async () => {
      const cacheKey = this.generatePermissionsKey(userId);
      
      const cacheData = {
        userId,
        permissions,
        cachedAt: new Date(),
        expiresAt: new Date(Date.now() + (ttl * 1000))
      };
      
      await this.caches.PERMISSIONS.set(cacheKey, cacheData, { ttl });
      
      logger.debug('User permissions cached', {
        userId,
        permissionCount: permissions.length,
        ttl
      });
      
      return true;
      
    }, context);
  }
  
  /**
   * Get cached user permissions
   * @param {Object} context - Operation context
   * @param {string} userId - User ID
   * @returns {Promise<Array|null>} Cached permissions
   */
  async getCachedUserPermissions(context, userId) {
    return this.executeOperation('cache.permissions.get', async () => {
      const cacheKey = this.generatePermissionsKey(userId);
      const cachedData = await this.caches.PERMISSIONS.get(cacheKey);
      
      if (cachedData && new Date() < new Date(cachedData.expiresAt)) {
        logger.debug('Permissions cache hit', { userId });
        return cachedData.permissions;
      }
      
      if (cachedData) {
        // Expired cache, remove it
        await this.caches.PERMISSIONS.delete(cacheKey);
        logger.debug('Expired permissions cache removed', { userId });
      }
      
      logger.debug('Permissions cache miss', { userId });
      return null;
      
    }, context);
  }
  
  /**
   * Cache user preferences
   * @param {Object} context - Operation context
   * @param {string} userId - User ID
   * @param {Object} preferences - User preferences
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} Success status
   */
  async cacheUserPreferences(context, userId, preferences, ttl = 3600) {
    return this.executeOperation('cache.preferences.set', async () => {
      const cacheKey = this.generatePreferencesKey(userId);
      
      await this.caches.PREFERENCES.set(cacheKey, preferences, { ttl });
      
      logger.debug('User preferences cached', { userId, ttl });
      
      return true;
      
    }, context);
  }
  
  /**
   * Get cached user preferences
   * @param {Object} context - Operation context
   * @param {string} userId - User ID
   * @returns {Promise<Object|null>} Cached preferences
   */
  async getCachedUserPreferences(context, userId) {
    return this.executeOperation('cache.preferences.get', async () => {
      const cacheKey = this.generatePreferencesKey(userId);
      const preferences = await this.caches.PREFERENCES.get(cacheKey);
      
      if (preferences) {
        logger.debug('Preferences cache hit', { userId });
      } else {
        logger.debug('Preferences cache miss', { userId });
      }
      
      return preferences;
      
    }, context);
  }
  
  /**
   * Cache analytics data
   * @param {Object} context - Operation context
   * @param {string} analyticsKey - Analytics identifier
   * @param {Object} data - Analytics data
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} Success status
   */
  async cacheAnalytics(context, analyticsKey, data, ttl = 900) {
    return this.executeOperation('cache.analytics.set', async () => {
      const cacheKey = this.generateAnalyticsKey(analyticsKey);
      
      const cacheData = {
        data,
        generatedAt: new Date(),
        validUntil: new Date(Date.now() + (ttl * 1000)),
        metadata: {
          dataPoints: Array.isArray(data) ? data.length : Object.keys(data).length,
          size: JSON.stringify(data).length
        }
      };
      
      await this.caches.ANALYTICS.set(cacheKey, cacheData, { ttl });
      
      logger.debug('Analytics data cached', {
        key: analyticsKey,
        dataPoints: cacheData.metadata.dataPoints,
        ttl
      });
      
      return true;
      
    }, context);
  }
  
  /**
   * Get cached analytics data
   * @param {Object} context - Operation context
   * @param {string} analyticsKey - Analytics identifier
   * @returns {Promise<Object|null>} Cached analytics data
   */
  async getCachedAnalytics(context, analyticsKey) {
    return this.executeOperation('cache.analytics.get', async () => {
      const cacheKey = this.generateAnalyticsKey(analyticsKey);
      const cachedData = await this.caches.ANALYTICS.get(cacheKey);
      
      if (cachedData && new Date() < new Date(cachedData.validUntil)) {
        logger.debug('Analytics cache hit', { key: analyticsKey });
        return cachedData.data;
      }
      
      logger.debug('Analytics cache miss', { key: analyticsKey });
      return null;
      
    }, context);
  }
  
  /**
   * Implement rate limiting using cache
   * @param {Object} context - Operation context
   * @param {string} identifier - Rate limit identifier
   * @param {Object} limits - Rate limit configuration
   * @returns {Promise<Object>} Rate limit status
   */
  async checkRateLimit(context, identifier, limits) {
    return this.executeOperation('cache.rate_limit.check', async () => {
      const { max, windowMs, blockDuration = 0 } = limits;
      const cacheKey = this.generateRateLimitKey(identifier);
      const blockKey = `${cacheKey}:blocked`;
      
      // Check if identifier is currently blocked
      const isBlocked = await this.caches.RATE_LIMITS.get(blockKey);
      if (isBlocked) {
        return {
          allowed: false,
          blocked: true,
          remaining: 0,
          resetTime: isBlocked.unblockAt,
          retryAfter: Math.ceil((new Date(isBlocked.unblockAt) - new Date()) / 1000)
        };
      }
      
      // Get current rate limit data
      let rateLimitData = await this.caches.RATE_LIMITS.get(cacheKey);
      
      if (!rateLimitData) {
        rateLimitData = {
          count: 0,
          firstRequest: new Date(),
          windowEnd: new Date(Date.now() + windowMs)
        };
      }
      
      // Check if window has expired
      if (new Date() > new Date(rateLimitData.windowEnd)) {
        rateLimitData = {
          count: 0,
          firstRequest: new Date(),
          windowEnd: new Date(Date.now() + windowMs)
        };
      }
      
      // Increment counter
      rateLimitData.count++;
      
      // Check if limit exceeded
      if (rateLimitData.count > max) {
        // Block if block duration is specified
        if (blockDuration > 0) {
          const blockData = {
            blockedAt: new Date(),
            unblockAt: new Date(Date.now() + blockDuration),
            reason: 'Rate limit exceeded'
          };
          
          await this.caches.RATE_LIMITS.set(blockKey, blockData, {
            ttl: Math.ceil(blockDuration / 1000)
          });
        }
        
        return {
          allowed: false,
          blocked: blockDuration > 0,
          remaining: 0,
          resetTime: rateLimitData.windowEnd,
          retryAfter: blockDuration > 0 ? Math.ceil(blockDuration / 1000) : 
                     Math.ceil((new Date(rateLimitData.windowEnd) - new Date()) / 1000)
        };
      }
      
      // Update rate limit data
      await this.caches.RATE_LIMITS.set(cacheKey, rateLimitData, {
        ttl: Math.ceil(windowMs / 1000)
      });
      
      return {
        allowed: true,
        blocked: false,
        remaining: max - rateLimitData.count,
        resetTime: rateLimitData.windowEnd,
        retryAfter: 0
      };
      
    }, context);
  }
  
  /**
   * Cache audit log aggregations
   * @param {Object} context - Operation context
   * @param {string} aggregationKey - Aggregation identifier
   * @param {Object} aggregatedData - Aggregated audit data
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} Success status
   */
  async cacheAuditLogAggregation(context, aggregationKey, aggregatedData, ttl = 1800) {
    return this.executeOperation('cache.audit_logs.set', async () => {
      const cacheKey = this.generateAuditLogKey(aggregationKey);
      
      const cacheData = {
        aggregation: aggregatedData,
        generatedAt: new Date(),
        recordCount: aggregatedData.totalRecords || 0,
        timeRange: aggregatedData.timeRange
      };
      
      await this.caches.AUDIT_LOGS.set(cacheKey, cacheData, { ttl });
      
      logger.debug('Audit log aggregation cached', {
        key: aggregationKey,
        recordCount: cacheData.recordCount,
        ttl
      });
      
      return true;
      
    }, context);
  }
  
  /**
   * Invalidate session cache
   * @param {Object} context - Operation context
   * @param {string} sessionId - Session ID
   * @returns {Promise<boolean>} Success status
   */
  async invalidateSession(context, sessionId) {
    return this.executeOperation('cache.session.invalidate', async () => {
      const cacheKey = this.generateSessionKey(sessionId);
      
      // Get session data to update user session list
      const sessionData = await this.caches.SESSIONS.get(cacheKey);
      
      // Remove session cache
      await this.caches.SESSIONS.delete(cacheKey);
      
      // Update user session cache
      if (sessionData?.userId) {
        await this.updateUserSessionCache(sessionData.userId, sessionId, 'remove');
      }
      
      logger.debug('Session cache invalidated', { sessionId });
      
      return true;
      
    }, context);
  }
  
  /**
   * Invalidate all caches for a user
   * @param {Object} context - Operation context
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} Success status
   */
  async invalidateUserCaches(context, userId) {
    return this.executeOperation('cache.user.invalidate_all', async () => {
      const keysToDelete = [
        this.generatePermissionsKey(userId),
        this.generatePreferencesKey(userId),
        this.generateUserSessionListKey(userId)
      ];
      
      // Delete all user-related caches
      await Promise.all(keysToDelete.map(key => 
        this.deleteFromAllCaches(key)
      ));
      
      // Invalidate all user sessions
      const userSessions = await this.getUserSessionsFromCache(userId);
      if (userSessions) {
        await Promise.all(userSessions.map(sessionId => 
          this.invalidateSession(context, sessionId)
        ));
      }
      
      logger.debug('All user caches invalidated', { userId });
      
      return true;
      
    }, context);
  }
  
  /**
   * Clear all caches
   * @param {Object} context - Operation context
   * @param {Object} options - Clear options
   * @returns {Promise<Object>} Clear results
   */
  async clearAllCaches(context, options = {}) {
    return this.executeOperation('cache.clear_all', async () => {
      const { namespaces = null, confirm = false } = options;
      
      if (!confirm) {
        throw new ValidationError('Cache clear operation requires explicit confirmation');
      }
      
      const results = {
        clearedNamespaces: [],
        errors: [],
        clearedAt: new Date()
      };
      
      const namespacesToClear = namespaces || Object.keys(this.caches);
      
      for (const namespace of namespacesToClear) {
        try {
          if (this.caches[namespace]) {
            await this.caches[namespace].clear();
            results.clearedNamespaces.push(namespace);
            
            logger.info(`Cache namespace cleared: ${namespace}`);
          }
        } catch (error) {
          results.errors.push({
            namespace,
            error: error.message
          });
          
          logger.error(`Failed to clear cache namespace: ${namespace}`, {
            error: error.message
          });
        }
      }
      
      logger.info('Cache clear operation completed', {
        clearedNamespaces: results.clearedNamespaces.length,
        errors: results.errors.length
      });
      
      return results;
      
    }, context);
  }
  
  /**
   * Get cache statistics
   * @param {Object} context - Operation context
   * @returns {Promise<Object>} Cache statistics
   */
  async getCacheStatistics(context) {
    return this.executeOperation('cache.statistics', async () => {
      const stats = {
        namespaces: {},
        overall: {
          totalKeys: 0,
          totalMemory: 0,
          hitRate: 0,
          missRate: 0
        },
        redis: {},
        generatedAt: new Date()
      };
      
      // Get Redis info
      try {
        const redisInfo = await this.redisClient.info();
        stats.redis = this.parseRedisInfo(redisInfo);
      } catch (error) {
        logger.warn('Failed to get Redis info', { error: error.message });
      }
      
      // Get namespace statistics
      for (const [name, cache] of Object.entries(this.caches)) {
        try {
          const namespaceStats = await cache.getStatistics();
          stats.namespaces[name] = namespaceStats;
          
          stats.overall.totalKeys += namespaceStats.keyCount || 0;
          stats.overall.totalMemory += namespaceStats.memoryUsage || 0;
        } catch (error) {
          logger.warn(`Failed to get stats for namespace: ${name}`, {
            error: error.message
          });
        }
      }
      
      return stats;
      
    }, context);
  }
  
  /**
   * Setup cache monitoring
   * @private
   */
  setupCacheMonitoring() {
    // Monitor cache hit/miss ratios
    this.on('cache:hit', (namespace, key) => {
      this.updateCacheMetrics(namespace, 'hit');
    });
    
    this.on('cache:miss', (namespace, key) => {
      this.updateCacheMetrics(namespace, 'miss');
    });
    
    // Monitor cache errors
    this.on('cache:error', (error) => {
      this.updateCacheMetrics('error', 'count');
    });
    
    // Periodic cache health check
    setInterval(() => {
      this.performCacheHealthCheck();
    }, 60000); // Every minute
  }
  
  /**
   * Warmup cache with frequently accessed data
   * @private
   */
  async warmupCache() {
    try {
      // Warmup active sessions
      await this.warmupActiveSessions();
      
      // Warmup frequently accessed preferences
      await this.warmupFrequentPreferences();
      
      logger.info('Cache warmup completed');
      
    } catch (error) {
      logger.warn('Cache warmup failed', { error: error.message });
    }
  }
  
  /**
   * Generate cache keys
   * @private
   */
  generateSessionKey(sessionId) {
    return `session:${sessionId}`;
  }
  
  generatePermissionsKey(userId) {
    return `permissions:${userId}`;
  }
  
  generatePreferencesKey(userId) {
    return `preferences:${userId}`;
  }
  
  generateAnalyticsKey(key) {
    return `analytics:${key}`;
  }
  
  generateRateLimitKey(identifier) {
    return `rate_limit:${identifier}`;
  }
  
  generateAuditLogKey(key) {
    return `audit:${key}`;
  }
  
  generateUserSessionListKey(userId) {
    return `user_sessions:${userId}`;
  }
  
  /**
   * Prepare data for caching
   * @param {*} data - Data to prepare
   * @param {Object} options - Preparation options
   * @returns {*} Prepared data
   * @private
   */
  prepareCacheData(data, options = {}) {
    let prepared = data;
    
    if (options.sanitize) {
      prepared = this.sanitizeForCache(prepared);
    }
    
    if (options.compress && typeof prepared === 'object') {
      prepared = this.compressData(prepared);
    }
    
    if (options.decompress && prepared?.compressed) {
      prepared = this.decompressData(prepared);
    }
    
    return prepared;
  }
  
  /**
   * Get session cache TTL based on session data
   * @param {Object} sessionData - Session data
   * @returns {number} TTL in seconds
   * @private
   */
  getSessionCacheTTL(sessionData) {
    const expiresAt = new Date(sessionData.expiresAt);
    const now = new Date();
    
    if (expiresAt <= now) {
      return 0; // Already expired
    }
    
    return Math.ceil((expiresAt - now) / 1000);
  }
  
  /**
   * Validate cached session data
   * @param {Object} cachedData - Cached session data
   * @returns {boolean} Is valid
   * @private
   */
  isSessionCacheValid(cachedData) {
    if (!cachedData || !cachedData.expiresAt) {
      return false;
    }
    
    return new Date() < new Date(cachedData.expiresAt);
  }
  
  /**
   * Update user session cache
   * @param {string} userId - User ID
   * @param {string} sessionId - Session ID
   * @param {string} action - 'add' or 'remove'
   * @private
   */
  async updateUserSessionCache(userId, sessionId, action) {
    const cacheKey = this.generateUserSessionListKey(userId);
    let sessions = await this.caches.SESSIONS.get(cacheKey) || [];
    
    if (action === 'add' && !sessions.includes(sessionId)) {
      sessions.push(sessionId);
    } else if (action === 'remove') {
      sessions = sessions.filter(id => id !== sessionId);
    }
    
    if (sessions.length > 0) {
      await this.caches.SESSIONS.set(cacheKey, sessions, { ttl: 86400 }); // 24 hours
    } else {
      await this.caches.SESSIONS.delete(cacheKey);
    }
  }
  
  /**
   * Parse Redis info response
   * @param {string} info - Redis info string
   * @returns {Object} Parsed info
   * @private
   */
  parseRedisInfo(info) {
    const parsed = {};
    const sections = info.split('\r\n\r\n');
    
    for (const section of sections) {
      const lines = section.split('\r\n');
      const sectionName = lines[0].replace('# ', '');
      
      if (sectionName && lines.length > 1) {
        parsed[sectionName] = {};
        
        for (let i = 1; i < lines.length; i++) {
          const [key, value] = lines[i].split(':');
          if (key && value !== undefined) {
            parsed[sectionName][key] = isNaN(value) ? value : Number(value);
          }
        }
      }
    }
    
    return parsed;
  }
}

module.exports = AdminCacheService;