// /server/shared/utils/helpers/cache-helper.js

/**
 * @file Cache Helper
 * @description Caching utilities with Redis and in-memory support
 * @version 1.0.0
 */

const crypto = require('crypto');

const Redis = require('ioredis');
const NodeCache = require('node-cache');

const config = require('../../config');
const constants = require('../../config/constants');
const logger = require('../logger');

/**
 * Cache Helper Class
 */
class CacheHelper {
  constructor() {
    this.redis = null;
    this.memoryCache = null;
    this.prefix = config.cache.prefix || 'insightserenity:';
    this.defaultTTL = config.cache.defaultTTL || constants.CACHE_TTL.MEDIUM;
    
    this.initializeCache();
  }
  
  /**
   * Initialize cache clients
   */
  initializeCache() {
    try {
      // Initialize Redis if configured
      if (config.redis.enabled !== false) {
        this.redis = new Redis({
          host: config.redis.host,
          port: config.redis.port,
          password: config.redis.password,
          db: config.redis.db || 0,
          keyPrefix: this.prefix,
          retryStrategy: (times) => {
            const delay = Math.min(times * 50, 2000);
            return delay;
          },
          reconnectOnError: (err) => {
            const targetError = 'READONLY';
            if (err.message.includes(targetError)) {
              return true;
            }
            return false;
          }
        });
        
        this.redis.on('connect', () => {
          logger.info('Redis cache connected');
        });
        
        this.redis.on('error', (error) => {
          logger.error('Redis cache error:', error);
        });
      }
      
      // Initialize in-memory cache as fallback
      this.memoryCache = new NodeCache({
        stdTTL: this.defaultTTL,
        checkperiod: 120,
        useClones: false,
        maxKeys: 10000
      });
      
      this.memoryCache.on('expired', (key, value) => {
        logger.debug(`Memory cache expired: ${key}`);
      });
      
    } catch (error) {
      logger.error('Cache initialization error:', error);
      // Continue with memory cache only
      this.redis = null;
    }
  }
  
  /**
   * Get cache client
   * @returns {Object} Active cache client
   */
  getClient() {
    return this.redis && this.redis.status === 'ready' ? this.redis : this.memoryCache;
  }
  
  /**
   * Generate cache key
   * @param {string} namespace - Cache namespace
   * @param {any} identifier - Unique identifier
   * @returns {string} Cache key
   */
  generateKey(namespace, identifier) {
    if (typeof identifier === 'object') {
      identifier = this.hashObject(identifier);
    }
    return `${namespace}:${identifier}`;
  }
  
  /**
   * Hash object for cache key
   * @param {Object} obj - Object to hash
   * @returns {string} Hash string
   */
  hashObject(obj) {
    const str = JSON.stringify(obj, Object.keys(obj).sort());
    return crypto.createHash('md5').update(str).digest('hex');
  }
  
  /**
   * Get value from cache
   * @param {string} key - Cache key
   * @returns {Promise<any>} Cached value or null
   */
  async get(key) {
    try {
      const client = this.getClient();
      
      if (client === this.redis) {
        const value = await this.redis.get(key);
        return value ? JSON.parse(value) : null;
      } else {
        return this.memoryCache.get(key) || null;
      }
    } catch (error) {
      logger.error(`Cache get error for key ${key}:`, error);
      return null;
    }
  }
  
  /**
   * Set value in cache
   * @param {string} key - Cache key
   * @param {any} value - Value to cache
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} Success status
   */
  async set(key, value, ttl = this.defaultTTL) {
    try {
      const client = this.getClient();
      
      if (client === this.redis) {
        const serialized = JSON.stringify(value);
        if (ttl) {
          await this.redis.setex(key, ttl, serialized);
        } else {
          await this.redis.set(key, serialized);
        }
      } else {
        this.memoryCache.set(key, value, ttl);
      }
      
      return true;
    } catch (error) {
      logger.error(`Cache set error for key ${key}:`, error);
      return false;
    }
  }
  
  /**
   * Delete value from cache
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} Success status
   */
  async del(key) {
    try {
      const client = this.getClient();
      
      if (client === this.redis) {
        await this.redis.del(key);
      } else {
        this.memoryCache.del(key);
      }
      
      return true;
    } catch (error) {
      logger.error(`Cache delete error for key ${key}:`, error);
      return false;
    }
  }
  
  /**
   * Delete multiple keys by pattern
   * @param {string} pattern - Key pattern
   * @returns {Promise<number>} Number of deleted keys
   */
  async delPattern(pattern) {
    try {
      if (this.redis && this.redis.status === 'ready') {
        const keys = await this.redis.keys(`${this.prefix}${pattern}`);
        if (keys.length > 0) {
          // Remove prefix before deletion
          const cleanKeys = keys.map(k => k.replace(this.prefix, ''));
          return await this.redis.del(...cleanKeys);
        }
      } else {
        // Memory cache pattern deletion
        const keys = this.memoryCache.keys();
        let deleted = 0;
        
        keys.forEach(key => {
          if (key.match(pattern)) {
            this.memoryCache.del(key);
            deleted++;
          }
        });
        
        return deleted;
      }
      
      return 0;
    } catch (error) {
      logger.error(`Cache pattern delete error for ${pattern}:`, error);
      return 0;
    }
  }
  
  /**
   * Check if key exists
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} Exists status
   */
  async exists(key) {
    try {
      const client = this.getClient();
      
      if (client === this.redis) {
        return await this.redis.exists(key) === 1;
      } else {
        return this.memoryCache.has(key);
      }
    } catch (error) {
      logger.error(`Cache exists error for key ${key}:`, error);
      return false;
    }
  }
  
  /**
   * Get remaining TTL
   * @param {string} key - Cache key
   * @returns {Promise<number>} TTL in seconds or -1
   */
  async ttl(key) {
    try {
      const client = this.getClient();
      
      if (client === this.redis) {
        return await this.redis.ttl(key);
      } else {
        return this.memoryCache.getTtl(key) || -1;
      }
    } catch (error) {
      logger.error(`Cache TTL error for key ${key}:`, error);
      return -1;
    }
  }
  
  /**
   * Flush all cache
   * @returns {Promise<boolean>} Success status
   */
  async flush() {
    try {
      if (this.redis && this.redis.status === 'ready') {
        await this.redis.flushdb();
      }
      
      this.memoryCache.flushAll();
      
      logger.info('Cache flushed successfully');
      return true;
    } catch (error) {
      logger.error('Cache flush error:', error);
      return false;
    }
  }
  
  /**
   * Cache with automatic refresh
   * @param {string} key - Cache key
   * @param {Function} fetchFn - Function to fetch fresh data
   * @param {Object} options - Cache options
   * @returns {Promise<any>} Cached or fresh data
   */
  async remember(key, fetchFn, options = {}) {
    const {
      ttl = this.defaultTTL,
      forceRefresh = false,
      gracePeriod = 60 // Grace period for stale data
    } = options;
    
    // Check if force refresh
    if (forceRefresh) {
      const freshData = await fetchFn();
      await this.set(key, freshData, ttl);
      return freshData;
    }
    
    // Try to get from cache
    const cached = await this.get(key);
    if (cached !== null) {
      // Check if we should refresh in background
      const remainingTTL = await this.ttl(key);
      if (remainingTTL > 0 && remainingTTL < gracePeriod) {
        // Refresh in background
        this.refreshInBackground(key, fetchFn, ttl);
      }
      return cached;
    }
    
    // Fetch fresh data
    const freshData = await fetchFn();
    await this.set(key, freshData, ttl);
    return freshData;
  }
  
  /**
   * Refresh cache in background
   * @param {string} key - Cache key
   * @param {Function} fetchFn - Function to fetch fresh data
   * @param {number} ttl - Time to live
   */
  async refreshInBackground(key, fetchFn, ttl) {
    try {
      const freshData = await fetchFn();
      await this.set(key, freshData, ttl);
      logger.debug(`Background cache refresh completed for ${key}`);
    } catch (error) {
      logger.error(`Background cache refresh error for ${key}:`, error);
    }
  }
  
  /**
   * Cache wrapper for functions
   * @param {Function} fn - Function to wrap
   * @param {Object} options - Cache options
   * @returns {Function} Wrapped function
   */
  wrap(fn, options = {}) {
    const {
      keyPrefix = fn.name || 'wrapped',
      ttl = this.defaultTTL,
      serialize = JSON.stringify
    } = options;
    
    return async (...args) => {
      const key = this.generateKey(keyPrefix, serialize(args));
      
      return this.remember(key, () => fn(...args), { ttl });
    };
  }
  
  /**
   * Invalidate related cache entries
   * @param {string} tag - Cache tag
   * @returns {Promise<number>} Number of invalidated entries
   */
  async invalidateTag(tag) {
    return this.delPattern(`*:tag:${tag}:*`);
  }
  
  /**
   * Tag cache entries
   * @param {string} key - Cache key
   * @param {Array<string>} tags - Tags to associate
   * @returns {Promise<boolean>} Success status
   */
  async tag(key, tags) {
    try {
      for (const tag of tags) {
        const tagKey = `tag:${tag}:${key}`;
        await this.set(tagKey, true, await this.ttl(key));
      }
      return true;
    } catch (error) {
      logger.error(`Cache tagging error for ${key}:`, error);
      return false;
    }
  }
  
  /**
   * Cache middleware for Express routes
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  middleware(options = {}) {
    const {
      keyGenerator = (req) => `route:${req.method}:${req.originalUrl}`,
      ttl = constants.CACHE_TTL.API_RESPONSE,
      condition = () => true,
      excludeHeaders = ['authorization', 'cookie']
    } = options;
    
    return async (req, res, next) => {
      // Check if caching should be applied
      if (!condition(req)) {
        return next();
      }
      
      // Only cache GET requests by default
      if (req.method !== 'GET') {
        return next();
      }
      
      const key = keyGenerator(req);
      
      // Try to get from cache
      const cached = await this.get(key);
      if (cached) {
        res.set('X-Cache', 'HIT');
        res.set('X-Cache-Key', key);
        return res.json(cached);
      }
      
      // Store original json method
      const originalJson = res.json;
      
      // Override json method to cache response
      res.json = (data) => {
        res.set('X-Cache', 'MISS');
        res.set('X-Cache-Key', key);
        
        // Cache successful responses only
        if (res.statusCode >= 200 && res.statusCode < 300) {
          this.set(key, data, ttl).catch(err => {
            logger.error('Response caching error:', err);
          });
        }
        
        // Call original json method
        return originalJson.call(res, data);
      };
      
      next();
    };
  }
  
  /**
   * Get cache statistics
   * @returns {Promise<Object>} Cache statistics
   */
  async getStats() {
    const stats = {
      type: this.redis && this.redis.status === 'ready' ? 'redis' : 'memory',
      connected: false,
      keys: 0,
      hits: 0,
      misses: 0,
      memory: 0
    };
    
    try {
      if (stats.type === 'redis') {
        const info = await this.redis.info('stats');
        const keyspace = await this.redis.info('keyspace');
        
        stats.connected = true;
        stats.keys = parseInt(keyspace.match(/keys=(\d+)/)?.[1] || 0);
        stats.hits = parseInt(info.match(/keyspace_hits:(\d+)/)?.[1] || 0);
        stats.misses = parseInt(info.match(/keyspace_misses:(\d+)/)?.[1] || 0);
      } else {
        stats.connected = true;
        stats.keys = this.memoryCache.keys().length;
        stats.hits = this.memoryCache.getStats().hits;
        stats.misses = this.memoryCache.getStats().misses;
      }
    } catch (error) {
      logger.error('Cache stats error:', error);
    }
    
    return stats;
  }
}

// Create singleton instance
const cacheHelper = new CacheHelper();

module.exports = cacheHelper;