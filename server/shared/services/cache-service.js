/**
 * @file Cache Service
 * @description Redis-based caching service for the platform
 * @version 1.0.0
 */

const Redis = require('ioredis');

const logger = require('../utils/logger');

class CacheService {
  constructor() {
    this.client = null;
    this.isConnected = false;
    this.defaultTTL = 3600; // 1 hour default
  }

  /**
   * Initialize Redis connection
   * @param {Object} config - Redis configuration
   */
  async initialize(config = {}) {
    try {
      const redisConfig = {
        host: config.host || process.env.REDIS_HOST || 'localhost',
        port: config.port || process.env.REDIS_PORT || 6379,
        password: config.password || process.env.REDIS_PASSWORD,
        db: config.db || process.env.REDIS_DB || 0,
        retryStrategy: (times) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
        enableOfflineQueue: false,
        maxRetriesPerRequest: 3
      };

      this.client = new Redis(redisConfig);

      this.client.on('connect', () => {
        this.isConnected = true;
        logger.info('Cache service connected to Redis');
      });

      this.client.on('error', (error) => {
        this.isConnected = false;
        logger.error('Cache service Redis error:', error);
      });

      this.client.on('close', () => {
        this.isConnected = false;
        logger.warn('Cache service Redis connection closed');
      });

      // Test connection
      await this.client.ping();
      return true;
    } catch (error) {
      logger.error('Failed to initialize cache service:', error);
      this.isConnected = false;
      return false;
    }
  }

  /**
   * Get value from cache
   * @param {string} key - Cache key
   * @returns {Promise<any>} - Cached value or null
   */
  async get(key) {
    if (!this.isConnected) return null;

    try {
      const value = await this.client.get(key);
      if (value) {
        return JSON.parse(value);
      }
      return null;
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
   * @returns {Promise<boolean>} - Success status
   */
  async set(key, value, ttl = this.defaultTTL) {
    if (!this.isConnected) return false;

    try {
      const serialized = JSON.stringify(value);
      if (ttl > 0) {
        await this.client.setex(key, ttl, serialized);
      } else {
        await this.client.set(key, serialized);
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
   * @returns {Promise<boolean>} - Success status
   */
  async del(key) {
    if (!this.isConnected) return false;

    try {
      await this.client.del(key);
      return true;
    } catch (error) {
      logger.error(`Cache delete error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Delete multiple keys matching a pattern
   * @param {string} pattern - Key pattern (e.g., 'user:*')
   * @returns {Promise<number>} - Number of keys deleted
   */
  async delPattern(pattern) {
    if (!this.isConnected) return 0;

    try {
      const keys = await this.client.keys(pattern);
      if (keys.length > 0) {
        return await this.client.del(...keys);
      }
      return 0;
    } catch (error) {
      logger.error(`Cache delete pattern error for ${pattern}:`, error);
      return 0;
    }
  }

  /**
   * Check if key exists
   * @param {string} key - Cache key
   * @returns {Promise<boolean>} - Existence status
   */
  async exists(key) {
    if (!this.isConnected) return false;

    try {
      const exists = await this.client.exists(key);
      return exists === 1;
    } catch (error) {
      logger.error(`Cache exists error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Set key expiration
   * @param {string} key - Cache key
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>} - Success status
   */
  async expire(key, ttl) {
    if (!this.isConnected) return false;

    try {
      await this.client.expire(key, ttl);
      return true;
    } catch (error) {
      logger.error(`Cache expire error for key ${key}:`, error);
      return false;
    }
  }

  /**
   * Get remaining TTL for a key
   * @param {string} key - Cache key
   * @returns {Promise<number>} - TTL in seconds, -1 if no expiry, -2 if not exists
   */
  async ttl(key) {
    if (!this.isConnected) return -2;

    try {
      return await this.client.ttl(key);
    } catch (error) {
      logger.error(`Cache TTL error for key ${key}:`, error);
      return -2;
    }
  }

  /**
   * Increment a counter
   * @param {string} key - Cache key
   * @param {number} increment - Increment value (default: 1)
   * @returns {Promise<number>} - New value
   */
  async incr(key, increment = 1) {
    if (!this.isConnected) return 0;

    try {
      if (increment === 1) {
        return await this.client.incr(key);
      }
      return await this.client.incrby(key, increment);
    } catch (error) {
      logger.error(`Cache increment error for key ${key}:`, error);
      return 0;
    }
  }

  /**
   * Add to a set
   * @param {string} key - Set key
   * @param {string|Array} members - Member(s) to add
   * @returns {Promise<number>} - Number of members added
   */
  async sadd(key, members) {
    if (!this.isConnected) return 0;

    try {
      const membersArray = Array.isArray(members) ? members : [members];
      return await this.client.sadd(key, ...membersArray);
    } catch (error) {
      logger.error(`Cache set add error for key ${key}:`, error);
      return 0;
    }
  }

  /**
   * Get set members
   * @param {string} key - Set key
   * @returns {Promise<Array>} - Set members
   */
  async smembers(key) {
    if (!this.isConnected) return [];

    try {
      return await this.client.smembers(key);
    } catch (error) {
      logger.error(`Cache set members error for key ${key}:`, error);
      return [];
    }
  }

  /**
   * Remove from a set
   * @param {string} key - Set key
   * @param {string|Array} members - Member(s) to remove
   * @returns {Promise<number>} - Number of members removed
   */
  async srem(key, members) {
    if (!this.isConnected) return 0;

    try {
      const membersArray = Array.isArray(members) ? members : [members];
      return await this.client.srem(key, ...membersArray);
    } catch (error) {
      logger.error(`Cache set remove error for key ${key}:`, error);
      return 0;
    }
  }

  /**
   * Cache with automatic refresh
   * @param {string} key - Cache key
   * @param {Function} fetchFunction - Function to fetch data if not cached
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<any>} - Cached or fetched value
   */
  async remember(key, fetchFunction, ttl = this.defaultTTL) {
    try {
      // Try to get from cache
      const cached = await this.get(key);
      if (cached !== null) {
        return cached;
      }

      // Fetch fresh data
      const fresh = await fetchFunction();
      
      // Cache the fresh data
      await this.set(key, fresh, ttl);
      
      return fresh;
    } catch (error) {
      logger.error(`Cache remember error for key ${key}:`, error);
      throw error;
    }
  }

  /**
   * Flush all cache
   * @returns {Promise<boolean>} - Success status
   */
  async flush() {
    if (!this.isConnected) return false;

    try {
      await this.client.flushdb();
      logger.info('Cache flushed successfully');
      return true;
    } catch (error) {
      logger.error('Cache flush error:', error);
      return false;
    }
  }

  /**
   * Close Redis connection
   */
  async close() {
    if (this.client) {
      await this.client.quit();
      this.isConnected = false;
      logger.info('Cache service connection closed');
    }
  }

  /**
   * Get cache statistics
   * @returns {Promise<Object>} - Cache statistics
   */
  async getStats() {
    if (!this.isConnected) {
      return { connected: false };
    }

    try {
      const info = await this.client.info('stats');
      const dbSize = await this.client.dbsize();
      
      return {
        connected: true,
        dbSize,
        info
      };
    } catch (error) {
      logger.error('Cache stats error:', error);
      return { connected: false, error: error.message };
    }
  }
}

// Create singleton instance
const cacheService = new CacheService();

// Export both the class and singleton instance
module.exports = {
  CacheService: cacheService,
  CacheServiceClass: CacheService
};