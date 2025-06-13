// server/shared/config/redis.js
/**
 * @file Redis Configuration
 * @description Redis cache and session store configuration
 * @version 3.0.0
 */

const { createClient } = require('redis');

/**
 * Redis Configuration Class
 * @class RedisConfig
 */
class RedisConfig {
  constructor() {
    this.enabled = process.env.REDIS_ENABLED !== 'false';
    this.host = process.env.REDIS_HOST || 'localhost';
    this.port = parseInt(process.env.REDIS_PORT, 10) || 6379;
    this.password = process.env.REDIS_PASSWORD;
    this.username = process.env.REDIS_USERNAME;
    this.database = parseInt(process.env.REDIS_DATABASE, 10) || 0;
    this.keyPrefix = process.env.REDIS_KEY_PREFIX || 'insightserenity:';
    
    // Connection options
    this.connection = {
      url: this.buildConnectionUrl(),
      socket: {
        host: this.host,
        port: this.port,
        connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT, 10) || 5000,
        keepAlive: parseInt(process.env.REDIS_KEEPALIVE, 10) || 30000,
        noDelay: true
      },
      password: this.password,
      username: this.username,
      database: this.database,
      lazyConnect: process.env.REDIS_LAZY_CONNECT === 'true',
      readonly: process.env.REDIS_READONLY === 'true'
    };
    
    // Retry strategy
    this.retry = {
      maxRetriesPerRequest: parseInt(process.env.REDIS_MAX_RETRIES, 10) || 3,
      enableOfflineQueue: process.env.REDIS_OFFLINE_QUEUE !== 'false',
      maxReconnectTime: parseInt(process.env.REDIS_MAX_RECONNECT_TIME, 10) || 30000,
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      }
    };
    
    // Cluster configuration
    this.cluster = {
      enabled: process.env.REDIS_CLUSTER_ENABLED === 'true',
      nodes: process.env.REDIS_CLUSTER_NODES?.split(',').map(node => {
        const [host, port] = node.split(':');
        return { host, port: parseInt(port, 10) || 6379 };
      }) || [],
      options: {
        clusterRetryStrategy: this.retry.retryStrategy,
        enableOfflineQueue: this.retry.enableOfflineQueue,
        scaleReads: process.env.REDIS_CLUSTER_SCALE_READS || 'master'
      }
    };
    
    // Sentinel configuration for high availability
    this.sentinel = {
      enabled: process.env.REDIS_SENTINEL_ENABLED === 'true',
      sentinels: process.env.REDIS_SENTINELS?.split(',').map(sentinel => {
        const [host, port] = sentinel.split(':');
        return { host, port: parseInt(port, 10) || 26379 };
      }) || [],
      name: process.env.REDIS_SENTINEL_NAME || 'mymaster',
      sentinelPassword: process.env.REDIS_SENTINEL_PASSWORD
    };
    
    // Cache configuration
    this.cache = {
      ttl: {
        default: parseInt(process.env.CACHE_TTL_DEFAULT, 10) || 3600, // 1 hour
        session: parseInt(process.env.CACHE_TTL_SESSION, 10) || 86400, // 24 hours
        user: parseInt(process.env.CACHE_TTL_USER, 10) || 300, // 5 minutes
        permission: parseInt(process.env.CACHE_TTL_PERMISSION, 10) || 600, // 10 minutes
        organization: parseInt(process.env.CACHE_TTL_ORGANIZATION, 10) || 1800 // 30 minutes
      },
      maxSize: parseInt(process.env.CACHE_MAX_SIZE, 10) || 1000,
      checkPeriod: parseInt(process.env.CACHE_CHECK_PERIOD, 10) || 600 // 10 minutes
    };
    
    // Key patterns for different data types
    this.keys = {
      session: (sessionId) => `${this.keyPrefix}session:${sessionId}`,
      user: (userId) => `${this.keyPrefix}user:${userId}`,
      token: (token) => `${this.keyPrefix}token:${token}`,
      blacklist: (token) => `${this.keyPrefix}blacklist:${token}`,
      rateLimit: (identifier) => `${this.keyPrefix}ratelimit:${identifier}`,
      cache: (key) => `${this.keyPrefix}cache:${key}`,
      lock: (resource) => `${this.keyPrefix}lock:${resource}`,
      queue: (name) => `${this.keyPrefix}queue:${name}`,
      pubsub: (channel) => `${this.keyPrefix}pubsub:${channel}`
    };
    
    // Performance monitoring
    this.monitoring = {
      enabled: process.env.REDIS_MONITORING_ENABLED === 'true',
      slowLogThreshold: parseInt(process.env.REDIS_SLOW_LOG_MS, 10) || 10,
      commandStats: process.env.REDIS_COMMAND_STATS === 'true'
    };
  }
  
  /**
   * Build Redis connection URL
   * @returns {string} Redis URL
   */
  buildConnectionUrl() {
    let url = 'redis://';
    
    if (this.username) {
      url += `${this.username}:${this.password}@`;
    } else if (this.password) {
      url += `:${this.password}@`;
    }
    
    url += `${this.host}:${this.port}`;
    
    if (this.database > 0) {
      url += `/${this.database}`;
    }
    
    return url;
  }
  
  /**
   * Create Redis client instance
   * @returns {Promise<RedisClient>} Redis client
   */
  async createClient() {
    if (!this.enabled) {
      console.log('Redis is disabled. Using in-memory alternatives.');
      return null;
    }
    
    let client;
    
    try {
      // Create cluster client if enabled
      if (this.cluster.enabled) {
        const { createCluster } = require('redis');
        client = createCluster({
          rootNodes: this.cluster.nodes,
          defaults: {
            socket: this.connection.socket,
            password: this.password
          },
          ...this.cluster.options
        });
      }
      // Create sentinel client if enabled
      else if (this.sentinel.enabled) {
        client = createClient({
          sentinels: this.sentinel.sentinels,
          sentinelName: this.sentinel.name,
          sentinelPassword: this.sentinel.sentinelPassword,
          ...this.connection
        });
      }
      // Create standard client
      else {
        client = createClient(this.connection);
      }
      
      // Set up event handlers
      this.setupEventHandlers(client);
      
      // Connect to Redis
      await client.connect();
      
      // Test connection
      await client.ping();
      
      return client;
    } catch (error) {
      console.error('Failed to create Redis client:', error.message);
      throw error;
    }
  }
  
  /**
   * Set up Redis client event handlers
   * @param {RedisClient} client - Redis client instance
   */
  setupEventHandlers(client) {
    client.on('connect', () => {
      console.log('✓ Redis client connected');
    });
    
    client.on('ready', () => {
      console.log('✓ Redis client ready');
    });
    
    client.on('error', (error) => {
      console.error('✗ Redis client error:', error.message);
    });
    
    client.on('close', () => {
      console.log('✗ Redis client connection closed');
    });
    
    client.on('reconnecting', () => {
      console.log('↻ Redis client reconnecting...');
    });
    
    client.on('end', () => {
      console.log('✗ Redis client disconnected');
    });
    
    // Monitor slow commands if enabled
    if (this.monitoring.enabled) {
      client.on('commandSent', (command, args) => {
        const startTime = Date.now();
        
        client.once('reply', () => {
          const duration = Date.now() - startTime;
          if (duration > this.monitoring.slowLogThreshold) {
            console.warn(`Slow Redis command (${duration}ms):`, command, args);
          }
        });
      });
    }
  }
  
  /**
   * Create cache wrapper with TTL management
   * @param {RedisClient} client - Redis client
   * @returns {Object} Cache wrapper
   */
  createCacheWrapper(client) {
    return {
      /**
       * Get value from cache
       * @param {string} key - Cache key
       * @returns {Promise<any>} Cached value
       */
      async get(key) {
        if (!client) return null;
        
        try {
          const value = await client.get(key);
          return value ? JSON.parse(value) : null;
        } catch (error) {
          console.error('Cache get error:', error);
          return null;
        }
      },
      
      /**
       * Set value in cache
       * @param {string} key - Cache key
       * @param {any} value - Value to cache
       * @param {number} ttl - TTL in seconds
       * @returns {Promise<boolean>} Success status
       */
      async set(key, value, ttl = this.cache.ttl.default) {
        if (!client) return false;
        
        try {
          const serialized = JSON.stringify(value);
          await client.setEx(key, ttl, serialized);
          return true;
        } catch (error) {
          console.error('Cache set error:', error);
          return false;
        }
      },
      
      /**
       * Delete value from cache
       * @param {string} key - Cache key
       * @returns {Promise<boolean>} Success status
       */
      async del(key) {
        if (!client) return false;
        
        try {
          await client.del(key);
          return true;
        } catch (error) {
          console.error('Cache delete error:', error);
          return false;
        }
      },
      
      /**
       * Clear cache by pattern
       * @param {string} pattern - Key pattern
       * @returns {Promise<number>} Number of deleted keys
       */
      async clear(pattern) {
        if (!client) return 0;
        
        try {
          const keys = await client.keys(pattern);
          if (keys.length > 0) {
            return await client.del(keys);
          }
          return 0;
        } catch (error) {
          console.error('Cache clear error:', error);
          return 0;
        }
      }
    };
  }
  
  /**
   * Create distributed lock mechanism
   * @param {RedisClient} client - Redis client
   * @returns {Object} Lock mechanism
   */
  createLockMechanism(client) {
    return {
      /**
       * Acquire lock
       * @param {string} resource - Resource identifier
       * @param {number} ttl - Lock TTL in seconds
       * @returns {Promise<string|null>} Lock token or null
       */
      async acquire(resource, ttl = 10) {
        if (!client) return null;
        
        const key = this.keys.lock(resource);
        const token = require('crypto').randomBytes(16).toString('hex');
        
        try {
          const result = await client.set(key, token, {
            NX: true,
            EX: ttl
          });
          
          return result === 'OK' ? token : null;
        } catch (error) {
          console.error('Lock acquire error:', error);
          return null;
        }
      },
      
      /**
       * Release lock
       * @param {string} resource - Resource identifier
       * @param {string} token - Lock token
       * @returns {Promise<boolean>} Success status
       */
      async release(resource, token) {
        if (!client) return false;
        
        const key = this.keys.lock(resource);
        
        try {
          const script = `
            if redis.call("get", KEYS[1]) == ARGV[1] then
              return redis.call("del", KEYS[1])
            else
              return 0
            end
          `;
          
          const result = await client.eval(script, {
            keys: [key],
            arguments: [token]
          });
          
          return result === 1;
        } catch (error) {
          console.error('Lock release error:', error);
          return false;
        }
      }
    };
  }
}

// Create and export singleton instance
module.exports = new RedisConfig();