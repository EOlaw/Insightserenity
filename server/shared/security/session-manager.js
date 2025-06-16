/**
 * @file Session Manager
 * @description Comprehensive session management for the InsightSerenity platform
 * @version 3.0.0
 */

const session = require('express-session');
const MongoStore = require('connect-mongo');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');
const crypto = require('crypto');
const logger = require('../utils/logger');
const config = require('../config/config');
const { AppError } = require('../utils/app-error');

/**
 * Session Manager Class
 * Handles session creation, validation, cleanup, and store management
 */
class SessionManager {
  constructor() {
    this.config = config.session || {};
    this.store = null;
    this.redisClient = null;
    this.activeSessions = new Map();
    this.cleanupInterval = null;
    
    // Session timeout settings
    this.idleTimeout = this.config.idleTimeout || 1800000; // 30 minutes
    this.absoluteTimeout = this.config.absoluteTimeout || 28800000; // 8 hours
    this.rotationMinutes = this.config.rotationMinutes || 60;
    
    // Initialize session store
    this.initializeStore();
  }

  /**
   * Initialize session store based on configuration
   */
  async initializeStore() {
    try {
      const storeType = this.config.store || 'mongodb';
      
      if (storeType === 'redis' && process.env.REDIS_ENABLED !== 'false') {
        await this.setupRedisStore();
      } else {
        await this.setupMongoStore();
      }
      
      // Start cleanup interval
      this.startCleanupInterval();
      
      logger.info('Session store initialized successfully', { 
        store: storeType,
        config: {
          idleTimeout: this.idleTimeout,
          absoluteTimeout: this.absoluteTimeout,
          rotationMinutes: this.rotationMinutes
        }
      });
    } catch (error) {
      logger.error('Failed to initialize session store', { error: error.message });
      throw new AppError('Session store initialization failed', 500);
    }
  }

  /**
   * Setup Redis session store
   */
  async setupRedisStore() {
    try {
      this.redisClient = createClient({
        url: process.env.REDIS_URL || 'redis://localhost:6379',
        password: process.env.REDIS_PASSWORD,
        database: parseInt(process.env.REDIS_SESSION_DB || '1', 10)
      });

      this.redisClient.on('error', (err) => {
        logger.error('Redis session store error', { error: err.message });
      });

      this.redisClient.on('connect', () => {
        logger.info('Redis session store connected');
      });

      await this.redisClient.connect();
      
      this.store = new RedisStore({
        client: this.redisClient,
        prefix: 'sess:',
        ttl: Math.floor(this.config.cookie?.maxAge / 1000) || 86400
      });
    } catch (error) {
      logger.warn('Redis store setup failed, falling back to MongoDB', { error: error.message });
      await this.setupMongoStore();
    }
  }

  /**
   * Setup MongoDB session store
   */
  async setupMongoStore() {
    const mongoUrl = process.env.DATABASE_URL || process.env.MONGODB_URI || 'mongodb://localhost:27017/insightserenity';
    
    this.store = MongoStore.create({
      mongoUrl,
      collectionName: 'sessions',
      ttl: Math.floor((this.config.cookie?.maxAge || 86400000) / 1000),
      touchAfter: 24 * 3600, // Lazy session update
      stringify: false,
      autoRemove: 'native',
      autoRemoveInterval: 10 // Minutes
    });

    this.store.on('error', (err) => {
      logger.error('MongoDB session store error', { error: err.message });
    });

    this.store.on('create', (sessionId) => {
      logger.debug('Session created', { sessionId });
    });

    this.store.on('destroy', (sessionId) => {
      logger.debug('Session destroyed', { sessionId });
    });
  }

  /**
   * Get Express session middleware
   * @returns {Function} Express session middleware
   */
  getSessionMiddleware() {
    const sessionConfig = {
      secret: this.config.secret || process.env.SESSION_SECRET || 'your-session-secret',
      name: this.config.name || 'insightserenity.sid',
      store: this.store,
      resave: this.config.resave !== undefined ? this.config.resave : false,
      saveUninitialized: this.config.saveUninitialized !== undefined ? this.config.saveUninitialized : false,
      rolling: this.config.rolling !== undefined ? this.config.rolling : true,
      proxy: this.config.proxy !== undefined ? this.config.proxy : true,
      cookie: {
        secure: this.config.cookie?.secure || process.env.NODE_ENV === 'production',
        httpOnly: this.config.cookie?.httpOnly !== undefined ? this.config.cookie.httpOnly : true,
        maxAge: this.config.cookie?.maxAge || 86400000, // 24 hours
        sameSite: this.config.cookie?.sameSite || 'lax'
      },
      genid: this.generateSessionId.bind(this)
    };

    // Ensure session secret is set
    if (!sessionConfig.secret || sessionConfig.secret === 'your-session-secret') {
      logger.warn('Using default session secret. Please set SESSION_SECRET environment variable for production.');
    }

    return session(sessionConfig);
  }

  /**
   * Generate unique session ID
   * @returns {string} Session ID
   */
  generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Create new session for user
   * @param {string} userId - User ID
   * @param {Object} sessionData - Additional session data
   * @param {Object} req - Express request object
   * @returns {Promise<Object>} Session information
   */
  async createSession(userId, sessionData = {}, req) {
    try {
      const sessionId = this.generateSessionId();
      const now = new Date();
      
      const session = {
        sessionId,
        userId,
        createdAt: now,
        lastActivityAt: now,
        expiresAt: new Date(now.getTime() + this.absoluteTimeout),
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
        active: true,
        ...sessionData
      };

      // Store in active sessions map for quick access
      this.activeSessions.set(sessionId, session);

      // Store in persistent store if available
      if (this.store && req.session) {
        req.session.userId = userId;
        req.session.sessionId = sessionId;
        req.session.createdAt = now;
        req.session.lastActivityAt = now;
        Object.assign(req.session, sessionData);
      }

      logger.info('Session created', { 
        sessionId, 
        userId, 
        userAgent: session.userAgent,
        ip: session.ip 
      });

      return session;
    } catch (error) {
      logger.error('Failed to create session', { error: error.message, userId });
      throw new AppError('Session creation failed', 500);
    }
  }

  /**
   * Validate session
   * @param {string} sessionId - Session ID
   * @param {Object} req - Express request object
   * @returns {Promise<Object|null>} Session data or null if invalid
   */
  async validateSession(sessionId, req) {
    try {
      let session = this.activeSessions.get(sessionId);
      
      // If not in memory, try to get from store
      if (!session && req.session && req.session.sessionId === sessionId) {
        session = {
          sessionId: req.session.sessionId,
          userId: req.session.userId,
          createdAt: req.session.createdAt,
          lastActivityAt: req.session.lastActivityAt,
          active: true
        };
      }

      if (!session || !session.active) {
        return null;
      }

      const now = new Date();
      
      // Check absolute timeout
      if (session.expiresAt && now > session.expiresAt) {
        await this.destroySession(sessionId, 'absolute_timeout');
        return null;
      }

      // Check idle timeout
      const idleTime = now - new Date(session.lastActivityAt);
      if (idleTime > this.idleTimeout) {
        await this.destroySession(sessionId, 'idle_timeout');
        return null;
      }

      // Check if session needs rotation
      const sessionAge = now - new Date(session.createdAt);
      const rotationInterval = this.rotationMinutes * 60 * 1000;
      
      if (sessionAge > rotationInterval) {
        return await this.rotateSession(sessionId, req);
      }

      // Update last activity
      await this.updateSessionActivity(sessionId, req);
      
      return session;
    } catch (error) {
      logger.error('Session validation failed', { error: error.message, sessionId });
      return null;
    }
  }

  /**
   * Update session activity timestamp
   * @param {string} sessionId - Session ID
   * @param {Object} req - Express request object
   */
  async updateSessionActivity(sessionId, req) {
    try {
      const session = this.activeSessions.get(sessionId);
      if (session) {
        session.lastActivityAt = new Date();
        this.activeSessions.set(sessionId, session);
      }

      if (req.session && req.session.sessionId === sessionId) {
        req.session.lastActivityAt = new Date();
      }
    } catch (error) {
      logger.error('Failed to update session activity', { error: error.message, sessionId });
    }
  }

  /**
   * Rotate session ID for security
   * @param {string} oldSessionId - Current session ID
   * @param {Object} req - Express request object
   * @returns {Promise<Object>} New session data
   */
  async rotateSession(oldSessionId, req) {
    try {
      const oldSession = this.activeSessions.get(oldSessionId);
      if (!oldSession) {
        return null;
      }

      // Create new session with same data
      const newSessionId = this.generateSessionId();
      const newSession = {
        ...oldSession,
        sessionId: newSessionId,
        createdAt: new Date(),
        lastActivityAt: new Date()
      };

      // Update stores
      this.activeSessions.delete(oldSessionId);
      this.activeSessions.set(newSessionId, newSession);

      if (req.session) {
        req.session.sessionId = newSessionId;
        req.session.createdAt = newSession.createdAt;
        req.session.lastActivityAt = newSession.lastActivityAt;
      }

      logger.info('Session rotated', { 
        oldSessionId, 
        newSessionId, 
        userId: newSession.userId 
      });

      return newSession;
    } catch (error) {
      logger.error('Session rotation failed', { error: error.message, oldSessionId });
      throw new AppError('Session rotation failed', 500);
    }
  }

  /**
   * Destroy session
   * @param {string} sessionId - Session ID
   * @param {string} reason - Reason for destruction
   * @param {Object} req - Express request object (optional)
   */
  async destroySession(sessionId, reason = 'manual', req = null) {
    try {
      // Remove from memory
      const session = this.activeSessions.get(sessionId);
      this.activeSessions.delete(sessionId);

      // Remove from persistent store
      if (req && req.session) {
        req.session.destroy((err) => {
          if (err) {
            logger.error('Failed to destroy session from store', { error: err.message });
          }
        });
      }

      logger.info('Session destroyed', { 
        sessionId, 
        reason,
        userId: session?.userId 
      });
    } catch (error) {
      logger.error('Failed to destroy session', { error: error.message, sessionId });
    }
  }

  /**
   * Destroy all sessions for a user
   * @param {string} userId - User ID
   * @param {string} excludeSessionId - Session ID to exclude (optional)
   */
  async destroyUserSessions(userId, excludeSessionId = null) {
    try {
      let destroyedCount = 0;
      
      // Remove from memory
      for (const [sessionId, session] of this.activeSessions) {
        if (session.userId === userId && sessionId !== excludeSessionId) {
          this.activeSessions.delete(sessionId);
          destroyedCount++;
        }
      }

      // Remove from persistent store (would need database query for MongoDB)
      // This is a simplified implementation
      
      logger.info('User sessions destroyed', { 
        userId, 
        destroyedCount,
        excludeSessionId 
      });

      return destroyedCount;
    } catch (error) {
      logger.error('Failed to destroy user sessions', { error: error.message, userId });
      return 0;
    }
  }

  /**
   * Get active sessions for user
   * @param {string} userId - User ID
   * @returns {Array} Active sessions
   */
  getUserSessions(userId) {
    const userSessions = [];
    
    for (const [sessionId, session] of this.activeSessions) {
      if (session.userId === userId && session.active) {
        userSessions.push({
          sessionId,
          createdAt: session.createdAt,
          lastActivityAt: session.lastActivityAt,
          userAgent: session.userAgent,
          ip: session.ip
        });
      }
    }
    
    return userSessions;
  }

  /**
   * Start cleanup interval for expired sessions
   */
  startCleanupInterval() {
    // Run cleanup every 10 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanupExpiredSessions();
    }, 10 * 60 * 1000);
  }

  /**
   * Stop cleanup interval
   */
  stopCleanupInterval() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Clean up expired sessions from memory
   */
  cleanupExpiredSessions() {
    const now = new Date();
    let cleanedCount = 0;

    for (const [sessionId, session] of this.activeSessions) {
      const isExpired = (session.expiresAt && now > session.expiresAt) ||
                       (now - new Date(session.lastActivityAt) > this.idleTimeout);
      
      if (isExpired) {
        this.activeSessions.delete(sessionId);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      logger.info('Expired sessions cleaned up', { count: cleanedCount });
    }
  }

  /**
   * Get session statistics
   * @returns {Object} Session statistics
   */
  getSessionStats() {
    return {
      totalActiveSessions: this.activeSessions.size,
      storeType: this.store?.constructor?.name || 'unknown',
      configuration: {
        idleTimeout: this.idleTimeout,
        absoluteTimeout: this.absoluteTimeout,
        rotationMinutes: this.rotationMinutes
      }
    };
  }

  /**
   * Graceful shutdown
   */
  async shutdown() {
    try {
      this.stopCleanupInterval();
      
      if (this.redisClient) {
        await this.redisClient.quit();
      }
      
      logger.info('Session manager shutdown completed');
    } catch (error) {
      logger.error('Session manager shutdown error', { error: error.message });
    }
  }
}

module.exports = SessionManager;