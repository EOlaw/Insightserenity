// server/shared/security/services/token-blacklist-service.js
/**
 * @file Token Blacklist Service
 * @description Manages revoked tokens and prevents their reuse
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const redis = require('../../config/redis');
const logger = require('../../utils/logger');
const { AppError } = require('../../utils/app-error');

/**
 * Token Blacklist Schema
 */
const tokenBlacklistSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  
  tokenId: {
    type: String,
    required: true,
    index: true
  },
  
  type: {
    type: String,
    enum: ['access', 'refresh', 'api_key', 'session'],
    required: true
  },
  
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  reason: {
    type: String,
    enum: ['logout', 'password_change', 'security_breach', 'manual_revoke', 'token_rotation', 'session_expired'],
    required: true
  },
  
  metadata: {
    ipAddress: String,
    userAgent: String,
    revokedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization'
    }
  },
  
  expiresAt: {
    type: Date,
    required: true,
    index: true
  },
  
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
});

// TTL index to automatically remove expired entries
tokenBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Compound indexes for efficient queries
tokenBlacklistSchema.index({ userId: 1, type: 1, createdAt: -1 });
tokenBlacklistSchema.index({ tokenId: 1, type: 1 });

const TokenBlacklist = mongoose.model('TokenBlacklist', tokenBlacklistSchema);

/**
 * Token Blacklist Service Class
 * @class TokenBlacklistService
 */
class TokenBlacklistService {
  constructor() {
    this.redisClient = null;
    this.cachePrefix = 'blacklist:';
    this.cacheTTL = 3600; // 1 hour
    this.initializeRedis();
  }
  
  /**
   * Initialize Redis client
   */
  async initializeRedis() {
    try {
      if (redis.enabled) {
        this.redisClient = await redis.createClient();
        logger.info('Token blacklist Redis cache initialized');
      }
    } catch (error) {
      logger.error('Failed to initialize Redis for token blacklist', { error });
    }
  }
  
  /**
   * Add token to blacklist
   * @param {Object} tokenData - Token information
   * @returns {Promise<boolean>} Success status
   */
  async blacklistToken(tokenData) {
    const {
      token,
      tokenId,
      type = 'access',
      userId,
      reason = 'manual_revoke',
      expiresAt,
      metadata = {}
    } = tokenData;
    
    try {
      // Create blacklist entry
      const entry = await TokenBlacklist.create({
        token: this.hashToken(token),
        tokenId,
        type,
        userId,
        reason,
        metadata,
        expiresAt: expiresAt || this.calculateExpiry(type)
      });
      
      // Add to Redis cache
      await this.addToCache(token, entry);
      
      // Log security event
      logger.info('Token blacklisted', {
        tokenId,
        type,
        userId,
        reason,
        metadata
      });
      
      return true;
    } catch (error) {
      if (error.code === 11000) {
        // Token already blacklisted
        return true;
      }
      
      logger.error('Failed to blacklist token', { error, tokenId });
      throw new AppError('Failed to blacklist token', 500, 'BLACKLIST_ERROR');
    }
  }
  
  /**
   * Check if token is blacklisted
   * @param {string} token - Token to check
   * @returns {Promise<boolean>} Is blacklisted
   */
  async isBlacklisted(token) {
    try {
      // Check Redis cache first
      const cached = await this.checkCache(token);
      if (cached !== null) {
        return cached;
      }
      
      // Check database
      const hashedToken = this.hashToken(token);
      const entry = await TokenBlacklist.findOne({
        token: hashedToken,
        expiresAt: { $gt: new Date() }
      });
      
      const isBlacklisted = !!entry;
      
      // Update cache
      await this.addToCache(token, isBlacklisted);
      
      return isBlacklisted;
    } catch (error) {
      logger.error('Failed to check token blacklist', { error });
      // Fail open to avoid blocking legitimate requests
      return false;
    }
  }
  
  /**
   * Blacklist all tokens for a user
   * @param {string} userId - User ID
   * @param {Object} options - Blacklist options
   * @returns {Promise<number>} Number of tokens blacklisted
   */
  async blacklistUserTokens(userId, options = {}) {
    const {
      types = ['access', 'refresh'],
      reason = 'security_breach',
      excludeTokenIds = [],
      metadata = {}
    } = options;
    
    try {
      // Find all active tokens for user
      const tokens = await this.findUserTokens(userId, types);
      
      // Filter out excluded tokens
      const tokensToBlacklist = tokens.filter(
        token => !excludeTokenIds.includes(token.tokenId)
      );
      
      // Bulk blacklist
      if (tokensToBlacklist.length > 0) {
        const blacklistEntries = tokensToBlacklist.map(token => ({
          token: token.hashedToken,
          tokenId: token.tokenId,
          type: token.type,
          userId,
          reason,
          metadata,
          expiresAt: token.expiresAt
        }));
        
        await TokenBlacklist.insertMany(blacklistEntries, { ordered: false });
        
        // Clear user's token cache
        await this.clearUserCache(userId);
      }
      
      logger.info('User tokens blacklisted', {
        userId,
        count: tokensToBlacklist.length,
        reason
      });
      
      return tokensToBlacklist.length;
    } catch (error) {
      logger.error('Failed to blacklist user tokens', { error, userId });
      throw new AppError('Failed to blacklist user tokens', 500, 'BLACKLIST_ERROR');
    }
  }
  
  /**
   * Blacklist tokens by pattern
   * @param {Object} criteria - Search criteria
   * @param {string} reason - Blacklist reason
   * @returns {Promise<number>} Number of tokens blacklisted
   */
  async blacklistByPattern(criteria, reason = 'security_breach') {
    const {
      organizationId,
      ipAddress,
      userAgent,
      createdBefore,
      createdAfter
    } = criteria;
    
    try {
      const query = {};
      
      if (organizationId) {
        query['metadata.organizationId'] = organizationId;
      }
      
      if (ipAddress) {
        query['metadata.ipAddress'] = ipAddress;
      }
      
      if (userAgent) {
        query['metadata.userAgent'] = new RegExp(userAgent, 'i');
      }
      
      if (createdBefore || createdAfter) {
        query.createdAt = {};
        if (createdBefore) query.createdAt.$lt = createdBefore;
        if (createdAfter) query.createdAt.$gt = createdAfter;
      }
      
      // This would need to be implemented based on your token storage
      // For now, returning 0 as placeholder
      
      logger.info('Tokens blacklisted by pattern', {
        criteria,
        reason
      });
      
      return 0;
    } catch (error) {
      logger.error('Failed to blacklist by pattern', { error, criteria });
      throw new AppError('Failed to blacklist tokens', 500, 'BLACKLIST_ERROR');
    }
  }
  
  /**
   * Clean up expired blacklist entries
   * @returns {Promise<number>} Number of entries removed
   */
  async cleanup() {
    try {
      const result = await TokenBlacklist.deleteMany({
        expiresAt: { $lt: new Date() }
      });
      
      logger.info('Blacklist cleanup completed', {
        removed: result.deletedCount
      });
      
      return result.deletedCount;
    } catch (error) {
      logger.error('Blacklist cleanup failed', { error });
      return 0;
    }
  }
  
  /**
   * Get blacklist statistics
   * @param {Object} filters - Query filters
   * @returns {Promise<Object>} Statistics
   */
  async getStatistics(filters = {}) {
    try {
      const query = {};
      
      if (filters.userId) {
        query.userId = filters.userId;
      }
      
      if (filters.startDate || filters.endDate) {
        query.createdAt = {};
        if (filters.startDate) query.createdAt.$gte = filters.startDate;
        if (filters.endDate) query.createdAt.$lte = filters.endDate;
      }
      
      const [total, byType, byReason] = await Promise.all([
        TokenBlacklist.countDocuments(query),
        TokenBlacklist.aggregate([
          { $match: query },
          { $group: { _id: '$type', count: { $sum: 1 } } }
        ]),
        TokenBlacklist.aggregate([
          { $match: query },
          { $group: { _id: '$reason', count: { $sum: 1 } } }
        ])
      ]);
      
      return {
        total,
        byType: byType.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        byReason: byReason.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {})
      };
    } catch (error) {
      logger.error('Failed to get blacklist statistics', { error });
      throw error;
    }
  }
  
  /**
   * Hash token for storage
   * @param {string} token - Token to hash
   * @returns {string} Hashed token
   */
  hashToken(token) {
    const crypto = require('crypto');
    return crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
  }
  
  /**
   * Calculate token expiry
   * @param {string} type - Token type
   * @returns {Date} Expiry date
   */
  calculateExpiry(type) {
    const expiryMinutes = {
      access: 15,
      refresh: 10080, // 7 days
      api_key: 525600, // 1 year
      session: 1440 // 24 hours
    };
    
    const minutes = expiryMinutes[type] || 60;
    return new Date(Date.now() + minutes * 60 * 1000);
  }
  
  /**
   * Add token to Redis cache
   * @param {string} token - Token
   * @param {any} value - Value to cache
   */
  async addToCache(token, value) {
    if (!this.redisClient) return;
    
    try {
      const key = `${this.cachePrefix}${this.hashToken(token)}`;
      const data = typeof value === 'boolean' ? value : 'true';
      
      await this.redisClient.setEx(key, this.cacheTTL, String(data));
    } catch (error) {
      logger.debug('Failed to add token to cache', { error });
    }
  }
  
  /**
   * Check token in Redis cache
   * @param {string} token - Token to check
   * @returns {Promise<boolean|null>} Cached value or null
   */
  async checkCache(token) {
    if (!this.redisClient) return null;
    
    try {
      const key = `${this.cachePrefix}${this.hashToken(token)}`;
      const cached = await this.redisClient.get(key);
      
      if (cached !== null) {
        return cached === 'true';
      }
      
      return null;
    } catch (error) {
      logger.debug('Failed to check token cache', { error });
      return null;
    }
  }
  
  /**
   * Clear user's token cache
   * @param {string} userId - User ID
   */
  async clearUserCache(userId) {
    if (!this.redisClient) return;
    
    try {
      // This would need to track user tokens in Redis
      // For now, just logging
      logger.debug('Clearing user token cache', { userId });
    } catch (error) {
      logger.debug('Failed to clear user cache', { error });
    }
  }
  
  /**
   * Find user's active tokens
   * @param {string} userId - User ID
   * @param {Array} types - Token types
   * @returns {Promise<Array>} User tokens
   */
  async findUserTokens(userId, types) {
    // This would need to be implemented based on your token storage strategy
    // Returning empty array as placeholder
    return [];
  }
  
  /**
   * Create middleware to check token blacklist
   * @returns {Function} Express middleware
   */
  createMiddleware() {
    return async (req, res, next) => {
      try {
        // Extract token from request
        const token = this.extractToken(req);
        
        if (!token) {
          return next();
        }
        
        // Check if token is blacklisted
        const isBlacklisted = await this.isBlacklisted(token);
        
        if (isBlacklisted) {
          return res.status(401).json({
            success: false,
            error: {
              message: 'Token has been revoked',
              code: 'TOKEN_REVOKED'
            }
          });
        }
        
        next();
      } catch (error) {
        logger.error('Token blacklist middleware error', { error });
        // Fail open
        next();
      }
    };
  }
  
  /**
   * Extract token from request
   * @param {Object} req - Express request
   * @returns {string|null} Token
   */
  extractToken(req) {
    // Check Authorization header
    const authHeader = req.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    
    // Check cookie
    if (req.cookies?.access_token) {
      return req.cookies.access_token;
    }
    
    // Check query parameter (for download links)
    if (req.query.token) {
      return req.query.token;
    }
    
    return null;
  }
}

// Create and export singleton instance
module.exports = new TokenBlacklistService();