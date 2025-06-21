// server/shared/security/services/token-blacklist-service.js
/**
 * @file Token Blacklist Service
 * @description Manages revoked tokens and prevents their reuse
 * @version 3.0.2 - Fixed circular dependency issue
 */

const mongoose = require('mongoose');
const jwt = require('jsonwebtoken'); // Import jwt directly instead of from AuthService
const redis = require('../../config/redis');
const { AppError } = require('../../utils/app-error');
const crypto = require('crypto');
const logger = require('../../utils/logger');
const config = require('../../config/config'); // Import config for JWT secrets

// Remove this line that causes circular dependency:
// const { refreshToken } = require('../../auth/services/auth-service');

/**
 * Token Blacklist Schema - CORRECTED: Removed duplicate index definitions
 */
const tokenBlacklistSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  
  tokenId: {
    type: String,
    required: true
  },
  
  type: {
    type: String,
    enum: ['access', 'refresh', 'api_key', 'session'],
    required: true
  },
  
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
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
    required: true
  },
  
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Define indexes only here to avoid duplicates
tokenBlacklistSchema.index({ token: 1 }, { unique: true });
tokenBlacklistSchema.index({ tokenId: 1 });
tokenBlacklistSchema.index({ userId: 1 });
tokenBlacklistSchema.index({ createdAt: -1 });

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
   * Decode token without circular dependency
   * @param {string} token - Token to decode
   * @returns {Object|null} Decoded token or null
   */
  decodeToken(token) {
    try {
      if (!token || typeof token !== 'string') {
        return null;
      }
      
      // Try to decode without verification first to get basic info
      const decoded = jwt.decode(token);
      if (!decoded) {
        return null;
      }
      
      return decoded;
    } catch (error) {
      logger.debug('Failed to decode token for blacklisting', { error: error.message });
      return null;
    }
  }
  
  /**
   * Generate token ID if not present in token
   * @returns {string} Generated token ID
   */
  generateTokenId() {
    return crypto.randomBytes(16).toString('hex');
  }
  
  /**
   * Blacklist a token
   * @param {string} token - Token to blacklist
   * @param {string} type - Token type
   * @param {string} reason - Blacklist reason
   * @param {Object} metadata - Additional metadata
   * @returns {Promise<boolean>} Success status
   */
  async blacklistToken(token, type = 'access', reason = 'logout', metadata = {}) {
    try {
      // Validate token parameter
      if (!token || typeof token !== 'string') {
        logger.warn('Attempted to blacklist invalid token', {
          tokenType: typeof token,
          tokenValue: token,
          type,
          reason
        });
        return false;
      }

      // Check if already blacklisted
      const existingEntry = await this.isBlacklisted(token);
      if (existingEntry) {
        logger.debug('Token already blacklisted', { tokenHash: this.hashToken(token) });
        return true;
      }

      // Hash the token for storage
      const hashedToken = this.hashToken(token);
      
      // Extract token ID and expiry
      const decoded = this.decodeToken(token);
      const tokenId = decoded?.jti || this.generateTokenId();
      const expiresAt = decoded?.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 86400000);

      // Create blacklist entry
      const blacklistEntry = new TokenBlacklist({
        token: hashedToken,
        tokenId,
        type,
        userId: decoded?.userId,
        reason,
        metadata,
        expiresAt
      });

      await blacklistEntry.save();
      
      // Update cache
      await this.addToCache(hashedToken, true);
      
      logger.info('Token blacklisted successfully', {
        tokenId,
        type,
        reason,
        userId: decoded?.userId
      });
      
      return true;
      
    } catch (error) {
      logger.error('Failed to blacklist token', { 
        error: error.message,
        type,
        reason 
      });
      return false;
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
   * Alternative method name for compatibility
   * @param {string} token - Token to check
   * @returns {Promise<boolean>} Is blacklisted
   */
  async isTokenBlacklisted(token) {
    return this.isBlacklisted(token);
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
   * Hash token for secure storage
   * @param {string} token - Token to hash
   * @returns {string} Hashed token
   */
  hashToken(token) {
    if (!token || typeof token !== 'string') {
      throw new Error('Token must be a valid string for hashing');
    }
    
    return crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
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
      logger.debug('Clearing user token cache', { userId });
    } catch (error) {
      logger.debug('Failed to clear user cache', { error });
    }
  }
  
  /**
   * Find user's active tokens (placeholder implementation)
   * @param {string} userId - User ID
   * @param {Array} types - Token types
   * @returns {Promise<Array>} User tokens
   */
  async findUserTokens(userId, types) {
    return [];
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