// server/shared/auth/services/token-service.js
// Description: Token Service for generating and managing JWT tokens in a multi-tenant application
/**
 * @file Token Service
 * @description JWT token generation and management for multi-tenant authentication
 * @version 3.0.0
 */

const crypto = require('crypto');

const jwt = require('jsonwebtoken');

const config = require('../../config/config');
const EncryptionService = require('../../security/services/encryption-service');
const { AppError, TokenError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

/**
 * Token Service Class
 * @class TokenService
 */
class TokenService {
  constructor() {
    this.accessTokenSecret = config.auth.jwtSecret;
    this.refreshTokenSecret = config.auth.jwtRefreshSecret;
    this.accessTokenExpiry = config.auth.accessTokenExpiry;
    this.refreshTokenExpiry = config.auth.refreshTokenExpiry;
    
    // Token types configuration
    this.tokenConfigs = {
      access: {
        secret: this.accessTokenSecret,
        expiry: this.accessTokenExpiry,
        algorithm: 'HS256'
      },
      refresh: {
        secret: this.refreshTokenSecret,
        expiry: this.refreshTokenExpiry,
        algorithm: 'HS256'
      },
      reset: {
        secret: this.accessTokenSecret,
        expiry: '1h',
        algorithm: 'HS256'
      },
      verification: {
        secret: this.accessTokenSecret,
        expiry: '24h',
        algorithm: 'HS256'
      },
      invitation: {
        secret: this.accessTokenSecret,
        expiry: '7d',
        algorithm: 'HS256'
      }
    };
  }
  
  /**
   * Generate authentication tokens
   * @param {Object} user - User document
   * @param {Object} options - Token options
   * @returns {Promise<Object>} Access and refresh tokens
   */
  async generateAuthTokens(user, options = {}) {
    try {
      const {
        ipAddress,
        userAgent,
        deviceId,
        organizationChanged = false,
        rememberMe = false
      } = options;
      
      // Generate token IDs
      const accessTokenId = this.generateTokenId();
      const refreshTokenId = this.generateTokenId();
      
      // Prepare token payload
      const basePayload = {
        userId: user._id.toString(),
        email: user.email,
        userType: user.userType,
        role: user.role.primary,
        roles: [user.role.primary, ...(user.role.secondary || [])],
        permissions: user.permissions || []
      };
      
      // Add organization context
      if (user.organization?.current) {
        basePayload.organizationId = user.organization.current.toString();
        basePayload.organizationType = user.organization.type;
      }
      
      // Access token payload
      const accessPayload = {
        ...basePayload,
        type: 'access',
        jti: accessTokenId,
        deviceId,
        sessionId: this.generateSessionId()
      };
      
      // Refresh token payload
      const refreshPayload = {
        userId: user._id.toString(),
        type: 'refresh',
        jti: refreshTokenId,
        accessTokenId,
        deviceId,
        ipAddress,
        userAgent
      };
      
      // Adjust expiry for remember me
      const refreshExpiry = rememberMe ? '30d' : this.refreshTokenExpiry;
      
      // Generate tokens
      const accessToken = await this.generateToken(accessPayload, 'access');
      const refreshToken = await this.generateToken(refreshPayload, 'refresh', { expiresIn: refreshExpiry });
      
      // Calculate expiry timestamps
      const now = Date.now();
      const accessTokenExpiry = now + this.parseExpiry(this.accessTokenExpiry);
      const refreshTokenExpiry = now + this.parseExpiry(refreshExpiry);
      
      return {
        accessToken,
        refreshToken,
        accessTokenExpiry,
        refreshTokenExpiry,
        tokenType: 'Bearer',
        organizationContext: basePayload.organizationId ? {
          organizationId: basePayload.organizationId,
          organizationType: basePayload.organizationType
        } : null
      };
    } catch (error) {
      logger.error('Token generation failed', { error, userId: user._id });
      throw new AppError('Failed to generate authentication tokens', 500, 'TOKEN_GENERATION_ERROR');
    }
  }
  
  /**
   * Generate single token
   * @param {Object} payload - Token payload
   * @param {string} type - Token type
   * @param {Object} options - Additional options
   * @returns {Promise<string>} Generated token
   */
  async generateToken(payload, type = 'access', options = {}) {
    try {
      const config = this.tokenConfigs[type];
      
      if (!config) {
        throw new Error(`Unknown token type: ${type}`);
      }
      
      const tokenOptions = {
        algorithm: config.algorithm,
        expiresIn: options.expiresIn || config.expiry,
        issuer: 'insightserenity',
        audience: 'insightserenity-platform',
        ...options
      };
      
      // Add standard claims
      const tokenPayload = {
        ...payload,
        iat: Math.floor(Date.now() / 1000),
        iss: tokenOptions.issuer,
        aud: tokenOptions.audience
      };
      
      return jwt.sign(tokenPayload, config.secret, tokenOptions);
    } catch (error) {
      logger.error('Token generation error', { error, type });
      throw error;
    }
  }
  
  /**
   * Verify token
   * @param {string} token - Token to verify
   * @param {string} type - Expected token type
   * @returns {Promise<Object>} Decoded token payload
   */
  async verifyToken(token, type = 'access') {
    try {
      const config = this.tokenConfigs[type];
      
      if (!config) {
        throw new TokenError(`Unknown token type: ${type}`, 'INVALID_TOKEN_TYPE');
      }
      
      const decoded = jwt.verify(token, config.secret, {
        algorithms: [config.algorithm],
        issuer: 'insightserenity',
        audience: 'insightserenity-platform'
      });
      
      // Verify token type
      if (decoded.type && decoded.type !== type) {
        throw new TokenError(`Invalid token type. Expected ${type}, got ${decoded.type}`, 'TOKEN_TYPE_MISMATCH');
      }
      
      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new TokenError('Token has expired', 'TOKEN_EXPIRED');
      }
      
      if (error.name === 'JsonWebTokenError') {
        throw new TokenError('Invalid token', 'TOKEN_INVALID');
      }
      
      throw error;
    }
  }
  
  /**
   * Verify access token
   * @param {string} token - Access token
   * @returns {Promise<Object>} Decoded token
   */
  async verifyAccessToken(token) {
    return this.verifyToken(token, 'access');
  }
  
  /**
   * Verify refresh token
   * @param {string} token - Refresh token
   * @returns {Promise<Object>} Decoded token
   */
  async verifyRefreshToken(token) {
    return this.verifyToken(token, 'refresh');
  }
  
  /**
   * Generate password reset token
   * @param {string} userId - User ID
   * @returns {Promise<string>} Reset token
   */
  async generateResetToken(userId) {
    const payload = {
      userId,
      type: 'reset',
      jti: this.generateTokenId(),
      purpose: 'password_reset'
    };
    
    return this.generateToken(payload, 'reset');
  }
  
  /**
   * Generate email verification token
   * @param {string} userId - User ID
   * @returns {Promise<string>} Verification token
   */
  async generateVerificationToken(userId) {
    const payload = {
      userId,
      type: 'verification',
      jti: this.generateTokenId(),
      purpose: 'email_verification'
    };
    
    return this.generateToken(payload, 'verification');
  }
  
  /**
   * Generate invitation token
   * @param {Object} invitationData - Invitation details
   * @returns {Promise<string>} Invitation token
   */
  async generateInvitationToken(invitationData) {
    const {
      email,
      organizationId,
      role,
      invitedBy,
      permissions = []
    } = invitationData;
    
    const payload = {
      email,
      organizationId,
      role,
      invitedBy,
      permissions,
      type: 'invitation',
      jti: this.generateTokenId(),
      purpose: 'user_invitation'
    };
    
    return this.generateToken(payload, 'invitation');
  }
  
  /**
   * Generate API key
   * @param {Object} keyData - API key data
   * @returns {Promise<Object>} API key and metadata
   */
  async generateAPIKey(keyData) {
    const {
      name,
      userId,
      organizationId,
      permissions = [],
      expiresAt
    } = keyData;
    
    // Generate key components
    const keyId = this.generateTokenId();
    const keySecret = EncryptionService.generateToken(32);
    const apiKey = `${keyId}.${keySecret}`;
    
    // Create key hash for storage
    const keyHash = EncryptionService.hash(apiKey);
    
    // Prepare metadata
    const metadata = {
      keyId,
      keyHash,
      name,
      userId,
      organizationId,
      permissions,
      createdAt: new Date(),
      expiresAt: expiresAt || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year default
      lastUsedAt: null,
      usageCount: 0
    };
    
    return {
      apiKey,
      metadata
    };
  }
  
  /**
   * Verify API key
   * @param {string} apiKey - API key to verify
   * @param {Object} storedMetadata - Stored key metadata
   * @returns {boolean} Is valid
   */
  verifyAPIKey(apiKey, storedMetadata) {
    try {
      const keyHash = EncryptionService.hash(apiKey);
      
      // Verify hash
      if (keyHash !== storedMetadata.keyHash) {
        return false;
      }
      
      // Check expiry
      if (storedMetadata.expiresAt && new Date() > new Date(storedMetadata.expiresAt)) {
        return false;
      }
      
      return true;
    } catch (error) {
      logger.error('API key verification error', { error });
      return false;
    }
  }
  
  /**
   * Decode token without verification
   * @param {string} token - Token to decode
   * @returns {Object|null} Decoded payload or null
   */
  decodeToken(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      return null;
    }
  }
  
  /**
   * Extract token from request
   * @param {Object} req - Express request object
   * @returns {string|null} Extracted token
   */
  extractTokenFromRequest(req) {
    // Check Authorization header
    const authHeader = req.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    
    // Check cookie
    if (req.cookies?.access_token) {
      return req.cookies.access_token;
    }
    
    // Check query parameter (for download links, etc.)
    if (req.query.token) {
      return req.query.token;
    }
    
    return null;
  }
  
  /**
   * Generate token ID
   * @returns {string} Unique token ID
   */
  generateTokenId() {
    return crypto.randomBytes(16).toString('hex');
  }
  
  /**
   * Generate session ID
   * @returns {string} Unique session ID
   */
  generateSessionId() {
    return `sess_${crypto.randomBytes(24).toString('hex')}`;
  }
  
  /**
   * Extract token ID from token
   * @param {string} token - JWT token
   * @returns {string|null} Token ID
   */
  extractTokenId(token) {
    try {
      const decoded = this.decodeToken(token);
      return decoded?.jti || null;
    } catch {
      return null;
    }
  }
  
  /**
   * Parse expiry string to milliseconds
   * @param {string} expiry - Expiry string (e.g., '15m', '7d')
   * @returns {number} Milliseconds
   */
  parseExpiry(expiry) {
    const units = {
      s: 1000,
      m: 60 * 1000,
      h: 60 * 60 * 1000,
      d: 24 * 60 * 60 * 1000
    };
    
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid expiry format: ${expiry}`);
    }
    
    const [, value, unit] = match;
    return parseInt(value) * units[unit];
  }
  
  /**
   * Create token validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  createValidationMiddleware(options = {}) {
    const {
      tokenType = 'access',
      required = true,
      checkBlacklist = true
    } = options;
    
    return async (req, res, next) => {
      try {
        // Extract token
        const token = this.extractTokenFromRequest(req);
        
        if (!token) {
          if (required) {
            return res.status(401).json({
              success: false,
              error: {
                message: 'Authentication token required',
                code: 'TOKEN_REQUIRED'
              }
            });
          }
          return next();
        }
        
        // Verify token
        const decoded = await this.verifyToken(token, tokenType);
        
        // Check blacklist if enabled
        if (checkBlacklist) {
          const TokenBlacklistService = require('../../security/services/token-blacklist-service');
          const isBlacklisted = await TokenBlacklistService.isBlacklisted(token);
          
          if (isBlacklisted) {
            return res.status(401).json({
              success: false,
              error: {
                message: 'Token has been revoked',
                code: 'TOKEN_REVOKED'
              }
            });
          }
        }
        
        // Attach decoded token to request
        req.token = decoded;
        req.tokenRaw = token;
        req.userId = decoded.userId;
        req.userRole = decoded.role;
        req.organizationId = decoded.organizationId;
        
        next();
      } catch (error) {
        if (error instanceof TokenError) {
          return res.status(401).json({
            success: false,
            error: {
              message: error.message,
              code: error.code
            }
          });
        }
        
        logger.error('Token validation error', { error });
        return res.status(500).json({
          success: false,
          error: {
            message: 'Token validation failed',
            code: 'TOKEN_VALIDATION_ERROR'
          }
        });
      }
    };
  }
}

// Create and export singleton instance
module.exports = new TokenService();