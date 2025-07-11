/**
 * @file Admin Authentication Middleware
 * @description Enhanced authentication middleware for administrative operations with elevated security controls
 * @version 1.0.0
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const config = require('../../../config/config');
const { asyncHandler } = require('../../../utils/async-handler');
const { AuthenticationError, AppError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../../audit/services/audit-service');
const EncryptionService = require('../../../security/services/encryption-service');
const User = require('../../../users/models/user-model');
const Auth = require('../../../auth/models/auth-model');
const TokenBlacklistService = require('../../../security/services/token-blacklist-service');

/**
 * Admin Authentication Middleware Class
 * @class AdminAuthMiddleware
 */
class AdminAuthMiddleware {
  /**
   * Verify admin token with enhanced security checks
   * @param {Object} options - Authentication options
   * @returns {Function} Express middleware
   */
  static authenticateAdmin(options = {}) {
    const {
      requireMFA = true,
      requireActiveSession = true,
      sessionTimeout = 3600000, // 1 hour for admin sessions
      allowAPIKey = false,
      elevatedPrivileges = false
    } = options;

    return asyncHandler(async (req, res, next) => {
      let token;
      let authMethod = 'bearer';

      // Extract token from various sources
      if (req.headers.authorization?.startsWith('Bearer ')) {
        token = req.headers.authorization.split(' ')[1];
      } else if (req.cookies?.adminJwt) {
        token = req.cookies.adminJwt;
        authMethod = 'cookie';
      } else if (allowAPIKey && req.headers['x-admin-api-key']) {
        return this.authenticateAdminAPIKey(req, res, next);
      }

      if (!token) {
        throw new AuthenticationError('Admin authentication required');
      }

      // Check token blacklist
      const isBlacklisted = await TokenBlacklistService.isBlacklisted(token);
      if (isBlacklisted) {
        await AuditService.log({
          type: 'admin_auth_blocked',
          action: 'authenticate',
          category: 'security',
          result: 'blocked',
          severity: 'high',
          metadata: {
            reason: 'blacklisted_token',
            ip: req.ip,
            userAgent: req.get('user-agent')
          }
        });
        throw new AuthenticationError('Token has been revoked');
      }

      try {
        // Verify token with strict validation
        const decoded = jwt.verify(token, config.auth.jwtSecret, {
          issuer: config.auth.jwt.issuer,
          audience: 'InsightSerenity-Admin',
          algorithms: [config.auth.jwt.algorithm]
        });

        // Validate token type
        if (decoded.type !== 'admin-access') {
          throw new AuthenticationError('Invalid token type for admin access');
        }

        // Load user with admin verification
        const user = await User.findById(decoded.id)
          .select('+active +lastPasswordChange +adminAccess')
          .populate('role.permissions');

        if (!user || !user.active) {
          throw new AuthenticationError('Admin account not found or inactive');
        }

        // Verify admin role
        const adminRoles = ['super_admin', 'platform_admin', 'admin', 'organization_admin'];
        if (!adminRoles.includes(user.role?.primary)) {
          throw new AuthenticationError('Insufficient privileges for admin access');
        }

        // Check password change after token issue
        if (user.lastPasswordChange && decoded.iat * 1000 < user.lastPasswordChange.getTime()) {
          await TokenBlacklistService.blacklist(token, 'password_changed');
          throw new AuthenticationError('Password changed, please re-authenticate');
        }

        // Load auth record for additional checks
        const authRecord = await Auth.findOne({ userId: user._id });
        if (!authRecord) {
          throw new AuthenticationError('Authentication record not found');
        }

        // Verify MFA if required
        if (requireMFA && authRecord.security.twoFactorEnabled) {
          if (!decoded.mfaVerified || decoded.mfaVerifiedAt < Date.now() - 3600000) {
            throw new AuthenticationError('MFA verification required for admin access');
          }
        }

        // Verify active session if required
        if (requireActiveSession) {
          const session = authRecord.sessions.find(s => 
            s.sessionId === decoded.sessionId && 
            s.active && 
            s.expiresAt > new Date()
          );

          if (!session) {
            throw new AuthenticationError('Invalid or expired admin session');
          }

          // Check session timeout
          const lastActivity = new Date(session.lastActivity);
          if (Date.now() - lastActivity.getTime() > sessionTimeout) {
            session.active = false;
            await authRecord.save();
            throw new AuthenticationError('Admin session timeout');
          }

          // Update last activity
          session.lastActivity = new Date();
          session.metadata.lastEndpoint = req.originalUrl;
          await authRecord.save();
        }

        // Check for elevated privileges requirement
        if (elevatedPrivileges) {
          const elevatedExpiry = decoded.elevatedUntil || 0;
          if (elevatedExpiry < Date.now()) {
            throw new AuthenticationError('Elevated privileges required. Please re-authenticate.');
          }
        }

        // Set request context
        req.user = user;
        req.adminAuth = {
          token,
          decoded,
          method: authMethod,
          sessionId: decoded.sessionId,
          mfaVerified: decoded.mfaVerified || false,
          elevatedPrivileges: (decoded.elevatedUntil || 0) > Date.now(),
          permissions: user.role?.permissions || []
        };
        
        // Set response locals for view rendering
        res.locals.user = user;
        res.locals.isAdmin = true;

        // Audit successful admin authentication
        await AuditService.log({
          type: 'admin_auth_success',
          action: 'authenticate',
          category: 'authentication',
          result: 'success',
          userId: user._id,
          target: {
            type: 'endpoint',
            id: req.originalUrl
          },
          metadata: {
            method: authMethod,
            sessionId: decoded.sessionId,
            mfaVerified: decoded.mfaVerified,
            elevatedPrivileges: req.adminAuth.elevatedPrivileges,
            ip: req.ip,
            userAgent: req.get('user-agent')
          }
        });

        next();
      } catch (error) {
        // Log authentication failure
        await AuditService.log({
          type: 'admin_auth_failed',
          action: 'authenticate',
          category: 'authentication',
          result: 'failure',
          severity: 'high',
          metadata: {
            error: error.message,
            method: authMethod,
            ip: req.ip,
            userAgent: req.get('user-agent')
          }
        });

        if (error.name === 'JsonWebTokenError') {
          throw new AuthenticationError('Invalid admin token');
        } else if (error.name === 'TokenExpiredError') {
          throw new AuthenticationError('Admin token expired');
        }
        
        throw error;
      }
    });
  }

  /**
   * Authenticate using admin API key
   * @param {Object} req - Express request
   * @param {Object} res - Express response
   * @param {Function} next - Express next
   */
  static async authenticateAdminAPIKey(req, res, next) {
    try {
      const apiKey = req.headers['x-admin-api-key'];
      const signature = req.headers['x-admin-signature'];

      if (!apiKey || !signature) {
        throw new AuthenticationError('Admin API key and signature required');
      }

      // Verify API key format
      const keyPattern = /^adm_[a-zA-Z0-9]{32}$/;
      if (!keyPattern.test(apiKey)) {
        throw new AuthenticationError('Invalid admin API key format');
      }

      // Load API key from auth record
      const authRecord = await Auth.findOne({
        'adminApiKeys.key': apiKey,
        'adminApiKeys.active': true
      });

      if (!authRecord) {
        throw new AuthenticationError('Invalid admin API key');
      }

      const apiKeyData = authRecord.adminApiKeys.find(k => k.key === apiKey);

      // Check expiration
      if (apiKeyData.expiresAt && apiKeyData.expiresAt < new Date()) {
        apiKeyData.active = false;
        await authRecord.save();
        throw new AuthenticationError('Admin API key expired');
      }

      // Verify signature
      const encryptionService = new EncryptionService();
      const payload = `${req.method}:${req.originalUrl}:${JSON.stringify(req.body)}`;
      const expectedSignature = encryptionService.sign(payload, apiKeyData.secret);

      if (signature !== expectedSignature) {
        throw new AuthenticationError('Invalid API request signature');
      }

      // Check rate limits
      const now = new Date();
      const windowStart = new Date(now.getTime() - 3600000); // 1 hour window
      const recentUsage = apiKeyData.usage.filter(u => u.timestamp > windowStart);

      if (recentUsage.length >= apiKeyData.rateLimit) {
        throw new AuthenticationError('Admin API rate limit exceeded');
      }

      // Load user
      const user = await User.findById(authRecord.userId)
        .select('+active +adminAccess')
        .populate('role.permissions');

      if (!user || !user.active) {
        throw new AuthenticationError('Admin account not found or inactive');
      }

      // Update usage
      apiKeyData.usage.push({
        timestamp: now,
        endpoint: req.originalUrl,
        ip: req.ip
      });
      apiKeyData.lastUsed = now;

      // Keep only recent usage (last 24 hours)
      const dayAgo = new Date(now.getTime() - 86400000);
      apiKeyData.usage = apiKeyData.usage.filter(u => u.timestamp > dayAgo);

      await authRecord.save();

      // Set request context
      req.user = user;
      req.adminAuth = {
        method: 'apikey',
        apiKey: apiKey.substring(0, 8) + '...',
        permissions: apiKeyData.permissions || user.role?.permissions || []
      };

      // Audit API key usage
      await AuditService.log({
        type: 'admin_api_key_used',
        action: 'authenticate',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        target: {
          type: 'endpoint',
          id: req.originalUrl
        },
        metadata: {
          apiKeyId: apiKeyData._id,
          endpoint: req.originalUrl,
          method: req.method,
          ip: req.ip,
          userAgent: req.get('user-agent')
        }
      });

      next();
    } catch (error) {
      await AuditService.log({
        type: 'admin_api_key_failed',
        action: 'authenticate',
        category: 'authentication',
        result: 'failure',
        severity: 'high',
        metadata: {
          error: error.message,
          endpoint: req.originalUrl,
          ip: req.ip,
          userAgent: req.get('user-agent')
        }
      });

      next(error);
    }
  }

  /**
   * Require elevated authentication for sensitive operations
   * @param {Object} options - Elevation options
   * @returns {Function} Express middleware
   */
  static requireElevatedAuth(options = {}) {
    const {
      duration = 300000, // 5 minutes
      reason = 'sensitive operation'
    } = options;

    return asyncHandler(async (req, res, next) => {
      if (!req.adminAuth) {
        throw new AuthenticationError('Admin authentication required');
      }

      if (!req.adminAuth.elevatedPrivileges) {
        // Return 402 to trigger re-authentication flow
        return res.status(402).json({
          success: false,
          error: 'Elevated authentication required',
          data: {
            reason,
            duration,
            authUrl: '/api/admin/auth/elevate'
          }
        });
      }

      next();
    });
  }

  /**
   * Verify admin session is still valid
   * @param {Object} req - Express request
   * @returns {Promise<boolean>} Session validity
   */
  static async verifyAdminSession(req) {
    if (!req.adminAuth?.sessionId || !req.user?._id) {
      return false;
    }

    const authRecord = await Auth.findOne({ userId: req.user._id });
    if (!authRecord) {
      return false;
    }

    const session = authRecord.sessions.find(s => 
      s.sessionId === req.adminAuth.sessionId && 
      s.active && 
      s.expiresAt > new Date()
    );

    return !!session;
  }

  /**
   * Refresh admin authentication
   * @param {Object} req - Express request
   * @param {Object} res - Express response
   * @param {Function} next - Express next
   */
  static refreshAdminAuth = asyncHandler(async (req, res, next) => {
    if (!req.adminAuth || !await this.verifyAdminSession(req)) {
      throw new AuthenticationError('Invalid admin session');
    }

    // Generate new token with refreshed expiry
    const newToken = jwt.sign({
      id: req.user._id,
      type: 'admin-access',
      sessionId: req.adminAuth.sessionId,
      mfaVerified: req.adminAuth.mfaVerified,
      elevatedUntil: req.adminAuth.elevatedPrivileges ? Date.now() + 300000 : 0
    }, config.auth.jwtSecret, {
      expiresIn: '1h',
      issuer: config.auth.jwt.issuer,
      audience: 'InsightSerenity-Admin'
    });

    // Set new token in response
    res.setHeader('X-Admin-Token', newToken);
    
    if (req.cookies?.adminJwt) {
      res.cookie('adminJwt', newToken, {
        httpOnly: true,
        secure: config.security.ssl.enabled,
        sameSite: 'strict',
        maxAge: 3600000 // 1 hour
      });
    }

    next();
  });
}

module.exports = AdminAuthMiddleware;