// server/admin/super-admin/middleware/emergency-bypass.js
/**
 * @file Emergency Bypass Middleware
 * @description Middleware for emergency bypass and override mechanisms
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

// Models
const EmergencyBypass = require('../../../shared/security/models/emergency-bypass-model');
const EmergencyAccess = require('../../../shared/security/models/emergency-access-model');
const AdminSession = require('../../../shared/admin/models/admin-session-model');
const SystemLock = require('../../../shared/security/models/system-lock-model');

// Services
const AuditService = require('../../../shared/security/services/audit-service');
const SecurityService = require('../../../shared/security/services/security-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const CacheService = require('../../../shared/utils/cache-service');

// Utilities
const { ForbiddenError, UnauthorizedError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

// Configuration
const config = require('../../../config');

/**
 * Emergency Bypass Middleware
 * Handles emergency access bypasses and system overrides
 */
class EmergencyBypassMiddleware {
  /**
   * Bypass types and their security levels
   */
  static bypassTypes = {
    AUTHENTICATION: {
      level: 1,
      description: 'Bypass authentication requirements',
      maxDuration: 3600 // 1 hour
    },
    AUTHORIZATION: {
      level: 2,
      description: 'Bypass authorization checks',
      maxDuration: 1800 // 30 minutes
    },
    RATE_LIMITING: {
      level: 1,
      description: 'Bypass rate limiting',
      maxDuration: 900 // 15 minutes
    },
    SECURITY_CHECKS: {
      level: 3,
      description: 'Bypass security validations',
      maxDuration: 600 // 10 minutes
    },
    SYSTEM_LOCKS: {
      level: 3,
      description: 'Bypass system locks and restrictions',
      maxDuration: 1800 // 30 minutes
    },
    FULL_OVERRIDE: {
      level: 4,
      description: 'Complete system override',
      maxDuration: 300 // 5 minutes
    }
  };

  /**
   * Check and apply emergency bypass
   * @param {Object} options - Bypass options
   * @returns {Function} Express middleware function
   */
  static check(options = {}) {
    const {
      allowedTypes = ['AUTHENTICATION', 'AUTHORIZATION'],
      requireActiveEmergencyAccess = true,
      validateBypassToken = true,
      monitorActions = true,
      alertOnUse = true
    } = options;

    return async (req, res, next) => {
      try {
        // Check for emergency bypass token
        const bypassToken = req.headers['x-emergency-bypass-token'];
        const emergencyAccessToken = req.headers['x-emergency-access-token'];

        if (!bypassToken && !emergencyAccessToken) {
          return next();
        }

        // Validate emergency access if required
        if (requireActiveEmergencyAccess && emergencyAccessToken) {
          const emergencyAccess = await this.validateEmergencyAccess(
            emergencyAccessToken,
            req.user
          );

          if (!emergencyAccess) {
            throw new ForbiddenError('Invalid or expired emergency access');
          }

          req.emergencyAccess = emergencyAccess;
        }

        // Process bypass token if provided
        if (bypassToken) {
          const bypass = await this.validateBypassToken(
            bypassToken,
            req.user,
            allowedTypes
          );

          if (!bypass) {
            throw new ForbiddenError('Invalid or expired bypass token');
          }

          // Apply bypass
          await this.applyBypass(req, res, bypass);

          // Monitor if enabled
          if (monitorActions) {
            await this.monitorBypassUsage(bypass, req);
          }

          // Alert if enabled
          if (alertOnUse) {
            await this.alertBypassUsage(bypass, req);
          }

          req.emergencyBypass = bypass;
        }

        next();

      } catch (error) {
        logger.error('Emergency bypass middleware error', {
          error: error.message,
          userId: req.user?.id,
          path: req.path,
          stack: error.stack
        });

        // Log security event
        await this.logSecurityEvent(req, error);

        next(error);
      }
    };
  }

  /**
   * Create emergency bypass
   * @param {Object} options - Bypass creation options
   * @returns {Function} Express middleware function
   */
  static create(options = {}) {
    const {
      bypassType,
      requireJustification = true,
      autoExpire = true,
      notifySecurityTeam = true
    } = options;

    return async (req, res, next) => {
      try {
        const user = req.user;
        
        if (!user || user.role?.primary !== 'super_admin') {
          throw new ForbiddenError('Super administrator access required to create bypass');
        }

        const {
          reason,
          duration = this.bypassTypes[bypassType]?.maxDuration || 600,
          targetSystems = [],
          restrictions = []
        } = req.body;

        // Validate justification
        if (requireJustification && (!reason || reason.length < 50)) {
          throw new ValidationError('Detailed justification required (minimum 50 characters)');
        }

        // Validate bypass type
        if (!this.bypassTypes[bypassType]) {
          throw new ValidationError(`Invalid bypass type: ${bypassType}`);
        }

        // Check duration limits
        const maxDuration = this.bypassTypes[bypassType].maxDuration;
        if (duration > maxDuration) {
          throw new ValidationError(`Duration exceeds maximum allowed (${maxDuration} seconds)`);
        }

        // Create bypass record
        const bypass = await this.createBypassRecord({
          type: bypassType,
          createdBy: user.id,
          reason,
          duration,
          targetSystems,
          restrictions,
          metadata: {
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            requestPath: req.originalUrl
          }
        });

        // Generate bypass token
        const token = await this.generateBypassToken(bypass);

        // Set up auto-expiration
        if (autoExpire) {
          await this.scheduleBypassExpiration(bypass);
        }

        // Notify security team
        if (notifySecurityTeam) {
          await this.notifySecurityTeamOfBypass(bypass, user);
        }

        // Audit bypass creation
        await this.auditBypassCreation(bypass, user, req);

        req.createdBypass = {
          id: bypass.id,
          token: token,
          expiresAt: bypass.expiresAt
        };

        next();

      } catch (error) {
        logger.error('Create emergency bypass error', {
          error: error.message,
          userId: req.user?.id,
          bypassType,
          stack: error.stack
        });

        next(error);
      }
    };
  }

  /**
   * Validate emergency access
   * @param {string} token - Emergency access token
   * @param {Object} user - User object
   * @returns {Promise<Object>} Emergency access data
   * @private
   */
  static async validateEmergencyAccess(token, user) {
    const emergencyAccess = await CacheService.get(`emergency_token:${token}`);

    if (!emergencyAccess) {
      // Check database
      const dbAccess = await EmergencyAccess.findOne({
        accessToken: token,
        status: 'active',
        expiresAt: { $gt: new Date() }
      });

      if (!dbAccess) {
        return null;
      }

      emergencyAccess = dbAccess.toObject();
    }

    // Validate user matches
    if (user && emergencyAccess.adminUserId !== user.id) {
      logger.warn('Emergency access token user mismatch', {
        tokenUser: emergencyAccess.adminUserId,
        requestUser: user.id
      });
      return null;
    }

    // Check if access is still valid
    if (new Date(emergencyAccess.expiresAt) < new Date()) {
      return null;
    }

    return emergencyAccess;
  }

  /**
   * Validate bypass token
   * @param {string} token - Bypass token
   * @param {Object} user - User object
   * @param {Array} allowedTypes - Allowed bypass types
   * @returns {Promise<Object>} Bypass data
   * @private
   */
  static async validateBypassToken(token, user, allowedTypes) {
    // Check cache first
    let bypass = await CacheService.get(`bypass:${token}`);

    if (!bypass) {
      // Check database
      const dbBypass = await EmergencyBypass.findOne({
        token: await this.hashToken(token),
        status: 'active',
        expiresAt: { $gt: new Date() }
      });

      if (!dbBypass) {
        return null;
      }

      bypass = dbBypass.toObject();
      
      // Cache for quick access
      await CacheService.set(
        `bypass:${token}`,
        bypass,
        Math.floor((new Date(bypass.expiresAt) - new Date()) / 1000)
      );
    }

    // Validate bypass type is allowed
    if (!allowedTypes.includes(bypass.type)) {
      logger.warn('Bypass type not allowed for this operation', {
        bypassType: bypass.type,
        allowedTypes
      });
      return null;
    }

    // Validate user if provided
    if (user && bypass.createdBy !== user.id && !bypass.sharedWith?.includes(user.id)) {
      logger.warn('Bypass token user mismatch', {
        bypassCreator: bypass.createdBy,
        requestUser: user.id
      });
      return null;
    }

    // Check usage limits
    if (bypass.usageCount >= (bypass.maxUsage || 100)) {
      logger.warn('Bypass token usage limit exceeded', {
        bypassId: bypass.id,
        usageCount: bypass.usageCount
      });
      return null;
    }

    return bypass;
  }

  /**
   * Apply bypass to request
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Object} bypass - Bypass data
   * @private
   */
  static async applyBypass(req, res, bypass) {
    // Set bypass flags based on type
    switch (bypass.type) {
      case 'AUTHENTICATION':
        req.bypassAuth = true;
        req.authenticated = true;
        break;

      case 'AUTHORIZATION':
        req.bypassAuthz = true;
        req.authorized = true;
        break;

      case 'RATE_LIMITING':
        req.bypassRateLimit = true;
        break;

      case 'SECURITY_CHECKS':
        req.bypassSecurity = true;
        req.skipSecurityValidation = true;
        break;

      case 'SYSTEM_LOCKS':
        req.bypassSystemLocks = true;
        break;

      case 'FULL_OVERRIDE':
        req.bypassAuth = true;
        req.bypassAuthz = true;
        req.bypassRateLimit = true;
        req.bypassSecurity = true;
        req.bypassSystemLocks = true;
        req.fullOverride = true;
        break;
    }

    // Set bypass headers
    res.setHeader('X-Emergency-Bypass-Active', 'true');
    res.setHeader('X-Bypass-Type', bypass.type);
    res.setHeader('X-Bypass-Expires', new Date(bypass.expiresAt).toISOString());

    // Update usage count
    await EmergencyBypass.findByIdAndUpdate(bypass._id || bypass.id, {
      $inc: { usageCount: 1 },
      $push: {
        usageLog: {
          timestamp: new Date(),
          path: req.path,
          method: req.method,
          ip: req.ip
        }
      }
    });
  }

  /**
   * Create bypass record
   * @param {Object} data - Bypass data
   * @returns {Promise<Object>} Created bypass
   * @private
   */
  static async createBypassRecord(data) {
    const bypassId = crypto.randomUUID();
    const token = crypto.randomBytes(32).toString('hex');
    const hashedToken = await this.hashToken(token);

    const bypass = new EmergencyBypass({
      bypassId,
      token: hashedToken,
      type: data.type,
      level: this.bypassTypes[data.type].level,
      createdBy: data.createdBy,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + data.duration * 1000),
      status: 'active',
      reason: data.reason,
      targetSystems: data.targetSystems,
      restrictions: data.restrictions,
      metadata: data.metadata,
      usageCount: 0,
      maxUsage: data.maxUsage || 100,
      securityLevel: this.bypassTypes[data.type].level
    });

    await bypass.save();

    // Store unhashed token in cache for quick validation
    await CacheService.set(
      `bypass:${token}`,
      bypass.toObject(),
      data.duration
    );

    return { ...bypass.toObject(), token };
  }

  /**
   * Generate bypass token
   * @param {Object} bypass - Bypass record
   * @returns {Promise<string>} Bypass token
   * @private
   */
  static async generateBypassToken(bypass) {
    // Token is already generated in createBypassRecord
    return bypass.token;
  }

  /**
   * Hash token for storage
   * @param {string} token - Plain token
   * @returns {Promise<string>} Hashed token
   * @private
   */
  static async hashToken(token) {
    return crypto
      .createHash('sha256')
      .update(token + config.auth.jwtSecret)
      .digest('hex');
  }

  /**
   * Schedule bypass expiration
   * @param {Object} bypass - Bypass record
   * @private
   */
  static async scheduleBypassExpiration(bypass) {
    const expirationTime = new Date(bypass.expiresAt).getTime() - Date.now();
    
    if (expirationTime > 0) {
      setTimeout(async () => {
        await this.expireBypass(bypass.bypassId);
      }, expirationTime);
    }
  }

  /**
   * Expire bypass
   * @param {string} bypassId - Bypass ID
   * @private
   */
  static async expireBypass(bypassId) {
    try {
      const bypass = await EmergencyBypass.findOne({ bypassId });
      
      if (bypass && bypass.status === 'active') {
        bypass.status = 'expired';
        bypass.expiredAt = new Date();
        await bypass.save();

        // Clear from cache
        await CacheService.delete(`bypass:*`); // Clear all bypass tokens

        // Log expiration
        await AuditService.log({
          userId: bypass.createdBy,
          action: AdminEvents.EMERGENCY_ACCESS.BYPASS_EXPIRED,
          resource: `bypass.${bypass.type}`,
          severity: 'medium',
          metadata: {
            bypassId: bypass.bypassId,
            type: bypass.type,
            usageCount: bypass.usageCount
          }
        });
      }
    } catch (error) {
      logger.error('Error expiring bypass', {
        error: error.message,
        bypassId
      });
    }
  }

  /**
   * Monitor bypass usage
   * @param {Object} bypass - Bypass data
   * @param {Object} req - Express request object
   * @private
   */
  static async monitorBypassUsage(bypass, req) {
    const monitoringData = {
      bypassId: bypass.bypassId,
      type: bypass.type,
      timestamp: new Date(),
      request: {
        method: req.method,
        path: req.path,
        query: req.query,
        body: this.sanitizeRequestData(req.body)
      },
      user: req.user?.id,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    };

    // Store monitoring data
    await CacheService.lpush(
      `bypass_monitoring:${bypass.bypassId}`,
      JSON.stringify(monitoringData)
    );

    // Set expiration on monitoring data
    await CacheService.expire(
      `bypass_monitoring:${bypass.bypassId}`,
      86400 // 24 hours
    );

    // Check for suspicious patterns
    await this.checkSuspiciousPatterns(bypass, monitoringData);
  }

  /**
   * Check for suspicious patterns
   * @param {Object} bypass - Bypass data
   * @param {Object} monitoringData - Monitoring data
   * @private
   */
  static async checkSuspiciousPatterns(bypass, monitoringData) {
    // Get recent usage
    const recentUsage = await CacheService.lrange(
      `bypass_monitoring:${bypass.bypassId}`,
      0,
      100
    );

    const usageData = recentUsage.map(item => JSON.parse(item));

    // Check for rapid usage
    const recentCount = usageData.filter(
      item => new Date(item.timestamp) > new Date(Date.now() - 60000) // Last minute
    ).length;

    if (recentCount > 10) {
      await SecurityService.reportSuspiciousActivity({
        type: 'bypass_rapid_usage',
        bypassId: bypass.bypassId,
        userId: bypass.createdBy,
        severity: 'high',
        details: {
          recentCount,
          monitoringData
        }
      });
    }

    // Check for unusual paths
    const uniquePaths = [...new Set(usageData.map(item => item.request.path))];
    
    if (uniquePaths.length > 20) {
      await SecurityService.reportSuspiciousActivity({
        type: 'bypass_excessive_paths',
        bypassId: bypass.bypassId,
        userId: bypass.createdBy,
        severity: 'medium',
        details: {
          pathCount: uniquePaths.length,
          paths: uniquePaths.slice(0, 10)
        }
      });
    }
  }

  /**
   * Alert bypass usage
   * @param {Object} bypass - Bypass data
   * @param {Object} req - Express request object
   * @private
   */
  static async alertBypassUsage(bypass, req) {
    // Only alert for high-level bypasses
    if (bypass.level >= 3) {
      await NotificationService.sendSecurityAlert({
        type: 'emergency_bypass_used',
        severity: bypass.level === 4 ? 'critical' : 'high',
        data: {
          bypassType: bypass.type,
          bypassId: bypass.bypassId,
          usedBy: req.user?.email || 'Unknown',
          path: req.path,
          method: req.method,
          ip: req.ip
        },
        recipients: ['security-team', 'super-admins']
      });
    }
  }

  /**
   * Notify security team of bypass creation
   * @param {Object} bypass - Bypass record
   * @param {Object} user - Creating user
   * @private
   */
  static async notifySecurityTeamOfBypass(bypass, user) {
    await NotificationService.notifySecurityTeam({
      type: 'emergency_bypass_created',
      priority: 'high',
      data: {
        bypassType: bypass.type,
        bypassId: bypass.bypassId,
        createdBy: user.email,
        reason: bypass.reason,
        duration: bypass.expiresAt - bypass.createdAt,
        level: bypass.level
      }
    });
  }

  /**
   * Audit bypass creation
   * @param {Object} bypass - Bypass record
   * @param {Object} user - Creating user
   * @param {Object} req - Express request object
   * @private
   */
  static async auditBypassCreation(bypass, user, req) {
    await AuditService.log({
      userId: user.id,
      action: AdminEvents.EMERGENCY_ACCESS.BYPASS_CREATED,
      resource: `bypass.${bypass.type}`,
      severity: 'critical',
      metadata: {
        bypassId: bypass.bypassId,
        type: bypass.type,
        level: bypass.level,
        duration: bypass.expiresAt - bypass.createdAt,
        reason: bypass.reason,
        targetSystems: bypass.targetSystems,
        ip: req.ip,
        userAgent: req.headers['user-agent']
      }
    });
  }

  /**
   * Log security event
   * @param {Object} req - Express request object
   * @param {Error} error - Error object
   * @private
   */
  static async logSecurityEvent(req, error) {
    await SecurityService.logSecurityEvent({
      type: 'bypass_error',
      severity: 'high',
      userId: req.user?.id,
      error: {
        message: error.message,
        code: error.code
      },
      request: {
        path: req.path,
        method: req.method,
        ip: req.ip
      }
    });
  }

  /**
   * Sanitize request data for logging
   * @param {Object} data - Request data
   * @returns {Object} Sanitized data
   * @private
   */
  static sanitizeRequestData(data) {
    if (!data) return {};

    const sensitiveFields = [
      'password',
      'token',
      'secret',
      'apiKey',
      'authorization'
    ];

    const sanitized = { ...data };

    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '***REDACTED***';
      }
    }

    return sanitized;
  }

  /**
   * Revoke bypass
   * @param {string} bypassId - Bypass ID
   * @param {Object} user - User revoking bypass
   * @param {string} reason - Revocation reason
   * @returns {Promise<void>}
   */
  static async revokeBypass(bypassId, user, reason) {
    const bypass = await EmergencyBypass.findOne({ bypassId });

    if (!bypass) {
      throw new NotFoundError('Bypass not found');
    }

    if (bypass.status !== 'active') {
      throw new ValidationError('Bypass is not active');
    }

    bypass.status = 'revoked';
    bypass.revokedAt = new Date();
    bypass.revokedBy = user.id;
    bypass.revocationReason = reason;

    await bypass.save();

    // Clear from cache
    await CacheService.delete(`bypass:*`);

    // Audit revocation
    await AuditService.log({
      userId: user.id,
      action: AdminEvents.EMERGENCY_ACCESS.BYPASS_REVOKED,
      resource: `bypass.${bypass.type}`,
      severity: 'high',
      metadata: {
        bypassId: bypass.bypassId,
        type: bypass.type,
        reason,
        usageCount: bypass.usageCount
      }
    });

    // Notify creator
    if (bypass.createdBy !== user.id) {
      await NotificationService.sendAdminNotification({
        userId: bypass.createdBy,
        type: 'bypass_revoked',
        priority: 'high',
        data: {
          bypassId: bypass.bypassId,
          revokedBy: user.email,
          reason
        }
      });
    }
  }
}

module.exports = EmergencyBypassMiddleware;