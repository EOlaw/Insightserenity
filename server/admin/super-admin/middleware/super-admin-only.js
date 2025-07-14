// server/admin/super-admin/middleware/super-admin-only.js
/**
 * @file Super Admin Only Middleware
 * @description Middleware to ensure only super administrators can access protected routes
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Models
const User = require('../../../shared/users/models/user-model');
const AdminSession = require('../../../shared/admin/models/admin-session-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');

// Services
const AuditService = require('../../../shared/security/services/audit-service');
const SecurityService = require('../../../shared/security/services/security-service');
const CacheService = require('../../../shared/utils/cache-service');

// Utilities
const { ForbiddenError, UnauthorizedError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

// Configuration
const config = require('../../../config');

/**
 * Super Admin Only Middleware
 * Validates that the requesting user has super administrator privileges
 */
class SuperAdminOnlyMiddleware {
  /**
   * Main middleware function
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware function
   */
  static enforce(options = {}) {
    const {
      requireMFA = true,
      requireActiveSession = true,
      checkIPWhitelist = true,
      auditAccess = true,
      allowEmergencyAccess = false,
      customPermission = null
    } = options;

    return async (req, res, next) => {
      try {
        const user = req.user;
        const requestId = req.id || req.headers['x-request-id'];

        // Basic authentication check
        if (!user) {
          throw new UnauthorizedError('Authentication required');
        }

        // Check if user is super admin
        const isSuperAdmin = await this.validateSuperAdminRole(user);
        if (!isSuperAdmin && !allowEmergencyAccess) {
          await this.logUnauthorizedAccess(user, req);
          throw new ForbiddenError('Super administrator access required');
        }

        // Check for emergency access if not super admin
        if (!isSuperAdmin && allowEmergencyAccess) {
          const hasEmergencyAccess = await this.checkEmergencyAccess(user, req);
          if (!hasEmergencyAccess) {
            await this.logUnauthorizedAccess(user, req);
            throw new ForbiddenError('Super administrator or emergency access required');
          }
        }

        // Validate MFA if required
        if (requireMFA && !await this.validateMFA(user)) {
          throw new ForbiddenError('Multi-factor authentication required for super admin access');
        }

        // Check active admin session
        if (requireActiveSession) {
          const hasValidSession = await this.validateAdminSession(user);
          if (!hasValidSession) {
            throw new ForbiddenError('Valid admin session required');
          }
        }

        // Validate IP whitelist
        if (checkIPWhitelist) {
          const isIPAllowed = await this.validateIPWhitelist(user, req);
          if (!isIPAllowed) {
            await this.logSuspiciousAccess(user, req);
            throw new ForbiddenError('Access denied from this IP address');
          }
        }

        // Check custom permission if specified
        if (customPermission) {
          const hasPermission = await this.checkCustomPermission(user, customPermission);
          if (!hasPermission) {
            throw new ForbiddenError(`Required permission not found: ${customPermission}`);
          }
        }

        // Additional security checks
        await this.performSecurityChecks(user, req);

        // Audit successful access
        if (auditAccess) {
          await this.auditSuperAdminAccess(user, req, true);
        }

        // Add super admin context to request
        req.superAdmin = {
          userId: user.id,
          permissions: await this.getSuperAdminPermissions(user),
          sessionId: req.adminSession?.id,
          emergencyAccess: !isSuperAdmin && allowEmergencyAccess
        };

        // Set response headers
        res.setHeader('X-Super-Admin-Access', 'true');
        res.setHeader('X-Admin-Session-ID', req.adminSession?.id || 'none');

        next();

      } catch (error) {
        logger.error('Super admin middleware error', {
          error: error.message,
          userId: req.user?.id,
          path: req.path,
          method: req.method,
          stack: error.stack
        });

        // Audit failed access attempt
        if (auditAccess && req.user) {
          await this.auditSuperAdminAccess(req.user, req, false, error.message);
        }

        next(error);
      }
    };
  }

  /**
   * Validate super admin role
   * @param {Object} user - User object
   * @returns {Promise<boolean>} Is super admin
   * @private
   */
  static async validateSuperAdminRole(user) {
    // Check primary role
    if (user.role?.primary === 'super_admin') {
      return true;
    }

    // Check permissions
    const hasSystemPermission = user.permissions?.system?.some(
      perm => perm.resource === AdminPermissions.SUPER_ADMIN.FULL_ACCESS && 
              perm.actions.includes('*')
    );

    if (hasSystemPermission) {
      return true;
    }

    // Check in database for recent role changes
    const freshUser = await User.findById(user.id)
      .select('role permissions')
      .lean();

    return freshUser?.role?.primary === 'super_admin' ||
           freshUser?.permissions?.system?.some(
             perm => perm.resource === AdminPermissions.SUPER_ADMIN.FULL_ACCESS
           );
  }

  /**
   * Check emergency access
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @returns {Promise<boolean>} Has emergency access
   * @private
   */
  static async checkEmergencyAccess(user, req) {
    const emergencyToken = req.headers['x-emergency-access-token'];
    
    if (!emergencyToken) {
      return false;
    }

    // Validate emergency access token
    const emergencyAccess = await CacheService.get(`emergency_token:${emergencyToken}`);
    
    if (!emergencyAccess) {
      return false;
    }

    // Check if token belongs to user
    if (emergencyAccess.adminUserId !== user.id) {
      await this.logSuspiciousAccess(user, req, 'Invalid emergency token usage');
      return false;
    }

    // Check if token is still valid
    if (new Date(emergencyAccess.expiresAt) < new Date()) {
      return false;
    }

    // Add emergency access context
    req.emergencyAccess = {
      id: emergencyAccess.id,
      type: emergencyAccess.accessType,
      expiresAt: emergencyAccess.expiresAt
    };

    return true;
  }

  /**
   * Validate MFA
   * @param {Object} user - User object
   * @returns {Promise<boolean>} MFA validated
   * @private
   */
  static async validateMFA(user) {
    // Check if MFA is enabled for user
    if (!user.auth?.twoFactor?.enabled) {
      return false;
    }

    // Check MFA verification status
    if (!user.auth?.mfaVerified) {
      return false;
    }

    // Check MFA verification timestamp
    const mfaVerifiedAt = user.auth?.mfaVerifiedAt;
    if (!mfaVerifiedAt) {
      return false;
    }

    // Ensure MFA was verified recently (within session timeout)
    const mfaTimeout = AdminSecurityConfig.mfa.superAdminTimeout || 3600000; // 1 hour
    const timeSinceVerification = Date.now() - new Date(mfaVerifiedAt).getTime();

    return timeSinceVerification < mfaTimeout;
  }

  /**
   * Validate admin session
   * @param {Object} user - User object
   * @returns {Promise<boolean>} Has valid session
   * @private
   */
  static async validateAdminSession(user) {
    const session = await AdminSession.findOne({
      adminUserId: user.id,
      type: 'admin',
      isActive: true,
      expiresAt: { $gt: new Date() }
    }).lean();

    if (!session) {
      return false;
    }

    // Validate session integrity
    if (session.securityHash) {
      const expectedHash = await SecurityService.generateSessionHash(session);
      if (session.securityHash !== expectedHash) {
        logger.warn('Admin session integrity check failed', {
          userId: user.id,
          sessionId: session._id
        });
        return false;
      }
    }

    return true;
  }

  /**
   * Validate IP whitelist
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @returns {Promise<boolean>} IP allowed
   * @private
   */
  static async validateIPWhitelist(user, req) {
    const clientIP = req.ip || req.connection.remoteAddress;

    // Check global super admin IP whitelist
    const globalWhitelist = AdminSecurityConfig.superAdmin.ipWhitelist || [];
    if (globalWhitelist.length > 0) {
      const isGloballyAllowed = await SecurityService.checkIPWhitelist(
        clientIP,
        globalWhitelist
      );

      if (!isGloballyAllowed) {
        return false;
      }
    }

    // Check user-specific IP restrictions
    if (user.security?.ipWhitelist && user.security.ipWhitelist.length > 0) {
      const isUserAllowed = await SecurityService.checkIPWhitelist(
        clientIP,
        user.security.ipWhitelist
      );

      if (!isUserAllowed) {
        return false;
      }
    }

    return true;
  }

  /**
   * Check custom permission
   * @param {Object} user - User object
   * @param {string} permission - Permission to check
   * @returns {Promise<boolean>} Has permission
   * @private
   */
  static async checkCustomPermission(user, permission) {
    // Parse permission format: resource.action
    const [resource, action] = permission.split('.');

    // Check in user permissions
    const hasPermission = user.permissions?.system?.some(
      perm => (perm.resource === resource || perm.resource === '*') &&
              (perm.actions.includes(action) || perm.actions.includes('*'))
    );

    return hasPermission;
  }

  /**
   * Perform additional security checks
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @private
   */
  static async performSecurityChecks(user, req) {
    // Check for account security flags
    if (user.security?.locked) {
      throw new ForbiddenError('Account is locked');
    }

    if (user.security?.suspended) {
      throw new ForbiddenError('Account is suspended');
    }

    // Check for suspicious activity patterns
    const recentFailedAttempts = await this.getRecentFailedAttempts(user.id);
    if (recentFailedAttempts > AdminSecurityConfig.superAdmin.maxFailedAttempts) {
      await this.lockAccount(user.id);
      throw new ForbiddenError('Too many failed access attempts');
    }

    // Validate request signature for critical operations
    if (req.method !== 'GET' && AdminSecurityConfig.superAdmin.requireRequestSignature) {
      const isValidSignature = await this.validateRequestSignature(req);
      if (!isValidSignature) {
        throw new ForbiddenError('Invalid request signature');
      }
    }

    // Check time-based restrictions
    if (user.security?.accessHours) {
      const isWithinAccessHours = await this.checkAccessHours(
        user.security.accessHours,
        user.timezone
      );

      if (!isWithinAccessHours) {
        throw new ForbiddenError('Access denied outside permitted hours');
      }
    }
  }

  /**
   * Get super admin permissions
   * @param {Object} user - User object
   * @returns {Promise<Array>} Permissions array
   * @private
   */
  static async getSuperAdminPermissions(user) {
    const cacheKey = `super_admin_permissions:${user.id}`;
    const cached = await CacheService.get(cacheKey);

    if (cached) {
      return cached;
    }

    // Get all super admin permissions
    const permissions = [
      AdminPermissions.SUPER_ADMIN.FULL_ACCESS,
      AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS,
      AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT,
      AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS,
      AdminPermissions.SUPER_ADMIN.USER_MANAGEMENT,
      AdminPermissions.SUPER_ADMIN.ORGANIZATION_MANAGEMENT,
      AdminPermissions.SUPER_ADMIN.SECURITY_MANAGEMENT,
      AdminPermissions.SUPER_ADMIN.AUDIT_MANAGEMENT,
      AdminPermissions.SUPER_ADMIN.BACKUP_MANAGEMENT,
      AdminPermissions.SUPER_ADMIN.SYSTEM_MAINTENANCE
    ];

    // Cache for 5 minutes
    await CacheService.set(cacheKey, permissions, 300);

    return permissions;
  }

  /**
   * Audit super admin access
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @param {boolean} success - Access granted
   * @param {string} reason - Failure reason
   * @private
   */
  static async auditSuperAdminAccess(user, req, success, reason = null) {
    const auditData = {
      userId: user.id,
      userEmail: user.email,
      action: success ? 
        AdminEvents.SUPER_ADMIN.ACCESS_GRANTED : 
        AdminEvents.SUPER_ADMIN.ACCESS_DENIED,
      resource: req.path,
      method: req.method,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'],
      success,
      reason,
      metadata: {
        superAdmin: true,
        emergencyAccess: !!req.emergencyAccess,
        sessionId: req.adminSession?.id,
        requestId: req.id || req.headers['x-request-id']
      }
    };

    await AuditService.log(auditData);

    // Alert on failed attempts
    if (!success) {
      await SecurityService.alertSecurityTeam({
        event: 'super_admin_access_denied',
        user: user.email,
        reason,
        ip: auditData.ip,
        path: req.path
      });
    }
  }

  /**
   * Log unauthorized access attempt
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @private
   */
  static async logUnauthorizedAccess(user, req) {
    logger.warn('Unauthorized super admin access attempt', {
      userId: user.id,
      userEmail: user.email,
      userRole: user.role?.primary,
      path: req.path,
      method: req.method,
      ip: req.ip || req.connection.remoteAddress
    });

    await AuditService.log({
      userId: user.id,
      action: AdminEvents.SUPER_ADMIN.UNAUTHORIZED_ACCESS_ATTEMPT,
      resource: req.path,
      severity: 'high',
      metadata: {
        userRole: user.role?.primary,
        method: req.method,
        ip: req.ip || req.connection.remoteAddress
      }
    });
  }

  /**
   * Log suspicious access
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @param {string} reason - Suspicious activity reason
   * @private
   */
  static async logSuspiciousAccess(user, req, reason = 'Unknown') {
    logger.error('Suspicious super admin access detected', {
      userId: user.id,
      userEmail: user.email,
      reason,
      path: req.path,
      method: req.method,
      ip: req.ip || req.connection.remoteAddress
    });

    await SecurityService.reportSuspiciousActivity({
      userId: user.id,
      activityType: 'super_admin_access',
      reason,
      severity: 'critical',
      details: {
        path: req.path,
        method: req.method,
        ip: req.ip || req.connection.remoteAddress,
        headers: req.headers
      }
    });
  }

  /**
   * Get recent failed attempts
   * @param {string} userId - User ID
   * @returns {Promise<number>} Failed attempt count
   * @private
   */
  static async getRecentFailedAttempts(userId) {
    const timeWindow = AdminSecurityConfig.superAdmin.failedAttemptWindow || 900000; // 15 minutes
    
    const count = await AuditLog.countDocuments({
      userId,
      action: AdminEvents.SUPER_ADMIN.ACCESS_DENIED,
      timestamp: { $gte: new Date(Date.now() - timeWindow) }
    });

    return count;
  }

  /**
   * Lock account due to security violations
   * @param {string} userId - User ID
   * @private
   */
  static async lockAccount(userId) {
    await User.findByIdAndUpdate(userId, {
      $set: {
        'security.locked': true,
        'security.lockedAt': new Date(),
        'security.lockReason': 'Too many failed super admin access attempts'
      }
    });

    await SecurityService.alertSecurityTeam({
      event: 'super_admin_account_locked',
      userId,
      reason: 'Excessive failed access attempts',
      severity: 'critical'
    });
  }

  /**
   * Validate request signature
   * @param {Object} req - Express request object
   * @returns {Promise<boolean>} Valid signature
   * @private
   */
  static async validateRequestSignature(req) {
    const signature = req.headers['x-admin-signature'];
    
    if (!signature) {
      return false;
    }

    const payload = {
      method: req.method,
      path: req.path,
      body: req.body,
      timestamp: req.headers['x-timestamp']
    };

    return await SecurityService.verifyRequestSignature(
      payload,
      signature,
      req.user.apiKey
    );
  }

  /**
   * Check access hours
   * @param {Object} accessHours - Access hours configuration
   * @param {string} timezone - User timezone
   * @returns {Promise<boolean>} Within access hours
   * @private
   */
  static async checkAccessHours(accessHours, timezone) {
    const now = new Date();
    const userTime = new Date(now.toLocaleString('en-US', { timeZone: timezone }));
    
    const currentDay = userTime.getDay();
    const currentHour = userTime.getHours();
    const currentMinute = userTime.getMinutes();

    const todayHours = accessHours[currentDay];
    
    if (!todayHours || !todayHours.enabled) {
      return false;
    }

    const startTime = todayHours.start.split(':');
    const endTime = todayHours.end.split(':');

    const startHour = parseInt(startTime[0]);
    const startMinute = parseInt(startTime[1]);
    const endHour = parseInt(endTime[0]);
    const endMinute = parseInt(endTime[1]);

    const currentMinutes = currentHour * 60 + currentMinute;
    const startMinutes = startHour * 60 + startMinute;
    const endMinutes = endHour * 60 + endMinute;

    return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
  }
}

module.exports = SuperAdminOnlyMiddleware;