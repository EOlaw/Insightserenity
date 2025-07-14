// server/admin/super-admin/middleware/critical-operation.js
/**
 * @file Critical Operation Middleware
 * @description Middleware for protecting and monitoring critical system operations
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

// Models
const CriticalOperation = require('../../../shared/security/models/critical-operation-model');
const AdminSession = require('../../../shared/admin/models/admin-session-model');
const User = require('../../../shared/users/models/user-model');

// Services
const AuditService = require('../../../shared/security/services/audit-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const SecurityService = require('../../../shared/security/services/security-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');

// Utilities
const { ForbiddenError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

// Configuration
const config = require('../../../config');

/**
 * Critical Operation Middleware
 * Provides additional security layers for high-risk operations
 */
class CriticalOperationMiddleware {
  /**
   * Define critical operations and their requirements
   */
  static criticalOperations = {
    // System-wide operations
    'system.shutdown': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: false,
      cooldownMinutes: 60,
      maxPerDay: 1
    },
    'system.configuration.modify': {
      level: 'high',
      requireDualAuth: false,
      requireVideoAuth: false,
      cooldownMinutes: 15,
      maxPerDay: 10
    },
    'system.backup.restore': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: true,
      cooldownMinutes: 120,
      maxPerDay: 1
    },

    // Emergency access operations
    'emergency.access.grant': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: false,
      cooldownMinutes: 30,
      maxPerDay: 3
    },
    'emergency.bypass.activate': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: true,
      cooldownMinutes: 60,
      maxPerDay: 1
    },

    // Role and permission operations
    'role.system.modify': {
      level: 'high',
      requireDualAuth: false,
      requireVideoAuth: false,
      cooldownMinutes: 10,
      maxPerDay: 20
    },
    'role.super_admin.assign': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: true,
      cooldownMinutes: 240,
      maxPerDay: 1
    },

    // Data operations
    'data.bulk.delete': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: false,
      cooldownMinutes: 60,
      maxPerDay: 2
    },
    'data.export.full': {
      level: 'high',
      requireDualAuth: false,
      requireVideoAuth: false,
      cooldownMinutes: 30,
      maxPerDay: 5
    },

    // Security operations
    'security.audit.modify': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: true,
      cooldownMinutes: 120,
      maxPerDay: 1
    },
    'security.encryption.rotate': {
      level: 'extreme',
      requireDualAuth: true,
      requireVideoAuth: false,
      cooldownMinutes: 240,
      maxPerDay: 1
    }
  };

  /**
   * Main middleware function
   * @param {string} operationType - Type of critical operation
   * @param {Object} options - Additional options
   * @returns {Function} Express middleware function
   */
  static protect(operationType, options = {}) {
    const {
      customRequirements = {},
      skipInDevelopment = false,
      notifyAllAdmins = true,
      recordDetailed = true
    } = options;

    return async (req, res, next) => {
      try {
        // Skip in development if configured
        if (skipInDevelopment && config.app.env === 'development') {
          logger.warn('Critical operation protection skipped in development', {
            operationType,
            userId: req.user?.id
          });
          return next();
        }

        const user = req.user;
        const operationConfig = {
          ...this.criticalOperations[operationType],
          ...customRequirements
        };

        if (!operationConfig) {
          throw new Error(`Unknown critical operation type: ${operationType}`);
        }

        // Create operation record
        const operationId = crypto.randomUUID();
        const operation = await this.createOperationRecord(
          operationId,
          operationType,
          user,
          req
        );

        // Perform all security checks
        await this.performSecurityChecks(user, operationType, operationConfig, req);

        // Check operation limits
        await this.checkOperationLimits(user, operationType, operationConfig);

        // Handle dual authentication if required
        if (operationConfig.requireDualAuth) {
          const dualAuthResult = await this.handleDualAuthentication(
            operation,
            user,
            req
          );

          if (!dualAuthResult.approved) {
            return res.status(202).json({
              message: 'Operation requires dual authentication',
              operationId,
              secondaryAdmin: dualAuthResult.secondaryAdmin,
              expiresAt: dualAuthResult.expiresAt
            });
          }
        }

        // Handle video authentication if required
        if (operationConfig.requireVideoAuth) {
          const videoAuthResult = await this.handleVideoAuthentication(
            operation,
            user,
            req
          );

          if (!videoAuthResult.verified) {
            return res.status(202).json({
              message: 'Operation requires video authentication',
              operationId,
              verificationUrl: videoAuthResult.verificationUrl,
              expiresAt: videoAuthResult.expiresAt
            });
          }
        }

        // Create confirmation token for extreme operations
        if (operationConfig.level === 'extreme') {
          const confirmationToken = await this.createConfirmationToken(
            operation,
            user
          );

          if (!req.body.confirmationToken || 
              req.body.confirmationToken !== confirmationToken.token) {
            
            await this.sendConfirmationCode(user, confirmationToken, operationType);
            
            return res.status(202).json({
              message: 'Confirmation token sent to your registered email',
              operationId,
              tokenRequired: true
            });
          }
        }

        // Record operation start
        operation.status = 'in_progress';
        operation.startedAt = new Date();
        await operation.save();

        // Set operation context in request
        req.criticalOperation = {
          id: operationId,
          type: operationType,
          level: operationConfig.level,
          startTime: operation.startedAt
        };

        // Set up operation monitoring
        if (recordDetailed) {
          await this.setupOperationMonitoring(operation, req);
        }

        // Notify admins if required
        if (notifyAllAdmins) {
          await this.notifyAdminsOfCriticalOperation(operation, user);
        }

        // Set response interceptor to record completion
        const originalJson = res.json;
        res.json = async function(data) {
          await CriticalOperationMiddleware.recordOperationCompletion(
            operation,
            true,
            data
          );
          return originalJson.call(this, data);
        };

        next();

      } catch (error) {
        logger.error('Critical operation middleware error', {
          error: error.message,
          operationType,
          userId: req.user?.id,
          path: req.path,
          stack: error.stack
        });

        // Record operation failure
        if (req.criticalOperation?.id) {
          await this.recordOperationCompletion(
            { _id: req.criticalOperation.id },
            false,
            error.message
          );
        }

        next(error);
      }
    };
  }

  /**
   * Create operation record
   * @param {string} operationId - Operation ID
   * @param {string} operationType - Operation type
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @returns {Promise<Object>} Operation record
   * @private
   */
  static async createOperationRecord(operationId, operationType, user, req) {
    const operation = new CriticalOperation({
      operationId,
      type: operationType,
      initiatedBy: user.id,
      initiatedAt: new Date(),
      status: 'pending',
      metadata: {
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.headers['user-agent'],
        method: req.method,
        path: req.path,
        body: this.sanitizeRequestBody(req.body)
      },
      securityChecks: {
        mfaVerified: false,
        dualAuthRequired: false,
        videoAuthRequired: false,
        confirmationRequired: false
      }
    });

    await operation.save();
    return operation;
  }

  /**
   * Perform security checks
   * @param {Object} user - User object
   * @param {string} operationType - Operation type
   * @param {Object} config - Operation configuration
   * @param {Object} req - Express request object
   * @private
   */
  static async performSecurityChecks(user, operationType, config, req) {
    // Verify MFA for all critical operations
    if (!user.auth?.mfaVerified) {
      throw new ForbiddenError('MFA verification required for critical operations');
    }

    // Check MFA recency for extreme operations
    if (config.level === 'extreme') {
      const mfaAge = Date.now() - new Date(user.auth.mfaVerifiedAt).getTime();
      const maxAge = AdminSecurityConfig.criticalOperations.mfaMaxAge || 900000; // 15 minutes

      if (mfaAge > maxAge) {
        throw new ForbiddenError('MFA re-verification required for this operation');
      }
    }

    // Verify session security
    const session = await AdminSession.findOne({
      adminUserId: user.id,
      isActive: true,
      type: 'admin'
    });

    if (!session || !session.securityLevel || session.securityLevel < 3) {
      throw new ForbiddenError('High-security session required for critical operations');
    }

    // Check for concurrent critical operations
    const activeCriticalOps = await CriticalOperation.countDocuments({
      initiatedBy: user.id,
      status: 'in_progress',
      initiatedAt: { $gte: new Date(Date.now() - 3600000) } // Last hour
    });

    if (activeCriticalOps > 0) {
      throw new ValidationError('Another critical operation is already in progress');
    }

    // Verify user hasn't been compromised
    const recentSuspiciousActivity = await SecurityService.checkRecentSuspiciousActivity(
      user.id,
      24 // hours
    );

    if (recentSuspiciousActivity.count > 0) {
      await SecurityService.alertSecurityTeam({
        event: 'critical_operation_blocked',
        reason: 'Recent suspicious activity detected',
        userId: user.id,
        operationType
      });

      throw new ForbiddenError('Account flagged for suspicious activity');
    }
  }

  /**
   * Check operation limits
   * @param {Object} user - User object
   * @param {string} operationType - Operation type
   * @param {Object} config - Operation configuration
   * @private
   */
  static async checkOperationLimits(user, operationType, config) {
    const now = new Date();

    // Check cooldown period
    if (config.cooldownMinutes > 0) {
      const lastOperation = await CriticalOperation.findOne({
        initiatedBy: user.id,
        type: operationType,
        status: { $in: ['completed', 'failed'] }
      }).sort({ completedAt: -1 });

      if (lastOperation && lastOperation.completedAt) {
        const timeSinceLastOp = now - lastOperation.completedAt;
        const cooldownMs = config.cooldownMinutes * 60 * 1000;

        if (timeSinceLastOp < cooldownMs) {
          const remainingMinutes = Math.ceil((cooldownMs - timeSinceLastOp) / 60000);
          throw new ValidationError(
            `Operation cooldown active. Try again in ${remainingMinutes} minutes.`
          );
        }
      }
    }

    // Check daily limit
    if (config.maxPerDay > 0) {
      const todayStart = new Date(now);
      todayStart.setHours(0, 0, 0, 0);

      const todayCount = await CriticalOperation.countDocuments({
        initiatedBy: user.id,
        type: operationType,
        initiatedAt: { $gte: todayStart },
        status: { $ne: 'cancelled' }
      });

      if (todayCount >= config.maxPerDay) {
        throw new ValidationError(
          `Daily limit reached for this operation (${config.maxPerDay} per day)`
        );
      }
    }
  }

  /**
   * Handle dual authentication
   * @param {Object} operation - Operation record
   * @param {Object} user - Initiating user
   * @param {Object} req - Express request object
   * @returns {Promise<Object>} Dual auth result
   * @private
   */
  static async handleDualAuthentication(operation, user, req) {
    const existingApproval = req.headers['x-dual-auth-token'];

    if (existingApproval) {
      // Verify existing approval
      const approval = await CacheService.get(`dual_auth:${existingApproval}`);
      
      if (approval && approval.operationId === operation.operationId) {
        operation.securityChecks.dualAuthVerified = true;
        operation.securityChecks.dualAuthBy = approval.approvedBy;
        await operation.save();

        return { approved: true };
      }
    }

    // Select secondary admin
    const secondaryAdmin = await this.selectSecondaryAdmin(user, operation.type);

    if (!secondaryAdmin) {
      throw new Error('No eligible secondary administrator available');
    }

    // Create dual auth request
    const dualAuthToken = crypto.randomUUID();
    const dualAuthRequest = {
      operationId: operation.operationId,
      operationType: operation.type,
      requestedBy: user.id,
      requestedByEmail: user.email,
      approvalRequired: secondaryAdmin.id,
      token: dualAuthToken,
      expiresAt: new Date(Date.now() + 900000) // 15 minutes
    };

    await CacheService.set(
      `dual_auth_pending:${dualAuthToken}`,
      dualAuthRequest,
      900
    );

    // Notify secondary admin
    await this.notifySecondaryAdmin(secondaryAdmin, operation, user);

    operation.securityChecks.dualAuthRequired = true;
    operation.securityChecks.dualAuthRequestedFrom = secondaryAdmin.id;
    await operation.save();

    return {
      approved: false,
      secondaryAdmin: {
        email: secondaryAdmin.email,
        name: `${secondaryAdmin.profile?.firstName || ''} ${secondaryAdmin.profile?.lastName || ''}`.trim()
      },
      expiresAt: dualAuthRequest.expiresAt
    };
  }

  /**
   * Handle video authentication
   * @param {Object} operation - Operation record
   * @param {Object} user - User object
   * @param {Object} req - Express request object
   * @returns {Promise<Object>} Video auth result
   * @private
   */
  static async handleVideoAuthentication(operation, user, req) {
    const videoToken = req.headers['x-video-auth-token'];

    if (videoToken) {
      // Verify video authentication
      const verified = await SecurityService.verifyVideoAuthentication(
        user.id,
        videoToken
      );

      if (verified) {
        operation.securityChecks.videoAuthVerified = true;
        operation.securityChecks.videoAuthAt = new Date();
        await operation.save();

        return { verified: true };
      }
    }

    // Generate video authentication session
    const videoSession = await SecurityService.createVideoAuthSession({
      userId: user.id,
      operationId: operation.operationId,
      operationType: operation.type,
      requiredBiometrics: ['face', 'voice'],
      expiresIn: 600 // 10 minutes
    });

    operation.securityChecks.videoAuthRequired = true;
    operation.securityChecks.videoAuthSessionId = videoSession.id;
    await operation.save();

    return {
      verified: false,
      verificationUrl: videoSession.verificationUrl,
      sessionId: videoSession.id,
      expiresAt: videoSession.expiresAt
    };
  }

  /**
   * Create confirmation token
   * @param {Object} operation - Operation record
   * @param {Object} user - User object
   * @returns {Promise<Object>} Confirmation token
   * @private
   */
  static async createConfirmationToken(operation, user) {
    const token = crypto.randomInt(100000, 999999).toString();
    const hashedToken = crypto
      .createHash('sha256')
      .update(token + operation.operationId)
      .digest('hex');

    const confirmationData = {
      operationId: operation.operationId,
      userId: user.id,
      token: hashedToken,
      expiresAt: new Date(Date.now() + 300000) // 5 minutes
    };

    await CacheService.set(
      `confirmation:${operation.operationId}`,
      confirmationData,
      300
    );

    return { token, hashedToken };
  }

  /**
   * Send confirmation code
   * @param {Object} user - User object
   * @param {Object} confirmationToken - Token data
   * @param {string} operationType - Operation type
   * @private
   */
  static async sendConfirmationCode(user, confirmationToken, operationType) {
    await EmailService.sendEmail({
      to: user.email,
      subject: 'Critical Operation Confirmation Code',
      template: 'critical-operation-confirmation',
      data: {
        code: confirmationToken.token,
        operationType: operationType.replace(/\./g, ' '),
        expiresIn: '5 minutes',
        userName: user.profile?.firstName || user.email
      }
    });
  }

  /**
   * Setup operation monitoring
   * @param {Object} operation - Operation record
   * @param {Object} req - Express request object
   * @private
   */
  static async setupOperationMonitoring(operation, req) {
    // Create monitoring session
    const monitoringSession = {
      operationId: operation.operationId,
      startTime: new Date(),
      metrics: {
        requestsIntercepted: 0,
        dataAccessed: [],
        modificationsMode: []
      }
    };

    await CacheService.set(
      `operation_monitoring:${operation.operationId}`,
      monitoringSession,
      3600 // 1 hour
    );

    // Set up request interceptor
    const originalSend = req.res.send;
    req.res.send = function(data) {
      CriticalOperationMiddleware.recordOperationActivity(
        operation.operationId,
        'response',
        { size: Buffer.byteLength(data) }
      );
      return originalSend.call(this, data);
    };
  }

  /**
   * Record operation completion
   * @param {Object} operation - Operation record
   * @param {boolean} success - Operation success
   * @param {*} result - Operation result or error
   * @private
   */
  static async recordOperationCompletion(operation, success, result) {
    try {
      const completedOperation = await CriticalOperation.findById(operation._id);
      
      if (!completedOperation) {
        return;
      }

      completedOperation.status = success ? 'completed' : 'failed';
      completedOperation.completedAt = new Date();
      completedOperation.duration = 
        completedOperation.completedAt - completedOperation.startedAt;

      if (!success) {
        completedOperation.error = {
          message: result.message || result,
          stack: result.stack
        };
      }

      await completedOperation.save();

      // Log completion
      await AuditService.log({
        userId: completedOperation.initiatedBy,
        action: success ? 
          AdminEvents.CRITICAL_OPERATION.COMPLETED :
          AdminEvents.CRITICAL_OPERATION.FAILED,
        resource: completedOperation.type,
        severity: 'critical',
        metadata: {
          operationId: completedOperation.operationId,
          duration: completedOperation.duration,
          success
        }
      });

      // Clear monitoring
      await CacheService.delete(`operation_monitoring:${completedOperation.operationId}`);

    } catch (error) {
      logger.error('Error recording operation completion', {
        error: error.message,
        operationId: operation._id
      });
    }
  }

  /**
   * Record operation activity
   * @param {string} operationId - Operation ID
   * @param {string} activityType - Activity type
   * @param {Object} data - Activity data
   * @private
   */
  static async recordOperationActivity(operationId, activityType, data) {
    try {
      const monitoring = await CacheService.get(`operation_monitoring:${operationId}`);
      
      if (monitoring) {
        monitoring.metrics.requestsIntercepted++;
        
        if (activityType === 'data_access') {
          monitoring.metrics.dataAccessed.push({
            resource: data.resource,
            timestamp: new Date()
          });
        }

        await CacheService.set(
          `operation_monitoring:${operationId}`,
          monitoring,
          3600
        );
      }
    } catch (error) {
      logger.error('Error recording operation activity', {
        error: error.message,
        operationId
      });
    }
  }

  /**
   * Select secondary admin for dual auth
   * @param {Object} requestingUser - User requesting operation
   * @param {string} operationType - Operation type
   * @returns {Promise<Object>} Secondary admin
   * @private
   */
  static async selectSecondaryAdmin(requestingUser, operationType) {
    // Find eligible admins
    const eligibleAdmins = await User.find({
      _id: { $ne: requestingUser.id },
      'role.primary': 'super_admin',
      status: 'active',
      'auth.twoFactor.enabled': true,
      lastActiveAt: { $gte: new Date(Date.now() - 86400000) } // Active in last 24h
    })
    .sort({ lastActiveAt: -1 })
    .limit(5);

    if (eligibleAdmins.length === 0) {
      return null;
    }

    // Select based on availability and workload
    const selected = eligibleAdmins[0]; // Simple selection, could be more sophisticated

    return selected;
  }

  /**
   * Notify secondary admin
   * @param {Object} admin - Secondary admin
   * @param {Object} operation - Operation record
   * @param {Object} requestingUser - User requesting operation
   * @private
   */
  static async notifySecondaryAdmin(admin, operation, requestingUser) {
    await NotificationService.sendHighPriorityNotification({
      userId: admin.id,
      type: 'dual_auth_required',
      title: 'Critical Operation Approval Required',
      message: `${requestingUser.email} requires approval for: ${operation.type}`,
      data: {
        operationId: operation.operationId,
        operationType: operation.type,
        requestedBy: requestingUser.email,
        urgency: 'high'
      },
      channels: ['email', 'sms', 'push']
    });
  }

  /**
   * Notify admins of critical operation
   * @param {Object} operation - Operation record
   * @param {Object} user - User performing operation
   * @private
   */
  static async notifyAdminsOfCriticalOperation(operation, user) {
    await NotificationService.notifyAdmins({
      type: 'critical_operation_started',
      priority: 'high',
      data: {
        operationType: operation.type,
        initiatedBy: user.email,
        startTime: operation.startedAt
      }
    });
  }

  /**
   * Sanitize request body for logging
   * @param {Object} body - Request body
   * @returns {Object} Sanitized body
   * @private
   */
  static sanitizeRequestBody(body) {
    const sensitiveFields = [
      'password',
      'token',
      'secret',
      'key',
      'authorization'
    ];

    const sanitized = { ...body };

    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '***REDACTED***';
      }
    }

    return sanitized;
  }
}

module.exports = CriticalOperationMiddleware;