// server/admin/super-admin/services/emergency-access-service.js
/**
 * @file Emergency Access Service
 * @description Service for managing emergency access, bypass mechanisms, and critical operations
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Core Models
const User = require('../../../shared/users/models/user-model');
const EmergencyAccess = require('../../../shared/security/models/emergency-access-model');
const EmergencyBypass = require('../../../shared/security/models/emergency-bypass-model');
const SystemLock = require('../../../shared/security/models/system-lock-model');
const AdminSession = require('../../../shared/admin/models/admin-session-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const EmailService = require('../../../shared/services/email-service');
const SMSService = require('../../../shared/services/sms-service');
const SecurityService = require('../../../shared/security/services/security-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { encrypt, decrypt } = require('../../../shared/utils/encryption');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

// Configuration
const config = require('../../../config');
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

/**
 * Emergency Access Service Class
 * @class EmergencyAccessService
 * @extends AdminBaseService
 */
class EmergencyAccessService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'EmergencyAccessService';
    this.cachePrefix = 'emergency-access';
    this.auditCategory = 'EMERGENCY_ACCESS';
    this.requiredPermission = AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS;

    // Emergency access types
    this.accessTypes = {
      BYPASS_AUTH: 'bypass_authentication',
      OVERRIDE_PERMISSIONS: 'override_permissions',
      UNLOCK_SYSTEM: 'unlock_system',
      DISABLE_SECURITY: 'disable_security',
      FULL_ACCESS: 'full_access',
      DATA_RECOVERY: 'data_recovery',
      SYSTEM_RESTORE: 'system_restore'
    };

    // Emergency codes configuration
    this.emergencyCodeConfig = {
      length: 16,
      segments: 4,
      expiryMinutes: 15,
      maxAttempts: 3
    };

    // Break glass configuration
    this.breakGlassConfig = {
      requireDualAuth: true,
      notifyAllAdmins: true,
      autoExpireMinutes: 60,
      requireVideoAuth: false
    };
  }

  /**
   * Request emergency access
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} requestData - Emergency access request data
   * @returns {Promise<Object>} Emergency access request result
   */
  async requestEmergencyAccess(adminUser, requestData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'request');

      const {
        accessType,
        reason,
        duration = 3600, // 1 hour default
        scope = {},
        urgencyLevel = 'high',
        affectedSystems = [],
        requireDualAuth = this.breakGlassConfig.requireDualAuth
      } = requestData;

      // Validate request
      if (!this.accessTypes[accessType]) {
        throw new ValidationError('Invalid emergency access type');
      }

      if (!reason || reason.trim().length < 30) {
        throw new ValidationError('Detailed reason required for emergency access (minimum 30 characters)');
      }

      if (duration > AdminLimits.EMERGENCY_ACCESS.MAX_DURATION) {
        throw new ValidationError(`Emergency access duration cannot exceed ${AdminLimits.EMERGENCY_ACCESS.MAX_DURATION / 3600} hours`);
      }

      // Check for existing active emergency access
      const activeAccess = await EmergencyAccess.findOne({
        requestedBy: adminUser.id,
        status: 'active',
        expiresAt: { $gt: new Date() }
      }).session(session);

      if (activeAccess) {
        throw new ValidationError('You already have an active emergency access session');
      }

      // Generate emergency access codes
      const primaryCode = this.generateEmergencyCode();
      const secondaryCode = requireDualAuth ? this.generateEmergencyCode() : null;

      // Create emergency access request
      const emergencyAccess = new EmergencyAccess({
        requestId: crypto.randomUUID(),
        requestedBy: adminUser.id,
        requestedAt: new Date(),
        accessType: this.accessTypes[accessType],
        reason: encrypt(reason),
        duration,
        scope: {
          systems: scope.systems || [],
          operations: scope.operations || [],
          dataAccess: scope.dataAccess || [],
          restrictions: scope.restrictions || []
        },
        urgencyLevel,
        affectedSystems,
        status: requireDualAuth ? 'pending_dual_auth' : 'pending_verification',
        authCodes: {
          primary: {
            code: await this.hashEmergencyCode(primaryCode),
            expiresAt: new Date(Date.now() + this.emergencyCodeConfig.expiryMinutes * 60 * 1000)
          },
          secondary: secondaryCode ? {
            code: await this.hashEmergencyCode(secondaryCode),
            assignedTo: null,
            expiresAt: new Date(Date.now() + this.emergencyCodeConfig.expiryMinutes * 60 * 1000)
          } : null
        },
        metadata: {
          requestIP: adminUser.lastLoginIP,
          requestUserAgent: adminUser.lastUserAgent,
          requestLocation: adminUser.lastLocation,
          riskScore: await this.calculateRiskScore(adminUser, accessType, scope)
        }
      });

      await emergencyAccess.save({ session });

      // Send primary code to requester
      await this.sendEmergencyCode(adminUser, primaryCode, 'primary');

      // If dual auth required, notify another admin
      let secondaryAdmin = null;
      if (requireDualAuth) {
        secondaryAdmin = await this.selectSecondaryAuthAdmin(adminUser, urgencyLevel);
        if (secondaryAdmin) {
          emergencyAccess.authCodes.secondary.assignedTo = secondaryAdmin.id;
          await emergencyAccess.save({ session });
          await this.sendEmergencyCode(secondaryAdmin, secondaryCode, 'secondary', {
            requester: adminUser.email,
            reason: reason,
            accessType: accessType
          });
        }
      }

      // Create action log
      await AdminActionLog.create([{
        actionId: emergencyAccess.requestId,
        adminUserId: adminUser.id,
        action: 'EMERGENCY_ACCESS_REQUESTED',
        category: 'EMERGENCY_ACCESS',
        severity: 'CRITICAL',
        targetResource: {
          type: 'emergency_access',
          id: emergencyAccess.requestId,
          accessType
        },
        data: {
          accessType,
          duration,
          urgencyLevel,
          requireDualAuth,
          secondaryAdmin: secondaryAdmin?.email,
          scope
        }
      }], { session });

      // Notify all admins
      if (this.breakGlassConfig.notifyAllAdmins) {
        await this.notifyAllAdminsOfEmergencyRequest({
          requester: adminUser,
          accessType,
          reason,
          urgencyLevel,
          requestId: emergencyAccess.requestId
        });
      }

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.EMERGENCY_ACCESS.ACCESS_REQUESTED, {
        requestId: emergencyAccess.requestId,
        accessType,
        duration,
        urgencyLevel,
        requireDualAuth
      }, { 
        session, 
        critical: true,
        alertLevel: 'critical'
      });

      await session.commitTransaction();

      return {
        requestId: emergencyAccess.requestId,
        status: emergencyAccess.status,
        message: requireDualAuth ? 
          'Emergency access requested. Both authentication codes required.' :
          'Emergency access requested. Enter your authentication code to proceed.',
        codeExpiresAt: emergencyAccess.authCodes.primary.expiresAt,
        requireDualAuth,
        secondaryAdmin: secondaryAdmin ? {
          email: secondaryAdmin.email,
          notified: true
        } : null
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Request emergency access error', {
        error: error.message,
        adminId: adminUser.id,
        accessType: requestData.accessType,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Activate emergency access
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} requestId - Emergency access request ID
   * @param {Object} activationData - Activation data including codes
   * @returns {Promise<Object>} Activation result
   */
  async activateEmergencyAccess(adminUser, requestId, activationData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'activate');

      const { primaryCode, secondaryCode = null } = activationData;

      // Find emergency access request
      const emergencyAccess = await EmergencyAccess.findOne({
        requestId,
        status: { $in: ['pending_verification', 'pending_dual_auth'] }
      }).session(session);

      if (!emergencyAccess) {
        throw new NotFoundError('Emergency access request not found or already processed');
      }

      // Check expiry
      if (emergencyAccess.authCodes.primary.expiresAt < new Date()) {
        emergencyAccess.status = 'expired';
        await emergencyAccess.save({ session });
        throw new ValidationError('Emergency access codes have expired');
      }

      // Verify primary code
      const primaryValid = await this.verifyEmergencyCode(
        primaryCode,
        emergencyAccess.authCodes.primary.code
      );

      if (!primaryValid) {
        emergencyAccess.authCodes.primary.attempts = 
          (emergencyAccess.authCodes.primary.attempts || 0) + 1;
        
        if (emergencyAccess.authCodes.primary.attempts >= this.emergencyCodeConfig.maxAttempts) {
          emergencyAccess.status = 'failed';
          await emergencyAccess.save({ session });
          throw new ForbiddenError('Maximum authentication attempts exceeded');
        }
        
        await emergencyAccess.save({ session });
        throw new ValidationError('Invalid primary authentication code');
      }

      // Verify secondary code if required
      if (emergencyAccess.authCodes.secondary) {
        if (!secondaryCode) {
          throw new ValidationError('Secondary authentication code required');
        }

        const secondaryValid = await this.verifyEmergencyCode(
          secondaryCode,
          emergencyAccess.authCodes.secondary.code
        );

        if (!secondaryValid) {
          emergencyAccess.authCodes.secondary.attempts = 
            (emergencyAccess.authCodes.secondary.attempts || 0) + 1;
          
          if (emergencyAccess.authCodes.secondary.attempts >= this.emergencyCodeConfig.maxAttempts) {
            emergencyAccess.status = 'failed';
            await emergencyAccess.save({ session });
            throw new ForbiddenError('Maximum authentication attempts exceeded');
          }
          
          await emergencyAccess.save({ session });
          throw new ValidationError('Invalid secondary authentication code');
        }

        // Verify secondary code was entered by correct admin
        if (emergencyAccess.authCodes.secondary.assignedTo && 
            emergencyAccess.authCodes.secondary.assignedTo.toString() !== adminUser.id) {
          throw new ForbiddenError('Secondary code must be entered by assigned administrator');
        }
      }

      // Activate emergency access
      emergencyAccess.status = 'active';
      emergencyAccess.activatedAt = new Date();
      emergencyAccess.activatedBy = adminUser.id;
      emergencyAccess.expiresAt = new Date(Date.now() + emergencyAccess.duration * 1000);

      // Generate access token
      const accessToken = await this.generateEmergencyAccessToken(emergencyAccess);
      emergencyAccess.accessToken = encrypt(accessToken);

      await emergencyAccess.save({ session });

      // Apply emergency access permissions
      await this.applyEmergencyAccess(emergencyAccess, session);

      // Create bypass entries if needed
      if (emergencyAccess.accessType === this.accessTypes.BYPASS_AUTH || 
          emergencyAccess.accessType === this.accessTypes.FULL_ACCESS) {
        await this.createBypassEntries(emergencyAccess, session);
      }

      // Clear security blocks if unlocking system
      if (emergencyAccess.accessType === this.accessTypes.UNLOCK_SYSTEM) {
        await this.clearSystemLocks(emergencyAccess, session);
      }

      // Log activation
      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'EMERGENCY_ACCESS_ACTIVATED',
        category: 'EMERGENCY_ACCESS',
        severity: 'CRITICAL',
        targetResource: {
          type: 'emergency_access',
          id: emergencyAccess.requestId,
          accessType: emergencyAccess.accessType
        },
        data: {
          requestedBy: emergencyAccess.requestedBy,
          activatedBy: adminUser.id,
          expiresAt: emergencyAccess.expiresAt,
          scope: emergencyAccess.scope
        }
      }], { session });

      // Alert security team
      await this.alertSecurityTeam({
        event: 'emergency_access_activated',
        requestId: emergencyAccess.requestId,
        accessType: emergencyAccess.accessType,
        admin: adminUser.email,
        expiresAt: emergencyAccess.expiresAt
      });

      // Set up monitoring
      await this.setupEmergencyAccessMonitoring(emergencyAccess);

      await this.auditLog(adminUser, AdminEvents.EMERGENCY_ACCESS.ACCESS_ACTIVATED, {
        requestId: emergencyAccess.requestId,
        accessType: emergencyAccess.accessType,
        duration: emergencyAccess.duration,
        expiresAt: emergencyAccess.expiresAt
      }, { 
        session, 
        critical: true,
        alertLevel: 'critical'
      });

      await session.commitTransaction();

      return {
        success: true,
        accessToken,
        expiresAt: emergencyAccess.expiresAt,
        permissions: await this.getEmergencyPermissions(emergencyAccess),
        restrictions: emergencyAccess.scope.restrictions,
        monitoringEnabled: true,
        message: 'Emergency access activated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Activate emergency access error', {
        error: error.message,
        adminId: adminUser.id,
        requestId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Revoke emergency access
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} requestId - Emergency access request ID
   * @param {Object} revokeData - Revocation data
   * @returns {Promise<Object>} Revocation result
   */
  async revokeEmergencyAccess(adminUser, requestId, revokeData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'revoke');

      const { reason, immediate = true } = revokeData;

      if (!reason || reason.trim().length < 20) {
        throw new ValidationError('Detailed reason required for revocation (minimum 20 characters)');
      }

      // Find active emergency access
      const emergencyAccess = await EmergencyAccess.findOne({
        requestId,
        status: 'active'
      }).session(session);

      if (!emergencyAccess) {
        throw new NotFoundError('Active emergency access not found');
      }

      // Check revocation permissions
      const canRevoke = emergencyAccess.requestedBy.toString() === adminUser.id ||
                       await this.hasOverridePermission(adminUser) ||
                       await this.isSecurityTeamMember(adminUser);

      if (!canRevoke) {
        throw new ForbiddenError('Insufficient permissions to revoke this emergency access');
      }

      // Revoke access
      emergencyAccess.status = 'revoked';
      emergencyAccess.revokedAt = new Date();
      emergencyAccess.revokedBy = adminUser.id;
      emergencyAccess.revocationReason = encrypt(reason);

      await emergencyAccess.save({ session });

      // Remove permissions and bypasses
      if (immediate) {
        await this.removeEmergencyAccess(emergencyAccess, session);
        await this.removeBypassEntries(emergencyAccess, session);
      } else {
        // Schedule removal
        await this.scheduleAccessRemoval(emergencyAccess);
      }

      // Invalidate access token
      await CacheService.delete(`emergency_token:${emergencyAccess.requestId}`);

      // Log all actions performed during emergency access
      const actionsLog = await this.getEmergencyAccessActions(emergencyAccess.requestId);

      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'EMERGENCY_ACCESS_REVOKED',
        category: 'EMERGENCY_ACCESS',
        severity: 'CRITICAL',
        targetResource: {
          type: 'emergency_access',
          id: emergencyAccess.requestId,
          accessType: emergencyAccess.accessType
        },
        data: {
          reason,
          immediate,
          requestedBy: emergencyAccess.requestedBy,
          activeDuration: emergencyAccess.revokedAt - emergencyAccess.activatedAt,
          actionsPerformed: actionsLog.length
        }
      }], { session });

      // Generate post-incident report
      const incidentReport = await this.generateIncidentReport(emergencyAccess, actionsLog);

      await this.auditLog(adminUser, AdminEvents.EMERGENCY_ACCESS.ACCESS_REVOKED, {
        requestId: emergencyAccess.requestId,
        reason,
        immediate,
        actionsPerformed: actionsLog.length
      }, { 
        session, 
        critical: true 
      });

      // Notify all parties
      await this.notifyEmergencyAccessRevocation(emergencyAccess, reason, adminUser);

      await session.commitTransaction();

      return {
        success: true,
        revokedAt: emergencyAccess.revokedAt,
        incidentReport: incidentReport.id,
        actionsPerformed: actionsLog.length,
        message: immediate ? 
          'Emergency access revoked immediately' : 
          'Emergency access revocation scheduled'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Revoke emergency access error', {
        error: error.message,
        adminId: adminUser.id,
        requestId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get active emergency access sessions
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Active sessions
   */
  async getActiveEmergencySessions(adminUser, options = {}) {
    try {
      await this.validateAccess(adminUser, 'read');

      const { includeExpired = false, includeActions = true } = options;

      const query = {
        status: 'active'
      };

      if (!includeExpired) {
        query.expiresAt = { $gt: new Date() };
      }

      const sessions = await EmergencyAccess.find(query)
        .populate('requestedBy', 'email profile')
        .populate('activatedBy', 'email profile')
        .sort({ activatedAt: -1 });

      const enhancedSessions = await Promise.all(
        sessions.map(async (session) => {
          const sessionData = session.toObject();
          
          // Decrypt reason
          sessionData.reason = decrypt(session.reason);
          
          // Get actions performed
          if (includeActions) {
            sessionData.actions = await this.getEmergencyAccessActions(session.requestId);
          }
          
          // Calculate remaining time
          sessionData.remainingTime = Math.max(0, session.expiresAt - new Date());
          
          // Get current permissions
          sessionData.activePermissions = await this.getActiveEmergencyPermissions(session);
          
          // Risk assessment
          sessionData.currentRisk = await this.assessCurrentRisk(session);
          
          return sessionData;
        })
      );

      // Get system-wide emergency status
      const systemStatus = await this.getSystemEmergencyStatus();

      await this.auditLog(adminUser, AdminEvents.EMERGENCY_ACCESS.SESSIONS_VIEWED, {
        count: enhancedSessions.length,
        includeExpired
      });

      return {
        sessions: enhancedSessions,
        systemStatus,
        statistics: {
          total: enhancedSessions.length,
          critical: enhancedSessions.filter(s => s.urgencyLevel === 'critical').length,
          expiringSoon: enhancedSessions.filter(s => s.remainingTime < 900000).length // 15 minutes
        }
      };

    } catch (error) {
      logger.error('Get active emergency sessions error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Create break glass access
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} breakGlassData - Break glass data
   * @returns {Promise<Object>} Break glass result
   */
  async createBreakGlassAccess(adminUser, breakGlassData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'break_glass');

      const {
        reason,
        systems = ['all'],
        duration = 3600, // 1 hour
        notificationList = [],
        videoAuthToken = null
      } = breakGlassData;

      if (!reason || reason.trim().length < 50) {
        throw new ValidationError('Detailed reason required for break glass access (minimum 50 characters)');
      }

      // Verify video authentication if required
      if (this.breakGlassConfig.requireVideoAuth && !videoAuthToken) {
        throw new ValidationError('Video authentication required for break glass access');
      }

      if (videoAuthToken) {
        const videoAuthValid = await this.verifyVideoAuth(adminUser, videoAuthToken);
        if (!videoAuthValid) {
          throw new ForbiddenError('Video authentication failed');
        }
      }

      // Create break glass session
      const breakGlassId = crypto.randomUUID();
      const breakGlassSession = {
        id: breakGlassId,
        adminId: adminUser.id,
        reason: encrypt(reason),
        systems,
        startTime: new Date(),
        expiresAt: new Date(Date.now() + duration * 1000),
        permissions: await this.generateBreakGlassPermissions(systems),
        restrictions: [],
        auditTrail: []
      };

      // Store in cache for immediate access
      await CacheService.set(
        `break_glass:${breakGlassId}`,
        breakGlassSession,
        duration
      );

      // Create formal emergency access record
      const emergencyAccess = new EmergencyAccess({
        requestId: breakGlassId,
        requestedBy: adminUser.id,
        requestedAt: new Date(),
        accessType: this.accessTypes.FULL_ACCESS,
        reason: encrypt(reason),
        duration,
        scope: {
          systems,
          operations: ['all'],
          dataAccess: ['all'],
          restrictions: []
        },
        urgencyLevel: 'critical',
        status: 'active',
        activatedAt: new Date(),
        activatedBy: adminUser.id,
        expiresAt: breakGlassSession.expiresAt,
        metadata: {
          breakGlass: true,
          videoAuth: !!videoAuthToken
        }
      });

      await emergencyAccess.save({ session });

      // Apply full system access
      await this.applyBreakGlassAccess(emergencyAccess, session);

      // Create comprehensive audit record
      await AdminActionLog.create([{
        actionId: breakGlassId,
        adminUserId: adminUser.id,
        action: 'BREAK_GLASS_ACTIVATED',
        category: 'EMERGENCY_ACCESS',
        severity: 'CRITICAL',
        data: {
          systems,
          duration,
          videoAuth: !!videoAuthToken,
          notificationList
        }
      }], { session });

      // Send critical alerts
      await this.sendBreakGlassAlerts({
        admin: adminUser,
        breakGlassId,
        reason,
        systems,
        expiresAt: breakGlassSession.expiresAt,
        notificationList
      });

      // Set up intensive monitoring
      await this.setupBreakGlassMonitoring(breakGlassId, adminUser.id);

      await this.auditLog(adminUser, AdminEvents.EMERGENCY_ACCESS.BREAK_GLASS_ACTIVATED, {
        breakGlassId,
        systems,
        duration,
        videoAuth: !!videoAuthToken
      }, { 
        session, 
        critical: true,
        alertLevel: 'critical'
      });

      await session.commitTransaction();

      return {
        breakGlassId,
        activated: true,
        expiresAt: breakGlassSession.expiresAt,
        permissions: breakGlassSession.permissions,
        monitoringActive: true,
        alertsSent: notificationList.length + 3, // +3 for default alerts
        message: 'Break glass access activated. All actions are being monitored and logged.'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Create break glass access error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get emergency access audit trail
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} requestId - Emergency access request ID
   * @returns {Promise<Object>} Audit trail
   */
  async getEmergencyAccessAuditTrail(adminUser, requestId) {
    try {
      await this.validateAccess(adminUser, 'audit');

      const emergencyAccess = await EmergencyAccess.findOne({ requestId });

      if (!emergencyAccess) {
        throw new NotFoundError('Emergency access request not found');
      }

      // Get all related audit logs
      const auditLogs = await AuditService.getAuditLogs({
        'metadata.emergencyAccessId': requestId,
        timestamp: {
          $gte: emergencyAccess.requestedAt,
          $lte: emergencyAccess.revokedAt || new Date()
        }
      });

      // Get all admin actions
      const adminActions = await AdminActionLog.find({
        'data.emergencyAccessId': requestId
      }).populate('adminUserId', 'email profile');

      // Get system changes during access period
      const systemChanges = await this.getSystemChangesDuringAccess(
        emergencyAccess.activatedAt,
        emergencyAccess.revokedAt || emergencyAccess.expiresAt
      );

      // Build comprehensive timeline
      const timeline = this.buildEmergencyAccessTimeline(
        emergencyAccess,
        auditLogs,
        adminActions,
        systemChanges
      );

      // Calculate impact assessment
      const impactAssessment = await this.assessEmergencyAccessImpact(emergencyAccess, timeline);

      return {
        emergencyAccess: {
          requestId: emergencyAccess.requestId,
          accessType: emergencyAccess.accessType,
          requestedBy: emergencyAccess.requestedBy,
          reason: decrypt(emergencyAccess.reason),
          duration: emergencyAccess.duration,
          status: emergencyAccess.status
        },
        timeline,
        statistics: {
          totalActions: timeline.length,
          criticalActions: timeline.filter(t => t.severity === 'critical').length,
          systemModifications: systemChanges.length,
          affectedUsers: impactAssessment.affectedUsers,
          affectedResources: impactAssessment.affectedResources
        },
        impactAssessment,
        recommendations: await this.generateSecurityRecommendations(impactAssessment)
      };

    } catch (error) {
      logger.error('Get emergency access audit trail error', {
        error: error.message,
        adminId: adminUser.id,
        requestId,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Helper methods
   */

  /**
   * Generate emergency access code
   * @returns {string} Emergency code
   * @private
   */
  generateEmergencyCode() {
    const code = crypto.randomBytes(this.emergencyCodeConfig.length).toString('hex').toUpperCase();
    const segments = [];
    
    for (let i = 0; i < this.emergencyCodeConfig.segments; i++) {
      const start = i * (code.length / this.emergencyCodeConfig.segments);
      const end = (i + 1) * (code.length / this.emergencyCodeConfig.segments);
      segments.push(code.substring(start, end));
    }
    
    return segments.join('-');
  }

  /**
   * Hash emergency code
   * @param {string} code - Plain text code
   * @returns {Promise<string>} Hashed code
   * @private
   */
  async hashEmergencyCode(code) {
    const normalizedCode = code.replace(/-/g, '').toUpperCase();
    return crypto.createHash('sha256').update(normalizedCode + config.auth.jwtSecret).digest('hex');
  }

  /**
   * Verify emergency code
   * @param {string} inputCode - Input code
   * @param {string} hashedCode - Stored hash
   * @returns {Promise<boolean>} Verification result
   * @private
   */
  async verifyEmergencyCode(inputCode, hashedCode) {
    const normalizedInput = inputCode.replace(/-/g, '').toUpperCase();
    const inputHash = crypto.createHash('sha256').update(normalizedInput + config.auth.jwtSecret).digest('hex');
    return inputHash === hashedCode;
  }

  /**
   * Send emergency code
   * @param {Object} admin - Admin user
   * @param {string} code - Emergency code
   * @param {string} type - Code type (primary/secondary)
   * @param {Object} context - Additional context
   * @private
   */
  async sendEmergencyCode(admin, code, type, context = {}) {
    // Send via multiple channels for security
    const channels = [];

    // Email
    if (admin.email) {
      channels.push(
        EmailService.sendEmail({
          to: admin.email,
          subject: 'Emergency Access Authentication Code',
          template: 'emergency-access-code',
          data: {
            code,
            type,
            expiryMinutes: this.emergencyCodeConfig.expiryMinutes,
            ...context
          }
        })
      );
    }

    // SMS if available
    if (admin.phone && admin.auth?.sms?.enabled) {
      channels.push(
        SMSService.sendSMS({
          to: admin.phone,
          message: `Emergency Access ${type} code: ${code}. Expires in ${this.emergencyCodeConfig.expiryMinutes} minutes.`
        })
      );
    }

    await Promise.all(channels);
  }

  /**
   * Apply emergency access permissions
   * @param {Object} emergencyAccess - Emergency access object
   * @param {Object} session - Database session
   * @private
   */
  async applyEmergencyAccess(emergencyAccess, session) {
    // Implementation would apply the necessary permissions
    // based on the access type and scope
    const permissions = await this.generateEmergencyPermissions(emergencyAccess);
    
    // Store in cache for quick lookup
    await CacheService.set(
      `emergency_permissions:${emergencyAccess.requestId}`,
      permissions,
      emergencyAccess.duration
    );
  }

  /**
   * Generate emergency permissions based on access type
   * @param {Object} emergencyAccess - Emergency access object
   * @returns {Promise<Array>} Permissions array
   * @private
   */
  async generateEmergencyPermissions(emergencyAccess) {
    const permissions = [];

    switch (emergencyAccess.accessType) {
      case this.accessTypes.FULL_ACCESS:
        permissions.push('*.*.*'); // All permissions
        break;
      
      case this.accessTypes.BYPASS_AUTH:
        permissions.push('auth.bypass.*');
        permissions.push('session.override.*');
        break;
      
      case this.accessTypes.OVERRIDE_PERMISSIONS:
        permissions.push('permissions.override.*');
        permissions.push('roles.bypass.*');
        break;
      
      case this.accessTypes.UNLOCK_SYSTEM:
        permissions.push('system.unlock.*');
        permissions.push('security.disable.*');
        break;
      
      case this.accessTypes.DATA_RECOVERY:
        permissions.push('data.recovery.*');
        permissions.push('backup.restore.*');
        break;
      
      case this.accessTypes.SYSTEM_RESTORE:
        permissions.push('system.restore.*');
        permissions.push('config.reset.*');
        break;
    }

    // Apply scope restrictions
    if (emergencyAccess.scope.systems && emergencyAccess.scope.systems.length > 0) {
      permissions.forEach((perm, index) => {
        permissions[index] = `${perm}:systems:${emergencyAccess.scope.systems.join(',')}`;
      });
    }

    return permissions;
  }

  /**
   * Validate access for emergency operations
   * @param {Object} user - User to validate
   * @param {string} action - Action to perform
   * @private
   */
  async validateAccess(user, action) {
    const hasPermission = await this.checkPermission(
      user,
      this.requiredPermission,
      action
    );

    if (!hasPermission) {
      await this.auditLog(user, AdminEvents.EMERGENCY_ACCESS.UNAUTHORIZED_ACCESS, {
        attemptedAction: action,
        permission: this.requiredPermission
      });
      throw new ForbiddenError(`Insufficient permissions for emergency access: ${action}`);
    }

    // Always require MFA for emergency access operations
    if (!user.auth?.mfaVerified) {
      throw new ForbiddenError('MFA verification required for emergency access operations');
    }

    // Additional security checks for break glass
    if (action === 'break_glass') {
      const recentBreakGlass = await EmergencyAccess.findOne({
        requestedBy: user.id,
        'metadata.breakGlass': true,
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
      });

      if (recentBreakGlass) {
        throw new ForbiddenError('Break glass access can only be used once per 24 hours');
      }
    }
  }

  /**
   * Additional helper methods would continue here...
   */
}

module.exports = new EmergencyAccessService();