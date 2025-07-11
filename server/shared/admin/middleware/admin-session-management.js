/**
 * @file Admin Session Management Middleware
 * @description Enhanced session management for administrative operations with security controls
 * @version 1.0.0
 */

const crypto = require('crypto');
const moment = require('moment');
const { SessionError, AuthenticationError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../../audit/services/audit-service');
const AdminAuditLogger = require('./admin-audit-logging');
const { CacheService } = require('../../../services/cache-service');
const Auth = require('../../../auth/models/auth-model');
const config = require('../../../config/config');

/**
 * Admin Session Manager Class
 * @class AdminSessionManager
 */
class AdminSessionManager {
  /**
   * Initialize session management configurations
   */
  static initialize() {
    this.cache = new CacheService('admin:sessions');
    
    // Session configuration
    this.sessionConfig = {
      duration: config.auth.sessionDuration || 3600000, // 1 hour
      maxConcurrent: 3,
      idleTimeout: 1800000, // 30 minutes
      absoluteTimeout: 28800000, // 8 hours
      renewalWindow: 300000, // 5 minutes before expiry
      requireIPConsistency: true,
      requireUserAgentConsistency: true,
      enableFingerprinting: true
    };
    
    // Active sessions tracking
    this.activeSessions = new Map();
    this.sessionActivity = new Map();
    this.suspiciousPatterns = new Map();
    
    // Session security levels
    this.securityLevels = {
      standard: {
        mfaRequired: false,
        ipValidation: true,
        deviceValidation: true,
        maxIdleTime: 1800000 // 30 minutes
      },
      elevated: {
        mfaRequired: true,
        ipValidation: true,
        deviceValidation: true,
        maxIdleTime: 600000, // 10 minutes
        requireRecentAuth: true
      },
      critical: {
        mfaRequired: true,
        ipValidation: true,
        deviceValidation: true,
        maxIdleTime: 300000, // 5 minutes
        requireRecentAuth: true,
        requirePasswordConfirmation: true
      }
    };
  }

  /**
   * Create admin session management middleware
   * @param {Object} options - Session options
   * @returns {Function} Express middleware
   */
  static manage(options = {}) {
    const {
      securityLevel = 'standard',
      requireActive = true,
      autoRenew = true,
      trackActivity = true
    } = options;

    return async (req, res, next) => {
      try {
        // Skip if no admin authentication
        if (!req.adminAuth || !req.user) {
          return next();
        }

        const sessionId = req.adminAuth.sessionId;
        if (!sessionId) {
          throw new SessionError('No admin session ID found');
        }

        // Validate session
        const sessionValidation = await this.validateSession(sessionId, req);
        if (!sessionValidation.valid) {
          throw new SessionError(sessionValidation.reason || 'Invalid admin session');
        }

        // Check security requirements
        const securityCheck = await this.checkSecurityRequirements(
          sessionId,
          securityLevel,
          req
        );
        if (!securityCheck.passed) {
          return res.status(402).json({
            success: false,
            error: 'Additional authentication required',
            requirements: securityCheck.requirements
          });
        }

        // Update session activity
        if (trackActivity) {
          await this.updateSessionActivity(sessionId, req);
        }

        // Check for session renewal
        if (autoRenew && this.shouldRenewSession(sessionValidation.session)) {
          await this.renewSession(sessionId, req, res);
        }

        // Set session context
        req.adminSession = {
          id: sessionId,
          securityLevel,
          createdAt: sessionValidation.session.createdAt,
          lastActivity: sessionValidation.session.lastActivity,
          expiresAt: sessionValidation.session.expiresAt,
          metadata: sessionValidation.session.metadata
        };

        // Monitor for suspicious patterns
        await this.monitorSessionPatterns(sessionId, req);

        next();
      } catch (error) {
        await this.handleSessionError(error, req);
        next(error);
      }
    };
  }

  /**
   * Create new admin session
   * @param {Object} user - User object
   * @param {Object} authData - Authentication data
   * @param {Object} req - Express request
   * @returns {Object} Session data
   */
  static async createSession(user, authData, req) {
    try {
      const sessionId = this.generateSessionId();
      const fingerprint = await this.generateFingerprint(req);
      
      // Check concurrent sessions
      const userSessions = await this.getUserSessions(user._id);
      if (userSessions.length >= this.sessionConfig.maxConcurrent) {
        // Terminate oldest session
        const oldestSession = userSessions.sort((a, b) => 
          new Date(a.createdAt) - new Date(b.createdAt)
        )[0];
        await this.terminateSession(oldestSession.sessionId, 'max_concurrent_reached');
      }

      // Create session data
      const session = {
        sessionId,
        userId: user._id,
        userRole: user.role?.primary,
        createdAt: new Date(),
        lastActivity: new Date(),
        expiresAt: new Date(Date.now() + this.sessionConfig.duration),
        absoluteExpiry: new Date(Date.now() + this.sessionConfig.absoluteTimeout),
        device: {
          fingerprint,
          userAgent: req.get('user-agent'),
          ip: req.ip,
          platform: this.extractPlatform(req.get('user-agent')),
          browser: this.extractBrowser(req.get('user-agent'))
        },
        security: {
          level: 'standard',
          mfaVerified: authData.mfaVerified || false,
          mfaVerifiedAt: authData.mfaVerifiedAt,
          elevatedUntil: null,
          lastPasswordVerification: authData.passwordVerifiedAt
        },
        metadata: {
          loginMethod: authData.method || 'password',
          location: await this.getLocationInfo(req.ip),
          initialEndpoint: req.originalUrl
        }
      };

      // Store in auth record
      const authRecord = await Auth.findOne({ userId: user._id });
      if (authRecord) {
        authRecord.sessions.push({
          sessionId,
          active: true,
          ...session
        });
        
        // Limit stored sessions
        if (authRecord.sessions.length > 10) {
          authRecord.sessions = authRecord.sessions
            .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
            .slice(0, 10);
        }
        
        await authRecord.save();
      }

      // Cache session
      await this.cache.set(sessionId, session, this.sessionConfig.duration / 1000);
      this.activeSessions.set(sessionId, session);

      // Audit log
      await AdminAuditLogger.logAdminEvent({
        eventType: 'admin_session_created',
        userId: user._id,
        targetType: 'session',
        operation: 'create',
        metadata: {
          sessionId,
          device: session.device,
          location: session.metadata.location
        }
      });

      return session;
    } catch (error) {
      logger.error('Failed to create admin session', {
        error: error.message,
        userId: user?._id
      });
      throw error;
    }
  }

  /**
   * Validate admin session
   * @param {string} sessionId - Session ID
   * @param {Object} req - Express request
   * @returns {Object} Validation result
   */
  static async validateSession(sessionId, req) {
    try {
      // Get session from cache or database
      let session = await this.cache.get(sessionId);
      
      if (!session) {
        // Try to load from database
        session = await this.loadSessionFromDatabase(sessionId, req.user?._id);
        if (!session) {
          return { valid: false, reason: 'Session not found' };
        }
      }

      // Check expiration
      if (new Date(session.expiresAt) < new Date()) {
        await this.terminateSession(sessionId, 'expired');
        return { valid: false, reason: 'Session expired' };
      }

      // Check absolute timeout
      if (new Date(session.absoluteExpiry) < new Date()) {
        await this.terminateSession(sessionId, 'absolute_timeout');
        return { valid: false, reason: 'Session absolute timeout' };
      }

      // Check idle timeout
      const idleTime = Date.now() - new Date(session.lastActivity).getTime();
      const maxIdleTime = this.securityLevels[session.security.level].maxIdleTime;
      
      if (idleTime > maxIdleTime) {
        await this.terminateSession(sessionId, 'idle_timeout');
        return { valid: false, reason: 'Session idle timeout' };
      }

      // Validate device consistency
      if (this.sessionConfig.requireIPConsistency && session.device.ip !== req.ip) {
        await this.handleIPChange(sessionId, session, req);
        return { valid: false, reason: 'IP address changed' };
      }

      if (this.sessionConfig.requireUserAgentConsistency) {
        const currentUA = req.get('user-agent');
        if (session.device.userAgent !== currentUA) {
          await this.handleUserAgentChange(sessionId, session, req);
          return { valid: false, reason: 'User agent changed' };
        }
      }

      // Validate fingerprint if enabled
      if (this.sessionConfig.enableFingerprinting) {
        const currentFingerprint = await this.generateFingerprint(req);
        if (session.device.fingerprint !== currentFingerprint) {
          await this.handleFingerprintChange(sessionId, session, req);
          return { valid: false, reason: 'Device fingerprint changed' };
        }
      }

      return { valid: true, session };
    } catch (error) {
      logger.error('Session validation error', {
        error: error.message,
        sessionId
      });
      return { valid: false, reason: 'Validation error' };
    }
  }

  /**
   * Check security requirements for session
   * @param {string} sessionId - Session ID
   * @param {string} securityLevel - Required security level
   * @param {Object} req - Express request
   * @returns {Object} Security check result
   */
  static async checkSecurityRequirements(sessionId, securityLevel, req) {
    const session = this.activeSessions.get(sessionId) || await this.cache.get(sessionId);
    if (!session) {
      return { passed: false, requirements: ['session_not_found'] };
    }

    const requirements = [];
    const levelConfig = this.securityLevels[securityLevel];

    // Check MFA requirement
    if (levelConfig.mfaRequired && !session.security.mfaVerified) {
      requirements.push('mfa_verification');
    }

    // Check recent authentication
    if (levelConfig.requireRecentAuth) {
      const authAge = Date.now() - new Date(session.createdAt).getTime();
      if (authAge > 3600000) { // 1 hour
        requirements.push('recent_authentication');
      }
    }

    // Check password confirmation
    if (levelConfig.requirePasswordConfirmation) {
      const lastVerification = session.security.lastPasswordVerification;
      if (!lastVerification || (Date.now() - new Date(lastVerification).getTime() > 300000)) {
        requirements.push('password_confirmation');
      }
    }

    // Check if current security level is sufficient
    const levelPriority = { standard: 1, elevated: 2, critical: 3 };
    if (levelPriority[session.security.level] < levelPriority[securityLevel]) {
      requirements.push('elevate_security_level');
    }

    return {
      passed: requirements.length === 0,
      requirements,
      currentLevel: session.security.level,
      requiredLevel: securityLevel
    };
  }

  /**
   * Update session activity
   * @param {string} sessionId - Session ID
   * @param {Object} req - Express request
   */
  static async updateSessionActivity(sessionId, req) {
    try {
      const session = this.activeSessions.get(sessionId) || await this.cache.get(sessionId);
      if (!session) return;

      // Update last activity
      session.lastActivity = new Date();
      
      // Track endpoint access
      if (!session.metadata.endpointAccess) {
        session.metadata.endpointAccess = {};
      }
      const endpoint = req.originalUrl.split('?')[0];
      session.metadata.endpointAccess[endpoint] = 
        (session.metadata.endpointAccess[endpoint] || 0) + 1;

      // Update cache
      await this.cache.set(sessionId, session, this.sessionConfig.duration / 1000);
      this.activeSessions.set(sessionId, session);

      // Update activity tracking
      const activityKey = `activity:${sessionId}`;
      const activity = this.sessionActivity.get(activityKey) || {
        actions: [],
        lastUpdate: new Date()
      };

      activity.actions.push({
        timestamp: new Date(),
        endpoint: req.originalUrl,
        method: req.method,
        ip: req.ip
      });

      // Keep only recent activity
      activity.actions = activity.actions.slice(-100);
      activity.lastUpdate = new Date();
      
      this.sessionActivity.set(activityKey, activity);
    } catch (error) {
      logger.error('Failed to update session activity', {
        error: error.message,
        sessionId
      });
    }
  }

  /**
   * Renew admin session
   * @param {string} sessionId - Session ID
   * @param {Object} req - Express request
   * @param {Object} res - Express response
   */
  static async renewSession(sessionId, req, res) {
    try {
      const session = this.activeSessions.get(sessionId) || await this.cache.get(sessionId);
      if (!session) return;

      // Calculate new expiry
      const now = Date.now();
      const newExpiry = new Date(now + this.sessionConfig.duration);
      
      // Don't exceed absolute timeout
      if (newExpiry > new Date(session.absoluteExpiry)) {
        session.expiresAt = session.absoluteExpiry;
      } else {
        session.expiresAt = newExpiry;
      }

      session.lastRenewal = new Date();
      session.renewalCount = (session.renewalCount || 0) + 1;

      // Update session
      await this.cache.set(sessionId, session, this.sessionConfig.duration / 1000);
      this.activeSessions.set(sessionId, session);

      // Update auth record
      await this.updateSessionInDatabase(sessionId, session);

      // Set renewal header
      res.setHeader('X-Admin-Session-Renewed', 'true');
      res.setHeader('X-Admin-Session-Expires', session.expiresAt.toISOString());

      logger.debug('Admin session renewed', {
        sessionId,
        expiresAt: session.expiresAt,
        renewalCount: session.renewalCount
      });
    } catch (error) {
      logger.error('Failed to renew session', {
        error: error.message,
        sessionId
      });
    }
  }

  /**
   * Terminate admin session
   * @param {string} sessionId - Session ID
   * @param {string} reason - Termination reason
   */
  static async terminateSession(sessionId, reason) {
    try {
      const session = this.activeSessions.get(sessionId) || await this.cache.get(sessionId);
      
      // Remove from cache
      await this.cache.delete(sessionId);
      this.activeSessions.delete(sessionId);
      this.sessionActivity.delete(`activity:${sessionId}`);

      // Update database
      if (session?.userId) {
        const authRecord = await Auth.findOne({ userId: session.userId });
        if (authRecord) {
          const sessionIndex = authRecord.sessions.findIndex(s => s.sessionId === sessionId);
          if (sessionIndex !== -1) {
            authRecord.sessions[sessionIndex].active = false;
            authRecord.sessions[sessionIndex].terminatedAt = new Date();
            authRecord.sessions[sessionIndex].terminationReason = reason;
            await authRecord.save();
          }
        }
      }

      // Audit log
      await AdminAuditLogger.logAdminEvent({
        eventType: 'admin_session_terminated',
        userId: session?.userId,
        targetType: 'session',
        operation: 'terminate',
        metadata: {
          sessionId,
          reason,
          duration: session ? Date.now() - new Date(session.createdAt).getTime() : 0
        }
      });
    } catch (error) {
      logger.error('Failed to terminate session', {
        error: error.message,
        sessionId,
        reason
      });
    }
  }

  /**
   * Monitor session patterns for anomalies
   * @param {string} sessionId - Session ID
   * @param {Object} req - Express request
   */
  static async monitorSessionPatterns(sessionId, req) {
    try {
      const patternKey = `pattern:${sessionId}`;
      const pattern = this.suspiciousPatterns.get(patternKey) || {
        rapidRequests: 0,
        unusualEndpoints: 0,
        geoChanges: 0,
        lastCheck: Date.now()
      };

      // Check rapid requests
      const activity = this.sessionActivity.get(`activity:${sessionId}`);
      if (activity) {
        const recentActions = activity.actions.filter(a => 
          Date.now() - new Date(a.timestamp).getTime() < 60000
        );
        if (recentActions.length > 100) {
          pattern.rapidRequests++;
          await this.handleSuspiciousPattern(sessionId, 'rapid_requests', {
            count: recentActions.length,
            timeWindow: '1 minute'
          });
        }
      }

      // Check unusual endpoints
      const endpoint = req.originalUrl;
      if (this.isUnusualEndpoint(endpoint)) {
        pattern.unusualEndpoints++;
        await this.handleSuspiciousPattern(sessionId, 'unusual_endpoint', {
          endpoint
        });
      }

      pattern.lastCheck = Date.now();
      this.suspiciousPatterns.set(patternKey, pattern);

      // Auto-terminate if too suspicious
      const suspicionScore = pattern.rapidRequests * 3 + 
                           pattern.unusualEndpoints * 2 + 
                           pattern.geoChanges * 5;
      
      if (suspicionScore > 10) {
        await this.terminateSession(sessionId, 'suspicious_activity');
        throw new SessionError('Session terminated due to suspicious activity');
      }
    } catch (error) {
      logger.error('Session pattern monitoring error', {
        error: error.message,
        sessionId
      });
    }
  }

  /**
   * Handle suspicious pattern detection
   * @param {string} sessionId - Session ID
   * @param {string} patternType - Pattern type
   * @param {Object} details - Pattern details
   */
  static async handleSuspiciousPattern(sessionId, patternType, details) {
    await AuditService.log({
      type: 'admin_session_suspicious_pattern',
      action: 'detect',
      category: 'security',
      result: 'detected',
      severity: 'high',
      metadata: {
        sessionId,
        patternType,
        details
      }
    });
  }

  /**
   * Get user sessions
   * @param {string} userId - User ID
   * @returns {Array} Active sessions
   */
  static async getUserSessions(userId) {
    try {
      const authRecord = await Auth.findOne({ userId });
      if (!authRecord) return [];

      return authRecord.sessions
        .filter(s => s.active && new Date(s.expiresAt) > new Date())
        .map(s => ({
          sessionId: s.sessionId,
          createdAt: s.createdAt,
          lastActivity: s.lastActivity,
          device: s.device
        }));
    } catch (error) {
      logger.error('Failed to get user sessions', {
        error: error.message,
        userId
      });
      return [];
    }
  }

  /**
   * Elevate session security level
   * @param {string} sessionId - Session ID
   * @param {string} newLevel - New security level
   * @param {number} duration - Elevation duration
   */
  static async elevateSecurityLevel(sessionId, newLevel, duration = 300000) {
    try {
      const session = this.activeSessions.get(sessionId) || await this.cache.get(sessionId);
      if (!session) {
        throw new SessionError('Session not found');
      }

      session.security.level = newLevel;
      session.security.elevatedAt = new Date();
      session.security.elevatedUntil = new Date(Date.now() + duration);

      // Update session
      await this.cache.set(sessionId, session, this.sessionConfig.duration / 1000);
      this.activeSessions.set(sessionId, session);

      // Audit log
      await AdminAuditLogger.logAdminEvent({
        eventType: 'admin_session_elevated',
        userId: session.userId,
        targetType: 'session',
        operation: 'elevate',
        metadata: {
          sessionId,
          previousLevel: session.security.level,
          newLevel,
          duration
        }
      });

      return session;
    } catch (error) {
      logger.error('Failed to elevate session security', {
        error: error.message,
        sessionId,
        newLevel
      });
      throw error;
    }
  }

  /**
   * Helper methods
   */

  static generateSessionId() {
    return `adm_ses_${crypto.randomBytes(16).toString('hex')}`;
  }

  static async generateFingerprint(req) {
    const components = [
      req.get('user-agent'),
      req.get('accept-language'),
      req.get('accept-encoding'),
      req.ip
    ];
    
    const fingerprint = crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');
    
    return fingerprint;
  }

  static shouldRenewSession(session) {
    const timeToExpiry = new Date(session.expiresAt).getTime() - Date.now();
    return timeToExpiry < this.sessionConfig.renewalWindow;
  }

  static extractPlatform(userAgent) {
    if (/Windows/.test(userAgent)) return 'Windows';
    if (/Mac/.test(userAgent)) return 'macOS';
    if (/Linux/.test(userAgent)) return 'Linux';
    if (/Android/.test(userAgent)) return 'Android';
    if (/iOS|iPhone|iPad/.test(userAgent)) return 'iOS';
    return 'Unknown';
  }

  static extractBrowser(userAgent) {
    if (/Chrome/.test(userAgent)) return 'Chrome';
    if (/Firefox/.test(userAgent)) return 'Firefox';
    if (/Safari/.test(userAgent) && !/Chrome/.test(userAgent)) return 'Safari';
    if (/Edge/.test(userAgent)) return 'Edge';
    return 'Unknown';
  }

  static async getLocationInfo(ip) {
    // This would integrate with a geolocation service
    return {
      ip,
      country: 'Unknown',
      city: 'Unknown',
      timezone: 'Unknown'
    };
  }

  static isUnusualEndpoint(endpoint) {
    const unusualPatterns = [
      /\.\.\//, // Directory traversal
      /\.(php|asp|jsp)$/i, // Suspicious file extensions
      /eval|exec|system/i, // Code execution attempts
      /union.*select/i, // SQL injection patterns
      /<script|javascript:/i // XSS attempts
    ];
    
    return unusualPatterns.some(pattern => pattern.test(endpoint));
  }

  static async loadSessionFromDatabase(sessionId, userId) {
    if (!userId) return null;
    
    try {
      const authRecord = await Auth.findOne({ 
        userId,
        'sessions.sessionId': sessionId 
      });
      
      if (!authRecord) return null;
      
      const session = authRecord.sessions.find(s => s.sessionId === sessionId);
      return session && session.active ? session : null;
    } catch (error) {
      logger.error('Failed to load session from database', {
        error: error.message,
        sessionId,
        userId
      });
      return null;
    }
  }

  static async updateSessionInDatabase(sessionId, sessionData) {
    try {
      await Auth.updateOne(
        { 'sessions.sessionId': sessionId },
        {
          $set: {
            'sessions.$.lastActivity': sessionData.lastActivity,
            'sessions.$.expiresAt': sessionData.expiresAt,
            'sessions.$.renewalCount': sessionData.renewalCount
          }
        }
      );
    } catch (error) {
      logger.error('Failed to update session in database', {
        error: error.message,
        sessionId
      });
    }
  }

  static async handleSessionError(error, req) {
    await AuditService.log({
      type: 'admin_session_error',
      action: 'error',
      category: 'security',
      result: 'error',
      severity: 'medium',
      metadata: {
        error: error.message,
        sessionId: req.adminAuth?.sessionId,
        endpoint: req.originalUrl
      }
    });
  }

  static async handleIPChange(sessionId, session, req) {
    await AuditService.log({
      type: 'admin_session_ip_change',
      action: 'detect',
      category: 'security',
      result: 'detected',
      severity: 'high',
      userId: session.userId,
      metadata: {
        sessionId,
        previousIP: session.device.ip,
        newIP: req.ip
      }
    });
  }

  static async handleUserAgentChange(sessionId, session, req) {
    await AuditService.log({
      type: 'admin_session_ua_change',
      action: 'detect',
      category: 'security',
      result: 'detected',
      severity: 'medium',
      userId: session.userId,
      metadata: {
        sessionId,
        previousUA: session.device.userAgent,
        newUA: req.get('user-agent')
      }
    });
  }

  static async handleFingerprintChange(sessionId, session, req) {
    await AuditService.log({
      type: 'admin_session_fingerprint_change',
      action: 'detect',
      category: 'security',
      result: 'detected',
      severity: 'high',
      userId: session.userId,
      metadata: {
        sessionId,
        endpoint: req.originalUrl
      }
    });
  }

  /**
   * Get session statistics
   * @returns {Object} Statistics
   */
  static getStatistics() {
    const stats = {
      activeSessions: this.activeSessions.size,
      trackedActivity: this.sessionActivity.size,
      suspiciousPatterns: this.suspiciousPatterns.size,
      sessionsBySecurityLevel: { standard: 0, elevated: 0, critical: 0 }
    };

    for (const session of this.activeSessions.values()) {
      const level = session.security?.level || 'standard';
      stats.sessionsBySecurityLevel[level]++;
    }

    return stats;
  }

  /**
   * Clean up expired data
   */
  static cleanup() {
    const now = Date.now();

    // Clean expired sessions
    for (const [sessionId, session] of this.activeSessions.entries()) {
      if (new Date(session.expiresAt).getTime() < now) {
        this.activeSessions.delete(sessionId);
        this.sessionActivity.delete(`activity:${sessionId}`);
      }
    }

    // Clean old patterns
    for (const [key, pattern] of this.suspiciousPatterns.entries()) {
      if (now - pattern.lastCheck > 86400000) { // 24 hours
        this.suspiciousPatterns.delete(key);
      }
    }
  }
}

// Initialize on module load
AdminSessionManager.initialize();

// Schedule periodic cleanup
setInterval(() => {
  AdminSessionManager.cleanup();
}, 3600000); // Every hour

module.exports = AdminSessionManager;