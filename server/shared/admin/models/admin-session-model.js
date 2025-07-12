/**
 * @file Admin Session Model
 * @description Comprehensive session management for administrative users with security monitoring and lifecycle tracking
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;
const crypto = require('crypto');

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { ValidationError, AppError, AuthenticationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

// Import admin constants
const { AdminRoles } = require('../constants/admin-roles');
const { AdminSecurityConfig } = require('../config/admin-security-config');

/**
 * Device Information Schema
 * Captures detailed device and browser information
 */
const deviceInfoSchema = new Schema({
  // Browser information
  browser: {
    name: String,
    version: String,
    engine: String,
    engineVersion: String
  },
  
  // Operating system
  os: {
    name: String,
    version: String,
    platform: String,
    architecture: String
  },
  
  // Device details
  device: {
    type: {
      type: String,
      enum: ['desktop', 'laptop', 'tablet', 'mobile', 'unknown'],
      default: 'unknown'
    },
    vendor: String,
    model: String,
    isMobile: { type: Boolean, default: false },
    isTablet: { type: Boolean, default: false }
  },
  
  // Screen information
  screen: {
    width: Number,
    height: Number,
    colorDepth: Number,
    pixelRatio: Number
  },
  
  // Browser capabilities
  capabilities: {
    cookies: { type: Boolean, default: true },
    localStorage: { type: Boolean, default: true },
    sessionStorage: { type: Boolean, default: true },
    webGL: { type: Boolean, default: false },
    touchScreen: { type: Boolean, default: false }
  },
  
  // Device fingerprint
  fingerprint: {
    canvas: String,
    webGL: String,
    audio: String,
    fonts: [String],
    plugins: [String],
    composite: String // Combined fingerprint hash
  },
  
  // Trust level
  trustLevel: {
    type: String,
    enum: ['unknown', 'untrusted', 'recognized', 'trusted'],
    default: 'unknown'
  },
  
  // Device registration
  isRegistered: { type: Boolean, default: false },
  registeredAt: Date,
  lastSeen: Date
}, {
  _id: false
});

/**
 * Network Information Schema
 * Captures network and location details
 */
const networkInfoSchema = new Schema({
  // IP address information
  ipAddress: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[a-fA-F0-9]*:+)+[a-fA-F0-9]+$/.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  
  ipVersion: {
    type: String,
    enum: ['IPv4', 'IPv6'],
    default: 'IPv4'
  },
  
  // Proxy and forwarding
  forwardedFor: [String],
  realIp: String,
  proxyDetected: { type: Boolean, default: false },
  vpnDetected: { type: Boolean, default: false },
  torDetected: { type: Boolean, default: false },
  
  // Geographic location
  geolocation: {
    country: String,
    countryCode: String,
    region: String,
    regionCode: String,
    city: String,
    postalCode: String,
    latitude: Number,
    longitude: Number,
    timezone: String,
    isp: String,
    organization: String,
    asn: String
  },
  
  // Network characteristics
  network: {
    connectionType: String, // 'broadband', 'cellular', 'wifi', etc.
    downlinkSpeed: Number,
    effectiveType: String, // '2g', '3g', '4g', '5g'
    rtt: Number // Round trip time
  },
  
  // Risk assessment
  riskFactors: [{
    factor: String,
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical']
    },
    details: String
  }],
  
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0
  }
}, {
  _id: false
});

/**
 * Authentication Details Schema
 * Tracks authentication methods and security events
 */
const authenticationDetailsSchema = new Schema({
  // Primary authentication
  method: {
    type: String,
    required: true,
    enum: ['password', 'mfa', 'sso', 'api_key', 'certificate', 'biometric']
  },
  
  // Multi-factor authentication
  mfa: {
    required: { type: Boolean, default: false },
    verified: { type: Boolean, default: false },
    method: {
      type: String,
      enum: ['totp', 'sms', 'email', 'webauthn', 'backup_codes']
    },
    verifiedAt: Date,
    attempts: { type: Number, default: 0 },
    maxAttempts: { type: Number, default: 3 }
  },
  
  // Single Sign-On details
  sso: {
    provider: String,
    providerId: String,
    assertion: String,
    attributes: Schema.Types.Mixed
  },
  
  // Certificate authentication
  certificate: {
    subject: String,
    issuer: String,
    fingerprint: String,
    validFrom: Date,
    validTo: Date
  },
  
  // Authentication timing
  authenticatedAt: {
    type: Date,
    required: true,
    default: Date.now
  },
  
  lastVerificationAt: Date,
  
  // Security events during authentication
  securityEvents: [{
    event: String,
    timestamp: Date,
    details: Schema.Types.Mixed,
    severity: {
      type: String,
      enum: ['info', 'warning', 'error', 'critical']
    }
  }],
  
  // Trust indicators
  trustIndicators: {
    knownDevice: { type: Boolean, default: false },
    knownLocation: { type: Boolean, default: false },
    regularPattern: { type: Boolean, default: false },
    recentActivity: { type: Boolean, default: false }
  }
}, {
  _id: false
});

/**
 * Session Activity Schema
 * Tracks user activity during the session
 */
const sessionActivitySchema = new Schema({
  // Activity tracking
  lastActivity: {
    type: Date,
    required: true,
    default: Date.now,
    index: true
  },
  
  activityCount: { type: Number, default: 0 },
  
  // Page/endpoint tracking
  pages: [{
    path: String,
    method: String,
    timestamp: Date,
    duration: Number, // Time spent on page in milliseconds
    exitMethod: String // 'navigation', 'close', 'timeout'
  }],
  
  // API usage tracking
  apiCalls: [{
    endpoint: String,
    method: String,
    timestamp: Date,
    responseTime: Number,
    statusCode: Number,
    userAgent: String
  }],
  
  // User interactions
  interactions: [{
    type: {
      type: String,
      enum: ['click', 'form_submit', 'search', 'filter', 'download', 'upload', 'delete', 'create', 'update']
    },
    target: String,
    timestamp: Date,
    metadata: Schema.Types.Mixed
  }],
  
  // Session metrics
  metrics: {
    totalRequests: { type: Number, default: 0 },
    totalDataTransferred: { type: Number, default: 0 },
    averageResponseTime: { type: Number, default: 0 },
    errorCount: { type: Number, default: 0 },
    warningCount: { type: Number, default: 0 }
  },
  
  // Idle tracking
  idle: {
    isIdle: { type: Boolean, default: false },
    idleSince: Date,
    idleDuration: { type: Number, default: 0 }, // Total idle time in milliseconds
    idleWarningsSent: { type: Number, default: 0 }
  },
  
  // Performance metrics
  performance: {
    memoryUsage: Number,
    cpuUsage: Number,
    networkLatency: Number,
    renderTime: Number
  }
}, {
  _id: false
});

/**
 * Security Context Schema
 * Security-related session information
 */
const securityContextSchema = new Schema({
  // Security level
  level: {
    type: String,
    enum: ['standard', 'elevated', 'high', 'critical'],
    default: 'standard'
  },
  
  // Privilege information
  privileges: {
    current: [String],
    elevated: [String],
    temporary: [{
      privilege: String,
      grantedAt: Date,
      expiresAt: Date,
      grantedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      reason: String
    }]
  },
  
  // Impersonation status
  impersonation: {
    active: { type: Boolean, default: false },
    originalUserId: { type: Schema.Types.ObjectId, ref: 'User' },
    targetUserId: { type: Schema.Types.ObjectId, ref: 'User' },
    startedAt: Date,
    reason: String,
    approvedBy: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    sessionRecording: { type: Boolean, default: true }
  },
  
  // Break glass access
  breakGlass: {
    active: { type: Boolean, default: false },
    activatedAt: Date,
    reason: String,
    approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    expiresAt: Date,
    autoRevoke: { type: Boolean, default: true }
  },
  
  // Security warnings and alerts
  warnings: [{
    type: String,
    message: String,
    timestamp: Date,
    acknowledged: { type: Boolean, default: false },
    acknowledgedAt: Date
  }],
  
  // Threat detection
  threatDetection: {
    anomalyScore: { type: Number, default: 0, min: 0, max: 100 },
    behaviorFlags: [String],
    riskAssessment: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'low'
    },
    lastThreatCheck: Date
  },
  
  // Compliance tracking
  compliance: {
    dataAccessLogged: { type: Boolean, default: true },
    auditTrailActive: { type: Boolean, default: true },
    retentionPolicy: String,
    jurisdiction: String
  }
}, {
  _id: false
});

/**
 * Admin Session Schema
 * Main schema for administrative session management
 */
const adminSessionSchema = new Schema({
  // Session Identification
  sessionId: {
    type: String,
    required: true,
    unique: true,
    default: function() {
      return crypto.randomBytes(32).toString('hex');
    }
  },
  
  // User Information
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  userInfo: {
    username: String,
    email: String,
    role: String,
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization' },
    tenantId: { type: Schema.Types.ObjectId, ref: 'OrganizationTenant' }
  },
  
  // Session Lifecycle
  status: {
    type: String,
    required: true,
    enum: ['active', 'idle', 'expired', 'terminated', 'locked', 'suspended'],
    default: 'active',
    index: true
  },
  
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
    index: true
  },
  
  expiresAt: {
    type: Date,
    required: true,
    index: true
  },
  
  terminatedAt: Date,
  
  // Session Configuration
  configuration: {
    maxDuration: { type: Number, default: 8 * 60 * 60 * 1000 }, // 8 hours in milliseconds
    idleTimeout: { type: Number, default: 30 * 60 * 1000 }, // 30 minutes
    absoluteTimeout: { type: Number, default: 24 * 60 * 60 * 1000 }, // 24 hours
    securityLevel: {
      type: String,
      enum: ['standard', 'elevated', 'high', 'critical'],
      default: 'standard'
    },
    allowConcurrent: { type: Boolean, default: true },
    maxConcurrent: { type: Number, default: 3 }
  },
  
  // Device and Network Information
  device: {
    type: deviceInfoSchema,
    required: true
  },
  
  network: {
    type: networkInfoSchema,
    required: true
  },
  
  // Authentication Details
  authentication: {
    type: authenticationDetailsSchema,
    required: true
  },
  
  // Session Activity
  activity: {
    type: sessionActivitySchema,
    default: () => ({})
  },
  
  // Security Context
  security: {
    type: securityContextSchema,
    default: () => ({})
  },
  
  // Session Tokens
  tokens: {
    accessToken: {
      value: String,
      expiresAt: Date,
      scopes: [String]
    },
    
    refreshToken: {
      value: String,
      expiresAt: Date,
      rotatedAt: Date,
      rotationCount: { type: Number, default: 0 }
    },
    
    csrfToken: {
      value: String,
      expiresAt: Date
    }
  },
  
  // Session Metadata
  metadata: {
    environment: {
      type: String,
      enum: ['development', 'staging', 'production'],
      default: config.nodeEnv || 'development'
    },
    
    version: String,
    buildNumber: String,
    
    // Custom metadata
    custom: Schema.Types.Mixed,
    
    // Integration context
    integration: {
      source: String,
      externalSessionId: String,
      correlationId: String
    }
  },
  
  // Termination Information
  termination: {
    reason: {
      type: String,
      enum: ['logout', 'timeout', 'admin_terminate', 'security_violation', 'system_shutdown', 'token_expired', 'max_sessions_exceeded']
    },
    
    terminatedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    
    details: String,
    
    graceful: { type: Boolean, default: true }
  }
}, {
  timestamps: true,
  collection: 'admin_sessions'
});

// Indexes for performance and querying
adminSessionSchema.index({ sessionId: 1 }, { unique: true });
adminSessionSchema.index({ userId: 1, status: 1 });
adminSessionSchema.index({ status: 1, expiresAt: 1 });
adminSessionSchema.index({ createdAt: -1 });
adminSessionSchema.index({ 'activity.lastActivity': -1 });
adminSessionSchema.index({ 'network.ipAddress': 1 });
adminSessionSchema.index({ 'userInfo.organizationId': 1 });
adminSessionSchema.index({ 'security.level': 1 });
adminSessionSchema.index({ 'device.fingerprint.composite': 1 });

// Compound indexes
adminSessionSchema.index({
  userId: 1,
  status: 1,
  createdAt: -1
});

adminSessionSchema.index({
  'userInfo.organizationId': 1,
  status: 1,
  'activity.lastActivity': -1
});

// TTL index for automatic cleanup
adminSessionSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

// Pre-save middleware
adminSessionSchema.pre('save', function(next) {
  try {
    // Set expiration if not set
    if (!this.expiresAt) {
      this.expiresAt = new Date(Date.now() + this.configuration.maxDuration);
    }
    
    // Update activity metrics
    if (this.isModified('activity.lastActivity')) {
      this.activity.activityCount += 1;
    }
    
    // Generate device fingerprint if not exists
    if (this.device && !this.device.fingerprint.composite) {
      this.device.fingerprint.composite = this.generateDeviceFingerprint();
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance Methods
adminSessionSchema.methods = {
  /**
   * Update session activity
   * @param {Object} activityData - Activity information
   * @returns {Promise<boolean>} Success status
   */
  async updateActivity(activityData = {}) {
    const now = new Date();
    
    // Update last activity
    this.activity.lastActivity = now;
    this.activity.activityCount += 1;
    
    // Reset idle status
    if (this.activity.idle.isIdle) {
      this.activity.idle.isIdle = false;
      this.activity.idle.idleDuration += now - this.activity.idle.idleSince;
      this.activity.idle.idleSince = null;
    }
    
    // Add specific activity if provided
    if (activityData.type) {
      this.activity.interactions.push({
        type: activityData.type,
        target: activityData.target,
        timestamp: now,
        metadata: activityData.metadata
      });
    }
    
    // Check if session should be extended
    if (this.shouldExtendSession()) {
      this.extendSession();
    }
    
    await this.save();
    return true;
  },
  
  /**
   * Check if session should be extended
   * @returns {boolean} Should extend
   */
  shouldExtendSession() {
    const timeUntilExpiry = this.expiresAt - new Date();
    const extensionThreshold = this.configuration.maxDuration * 0.1; // 10% of max duration
    
    return timeUntilExpiry < extensionThreshold && timeUntilExpiry > 0;
  },
  
  /**
   * Extend session expiration
   * @param {number} extensionMs - Extension time in milliseconds
   * @returns {Date} New expiration time
   */
  extendSession(extensionMs = null) {
    const extension = extensionMs || (this.configuration.maxDuration * 0.5); // 50% extension
    const maxExtendedTime = new Date(this.createdAt.getTime() + this.configuration.absoluteTimeout);
    
    const newExpiration = new Date(this.expiresAt.getTime() + extension);
    this.expiresAt = newExpiration > maxExtendedTime ? maxExtendedTime : newExpiration;
    
    logger.info('Admin session extended', {
      sessionId: this.sessionId,
      userId: this.userId,
      newExpiration: this.expiresAt
    });
    
    return this.expiresAt;
  },
  
  /**
   * Mark session as idle
   * @returns {Promise<boolean>} Success status
   */
  async markAsIdle() {
    if (!this.activity.idle.isIdle) {
      this.activity.idle.isIdle = true;
      this.activity.idle.idleSince = new Date();
      this.status = 'idle';
      
      await this.save();
      
      logger.info('Admin session marked as idle', {
        sessionId: this.sessionId,
        userId: this.userId
      });
    }
    
    return true;
  },
  
  /**
   * Terminate session
   * @param {string} reason - Termination reason
   * @param {string} terminatedBy - User ID who terminated the session
   * @param {boolean} graceful - Whether termination was graceful
   * @returns {Promise<boolean>} Success status
   */
  async terminate(reason = 'logout', terminatedBy = null, graceful = true) {
    this.status = 'terminated';
    this.terminatedAt = new Date();
    this.termination = {
      reason,
      terminatedBy,
      graceful,
      details: this.getTerminationDetails(reason)
    };
    
    // Invalidate tokens
    if (this.tokens.accessToken) {
      this.tokens.accessToken.expiresAt = new Date();
    }
    if (this.tokens.refreshToken) {
      this.tokens.refreshToken.expiresAt = new Date();
    }
    
    await this.save();
    
    logger.info('Admin session terminated', {
      sessionId: this.sessionId,
      userId: this.userId,
      reason,
      graceful
    });
    
    return true;
  },
  
  /**
   * Get termination details based on reason
   * @param {string} reason - Termination reason
   * @returns {string} Termination details
   */
  getTerminationDetails(reason) {
    const details = {
      logout: 'User initiated logout',
      timeout: 'Session timed out due to inactivity',
      admin_terminate: 'Session terminated by administrator',
      security_violation: 'Session terminated due to security violation',
      system_shutdown: 'Session terminated due to system shutdown',
      token_expired: 'Session terminated due to token expiration',
      max_sessions_exceeded: 'Session terminated due to maximum session limit'
    };
    
    return details[reason] || 'Session terminated';
  },
  
  /**
   * Check if session is valid
   * @returns {boolean} Is valid
   */
  isValid() {
    if (this.status === 'terminated' || this.status === 'expired') {
      return false;
    }
    
    if (new Date() > this.expiresAt) {
      return false;
    }
    
    // Check idle timeout
    if (this.activity.idle.isIdle) {
      const idleDuration = new Date() - this.activity.idle.idleSince;
      if (idleDuration > this.configuration.idleTimeout) {
        return false;
      }
    }
    
    return true;
  },
  
  /**
   * Generate device fingerprint
   * @returns {string} Device fingerprint
   */
  generateDeviceFingerprint() {
    const components = [
      this.device.browser?.name,
      this.device.browser?.version,
      this.device.os?.name,
      this.device.os?.version,
      this.device.screen?.width,
      this.device.screen?.height,
      this.device.capabilities?.webGL,
      this.device.fingerprint?.canvas
    ].filter(Boolean);
    
    return crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');
  },
  
  /**
   * Calculate session risk score
   * @returns {number} Risk score (0-100)
   */
  calculateRiskScore() {
    let riskScore = 0;
    
    // Network risk factors
    if (this.network.proxyDetected) riskScore += 10;
    if (this.network.vpnDetected) riskScore += 15;
    if (this.network.torDetected) riskScore += 25;
    
    // Device risk factors
    if (this.device.trustLevel === 'untrusted') riskScore += 20;
    if (this.device.trustLevel === 'unknown') riskScore += 10;
    
    // Authentication risk factors
    if (!this.authentication.mfa.verified) riskScore += 15;
    if (this.authentication.securityEvents.length > 0) riskScore += 10;
    
    // Activity risk factors
    if (this.activity.metrics.errorCount > 10) riskScore += 5;
    if (this.security.privileges.elevated.length > 0) riskScore += 10;
    
    // Impersonation adds risk
    if (this.security.impersonation.active) riskScore += 20;
    
    // Break glass access is high risk
    if (this.security.breakGlass.active) riskScore += 30;
    
    return Math.min(riskScore, 100);
  },
  
  /**
   * Get session summary for dashboard
   * @returns {Object} Session summary
   */
  getSummary() {
    return {
      sessionId: this.sessionId,
      userId: this.userId,
      username: this.userInfo.username,
      role: this.userInfo.role,
      status: this.status,
      createdAt: this.createdAt,
      lastActivity: this.activity.lastActivity,
      expiresAt: this.expiresAt,
      ipAddress: this.network.ipAddress,
      location: this.network.geolocation?.city,
      device: this.device.device?.type,
      browser: this.device.browser?.name,
      riskScore: this.calculateRiskScore(),
      isImpersonating: this.security.impersonation.active,
      hasElevatedPrivileges: this.security.privileges.elevated.length > 0
    };
  }
};

// Static Methods
adminSessionSchema.statics = {
  /**
   * Create new admin session
   * @param {Object} sessionData - Session creation data
   * @returns {Promise<Object>} Created session
   */
  async createSession(sessionData) {
    try {
      // Check for existing active sessions
      const existingSessions = await this.countDocuments({
        userId: sessionData.userId,
        status: 'active'
      });
      
      // Enforce session limits
      const maxSessions = sessionData.configuration?.maxConcurrent || 3;
      if (existingSessions >= maxSessions) {
        throw new AuthenticationError('Maximum number of concurrent sessions exceeded');
      }
      
      const session = new this(sessionData);
      await session.save();
      
      logger.info('Admin session created', {
        sessionId: session.sessionId,
        userId: session.userId,
        ipAddress: session.network.ipAddress
      });
      
      return session;
    } catch (error) {
      logger.error('Failed to create admin session', {
        error: error.message,
        userId: sessionData.userId
      });
      throw error;
    }
  },
  
  /**
   * Get active sessions for user
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Active sessions
   */
  async getActiveSessions(userId) {
    return this.find({
      userId,
      status: { $in: ['active', 'idle'] },
      expiresAt: { $gt: new Date() }
    }).sort({ 'activity.lastActivity': -1 });
  },
  
  /**
   * Terminate all sessions for user
   * @param {string} userId - User ID
   * @param {string} reason - Termination reason
   * @param {string} terminatedBy - Who terminated the sessions
   * @returns {Promise<number>} Number of sessions terminated
   */
  async terminateAllUserSessions(userId, reason = 'admin_terminate', terminatedBy = null) {
    const sessions = await this.find({
      userId,
      status: { $in: ['active', 'idle'] }
    });
    
    let terminatedCount = 0;
    
    for (const session of sessions) {
      await session.terminate(reason, terminatedBy, false);
      terminatedCount++;
    }
    
    logger.info('All user sessions terminated', {
      userId,
      terminatedCount,
      reason
    });
    
    return terminatedCount;
  },
  
  /**
   * Cleanup expired sessions
   * @param {Object} options - Cleanup options
   * @returns {Promise<Object>} Cleanup results
   */
  async cleanupExpiredSessions(options = {}) {
    const { batchSize = 1000, olderThan = 24 * 60 * 60 * 1000 } = options; // 24 hours
    
    const cutoffTime = new Date(Date.now() - olderThan);
    
    // Find expired sessions
    const expiredQuery = {
      $or: [
        { expiresAt: { $lt: new Date() } },
        { 
          status: 'terminated',
          terminatedAt: { $lt: cutoffTime }
        }
      ]
    };
    
    const expiredCount = await this.countDocuments(expiredQuery);
    
    // Delete expired sessions in batches
    const deleteResult = await this.deleteMany(expiredQuery);
    
    logger.info('Expired admin sessions cleaned up', {
      deletedCount: deleteResult.deletedCount,
      totalExpired: expiredCount
    });
    
    return {
      deletedCount: deleteResult.deletedCount,
      totalExpired: expiredCount
    };
  },
  
  /**
   * Get session analytics
   * @param {Object} filters - Analytics filters
   * @returns {Promise<Object>} Session analytics
   */
  async getSessionAnalytics(filters = {}) {
    const {
      timeWindow = 24 * 60 * 60 * 1000, // 24 hours
      organizationId,
      userId
    } = filters;
    
    const matchQuery = {
      createdAt: { $gte: new Date(Date.now() - timeWindow) }
    };
    
    if (organizationId) {
      matchQuery['userInfo.organizationId'] = organizationId;
    }
    
    if (userId) {
      matchQuery.userId = userId;
    }
    
    const pipeline = [
      { $match: matchQuery },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            status: '$status'
          },
          count: { $sum: 1 },
          avgDuration: {
            $avg: {
              $subtract: [
                { $ifNull: ['$terminatedAt', new Date()] },
                '$createdAt'
              ]
            }
          },
          avgRiskScore: { $avg: '$security.threatDetection.anomalyScore' }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          statuses: {
            $push: {
              status: '$_id.status',
              count: '$count',
              avgDuration: '$avgDuration',
              avgRiskScore: '$avgRiskScore'
            }
          },
          totalSessions: { $sum: '$count' }
        }
      },
      { $sort: { _id: 1 } }
    ];
    
    const results = await this.aggregate(pipeline);
    
    // Calculate summary statistics
    const totalSessions = results.reduce((sum, day) => sum + day.totalSessions, 0);
    const avgSessionsPerDay = totalSessions / (results.length || 1);
    
    return {
      timeWindow,
      totalSessions,
      avgSessionsPerDay,
      dailyBreakdown: results,
      generatedAt: new Date()
    };
  },
  
  /**
   * Detect suspicious sessions
   * @param {Object} criteria - Detection criteria
   * @returns {Promise<Array>} Suspicious sessions
   */
  async detectSuspiciousSessions(criteria = {}) {
    const {
      minRiskScore = 50,
      maxIdleTime = 2 * 60 * 60 * 1000, // 2 hours
      checkImpersonation = true,
      checkVPN = true
    } = criteria;
    
    const suspiciousQuery = {
      status: { $in: ['active', 'idle'] },
      $or: []
    };
    
    // High risk score
    suspiciousQuery.$or.push({
      'security.threatDetection.anomalyScore': { $gte: minRiskScore }
    });
    
    // Long idle sessions
    suspiciousQuery.$or.push({
      'activity.idle.isIdle': true,
      'activity.idle.idleSince': { $lt: new Date(Date.now() - maxIdleTime) }
    });
    
    // Active impersonation (if checking)
    if (checkImpersonation) {
      suspiciousQuery.$or.push({
        'security.impersonation.active': true
      });
    }
    
    // VPN/Proxy detection (if checking)
    if (checkVPN) {
      suspiciousQuery.$or.push({
        $or: [
          { 'network.vpnDetected': true },
          { 'network.proxyDetected': true },
          { 'network.torDetected': true }
        ]
      });
    }
    
    const suspiciousSessions = await this.find(suspiciousQuery)
      .populate('userId', 'username email')
      .sort({ 'security.threatDetection.anomalyScore': -1 })
      .limit(100);
    
    logger.info('Suspicious session detection completed', {
      criteriaUsed: criteria,
      suspiciousCount: suspiciousSessions.length
    });
    
    return suspiciousSessions;
  },
  
  /**
   * Get session by token
   * @param {string} token - Session token
   * @param {string} tokenType - Token type ('access', 'refresh', 'csrf')
   * @returns {Promise<Object|null>} Session object
   */
  async getByToken(token, tokenType = 'access') {
    const tokenField = `tokens.${tokenType}Token.value`;
    const expiryField = `tokens.${tokenType}Token.expiresAt`;
    
    return this.findOne({
      [tokenField]: token,
      [expiryField]: { $gt: new Date() },
      status: { $in: ['active', 'idle'] }
    });
  }
};

// Create the model
const AdminSession = mongoose.model('AdminSession', adminSessionSchema);

module.exports = AdminSession;