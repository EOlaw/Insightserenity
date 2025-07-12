/**
 * @file Admin Action Log Model
 * @description Comprehensive audit logging model for administrative actions and system events
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { ValidationError, AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

// Import admin constants
const { AdminActions } = require('../constants/admin-actions');
const { AdminRoles } = require('../constants/admin-roles');

/**
 * Request Context Schema
 * Captures the context of the request that triggered the action
 */
const requestContextSchema = new Schema({
  // HTTP Request Information
  method: {
    type: String,
    enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
    required: true
  },
  
  url: {
    type: String,
    required: true,
    trim: true
  },
  
  endpoint: {
    type: String,
    trim: true
  },
  
  userAgent: {
    type: String,
    trim: true
  },
  
  // Network Information
  sourceIP: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[a-fA-F0-9]*:+)+[a-fA-F0-9]+$/.test(v);
      },
      message: 'Invalid IP address format'
    }
  },
  
  forwardedFor: [String], // X-Forwarded-For chain
  
  // Geographic Information
  geolocation: {
    country: String,
    region: String,
    city: String,
    latitude: Number,
    longitude: Number,
    timezone: String
  },
  
  // Device Information
  device: {
    type: String,
    browser: String,
    os: String,
    platform: String,
    fingerprint: String
  },
  
  // Session Information
  sessionId: {
    type: String,
    required: true
  },
  
  requestId: String,
  correlationId: String,
  
  // Request Headers (selected important ones)
  headers: {
    contentType: String,
    authorization: String, // Redacted for security
    acceptLanguage: String,
    referer: String
  }
}, {
  _id: false
});

/**
 * Action Target Schema
 * Describes what was acted upon
 */
const actionTargetSchema = new Schema({
  // Primary target
  resourceType: {
    type: String,
    required: true,
    enum: [
      'user', 'organization', 'project', 'service', 'contract', 'proposal',
      'team', 'role', 'permission', 'configuration', 'system', 'audit_log',
      'notification', 'session', 'api_key', 'webhook', 'integration',
      'backup', 'report', 'dashboard', 'billing', 'subscription'
    ]
  },
  
  resourceId: {
    type: String,
    required: true
  },
  
  resourceName: String,
  
  // Additional target information
  parentResource: {
    type: String,
    id: String
  },
  
  // Related resources affected
  relatedResources: [{
    type: String,
    id: String,
    name: String,
    relationship: String // 'child', 'parent', 'sibling', 'reference'
  }],
  
  // Organization context
  organizationId: {
    type: Schema.Types.ObjectId,
    ref: 'Organization'
  },
  
  // Tenant context
  tenantId: {
    type: Schema.Types.ObjectId,
    ref: 'OrganizationTenant'
  }
}, {
  _id: false
});

/**
 * Change Details Schema
 * Captures what changed in the action
 */
const changeDetailsSchema = new Schema({
  // Change type
  changeType: {
    type: String,
    enum: ['create', 'update', 'delete', 'read', 'execute', 'grant', 'revoke'],
    required: true
  },
  
  // Field-level changes
  fieldChanges: [{
    field: String,
    oldValue: Schema.Types.Mixed,
    newValue: Schema.Types.Mixed,
    dataType: String, // 'string', 'number', 'boolean', 'object', 'array'
    encrypted: { type: Boolean, default: false }
  }],
  
  // Bulk operation details
  bulkOperation: {
    enabled: { type: Boolean, default: false },
    totalRecords: Number,
    successfulRecords: Number,
    failedRecords: Number,
    batchSize: Number
  },
  
  // Query details for read operations
  queryDetails: {
    filter: Schema.Types.Mixed,
    sort: Schema.Types.Mixed,
    limit: Number,
    skip: Number,
    projection: Schema.Types.Mixed
  },
  
  // File operations
  fileOperations: [{
    operation: String, // 'upload', 'download', 'delete', 'view'
    filename: String,
    fileSize: Number,
    mimeType: String,
    checksum: String
  }]
}, {
  _id: false
});

/**
 * Security Context Schema
 * Security-related information about the action
 */
const securityContextSchema = new Schema({
  // Authentication details
  authenticationMethod: {
    type: String,
    enum: ['password', 'mfa', 'api_key', 'oauth', 'sso', 'certificate'],
    required: true
  },
  
  mfaVerified: {
    type: Boolean,
    default: false
  },
  
  // Authorization details
  permissionsUsed: [String],
  roleAtTimeOfAction: String,
  
  // Security flags
  elevatedPrivileges: {
    type: Boolean,
    default: false
  },
  
  breakGlassAccess: {
    type: Boolean,
    default: false
  },
  
  impersonationActive: {
    type: Boolean,
    default: false
  },
  
  // Risk assessment
  riskLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low'
  },
  
  riskFactors: [String],
  
  // Approval information
  requiresApproval: {
    type: Boolean,
    default: false
  },
  
  approvalStatus: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'not_required'],
    default: 'not_required'
  },
  
  approvedBy: [{
    userId: { type: Schema.Types.ObjectId, ref: 'User' },
    approvedAt: Date,
    reason: String
  }]
}, {
  _id: false
});

/**
 * Admin Action Log Schema
 * Main schema for logging administrative actions
 */
const adminActionLogSchema = new Schema({
  // Action Identification
  actionId: {
    type: String,
    required: true,
    unique: true,
    default: function() {
      return `ACT-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
    }
  },
  
  // Action Type and Category
  action: {
    type: String,
    required: true,
    validate: {
      validator: function(v) {
        return Object.values(AdminActions).flat().includes(v) || 
               Object.values(AdminActions).some(category => 
                 typeof category === 'object' && Object.values(category).includes(v)
               );
      },
      message: 'Invalid admin action type'
    }
  },
  
  category: {
    type: String,
    required: true,
    enum: ['auth', 'user', 'organization', 'platform', 'security', 'system', 'billing', 'api', 'emergency']
  },
  
  subcategory: String,
  
  // Actor Information
  actor: {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    
    username: String,
    email: String,
    role: String,
    
    // For API actions
    apiKeyId: String,
    applicationName: String,
    
    // For impersonation
    originalUserId: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    
    isSystemAction: {
      type: Boolean,
      default: false
    }
  },
  
  // Timestamp Information
  timestamp: {
    type: Date,
    required: true,
    default: Date.now,
    index: true
  },
  
  // Request Context
  requestContext: {
    type: requestContextSchema,
    required: true
  },
  
  // Action Target
  target: {
    type: actionTargetSchema,
    required: true
  },
  
  // Change Details
  changes: changeDetailsSchema,
  
  // Security Context
  security: {
    type: securityContextSchema,
    required: true
  },
  
  // Result Information
  result: {
    status: {
      type: String,
      enum: ['success', 'failure', 'partial', 'pending'],
      required: true
    },
    
    statusCode: Number,
    
    message: String,
    
    errorCode: String,
    errorDetails: Schema.Types.Mixed,
    
    duration: Number, // in milliseconds
    
    // Performance metrics
    performance: {
      databaseQueries: Number,
      cacheHits: Number,
      cacheMisses: Number,
      memoryUsage: Number,
      cpuTime: Number
    }
  },
  
  // Additional Metadata
  metadata: {
    environment: {
      type: String,
      enum: ['development', 'staging', 'production'],
      default: config.nodeEnv || 'development'
    },
    
    version: String,
    buildNumber: String,
    
    // Custom fields for specific actions
    customFields: Schema.Types.Mixed,
    
    // Integration context
    integrationContext: {
      source: String,
      externalId: String,
      correlationId: String
    },
    
    // Compliance and retention
    retentionPolicy: {
      category: String,
      retainUntil: Date,
      classification: {
        type: String,
        enum: ['public', 'internal', 'confidential', 'restricted', 'top_secret'],
        default: 'confidential'
      }
    }
  },
  
  // Hash for integrity verification
  integrityHash: {
    type: String,
    required: true
  },
  
  // Chain linking for tamper detection
  previousHash: String,
  
  // Archive status
  archived: {
    type: Boolean,
    default: false
  },
  
  archivedAt: Date
}, {
  timestamps: true,
  collection: 'admin_action_logs'
});

// Indexes for performance and querying
adminActionLogSchema.index({ timestamp: -1 }); // Primary sorting index
adminActionLogSchema.index({ 'actor.userId': 1, timestamp: -1 }); // User activity
adminActionLogSchema.index({ action: 1, timestamp: -1 }); // Action type queries
adminActionLogSchema.index({ category: 1, timestamp: -1 }); // Category queries
adminActionLogSchema.index({ 'target.resourceType': 1, 'target.resourceId': 1 }); // Resource tracking
adminActionLogSchema.index({ 'target.organizationId': 1, timestamp: -1 }); // Organization filtering
adminActionLogSchema.index({ 'result.status': 1, timestamp: -1 }); // Status filtering
adminActionLogSchema.index({ 'security.riskLevel': 1, timestamp: -1 }); // Security monitoring
adminActionLogSchema.index({ 'requestContext.sourceIP': 1 }); // IP tracking
adminActionLogSchema.index({ 'requestContext.sessionId': 1 }); // Session tracking
adminActionLogSchema.index({ archived: 1, timestamp: -1 }); // Archive management

// Compound indexes for complex queries
adminActionLogSchema.index({ 
  'actor.userId': 1, 
  action: 1, 
  timestamp: -1 
}); // User action history

adminActionLogSchema.index({ 
  'target.organizationId': 1, 
  'security.riskLevel': 1, 
  timestamp: -1 
}); // Organization security monitoring

adminActionLogSchema.index({
  category: 1,
  'result.status': 1,
  timestamp: -1
}); // Category performance monitoring

// TTL index for automatic archiving (if enabled)
adminActionLogSchema.index(
  { timestamp: 1 }, 
  { 
    expireAfterSeconds: config.audit?.logRetentionSeconds || 31536000, // 1 year default
    partialFilterExpression: { archived: false }
  }
);

// Pre-save middleware for integrity hash generation
adminActionLogSchema.pre('save', function(next) {
  try {
    // Generate integrity hash
    this.integrityHash = this.generateIntegrityHash();
    
    // Set retention policy if not set
    if (!this.metadata.retentionPolicy.retainUntil) {
      const retentionPeriod = this.getRetentionPeriod();
      this.metadata.retentionPolicy.retainUntil = new Date(Date.now() + retentionPeriod);
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance Methods
adminActionLogSchema.methods = {
  /**
   * Generate integrity hash for tamper detection
   * @returns {string} Integrity hash
   */
  generateIntegrityHash() {
    const crypto = require('crypto');
    
    const hashData = {
      action: this.action,
      actor: this.actor.userId,
      timestamp: this.timestamp,
      target: this.target,
      result: this.result.status
    };
    
    return crypto
      .createHash('sha256')
      .update(JSON.stringify(hashData))
      .digest('hex');
  },
  
  /**
   * Verify integrity of log entry
   * @returns {boolean} Is integrity intact
   */
  verifyIntegrity() {
    const currentHash = this.generateIntegrityHash();
    return currentHash === this.integrityHash;
  },
  
  /**
   * Get retention period based on action type and security level
   * @returns {number} Retention period in milliseconds
   */
  getRetentionPeriod() {
    // Base retention periods (in milliseconds)
    const retentionPeriods = {
      security: 7 * 365 * 24 * 60 * 60 * 1000, // 7 years
      auth: 2 * 365 * 24 * 60 * 60 * 1000, // 2 years
      user: 5 * 365 * 24 * 60 * 60 * 1000, // 5 years
      system: 3 * 365 * 24 * 60 * 60 * 1000, // 3 years
      emergency: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
      default: 3 * 365 * 24 * 60 * 60 * 1000 // 3 years
    };
    
    // Extend retention for high-risk actions
    let period = retentionPeriods[this.category] || retentionPeriods.default;
    
    if (this.security.riskLevel === 'critical') {
      period *= 2; // Double retention for critical actions
    }
    
    return period;
  },
  
  /**
   * Sanitize sensitive data for export
   * @returns {Object} Sanitized log entry
   */
  sanitizeForExport() {
    const sanitized = this.toObject();
    
    // Remove sensitive fields
    delete sanitized.requestContext.headers.authorization;
    delete sanitized.integrityHash;
    delete sanitized.previousHash;
    
    // Sanitize IP addresses (keep first 3 octets only)
    if (sanitized.requestContext.sourceIP) {
      const ipParts = sanitized.requestContext.sourceIP.split('.');
      if (ipParts.length === 4) {
        sanitized.requestContext.sourceIP = `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.xxx`;
      }
    }
    
    // Sanitize change details if containing sensitive data
    if (sanitized.changes && sanitized.changes.fieldChanges) {
      sanitized.changes.fieldChanges = sanitized.changes.fieldChanges.map(change => {
        if (change.encrypted || change.field.includes('password') || change.field.includes('secret')) {
          return {
            ...change,
            oldValue: '[REDACTED]',
            newValue: '[REDACTED]'
          };
        }
        return change;
      });
    }
    
    return sanitized;
  }
};

// Static Methods
adminActionLogSchema.statics = {
  /**
   * Log an admin action
   * @param {Object} actionData - Action data
   * @returns {Promise<Object>} Created log entry
   */
  async logAction(actionData) {
    try {
      const logEntry = new this(actionData);
      await logEntry.save();
      
      logger.info('Admin action logged', {
        actionId: logEntry.actionId,
        action: logEntry.action,
        actor: logEntry.actor.userId,
        target: logEntry.target.resourceType
      });
      
      return logEntry;
    } catch (error) {
      logger.error('Failed to log admin action', {
        error: error.message,
        action: actionData.action,
        actor: actionData.actor?.userId
      });
      throw error;
    }
  },
  
  /**
   * Get action history for user
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} Action history
   */
  async getUserActionHistory(userId, options = {}) {
    const {
      limit = 100,
      skip = 0,
      startDate,
      endDate,
      actions,
      includeDetails = false
    } = options;
    
    const query = { 'actor.userId': userId };
    
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) query.timestamp.$gte = new Date(startDate);
      if (endDate) query.timestamp.$lte = new Date(endDate);
    }
    
    if (actions && actions.length) {
      query.action = { $in: actions };
    }
    
    const projection = includeDetails ? {} : {
      action: 1,
      category: 1,
      timestamp: 1,
      'target.resourceType': 1,
      'target.resourceId': 1,
      'result.status': 1
    };
    
    return this.find(query, projection)
      .sort({ timestamp: -1 })
      .limit(limit)
      .skip(skip)
      .lean();
  },
  
  /**
   * Get security events for monitoring
   * @param {Object} filters - Security filters
   * @returns {Promise<Array>} Security events
   */
  async getSecurityEvents(filters = {}) {
    const {
      riskLevel,
      timeWindow = 24 * 60 * 60 * 1000, // 24 hours
      organizationId,
      limit = 1000
    } = filters;
    
    const query = {
      timestamp: { $gte: new Date(Date.now() - timeWindow) }
    };
    
    if (riskLevel) {
      query['security.riskLevel'] = riskLevel;
    }
    
    if (organizationId) {
      query['target.organizationId'] = organizationId;
    }
    
    // Focus on security-relevant actions
    query.$or = [
      { category: 'security' },
      { 'security.elevatedPrivileges': true },
      { 'security.breakGlassAccess': true },
      { 'security.riskLevel': { $in: ['high', 'critical'] } },
      { 'result.status': 'failure' }
    ];
    
    return this.find(query)
      .sort({ timestamp: -1 })
      .limit(limit)
      .populate('actor.userId', 'username email')
      .lean();
  },
  
  /**
   * Verify log chain integrity
   * @param {Object} options - Verification options
   * @returns {Promise<Object>} Verification result
   */
  async verifyLogChainIntegrity(options = {}) {
    const { limit = 1000, startDate } = options;
    
    const query = startDate ? { timestamp: { $gte: new Date(startDate) } } : {};
    
    const logs = await this.find(query)
      .sort({ timestamp: 1 })
      .limit(limit)
      .lean();
    
    let integrityIssues = 0;
    let chainIssues = 0;
    
    for (let i = 0; i < logs.length; i++) {
      const log = logs[i];
      
      // Verify individual log integrity
      if (!this.prototype.verifyIntegrity.call(log)) {
        integrityIssues++;
      }
      
      // Verify chain linkage
      if (i > 0 && log.previousHash !== logs[i - 1].integrityHash) {
        chainIssues++;
      }
    }
    
    return {
      totalLogs: logs.length,
      integrityIssues,
      chainIssues,
      isIntact: integrityIssues === 0 && chainIssues === 0,
      verifiedAt: new Date()
    };
  }
};

// Create the model
const AdminActionLog = mongoose.model('AdminActionLog', adminActionLogSchema);

module.exports = AdminActionLog;