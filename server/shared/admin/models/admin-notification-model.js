/**
 * @file Admin Notification Model
 * @description Comprehensive notification system for administrative alerts, warnings, and system messages
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { ValidationError, AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

// Import admin constants
const { AdminRoles } = require('../constants/admin-roles');
const { AdminActions } = require('../constants/admin-actions');

/**
 * Notification Channel Schema
 * Defines how notifications are delivered
 */
const notificationChannelSchema = new Schema({
  // Channel type
  type: {
    type: String,
    required: true,
    enum: ['in_app', 'email', 'sms', 'push', 'webhook', 'slack', 'teams', 'pager']
  },
  
  // Channel configuration
  configuration: {
    // Email configuration
    emailTemplate: String,
    emailSubject: String,
    emailPriority: {
      type: String,
      enum: ['low', 'normal', 'high', 'urgent'],
      default: 'normal'
    },
    
    // SMS configuration
    smsTemplate: String,
    
    // Push notification configuration
    pushTitle: String,
    pushIcon: String,
    pushSound: String,
    
    // Webhook configuration
    webhookUrl: String,
    webhookMethod: {
      type: String,
      enum: ['GET', 'POST', 'PUT', 'PATCH'],
      default: 'POST'
    },
    webhookHeaders: Schema.Types.Mixed,
    webhookPayload: Schema.Types.Mixed,
    
    // Third-party integrations
    slackChannel: String,
    slackWebhook: String,
    teamsWebhook: String,
    pagerDutyKey: String
  },
  
  // Delivery status
  deliveryStatus: {
    type: String,
    enum: ['pending', 'sent', 'delivered', 'failed', 'bounced', 'opened', 'clicked'],
    default: 'pending'
  },
  
  deliveryAttempts: {
    type: Number,
    default: 0
  },
  
  lastAttemptAt: Date,
  deliveredAt: Date,
  
  // Error information
  errorMessage: String,
  errorCode: String,
  
  // Tracking information
  messageId: String, // External message ID from provider
  trackingId: String,
  
  // Metrics
  openedAt: Date,
  clickedAt: Date,
  responseTime: Number // Time to delivery in milliseconds
}, {
  _id: false
});

/**
 * Notification Target Schema
 * Defines who should receive the notification
 */
const notificationTargetSchema = new Schema({
  // Target type
  targetType: {
    type: String,
    required: true,
    enum: ['user', 'role', 'group', 'organization', 'all_admins', 'custom']
  },
  
  // Specific targets
  users: [{
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    username: String,
    email: String,
    preferredChannels: [String],
    deliveryStatus: {
      type: String,
      enum: ['pending', 'sent', 'delivered', 'failed', 'dismissed', 'acknowledged'],
      default: 'pending'
    },
    acknowledgedAt: Date,
    dismissedAt: Date
  }],
  
  // Role-based targeting
  roles: [{
    type: String,
    validate: {
      validator: function(v) {
        return Object.values(AdminRoles).some(role => role.name === v);
      },
      message: 'Invalid admin role'
    }
  }],
  
  // Organization targeting
  organizations: [{
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization' },
    tenantId: { type: Schema.Types.ObjectId, ref: 'OrganizationTenant' }
  }],
  
  // Custom groups
  customGroups: [String],
  
  // Filtering criteria
  filters: {
    minimumRole: String,
    permissions: [String],
    departments: [String],
    locations: [String],
    activeOnly: { type: Boolean, default: true }
  }
}, {
  _id: false
});

/**
 * Notification Content Schema
 * Contains the actual notification content
 */
const notificationContentSchema = new Schema({
  // Basic content
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: [200, 'Title cannot exceed 200 characters']
  },
  
  message: {
    type: String,
    required: true,
    trim: true,
    maxlength: [2000, 'Message cannot exceed 2000 characters']
  },
  
  summary: {
    type: String,
    trim: true,
    maxlength: [500, 'Summary cannot exceed 500 characters']
  },
  
  // Rich content
  htmlContent: String,
  markdownContent: String,
  
  // Multimedia attachments
  attachments: [{
    type: {
      type: String,
      enum: ['image', 'document', 'video', 'audio', 'link'],
      required: true
    },
    url: String,
    filename: String,
    size: Number,
    mimeType: String,
    thumbnail: String,
    description: String
  }],
  
  // Action buttons
  actions: [{
    id: String,
    label: String,
    action: String, // URL or action identifier
    style: {
      type: String,
      enum: ['primary', 'secondary', 'danger', 'warning', 'success'],
      default: 'secondary'
    },
    requiresConfirmation: { type: Boolean, default: false },
    confirmationMessage: String
  }],
  
  // Localization
  localization: {
    defaultLanguage: { type: String, default: 'en' },
    translations: Schema.Types.Mixed // { 'es': { title: '...', message: '...' } }
  },
  
  // Content metadata
  contentType: {
    type: String,
    enum: ['plain', 'rich', 'interactive', 'alert', 'digest'],
    default: 'plain'
  },
  
  encoding: { type: String, default: 'utf-8' }
}, {
  _id: false
});

/**
 * Admin Notification Schema
 * Main schema for administrative notifications
 */
const adminNotificationSchema = new Schema({
  // Notification Identification
  notificationId: {
    type: String,
    required: true,
    unique: true,
    default: function() {
      return `NOTIF-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
    }
  },
  
  // Notification Type and Category
  type: {
    type: String,
    required: true,
    enum: [
      'security_alert', 'system_alert', 'performance_warning', 'maintenance_notice',
      'user_action', 'policy_violation', 'audit_alert', 'compliance_reminder',
      'quota_warning', 'service_disruption', 'update_available', 'emergency_alert',
      'approval_request', 'task_assignment', 'deadline_reminder', 'report_ready',
      'integration_status', 'backup_status', 'license_expiry', 'custom_alert'
    ]
  },
  
  category: {
    type: String,
    required: true,
    enum: ['security', 'system', 'operations', 'compliance', 'business', 'maintenance', 'emergency']
  },
  
  subcategory: String,
  
  // Priority and Urgency
  priority: {
    type: String,
    required: true,
    enum: ['low', 'normal', 'high', 'urgent', 'critical'],
    default: 'normal'
  },
  
  urgency: {
    type: String,
    enum: ['defer', 'normal', 'expedite', 'immediate'],
    default: 'normal'
  },
  
  // Severity for alerts
  severity: {
    type: String,
    enum: ['info', 'warning', 'error', 'critical'],
    default: 'info'
  },
  
  // Source Information
  source: {
    system: {
      type: String,
      required: true,
      default: 'admin_system'
    },
    
    component: String, // 'auth', 'billing', 'user_management', etc.
    
    triggeredBy: {
      type: {
        type: String,
        enum: ['user', 'system', 'schedule', 'webhook', 'api'],
        required: true
      },
      
      userId: { type: Schema.Types.ObjectId, ref: 'User' },
      username: String,
      
      // For system-triggered notifications
      processId: String,
      jobId: String,
      
      // For external triggers
      apiKeyId: String,
      webhookId: String,
      integrationId: String
    },
    
    originatingEvent: {
      eventId: String,
      eventType: String,
      timestamp: Date
    }
  },
  
  // Timing Information
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
    index: true
  },
  
  scheduledFor: Date, // For scheduled notifications
  
  expiresAt: Date, // When notification becomes irrelevant
  
  // Content
  content: {
    type: notificationContentSchema,
    required: true
  },
  
  // Targeting
  targeting: {
    type: notificationTargetSchema,
    required: true
  },
  
  // Delivery Channels
  channels: [notificationChannelSchema],
  
  // Context and Metadata
  context: {
    // Related resources
    relatedResources: [{
      resourceType: String,
      resourceId: String,
      resourceName: String,
      url: String
    }],
    
    // Geographic context
    geographic: {
      regions: [String],
      countries: [String],
      timezones: [String]
    },
    
    // Business context
    business: {
      organizationId: { type: Schema.Types.ObjectId, ref: 'Organization' },
      tenantId: { type: Schema.Types.ObjectId, ref: 'OrganizationTenant' },
      projectId: { type: Schema.Types.ObjectId, ref: 'Project' },
      departmentId: String,
      costCenter: String
    },
    
    // Technical context
    technical: {
      environment: {
        type: String,
        enum: ['development', 'staging', 'production'],
        default: config.nodeEnv || 'development'
      },
      version: String,
      buildNumber: String,
      correlationId: String,
      traceId: String
    }
  },
  
  // Rules and Conditions
  rules: {
    // Delivery rules
    delivery: {
      respectQuietHours: { type: Boolean, default: true },
      respectDoNotDisturb: { type: Boolean, default: true },
      respectUserPreferences: { type: Boolean, default: true },
      batchingEnabled: { type: Boolean, default: false },
      batchingWindow: Number, // in minutes
      maxRetries: { type: Number, default: 3 },
      retryInterval: Number, // in minutes
      fallbackChannels: [String]
    },
    
    // Escalation rules
    escalation: {
      enabled: { type: Boolean, default: false },
      escalationDelay: Number, // in minutes
      escalationTargets: [{
        delay: Number,
        targetType: String,
        targets: [String]
      }],
      stopOnAcknowledge: { type: Boolean, default: true }
    },
    
    // Suppression rules
    suppression: {
      duplicateWindow: Number, // in minutes
      duplicateKey: String,
      rateLimitWindow: Number, // in minutes
      rateLimitCount: Number
    }
  },
  
  // Status and Lifecycle
  status: {
    type: String,
    required: true,
    enum: ['draft', 'scheduled', 'sending', 'sent', 'delivered', 'failed', 'cancelled', 'expired'],
    default: 'draft'
  },
  
  deliveryStats: {
    totalTargets: { type: Number, default: 0 },
    successfulDeliveries: { type: Number, default: 0 },
    failedDeliveries: { type: Number, default: 0 },
    pendingDeliveries: { type: Number, default: 0 },
    acknowledgedCount: { type: Number, default: 0 },
    dismissedCount: { type: Number, default: 0 },
    
    firstDeliveryAt: Date,
    lastDeliveryAt: Date,
    averageDeliveryTime: Number // in milliseconds
  },
  
  // Interaction Tracking
  interactions: [{
    userId: { type: Schema.Types.ObjectId, ref: 'User' },
    action: {
      type: String,
      enum: ['viewed', 'acknowledged', 'dismissed', 'clicked', 'replied', 'escalated']
    },
    timestamp: { type: Date, default: Date.now },
    channel: String,
    metadata: Schema.Types.Mixed
  }],
  
  // Workflow Integration
  workflow: {
    workflowId: String,
    stepId: String,
    workflowInstance: String,
    nextSteps: [String],
    
    // Approval workflow
    approvalRequired: { type: Boolean, default: false },
    approvalStatus: {
      type: String,
      enum: ['pending', 'approved', 'rejected', 'timeout'],
      default: 'pending'
    },
    approvers: [{
      userId: { type: Schema.Types.ObjectId, ref: 'User' },
      status: String,
      timestamp: Date,
      comments: String
    }]
  },
  
  // Archive and Retention
  archived: { type: Boolean, default: false },
  archivedAt: Date,
  retentionPolicy: {
    category: String,
    retainUntil: Date
  }
}, {
  timestamps: true,
  collection: 'admin_notifications'
});

// Indexes for performance and querying
adminNotificationSchema.index({ createdAt: -1 }); // Primary sorting
adminNotificationSchema.index({ type: 1, createdAt: -1 }); // Type filtering
adminNotificationSchema.index({ category: 1, priority: 1, createdAt: -1 }); // Category and priority
adminNotificationSchema.index({ status: 1, createdAt: -1 }); // Status filtering
adminNotificationSchema.index({ 'targeting.users.userId': 1, createdAt: -1 }); // User notifications
adminNotificationSchema.index({ 'targeting.roles': 1 }); // Role-based targeting
adminNotificationSchema.index({ 'context.business.organizationId': 1 }); // Organization filtering
adminNotificationSchema.index({ scheduledFor: 1 }); // Scheduled notifications
adminNotificationSchema.index({ expiresAt: 1 }); // Expiration cleanup
adminNotificationSchema.index({ 'source.triggeredBy.userId': 1 }); // Source tracking

// Compound indexes
adminNotificationSchema.index({
  'targeting.users.userId': 1,
  status: 1,
  createdAt: -1
}); // User notification status

adminNotificationSchema.index({
  priority: 1,
  status: 1,
  createdAt: -1
}); // Priority delivery queue

adminNotificationSchema.index({
  category: 1,
  severity: 1,
  createdAt: -1
}); // Security and monitoring alerts

// TTL index for expired notifications
adminNotificationSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

// Pre-save middleware
adminNotificationSchema.pre('save', function(next) {
  try {
    // Set expiration if not set
    if (!this.expiresAt && this.type !== 'emergency_alert') {
      const expirationPeriods = {
        security_alert: 30 * 24 * 60 * 60 * 1000, // 30 days
        system_alert: 7 * 24 * 60 * 60 * 1000, // 7 days
        maintenance_notice: 3 * 24 * 60 * 60 * 1000, // 3 days
        default: 7 * 24 * 60 * 60 * 1000 // 7 days
      };
      
      const period = expirationPeriods[this.type] || expirationPeriods.default;
      this.expiresAt = new Date(Date.now() + period);
    }
    
    // Set retention policy
    if (!this.retentionPolicy.retainUntil) {
      const retentionPeriods = {
        security: 2 * 365 * 24 * 60 * 60 * 1000, // 2 years
        emergency: 7 * 365 * 24 * 60 * 60 * 1000, // 7 years
        default: 1 * 365 * 24 * 60 * 60 * 1000 // 1 year
      };
      
      const period = retentionPeriods[this.category] || retentionPeriods.default;
      this.retentionPolicy.retainUntil = new Date(Date.now() + period);
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance Methods
adminNotificationSchema.methods = {
  /**
   * Mark notification as acknowledged by user
   * @param {string} userId - User ID
   * @param {Object} metadata - Additional metadata
   * @returns {Promise<boolean>} Success status
   */
  async acknowledge(userId, metadata = {}) {
    // Update user status in targeting
    const userTarget = this.targeting.users.find(u => u.userId.toString() === userId);
    if (userTarget) {
      userTarget.deliveryStatus = 'acknowledged';
      userTarget.acknowledgedAt = new Date();
    }
    
    // Add interaction record
    this.interactions.push({
      userId,
      action: 'acknowledged',
      timestamp: new Date(),
      metadata
    });
    
    // Update stats
    this.deliveryStats.acknowledgedCount = 
      (this.deliveryStats.acknowledgedCount || 0) + 1;
    
    await this.save();
    
    logger.info('Notification acknowledged', {
      notificationId: this.notificationId,
      userId,
      type: this.type
    });
    
    return true;
  },
  
  /**
   * Mark notification as dismissed by user
   * @param {string} userId - User ID
   * @param {Object} metadata - Additional metadata
   * @returns {Promise<boolean>} Success status
   */
  async dismiss(userId, metadata = {}) {
    // Update user status in targeting
    const userTarget = this.targeting.users.find(u => u.userId.toString() === userId);
    if (userTarget) {
      userTarget.deliveryStatus = 'dismissed';
      userTarget.dismissedAt = new Date();
    }
    
    // Add interaction record
    this.interactions.push({
      userId,
      action: 'dismissed',
      timestamp: new Date(),
      metadata
    });
    
    // Update stats
    this.deliveryStats.dismissedCount = 
      (this.deliveryStats.dismissedCount || 0) + 1;
    
    await this.save();
    
    return true;
  },
  
  /**
   * Check if notification should be delivered to user
   * @param {Object} user - User object
   * @returns {boolean} Should deliver
   */
  shouldDeliverToUser(user) {
    // Check if user is in target list
    if (this.targeting.targetType === 'user') {
      return this.targeting.users.some(u => u.userId.toString() === user._id.toString());
    }
    
    // Check role-based targeting
    if (this.targeting.targetType === 'role') {
      return this.targeting.roles.includes(user.role?.primary);
    }
    
    // Check organization targeting
    if (this.targeting.targetType === 'organization') {
      return this.targeting.organizations.some(org => 
        org.organizationId?.toString() === user.organization?.current?.toString()
      );
    }
    
    // Check filters
    const filters = this.targeting.filters;
    if (filters) {
      if (filters.activeOnly && !user.active) return false;
      if (filters.minimumRole && !this.hasMinimumRole(user, filters.minimumRole)) return false;
      if (filters.permissions && !this.hasRequiredPermissions(user, filters.permissions)) return false;
    }
    
    return true;
  },
  
  /**
   * Check if user has minimum role
   * @param {Object} user - User object
   * @param {string} minimumRole - Minimum role required
   * @returns {boolean} Has minimum role
   */
  hasMinimumRole(user, minimumRole) {
    const roleHierarchy = {
      super_admin: 100,
      platform_admin: 90,
      organization_admin: 80,
      security_admin: 85,
      system_admin: 85,
      billing_admin: 75
    };
    
    const userRoleLevel = roleHierarchy[user.role?.primary] || 0;
    const minimumRoleLevel = roleHierarchy[minimumRole] || 0;
    
    return userRoleLevel >= minimumRoleLevel;
  },
  
  /**
   * Check if user has required permissions
   * @param {Object} user - User object
   * @param {Array} requiredPermissions - Required permissions
   * @returns {boolean} Has required permissions
   */
  hasRequiredPermissions(user, requiredPermissions) {
    if (!user.permissions || !requiredPermissions.length) return true;
    
    return requiredPermissions.every(permission => 
      user.permissions.includes(permission)
    );
  },
  
  /**
   * Get notification summary for dashboard
   * @returns {Object} Notification summary
   */
  getSummary() {
    return {
      id: this.notificationId,
      type: this.type,
      category: this.category,
      priority: this.priority,
      title: this.content.title,
      summary: this.content.summary || this.content.message.substring(0, 100),
      createdAt: this.createdAt,
      status: this.status,
      targetCount: this.targeting.users.length,
      acknowledgedCount: this.deliveryStats.acknowledgedCount || 0,
      hasActions: this.content.actions && this.content.actions.length > 0
    };
  }
};

// Static Methods
adminNotificationSchema.statics = {
  /**
   * Create and send notification
   * @param {Object} notificationData - Notification data
   * @returns {Promise<Object>} Created notification
   */
  async createAndSend(notificationData) {
    try {
      const notification = new this(notificationData);
      await notification.save();
      
      // Queue for delivery
      await this.queueForDelivery(notification);
      
      logger.info('Admin notification created and queued', {
        notificationId: notification.notificationId,
        type: notification.type,
        priority: notification.priority
      });
      
      return notification;
    } catch (error) {
      logger.error('Failed to create admin notification', {
        error: error.message,
        type: notificationData.type
      });
      throw error;
    }
  },
  
  /**
   * Get notifications for user
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} User notifications
   */
  async getForUser(userId, options = {}) {
    const {
      limit = 50,
      skip = 0,
      unreadOnly = false,
      categories,
      priorities,
      includeArchived = false
    } = options;
    
    const query = {
      'targeting.users.userId': userId,
      status: { $in: ['sent', 'delivered'] }
    };
    
    if (unreadOnly) {
      query['targeting.users.deliveryStatus'] = { $nin: ['acknowledged', 'dismissed'] };
    }
    
    if (categories && categories.length) {
      query.category = { $in: categories };
    }
    
    if (priorities && priorities.length) {
      query.priority = { $in: priorities };
    }
    
    if (!includeArchived) {
      query.archived = { $ne: true };
    }
    
    return this.find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip(skip)
      .select('notificationId type category priority content.title content.summary status createdAt targeting.users.$')
      .lean();
  },
  
  /**
   * Get dashboard metrics
   * @param {Object} filters - Dashboard filters
   * @returns {Promise<Object>} Dashboard metrics
   */
  async getDashboardMetrics(filters = {}) {
    const {
      timeWindow = 24 * 60 * 60 * 1000, // 24 hours
      organizationId
    } = filters;
    
    const matchQuery = {
      createdAt: { $gte: new Date(Date.now() - timeWindow) }
    };
    
    if (organizationId) {
      matchQuery['context.business.organizationId'] = organizationId;
    }
    
    const pipeline = [
      { $match: matchQuery },
      {
        $group: {
          _id: {
            category: '$category',
            priority: '$priority'
          },
          count: { $sum: 1 },
          avgDeliveryTime: { $avg: '$deliveryStats.averageDeliveryTime' }
        }
      },
      {
        $group: {
          _id: '$_id.category',
          priorities: {
            $push: {
              priority: '$_id.priority',
              count: '$count',
              avgDeliveryTime: '$avgDeliveryTime'
            }
          },
          totalCount: { $sum: '$count' }
        }
      }
    ];
    
    const results = await this.aggregate(pipeline);
    
    // Calculate totals
    const totalNotifications = results.reduce((sum, cat) => sum + cat.totalCount, 0);
    const criticalAlerts = results
      .flatMap(cat => cat.priorities)
      .filter(p => p.priority === 'critical')
      .reduce((sum, p) => sum + p.count, 0);
    
    return {
      totalNotifications,
      criticalAlerts,
      categories: results,
      timeWindow: timeWindow,
      generatedAt: new Date()
    };
  },
  
  /**
   * Queue notification for delivery
   * @param {Object} notification - Notification object
   * @returns {Promise<void>}
   */
  async queueForDelivery(notification) {
    // Implementation would depend on your queue system
    // This is a placeholder for the actual queue integration
    logger.info('Notification queued for delivery', {
      notificationId: notification.notificationId,
      channels: notification.channels.map(c => c.type),
      targetCount: notification.targeting.users.length
    });
  },
  
  /**
   * Clean up expired notifications
   * @param {Object} options - Cleanup options
   * @returns {Promise<Object>} Cleanup results
   */
  async cleanupExpired(options = {}) {
    const { batchSize = 1000, dryRun = false } = options;
    
    const expiredQuery = {
      $or: [
        { expiresAt: { $lt: new Date() } },
        { 
          status: 'sent',
          createdAt: { $lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // 30 days old
        }
      ],
      archived: { $ne: true }
    };
    
    const expiredCount = await this.countDocuments(expiredQuery);
    
    if (dryRun) {
      return {
        expiredCount,
        wouldArchive: expiredCount,
        dryRun: true
      };
    }
    
    const result = await this.updateMany(
      expiredQuery,
      {
        $set: {
          archived: true,
          archivedAt: new Date()
        }
      },
      { limit: batchSize }
    );
    
    logger.info('Expired notifications archived', {
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount
    });
    
    return {
      expiredCount,
      archivedCount: result.modifiedCount
    };
  }
};

// Create the model
const AdminNotification = mongoose.model('AdminNotification', adminNotificationSchema);

module.exports = AdminNotification;