/**
 * @file Admin Notification Service
 * @description Comprehensive notification service for administrative alerts, system messages, and user communications
 * @version 1.0.0
 */

const cron = require('node-cron');
const mustache = require('mustache');

const AdminBaseService = require('./admin-base-service');
const config = require('../../../shared/config/config');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { EmailService } = require('../../../shared/services/email-service');
const { CacheService } = require('../../../shared/services/cache-service');

// Import admin models
const AdminNotification = require('../models/admin-notification-model');
const AdminPreference = require('../models/admin-preference-model');
const AdminSession = require('../models/admin-session-model');
const User = require('../../../shared/users/models/user-model');

/**
 * Admin Notification Service Class
 * Handles all administrative notification operations
 */
class AdminNotificationService extends AdminBaseService {
  constructor() {
    super('AdminNotificationService');
    
    this.notificationConfig = {
      channels: {
        email: {
          enabled: config.notifications?.email?.enabled || true,
          provider: config.notifications?.email?.provider || 'smtp',
          templates: config.notifications?.email?.templates || './templates/email'
        },
        sms: {
          enabled: config.notifications?.sms?.enabled || false,
          provider: config.notifications?.sms?.provider || 'twilio',
          templates: config.notifications?.sms?.templates || './templates/sms'
        },
        push: {
          enabled: config.notifications?.push?.enabled || true,
          provider: config.notifications?.push?.provider || 'firebase',
          templates: config.notifications?.push?.templates || './templates/push'
        },
        webhook: {
          enabled: config.notifications?.webhook?.enabled || true,
          retryAttempts: config.notifications?.webhook?.retryAttempts || 3,
          timeout: config.notifications?.webhook?.timeout || 30000
        },
        inApp: {
          enabled: true,
          persistence: config.notifications?.inApp?.persistence || 30 // days
        }
      },
      delivery: {
        batchSize: config.notifications?.delivery?.batchSize || 100,
        retryAttempts: config.notifications?.delivery?.retryAttempts || 3,
        retryDelay: config.notifications?.delivery?.retryDelay || 60000, // 1 minute
        maxRetryDelay: config.notifications?.delivery?.maxRetryDelay || 3600000, // 1 hour
        deliveryTimeout: config.notifications?.delivery?.timeout || 300000 // 5 minutes
      },
      rateLimiting: {
        perUser: config.notifications?.rateLimiting?.perUser || 100, // per hour
        perChannel: config.notifications?.rateLimiting?.perChannel || 1000, // per hour
        global: config.notifications?.rateLimiting?.global || 10000 // per hour
      },
      templates: new Map(),
      deliveryQueue: new Map(),
      deliveryStats: new Map()
    };
    
    this.notificationTypes = {
      SECURITY_ALERT: 'security_alert',
      SYSTEM_ALERT: 'system_alert',
      MAINTENANCE_NOTICE: 'maintenance_notice',
      USER_ACTION: 'user_action',
      POLICY_VIOLATION: 'policy_violation',
      AUDIT_ALERT: 'audit_alert',
      PERFORMANCE_WARNING: 'performance_warning',
      QUOTA_WARNING: 'quota_warning',
      APPROVAL_REQUEST: 'approval_request',
      COMPLIANCE_REMINDER: 'compliance_reminder'
    };
    
    this.channels = {
      IN_APP: 'in_app',
      EMAIL: 'email',
      SMS: 'sms',
      PUSH: 'push',
      WEBHOOK: 'webhook',
      SLACK: 'slack',
      TEAMS: 'teams'
    };
    
    this.initializeNotificationService();
  }
  
  /**
   * Initialize notification service
   * @private
   */
  async initializeNotificationService() {
    try {
      // Initialize delivery queue
      this.initializeDeliveryQueue();
      
      // Load notification templates
      await this.loadNotificationTemplates();
      
      // Set up delivery workers
      this.setupDeliveryWorkers();
      
      // Set up cleanup tasks
      this.setupCleanupTasks();
      
      // Initialize delivery statistics
      this.initializeDeliveryStats();
      
      logger.info('Admin notification service initialized', {
        enabledChannels: Object.keys(this.notificationConfig.channels).filter(
          channel => this.notificationConfig.channels[channel].enabled
        )
      });
      
    } catch (error) {
      logger.error('Failed to initialize notification service', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Send notification to admin users
   * @param {Object} context - Operation context
   * @param {Object} notificationData - Notification data
   * @returns {Promise<Object>} Notification result
   */
  async sendNotification(context, notificationData) {
    return this.executeOperation('notification.send', async () => {
      const {
        type,
        title,
        message,
        priority = 'normal',
        category = 'system',
        targeting,
        channels = [this.channels.IN_APP],
        templateId = null,
        templateData = {},
        scheduledFor = null,
        expiresAt = null,
        metadata = {}
      } = notificationData;
      
      // Validate notification data
      this.validateNotificationData(notificationData);
      
      // Resolve notification targets
      const resolvedTargets = await this.resolveNotificationTargets(targeting);
      
      if (resolvedTargets.length === 0) {
        throw new ValidationError('No valid targets found for notification');
      }
      
      // Apply rate limiting
      await this.checkNotificationRateLimit(context, resolvedTargets.length);
      
      // Create notification record
      const notification = new AdminNotification({
        type,
        category,
        priority,
        source: {
          system: 'admin_system',
          component: context.component || 'admin_service',
          triggeredBy: {
            type: 'user',
            userId: context.userId,
            username: context.user?.username
          }
        },
        content: {
          title,
          message,
          templateId,
          templateData
        },
        targeting: {
          targetType: targeting.type,
          users: resolvedTargets,
          filters: targeting.filters
        },
        channels: channels.map(channel => ({
          type: channel,
          deliveryStatus: 'pending'
        })),
        scheduledFor,
        expiresAt,
        metadata: {
          ...metadata,
          createdBy: context.userId
        }
      });
      
      await notification.save();
      
      logger.info('Notification created', {
        notificationId: notification.notificationId,
        type,
        priority,
        targetCount: resolvedTargets.length,
        channels
      });
      
      // Queue for delivery
      if (!scheduledFor || new Date(scheduledFor) <= new Date()) {
        await this.queueNotificationForDelivery(notification);
      } else {
        // Schedule for future delivery
        await this.scheduleNotificationDelivery(notification);
      }
      
      return {
        notificationId: notification.notificationId,
        type,
        priority,
        targetCount: resolvedTargets.length,
        channels,
        createdAt: notification.createdAt,
        scheduledFor: notification.scheduledFor,
        status: 'queued'
      };
      
    }, context);
  }
  
  /**
   * Send security alert
   * @param {Object} context - Operation context
   * @param {Object} alertData - Security alert data
   * @returns {Promise<Object>} Alert result
   */
  async sendSecurityAlert(context, alertData) {
    return this.executeOperation('notification.security_alert', async () => {
      const {
        severity = 'high',
        incident,
        affectedResources = [],
        recommendations = [],
        autoResponse = null
      } = alertData;
      
      // Determine targets based on severity
      const targeting = this.getSecurityAlertTargeting(severity);
      
      // Prepare alert content
      const alertContent = {
        type: this.notificationTypes.SECURITY_ALERT,
        title: `Security Alert: ${incident.type}`,
        message: incident.description,
        priority: this.mapSeverityToPriority(severity),
        category: 'security',
        targeting,
        channels: this.getSecurityAlertChannels(severity),
        templateId: 'security_alert',
        templateData: {
          severity,
          incident,
          affectedResources,
          recommendations,
          autoResponse,
          timestamp: new Date(),
          incidentId: incident.id || context.correlationId
        },
        metadata: {
          severity,
          incidentId: incident.id,
          autoResponse: autoResponse?.action
        }
      };
      
      return this.sendNotification(context, alertContent);
      
    }, context);
  }
  
  /**
   * Send system maintenance notification
   * @param {Object} context - Operation context
   * @param {Object} maintenanceData - Maintenance notification data
   * @returns {Promise<Object>} Notification result
   */
  async sendMaintenanceNotification(context, maintenanceData) {
    return this.executeOperation('notification.maintenance', async () => {
      const {
        maintenanceType = 'scheduled',
        startTime,
        estimatedDuration,
        affectedSystems = [],
        impact = 'low',
        advanceNotice = false
      } = maintenanceData;
      
      const targeting = {
        type: 'all_admins',
        filters: {
          activeOnly: true
        }
      };
      
      const notificationContent = {
        type: this.notificationTypes.MAINTENANCE_NOTICE,
        title: `System Maintenance ${advanceNotice ? 'Scheduled' : 'Starting'}`,
        message: `System maintenance is ${advanceNotice ? 'scheduled to begin' : 'beginning'} at ${startTime}`,
        priority: impact === 'high' ? 'high' : 'normal',
        category: 'maintenance',
        targeting,
        channels: [this.channels.IN_APP, this.channels.EMAIL],
        templateId: 'maintenance_notice',
        templateData: {
          maintenanceType,
          startTime,
          estimatedDuration,
          affectedSystems,
          impact,
          advanceNotice
        },
        scheduledFor: advanceNotice ? new Date(Date.now() + 24 * 60 * 60 * 1000) : null // 24 hours advance
      };
      
      return this.sendNotification(context, notificationContent);
      
    }, context);
  }
  
  /**
   * Send approval request notification
   * @param {Object} context - Operation context
   * @param {Object} requestData - Approval request data
   * @returns {Promise<Object>} Notification result
   */
  async sendApprovalRequest(context, requestData) {
    return this.executeOperation('notification.approval_request', async () => {
      const {
        requestType,
        requestor,
        details,
        urgency = 'normal',
        deadline,
        approvers = [],
        requiredApprovals = 1
      } = requestData;
      
      // Target specific approvers or all admins with approval permissions
      const targeting = approvers.length > 0 ? {
        type: 'user',
        users: approvers
      } : {
        type: 'role',
        roles: ['super_admin', 'platform_admin'],
        filters: {
          permissions: ['admin.approvals.manage']
        }
      };
      
      const notificationContent = {
        type: this.notificationTypes.APPROVAL_REQUEST,
        title: `Approval Required: ${requestType}`,
        message: `${requestor.name} has requested approval for ${requestType}`,
        priority: urgency === 'urgent' ? 'urgent' : 'high',
        category: 'business',
        targeting,
        channels: [this.channels.IN_APP, this.channels.EMAIL],
        templateId: 'approval_request',
        templateData: {
          requestType,
          requestor,
          details,
          urgency,
          deadline,
          requiredApprovals,
          approvalUrl: this.generateApprovalUrl(context.requestId)
        },
        expiresAt: deadline ? new Date(deadline) : null,
        metadata: {
          requestId: context.requestId,
          requestType,
          urgency
        }
      };
      
      return this.sendNotification(context, notificationContent);
      
    }, context);
  }
  
  /**
   * Get notifications for user
   * @param {Object} context - Operation context
   * @param {Object} filters - Notification filters
   * @returns {Promise<Object>} User notifications
   */
  async getUserNotifications(context, filters = {}) {
    return this.executeOperation('notification.get_user', async () => {
      const {
        unreadOnly = false,
        categories = [],
        priorities = [],
        limit = 25,
        skip = 0,
        includeArchived = false
      } = filters;
      
      const notifications = await AdminNotification.getForUser(context.userId, {
        limit,
        skip,
        unreadOnly,
        categories,
        priorities,
        includeArchived
      });
      
      // Get unread count
      const unreadCount = await AdminNotification.countDocuments({
        'targeting.users.userId': context.userId,
        'targeting.users.deliveryStatus': { $nin: ['acknowledged', 'dismissed'] },
        status: { $in: ['sent', 'delivered'] },
        archived: { $ne: true }
      });
      
      return {
        notifications,
        unreadCount,
        filters: {
          unreadOnly,
          categories,
          priorities,
          limit,
          skip
        }
      };
      
    }, context);
  }
  
  /**
   * Mark notification as read
   * @param {Object} context - Operation context
   * @param {string} notificationId - Notification ID
   * @returns {Promise<Object>} Update result
   */
  async markNotificationAsRead(context, notificationId) {
    return this.executeOperation('notification.mark_read', async () => {
      const notification = await AdminNotification.findOne({
        notificationId,
        'targeting.users.userId': context.userId
      });
      
      if (!notification) {
        throw new NotFoundError('Notification', notificationId);
      }
      
      await notification.acknowledge(context.userId, {
        acknowledgedVia: 'user_action',
        timestamp: new Date()
      });
      
      return {
        notificationId,
        acknowledged: true,
        acknowledgedAt: new Date()
      };
      
    }, context);
  }
  
  /**
   * Dismiss notification
   * @param {Object} context - Operation context
   * @param {string} notificationId - Notification ID
   * @returns {Promise<Object>} Dismiss result
   */
  async dismissNotification(context, notificationId) {
    return this.executeOperation('notification.dismiss', async () => {
      const notification = await AdminNotification.findOne({
        notificationId,
        'targeting.users.userId': context.userId
      });
      
      if (!notification) {
        throw new NotFoundError('Notification', notificationId);
      }
      
      await notification.dismiss(context.userId, {
        dismissedVia: 'user_action',
        timestamp: new Date()
      });
      
      return {
        notificationId,
        dismissed: true,
        dismissedAt: new Date()
      };
      
    }, context);
  }
  
  /**
   * Get notification delivery statistics
   * @param {Object} context - Operation context
   * @param {Object} filters - Statistics filters
   * @returns {Promise<Object>} Delivery statistics
   */
  async getDeliveryStatistics(context, filters = {}) {
    return this.executeOperation('notification.stats', async () => {
      const {
        timeWindow = 24 * 60 * 60 * 1000, // 24 hours
        groupBy = 'hour',
        includeChannelBreakdown = true,
        includeTypeBreakdown = true
      } = filters;
      
      const metrics = await AdminNotification.getDashboardMetrics({
        timeWindow,
        organizationId: context.organizationId
      });
      
      // Add service-level statistics
      const serviceStats = this.getServiceStatistics(timeWindow);
      
      return {
        ...metrics,
        serviceStats,
        deliveryQueue: {
          pending: this.notificationConfig.deliveryQueue.size,
          processing: Array.from(this.notificationConfig.deliveryQueue.values())
            .filter(item => item.status === 'processing').length
        },
        channels: includeChannelBreakdown ? this.getChannelStatistics() : undefined,
        types: includeTypeBreakdown ? this.getTypeStatistics() : undefined
      };
      
    }, context);
  }
  
  /**
   * Manage notification preferences
   * @param {Object} context - Operation context
   * @param {Object} preferences - Notification preferences
   * @returns {Promise<Object>} Updated preferences
   */
  async updateNotificationPreferences(context, preferences) {
    return this.executeOperation('notification.preferences.update', async () => {
      const userPreferences = await AdminPreference.getOrCreateForUser(
        context.userId,
        context.user
      );
      
      // Update notification preferences
      Object.assign(userPreferences.notifications, preferences);
      
      await userPreferences.save();
      
      // Clear cache for user preferences
      await this.cache.delete(`user_preferences:${context.userId}`);
      
      logger.info('Notification preferences updated', {
        userId: context.userId,
        preferences: Object.keys(preferences)
      });
      
      return {
        userId: context.userId,
        preferences: userPreferences.notifications,
        updatedAt: new Date()
      };
      
    }, context);
  }
  
  /**
   * Initialize delivery queue
   * @private
   */
  initializeDeliveryQueue() {
    this.deliveryWorkers = new Map();
    
    // Start delivery workers for each channel
    for (const channel of Object.keys(this.notificationConfig.channels)) {
      if (this.notificationConfig.channels[channel].enabled) {
        this.startDeliveryWorker(channel);
      }
    }
  }
  
  /**
   * Start delivery worker for channel
   * @param {string} channel - Delivery channel
   * @private
   */
  startDeliveryWorker(channel) {
    const worker = setInterval(async () => {
      await this.processDeliveryQueue(channel);
    }, 5000); // Process every 5 seconds
    
    this.deliveryWorkers.set(channel, worker);
    
    logger.debug(`Started delivery worker for channel: ${channel}`);
  }
  
  /**
   * Process delivery queue for channel
   * @param {string} channel - Delivery channel
   * @private
   */
  async processDeliveryQueue(channel) {
    try {
      // Find pending notifications for this channel
      const pendingNotifications = await AdminNotification.find({
        'channels.type': channel,
        'channels.deliveryStatus': 'pending',
        status: 'sending',
        scheduledFor: { $lte: new Date() }
      }).limit(this.notificationConfig.delivery.batchSize);
      
      for (const notification of pendingNotifications) {
        try {
          await this.deliverNotificationToChannel(notification, channel);
        } catch (error) {
          logger.error('Failed to deliver notification', {
            notificationId: notification.notificationId,
            channel,
            error: error.message
          });
          
          await this.handleDeliveryFailure(notification, channel, error);
        }
      }
      
    } catch (error) {
      logger.error(`Error processing delivery queue for ${channel}`, {
        error: error.message
      });
    }
  }
  
  /**
   * Resolve notification targets
   * @param {Object} targeting - Targeting configuration
   * @returns {Promise<Array>} Resolved targets
   * @private
   */
  async resolveNotificationTargets(targeting) {
    const { type, users = [], roles = [], filters = {} } = targeting;
    
    let targets = [];
    
    switch (type) {
      case 'user':
        // Direct user targeting
        targets = await User.find({
          _id: { $in: users },
          active: true
        }).select('_id username email role permissions');
        break;
        
      case 'role':
        // Role-based targeting
        targets = await User.find({
          'role.primary': { $in: roles },
          active: true
        }).select('_id username email role permissions');
        break;
        
      case 'all_admins':
        // All admin users
        targets = await User.find({
          'role.primary': { $in: ['super_admin', 'platform_admin', 'organization_admin'] },
          active: true
        }).select('_id username email role permissions');
        break;
        
      case 'organization':
        // Organization-based targeting
        const orgFilter = {
          'organization.current': { $in: targeting.organizations || [] },
          active: true
        };
        targets = await User.find(orgFilter).select('_id username email role permissions');
        break;
    }
    
    // Apply additional filters
    if (filters.permissions) {
      targets = targets.filter(user => 
        filters.permissions.some(permission => 
          user.permissions?.includes(permission)
        )
      );
    }
    
    if (filters.departments) {
      targets = targets.filter(user => 
        filters.departments.includes(user.profile?.department)
      );
    }
    
    // Convert to notification target format
    return targets.map(user => ({
      userId: user._id,
      username: user.username,
      email: user.email,
      preferredChannels: this.getUserPreferredChannels(user),
      deliveryStatus: 'pending'
    }));
  }
  
  /**
   * Queue notification for delivery
   * @param {Object} notification - Notification object
   * @private
   */
  async queueNotificationForDelivery(notification) {
    // Update notification status
    notification.status = 'sending';
    notification.deliveryStats.firstDeliveryAt = new Date();
    
    await notification.save();
    
    // Add to delivery queue
    this.notificationConfig.deliveryQueue.set(notification.notificationId, {
      notification,
      queuedAt: new Date(),
      status: 'queued'
    });
    
    logger.debug('Notification queued for delivery', {
      notificationId: notification.notificationId,
      channels: notification.channels.map(c => c.type)
    });
  }
  
  /**
   * Get user preferred channels
   * @param {Object} user - User object
   * @returns {Array} Preferred channels
   * @private
   */
  getUserPreferredChannels(user) {
    // This would normally fetch from user preferences
    // For now, return default channels based on role
    const roleChannels = {
      super_admin: [this.channels.IN_APP, this.channels.EMAIL, this.channels.SMS],
      platform_admin: [this.channels.IN_APP, this.channels.EMAIL],
      organization_admin: [this.channels.IN_APP, this.channels.EMAIL],
      default: [this.channels.IN_APP]
    };
    
    return roleChannels[user.role?.primary] || roleChannels.default;
  }
  
  /**
   * Get security alert targeting based on severity
   * @param {string} severity - Alert severity
   * @returns {Object} Targeting configuration
   * @private
   */
  getSecurityAlertTargeting(severity) {
    switch (severity) {
      case 'critical':
        return {
          type: 'all_admins',
          filters: { activeOnly: true }
        };
      case 'high':
        return {
          type: 'role',
          roles: ['super_admin', 'platform_admin', 'security_admin'],
          filters: { activeOnly: true }
        };
      case 'medium':
        return {
          type: 'role',
          roles: ['security_admin'],
          filters: { activeOnly: true }
        };
      default:
        return {
          type: 'role',
          roles: ['security_admin'],
          filters: { activeOnly: true }
        };
    }
  }
  
  /**
   * Map severity to priority
   * @param {string} severity - Severity level
   * @returns {string} Priority level
   * @private
   */
  mapSeverityToPriority(severity) {
    const mapping = {
      critical: 'critical',
      high: 'urgent',
      medium: 'high',
      low: 'normal'
    };
    
    return mapping[severity] || 'normal';
  }
  
  /**
   * Get security alert channels based on severity
   * @param {string} severity - Alert severity
   * @returns {Array} Delivery channels
   * @private
   */
  getSecurityAlertChannels(severity) {
    switch (severity) {
      case 'critical':
        return [this.channels.IN_APP, this.channels.EMAIL, this.channels.SMS, this.channels.PUSH];
      case 'high':
        return [this.channels.IN_APP, this.channels.EMAIL, this.channels.PUSH];
      case 'medium':
        return [this.channels.IN_APP, this.channels.EMAIL];
      default:
        return [this.channels.IN_APP];
    }
  }
  
  /**
   * Generate approval URL
   * @param {string} requestId - Request ID
   * @returns {string} Approval URL
   * @private
   */
  generateApprovalUrl(requestId) {
    return `${config.app.baseUrl}/admin/approvals/${requestId}`;
  }
  
  /**
   * Load notification templates
   * @private
   */
  async loadNotificationTemplates() {
    // Load templates for different channels and notification types
    const templates = {
      security_alert: {
        email: {
          subject: 'Security Alert: {{incident.type}}',
          body: 'A security incident has been detected...'
        },
        sms: {
          body: 'SECURITY ALERT: {{incident.type}} - Check admin panel immediately'
        }
      },
      maintenance_notice: {
        email: {
          subject: 'System Maintenance {{#advanceNotice}}Scheduled{{/advanceNotice}}{{^advanceNotice}}Starting{{/advanceNotice}}',
          body: 'System maintenance is scheduled...'
        }
      },
      approval_request: {
        email: {
          subject: 'Approval Required: {{requestType}}',
          body: '{{requestor.name}} has requested approval for {{requestType}}...'
        }
      }
    };
    
    this.notificationConfig.templates = new Map(Object.entries(templates));
  }
  
  /**
   * Setup cleanup tasks
   * @private
   */
  setupCleanupTasks() {
    // Clean up old notifications daily at 2 AM
    cron.schedule('0 2 * * *', async () => {
      try {
        const result = await AdminNotification.cleanupExpired();
        logger.info('Notification cleanup completed', result);
      } catch (error) {
        logger.error('Notification cleanup failed', { error: error.message });
      }
    });
  }
}

module.exports = AdminNotificationService;