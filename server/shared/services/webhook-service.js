// /server/shared/services/webhook-service.js

/**
 * @file Webhook Service
 * @description Webhook management and delivery service
 * @version 1.0.0
 */

const crypto = require('crypto');

const axios = require('axios');

const config = require('../config');
const { AppError } = require('../utils/app-error');
const cacheHelper = require('../utils/helpers/cache-helper');
const queueHelper = require('../utils/helpers/queue-helper');
const logger = require('../utils/logger');

/**
 * Webhook Service Class
 */
class WebhookService {
  constructor() {
    this.webhooks = new Map();
    this.eventTypes = this.defineEventTypes();
    this.retryConfig = {
      maxAttempts: config.webhooks.maxRetries || 5,
      initialDelay: 1000, // 1 second
      maxDelay: 300000, // 5 minutes
      backoffMultiplier: 2
    };
  }
  
  /**
   * Define webhook event types
   */
  defineEventTypes() {
    return {
      // User events
      USER_CREATED: 'user.created',
      USER_UPDATED: 'user.updated',
      USER_DELETED: 'user.deleted',
      USER_VERIFIED: 'user.verified',
      USER_SUSPENDED: 'user.suspended',
      USER_ACTIVATED: 'user.activated',
      
      // Organization events
      ORGANIZATION_CREATED: 'organization.created',
      ORGANIZATION_UPDATED: 'organization.updated',
      ORGANIZATION_DELETED: 'organization.deleted',
      ORGANIZATION_MEMBER_ADDED: 'organization.member.added',
      ORGANIZATION_MEMBER_REMOVED: 'organization.member.removed',
      ORGANIZATION_MEMBER_UPDATED: 'organization.member.updated',
      
      // Project events
      PROJECT_CREATED: 'project.created',
      PROJECT_UPDATED: 'project.updated',
      PROJECT_DELETED: 'project.deleted',
      PROJECT_COMPLETED: 'project.completed',
      PROJECT_ARCHIVED: 'project.archived',
      
      // Billing events
      SUBSCRIPTION_CREATED: 'subscription.created',
      SUBSCRIPTION_UPDATED: 'subscription.updated',
      SUBSCRIPTION_CANCELLED: 'subscription.cancelled',
      SUBSCRIPTION_RENEWED: 'subscription.renewed',
      PAYMENT_SUCCEEDED: 'payment.succeeded',
      PAYMENT_FAILED: 'payment.failed',
      INVOICE_CREATED: 'invoice.created',
      INVOICE_PAID: 'invoice.paid',
      
      // Recruitment events
      JOB_POSTED: 'job.posted',
      JOB_UPDATED: 'job.updated',
      JOB_CLOSED: 'job.closed',
      APPLICATION_SUBMITTED: 'application.submitted',
      APPLICATION_REVIEWED: 'application.reviewed',
      APPLICATION_STATUS_CHANGED: 'application.status.changed',
      INTERVIEW_SCHEDULED: 'interview.scheduled',
      INTERVIEW_COMPLETED: 'interview.completed',
      OFFER_EXTENDED: 'offer.extended',
      OFFER_ACCEPTED: 'offer.accepted',
      OFFER_DECLINED: 'offer.declined',
      
      // Security events
      LOGIN_SUCCESS: 'security.login.success',
      LOGIN_FAILED: 'security.login.failed',
      PASSWORD_CHANGED: 'security.password.changed',
      TWO_FACTOR_ENABLED: 'security.2fa.enabled',
      TWO_FACTOR_DISABLED: 'security.2fa.disabled',
      API_KEY_CREATED: 'security.api_key.created',
      API_KEY_REVOKED: 'security.api_key.revoked',
      
      // System events
      MAINTENANCE_SCHEDULED: 'system.maintenance.scheduled',
      MAINTENANCE_COMPLETED: 'system.maintenance.completed',
      SERVICE_DEGRADATION: 'system.service.degradation',
      SERVICE_RESTORED: 'system.service.restored'
    };
  }
  
  /**
   * Register webhook
   * @param {Object} webhook - Webhook configuration
   * @returns {Promise<Object>} Registered webhook
   */
  async register(webhook) {
    try {
      const {
        url,
        events,
        secret,
        organizationId,
        userId,
        active = true,
        headers = {},
        description
      } = webhook;
      
      // Validate webhook URL
      await this.validateWebhookUrl(url);
      
      // Validate events
      this.validateEvents(events);
      
      // Generate webhook ID and secret if not provided
      const webhookId = this.generateWebhookId();
      const webhookSecret = secret || this.generateSecret();
      
      // Create webhook object
      const webhookData = {
        id: webhookId,
        url,
        events,
        secret: webhookSecret,
        organizationId,
        userId,
        active,
        headers,
        description,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastTriggeredAt: null,
        failureCount: 0,
        successCount: 0
      };
      
      // Store webhook
      this.webhooks.set(webhookId, webhookData);
      
      // Also store in database
      // await WebhookModel.create(webhookData);
      
      logger.info('Webhook registered', {
        webhookId,
        url,
        events,
        organizationId
      });
      
      return {
        id: webhookId,
        url,
        events,
        secret: webhookSecret,
        active
      };
    } catch (error) {
      logger.error('Failed to register webhook:', error);
      throw error instanceof AppError ? error : new AppError('Failed to register webhook', 500);
    }
  }
  
  /**
   * Update webhook
   * @param {string} webhookId - Webhook ID
   * @param {Object} updates - Update data
   * @returns {Promise<Object>} Updated webhook
   */
  async update(webhookId, updates) {
    const webhook = this.webhooks.get(webhookId);
    if (!webhook) {
      throw new AppError('Webhook not found', 404);
    }
    
    // Validate updates
    if (updates.url) {
      await this.validateWebhookUrl(updates.url);
    }
    
    if (updates.events) {
      this.validateEvents(updates.events);
    }
    
    // Update webhook
    const updatedWebhook = {
      ...webhook,
      ...updates,
      updatedAt: new Date()
    };
    
    this.webhooks.set(webhookId, updatedWebhook);
    
    // Update in database
    // await WebhookModel.updateOne({ id: webhookId }, updatedWebhook);
    
    logger.info('Webhook updated', { webhookId, updates });
    
    return updatedWebhook;
  }
  
  /**
   * Delete webhook
   * @param {string} webhookId - Webhook ID
   * @returns {Promise<boolean>} Success status
   */
  async delete(webhookId) {
    const webhook = this.webhooks.get(webhookId);
    if (!webhook) {
      throw new AppError('Webhook not found', 404);
    }
    
    this.webhooks.delete(webhookId);
    
    // Delete from database
    // await WebhookModel.deleteOne({ id: webhookId });
    
    logger.info('Webhook deleted', { webhookId });
    
    return true;
  }
  
  /**
   * Trigger webhook event
   * @param {string} eventType - Event type
   * @param {Object} payload - Event payload
   * @param {Object} options - Trigger options
   * @returns {Promise<Object>} Trigger results
   */
  async trigger(eventType, payload, options = {}) {
    try {
      const {
        organizationId,
        userId,
        async = true
      } = options;
      
      // Get webhooks subscribed to this event
      const webhooks = await this.getWebhooksForEvent(eventType, organizationId);
      
      if (webhooks.length === 0) {
        logger.debug('No webhooks found for event', { eventType, organizationId });
        return { triggered: 0 };
      }
      
      // Create event data
      const eventData = {
        id: this.generateEventId(),
        type: eventType,
        timestamp: new Date().toISOString(),
        data: payload,
        metadata: {
          organizationId,
          userId,
          version: '1.0'
        }
      };
      
      // Trigger webhooks
      if (async) {
        // Queue for async delivery
        const jobs = webhooks.map(webhook => 
          queueHelper.addJob('webhooks', 'deliver-webhook', {
            webhookId: webhook.id,
            eventData
          })
        );
        
        await Promise.all(jobs);
      } else {
        // Deliver synchronously
        const results = await Promise.allSettled(
          webhooks.map(webhook => this.deliver(webhook, eventData))
        );
        
        return {
          triggered: webhooks.length,
          results: results.map((result, index) => ({
            webhookId: webhooks[index].id,
            success: result.status === 'fulfilled',
            error: result.reason?.message
          }))
        };
      }
      
      return { triggered: webhooks.length };
    } catch (error) {
      logger.error('Failed to trigger webhook:', error);
      throw new AppError('Failed to trigger webhook', 500);
    }
  }
  
  /**
   * Deliver webhook
   * @param {Object} webhook - Webhook configuration
   * @param {Object} eventData - Event data
   * @returns {Promise<Object>} Delivery result
   */
  async deliver(webhook, eventData) {
    const startTime = Date.now();
    
    try {
      // Generate signature
      const signature = this.generateSignature(webhook.secret, eventData);
      
      // Prepare headers
      const headers = {
        'Content-Type': 'application/json',
        'X-Webhook-ID': webhook.id,
        'X-Webhook-Signature': signature,
        'X-Webhook-Timestamp': eventData.timestamp,
        'X-Event-Type': eventData.type,
        'X-Event-ID': eventData.id,
        'User-Agent': 'Insightserenity-Webhook/1.0',
        ...webhook.headers
      };
      
      // Make request
      const response = await axios({
        method: 'POST',
        url: webhook.url,
        data: eventData,
        headers,
        timeout: 30000, // 30 seconds
        maxRedirects: 0,
        validateStatus: (status) => status < 500 // Don't throw on 4xx
      });
      
      const duration = Date.now() - startTime;
      
      // Log delivery
      await this.logDelivery(webhook, eventData, {
        status: response.status,
        duration,
        success: response.status >= 200 && response.status < 300
      });
      
      // Update webhook stats
      if (response.status >= 200 && response.status < 300) {
        webhook.successCount++;
        webhook.failureCount = 0;
      } else {
        webhook.failureCount++;
      }
      
      webhook.lastTriggeredAt = new Date();
      
      return {
        success: response.status >= 200 && response.status < 300,
        status: response.status,
        duration,
        response: response.data
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      
      // Log failure
      await this.logDelivery(webhook, eventData, {
        status: error.response?.status || 0,
        duration,
        success: false,
        error: error.message
      });
      
      // Update failure count
      webhook.failureCount++;
      webhook.lastTriggeredAt = new Date();
      
      // Check if should disable webhook
      if (webhook.failureCount >= 10) {
        webhook.active = false;
        logger.warn('Webhook disabled due to repeated failures', {
          webhookId: webhook.id,
          failureCount: webhook.failureCount
        });
      }
      
      throw error;
    }
  }
  
  /**
   * Retry failed webhook delivery
   * @param {Object} webhook - Webhook configuration
   * @param {Object} eventData - Event data
   * @param {number} attempt - Current attempt number
   * @returns {Promise<Object>} Retry result
   */
  async retry(webhook, eventData, attempt = 1) {
    if (attempt > this.retryConfig.maxAttempts) {
      logger.error('Max webhook retry attempts reached', {
        webhookId: webhook.id,
        eventId: eventData.id,
        attempts: attempt
      });
      
      // Disable webhook if too many failures
      if (webhook.failureCount >= 10) {
        await this.update(webhook.id, { active: false });
      }
      
      return { success: false, reason: 'max_attempts_reached' };
    }
    
    // Calculate delay with exponential backoff
    const delay = Math.min(
      this.retryConfig.initialDelay * Math.pow(this.retryConfig.backoffMultiplier, attempt - 1),
      this.retryConfig.maxDelay
    );
    
    // Queue retry
    await queueHelper.addJob('webhooks', 'retry-webhook', {
      webhookId: webhook.id,
      eventData,
      attempt
    }, {
      delay,
      attempts: 1 // Don't use Bull's retry mechanism
    });
    
    logger.info('Webhook delivery retry scheduled', {
      webhookId: webhook.id,
      eventId: eventData.id,
      attempt,
      delay
    });
    
    return { success: true, scheduled: true, delay };
  }
  
  /**
   * Get webhooks for event
   * @param {string} eventType - Event type
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Array>} Webhooks
   */
  async getWebhooksForEvent(eventType, organizationId = null) {
    const webhooks = [];
    
    for (const webhook of this.webhooks.values()) {
      if (!webhook.active) continue;
      
      if (webhook.events.includes(eventType) || webhook.events.includes('*')) {
        if (!organizationId || webhook.organizationId === organizationId) {
          webhooks.push(webhook);
        }
      }
    }
    
    return webhooks;
  }
  
  /**
   * Validate webhook URL
   * @param {string} url - Webhook URL
   * @returns {Promise<void>}
   */
  async validateWebhookUrl(url) {
    // Validate URL format
    try {
      const urlObj = new URL(url);
      
      // Must be HTTPS in production
      if (config.isProduction && urlObj.protocol !== 'https:') {
        throw new AppError('Webhook URL must use HTTPS', 400);
      }
      
      // Prevent localhost/internal IPs in production
      if (config.isProduction) {
        const hostname = urlObj.hostname;
        const isLocal = hostname === 'localhost' || 
                       hostname === '127.0.0.1' ||
                       hostname.startsWith('192.168.') ||
                       hostname.startsWith('10.') ||
                       hostname.startsWith('172.');
        
        if (isLocal) {
          throw new AppError('Webhook URL cannot point to internal addresses', 400);
        }
      }
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('Invalid webhook URL', 400);
    }
    
    // Test URL reachability
    try {
      await axios.head(url, { timeout: 5000 });
    } catch (error) {
      logger.warn('Webhook URL not reachable during validation', { url, error: error.message });
      // Don't fail validation, just warn
    }
  }
  
  /**
   * Validate events
   * @param {Array} events - Event types
   */
  validateEvents(events) {
    if (!Array.isArray(events) || events.length === 0) {
      throw new AppError('At least one event type is required', 400);
    }
    
    const validEvents = Object.values(this.eventTypes);
    validEvents.push('*'); // Wildcard for all events
    
    for (const event of events) {
      if (!validEvents.includes(event)) {
        throw new AppError(`Invalid event type: ${event}`, 400);
      }
    }
  }
  
  /**
   * Generate webhook ID
   * @returns {string} Webhook ID
   */
  generateWebhookId() {
    return `whk_${crypto.randomBytes(16).toString('hex')}`;
  }
  
  /**
   * Generate event ID
   * @returns {string} Event ID
   */
  generateEventId() {
    return `evt_${crypto.randomBytes(16).toString('hex')}`;
  }
  
  /**
   * Generate webhook secret
   * @returns {string} Webhook secret
   */
  generateSecret() {
    return `whsec_${crypto.randomBytes(32).toString('hex')}`;
  }
  
  /**
   * Generate signature
   * @param {string} secret - Webhook secret
   * @param {Object} payload - Payload to sign
   * @returns {string} Signature
   */
  generateSignature(secret, payload) {
    const timestamp = Date.now();
    const message = `${timestamp}.${JSON.stringify(payload)}`;
    const signature = crypto
      .createHmac('sha256', secret)
      .update(message)
      .digest('hex');
    
    return `t=${timestamp},v1=${signature}`;
  }
  
  /**
   * Verify webhook signature
   * @param {string} secret - Webhook secret
   * @param {Object} payload - Received payload
   * @param {string} signature - Received signature
   * @returns {boolean} Is valid
   */
  verifySignature(secret, payload, signature) {
    try {
      const parts = signature.split(',');
      const timestamp = parts[0].split('=')[1];
      const receivedSignature = parts[1].split('=')[1];
      
      // Check timestamp (5 minute tolerance)
      const currentTime = Date.now();
      const webhookTime = parseInt(timestamp);
      if (Math.abs(currentTime - webhookTime) > 300000) {
        return false;
      }
      
      // Generate expected signature
      const message = `${timestamp}.${JSON.stringify(payload)}`;
      const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(message)
        .digest('hex');
      
      // Compare signatures
      return crypto.timingSafeEqual(
        Buffer.from(receivedSignature),
        Buffer.from(expectedSignature)
      );
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Log webhook delivery
   * @param {Object} webhook - Webhook configuration
   * @param {Object} eventData - Event data
   * @param {Object} result - Delivery result
   */
  async logDelivery(webhook, eventData, result) {
    const logEntry = {
      webhookId: webhook.id,
      eventId: eventData.id,
      eventType: eventData.type,
      url: webhook.url,
      status: result.status,
      success: result.success,
      duration: result.duration,
      error: result.error,
      timestamp: new Date()
    };
    
    // Log to system
    if (result.success) {
      logger.info('Webhook delivered successfully', logEntry);
    } else {
      logger.error('Webhook delivery failed', logEntry);
    }
    
    // Store in database
    // await WebhookLogModel.create(logEntry);
    
    // Update metrics
    if (config.metrics.enabled) {
      // metrics.webhookDelivery(result.success, result.duration, eventData.type);
    }
  }
  
  /**
   * Get webhook statistics
   * @param {string} webhookId - Webhook ID
   * @returns {Promise<Object>} Statistics
   */
  async getStatistics(webhookId) {
    const webhook = this.webhooks.get(webhookId);
    if (!webhook) {
      throw new AppError('Webhook not found', 404);
    }
    
    // Get delivery logs from database
    // const logs = await WebhookLogModel.find({ webhookId }).sort({ timestamp: -1 }).limit(100);
    
    return {
      webhook: {
        id: webhook.id,
        url: webhook.url,
        active: webhook.active,
        events: webhook.events,
        createdAt: webhook.createdAt,
        lastTriggeredAt: webhook.lastTriggeredAt
      },
      statistics: {
        totalDeliveries: webhook.successCount + webhook.failureCount,
        successfulDeliveries: webhook.successCount,
        failedDeliveries: webhook.failureCount,
        successRate: webhook.successCount / (webhook.successCount + webhook.failureCount) || 0,
        averageResponseTime: 0, // Calculate from logs
        lastFailure: null, // Get from logs
        consecutiveFailures: webhook.failureCount
      },
      recentDeliveries: [] // logs
    };
  }
  
  /**
   * Test webhook
   * @param {string} webhookId - Webhook ID
   * @returns {Promise<Object>} Test result
   */
  async test(webhookId) {
    const webhook = this.webhooks.get(webhookId);
    if (!webhook) {
      throw new AppError('Webhook not found', 404);
    }
    
    // Create test event
    const testEvent = {
      id: this.generateEventId(),
      type: 'webhook.test',
      timestamp: new Date().toISOString(),
      data: {
        message: 'This is a test webhook delivery',
        webhookId: webhook.id,
        timestamp: new Date().toISOString()
      },
      metadata: {
        test: true,
        version: '1.0'
      }
    };
    
    // Deliver test webhook
    try {
      const result = await this.deliver(webhook, testEvent);
      return {
        success: true,
        ...result
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        status: error.response?.status || 0
      };
    }
  }
  
  /**
   * Batch trigger webhooks
   * @param {Array} events - Array of events to trigger
   * @returns {Promise<Object>} Batch results
   */
  async batchTrigger(events) {
    const results = await Promise.allSettled(
      events.map(event => 
        this.trigger(event.type, event.payload, event.options)
      )
    );
    
    return {
      total: events.length,
      successful: results.filter(r => r.status === 'fulfilled').length,
      failed: results.filter(r => r.status === 'rejected').length,
      results: results.map((result, index) => ({
        event: events[index].type,
        success: result.status === 'fulfilled',
        error: result.reason?.message
      }))
    };
  }
}

// Create singleton instance
const webhookService = new WebhookService();

module.exports = webhookService;