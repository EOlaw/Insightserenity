/**
 * @file Audit Service
 * @description Core audit logging service with batch processing and compliance features
 * @version 2.0.0
 */

const config = require('../../config/config');
const logger = require('../../utils/logger');
const AuditRepository = require('../repositories/audit-repository');
const AuditComplianceService = require('./audit-compliance-service');
const { AuditEventTypes, AuditCategories } = require('./audit-event-types');
const { calculateRiskScore, detectAnomalies } = require('../utils/audit-helpers');

/**
 * Audit Service Class
 * @class AuditService
 */
class AuditService {
  constructor() {
    this.repository = new AuditRepository();
    this.complianceService = new AuditComplianceService();
    
    // Batch processing configuration
    this.queue = [];
    this.processing = false;
    this.batchSize = config.audit?.batchSize || 100;
    this.flushInterval = config.audit?.flushInterval || 5000;
    this.maxQueueSize = config.audit?.maxQueueSize || 1000;
    
    // Initialize batch processor
    this.startBatchProcessor();
    
    // Bind methods
    this.log = this.log.bind(this);
    this.flush = this.flush.bind(this);
  }
  
  /**
   * Log an audit event
   * @param {Object} eventData - Event data to log
   * @returns {Promise<Object>} Created audit log entry
   */
  async log(eventData) {
    try {
      // Validate required fields
      this.validateEventData(eventData);
      
      // Build audit entry
      const auditEntry = await this.buildAuditEntry(eventData);
      
      // Check if immediate logging is required
      if (this.requiresImmediateLogging(auditEntry)) {
        return await this.repository.create(auditEntry);
      }
      
      // Add to queue for batch processing
      this.addToQueue(auditEntry);
      
      // Log to application logger for real-time monitoring
      this.logToApplicationLogger(auditEntry);
      
      return auditEntry;
    } catch (error) {
      logger.error('Audit logging failed', {
        error: error.message,
        stack: error.stack,
        eventData
      });
      
      // Audit failures should not break the application
      // Optionally, you could send to a fallback logging mechanism
      this.handleAuditFailure(error, eventData);
    }
  }
  
  /**
   * Log multiple events in batch
   * @param {Array<Object>} events - Array of event data
   * @returns {Promise<Object>} Batch operation result
   */
  async logBatch(events) {
    const results = {
      successful: 0,
      failed: 0,
      errors: []
    };
    
    for (const event of events) {
      try {
        await this.log(event);
        results.successful++;
      } catch (error) {
        results.failed++;
        results.errors.push({
          event,
          error: error.message
        });
      }
    }
    
    return results;
  }
  
  /**
   * Build complete audit entry from event data
   * @private
   * @param {Object} eventData - Raw event data
   * @returns {Promise<Object>} Complete audit entry
   */
  async buildAuditEntry(eventData) {
    const { category, severity } = this.categorizeEvent(eventData);
    const riskAssessment = await this.assessRisk(eventData);
    const complianceInfo = await this.complianceService.mapCompliance(eventData);
    
    return {
      event: {
        type: eventData.type || eventData.action,
        category,
        action: eventData.action,
        result: eventData.result || 'success',
        severity,
        description: eventData.description || this.generateDescription(eventData)
      },
      
      actor: {
        userId: eventData.userId,
        email: eventData.userEmail,
        role: eventData.userRole,
        organizationId: eventData.organizationId,
        ipAddress: eventData.ipAddress,
        userAgent: eventData.userAgent,
        sessionId: eventData.sessionId,
        location: eventData.location
      },
      
      target: {
        type: eventData.targetType || eventData.target?.type,
        id: eventData.targetId || eventData.target?.id,
        name: eventData.targetName || eventData.target?.name,
        organizationId: eventData.targetOrgId || eventData.target?.organizationId,
        metadata: eventData.targetMetadata || eventData.target?.metadata
      },
      
      changes: this.buildChangesObject(eventData),
      
      context: {
        requestId: eventData.requestId,
        correlationId: eventData.correlationId,
        source: eventData.source || 'api',
        endpoint: eventData.endpoint,
        method: eventData.method,
        duration: eventData.duration,
        version: config.app.version,
        environment: config.app.env
      },
      
      security: {
        risk: riskAssessment,
        compliance: complianceInfo,
        encryption: {
          enabled: this.shouldEncrypt(eventData),
          algorithm: config.security.encryption.algorithm,
          keyVersion: eventData.encryptionKeyVersion
        }
      },
      
      retention: this.calculateRetention(eventData, complianceInfo),
      
      metadata: {
        tags: eventData.tags || [],
        customFields: eventData.customFields || {},
        processed: false
      }
    };
  }
  
  /**
   * Validate event data
   * @private
   * @param {Object} eventData - Event data to validate
   * @throws {Error} If validation fails
   */
  validateEventData(eventData) {
    if (!eventData.action) {
      throw new Error('Audit event action is required');
    }
    
    if (!eventData.userId && !eventData.systemGenerated) {
      throw new Error('Audit event must have an actor (userId) or be marked as system generated');
    }
    
    // Additional validation rules can be added here
  }
  
  /**
   * Categorize event and determine severity
   * @private
   * @param {Object} eventData - Event data
   * @returns {Object} Category and severity
   */
  categorizeEvent(eventData) {
    let category = eventData.category;
    let severity = eventData.severity;
    
    // Auto-categorize if not provided
    if (!category) {
      category = this.inferCategory(eventData.action || eventData.type);
    }
    
    // Auto-determine severity if not provided
    if (!severity) {
      severity = this.calculateSeverity(eventData, category);
    }
    
    return { category, severity };
  }
  
  /**
   * Infer category from action
   * @private
   * @param {string} action - Event action
   * @returns {string} Inferred category
   */
  inferCategory(action) {
    const actionLower = action.toLowerCase();
    
    const categoryMappings = {
      authentication: ['login', 'logout', 'password_reset', 'mfa_', '2fa_', 'auth_'],
      authorization: ['permission_', 'role_', 'access_denied', 'forbidden'],
      data_access: ['view_', 'read_', 'list_', 'search_', 'export_', 'download_'],
      data_modification: ['create_', 'update_', 'delete_', 'import_', 'upload_'],
      configuration: ['config_', 'settings_', 'preference_', 'setup_'],
      security: ['security_', 'threat_', 'vulnerability_', 'encryption_', 'block_'],
      compliance: ['compliance_', 'audit_', 'regulation_', 'gdpr_', 'pci_'],
      system: ['system_', 'startup', 'shutdown', 'error_', 'performance_']
    };
    
    for (const [category, patterns] of Object.entries(categoryMappings)) {
      if (patterns.some(pattern => actionLower.includes(pattern))) {
        return category;
      }
    }
    
    return 'system';
  }
  
  /**
   * Calculate event severity
   * @private
   * @param {Object} eventData - Event data
   * @param {string} category - Event category
   * @returns {string} Severity level
   */
  calculateSeverity(eventData, category) {
    // Critical severity conditions
    if (
      eventData.type?.includes('security_breach') ||
      eventData.type?.includes('data_leak') ||
      eventData.result === 'blocked' ||
      eventData.critical === true
    ) {
      return 'critical';
    }
    
    // High severity conditions
    if (
      eventData.type?.includes('unauthorized_access') ||
      eventData.type?.includes('permission_escalation') ||
      category === 'security' && eventData.result === 'failure' ||
      eventData.action?.includes('delete_')
    ) {
      return 'high';
    }
    
    // Low severity conditions
    if (
      category === 'data_access' ||
      eventData.action?.includes('view_') ||
      eventData.action?.includes('list_')
    ) {
      return 'low';
    }
    
    return 'medium';
  }
  
  /**
   * Assess security risk
   * @private
   * @param {Object} eventData - Event data
   * @returns {Promise<Object>} Risk assessment
   */
  async assessRisk(eventData) {
    const riskFactors = [];
    let score = 0;
    
    // Calculate base risk score
    const baseScore = calculateRiskScore(eventData);
    score += baseScore;
    
    // Detect anomalies
    const anomalies = await detectAnomalies(eventData, this.repository);
    if (anomalies.length > 0) {
      riskFactors.push(...anomalies);
      score += anomalies.length * 10;
    }
    
    // Additional risk factors
    if (eventData.type === 'login_failed') {
      score += 20;
      riskFactors.push('failed_authentication');
    }
    
    if (eventData.unusualLocation) {
      score += 30;
      riskFactors.push('unusual_location');
    }
    
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) {
      score += 10;
      riskFactors.push('after_hours_access');
    }
    
    if (eventData.sensitiveData || eventData.targetType === 'payment_method') {
      score += 25;
      riskFactors.push('sensitive_data_access');
    }
    
    if (eventData.bulk || eventData.count > 100) {
      score += 15;
      riskFactors.push('bulk_operation');
    }
    
    return {
      score: Math.min(score, 100),
      factors: riskFactors,
      anomalies
    };
  }
  
  /**
   * Build changes object
   * @private
   * @param {Object} eventData - Event data
   * @returns {Object} Changes object
   */
  buildChangesObject(eventData) {
    if (!eventData.changes && !eventData.before && !eventData.after) {
      return null;
    }
    
    return {
      before: eventData.changes?.before || eventData.before,
      after: eventData.changes?.after || eventData.after,
      fields: eventData.changes?.fields || eventData.changedFields || [],
      summary: eventData.changes?.summary || this.generateChangeSummary(eventData)
    };
  }
  
  /**
   * Generate change summary
   * @private
   * @param {Object} eventData - Event data
   * @returns {string} Change summary
   */
  generateChangeSummary(eventData) {
    if (eventData.changes?.summary) return eventData.changes.summary;
    
    const fields = eventData.changes?.fields || eventData.changedFields || [];
    if (fields.length === 0) return null;
    
    return `Modified fields: ${fields.join(', ')}`;
  }
  
  /**
   * Generate event description
   * @private
   * @param {Object} eventData - Event data
   * @returns {string} Event description
   */
  generateDescription(eventData) {
    const { action, targetType, targetName } = eventData;
    
    if (targetType && targetName) {
      return `${action} on ${targetType}: ${targetName}`;
    }
    
    return action;
  }
  
  /**
   * Determine if event should be encrypted
   * @private
   * @param {Object} eventData - Event data
   * @returns {boolean} Should encrypt
   */
  shouldEncrypt(eventData) {
    return eventData.category === 'data_modification' ||
           eventData.targetType === 'payment_method' ||
           eventData.targetType === 'personal_data' ||
           eventData.containsSensitiveData === true ||
           eventData.encrypt === true;
  }
  
  /**
   * Calculate retention settings
   * @private
   * @param {Object} eventData - Event data
   * @param {Object} complianceInfo - Compliance information
   * @returns {Object} Retention settings
   */
  calculateRetention(eventData, complianceInfo) {
    let retentionDays = config.audit?.defaultRetentionDays || 90;
    let policy = 'standard';
    
    // Compliance-based retention
    if (complianceInfo.regulations.includes('GDPR')) {
      retentionDays = Math.max(retentionDays, 365 * 3); // 3 years
      policy = 'extended';
    }
    
    if (complianceInfo.regulations.includes('PCI-DSS')) {
      retentionDays = Math.max(retentionDays, 365 * 2); // 2 years
      policy = 'extended';
    }
    
    // Security events - longer retention
    if (eventData.category === 'security' || eventData.severity === 'critical') {
      retentionDays = Math.max(retentionDays, 365 * 5); // 5 years
      policy = 'extended';
    }
    
    // Legal hold
    if (eventData.legalHold) {
      policy = 'legal_hold';
      retentionDays = null; // No automatic expiration
    }
    
    const expiresAt = retentionDays ? 
      new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000) : 
      null;
    
    return {
      policy,
      expiresAt,
      archived: false
    };
  }
  
  /**
   * Check if immediate logging is required
   * @private
   * @param {Object} auditEntry - Audit entry
   * @returns {boolean} Requires immediate logging
   */
  requiresImmediateLogging(auditEntry) {
    return auditEntry.event.severity === 'critical' ||
           auditEntry.security.risk.score >= 80 ||
           auditEntry.event.category === 'security';
  }
  
  /**
   * Add event to queue
   * @private
   * @param {Object} auditEntry - Audit entry
   */
  addToQueue(auditEntry) {
    this.queue.push(auditEntry);
    
    // Check if queue size limit reached
    if (this.queue.length >= this.maxQueueSize) {
      this.flush().catch(error => {
        logger.error('Failed to flush audit queue on size limit', { error });
      });
    }
  }
  
  /**
   * Log to application logger
   * @private
   * @param {Object} auditEntry - Audit entry
   */
  logToApplicationLogger(auditEntry) {
    const logData = {
      audit: true,
      eventId: auditEntry.eventId,
      action: auditEntry.event.action,
      category: auditEntry.event.category,
      result: auditEntry.event.result,
      actor: auditEntry.actor.email || auditEntry.actor.userId,
      target: `${auditEntry.target.type}:${auditEntry.target.id}`,
      risk: auditEntry.security.risk.score
    };
    
    switch (auditEntry.event.severity) {
      case 'critical':
        logger.error(`AUDIT: ${auditEntry.event.action}`, logData);
        break;
      case 'high':
        logger.warn(`AUDIT: ${auditEntry.event.action}`, logData);
        break;
      default:
        logger.info(`AUDIT: ${auditEntry.event.action}`, logData);
    }
  }
  
  /**
   * Start batch processor
   * @private
   */
  startBatchProcessor() {
    // Set up interval for regular flushing
    this.flushIntervalId = setInterval(() => {
      if (this.queue.length > 0 && !this.processing) {
        this.flush().catch(error => {
          logger.error('Failed to flush audit queue', { error });
        });
      }
    }, this.flushInterval);
    
    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      await this.shutdown();
    });
    
    process.on('SIGTERM', async () => {
      await this.shutdown();
    });
  }
  
  /**
   * Flush audit queue
   * @returns {Promise<Object>} Flush result
   */
  async flush() {
    if (this.processing || this.queue.length === 0) {
      return { flushed: 0 };
    }
    
    this.processing = true;
    const batch = this.queue.splice(0, this.batchSize);
    
    try {
      const result = await this.repository.bulkInsert(batch);
      
      logger.debug('Flushed audit logs', {
        count: result.inserted,
        errors: result.errors.length
      });
      
      return {
        flushed: result.inserted,
        errors: result.errors
      };
    } catch (error) {
      logger.error('Failed to flush audit logs', {
        error: error.message,
        count: batch.length
      });
      
      // Re-queue failed items at the beginning
      this.queue.unshift(...batch);
      
      throw error;
    } finally {
      this.processing = false;
    }
  }
  
  /**
   * Handle audit failure
   * @private
   * @param {Error} error - The error that occurred
   * @param {Object} eventData - Original event data
   */
  handleAuditFailure(error, eventData) {
    // You could implement fallback mechanisms here:
    // - Write to file
    // - Send to external service
    // - Store in memory for later retry
    // For now, just log the failure
    
    logger.error('Audit system failure - fallback activated', {
      error: error.message,
      eventData,
      timestamp: new Date().toISOString()
    });
  }
  
  /**
   * Graceful shutdown
   * @returns {Promise<void>}
   */
  async shutdown() {
    logger.info('Shutting down audit service...');
    
    // Clear interval
    if (this.flushIntervalId) {
      clearInterval(this.flushIntervalId);
    }
    
    // Flush remaining events
    try {
      await this.flush();
      logger.info('Audit service shutdown complete');
    } catch (error) {
      logger.error('Error during audit service shutdown', { error });
    }
  }
  
  /**
   * Query audit logs
   * @param {Object} filters - Query filters
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Query results
   */
  async query(filters = {}, options = {}) {
    return this.repository.query(filters, options);
  }
  
  /**
   * Get audit log by ID
   * @param {string} id - Audit log ID
   * @returns {Promise<Object>} Audit log
   */
  async getById(id) {
    return this.repository.findById(id);
  }
  
  /**
   * Generate compliance report
   * @param {string} regulation - Regulation type
   * @param {Date} startDate - Report start date
   * @param {Date} endDate - Report end date
   * @returns {Promise<Object>} Compliance report
   */
  async generateComplianceReport(regulation, startDate, endDate) {
    return this.complianceService.generateReport(regulation, startDate, endDate);
  }
  
  /**
   * Archive old logs
   * @param {number} daysOld - Days threshold
   * @returns {Promise<number>} Number of archived logs
   */
  async archiveOldLogs(daysOld = 365) {
    return this.repository.archiveOldLogs(daysOld);
  }
  
  /**
   * Get statistics
   * @param {Object} filters - Statistics filters
   * @returns {Promise<Object>} Audit statistics
   */
  async getStatistics(filters = {}) {
    return this.repository.getStatistics(filters);
  }
}

// Export singleton instance
module.exports = new AuditService();