/**
 * @file Admin Audit Logging Middleware
 * @description Enhanced audit logging for administrative operations with compliance and forensics capabilities
 * @version 1.0.0
 */

const crypto = require('crypto');
const AuditService = require('../../../audit/services/audit-service');
const EncryptionService = require('../../../security/services/encryption-service');
const logger = require('../../../utils/logger');
const { asyncHandler } = require('../../../utils/async-handler');
const config = require('../../../config/config');

/**
 * Admin Audit Logging Middleware Class
 * @class AdminAuditLogger
 */
class AdminAuditLogger {
  /**
   * Initialize admin audit configurations
   */
  static initialize() {
    this.encryptionService = new EncryptionService();
    
    // Define admin event types
    this.adminEventTypes = {
      // System Administration
      SYSTEM_CONFIG_CHANGED: 'admin_system_config_changed',
      SYSTEM_MAINTENANCE_STARTED: 'admin_system_maintenance_started',
      SYSTEM_MAINTENANCE_COMPLETED: 'admin_system_maintenance_completed',
      SYSTEM_BACKUP_CREATED: 'admin_system_backup_created',
      SYSTEM_RESTORE_INITIATED: 'admin_system_restore_initiated',
      
      // User Administration
      USER_CREATED_BY_ADMIN: 'admin_user_created',
      USER_MODIFIED_BY_ADMIN: 'admin_user_modified',
      USER_DELETED_BY_ADMIN: 'admin_user_deleted',
      USER_SUSPENDED_BY_ADMIN: 'admin_user_suspended',
      USER_REACTIVATED_BY_ADMIN: 'admin_user_reactivated',
      USER_ROLE_CHANGED_BY_ADMIN: 'admin_user_role_changed',
      USER_IMPERSONATION_STARTED: 'admin_user_impersonation_started',
      USER_IMPERSONATION_ENDED: 'admin_user_impersonation_ended',
      
      // Organization Administration
      ORG_CREATED_BY_ADMIN: 'admin_org_created',
      ORG_MODIFIED_BY_ADMIN: 'admin_org_modified',
      ORG_SUSPENDED_BY_ADMIN: 'admin_org_suspended',
      ORG_DELETED_BY_ADMIN: 'admin_org_deleted',
      ORG_BILLING_MODIFIED: 'admin_org_billing_modified',
      ORG_LIMITS_CHANGED: 'admin_org_limits_changed',
      
      // Security Administration
      SECURITY_POLICY_CHANGED: 'admin_security_policy_changed',
      SECURITY_ALERT_TRIGGERED: 'admin_security_alert_triggered',
      SECURITY_BREACH_DETECTED: 'admin_security_breach_detected',
      SECURITY_AUDIT_EXPORTED: 'admin_security_audit_exported',
      
      // Access Control
      ADMIN_ACCESS_GRANTED: 'admin_access_granted',
      ADMIN_ACCESS_REVOKED: 'admin_access_revoked',
      ADMIN_PERMISSION_CHANGED: 'admin_permission_changed',
      EMERGENCY_ACCESS_ACTIVATED: 'admin_emergency_access_activated',
      
      // Data Operations
      BULK_DATA_EXPORT: 'admin_bulk_data_export',
      BULK_DATA_IMPORT: 'admin_bulk_data_import',
      BULK_DATA_DELETION: 'admin_bulk_data_deletion',
      DATA_ANONYMIZATION: 'admin_data_anonymization',
      
      // Compliance Operations
      COMPLIANCE_REPORT_GENERATED: 'admin_compliance_report_generated',
      COMPLIANCE_AUDIT_INITIATED: 'admin_compliance_audit_initiated',
      GDPR_REQUEST_PROCESSED: 'admin_gdpr_request_processed',
      LEGAL_HOLD_APPLIED: 'admin_legal_hold_applied'
    };

    // Define severity mappings for admin events
    this.severityMappings = {
      [this.adminEventTypes.SYSTEM_CONFIG_CHANGED]: 'high',
      [this.adminEventTypes.USER_IMPERSONATION_STARTED]: 'critical',
      [this.adminEventTypes.SECURITY_BREACH_DETECTED]: 'critical',
      [this.adminEventTypes.EMERGENCY_ACCESS_ACTIVATED]: 'critical',
      [this.adminEventTypes.BULK_DATA_DELETION]: 'high',
      [this.adminEventTypes.LEGAL_HOLD_APPLIED]: 'high'
    };

    // Define required fields for different event types
    this.requiredFields = {
      user_operation: ['targetUserId', 'operation', 'changes'],
      org_operation: ['organizationId', 'operation', 'changes'],
      system_operation: ['component', 'operation', 'previousValue', 'newValue'],
      security_operation: ['securityEvent', 'riskScore', 'affectedResources'],
      data_operation: ['dataType', 'recordCount', 'operation', 'reason']
    };
  }

  /**
   * Core admin audit logging middleware
   * @param {Object} options - Logging options
   * @returns {Function} Express middleware
   */
  static auditLog(options = {}) {
    const {
      eventType,
      category = 'admin_action',
      captureRequestBody = true,
      captureResponseBody = false,
      sensitiveFields = [],
      requireReason = false,
      complianceMode = false
    } = options;

    return asyncHandler(async (req, res, next) => {
      const startTime = Date.now();
      const auditId = crypto.randomUUID();
      
      // Capture original methods
      const originalSend = res.send;
      const originalJson = res.json;
      const originalStatus = res.status;
      
      let responseBody = null;
      let statusCode = 200;

      // Override response methods to capture data
      res.status = function(code) {
        statusCode = code;
        return originalStatus.call(this, code);
      };

      res.json = function(body) {
        responseBody = body;
        return originalJson.call(this, body);
      };

      res.send = function(body) {
        responseBody = body;
        return originalSend.call(this, body);
      };

      // Prepare audit context
      const auditContext = {
        auditId,
        timestamp: new Date(),
        eventType: eventType || 'admin_action',
        category,
        userId: req.user?._id,
        adminRole: req.user?.role?.primary,
        sessionId: req.adminAuth?.sessionId,
        endpoint: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        requestId: req.id || auditId
      };

      // Capture request details
      if (captureRequestBody && req.body) {
        auditContext.requestBody = this.sanitizeSensitiveData(
          req.body, 
          [...sensitiveFields, 'password', 'token', 'secret', 'apiKey']
        );
      }

      // Check for required reason
      if (requireReason && !req.body?.reason && !req.query?.reason) {
        return res.status(400).json({
          success: false,
          error: 'Audit reason required for this operation',
          data: { field: 'reason' }
        });
      }

      auditContext.reason = req.body?.reason || req.query?.reason;

      // Set audit context in request
      req.auditContext = auditContext;

      // Continue with request processing
      const processRequest = () => {
        next();

        // After response is sent
        res.on('finish', async () => {
          try {
            const duration = Date.now() - startTime;
            const result = statusCode >= 200 && statusCode < 400 ? 'success' : 'failure';
            const severity = this.determineSeverity(eventType, result, statusCode);

            // Build complete audit log
            const auditLog = {
              ...auditContext,
              result,
              statusCode,
              duration,
              severity,
              metadata: {
                ...auditContext,
                duration,
                responseSize: res.get('content-length') || 0,
                ...(captureResponseBody && responseBody && {
                  responseBody: this.sanitizeSensitiveData(responseBody, sensitiveFields)
                })
              }
            };

            // Add compliance data if enabled
            if (complianceMode) {
              auditLog.compliance = {
                dataClassification: this.classifyData(req, res),
                retentionPeriod: this.getRetentionPeriod(eventType),
                encryptionRequired: this.requiresEncryption(eventType),
                regulatoryFramework: this.getApplicableFrameworks(req)
              };
            }

            // Encrypt sensitive audit data if required
            if (this.requiresEncryption(eventType)) {
              auditLog.encryptedData = this.encryptionService.encryptField(
                auditLog.metadata,
                'admin_audit_metadata'
              );
              delete auditLog.metadata.requestBody;
              delete auditLog.metadata.responseBody;
            }

            // Log to audit service
            await AuditService.log({
              type: auditLog.eventType,
              action: this.extractAction(req),
              category: auditLog.category,
              result: auditLog.result,
              severity: auditLog.severity,
              userId: auditLog.userId,
              target: this.extractTarget(req),
              metadata: auditLog.metadata,
              compliance: auditLog.compliance,
              encryptedData: auditLog.encryptedData
            });

            // Check for high-severity events
            if (severity === 'critical' || severity === 'high') {
              await this.handleHighSeverityEvent(auditLog);
            }

            // Check for anomalous behavior
            await this.checkForAnomalies(auditLog);

          } catch (error) {
            logger.error('Admin audit logging error', {
              error: error.message,
              auditId,
              userId: req.user?._id
            });
          }
        });
      };

      processRequest();
    });
  }

  /**
   * Log specific admin event
   * @param {Object} eventData - Event data
   * @returns {Promise<void>}
   */
  static async logAdminEvent(eventData) {
    try {
      const {
        eventType,
        userId,
        targetId,
        targetType,
        operation,
        changes,
        reason,
        metadata = {}
      } = eventData;

      const severity = this.severityMappings[eventType] || 'medium';

      await AuditService.log({
        type: eventType,
        action: operation,
        category: 'admin_action',
        result: 'success',
        severity,
        userId,
        target: {
          type: targetType,
          id: targetId
        },
        metadata: {
          ...metadata,
          changes,
          reason,
          timestamp: new Date().toISOString()
        }
      });

    } catch (error) {
      logger.error('Failed to log admin event', {
        error: error.message,
        eventType: eventData.eventType
      });
    }
  }

  /**
   * Create audit trail for multi-step operations
   * @param {Object} operation - Operation details
   * @returns {Object} Audit trail tracker
   */
  static createAuditTrail(operation) {
    const trailId = crypto.randomUUID();
    const trail = {
      id: trailId,
      operation: operation.name,
      startedAt: new Date(),
      userId: operation.userId,
      steps: [],
      
      // Add step to trail
      addStep: async function(stepData) {
        const step = {
          id: crypto.randomUUID(),
          timestamp: new Date(),
          ...stepData
        };
        
        this.steps.push(step);
        
        await AuditService.log({
          type: 'admin_trail_step',
          action: stepData.action,
          category: 'admin_trail',
          result: stepData.result || 'in_progress',
          userId: this.userId,
          target: {
            type: 'audit_trail',
            id: this.id
          },
          metadata: {
            trailId: this.id,
            stepId: step.id,
            stepNumber: this.steps.length,
            ...stepData
          }
        });
      },
      
      // Complete trail
      complete: async function(result = 'success') {
        this.completedAt = new Date();
        this.result = result;
        this.duration = this.completedAt - this.startedAt;
        
        await AuditService.log({
          type: 'admin_trail_completed',
          action: 'complete',
          category: 'admin_trail',
          result,
          userId: this.userId,
          target: {
            type: 'audit_trail',
            id: this.id
          },
          metadata: {
            operation: this.operation,
            stepCount: this.steps.length,
            duration: this.duration,
            steps: this.steps
          }
        });
      }
    };
    
    return trail;
  }

  /**
   * Sanitize sensitive data for logging
   * @param {Object} data - Data to sanitize
   * @param {Array} fields - Sensitive fields
   * @returns {Object} Sanitized data
   */
  static sanitizeSensitiveData(data, fields = []) {
    if (!data || typeof data !== 'object') return data;
    
    const sanitized = JSON.parse(JSON.stringify(data));
    const defaultSensitive = [
      'password', 'token', 'secret', 'apiKey', 'creditCard',
      'ssn', 'bankAccount', 'pin', 'privateKey', 'clientSecret'
    ];
    
    const allFields = [...new Set([...defaultSensitive, ...fields])];
    
    const sanitizeObject = (obj) => {
      for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        
        if (allFields.some(field => lowerKey.includes(field.toLowerCase()))) {
          obj[key] = '[REDACTED]';
        } else if (value && typeof value === 'object') {
          sanitizeObject(value);
        }
      }
    };
    
    sanitizeObject(sanitized);
    return sanitized;
  }

  /**
   * Determine event severity
   * @param {string} eventType - Event type
   * @param {string} result - Operation result
   * @param {number} statusCode - HTTP status code
   * @returns {string} Severity level
   */
  static determineSeverity(eventType, result, statusCode) {
    // Check predefined severity mappings
    if (this.severityMappings[eventType]) {
      return this.severityMappings[eventType];
    }
    
    // Determine by result and status
    if (result === 'failure') {
      if (statusCode >= 500) return 'high';
      if (statusCode === 403) return 'medium';
      if (statusCode === 401) return 'medium';
      return 'low';
    }
    
    // Default severities for specific operations
    if (eventType?.includes('delete') || eventType?.includes('remove')) {
      return 'medium';
    }
    
    if (eventType?.includes('create') || eventType?.includes('update')) {
      return 'low';
    }
    
    return 'low';
  }

  /**
   * Check if event requires encryption
   * @param {string} eventType - Event type
   * @returns {boolean} Requires encryption
   */
  static requiresEncryption(eventType) {
    const encryptionRequired = [
      this.adminEventTypes.USER_IMPERSONATION_STARTED,
      this.adminEventTypes.SECURITY_BREACH_DETECTED,
      this.adminEventTypes.BULK_DATA_EXPORT,
      this.adminEventTypes.GDPR_REQUEST_PROCESSED
    ];
    
    return encryptionRequired.includes(eventType);
  }

  /**
   * Get retention period for event type
   * @param {string} eventType - Event type
   * @returns {number} Retention days
   */
  static getRetentionPeriod(eventType) {
    const retentionPolicies = config.audit.retentionPolicies;
    
    // Legal and compliance events
    if (eventType?.includes('legal_hold') || eventType?.includes('compliance')) {
      return retentionPolicies.legal_hold;
    }
    
    // Security events
    if (eventType?.includes('security') || eventType?.includes('breach')) {
      return retentionPolicies.soc2;
    }
    
    // GDPR-related events
    if (eventType?.includes('gdpr') || eventType?.includes('data_deletion')) {
      return retentionPolicies.gdpr;
    }
    
    // Default retention
    return retentionPolicies.standard;
  }

  /**
   * Classify data for compliance
   * @param {Object} req - Express request
   * @param {Object} res - Express response
   * @returns {string} Data classification
   */
  static classifyData(req, res) {
    const endpoint = req.originalUrl.toLowerCase();
    
    if (endpoint.includes('user') || endpoint.includes('profile')) {
      return 'PII';
    }
    
    if (endpoint.includes('payment') || endpoint.includes('billing')) {
      return 'PCI';
    }
    
    if (endpoint.includes('health') || endpoint.includes('medical')) {
      return 'PHI';
    }
    
    if (endpoint.includes('security') || endpoint.includes('auth')) {
      return 'SENSITIVE';
    }
    
    return 'INTERNAL';
  }

  /**
   * Get applicable regulatory frameworks
   * @param {Object} req - Express request
   * @returns {Array} Applicable frameworks
   */
  static getApplicableFrameworks(req) {
    const frameworks = [];
    const endpoint = req.originalUrl.toLowerCase();
    
    // GDPR - European users
    if (req.user?.preferences?.region === 'EU' || endpoint.includes('gdpr')) {
      frameworks.push('GDPR');
    }
    
    // HIPAA - Health data
    if (endpoint.includes('health') || endpoint.includes('medical')) {
      frameworks.push('HIPAA');
    }
    
    // PCI DSS - Payment data
    if (endpoint.includes('payment') || endpoint.includes('card')) {
      frameworks.push('PCI-DSS');
    }
    
    // SOC 2 - Security operations
    if (endpoint.includes('security') || endpoint.includes('audit')) {
      frameworks.push('SOC2');
    }
    
    return frameworks;
  }

  /**
   * Handle high severity events
   * @param {Object} auditLog - Audit log entry
   * @returns {Promise<void>}
   */
  static async handleHighSeverityEvent(auditLog) {
    try {
      // Send immediate alert
      if (config.audit.alerting.enabled) {
        logger.alert('High severity admin event detected', {
          eventType: auditLog.eventType,
          userId: auditLog.userId,
          severity: auditLog.severity,
          endpoint: auditLog.endpoint,
          result: auditLog.result
        });
        
        // Queue email notification for critical events
        if (auditLog.severity === 'critical') {
          // This would integrate with your email service
          logger.error('Critical admin event - email notification required', {
            to: config.audit.alerting.criticalEventsEmail,
            event: auditLog.eventType,
            userId: auditLog.userId
          });
        }
      }
      
      // Create incident record for tracking
      await AuditService.log({
        type: 'admin_incident_created',
        action: 'create_incident',
        category: 'security',
        result: 'success',
        severity: 'high',
        userId: auditLog.userId,
        metadata: {
          triggeringEvent: auditLog.auditId,
          eventType: auditLog.eventType,
          automatic: true
        }
      });
      
    } catch (error) {
      logger.error('Failed to handle high severity event', {
        error: error.message,
        auditId: auditLog.auditId
      });
    }
  }

  /**
   * Check for anomalous admin behavior
   * @param {Object} auditLog - Audit log entry
   * @returns {Promise<void>}
   */
  static async checkForAnomalies(auditLog) {
    try {
      // Define anomaly patterns
      const anomalyPatterns = [
        {
          name: 'unusual_hours',
          check: () => {
            const hour = new Date(auditLog.timestamp).getHours();
            return hour < 6 || hour > 22; // Outside business hours
          }
        },
        {
          name: 'rapid_operations',
          check: async () => {
            // Check for rapid successive admin operations
            const recentOps = await AuditService.getRecentLogs({
              userId: auditLog.userId,
              category: 'admin_action',
              minutes: 5
            });
            return recentOps.length > 50; // More than 50 ops in 5 minutes
          }
        },
        {
          name: 'unusual_location',
          check: () => {
            // This would integrate with GeoIP service
            return false; // Placeholder
          }
        }
      ];
      
      // Check each pattern
      for (const pattern of anomalyPatterns) {
        const isAnomaly = await pattern.check();
        
        if (isAnomaly) {
          await AuditService.log({
            type: 'admin_anomaly_detected',
            action: 'detect_anomaly',
            category: 'security',
            result: 'detected',
            severity: 'medium',
            userId: auditLog.userId,
            metadata: {
              anomalyType: pattern.name,
              triggeringEvent: auditLog.auditId,
              details: auditLog
            }
          });
        }
      }
      
    } catch (error) {
      logger.error('Anomaly detection error', {
        error: error.message,
        auditId: auditLog.auditId
      });
    }
  }

  /**
   * Extract action from request
   * @param {Object} req - Express request
   * @returns {string} Action
   */
  static extractAction(req) {
    const method = req.method.toLowerCase();
    const endpoint = req.originalUrl.split('?')[0];
    const lastSegment = endpoint.split('/').pop();
    
    const actionMap = {
      get: 'read',
      post: 'create',
      put: 'update',
      patch: 'modify',
      delete: 'delete'
    };
    
    return actionMap[method] || method;
  }

  /**
   * Extract target from request
   * @param {Object} req - Express request
   * @returns {Object} Target info
   */
  static extractTarget(req) {
    const endpoint = req.originalUrl.split('?')[0];
    const segments = endpoint.split('/').filter(Boolean);
    
    // Common patterns
    if (segments.includes('users') && req.params.id) {
      return { type: 'user', id: req.params.id };
    }
    
    if (segments.includes('organizations') && req.params.id) {
      return { type: 'organization', id: req.params.id };
    }
    
    if (segments.includes('settings')) {
      return { type: 'settings', id: segments[segments.length - 1] };
    }
    
    return { type: 'endpoint', id: endpoint };
  }
}

// Initialize on module load
AdminAuditLogger.initialize();

module.exports = AdminAuditLogger;