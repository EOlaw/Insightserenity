// server/admin/security-administration/services/audit-service.js
/**
 * @file Admin Audit Service
 * @description Comprehensive audit management service for administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

// Core Models
const AuditLog = require('../../../shared/security/models/audit-log-model');
const AuditReport = require('../../../shared/security/models/audit-report-model');
const AuditRetention = require('../../../shared/security/models/audit-retention-model');
const AuditExport = require('../../../shared/security/models/audit-export-model');
const ComplianceMapping = require('../../../shared/security/models/compliance-mapping-model');
const AuditAlert = require('../../../shared/security/models/audit-alert-model');
const User = require('../../../shared/users/models/user-model');
const Organization = require('../../../hosted-organizations/organizations/models/organization-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const CoreAuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const EmailService = require('../../../shared/services/email-service');
const ExportService = require('../../../shared/admin/services/admin-export-service');
const EncryptionService = require('../../../shared/security/services/encryption-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

// Configuration
const config = require('../../../config');

/**
 * Admin Audit Service Class
 * @class AuditService
 * @extends AdminBaseService
 */
class AuditService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'AdminAuditService';
    this.cachePrefix = 'admin-audit';
    this.auditCategory = 'AUDIT_MANAGEMENT';
    this.requiredPermission = AdminPermissions.AUDIT.VIEW;
  }

  /**
   * Get audit logs with advanced filtering
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Paginated audit logs
   */
  static async getAuditLogs(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW);

      const {
        page = 1,
        limit = 50,
        startDate,
        endDate,
        eventType,
        eventCategory,
        severity,
        userId,
        organizationId,
        targetType,
        targetId,
        result,
        search,
        includeSystemEvents = false,
        sortBy = 'timestamp',
        sortOrder = 'desc'
      } = options;

      // Build query
      const query = this.buildAuditQuery({
        startDate,
        endDate,
        eventType,
        eventCategory,
        severity,
        userId,
        organizationId,
        targetType,
        targetId,
        result,
        search,
        includeSystemEvents
      });

      // Check if sensitive data access
      const accessingSensitiveData = this.isAccessingSensitiveAuditData(query);
      if (accessingSensitiveData) {
        await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW_SENSITIVE);
      }

      // Calculate pagination
      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

      // Execute query with population
      const [logs, totalCount] = await Promise.all([
        AuditLog.find(query)
          .populate('actor.userId', 'email profile.firstName profile.lastName')
          .populate('actor.organizationId', 'name subdomain')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        AuditLog.countDocuments(query)
      ]);

      // Decrypt sensitive fields if authorized
      const decryptedLogs = await this.decryptAuditLogs(logs, adminUser);

      // Enhance audit data
      const enhancedLogs = await this.enhanceAuditData(decryptedLogs);

      // Generate analytics
      const analytics = await this.generateAuditAnalytics(query, options);

      // Prepare response
      const response = {
        logs: enhancedLogs,
        pagination: {
          total: totalCount,
          page,
          limit,
          pages: Math.ceil(totalCount / limit),
          hasMore: skip + logs.length < totalCount
        },
        analytics,
        filters: {
          applied: Object.keys(options).filter(key => 
            options[key] !== undefined && 
            !['page', 'limit', 'sortBy', 'sortOrder'].includes(key)
          ),
          available: await this.getAvailableAuditFilters()
        }
      };

      // Log audit access event
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOGS_VIEWED, {
        count: logs.length,
        filters: response.filters.applied,
        sensitiveAccess: accessingSensitiveData
      });

      return response;

    } catch (error) {
      logger.error('Get audit logs error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get detailed audit event
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} auditId - Audit log ID
   * @returns {Promise<Object>} Detailed audit event
   */
  static async getAuditDetails(adminUser, auditId) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW);

      // Find audit log
      const auditLog = await AuditLog.findById(auditId)
        .populate('actor.userId', 'email profile role')
        .populate('actor.organizationId', 'name plan status')
        .populate('target.userId', 'email profile')
        .populate('target.organizationId', 'name')
        .lean();

      if (!auditLog) {
        throw new NotFoundError('Audit log not found');
      }

      // Check if sensitive data
      if (auditLog.security.classification === 'restricted') {
        await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW_SENSITIVE);
      }

      // Decrypt sensitive fields
      const decryptedLog = await this.decryptSingleAuditLog(auditLog, adminUser);

      // Get related events
      const relatedEvents = await this.getRelatedAuditEvents(auditLog);

      // Get compliance mappings
      const complianceMappings = await this.getComplianceMappings(auditLog);

      // Compile detailed response
      const details = {
        ...decryptedLog,
        relatedEvents,
        complianceMappings,
        metadata: {
          viewedAt: new Date(),
          viewedBy: adminUser.id,
          decrypted: !!decryptedLog.changes
        }
      };

      // Log detailed view
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOG_DETAILS_VIEWED, {
        auditId,
        eventType: auditLog.event.type,
        sensitive: auditLog.security.classification === 'restricted'
      });

      return details;

    } catch (error) {
      logger.error('Get audit details error', {
        error: error.message,
        adminId: adminUser.id,
        auditId,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Configure audit retention policies
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} policyData - Retention policy data
   * @returns {Promise<Object>} Updated retention policy
   */
  static async configureRetentionPolicy(adminUser, policyData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.CONFIGURE_RETENTION);

      const {
        name,
        description,
        eventTypes,
        retentionDays,
        complianceStandard,
        autoArchive = true,
        archiveAfterDays,
        deletionStrategy = 'soft'
      } = policyData;

      // Validate retention period against compliance requirements
      await this.validateRetentionCompliance(retentionDays, complianceStandard);

      // Check for existing policy
      const existingPolicy = await AuditRetention.findOne({
        name,
        isActive: true
      }).session(session);

      if (existingPolicy) {
        throw new ValidationError('Active retention policy with this name already exists');
      }

      // Create retention policy
      const policy = await AuditRetention.create([{
        name,
        description,
        eventTypes,
        retentionDays,
        complianceStandard,
        autoArchive,
        archiveAfterDays: archiveAfterDays || retentionDays - 30,
        deletionStrategy,
        createdBy: adminUser.id,
        isActive: true,
        statistics: {
          eventsAffected: 0,
          lastApplied: null,
          nextExecution: new Date(Date.now() + 24 * 60 * 60 * 1000)
        }
      }], { session });

      // Apply policy to existing logs
      const applyResult = await this.applyRetentionPolicy(policy[0], session);

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.RETENTION_POLICY_CONFIGURED, {
        policyId: policy[0]._id,
        policyName: name,
        retentionDays,
        eventsAffected: applyResult.affected
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        policy: policy[0],
        applied: applyResult,
        message: 'Retention policy configured successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Configure retention policy error', {
        error: error.message,
        adminId: adminUser.id,
        policyData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Export audit logs
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} exportOptions - Export options
   * @returns {Promise<Object>} Export result
   */
  static async exportAuditLogs(adminUser, exportOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.EXPORT);

      const {
        format = 'csv',
        filters = {},
        includeRawData = false,
        complianceFormat = null,
        encryptExport = true,
        notificationEmail
      } = exportOptions;

      // Validate export request
      if (includeRawData) {
        await this.validatePermission(adminUser, AdminPermissions.AUDIT.EXPORT_RAW);
      }

      // Build query from filters
      const query = this.buildAuditQuery(filters);

      // Count total records
      const totalRecords = await AuditLog.countDocuments(query);

      if (totalRecords > AdminLimits.AUDIT.MAX_EXPORT_RECORDS) {
        throw new ValidationError(
          `Export exceeds maximum limit of ${AdminLimits.AUDIT.MAX_EXPORT_RECORDS} records`
        );
      }

      // Create export job
      const exportJob = await AuditExport.create({
        initiatedBy: adminUser.id,
        format,
        filters,
        totalRecords,
        includeRawData,
        complianceFormat,
        status: 'processing',
        metadata: {
          encryptExport,
          notificationEmail: notificationEmail || adminUser.email
        }
      });

      // Process export asynchronously
      this.processAuditExport(exportJob, query, adminUser)
        .catch(error => {
          logger.error('Audit export processing error', {
            error: error.message,
            exportId: exportJob._id,
            stack: error.stack
          });
        });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOGS_EXPORTED, {
        exportId: exportJob._id,
        format,
        recordCount: totalRecords,
        includeRawData
      }, { critical: includeRawData });

      return {
        exportId: exportJob._id,
        status: 'processing',
        estimatedRecords: totalRecords,
        message: 'Audit export initiated. You will be notified when complete.'
      };

    } catch (error) {
      logger.error('Export audit logs error', {
        error: error.message,
        adminId: adminUser.id,
        exportOptions,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Configure audit alerts
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} alertConfig - Alert configuration
   * @returns {Promise<Object>} Alert configuration result
   */
  static async configureAuditAlerts(adminUser, alertConfig) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.CONFIGURE_ALERTS);

      const {
        name,
        description,
        conditions,
        actions,
        severity = 'medium',
        enabled = true,
        throttleMinutes = 15
      } = alertConfig;

      // Validate alert conditions
      this.validateAlertConditions(conditions);

      // Create alert configuration
      const alert = await AuditAlert.create([{
        name,
        description,
        conditions,
        actions,
        severity,
        enabled,
        throttleMinutes,
        createdBy: adminUser.id,
        statistics: {
          triggered: 0,
          lastTriggered: null,
          notifications: 0
        }
      }], { session });

      // Test alert if requested
      if (alertConfig.test) {
        await this.testAuditAlert(alert[0], session);
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.ALERT_CONFIGURED, {
        alertId: alert[0]._id,
        alertName: name,
        severity,
        enabled
      }, { session });

      await session.commitTransaction();

      return {
        alert: alert[0],
        message: 'Audit alert configured successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Configure audit alerts error', {
        error: error.message,
        adminId: adminUser.id,
        alertConfig,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Search audit logs
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} searchParams - Search parameters
   * @returns {Promise<Object>} Search results
   */
  static async searchAuditLogs(adminUser, searchParams) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.SEARCH);

      const {
        query,
        searchIn = ['event.action', 'event.description', 'changes.summary'],
        timeRange,
        page = 1,
        limit = 50,
        highlight = true
      } = searchParams;

      if (!query || query.trim().length < 3) {
        throw new ValidationError('Search query must be at least 3 characters');
      }

      // Build search query
      const searchQuery = {
        $text: { $search: query }
      };

      // Add time range if specified
      if (timeRange) {
        const timeMs = this.parseTimeRange(timeRange);
        searchQuery.timestamp = { $gte: new Date(Date.now() - timeMs) };
      }

      // Add text score for relevance
      const projection = highlight ? { score: { $meta: 'textScore' } } : {};

      // Execute search
      const [results, totalCount] = await Promise.all([
        AuditLog.find(searchQuery, projection)
          .sort(highlight ? { score: { $meta: 'textScore' } } : { timestamp: -1 })
          .skip((page - 1) * limit)
          .limit(limit)
          .populate('actor.userId', 'email profile.firstName profile.lastName')
          .lean(),
        AuditLog.countDocuments(searchQuery)
      ]);

      // Highlight search terms if requested
      const processedResults = highlight ? 
        this.highlightSearchResults(results, query) : 
        results;

      // Log search
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOGS_SEARCHED, {
        query,
        resultCount: results.length,
        totalMatches: totalCount
      });

      return {
        results: processedResults,
        pagination: {
          total: totalCount,
          page,
          limit,
          pages: Math.ceil(totalCount / limit)
        },
        query,
        searchTime: new Date()
      };

    } catch (error) {
      logger.error('Search audit logs error', {
        error: error.message,
        adminId: adminUser.id,
        searchParams,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Generate audit compliance report
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} reportOptions - Report options
   * @returns {Promise<Object>} Compliance report
   */
  static async generateComplianceReport(adminUser, reportOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.GENERATE_REPORTS);

      const {
        standard,
        startDate,
        endDate,
        scope = ['all'],
        format = 'detailed',
        includeEvidence = true
      } = reportOptions;

      if (!standard) {
        throw new ValidationError('Compliance standard must be specified');
      }

      // Validate compliance standard
      const validStandards = ['GDPR', 'HIPAA', 'PCI-DSS', 'SOC2', 'ISO27001'];
      if (!validStandards.includes(standard)) {
        throw new ValidationError('Invalid compliance standard');
      }

      // Get compliance mappings
      const mappings = await ComplianceMapping.find({
        standard,
        isActive: true
      });

      // Generate date range
      const dateRange = {
        start: startDate ? new Date(startDate) : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
        end: endDate ? new Date(endDate) : new Date()
      };

      // Collect compliance data
      const complianceData = await this.collectComplianceData(
        standard,
        mappings,
        dateRange,
        scope
      );

      // Generate report
      const report = {
        id: crypto.randomUUID(),
        standard,
        generatedAt: new Date(),
        generatedBy: adminUser.id,
        period: dateRange,
        scope,
        summary: {
          compliant: complianceData.compliant,
          nonCompliant: complianceData.nonCompliant,
          gaps: complianceData.gaps,
          score: complianceData.overallScore
        },
        controls: complianceData.controls,
        findings: complianceData.findings,
        recommendations: complianceData.recommendations
      };

      // Add evidence if requested
      if (includeEvidence) {
        report.evidence = await this.collectComplianceEvidence(
          complianceData.controls,
          dateRange
        );
      }

      // Save report
      await AuditReport.create({
        type: 'compliance',
        standard,
        report,
        generatedBy: adminUser.id
      });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.COMPLIANCE_REPORT_GENERATED, {
        reportId: report.id,
        standard,
        complianceScore: report.summary.score
      });

      return report;

    } catch (error) {
      logger.error('Generate compliance report error', {
        error: error.message,
        adminId: adminUser.id,
        reportOptions,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Archive audit logs
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} archiveOptions - Archive options
   * @returns {Promise<Object>} Archive result
   */
  static async archiveAuditLogs(adminUser, archiveOptions = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.ARCHIVE);

      const {
        olderThanDays = 365,
        eventTypes,
        compress = true,
        encrypt = true,
        deleteAfterArchive = false
      } = archiveOptions;

      // Calculate cutoff date
      const cutoffDate = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);

      // Build archive query
      const query = {
        timestamp: { $lt: cutoffDate },
        'retention.archived': false
      };

      if (eventTypes && eventTypes.length > 0) {
        query['event.type'] = { $in: eventTypes };
      }

      // Count logs to archive
      const logsToArchive = await AuditLog.countDocuments(query);

      if (logsToArchive === 0) {
        return {
          message: 'No logs found matching archive criteria',
          archived: 0
        };
      }

      // Create archive job
      const archiveId = crypto.randomUUID();
      const archiveStartTime = Date.now();

      logger.info('Starting audit log archive', {
        archiveId,
        logsToArchive,
        cutoffDate,
        initiatedBy: adminUser.id
      });

      // Process archive in batches
      const batchSize = 1000;
      let processed = 0;
      let archived = 0;

      while (processed < logsToArchive) {
        const logs = await AuditLog.find(query)
          .limit(batchSize)
          .session(session);

        if (logs.length === 0) break;

        // Archive batch
        const archiveResult = await this.archiveBatch(logs, {
          compress,
          encrypt,
          archiveId,
          session
        });

        // Update logs
        const logIds = logs.map(log => log._id);
        await AuditLog.updateMany(
          { _id: { $in: logIds } },
          {
            $set: {
              'retention.archived': true,
              'retention.archivedAt': new Date(),
              'retention.archiveLocation': archiveResult.location
            }
          },
          { session }
        );

        // Delete if requested
        if (deleteAfterArchive) {
          await AuditLog.deleteMany(
            { _id: { $in: logIds } },
            { session }
          );
        }

        processed += logs.length;
        archived += archiveResult.count;

        // Progress update
        if (processed % 10000 === 0) {
          logger.info('Archive progress', {
            archiveId,
            processed,
            total: logsToArchive,
            percentage: Math.round((processed / logsToArchive) * 100)
          });
        }
      }

      const archiveDuration = Date.now() - archiveStartTime;

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOGS_ARCHIVED, {
        archiveId,
        logsArchived: archived,
        cutoffDate,
        duration: archiveDuration,
        compressed: compress,
        encrypted: encrypt,
        deleted: deleteAfterArchive
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        archiveId,
        archived,
        duration: archiveDuration,
        message: `Successfully archived ${archived} audit logs`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Archive audit logs error', {
        error: error.message,
        adminId: adminUser.id,
        archiveOptions,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  // ========== Private Helper Methods ==========

  /**
   * Build audit query from filters
   * @param {Object} filters - Filter parameters
   * @returns {Object} MongoDB query
   * @private
   */
  static buildAuditQuery(filters) {
    const query = {};

    if (filters.startDate || filters.endDate) {
      query.timestamp = {};
      if (filters.startDate) {
        query.timestamp.$gte = new Date(filters.startDate);
      }
      if (filters.endDate) {
        query.timestamp.$lte = new Date(filters.endDate);
      }
    }

    if (filters.eventType) {
      query['event.type'] = filters.eventType;
    }

    if (filters.eventCategory) {
      query['event.category'] = filters.eventCategory;
    }

    if (filters.severity) {
      query['event.severity'] = filters.severity;
    }

    if (filters.userId) {
      query['actor.userId'] = filters.userId;
    }

    if (filters.organizationId) {
      query['actor.organizationId'] = filters.organizationId;
    }

    if (filters.targetType && filters.targetId) {
      query['target.type'] = filters.targetType;
      query['target.id'] = filters.targetId;
    }

    if (filters.result) {
      query['event.result'] = filters.result;
    }

    if (!filters.includeSystemEvents) {
      query['actor.type'] = { $ne: 'system' };
    }

    if (filters.search) {
      query.$or = [
        { 'event.action': { $regex: filters.search, $options: 'i' } },
        { 'event.description': { $regex: filters.search, $options: 'i' } },
        { 'actor.email': { $regex: filters.search, $options: 'i' } }
      ];
    }

    return query;
  }

  /**
   * Check if accessing sensitive audit data
   * @param {Object} query - Audit query
   * @returns {boolean} Is sensitive
   * @private
   */
  static isAccessingSensitiveAuditData(query) {
    const sensitiveEventTypes = [
      'security_breach',
      'data_leak',
      'privilege_escalation',
      'emergency_access',
      'encryption_key_rotation'
    ];

    return query['event.type'] && sensitiveEventTypes.includes(query['event.type']);
  }

  /**
   * Decrypt audit logs for authorized users
   * @param {Array} logs - Audit logs
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Array>} Decrypted logs
   * @private
   */
  static async decryptAuditLogs(logs, adminUser) {
    const canDecrypt = await this.hasPermission(
      adminUser, 
      AdminPermissions.AUDIT.VIEW_ENCRYPTED
    );

    if (!canDecrypt) {
      return logs;
    }

    return Promise.all(logs.map(log => this.decryptSingleAuditLog(log, adminUser)));
  }

  /**
   * Decrypt single audit log
   * @param {Object} log - Audit log
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Decrypted log
   * @private
   */
  static async decryptSingleAuditLog(log, adminUser) {
    if (!log.security?.encryption?.enabled || !log.changes) {
      return log;
    }

    try {
      const decrypted = { ...log };

      if (log.changes.before) {
        decrypted.changes.before = await EncryptionService.decryptField(
          log.changes.before,
          'audit_changes'
        );
      }

      if (log.changes.after) {
        decrypted.changes.after = await EncryptionService.decryptField(
          log.changes.after,
          'audit_changes'
        );
      }

      return decrypted;
    } catch (error) {
      logger.error('Failed to decrypt audit log', {
        logId: log._id,
        error: error.message
      });
      return log;
    }
  }

  /**
   * Generate audit analytics
   * @param {Object} query - Audit query
   * @param {Object} options - Options
   * @returns {Promise<Object>} Analytics data
   * @private
   */
  static async generateAuditAnalytics(query, options) {
    const pipeline = [
      { $match: query },
      {
        $facet: {
          byCategory: [
            { $group: { _id: '$event.category', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
          ],
          bySeverity: [
            { $group: { _id: '$event.severity', count: { $sum: 1 } } }
          ],
          byResult: [
            { $group: { _id: '$event.result', count: { $sum: 1 } } }
          ],
          byHour: [
            {
              $group: {
                _id: { $hour: '$timestamp' },
                count: { $sum: 1 }
              }
            },
            { $sort: { _id: 1 } }
          ],
          topActors: [
            { $group: { _id: '$actor.userId', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 }
          ]
        }
      }
    ];

    const [analytics] = await AuditLog.aggregate(pipeline);

    return {
      distribution: {
        categories: analytics.byCategory,
        severities: analytics.bySeverity,
        results: analytics.byResult
      },
      patterns: {
        hourlyActivity: analytics.byHour,
        topActors: analytics.topActors
      },
      generated: new Date()
    };
  }

  /**
   * Additional helper methods would continue here...
   */
}

module.exports = AuditService;