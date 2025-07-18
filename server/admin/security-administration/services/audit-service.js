// server/admin/security-administration/services/audit-service.js
/**
 * @file Admin Audit Service
 * @description Comprehensive audit management service for administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const { parse } = require('csv-parse');
const { stringify } = require('csv-stringify');

// Core Models
const AuditLog = require('../../../shared/security/models/audit-log-model');
const AuditRetentionPolicy = require('../../../shared/security/models/audit-retention-policy-model');
const AuditAlert = require('../../../shared/security/models/audit-alert-model');
const AuditExport = require('../../../shared/security/models/audit-export-model');
const AuditArchive = require('../../../shared/security/models/audit-archive-model');
const ComplianceMapping = require('../../../shared/security/models/compliance-mapping-model');
const User = require('../../../shared/users/models/user-model');
const Organization = require('../../../shared/organizations/models/organization-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const ExportService = require('../../../shared/admin/services/admin-export-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const EncryptionService = require('../../../shared/security/services/encryption-service');
const StorageService = require('../../../shared/services/storage-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

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
   * Search audit logs with advanced filtering
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} searchParams - Search parameters
   * @returns {Promise<Object>} Search results
   */
  static async searchAuditLogs(adminUser, searchParams = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW);

      const {
        query = '',
        eventType,
        severity,
        userId,
        organizationId,
        dateFrom,
        dateTo,
        ipAddress,
        userAgent,
        category,
        riskScore,
        compliance,
        page = 1,
        limit = 50,
        sort = '-timestamp',
        includeRelated = false,
        decrypt = false
      } = searchParams;

      // Build search query
      const searchQuery = await this.buildAuditSearchQuery({
        query,
        eventType,
        severity,
        userId,
        organizationId,
        dateFrom,
        dateTo,
        ipAddress,
        userAgent,
        category,
        riskScore,
        compliance
      });

      // Check if admin can view sensitive logs
      if (decrypt) {
        await this.validatePermission(adminUser, AdminPermissions.AUDIT.DECRYPT);
      }

      // Execute search with pagination
      const skip = (page - 1) * limit;
      const [logs, total] = await Promise.all([
        AuditLog.find(searchQuery)
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .populate('userId', 'email profile.firstName profile.lastName')
          .populate('organizationId', 'name slug')
          .lean(),
        AuditLog.countDocuments(searchQuery)
      ]);

      // Decrypt sensitive data if requested and authorized
      let processedLogs = logs;
      if (decrypt) {
        processedLogs = await this.decryptAuditLogs(logs, adminUser);
      }

      // Include related events if requested
      if (includeRelated) {
        processedLogs = await this.includeRelatedEvents(processedLogs);
      }

      // Calculate statistics
      const statistics = await this.calculateAuditStatistics(searchQuery);

      // Log audit search
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOGS_SEARCHED, {
        searchParams: { ...searchParams, decrypt: undefined },
        resultsCount: total,
        decrypted: decrypt
      });

      return {
        logs: processedLogs,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit)
        },
        statistics,
        searchCriteria: searchParams
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
   * Get audit log details with full context
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} auditLogId - Audit log ID
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Audit log details
   */
  static async getAuditLogDetails(adminUser, auditLogId, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW);

      const { decrypt = false, includeContext = true } = options;

      // Get audit log
      const auditLog = await AuditLog.findById(auditLogId)
        .populate('userId', 'email profile.firstName profile.lastName role')
        .populate('organizationId', 'name slug plan')
        .populate('affectedUsers', 'email profile.firstName profile.lastName')
        .lean();

      if (!auditLog) {
        throw new NotFoundError('Audit log not found');
      }

      // Check if admin can view this log
      await this.validateAuditAccess(adminUser, auditLog);

      // Decrypt if requested and authorized
      let processedLog = auditLog;
      if (decrypt) {
        await this.validatePermission(adminUser, AdminPermissions.AUDIT.DECRYPT);
        processedLog = await this.decryptSingleAuditLog(auditLog, adminUser);
      }

      // Include additional context if requested
      if (includeContext) {
        processedLog.context = await this.getAuditContext(auditLog);
        processedLog.relatedEvents = await this.getRelatedAuditEvents(auditLog);
        processedLog.complianceMappings = await this.getComplianceMappings(auditLog);
      }

      // Log access to sensitive audit log
      if (auditLog.severity === 'critical' || decrypt) {
        await this.auditLog(adminUser, AdminEvents.AUDIT.SENSITIVE_LOG_ACCESSED, {
          auditLogId,
          severity: auditLog.severity,
          decrypted: decrypt
        }, { critical: true });
      }

      return {
        auditLog: processedLog,
        access: {
          canDecrypt: await this.hasPermission(adminUser, AdminPermissions.AUDIT.DECRYPT),
          canExport: await this.hasPermission(adminUser, AdminPermissions.AUDIT.EXPORT),
          canManage: await this.hasPermission(adminUser, AdminPermissions.AUDIT.MANAGE)
        }
      };

    } catch (error) {
      logger.error('Get audit log details error', {
        error: error.message,
        adminId: adminUser.id,
        auditLogId,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Configure audit retention policies
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} policyData - Retention policy data
   * @returns {Promise<Object>} Configuration result
   */
  static async configureRetentionPolicies(adminUser, policyData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.CONFIGURE);

      const {
        standard,
        retentionDays,
        applyToExisting = false,
        excludePatterns = [],
        includePatterns = [],
        compressAfterDays,
        archiveAfterDays,
        deleteAfterDays
      } = policyData;

      // Validate retention against compliance requirements
      const complianceValid = await this.validateRetentionCompliance(retentionDays, standard);
      if (!complianceValid) {
        throw new ValidationError(`Retention period does not meet ${standard} compliance requirements`);
      }

      // Check for existing policy
      let policy = await AuditRetentionPolicy.findOne({ standard }).session(session);

      if (policy) {
        // Update existing policy
        policy.retentionDays = retentionDays;
        policy.excludePatterns = excludePatterns;
        policy.includePatterns = includePatterns;
        policy.compressAfterDays = compressAfterDays;
        policy.archiveAfterDays = archiveAfterDays;
        policy.deleteAfterDays = deleteAfterDays;
        policy.updatedBy = adminUser.id;
        policy.updatedAt = new Date();
        await policy.save({ session });
      } else {
        // Create new policy
        policy = await AuditRetentionPolicy.create([{
          standard,
          retentionDays,
          excludePatterns,
          includePatterns,
          compressAfterDays,
          archiveAfterDays,
          deleteAfterDays,
          createdBy: adminUser.id,
          active: true
        }], { session });
        policy = policy[0];
      }

      // Apply to existing logs if requested
      let appliedResult = null;
      if (applyToExisting) {
        appliedResult = await this.applyRetentionPolicy(policy, session);
      }

      // Clear retention cache
      await CacheService.delete(`${this.cachePrefix}:retention-policies`);

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.RETENTION_CONFIGURED, {
        standard,
        retentionDays,
        applyToExisting,
        appliedCount: appliedResult?.affected || 0
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        policy,
        applied: appliedResult,
        message: 'Retention policy configured successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Configure retention policies error', {
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
        query = {},
        dateFrom,
        dateTo,
        includeDecrypted = false,
        compress = true,
        encryption = true,
        password,
        notificationEmail
      } = exportOptions;

      // Validate export format
      const validFormats = ['csv', 'json', 'pdf', 'excel'];
      if (!validFormats.includes(format)) {
        throw new ValidationError('Invalid export format');
      }

      // Build export query
      const exportQuery = await this.buildAuditSearchQuery({
        ...query,
        dateFrom,
        dateTo
      });

      // Check export size
      const count = await AuditLog.countDocuments(exportQuery);
      if (count > AdminLimits.AUDIT.MAX_EXPORT_RECORDS) {
        throw new ValidationError(`Export exceeds maximum record limit of ${AdminLimits.AUDIT.MAX_EXPORT_RECORDS}`);
      }

      // Create export job
      const exportJob = await AuditExport.create({
        exportedBy: adminUser.id,
        format,
        query: exportQuery,
        recordCount: count,
        options: {
          includeDecrypted,
          compress,
          encryption,
          hasPassword: !!password
        },
        status: 'pending'
      });

      // Process export asynchronously
      this.processAuditExport(exportJob, exportQuery, adminUser, {
        format,
        includeDecrypted,
        compress,
        encryption,
        password,
        notificationEmail: notificationEmail || adminUser.email
      }).catch(error => {
        logger.error('Audit export processing error', {
          error: error.message,
          exportId: exportJob._id,
          adminId: adminUser.id
        });
      });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOGS_EXPORTED, {
        exportId: exportJob._id,
        format,
        recordCount: count,
        encrypted: encryption
      }, { critical: includeDecrypted });

      return {
        exportId: exportJob._id,
        status: 'processing',
        estimatedRecords: count,
        message: 'Export job created. You will be notified when complete.'
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
   * @param {Object} alertData - Alert configuration data
   * @returns {Promise<Object>} Alert configuration result
   */
  static async configureAuditAlerts(adminUser, alertData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.CONFIGURE);

      const {
        name,
        description,
        conditions,
        actions,
        severity = 'medium',
        enabled = true,
        cooldownMinutes = 60,
        maxAlertsPerHour = 10
      } = alertData;

      // Validate alert conditions
      const validConditions = await this.validateAlertConditions(conditions);
      if (!validConditions) {
        throw new ValidationError('Invalid alert conditions');
      }

      // Create alert configuration
      const alert = await AuditAlert.create([{
        name,
        description,
        conditions,
        actions,
        severity,
        enabled,
        cooldownMinutes,
        maxAlertsPerHour,
        createdBy: adminUser.id,
        statistics: {
          triggered: 0,
          lastTriggered: null,
          falsePositives: 0
        }
      }], { session });

      // Test alert if requested
      if (alertData.test) {
        await this.testAuditAlert(alert[0], session);
      }

      // Clear alerts cache
      await CacheService.delete(`${this.cachePrefix}:alerts`);

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
        alertData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
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
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.MANAGE);

      const {
        dateFrom,
        dateTo,
        compress = true,
        encrypt = true,
        deleteOriginal = false,
        archiveLocation = 'default'
      } = archiveOptions;

      if (!dateFrom || !dateTo) {
        throw new ValidationError('Date range is required for archiving');
      }

      // Validate critical operation
      if (deleteOriginal) {
        await this.validateCriticalOperation(adminUser, 'audit.archive.delete', {
          dateFrom,
          dateTo
        });
      }

      // Find logs to archive
      const archiveQuery = {
        timestamp: {
          $gte: new Date(dateFrom),
          $lte: new Date(dateTo)
        },
        archived: false
      };

      const logsToArchive = await AuditLog.find(archiveQuery)
        .select('_id timestamp eventType severity')
        .session(session)
        .lean();

      if (logsToArchive.length === 0) {
        throw new ValidationError('No logs found in the specified date range');
      }

      // Create archive record
      const archive = await AuditArchive.create([{
        dateRange: { from: dateFrom, to: dateTo },
        recordCount: logsToArchive.length,
        compressed: compress,
        encrypted: encrypt,
        location: archiveLocation,
        archivedBy: adminUser.id,
        status: 'processing'
      }], { session });

      // Process archive in batches
      const batchSize = 1000;
      let processed = 0;
      const archiveResults = {
        processed: 0,
        failed: 0,
        errors: []
      };

      for (let i = 0; i < logsToArchive.length; i += batchSize) {
        const batch = logsToArchive.slice(i, i + batchSize);
        
        try {
          const result = await this.archiveBatch(batch, {
            archiveId: archive[0]._id,
            compress,
            encrypt,
            session
          });

          // Mark as archived
          await AuditLog.updateMany(
            { _id: { $in: batch.map(log => log._id) } },
            {
              $set: {
                archived: true,
                archiveId: archive[0]._id,
                archivedAt: new Date()
              }
            },
            { session }
          );

          processed += result.count;
          archiveResults.processed += result.count;

          // Delete original if requested
          if (deleteOriginal) {
            await AuditLog.deleteMany(
              { _id: { $in: batch.map(log => log._id) } },
              { session }
            );
          }

        } catch (error) {
          archiveResults.failed += batch.length;
          archiveResults.errors.push({
            batch: i / batchSize,
            error: error.message
          });
        }
      }

      // Update archive status
      archive[0].status = archiveResults.failed === 0 ? 'completed' : 'partial';
      archive[0].completedAt = new Date();
      archive[0].results = archiveResults;
      await archive[0].save({ session });

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.LOGS_ARCHIVED, {
        archiveId: archive[0]._id,
        dateRange: { from: dateFrom, to: dateTo },
        recordCount: logsToArchive.length,
        deletedOriginal: deleteOriginal,
        results: archiveResults
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        archiveId: archive[0]._id,
        archived: archiveResults.processed,
        failed: archiveResults.failed,
        message: `Successfully archived ${archiveResults.processed} audit logs`
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

  /**
   * Get audit statistics and analytics
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Statistics options
   * @returns {Promise<Object>} Audit statistics
   */
  static async getAuditStatistics(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW);

      const {
        timeRange = '30d',
        groupBy = 'day',
        includeCompliance = true,
        includeRiskAnalysis = true
      } = options;

      const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));
      const endDate = new Date();

      // Get cached statistics if available
      const cacheKey = `${this.cachePrefix}:statistics:${timeRange}:${groupBy}`;
      const cached = await CacheService.get(cacheKey);
      if (cached) return cached;

      // Gather statistics in parallel
      const [
        eventStats,
        severityStats,
        userStats,
        organizationStats,
        complianceStats,
        riskStats,
        trends
      ] = await Promise.all([
        this.getEventTypeStatistics(startDate, endDate, groupBy),
        this.getSeverityStatistics(startDate, endDate),
        this.getUserActivityStatistics(startDate, endDate),
        this.getOrganizationStatistics(startDate, endDate),
        includeCompliance ? this.getComplianceStatistics(startDate, endDate) : null,
        includeRiskAnalysis ? this.getRiskAnalysisStatistics(startDate, endDate) : null,
        this.getAuditTrends(startDate, endDate, groupBy)
      ]);

      const statistics = {
        timeRange: {
          start: startDate,
          end: endDate,
          groupBy
        },
        summary: {
          totalEvents: await AuditLog.countDocuments({
            timestamp: { $gte: startDate, $lte: endDate }
          }),
          uniqueUsers: userStats.unique,
          criticalEvents: severityStats.critical || 0,
          complianceScore: complianceStats?.overallScore || null
        },
        events: eventStats,
        severity: severityStats,
        users: userStats,
        organizations: organizationStats,
        compliance: complianceStats,
        risk: riskStats,
        trends
      };

      // Cache statistics
      await CacheService.set(cacheKey, statistics, 300); // 5 minutes

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.STATISTICS_VIEWED, {
        timeRange,
        groupBy
      });

      return statistics;

    } catch (error) {
      logger.error('Get audit statistics error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Manage compliance mappings
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} mappingData - Compliance mapping data
   * @returns {Promise<Object>} Mapping result
   */
  static async manageComplianceMappings(adminUser, mappingData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.CONFIGURE);

      const {
        action,
        standard,
        eventTypes,
        requirements,
        controls,
        description
      } = mappingData;

      let result;

      switch (action) {
        case 'create':
          result = await ComplianceMapping.create([{
            standard,
            eventTypes,
            requirements,
            controls,
            description,
            createdBy: adminUser.id,
            active: true
          }], { session });
          result = result[0];
          break;

        case 'update':
          result = await ComplianceMapping.findOneAndUpdate(
            { standard, active: true },
            {
              $set: {
                eventTypes,
                requirements,
                controls,
                description,
                updatedBy: adminUser.id,
                updatedAt: new Date()
              }
            },
            { new: true, session }
          );
          break;

        case 'delete':
          result = await ComplianceMapping.findOneAndUpdate(
            { standard, active: true },
            {
              $set: {
                active: false,
                deletedBy: adminUser.id,
                deletedAt: new Date()
              }
            },
            { session }
          );
          break;

        case 'list':
          result = await ComplianceMapping.find({ active: true })
            .populate('createdBy', 'email profile.firstName profile.lastName')
            .lean();
          break;
      }

      // Clear compliance cache
      await CacheService.delete(`${this.cachePrefix}:compliance-mappings`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.COMPLIANCE_MAPPING_MANAGED, {
        action,
        standard,
        eventTypesCount: eventTypes?.length
      }, { session });

      await session.commitTransaction();

      return {
        action,
        result,
        message: `Compliance mapping ${action}d successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage compliance mappings error', {
        error: error.message,
        adminId: adminUser.id,
        mappingData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Generate compliance report
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} reportOptions - Report options
   * @returns {Promise<Object>} Compliance report
   */
  static async generateComplianceReport(adminUser, reportOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW_REPORTS);

      const {
        standard,
        dateFrom,
        dateTo,
        scope = 'organization',
        format = 'detailed',
        includeEvidence = true
      } = reportOptions;

      if (!standard) {
        throw new ValidationError('Compliance standard is required');
      }

      const dateRange = {
        start: dateFrom ? new Date(dateFrom) : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
        end: dateTo ? new Date(dateTo) : new Date()
      };

      // Get compliance mappings
      const mappings = await ComplianceMapping.findOne({
        standard,
        active: true
      }).lean();

      if (!mappings) {
        throw new NotFoundError(`No compliance mappings found for ${standard}`);
      }

      // Collect compliance data
      const complianceData = await this.collectComplianceData(
        standard,
        mappings,
        dateRange,
        scope
      );

      // Generate evidence if requested
      let evidence = null;
      if (includeEvidence) {
        evidence = await this.collectComplianceEvidence(
          complianceData.controls,
          dateRange
        );
      }

      // Create report
      const report = {
        id: crypto.randomUUID(),
        standard,
        generatedAt: new Date(),
        generatedBy: adminUser.id,
        dateRange,
        scope,
        summary: {
          overallCompliance: complianceData.overallScore,
          compliantControls: complianceData.compliant,
          nonCompliantControls: complianceData.nonCompliant,
          gaps: complianceData.gaps
        },
        controls: complianceData.controls,
        findings: complianceData.findings,
        recommendations: complianceData.recommendations,
        evidence: evidence
      };

      // Format report based on requested format
      const formattedReport = this.formatComplianceReport(report, format);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.AUDIT.COMPLIANCE_REPORT_GENERATED, {
        standard,
        dateRange,
        scope,
        complianceScore: complianceData.overallScore
      });

      return formattedReport;

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

  // ========== Private Helper Methods ==========

  /**
   * Build audit search query
   * @param {Object} params - Search parameters
   * @returns {Object} MongoDB query
   * @private
   */
  static async buildAuditSearchQuery(params) {
    const query = {};

    if (params.query) {
      query.$or = [
        { eventType: { $regex: params.query, $options: 'i' } },
        { 'details.description': { $regex: params.query, $options: 'i' } },
        { 'metadata.userAgent': { $regex: params.query, $options: 'i' } }
      ];
    }

    if (params.eventType) {
      query.eventType = Array.isArray(params.eventType) 
        ? { $in: params.eventType }
        : params.eventType;
    }

    if (params.severity) {
      query.severity = params.severity;
    }

    if (params.userId) {
      query.userId = params.userId;
    }

    if (params.organizationId) {
      query.organizationId = params.organizationId;
    }

    if (params.dateFrom || params.dateTo) {
      query.timestamp = {};
      if (params.dateFrom) query.timestamp.$gte = new Date(params.dateFrom);
      if (params.dateTo) query.timestamp.$lte = new Date(params.dateTo);
    }

    if (params.ipAddress) {
      query['metadata.ipAddress'] = params.ipAddress;
    }

    if (params.userAgent) {
      query['metadata.userAgent'] = { $regex: params.userAgent, $options: 'i' };
    }

    if (params.category) {
      query.category = params.category;
    }

    if (params.riskScore) {
      query.riskScore = { $gte: params.riskScore };
    }

    if (params.compliance) {
      query['compliance.standards'] = params.compliance;
    }

    return query;
  }

  /**
   * Calculate audit statistics
   * @param {Object} query - MongoDB query
   * @returns {Promise<Object>} Statistics
   * @private
   */
  static async calculateAuditStatistics(query) {
    const [
      severityStats,
      categoryStats,
      topEvents
    ] = await Promise.all([
      AuditLog.aggregate([
        { $match: query },
        { $group: { _id: '$severity', count: { $sum: 1 } } }
      ]),
      AuditLog.aggregate([
        { $match: query },
        { $group: { _id: '$category', count: { $sum: 1 } } }
      ]),
      AuditLog.aggregate([
        { $match: query },
        { $group: { _id: '$eventType', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ])
    ]);

    return {
      severity: severityStats.reduce((acc, stat) => {
        acc[stat._id] = stat.count;
        return acc;
      }, {}),
      categories: categoryStats.reduce((acc, stat) => {
        acc[stat._id] = stat.count;
        return acc;
      }, {}),
      topEvents: topEvents.map(event => ({
        eventType: event._id,
        count: event.count
      }))
    };
  }

  /**
   * Decrypt audit logs
   * @param {Array} logs - Audit logs
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Array>} Decrypted logs
   * @private
   */
  static async decryptAuditLogs(logs, adminUser) {
    const decrypted = [];

    for (const log of logs) {
      try {
        const decryptedLog = { ...log };
        
        if (log.details?.encrypted) {
          decryptedLog.details = await EncryptionService.decrypt(
            log.details.data,
            'audit'
          );
        }

        if (log.sensitiveData?.encrypted) {
          decryptedLog.sensitiveData = await EncryptionService.decrypt(
            log.sensitiveData.data,
            'audit'
          );
        }

        decrypted.push(decryptedLog);
      } catch (error) {
        logger.error('Failed to decrypt audit log', {
          logId: log._id,
          error: error.message
        });
        decrypted.push(log);
      }
    }

    return decrypted;
  }

  /**
   * Include related audit events
   * @param {Array} logs - Audit logs
   * @returns {Promise<Array>} Logs with related events
   * @private
   */
  static async includeRelatedEvents(logs) {
    const enhanced = [];

    for (const log of logs) {
      const relatedEvents = await AuditLog.find({
        $or: [
          { sessionId: log.sessionId },
          { 'metadata.correlationId': log.metadata?.correlationId }
        ],
        _id: { $ne: log._id }
      })
        .select('eventType timestamp severity')
        .limit(5)
        .lean();

      enhanced.push({
        ...log,
        relatedEvents
      });
    }

    return enhanced;
  }

  /**
   * Get audit context
   * @param {Object} auditLog - Audit log
   * @returns {Promise<Object>} Context data
   * @private
   */
  static async getAuditContext(auditLog) {
    const context = {
      session: null,
      previousEvents: [],
      affectedResources: []
    };

    // Get session context
    if (auditLog.sessionId) {
      const sessionEvents = await AuditLog.find({
        sessionId: auditLog.sessionId,
        timestamp: { $lt: auditLog.timestamp }
      })
        .select('eventType timestamp')
        .sort({ timestamp: -1 })
        .limit(10)
        .lean();

      context.session = {
        id: auditLog.sessionId,
        events: sessionEvents
      };
    }

    // Get previous events by same user
    context.previousEvents = await AuditLog.find({
      userId: auditLog.userId,
      timestamp: { 
        $gte: new Date(auditLog.timestamp - 24 * 60 * 60 * 1000),
        $lt: auditLog.timestamp
      }
    })
      .select('eventType timestamp severity')
      .sort({ timestamp: -1 })
      .limit(20)
      .lean();

    return context;
  }

  /**
   * Validate audit access
   * @param {Object} adminUser - Admin user
   * @param {Object} auditLog - Audit log
   * @private
   */
  static async validateAuditAccess(adminUser, auditLog) {
    // Super admins can access all logs
    if (adminUser.role === 'super_admin') {
      return true;
    }

    // Check organization access
    if (auditLog.organizationId && adminUser.organizationId) {
      if (auditLog.organizationId.toString() !== adminUser.organizationId.toString()) {
        throw new ForbiddenError('Access denied to audit log from different organization');
      }
    }

    // Check severity-based access
    if (auditLog.severity === 'critical') {
      await this.validatePermission(adminUser, AdminPermissions.AUDIT.VIEW_CRITICAL);
    }

    return true;
  }

  /**
   * Get event type statistics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {string} groupBy - Grouping period
   * @returns {Promise<Array>} Event statistics
   * @private
   */
  static async getEventTypeStatistics(startDate, endDate, groupBy) {
    const groupStage = this.getDateGroupStage(groupBy);

    return AuditLog.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: {
            date: groupStage,
            eventType: '$eventType'
          },
          count: { $sum: 1 }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          events: {
            $push: {
              eventType: '$_id.eventType',
              count: '$count'
            }
          },
          total: { $sum: '$count' }
        }
      },
      { $sort: { _id: 1 } }
    ]);
  }

  /**
   * Get severity statistics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Object>} Severity statistics
   * @private
   */
  static async getSeverityStatistics(startDate, endDate) {
    const stats = await AuditLog.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: '$severity',
          count: { $sum: 1 },
          avgRiskScore: { $avg: '$riskScore' }
        }
      }
    ]);

    return stats.reduce((acc, stat) => {
      acc[stat._id] = {
        count: stat.count,
        avgRiskScore: Math.round(stat.avgRiskScore || 0)
      };
      return acc;
    }, {});
  }

  /**
   * Get user activity statistics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Object>} User statistics
   * @private
   */
  static async getUserActivityStatistics(startDate, endDate) {
    const [
      uniqueUsers,
      topUsers,
      usersByRole
    ] = await Promise.all([
      AuditLog.distinct('userId', {
        timestamp: { $gte: startDate, $lte: endDate }
      }),
      AuditLog.aggregate([
        {
          $match: {
            timestamp: { $gte: startDate, $lte: endDate }
          }
        },
        {
          $group: {
            _id: '$userId',
            count: { $sum: 1 },
            criticalEvents: {
              $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
            }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 },
        {
          $lookup: {
            from: 'users',
            localField: '_id',
            foreignField: '_id',
            as: 'user'
          }
        },
        { $unwind: '$user' },
        {
          $project: {
            userId: '$_id',
            count: 1,
            criticalEvents: 1,
            email: '$user.email',
            name: { $concat: ['$user.profile.firstName', ' ', '$user.profile.lastName'] }
          }
        }
      ]),
      User.aggregate([
        {
          $match: {
            _id: { $in: uniqueUsers }
          }
        },
        {
          $group: {
            _id: '$role',
            count: { $sum: 1 }
          }
        }
      ])
    ]);

    return {
      unique: uniqueUsers.length,
      topUsers,
      byRole: usersByRole.reduce((acc, role) => {
        acc[role._id] = role.count;
        return acc;
      }, {})
    };
  }

  /**
   * Get organization statistics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Object>} Organization statistics
   * @private
   */
  static async getOrganizationStatistics(startDate, endDate) {
    const orgStats = await AuditLog.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate },
          organizationId: { $exists: true }
        }
      },
      {
        $group: {
          _id: '$organizationId',
          count: { $sum: 1 },
          criticalEvents: {
            $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
          },
          avgRiskScore: { $avg: '$riskScore' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 20 },
      {
        $lookup: {
          from: 'organizations',
          localField: '_id',
          foreignField: '_id',
          as: 'organization'
        }
      },
      { $unwind: '$organization' },
      {
        $project: {
          organizationId: '$_id',
          name: '$organization.name',
          plan: '$organization.subscription.plan',
          count: 1,
          criticalEvents: 1,
          avgRiskScore: { $round: ['$avgRiskScore', 0] }
        }
      }
    ]);

    return {
      total: orgStats.length,
      organizations: orgStats
    };
  }

  /**
   * Get compliance statistics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Object>} Compliance statistics
   * @private
   */
  static async getComplianceStatistics(startDate, endDate) {
    const mappings = await ComplianceMapping.find({ active: true }).lean();
    const statistics = {
      overallScore: 0,
      byStandard: {}
    };

    for (const mapping of mappings) {
      const compliantEvents = await AuditLog.countDocuments({
        timestamp: { $gte: startDate, $lte: endDate },
        eventType: { $in: mapping.eventTypes },
        'compliance.compliant': true
      });

      const totalEvents = await AuditLog.countDocuments({
        timestamp: { $gte: startDate, $lte: endDate },
        eventType: { $in: mapping.eventTypes }
      });

      const score = totalEvents > 0 ? Math.round((compliantEvents / totalEvents) * 100) : 100;
      
      statistics.byStandard[mapping.standard] = {
        score,
        compliantEvents,
        totalEvents,
        requirements: mapping.requirements.length,
        controls: mapping.controls.length
      };
    }

    // Calculate overall score
    const scores = Object.values(statistics.byStandard).map(s => s.score);
    statistics.overallScore = scores.length > 0 
      ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
      : 0;

    return statistics;
  }

  /**
   * Get risk analysis statistics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @returns {Promise<Object>} Risk statistics
   * @private
   */
  static async getRiskAnalysisStatistics(startDate, endDate) {
    const riskStats = await AuditLog.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate },
          riskScore: { $exists: true }
        }
      },
      {
        $group: {
          _id: null,
          avgRiskScore: { $avg: '$riskScore' },
          maxRiskScore: { $max: '$riskScore' },
          highRiskEvents: {
            $sum: { $cond: [{ $gte: ['$riskScore', 70] }, 1, 0] }
          },
          criticalRiskEvents: {
            $sum: { $cond: [{ $gte: ['$riskScore', 90] }, 1, 0] }
          }
        }
      }
    ]);

    const topRiskEvents = await AuditLog.find({
      timestamp: { $gte: startDate, $lte: endDate },
      riskScore: { $gte: 70 }
    })
      .sort({ riskScore: -1 })
      .limit(10)
      .select('eventType riskScore timestamp userId')
      .populate('userId', 'email')
      .lean();

    return {
      summary: riskStats[0] || {
        avgRiskScore: 0,
        maxRiskScore: 0,
        highRiskEvents: 0,
        criticalRiskEvents: 0
      },
      topRiskEvents
    };
  }

  /**
   * Get audit trends
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {string} groupBy - Grouping period
   * @returns {Promise<Object>} Trend data
   * @private
   */
  static async getAuditTrends(startDate, endDate, groupBy) {
    const groupStage = this.getDateGroupStage(groupBy);

    const trends = await AuditLog.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: groupStage,
          count: { $sum: 1 },
          avgRiskScore: { $avg: '$riskScore' },
          criticalCount: {
            $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] }
          }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    // Calculate trend direction
    const trendDirection = this.calculateTrendDirection(trends);

    return {
      data: trends,
      direction: trendDirection,
      groupBy
    };
  }

  /**
   * Get date grouping stage for aggregation
   * @param {string} groupBy - Grouping period
   * @returns {Object} MongoDB aggregation stage
   * @private
   */
  static getDateGroupStage(groupBy) {
    switch (groupBy) {
      case 'hour':
        return {
          $dateToString: {
            format: '%Y-%m-%d %H:00',
            date: '$timestamp'
          }
        };
      case 'day':
        return {
          $dateToString: {
            format: '%Y-%m-%d',
            date: '$timestamp'
          }
        };
      case 'week':
        return {
          $dateToString: {
            format: '%Y-W%V',
            date: '$timestamp'
          }
        };
      case 'month':
        return {
          $dateToString: {
            format: '%Y-%m',
            date: '$timestamp'
          }
        };
      default:
        return {
          $dateToString: {
            format: '%Y-%m-%d',
            date: '$timestamp'
          }
        };
    }
  }

  /**
   * Calculate trend direction
   * @param {Array} trends - Trend data
   * @returns {string} Trend direction
   * @private
   */
  static calculateTrendDirection(trends) {
    if (trends.length < 2) return 'stable';

    const firstHalf = trends.slice(0, Math.floor(trends.length / 2));
    const secondHalf = trends.slice(Math.floor(trends.length / 2));

    const firstAvg = firstHalf.reduce((sum, t) => sum + t.count, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((sum, t) => sum + t.count, 0) / secondHalf.length;

    const change = ((secondAvg - firstAvg) / firstAvg) * 100;

    if (change > 10) return 'increasing';
    if (change < -10) return 'decreasing';
    return 'stable';
  }

  /**
   * Format compliance report
   * @param {Object} report - Raw report data
   * @param {string} format - Output format
   * @returns {Object} Formatted report
   * @private
   */
  static formatComplianceReport(report, format) {
    switch (format) {
      case 'summary':
        return {
          id: report.id,
          standard: report.standard,
          generatedAt: report.generatedAt,
          summary: report.summary
        };

      case 'executive':
        return {
          ...report,
          evidence: undefined,
          controls: report.controls.map(c => ({
            id: c.id,
            name: c.name,
            status: c.status,
            score: c.score
          }))
        };

      case 'detailed':
      default:
        return report;
    }
  }

  /**
   * Parse time range string
   * @param {string} timeRange - Time range string
   * @returns {number} Time in milliseconds
   * @private
   */
  static parseTimeRange(timeRange) {
    const unit = timeRange.slice(-1);
    const value = parseInt(timeRange.slice(0, -1));

    const multipliers = {
      'h': 60 * 60 * 1000,
      'd': 24 * 60 * 60 * 1000,
      'w': 7 * 24 * 60 * 60 * 1000,
      'm': 30 * 24 * 60 * 60 * 1000
    };

    return value * (multipliers[unit] || multipliers['d']);
  }
}

// Inherit from AdminBaseService
Object.setPrototypeOf(AuditService, AdminBaseService);
Object.setPrototypeOf(AuditService.prototype, AdminBaseService.prototype);

module.exports = AuditService;