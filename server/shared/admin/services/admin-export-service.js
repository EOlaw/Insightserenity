/**
 * @file Admin Export Service
 * @description Comprehensive data export service for administrative data with multiple formats and security controls
 * @version 1.0.0
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const XLSX = require('xlsx');
const PDFDocument = require('pdfkit');
const json2csv = require('json2csv');

const AdminBaseService = require('./admin-base-service');
const config = require('../../../shared/config/config');
const { AppError, ValidationError, AuthorizationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { FileService } = require('../../../shared/services/file-service');

// Import admin models
const AdminActionLog = require('../models/admin-action-log-model');
const AdminSession = require('../models/admin-session-model');
const AdminPreference = require('../models/admin-preference-model');
const AdminNotification = require('../models/admin-notification-model');

// Import shared models
const User = require('../../../shared/users/models/user-model');
const Organization = require('../../../hosted-organizations/organizations/models/organization-model');

/**
 * Admin Export Service Class
 * Handles data export operations for administrative data
 */
class AdminExportService extends AdminBaseService {
  constructor() {
    super('AdminExportService');
    
    this.exportConfig = {
      baseDirectory: config.export?.directory || './exports',
      maxFileSize: config.export?.maxFileSize || 100 * 1024 * 1024, // 100MB
      maxRecords: config.export?.maxRecords || 100000,
      retention: config.export?.retention || 7 * 24 * 60 * 60 * 1000, // 7 days
      compression: config.export?.compression || true,
      encryption: config.export?.encryption || true,
      formats: {
        CSV: 'csv',
        EXCEL: 'xlsx',
        JSON: 'json',
        PDF: 'pdf',
        XML: 'xml'
      }
    };
    
    this.exportTypes = {
      AUDIT_LOGS: 'audit_logs',
      USER_DATA: 'user_data',
      SESSIONS: 'sessions',
      NOTIFICATIONS: 'notifications',
      ANALYTICS: 'analytics',
      COMPLIANCE: 'compliance',
      SECURITY_REPORT: 'security_report',
      CONFIGURATION: 'configuration'
    };
    
    this.sensitiveFields = [
      'password', 'secret', 'token', 'key', 'credential', 'hash',
      'salt', 'iv', 'privateKey', 'accessToken', 'refreshToken'
    ];
    
    this.initializeExportService();
  }
  
  /**
   * Initialize export service
   * @private
   */
  async initializeExportService() {
    try {
      // Ensure export directory exists
      await this.ensureExportDirectory();
      
      // Initialize export templates
      this.initializeExportTemplates();
      
      // Set up cleanup scheduler
      this.setupCleanupScheduler();
      
      logger.info('Admin export service initialized', {
        baseDirectory: this.exportConfig.baseDirectory,
        supportedFormats: Object.values(this.exportConfig.formats)
      });
      
    } catch (error) {
      logger.error('Failed to initialize export service', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Export audit logs
   * @param {Object} context - Operation context
   * @param {Object} filters - Export filters
   * @param {Object} options - Export options
   * @returns {Promise<Object>} Export information
   */
  async exportAuditLogs(context, filters = {}, options = {}) {
    return this.executeOperation('export.audit_logs', async () => {
      const {
        startDate,
        endDate,
        categories = [],
        users = [],
        actions = [],
        riskLevels = []
      } = filters;
      
      const {
        format = this.exportConfig.formats.CSV,
        includeDetails = true,
        sanitizeSensitive = true,
        compression = true,
        encryption = false
      } = options;
      
      logger.info('Starting audit logs export', {
        filters,
        format,
        userId: context.userId
      });
      
      // Build query
      const query = this.buildAuditLogQuery(filters);
      
      // Validate export permissions
      await this.validateExportPermissions(context, this.exportTypes.AUDIT_LOGS, filters);
      
      // Check export limits
      const recordCount = await AdminActionLog.countDocuments(query);
      this.validateExportLimits(recordCount, format);
      
      // Generate export ID
      const exportId = this.generateExportId('audit_logs', format);
      const exportPath = await this.createExportDirectory(exportId);
      
      // Execute export
      const cursor = AdminActionLog.find(query)
        .populate('actor.userId', 'username email')
        .sort({ timestamp: -1 })
        .cursor();
      
      const exportData = [];
      const exportMetadata = {
        exportId,
        type: this.exportTypes.AUDIT_LOGS,
        format,
        filters,
        recordCount: 0,
        createdBy: context.userId,
        createdAt: new Date(),
        columns: this.getAuditLogColumns(includeDetails)
      };
      
      // Process records in batches
      for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
        const processedRecord = this.processAuditLogForExport(doc, {
          includeDetails,
          sanitizeSensitive
        });
        
        exportData.push(processedRecord);
        exportMetadata.recordCount++;
        
        // Process in batches to manage memory
        if (exportData.length >= 1000) {
          await this.writeExportBatch(exportPath, exportData, format, exportMetadata);
          exportData.length = 0; // Clear array
        }
      }
      
      // Write remaining records
      if (exportData.length > 0) {
        await this.writeExportBatch(exportPath, exportData, format, exportMetadata);
      }
      
      // Finalize export file
      const finalPath = await this.finalizeExport(exportPath, format, exportMetadata, {
        compression,
        encryption
      });
      
      // Log export action
      await this.logExportAction(context, exportMetadata, finalPath);
      
      logger.info('Audit logs export completed', {
        exportId,
        recordCount: exportMetadata.recordCount,
        format
      });
      
      return {
        exportId,
        type: this.exportTypes.AUDIT_LOGS,
        format,
        recordCount: exportMetadata.recordCount,
        filePath: finalPath,
        fileSize: await this.getFileSize(finalPath),
        createdAt: exportMetadata.createdAt,
        expiresAt: new Date(Date.now() + this.exportConfig.retention),
        downloadUrl: this.generateDownloadUrl(exportId)
      };
      
    }, context);
  }
  
  /**
   * Export user data
   * @param {Object} context - Operation context
   * @param {Object} filters - Export filters
   * @param {Object} options - Export options
   * @returns {Promise<Object>} Export information
   */
  async exportUserData(context, filters = {}, options = {}) {
    return this.executeOperation('export.user_data', async () => {
      const {
        organizationId,
        roles = [],
        status = [],
        includeInactive = false
      } = filters;
      
      const {
        format = this.exportConfig.formats.EXCEL,
        includePersonalData = false,
        includePreferences = false,
        includeSessions = false,
        sanitizeSensitive = true
      } = options;
      
      // Validate permissions for user data export
      await this.validateExportPermissions(context, this.exportTypes.USER_DATA, filters);
      
      // Build user query
      const query = this.buildUserQuery(filters);
      
      const recordCount = await User.countDocuments(query);
      this.validateExportLimits(recordCount, format);
      
      const exportId = this.generateExportId('user_data', format);
      const exportPath = await this.createExportDirectory(exportId);
      
      const exportMetadata = {
        exportId,
        type: this.exportTypes.USER_DATA,
        format,
        filters,
        options,
        recordCount: 0,
        createdBy: context.userId,
        createdAt: new Date(),
        sheets: [] // For multi-sheet exports
      };
      
      // Export user data
      const userData = await this.exportUsersData(query, options, exportMetadata);
      
      // Export additional data if requested
      if (includePreferences) {
        const preferencesData = await this.exportUserPreferences(userData.userIds, exportMetadata);
        exportMetadata.sheets.push({ name: 'User Preferences', recordCount: preferencesData.length });
      }
      
      if (includeSessions) {
        const sessionsData = await this.exportUserSessions(userData.userIds, exportMetadata);
        exportMetadata.sheets.push({ name: 'User Sessions', recordCount: sessionsData.length });
      }
      
      // Create export file based on format
      let finalPath;
      if (format === this.exportConfig.formats.EXCEL) {
        finalPath = await this.createExcelExport(exportPath, exportMetadata);
      } else {
        finalPath = await this.createSingleFormatExport(exportPath, userData.data, format, exportMetadata);
      }
      
      // Apply compression and encryption
      if (options.compression || options.encryption) {
        finalPath = await this.finalizeExport(finalPath, format, exportMetadata, options);
      }
      
      await this.logExportAction(context, exportMetadata, finalPath);
      
      return {
        exportId,
        type: this.exportTypes.USER_DATA,
        format,
        recordCount: exportMetadata.recordCount,
        filePath: finalPath,
        fileSize: await this.getFileSize(finalPath),
        createdAt: exportMetadata.createdAt,
        expiresAt: new Date(Date.now() + this.exportConfig.retention),
        downloadUrl: this.generateDownloadUrl(exportId)
      };
      
    }, context);
  }
  
  /**
   * Export compliance report
   * @param {Object} context - Operation context
   * @param {Object} parameters - Report parameters
   * @param {Object} options - Export options
   * @returns {Promise<Object>} Export information
   */
  async exportComplianceReport(context, parameters = {}, options = {}) {
    return this.executeOperation('export.compliance_report', async () => {
      const {
        reportType = 'audit_trail',
        timeRange,
        organizationId,
        includeUserActivity = true,
        includeSystemEvents = true,
        includeSecurityEvents = true
      } = parameters;
      
      const {
        format = this.exportConfig.formats.PDF,
        template = 'standard',
        includeCharts = true,
        includeMetadata = true
      } = options;
      
      // Validate compliance export permissions
      await this.validateExportPermissions(context, this.exportTypes.COMPLIANCE, parameters);
      
      const exportId = this.generateExportId('compliance', format);
      const exportPath = await this.createExportDirectory(exportId);
      
      logger.info('Generating compliance report', {
        exportId,
        reportType,
        timeRange,
        format
      });
      
      // Gather compliance data
      const complianceData = await this.gatherComplianceData(parameters);
      
      // Generate report based on format
      let reportPath;
      if (format === this.exportConfig.formats.PDF) {
        reportPath = await this.generatePDFComplianceReport(
          exportPath,
          complianceData,
          parameters,
          options
        );
      } else {
        reportPath = await this.generateStructuredComplianceReport(
          exportPath,
          complianceData,
          format,
          parameters
        );
      }
      
      const exportMetadata = {
        exportId,
        type: this.exportTypes.COMPLIANCE,
        reportType,
        format,
        parameters,
        createdBy: context.userId,
        createdAt: new Date(),
        recordCount: complianceData.totalRecords || 0
      };
      
      await this.logExportAction(context, exportMetadata, reportPath);
      
      return {
        exportId,
        type: this.exportTypes.COMPLIANCE,
        reportType,
        format,
        filePath: reportPath,
        fileSize: await this.getFileSize(reportPath),
        createdAt: exportMetadata.createdAt,
        expiresAt: new Date(Date.now() + this.exportConfig.retention),
        downloadUrl: this.generateDownloadUrl(exportId)
      };
      
    }, context);
  }
  
  /**
   * Export security analytics report
   * @param {Object} context - Operation context
   * @param {Object} parameters - Analytics parameters
   * @param {Object} options - Export options
   * @returns {Promise<Object>} Export information
   */
  async exportSecurityReport(context, parameters = {}, options = {}) {
    return this.executeOperation('export.security_report', async () => {
      const {
        timeRange,
        includeThreats = true,
        includeIncidents = true,
        includeAnomalies = true,
        riskLevelFilter = []
      } = parameters;
      
      const { format = this.exportConfig.formats.PDF } = options;
      
      await this.validateExportPermissions(context, this.exportTypes.SECURITY_REPORT, parameters);
      
      const exportId = this.generateExportId('security_report', format);
      const exportPath = await this.createExportDirectory(exportId);
      
      // Gather security analytics data
      const securityData = await this.gatherSecurityAnalytics(parameters);
      
      // Generate security report
      const reportPath = await this.generateSecurityReport(
        exportPath,
        securityData,
        format,
        parameters,
        options
      );
      
      const exportMetadata = {
        exportId,
        type: this.exportTypes.SECURITY_REPORT,
        format,
        parameters,
        createdBy: context.userId,
        createdAt: new Date(),
        findings: securityData.findings?.length || 0
      };
      
      await this.logExportAction(context, exportMetadata, reportPath);
      
      return {
        exportId,
        type: this.exportTypes.SECURITY_REPORT,
        format,
        filePath: reportPath,
        fileSize: await this.getFileSize(reportPath),
        createdAt: exportMetadata.createdAt,
        expiresAt: new Date(Date.now() + this.exportConfig.retention),
        downloadUrl: this.generateDownloadUrl(exportId)
      };
      
    }, context);
  }
  
  /**
   * Download exported file
   * @param {Object} context - Operation context
   * @param {string} exportId - Export ID
   * @returns {Promise<Object>} Download information
   */
  async downloadExport(context, exportId) {
    return this.executeOperation('export.download', async () => {
      // Validate export exists and user has access
      const exportInfo = await this.getExportInfo(exportId);
      
      if (!exportInfo) {
        throw new NotFoundError('Export', exportId);
      }
      
      // Check if export has expired
      if (new Date() > new Date(exportInfo.expiresAt)) {
        throw new AppError('Export has expired', 410);
      }
      
      // Validate download permissions
      await this.validateDownloadPermissions(context, exportInfo);
      
      // Check if file exists
      const fileExists = await this.fileExists(exportInfo.filePath);
      if (!fileExists) {
        throw new NotFoundError('Export file not found');
      }
      
      // Log download action
      await this.logDownloadAction(context, exportInfo);
      
      return {
        exportId,
        filePath: exportInfo.filePath,
        fileName: path.basename(exportInfo.filePath),
        fileSize: exportInfo.fileSize,
        mimeType: this.getMimeType(exportInfo.format),
        downloadUrl: this.generateTemporaryDownloadUrl(exportId)
      };
      
    }, context);
  }
  
  /**
   * List user exports
   * @param {Object} context - Operation context
   * @param {Object} filters - List filters
   * @returns {Promise<Object>} Export list
   */
  async listExports(context, filters = {}) {
    return this.executeOperation('export.list', async () => {
      const {
        type = null,
        format = null,
        startDate = null,
        endDate = null,
        includeExpired = false,
        limit = 50,
        offset = 0
      } = filters;
      
      // For non-admin users, only show their own exports
      const query = { createdBy: context.userId };
      
      if (type) query.type = type;
      if (format) query.format = format;
      if (startDate || endDate) {
        query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
      }
      
      if (!includeExpired) {
        query.expiresAt = { $gt: new Date() };
      }
      
      // Get exports from database or cache
      const exports = await this.getExportsFromStorage(query, { limit, offset });
      
      return {
        exports: exports.map(exp => this.sanitizeExportInfo(exp)),
        total: exports.length,
        offset,
        limit
      };
      
    }, context);
  }
  
  /**
   * Delete export
   * @param {Object} context - Operation context
   * @param {string} exportId - Export ID
   * @returns {Promise<Object>} Delete result
   */
  async deleteExport(context, exportId) {
    return this.executeOperation('export.delete', async () => {
      const exportInfo = await this.getExportInfo(exportId);
      
      if (!exportInfo) {
        throw new NotFoundError('Export', exportId);
      }
      
      // Validate delete permissions
      await this.validateDeletePermissions(context, exportInfo);
      
      // Delete export file
      if (await this.fileExists(exportInfo.filePath)) {
        await fs.unlink(exportInfo.filePath);
      }
      
      // Remove from storage
      await this.removeExportFromStorage(exportId);
      
      logger.info('Export deleted', { exportId, userId: context.userId });
      
      return {
        exportId,
        deleted: true,
        deletedAt: new Date()
      };
      
    }, context);
  }
  
  /**
   * Build audit log query from filters
   * @param {Object} filters - Export filters
   * @returns {Object} MongoDB query
   * @private
   */
  buildAuditLogQuery(filters) {
    const query = {};
    
    if (filters.startDate || filters.endDate) {
      query.timestamp = {};
      if (filters.startDate) query.timestamp.$gte = new Date(filters.startDate);
      if (filters.endDate) query.timestamp.$lte = new Date(filters.endDate);
    }
    
    if (filters.categories && filters.categories.length) {
      query.category = { $in: filters.categories };
    }
    
    if (filters.users && filters.users.length) {
      query['actor.userId'] = { $in: filters.users };
    }
    
    if (filters.actions && filters.actions.length) {
      query.action = { $in: filters.actions };
    }
    
    if (filters.riskLevels && filters.riskLevels.length) {
      query['security.riskLevel'] = { $in: filters.riskLevels };
    }
    
    return query;
  }
  
  /**
   * Process audit log record for export
   * @param {Object} record - Audit log record
   * @param {Object} options - Processing options
   * @returns {Object} Processed record
   * @private
   */
  processAuditLogForExport(record, options) {
    const processed = {
      timestamp: record.timestamp,
      action: record.action,
      category: record.category,
      actor: record.actor.username || record.actor.email,
      actorRole: record.actor.role,
      resourceType: record.target.resourceType,
      resourceId: record.target.resourceId,
      resourceName: record.target.resourceName,
      result: record.result.status,
      sourceIP: record.requestContext.sourceIP,
      userAgent: record.requestContext.userAgent,
      riskLevel: record.security.riskLevel
    };
    
    if (options.includeDetails) {
      processed.changeType = record.changes?.changeType;
      processed.fieldChanges = record.changes?.fieldChanges?.length || 0;
      processed.duration = record.result.duration;
      processed.errorMessage = record.result.message;
    }
    
    if (options.sanitizeSensitive) {
      processed = this.sanitizeSensitiveData(processed);
    }
    
    return processed;
  }
  
  /**
   * Generate export ID
   * @param {string} type - Export type
   * @param {string} format - Export format
   * @returns {string} Export ID
   * @private
   */
  generateExportId(type, format) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const randomId = crypto.randomBytes(8).toString('hex');
    return `${type}-${format}-${timestamp}-${randomId}`;
  }
  
  /**
   * Create export directory
   * @param {string} exportId - Export ID
   * @returns {Promise<string>} Export directory path
   * @private
   */
  async createExportDirectory(exportId) {
    const exportPath = path.join(this.exportConfig.baseDirectory, exportId);
    await fs.mkdir(exportPath, { recursive: true });
    return exportPath;
  }
  
  /**
   * Ensure export directory exists
   * @private
   */
  async ensureExportDirectory() {
    await fs.mkdir(this.exportConfig.baseDirectory, { recursive: true });
  }
  
  /**
   * Validate export permissions
   * @param {Object} context - Operation context
   * @param {string} exportType - Type of export
   * @param {Object} filters - Export filters
   * @throws {AuthorizationError} If user lacks permissions
   * @private
   */
  async validateExportPermissions(context, exportType, filters) {
    const { user } = context;
    
    // Define export permissions
    const exportPermissions = {
      [this.exportTypes.AUDIT_LOGS]: ['admin.audit.export', 'audit.export'],
      [this.exportTypes.USER_DATA]: ['admin.users.export', 'users.export'],
      [this.exportTypes.COMPLIANCE]: ['admin.compliance.export', 'compliance.export'],
      [this.exportTypes.SECURITY_REPORT]: ['admin.security.export', 'security.export']
    };
    
    const requiredPermissions = exportPermissions[exportType] || [];
    
    if (requiredPermissions.length === 0) {
      return; // No specific permissions required
    }
    
    const hasPermission = requiredPermissions.some(permission => 
      this.checkUserPermission(user, permission)
    );
    
    if (!hasPermission) {
      throw new AuthorizationError(`Insufficient permissions for ${exportType} export`);
    }
    
    // Additional organization-level checks
    if (filters.organizationId && user.role?.primary !== 'super_admin') {
      if (user.organization?.current?.toString() !== filters.organizationId) {
        throw new AuthorizationError('Cannot export data from other organizations');
      }
    }
  }
  
  /**
   * Validate export limits
   * @param {number} recordCount - Number of records to export
   * @param {string} format - Export format
   * @throws {ValidationError} If limits exceeded
   * @private
   */
  validateExportLimits(recordCount, format) {
    if (recordCount > this.exportConfig.maxRecords) {
      throw new ValidationError(
        `Export record count (${recordCount}) exceeds maximum allowed (${this.exportConfig.maxRecords})`
      );
    }
    
    // Format-specific limits
    const formatLimits = {
      [this.exportConfig.formats.EXCEL]: 1000000, // Excel row limit
      [this.exportConfig.formats.CSV]: this.exportConfig.maxRecords
    };
    
    const formatLimit = formatLimits[format];
    if (formatLimit && recordCount > formatLimit) {
      throw new ValidationError(
        `Export record count (${recordCount}) exceeds ${format} format limit (${formatLimit})`
      );
    }
  }
  
  /**
   * Sanitize sensitive data
   * @param {Object} data - Data to sanitize
   * @returns {Object} Sanitized data
   * @private
   */
  sanitizeSensitiveData(data) {
    const sanitized = { ...data };
    
    for (const field of this.sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }
    
    return sanitized;
  }
  
  /**
   * Get file size
   * @param {string} filePath - File path
   * @returns {Promise<number>} File size in bytes
   * @private
   */
  async getFileSize(filePath) {
    try {
      const stats = await fs.stat(filePath);
      return stats.size;
    } catch (error) {
      return 0;
    }
  }
  
  /**
   * Check if file exists
   * @param {string} filePath - File path
   * @returns {Promise<boolean>} File exists
   * @private
   */
  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
  
  /**
   * Get MIME type for format
   * @param {string} format - Export format
   * @returns {string} MIME type
   * @private
   */
  getMimeType(format) {
    const mimeTypes = {
      [this.exportConfig.formats.CSV]: 'text/csv',
      [this.exportConfig.formats.EXCEL]: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      [this.exportConfig.formats.JSON]: 'application/json',
      [this.exportConfig.formats.PDF]: 'application/pdf',
      [this.exportConfig.formats.XML]: 'application/xml'
    };
    
    return mimeTypes[format] || 'application/octet-stream';
  }
  
  /**
   * Generate download URL
   * @param {string} exportId - Export ID
   * @returns {string} Download URL
   * @private
   */
  generateDownloadUrl(exportId) {
    return `/api/admin/exports/${exportId}/download`;
  }
  
  /**
   * Log export action
   * @param {Object} context - Operation context
   * @param {Object} exportMetadata - Export metadata
   * @param {string} filePath - Export file path
   * @private
   */
  async logExportAction(context, exportMetadata, filePath) {
    try {
      await AdminActionLog.logAction({
        action: 'admin.export.create',
        category: 'export',
        actor: {
          userId: context.userId,
          username: context.user?.username,
          email: context.user?.email,
          role: context.user?.role?.primary
        },
        requestContext: context.requestContext,
        target: {
          resourceType: 'export',
          resourceId: exportMetadata.exportId,
          resourceName: `${exportMetadata.type} export`
        },
        changes: {
          changeType: 'create',
          fieldChanges: []
        },
        security: this.buildSecurityContext(context),
        result: {
          status: 'success',
          message: 'Export created successfully'
        },
        metadata: {
          exportType: exportMetadata.type,
          format: exportMetadata.format,
          recordCount: exportMetadata.recordCount,
          fileSize: await this.getFileSize(filePath)
        }
      });
    } catch (error) {
      logger.warn('Failed to log export action', {
        exportId: exportMetadata.exportId,
        error: error.message
      });
    }
  }
}

module.exports = AdminExportService;