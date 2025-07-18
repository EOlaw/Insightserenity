// server/admin/security-administration/controllers/audit-controller.js
/**
 * @file Admin Audit Controller
 * @description Handles HTTP requests for audit management operations
 * @version 1.0.0
 */

const AuditService = require('../services/audit-service');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const asyncHandler = require('../../../shared/middleware/async-handler');
const responseFormatter = require('../../../shared/utils/response-formatter');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');

/**
 * Admin Audit Controller Class
 * @class AuditController
 */
class AuditController {
  /**
   * Search audit logs
   * @route GET /api/admin/audit/logs
   * @access Admin - Audit View
   */
  static searchAuditLogs = asyncHandler(async (req, res) => {
    const {
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
      compliance,
      page = 1,
      limit = 50,
      sort = '-timestamp',
      includeRelated,
      decrypt
    } = req.query;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.logs.searched', {
      hasQuery: !!query,
      filters: {
        eventType: !!eventType,
        severity: !!severity,
        userId: !!userId,
        dateRange: !!(dateFrom || dateTo)
      },
      decrypt: decrypt === 'true'
    });

    const searchParams = {
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
      riskScore: riskScore ? parseInt(riskScore) : undefined,
      compliance,
      page: parseInt(page),
      limit: parseInt(limit),
      sort,
      includeRelated: includeRelated === 'true',
      decrypt: decrypt === 'true'
    };

    const result = await AuditService.searchAuditLogs(req.adminUser, searchParams);

    res.status(200).json(
      responseFormatter.success(result, 'Audit logs retrieved successfully')
    );
  });

  /**
   * Get audit log details
   * @route GET /api/admin/audit/logs/:auditLogId
   * @access Admin - Audit View
   */
  static getAuditLogDetails = asyncHandler(async (req, res) => {
    const { auditLogId } = req.params;
    const { decrypt, includeContext } = req.query;

    if (!auditLogId) {
      throw new ValidationError('Audit log ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.log.viewed', {
      auditLogId,
      decrypt: decrypt === 'true'
    });

    const result = await AuditService.getAuditLogDetails(req.adminUser, auditLogId, {
      decrypt: decrypt === 'true',
      includeContext: includeContext !== 'false'
    });

    res.status(200).json(
      responseFormatter.success(result, 'Audit log details retrieved successfully')
    );
  });

  /**
   * Configure retention policies
   * @route POST /api/admin/audit/retention
   * @access Admin - Audit Configure
   */
  static configureRetentionPolicies = asyncHandler(async (req, res) => {
    const {
      standard,
      retentionDays,
      applyToExisting,
      excludePatterns,
      includePatterns,
      compressAfterDays,
      archiveAfterDays,
      deleteAfterDays
    } = req.body;

    // Validate required fields
    if (!standard || !retentionDays) {
      throw new ValidationError('Standard and retention days are required');
    }

    // Validate retention days
    if (retentionDays < 1) {
      throw new ValidationError('Retention days must be at least 1');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.retention.configured', {
      standard,
      retentionDays,
      applyToExisting
    });

    const result = await AuditService.configureRetentionPolicies(req.adminUser, {
      standard,
      retentionDays,
      applyToExisting: applyToExisting || false,
      excludePatterns: excludePatterns || [],
      includePatterns: includePatterns || [],
      compressAfterDays,
      archiveAfterDays,
      deleteAfterDays
    });

    res.status(200).json(
      responseFormatter.success(result, 'Retention policy configured successfully')
    );
  });

  /**
   * Get retention policies
   * @route GET /api/admin/audit/retention
   * @access Admin - Audit View
   */
  static getRetentionPolicies = asyncHandler(async (req, res) => {
    const { active } = req.query;

    const policies = await AuditService.getRetentionPolicies({
      active: active === 'true' ? true : active === 'false' ? false : undefined
    });

    res.status(200).json(
      responseFormatter.success({ policies }, 'Retention policies retrieved successfully')
    );
  });

  /**
   * Export audit logs
   * @route POST /api/admin/audit/export
   * @access Admin - Audit Export
   */
  static exportAuditLogs = asyncHandler(async (req, res) => {
    const {
      format,
      query,
      dateFrom,
      dateTo,
      includeDecrypted,
      compress,
      encryption,
      password,
      notificationEmail
    } = req.body;

    // Validate format
    const validFormats = ['csv', 'json', 'pdf', 'excel'];
    if (!format || !validFormats.includes(format)) {
      throw new ValidationError('Valid export format is required (csv, json, pdf, excel)');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.logs.exported', {
      format,
      hasQuery: !!query,
      dateRange: !!(dateFrom || dateTo),
      includeDecrypted,
      encrypted: encryption
    });

    const result = await AuditService.exportAuditLogs(req.adminUser, {
      format,
      query: query || {},
      dateFrom,
      dateTo,
      includeDecrypted: includeDecrypted || false,
      compress: compress !== false,
      encryption: encryption !== false,
      password,
      notificationEmail: notificationEmail || req.adminUser.email
    });

    res.status(200).json(
      responseFormatter.success(result, 'Audit log export initiated successfully')
    );
  });

  /**
   * Get export status
   * @route GET /api/admin/audit/export/:exportId
   * @access Admin - Audit View
   */
  static getExportStatus = asyncHandler(async (req, res) => {
    const { exportId } = req.params;

    if (!exportId) {
      throw new ValidationError('Export ID is required');
    }

    const status = await AuditService.getExportStatus(exportId);

    res.status(200).json(
      responseFormatter.success({ status }, 'Export status retrieved successfully')
    );
  });

  /**
   * Configure audit alerts
   * @route POST /api/admin/audit/alerts
   * @access Admin - Audit Configure
   */
  static configureAuditAlerts = asyncHandler(async (req, res) => {
    const {
      name,
      description,
      conditions,
      actions,
      severity,
      enabled,
      cooldownMinutes,
      maxAlertsPerHour,
      test
    } = req.body;

    // Validate required fields
    if (!name || !conditions || !actions) {
      throw new ValidationError('Name, conditions, and actions are required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.alert.configured', {
      alertName: name,
      severity,
      enabled,
      test
    });

    const result = await AuditService.configureAuditAlerts(req.adminUser, {
      name,
      description,
      conditions,
      actions,
      severity: severity || 'medium',
      enabled: enabled !== false,
      cooldownMinutes: cooldownMinutes || 60,
      maxAlertsPerHour: maxAlertsPerHour || 10,
      test: test || false
    });

    res.status(200).json(
      responseFormatter.success(result, 'Audit alert configured successfully')
    );
  });

  /**
   * Get audit alerts
   * @route GET /api/admin/audit/alerts
   * @access Admin - Audit View
   */
  static getAuditAlerts = asyncHandler(async (req, res) => {
    const { enabled, severity, triggered } = req.query;

    const alerts = await AuditService.getAuditAlerts({
      enabled: enabled === 'true' ? true : enabled === 'false' ? false : undefined,
      severity,
      triggered: triggered === 'true'
    });

    res.status(200).json(
      responseFormatter.success({ alerts }, 'Audit alerts retrieved successfully')
    );
  });

  /**
   * Archive audit logs
   * @route POST /api/admin/audit/archive
   * @access Admin - Audit Manage
   */
  static archiveAuditLogs = asyncHandler(async (req, res) => {
    const {
      dateFrom,
      dateTo,
      compress,
      encrypt,
      deleteOriginal,
      archiveLocation
    } = req.body;

    // Validate date range
    if (!dateFrom || !dateTo) {
      throw new ValidationError('Date range (dateFrom and dateTo) is required');
    }

    const fromDate = new Date(dateFrom);
    const toDate = new Date(dateTo);

    if (fromDate >= toDate) {
      throw new ValidationError('Invalid date range: dateFrom must be before dateTo');
    }

    // Validate critical operation
    if (deleteOriginal) {
      if (!req.body.confirmDelete) {
        throw new ValidationError('Confirmation required to delete original logs');
      }
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.logs.archived', {
      dateFrom,
      dateTo,
      compress,
      encrypt,
      deleteOriginal
    });

    const result = await AuditService.archiveAuditLogs(req.adminUser, {
      dateFrom,
      dateTo,
      compress: compress !== false,
      encrypt: encrypt !== false,
      deleteOriginal: deleteOriginal || false,
      archiveLocation: archiveLocation || 'default'
    });

    res.status(200).json(
      responseFormatter.success(result, 'Audit logs archived successfully')
    );
  });

  /**
   * Get archive status
   * @route GET /api/admin/audit/archive/:archiveId
   * @access Admin - Audit View
   */
  static getArchiveStatus = asyncHandler(async (req, res) => {
    const { archiveId } = req.params;

    if (!archiveId) {
      throw new ValidationError('Archive ID is required');
    }

    const status = await AuditService.getArchiveStatus(archiveId);

    res.status(200).json(
      responseFormatter.success({ status }, 'Archive status retrieved successfully')
    );
  });

  /**
   * Get audit statistics
   * @route GET /api/admin/audit/statistics
   * @access Admin - Audit View
   */
  static getAuditStatistics = asyncHandler(async (req, res) => {
    const {
      timeRange,
      groupBy,
      includeCompliance,
      includeRiskAnalysis
    } = req.query;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.statistics.viewed', {
      timeRange,
      groupBy
    });

    const statistics = await AuditService.getAuditStatistics(req.adminUser, {
      timeRange: timeRange || '30d',
      groupBy: groupBy || 'day',
      includeCompliance: includeCompliance !== 'false',
      includeRiskAnalysis: includeRiskAnalysis !== 'false'
    });

    res.status(200).json(
      responseFormatter.success(statistics, 'Audit statistics retrieved successfully')
    );
  });

  /**
   * Manage compliance mappings
   * @route POST /api/admin/audit/compliance-mappings
   * @access Admin - Audit Configure
   */
  static manageComplianceMappings = asyncHandler(async (req, res) => {
    const {
      action,
      standard,
      eventTypes,
      requirements,
      controls,
      description
    } = req.body;

    // Validate action
    if (!action || !['create', 'update', 'delete'].includes(action)) {
      throw new ValidationError('Valid action is required (create, update, delete)');
    }

    // Validate required fields based on action
    if (action !== 'delete') {
      if (!standard || !eventTypes || eventTypes.length === 0) {
        throw new ValidationError('Standard and event types are required');
      }
    } else if (!standard) {
      throw new ValidationError('Standard is required for deletion');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.compliance_mapping.managed', {
      action,
      standard,
      eventTypesCount: eventTypes?.length
    });

    const result = await AuditService.manageComplianceMappings(req.adminUser, {
      action,
      standard,
      eventTypes,
      requirements: requirements || [],
      controls: controls || [],
      description
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance mapping managed successfully')
    );
  });

  /**
   * Get compliance mappings
   * @route GET /api/admin/audit/compliance-mappings
   * @access Admin - Audit View
   */
  static getComplianceMappings = asyncHandler(async (req, res) => {
    const result = await AuditService.manageComplianceMappings(req.adminUser, {
      action: 'list'
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance mappings retrieved successfully')
    );
  });

  /**
   * Generate compliance report
   * @route POST /api/admin/audit/compliance-report
   * @access Admin - Audit View Reports
   */
  static generateComplianceReport = asyncHandler(async (req, res) => {
    const {
      standard,
      dateFrom,
      dateTo,
      scope,
      format,
      includeEvidence
    } = req.body;

    // Validate required fields
    if (!standard) {
      throw new ValidationError('Compliance standard is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.compliance_report.generated', {
      standard,
      dateRange: !!(dateFrom || dateTo),
      scope,
      format
    });

    const report = await AuditService.generateComplianceReport(req.adminUser, {
      standard,
      dateFrom,
      dateTo,
      scope: scope || 'organization',
      format: format || 'detailed',
      includeEvidence: includeEvidence !== false
    });

    res.status(200).json(
      responseFormatter.success(report, 'Compliance report generated successfully')
    );
  });

  /**
   * Real-time audit monitoring
   * @route GET /api/admin/audit/monitor
   * @access Admin - Audit View
   */
  static monitorAuditEvents = asyncHandler(async (req, res) => {
    const { filters, severity, eventTypes } = req.query;

    // Set up SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.monitoring.started', {
      filters,
      severity,
      eventTypes
    });

    // Send initial connection message
    res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Audit monitoring started' })}\n\n`);

    // Set up monitoring
    const monitoringOptions = {
      filters: filters ? JSON.parse(filters) : {},
      severity,
      eventTypes: eventTypes ? eventTypes.split(',') : null
    };

    // Clean up on client disconnect
    req.on('close', () => {
      AdminActivityTracker.track(req.adminUser, 'audit.monitoring.stopped', {});
    });

    // Keep connection alive
    const keepAlive = setInterval(() => {
      res.write(':keep-alive\n\n');
    }, 30000);

    req.on('close', () => {
      clearInterval(keepAlive);
    });
  });

  /**
   * Analyze audit patterns
   * @route POST /api/admin/audit/analyze
   * @access Admin - Audit View
   */
  static analyzeAuditPatterns = asyncHandler(async (req, res) => {
    const {
      timeRange,
      analysisType,
      userId,
      organizationId,
      eventTypes
    } = req.body;

    // Validate analysis type
    const validAnalysisTypes = ['user_behavior', 'security_threats', 'compliance_gaps', 'anomaly_detection'];
    if (!analysisType || !validAnalysisTypes.includes(analysisType)) {
      throw new ValidationError('Valid analysis type is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'audit.analysis.performed', {
      analysisType,
      timeRange,
      hasFilters: !!(userId || organizationId || eventTypes)
    });

    const analysis = await AuditService.analyzeAuditPatterns(req.adminUser, {
      timeRange: timeRange || '7d',
      analysisType,
      userId,
      organizationId,
      eventTypes
    });

    res.status(200).json(
      responseFormatter.success(analysis, 'Audit analysis completed successfully')
    );
  });

  /**
   * Get audit filters
   * @route GET /api/admin/audit/filters
   * @access Admin - Audit View
   */
  static getAuditFilters = asyncHandler(async (req, res) => {
    const filters = await AuditService.getAvailableAuditFilters();

    res.status(200).json(
      responseFormatter.success({ filters }, 'Audit filters retrieved successfully')
    );
  });

  /**
   * Decrypt audit log
   * @route POST /api/admin/audit/decrypt/:auditLogId
   * @access Admin - Audit Decrypt
   */
  static decryptAuditLog = asyncHandler(async (req, res) => {
    const { auditLogId } = req.params;
    const { reason } = req.body;

    if (!auditLogId) {
      throw new ValidationError('Audit log ID is required');
    }

    if (!reason || reason.trim().length < 10) {
      throw new ValidationError('Detailed reason for decryption is required (minimum 10 characters)');
    }

    // Track admin activity - critical operation
    await AdminActivityTracker.track(req.adminUser, 'audit.log.decrypted', {
      auditLogId,
      reason
    });

    const decrypted = await AuditService.decryptSingleAuditLog(auditLogId, req.adminUser);

    res.status(200).json(
      responseFormatter.success({ decrypted }, 'Audit log decrypted successfully')
    );
  });

  /**
   * Purge audit logs
   * @route DELETE /api/admin/audit/purge
   * @access Admin - Audit Manage (Critical)
   */
  static purgeAuditLogs = asyncHandler(async (req, res) => {
    const {
      dateFrom,
      dateTo,
      eventTypes,
      severity,
      confirmPurge,
      reason
    } = req.body;

    // Validate confirmation
    if (!confirmPurge) {
      throw new ValidationError('Purge confirmation is required');
    }

    // Validate reason
    if (!reason || reason.trim().length < 20) {
      throw new ValidationError('Detailed reason for purge is required (minimum 20 characters)');
    }

    // Validate date range
    if (!dateFrom || !dateTo) {
      throw new ValidationError('Date range is required for purge operation');
    }

    // Track admin activity - critical operation
    await AdminActivityTracker.track(req.adminUser, 'audit.logs.purged', {
      dateFrom,
      dateTo,
      eventTypes,
      severity,
      reason
    });

    const result = await AuditService.purgeAuditLogs(req.adminUser, {
      dateFrom,
      dateTo,
      eventTypes,
      severity,
      reason
    });

    res.status(200).json(
      responseFormatter.success(result, 'Audit logs purged successfully')
    );
  });

  /**
   * Get audit health status
   * @route GET /api/admin/audit/health
   * @access Admin - Audit View
   */
  static getAuditHealth = asyncHandler(async (req, res) => {
    const health = await AuditService.getAuditSystemHealth();

    res.status(200).json(
      responseFormatter.success({ health }, 'Audit system health retrieved successfully')
    );
  });
}

module.exports = AuditController;