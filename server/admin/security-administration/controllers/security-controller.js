// server/admin/security-administration/controllers/security-controller.js
/**
 * @file Admin Security Controller
 * @description Handles HTTP requests for security management operations
 * @version 1.0.0
 */

const SecurityService = require('../services/security-service');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const asyncHandler = require('../../../shared/middleware/async-handler');
const responseFormatter = require('../../../shared/utils/response-formatter');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');

/**
 * Admin Security Controller Class
 * @class SecurityController
 */
class SecurityController {
  /**
   * Get security overview
   * @route GET /api/admin/security/overview
   * @access Admin - Security View
   */
  static getSecurityOverview = asyncHandler(async (req, res) => {
    const { timeRange, includeMetrics, includeThreats, includeVulnerabilities, includeCompliance } = req.query;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.overview.viewed', {
      timeRange
    });

    const overview = await SecurityService.getSecurityOverview(req.adminUser, {
      timeRange,
      includeMetrics: includeMetrics !== 'false',
      includeThreats: includeThreats !== 'false',
      includeVulnerabilities: includeVulnerabilities !== 'false',
      includeCompliance: includeCompliance !== 'false'
    });

    res.status(200).json(
      responseFormatter.success(overview, 'Security overview retrieved successfully')
    );
  });

  /**
   * Update security settings
   * @route PUT /api/admin/security/settings
   * @access Admin - Security Update
   */
  static updateSecuritySettings = asyncHandler(async (req, res) => {
    const settings = req.body;

    // Validate request body
    if (!settings || Object.keys(settings).length === 0) {
      throw new ValidationError('Security settings data is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.settings.update_initiated', {
      settingsKeys: Object.keys(settings)
    });

    const result = await SecurityService.updateSecuritySettings(req.adminUser, settings);

    res.status(200).json(
      responseFormatter.success(result, 'Security settings updated successfully')
    );
  });

  /**
   * Get security settings
   * @route GET /api/admin/security/settings
   * @access Admin - Security View
   */
  static getSecuritySettings = asyncHandler(async (req, res) => {
    const settings = await SecurityService.getGlobalSecuritySettings();

    res.status(200).json(
      responseFormatter.success({ settings }, 'Security settings retrieved successfully')
    );
  });

  /**
   * Manage IP whitelist
   * @route POST /api/admin/security/ip-whitelist
   * @access Admin - Security Manage Whitelist
   */
  static manageIPWhitelist = asyncHandler(async (req, res) => {
    const { action, ips, ip, description, scope, expiresAt } = req.body;

    // Validate action
    if (!action || !['add', 'remove', 'update'].includes(action)) {
      throw new ValidationError('Valid action is required (add, remove, update)');
    }

    // Validate IPs
    const ipList = ips || (ip ? [ip] : []);
    if (action !== 'list' && ipList.length === 0) {
      throw new ValidationError('At least one IP address is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.ip_whitelist.managed', {
      action,
      ipCount: ipList.length
    });

    const result = await SecurityService.manageIPWhitelist(req.adminUser, {
      action,
      ips: ipList,
      description,
      scope,
      expiresAt
    });

    res.status(200).json(
      responseFormatter.success(result, 'IP whitelist operation completed successfully')
    );
  });

  /**
   * Get IP whitelist
   * @route GET /api/admin/security/ip-whitelist
   * @access Admin - Security View
   */
  static getIPWhitelist = asyncHandler(async (req, res) => {
    const { scope = 'admin' } = req.query;

    const result = await SecurityService.manageIPWhitelist(req.adminUser, {
      action: 'list',
      scope
    });

    res.status(200).json(
      responseFormatter.success(result, 'IP whitelist retrieved successfully')
    );
  });

  /**
   * Rotate encryption keys
   * @route POST /api/admin/security/encryption/rotate
   * @access Admin - Security Rotate Keys
   */
  static rotateEncryptionKeys = asyncHandler(async (req, res) => {
    const { keyTypes, reason, immediate, notifyUsers } = req.body;

    // Validate reason
    if (!reason || reason.trim().length < 10) {
      throw new ValidationError('Detailed reason for key rotation is required (minimum 10 characters)');
    }

    // Validate key types
    const validKeyTypes = ['master', 'session', 'data'];
    if (keyTypes && !keyTypes.every(type => validKeyTypes.includes(type))) {
      throw new ValidationError('Invalid key type specified');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.encryption.rotation_initiated', {
      keyTypes: keyTypes || validKeyTypes,
      immediate
    });

    const result = await SecurityService.rotateEncryptionKeys(req.adminUser, {
      keyTypes: keyTypes || validKeyTypes,
      reason,
      immediate: immediate || false,
      notifyUsers: notifyUsers !== false
    });

    res.status(200).json(
      responseFormatter.success(result, 'Encryption keys rotation initiated successfully')
    );
  });

  /**
   * Manage security incident
   * @route POST /api/admin/security/incidents
   * @access Admin - Security Manage Incidents
   */
  static manageSecurityIncident = asyncHandler(async (req, res) => {
    const { action, incidentId, type, severity, description, affectedResources, resolution, status } = req.body;

    // Validate action
    if (!action || !['create', 'update', 'escalate', 'resolve'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate required fields based on action
    if (action === 'create') {
      if (!type || !severity || !description) {
        throw new ValidationError('Type, severity, and description are required for creating an incident');
      }
    } else {
      if (!incidentId) {
        throw new ValidationError('Incident ID is required');
      }
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.incident.managed', {
      action,
      incidentId,
      severity
    });

    const result = await SecurityService.manageSecurityIncident(req.adminUser, {
      action,
      incidentId,
      type,
      severity,
      description,
      affectedResources,
      resolution,
      status
    });

    res.status(200).json(
      responseFormatter.success(result, 'Security incident managed successfully')
    );
  });

  /**
   * Get security incidents
   * @route GET /api/admin/security/incidents
   * @access Admin - Security View
   */
  static getSecurityIncidents = asyncHandler(async (req, res) => {
    const { status, severity, dateFrom, dateTo, page = 1, limit = 20, sort = '-createdAt' } = req.query;

    const startDate = dateFrom ? new Date(dateFrom) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const incidents = await SecurityService.getRecentIncidents(startDate, limit);

    res.status(200).json(
      responseFormatter.success(
        {
          incidents,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: incidents.length
          }
        },
        'Security incidents retrieved successfully'
      )
    );
  });

  /**
   * Configure threat detection
   * @route POST /api/admin/security/threat-detection
   * @access Admin - Security Configure Threat Detection
   */
  static configureThreatDetection = asyncHandler(async (req, res) => {
    const { action, ruleId, name, type, conditions, actions, severity, enabled } = req.body;

    // Validate action
    if (!action || !['create', 'update', 'delete', 'test'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate required fields based on action
    if (action === 'create') {
      if (!name || !type || !conditions || !actions) {
        throw new ValidationError('Name, type, conditions, and actions are required');
      }
    } else if (action !== 'create' && !ruleId) {
      throw new ValidationError('Rule ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.threat_detection.configured', {
      action,
      ruleId,
      ruleType: type
    });

    const result = await SecurityService.configureThreatDetection(req.adminUser, {
      action,
      ruleId,
      name,
      type,
      conditions,
      actions: actions || [],
      severity,
      enabled
    });

    res.status(200).json(
      responseFormatter.success(result, 'Threat detection configured successfully')
    );
  });

  /**
   * Get threat detection rules
   * @route GET /api/admin/security/threat-detection
   * @access Admin - Security View
   */
  static getThreatDetectionRules = asyncHandler(async (req, res) => {
    const { enabled, type, severity } = req.query;

    const rules = await SecurityService.getThreatDetectionRules({
      enabled: enabled === 'true' ? true : enabled === 'false' ? false : undefined,
      type,
      severity
    });

    res.status(200).json(
      responseFormatter.success({ rules }, 'Threat detection rules retrieved successfully')
    );
  });

  /**
   * Perform security scan
   * @route POST /api/admin/security/scan
   * @access Admin - Security Perform Scan
   */
  static performSecurityScan = asyncHandler(async (req, res) => {
    const { scanType, targets, deep, schedule } = req.body;

    // Validate scan type
    const validScanTypes = ['full', 'vulnerability', 'compliance', 'access', 'configuration'];
    if (!scanType || !validScanTypes.includes(scanType)) {
      throw new ValidationError('Valid scan type is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.scan.initiated', {
      scanType,
      targetsCount: targets?.length || 1,
      deep
    });

    const result = await SecurityService.performSecurityScan(req.adminUser, {
      scanType,
      targets: targets || ['system'],
      deep: deep || false,
      schedule: schedule || false
    });

    res.status(200).json(
      responseFormatter.success(result, 'Security scan completed successfully')
    );
  });

  /**
   * Get security scan results
   * @route GET /api/admin/security/scan/:scanId
   * @access Admin - Security View
   */
  static getSecurityScanResults = asyncHandler(async (req, res) => {
    const { scanId } = req.params;

    if (!scanId) {
      throw new ValidationError('Scan ID is required');
    }

    const results = await SecurityService.getScanResults(scanId);

    res.status(200).json(
      responseFormatter.success({ results }, 'Scan results retrieved successfully')
    );
  });

  /**
   * Generate security report
   * @route POST /api/admin/security/reports
   * @access Admin - Security View Reports
   */
  static generateSecurityReport = asyncHandler(async (req, res) => {
    const { reportType, timeRange, format, includeRecommendations } = req.body;

    // Validate report type
    const validReportTypes = ['comprehensive', 'executive', 'technical', 'compliance', 'incident'];
    if (!reportType || !validReportTypes.includes(reportType)) {
      throw new ValidationError('Valid report type is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.report.generated', {
      reportType,
      timeRange,
      format
    });

    const report = await SecurityService.generateSecurityReport(req.adminUser, {
      reportType,
      timeRange: timeRange || '30d',
      format: format || 'detailed',
      includeRecommendations: includeRecommendations !== false
    });

    res.status(200).json(
      responseFormatter.success({ report }, 'Security report generated successfully')
    );
  });

  /**
   * Get security reports
   * @route GET /api/admin/security/reports
   * @access Admin - Security View Reports
   */
  static getSecurityReports = asyncHandler(async (req, res) => {
    const { type, dateFrom, dateTo, page = 1, limit = 20 } = req.query;

    const reports = await SecurityService.getSecurityReports({
      type,
      dateFrom,
      dateTo,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(reports, 'Security reports retrieved successfully')
    );
  });

  /**
   * Update access control
   * @route PUT /api/admin/security/access-control
   * @access Admin - Security Update
   */
  static updateAccessControl = asyncHandler(async (req, res) => {
    const { resource, permissions, roles, conditions } = req.body;

    if (!resource || !permissions) {
      throw new ValidationError('Resource and permissions are required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.access_control.updated', {
      resource,
      permissionCount: permissions.length
    });

    const result = await SecurityService.updateAccessControl(req.adminUser, {
      resource,
      permissions,
      roles,
      conditions
    });

    res.status(200).json(
      responseFormatter.success(result, 'Access control updated successfully')
    );
  });

  /**
   * Get vulnerability report
   * @route GET /api/admin/security/vulnerabilities
   * @access Admin - Security View
   */
  static getVulnerabilityReport = asyncHandler(async (req, res) => {
    const { severity, status, category } = req.query;

    const vulnerabilities = await SecurityService.getVulnerabilitySummary();

    res.status(200).json(
      responseFormatter.success({ vulnerabilities }, 'Vulnerability report retrieved successfully')
    );
  });

  /**
   * Manage session security
   * @route POST /api/admin/security/sessions
   * @access Admin - Security Manage Sessions
   */
  static manageSessionSecurity = asyncHandler(async (req, res) => {
    const { action, sessionId, userId, reason } = req.body;

    // Validate action
    if (!action || !['terminate', 'terminate-all', 'review'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate required fields
    if (action === 'terminate' && !sessionId) {
      throw new ValidationError('Session ID is required for termination');
    }
    if (action === 'terminate-all' && !userId) {
      throw new ValidationError('User ID is required for terminating all sessions');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.session.managed', {
      action,
      sessionId,
      userId
    });

    const result = await SecurityService.manageSessionSecurity(req.adminUser, {
      action,
      sessionId,
      userId,
      reason
    });

    res.status(200).json(
      responseFormatter.success(result, 'Session security action completed successfully')
    );
  });

  /**
   * Get active sessions
   * @route GET /api/admin/security/sessions
   * @access Admin - Security View
   */
  static getActiveSessions = asyncHandler(async (req, res) => {
    const { userId, suspicious, elevated, page = 1, limit = 50 } = req.query;

    const sessions = await SecurityService.getSessionSecurityMetrics(new Date(Date.now() - 24 * 60 * 60 * 1000));

    res.status(200).json(
      responseFormatter.success(
        {
          sessions,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: sessions.total || 0
          }
        },
        'Active sessions retrieved successfully'
      )
    );
  });

  /**
   * Configure security alerts
   * @route POST /api/admin/security/alerts
   * @access Admin - Security Configure
   */
  static configureSecurityAlerts = asyncHandler(async (req, res) => {
    const { alertType, conditions, actions, enabled, channels } = req.body;

    if (!alertType || !conditions || !actions) {
      throw new ValidationError('Alert type, conditions, and actions are required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.alerts.configured', {
      alertType,
      enabled
    });

    const result = await SecurityService.configureSecurityAlerts(req.adminUser, {
      alertType,
      conditions,
      actions,
      enabled: enabled !== false,
      channels: channels || []
    });

    res.status(200).json(
      responseFormatter.success(result, 'Security alerts configured successfully')
    );
  });

  /**
   * Get security metrics
   * @route GET /api/admin/security/metrics
   * @access Admin - Security View
   */
  static getSecurityMetrics = asyncHandler(async (req, res) => {
    const { timeRange = '24h', metrics } = req.query;

    const metricsData = await SecurityService.getSecurityMetrics({
      timeRange,
      metrics: metrics ? metrics.split(',') : null
    });

    res.status(200).json(
      responseFormatter.success({ metrics: metricsData }, 'Security metrics retrieved successfully')
    );
  });

  /**
   * Export security data
   * @route POST /api/admin/security/export
   * @access Admin - Security Export
   */
  static exportSecurityData = asyncHandler(async (req, res) => {
    const { dataType, format, dateFrom, dateTo, filters } = req.body;

    if (!dataType) {
      throw new ValidationError('Data type is required for export');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'security.data.exported', {
      dataType,
      format
    });

    const exportData = await SecurityService.exportSecurityData(req.adminUser, {
      dataType,
      format: format || 'csv',
      dateFrom,
      dateTo,
      filters
    });

    res.status(200).json(
      responseFormatter.success({ export: exportData }, 'Security data export initiated successfully')
    );
  });
}

module.exports = SecurityController;