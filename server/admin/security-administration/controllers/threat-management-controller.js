// server/admin/security-administration/controllers/threat-management-controller.js
/**
 * @file Admin Threat Management Controller
 * @description Handles HTTP requests for threat detection and management operations
 * @version 1.0.0
 */

const ThreatManagementService = require('../services/threat-management-service');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const asyncHandler = require('../../../shared/middleware/async-handler');
const responseFormatter = require('../../../shared/utils/response-formatter');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');

/**
 * Admin Threat Management Controller Class
 * @class ThreatManagementController
 */
class ThreatManagementController {
  /**
   * Get threat overview
   * @route GET /api/admin/threats/overview
   * @access Admin - Threat View
   */
  static getThreatOverview = asyncHandler(async (req, res) => {
    const {
      timeRange,
      includeIntelligence,
      includePatterns,
      includeActors,
      organizationId
    } = req.query;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.overview.viewed', {
      timeRange,
      organizationId
    });

    const overview = await ThreatManagementService.getThreatOverview(req.adminUser, {
      timeRange: timeRange || '24h',
      includeIntelligence: includeIntelligence !== 'false',
      includePatterns: includePatterns !== 'false',
      includeActors: includeActors !== 'false',
      organizationId
    });

    res.status(200).json(
      responseFormatter.success(overview, 'Threat overview retrieved successfully')
    );
  });

  /**
   * Manage threat rule
   * @route POST /api/admin/threats/rules
   * @access Admin - Threat Manage Rules
   */
  static manageThreatRule = asyncHandler(async (req, res) => {
    const {
      action,
      ruleId,
      name,
      description,
      type,
      severity,
      conditions,
      actions,
      enabled,
      priority,
      tags,
      testData
    } = req.body;

    // Validate action
    if (!action || !['create', 'update', 'disable', 'enable', 'test', 'delete'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate required fields based on action
    if (action === 'create') {
      if (!name || !type || !conditions || !actions) {
        throw new ValidationError('Name, type, conditions, and actions are required');
      }
    } else if (!ruleId) {
      throw new ValidationError('Rule ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.rule.managed', {
      action,
      ruleId,
      ruleName: name,
      ruleType: type
    });

    const result = await ThreatManagementService.manageThreatRule(req.adminUser, {
      action,
      ruleId,
      name,
      description,
      type,
      severity: severity || 'medium',
      conditions,
      actions,
      enabled: enabled !== false,
      priority: priority || 50,
      tags: tags || [],
      testData
    });

    res.status(200).json(
      responseFormatter.success(result, 'Threat rule managed successfully')
    );
  });

  /**
   * Get threat rules
   * @route GET /api/admin/threats/rules
   * @access Admin - Threat View
   */
  static getThreatRules = asyncHandler(async (req, res) => {
    const {
      type,
      severity,
      enabled,
      tags,
      search,
      page = 1,
      limit = 20,
      sort = '-priority'
    } = req.query;

    const rules = await ThreatManagementService.getThreatRules({
      type,
      severity,
      enabled: enabled === 'true' ? true : enabled === 'false' ? false : undefined,
      tags: tags ? tags.split(',') : undefined,
      search,
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });

    res.status(200).json(
      responseFormatter.success(rules, 'Threat rules retrieved successfully')
    );
  });

  /**
   * Investigate threat event
   * @route POST /api/admin/threats/investigate/:eventId
   * @access Admin - Threat Investigate
   */
  static investigateThreatEvent = asyncHandler(async (req, res) => {
    const { eventId } = req.params;
    const { deep, includeContext } = req.body;

    if (!eventId) {
      throw new ValidationError('Event ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.event.investigated', {
      eventId,
      deep,
      includeContext
    });

    const investigation = await ThreatManagementService.investigateThreatEvent(
      req.adminUser,
      eventId,
      {
        deep: deep || false,
        includeContext: includeContext !== false
      }
    );

    res.status(200).json(
      responseFormatter.success(investigation, 'Threat investigation completed successfully')
    );
  });

  /**
   * Respond to threat
   * @route POST /api/admin/threats/respond
   * @access Admin - Threat Respond
   */
  static respondToThreat = asyncHandler(async (req, res) => {
    const {
      threatId,
      threatType,
      responseType,
      actions,
      automate,
      notifyAffected,
      escalate,
      notes
    } = req.body;

    // Validate required fields
    if (!threatId || !threatType || !responseType) {
      throw new ValidationError('Threat ID, threat type, and response type are required');
    }

    // Validate response type
    const validResponseTypes = ['block', 'quarantine', 'monitor', 'mitigate', 'custom'];
    if (!validResponseTypes.includes(responseType)) {
      throw new ValidationError('Invalid response type');
    }

    // Validate actions
    if (!actions || actions.length === 0) {
      throw new ValidationError('At least one action is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.response.initiated', {
      threatId,
      threatType,
      responseType,
      actionsCount: actions.length,
      automated: automate
    });

    const result = await ThreatManagementService.respondToThreat(req.adminUser, {
      threatId,
      threatType,
      responseType,
      actions,
      automate: automate || false,
      notifyAffected: notifyAffected !== false,
      escalate: escalate || false,
      notes
    });

    res.status(200).json(
      responseFormatter.success(result, 'Threat response executed successfully')
    );
  });

  /**
   * Get threat events
   * @route GET /api/admin/threats/events
   * @access Admin - Threat View
   */
  static getThreatEvents = asyncHandler(async (req, res) => {
    const {
      type,
      severity,
      status,
      source,
      target,
      organizationId,
      dateFrom,
      dateTo,
      page = 1,
      limit = 50,
      sort = '-timestamp'
    } = req.query;

    const events = await ThreatManagementService.getThreatEvents({
      type,
      severity,
      status,
      source,
      target,
      organizationId,
      dateFrom,
      dateTo,
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });

    res.status(200).json(
      responseFormatter.success(events, 'Threat events retrieved successfully')
    );
  });

  /**
   * Manage threat indicator
   * @route POST /api/admin/threats/indicators
   * @access Admin - Threat Manage Indicators
   */
  static manageThreatIndicator = asyncHandler(async (req, res) => {
    const {
      action,
      indicatorId,
      type,
      value,
      severity,
      confidence,
      source,
      description,
      tags,
      expiration,
      reason
    } = req.body;

    // Validate action
    if (!action || !['add', 'update', 'remove', 'verify'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate required fields based on action
    if (action === 'add') {
      if (!type || !value) {
        throw new ValidationError('Type and value are required');
      }
    } else if (!indicatorId) {
      throw new ValidationError('Indicator ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.indicator.managed', {
      action,
      indicatorId,
      indicatorType: type,
      severity
    });

    const result = await ThreatManagementService.manageThreatIndicator(req.adminUser, {
      action,
      indicatorId,
      type,
      value,
      severity: severity || 'medium',
      confidence: confidence || 50,
      source,
      description,
      tags: tags || [],
      expiration,
      reason
    });

    res.status(200).json(
      responseFormatter.success(result, 'Threat indicator managed successfully')
    );
  });

  /**
   * Get threat indicators
   * @route GET /api/admin/threats/indicators
   * @access Admin - Threat View
   */
  static getThreatIndicators = asyncHandler(async (req, res) => {
    const {
      type,
      severity,
      source,
      active,
      verified,
      tags,
      page = 1,
      limit = 50
    } = req.query;

    const indicators = await ThreatManagementService.getThreatIndicators({
      type,
      severity,
      source,
      active: active === 'true' ? true : active === 'false' ? false : undefined,
      verified: verified === 'true' ? true : verified === 'false' ? false : undefined,
      tags: tags ? tags.split(',') : undefined,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(indicators, 'Threat indicators retrieved successfully')
    );
  });

  /**
   * Manage IP block
   * @route POST /api/admin/threats/ip-blocks
   * @access Admin - Threat Block IPs
   */
  static manageIPBlock = asyncHandler(async (req, res) => {
    const {
      action,
      ip,
      ips,
      reason,
      duration,
      permanent,
      scope
    } = req.body;

    // Validate action
    if (!action || !['block', 'unblock'].includes(action)) {
      throw new ValidationError('Valid action is required (block or unblock)');
    }

    // Validate IPs
    const targetIPs = ips || (ip ? [ip] : []);
    if (targetIPs.length === 0) {
      throw new ValidationError('At least one IP address is required');
    }

    // Validate reason
    if (!reason) {
      throw new ValidationError('Reason is required for IP blocking/unblocking');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.ip_block.managed', {
      action,
      ipCount: targetIPs.length,
      permanent,
      scope
    });

    const result = await ThreatManagementService.manageIPBlock(req.adminUser, {
      action,
      ips: targetIPs,
      reason,
      duration,
      permanent: permanent || false,
      scope: scope || 'global'
    });

    res.status(200).json(
      responseFormatter.success(result, 'IP block operation completed successfully')
    );
  });

  /**
   * Get blocked IPs
   * @route GET /api/admin/threats/ip-blocks
   * @access Admin - Threat View
   */
  static getBlockedIPs = asyncHandler(async (req, res) => {
    const {
      active,
      permanent,
      scope,
      search,
      page = 1,
      limit = 50
    } = req.query;

    const blockedIPs = await ThreatManagementService.getBlockedIPs({
      active: active === 'true' ? true : active === 'false' ? false : undefined,
      permanent: permanent === 'true' ? true : permanent === 'false' ? false : undefined,
      scope,
      search,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(blockedIPs, 'Blocked IPs retrieved successfully')
    );
  });

  /**
   * Analyze threat patterns
   * @route POST /api/admin/threats/analyze-patterns
   * @access Admin - Threat Analyze
   */
  static analyzeThreatPatterns = asyncHandler(async (req, res) => {
    const {
      timeRange,
      minOccurrences,
      includeML,
      organizationId
    } = req.body;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.patterns.analyzed', {
      timeRange,
      minOccurrences,
      includeML,
      organizationId
    });

    const analysis = await ThreatManagementService.analyzeThreatPatterns(req.adminUser, {
      timeRange: timeRange || '7d',
      minOccurrences: minOccurrences || 3,
      includeML: includeML !== false,
      organizationId
    });

    res.status(200).json(
      responseFormatter.success(analysis, 'Threat pattern analysis completed successfully')
    );
  });

  /**
   * Get threat intelligence
   * @route GET /api/admin/threats/intelligence
   * @access Admin - Threat View Intelligence
   */
  static getThreatIntelligence = asyncHandler(async (req, res) => {
    const {
      sources,
      severity,
      limit,
      includeIOCs
    } = req.query;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.intelligence.accessed', {
      sources: sources ? sources.split(',') : ['all'],
      severity,
      includeIOCs
    });

    const intelligence = await ThreatManagementService.getThreatIntelligence(req.adminUser, {
      sources: sources ? sources.split(',') : ['all'],
      severity,
      limit: parseInt(limit) || 50,
      includeIOCs: includeIOCs !== 'false'
    });

    res.status(200).json(
      responseFormatter.success(intelligence, 'Threat intelligence retrieved successfully')
    );
  });

  /**
   * Generate threat report
   * @route POST /api/admin/threats/reports
   * @access Admin - Threat Generate Reports
   */
  static generateThreatReport = asyncHandler(async (req, res) => {
    const {
      reportType,
      timeRange,
      format,
      organizationId,
      includePredictions
    } = req.body;

    // Validate report type
    const validReportTypes = ['comprehensive', 'executive', 'technical', 'incident'];
    if (!reportType || !validReportTypes.includes(reportType)) {
      throw new ValidationError('Valid report type is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.report.generated', {
      reportType,
      timeRange,
      format,
      organizationId
    });

    const report = await ThreatManagementService.generateThreatReport(req.adminUser, {
      reportType,
      timeRange: timeRange || '30d',
      format: format || 'detailed',
      organizationId,
      includePredictions: includePredictions !== false
    });

    res.status(200).json(
      responseFormatter.success(report, 'Threat report generated successfully')
    );
  });

  /**
   * Get threat reports
   * @route GET /api/admin/threats/reports
   * @access Admin - Threat View Reports
   */
  static getThreatReports = asyncHandler(async (req, res) => {
    const {
      type,
      organizationId,
      dateFrom,
      dateTo,
      page = 1,
      limit = 20
    } = req.query;

    const reports = await ThreatManagementService.getThreatReports({
      type,
      organizationId,
      dateFrom,
      dateTo,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(reports, 'Threat reports retrieved successfully')
    );
  });

  /**
   * Configure automated response
   * @route POST /api/admin/threats/automation
   * @access Admin - Threat Configure Automation
   */
  static configureAutomatedResponse = asyncHandler(async (req, res) => {
    const {
      threatType,
      conditions,
      actions,
      enabled,
      requireApproval,
      notificationChannels,
      cooldownMinutes
    } = req.body;

    // Validate required fields
    if (!threatType || !conditions || !actions) {
      throw new ValidationError('Threat type, conditions, and actions are required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.automation.configured', {
      threatType,
      enabled,
      requireApproval
    });

    const result = await ThreatManagementService.configureAutomatedResponse(req.adminUser, {
      threatType,
      conditions,
      actions,
      enabled: enabled !== false,
      requireApproval: requireApproval || false,
      notificationChannels: notificationChannels || [],
      cooldownMinutes: cooldownMinutes || 5
    });

    res.status(200).json(
      responseFormatter.success(result, 'Automated threat response configured successfully')
    );
  });

  /**
   * Get automated responses
   * @route GET /api/admin/threats/automation
   * @access Admin - Threat View
   */
  static getAutomatedResponses = asyncHandler(async (req, res) => {
    const { threatType, enabled } = req.query;

    const automations = await ThreatManagementService.getAutomatedResponses({
      threatType,
      enabled: enabled === 'true' ? true : enabled === 'false' ? false : undefined
    });

    res.status(200).json(
      responseFormatter.success({ automations }, 'Automated responses retrieved successfully')
    );
  });

  /**
   * Get security incidents
   * @route GET /api/admin/threats/incidents
   * @access Admin - Threat View
   */
  static getSecurityIncidents = asyncHandler(async (req, res) => {
    const {
      type,
      severity,
      status,
      organizationId,
      dateFrom,
      dateTo,
      page = 1,
      limit = 20,
      sort = '-createdAt'
    } = req.query;

    const incidents = await ThreatManagementService.getSecurityIncidents({
      type,
      severity,
      status,
      organizationId,
      dateFrom,
      dateTo,
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });

    res.status(200).json(
      responseFormatter.success(incidents, 'Security incidents retrieved successfully')
    );
  });

  /**
   * Create security incident
   * @route POST /api/admin/threats/incidents
   * @access Admin - Threat Manage
   */
  static createSecurityIncident = asyncHandler(async (req, res) => {
    const {
      type,
      severity,
      description,
      affectedResources,
      organizationId
    } = req.body;

    // Validate required fields
    if (!type || !severity || !description) {
      throw new ValidationError('Type, severity, and description are required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.incident.created', {
      type,
      severity,
      organizationId
    });

    const incident = await ThreatManagementService.createSecurityIncident(req.adminUser, {
      type,
      severity,
      description,
      affectedResources: affectedResources || [],
      organizationId
    });

    res.status(201).json(
      responseFormatter.success(incident, 'Security incident created successfully')
    );
  });

  /**
   * Update threat detection settings
   * @route PUT /api/admin/threats/settings
   * @access Admin - Threat Configure
   */
  static updateThreatDetectionSettings = asyncHandler(async (req, res) => {
    const {
      detectionSensitivity,
      autoBlockThreshold,
      alertThresholds,
      enableMLDetection,
      enableRealTimeAnalysis,
      retentionDays
    } = req.body;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.settings.updated', {
      fieldsUpdated: Object.keys(req.body)
    });

    const result = await ThreatManagementService.updateThreatDetectionSettings(req.adminUser, {
      detectionSensitivity,
      autoBlockThreshold,
      alertThresholds,
      enableMLDetection,
      enableRealTimeAnalysis,
      retentionDays
    });

    res.status(200).json(
      responseFormatter.success(result, 'Threat detection settings updated successfully')
    );
  });

  /**
   * Get threat statistics
   * @route GET /api/admin/threats/statistics
   * @access Admin - Threat View
   */
  static getThreatStatistics = asyncHandler(async (req, res) => {
    const {
      timeRange,
      groupBy,
      organizationId,
      metrics
    } = req.query;

    const statistics = await ThreatManagementService.getThreatStatistics({
      timeRange: timeRange || '30d',
      groupBy: groupBy || 'day',
      organizationId,
      metrics: metrics ? metrics.split(',') : null
    });

    res.status(200).json(
      responseFormatter.success(statistics, 'Threat statistics retrieved successfully')
    );
  });

  /**
   * Export threat data
   * @route POST /api/admin/threats/export
   * @access Admin - Threat Export
   */
  static exportThreatData = asyncHandler(async (req, res) => {
    const {
      dataType,
      format,
      dateFrom,
      dateTo,
      filters
    } = req.body;

    // Validate data type
    const validDataTypes = ['events', 'indicators', 'patterns', 'incidents', 'blocklist'];
    if (!dataType || !validDataTypes.includes(dataType)) {
      throw new ValidationError('Valid data type is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.data.exported', {
      dataType,
      format,
      dateRange: !!(dateFrom || dateTo)
    });

    const result = await ThreatManagementService.exportThreatData(req.adminUser, {
      dataType,
      format: format || 'csv',
      dateFrom,
      dateTo,
      filters: filters || {}
    });

    res.status(200).json(
      responseFormatter.success(result, 'Threat data export initiated successfully')
    );
  });

  /**
   * Real-time threat monitoring
   * @route GET /api/admin/threats/monitor
   * @access Admin - Threat View
   */
  static monitorThreats = asyncHandler(async (req, res) => {
    const { filters, severity, types } = req.query;

    // Set up SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    });

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'threat.monitoring.started', {
      filters,
      severity,
      types
    });

    // Send initial connection message
    res.write(`data: ${JSON.stringify({ type: 'connected', message: 'Threat monitoring started' })}\n\n`);

    // Set up monitoring
    const monitoringOptions = {
      filters: filters ? JSON.parse(filters) : {},
      severity,
      types: types ? types.split(',') : null
    };

    // Clean up on client disconnect
    req.on('close', () => {
      AdminActivityTracker.track(req.adminUser, 'threat.monitoring.stopped', {});
    });

    // Keep connection alive
    const keepAlive = setInterval(() => {
      res.write(':keep-alive\n\n');
    }, 30000);

    req.on('close', () => {
      clearInterval(keepAlive);
    });
  });
}

module.exports = ThreatManagementController;