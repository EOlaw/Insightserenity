// server/admin/security-administration/controllers/compliance-controller.js
/**
 * @file Admin Compliance Controller
 * @description Handles HTTP requests for compliance management operations
 * @version 1.0.0
 */

const ComplianceService = require('../services/compliance-service');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const asyncHandler = require('../../../shared/middleware/async-handler');
const responseFormatter = require('../../../shared/utils/response-formatter');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');

/**
 * Admin Compliance Controller Class
 * @class ComplianceController
 */
class ComplianceController {
  /**
   * Get compliance overview
   * @route GET /api/admin/compliance/overview
   * @access Admin - Compliance View
   */
  static getComplianceOverview = asyncHandler(async (req, res) => {
    const {
      includeAssessments,
      includeGaps,
      includeSchedule,
      organizationId,
      timeRange
    } = req.query;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.overview.viewed', {
      organizationId,
      timeRange
    });

    const overview = await ComplianceService.getComplianceOverview(req.adminUser, {
      includeAssessments: includeAssessments !== 'false',
      includeGaps: includeGaps !== 'false',
      includeSchedule: includeSchedule !== 'false',
      organizationId,
      timeRange: timeRange || '90d'
    });

    res.status(200).json(
      responseFormatter.success(overview, 'Compliance overview retrieved successfully')
    );
  });

  /**
   * Manage compliance standard
   * @route POST /api/admin/compliance/standards
   * @access Admin - Compliance Manage
   */
  static manageComplianceStandard = asyncHandler(async (req, res) => {
    const {
      action,
      standardId,
      name,
      acronym,
      version,
      description,
      requirements,
      controls,
      categories,
      assessmentFrequency,
      enabled
    } = req.body;

    // Validate action
    if (!action || !['create', 'update', 'disable', 'enable'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate required fields based on action
    if (action === 'create') {
      if (!name || !acronym || !version) {
        throw new ValidationError('Name, acronym, and version are required');
      }
    } else if (!standardId) {
      throw new ValidationError('Standard ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.standard.managed', {
      action,
      standardId,
      standardName: name,
      standardAcronym: acronym
    });

    const result = await ComplianceService.manageComplianceStandard(req.adminUser, {
      action,
      standardId,
      name,
      acronym,
      version,
      description,
      requirements,
      controls,
      categories,
      assessmentFrequency,
      enabled: enabled !== false
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance standard managed successfully')
    );
  });

  /**
   * Get compliance standards
   * @route GET /api/admin/compliance/standards
   * @access Admin - Compliance View
   */
  static getComplianceStandards = asyncHandler(async (req, res) => {
    const { enabled, search, page = 1, limit = 20 } = req.query;

    const standards = await ComplianceService.getComplianceStandards({
      enabled: enabled === 'true' ? true : enabled === 'false' ? false : undefined,
      search,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(standards, 'Compliance standards retrieved successfully')
    );
  });

  /**
   * Get compliance standard details
   * @route GET /api/admin/compliance/standards/:standardId
   * @access Admin - Compliance View
   */
  static getComplianceStandardDetails = asyncHandler(async (req, res) => {
    const { standardId } = req.params;
    const { includeControls, includeAssessments } = req.query;

    if (!standardId) {
      throw new ValidationError('Standard ID is required');
    }

    const standard = await ComplianceService.getComplianceStandardDetails(standardId, {
      includeControls: includeControls !== 'false',
      includeAssessments: includeAssessments === 'true'
    });

    res.status(200).json(
      responseFormatter.success({ standard }, 'Compliance standard details retrieved successfully')
    );
  });

  /**
   * Perform compliance assessment
   * @route POST /api/admin/compliance/assessments
   * @access Admin - Compliance Assess
   */
  static performComplianceAssessment = asyncHandler(async (req, res) => {
    const {
      standardId,
      organizationId,
      scope,
      controlResponses,
      evidence,
      notes
    } = req.body;

    // Validate required fields
    if (!standardId || !organizationId) {
      throw new ValidationError('Standard ID and organization ID are required');
    }

    if (!controlResponses || Object.keys(controlResponses).length === 0) {
      throw new ValidationError('Control responses are required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.assessment.started', {
      standardId,
      organizationId,
      scope,
      controlsCount: Object.keys(controlResponses).length
    });

    const result = await ComplianceService.performComplianceAssessment(req.adminUser, {
      standardId,
      organizationId,
      scope: scope || 'full',
      controlResponses,
      evidence: evidence || [],
      notes
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance assessment completed successfully')
    );
  });

  /**
   * Get compliance assessments
   * @route GET /api/admin/compliance/assessments
   * @access Admin - Compliance View
   */
  static getComplianceAssessments = asyncHandler(async (req, res) => {
    const {
      standardId,
      organizationId,
      status,
      dateFrom,
      dateTo,
      page = 1,
      limit = 20,
      sort = '-completionDate'
    } = req.query;

    const assessments = await ComplianceService.getComplianceAssessments({
      standardId,
      organizationId,
      status,
      dateFrom,
      dateTo,
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });

    res.status(200).json(
      responseFormatter.success(assessments, 'Compliance assessments retrieved successfully')
    );
  });

  /**
   * Get assessment details
   * @route GET /api/admin/compliance/assessments/:assessmentId
   * @access Admin - Compliance View
   */
  static getAssessmentDetails = asyncHandler(async (req, res) => {
    const { assessmentId } = req.params;
    const { includeEvidence, includeGaps } = req.query;

    if (!assessmentId) {
      throw new ValidationError('Assessment ID is required');
    }

    const assessment = await ComplianceService.getAssessmentDetails(assessmentId, {
      includeEvidence: includeEvidence === 'true',
      includeGaps: includeGaps !== 'false'
    });

    res.status(200).json(
      responseFormatter.success({ assessment }, 'Assessment details retrieved successfully')
    );
  });

  /**
   * Manage compliance gap
   * @route POST /api/admin/compliance/gaps
   * @access Admin - Compliance Manage Gaps
   */
  static manageComplianceGap = asyncHandler(async (req, res) => {
    const {
      action,
      gapId,
      status,
      remediationPlan,
      targetDate,
      assignedTo,
      notes,
      evidence
    } = req.body;

    // Validate action
    if (!action || !['update', 'close', 'reopen', 'escalate'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate gap ID
    if (!gapId) {
      throw new ValidationError('Gap ID is required');
    }

    // Validate required fields based on action
    if (action === 'close' && (!evidence || evidence.length === 0)) {
      throw new ValidationError('Evidence is required to close a compliance gap');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.gap.managed', {
      action,
      gapId,
      status
    });

    const result = await ComplianceService.manageComplianceGap(req.adminUser, {
      action,
      gapId,
      status,
      remediationPlan,
      targetDate,
      assignedTo,
      notes,
      evidence
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance gap managed successfully')
    );
  });

  /**
   * Get compliance gaps
   * @route GET /api/admin/compliance/gaps
   * @access Admin - Compliance View
   */
  static getComplianceGaps = asyncHandler(async (req, res) => {
    const {
      standardId,
      organizationId,
      status,
      severity,
      assignedTo,
      page = 1,
      limit = 20,
      sort = '-identifiedDate'
    } = req.query;

    const gaps = await ComplianceService.getComplianceGaps({
      standardId,
      organizationId,
      status,
      severity,
      assignedTo,
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });

    res.status(200).json(
      responseFormatter.success(gaps, 'Compliance gaps retrieved successfully')
    );
  });

  /**
   * Generate compliance report
   * @route POST /api/admin/compliance/reports
   * @access Admin - Compliance Generate Reports
   */
  static generateComplianceReport = asyncHandler(async (req, res) => {
    const {
      reportType,
      standardId,
      organizationId,
      dateFrom,
      dateTo,
      includeEvidence,
      format,
      export: exportReport
    } = req.body;

    // Validate report type
    const validReportTypes = ['comprehensive', 'standard', 'gap', 'remediation', 'executive'];
    if (!reportType || !validReportTypes.includes(reportType)) {
      throw new ValidationError('Valid report type is required');
    }

    // Validate required fields based on report type
    if (reportType === 'standard' && !standardId) {
      throw new ValidationError('Standard ID is required for standard-specific reports');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.report.generated', {
      reportType,
      standardId,
      organizationId,
      dateRange: !!(dateFrom || dateTo)
    });

    const report = await ComplianceService.generateComplianceReport(req.adminUser, {
      reportType,
      standardId,
      organizationId,
      dateFrom,
      dateTo,
      includeEvidence: includeEvidence || false,
      format: format || 'detailed',
      export: exportReport
    });

    res.status(200).json(
      responseFormatter.success(report, 'Compliance report generated successfully')
    );
  });

  /**
   * Get compliance reports
   * @route GET /api/admin/compliance/reports
   * @access Admin - Compliance View Reports
   */
  static getComplianceReports = asyncHandler(async (req, res) => {
    const {
      type,
      standardId,
      organizationId,
      dateFrom,
      dateTo,
      page = 1,
      limit = 20
    } = req.query;

    const reports = await ComplianceService.getComplianceReports({
      type,
      standardId,
      organizationId,
      dateFrom,
      dateTo,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(reports, 'Compliance reports retrieved successfully')
    );
  });

  /**
   * Schedule compliance activity
   * @route POST /api/admin/compliance/schedule
   * @access Admin - Compliance Schedule
   */
  static scheduleComplianceActivity = asyncHandler(async (req, res) => {
    const {
      activityType,
      standardId,
      organizationId,
      scheduledDate,
      recurrence,
      assignedTo,
      description,
      reminders
    } = req.body;

    // Validate required fields
    if (!activityType || !scheduledDate) {
      throw new ValidationError('Activity type and scheduled date are required');
    }

    // Validate activity type
    const validActivityTypes = ['assessment', 'audit', 'review', 'training', 'certification'];
    if (!validActivityTypes.includes(activityType)) {
      throw new ValidationError('Invalid activity type');
    }

    // Validate scheduled date
    const schedDate = new Date(scheduledDate);
    if (schedDate <= new Date()) {
      throw new ValidationError('Scheduled date must be in the future');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.activity.scheduled', {
      activityType,
      standardId,
      organizationId,
      scheduledDate
    });

    const result = await ComplianceService.scheduleComplianceActivity(req.adminUser, {
      activityType,
      standardId,
      organizationId,
      scheduledDate,
      recurrence,
      assignedTo,
      description,
      reminders: reminders !== false
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance activity scheduled successfully')
    );
  });

  /**
   * Get compliance schedule
   * @route GET /api/admin/compliance/schedule
   * @access Admin - Compliance View
   */
  static getComplianceSchedule = asyncHandler(async (req, res) => {
    const {
      activityType,
      standardId,
      organizationId,
      assignedTo,
      dateFrom,
      dateTo,
      status,
      page = 1,
      limit = 20
    } = req.query;

    const schedule = await ComplianceService.getComplianceSchedule({
      activityType,
      standardId,
      organizationId,
      assignedTo,
      dateFrom,
      dateTo,
      status,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(schedule, 'Compliance schedule retrieved successfully')
    );
  });

  /**
   * Manage compliance evidence
   * @route POST /api/admin/compliance/evidence
   * @access Admin - Compliance Manage Evidence
   */
  static manageComplianceEvidence = asyncHandler(async (req, res) => {
    const {
      action,
      evidenceId,
      type,
      relatedTo,
      relatedId,
      title,
      description,
      files,
      metadata,
      tags,
      notes
    } = req.body;

    // Validate action
    if (!action || !['upload', 'update', 'verify', 'archive'].includes(action)) {
      throw new ValidationError('Valid action is required');
    }

    // Validate required fields based on action
    if (action === 'upload') {
      if (!type || !relatedTo || !relatedId || !title) {
        throw new ValidationError('Type, relatedTo, relatedId, and title are required');
      }
      if (!files || files.length === 0) {
        throw new ValidationError('At least one file is required for upload');
      }
    } else if (!evidenceId) {
      throw new ValidationError('Evidence ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.evidence.managed', {
      action,
      evidenceId,
      type,
      relatedTo,
      filesCount: files?.length
    });

    const result = await ComplianceService.manageComplianceEvidence(req.adminUser, {
      action,
      evidenceId,
      type,
      relatedTo,
      relatedId,
      title,
      description,
      files,
      metadata,
      tags,
      notes
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance evidence managed successfully')
    );
  });

  /**
   * Get compliance evidence
   * @route GET /api/admin/compliance/evidence
   * @access Admin - Compliance View
   */
  static getComplianceEvidence = asyncHandler(async (req, res) => {
    const {
      type,
      relatedTo,
      relatedId,
      verified,
      tags,
      page = 1,
      limit = 20
    } = req.query;

    const evidence = await ComplianceService.getComplianceEvidence({
      type,
      relatedTo,
      relatedId,
      verified: verified === 'true' ? true : verified === 'false' ? false : undefined,
      tags: tags ? tags.split(',') : undefined,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(evidence, 'Compliance evidence retrieved successfully')
    );
  });

  /**
   * Get compliance dashboard
   * @route GET /api/admin/compliance/dashboard
   * @access Admin - Compliance View
   */
  static getComplianceDashboard = asyncHandler(async (req, res) => {
    const { organizationId, timeRange, standardId } = req.query;

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.dashboard.viewed', {
      organizationId,
      timeRange,
      standardId
    });

    const dashboard = await ComplianceService.getComplianceDashboard(req.adminUser, {
      organizationId,
      timeRange: timeRange || '30d',
      standardId
    });

    res.status(200).json(
      responseFormatter.success(dashboard, 'Compliance dashboard retrieved successfully')
    );
  });

  /**
   * Update compliance control
   * @route PUT /api/admin/compliance/controls/:controlId
   * @access Admin - Compliance Manage
   */
  static updateComplianceControl = asyncHandler(async (req, res) => {
    const { controlId } = req.params;
    const {
      title,
      description,
      category,
      requirements,
      testingProcedures,
      implementationGuidance,
      severity
    } = req.body;

    if (!controlId) {
      throw new ValidationError('Control ID is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.control.updated', {
      controlId,
      fieldsUpdated: Object.keys(req.body)
    });

    const result = await ComplianceService.updateComplianceControl(req.adminUser, controlId, {
      title,
      description,
      category,
      requirements,
      testingProcedures,
      implementationGuidance,
      severity
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance control updated successfully')
    );
  });

  /**
   * Get compliance controls
   * @route GET /api/admin/compliance/controls
   * @access Admin - Compliance View
   */
  static getComplianceControls = asyncHandler(async (req, res) => {
    const {
      standardId,
      category,
      severity,
      search,
      page = 1,
      limit = 50
    } = req.query;

    const controls = await ComplianceService.getComplianceControls({
      standardId,
      category,
      severity,
      search,
      page: parseInt(page),
      limit: parseInt(limit)
    });

    res.status(200).json(
      responseFormatter.success(controls, 'Compliance controls retrieved successfully')
    );
  });

  /**
   * Import compliance standard
   * @route POST /api/admin/compliance/import
   * @access Admin - Compliance Manage
   */
  static importComplianceStandard = asyncHandler(async (req, res) => {
    const { format, data, file, overwrite } = req.body;

    // Validate format
    const validFormats = ['json', 'xml', 'csv'];
    if (!format || !validFormats.includes(format)) {
      throw new ValidationError('Valid import format is required');
    }

    // Validate data source
    if (!data && !file) {
      throw new ValidationError('Either data or file is required for import');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.standard.imported', {
      format,
      overwrite
    });

    const result = await ComplianceService.importComplianceStandard(req.adminUser, {
      format,
      data,
      file,
      overwrite: overwrite || false
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance standard imported successfully')
    );
  });

  /**
   * Export compliance data
   * @route POST /api/admin/compliance/export
   * @access Admin - Compliance Export
   */
  static exportComplianceData = asyncHandler(async (req, res) => {
    const {
      dataType,
      standardId,
      organizationId,
      format,
      dateFrom,
      dateTo
    } = req.body;

    // Validate data type
    const validDataTypes = ['standards', 'assessments', 'gaps', 'evidence', 'reports'];
    if (!dataType || !validDataTypes.includes(dataType)) {
      throw new ValidationError('Valid data type is required');
    }

    // Track admin activity
    await AdminActivityTracker.track(req.adminUser, 'compliance.data.exported', {
      dataType,
      format,
      hasFilters: !!(standardId || organizationId || dateFrom || dateTo)
    });

    const result = await ComplianceService.exportComplianceData(req.adminUser, {
      dataType,
      standardId,
      organizationId,
      format: format || 'csv',
      dateFrom,
      dateTo
    });

    res.status(200).json(
      responseFormatter.success(result, 'Compliance data export initiated successfully')
    );
  });

  /**
   * Get compliance statistics
   * @route GET /api/admin/compliance/statistics
   * @access Admin - Compliance View
   */
  static getComplianceStatistics = asyncHandler(async (req, res) => {
    const {
      organizationId,
      standardId,
      timeRange,
      groupBy
    } = req.query;

    const statistics = await ComplianceService.getComplianceStatistics({
      organizationId,
      standardId,
      timeRange: timeRange || '90d',
      groupBy: groupBy || 'standard'
    });

    res.status(200).json(
      responseFormatter.success(statistics, 'Compliance statistics retrieved successfully')
    );
  });
}

module.exports = ComplianceController;