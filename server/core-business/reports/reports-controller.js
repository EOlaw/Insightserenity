// server/core-business/reports/controllers/reports-controller.js
/**
 * @file Reports Controller
 * @description Handles HTTP requests for reports management
 * @version 3.0.0
 */

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { 
  ValidationError, 
  NotFoundError,
  ForbiddenError,
  BusinessRuleError 
} = require('../../../shared/utils/app-error');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const logger = require('../../../shared/utils/logger');
const responseHandler = require('../../../shared/utils/response-handler');
const ReportsService = require('../services/reports-service');
const FileService = require('../../../shared/services/file-service');

/**
 * Reports Controller Class
 * @class ReportsController
 */
class ReportsController {
  /**
   * Create new report
   * @route   POST /api/reports
   * @access  Private - Manager, Admin
   */
  static createReport = asyncHandler(async (req, res) => {
    const reportData = {
      name: req.body.name,
      slug: req.body.slug,
      description: req.body.description,
      type: req.body.type,
      category: req.body.category,
      subCategory: req.body.subCategory,
      dataSources: req.body.dataSources,
      parameters: req.body.parameters,
      filters: req.body.filters,
      query: req.body.query,
      visualizations: req.body.visualizations,
      layout: req.body.layout,
      schedule: req.body.schedule,
      access: req.body.access,
      exportConfig: req.body.exportConfig,
      performance: req.body.performance,
      metadata: req.body.metadata
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current || req.body.organizationId,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    if (!context.organizationId) {
      throw new ValidationError('Organization context is required');
    }
    
    const report = await ReportsService.createReport(reportData, context);
    
    responseHandler.success(res, { report }, 'Report created successfully', 201);
  });
  
  /**
   * Get report by ID
   * @route   GET /api/reports/:reportId
   * @access  Private
   */
  static getReport = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const { 
      includeExecutionStatus = false,
      includeLastData = false 
    } = req.query;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const options = {
      populate: [
        { path: 'metadata.createdBy', select: 'firstName lastName email' },
        { path: 'metadata.lastModifiedBy', select: 'firstName lastName email' }
      ],
      includeExecutionStatus: includeExecutionStatus === 'true',
      includeLastData: includeLastData === 'true'
    };
    
    const report = await ReportsService.getReportById(reportId, context, options);
    
    responseHandler.success(res, { report }, 'Report retrieved successfully');
  });
  
  /**
   * Update report
   * @route   PUT /api/reports/:reportId
   * @access  Private - Report Owner, Admin
   */
  static updateReport = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const updateData = req.body;
    
    // Remove system fields from update
    delete updateData._id;
    delete updateData.reportId;
    delete updateData.createdAt;
    delete updateData.updatedAt;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const updatedReport = await ReportsService.updateReport(reportId, updateData, context);
    
    responseHandler.success(res, { report: updatedReport }, 'Report updated successfully');
  });
  
  /**
   * Delete report
   * @route   DELETE /api/reports/:reportId
   * @access  Private - Report Owner, Admin
   */
  static deleteReport = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const { reason } = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin',
      reason
    };
    
    await ReportsService.deleteReport(reportId, context);
    
    responseHandler.success(res, null, 'Report deleted successfully');
  });
  
  /**
   * List reports
   * @route   GET /api/reports
   * @access  Private
   */
  static listReports = asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 20,
      sort = '-createdAt',
      search,
      type,
      category,
      status,
      createdBy,
      tags,
      createdAfter,
      createdBefore
    } = req.query;
    
    const filters = {
      type,
      category,
      status,
      createdBy,
      tags: tags ? tags.split(',') : undefined,
      createdAfter,
      createdBefore
    };
    
    // Remove undefined values
    Object.keys(filters).forEach(key => 
      filters[key] === undefined && delete filters[key]
    );
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      roles: [req.user.role?.primary, ...(req.user.role?.secondary || [])],
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort,
      search
    };
    
    const result = await ReportsService.listReports(filters, context, options);
    
    responseHandler.success(res, result, 'Reports retrieved successfully');
  });
  
  /**
   * Execute report
   * @route   POST /api/reports/:reportId/execute
   * @access  Private
   */
  static executeReport = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const { 
      parameters = {},
      format,
      synchronous = false
    } = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin',
      synchronous: synchronous === true || synchronous === 'true',
      priority: req.user.subscription?.priority || 'normal'
    };
    
    const result = await ReportsService.executeReport(reportId, parameters, context);
    
    // For synchronous execution with format, handle export
    if (context.synchronous && format) {
      const exportResult = await ReportsService.exportReport(
        reportId, 
        format, 
        { data: result.data }, 
        context
      );
      
      responseHandler.success(res, {
        execution: result,
        export: exportResult
      }, 'Report executed and exported successfully');
    } else {
      responseHandler.success(res, result, 'Report execution initiated');
    }
  });
  
  /**
   * Get report execution status
   * @route   GET /api/reports/:reportId/executions/:executionId
   * @access  Private
   */
  static getExecutionStatus = asyncHandler(async (req, res) => {
    const { reportId, executionId } = req.params;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions
    };
    
    const report = await ReportsService.getReportById(reportId, context);
    
    const execution = report.executions.find(e => e.executionId === executionId);
    
    if (!execution) {
      throw new NotFoundError('Execution not found');
    }
    
    responseHandler.success(res, { execution }, 'Execution status retrieved');
  });
  
  /**
   * Export report
   * @route   POST /api/reports/:reportId/export
   * @access  Private
   */
  static exportReport = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const {
      format = 'pdf',
      parameters,
      executeFirst = false,
      options = {}
    } = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const exportOptions = {
      ...options,
      executeFirst: executeFirst === true || executeFirst === 'true',
      parameters
    };
    
    const result = await ReportsService.exportReport(reportId, format, exportOptions, context);
    
    // If client wants to download immediately
    if (req.query.download === 'true') {
      const file = await FileService.getFile(result.filePath);
      res.setHeader('Content-Type', result.mimeType);
      res.setHeader('Content-Disposition', `attachment; filename="${result.filename}"`);
      res.setHeader('Content-Length', result.size);
      return res.send(file);
    }
    
    responseHandler.success(res, result, 'Report exported successfully');
  });
  
  /**
   * Share report
   * @route   POST /api/reports/:reportId/share
   * @access  Private
   */
  static shareReport = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const {
      recipients,
      permissions = 'view',
      message,
      expiresAt,
      makePublic = false
    } = req.body;
    
    if (!recipients || recipients.length === 0) {
      throw new ValidationError('At least one recipient is required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const shareData = {
      recipients,
      permissions,
      message,
      expiresAt,
      makePublic
    };
    
    const result = await ReportsService.shareReport(reportId, shareData, context);
    
    responseHandler.success(res, result, 'Report shared successfully');
  });
  
  /**
   * Unshare report
   * @route   DELETE /api/reports/:reportId/share/:userId
   * @access  Private
   */
  static unshareReport = asyncHandler(async (req, res) => {
    const { reportId, userId } = req.params;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const report = await ReportsService.getReportById(reportId, context);
    
    // Check permission
    if (report.metadata.createdBy.toString() !== context.userId && !context.isAdmin) {
      throw new ForbiddenError('Permission denied to modify sharing');
    }
    
    // Remove sharing
    report.sharing.sharedWith = report.sharing.sharedWith.filter(
      share => share.user?.toString() !== userId
    );
    
    await report.save();
    
    responseHandler.success(res, null, 'Report unshared successfully');
  });
  
  /**
   * Clone report
   * @route   POST /api/reports/:reportId/clone
   * @access  Private
   */
  static cloneReport = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const {
      name,
      includeSchedule = false,
      includeSharing = false,
      targetOrganization
    } = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: targetOrganization || req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const options = {
      name,
      includeSchedule,
      includeSharing
    };
    
    const clonedReport = await ReportsService.cloneReport(reportId, options, context);
    
    responseHandler.success(res, { report: clonedReport }, 'Report cloned successfully', 201);
  });
  
  /**
   * Update report schedule
   * @route   PUT /api/reports/:reportId/schedule
   * @access  Private
   */
  static updateSchedule = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const scheduleData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    // Update report with new schedule
    const updateData = { schedule: scheduleData };
    const updatedReport = await ReportsService.updateReport(reportId, updateData, context);
    
    responseHandler.success(res, 
      { schedule: updatedReport.schedule }, 
      scheduleData.isActive ? 'Schedule updated successfully' : 'Schedule disabled'
    );
  });
  
  /**
   * Get report templates
   * @route   GET /api/reports/templates
   * @access  Private
   */
  static getTemplates = asyncHandler(async (req, res) => {
    const {
      category,
      type,
      search
    } = req.query;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions
    };
    
    // This would fetch from a templates collection or predefined templates
    const templates = await ReportsService.getReportTemplates({ category, type, search }, context);
    
    responseHandler.success(res, { templates }, 'Templates retrieved successfully');
  });
  
  /**
   * Create report from template
   * @route   POST /api/reports/from-template
   * @access  Private
   */
  static createFromTemplate = asyncHandler(async (req, res) => {
    const {
      templateId,
      name,
      customizations = {}
    } = req.body;
    
    if (!templateId) {
      throw new ValidationError('Template ID is required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const report = await ReportsService.createReportFromTemplate(
      templateId,
      { name, ...customizations },
      context
    );
    
    responseHandler.success(res, { report }, 'Report created from template successfully', 201);
  });
  
  /**
   * Get report statistics
   * @route   GET /api/reports/statistics
   * @access  Private
   */
  static getStatistics = asyncHandler(async (req, res) => {
    const {
      startDate,
      endDate,
      groupBy = 'category'
    } = req.query;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const filters = {
      startDate,
      endDate,
      groupBy
    };
    
    const statistics = await ReportsService.getReportStatistics(filters, context);
    
    responseHandler.success(res, { statistics }, 'Statistics retrieved successfully');
  });
  
  /**
   * Get report activity log
   * @route   GET /api/reports/:reportId/activity
   * @access  Private
   */
  static getActivityLog = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const {
      page = 1,
      limit = 50,
      startDate,
      endDate,
      action
    } = req.query;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const report = await ReportsService.getReportById(reportId, context);
    
    // Get audit logs for this report
    const activityLog = await AuditService.getResourceLogs({
      resourceType: 'report',
      resourceId: report._id,
      startDate,
      endDate,
      action,
      page: parseInt(page),
      limit: parseInt(limit)
    });
    
    responseHandler.success(res, activityLog, 'Activity log retrieved successfully');
  });
  
  /**
   * Test report query
   * @route   POST /api/reports/test-query
   * @access  Private - Admin
   */
  static testQuery = asyncHandler(async (req, res) => {
    const {
      dataSource,
      query,
      parameters = {},
      limit = 10
    } = req.body;
    
    if (!dataSource || !query) {
      throw new ValidationError('Data source and query are required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    // Only allow admins or report creators to test queries
    if (!context.isAdmin && !req.user.permissions?.includes('report.create')) {
      throw new ForbiddenError('Permission denied to test queries');
    }
    
    const result = await ReportsService.testReportQuery(
      { dataSource, query, parameters, limit },
      context
    );
    
    responseHandler.success(res, result, 'Query tested successfully');
  });
  
  /**
   * Get report access log
   * @route   GET /api/reports/:reportId/access-log
   * @access  Private - Report Owner, Admin
   */
  static getAccessLog = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const {
      page = 1,
      limit = 50,
      userId,
      action,
      startDate,
      endDate
    } = req.query;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const report = await ReportsService.getReportById(reportId, context);
    
    // Check if user has permission to view access logs
    if (report.metadata.createdBy.toString() !== context.userId && !context.isAdmin) {
      throw new ForbiddenError('Permission denied to view access logs');
    }
    
    const accessLog = await ReportsService.getReportAccessLog(reportId, {
      page: parseInt(page),
      limit: parseInt(limit),
      userId,
      action,
      startDate,
      endDate
    });
    
    responseHandler.success(res, accessLog, 'Access log retrieved successfully');
  });
  
  /**
   * Update report access
   * @route   PUT /api/reports/:reportId/access
   * @access  Private - Report Owner, Admin
   */
  static updateAccess = asyncHandler(async (req, res) => {
    const { reportId } = req.params;
    const accessData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const report = await ReportsService.getReportById(reportId, context);
    
    // Check permission
    if (report.metadata.createdBy.toString() !== context.userId && !context.isAdmin) {
      throw new ForbiddenError('Permission denied to update access control');
    }
    
    // Update access control
    const updateData = { access: accessData };
    const updatedReport = await ReportsService.updateReport(reportId, updateData, context);
    
    responseHandler.success(res, 
      { access: updatedReport.access }, 
      'Access control updated successfully'
    );
  });
  
  /**
   * Bulk operations on reports
   * @route   POST /api/reports/bulk
   * @access  Private - Admin
   */
  static bulkOperation = asyncHandler(async (req, res) => {
    const {
      operation,
      reportIds,
      data
    } = req.body;
    
    if (!operation || !reportIds || reportIds.length === 0) {
      throw new ValidationError('Operation and report IDs are required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    // Only admins can perform bulk operations
    if (!context.isAdmin && !req.user.permissions?.includes('report.bulk')) {
      throw new ForbiddenError('Permission denied for bulk operations');
    }
    
    const result = await ReportsService.bulkOperation(operation, reportIds, data, context);
    
    responseHandler.success(res, result, `Bulk ${operation} completed successfully`);
  });
}

module.exports = ReportsController;