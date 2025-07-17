// server/admin/organization-management/controllers/organization-analytics-controller.js
/**
 * @file Organization Analytics Controller
 * @description Controller for organization analytics and reporting endpoints
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const OrganizationAnalyticsService = require('../services/organization-analytics-service');
const AdminOrganizationService = require('../services/admin-organization-service');
const SubscriptionManagementService = require('../services/subscription-management-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizer');
const ResponseFormatter = require('../../../shared/utils/response-formatter');
const ExportHelper = require('../../../shared/utils/export-helper');

// Validation
const {
  validateAnalyticsQuery,
  validateReportConfig,
  validateComparisonQuery,
  validateGrowthQuery,
  validatePerformanceQuery,
  validatePredictiveQuery,
  validateCustomEvent
} = require('../validation/analytics-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * Organization Analytics Controller Class
 * @class OrganizationAnalyticsController
 */
class OrganizationAnalyticsController {
  /**
   * Get comprehensive organization analytics
   * @route GET /api/admin/analytics/organizations/:organizationId
   * @access Admin
   */
  getOrganizationAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate query parameters
      const { error, value } = validateAnalyticsQuery(req.query);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const options = sanitizeQuery(value);
      
      const analytics = await OrganizationAnalyticsService.getOrganizationAnalytics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          analytics,
          'Organization analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getOrganizationAnalytics:', error);
      next(error);
    }
  });

  /**
   * Generate organization report
   * @route POST /api/admin/analytics/organizations/:organizationId/report
   * @access Admin
   */
  generateOrganizationReport = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate report configuration
      const { error, value } = validateReportConfig(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const reportConfig = sanitizeBody(value);
      
      const report = await OrganizationAnalyticsService.generateOrganizationReport(
        organizationId,
        reportConfig,
        req.user
      );
      
      // Handle different output formats
      if (reportConfig.format === 'pdf') {
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="organization_report_${organizationId}_${Date.now()}.pdf"`);
        res.send(report.pdfBuffer);
      } else if (reportConfig.format === 'excel') {
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="organization_report_${organizationId}_${Date.now()}.xlsx"`);
        res.send(report.excelBuffer);
      } else {
        res.status(200).json(
          ResponseFormatter.success(
            report,
            'Organization report generated successfully'
          )
        );
      }
    } catch (error) {
      logger.error('Error in generateOrganizationReport:', error);
      next(error);
    }
  });

  /**
   * Compare multiple organizations
   * @route POST /api/admin/analytics/organizations/compare
   * @access Admin
   */
  compareOrganizations = asyncHandler(async (req, res, next) => {
    try {
      // Validate comparison query
      const { error, value } = validateComparisonQuery(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const { organizationIds, config } = sanitizeBody(value);
      
      // Validate all organization IDs
      organizationIds.forEach(id => {
        if (!mongoose.isValidObjectId(id)) {
          throw new ValidationError(`Invalid organization ID: ${id}`);
        }
      });
      
      const comparison = await OrganizationAnalyticsService.compareOrganizations(
        organizationIds,
        config,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          comparison,
          'Organization comparison completed successfully'
        )
      );
    } catch (error) {
      logger.error('Error in compareOrganizations:', error);
      next(error);
    }
  });

  /**
   * Get organization growth analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/growth
   * @access Admin
   */
  getGrowthAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate growth query
      const { error, value } = validateGrowthQuery(req.query);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const options = sanitizeQuery(value);
      
      const growthAnalytics = await OrganizationAnalyticsService.getGrowthAnalytics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          growthAnalytics,
          'Growth analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getGrowthAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get performance metrics
   * @route GET /api/admin/analytics/organizations/:organizationId/performance
   * @access Admin
   */
  getPerformanceMetrics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate performance query
      const { error, value } = validatePerformanceQuery(req.query);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const options = sanitizeQuery(value);
      
      const performanceMetrics = await OrganizationAnalyticsService.getPerformanceMetrics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          performanceMetrics,
          'Performance metrics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getPerformanceMetrics:', error);
      next(error);
    }
  });

  /**
   * Get predictive analytics
   * @route POST /api/admin/analytics/organizations/:organizationId/predict
   * @access Admin - Platform Admin or higher
   */
  getPredictiveAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate predictive query
      const { error, value } = validatePredictiveQuery(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const predictionConfig = sanitizeBody(value);
      
      const predictions = await OrganizationAnalyticsService.getPredictiveAnalytics(
        organizationId,
        predictionConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          predictions,
          'Predictive analytics generated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getPredictiveAnalytics:', error);
      next(error);
    }
  });

  /**
   * Track custom analytics event
   * @route POST /api/admin/analytics/organizations/:organizationId/track
   * @access Admin
   */
  trackAnalyticsEvent = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate custom event
      const { error, value } = validateCustomEvent(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const eventData = sanitizeBody(value);
      
      const result = await OrganizationAnalyticsService.trackAnalyticsEvent(
        organizationId,
        eventData,
        req.user
      );
      
      res.status(201).json(
        ResponseFormatter.success(
          result,
          'Analytics event tracked successfully'
        )
      );
    } catch (error) {
      logger.error('Error in trackAnalyticsEvent:', error);
      next(error);
    }
  });

  /**
   * Get engagement analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/engagement
   * @access Admin
   */
  getEngagementAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const query = sanitizeQuery(req.query);
      
      const options = {
        period: query.period || 'month',
        startDate: query.startDate,
        endDate: query.endDate,
        metrics: query.metrics ? query.metrics.split(',') : null,
        groupBy: query.groupBy || 'day'
      };
      
      const engagement = await OrganizationAnalyticsService.getEngagementAnalytics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          engagement,
          'Engagement analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getEngagementAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get usage analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/usage
   * @access Admin
   */
  getUsageAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const query = sanitizeQuery(req.query);
      
      const options = {
        period: query.period || 'month',
        startDate: query.startDate,
        endDate: query.endDate,
        resources: query.resources ? query.resources.split(',') : null,
        includeProjections: query.includeProjections === 'true'
      };
      
      const usage = await OrganizationAnalyticsService.getUsageAnalytics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          usage,
          'Usage analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getUsageAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get financial analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/financial
   * @access Admin
   */
  getFinancialAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const query = sanitizeQuery(req.query);
      
      const options = {
        period: query.period || 'month',
        startDate: query.startDate,
        endDate: query.endDate,
        includeForecasts: query.includeForecasts === 'true',
        includeBenchmarks: query.includeBenchmarks === 'true'
      };
      
      const financial = await OrganizationAnalyticsService.getFinancialAnalytics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          financial,
          'Financial analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getFinancialAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get retention analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/retention
   * @access Admin
   */
  getRetentionAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const query = sanitizeQuery(req.query);
      
      const options = {
        cohortType: query.cohortType || 'monthly',
        startDate: query.startDate,
        endDate: query.endDate,
        includeCohortAnalysis: query.includeCohortAnalysis !== 'false'
      };
      
      const retention = await OrganizationAnalyticsService.getRetentionAnalytics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          retention,
          'Retention analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getRetentionAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get churn analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/churn
   * @access Admin
   */
  getChurnAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const query = sanitizeQuery(req.query);
      
      const options = {
        period: query.period || 'quarter',
        includePredictions: query.includePredictions === 'true',
        includeReasons: query.includeReasons !== 'false'
      };
      
      const churn = await OrganizationAnalyticsService.getChurnAnalytics(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          churn,
          'Churn analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getChurnAnalytics:', error);
      next(error);
    }
  });

  /**
   * Export analytics data
   * @route POST /api/admin/analytics/organizations/:organizationId/export
   * @access Admin
   */
  exportAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const exportConfig = sanitizeBody(req.body);
      
      const exportData = await OrganizationAnalyticsService.exportAnalytics(
        organizationId,
        exportConfig,
        req.user
      );
      
      // Set appropriate headers based on format
      const format = exportConfig.format || 'csv';
      const filename = `analytics_export_${organizationId}_${Date.now()}.${format}`;
      
      res.setHeader('Content-Type', ExportHelper.getContentType(format));
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      
      res.send(exportData.data);
    } catch (error) {
      logger.error('Error in exportAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get real-time analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/realtime
   * @access Admin
   */
  getRealTimeAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const realTimeData = await OrganizationAnalyticsService.getRealTimeAnalytics(
        organizationId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          realTimeData,
          'Real-time analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getRealTimeAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get analytics dashboard data
   * @route GET /api/admin/analytics/dashboard
   * @access Admin
   */
  getAnalyticsDashboard = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      const dashboardConfig = {
        period: query.period || 'week',
        widgets: query.widgets ? query.widgets.split(',') : null,
        organizationFilter: query.organizationId,
        planFilter: query.plan,
        statusFilter: query.status
      };
      
      const dashboard = await OrganizationAnalyticsService.getAnalyticsDashboard(
        dashboardConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          dashboard,
          'Analytics dashboard data retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getAnalyticsDashboard:', error);
      next(error);
    }
  });

  /**
   * Get cohort analysis
   * @route GET /api/admin/analytics/organizations/:organizationId/cohorts
   * @access Admin
   */
  getCohortAnalysis = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const query = sanitizeQuery(req.query);
      
      const cohortConfig = {
        cohortType: query.cohortType || 'signup_month',
        metric: query.metric || 'retention',
        startDate: query.startDate,
        endDate: query.endDate,
        segmentBy: query.segmentBy
      };
      
      const cohortAnalysis = await OrganizationAnalyticsService.getCohortAnalysis(
        organizationId,
        cohortConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          cohortAnalysis,
          'Cohort analysis retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getCohortAnalysis:', error);
      next(error);
    }
  });

  /**
   * Get funnel analytics
   * @route POST /api/admin/analytics/organizations/:organizationId/funnel
   * @access Admin
   */
  getFunnelAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const funnelConfig = sanitizeBody(req.body);
      
      if (!Array.isArray(funnelConfig.steps) || funnelConfig.steps.length < 2) {
        throw new ValidationError('At least 2 funnel steps are required');
      }
      
      const funnelAnalysis = await OrganizationAnalyticsService.getFunnelAnalytics(
        organizationId,
        funnelConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          funnelAnalysis,
          'Funnel analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getFunnelAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get benchmark analytics
   * @route GET /api/admin/analytics/organizations/:organizationId/benchmarks
   * @access Admin
   */
  getBenchmarkAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const query = sanitizeQuery(req.query);
      
      const benchmarkConfig = {
        compareWith: query.compareWith || 'industry', // industry, size, plan
        metrics: query.metrics ? query.metrics.split(',') : null,
        period: query.period || 'quarter'
      };
      
      const benchmarks = await OrganizationAnalyticsService.getBenchmarkAnalytics(
        organizationId,
        benchmarkConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          benchmarks,
          'Benchmark analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getBenchmarkAnalytics:', error);
      next(error);
    }
  });

  /**
   * Schedule analytics report
   * @route POST /api/admin/analytics/schedule-report
   * @access Admin - Platform Admin or higher
   */
  scheduleAnalyticsReport = asyncHandler(async (req, res, next) => {
    try {
      const scheduleConfig = sanitizeBody(req.body);
      
      if (!scheduleConfig.recipients || scheduleConfig.recipients.length === 0) {
        throw new ValidationError('At least one recipient is required');
      }
      
      const schedule = await OrganizationAnalyticsService.scheduleAnalyticsReport(
        scheduleConfig,
        req.user
      );
      
      res.status(201).json(
        ResponseFormatter.success(
          schedule,
          'Analytics report scheduled successfully'
        )
      );
    } catch (error) {
      logger.error('Error in scheduleAnalyticsReport:', error);
      next(error);
    }
  });

  /**
   * Get scheduled reports
   * @route GET /api/admin/analytics/scheduled-reports
   * @access Admin
   */
  getScheduledReports = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      const filters = {
        status: query.status,
        createdBy: query.createdBy,
        organizationId: query.organizationId,
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 20
      };
      
      const scheduledReports = await OrganizationAnalyticsService.getScheduledReports(
        filters,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          scheduledReports,
          'Scheduled reports retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getScheduledReports:', error);
      next(error);
    }
  });

  /**
   * Update scheduled report
   * @route PUT /api/admin/analytics/scheduled-reports/:scheduleId
   * @access Admin
   */
  updateScheduledReport = asyncHandler(async (req, res, next) => {
    try {
      const { scheduleId } = req.params;
      
      if (!mongoose.isValidObjectId(scheduleId)) {
        throw new ValidationError('Invalid schedule ID');
      }
      
      const updates = sanitizeBody(req.body);
      
      const schedule = await OrganizationAnalyticsService.updateScheduledReport(
        scheduleId,
        updates,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          schedule,
          'Scheduled report updated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in updateScheduledReport:', error);
      next(error);
    }
  });

  /**
   * Delete scheduled report
   * @route DELETE /api/admin/analytics/scheduled-reports/:scheduleId
   * @access Admin
   */
  deleteScheduledReport = asyncHandler(async (req, res, next) => {
    try {
      const { scheduleId } = req.params;
      
      if (!mongoose.isValidObjectId(scheduleId)) {
        throw new ValidationError('Invalid schedule ID');
      }
      
      await OrganizationAnalyticsService.deleteScheduledReport(
        scheduleId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          null,
          'Scheduled report deleted successfully'
        )
      );
    } catch (error) {
      logger.error('Error in deleteScheduledReport:', error);
      next(error);
    }
  });
}

module.exports = new OrganizationAnalyticsController();