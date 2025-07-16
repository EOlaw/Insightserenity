// server/admin/user-management/controllers/user-analytics-controller.js
/**
 * @file User Analytics Controller
 * @description Controller for handling user analytics and reporting operations
 * @version 1.0.0
 */

// Services
const UserAnalyticsService = require('../services/user-analytics-service');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');

// Utilities
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizers');
const ResponseFormatter = require('../../../shared/utils/response-formatter');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * User Analytics Controller Class
 */
class UserAnalyticsController {
  /**
   * Get user analytics dashboard
   * @route GET /api/admin/users/analytics/dashboard
   */
  getAnalyticsDashboard = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate time range
    const allowedTimeRanges = ['last24h', 'last7d', 'last30d', 'last90d', 'last365d', 'custom'];
    const timeRange = queryParams.timeRange || 'last30d';
    
    if (!allowedTimeRanges.includes(timeRange)) {
      throw new ValidationError(`Invalid time range. Allowed values: ${allowedTimeRanges.join(', ')}`);
    }

    // Validate custom date range if provided
    if (timeRange === 'custom') {
      if (!queryParams.startDate || !queryParams.endDate) {
        throw new ValidationError('Start date and end date are required for custom time range');
      }

      const startDate = new Date(queryParams.startDate);
      const endDate = new Date(queryParams.endDate);

      if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
        throw new ValidationError('Invalid date format');
      }

      if (startDate >= endDate) {
        throw new ValidationError('Start date must be before end date');
      }

      // Maximum 1 year range
      const maxRange = 365 * 24 * 60 * 60 * 1000;
      if (endDate - startDate > maxRange) {
        throw new ValidationError('Date range cannot exceed 1 year');
      }
    }

    // Validate organization ID if provided
    if (queryParams.organizationId && !AdminHelpers.isValidObjectId(queryParams.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    const options = {
      timeRange,
      startDate: queryParams.startDate,
      endDate: queryParams.endDate,
      organizationId: queryParams.organizationId,
      compareWithPrevious: queryParams.compareWithPrevious !== 'false',
      includeForecasts: queryParams.includeForecasts === 'true',
      skipCache: queryParams.skipCache === 'true'
    };

    // Get analytics dashboard
    const dashboard = await UserAnalyticsService.getUserAnalyticsDashboard(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(dashboard, 'Analytics dashboard retrieved successfully')
    );
  });

  /**
   * Get user growth analytics
   * @route GET /api/admin/users/analytics/growth
   */
  getUserGrowthAnalytics = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate date range
    const startDate = queryParams.startDate ? new Date(queryParams.startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = queryParams.endDate ? new Date(queryParams.endDate) : new Date();

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      throw new ValidationError('Invalid date format');
    }

    if (startDate >= endDate) {
      throw new ValidationError('Start date must be before end date');
    }

    // Validate granularity
    const allowedGranularities = ['hour', 'day', 'week', 'month'];
    const granularity = queryParams.granularity || 'day';
    
    if (!allowedGranularities.includes(granularity)) {
      throw new ValidationError(`Invalid granularity. Allowed values: ${allowedGranularities.join(', ')}`);
    }

    // Validate segment by
    const allowedSegments = ['role', 'organization', 'source', 'country', 'plan'];
    if (queryParams.segmentBy && !allowedSegments.includes(queryParams.segmentBy)) {
      throw new ValidationError(`Invalid segment. Allowed values: ${allowedSegments.join(', ')}`);
    }

    const options = {
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      granularity,
      segmentBy: queryParams.segmentBy,
      includeChurn: queryParams.includeChurn !== 'false'
    };

    // Get growth analytics
    const analytics = await UserAnalyticsService.getUserGrowthAnalytics(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analytics, 'Growth analytics retrieved successfully')
    );
  });

  /**
   * Get user engagement analytics
   * @route GET /api/admin/users/analytics/engagement
   */
  getUserEngagementAnalytics = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate time range
    const allowedTimeRanges = ['last24h', 'last7d', 'last30d', 'last90d'];
    const timeRange = queryParams.timeRange || 'last30d';
    
    if (!allowedTimeRanges.includes(timeRange)) {
      throw new ValidationError(`Invalid time range. Allowed values: ${allowedTimeRanges.join(', ')}`);
    }

    // Validate engagement metrics
    const allowedMetrics = ['dau', 'wau', 'mau', 'stickiness', 'sessions', 'actions'];
    let engagementMetrics = ['dau', 'wau', 'mau', 'stickiness'];
    
    if (queryParams.metrics) {
      const requestedMetrics = queryParams.metrics.split(',').map(m => m.trim());
      const invalidMetrics = requestedMetrics.filter(m => !allowedMetrics.includes(m));
      
      if (invalidMetrics.length > 0) {
        throw new ValidationError(`Invalid metrics: ${invalidMetrics.join(', ')}`);
      }
      
      engagementMetrics = requestedMetrics;
    }

    // Validate organization ID if provided
    if (queryParams.organizationId && !AdminHelpers.isValidObjectId(queryParams.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    const options = {
      timeRange,
      engagementMetrics,
      activityTypes: queryParams.activityTypes ? queryParams.activityTypes.split(',').map(t => t.trim()) : null,
      organizationId: queryParams.organizationId
    };

    // Get engagement analytics
    const analytics = await UserAnalyticsService.getUserEngagementAnalytics(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analytics, 'Engagement analytics retrieved successfully')
    );
  });

  /**
   * Get user retention analytics
   * @route GET /api/admin/users/analytics/retention
   */
  getUserRetentionAnalytics = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate cohort type
    const allowedCohortTypes = ['signup', 'first_action', 'subscription', 'organization'];
    const cohortType = queryParams.cohortType || 'signup';
    
    if (!allowedCohortTypes.includes(cohortType)) {
      throw new ValidationError(`Invalid cohort type. Allowed values: ${allowedCohortTypes.join(', ')}`);
    }

    // Validate cohort period
    const allowedPeriods = ['day', 'week', 'month'];
    const cohortPeriod = queryParams.cohortPeriod || 'month';
    
    if (!allowedPeriods.includes(cohortPeriod)) {
      throw new ValidationError(`Invalid cohort period. Allowed values: ${allowedPeriods.join(', ')}`);
    }

    // Validate retention periods
    const retentionPeriods = parseInt(queryParams.retentionPeriods) || 12;
    if (retentionPeriods < 1 || retentionPeriods > 24) {
      throw new ValidationError('Retention periods must be between 1 and 24');
    }

    // Validate segment by
    const allowedSegments = ['role', 'organization', 'source', 'plan'];
    if (queryParams.segmentBy && !allowedSegments.includes(queryParams.segmentBy)) {
      throw new ValidationError(`Invalid segment. Allowed values: ${allowedSegments.join(', ')}`);
    }

    const options = {
      cohortType,
      cohortPeriod,
      retentionPeriods,
      startDate: queryParams.startDate,
      endDate: queryParams.endDate,
      segmentBy: queryParams.segmentBy
    };

    // Get retention analytics
    const analytics = await UserAnalyticsService.getUserRetentionAnalytics(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analytics, 'Retention analytics retrieved successfully')
    );
  });

  /**
   * Get user behavior analytics
   * @route GET /api/admin/users/analytics/behavior
   */
  getUserBehaviorAnalytics = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate time range
    const allowedTimeRanges = ['last24h', 'last7d', 'last30d', 'last90d'];
    const timeRange = queryParams.timeRange || 'last30d';
    
    if (!allowedTimeRanges.includes(timeRange)) {
      throw new ValidationError(`Invalid time range. Allowed values: ${allowedTimeRanges.join(', ')}`);
    }

    // Validate behavior types
    const allowedBehaviors = ['user_journey', 'feature_adoption', 'activity_patterns', 'conversion_funnel'];
    let behaviorTypes = ['user_journey', 'feature_adoption', 'activity_patterns'];
    
    if (queryParams.behaviorTypes) {
      const requestedTypes = queryParams.behaviorTypes.split(',').map(t => t.trim());
      const invalidTypes = requestedTypes.filter(t => !allowedBehaviors.includes(t));
      
      if (invalidTypes.length > 0) {
        throw new ValidationError(`Invalid behavior types: ${invalidTypes.join(', ')}`);
      }
      
      behaviorTypes = requestedTypes;
    }

    // Validate user ID if provided
    if (queryParams.userId && !AdminHelpers.isValidObjectId(queryParams.userId)) {
      throw new ValidationError('Invalid user ID');
    }

    // Validate organization ID if provided
    if (queryParams.organizationId && !AdminHelpers.isValidObjectId(queryParams.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    const options = {
      timeRange,
      behaviorTypes,
      userId: queryParams.userId,
      organizationId: queryParams.organizationId
    };

    // Get behavior analytics
    const analytics = await UserAnalyticsService.getUserBehaviorAnalytics(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analytics, 'Behavior analytics retrieved successfully')
    );
  });

  /**
   * Get user demographics analytics
   * @route GET /api/admin/users/analytics/demographics
   */
  getUserDemographicsAnalytics = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate organization ID if provided
    if (queryParams.organizationId && !AdminHelpers.isValidObjectId(queryParams.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    const options = {
      organizationId: queryParams.organizationId,
      includeInactive: queryParams.includeInactive === 'true'
    };

    // Get demographics analytics
    const analytics = await UserAnalyticsService.getUserDemographicsAnalytics(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analytics, 'Demographics analytics retrieved successfully')
    );
  });

  /**
   * Get user activity heatmap
   * @route GET /api/admin/users/analytics/activity-heatmap
   */
  getUserActivityHeatmap = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate time range
    const allowedTimeRanges = ['last7d', 'last30d', 'last90d'];
    const timeRange = queryParams.timeRange || 'last30d';
    
    if (!allowedTimeRanges.includes(timeRange)) {
      throw new ValidationError(`Invalid time range. Allowed values: ${allowedTimeRanges.join(', ')}`);
    }

    // Validate timezone
    const timezone = queryParams.timezone || 'UTC';
    if (!moment.tz.zone(timezone)) {
      throw new ValidationError('Invalid timezone');
    }

    // Validate organization ID if provided
    if (queryParams.organizationId && !AdminHelpers.isValidObjectId(queryParams.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    const options = {
      timeRange,
      timezone,
      organizationId: queryParams.organizationId,
      activityType: queryParams.activityType
    };

    // Get activity heatmap
    const heatmap = await UserAnalyticsService.getUserActivityHeatmap(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(heatmap, 'Activity heatmap retrieved successfully')
    );
  });

  /**
   * Get user funnel analytics
   * @route POST /api/admin/users/analytics/funnel
   */
  getUserFunnelAnalytics = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const funnelData = sanitizeBody(req.body);

    // Validate funnel steps
    if (!funnelData.steps || !Array.isArray(funnelData.steps)) {
      throw new ValidationError('Funnel steps must be provided as an array');
    }

    if (funnelData.steps.length < 2) {
      throw new ValidationError('Funnel must have at least 2 steps');
    }

    if (funnelData.steps.length > 10) {
      throw new ValidationError('Funnel cannot have more than 10 steps');
    }

    // Validate each step
    funnelData.steps.forEach((step, index) => {
      if (!step.name || !step.event) {
        throw new ValidationError(`Step ${index + 1} must have name and event`);
      }
    });

    // Validate date range
    const startDate = funnelData.startDate ? new Date(funnelData.startDate) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const endDate = funnelData.endDate ? new Date(funnelData.endDate) : new Date();

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      throw new ValidationError('Invalid date format');
    }

    if (startDate >= endDate) {
      throw new ValidationError('Start date must be before end date');
    }

    const options = {
      steps: funnelData.steps,
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      conversionWindow: funnelData.conversionWindow || 7, // days
      segmentBy: funnelData.segmentBy
    };

    // Get funnel analytics
    const analytics = await UserAnalyticsService.getUserFunnelAnalytics(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analytics, 'Funnel analytics retrieved successfully')
    );
  });

  /**
   * Get user segmentation analysis
   * @route GET /api/admin/users/analytics/segmentation
   */
  getUserSegmentationAnalysis = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate segment type
    const allowedSegmentTypes = ['behavioral', 'demographic', 'technographic', 'psychographic', 'lifecycle'];
    const segmentType = queryParams.segmentType || 'behavioral';
    
    if (!allowedSegmentTypes.includes(segmentType)) {
      throw new ValidationError(`Invalid segment type. Allowed values: ${allowedSegmentTypes.join(', ')}`);
    }

    // Validate time range
    const timeRange = queryParams.timeRange || 'last30d';

    const options = {
      segmentType,
      timeRange,
      minSegmentSize: parseInt(queryParams.minSegmentSize) || 10,
      includeRecommendations: queryParams.includeRecommendations !== 'false'
    };

    // Get segmentation analysis
    const analysis = await UserAnalyticsService.getUserSegmentationAnalysis(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analysis, 'Segmentation analysis retrieved successfully')
    );
  });

  /**
   * Generate custom user report
   * @route POST /api/admin/users/analytics/report
   */
  generateUserReport = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const reportConfig = sanitizeBody(req.body);

    // Validate report type
    const allowedReportTypes = [
      'executive_summary',
      'growth_analysis',
      'engagement_report',
      'retention_analysis',
      'behavior_insights',
      'demographic_breakdown',
      'custom'
    ];
    
    if (!reportConfig.reportType || !allowedReportTypes.includes(reportConfig.reportType)) {
      throw new ValidationError(`Invalid report type. Allowed values: ${allowedReportTypes.join(', ')}`);
    }

    // Validate required fields
    if (!reportConfig.title || reportConfig.title.trim().length < 3) {
      throw new ValidationError('Report title is required (minimum 3 characters)');
    }

    if (reportConfig.title.length > 100) {
      throw new ValidationError('Report title cannot exceed 100 characters');
    }

    // Validate metrics
    if (!reportConfig.metrics || !Array.isArray(reportConfig.metrics) || reportConfig.metrics.length === 0) {
      throw new ValidationError('At least one metric must be selected');
    }

    // Validate format
    const allowedFormats = ['pdf', 'excel', 'csv', 'html'];
    const format = reportConfig.format || 'pdf';
    
    if (!allowedFormats.includes(format)) {
      throw new ValidationError(`Invalid format. Allowed values: ${allowedFormats.join(', ')}`);
    }

    // Validate recipients if provided
    if (reportConfig.recipients && Array.isArray(reportConfig.recipients)) {
      const invalidEmails = reportConfig.recipients.filter(email => !AdminHelpers.isValidEmail(email));
      if (invalidEmails.length > 0) {
        throw new ValidationError(`Invalid email addresses: ${invalidEmails.join(', ')}`);
      }
      
      if (reportConfig.recipients.length > 10) {
        throw new ValidationError('Cannot send report to more than 10 recipients');
      }
    }

    // Validate schedule if provided
    if (reportConfig.schedule) {
      const allowedFrequencies = ['once', 'daily', 'weekly', 'monthly'];
      if (!allowedFrequencies.includes(reportConfig.schedule.frequency)) {
        throw new ValidationError(`Invalid schedule frequency. Allowed values: ${allowedFrequencies.join(', ')}`);
      }
      
      if (reportConfig.schedule.frequency !== 'once' && !reportConfig.schedule.endDate) {
        throw new ValidationError('End date is required for recurring schedules');
      }
    }

    // Generate report
    const result = await UserAnalyticsService.generateUserReport(adminUser, reportConfig);

    res.status(202).json(
      ResponseFormatter.success(result, 'Report generation initiated successfully')
    );
  });

  /**
   * Get saved reports
   * @route GET /api/admin/users/analytics/reports
   */
  getSavedReports = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    const options = {
      page: parseInt(queryParams.page) || 1,
      limit: Math.min(parseInt(queryParams.limit) || 20, AdminLimits.PAGINATION.MAX_LIMIT),
      reportType: queryParams.reportType,
      sortBy: queryParams.sortBy || 'createdAt',
      sortOrder: queryParams.sortOrder || 'desc'
    };

    // Get saved reports
    const reports = await UserAnalyticsService.getSavedReports(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(reports, 'Saved reports retrieved successfully')
    );
  });

  /**
   * Download analytics report
   * @route GET /api/admin/users/analytics/reports/:reportId/download
   */
  downloadReport = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { reportId } = req.params;

    // Validate report ID
    if (!reportId || !AdminHelpers.isValidUUID(reportId)) {
      throw new ValidationError('Invalid report ID');
    }

    // Get download URL
    const result = await UserAnalyticsService.getReportDownload(adminUser, reportId);

    // Redirect to download URL
    res.redirect(result.downloadUrl);
  });

  /**
   * Get analytics insights
   * @route GET /api/admin/users/analytics/insights
   */
  getAnalyticsInsights = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate time range
    const timeRange = queryParams.timeRange || 'last30d';

    const options = {
      timeRange,
      insightTypes: queryParams.insightTypes ? queryParams.insightTypes.split(',').map(t => t.trim()) : null,
      minConfidence: parseFloat(queryParams.minConfidence) || 0.7,
      maxInsights: parseInt(queryParams.maxInsights) || 10
    };

    // Get analytics insights
    const insights = await UserAnalyticsService.getAnalyticsInsights(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(insights, 'Analytics insights retrieved successfully')
    );
  });

  /**
   * Export analytics data
   * @route POST /api/admin/users/analytics/export
   */
  exportAnalyticsData = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const exportConfig = sanitizeBody(req.body);

    // Validate data type
    const allowedDataTypes = ['raw', 'aggregated', 'processed'];
    if (!exportConfig.dataType || !allowedDataTypes.includes(exportConfig.dataType)) {
      throw new ValidationError(`Invalid data type. Allowed values: ${allowedDataTypes.join(', ')}`);
    }

    // Validate metrics
    if (!exportConfig.metrics || !Array.isArray(exportConfig.metrics) || exportConfig.metrics.length === 0) {
      throw new ValidationError('At least one metric must be selected for export');
    }

    // Validate date range
    const startDate = new Date(exportConfig.startDate);
    const endDate = new Date(exportConfig.endDate);

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      throw new ValidationError('Invalid date format');
    }

    if (startDate >= endDate) {
      throw new ValidationError('Start date must be before end date');
    }

    // Maximum 1 year export
    const maxRange = 365 * 24 * 60 * 60 * 1000;
    if (endDate - startDate > maxRange) {
      throw new ValidationError('Export date range cannot exceed 1 year');
    }

    // Validate format
    const allowedFormats = ['csv', 'json', 'parquet'];
    const format = exportConfig.format || 'csv';
    
    if (!allowedFormats.includes(format)) {
      throw new ValidationError(`Invalid format. Allowed values: ${allowedFormats.join(', ')}`);
    }

    // Export analytics data
    const result = await UserAnalyticsService.exportAnalyticsData(adminUser, exportConfig);

    res.status(202).json(
      ResponseFormatter.success(result, 'Analytics export initiated successfully')
    );
  });
}

module.exports = new UserAnalyticsController();