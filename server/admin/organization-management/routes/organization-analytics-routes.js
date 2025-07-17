// server/admin/organization-management/routes/organization-analytics-routes.js
/**
 * @file Organization Analytics Routes
 * @description Routes for organization analytics and reporting
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const OrganizationAnalyticsController = require('../controllers/organization-analytics-controller');

// Middleware
const { requireOrganizationManagementPermission, verifyOrganizationScope, requireElevatedPrivileges, trackOrganizationManagementAction } = require('../middleware/organization-access');
const { adminRateLimiter } = require('../../../shared/admin/middleware/admin-rate-limiting');
const { cacheMiddleware } = require('../../../shared/admin/middleware/admin-cache-middleware');

// Validation
const { middleware: analyticsValidationMiddleware } = require('../validation/organization-management-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * @route   GET /api/admin/organizations/analytics/overview
 * @desc    Get platform-wide organization analytics overview
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/overview',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  analyticsValidationMiddleware.validateAnalyticsOverview,
  cacheMiddleware('org_analytics_overview', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_analytics_overview'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getAnalyticsOverview
);

/**
 * @route   GET /api/admin/organizations/analytics/growth
 * @desc    Get organization growth metrics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/growth',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  analyticsValidationMiddleware.validateGrowthMetrics,
  cacheMiddleware('org_growth_metrics', 3600), // 1 hour cache
  trackOrganizationManagementAction('view_growth_metrics'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getGrowthMetrics
);

/**
 * @route   GET /api/admin/organizations/analytics/health-scores
 * @desc    Get organization health scores
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/health-scores',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  analyticsValidationMiddleware.validateHealthScores,
  cacheMiddleware('org_health_scores', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_health_scores'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getHealthScores
);

/**
 * @route   GET /api/admin/organizations/analytics/:organizationId
 * @desc    Get specific organization analytics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/:organizationId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  analyticsValidationMiddleware.validateOrganizationAnalytics,
  cacheMiddleware('org_specific_analytics', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_organization_analytics'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getOrganizationAnalytics
);

/**
 * @route   GET /api/admin/organizations/analytics/:organizationId/engagement
 * @desc    Get organization engagement metrics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/:organizationId/engagement',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  analyticsValidationMiddleware.validateEngagementMetrics,
  cacheMiddleware('org_engagement', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_engagement_metrics'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getEngagementMetrics
);

/**
 * @route   GET /api/admin/organizations/analytics/:organizationId/retention
 * @desc    Get organization retention analytics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/:organizationId/retention',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  analyticsValidationMiddleware.validateRetentionAnalytics,
  cacheMiddleware('org_retention', 3600), // 1 hour cache
  trackOrganizationManagementAction('view_retention_analytics'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getRetentionAnalytics
);

/**
 * @route   GET /api/admin/organizations/analytics/:organizationId/usage-patterns
 * @desc    Get organization usage patterns
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/:organizationId/usage-patterns',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  analyticsValidationMiddleware.validateUsagePatterns,
  cacheMiddleware('org_usage_patterns', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_usage_patterns'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getUsagePatterns
);

/**
 * @route   GET /api/admin/organizations/analytics/comparative
 * @desc    Get comparative analytics across organizations
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_COMPARATIVE permission
 */
router.get(
  '/comparative',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_COMPARATIVE),
  analyticsValidationMiddleware.validateComparativeAnalytics,
  cacheMiddleware('org_comparative_analytics', 3600), // 1 hour cache
  trackOrganizationManagementAction('view_comparative_analytics'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getComparativeAnalytics
);

/**
 * @route   GET /api/admin/organizations/analytics/revenue
 * @desc    Get revenue analytics by organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_REVENUE permission
 */
router.get(
  '/revenue',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_REVENUE),
  analyticsValidationMiddleware.validateRevenueAnalytics,
  cacheMiddleware('org_revenue_analytics', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_revenue_analytics'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getRevenueAnalytics
);

/**
 * @route   GET /api/admin/organizations/analytics/churn-prediction
 * @desc    Get churn prediction analytics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_PREDICTIONS permission
 */
router.get(
  '/churn-prediction',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_PREDICTIONS),
  analyticsValidationMiddleware.validateChurnPrediction,
  cacheMiddleware('org_churn_prediction', 3600), // 1 hour cache
  trackOrganizationManagementAction('view_churn_prediction'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getChurnPrediction
);

/**
 * @route   POST /api/admin/organizations/analytics/report
 * @desc    Generate custom analytics report
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.GENERATE_REPORTS permission
 */
router.post(
  '/report',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.GENERATE_REPORTS),
  requireElevatedPrivileges({ requireMFA: true }),
  analyticsValidationMiddleware.validateGenerateReport,
  trackOrganizationManagementAction('generate_analytics_report'),
  adminRateLimiter('reportGeneration'),
  OrganizationAnalyticsController.generateAnalyticsReport
);

/**
 * @route   GET /api/admin/organizations/analytics/report/:reportId
 * @desc    Get generated report
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_REPORTS permission
 */
router.get(
  '/report/:reportId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_REPORTS),
  cacheMiddleware('org_report', 3600), // 1 hour cache
  trackOrganizationManagementAction('view_analytics_report'),
  adminRateLimiter('reportView'),
  OrganizationAnalyticsController.getReport
);

/**
 * @route   POST /api/admin/organizations/analytics/export
 * @desc    Export analytics data
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.EXPORT_ANALYTICS permission
 */
router.post(
  '/export',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.EXPORT_ANALYTICS),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requireRecentAuth: true
  }),
  analyticsValidationMiddleware.validateExportAnalytics,
  trackOrganizationManagementAction('export_analytics'),
  adminRateLimiter('analyticsExport'),
  OrganizationAnalyticsController.exportAnalytics
);

/**
 * @route   GET /api/admin/organizations/analytics/benchmarks
 * @desc    Get industry benchmarks
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_BENCHMARKS permission
 */
router.get(
  '/benchmarks',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_BENCHMARKS),
  analyticsValidationMiddleware.validateBenchmarks,
  cacheMiddleware('org_benchmarks', 7200), // 2 hours cache
  trackOrganizationManagementAction('view_benchmarks'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getBenchmarks
);

/**
 * @route   GET /api/admin/organizations/analytics/segments
 * @desc    Get organization segments analysis
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_SEGMENTS permission
 */
router.get(
  '/segments',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_SEGMENTS),
  analyticsValidationMiddleware.validateSegmentAnalysis,
  cacheMiddleware('org_segments', 3600), // 1 hour cache
  trackOrganizationManagementAction('view_segment_analysis'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getSegmentAnalysis
);

/**
 * @route   GET /api/admin/organizations/analytics/activity-trends
 * @desc    Get platform-wide activity trends
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/activity-trends',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  analyticsValidationMiddleware.validateActivityTrends,
  cacheMiddleware('org_activity_trends', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_activity_trends'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getActivityTrends
);

/**
 * @route   GET /api/admin/organizations/analytics/feature-adoption
 * @desc    Get feature adoption analytics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/feature-adoption',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS),
  analyticsValidationMiddleware.validateFeatureAdoption,
  cacheMiddleware('org_feature_adoption', 3600), // 1 hour cache
  trackOrganizationManagementAction('view_feature_adoption'),
  adminRateLimiter('analyticsView'),
  OrganizationAnalyticsController.getFeatureAdoption
);

/**
 * @route   POST /api/admin/organizations/analytics/schedule-report
 * @desc    Schedule recurring analytics report
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SCHEDULE_REPORTS permission
 */
router.post(
  '/schedule-report',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SCHEDULE_REPORTS),
  requireElevatedPrivileges({ requireMFA: true }),
  analyticsValidationMiddleware.validateScheduleReport,
  trackOrganizationManagementAction('schedule_analytics_report'),
  adminRateLimiter('reportSchedule'),
  OrganizationAnalyticsController.scheduleReport
);

/**
 * @route   GET /api/admin/organizations/analytics/scheduled-reports
 * @desc    Get scheduled reports
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_REPORTS permission
 */
router.get(
  '/scheduled-reports',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_REPORTS),
  cacheMiddleware('org_scheduled_reports', 600), // 10 minutes cache
  trackOrganizationManagementAction('view_scheduled_reports'),
  adminRateLimiter('reportView'),
  OrganizationAnalyticsController.getScheduledReports
);

/**
 * @route   DELETE /api/admin/organizations/analytics/scheduled-reports/:reportId
 * @desc    Cancel scheduled report
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SCHEDULE_REPORTS permission
 */
router.delete(
  '/scheduled-reports/:reportId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SCHEDULE_REPORTS),
  trackOrganizationManagementAction('cancel_scheduled_report'),
  adminRateLimiter('reportCancel'),
  OrganizationAnalyticsController.cancelScheduledReport
);

module.exports = router;