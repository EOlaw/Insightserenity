// server/admin/user-management/routes/user-analytics-routes.js
/**
 * @file User Analytics Routes
 * @description Routes for user analytics and reporting operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const UserAnalyticsController = require('../controllers/user-analytics-controller');

// Middleware
const { requireUserManagementPermission, verifyOrganizationScope, requireElevatedPrivileges, trackUserManagementAction } = require('../middleware/user-management-auth');
const { adminRateLimiter } = require('../../../shared/admin/middleware/admin-rate-limiting');
const { cacheMiddleware } = require('../../../shared/admin/middleware/admin-cache-middleware');

// Validation
const { middleware: exportValidationMiddleware } = require('../validation/export-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * @route   GET /api/admin/users/analytics/dashboard
 * @desc    Get comprehensive user analytics dashboard
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/dashboard',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_dashboard', 3600), // 1 hour cache
  trackUserManagementAction('view_analytics_dashboard'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getAnalyticsDashboard
);

/**
 * @route   GET /api/admin/users/analytics/growth
 * @desc    Get user growth analytics
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/growth',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_growth', 1800), // 30 minutes cache
  trackUserManagementAction('view_growth_analytics'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserGrowthAnalytics
);

/**
 * @route   GET /api/admin/users/analytics/engagement
 * @desc    Get user engagement analytics
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/engagement',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_engagement', 1800), // 30 minutes cache
  trackUserManagementAction('view_engagement_analytics'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserEngagementAnalytics
);

/**
 * @route   GET /api/admin/users/analytics/retention
 * @desc    Get user retention analytics
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/retention',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_retention', 3600), // 1 hour cache
  trackUserManagementAction('view_retention_analytics'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserRetentionAnalytics
);

/**
 * @route   GET /api/admin/users/analytics/behavior
 * @desc    Get user behavior analytics
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/behavior',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_behavior', 1800), // 30 minutes cache
  trackUserManagementAction('view_behavior_analytics'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserBehaviorAnalytics
);

/**
 * @route   GET /api/admin/users/analytics/demographics
 * @desc    Get user demographics analytics
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/demographics',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_demographics', 7200), // 2 hours cache
  trackUserManagementAction('view_demographics_analytics'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserDemographicsAnalytics
);

/**
 * @route   GET /api/admin/users/analytics/activity-heatmap
 * @desc    Get user activity heatmap
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/activity-heatmap',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_heatmap', 3600), // 1 hour cache
  trackUserManagementAction('view_activity_heatmap'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserActivityHeatmap
);

/**
 * @route   POST /api/admin/users/analytics/funnel
 * @desc    Get user funnel analytics
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.post(
  '/funnel',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  trackUserManagementAction('view_funnel_analytics'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserFunnelAnalytics
);

/**
 * @route   GET /api/admin/users/analytics/segmentation
 * @desc    Get user segmentation analysis
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/segmentation',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_segmentation', 3600), // 1 hour cache
  trackUserManagementAction('view_segmentation_analysis'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getUserSegmentationAnalysis
);

/**
 * @route   POST /api/admin/users/analytics/report
 * @desc    Generate custom user report
 * @access  Admin - Requires USER_MANAGEMENT.GENERATE_REPORTS permission
 */
router.post(
  '/report',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.GENERATE_REPORTS),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  exportValidationMiddleware.validateReportGeneration,
  trackUserManagementAction('generate_report'),
  adminRateLimiter('reportGeneration'),
  UserAnalyticsController.generateUserReport
);

/**
 * @route   GET /api/admin/users/analytics/reports
 * @desc    Get saved reports
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/reports',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  trackUserManagementAction('view_saved_reports'),
  adminRateLimiter('reportView'),
  UserAnalyticsController.getSavedReports
);

/**
 * @route   GET /api/admin/users/analytics/reports/:reportId/download
 * @desc    Download analytics report
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/reports/:reportId/download',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  trackUserManagementAction('download_report'),
  adminRateLimiter('reportDownload'),
  UserAnalyticsController.downloadReport
);

/**
 * @route   GET /api/admin/users/analytics/insights
 * @desc    Get AI-powered analytics insights
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/insights',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  cacheMiddleware('analytics_insights', 1800), // 30 minutes cache
  trackUserManagementAction('view_analytics_insights'),
  adminRateLimiter('analyticsView'),
  UserAnalyticsController.getAnalyticsInsights
);

/**
 * @route   POST /api/admin/users/analytics/export
 * @desc    Export analytics data
 * @access  Admin - Requires USER_MANAGEMENT.EXPORT permission
 */
router.post(
  '/export',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.EXPORT),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  exportValidationMiddleware.validateAnalyticsExport,
  trackUserManagementAction('export_analytics_data'),
  adminRateLimiter('dataExport'),
  UserAnalyticsController.exportAnalyticsData
);

module.exports = router;