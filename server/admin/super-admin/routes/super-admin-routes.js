// server/admin/super-admin/routes/super-admin-routes.js
/**
 * @file Super Admin Routes
 * @description Route definitions for super administrator system management
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const SuperAdminController = require('../controllers/super-admin-controller');

// Middleware
const { authenticate } = require('../../../shared/middleware/auth');
const { authorize } = require('../../../shared/middleware/authorization');
const SuperAdminOnly = require('../middleware/super-admin-only');
const CriticalOperation = require('../middleware/critical-operation');
const { validateRequest } = require('../../../shared/middleware/validate-request');
const { rateLimiter } = require('../../../shared/middleware/rate-limiter');
const { auditLog } = require('../../../shared/middleware/audit-logger');
const { sanitize } = require('../../../shared/middleware/sanitizer');
const { cache } = require('../../../shared/middleware/cache');

// Validation
const SuperAdminValidation = require('../validation/super-admin-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * Super Admin Routes
 * Base path: /api/admin/super-admin
 */

// Apply authentication to all routes
router.use(authenticate);

// Apply super admin only middleware to all routes
router.use(SuperAdminOnly.enforce({
  requireMFA: true,
  requireActiveSession: true,
  checkIPWhitelist: true,
  auditAccess: true
}));

/**
 * @route   GET /api/admin/super-admin/overview
 * @desc    Get comprehensive system overview
 * @access  Super Admin
 */
router.get(
  '/overview',
  rateLimiter('super_admin_overview', { max: 30, window: 60 }),
  cache({ ttl: 300, key: 'system_overview' }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_OVERVIEW, 'read'),
  auditLog('system.overview.accessed'),
  SuperAdminController.getSystemOverview
);

/**
 * @route   GET /api/admin/super-admin/statistics
 * @desc    Get detailed system statistics with custom date range
 * @access  Super Admin
 */
router.get(
  '/statistics',
  rateLimiter('super_admin_statistics', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_STATISTICS, 'read'),
  validateRequest(SuperAdminValidation.platformAnalytics, 'query'),
  auditLog('system.statistics.accessed'),
  SuperAdminController.getSystemStatistics
);

/**
 * @route   GET /api/admin/super-admin/search
 * @desc    Search across system entities
 * @access  Super Admin
 */
router.get(
  '/search',
  rateLimiter('super_admin_search', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SEARCH, 'read'),
  validateRequest(SuperAdminValidation.searchEntities, 'query'),
  sanitize(['query']),
  auditLog('system.search.performed'),
  SuperAdminController.searchSystemEntities
);

/**
 * @route   POST /api/admin/super-admin/impersonate
 * @desc    Impersonate a user for support/debugging
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/impersonate',
  rateLimiter('super_admin_impersonate', { max: 5, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.USER_IMPERSONATION, 'execute'),
  CriticalOperation.protect('user.impersonation', {
    notifyAllAdmins: true,
    recordDetailed: true
  }),
  validateRequest(SuperAdminValidation.impersonateUser, 'body'),
  sanitize(['body']),
  auditLog('user.impersonation.initiated', { critical: true }),
  SuperAdminController.impersonateUser
);

/**
 * @route   POST /api/admin/super-admin/impersonate/:sessionId/end
 * @desc    End impersonation session
 * @access  Super Admin
 */
router.post(
  '/impersonate/:sessionId/end',
  rateLimiter('super_admin_end_impersonate', { max: 10, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.USER_IMPERSONATION, 'end'),
  auditLog('user.impersonation.ended', { critical: true }),
  SuperAdminController.endImpersonation
);

/**
 * @route   POST /api/admin/super-admin/emergency-action
 * @desc    Execute emergency system action
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/emergency-action',
  rateLimiter('super_admin_emergency', { max: 3, window: 600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACTIONS, 'execute'),
  CriticalOperation.protect('system.emergency.action', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(SuperAdminValidation.emergencyAction, 'body'),
  auditLog('system.emergency.action.executed', { critical: true, alert: true }),
  SuperAdminController.executeEmergencyAction
);

/**
 * @route   PUT /api/admin/super-admin/configuration
 * @desc    Modify system configuration
 * @access  Super Admin + Critical Operation
 */
router.put(
  '/configuration',
  rateLimiter('super_admin_config', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_CONFIGURATION, 'update'),
  CriticalOperation.protect('system.configuration.modify', {
    requireDualAuth: false,
    recordDetailed: true
  }),
  validateRequest(SuperAdminValidation.modifyConfiguration, 'body'),
  auditLog('system.configuration.modified', { critical: true }),
  SuperAdminController.modifySystemConfiguration
);

/**
 * @route   GET /api/admin/super-admin/health
 * @desc    Get system health status
 * @access  Super Admin
 */
router.get(
  '/health',
  rateLimiter('super_admin_health', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_HEALTH, 'read'),
  cache({ ttl: 60, key: 'system_health' }),
  auditLog('system.health.checked'),
  SuperAdminController.getSystemHealth
);

/**
 * @route   GET /api/admin/super-admin/activity-logs
 * @desc    Get admin activity logs
 * @access  Super Admin
 */
router.get(
  '/activity-logs',
  rateLimiter('super_admin_logs', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.AUDIT_LOGS, 'read'),
  validateRequest(SuperAdminValidation.platformAnalytics, 'query'),
  auditLog('admin.activity.logs.accessed'),
  SuperAdminController.getAdminActivityLogs
);

/**
 * @route   POST /api/admin/super-admin/reports/generate
 * @desc    Generate system report
 * @access  Super Admin
 */
router.post(
  '/reports/generate',
  rateLimiter('super_admin_reports', { max: 5, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.REPORTS, 'create'),
  validateRequest(SuperAdminValidation.generateReport, 'body'),
  auditLog('system.report.generated'),
  SuperAdminController.generateSystemReport
);

/**
 * @route   POST /api/admin/super-admin/maintenance
 * @desc    Schedule system maintenance
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/maintenance',
  rateLimiter('super_admin_maintenance', { max: 3, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_MAINTENANCE, 'execute'),
  CriticalOperation.protect('system.maintenance.scheduled', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(SuperAdminValidation.systemMaintenance, 'body'),
  auditLog('system.maintenance.scheduled', { critical: true, alert: true }),
  SuperAdminController.executeSystemMaintenance
);

/**
 * @route   GET /api/admin/super-admin/analytics
 * @desc    Get platform analytics
 * @access  Super Admin
 */
router.get(
  '/analytics',
  rateLimiter('super_admin_analytics', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ANALYTICS, 'read'),
  validateRequest(SuperAdminValidation.platformAnalytics, 'query'),
  cache({ ttl: 600, key: 'platform_analytics' }),
  auditLog('platform.analytics.accessed'),
  SuperAdminController.getPlatformAnalytics
);

/**
 * @route   POST /api/admin/super-admin/notifications/broadcast
 * @desc    Send broadcast notification
 * @access  Super Admin
 */
router.post(
  '/notifications/broadcast',
  rateLimiter('super_admin_broadcast', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.BROADCAST, 'send'),
  validateRequest(SuperAdminValidation.broadcastNotification, 'body'),
  sanitize(['body.message', 'body.title']),
  auditLog('notification.broadcast.sent', { critical: false }),
  SuperAdminController.broadcastNotification
);

/**
 * @route   POST /api/admin/super-admin/export
 * @desc    Export system data
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/export',
  rateLimiter('super_admin_export', { max: 3, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.DATA_EXPORT, 'execute'),
  CriticalOperation.protect('data.export.full', {
    requireDualAuth: true,
    recordDetailed: true
  }),
  validateRequest(SuperAdminValidation.exportData, 'body'),
  auditLog('system.data.exported', { critical: true, alert: true }),
  SuperAdminController.exportSystemData
);

/**
 * @route   GET /api/admin/super-admin/audit-summary
 * @desc    Get system audit summary
 * @access  Super Admin
 */
router.get(
  '/audit-summary',
  rateLimiter('super_admin_audit', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.AUDIT_LOGS, 'read'),
  cache({ ttl: 300, key: 'audit_summary' }),
  auditLog('audit.summary.accessed'),
  SuperAdminController.getAuditSummary
);

/**
 * @route   GET /api/admin/super-admin/users
 * @desc    Search and manage users (advanced)
 * @access  Super Admin
 */
router.get(
  '/users',
  rateLimiter('super_admin_users', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.USER_MANAGEMENT, 'read'),
  validateRequest(SuperAdminValidation.userSearch, 'query'),
  auditLog('users.search.performed'),
  SuperAdminController.searchUsers
);

/**
 * @route   PUT /api/admin/super-admin/users/:userId/status
 * @desc    Update user status (suspend, activate, etc.)
 * @access  Super Admin
 */
router.put(
  '/users/:userId/status',
  rateLimiter('super_admin_user_status', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.USER_MANAGEMENT, 'update'),
  CriticalOperation.protect('user.status.change', {
    requireDualAuth: false,
    recordDetailed: true
  }),
  auditLog('user.status.updated', { critical: true }),
  SuperAdminController.updateUserStatus
);

/**
 * @route   DELETE /api/admin/super-admin/users/:userId
 * @desc    Permanently delete user account
 * @access  Super Admin + Critical Operation
 */
router.delete(
  '/users/:userId',
  rateLimiter('super_admin_delete_user', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.USER_MANAGEMENT, 'delete'),
  CriticalOperation.protect('user.permanent.delete', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  auditLog('user.permanently.deleted', { critical: true, alert: true }),
  SuperAdminController.deleteUser
);

/**
 * @route   GET /api/admin/super-admin/organizations
 * @desc    List and search organizations
 * @access  Super Admin
 */
router.get(
  '/organizations',
  rateLimiter('super_admin_orgs', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ORGANIZATION_MANAGEMENT, 'read'),
  cache({ ttl: 300, key: 'organizations_list' }),
  auditLog('organizations.list.accessed'),
  SuperAdminController.listOrganizations
);

/**
 * @route   PUT /api/admin/super-admin/organizations/:orgId/status
 * @desc    Update organization status
 * @access  Super Admin + Critical Operation
 */
router.put(
  '/organizations/:orgId/status',
  rateLimiter('super_admin_org_status', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.ORGANIZATION_MANAGEMENT, 'update'),
  CriticalOperation.protect('organization.status.change', {
    requireDualAuth: true,
    recordDetailed: true
  }),
  auditLog('organization.status.updated', { critical: true }),
  SuperAdminController.updateOrganizationStatus
);

/**
 * Error handling middleware for super admin routes
 */
router.use((error, req, res, next) => {
  // Log critical errors
  if (error.severity === 'critical' || error.statusCode === 500) {
    logger.critical('Super admin route error', {
      error: error.message,
      path: req.path,
      method: req.method,
      user: req.user?.id,
      stack: error.stack
    });
  }

  next(error);
});

module.exports = router;