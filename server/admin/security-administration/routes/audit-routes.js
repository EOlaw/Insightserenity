// server/admin/security-administration/routes/audit-routes.js
/**
 * @file Audit Administration Routes
 * @description Routes for audit log management operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const AuditController = require('../controllers/audit-controller');

// Middleware
const { validateRequest } = require('../../../shared/middleware/validate-request');
const AuditValidation = require('../validation/audit-validation');
const AdminAuthMiddleware = require('../../../shared/admin/middleware/admin-authentication');
const AuditAccessMiddleware = require('../middleware/audit-compliance');
const AdminAuditMiddleware = require('../../../shared/admin/middleware/admin-audit-logging');
const AdminRateLimitMiddleware = require('../../../shared/admin/middleware/admin-rate-limiting');
const MFAMiddleware = require('../../../shared/admin/middleware/multi-factor-validation');

/**
 * @swagger
 * tags:
 *   name: Admin Audit
 *   description: Audit log management and compliance endpoints
 */

/**
 * @route POST /api/admin/audit/search
 * @desc Search audit logs with advanced filtering
 * @access Admin - Audit View
 */
router.post(
  '/search',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  validateRequest(AuditValidation.searchLogs),
  AdminAuditMiddleware.logDataAccess,
  AuditController.searchAuditLogs
);

/**
 * @route GET /api/admin/audit/logs/:auditId
 * @desc Get detailed audit log information
 * @access Admin - Audit View
 */
router.get(
  '/logs/:auditId',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  validateRequest(AuditValidation.getDetails),
  AdminAuditMiddleware.logDataAccess,
  AuditController.getAuditDetails
);

/**
 * @route POST /api/admin/audit/export
 * @desc Export audit logs
 * @access Admin - Audit Export
 */
router.post(
  '/export',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canExportAuditLogs,
  AdminRateLimitMiddleware.strict,
  validateRequest(AuditValidation.exportLogs),
  AdminAuditMiddleware.logDataExport,
  AuditController.exportAuditLogs
);

/**
 * @route GET /api/admin/audit/exports
 * @desc Get audit export history
 * @access Admin - Audit View
 */
router.get(
  '/exports',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  AuditController.getExportHistory
);

/**
 * @route POST /api/admin/audit/retention
 * @desc Configure audit retention policies
 * @access Admin - Audit Configure (MFA required)
 */
router.post(
  '/retention',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canConfigureAudit,
  MFAMiddleware.requireMFA,
  validateRequest(AuditValidation.configureRetention),
  AdminAuditMiddleware.logConfigChange,
  AuditController.configureRetention
);

/**
 * @route GET /api/admin/audit/retention
 * @desc Get audit retention policies
 * @access Admin - Audit View
 */
router.get(
  '/retention',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  AuditController.getRetentionPolicies
);

/**
 * @route POST /api/admin/audit/alerts
 * @desc Configure audit alerts
 * @access Admin - Audit Configure (MFA required)
 */
router.post(
  '/alerts',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canConfigureAudit,
  MFAMiddleware.requireMFA,
  validateRequest(AuditValidation.configureAlerts),
  AdminAuditMiddleware.logConfigChange,
  AuditController.configureAlerts
);

/**
 * @route GET /api/admin/audit/alerts
 * @desc Get audit alert configurations
 * @access Admin - Audit View
 */
router.get(
  '/alerts',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  AuditController.getAlertConfigurations
);

/**
 * @route POST /api/admin/audit/archive
 * @desc Archive audit logs
 * @access Admin - Audit Archive (MFA required)
 */
router.post(
  '/archive',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canArchiveAuditLogs,
  MFAMiddleware.requireMFA,
  AdminRateLimitMiddleware.strict,
  validateRequest(AuditValidation.archiveLogs),
  AdminAuditMiddleware.logCriticalAction,
  AuditController.archiveAuditLogs
);

/**
 * @route GET /api/admin/audit/archives
 * @desc Get audit archive list
 * @access Admin - Audit View
 */
router.get(
  '/archives',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  AuditController.getArchiveList
);

/**
 * @route GET /api/admin/audit/statistics
 * @desc Get audit statistics and trends
 * @access Admin - Audit View
 */
router.get(
  '/statistics',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  validateRequest(AuditValidation.getStatistics),
  AuditController.getAuditStatistics
);

/**
 * @route POST /api/admin/audit/compliance-mappings
 * @desc Manage compliance mappings for audit events
 * @access Admin - Compliance Configure (MFA required)
 */
router.post(
  '/compliance-mappings',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canConfigureCompliance,
  MFAMiddleware.requireMFA,
  validateRequest(AuditValidation.manageComplianceMappings),
  AdminAuditMiddleware.logConfigChange,
  AuditController.manageComplianceMappings
);

/**
 * @route GET /api/admin/audit/compliance-mappings
 * @desc Get compliance mappings
 * @access Admin - Audit View
 */
router.get(
  '/compliance-mappings',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canViewAuditLogs,
  AuditController.getComplianceMappings
);

/**
 * @route POST /api/admin/audit/compliance-report
 * @desc Generate compliance report from audit logs
 * @access Admin - Compliance Reports
 */
router.post(
  '/compliance-report',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canGenerateComplianceReports,
  AdminRateLimitMiddleware.moderate,
  validateRequest(AuditValidation.generateComplianceReport),
  AdminAuditMiddleware.logDataAccess,
  AuditController.generateComplianceReport
);

/**
 * @route GET /api/admin/audit/monitor
 * @desc Real-time audit event monitoring (Server-Sent Events)
 * @access Admin - Audit Monitor
 */
router.get(
  '/monitor',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canMonitorAuditEvents,
  AuditController.monitorAuditEvents
);

/**
 * @route POST /api/admin/audit/analyze
 * @desc Analyze audit patterns and anomalies
 * @access Admin - Audit Analyze
 */
router.post(
  '/analyze',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canAnalyzeAuditData,
  AdminRateLimitMiddleware.moderate,
  validateRequest(AuditValidation.analyzePatterns),
  AdminAuditMiddleware.logDataAccess,
  AuditController.analyzeAuditPatterns
);

/**
 * @route DELETE /api/admin/audit/logs
 * @desc Delete audit logs (restricted operation)
 * @access Super Admin Only (MFA required)
 */
router.delete(
  '/logs',
  AdminAuthMiddleware.verifyAdminToken,
  AuditAccessMiddleware.canDeleteAuditLogs,
  MFAMiddleware.requireMFA,
  AdminAuditMiddleware.logCriticalAction,
  AuditController.deleteAuditLogs
);

module.exports = router;