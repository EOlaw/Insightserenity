// server/admin/security-administration/routes/threat-management-routes.js
/**
 * @file Threat Management Routes
 * @description Routes for threat detection and management operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const ThreatManagementController = require('../controllers/threat-management-controller');

// Middleware
const { validateRequest } = require('../../../shared/middleware/validate-request');
const ThreatManagementValidation = require('../validation/threat-management-validation');
const AdminAuthMiddleware = require('../../../shared/admin/middleware/admin-authentication');
const ThreatAccessMiddleware = require('../middleware/compliance-check');
const AdminAuditMiddleware = require('../../../shared/admin/middleware/admin-audit-logging');
const AdminRateLimitMiddleware = require('../../../shared/admin/middleware/admin-rate-limiting');
const MFAMiddleware = require('../../../shared/admin/middleware/multi-factor-validation');

/**
 * @swagger
 * tags:
 *   name: Admin Threat Management
 *   description: Threat detection, analysis, and response endpoints
 */

/**
 * @route GET /api/admin/threats/overview
 * @desc Get threat overview and current status
 * @access Admin - Threat View
 */
router.get(
  '/overview',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  validateRequest(ThreatManagementValidation.getOverview),
  ThreatManagementController.getThreatOverview
);

/**
 * @route POST /api/admin/threats/search
 * @desc Search and filter threats
 * @access Admin - Threat View
 */
router.post(
  '/search',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  validateRequest(ThreatManagementValidation.searchThreats),
  ThreatManagementController.searchThreats
);

/**
 * @route POST /api/admin/threats/:threatId/manage
 * @desc Manage threat response and mitigation
 * @access Admin - Threat Management (MFA required)
 */
router.post(
  '/:threatId/manage',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canManageThreats,
  MFAMiddleware.requireMFA,
  validateRequest(ThreatManagementValidation.manageThreat),
  AdminAuditMiddleware.logSecurityAction,
  ThreatManagementController.manageThreat
);

/**
 * @route GET /api/admin/threats/:threatId
 * @desc Get threat details
 * @access Admin - Threat View
 */
router.get(
  '/:threatId',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getThreatDetails
);

/**
 * @route POST /api/admin/threats/:threatId/investigate
 * @desc Investigate threat with deep analysis
 * @access Admin - Threat Investigation
 */
router.post(
  '/:threatId/investigate',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canInvestigateThreats,
  validateRequest(ThreatManagementValidation.investigateThreat),
  AdminAuditMiddleware.logDataAccess,
  ThreatManagementController.investigateThreat
);

/**
 * @route POST /api/admin/threats/rules
 * @desc Manage threat detection rules
 * @access Admin - Threat Rules (MFA required)
 */
router.post(
  '/rules',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canManageThreatRules,
  MFAMiddleware.requireMFA,
  validateRequest(ThreatManagementValidation.manageThreatRule),
  AdminAuditMiddleware.logConfigChange,
  ThreatManagementController.manageThreatRule
);

/**
 * @route GET /api/admin/threats/rules
 * @desc Get threat detection rules
 * @access Admin - Threat View
 */
router.get(
  '/rules',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getThreatRules
);

/**
 * @route GET /api/admin/threats/rules/:ruleId
 * @desc Get threat rule details
 * @access Admin - Threat View
 */
router.get(
  '/rules/:ruleId',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getThreatRuleDetails
);

/**
 * @route POST /api/admin/threats/intelligence
 * @desc Manage threat intelligence feeds
 * @access Admin - Threat Intelligence (MFA required)
 */
router.post(
  '/intelligence',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canManageIntelligence,
  MFAMiddleware.requireMFA,
  validateRequest(ThreatManagementValidation.manageThreatIntelligence),
  AdminAuditMiddleware.logConfigChange,
  ThreatManagementController.manageThreatIntelligence
);

/**
 * @route GET /api/admin/threats/intelligence
 * @desc Get threat intelligence feeds
 * @access Admin - Threat View
 */
router.get(
  '/intelligence',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getThreatIntelligence
);

/**
 * @route GET /api/admin/threats/indicators
 * @desc Get threat indicators
 * @access Admin - Threat View
 */
router.get(
  '/indicators',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getThreatIndicators
);

/**
 * @route POST /api/admin/threats/indicators
 * @desc Add threat indicators
 * @access Admin - Threat Management
 */
router.post(
  '/indicators',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canManageThreats,
  AdminAuditMiddleware.logSecurityAction,
  ThreatManagementController.addThreatIndicators
);

/**
 * @route POST /api/admin/threats/reports
 * @desc Generate threat report
 * @access Admin - Threat Reports
 */
router.post(
  '/reports',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canGenerateReports,
  AdminRateLimitMiddleware.moderate,
  validateRequest(ThreatManagementValidation.generateThreatReport),
  AdminAuditMiddleware.logDataAccess,
  ThreatManagementController.generateThreatReport
);

/**
 * @route GET /api/admin/threats/statistics
 * @desc Get threat statistics and trends
 * @access Admin - Threat View
 */
router.get(
  '/statistics',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getThreatStatistics
);

/**
 * @route GET /api/admin/threats/active
 * @desc Get active threats requiring attention
 * @access Admin - Threat View
 */
router.get(
  '/active',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getActiveThreats
);

/**
 * @route POST /api/admin/threats/bulk-action
 * @desc Perform bulk actions on threats
 * @access Admin - Threat Management (MFA required)
 */
router.post(
  '/bulk-action',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canManageThreats,
  MFAMiddleware.requireMFA,
  AdminAuditMiddleware.logBulkAction,
  ThreatManagementController.performBulkThreatAction
);

/**
 * @route GET /api/admin/threats/timeline/:threatId
 * @desc Get threat timeline and history
 * @access Admin - Threat View
 */
router.get(
  '/timeline/:threatId',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getThreatTimeline
);

/**
 * @route POST /api/admin/threats/simulate
 * @desc Simulate threat scenarios
 * @access Admin - Threat Testing (MFA required)
 */
router.post(
  '/simulate',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canTestThreats,
  MFAMiddleware.requireMFA,
  AdminRateLimitMiddleware.strict,
  AdminAuditMiddleware.logSecurityAction,
  ThreatManagementController.simulateThreatScenario
);

/**
 * @route GET /api/admin/threats/mitigation-strategies
 * @desc Get available mitigation strategies
 * @access Admin - Threat View
 */
router.get(
  '/mitigation-strategies',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canViewThreats,
  ThreatManagementController.getMitigationStrategies
);

/**
 * @route POST /api/admin/threats/containment
 * @desc Execute threat containment
 * @access Admin - Emergency Response (MFA required)
 */
router.post(
  '/containment',
  AdminAuthMiddleware.verifyAdminToken,
  ThreatAccessMiddleware.canExecuteContainment,
  MFAMiddleware.requireMFA,
  AdminAuditMiddleware.logEmergencyAction,
  ThreatManagementController.executeThreatContainment
);

module.exports = router;