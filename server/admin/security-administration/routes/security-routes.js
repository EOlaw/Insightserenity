// server/admin/security-administration/routes/security-routes.js
/**
 * @file Security Administration Routes
 * @description Routes for security management operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const SecurityController = require('../controllers/security-controller');

// Middleware
const { validateRequest } = require('../../../shared/middleware/validate-request');
const SecurityValidation = require('../validation/security-validation');
const AdminAuthMiddleware = require('../../../shared/admin/middleware/admin-authentication');
const SecurityAccessMiddleware = require('../middleware/security-clearance');
const AdminAuditMiddleware = require('../../../shared/admin/middleware/admin-audit-logging');
const AdminRateLimitMiddleware = require('../../../shared/admin/middleware/admin-rate-limiting');
const MFAMiddleware = require('../../../shared/admin/middleware/multi-factor-validation');

/**
 * @swagger
 * tags:
 *   name: Admin Security
 *   description: Security administration and management endpoints
 */

/**
 * @route GET /api/admin/security/overview
 * @desc Get security overview and dashboard data
 * @access Admin - Security View
 */
router.get(
  '/overview',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  validateRequest(SecurityValidation.getOverview),
  SecurityController.getSecurityOverview
);

/**
 * @route PUT /api/admin/security/settings
 * @desc Update security settings
 * @access Admin - Security Update (MFA required)
 */
router.put(
  '/settings',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canUpdateSecurity,
  MFAMiddleware.requireMFA,
  validateRequest(SecurityValidation.updateSettings),
  AdminAuditMiddleware.logConfigChange,
  SecurityController.updateSecuritySettings
);

/**
 * @route POST /api/admin/security/policies
 * @desc Manage security policies
 * @access Admin - Security Policy Management (MFA required)
 */
router.post(
  '/policies',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canManagePolicies,
  MFAMiddleware.requireMFA,
  validateRequest(SecurityValidation.managePolicy),
  AdminAuditMiddleware.logCriticalAction,
  SecurityController.manageSecurityPolicy
);

/**
 * @route GET /api/admin/security/policies
 * @desc Get security policies
 * @access Admin - Security View
 */
router.get(
  '/policies',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getSecurityPolicies
);

/**
 * @route POST /api/admin/security/ip-management
 * @desc Manage IP whitelist/blacklist
 * @access Admin - Security IP Management (MFA required)
 */
router.post(
  '/ip-management',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canManageIPLists,
  MFAMiddleware.requireMFA,
  validateRequest(SecurityValidation.manageIpList),
  AdminAuditMiddleware.logSecurityAction,
  SecurityController.manageIpList
);

/**
 * @route GET /api/admin/security/ip-lists
 * @desc Get IP whitelist and blacklist
 * @access Admin - Security View
 */
router.get(
  '/ip-lists',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getIpLists
);

/**
 * @route POST /api/admin/security/threat-detection
 * @desc Configure threat detection rules
 * @access Admin - Security Threat Management (MFA required)
 */
router.post(
  '/threat-detection',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canManageThreats,
  MFAMiddleware.requireMFA,
  validateRequest(SecurityValidation.configureThreatDetection),
  AdminAuditMiddleware.logSecurityAction,
  SecurityController.configureThreatDetection
);

/**
 * @route POST /api/admin/security/scan
 * @desc Perform security scan
 * @access Admin - Security Scan (MFA required)
 */
router.post(
  '/scan',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canPerformScan,
  MFAMiddleware.requireMFA,
  AdminRateLimitMiddleware.strict,
  validateRequest(SecurityValidation.performScan),
  AdminAuditMiddleware.logSecurityAction,
  SecurityController.performSecurityScan
);

/**
 * @route GET /api/admin/security/scans
 * @desc Get security scan history
 * @access Admin - Security View
 */
router.get(
  '/scans',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getScanHistory
);

/**
 * @route GET /api/admin/security/scans/:scanId
 * @desc Get security scan details
 * @access Admin - Security View
 */
router.get(
  '/scans/:scanId',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getScanDetails
);

/**
 * @route POST /api/admin/security/incidents
 * @desc Manage security incidents
 * @access Admin - Security Incident Management (MFA required)
 */
router.post(
  '/incidents',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canManageIncidents,
  MFAMiddleware.requireMFA,
  validateRequest(SecurityValidation.manageIncident),
  AdminAuditMiddleware.logCriticalAction,
  SecurityController.manageSecurityIncident
);

/**
 * @route GET /api/admin/security/incidents
 * @desc Get security incidents
 * @access Admin - Security View
 */
router.get(
  '/incidents',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getSecurityIncidents
);

/**
 * @route GET /api/admin/security/incidents/:incidentId
 * @desc Get incident details
 * @access Admin - Security View
 */
router.get(
  '/incidents/:incidentId',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getIncidentDetails
);

/**
 * @route POST /api/admin/security/reports
 * @desc Generate security report
 * @access Admin - Security Reports
 */
router.post(
  '/reports',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canGenerateReports,
  AdminRateLimitMiddleware.moderate,
  validateRequest(SecurityValidation.generateReport),
  AdminAuditMiddleware.logDataAccess,
  SecurityController.generateSecurityReport
);

/**
 * @route GET /api/admin/security/vulnerabilities
 * @desc Get vulnerability list
 * @access Admin - Security View
 */
router.get(
  '/vulnerabilities',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getVulnerabilities
);

/**
 * @route PUT /api/admin/security/vulnerabilities/:vulnerabilityId
 * @desc Update vulnerability status
 * @access Admin - Security Update (MFA required)
 */
router.put(
  '/vulnerabilities/:vulnerabilityId',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canUpdateSecurity,
  MFAMiddleware.requireMFA,
  AdminAuditMiddleware.logSecurityAction,
  SecurityController.updateVulnerabilityStatus
);

/**
 * @route GET /api/admin/security/activity
 * @desc Get security activity log
 * @access Admin - Security View
 */
router.get(
  '/activity',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canViewSecurity,
  SecurityController.getSecurityActivity
);

/**
 * @route POST /api/admin/security/emergency-response
 * @desc Initiate emergency security response
 * @access Admin - Emergency Access (MFA required)
 */
router.post(
  '/emergency-response',
  AdminAuthMiddleware.verifyAdminToken,
  SecurityAccessMiddleware.canInitiateEmergencyResponse,
  MFAMiddleware.requireMFA,
  AdminAuditMiddleware.logEmergencyAction,
  SecurityController.initiateEmergencyResponse
);

module.exports = router;