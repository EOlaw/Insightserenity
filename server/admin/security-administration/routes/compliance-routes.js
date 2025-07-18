// server/admin/security-administration/routes/compliance-routes.js
/**
 * @file Compliance Administration Routes
 * @description Routes for compliance management operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const ComplianceController = require('../controllers/compliance-controller');

// Middleware
const { validateRequest } = require('../../../shared/middleware/validate-request');
const ComplianceValidation = require('../validation/compliance-validation');
const AdminAuthMiddleware = require('../../../shared/admin/middleware/admin-authentication');
const ComplianceAccessMiddleware = require('../middleware/compliance-check');
const AdminAuditMiddleware = require('../../../shared/admin/middleware/admin-audit-logging');
const AdminRateLimitMiddleware = require('../../../shared/admin/middleware/admin-rate-limiting');
const MFAMiddleware = require('../../../shared/admin/middleware/multi-factor-validation');

/**
 * @swagger
 * tags:
 *   name: Admin Compliance
 *   description: Compliance management and assessment endpoints
 */

/**
 * @route GET /api/admin/compliance/standards
 * @desc Get compliance standards
 * @access Admin - Compliance View
 */
router.get(
  '/standards',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  validateRequest(ComplianceValidation.getStandards),
  ComplianceController.getComplianceStandards
);

/**
 * @route POST /api/admin/compliance/standards
 * @desc Manage compliance standards
 * @access Admin - Compliance Configure (MFA required)
 */
router.post(
  '/standards',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canConfigureCompliance,
  MFAMiddleware.requireMFA,
  validateRequest(ComplianceValidation.manageStandard),
  AdminAuditMiddleware.logConfigChange,
  ComplianceController.manageComplianceStandard
);

/**
 * @route GET /api/admin/compliance/standards/:standardId
 * @desc Get compliance standard details
 * @access Admin - Compliance View
 */
router.get(
  '/standards/:standardId',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getStandardDetails
);

/**
 * @route POST /api/admin/compliance/assessments
 * @desc Perform compliance assessment
 * @access Admin - Compliance Assess (MFA required)
 */
router.post(
  '/assessments',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canPerformAssessment,
  MFAMiddleware.requireMFA,
  validateRequest(ComplianceValidation.performAssessment),
  AdminAuditMiddleware.logComplianceAction,
  ComplianceController.performComplianceAssessment
);

/**
 * @route GET /api/admin/compliance/assessments
 * @desc Get compliance assessments
 * @access Admin - Compliance View
 */
router.get(
  '/assessments',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  validateRequest(ComplianceValidation.getAssessments),
  ComplianceController.getComplianceAssessments
);

/**
 * @route GET /api/admin/compliance/assessments/:assessmentId
 * @desc Get assessment details
 * @access Admin - Compliance View
 */
router.get(
  '/assessments/:assessmentId',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  validateRequest(ComplianceValidation.getAssessmentDetails),
  ComplianceController.getAssessmentDetails
);

/**
 * @route POST /api/admin/compliance/gaps
 * @desc Manage compliance gaps
 * @access Admin - Compliance Gap Management (MFA required)
 */
router.post(
  '/gaps',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canManageGaps,
  MFAMiddleware.requireMFA,
  validateRequest(ComplianceValidation.manageGap),
  AdminAuditMiddleware.logComplianceAction,
  ComplianceController.manageComplianceGap
);

/**
 * @route GET /api/admin/compliance/gaps
 * @desc Get compliance gaps
 * @access Admin - Compliance View
 */
router.get(
  '/gaps',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getComplianceGaps
);

/**
 * @route GET /api/admin/compliance/gaps/:gapId
 * @desc Get gap details
 * @access Admin - Compliance View
 */
router.get(
  '/gaps/:gapId',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getGapDetails
);

/**
 * @route POST /api/admin/compliance/schedules
 * @desc Schedule compliance activities
 * @access Admin - Compliance Schedule (MFA required)
 */
router.post(
  '/schedules',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canScheduleActivities,
  MFAMiddleware.requireMFA,
  validateRequest(ComplianceValidation.scheduleActivity),
  AdminAuditMiddleware.logConfigChange,
  ComplianceController.scheduleComplianceActivity
);

/**
 * @route GET /api/admin/compliance/schedules
 * @desc Get compliance schedules
 * @access Admin - Compliance View
 */
router.get(
  '/schedules',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getComplianceSchedules
);

/**
 * @route POST /api/admin/compliance/reports
 * @desc Generate compliance report
 * @access Admin - Compliance Reports
 */
router.post(
  '/reports',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canGenerateReports,
  AdminRateLimitMiddleware.moderate,
  validateRequest(ComplianceValidation.generateReport),
  AdminAuditMiddleware.logDataAccess,
  ComplianceController.generateComplianceReport
);

/**
 * @route GET /api/admin/compliance/reports
 * @desc Get compliance report history
 * @access Admin - Compliance View
 */
router.get(
  '/reports',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getReportHistory
);

/**
 * @route GET /api/admin/compliance/reports/:reportId
 * @desc Get compliance report details
 * @access Admin - Compliance View
 */
router.get(
  '/reports/:reportId',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getReportDetails
);

/**
 * @route GET /api/admin/compliance/dashboard
 * @desc Get compliance dashboard data
 * @access Admin - Compliance View
 */
router.get(
  '/dashboard',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  validateRequest(ComplianceValidation.getDashboard),
  ComplianceController.getComplianceDashboard
);

/**
 * @route GET /api/admin/compliance/evidence/:evidenceId
 * @desc Get compliance evidence
 * @access Admin - Compliance View
 */
router.get(
  '/evidence/:evidenceId',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getComplianceEvidence
);

/**
 * @route POST /api/admin/compliance/evidence
 * @desc Upload compliance evidence
 * @access Admin - Compliance Evidence Management
 */
router.post(
  '/evidence',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canManageEvidence,
  AdminAuditMiddleware.logDataAccess,
  ComplianceController.uploadComplianceEvidence
);

/**
 * @route GET /api/admin/compliance/controls
 * @desc Get compliance controls
 * @access Admin - Compliance View
 */
router.get(
  '/controls',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getComplianceControls
);

/**
 * @route PUT /api/admin/compliance/controls/:controlId
 * @desc Update control implementation
 * @access Admin - Compliance Update (MFA required)
 */
router.put(
  '/controls/:controlId',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canUpdateCompliance,
  MFAMiddleware.requireMFA,
  AdminAuditMiddleware.logComplianceAction,
  ComplianceController.updateControlImplementation
);

/**
 * @route GET /api/admin/compliance/remediations
 * @desc Get remediation plans
 * @access Admin - Compliance View
 */
router.get(
  '/remediations',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canViewCompliance,
  ComplianceController.getRemediationPlans
);

/**
 * @route PUT /api/admin/compliance/remediations/:remediationId
 * @desc Update remediation progress
 * @access Admin - Compliance Update
 */
router.put(
  '/remediations/:remediationId',
  AdminAuthMiddleware.verifyAdminToken,
  ComplianceAccessMiddleware.canUpdateCompliance,
  AdminAuditMiddleware.logComplianceAction,
  ComplianceController.updateRemediationProgress
);

module.exports = router;