/**
 * @file Emergency Access Routes
 * @description Routes for emergency access and break-glass procedures
 * @module admin/super-admin/routes
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();
const emergencyAccessController = require('../controllers/emergency-access-controller');
const { 
    validateRequestBody, 
    validateQueryParams,
    enforceMFAForCriticalOps 
} = require('../../admin-middleware');
const { emergencyAccessValidation } = require('../validation/emergency-access-validation');

/**
 * @route POST /api/admin/emergency/request
 * @description Request emergency access
 * @access Admin with proper permissions
 */
router.post(
    '/request',
    validateRequestBody(emergencyAccessValidation.requestEmergencyAccess),
    emergencyAccessController.requestEmergencyAccess.bind(emergencyAccessController)
);

/**
 * @route GET /api/admin/emergency/requests
 * @description Get emergency access requests
 * @access Super Admin
 */
router.get(
    '/requests',
    validateQueryParams(emergencyAccessValidation.getRequestsQuery),
    emergencyAccessController.getEmergencyAccessRequests.bind(emergencyAccessController)
);

/**
 * @route POST /api/admin/emergency/requests/:id/approve
 * @description Approve emergency access request
 * @access Super Admin with MFA
 */
router.post(
    '/requests/:id/approve',
    enforceMFAForCriticalOps,
    validateRequestBody(emergencyAccessValidation.approveEmergencyAccess),
    emergencyAccessController.approveEmergencyAccess.bind(emergencyAccessController)
);

/**
 * @route POST /api/admin/emergency/requests/:id/deny
 * @description Deny emergency access request
 * @access Super Admin
 */
router.post(
    '/requests/:id/deny',
    validateRequestBody(emergencyAccessValidation.denyEmergencyAccess),
    emergencyAccessController.denyEmergencyAccess.bind(emergencyAccessController)
);

/**
 * @route GET /api/admin/emergency/active
 * @description Get active emergency accesses
 * @access Super Admin
 */
router.get(
    '/active',
    emergencyAccessController.getActiveEmergencyAccesses.bind(emergencyAccessController)
);

/**
 * @route POST /api/admin/emergency/revoke/:id
 * @description Revoke active emergency access
 * @access Super Admin with MFA
 */
router.post(
    '/revoke/:id',
    enforceMFAForCriticalOps,
    validateRequestBody(emergencyAccessValidation.revokeEmergencyAccess),
    emergencyAccessController.revokeEmergencyAccess.bind(emergencyAccessController)
);

/**
 * @route GET /api/admin/emergency/audit/:id
 * @description Get emergency access audit trail
 * @access Super Admin
 */
router.get(
    '/audit/:id',
    emergencyAccessController.getEmergencyAccessAuditTrail.bind(emergencyAccessController)
);

/**
 * @route POST /api/admin/emergency/break-glass
 * @description Execute break-glass procedure
 * @access Super Admin with MFA and verification
 */
router.post(
    '/break-glass',
    enforceMFAForCriticalOps,
    validateRequestBody(emergencyAccessValidation.executeBreakGlass),
    emergencyAccessController.executeBreakGlass.bind(emergencyAccessController)
);

/**
 * @route GET /api/admin/emergency/report
 * @description Generate emergency access report
 * @access Super Admin
 */
router.get(
    '/report',
    validateQueryParams(emergencyAccessValidation.getReportQuery),
    emergencyAccessController.generateEmergencyAccessReport.bind(emergencyAccessController)
);

module.exports = router;