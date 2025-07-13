/**
 * @file Super Admin Routes
 * @description Routes for super admin operations
 * @module admin/super-admin/routes
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();
const superAdminController = require('../controllers/super-admin-controller');
const { validateRequestBody, validateQueryParams } = require('../../admin-middleware');
const { superAdminValidation } = require('../validation/super-admin-validation');

// Middleware already applied from parent router
// All routes here require super admin access

/**
 * @route GET /api/admin/super-admin/dashboard
 * @description Get super admin dashboard data
 * @access Super Admin
 */
router.get('/dashboard', superAdminController.getDashboard.bind(superAdminController));

/**
 * @route GET /api/admin/super-admin/overview
 * @description Get system overview and statistics
 * @access Super Admin
 */
router.get('/overview', superAdminController.getSystemOverview.bind(superAdminController));

/**
 * @route GET /api/admin/super-admin/admins
 * @description Get all admin users
 * @access Super Admin
 */
router.get(
    '/admins',
    validateQueryParams(superAdminValidation.getAdminUsersQuery),
    superAdminController.getAdminUsers.bind(superAdminController)
);

/**
 * @route POST /api/admin/super-admin/admins
 * @description Create new admin user
 * @access Super Admin
 */
router.post(
    '/admins',
    validateRequestBody(superAdminValidation.createAdminUser),
    superAdminController.createAdminUser.bind(superAdminController)
);

/**
 * @route PUT /api/admin/super-admin/admins/:id
 * @description Update admin user
 * @access Super Admin
 */
router.put(
    '/admins/:id',
    validateRequestBody(superAdminValidation.updateAdminUser),
    superAdminController.updateAdminUser.bind(superAdminController)
);

/**
 * @route POST /api/admin/super-admin/admins/:id/revoke
 * @description Revoke admin access
 * @access Super Admin
 */
router.post(
    '/admins/:id/revoke',
    validateRequestBody(superAdminValidation.revokeAdminAccess),
    superAdminController.revokeAdminAccess.bind(superAdminController)
);

/**
 * @route GET /api/admin/super-admin/activity-logs
 * @description Get system activity logs
 * @access Super Admin
 */
router.get(
    '/activity-logs',
    validateQueryParams(superAdminValidation.getActivityLogsQuery),
    superAdminController.getSystemActivityLogs.bind(superAdminController)
);

/**
 * @route POST /api/admin/super-admin/maintenance
 * @description Execute system maintenance task
 * @access Super Admin
 */
router.post(
    '/maintenance',
    validateRequestBody(superAdminValidation.executeMaintenanceTask),
    superAdminController.executeMaintenanceTask.bind(superAdminController)
);

/**
 * @route GET /api/admin/super-admin/permissions
 * @description Get super admin permissions
 * @access Super Admin
 */
router.get('/permissions', superAdminController.getPermissions.bind(superAdminController));

/**
 * @route POST /api/admin/super-admin/export
 * @description Export system data
 * @access Super Admin
 */
router.post(
    '/export',
    validateRequestBody(superAdminValidation.exportSystemData),
    superAdminController.exportSystemData.bind(superAdminController)
);

module.exports = router;