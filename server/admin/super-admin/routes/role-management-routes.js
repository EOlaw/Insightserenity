/**
 * @file Role Management Routes
 * @description Routes for admin role and permission management
 * @module admin/super-admin/routes
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();
const roleManagementController = require('../controllers/role-management-controller');
const { validateRequestBody, validateQueryParams } = require('../../admin-middleware');
const { roleValidation } = require('../../../shared/admin/validation/security-validation');

/**
 * @route GET /api/admin/roles
 * @description Get all admin roles
 * @access Super Admin
 */
router.get(
    '/',
    validateQueryParams(roleValidation.getRolesQuery),
    roleManagementController.getRoles.bind(roleManagementController)
);

/**
 * @route GET /api/admin/roles/permissions
 * @description Get all available permissions
 * @access Super Admin
 */
router.get(
    '/permissions',
    validateQueryParams(roleValidation.getPermissionsQuery),
    roleManagementController.getPermissions.bind(roleManagementController)
);

/**
 * @route GET /api/admin/roles/:id
 * @description Get role by ID
 * @access Super Admin
 */
router.get('/:id', roleManagementController.getRoleById.bind(roleManagementController));

/**
 * @route POST /api/admin/roles
 * @description Create custom admin role
 * @access Super Admin
 */
router.post(
    '/',
    validateRequestBody(roleValidation.createRole),
    roleManagementController.createRole.bind(roleManagementController)
);

/**
 * @route PUT /api/admin/roles/:id
 * @description Update admin role
 * @access Super Admin
 */
router.put(
    '/:id',
    validateRequestBody(roleValidation.updateRole),
    roleManagementController.updateRole.bind(roleManagementController)
);

/**
 * @route DELETE /api/admin/roles/:id
 * @description Delete custom admin role
 * @access Super Admin
 */
router.delete(
    '/:id',
    validateRequestBody(roleValidation.deleteRole),
    roleManagementController.deleteRole.bind(roleManagementController)
);

/**
 * @route POST /api/admin/roles/assign
 * @description Assign role to admin user
 * @access Super Admin
 */
router.post(
    '/assign',
    validateRequestBody(roleValidation.assignRole),
    roleManagementController.assignRole.bind(roleManagementController)
);

/**
 * @route POST /api/admin/roles/revoke/:userId
 * @description Revoke role from admin user
 * @access Super Admin
 */
router.post(
    '/revoke/:userId',
    validateRequestBody(roleValidation.revokeRole),
    roleManagementController.revokeRole.bind(roleManagementController)
);

/**
 * @route GET /api/admin/roles/history/:userId
 * @description Get role assignment history for user
 * @access Super Admin
 */
router.get(
    '/history/:userId',
    validateQueryParams(roleValidation.getRoleHistoryQuery),
    roleManagementController.getRoleHistory.bind(roleManagementController)
);

/**
 * @route POST /api/admin/roles/:id/clone
 * @description Clone existing role
 * @access Super Admin
 */
router.post(
    '/:id/clone',
    validateRequestBody(roleValidation.cloneRole),
    roleManagementController.cloneRole.bind(roleManagementController)
);

module.exports = router;