// server/admin/super-admin/routes/role-management-routes.js
/**
 * @file Role Management Routes
 * @description Route definitions for system-wide role and permission management
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const RoleManagementController = require('../controllers/role-management-controller');

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
const { checkResourceLock } = require('../../../shared/middleware/resource-lock');

// Validation
const RoleManagementValidation = require('../validation/role-management-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * Role Management Routes
 * Base path: /api/admin/super-admin/roles
 */

// Apply authentication to all routes
router.use(authenticate);

// Apply super admin only middleware to all routes
router.use(SuperAdminOnly.enforce({
  requireMFA: true,
  requireActiveSession: true,
  checkIPWhitelist: true,
  auditAccess: true,
  customPermission: AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT
}));

/**
 * @route   GET /api/admin/super-admin/roles
 * @desc    Get all system roles with filtering and pagination
 * @access  Super Admin
 */
router.get(
  '/',
  rateLimiter('role_list', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  validateRequest(RoleManagementValidation.searchRoles, 'query'),
  cache({ ttl: 300, key: 'roles_list' }),
  auditLog('roles.list.accessed'),
  RoleManagementController.getAllRoles
);

/**
 * @route   GET /api/admin/super-admin/roles/hierarchy
 * @desc    Get role hierarchy visualization
 * @access  Super Admin
 */
router.get(
  '/hierarchy',
  rateLimiter('role_hierarchy', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  cache({ ttl: 600, key: 'role_hierarchy' }),
  auditLog('roles.hierarchy.viewed'),
  RoleManagementController.getRoleHierarchy
);

/**
 * @route   GET /api/admin/super-admin/roles/export
 * @desc    Export roles configuration
 * @access  Super Admin
 */
router.get(
  '/export',
  rateLimiter('role_export', { max: 5, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'export'),
  CriticalOperation.protect('role.configuration.export', {
    requireDualAuth: false,
    recordDetailed: true
  }),
  auditLog('roles.configuration.exported', { critical: true }),
  RoleManagementController.exportRoles
);

/**
 * @route   POST /api/admin/super-admin/roles/import
 * @desc    Import roles configuration
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/import',
  rateLimiter('role_import', { max: 3, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'import'),
  CriticalOperation.protect('role.configuration.import', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(RoleManagementValidation.importRoles, 'body'),
  auditLog('roles.configuration.imported', { critical: true, alert: true }),
  RoleManagementController.importRoles
);

/**
 * @route   POST /api/admin/super-admin/roles/validate
 * @desc    Validate role configuration without saving
 * @access  Super Admin
 */
router.post(
  '/validate',
  rateLimiter('role_validate', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  validateRequest(RoleManagementValidation.createRole, 'body'),
  RoleManagementController.validateRoleConfiguration
);

/**
 * @route   POST /api/admin/super-admin/roles/merge
 * @desc    Merge multiple roles into one
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/merge',
  rateLimiter('role_merge', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'update'),
  CriticalOperation.protect('role.merge', {
    requireDualAuth: true,
    recordDetailed: true
  }),
  validateRequest(RoleManagementValidation.mergeRoles, 'body'),
  auditLog('roles.merged', { critical: true }),
  RoleManagementController.mergeRoles
);

/**
 * @route   GET /api/admin/super-admin/roles/assignment-history
 * @desc    Get role assignment history
 * @access  Super Admin
 */
router.get(
  '/assignment-history',
  rateLimiter('role_history', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  cache({ ttl: 300, key: 'role_assignment_history' }),
  auditLog('roles.assignment.history.accessed'),
  RoleManagementController.getRoleAssignmentHistory
);

/**
 * @route   POST /api/admin/super-admin/roles
 * @desc    Create a new system role
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/',
  rateLimiter('role_create', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'create'),
  CriticalOperation.protect('role.create', {
    requireDualAuth: false,
    recordDetailed: true
  }),
  validateRequest(RoleManagementValidation.createRole, 'body'),
  sanitize(['body.name', 'body.displayName', 'body.description']),
  auditLog('role.created', { critical: true }),
  RoleManagementController.createRole
);

/**
 * @route   GET /api/admin/super-admin/roles/:roleId
 * @desc    Get detailed role information
 * @access  Super Admin
 */
router.get(
  '/:roleId',
  rateLimiter('role_details', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  cache({ ttl: 300, key: req => `role_${req.params.roleId}` }),
  auditLog('role.details.accessed'),
  RoleManagementController.getRoleDetails
);

/**
 * @route   PUT /api/admin/super-admin/roles/:roleId
 * @desc    Update existing role
 * @access  Super Admin + Critical Operation
 */
router.put(
  '/:roleId',
  rateLimiter('role_update', { max: 20, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'update'),
  checkResourceLock('role', req => req.params.roleId),
  CriticalOperation.protect('role.system.modify', {
    requireDualAuth: false,
    recordDetailed: true
  }),
  validateRequest(RoleManagementValidation.updateRole),
  sanitize(['body.displayName', 'body.description']),
  auditLog('role.updated', { critical: true }),
  RoleManagementController.updateRole
);

/**
 * @route   DELETE /api/admin/super-admin/roles/:roleId
 * @desc    Delete a role
 * @access  Super Admin + Critical Operation
 */
router.delete(
  '/:roleId',
  rateLimiter('role_delete', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'delete'),
  checkResourceLock('role', req => req.params.roleId),
  CriticalOperation.protect('role.delete', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(RoleManagementValidation.deleteRole),
  auditLog('role.deleted', { critical: true, alert: true }),
  RoleManagementController.deleteRole
);

/**
 * @route   POST /api/admin/super-admin/roles/:roleId/clone
 * @desc    Clone an existing role
 * @access  Super Admin
 */
router.post(
  '/:roleId/clone',
  rateLimiter('role_clone', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'create'),
  validateRequest(RoleManagementValidation.cloneRole),
  sanitize(['body.name', 'body.displayName']),
  auditLog('role.cloned'),
  RoleManagementController.cloneRole
);

/**
 * @route   GET /api/admin/super-admin/roles/:roleId/permissions
 * @desc    Get role permissions
 * @access  Super Admin
 */
router.get(
  '/:roleId/permissions',
  rateLimiter('role_permissions', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  cache({ ttl: 300, key: req => `role_permissions_${req.params.roleId}` }),
  auditLog('role.permissions.accessed'),
  RoleManagementController.getRolePermissions
);

/**
 * @route   PUT /api/admin/super-admin/roles/:roleId/permissions
 * @desc    Update role permissions
 * @access  Super Admin + Critical Operation
 */
router.put(
  '/:roleId/permissions',
  rateLimiter('role_permissions_update', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'update'),
  checkResourceLock('role', req => req.params.roleId),
  CriticalOperation.protect('role.permissions.modify', {
    requireDualAuth: req => req.body.permissions?.some(p => p.includes('admin')),
    recordDetailed: true
  }),
  validateRequest(RoleManagementValidation.updatePermissions),
  auditLog('role.permissions.updated', { critical: true }),
  RoleManagementController.updateRolePermissions
);

/**
 * @route   POST /api/admin/super-admin/roles/:roleId/bulk-assign
 * @desc    Bulk assign role to multiple users
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/:roleId/bulk-assign',
  rateLimiter('role_bulk_assign', { max: 5, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'assign'),
  CriticalOperation.protect('role.bulk.assign', {
    requireDualAuth: req => req.body.userIds?.length > 10,
    recordDetailed: true
  }),
  validateRequest(RoleManagementValidation.bulkAssignRole),
  auditLog('role.bulk.assigned', { critical: true }),
  RoleManagementController.bulkAssignRole
);

/**
 * @route   GET /api/admin/super-admin/roles/:roleId/analysis
 * @desc    Analyze role usage and get recommendations
 * @access  Super Admin
 */
router.get(
  '/:roleId/analysis',
  rateLimiter('role_analysis', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  cache({ ttl: 600, key: req => `role_analysis_${req.params.roleId}` }),
  auditLog('role.analysis.performed'),
  RoleManagementController.analyzeRoleUsage
);

/**
 * Permission Management Routes
 */

/**
 * @route   GET /api/admin/super-admin/permissions
 * @desc    Get all available permissions
 * @access  Super Admin
 */
router.get(
  '/permissions',
  rateLimiter('permission_list', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  validateRequest(RoleManagementValidation.searchPermissions, 'query'),
  cache({ ttl: 600, key: 'permissions_list' }),
  auditLog('permissions.list.accessed'),
  RoleManagementController.getAvailablePermissions
);

/**
 * @route   POST /api/admin/super-admin/permissions
 * @desc    Create custom permission
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/permissions',
  rateLimiter('permission_create', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'create'),
  CriticalOperation.protect('permission.create', {
    requireDualAuth: true,
    recordDetailed: true
  }),
  validateRequest(RoleManagementValidation.createPermission, 'body'),
  sanitize(['body.resource', 'body.displayName', 'body.description']),
  auditLog('permission.created', { critical: true }),
  RoleManagementController.createPermission
);

/**
 * @route   PUT /api/admin/super-admin/permissions/:permissionId
 * @desc    Update permission details
 * @access  Super Admin + Critical Operation
 */
router.put(
  '/permissions/:permissionId',
  rateLimiter('permission_update', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'update'),
  CriticalOperation.protect('permission.update', {
    requireDualAuth: true,
    recordDetailed: true
  }),
  auditLog('permission.updated', { critical: true }),
  RoleManagementController.updatePermission
);

/**
 * @route   DELETE /api/admin/super-admin/permissions/:permissionId
 * @desc    Delete custom permission
 * @access  Super Admin + Critical Operation
 */
router.delete(
  '/permissions/:permissionId',
  rateLimiter('permission_delete', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'delete'),
  CriticalOperation.protect('permission.delete', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  auditLog('permission.deleted', { critical: true, alert: true }),
  RoleManagementController.deletePermission
);

/**
 * @route   GET /api/admin/super-admin/permissions/matrix
 * @desc    Get permission matrix for all roles
 * @access  Super Admin
 */
router.get(
  '/permissions/matrix',
  rateLimiter('permission_matrix', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  cache({ ttl: 600, key: 'permission_matrix' }),
  auditLog('permissions.matrix.accessed'),
  RoleManagementController.getPermissionMatrix
);

/**
 * @route   POST /api/admin/super-admin/permissions/analyze
 * @desc    Analyze permission conflicts and redundancies
 * @access  Super Admin
 */
router.post(
  '/permissions/analyze',
  rateLimiter('permission_analyze', { max: 10, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT, 'read'),
  auditLog('permissions.analysis.performed'),
  RoleManagementController.analyzePermissions
);

/**
 * Error handling middleware for role management routes
 */
router.use((error, req, res, next) => {
  // Log role-related critical errors
  if (error.severity === 'critical' || error.statusCode === 500) {
    logger.critical('Role management route error', {
      error: error.message,
      path: req.path,
      method: req.method,
      user: req.user?.id,
      roleId: req.params?.roleId,
      stack: error.stack
    });
  }

  next(error);
});

module.exports = router;