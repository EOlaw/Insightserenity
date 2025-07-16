// server/admin/user-management/routes/admin-user-routes.js
/**
 * @file Admin User Routes
 * @description Routes for admin user management operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const AdminUserController = require('../controllers/admin-user-controller');

// Middleware
const { requireUserManagementPermission, verifyTargetUserAccess, verifyOrganizationScope, requireElevatedPrivileges, validateSensitiveDataAccess, trackUserManagementAction } = require('../middleware/user-management-auth');
const { adminRateLimiter } = require('../../../shared/admin/middleware/admin-rate-limiting');

// Validation
const { middleware: validationMiddleware } = require('../validation/user-management-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * @route   GET /api/admin/users
 * @desc    Get users with filtering and pagination
 * @access  Admin - Requires USER_MANAGEMENT.VIEW permission
 */
router.get(
  '/',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW),
  verifyOrganizationScope,
  validateSensitiveDataAccess,
  validationMiddleware.validateGetUsers,
  trackUserManagementAction('list_users'),
  adminRateLimiter('userList'),
  AdminUserController.getUsers
);

/**
 * @route   GET /api/admin/users/:userId
 * @desc    Get detailed user information
 * @access  Admin - Requires USER_MANAGEMENT.VIEW permission
 */
router.get(
  '/:userId',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW),
  verifyTargetUserAccess,
  validateSensitiveDataAccess,
  trackUserManagementAction('view_user'),
  adminRateLimiter('userView'),
  AdminUserController.getUserDetails
);

/**
 * @route   POST /api/admin/users
 * @desc    Create new user
 * @access  Admin - Requires USER_MANAGEMENT.CREATE permission
 */
router.post(
  '/',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.CREATE),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  validationMiddleware.validateCreateUser,
  trackUserManagementAction('create_user'),
  adminRateLimiter('userCreate'),
  AdminUserController.createUser
);

/**
 * @route   PUT /api/admin/users/:userId
 * @desc    Update user information
 * @access  Admin - Requires USER_MANAGEMENT.UPDATE permission
 */
router.put(
  '/:userId',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.UPDATE),
  verifyTargetUserAccess,
  verifyOrganizationScope,
  validationMiddleware.validateUpdateUser,
  trackUserManagementAction('update_user'),
  adminRateLimiter('userUpdate'),
  AdminUserController.updateUser
);

/**
 * @route   DELETE /api/admin/users/:userId
 * @desc    Delete user account
 * @access  Admin - Requires USER_MANAGEMENT.DELETE permission
 */
router.delete(
  '/:userId',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.DELETE),
  requireElevatedPrivileges({ 
    requireMFA: true, 
    requirePasswordConfirmation: true 
  }),
  verifyTargetUserAccess,
  validationMiddleware.validateDeleteUser,
  trackUserManagementAction('delete_user'),
  adminRateLimiter('userDelete'),
  AdminUserController.deleteUser
);

/**
 * @route   POST /api/admin/users/:userId/reset-password
 * @desc    Reset user password
 * @access  Admin - Requires USER_MANAGEMENT.RESET_PASSWORD permission
 */
router.post(
  '/:userId/reset-password',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.RESET_PASSWORD),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyTargetUserAccess,
  validationMiddleware.validateResetPassword,
  trackUserManagementAction('reset_password'),
  adminRateLimiter('passwordReset'),
  AdminUserController.resetUserPassword
);

/**
 * @route   POST /api/admin/users/:userId/suspension
 * @desc    Toggle user suspension
 * @access  Admin - Requires USER_MANAGEMENT.SUSPEND permission
 */
router.post(
  '/:userId/suspension',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.SUSPEND),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyTargetUserAccess,
  validationMiddleware.validateToggleSuspension,
  trackUserManagementAction('toggle_suspension'),
  adminRateLimiter('userSuspend'),
  AdminUserController.toggleUserSuspension
);

/**
 * @route   POST /api/admin/users/:userId/force-logout
 * @desc    Force user logout across all sessions
 * @access  Admin - Requires USER_MANAGEMENT.FORCE_LOGOUT permission
 */
router.post(
  '/:userId/force-logout',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.FORCE_LOGOUT),
  verifyTargetUserAccess,
  validationMiddleware.validateForceLogout,
  trackUserManagementAction('force_logout'),
  adminRateLimiter('forceLogout'),
  AdminUserController.forceUserLogout
);

/**
 * @route   GET /api/admin/users/:userId/activity
 * @desc    Get user activity logs
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ACTIVITY permission
 */
router.get(
  '/:userId/activity',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ACTIVITY),
  verifyTargetUserAccess,
  validationMiddleware.validateUserActivity,
  trackUserManagementAction('view_activity'),
  adminRateLimiter('activityView'),
  AdminUserController.getUserActivity
);

/**
 * @route   GET /api/admin/users/:userId/sessions
 * @desc    Get user sessions
 * @access  Admin - Requires USER_MANAGEMENT.VIEW permission
 */
router.get(
  '/:userId/sessions',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW),
  verifyTargetUserAccess,
  validationMiddleware.validateUserSessions,
  trackUserManagementAction('view_sessions'),
  adminRateLimiter('sessionView'),
  AdminUserController.getUserSessions
);

/**
 * @route   PUT /api/admin/users/:userId/permissions
 * @desc    Update user permissions
 * @access  Admin - Requires USER_MANAGEMENT.MANAGE_PERMISSIONS permission
 */
router.put(
  '/:userId/permissions',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.MANAGE_PERMISSIONS),
  requireElevatedPrivileges({ 
    requireMFA: true, 
    requireRecentAuth: true 
  }),
  verifyTargetUserAccess,
  validationMiddleware.validateUpdatePermissions,
  trackUserManagementAction('update_permissions'),
  adminRateLimiter('permissionUpdate'),
  AdminUserController.updateUserPermissions
);

/**
 * @route   POST /api/admin/users/:userId/send-password-reset
 * @desc    Send password reset email to user
 * @access  Admin - Requires USER_MANAGEMENT.SEND_COMMUNICATIONS permission
 */
router.post(
  '/:userId/send-password-reset',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.SEND_COMMUNICATIONS),
  verifyTargetUserAccess,
  validationMiddleware.validateSendPasswordResetEmail,
  trackUserManagementAction('send_password_reset'),
  adminRateLimiter('sendEmail'),
  AdminUserController.sendPasswordResetEmail
);

/**
 * @route   POST /api/admin/users/:userId/verify-email
 * @desc    Manually verify user email
 * @access  Admin - Requires USER_MANAGEMENT.VERIFY_ACCOUNTS permission
 */
router.post(
  '/:userId/verify-email',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VERIFY_ACCOUNTS),
  verifyTargetUserAccess,
  validationMiddleware.validateVerifyEmail,
  trackUserManagementAction('verify_email'),
  adminRateLimiter('verifyEmail'),
  AdminUserController.verifyUserEmail
);

/**
 * @route   GET /api/admin/users/:userId/audit-logs
 * @desc    Get user-specific audit logs
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_AUDIT_LOGS permission
 */
router.get(
  '/:userId/audit-logs',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_AUDIT_LOGS),
  verifyTargetUserAccess,
  validationMiddleware.validateAuditLogs,
  trackUserManagementAction('view_audit_logs'),
  adminRateLimiter('auditLogView'),
  AdminUserController.getUserAuditLogs
);

module.exports = router;