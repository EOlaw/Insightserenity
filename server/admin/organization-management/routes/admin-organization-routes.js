// server/admin/organization-management/routes/admin-organization-routes.js
/**
 * @file Admin Organization Routes
 * @description Routes for administrative organization management operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const AdminOrganizationController = require('../controllers/admin-organization-controller');

// Middleware
const { requireOrganizationManagementPermission, verifyOrganizationScope, requireElevatedPrivileges, trackOrganizationManagementAction, validateCrossOrganizationOperation } = require('../middleware/organization-access');
const { adminRateLimiter } = require('../../../shared/admin/middleware/admin-rate-limiting');
const { cacheMiddleware } = require('../../../shared/admin/middleware/admin-cache-middleware');

// Validation
const { middleware: organizationValidationMiddleware } = require('../validation/organization-management-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * @route   GET /api/admin/organizations
 * @desc    List all organizations with advanced filtering
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS permission
 */
router.get(
  '/',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS),
  organizationValidationMiddleware.validateListOrganizations,
  cacheMiddleware('organizations_list', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_organizations_list'),
  adminRateLimiter('organizationList'),
  AdminOrganizationController.listOrganizations
);

/**
 * @route   GET /api/admin/organizations/search
 * @desc    Search organizations with advanced filters
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS permission
 */
router.get(
  '/search',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS),
  organizationValidationMiddleware.validateOrganizationSearch,
  trackOrganizationManagementAction('search_organizations'),
  adminRateLimiter('organizationSearch'),
  AdminOrganizationController.searchOrganizations
);

/**
 * @route   GET /api/admin/organizations/:organizationId
 * @desc    Get detailed organization information
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS permission
 */
router.get(
  '/:organizationId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS),
  verifyOrganizationScope,
  cacheMiddleware('organization_detail', 600), // 10 minutes cache
  trackOrganizationManagementAction('view_organization_detail'),
  adminRateLimiter('organizationView'),
  AdminOrganizationController.getOrganizationDetail
);

/**
 * @route   POST /api/admin/organizations
 * @desc    Create new organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.CREATE_ORGANIZATION permission
 */
router.post(
  '/',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.CREATE_ORGANIZATION),
  requireElevatedPrivileges({ requireMFA: true }),
  organizationValidationMiddleware.validateCreateOrganization,
  trackOrganizationManagementAction('create_organization'),
  adminRateLimiter('organizationCreate'),
  AdminOrganizationController.createOrganization
);

/**
 * @route   PUT /api/admin/organizations/:organizationId
 * @desc    Update organization details
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.UPDATE_ORGANIZATION permission
 */
router.put(
  '/:organizationId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.UPDATE_ORGANIZATION),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateUpdateOrganization,
  trackOrganizationManagementAction('update_organization'),
  adminRateLimiter('organizationUpdate'),
  AdminOrganizationController.updateOrganization
);

/**
 * @route   POST /api/admin/organizations/:organizationId/suspend
 * @desc    Suspend organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SUSPEND_ORGANIZATION permission
 */
router.post(
  '/:organizationId/suspend',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SUSPEND_ORGANIZATION),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateSuspendOrganization,
  trackOrganizationManagementAction('suspend_organization'),
  adminRateLimiter('organizationSuspend'),
  AdminOrganizationController.suspendOrganization
);

/**
 * @route   POST /api/admin/organizations/:organizationId/reactivate
 * @desc    Reactivate suspended organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SUSPEND_ORGANIZATION permission
 */
router.post(
  '/:organizationId/reactivate',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SUSPEND_ORGANIZATION),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateReactivateOrganization,
  trackOrganizationManagementAction('reactivate_organization'),
  adminRateLimiter('organizationReactivate'),
  AdminOrganizationController.reactivateOrganization
);

/**
 * @route   DELETE /api/admin/organizations/:organizationId
 * @desc    Delete organization (soft delete)
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.DELETE_ORGANIZATION permission
 */
router.delete(
  '/:organizationId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.DELETE_ORGANIZATION),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true,
    requireRecentAuth: true
  }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateDeleteOrganization,
  trackOrganizationManagementAction('delete_organization'),
  adminRateLimiter('organizationDelete'),
  AdminOrganizationController.deleteOrganization
);

/**
 * @route   POST /api/admin/organizations/:organizationId/transfer-ownership
 * @desc    Transfer organization ownership
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.TRANSFER_OWNERSHIP permission
 */
router.post(
  '/:organizationId/transfer-ownership',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.TRANSFER_OWNERSHIP),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateTransferOwnership,
  trackOrganizationManagementAction('transfer_ownership'),
  adminRateLimiter('ownershipTransfer'),
  AdminOrganizationController.transferOwnership
);

/**
 * @route   GET /api/admin/organizations/:organizationId/audit-logs
 * @desc    Get organization audit logs
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_AUDIT_LOGS permission
 */
router.get(
  '/:organizationId/audit-logs',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_AUDIT_LOGS),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateGetAuditLogs,
  cacheMiddleware('organization_audit_logs', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_audit_logs'),
  adminRateLimiter('auditLogView'),
  AdminOrganizationController.getOrganizationAuditLogs
);

/**
 * @route   POST /api/admin/organizations/:organizationId/settings
 * @desc    Update organization settings
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.UPDATE_SETTINGS permission
 */
router.post(
  '/:organizationId/settings',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.UPDATE_SETTINGS),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateUpdateSettings,
  trackOrganizationManagementAction('update_settings'),
  adminRateLimiter('settingsUpdate'),
  AdminOrganizationController.updateOrganizationSettings
);

/**
 * @route   POST /api/admin/organizations/:organizationId/limits
 * @desc    Set organization resource limits
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SET_LIMITS permission
 */
router.post(
  '/:organizationId/limits',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SET_LIMITS),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateSetLimits,
  trackOrganizationManagementAction('set_resource_limits'),
  adminRateLimiter('limitsUpdate'),
  AdminOrganizationController.setOrganizationLimits
);

/**
 * @route   POST /api/admin/organizations/bulk/update
 * @desc    Bulk update organizations
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.BULK_UPDATE permission
 */
router.post(
  '/bulk/update',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.BULK_UPDATE),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateCrossOrganizationOperation,
  organizationValidationMiddleware.validateBulkUpdate,
  trackOrganizationManagementAction('bulk_update_organizations'),
  adminRateLimiter('bulkOrganizationUpdate'),
  AdminOrganizationController.bulkUpdateOrganizations
);

/**
 * @route   POST /api/admin/organizations/bulk/suspend
 * @desc    Bulk suspend organizations
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.BULK_SUSPEND permission
 */
router.post(
  '/bulk/suspend',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.BULK_SUSPEND),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateCrossOrganizationOperation,
  organizationValidationMiddleware.validateBulkSuspend,
  trackOrganizationManagementAction('bulk_suspend_organizations'),
  adminRateLimiter('bulkOrganizationSuspend'),
  AdminOrganizationController.bulkSuspendOrganizations
);

/**
 * @route   GET /api/admin/organizations/:organizationId/team
 * @desc    Get organization team members
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS permission
 */
router.get(
  '/:organizationId/team',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateGetTeam,
  cacheMiddleware('organization_team', 600), // 10 minutes cache
  trackOrganizationManagementAction('view_team_members'),
  adminRateLimiter('teamView'),
  AdminOrganizationController.getOrganizationTeam
);

/**
 * @route   POST /api/admin/organizations/:organizationId/team/member
 * @desc    Add team member to organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_TEAM permission
 */
router.post(
  '/:organizationId/team/member',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_TEAM),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateAddTeamMember,
  trackOrganizationManagementAction('add_team_member'),
  adminRateLimiter('teamUpdate'),
  AdminOrganizationController.addTeamMember
);

/**
 * @route   DELETE /api/admin/organizations/:organizationId/team/member/:userId
 * @desc    Remove team member from organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_TEAM permission
 */
router.delete(
  '/:organizationId/team/member/:userId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_TEAM),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  trackOrganizationManagementAction('remove_team_member'),
  adminRateLimiter('teamUpdate'),
  AdminOrganizationController.removeTeamMember
);

/**
 * @route   POST /api/admin/organizations/:organizationId/export
 * @desc    Export organization data
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.EXPORT_DATA permission
 */
router.post(
  '/:organizationId/export',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.EXPORT_DATA),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requireRecentAuth: true
  }),
  verifyOrganizationScope,
  organizationValidationMiddleware.validateExportData,
  trackOrganizationManagementAction('export_organization_data'),
  adminRateLimiter('dataExport'),
  AdminOrganizationController.exportOrganizationData
);

/**
 * @route   GET /api/admin/organizations/:organizationId/integrations
 * @desc    Get organization integrations
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_INTEGRATIONS permission
 */
router.get(
  '/:organizationId/integrations',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_INTEGRATIONS),
  verifyOrganizationScope,
  cacheMiddleware('organization_integrations', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_integrations'),
  adminRateLimiter('integrationsView'),
  AdminOrganizationController.getOrganizationIntegrations
);

module.exports = router;