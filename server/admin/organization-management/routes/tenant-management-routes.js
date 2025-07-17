// server/admin/organization-management/routes/tenant-management-routes.js
/**
 * @file Tenant Management Routes
 * @description Routes for managing organization tenant infrastructure
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const TenantManagementController = require('../controllers/tenant-management-controller');

// Middleware
const { requireOrganizationManagementPermission, verifyOrganizationScope, requireElevatedPrivileges, trackOrganizationManagementAction, validateTenantOperation } = require('../middleware/organization-access');
const { adminRateLimiter } = require('../../../shared/admin/middleware/admin-rate-limiting');
const { cacheMiddleware } = require('../../../shared/admin/middleware/admin-cache-middleware');
const { tenantIsolation } = require('../middleware/tenant-isolation');

// Validation
const { middleware: tenantValidationMiddleware } = require('../validation/tenant-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * @route   GET /api/admin/tenants
 * @desc    List all tenants across organizations
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_TENANTS permission
 */
router.get(
  '/',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_TENANTS),
  tenantValidationMiddleware.validateListTenants,
  cacheMiddleware('tenants_list', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_tenants_list'),
  adminRateLimiter('tenantList'),
  TenantManagementController.listTenants
);

/**
 * @route   GET /api/admin/tenants/:tenantId
 * @desc    Get detailed tenant information
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_TENANTS permission
 */
router.get(
  '/:tenantId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_TENANTS),
  validateTenantOperation,
  cacheMiddleware('tenant_detail', 600), // 10 minutes cache
  trackOrganizationManagementAction('view_tenant_detail'),
  adminRateLimiter('tenantView'),
  TenantManagementController.getTenantDetail
);

/**
 * @route   POST /api/admin/tenants/provision
 * @desc    Provision new tenant for organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.PROVISION_TENANT permission
 */
router.post(
  '/provision',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.PROVISION_TENANT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  tenantValidationMiddleware.validateProvisionTenant,
  trackOrganizationManagementAction('provision_tenant'),
  adminRateLimiter('tenantProvision'),
  TenantManagementController.provisionTenant
);

/**
 * @route   PUT /api/admin/tenants/:tenantId/configuration
 * @desc    Update tenant configuration
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_TENANTS permission
 */
router.put(
  '/:tenantId/configuration',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_TENANTS),
  requireElevatedPrivileges({ requireMFA: true }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateUpdateConfiguration,
  trackOrganizationManagementAction('update_tenant_config'),
  adminRateLimiter('tenantUpdate'),
  TenantManagementController.updateTenantConfiguration
);

/**
 * @route   POST /api/admin/tenants/:tenantId/migrate
 * @desc    Migrate tenant to different infrastructure
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MIGRATE_TENANT permission
 */
router.post(
  '/:tenantId/migrate',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MIGRATE_TENANT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true,
    requireRecentAuth: true
  }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateMigrateTenant,
  trackOrganizationManagementAction('migrate_tenant'),
  adminRateLimiter('tenantMigration'),
  TenantManagementController.migrateTenant
);

/**
 * @route   GET /api/admin/tenants/:tenantId/resources
 * @desc    Get tenant resource usage
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_RESOURCES permission
 */
router.get(
  '/:tenantId/resources',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_RESOURCES),
  validateTenantOperation,
  tenantIsolation,
  cacheMiddleware('tenant_resources', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_tenant_resources'),
  adminRateLimiter('resourceView'),
  TenantManagementController.getTenantResources
);

/**
 * @route   PUT /api/admin/tenants/:tenantId/resources/limits
 * @desc    Update tenant resource limits
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SET_LIMITS permission
 */
router.put(
  '/:tenantId/resources/limits',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SET_LIMITS),
  requireElevatedPrivileges({ requireMFA: true }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateResourceLimits,
  trackOrganizationManagementAction('update_resource_limits'),
  adminRateLimiter('limitsUpdate'),
  TenantManagementController.updateResourceLimits
);

/**
 * @route   POST /api/admin/tenants/:tenantId/backup
 * @desc    Create tenant backup
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.BACKUP_TENANT permission
 */
router.post(
  '/:tenantId/backup',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.BACKUP_TENANT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requireRecentAuth: true
  }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateBackupTenant,
  trackOrganizationManagementAction('backup_tenant'),
  adminRateLimiter('tenantBackup'),
  TenantManagementController.backupTenant
);

/**
 * @route   POST /api/admin/tenants/:tenantId/restore
 * @desc    Restore tenant from backup
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.RESTORE_TENANT permission
 */
router.post(
  '/:tenantId/restore',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.RESTORE_TENANT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true,
    requireRecentAuth: true
  }),
  validateTenantOperation,
  tenantValidationMiddleware.validateRestoreTenant,
  trackOrganizationManagementAction('restore_tenant'),
  adminRateLimiter('tenantRestore'),
  TenantManagementController.restoreTenant
);

/**
 * @route   POST /api/admin/tenants/:tenantId/suspend
 * @desc    Suspend tenant operations
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SUSPEND_TENANT permission
 */
router.post(
  '/:tenantId/suspend',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SUSPEND_TENANT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateSuspendTenant,
  trackOrganizationManagementAction('suspend_tenant'),
  adminRateLimiter('tenantSuspend'),
  TenantManagementController.suspendTenant
);

/**
 * @route   POST /api/admin/tenants/:tenantId/reactivate
 * @desc    Reactivate suspended tenant
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SUSPEND_TENANT permission
 */
router.post(
  '/:tenantId/reactivate',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SUSPEND_TENANT),
  requireElevatedPrivileges({ requireMFA: true }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateReactivateTenant,
  trackOrganizationManagementAction('reactivate_tenant'),
  adminRateLimiter('tenantReactivate'),
  TenantManagementController.reactivateTenant
);

/**
 * @route   DELETE /api/admin/tenants/:tenantId
 * @desc    Delete tenant (with data archival)
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.DELETE_TENANT permission
 */
router.delete(
  '/:tenantId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.DELETE_TENANT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true,
    requireRecentAuth: true
  }),
  validateTenantOperation,
  tenantValidationMiddleware.validateDeleteTenant,
  trackOrganizationManagementAction('delete_tenant'),
  adminRateLimiter('tenantDelete'),
  TenantManagementController.deleteTenant
);

/**
 * @route   GET /api/admin/tenants/:tenantId/health
 * @desc    Get tenant health status
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_HEALTH permission
 */
router.get(
  '/:tenantId/health',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_HEALTH),
  validateTenantOperation,
  tenantIsolation,
  cacheMiddleware('tenant_health', 60), // 1 minute cache
  trackOrganizationManagementAction('view_tenant_health'),
  adminRateLimiter('healthCheck'),
  TenantManagementController.getTenantHealth
);

/**
 * @route   GET /api/admin/tenants/:tenantId/metrics
 * @desc    Get tenant metrics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_METRICS permission
 */
router.get(
  '/:tenantId/metrics',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_METRICS),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateGetMetrics,
  cacheMiddleware('tenant_metrics', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_tenant_metrics'),
  adminRateLimiter('metricsView'),
  TenantManagementController.getTenantMetrics
);

/**
 * @route   POST /api/admin/tenants/:tenantId/maintenance
 * @desc    Enable/disable tenant maintenance mode
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MAINTENANCE_MODE permission
 */
router.post(
  '/:tenantId/maintenance',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MAINTENANCE_MODE),
  requireElevatedPrivileges({ requireMFA: true }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateMaintenanceMode,
  trackOrganizationManagementAction('toggle_maintenance_mode'),
  adminRateLimiter('maintenanceToggle'),
  TenantManagementController.toggleMaintenanceMode
);

/**
 * @route   GET /api/admin/tenants/:tenantId/database
 * @desc    Get tenant database information
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_DATABASE permission
 */
router.get(
  '/:tenantId/database',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_DATABASE),
  validateTenantOperation,
  tenantIsolation,
  cacheMiddleware('tenant_database', 600), // 10 minutes cache
  trackOrganizationManagementAction('view_database_info'),
  adminRateLimiter('databaseView'),
  TenantManagementController.getTenantDatabaseInfo
);

/**
 * @route   POST /api/admin/tenants/:tenantId/scaling
 * @desc    Scale tenant resources
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SCALE_TENANT permission
 */
router.post(
  '/:tenantId/scaling',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SCALE_TENANT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateTenantOperation,
  tenantIsolation,
  tenantValidationMiddleware.validateScaleTenant,
  trackOrganizationManagementAction('scale_tenant_resources'),
  adminRateLimiter('tenantScaling'),
  TenantManagementController.scaleTenantResources
);

/**
 * @route   POST /api/admin/tenants/bulk/update
 * @desc    Bulk update tenant configurations
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.BULK_TENANT_UPDATE permission
 */
router.post(
  '/bulk/update',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.BULK_TENANT_UPDATE),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  tenantValidationMiddleware.validateBulkUpdate,
  trackOrganizationManagementAction('bulk_update_tenants'),
  adminRateLimiter('bulkTenantUpdate'),
  TenantManagementController.bulkUpdateTenants
);

module.exports = router;