// server/admin/organization-management/controllers/tenant-management-controller.js
/**
 * @file Tenant Management Controller
 * @description Controller for managing organization tenant infrastructure
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const TenantManagementService = require('../services/tenant-management-service');
const AdminOrganizationService = require('../services/admin-organization-service');
const AuditService = require('../../../shared/security/services/audit-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizer');
const ResponseFormatter = require('../../../shared/utils/response-formatter');

// Validation
const {
  validateTenantConfigUpdate,
  validateResourceLimits,
  validateMigrationConfig,
  validateMaintenanceConfig,
  validateTenantReset,
  validateCloneConfig
} = require('../validation/tenant-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * Tenant Management Controller Class
 * @class TenantManagementController
 */
class TenantManagementController {
  /**
   * Get tenant details
   * @route GET /api/admin/tenants/:tenantId
   * @access Admin
   */
  getTenantDetails = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const options = {
        includeUsage: req.query.includeUsage === 'true',
        includeHealth: req.query.includeHealth === 'true',
        includeConfiguration: req.query.includeConfiguration === 'true',
        includeMetrics: req.query.includeMetrics === 'true'
      };
      
      const tenant = await TenantManagementService.getTenantDetails(
        tenantId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          tenant,
          'Tenant details retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getTenantDetails:', error);
      next(error);
    }
  });

  /**
   * Update tenant configuration
   * @route PUT /api/admin/tenants/:tenantId/configuration
   * @access Admin - Platform Admin or higher
   */
  updateTenantConfiguration = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      // Validate configuration updates
      const { error, value } = validateTenantConfigUpdate(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const configUpdates = sanitizeBody(value);
      
      const options = {
        validateChanges: req.body.validateChanges !== false,
        applyImmediately: req.body.applyImmediately || false,
        notifyUsers: req.body.notifyUsers !== false
      };
      
      const tenant = await TenantManagementService.updateTenantConfiguration(
        tenantId,
        configUpdates,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          tenant,
          'Tenant configuration updated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in updateTenantConfiguration:', error);
      next(error);
    }
  });

  /**
   * Update tenant resource limits
   * @route PUT /api/admin/tenants/:tenantId/resource-limits
   * @access Admin - Platform Admin or higher
   */
  updateResourceLimits = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      // Validate resource limits
      const { error, value } = validateResourceLimits(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const newLimits = sanitizeBody(value);
      
      const options = {
        reason: req.body.reason || 'Administrative adjustment',
        skipNotifications: req.body.skipNotifications || false,
        enforceImmediately: req.body.enforceImmediately || false
      };
      
      const tenant = await TenantManagementService.updateResourceLimits(
        tenantId,
        newLimits,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          tenant,
          'Resource limits updated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in updateResourceLimits:', error);
      next(error);
    }
  });

  /**
   * Migrate tenant infrastructure
   * @route POST /api/admin/tenants/:tenantId/migrate
   * @access Admin - Super Admin only
   */
  migrateTenant = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      // Validate migration configuration
      const { error, value } = validateMigrationConfig(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const migrationConfig = sanitizeBody(value);
      
      const options = {
        dryRun: req.body.dryRun || false,
        notifyUsers: req.body.notifyUsers !== false,
        scheduleAt: req.body.scheduleAt
      };
      
      const result = await TenantManagementService.migrateTenant(
        tenantId,
        migrationConfig,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Tenant migration initiated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in migrateTenant:', error);
      next(error);
    }
  });

  /**
   * Enable/disable maintenance mode
   * @route POST /api/admin/tenants/:tenantId/maintenance
   * @access Admin - Platform Admin or higher
   */
  setMaintenanceMode = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      // Validate maintenance configuration
      const { error, value } = validateMaintenanceConfig(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const { enabled, config } = sanitizeBody(value);
      
      const tenant = await TenantManagementService.setMaintenanceMode(
        tenantId,
        enabled,
        config,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          tenant,
          `Maintenance mode ${enabled ? 'enabled' : 'disabled'} successfully`
        )
      );
    } catch (error) {
      logger.error('Error in setMaintenanceMode:', error);
      next(error);
    }
  });

  /**
   * Monitor tenant health
   * @route GET /api/admin/tenants/:tenantId/health
   * @access Admin
   */
  monitorTenantHealth = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const health = await TenantManagementService.monitorTenantHealth(
        tenantId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          health,
          'Tenant health check completed'
        )
      );
    } catch (error) {
      logger.error('Error in monitorTenantHealth:', error);
      next(error);
    }
  });

  /**
   * Reset tenant data
   * @route POST /api/admin/tenants/:tenantId/reset
   * @access Admin - Super Admin only
   */
  resetTenantData = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      // Validate reset configuration
      const { error, value } = validateTenantReset(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const resetConfig = sanitizeBody(value);
      
      const result = await TenantManagementService.resetTenantData(
        tenantId,
        resetConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Tenant data reset completed'
        )
      );
    } catch (error) {
      logger.error('Error in resetTenantData:', error);
      next(error);
    }
  });

  /**
   * Clone tenant configuration
   * @route POST /api/admin/tenants/clone-config
   * @access Admin - Platform Admin or higher
   */
  cloneTenantConfiguration = asyncHandler(async (req, res, next) => {
    try {
      // Validate clone configuration
      const { error, value } = validateCloneConfig(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const { sourceTenantId, targetTenantId, config } = sanitizeBody(value);
      
      if (!mongoose.isValidObjectId(sourceTenantId) || !mongoose.isValidObjectId(targetTenantId)) {
        throw new ValidationError('Invalid tenant ID(s)');
      }
      
      const result = await TenantManagementService.cloneTenantConfiguration(
        sourceTenantId,
        targetTenantId,
        config,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Tenant configuration cloned successfully'
        )
      );
    } catch (error) {
      logger.error('Error in cloneTenantConfiguration:', error);
      next(error);
    }
  });

  /**
   * Get tenant resource usage report
   * @route GET /api/admin/tenants/:tenantId/resource-report
   * @access Admin
   */
  getTenantResourceReport = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      const query = sanitizeQuery(req.query);
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const options = {
        period: query.period || 'month',
        startDate: query.startDate,
        endDate: query.endDate,
        includeProjections: query.includeProjections === 'true',
        format: query.format || 'json'
      };
      
      const report = await TenantManagementService.getTenantResourceReport(
        tenantId,
        options,
        req.user
      );
      
      // Handle different format outputs
      if (options.format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="tenant_resource_report_${tenantId}_${Date.now()}.csv"`);
        res.send(report.csvData);
      } else {
        res.status(200).json(
          ResponseFormatter.success(
            report,
            'Resource report generated successfully'
          )
        );
      }
    } catch (error) {
      logger.error('Error in getTenantResourceReport:', error);
      next(error);
    }
  });

  /**
   * Get all tenants overview
   * @route GET /api/admin/tenants
   * @access Admin
   */
  getAllTenants = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      const filters = {
        status: query.status,
        plan: query.plan,
        search: query.search,
        databaseStrategy: query.databaseStrategy,
        hasIssues: query.hasIssues === 'true',
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 20
      };
      
      const options = {
        sort: query.sort || '-createdAt',
        includeHealth: query.includeHealth === 'true',
        includeUsage: query.includeUsage === 'true'
      };
      
      const result = await TenantManagementService.getAllTenants(
        filters,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Tenants retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getAllTenants:', error);
      next(error);
    }
  });

  /**
   * Bulk update tenant configurations
   * @route POST /api/admin/tenants/bulk/update-config
   * @access Admin - Platform Admin or higher
   */
  bulkUpdateConfiguration = asyncHandler(async (req, res, next) => {
    try {
      const { tenantIds, updates } = req.body;
      
      if (!Array.isArray(tenantIds) || tenantIds.length === 0) {
        throw new ValidationError('Tenant IDs array is required');
      }
      
      // Validate all tenant IDs
      tenantIds.forEach(id => {
        if (!mongoose.isValidObjectId(id)) {
          throw new ValidationError(`Invalid tenant ID: ${id}`);
        }
      });
      
      const options = {
        skipFailures: req.body.skipFailures || false,
        notifyUsers: req.body.notifyUsers !== false
      };
      
      const results = await TenantManagementService.bulkUpdateConfiguration(
        tenantIds,
        updates,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          results,
          'Bulk configuration update completed'
        )
      );
    } catch (error) {
      logger.error('Error in bulkUpdateConfiguration:', error);
      next(error);
    }
  });

  /**
   * Get tenant migration status
   * @route GET /api/admin/tenants/:tenantId/migration-status
   * @access Admin
   */
  getMigrationStatus = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const status = await TenantManagementService.getMigrationStatus(
        tenantId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          status,
          'Migration status retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getMigrationStatus:', error);
      next(error);
    }
  });

  /**
   * Cancel tenant migration
   * @route POST /api/admin/tenants/:tenantId/cancel-migration
   * @access Admin - Super Admin only
   */
  cancelMigration = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const result = await TenantManagementService.cancelMigration(
        tenantId,
        req.body.reason,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Migration cancelled successfully'
        )
      );
    } catch (error) {
      logger.error('Error in cancelMigration:', error);
      next(error);
    }
  });

  /**
   * Optimize tenant resources
   * @route POST /api/admin/tenants/:tenantId/optimize
   * @access Admin - Platform Admin or higher
   */
  optimizeTenantResources = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const optimizationConfig = {
        compactDatabase: req.body.compactDatabase !== false,
        cleanupOrphanedData: req.body.cleanupOrphanedData !== false,
        optimizeIndexes: req.body.optimizeIndexes !== false,
        archiveOldData: req.body.archiveOldData || false,
        archiveBeforeDate: req.body.archiveBeforeDate
      };
      
      const result = await TenantManagementService.optimizeTenantResources(
        tenantId,
        optimizationConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Tenant resources optimized successfully'
        )
      );
    } catch (error) {
      logger.error('Error in optimizeTenantResources:', error);
      next(error);
    }
  });

  /**
   * Get tenant backup status
   * @route GET /api/admin/tenants/:tenantId/backups
   * @access Admin
   */
  getTenantBackups = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const backups = await TenantManagementService.getTenantBackups(
        tenantId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          backups,
          'Tenant backups retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getTenantBackups:', error);
      next(error);
    }
  });

  /**
   * Create tenant backup
   * @route POST /api/admin/tenants/:tenantId/backup
   * @access Admin - Platform Admin or higher
   */
  createTenantBackup = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const backupConfig = {
        type: req.body.type || 'full',
        includeFiles: req.body.includeFiles !== false,
        compress: req.body.compress !== false,
        encrypt: req.body.encrypt !== false,
        description: req.body.description
      };
      
      const backup = await TenantManagementService.createTenantBackup(
        tenantId,
        backupConfig,
        req.user
      );
      
      res.status(201).json(
        ResponseFormatter.success(
          backup,
          'Tenant backup created successfully'
        )
      );
    } catch (error) {
      logger.error('Error in createTenantBackup:', error);
      next(error);
    }
  });

  /**
   * Restore tenant from backup
   * @route POST /api/admin/tenants/:tenantId/restore
   * @access Admin - Super Admin only
   */
  restoreTenantBackup = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      const { backupId } = req.body;
      
      if (!mongoose.isValidObjectId(tenantId) || !backupId) {
        throw new ValidationError('Valid tenant ID and backup ID are required');
      }
      
      const restoreConfig = {
        backupId,
        restoreData: req.body.restoreData !== false,
        restoreConfiguration: req.body.restoreConfiguration !== false,
        restoreUsers: req.body.restoreUsers || false,
        createNewBackup: req.body.createNewBackup !== false
      };
      
      const result = await TenantManagementService.restoreTenantBackup(
        tenantId,
        restoreConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Tenant restored from backup successfully'
        )
      );
    } catch (error) {
      logger.error('Error in restoreTenantBackup:', error);
      next(error);
    }
  });

  /**
   * Get tenant compliance status
   * @route GET /api/admin/tenants/:tenantId/compliance
   * @access Admin
   */
  getTenantCompliance = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const compliance = await TenantManagementService.getTenantCompliance(
        tenantId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          compliance,
          'Tenant compliance status retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getTenantCompliance:', error);
      next(error);
    }
  });

  /**
   * Update tenant security settings
   * @route PUT /api/admin/tenants/:tenantId/security
   * @access Admin - Platform Admin or higher
   */
  updateSecuritySettings = asyncHandler(async (req, res, next) => {
    try {
      const { tenantId } = req.params;
      
      if (!mongoose.isValidObjectId(tenantId)) {
        throw new ValidationError('Invalid tenant ID');
      }
      
      const securityUpdates = sanitizeBody(req.body);
      
      const tenant = await TenantManagementService.updateSecuritySettings(
        tenantId,
        securityUpdates,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          tenant,
          'Security settings updated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in updateSecuritySettings:', error);
      next(error);
    }
  });
}

module.exports = new TenantManagementController();