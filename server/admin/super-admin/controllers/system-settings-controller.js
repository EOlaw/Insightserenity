// server/admin/super-admin/controllers/system-settings-controller.js
/**
 * @file System Settings Controller
 * @description Controller for managing global system configuration and settings
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const SystemSettingsService = require('../services/system-settings-service');
const AuditService = require('../../../shared/security/services/audit-service');
const BackupService = require('../../../shared/admin/services/admin-backup-service');
const CacheService = require('../../../shared/utils/cache-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const ResponseHandler = require('../../../shared/utils/response-handler');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');

// Validation
const { validateRequest } = require('../../../shared/middleware/validate-request');
const SystemSettingsValidation = require('../validation/system-settings-validation');

/**
 * System Settings Controller Class
 * @class SystemSettingsController
 */
class SystemSettingsController {
  /**
   * Get all system settings
   * @route GET /api/admin/super-admin/settings
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getAllSettings(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        category,
        search,
        includeSecrets = 'false',
        includeHistory = 'false',
        groupByCategory = 'true'
      } = req.query;

      logger.info('Get all settings requested', {
        adminId: adminUser.id,
        filters: { category, search },
        includeSecrets: includeSecrets === 'true'
      });

      const result = await SystemSettingsService.getAllSettings(adminUser, {
        category,
        search,
        includeSecrets: includeSecrets === 'true',
        includeHistory: includeHistory === 'true',
        groupByCategory: groupByCategory === 'true'
      });

      ResponseHandler.success(res, {
        message: 'System settings retrieved successfully',
        data: {
          settings: result.settings,
          metadata: result.metadata
        }
      });

    } catch (error) {
      logger.error('Get all settings error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get specific setting by key
   * @route GET /api/admin/super-admin/settings/:settingKey
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getSettingByKey(req, res, next) {
    try {
      const adminUser = req.user;
      const { settingKey } = req.params;

      logger.info('Get setting by key requested', {
        adminId: adminUser.id,
        settingKey
      });

      const setting = await SystemSettingsService.getSettingByKey(adminUser, settingKey);

      ResponseHandler.success(res, {
        message: 'Setting retrieved successfully',
        data: setting
      });

    } catch (error) {
      logger.error('Get setting by key error', {
        error: error.message,
        adminId: req.user?.id,
        settingKey: req.params?.settingKey,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Update system setting
   * @route PUT /api/admin/super-admin/settings/:settingKey
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async updateSetting(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.updateSetting, req);

      const adminUser = req.user;
      const { settingKey } = req.params;
      const updateData = req.body;

      logger.warn('Update setting requested', {
        adminId: adminUser.id,
        settingKey,
        testMode: updateData.testMode
      });

      const result = await SystemSettingsService.updateSetting(
        adminUser,
        settingKey,
        updateData
      );

      // Handle confirmation requirement for critical changes
      if (result.requiresConfirmation) {
        return ResponseHandler.success(res, {
          message: result.message,
          data: {
            requiresConfirmation: true,
            impact: result.impact
          }
        }, 202);
      }

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          setting: result.setting,
          change: result.change,
          impact: result.impact
        }
      });

    } catch (error) {
      logger.error('Update setting error', {
        error: error.message,
        adminId: req.user?.id,
        settingKey: req.params?.settingKey,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Bulk update settings
   * @route PUT /api/admin/super-admin/settings/bulk
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async bulkUpdateSettings(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.bulkUpdateSettings, req);

      const adminUser = req.user;
      const { updates, options } = req.body;

      logger.warn('Bulk update settings requested', {
        adminId: adminUser.id,
        updateCount: updates.length,
        testMode: options?.testMode
      });

      const result = await SystemSettingsService.bulkUpdateSettings(
        adminUser,
        updates,
        options
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          results: result.results,
          summary: result.summary,
          backupId: result.backupId
        }
      });

    } catch (error) {
      logger.error('Bulk update settings error', {
        error: error.message,
        adminId: req.user?.id,
        updateCount: req.body?.updates?.length,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Reset setting to default
   * @route POST /api/admin/super-admin/settings/:settingKey/reset
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async resetSetting(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.resetSetting, req);

      const adminUser = req.user;
      const { settingKey } = req.params;
      const { reason, notifyServices = true } = req.body;

      logger.warn('Reset setting requested', {
        adminId: adminUser.id,
        settingKey
      });

      const result = await SystemSettingsService.resetSetting(
        adminUser,
        settingKey,
        { reason, notifyServices }
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          setting: result.setting,
          backupId: result.backupId
        }
      });

    } catch (error) {
      logger.error('Reset setting error', {
        error: error.message,
        adminId: req.user?.id,
        settingKey: req.params?.settingKey,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get feature flags
   * @route GET /api/admin/super-admin/feature-flags
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getFeatureFlags(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        environment = 'all',
        includeMetrics = 'false',
        includeHistory = 'false'
      } = req.query;

      logger.info('Get feature flags requested', {
        adminId: adminUser.id,
        environment
      });

      const result = await SystemSettingsService.getFeatureFlags(adminUser, {
        environment,
        includeMetrics: includeMetrics === 'true',
        includeHistory: includeHistory === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Feature flags retrieved successfully',
        data: {
          flags: result.flags,
          environments: result.environments,
          summary: result.summary
        }
      });

    } catch (error) {
      logger.error('Get feature flags error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Update feature flag
   * @route PUT /api/admin/super-admin/feature-flags/:flagKey
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async updateFeatureFlag(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.updateFeatureFlag, req);

      const adminUser = req.user;
      const { flagKey } = req.params;
      const updateData = req.body;

      logger.info('Update feature flag requested', {
        adminId: adminUser.id,
        flagKey,
        environment: updateData.environment
      });

      const result = await SystemSettingsService.updateFeatureFlag(
        adminUser,
        flagKey,
        updateData
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          flag: result.flag,
          impact: result.impact,
          changes: result.changes
        }
      });

    } catch (error) {
      logger.error('Update feature flag error', {
        error: error.message,
        adminId: req.user?.id,
        flagKey: req.params?.flagKey,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Create feature flag
   * @route POST /api/admin/super-admin/feature-flags
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async createFeatureFlag(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.createFeatureFlag, req);

      const adminUser = req.user;
      const flagData = req.body;

      logger.info('Create feature flag requested', {
        adminId: adminUser.id,
        flagKey: flagData.key
      });

      const flag = await SystemSettingsService.createFeatureFlag(adminUser, flagData);

      ResponseHandler.success(res, {
        message: 'Feature flag created successfully',
        data: flag
      }, 201);

    } catch (error) {
      logger.error('Create feature flag error', {
        error: error.message,
        adminId: req.user?.id,
        flagKey: req.body?.key,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Export configuration
   * @route GET /api/admin/super-admin/settings/export
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async exportConfiguration(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        includeSettings = 'true',
        includeFeatureFlags = 'true',
        includeTemplates = 'true',
        format = 'json',
        encrypt = 'true',
        categories
      } = req.query;

      logger.warn('Export configuration requested', {
        adminId: adminUser.id,
        format,
        encrypt: encrypt === 'true'
      });

      const result = await SystemSettingsService.exportConfiguration(adminUser, {
        includeSettings: includeSettings === 'true',
        includeFeatureFlags: includeFeatureFlags === 'true',
        includeTemplates: includeTemplates === 'true',
        format,
        encrypt: encrypt === 'true',
        categories: categories ? categories.split(',') : null
      });

      if (req.query.download === 'true') {
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${result.metadata.filename}"`);
        return res.send(result.export);
      }

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          export: result.export,
          metadata: result.metadata
        }
      });

    } catch (error) {
      logger.error('Export configuration error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Import configuration
   * @route POST /api/admin/super-admin/settings/import
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async importConfiguration(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.importConfiguration, req);

      const adminUser = req.user;
      const { data, options } = req.body;

      logger.critical('Import configuration requested', {
        adminId: adminUser.id,
        testMode: options?.testMode,
        merge: options?.merge
      });

      const result = await SystemSettingsService.importConfiguration(
        adminUser,
        data,
        options
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          results: result.results,
          backupId: result.backupId
        }
      }, 201);

    } catch (error) {
      logger.error('Import configuration error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get configuration templates
   * @route GET /api/admin/super-admin/settings/templates
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getConfigurationTemplates(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        category,
        environment,
        includeInactive = 'false'
      } = req.query;

      logger.info('Get configuration templates requested', {
        adminId: adminUser.id,
        category,
        environment
      });

      const result = await SystemSettingsService.getConfigurationTemplates(adminUser, {
        category,
        environment,
        includeInactive: includeInactive === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Configuration templates retrieved successfully',
        data: result
      });

    } catch (error) {
      logger.error('Get configuration templates error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Apply configuration template
   * @route POST /api/admin/super-admin/settings/templates/:templateId/apply
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async applyConfigurationTemplate(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.applyTemplate, req);

      const adminUser = req.user;
      const { templateId } = req.params;
      const { environment, testMode = false, overrides = {} } = req.body;

      logger.warn('Apply configuration template requested', {
        adminId: adminUser.id,
        templateId,
        environment,
        testMode
      });

      const result = await SystemSettingsService.applyConfigurationTemplate(
        adminUser,
        templateId,
        {
          environment,
          testMode,
          overrides
        }
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: result
      });

    } catch (error) {
      logger.error('Apply configuration template error', {
        error: error.message,
        adminId: req.user?.id,
        templateId: req.params?.templateId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get setting history
   * @route GET /api/admin/super-admin/settings/:settingKey/history
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getSettingHistory(req, res, next) {
    try {
      const adminUser = req.user;
      const { settingKey } = req.params;
      const { limit = 20, startDate, endDate } = req.query;

      logger.info('Get setting history requested', {
        adminId: adminUser.id,
        settingKey,
        limit
      });

      const history = await SystemSettingsService.getSettingHistory(
        adminUser,
        settingKey,
        {
          limit: parseInt(limit),
          startDate: startDate ? new Date(startDate) : undefined,
          endDate: endDate ? new Date(endDate) : undefined
        }
      );

      ResponseHandler.success(res, {
        message: 'Setting history retrieved successfully',
        data: history
      });

    } catch (error) {
      logger.error('Get setting history error', {
        error: error.message,
        adminId: req.user?.id,
        settingKey: req.params?.settingKey,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Validate configuration
   * @route POST /api/admin/super-admin/settings/validate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async validateConfiguration(req, res, next) {
    try {
      const adminUser = req.user;
      const { settings, checkDependencies = true, checkConflicts = true } = req.body;

      logger.info('Validate configuration requested', {
        adminId: adminUser.id,
        settingCount: Object.keys(settings).length
      });

      const validation = await SystemSettingsService.validateConfiguration(
        adminUser,
        settings,
        {
          checkDependencies,
          checkConflicts
        }
      );

      ResponseHandler.success(res, {
        message: 'Configuration validated',
        data: validation
      });

    } catch (error) {
      logger.error('Validate configuration error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Create configuration backup
   * @route POST /api/admin/super-admin/settings/backup
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async createConfigurationBackup(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.createBackup, req);

      const adminUser = req.user;
      const { name, description, categories, includeAuditLogs = false } = req.body;

      logger.info('Create configuration backup requested', {
        adminId: adminUser.id,
        name,
        includeAuditLogs
      });

      const backup = await BackupService.createConfigurationBackup({
        adminId: adminUser.id,
        name,
        description,
        categories,
        includeAuditLogs
      });

      ResponseHandler.success(res, {
        message: 'Configuration backup created successfully',
        data: {
          backupId: backup.id,
          filename: backup.filename,
          size: backup.size,
          checksum: backup.checksum
        }
      }, 201);

    } catch (error) {
      logger.error('Create configuration backup error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Restore configuration from backup
   * @route POST /api/admin/super-admin/settings/restore
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async restoreConfiguration(req, res, next) {
    try {
      await validateRequest(SystemSettingsValidation.restoreBackup, req);

      const adminUser = req.user;
      const { backupId, testMode = true, categories } = req.body;

      logger.critical('Restore configuration requested', {
        adminId: adminUser.id,
        backupId,
        testMode
      });

      const result = await BackupService.restoreConfigurationBackup({
        adminId: adminUser.id,
        backupId,
        testMode,
        categories
      });

      ResponseHandler.success(res, {
        message: result.message,
        data: result
      });

    } catch (error) {
      logger.error('Restore configuration error', {
        error: error.message,
        adminId: req.user?.id,
        backupId: req.body?.backupId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get configuration health status
   * @route GET /api/admin/super-admin/settings/health
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getConfigurationHealth(req, res, next) {
    try {
      const adminUser = req.user;
      const { detailed = 'false' } = req.query;

      logger.info('Get configuration health requested', {
        adminId: adminUser.id,
        detailed: detailed === 'true'
      });

      const health = await SystemSettingsService.getConfigurationHealth(adminUser, {
        detailed: detailed === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Configuration health retrieved successfully',
        data: health
      });

    } catch (error) {
      logger.error('Get configuration health error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Search settings
   * @route GET /api/admin/super-admin/settings/search
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async searchSettings(req, res, next) {
    try {
      const adminUser = req.user;
      const { query, categories, valueTypes, page = 1, limit = 20 } = req.query;

      if (!query || query.trim().length < 2) {
        throw new ValidationError('Search query must be at least 2 characters');
      }

      logger.info('Search settings requested', {
        adminId: adminUser.id,
        query,
        categories
      });

      const results = await SystemSettingsService.searchSettings(adminUser, {
        query,
        categories: categories ? categories.split(',') : null,
        valueTypes: valueTypes ? valueTypes.split(',') : null,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit)
        }
      });

      ResponseHandler.success(res, {
        message: 'Search completed successfully',
        data: results.settings,
        pagination: results.pagination
      });

    } catch (error) {
      logger.error('Search settings error', {
        error: error.message,
        adminId: req.user?.id,
        query: req.query?.query,
        stack: error.stack
      });
      next(error);
    }
  }
}

module.exports = new SystemSettingsController();