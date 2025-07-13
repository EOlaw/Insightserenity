/**
 * @file System Settings Controller
 * @description Handles system-wide configuration and settings management
 * @module admin/super-admin/controllers
 * @version 1.0.0
 */

const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../../../shared/admin/utils/admin-helpers');
const { AdminMetrics } = require('../../../shared/admin/utils/admin-metrics');
const { ADMIN_ACTIONS } = require('../../../shared/admin/constants/admin-actions');
const { ADMIN_EVENTS } = require('../../../shared/admin/constants/admin-events');
const SystemSettingsService = require('../services/system-settings-service');
const { AuditService } = require('../../../shared/services/audit-service');
const config = require('../../../config/configuration');

class SystemSettingsController {
    constructor() {
        this.logger = new AdminLogger('SystemSettingsController');
        this.service = new SystemSettingsService();
        this.metrics = AdminMetrics.getInstance();
        this.auditService = new AuditService();
    }

    /**
     * Get all system settings
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getSettings(req, res, next) {
        try {
            const { category, includeSecrets = false } = req.query;

            this.logger.info('Fetching system settings', {
                adminId: req.user.id,
                category,
                includeSecrets
            });

            const settings = await this.service.getAllSettings({
                category,
                includeSecrets: includeSecrets === 'true' && req.user.role === 'super_admin'
            });

            // Audit sensitive data access
            if (includeSecrets === 'true') {
                await this.auditService.logAction({
                    action: ADMIN_ACTIONS.SYSTEM_SETTINGS.VIEW_SECRETS,
                    userId: req.user.id,
                    resourceType: 'system_settings',
                    details: {
                        category,
                        settingsAccessed: Object.keys(settings)
                    },
                    severity: 'high'
                });
            }

            res.json({
                success: true,
                data: settings
            });
        } catch (error) {
            this.logger.error('Error fetching system settings', error);
            next(error);
        }
    }

    /**
     * Get setting by key
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getSettingByKey(req, res, next) {
        try {
            const { key } = req.params;

            this.logger.info('Fetching specific setting', {
                adminId: req.user.id,
                settingKey: key
            });

            const setting = await this.service.getSettingByKey(key);

            if (!setting) {
                return res.status(404).json({
                    success: false,
                    error: {
                        message: 'Setting not found',
                        code: 'SETTING_NOT_FOUND'
                    }
                });
            }

            res.json({
                success: true,
                data: setting
            });
        } catch (error) {
            this.logger.error('Error fetching setting', error);
            next(error);
        }
    }

    /**
     * Update system setting
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async updateSetting(req, res, next) {
        try {
            const { key } = req.params;
            const { value, description, metadata } = req.body;

            this.logger.warn('Updating system setting', {
                adminId: req.user.id,
                settingKey: key,
                hasNewValue: value !== undefined
            });

            // Get previous value for audit
            const previousSetting = await this.service.getSettingByKey(key);
            
            const updatedSetting = await this.service.updateSetting(key, {
                value,
                description,
                metadata,
                updatedBy: req.user.id
            });

            // Record metrics
            this.metrics.incrementCounter('system_settings.updated');

            // Audit configuration change
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SYSTEM_SETTINGS.UPDATE,
                userId: req.user.id,
                resourceType: 'system_setting',
                resourceId: key,
                details: {
                    previousValue: previousSetting?.value,
                    newValue: value,
                    category: updatedSetting.category,
                    metadata
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.SETTING_UPDATED, {
                key,
                previousValue: previousSetting?.value,
                newValue: value,
                updatedBy: req.user.id
            });

            // Invalidate related caches
            await req.adminContext.cache.invalidate(`settings:${key}`);
            await req.adminContext.cache.invalidate(`settings:category:${updatedSetting.category}`);

            res.json({
                success: true,
                message: 'Setting updated successfully',
                data: updatedSetting
            });
        } catch (error) {
            this.logger.error('Error updating setting', error);
            next(error);
        }
    }

    /**
     * Bulk update system settings
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async bulkUpdateSettings(req, res, next) {
        try {
            const { settings } = req.body;

            this.logger.warn('Bulk updating system settings', {
                adminId: req.user.id,
                settingCount: settings.length
            });

            const results = await this.service.bulkUpdateSettings(settings, req.user);

            // Audit configuration changes
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SYSTEM_SETTINGS.BULK_UPDATE,
                userId: req.user.id,
                resourceType: 'system_settings',
                details: {
                    updatedCount: results.updated.length,
                    failedCount: results.failed.length,
                    updatedKeys: results.updated.map(s => s.key)
                },
                severity: 'critical'
            });

            // Emit event for each successful update
            results.updated.forEach(setting => {
                req.adminContext.events.emit(ADMIN_EVENTS.SETTING_UPDATED, {
                    key: setting.key,
                    updatedBy: req.user.id
                });
            });

            // Clear all settings cache
            await req.adminContext.cache.invalidate('settings:*');

            res.json({
                success: true,
                message: `Updated ${results.updated.length} settings`,
                data: {
                    updated: results.updated,
                    failed: results.failed
                }
            });
        } catch (error) {
            this.logger.error('Error bulk updating settings', error);
            next(error);
        }
    }

    /**
     * Reset setting to default value
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async resetSetting(req, res, next) {
        try {
            const { key } = req.params;

            this.logger.warn('Resetting setting to default', {
                adminId: req.user.id,
                settingKey: key
            });

            const resetSetting = await this.service.resetToDefault(key, req.user);

            // Audit action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SYSTEM_SETTINGS.RESET,
                userId: req.user.id,
                resourceType: 'system_setting',
                resourceId: key,
                details: {
                    previousValue: resetSetting.previousValue,
                    defaultValue: resetSetting.value
                },
                severity: 'high'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.SETTING_RESET, {
                key,
                resetBy: req.user.id
            });

            res.json({
                success: true,
                message: 'Setting reset to default value',
                data: resetSetting
            });
        } catch (error) {
            this.logger.error('Error resetting setting', error);
            next(error);
        }
    }

    /**
     * Get system configuration categories
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getCategories(req, res, next) {
        try {
            this.logger.info('Fetching setting categories', {
                adminId: req.user.id
            });

            const categories = await this.service.getCategories();

            res.json({
                success: true,
                data: categories
            });
        } catch (error) {
            this.logger.error('Error fetching categories', error);
            next(error);
        }
    }

    /**
     * Export system configuration
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async exportConfiguration(req, res, next) {
        try {
            const { format = 'json', categories, includeSecrets = false } = req.query;

            this.logger.info('Exporting system configuration', {
                adminId: req.user.id,
                format,
                categories,
                includeSecrets
            });

            const exportData = await this.service.exportConfiguration({
                format,
                categories: categories ? categories.split(',') : null,
                includeSecrets: includeSecrets === 'true' && req.user.role === 'super_admin'
            });

            // Audit export action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SYSTEM_SETTINGS.EXPORT,
                userId: req.user.id,
                resourceType: 'system_configuration',
                details: {
                    format,
                    categories,
                    includeSecrets,
                    settingCount: exportData.settingCount
                },
                severity: 'high'
            });

            res.json({
                success: true,
                message: 'Configuration exported successfully',
                data: {
                    format,
                    content: exportData.content,
                    settingCount: exportData.settingCount,
                    exportedAt: new Date()
                }
            });
        } catch (error) {
            this.logger.error('Error exporting configuration', error);
            next(error);
        }
    }

    /**
     * Import system configuration
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async importConfiguration(req, res, next) {
        try {
            const { configuration, overwrite = false, dryRun = false } = req.body;

            this.logger.warn('Importing system configuration', {
                adminId: req.user.id,
                overwrite,
                dryRun,
                settingCount: Object.keys(configuration).length
            });

            const importResult = await this.service.importConfiguration({
                configuration,
                overwrite,
                dryRun,
                importedBy: req.user.id
            });

            if (!dryRun) {
                // Audit critical action
                await this.auditService.logAction({
                    action: ADMIN_ACTIONS.SYSTEM_SETTINGS.IMPORT,
                    userId: req.user.id,
                    resourceType: 'system_configuration',
                    details: {
                        imported: importResult.imported.length,
                        skipped: importResult.skipped.length,
                        failed: importResult.failed.length,
                        overwrite
                    },
                    severity: 'critical'
                });

                // Emit events
                req.adminContext.events.emit(ADMIN_EVENTS.CONFIGURATION_IMPORTED, {
                    importedBy: req.user.id,
                    results: importResult.summary
                });

                // Clear all settings cache
                await req.adminContext.cache.invalidate('settings:*');
            }

            res.json({
                success: true,
                message: dryRun ? 'Configuration import preview' : 'Configuration imported successfully',
                data: importResult
            });
        } catch (error) {
            this.logger.error('Error importing configuration', error);
            next(error);
        }
    }

    /**
     * Get setting change history
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getSettingHistory(req, res, next) {
        try {
            const { key } = req.params;
            const { limit = 50, startDate, endDate } = req.query;

            this.logger.info('Fetching setting change history', {
                adminId: req.user.id,
                settingKey: key
            });

            const history = await this.service.getSettingHistory({
                key,
                limit: parseInt(limit),
                startDate,
                endDate
            });

            res.json({
                success: true,
                data: history
            });
        } catch (error) {
            this.logger.error('Error fetching setting history', error);
            next(error);
        }
    }

    /**
     * Validate configuration changes
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async validateConfiguration(req, res, next) {
        try {
            const { settings } = req.body;

            this.logger.info('Validating configuration changes', {
                adminId: req.user.id,
                settingCount: settings.length
            });

            const validationResult = await this.service.validateConfiguration(settings);

            res.json({
                success: true,
                data: {
                    valid: validationResult.valid,
                    errors: validationResult.errors,
                    warnings: validationResult.warnings
                }
            });
        } catch (error) {
            this.logger.error('Error validating configuration', error);
            next(error);
        }
    }

    /**
     * Toggle maintenance mode
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async toggleMaintenanceMode(req, res, next) {
        try {
            const { enabled, message, estimatedDuration } = req.body;

            this.logger.warn('Toggling maintenance mode', {
                adminId: req.user.id,
                enabled,
                estimatedDuration
            });

            const result = await this.service.toggleMaintenanceMode({
                enabled,
                message,
                estimatedDuration,
                toggledBy: req.user.id
            });

            // Record metrics
            this.metrics.incrementCounter(`system.maintenance_mode.${enabled ? 'enabled' : 'disabled'}`);

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SYSTEM_SETTINGS.TOGGLE_MAINTENANCE,
                userId: req.user.id,
                resourceType: 'system',
                details: {
                    enabled,
                    message,
                    estimatedDuration
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.MAINTENANCE_MODE_CHANGED, {
                enabled,
                toggledBy: req.user.id,
                message
            });

            // Send notification to all admins
            if (enabled) {
                await req.adminContext.notifications.broadcastToAdmins({
                    type: 'maintenance_mode_enabled',
                    priority: 'high',
                    data: {
                        enabledBy: req.user.email,
                        message,
                        estimatedDuration
                    }
                });
            }

            res.json({
                success: true,
                message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'}`,
                data: result
            });
        } catch (error) {
            this.logger.error('Error toggling maintenance mode', error);
            next(error);
        }
    }
}

module.exports = new SystemSettingsController();