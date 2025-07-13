/**
 * @file System Settings Service
 * @description Service for managing system-wide configuration and settings
 * @module admin/super-admin/services
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminCacheService } = require('../../../shared/admin/services/admin-cache-service');
const { AdminBaseService } = require('../../../shared/admin/services/admin-base-service');
const { AdminEventEmitter } = require('../../../shared/admin/services/admin-event-emitter');
const SystemSetting = require('../../../models/system-setting-model');
const SettingHistory = require('../../../models/setting-history-model');
const config = require('../../../config/configuration');
const Joi = require('joi');

class SystemSettingsService extends AdminBaseService {
    constructor() {
        super('SystemSettingsService');
        this.cache = AdminCacheService.getInstance();
        this.eventEmitter = AdminEventEmitter.getInstance();
        this.initializeDefaultSettings();
    }

    /**
     * Initialize default system settings
     * @private
     */
    async initializeDefaultSettings() {
        try {
            const defaultSettings = this.getDefaultSettings();
            
            for (const [key, setting] of Object.entries(defaultSettings)) {
                await SystemSetting.findOneAndUpdate(
                    { key },
                    {
                        $setOnInsert: {
                            key,
                            value: setting.value,
                            type: setting.type,
                            category: setting.category,
                            description: setting.description,
                            isSecret: setting.isSecret || false,
                            isReadOnly: setting.isReadOnly || false,
                            validationRules: setting.validationRules || {},
                            defaultValue: setting.value
                        }
                    },
                    { upsert: true, new: false }
                );
            }
        } catch (error) {
            this.logger.error('Error initializing default settings', error);
        }
    }

    /**
     * Get all system settings
     * @param {Object} options - Query options
     * @returns {Promise<Object>}
     */
    async getAllSettings(options = {}) {
        try {
            const { category, includeSecrets = false } = options;
            const cacheKey = `system:settings:${category || 'all'}:${includeSecrets}`;
            
            const cached = await this.cache.get(cacheKey);
            if (cached) {
                return cached;
            }

            const query = { isDeleted: false };
            if (category) {
                query.category = category;
            }

            const settings = await SystemSetting.find(query).lean();
            
            const formattedSettings = settings.reduce((acc, setting) => {
                const cat = setting.category;
                if (!acc[cat]) {
                    acc[cat] = {};
                }
                
                acc[cat][setting.key] = {
                    value: setting.isSecret && !includeSecrets ? '***REDACTED***' : setting.value,
                    type: setting.type,
                    description: setting.description,
                    isSecret: setting.isSecret,
                    isReadOnly: setting.isReadOnly,
                    lastModified: setting.updatedAt,
                    modifiedBy: setting.lastModifiedBy
                };
                
                return acc;
            }, {});

            // Cache for 5 minutes
            await this.cache.set(cacheKey, formattedSettings, 300);
            
            return formattedSettings;
        } catch (error) {
            this.logger.error('Error fetching all settings', error);
            throw error;
        }
    }

    /**
     * Get setting by key
     * @param {String} key - Setting key
     * @returns {Promise<Object>}
     */
    async getSettingByKey(key) {
        try {
            const cacheKey = `system:setting:${key}`;
            const cached = await this.cache.get(cacheKey);
            
            if (cached) {
                return cached;
            }

            const setting = await SystemSetting.findOne({ key, isDeleted: false }).lean();
            
            if (setting) {
                // Cache for 10 minutes
                await this.cache.set(cacheKey, setting, 600);
            }
            
            return setting;
        } catch (error) {
            this.logger.error('Error fetching setting by key', error);
            throw error;
        }
    }

    /**
     * Update system setting
     * @param {String} key - Setting key
     * @param {Object} updateData - Update data
     * @returns {Promise<Object>}
     */
    async updateSetting(key, updateData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { value, description, metadata, updatedBy } = updateData;

            const setting = await SystemSetting.findOne({ key, isDeleted: false }).session(session);
            if (!setting) {
                throw new Error('Setting not found');
            }

            if (setting.isReadOnly) {
                throw new Error('Cannot modify read-only setting');
            }

            // Validate new value
            await this.validateSettingValue(setting, value);

            // Store previous value for history
            const previousValue = setting.value;

            // Update setting
            if (value !== undefined) setting.value = value;
            if (description) setting.description = description;
            if (metadata) setting.metadata = { ...setting.metadata, ...metadata };
            
            setting.lastModifiedBy = updatedBy;
            setting.updatedAt = new Date();

            await setting.save({ session });

            // Create history record
            await SettingHistory.create([{
                settingKey: key,
                previousValue,
                newValue: value,
                changedBy: updatedBy,
                changeReason: metadata?.reason || 'Manual update',
                metadata: {
                    category: setting.category,
                    type: setting.type
                }
            }], { session });

            await session.commitTransaction();

            // Clear cache
            await this.cache.invalidate(`system:setting:${key}`);
            await this.cache.invalidate(`system:settings:*`);

            // Emit event
            this.eventEmitter.emit('system:setting:updated', {
                key,
                previousValue,
                newValue: value,
                updatedBy
            });

            return setting;
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error updating setting', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Bulk update system settings
     * @param {Array} settings - Array of settings to update
     * @param {Object} updatedBy - User making the update
     * @returns {Promise<Object>}
     */
    async bulkUpdateSettings(settings, updatedBy) {
        const results = {
            updated: [],
            failed: []
        };

        for (const { key, value, description, metadata } of settings) {
            try {
                const updated = await this.updateSetting(key, {
                    value,
                    description,
                    metadata,
                    updatedBy: updatedBy.id
                });
                
                results.updated.push({
                    key,
                    value: updated.value
                });
            } catch (error) {
                results.failed.push({
                    key,
                    error: error.message
                });
            }
        }

        return results;
    }

    /**
     * Reset setting to default value
     * @param {String} key - Setting key
     * @param {Object} resetBy - User resetting the setting
     * @returns {Promise<Object>}
     */
    async resetToDefault(key, resetBy) {
        try {
            const setting = await SystemSetting.findOne({ key, isDeleted: false });
            if (!setting) {
                throw new Error('Setting not found');
            }

            const previousValue = setting.value;
            
            await this.updateSetting(key, {
                value: setting.defaultValue,
                metadata: {
                    reason: 'Reset to default',
                    resetAt: new Date()
                },
                updatedBy: resetBy.id
            });

            return {
                key,
                previousValue,
                value: setting.defaultValue,
                resetAt: new Date()
            };
        } catch (error) {
            this.logger.error('Error resetting setting', error);
            throw error;
        }
    }

    /**
     * Get setting categories
     * @returns {Promise<Array>}
     */
    async getCategories() {
        try {
            const categories = await SystemSetting.distinct('category', { isDeleted: false });
            
            return categories.map(category => ({
                id: category,
                name: this.formatCategoryName(category),
                settingsCount: 0 // Would need aggregation for count
            }));
        } catch (error) {
            this.logger.error('Error fetching categories', error);
            throw error;
        }
    }

    /**
     * Export system configuration
     * @param {Object} options - Export options
     * @returns {Promise<Object>}
     */
    async exportConfiguration(options = {}) {
        try {
            const { format = 'json', categories, includeSecrets = false } = options;

            const query = { isDeleted: false };
            if (categories && categories.length > 0) {
                query.category = { $in: categories };
            }

            const settings = await SystemSetting.find(query).lean();
            
            const exportData = settings.map(setting => ({
                key: setting.key,
                value: setting.isSecret && !includeSecrets ? '***REDACTED***' : setting.value,
                type: setting.type,
                category: setting.category,
                description: setting.description,
                isSecret: setting.isSecret,
                isReadOnly: setting.isReadOnly,
                defaultValue: setting.defaultValue
            }));

            let content;
            switch (format) {
                case 'json':
                    content = JSON.stringify(exportData, null, 2);
                    break;
                case 'env':
                    content = this.convertToEnvFormat(exportData);
                    break;
                default:
                    content = exportData;
            }

            return {
                format,
                content,
                settingCount: exportData.length,
                exportedAt: new Date()
            };
        } catch (error) {
            this.logger.error('Error exporting configuration', error);
            throw error;
        }
    }

    /**
     * Import system configuration
     * @param {Object} importData - Import data
     * @returns {Promise<Object>}
     */
    async importConfiguration(importData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { configuration, overwrite = false, dryRun = false, importedBy } = importData;
            
            const results = {
                imported: [],
                skipped: [],
                failed: [],
                summary: {}
            };

            for (const [key, value] of Object.entries(configuration)) {
                try {
                    const existingSetting = await SystemSetting.findOne({ key }).session(session);
                    
                    if (existingSetting && !overwrite) {
                        results.skipped.push({
                            key,
                            reason: 'Already exists'
                        });
                        continue;
                    }

                    if (existingSetting && existingSetting.isReadOnly) {
                        results.skipped.push({
                            key,
                            reason: 'Read-only setting'
                        });
                        continue;
                    }

                    if (!dryRun) {
                        if (existingSetting) {
                            // Update existing
                            await this.updateSetting(key, {
                                value: value.value || value,
                                description: value.description,
                                updatedBy: importedBy
                            });
                        } else {
                            // Create new
                            await SystemSetting.create([{
                                key,
                                value: value.value || value,
                                type: value.type || 'string',
                                category: value.category || 'imported',
                                description: value.description || 'Imported setting',
                                defaultValue: value.value || value,
                                createdBy: importedBy
                            }], { session });
                        }
                    }

                    results.imported.push({ key, value: value.value || value });
                } catch (error) {
                    results.failed.push({
                        key,
                        error: error.message
                    });
                }
            }

            if (!dryRun) {
                await session.commitTransaction();
                
                // Clear all settings cache
                await this.cache.invalidate('system:settings:*');
                await this.cache.invalidate('system:setting:*');
            }

            results.summary = {
                total: Object.keys(configuration).length,
                imported: results.imported.length,
                skipped: results.skipped.length,
                failed: results.failed.length
            };

            return results;
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error importing configuration', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get setting change history
     * @param {Object} options - Query options
     * @returns {Promise<Array>}
     */
    async getSettingHistory(options = {}) {
        try {
            const { key, limit = 50, startDate, endDate } = options;

            const query = {};
            if (key) query.settingKey = key;
            
            if (startDate || endDate) {
                query.createdAt = {};
                if (startDate) query.createdAt.$gte = new Date(startDate);
                if (endDate) query.createdAt.$lte = new Date(endDate);
            }

            const history = await SettingHistory.find(query)
                .populate('changedBy', 'email fullName')
                .sort({ createdAt: -1 })
                .limit(limit)
                .lean();

            return history;
        } catch (error) {
            this.logger.error('Error fetching setting history', error);
            throw error;
        }
    }

    /**
     * Validate configuration changes
     * @param {Array} settings - Settings to validate
     * @returns {Promise<Object>}
     */
    async validateConfiguration(settings) {
        const validationResult = {
            valid: true,
            errors: [],
            warnings: []
        };

        for (const { key, value } of settings) {
            try {
                const setting = await SystemSetting.findOne({ key });
                
                if (!setting) {
                    validationResult.warnings.push({
                        key,
                        message: 'Setting does not exist, will be created'
                    });
                    continue;
                }

                if (setting.isReadOnly) {
                    validationResult.errors.push({
                        key,
                        message: 'Cannot modify read-only setting'
                    });
                    validationResult.valid = false;
                    continue;
                }

                await this.validateSettingValue(setting, value);
            } catch (error) {
                validationResult.errors.push({
                    key,
                    message: error.message
                });
                validationResult.valid = false;
            }
        }

        return validationResult;
    }

    /**
     * Toggle maintenance mode
     * @param {Object} maintenanceData - Maintenance mode data
     * @returns {Promise<Object>}
     */
    async toggleMaintenanceMode(maintenanceData) {
        try {
            const { enabled, message, estimatedDuration, toggledBy } = maintenanceData;

            // Update maintenance mode setting
            await this.updateSetting('system.maintenanceMode', {
                value: enabled,
                metadata: {
                    message,
                    estimatedDuration,
                    toggledAt: new Date(),
                    toggledBy
                },
                updatedBy: toggledBy
            });

            // Update related settings
            if (enabled) {
                await this.updateSetting('system.maintenanceMessage', {
                    value: message || 'System is under maintenance. Please try again later.',
                    updatedBy: toggledBy
                });

                if (estimatedDuration) {
                    await this.updateSetting('system.maintenanceEndTime', {
                        value: new Date(Date.now() + estimatedDuration).toISOString(),
                        updatedBy: toggledBy
                    });
                }
            }

            // Emit global event
            this.eventEmitter.emit('system:maintenance:toggled', {
                enabled,
                message,
                estimatedDuration,
                toggledBy
            });

            return {
                enabled,
                message,
                estimatedDuration,
                toggledAt: new Date()
            };
        } catch (error) {
            this.logger.error('Error toggling maintenance mode', error);
            throw error;
        }
    }

    // Private helper methods

    getDefaultSettings() {
        return {
            'system.maintenanceMode': {
                value: false,
                type: 'boolean',
                category: 'system',
                description: 'Enable/disable system maintenance mode'
            },
            'system.maintenanceMessage': {
                value: 'System is under maintenance. Please try again later.',
                type: 'string',
                category: 'system',
                description: 'Message displayed during maintenance mode'
            },
            'system.allowRegistration': {
                value: true,
                type: 'boolean',
                category: 'system',
                description: 'Allow new user registrations'
            },
            'security.maxLoginAttempts': {
                value: 5,
                type: 'number',
                category: 'security',
                description: 'Maximum login attempts before account lockout'
            },
            'security.sessionTimeout': {
                value: 3600000, // 1 hour
                type: 'number',
                category: 'security',
                description: 'Session timeout in milliseconds'
            },
            'security.requireMFA': {
                value: false,
                type: 'boolean',
                category: 'security',
                description: 'Require MFA for all admin users'
            },
            'email.defaultFrom': {
                value: config.email.from,
                type: 'string',
                category: 'email',
                description: 'Default from email address'
            },
            'email.supportEmail': {
                value: config.email.supportEmail,
                type: 'string',
                category: 'email',
                description: 'Support email address'
            },
            'platform.name': {
                value: config.platform.name,
                type: 'string',
                category: 'platform',
                description: 'Platform display name'
            },
            'platform.maxOrgsPerUser': {
                value: config.platform.maxOrgsPerUser,
                type: 'number',
                category: 'platform',
                description: 'Maximum organizations per user'
            },
            'billing.trialDays': {
                value: config.tenant.trialDays,
                type: 'number',
                category: 'billing',
                description: 'Default trial period in days'
            },
            'billing.gracePeriodDays': {
                value: config.subscription.gracePeriodDays,
                type: 'number',
                category: 'billing',
                description: 'Grace period for expired subscriptions'
            }
        };
    }

    async validateSettingValue(setting, value) {
        // Type validation
        const typeValidators = {
            string: Joi.string(),
            number: Joi.number(),
            boolean: Joi.boolean(),
            array: Joi.array(),
            object: Joi.object()
        };

        const validator = typeValidators[setting.type];
        if (!validator) {
            throw new Error(`Unknown setting type: ${setting.type}`);
        }

        const { error } = validator.validate(value);
        if (error) {
            throw new Error(`Invalid value for ${setting.type}: ${error.message}`);
        }

        // Custom validation rules
        if (setting.validationRules) {
            if (setting.validationRules.min !== undefined && value < setting.validationRules.min) {
                throw new Error(`Value must be at least ${setting.validationRules.min}`);
            }
            
            if (setting.validationRules.max !== undefined && value > setting.validationRules.max) {
                throw new Error(`Value must be at most ${setting.validationRules.max}`);
            }
            
            if (setting.validationRules.pattern) {
                const pattern = new RegExp(setting.validationRules.pattern);
                if (!pattern.test(value)) {
                    throw new Error(`Value does not match required pattern`);
                }
            }
        }
    }

    formatCategoryName(category) {
        return category
            .split(/[._-]/)
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

    convertToEnvFormat(settings) {
        return settings
            .filter(s => !s.isSecret)
            .map(s => `${s.key.toUpperCase().replace(/\./g, '_')}=${s.value}`)
            .join('\n');
    }
}

module.exports = SystemSettingsService;