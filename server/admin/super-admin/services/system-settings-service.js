// server/admin/super-admin/services/system-settings-service.js
/**
 * @file System Settings Service
 * @description Service for managing global system configuration and settings
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

// Core Models
const SystemSetting = require('../../../shared/config/models/system-setting-model');
const FeatureFlag = require('../../../shared/config/models/feature-flag-model');
const ConfigurationTemplate = require('../../../shared/config/models/configuration-template-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const BackupService = require('../../../shared/admin/services/admin-backup-service');
const ValidationService = require('../../../shared/utils/validation-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { encrypt, decrypt } = require('../../../shared/utils/encryption');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

// Configuration
const config = require('../../../config');
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

/**
 * System Settings Service Class
 * @class SystemSettingsService
 * @extends AdminBaseService
 */
class SystemSettingsService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'SystemSettingsService';
    this.cachePrefix = 'system-settings';
    this.auditCategory = 'SYSTEM_SETTINGS';
    this.requiredPermission = AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS;

    // Setting categories
    this.settingCategories = {
      CORE: 'core',
      SECURITY: 'security',
      AUTHENTICATION: 'authentication',
      PERFORMANCE: 'performance',
      FEATURES: 'features',
      BILLING: 'billing',
      NOTIFICATIONS: 'notifications',
      INTEGRATIONS: 'integrations',
      API: 'api',
      UI: 'ui',
      COMPLIANCE: 'compliance',
      MAINTENANCE: 'maintenance'
    };

    // Setting value types
    this.valueTypes = {
      STRING: 'string',
      NUMBER: 'number',
      BOOLEAN: 'boolean',
      JSON: 'json',
      ENCRYPTED: 'encrypted',
      ARRAY: 'array',
      DATE: 'date'
    };

    // Protected settings that require additional validation
    this.protectedSettings = [
      'system.maintenance.enabled',
      'security.mfa.required',
      'authentication.session.timeout',
      'billing.payment.processor',
      'api.rate.limit.global'
    ];
  }

  /**
   * Get all system settings
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} System settings
   */
  async getAllSettings(adminUser, options = {}) {
    try {
      await this.validateAccess(adminUser, 'read');

      const {
        category = null,
        search = '',
        includeSecrets = false,
        includeHistory = false,
        groupByCategory = true
      } = options;

      // Build query
      const query = { deleted: { $ne: true } };

      if (category) {
        query.category = category;
      }

      if (search) {
        query.$or = [
          { key: new RegExp(search, 'i') },
          { displayName: new RegExp(search, 'i') },
          { description: new RegExp(search, 'i') }
        ];
      }

      // Fetch settings
      const settings = await SystemSetting.find(query)
        .populate('lastModifiedBy', 'email profile')
        .sort({ category: 1, key: 1 });

      // Process settings
      const processedSettings = await Promise.all(
        settings.map(async (setting) => {
          const processed = setting.toObject();

          // Decrypt encrypted values if authorized
          if (setting.valueType === 'encrypted' && includeSecrets) {
            if (await this.canViewSecrets(adminUser)) {
              processed.value = decrypt(setting.value);
              processed.decrypted = true;
            } else {
              processed.value = '********';
              processed.encrypted = true;
            }
          }

          // Add validation status
          processed.validationStatus = await this.validateSettingValue(
            setting.key,
            setting.value,
            setting.valueType
          );

          // Add history if requested
          if (includeHistory) {
            processed.history = await this.getSettingHistory(setting.key, 10);
          }

          // Add usage information
          processed.usage = await this.getSettingUsageInfo(setting.key);

          return processed;
        })
      );

      // Group by category if requested
      let result;
      if (groupByCategory) {
        result = this.groupSettingsByCategory(processedSettings);
      } else {
        result = processedSettings;
      }

      // Get metadata
      const metadata = {
        totalSettings: processedSettings.length,
        categories: await this.getActiveCategories(),
        lastModified: await this.getLastModificationTime(),
        configurationHealth: await this.assessConfigurationHealth()
      };

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.SETTINGS_VIEWED, {
        count: processedSettings.length,
        categories: Object.keys(result),
        includeSecrets
      });

      return {
        settings: result,
        metadata
      };

    } catch (error) {
      logger.error('Get all settings error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get specific setting by key
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} settingKey - Setting key
   * @returns {Promise<Object>} Setting details
   */
  async getSettingByKey(adminUser, settingKey) {
    try {
      await this.validateAccess(adminUser, 'read');

      const setting = await SystemSetting.findOne({ key: settingKey })
        .populate('lastModifiedBy', 'email profile')
        .populate('createdBy', 'email profile');

      if (!setting) {
        throw new NotFoundError(`Setting with key '${settingKey}' not found`);
      }

      const settingData = setting.toObject();

      // Decrypt if encrypted and authorized
      if (setting.valueType === 'encrypted' && await this.canViewSecrets(adminUser)) {
        settingData.value = decrypt(setting.value);
        settingData.decrypted = true;
      } else if (setting.valueType === 'encrypted') {
        settingData.value = '********';
        settingData.encrypted = true;
      }

      // Get comprehensive information
      const [
        history,
        dependencies,
        impacts,
        relatedSettings
      ] = await Promise.all([
        this.getSettingHistory(settingKey, 20),
        this.getSettingDependencies(settingKey),
        this.analyzeSettingImpact(settingKey),
        this.getRelatedSettings(settingKey)
      ]);

      const detailedSetting = {
        ...settingData,
        history,
        dependencies,
        impacts,
        relatedSettings,
        validation: await this.getSettingValidationRules(settingKey),
        currentStatus: await this.getSettingStatus(setting),
        recommendations: await this.getSettingRecommendations(setting)
      };

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.SETTING_VIEWED, {
        settingKey,
        category: setting.category
      });

      return detailedSetting;

    } catch (error) {
      logger.error('Get setting by key error', {
        error: error.message,
        adminId: adminUser.id,
        settingKey,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Update system setting
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} settingKey - Setting key
   * @param {Object} updateData - Update data
   * @returns {Promise<Object>} Updated setting
   */
  async updateSetting(adminUser, settingKey, updateData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'update');

      const { value, reason, effectiveDate = new Date(), testMode = false } = updateData;

      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Update reason must be provided (minimum 10 characters)');
      }

      // Find setting
      const setting = await SystemSetting.findOne({ key: settingKey }).session(session);

      if (!setting) {
        throw new NotFoundError(`Setting with key '${settingKey}' not found`);
      }

      // Check if setting is protected
      if (this.protectedSettings.includes(settingKey)) {
        await this.validateProtectedSettingUpdate(adminUser, setting, value);
      }

      // Store original value
      const originalValue = setting.value;
      const originalDecrypted = setting.valueType === 'encrypted' ? 
        decrypt(setting.value) : setting.value;

      // Validate new value
      const validationResult = await this.validateSettingValue(
        settingKey,
        value,
        setting.valueType
      );

      if (!validationResult.isValid) {
        throw new ValidationError(
          `Invalid value for setting '${settingKey}': ${validationResult.errors.join(', ')}`
        );
      }

      // Check for breaking changes
      const impactAnalysis = await this.analyzeSettingChangeImpact(
        setting,
        originalValue,
        value
      );

      if (impactAnalysis.severity === 'critical' && !updateData.acknowledgeImpact) {
        return {
          requiresConfirmation: true,
          impact: impactAnalysis,
          message: 'This change has critical impact. Please acknowledge to proceed.'
        };
      }

      // Process value based on type
      let processedValue = value;
      if (setting.valueType === 'encrypted') {
        processedValue = encrypt(value);
      } else if (setting.valueType === 'json') {
        processedValue = JSON.stringify(value);
      }

      // Create backup before update
      const backup = await this.createSettingBackup(setting, adminUser.id);

      if (!testMode) {
        // Update setting
        setting.value = processedValue;
        setting.previousValue = originalValue;
        setting.lastModifiedBy = adminUser.id;
        setting.lastModifiedAt = new Date();
        setting.modificationReason = reason;
        setting.version = (setting.version || 0) + 1;

        await setting.save({ session });

        // Clear related caches
        await this.clearSettingCaches(settingKey, setting.category);

        // Apply setting if immediate effect
        if (effectiveDate <= new Date()) {
          await this.applySettingChange(setting, originalValue, processedValue);
        } else {
          // Schedule future application
          await this.scheduleSettingChange(setting, effectiveDate);
        }
      }

      // Create change record
      const changeRecord = {
        settingKey,
        category: setting.category,
        originalValue: originalDecrypted,
        newValue: value,
        effectiveDate,
        testMode,
        impact: impactAnalysis,
        backupId: backup.id
      };

      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'SETTING_UPDATED',
        category: 'SYSTEM_SETTINGS',
        severity: impactAnalysis.severity === 'critical' ? 'CRITICAL' : 'HIGH',
        targetResource: {
          type: 'setting',
          key: settingKey,
          category: setting.category
        },
        data: changeRecord
      }], { session });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.SETTING_UPDATED, {
        settingKey,
        category: setting.category,
        impact: impactAnalysis.severity,
        testMode
      }, { 
        session, 
        critical: impactAnalysis.severity === 'critical' 
      });

      // Notify relevant parties
      if (!testMode && impactAnalysis.affectedServices.length > 0) {
        await this.notifySettingChange(
          setting,
          changeRecord,
          impactAnalysis.affectedServices
        );
      }

      await session.commitTransaction();

      return {
        setting: {
          key: setting.key,
          displayName: setting.displayName,
          value: value,
          previousValue: originalDecrypted,
          category: setting.category,
          version: setting.version
        },
        change: changeRecord,
        impact: impactAnalysis,
        message: testMode ? 
          'Setting validated successfully (test mode - no changes applied)' : 
          'Setting updated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Update setting error', {
        error: error.message,
        adminId: adminUser.id,
        settingKey,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Bulk update multiple settings
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Array} updates - Array of setting updates
   * @param {Object} options - Update options
   * @returns {Promise<Object>} Bulk update result
   */
  async bulkUpdateSettings(adminUser, updates, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'update');

      const {
        reason,
        testMode = false,
        stopOnError = true,
        createBackup = true
      } = options;

      if (!reason || reason.trim().length < 20) {
        throw new ValidationError('Bulk update reason must be detailed (minimum 20 characters)');
      }

      if (!Array.isArray(updates) || updates.length === 0) {
        throw new ValidationError('Updates must be a non-empty array');
      }

      if (updates.length > AdminLimits.BULK_OPERATIONS.MAX_SETTINGS) {
        throw new ValidationError(
          `Cannot update more than ${AdminLimits.BULK_OPERATIONS.MAX_SETTINGS} settings at once`
        );
      }

      // Create full backup if requested
      let backupId;
      if (createBackup && !testMode) {
        const backup = await BackupService.createConfigurationBackup({
          type: 'settings_bulk_update',
          adminId: adminUser.id,
          reason
        });
        backupId = backup.id;
      }

      // Process updates
      const results = {
        successful: [],
        failed: [],
        warnings: []
      };

      for (const update of updates) {
        try {
          const { key, value } = update;

          const setting = await SystemSetting.findOne({ key }).session(session);
          if (!setting) {
            if (stopOnError) {
              throw new NotFoundError(`Setting '${key}' not found`);
            }
            results.failed.push({
              key,
              error: 'Setting not found'
            });
            continue;
          }

          // Validate value
          const validation = await this.validateSettingValue(key, value, setting.valueType);
          if (!validation.isValid) {
            if (stopOnError) {
              throw new ValidationError(
                `Invalid value for '${key}': ${validation.errors.join(', ')}`
              );
            }
            results.failed.push({
              key,
              error: validation.errors.join(', ')
            });
            continue;
          }

          // Check for warnings
          const impact = await this.analyzeSettingChangeImpact(
            setting,
            setting.value,
            value
          );

          if (impact.severity === 'high' || impact.severity === 'critical') {
            results.warnings.push({
              key,
              severity: impact.severity,
              message: impact.description
            });
          }

          if (!testMode) {
            // Process and update value
            let processedValue = value;
            if (setting.valueType === 'encrypted') {
              processedValue = encrypt(value);
            } else if (setting.valueType === 'json') {
              processedValue = JSON.stringify(value);
            }

            const originalValue = setting.value;
            
            setting.value = processedValue;
            setting.previousValue = originalValue;
            setting.lastModifiedBy = adminUser.id;
            setting.lastModifiedAt = new Date();
            setting.modificationReason = reason;
            setting.version = (setting.version || 0) + 1;

            await setting.save({ session });

            results.successful.push({
              key,
              displayName: setting.displayName,
              oldValue: setting.valueType === 'encrypted' ? '********' : originalValue,
              newValue: setting.valueType === 'encrypted' ? '********' : value,
              impact: impact.severity
            });
          } else {
            // Test mode - just validate
            results.successful.push({
              key,
              displayName: setting.displayName,
              wouldUpdate: true,
              impact: impact.severity
            });
          }

        } catch (error) {
          if (stopOnError) {
            throw error;
          }
          results.failed.push({
            key: update.key,
            error: error.message
          });
        }
      }

      if (!testMode && results.successful.length > 0) {
        // Clear all setting caches
        await this.clearAllSettingCaches();

        // Apply changes
        for (const success of results.successful) {
          const setting = await SystemSetting.findOne({ key: success.key }).session(session);
          await this.applySettingChange(setting, success.oldValue, success.newValue);
        }
      }

      // Create bulk update record
      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'SETTINGS_BULK_UPDATED',
        category: 'SYSTEM_SETTINGS',
        severity: results.warnings.some(w => w.severity === 'critical') ? 'CRITICAL' : 'HIGH',
        data: {
          totalUpdates: updates.length,
          successful: results.successful.length,
          failed: results.failed.length,
          warnings: results.warnings.length,
          testMode,
          backupId,
          reason
        }
      }], { session });

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.SETTINGS_BULK_UPDATED, {
        total: updates.length,
        successful: results.successful.length,
        failed: results.failed.length,
        testMode
      }, { session, critical: results.warnings.some(w => w.severity === 'critical') });

      await session.commitTransaction();

      return {
        results,
        summary: {
          total: updates.length,
          successful: results.successful.length,
          failed: results.failed.length,
          warnings: results.warnings.length
        },
        backupId,
        testMode,
        message: testMode ? 
          'Bulk update validated successfully (test mode - no changes applied)' : 
          `Successfully updated ${results.successful.length} settings`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Bulk update settings error', {
        error: error.message,
        adminId: adminUser.id,
        updateCount: updates.length,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Reset setting to default value
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} settingKey - Setting key
   * @param {Object} resetOptions - Reset options
   * @returns {Promise<Object>} Reset result
   */
  async resetSetting(adminUser, settingKey, resetOptions = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'update');

      const { reason, notifyServices = true } = resetOptions;

      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Reset reason must be provided (minimum 10 characters)');
      }

      const setting = await SystemSetting.findOne({ key: settingKey }).session(session);

      if (!setting) {
        throw new NotFoundError(`Setting with key '${settingKey}' not found`);
      }

      if (!setting.defaultValue) {
        throw new ValidationError(`Setting '${settingKey}' has no default value`);
      }

      const originalValue = setting.value;
      const originalDecrypted = setting.valueType === 'encrypted' ? 
        decrypt(setting.value) : setting.value;

      // Create backup
      const backup = await this.createSettingBackup(setting, adminUser.id);

      // Reset to default
      setting.value = setting.defaultValue;
      setting.previousValue = originalValue;
      setting.lastModifiedBy = adminUser.id;
      setting.lastModifiedAt = new Date();
      setting.modificationReason = `Reset to default: ${reason}`;
      setting.version = (setting.version || 0) + 1;
      setting.isDefault = true;

      await setting.save({ session });

      // Clear caches
      await this.clearSettingCaches(settingKey, setting.category);

      // Apply change
      await this.applySettingChange(setting, originalValue, setting.defaultValue);

      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'SETTING_RESET',
        category: 'SYSTEM_SETTINGS',
        severity: 'MEDIUM',
        targetResource: {
          type: 'setting',
          key: settingKey,
          category: setting.category
        },
        data: {
          originalValue: originalDecrypted,
          defaultValue: setting.valueType === 'encrypted' ? 
            '********' : setting.defaultValue,
          reason,
          backupId: backup.id
        }
      }], { session });

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.SETTING_RESET, {
        settingKey,
        category: setting.category,
        reason
      }, { session });

      if (notifyServices) {
        await this.notifySettingChange(setting, {
          type: 'reset',
          originalValue: originalDecrypted,
          newValue: setting.defaultValue
        });
      }

      await session.commitTransaction();

      return {
        setting: {
          key: setting.key,
          displayName: setting.displayName,
          value: setting.defaultValue,
          previousValue: originalDecrypted,
          category: setting.category
        },
        backupId: backup.id,
        message: 'Setting reset to default value successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Reset setting error', {
        error: error.message,
        adminId: adminUser.id,
        settingKey,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Manage feature flags
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Feature flags
   */
  async getFeatureFlags(adminUser, options = {}) {
    try {
      await this.validateAccess(adminUser, 'read');

      const {
        environment = 'all',
        includeMetrics = false,
        includeHistory = false
      } = options;

      const query = {};
      if (environment !== 'all') {
        query[`environments.${environment}`] = { $exists: true };
      }

      const flags = await FeatureFlag.find(query)
        .populate('lastModifiedBy', 'email profile')
        .sort({ key: 1 });

      const processedFlags = await Promise.all(
        flags.map(async (flag) => {
          const flagData = flag.toObject();

          if (includeMetrics) {
            flagData.metrics = await this.getFeatureFlagMetrics(flag.key);
          }

          if (includeHistory) {
            flagData.history = await this.getFeatureFlagHistory(flag.key, 10);
          }

          flagData.rolloutStatus = this.calculateRolloutStatus(flag);
          flagData.userCount = await this.getFeatureFlagUserCount(flag.key);

          return flagData;
        })
      );

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.FEATURE_FLAGS_VIEWED, {
        count: processedFlags.length,
        environment
      });

      return {
        flags: processedFlags,
        environments: await this.getAvailableEnvironments(),
        summary: {
          total: processedFlags.length,
          enabled: processedFlags.filter(f => f.enabled).length,
          inRollout: processedFlags.filter(f => f.rolloutStatus === 'partial').length
        }
      };

    } catch (error) {
      logger.error('Get feature flags error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Update feature flag
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} flagKey - Feature flag key
   * @param {Object} updateData - Update data
   * @returns {Promise<Object>} Updated feature flag
   */
  async updateFeatureFlag(adminUser, flagKey, updateData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'update');

      const {
        environment = 'production',
        enabled,
        rolloutPercentage,
        targetGroups,
        reason
      } = updateData;

      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Update reason must be provided (minimum 10 characters)');
      }

      const flag = await FeatureFlag.findOne({ key: flagKey }).session(session);

      if (!flag) {
        throw new NotFoundError(`Feature flag '${flagKey}' not found`);
      }

      // Store original state
      const originalState = {
        ...flag.environments[environment]
      };

      // Update flag configuration
      if (!flag.environments[environment]) {
        flag.environments[environment] = {};
      }

      if (enabled !== undefined) {
        flag.environments[environment].enabled = enabled;
      }

      if (rolloutPercentage !== undefined) {
        if (rolloutPercentage < 0 || rolloutPercentage > 100) {
          throw new ValidationError('Rollout percentage must be between 0 and 100');
        }
        flag.environments[environment].rolloutPercentage = rolloutPercentage;
      }

      if (targetGroups !== undefined) {
        flag.environments[environment].targetGroups = targetGroups;
      }

      flag.lastModifiedBy = adminUser.id;
      flag.lastModifiedAt = new Date();
      flag.markModified('environments');

      await flag.save({ session });

      // Clear feature flag caches
      await CacheService.delete(`feature_flag:${flagKey}:*`);

      // Calculate impact
      const impact = await this.calculateFeatureFlagImpact(flag, environment, originalState);

      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'FEATURE_FLAG_UPDATED',
        category: 'SYSTEM_SETTINGS',
        severity: impact.affectedUsers > 1000 ? 'HIGH' : 'MEDIUM',
        targetResource: {
          type: 'feature_flag',
          key: flagKey,
          environment
        },
        data: {
          originalState,
          newState: flag.environments[environment],
          impact,
          reason
        }
      }], { session });

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.FEATURE_FLAG_UPDATED, {
        flagKey,
        environment,
        changes: this.compareFeatureFlagStates(originalState, flag.environments[environment]),
        impact: impact.affectedUsers
      }, { session });

      // Notify about significant changes
      if (impact.affectedUsers > 100 || environment === 'production') {
        await NotificationService.notifyAdmins({
          type: 'feature_flag_change',
          priority: impact.affectedUsers > 1000 ? 'high' : 'medium',
          data: {
            flagKey,
            environment,
            change: enabled ? 'enabled' : 'modified',
            affectedUsers: impact.affectedUsers,
            adminName: adminUser.email
          }
        });
      }

      await session.commitTransaction();

      return {
        flag: await FeatureFlag.findById(flag._id),
        impact,
        changes: this.compareFeatureFlagStates(originalState, flag.environments[environment]),
        message: 'Feature flag updated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Update feature flag error', {
        error: error.message,
        adminId: adminUser.id,
        flagKey,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Export system configuration
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} exportOptions - Export options
   * @returns {Promise<Object>} Export result
   */
  async exportConfiguration(adminUser, exportOptions = {}) {
    try {
      await this.validateAccess(adminUser, 'export');

      const {
        includeSettings = true,
        includeFeatureFlags = true,
        includeTemplates = true,
        format = 'json',
        encrypt = true,
        categories = null
      } = exportOptions;

      const exportData = {
        metadata: {
          exportedAt: new Date(),
          exportedBy: adminUser.id,
          version: config.app.version,
          environment: config.app.env
        },
        data: {}
      };

      // Export settings
      if (includeSettings) {
        const settingsQuery = { deleted: { $ne: true } };
        if (categories) {
          settingsQuery.category = { $in: categories };
        }

        const settings = await SystemSetting.find(settingsQuery)
          .select('-_id -__v -createdBy -lastModifiedBy');

        exportData.data.settings = settings.map(s => {
          const data = s.toObject();
          // Don't export encrypted values in plain text
          if (s.valueType === 'encrypted') {
            data.value = '***ENCRYPTED***';
          }
          return data;
        });
      }

      // Export feature flags
      if (includeFeatureFlags) {
        const flags = await FeatureFlag.find({})
          .select('-_id -__v -createdBy -lastModifiedBy');
        
        exportData.data.featureFlags = flags;
      }

      // Export configuration templates
      if (includeTemplates) {
        const templates = await ConfigurationTemplate.find({ active: true })
          .select('-_id -__v -createdBy');
        
        exportData.data.templates = templates;
      }

      // Format export
      let exportContent;
      if (format === 'json') {
        exportContent = JSON.stringify(exportData, null, 2);
      } else if (format === 'yaml') {
        // Would use a YAML library here
        exportContent = this.convertToYAML(exportData);
      }

      // Encrypt if requested
      if (encrypt) {
        exportContent = encrypt(exportContent);
      }

      // Create export record
      const exportRecord = {
        id: crypto.randomUUID(),
        filename: `system-config-export-${Date.now()}.${format}${encrypt ? '.enc' : ''}`,
        size: Buffer.byteLength(exportContent),
        checksum: crypto.createHash('sha256').update(exportContent).digest('hex')
      };

      await AdminActionLog.create([{
        actionId: exportRecord.id,
        adminUserId: adminUser.id,
        action: 'CONFIGURATION_EXPORTED',
        category: 'SYSTEM_SETTINGS',
        severity: 'HIGH',
        data: {
          format,
          encrypted: encrypt,
          includeSettings,
          includeFeatureFlags,
          includeTemplates,
          categories,
          filename: exportRecord.filename,
          checksum: exportRecord.checksum
        }
      }]);

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.CONFIGURATION_EXPORTED, {
        format,
        encrypted: encrypt,
        components: Object.keys(exportData.data),
        size: exportRecord.size
      }, { critical: true });

      return {
        export: exportContent,
        metadata: exportRecord,
        message: 'Configuration exported successfully'
      };

    } catch (error) {
      logger.error('Export configuration error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Import system configuration
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} importData - Import data
   * @param {Object} importOptions - Import options
   * @returns {Promise<Object>} Import result
   */
  async importConfiguration(adminUser, importData, importOptions = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'import');

      const {
        encrypted = false,
        merge = true,
        overwrite = false,
        testMode = true,
        categories = null
      } = importOptions;

      // Decrypt if needed
      let configData;
      if (encrypted) {
        configData = JSON.parse(decrypt(importData));
      } else {
        configData = typeof importData === 'string' ? JSON.parse(importData) : importData;
      }

      // Validate import structure
      if (!configData.metadata || !configData.data) {
        throw new ValidationError('Invalid configuration format');
      }

      // Create backup before import
      const backup = await BackupService.createConfigurationBackup({
        type: 'pre_import',
        adminId: adminUser.id,
        reason: 'Configuration import backup'
      });

      const importResults = {
        settings: { created: 0, updated: 0, skipped: 0, errors: [] },
        featureFlags: { created: 0, updated: 0, skipped: 0, errors: [] },
        templates: { created: 0, updated: 0, skipped: 0, errors: [] }
      };

      // Import settings
      if (configData.data.settings && importOptions.includeSettings !== false) {
        for (const settingData of configData.data.settings) {
          try {
            if (categories && !categories.includes(settingData.category)) {
              importResults.settings.skipped++;
              continue;
            }

            const existing = await SystemSetting.findOne({ 
              key: settingData.key 
            }).session(session);

            if (existing && !overwrite && !merge) {
              importResults.settings.skipped++;
              continue;
            }

            if (!testMode) {
              if (existing) {
                // Update existing
                if (settingData.value !== '***ENCRYPTED***') {
                  existing.value = settingData.value;
                  existing.lastModifiedBy = adminUser.id;
                  existing.lastModifiedAt = new Date();
                  await existing.save({ session });
                  importResults.settings.updated++;
                }
              } else {
                // Create new
                await SystemSetting.create([{
                  ...settingData,
                  createdBy: adminUser.id,
                  lastModifiedBy: adminUser.id
                }], { session });
                importResults.settings.created++;
              }
            } else {
              // Test mode - just count
              if (existing) {
                importResults.settings.updated++;
              } else {
                importResults.settings.created++;
              }
            }
          } catch (error) {
            importResults.settings.errors.push({
              key: settingData.key,
              error: error.message
            });
          }
        }
      }

      // Similar import logic for feature flags and templates...

      if (!testMode) {
        // Clear all caches after import
        await this.clearAllSettingCaches();
      }

      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'CONFIGURATION_IMPORTED',
        category: 'SYSTEM_SETTINGS',
        severity: 'CRITICAL',
        data: {
          source: configData.metadata,
          results: importResults,
          options: importOptions,
          backupId: backup.id
        }
      }], { session });

      await this.auditLog(adminUser, AdminEvents.SYSTEM_SETTINGS.CONFIGURATION_IMPORTED, {
        results: importResults,
        testMode,
        backupId: backup.id
      }, { session, critical: true });

      if (!testMode) {
        await session.commitTransaction();
      } else {
        await session.abortTransaction();
      }

      return {
        results: importResults,
        backupId: backup.id,
        testMode,
        message: testMode ? 
          'Configuration validated successfully (test mode - no changes applied)' : 
          'Configuration imported successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Import configuration error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get configuration templates
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Configuration templates
   */
  async getConfigurationTemplates(adminUser, options = {}) {
    try {
      await this.validateAccess(adminUser, 'read');

      const {
        category = null,
        environment = null,
        includeInactive = false
      } = options;

      const query = {};
      if (!includeInactive) {
        query.active = true;
      }
      if (category) {
        query.category = category;
      }
      if (environment) {
        query.environments = environment;
      }

      const templates = await ConfigurationTemplate.find(query)
        .populate('createdBy', 'email profile')
        .populate('lastUsedBy', 'email profile')
        .sort({ priority: -1, name: 1 });

      const enhancedTemplates = await Promise.all(
        templates.map(async (template) => {
          const templateData = template.toObject();
          
          templateData.usageCount = await this.getTemplateUsageCount(template._id);
          templateData.lastApplied = await this.getTemplateLastApplied(template._id);
          templateData.compatibility = await this.checkTemplateCompatibility(template);
          
          return templateData;
        })
      );

      return {
        templates: enhancedTemplates,
        categories: await this.getTemplateCategories(),
        environments: ['development', 'staging', 'production']
      };

    } catch (error) {
      logger.error('Get configuration templates error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Validate access for system settings operations
   * @param {Object} user - User to validate
   * @param {string} action - Action to perform
   * @private
   */
  async validateAccess(user, action) {
    const hasPermission = await this.checkPermission(
      user,
      this.requiredPermission,
      action
    );

    if (!hasPermission) {
      await this.auditLog(user, AdminEvents.SYSTEM_SETTINGS.UNAUTHORIZED_ACCESS, {
        attemptedAction: action,
        permission: this.requiredPermission
      });
      throw new ForbiddenError(`Insufficient permissions for system settings: ${action}`);
    }

    // Additional MFA check for critical operations
    const criticalActions = ['update', 'delete', 'import', 'export'];
    if (criticalActions.includes(action) && user.security?.requireMFA && !user.auth?.mfaVerified) {
      throw new ForbiddenError('MFA verification required for this operation');
    }
  }

  /**
   * Additional helper methods would continue here...
   * Including all the validation, impact analysis, cache management,
   * and notification methods referenced above
   */
}

module.exports = new SystemSettingsService();