// server/admin/super-admin/routes/system-settings-routes.js
/**
 * @file System Settings Routes
 * @description Route definitions for system configuration and settings management
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const SystemSettingsController = require('../controllers/system-settings-controller');

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
const { compress } = require('../../../shared/middleware/compression');

// Validation
const SystemSettingsValidation = require('../validation/system-settings-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * System Settings Routes
 * Base path: /api/admin/super-admin/settings
 */

// Apply authentication to all routes
router.use(authenticate);

// Apply super admin only middleware to all routes
router.use(SuperAdminOnly.enforce({
  requireMFA: true,
  requireActiveSession: true,
  checkIPWhitelist: true,
  auditAccess: true,
  customPermission: AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS
}));

/**
 * Settings Management Routes
 */

/**
 * @route   GET /api/admin/super-admin/settings
 * @desc    Get all system settings
 * @access  Super Admin
 */
router.get(
  '/',
  rateLimiter('settings_list', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 300, key: 'system_settings' }),
  auditLog('settings.list.accessed'),
  SystemSettingsController.getAllSettings
);

/**
 * @route   GET /api/admin/super-admin/settings/search
 * @desc    Search system settings
 * @access  Super Admin
 */
router.get(
  '/search',
  rateLimiter('settings_search', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  validateRequest(SystemSettingsValidation.searchSettings, 'query'),
  sanitize(['query.query']),
  auditLog('settings.search.performed'),
  SystemSettingsController.searchSettings
);

/**
 * @route   GET /api/admin/super-admin/settings/health
 * @desc    Get configuration health status
 * @access  Super Admin
 */
router.get(
  '/health',
  rateLimiter('settings_health', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 300, key: 'config_health' }),
  auditLog('settings.health.checked'),
  SystemSettingsController.getConfigurationHealth
);

/**
 * @route   GET /api/admin/super-admin/settings/export
 * @desc    Export system configuration
 * @access  Super Admin + Critical Operation
 */
router.get(
  '/export',
  rateLimiter('settings_export', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'export'),
  CriticalOperation.protect('system.configuration.export', {
    requireDualAuth: false,
    recordDetailed: true
  }),
  validateRequest(SystemSettingsValidation.exportConfiguration, 'query'),
  compress(),
  auditLog('settings.configuration.exported', { critical: true }),
  SystemSettingsController.exportConfiguration
);

/**
 * @route   POST /api/admin/super-admin/settings/import
 * @desc    Import system configuration
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/import',
  rateLimiter('settings_import', { max: 3, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'import'),
  CriticalOperation.protect('system.configuration.import', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(SystemSettingsValidation.importConfiguration, 'body'),
  auditLog('settings.configuration.imported', { critical: true, alert: true }),
  SystemSettingsController.importConfiguration
);

/**
 * @route   POST /api/admin/super-admin/settings/validate
 * @desc    Validate configuration without applying
 * @access  Super Admin
 */
router.post(
  '/validate',
  rateLimiter('settings_validate', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  validateRequest(SystemSettingsValidation.validateConfiguration, 'body'),
  auditLog('settings.configuration.validated'),
  SystemSettingsController.validateConfiguration
);

/**
 * @route   PUT /api/admin/super-admin/settings/bulk
 * @desc    Bulk update multiple settings
 * @access  Super Admin + Critical Operation
 */
router.put(
  '/bulk',
  rateLimiter('settings_bulk_update', { max: 5, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'update'),
  CriticalOperation.protect('system.settings.bulk.update', {
    requireDualAuth: req => req.body.updates?.length > 10,
    recordDetailed: true
  }),
  validateRequest(SystemSettingsValidation.bulkUpdateSettings, 'body'),
  auditLog('settings.bulk.updated', { critical: true }),
  SystemSettingsController.bulkUpdateSettings
);

/**
 * Configuration Backup Routes
 */

/**
 * @route   POST /api/admin/super-admin/settings/backup
 * @desc    Create configuration backup
 * @access  Super Admin
 */
router.post(
  '/backup',
  rateLimiter('settings_backup', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'backup'),
  validateRequest(SystemSettingsValidation.createBackup, 'body'),
  auditLog('settings.backup.created', { critical: false }),
  SystemSettingsController.createConfigurationBackup
);

/**
 * @route   POST /api/admin/super-admin/settings/restore
 * @desc    Restore configuration from backup
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/restore',
  rateLimiter('settings_restore', { max: 3, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'restore'),
  CriticalOperation.protect('system.backup.restore', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(SystemSettingsValidation.restoreBackup, 'body'),
  auditLog('settings.backup.restored', { critical: true, alert: true }),
  SystemSettingsController.restoreConfiguration
);

/**
 * @route   GET /api/admin/super-admin/settings/backups
 * @desc    List available configuration backups
 * @access  Super Admin
 */
router.get(
  '/backups',
  rateLimiter('settings_backup_list', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 300, key: 'backup_list' }),
  auditLog('settings.backups.listed'),
  SystemSettingsController.listBackups
);

/**
 * Configuration Template Routes
 */

/**
 * @route   GET /api/admin/super-admin/settings/templates
 * @desc    Get configuration templates
 * @access  Super Admin
 */
router.get(
  '/templates',
  rateLimiter('settings_templates', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 600, key: 'config_templates' }),
  auditLog('settings.templates.accessed'),
  SystemSettingsController.getConfigurationTemplates
);

/**
 * @route   POST /api/admin/super-admin/settings/templates
 * @desc    Create configuration template
 * @access  Super Admin
 */
router.post(
  '/templates',
  rateLimiter('settings_template_create', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'create'),
  validateRequest(SystemSettingsValidation.createTemplate, 'body'),
  sanitize(['body.name', 'body.description']),
  auditLog('settings.template.created'),
  SystemSettingsController.createTemplate
);

/**
 * @route   POST /api/admin/super-admin/settings/templates/:templateId/apply
 * @desc    Apply configuration template
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/templates/:templateId/apply',
  rateLimiter('settings_template_apply', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'update'),
  CriticalOperation.protect('system.template.apply', {
    requireDualAuth: req => req.body.environment === 'production',
    recordDetailed: true
  }),
  validateRequest(SystemSettingsValidation.applyTemplate),
  auditLog('settings.template.applied', { critical: true }),
  SystemSettingsController.applyConfigurationTemplate
);

/**
 * Individual Setting Routes
 */

/**
 * @route   GET /api/admin/super-admin/settings/:settingKey
 * @desc    Get specific setting details
 * @access  Super Admin
 */
router.get(
  '/:settingKey',
  rateLimiter('setting_details', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 300, key: req => `setting_${req.params.settingKey}` }),
  auditLog('setting.details.accessed'),
  SystemSettingsController.getSettingByKey
);

/**
 * @route   PUT /api/admin/super-admin/settings/:settingKey
 * @desc    Update system setting
 * @access  Super Admin + Critical Operation
 */
router.put(
  '/:settingKey',
  rateLimiter('setting_update', { max: 20, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'update'),
  checkResourceLock('setting', req => req.params.settingKey),
  CriticalOperation.protect('system.configuration.modify', {
    requireDualAuth: req => ['security', 'authentication', 'billing'].includes(req.params.settingKey.split('.')[0]),
    recordDetailed: true
  }),
  validateRequest(SystemSettingsValidation.updateSetting),
  auditLog('setting.updated', { critical: true }),
  SystemSettingsController.updateSetting
);

/**
 * @route   POST /api/admin/super-admin/settings/:settingKey/reset
 * @desc    Reset setting to default value
 * @access  Super Admin
 */
router.post(
  '/:settingKey/reset',
  rateLimiter('setting_reset', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'update'),
  validateRequest(SystemSettingsValidation.resetSetting),
  auditLog('setting.reset', { critical: false }),
  SystemSettingsController.resetSetting
);

/**
 * @route   GET /api/admin/super-admin/settings/:settingKey/history
 * @desc    Get setting change history
 * @access  Super Admin
 */
router.get(
  '/:settingKey/history',
  rateLimiter('setting_history', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  validateRequest(SystemSettingsValidation.settingHistory),
  cache({ ttl: 300, key: req => `setting_history_${req.params.settingKey}` }),
  auditLog('setting.history.accessed'),
  SystemSettingsController.getSettingHistory
);

/**
 * Feature Flag Routes
 */

/**
 * @route   GET /api/admin/super-admin/feature-flags
 * @desc    Get all feature flags
 * @access  Super Admin
 */
router.get(
  '/feature-flags',
  rateLimiter('feature_flags_list', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 300, key: 'feature_flags' }),
  auditLog('feature.flags.accessed'),
  SystemSettingsController.getFeatureFlags
);

/**
 * @route   POST /api/admin/super-admin/feature-flags
 * @desc    Create new feature flag
 * @access  Super Admin
 */
router.post(
  '/feature-flags',
  rateLimiter('feature_flag_create', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'create'),
  validateRequest(SystemSettingsValidation.createFeatureFlag, 'body'),
  sanitize(['body.key', 'body.displayName', 'body.description']),
  auditLog('feature.flag.created'),
  SystemSettingsController.createFeatureFlag
);

/**
 * @route   PUT /api/admin/super-admin/feature-flags/:flagKey
 * @desc    Update feature flag
 * @access  Super Admin
 */
router.put(
  '/feature-flags/:flagKey',
  rateLimiter('feature_flag_update', { max: 20, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'update'),
  checkResourceLock('feature_flag', req => req.params.flagKey),
  CriticalOperation.protect('feature.flag.update', {
    requireDualAuth: req => req.body.environment === 'production' && req.body.enabled === true,
    recordDetailed: true
  }),
  validateRequest(SystemSettingsValidation.updateFeatureFlag),
  auditLog('feature.flag.updated', { critical: true }),
  SystemSettingsController.updateFeatureFlag
);

/**
 * @route   DELETE /api/admin/super-admin/feature-flags/:flagKey
 * @desc    Delete feature flag
 * @access  Super Admin + Critical Operation
 */
router.delete(
  '/feature-flags/:flagKey',
  rateLimiter('feature_flag_delete', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'delete'),
  CriticalOperation.protect('feature.flag.delete', {
    requireDualAuth: true,
    recordDetailed: true
  }),
  auditLog('feature.flag.deleted', { critical: true }),
  SystemSettingsController.deleteFeatureFlag
);

/**
 * @route   GET /api/admin/super-admin/feature-flags/:flagKey/history
 * @desc    Get feature flag change history
 * @access  Super Admin
 */
router.get(
  '/feature-flags/:flagKey/history',
  rateLimiter('feature_flag_history', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 300, key: req => `flag_history_${req.params.flagKey}` }),
  auditLog('feature.flag.history.accessed'),
  SystemSettingsController.getFeatureFlagHistory
);

/**
 * @route   POST /api/admin/super-admin/feature-flags/:flagKey/test
 * @desc    Test feature flag impact
 * @access  Super Admin
 */
router.post(
  '/feature-flags/:flagKey/test',
  rateLimiter('feature_flag_test', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'update'),
  auditLog('feature.flag.tested'),
  SystemSettingsController.testFeatureFlag
);

/**
 * Configuration Categories Routes
 */

/**
 * @route   GET /api/admin/super-admin/settings/categories
 * @desc    Get all setting categories
 * @access  Super Admin
 */
router.get(
  '/categories',
  rateLimiter('settings_categories', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 3600, key: 'setting_categories' }),
  auditLog('settings.categories.accessed'),
  SystemSettingsController.getSettingCategories
);

/**
 * @route   GET /api/admin/super-admin/settings/categories/:category
 * @desc    Get settings by category
 * @access  Super Admin
 */
router.get(
  '/categories/:category',
  rateLimiter('settings_by_category', { max: 60, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  cache({ ttl: 300, key: req => `settings_category_${req.params.category}` }),
  auditLog('settings.category.accessed'),
  SystemSettingsController.getSettingsByCategory
);

/**
 * Configuration Comparison Routes
 */

/**
 * @route   POST /api/admin/super-admin/settings/compare
 * @desc    Compare configurations
 * @access  Super Admin
 */
router.post(
  '/compare',
  rateLimiter('settings_compare', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  auditLog('settings.comparison.performed'),
  SystemSettingsController.compareConfigurations
);

/**
 * @route   POST /api/admin/super-admin/settings/diff
 * @desc    Get configuration diff
 * @access  Super Admin
 */
router.post(
  '/diff',
  rateLimiter('settings_diff', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.SYSTEM_SETTINGS, 'read'),
  auditLog('settings.diff.generated'),
  SystemSettingsController.getConfigurationDiff
);

/**
 * Error handling middleware for system settings routes
 */
router.use((error, req, res, next) => {
  // Log configuration-related critical errors
  if (error.severity === 'critical' || error.statusCode === 500) {
    logger.critical('System settings route error', {
      error: error.message,
      path: req.path,
      method: req.method,
      user: req.user?.id,
      settingKey: req.params?.settingKey,
      stack: error.stack
    });
  }

  next(error);
});

module.exports = router;