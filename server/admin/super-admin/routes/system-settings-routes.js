/**
 * @file System Settings Routes
 * @description Routes for system configuration and settings management
 * @module admin/super-admin/routes
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();
const systemSettingsController = require('../controllers/system-settings-controller');
const { validateRequestBody, validateQueryParams } = require('../../admin-middleware');
const { systemSettingsValidation } = require('../validation/system-settings-validation');

/**
 * @route GET /api/admin/system-settings
 * @description Get all system settings
 * @access Super Admin
 */
router.get(
    '/',
    validateQueryParams(systemSettingsValidation.getSettingsQuery),
    systemSettingsController.getSettings.bind(systemSettingsController)
);

/**
 * @route GET /api/admin/system-settings/categories
 * @description Get system configuration categories
 * @access Super Admin
 */
router.get('/categories', systemSettingsController.getCategories.bind(systemSettingsController));

/**
 * @route GET /api/admin/system-settings/export
 * @description Export system configuration
 * @access Super Admin
 */
router.get(
    '/export',
    validateQueryParams(systemSettingsValidation.exportConfigurationQuery),
    systemSettingsController.exportConfiguration.bind(systemSettingsController)
);

/**
 * @route GET /api/admin/system-settings/:key
 * @description Get setting by key
 * @access Super Admin
 */
router.get('/:key', systemSettingsController.getSettingByKey.bind(systemSettingsController));

/**
 * @route PUT /api/admin/system-settings/:key
 * @description Update system setting
 * @access Super Admin
 */
router.put(
    '/:key',
    validateRequestBody(systemSettingsValidation.updateSetting),
    systemSettingsController.updateSetting.bind(systemSettingsController)
);

/**
 * @route POST /api/admin/system-settings/bulk
 * @description Bulk update system settings
 * @access Super Admin
 */
router.post(
    '/bulk',
    validateRequestBody(systemSettingsValidation.bulkUpdateSettings),
    systemSettingsController.bulkUpdateSettings.bind(systemSettingsController)
);

/**
 * @route POST /api/admin/system-settings/:key/reset
 * @description Reset setting to default value
 * @access Super Admin
 */
router.post('/:key/reset', systemSettingsController.resetSetting.bind(systemSettingsController));

/**
 * @route POST /api/admin/system-settings/import
 * @description Import system configuration
 * @access Super Admin
 */
router.post(
    '/import',
    validateRequestBody(systemSettingsValidation.importConfiguration),
    systemSettingsController.importConfiguration.bind(systemSettingsController)
);

/**
 * @route GET /api/admin/system-settings/:key/history
 * @description Get setting change history
 * @access Super Admin
 */
router.get(
    '/:key/history',
    validateQueryParams(systemSettingsValidation.getSettingHistoryQuery),
    systemSettingsController.getSettingHistory.bind(systemSettingsController)
);

/**
 * @route POST /api/admin/system-settings/validate
 * @description Validate configuration changes
 * @access Super Admin
 */
router.post(
    '/validate',
    validateRequestBody(systemSettingsValidation.validateConfiguration),
    systemSettingsController.validateConfiguration.bind(systemSettingsController)
);

/**
 * @route POST /api/admin/system-settings/maintenance-mode
 * @description Toggle maintenance mode
 * @access Super Admin
 */
router.post(
    '/maintenance-mode',
    validateRequestBody(systemSettingsValidation.toggleMaintenanceMode),
    systemSettingsController.toggleMaintenanceMode.bind(systemSettingsController)
);

module.exports = router;