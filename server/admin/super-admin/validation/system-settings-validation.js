/**
 * @file System Settings Validation
 * @description Validation schemas for system settings operations
 * @module admin/super-admin/validation
 * @version 1.0.0
 */

const Joi = require('joi');

const systemSettingsValidation = {
    /**
     * Validation for getting settings query
     */
    getSettingsQuery: Joi.object({
        category: Joi.string().max(50),
        includeSecrets: Joi.boolean().default(false)
    }),

    /**
     * Validation for updating setting
     */
    updateSetting: Joi.object({
        value: Joi.alternatives()
            .try(
                Joi.string(),
                Joi.number(),
                Joi.boolean(),
                Joi.array(),
                Joi.object()
            )
            .required(),
        description: Joi.string().max(500),
        metadata: Joi.object({
            reason: Joi.string().max(500),
            ticketId: Joi.string().max(50),
            approvedBy: Joi.string()
        })
    }),

    /**
     * Validation for bulk update settings
     */
    bulkUpdateSettings: Joi.object({
        settings: Joi.array()
            .items(
                Joi.object({
                    key: Joi.string().required(),
                    value: Joi.alternatives()
                        .try(
                            Joi.string(),
                            Joi.number(),
                            Joi.boolean(),
                            Joi.array(),
                            Joi.object()
                        )
                        .required(),
                    description: Joi.string().max(500),
                    metadata: Joi.object()
                })
            )
            .min(1)
            .max(50)
            .required()
    }),

    /**
     * Validation for export configuration query
     */
    exportConfigurationQuery: Joi.object({
        format: Joi.string().valid('json', 'env', 'yaml').default('json'),
        categories: Joi.string(), // Comma-separated list
        includeSecrets: Joi.boolean().default(false)
    }),

    /**
     * Validation for import configuration
     */
    importConfiguration: Joi.object({
        configuration: Joi.object().required(),
        overwrite: Joi.boolean().default(false),
        dryRun: Joi.boolean().default(false)
    }),

    /**
     * Validation for getting setting history query
     */
    getSettingHistoryQuery: Joi.object({
        limit: Joi.number().integer().min(1).max(100).default(50),
        startDate: Joi.date().iso(),
        endDate: Joi.date().iso().min(Joi.ref('startDate'))
    }),

    /**
     * Validation for validate configuration
     */
    validateConfiguration: Joi.object({
        settings: Joi.array()
            .items(
                Joi.object({
                    key: Joi.string().required(),
                    value: Joi.any().required()
                })
            )
            .min(1)
            .required()
    }),

    /**
     * Validation for toggle maintenance mode
     */
    toggleMaintenanceMode: Joi.object({
        enabled: Joi.boolean().required(),
        message: Joi.string().max(500).when('enabled', {
            is: true,
            then: Joi.required(),
            otherwise: Joi.optional()
        }),
        estimatedDuration: Joi.number().integer().min(0).when('enabled', {
            is: true,
            then: Joi.optional(),
            otherwise: Joi.forbidden()
        })
    })
};

module.exports = { systemSettingsValidation };