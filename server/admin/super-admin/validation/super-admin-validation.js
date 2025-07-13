/**
 * @file Super Admin Validation
 * @description Validation schemas for super admin operations
 * @module admin/super-admin/validation
 * @version 1.0.0
 */

const Joi = require('joi');
const { ADMIN_ROLES } = require('../../../shared/admin/constants/admin-roles');
const { ADMIN_PERMISSIONS } = require('../../../shared/admin/constants/admin-permissions');

const superAdminValidation = {
    /**
     * Validation for getting admin users query
     */
    getAdminUsersQuery: Joi.object({
        page: Joi.number().integer().min(1).default(1),
        limit: Joi.number().integer().min(1).max(100).default(20),
        role: Joi.string().valid(...Object.keys(ADMIN_ROLES)),
        status: Joi.string().valid('active', 'inactive', 'suspended'),
        search: Joi.string().max(100)
    }),

    /**
     * Validation for creating admin user
     */
    createAdminUser: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])/)
            .required()
            .messages({
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
            }),
        fullName: Joi.string().min(2).max(100).required(),
        role: Joi.string().valid(...Object.keys(ADMIN_ROLES)).required(),
        permissions: Joi.array()
            .items(Joi.string().valid(...Object.values(ADMIN_PERMISSIONS).flat()))
            .unique()
            .optional()
    }),

    /**
     * Validation for updating admin user
     */
    updateAdminUser: Joi.object({
        fullName: Joi.string().min(2).max(100),
        role: Joi.string().valid(...Object.keys(ADMIN_ROLES)),
        permissions: Joi.array()
            .items(Joi.string().valid(...Object.values(ADMIN_PERMISSIONS).flat()))
            .unique(),
        status: Joi.string().valid('active', 'inactive', 'suspended')
    }).min(1),

    /**
     * Validation for revoking admin access
     */
    revokeAdminAccess: Joi.object({
        reason: Joi.string().min(10).max(500).required(),
        immediate: Joi.boolean().default(false)
    }),

    /**
     * Validation for getting activity logs query
     */
    getActivityLogsQuery: Joi.object({
        startDate: Joi.date().iso(),
        endDate: Joi.date().iso().min(Joi.ref('startDate')),
        userId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
        action: Joi.string().max(100),
        severity: Joi.string().valid('low', 'medium', 'high', 'critical'),
        page: Joi.number().integer().min(1).default(1),
        limit: Joi.number().integer().min(1).max(100).default(50)
    }),

    /**
     * Validation for executing maintenance task
     */
    executeMaintenanceTask: Joi.object({
        task: Joi.string()
            .valid(
                'clear_cache',
                'cleanup_sessions',
                'optimize_database',
                'rotate_logs',
                'backup_database'
            )
            .required(),
        parameters: Joi.object({
            pattern: Joi.string().when('$task', {
                is: 'clear_cache',
                then: Joi.optional(),
                otherwise: Joi.forbidden()
            }),
            olderThan: Joi.number().integer().min(1).when('$task', {
                is: 'cleanup_sessions',
                then: Joi.optional(),
                otherwise: Joi.forbidden()
            }),
            collections: Joi.array().items(Joi.string()).when('$task', {
                is: 'optimize_database',
                then: Joi.optional(),
                otherwise: Joi.forbidden()
            }),
            retention: Joi.number().integer().min(1).when('$task', {
                is: 'rotate_logs',
                then: Joi.optional(),
                otherwise: Joi.forbidden()
            }),
            destination: Joi.string().when('$task', {
                is: 'backup_database',
                then: Joi.optional(),
                otherwise: Joi.forbidden()
            })
        }).default({})
    }),

    /**
     * Validation for exporting system data
     */
    exportSystemData: Joi.object({
        dataType: Joi.string()
            .valid('users', 'organizations', 'audit_logs', 'system_config')
            .required(),
        format: Joi.string().valid('json', 'csv', 'xlsx').default('json'),
        filters: Joi.object({
            startDate: Joi.date().iso(),
            endDate: Joi.date().iso().min(Joi.ref('startDate')),
            status: Joi.string(),
            role: Joi.string(),
            category: Joi.string()
        }).default({})
    })
};

module.exports = { superAdminValidation };