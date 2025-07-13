/**
 * @file Emergency Access Validation
 * @description Validation schemas for emergency access operations
 * @module admin/super-admin/validation
 * @version 1.0.0
 */

const Joi = require('joi');

const emergencyAccessValidation = {
    /**
     * Validation for requesting emergency access
     */
    requestEmergencyAccess: Joi.object({
        reason: Joi.string().min(20).max(1000).required(),
        resourceType: Joi.string()
            .valid('user', 'organization', 'system', 'database', 'billing')
            .required(),
        resourceId: Joi.string().when('resourceType', {
            is: Joi.valid('user', 'organization'),
            then: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).required(),
            otherwise: Joi.string().max(100).required()
        }),
        duration: Joi.number()
            .integer()
            .min(900000) // 15 minutes
            .max(86400000) // 24 hours
            .required(),
        justification: Joi.string().min(50).max(2000).required(),
        ticketId: Joi.string().max(50).required()
    }),

    /**
     * Validation for getting requests query
     */
    getRequestsQuery: Joi.object({
        status: Joi.string().valid('pending', 'approved', 'denied', 'expired'),
        requesterId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/),
        resourceType: Joi.string().valid('user', 'organization', 'system', 'database', 'billing'),
        startDate: Joi.date().iso(),
        endDate: Joi.date().iso().min(Joi.ref('startDate')),
        page: Joi.number().integer().min(1).default(1),
        limit: Joi.number().integer().min(1).max(50).default(20)
    }),

    /**
     * Validation for approving emergency access
     */
    approveEmergencyAccess: Joi.object({
        comments: Joi.string().min(10).max(500).required(),
        conditions: Joi.array()
            .items(Joi.string().max(200))
            .max(5),
        expiresAt: Joi.date()
            .iso()
            .min('now')
            .max(Joi.ref('$now', { adjust: (value) => value + 86400000 })) // Max 24 hours from now
    }),

    /**
     * Validation for denying emergency access
     */
    denyEmergencyAccess: Joi.object({
        reason: Joi.string().min(20).max(500).required(),
        recommendations: Joi.array()
            .items(Joi.string().max(200))
            .max(5)
    }),

    /**
     * Validation for revoking emergency access
     */
    revokeEmergencyAccess: Joi.object({
        reason: Joi.string().min(20).max(500).required(),
        immediate: Joi.boolean().default(true)
    }),

    /**
     * Validation for executing break-glass
     */
    executeBreakGlass: Joi.object({
        reason: Joi.string().min(50).max(1000).required(),
        targetSystem: Joi.string()
            .valid('all', 'database', 'infrastructure', 'security', 'billing')
            .required(),
        urgencyLevel: Joi.string()
            .valid('critical', 'high', 'medium')
            .required(),
        incidentId: Joi.string().max(50).required(),
        verificationCode: Joi.string()
            .pattern(/^\d{6}$/)
            .required()
            .messages({
                'string.pattern.base': 'Verification code must be 6 digits'
            })
    }),

    /**
     * Validation for getting report query
     */
    getReportQuery: Joi.object({
        startDate: Joi.date().iso().required(),
        endDate: Joi.date()
            .iso()
            .min(Joi.ref('startDate'))
            .required(),
        includeBreakGlass: Joi.boolean().default(true)
    })
};

module.exports = { emergencyAccessValidation };