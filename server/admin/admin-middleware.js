/**
 * @file Common Admin Middleware
 * @description Aggregates and exports all admin-specific middleware
 * @module admin/middleware
 * @version 1.0.0
 */

const express = require('express');

// Import shared admin middleware
const { 
    AdminAuthentication,
    ensureAdminAuthenticated,
    ensureSuperAdmin,
    validateAdminToken
} = require('../shared/admin/middleware/admin-authentication');

const { 
    AdminAuthorization,
    requirePermission,
    requireAnyPermission,
    requireAllPermissions,
    checkResourceAccess
} = require('../shared/admin/middleware/admin-authorization');

const { 
    AdminRateLimiting,
    createAdminRateLimiter,
    strictRateLimit,
    moderateRateLimit,
    lightRateLimit
} = require('../shared/admin/middleware/admin-rate-limiting');

const { 
    AdminAuditLogging,
    auditLog,
    auditCriticalAction,
    auditDataAccess,
    auditConfigChange
} = require('../shared/admin/middleware/admin-audit-logging');

const { 
    AdminSessionManagement,
    validateAdminSession,
    refreshAdminSession,
    enforceSessionPolicy
} = require('../shared/admin/middleware/admin-session-management');

const { 
    MultiFactorValidation,
    requireMFA,
    validateMFAToken,
    enforceMFAForCriticalOps
} = require('../shared/admin/middleware/multi-factor-validation');

const { 
    AdminIPValidation,
    enforceIPWhitelist,
    validateAdminIP,
    checkIPReputation
} = require('../shared/admin/middleware/admin-ip-validation');

// Import utilities and helpers
const { AdminLogger } = require('../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../shared/admin/utils/admin-helpers');
const { AdminPermissions } = require('../shared/admin/utils/admin-permissions');

// Import configuration
const config = require('../config/configuration');

// Create logger instance
const logger = new AdminLogger('AdminMiddleware');

/**
 * Common middleware applied to all admin routes
 */
const commonMiddleware = [
    // Basic admin authentication
    ensureAdminAuthenticated,
    
    // Validate admin session
    validateAdminSession,
    
    // IP validation (if enabled)
    (req, res, next) => {
        if (config.organization.security.ipWhitelistEnabled) {
            return enforceIPWhitelist(req, res, next);
        }
        next();
    },
    
    // Refresh session activity
    refreshAdminSession,
    
    // Add admin context to request
    (req, res, next) => {
        req.isAdminRequest = true;
        req.adminUser = req.user;
        next();
    },
    
    // Set security headers
    (req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        next();
    }
];

/**
 * Middleware for super admin only routes
 */
const requireSuperAdmin = [
    ...commonMiddleware,
    ensureSuperAdmin,
    enforceMFAForCriticalOps,
    auditCriticalAction
];

/**
 * Middleware for routes that modify system configuration
 */
const requireSystemConfig = [
    ...commonMiddleware,
    requirePermission('system:config:write'),
    enforceMFAForCriticalOps,
    auditConfigChange
];

/**
 * Middleware for user management routes
 */
const requireUserManagement = [
    ...commonMiddleware,
    requireAnyPermission(['users:read', 'users:write', 'users:delete']),
    auditDataAccess
];

/**
 * Middleware for organization management routes
 */
const requireOrgManagement = [
    ...commonMiddleware,
    requireAnyPermission(['organizations:read', 'organizations:write', 'organizations:delete']),
    auditDataAccess
];

/**
 * Middleware for billing administration routes
 */
const requireBillingAccess = [
    ...commonMiddleware,
    requirePermission('billing:access'),
    enforceMFAForCriticalOps,
    auditDataAccess
];

/**
 * Middleware for security administration routes
 */
const requireSecurityAccess = [
    ...commonMiddleware,
    requirePermission('security:access'),
    enforceMFAForCriticalOps,
    auditCriticalAction
];

/**
 * Middleware for platform management routes
 */
const requirePlatformAccess = [
    ...commonMiddleware,
    requireAnyPermission(['platform:read', 'platform:write']),
    auditLog
];

/**
 * Middleware for monitoring routes
 */
const requireMonitoringAccess = [
    ...commonMiddleware,
    requirePermission('monitoring:access'),
    // Use light rate limiting for monitoring endpoints
    lightRateLimit
];

/**
 * Middleware for report generation routes
 */
const requireReportAccess = [
    ...commonMiddleware,
    requirePermission('reports:access'),
    // Use moderate rate limiting for report generation
    moderateRateLimit,
    auditDataAccess
];

/**
 * Middleware for support administration routes
 */
const requireSupportAccess = [
    ...commonMiddleware,
    requireAnyPermission(['support:read', 'support:write']),
    auditLog
];

/**
 * Error handling middleware for admin routes
 */
const errorHandler = (err, req, res, next) => {
    logger.error('Admin route error', {
        error: err,
        path: req.path,
        method: req.method,
        user: req.user?.id,
        ip: req.ip
    });

    // Audit the error if it's a security-related error
    if (err.type === 'security' || err.statusCode === 403) {
        req.adminContext?.audit?.logAction({
            action: 'admin.error.security',
            userId: req.user?.id,
            resourceType: 'admin',
            details: {
                error: err.message,
                path: req.path,
                method: req.method
            },
            severity: 'high',
            ip: req.ip
        });
    }

    // Send appropriate error response
    const statusCode = err.statusCode || 500;
    const message = config.app.env === 'production' 
        ? 'An error occurred processing your request'
        : err.message;

    res.status(statusCode).json({
        success: false,
        error: {
            message,
            code: err.code || 'ADMIN_ERROR',
            ...(config.app.env !== 'production' && { stack: err.stack })
        }
    });
};

/**
 * Not found handler for admin routes
 */
const notFoundHandler = (req, res) => {
    logger.warn('Admin route not found', {
        path: req.path,
        method: req.method,
        user: req.user?.id
    });

    res.status(404).json({
        success: false,
        error: {
            message: 'Admin endpoint not found',
            code: 'ADMIN_NOT_FOUND'
        }
    });
};

/**
 * Create custom middleware combinations
 */
const createCustomMiddleware = (permissions, options = {}) => {
    const middleware = [...commonMiddleware];

    // Add permission checks
    if (permissions) {
        if (Array.isArray(permissions)) {
            middleware.push(options.requireAll 
                ? requireAllPermissions(permissions)
                : requireAnyPermission(permissions)
            );
        } else {
            middleware.push(requirePermission(permissions));
        }
    }

    // Add MFA if required
    if (options.requireMFA) {
        middleware.push(enforceMFAForCriticalOps);
    }

    // Add rate limiting
    if (options.rateLimit) {
        switch (options.rateLimit) {
            case 'strict':
                middleware.push(strictRateLimit);
                break;
            case 'moderate':
                middleware.push(moderateRateLimit);
                break;
            case 'light':
                middleware.push(lightRateLimit);
                break;
            default:
                middleware.push(createAdminRateLimiter(options.rateLimit));
        }
    }

    // Add audit logging
    if (options.audit) {
        switch (options.audit) {
            case 'critical':
                middleware.push(auditCriticalAction);
                break;
            case 'data':
                middleware.push(auditDataAccess);
                break;
            case 'config':
                middleware.push(auditConfigChange);
                break;
            default:
                middleware.push(auditLog);
        }
    }

    return middleware;
};

/**
 * Validate request body middleware
 */
const validateRequestBody = (schema) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.body, {
            abortEarly: false,
            stripUnknown: true
        });

        if (error) {
            logger.warn('Request validation failed', {
                path: req.path,
                errors: error.details,
                user: req.user?.id
            });

            return res.status(400).json({
                success: false,
                error: {
                    message: 'Validation failed',
                    code: 'VALIDATION_ERROR',
                    details: error.details.map(detail => ({
                        field: detail.path.join('.'),
                        message: detail.message
                    }))
                }
            });
        }

        req.body = value;
        next();
    };
};

/**
 * Validate query parameters middleware
 */
const validateQueryParams = (schema) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.query, {
            abortEarly: false,
            stripUnknown: true
        });

        if (error) {
            logger.warn('Query validation failed', {
                path: req.path,
                errors: error.details,
                user: req.user?.id
            });

            return res.status(400).json({
                success: false,
                error: {
                    message: 'Invalid query parameters',
                    code: 'VALIDATION_ERROR',
                    details: error.details.map(detail => ({
                        field: detail.path.join('.'),
                        message: detail.message
                    }))
                }
            });
        }

        req.query = value;
        next();
    };
};

// Export all middleware
module.exports = {
    // Common middleware
    commonMiddleware,
    requireSuperAdmin,
    requireSystemConfig,
    requireUserManagement,
    requireOrgManagement,
    requireBillingAccess,
    requireSecurityAccess,
    requirePlatformAccess,
    requireMonitoringAccess,
    requireReportAccess,
    requireSupportAccess,
    
    // Individual middleware exports
    ensureAdminAuthenticated,
    ensureSuperAdmin,
    validateAdminToken,
    requirePermission,
    requireAnyPermission,
    requireAllPermissions,
    checkResourceAccess,
    createAdminRateLimiter,
    strictRateLimit,
    moderateRateLimit,
    lightRateLimit,
    auditLog,
    auditCriticalAction,
    auditDataAccess,
    auditConfigChange,
    validateAdminSession,
    refreshAdminSession,
    enforceSessionPolicy,
    requireMFA,
    validateMFAToken,
    enforceMFAForCriticalOps,
    enforceIPWhitelist,
    validateAdminIP,
    checkIPReputation,
    
    // Utility middleware
    errorHandler,
    notFoundHandler,
    createCustomMiddleware,
    validateRequestBody,
    validateQueryParams
};