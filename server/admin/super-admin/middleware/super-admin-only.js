/**
 * @file Super Admin Access Middleware
 * @description Middleware for super admin specific access controls
 * @module admin/super-admin/middleware
 * @version 1.0.0
 */

const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../../../shared/admin/utils/admin-helpers');
const { ADMIN_ROLES } = require('../../../shared/admin/constants/admin-roles');
const User = require('../../../models/user-model');

const logger = new AdminLogger('SuperAdminAccessMiddleware');

/**
 * Ensure user is a super admin
 */
const ensureSuperAdmin = async (req, res, next) => {
    try {
        if (!req.user || req.user.role !== 'super_admin') {
            logger.warn('Non-super admin attempted to access super admin route', {
                userId: req.user?.id,
                role: req.user?.role,
                path: req.path
            });

            return res.status(403).json({
                success: false,
                error: {
                    message: 'Super admin access required',
                    code: 'SUPER_ADMIN_REQUIRED'
                }
            });
        }

        // Verify super admin status in database (extra security)
        const user = await User.findById(req.user.id).select('role status');
        if (!user || user.role !== 'super_admin' || user.status !== 'active') {
            logger.error('Super admin verification failed', {
                userId: req.user.id,
                dbRole: user?.role,
                dbStatus: user?.status
            });

            return res.status(403).json({
                success: false,
                error: {
                    message: 'Super admin verification failed',
                    code: 'SUPER_ADMIN_VERIFICATION_FAILED'
                }
            });
        }

        next();
    } catch (error) {
        logger.error('Error in super admin middleware', error);
        res.status(500).json({
            success: false,
            error: {
                message: 'Internal server error',
                code: 'INTERNAL_ERROR'
            }
        });
    }
};

/**
 * Check if user can perform critical operations
 */
const canPerformCriticalOperation = (req, res, next) => {
    try {
        // Check if session is recent (within last 30 minutes)
        const sessionAge = Date.now() - new Date(req.user.lastActivity).getTime();
        const maxAge = 30 * 60 * 1000; // 30 minutes

        if (sessionAge > maxAge) {
            logger.warn('Session too old for critical operation', {
                userId: req.user.id,
                sessionAge: Math.floor(sessionAge / 1000 / 60) + ' minutes'
            });

            return res.status(403).json({
                success: false,
                error: {
                    message: 'Please re-authenticate to perform this operation',
                    code: 'REAUTHENTICATION_REQUIRED'
                }
            });
        }

        // Check if MFA was recently verified (within last 15 minutes)
        if (req.user.lastMFAVerification) {
            const mfaAge = Date.now() - new Date(req.user.lastMFAVerification).getTime();
            const maxMFAAge = 15 * 60 * 1000; // 15 minutes

            if (mfaAge > maxMFAAge) {
                return res.status(403).json({
                    success: false,
                    error: {
                        message: 'MFA verification required for this operation',
                        code: 'MFA_VERIFICATION_REQUIRED'
                    }
                });
            }
        }

        next();
    } catch (error) {
        logger.error('Error checking critical operation permission', error);
        res.status(500).json({
            success: false,
            error: {
                message: 'Internal server error',
                code: 'INTERNAL_ERROR'
            }
        });
    }
};

/**
 * Validate emergency access approval permissions
 */
const canApproveEmergencyAccess = async (req, res, next) => {
    try {
        const user = req.user;

        // Check if user has emergency approval permission
        const hasPermission = user.role === 'super_admin' || 
                            user.permissions?.includes('emergency:approve');

        if (!hasPermission) {
            logger.warn('User lacks emergency approval permission', {
                userId: user.id,
                role: user.role
            });

            return res.status(403).json({
                success: false,
                error: {
                    message: 'Insufficient permissions to approve emergency access',
                    code: 'EMERGENCY_APPROVAL_FORBIDDEN'
                }
            });
        }

        // Cannot approve own requests
        if (req.body.requestedBy === user.id) {
            return res.status(403).json({
                success: false,
                error: {
                    message: 'Cannot approve your own emergency access request',
                    code: 'SELF_APPROVAL_FORBIDDEN'
                }
            });
        }

        next();
    } catch (error) {
        logger.error('Error checking emergency approval permission', error);
        res.status(500).json({
            success: false,
            error: {
                message: 'Internal server error',
                code: 'INTERNAL_ERROR'
            }
        });
    }
};

/**
 * Rate limit critical super admin operations
 */
const rateLimitCriticalOps = (req, res, next) => {
    const key = `critical_ops:${req.user.id}`;
    const limit = 10; // 10 operations per hour
    const window = 60 * 60 * 1000; // 1 hour

    // This would integrate with Redis or similar for distributed rate limiting
    // For now, using in-memory tracking
    if (!global.criticalOpsTracker) {
        global.criticalOpsTracker = new Map();
    }

    const now = Date.now();
    const userOps = global.criticalOpsTracker.get(key) || [];
    
    // Clean old entries
    const recentOps = userOps.filter(timestamp => now - timestamp < window);
    
    if (recentOps.length >= limit) {
        logger.warn('Critical operation rate limit exceeded', {
            userId: req.user.id,
            operations: recentOps.length,
            window: '1 hour'
        });

        return res.status(429).json({
            success: false,
            error: {
                message: 'Too many critical operations. Please try again later.',
                code: 'RATE_LIMIT_EXCEEDED',
                retryAfter: Math.ceil((recentOps[0] + window - now) / 1000) + ' seconds'
            }
        });
    }

    // Track this operation
    recentOps.push(now);
    global.criticalOpsTracker.set(key, recentOps);

    next();
};

/**
 * Log critical operations
 */
const logCriticalOperation = (operationType) => {
    return (req, res, next) => {
        // Log the operation
        logger.warn(`Critical operation initiated: ${operationType}`, {
            userId: req.user.id,
            operation: operationType,
            path: req.path,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('user-agent')
        });

        // Add to request for audit
        req.criticalOperation = {
            type: operationType,
            timestamp: new Date()
        };

        next();
    };
};

module.exports = {
    ensureSuperAdmin,
    canPerformCriticalOperation,
    canApproveEmergencyAccess,
    rateLimitCriticalOps,
    logCriticalOperation
};