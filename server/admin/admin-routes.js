/**
 * @file Main Admin Router Aggregator
 * @description Aggregates all admin routes from sub-modules
 * @module admin/routes
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Import shared admin utilities
const { AdminLogger } = require('../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../shared/admin/utils/admin-helpers');
const { AdminFeaturesConfig } = require('../shared/admin/config/admin-features-config');

// Import middleware
const {
    commonMiddleware,
    requireSuperAdmin,
    errorHandler,
    notFoundHandler,
    auditLog
} = require('./admin-middleware');

// Create logger instance
const logger = new AdminLogger('AdminRoutes');

/**
 * Initialize admin routes
 */
const initializeRoutes = () => {
    logger.info('Initializing admin routes...');

    // Apply common middleware to all admin routes
    router.use(commonMiddleware);

    // Root admin endpoint
    router.get('/', auditLog, (req, res) => {
        const adminInfo = {
            message: 'InsightSerenity Admin API',
            version: '1.0.0',
            timestamp: new Date(),
            user: {
                id: req.user.id,
                email: req.user.email,
                role: req.user.role,
                permissions: req.user.permissions || []
            },
            availableModules: getAvailableModules(req.user),
            features: AdminFeaturesConfig.getEnabledFeatures()
        };

        logger.info('Admin root accessed', {
            userId: req.user.id,
            ip: req.ip
        });

        res.json({
            success: true,
            data: adminInfo
        });
    });

    // Mount sub-module routes with feature flag checks
    mountSubModuleRoutes();

    // Admin dashboard data endpoint
    router.get('/dashboard', auditLog, async (req, res, next) => {
        try {
            const dashboardData = await getDashboardData(req);
            
            res.json({
                success: true,
                data: dashboardData
            });
        } catch (error) {
            next(error);
        }
    });

    // Admin search endpoint
    router.get('/search', auditLog, async (req, res, next) => {
        try {
            const { query, type, limit = 10 } = req.query;
            
            if (!query) {
                return res.status(400).json({
                    success: false,
                    error: {
                        message: 'Search query is required',
                        code: 'MISSING_QUERY'
                    }
                });
            }

            const searchResults = await performAdminSearch(req, {
                query,
                type,
                limit: parseInt(limit)
            });

            res.json({
                success: true,
                data: searchResults
            });
        } catch (error) {
            next(error);
        }
    });

    // Admin notifications endpoint
    router.get('/notifications', async (req, res, next) => {
        try {
            const notifications = await req.adminContext.notifications.getAdminNotifications(
                req.user.id,
                {
                    unreadOnly: req.query.unreadOnly === 'true',
                    limit: parseInt(req.query.limit) || 20,
                    offset: parseInt(req.query.offset) || 0
                }
            );

            res.json({
                success: true,
                data: notifications
            });
        } catch (error) {
            next(error);
        }
    });

    // Mark notification as read
    router.put('/notifications/:id/read', async (req, res, next) => {
        try {
            await req.adminContext.notifications.markAsRead(
                req.params.id,
                req.user.id
            );

            res.json({
                success: true,
                message: 'Notification marked as read'
            });
        } catch (error) {
            next(error);
        }
    });

    // Admin activity feed
    router.get('/activity', requireSuperAdmin, async (req, res, next) => {
        try {
            const { startDate, endDate, userId, action, limit = 50 } = req.query;
            
            const activities = await getAdminActivityFeed({
                startDate,
                endDate,
                userId,
                action,
                limit: parseInt(limit)
            });

            res.json({
                success: true,
                data: activities
            });
        } catch (error) {
            next(error);
        }
    });

    // Apply error handlers
    router.use(errorHandler);
    router.use(notFoundHandler);

    logger.info('Admin routes initialized successfully');
};

/**
 * Mount sub-module routes based on features
 */
const mountSubModuleRoutes = () => {
    try {
        // Platform Management Routes
        if (AdminFeaturesConfig.isFeatureEnabled('platformManagement')) {
            const platformRoutes = require('./platform-management/routes/platform-routes');
            const integrationRoutes = require('./platform-management/routes/integration-routes');
            const contentRoutes = require('./platform-management/routes/content-routes');
            const announcementRoutes = require('./platform-management/routes/announcement-routes');

            router.use('/platform', platformRoutes);
            router.use('/integrations', integrationRoutes);
            router.use('/content', contentRoutes);
            router.use('/announcements', announcementRoutes);
            
            logger.info('Platform management routes mounted');
        }

        // Super Admin Routes
        if (AdminFeaturesConfig.isFeatureEnabled('superAdmin')) {
            const superAdminRoutes = require('./super-admin/routes/super-admin-routes');
            const roleManagementRoutes = require('./super-admin/routes/role-management-routes');
            const systemSettingsRoutes = require('./super-admin/routes/system-settings-routes');
            const emergencyAccessRoutes = require('./super-admin/routes/emergency-access-routes');

            router.use('/super-admin', superAdminRoutes);
            router.use('/roles', roleManagementRoutes);
            router.use('/system-settings', systemSettingsRoutes);
            router.use('/emergency', emergencyAccessRoutes);
            
            logger.info('Super admin routes mounted');
        }

        // System Monitoring Routes
        if (AdminFeaturesConfig.isFeatureEnabled('systemMonitoring')) {
            const monitoringRoutes = require('./system-monitoring/routes/monitoring-routes');
            const performanceRoutes = require('./system-monitoring/routes/performance-routes');
            const healthRoutes = require('./system-monitoring/routes/health-routes');
            const alertsRoutes = require('./system-monitoring/routes/alerts-routes');

            router.use('/monitoring', monitoringRoutes);
            router.use('/performance', performanceRoutes);
            router.use('/health', healthRoutes);
            router.use('/alerts', alertsRoutes);
            
            logger.info('System monitoring routes mounted');
        }

        // User Management Routes
        if (AdminFeaturesConfig.isFeatureEnabled('userManagement')) {
            const adminUserRoutes = require('./user-management/routes/admin-user-routes');
            const bulkOperationsRoutes = require('./user-management/routes/bulk-operations-routes');
            const userAnalyticsRoutes = require('./user-management/routes/user-analytics-routes');
            const accountLifecycleRoutes = require('./user-management/routes/account-lifecycle-routes');

            router.use('/users', adminUserRoutes);
            router.use('/users/bulk', bulkOperationsRoutes);
            router.use('/users/analytics', userAnalyticsRoutes);
            router.use('/users/lifecycle', accountLifecycleRoutes);
            
            logger.info('User management routes mounted');
        }

        // Organization Management Routes
        if (AdminFeaturesConfig.isFeatureEnabled('organizationManagement')) {
            const adminOrgRoutes = require('./organization-management/routes/admin-organization-routes');
            const tenantRoutes = require('./organization-management/routes/tenant-management-routes');
            const subscriptionRoutes = require('./organization-management/routes/subscription-management-routes');
            const orgAnalyticsRoutes = require('./organization-management/routes/organization-analytics-routes');

            router.use('/organizations', adminOrgRoutes);
            router.use('/tenants', tenantRoutes);
            router.use('/subscriptions', subscriptionRoutes);
            router.use('/organizations/analytics', orgAnalyticsRoutes);
            
            logger.info('Organization management routes mounted');
        }

        // Security Administration Routes
        if (AdminFeaturesConfig.isFeatureEnabled('securityAdministration')) {
            const securityRoutes = require('./security-administration/routes/security-routes');
            const auditRoutes = require('./security-administration/routes/audit-routes');
            const complianceRoutes = require('./security-administration/routes/compliance-routes');
            const threatRoutes = require('./security-administration/routes/threat-management-routes');

            router.use('/security', securityRoutes);
            router.use('/audit', auditRoutes);
            router.use('/compliance', complianceRoutes);
            router.use('/threats', threatRoutes);
            
            logger.info('Security administration routes mounted');
        }

        // Billing Administration Routes
        if (AdminFeaturesConfig.isFeatureEnabled('billingAdministration')) {
            const billingRoutes = require('./billing-administration/routes/admin-billing-routes');
            const revenueRoutes = require('./billing-administration/routes/revenue-analytics-routes');
            const paymentRoutes = require('./billing-administration/routes/payment-management-routes');
            const subscriptionLifecycleRoutes = require('./billing-administration/routes/subscription-lifecycle-routes');

            router.use('/billing', billingRoutes);
            router.use('/revenue', revenueRoutes);
            router.use('/payments', paymentRoutes);
            router.use('/billing/subscriptions', subscriptionLifecycleRoutes);
            
            logger.info('Billing administration routes mounted');
        }

        // Support Administration Routes
        if (AdminFeaturesConfig.isFeatureEnabled('supportAdministration')) {
            const supportRoutes = require('./support-administration/routes/admin-support-routes');
            const ticketRoutes = require('./support-administration/routes/ticket-management-routes');
            const escalationRoutes = require('./support-administration/routes/escalation-routes');
            const supportAnalyticsRoutes = require('./support-administration/routes/support-analytics-routes');

            router.use('/support', supportRoutes);
            router.use('/tickets', ticketRoutes);
            router.use('/escalations', escalationRoutes);
            router.use('/support/analytics', supportAnalyticsRoutes);
            
            logger.info('Support administration routes mounted');
        }

        // Reports and Analytics Routes
        if (AdminFeaturesConfig.isFeatureEnabled('reportsAndAnalytics')) {
            const reportsRoutes = require('./reports-and-analytics/routes/admin-reports-routes');
            const biRoutes = require('./reports-and-analytics/routes/business-intelligence-routes');
            const dashboardRoutes = require('./reports-and-analytics/routes/executive-dashboard-routes');
            const customAnalyticsRoutes = require('./reports-and-analytics/routes/custom-analytics-routes');

            router.use('/reports', reportsRoutes);
            router.use('/bi', biRoutes);
            router.use('/executive-dashboard', dashboardRoutes);
            router.use('/analytics/custom', customAnalyticsRoutes);
            
            logger.info('Reports and analytics routes mounted');
        }
    } catch (error) {
        logger.error('Error mounting sub-module routes', error);
        // Continue with available routes even if some fail
    }
};

/**
 * Get available modules for user based on permissions
 */
const getAvailableModules = (user) => {
    const modules = [];
    const allFeatures = AdminFeaturesConfig.getAllFeatures();

    // Check each feature and user permissions
    Object.entries(allFeatures).forEach(([feature, config]) => {
        if (config.enabled && hasModuleAccess(user, feature)) {
            modules.push({
                id: feature,
                name: config.name || feature,
                description: config.description,
                path: config.path || `/${feature.toLowerCase()}`
            });
        }
    });

    return modules;
};

/**
 * Check if user has access to module
 */
const hasModuleAccess = (user, module) => {
    // Super admin has access to all modules
    if (user.role === 'super_admin') {
        return true;
    }

    // Check specific module permissions
    const modulePermissions = {
        platformManagement: ['platform:read', 'platform:write'],
        superAdmin: ['super_admin'],
        systemMonitoring: ['monitoring:access'],
        userManagement: ['users:read', 'users:write'],
        organizationManagement: ['organizations:read', 'organizations:write'],
        securityAdministration: ['security:access'],
        billingAdministration: ['billing:access'],
        supportAdministration: ['support:read', 'support:write'],
        reportsAndAnalytics: ['reports:access']
    };

    const requiredPermissions = modulePermissions[module] || [];
    return requiredPermissions.some(permission => 
        user.permissions?.includes(permission)
    );
};

/**
 * Get dashboard data for admin user
 */
const getDashboardData = async (req) => {
    const dashboardData = {
        overview: {
            totalUsers: 0,
            totalOrganizations: 0,
            activeSubscriptions: 0,
            revenue: {
                monthly: 0,
                annual: 0
            }
        },
        recentActivity: [],
        systemHealth: {
            status: 'operational',
            uptime: process.uptime(),
            performance: {}
        },
        alerts: [],
        quickStats: []
    };

    // Fetch data based on user permissions
    try {
        // Get metrics from cache if available
        const cachedData = await req.adminContext.cache.get('admin:dashboard:' + req.user.id);
        if (cachedData) {
            return cachedData;
        }

        // Fetch fresh data (implementation depends on available services)
        // This is a placeholder - actual implementation would fetch from services

        // Cache the dashboard data
        await req.adminContext.cache.set(
            'admin:dashboard:' + req.user.id,
            dashboardData,
            300 // 5 minutes
        );

        return dashboardData;
    } catch (error) {
        logger.error('Error fetching dashboard data', error);
        return dashboardData;
    }
};

/**
 * Perform admin search across entities
 */
const performAdminSearch = async (req, options) => {
    const { query, type, limit } = options;
    const results = {
        users: [],
        organizations: [],
        tickets: [],
        total: 0
    };

    try {
        // Search based on user permissions and type filter
        if (!type || type === 'users') {
            if (req.user.permissions?.includes('users:read')) {
                // Placeholder for user search
                results.users = [];
            }
        }

        if (!type || type === 'organizations') {
            if (req.user.permissions?.includes('organizations:read')) {
                // Placeholder for organization search
                results.organizations = [];
            }
        }

        if (!type || type === 'tickets') {
            if (req.user.permissions?.includes('support:read')) {
                // Placeholder for ticket search
                results.tickets = [];
            }
        }

        results.total = results.users.length + 
                       results.organizations.length + 
                       results.tickets.length;

        return results;
    } catch (error) {
        logger.error('Error performing admin search', error);
        throw error;
    }
};

/**
 * Get admin activity feed
 */
const getAdminActivityFeed = async (filters) => {
    try {
        // Placeholder for activity feed implementation
        // Would fetch from audit logs based on filters
        return {
            activities: [],
            total: 0,
            filters: filters
        };
    } catch (error) {
        logger.error('Error fetching activity feed', error);
        throw error;
    }
};

// Initialize routes
initializeRoutes();

// Export router
module.exports = router;