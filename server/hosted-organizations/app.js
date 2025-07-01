/**
 * @file Hosted Organizations Module App
 * @description Express application for multi-tenant hosted organization management
 * @version 2.0.0
 */

const express = require('express');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const cors = require('cors');

// Import shared configuration
const config = require('../shared/config/config');
const logger = require('../shared/utils/logger');

// Create module app
const app = express();

// Module-specific CORS configuration for multi-tenant support
const corsOptions = {
    origin: function (origin, callback) {
        // Build allowed origins array dynamically
        const allowedOrigins = [];
        
        // Add main application URL
        if (config.app.url) {
            allowedOrigins.push(config.app.url);
        } else if (process.env.APP_URL) {
            allowedOrigins.push(process.env.APP_URL);
        }
        
        // Add configured additional origins
        if (config.cors && config.cors.allowedOrigins) {
            allowedOrigins.push(...config.cors.allowedOrigins);
        }
        
        // Check against patterns for subdomains
        const domainPatterns = [
            new RegExp(`\\.${config.app.domain || 'insightserenity.com'}$`),
            /^https:\/\/[a-zA-Z0-9-]+\.insightserenity\.app$/
        ];
        
        // Allow requests from allowed origins or matching patterns
        if (!origin) {
            // Allow requests with no origin (like mobile apps or Postman)
            callback(null, true);
        } else if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else if (domainPatterns.some(pattern => pattern.test(origin))) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Organization-ID', 'X-Tenant-ID'],
    exposedHeaders: ['X-Organization-ID', 'X-Tenant-ID', 'X-Rate-Limit-Remaining']
};

app.use(cors(corsOptions));
app.use(helmet(config.security.helmet || {}));
app.use(compression());
app.use(mongoSanitize());
app.use(express.json({ limit: config.multiTenant?.requestLimit || '50mb' })); // Larger limit for organization imports
app.use(express.urlencoded({ extended: true, limit: config.multiTenant?.requestLimit || '50mb' }));

// Import route modules
const organizationRoutes = require('./organizations/routes/routes');
// const subscriptionRoutes = require('./subscriptions/routes/subscription-routes');
// const billingRoutes = require('./billing/routes/billing-routes');
// const tenantRoutes = require('./tenants/routes/tenant-routes');
// const brandingRoutes = require('./branding/routes/branding-routes');
// const domainRoutes = require('./domains/routes/domain-routes');
// const integrationRoutes = require('./integrations/routes/integration-routes');
// const auditRoutes = require('./audit/routes/audit-routes');
// const usageRoutes = require('./usage/routes/usage-routes');
// const migrationRoutes = require('./migrations/routes/migration-routes');
// const backupRoutes = require('./backups/routes/backup-routes');
// const notificationRoutes = require('./notifications/routes/notification-routes');

// Multi-tenant middleware
const { detectTenant } = require('./middleware/tenant-detection');
const { enforceQuotas } = require('./middleware/quota-enforcement');
const { trackUsage } = require('./middleware/usage-tracking');
const { validateSubscription } = require('./middleware/subscription-validation');
const { organizationRateLimiter } = require('./middleware/organization-rate-limiter');

// Apply tenant detection globally for this module
app.use(detectTenant);

// Health check with tenant awareness
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        module: 'hosted-organizations',
        timestamp: new Date().toISOString(),
        environment: config.app.env,
        version: config.app.version,
        tenant: req.tenantId || 'none',
        multiTenantEnabled: config.multiTenant?.enabled || false,
        services: {
            organizations: 'active',
            subscriptions: 'active',
            billing: 'active',
            tenants: 'active',
            domains: 'active',
            integrations: 'active'
        }
    });
});

// Log module initialization
logger.info('Hosted Organizations module initialized', {
    environment: config.app.env,
    multiTenantEnabled: config.multiTenant?.enabled,
    requestLimit: config.multiTenant?.requestLimit
});

/**
 * Mount routes in order of dependency and importance
 */

// // 1. Tenant Management (Foundation for multi-tenancy)
// app.use('/tenants', tenantRoutes);

// 2. Organization Management (Core entity)
app.use('/organizations', organizationRoutes);

// // 3. Subscription Management (Business model)
// app.use('/subscriptions', validateSubscription, subscriptionRoutes);

// // 4. Billing Management (Revenue operations)
// app.use('/billing', validateSubscription, billingRoutes);

// // 5. Usage Tracking (Metering and limits)
// app.use('/usage', trackUsage, usageRoutes);

// // 6. Domain Management (Custom domains)
// app.use('/domains', enforceQuotas, domainRoutes);

// // 7. Branding & Customization (White-label support)
// app.use('/branding', brandingRoutes);

// // 8. Integrations (Third-party connections)
// app.use('/integrations', enforceQuotas, integrationRoutes);

// // 9. Audit Trails (Compliance and security)
// app.use('/audit', auditRoutes);

// // 10. Data Migration (Import/Export)
// app.use('/migrations', organizationRateLimiter, migrationRoutes);

// // 11. Backup Management (Data protection)
// app.use('/backups', organizationRateLimiter, backupRoutes);

// // 12. Notifications (Organization-level notifications)
// app.use('/notifications', notificationRoutes);

// Apply organization-specific rate limiting
app.use(organizationRateLimiter);

// Module-specific error handling
app.use((err, req, res, next) => {
    if (err.type === 'TenantNotFound') {
        return res.status(404).json({
            status: 'error',
            type: 'tenant_not_found',
            message: 'Organization not found or access denied',
            code: 'ORG_NOT_FOUND'
        });
    }
    
    if (err.type === 'SubscriptionExpired') {
        return res.status(402).json({
            status: 'error',
            type: 'subscription_expired',
            message: 'Organization subscription has expired',
            code: 'SUB_EXPIRED',
            upgradeUrl: '/billing/upgrade'
        });
    }
    
    if (err.type === 'QuotaExceeded') {
        return res.status(429).json({
            status: 'error',
            type: 'quota_exceeded',
            message: err.message,
            code: 'QUOTA_EXCEEDED',
            quota: err.quota,
            usage: err.usage,
            upgradeUrl: '/billing/upgrade'
        });
    }
    
    if (err.type === 'DomainConflict') {
        return res.status(409).json({
            status: 'error',
            type: 'domain_conflict',
            message: 'Domain is already registered to another organization',
            code: 'DOMAIN_CONFLICT'
        });
    }
    
    next(err);
});

// 404 handler for this module
app.use('*', (req, res) => {
    res.status(404).json({
        status: 'error',
        module: 'hosted-organizations',
        message: `Hosted organization route ${req.originalUrl} not found`,
        tenant: req.tenantId || 'none',
        availableEndpoints: [
            '/tenants',
            '/organizations',
            '/subscriptions',
            '/billing',
            '/usage',
            '/domains',
            '/branding',
            '/integrations',
            '/audit',
            '/migrations',
            '/backups',
            '/notifications'
        ]
    });
});

module.exports = app;