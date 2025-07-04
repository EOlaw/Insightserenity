/**
 * @file Hosted Organizations Module App
 * @description Express application for multi-tenant hosted organization management
 * @version 2.1.0
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
const organizationRoutes = require('./organizations/routes/organization-routes');
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

// Multi-tenant middleware - Updated imports
const { 
  detectTenant, 
  requireTenantContext 
} = require('../shared/middleware/hosted-organizations/tenant-detection');

const { 
  enforceQuotas,
  enforceAPIQuotas,
  enforceStorageQuotas 
} = require('../shared/middleware/hosted-organizations/quota-enforcement');

const { 
  trackUsage,
  trackAPIUsage,
  trackAllUsage 
} = require('../shared/middleware/hosted-organizations/usage-tracking');

const { 
  validateSubscription,
  requireActiveSubscription,
  requirePaidSubscription 
} = require('../shared/middleware/hosted-organizations/subscription-validation');

const { 
  organizationRateLimiter,
  generalAPIRateLimiter,
  sensitiveOperationsRateLimiter
} = require('../shared/middleware/hosted-organizations/organization-rate-limiter');

// Apply tenant detection globally for this module
app.use(detectTenant);

// Apply general API rate limiting
app.use(generalAPIRateLimiter);

// Apply usage tracking for all requests
app.use(trackAPIUsage);

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

// 1. Organization Management (Core entity) - with subscription validation
app.use('/organizations', 
  // requireActiveSubscription, // Ensure active subscription for organization operations
  organizationRoutes
);

// // 2. Subscription Management (Business model) - with enhanced tracking
// app.use('/subscriptions', 
//   validateSubscription, 
//   trackAllUsage,
//   subscriptionRoutes
// );

// // 3. Billing Management (Revenue operations) - with strict rate limiting
// app.use('/billing', 
//   requirePaidSubscription, 
//   sensitiveOperationsRateLimiter,
//   trackUsage({ resources: ['billing_operations'] }),
//   billingRoutes
// );

// // 4. Usage Tracking (Metering and limits)
// app.use('/usage', 
//   trackUsage({ resources: ['usage_queries'] }), 
//   usageRoutes
// );

// // 5. Domain Management (Custom domains) - with quota enforcement
// app.use('/domains', 
//   enforceQuotas({ resource: 'domains' }),
//   sensitiveOperationsRateLimiter,
//   domainRoutes
// );

// // 6. Branding & Customization (White-label support)
// app.use('/branding', 
//   requirePaidSubscription,
//   brandingRoutes
// );

// // 7. Integrations (Third-party connections) - with integration quotas
// app.use('/integrations', 
//   enforceQuotas({ resource: 'integrations' }),
//   trackUsage({ resources: ['integration_calls'] }),
//   integrationRoutes
// );

// // 8. Audit Trails (Compliance and security)
// app.use('/audit', 
//   requirePaidSubscription,
//   auditRoutes
// );

// // 9. Data Migration (Import/Export) - with strict rate limiting
// app.use('/migrations', 
//   sensitiveOperationsRateLimiter,
//   enforceStorageQuotas,
//   trackUsage({ resources: ['migration_operations'] }),
//   migrationRoutes
// );

// // 10. Backup Management (Data protection)
// app.use('/backups', 
//   requirePaidSubscription,
//   sensitiveOperationsRateLimiter,
//   enforceStorageQuotas,
//   backupRoutes
// );

// // 11. Notifications (Organization-level notifications)
// app.use('/notifications', 
//   trackUsage({ resources: ['notification_sends'] }),
//   notificationRoutes
// );

// Module-specific error handling
app.use((err, req, res, next) => {
    // Log error with tenant context
    logger.error('Hosted Organizations module error', {
        error: err.message,
        stack: err.stack,
        type: err.type,
        tenantId: req.tenantId,
        organizationId: req.organizationId,
        path: req.path,
        method: req.method,
        userId: req.user?._id
    });

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
            upgradeUrl: '/billing/upgrade',
            subscription: err.subscription
        });
    }

    if (err.type === 'SubscriptionRequired') {
        return res.status(402).json({
            status: 'error',
            type: 'subscription_required',
            message: 'An active subscription is required to access this feature',
            code: 'SUB_REQUIRED',
            upgradeUrl: '/billing/upgrade'
        });
    }

    if (err.type === 'PlanUpgradeRequired') {
        return res.status(402).json({
            status: 'error',
            type: 'plan_upgrade_required',
            message: 'Your current plan does not include this feature',
            code: 'PLAN_UPGRADE_REQUIRED',
            upgradeUrl: '/billing/upgrade',
            subscription: err.subscription
        });
    }

    if (err.type === 'FeatureNotAvailable') {
        return res.status(403).json({
            status: 'error',
            type: 'feature_not_available',
            message: 'This feature is not available on your current plan',
            code: 'FEATURE_NOT_AVAILABLE',
            features: err.features,
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

    if (err.type === 'RateLimitExceeded') {
        return res.status(429).json({
            status: 'error',
            type: 'rate_limit_exceeded',
            message: err.message,
            code: 'RATE_LIMIT_EXCEEDED',
            rateLimit: err.rateLimit
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

    if (err.type === 'PaymentOverdue') {
        return res.status(402).json({
            status: 'error',
            type: 'payment_overdue',
            message: 'Your account has overdue payments',
            code: 'PAYMENT_OVERDUE',
            upgradeUrl: '/billing/payment'
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