/**
 * @file External APIs Module App
 * @description Express application for external API integrations and webhook management
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

// Module-specific CORS for external integrations
const corsOptions = {
    origin: function (origin, callback) {
        // Use configured trusted domains
        const trustedDomains = config.externalAPIs?.trustedDomains || [
            'https://api.stripe.com',
            'https://api.paypal.com',
            'https://slack.com',
            'https://api.github.com',
            'https://api.linkedin.com',
            'https://graph.microsoft.com',
            'https://www.googleapis.com',
            'https://api.zoom.us',
            'https://api.sendgrid.com',
            'https://api.twilio.com',
            /^https:\/\/.*\.salesforce\.com$/,
            /^https:\/\/.*\.hubspot\.com$/
        ];
        
        // Add any additional configured domains
        if (config.externalAPIs?.additionalDomains) {
            trustedDomains.push(...config.externalAPIs.additionalDomains);
        }
        
        // Allow requests from trusted domains or no origin (server-to-server)
        if (!origin || trustedDomains.some(domain => 
            domain instanceof RegExp ? domain.test(origin) : domain === origin
        )) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS policy'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Webhook-Signature', 'X-API-Key'],
    exposedHeaders: ['X-Rate-Limit-Remaining', 'X-Webhook-ID']
};

app.use(cors(corsOptions));
app.use(helmet({
    contentSecurityPolicy: config.externalAPIs?.webhooks ? false : config.security.contentSecurityPolicy
}));
app.use(compression());
app.use(mongoSanitize());

// Raw body parser for webhook signature verification
app.use('/webhooks/*', express.raw({ 
    type: 'application/json', 
    limit: config.externalAPIs?.webhookLimit || '10mb' 
}));

// JSON parser for other routes
app.use(express.json({ limit: config.externalAPIs?.requestLimit || '5mb' }));
app.use(express.urlencoded({ extended: true, limit: config.externalAPIs?.requestLimit || '5mb' }));

// Import route modules
const webhookRoutes = require('./webhooks/routes/webhook-routes');
const oauthRoutes = require('./oauth/routes/oauth-routes');
const paymentGatewayRoutes = require('./payment-gateways/routes/payment-gateway-routes');
const emailServiceRoutes = require('./email-services/routes/email-service-routes');
const smsServiceRoutes = require('./sms-services/routes/sms-service-routes');
const storageServiceRoutes = require('./storage-services/routes/storage-service-routes');
const calendarIntegrationRoutes = require('./calendar/routes/calendar-integration-routes');
const crmIntegrationRoutes = require('./crm/routes/crm-integration-routes');
const socialMediaRoutes = require('./social-media/routes/social-media-routes');
const analyticsIntegrationRoutes = require('./analytics/routes/analytics-integration-routes');
const aiServiceRoutes = require('./ai-services/routes/ai-service-routes');
const mapServiceRoutes = require('./map-services/routes/map-service-routes');
const videoConferenceRoutes = require('./video-conference/routes/video-conference-routes');
const documentSigningRoutes = require('./document-signing/routes/document-signing-routes');

// External API specific middleware
const { verifyWebhookSignature } = require('./middleware/webhook-verification');
const { rateLimitByAPI } = require('./middleware/api-rate-limiting');
const { validateAPIKey } = require('./middleware/api-key-validation');
const { logAPIUsage } = require('./middleware/api-usage-logging');
const { handleAPIRetries } = require('./middleware/api-retry-handler');
const { cacheAPIResponses } = require('./middleware/api-response-cache');

// Health check with external service status
app.get('/health', async (req, res) => {
    const serviceStatuses = await checkExternalServices();
    res.status(200).json({
        status: 'healthy',
        module: 'external-apis',
        timestamp: new Date().toISOString(),
        environment: config.app.env,
        version: config.app.version,
        webhooksEnabled: config.externalAPIs?.webhooksEnabled !== false,
        services: serviceStatuses
    });
});

// Log module initialization
logger.info('External APIs module initialized', {
    environment: config.app.env,
    webhooksEnabled: config.externalAPIs?.webhooksEnabled,
    trustedDomainsCount: config.externalAPIs?.trustedDomains?.length || 12
});

/**
 * Webhook endpoints (no authentication, signature verification instead)
 */
app.use('/webhooks', verifyWebhookSignature, webhookRoutes);

/**
 * OAuth callback endpoints (special authentication flow)
 */
app.use('/oauth', oauthRoutes);

/**
 * Protected API integration endpoints
 * Ordered by criticality and usage frequency
 */

// Apply API key validation for all protected routes
app.use(validateAPIKey);

// 1. Payment Gateways (Critical for revenue)
app.use('/payment-gateways', rateLimitByAPI('payment', 100), paymentGatewayRoutes);

// 2. Email Services (Critical for communication)
app.use('/email-services', rateLimitByAPI('email', 1000), emailServiceRoutes);

// 3. SMS Services (Important for notifications)
app.use('/sms-services', rateLimitByAPI('sms', 500), smsServiceRoutes);

// 4. CRM Integrations (Important for sales)
app.use('/crm', rateLimitByAPI('crm', 500), cacheAPIResponses(300), crmIntegrationRoutes);

// 5. Calendar Integrations (Scheduling)
app.use('/calendar', rateLimitByAPI('calendar', 300), calendarIntegrationRoutes);

// 6. Document Signing (Legal compliance)
app.use('/document-signing', rateLimitByAPI('signing', 100), documentSigningRoutes);

// 7. Video Conference (Remote collaboration)
app.use('/video-conference', rateLimitByAPI('video', 200), videoConferenceRoutes);

// 8. Storage Services (File management)
app.use('/storage', rateLimitByAPI('storage', 500), storageServiceRoutes);

// 9. AI Services (Enhanced features)
app.use('/ai-services', rateLimitByAPI('ai', 100), aiServiceRoutes);

// 10. Analytics Integrations (Business intelligence)
app.use('/analytics', rateLimitByAPI('analytics', 200), cacheAPIResponses(600), analyticsIntegrationRoutes);

// 11. Social Media (Marketing)
app.use('/social-media', rateLimitByAPI('social', 300), socialMediaRoutes);

// 12. Map Services (Location features)
app.use('/maps', rateLimitByAPI('maps', 500), cacheAPIResponses(3600), mapServiceRoutes);

// Apply usage logging and retry handling
app.use(logAPIUsage);
app.use(handleAPIRetries);

// Module-specific error handling
app.use((err, req, res, next) => {
    if (err.type === 'WebhookVerificationFailed') {
        return res.status(401).json({
            status: 'error',
            type: 'webhook_verification_failed',
            message: 'Invalid webhook signature',
            code: 'INVALID_SIGNATURE'
        });
    }
    
    if (err.type === 'APIKeyInvalid') {
        return res.status(401).json({
            status: 'error',
            type: 'api_key_invalid',
            message: 'Invalid or missing API key',
            code: 'INVALID_API_KEY'
        });
    }
    
    if (err.type === 'ExternalAPIError') {
        return res.status(502).json({
            status: 'error',
            type: 'external_api_error',
            message: 'External service error',
            code: 'EXTERNAL_ERROR',
            service: err.service,
            originalError: process.env.NODE_ENV === 'development' ? err.originalError : undefined
        });
    }
    
    if (err.type === 'RateLimitExceeded') {
        return res.status(429).json({
            status: 'error',
            type: 'rate_limit_exceeded',
            message: 'API rate limit exceeded',
            code: 'RATE_LIMIT',
            service: err.service,
            limit: err.limit,
            resetAt: err.resetAt
        });
    }
    
    if (err.type === 'OAuthFlowError') {
        return res.status(400).json({
            status: 'error',
            type: 'oauth_flow_error',
            message: 'OAuth authentication flow failed',
            code: 'OAUTH_ERROR',
            provider: err.provider
        });
    }
    
    next(err);
});

// 404 handler for this module
app.use('*', (req, res) => {
    res.status(404).json({
        status: 'error',
        module: 'external-apis',
        message: `External API route ${req.originalUrl} not found`,
        availableEndpoints: [
            '/webhooks',
            '/oauth',
            '/payment-gateways',
            '/email-services',
            '/sms-services',
            '/crm',
            '/calendar',
            '/document-signing',
            '/video-conference',
            '/storage',
            '/ai-services',
            '/analytics',
            '/social-media',
            '/maps'
        ]
    });
});

// Helper function to check external service status
async function checkExternalServices() {
    // This would be implemented to actually check service health
    return {
        stripe: 'operational',
        sendgrid: 'operational',
        twilio: 'operational',
        aws_s3: 'operational',
        google_calendar: 'operational',
        salesforce: 'operational',
        zoom: 'operational',
        docusign: 'operational',
        openai: 'operational'
    };
}

module.exports = app;