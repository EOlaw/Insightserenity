/**
 * @file Application Setup
 * @description Express application configuration and setup with multi-tenant database support
 * @version 3.0.0
 */
require('dotenv').config();

const path = require('path');

const compression = require('compression');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const express = require('express');
const flash = require('express-flash');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const methodOverride = require('method-override');
const morgan = require('morgan');
const passport = require('passport');

// Core imports from shared folder
const config = require('./server/shared/config/config');
const logger = require('./server/shared/utils/logger');
const SessionManager = require('./server/shared/security/session-manager');
const Database = require('./server/shared/database/database');
const { AppError } = require('./server/shared/utils/app-error');

// Import the production-grade authentication strategy manager
const AuthStrategiesManager = require('./server/shared/security/passport/strategies/auth-strategy-index');

// Import audit middleware and service
const { auditMiddleware } = require('./server/shared/audit/middleware/audit-middleware');
const AuditService = require('./server/shared/audit/services/audit-service');
const { AuditEventTypes } = require('./server/shared/audit/services/audit-event-types');

// Import routes
const authRoutes = require('./server/shared/auth/routes/auth-routes');
const userRoutes = require('./server/shared/users/routes/user-routes');
const organizationRoutes = require('./server/organization-tenants/routes/organization-tenant-routes');
const roleConversionRoutes = require('./server/shared/auth/routes/role-conversion-routes');

// Import domain apps
const coreBusiness = require('./server/core-business/app');
const hostedOrganizations = require('./server/hosted-organizations/app');

// Middleware imports
const errorHandler = require('./server/shared/middleware/error-handler');
const notFoundHandler = require('./server/shared/middleware/not-found-handler');

/**
 * Application class
 * Handle Express app setup, middleware, routes, error handling, and configuration
 */
class Application {
    constructor() {
        this.app = express();
        this.connections = new Set();
        this.isShuttingDown = false;
        this.authManager = new AuthStrategiesManager();
    }

    /**
     * Initialize the application
     */
    async initialize() {
        this.setupMiddleware();
        this.setupTenantMiddleware();
        await this.setupAuthentication();
        this.setupAuditMiddleware(); // Add audit middleware after authentication
        this.setupRoutes();
        this.setupErrorHandling();
    }

    /**
     * Setup authentication strategies
     */
    async setupAuthentication() {
        try {
            await this.authManager.initialize(this.app, {
                enableSessions: config.security.session.enabled
            });
            
            logger.info('Authentication strategies initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize authentication', { error });
            throw error;
        }

        this.app.use((req, res, next) => {
            res.locals.user = req.user;
            res.locals.isAuthenticated = req.isAuthenticated();
            next();
        });
    }

    /**
     * Setup audit middleware for automatic logging
     */
    setupAuditMiddleware() {
        // Configure audit middleware
        this.app.use(auditMiddleware({
            enabled: config.features?.auditLogs !== false, // Enable by default
            skipRoutes: [
                '/health',
                '/metrics',
                '/public',
                '/uploads',
                '/favicon.ico'
            ],
            sensitiveFields: [
                'password',
                'token',
                'secret',
                'key',
                'authorization',
                'cookie',
                'creditCard',
                'cvv',
                'ssn'
            ],
            includeRequestBody: config.app.env !== 'production', // Only in dev/staging
            includeResponseBody: false // Generally too verbose
        }));

        // Add audit context enrichment middleware
        this.app.use((req, res, next) => {
            // Enrich audit context with tenant information
            if (req.tenantId) {
                req.auditContext = {
                    ...req.auditContext,
                    tenantId: req.tenantId,
                    organizationId: req.user?.organizationId
                };
            }
            next();
        });

        logger.info('Audit middleware initialized', {
            enabled: config.features?.auditLogs !== false,
            environment: config.app.env
        });
    }

    /**
     * Setup tenant identification and context middleware
     */
    setupTenantMiddleware() {
        this.app.use(async (req, res, next) => {
            try {
                if (!Database.multiTenant.enabled) {
                    return next();
                }

                const tenantId = req.headers['x-tenant-id'] || 
                               req.query.tenantId || 
                               this.extractTenantFromDomain(req.hostname) ||
                               this.extractTenantFromSubdomain(req);
                
                if (tenantId) {
                    const tenantConnection = await Database.getTenantConnection(tenantId);
                    req.tenantId = tenantId;
                    req.tenantConnection = tenantConnection;
                    
                    logger.debug('Tenant context established', {
                        tenantId,
                        connectionState: Database.getReadyStateText(tenantConnection.readyState),
                        path: req.path,
                        method: req.method
                    });

                    res.setHeader('X-Tenant-ID', tenantId);
                }
                
                next();
            } catch (error) {
                logger.error('Tenant middleware error', {
                    error: error.message,
                    path: req.path,
                    method: req.method,
                    headers: {
                        'x-tenant-id': req.headers['x-tenant-id'],
                        host: req.headers.host
                    }
                });
                next(); // Continue without tenant context
            }
        });
    }

    /**
     * Extract tenant ID from domain hostname
     */
    extractTenantFromDomain(hostname) {
        if (!hostname || typeof hostname !== 'string') {
            return null;
        }

        const parts = hostname.split('.');
        if (parts.length > 2) {
            const subdomain = parts[0];
            if (subdomain && subdomain !== 'www' && subdomain !== 'api') {
                return subdomain.toLowerCase();
            }
        }
        return null;
    }

    /**
     * Extract tenant ID from subdomain
     */
    extractTenantFromSubdomain(req) {
        const host = req.get('host');
        if (!host) return null;

        const subdomain = host.split('.')[0];
        if (subdomain && subdomain !== 'www' && subdomain !== 'api' && subdomain !== 'localhost') {
            return subdomain.toLowerCase();
        }
        return null;
    }

    /**
     * Setup application middleware
     */
    setupMiddleware() {
        if (config.app.env === 'production') {
            this.app.set('trust proxy', 1);
        }

        if (config.security.helmet.enabled) {
            this.app.use(helmet({
                contentSecurityPolicy: config.app.env === 'production' ? undefined : false,
                crossOriginEmbedderPolicy: false,
                ...config.security.helmet
            }));
        }

        if (config.security.cors.enabled) {
            logger.info('CORS Configuration Debug', {
                enabled: config.security.cors.enabled,
                origins: config.security.cors.origins,
                methods: config.security.cors.methods,
                allowCredentials: config.security.cors.allowCredentials,
                environment: config.app.env
            });

            this.app.use(cors({
                origin: (origin, callback) => {
                    if (!origin) {
                        return callback(null, true);
                    }

                    const allowedOrigins = Array.isArray(config.security.cors.origins) 
                        ? config.security.cors.origins 
                        : [config.security.cors.origins].filter(Boolean);

                    const trimmedAllowedOrigins = allowedOrigins.map(o => o.trim());
                    const trimmedIncomingOrigin = origin.trim();

                    if (trimmedAllowedOrigins.includes(trimmedIncomingOrigin)) {
                        return callback(null, true);
                    }

                    if (config.app.env === 'development') {
                        const isLocalhost = /^https?:\/\/localhost(:\d+)?$/.test(trimmedIncomingOrigin) ||
                                        /^https?:\/\/127\.0\.0\.1(:\d+)?$/.test(trimmedIncomingOrigin) ||
                                        /^https?:\/\/10\.0\.0\.\d+(:\d+)?$/.test(trimmedIncomingOrigin);

                        if (isLocalhost) {
                            return callback(null, true);
                        }
                    }

                    callback(new Error('Not allowed by CORS'));
                },
                credentials: config.security.cors.allowCredentials,
                methods: config.security.cors.methods,
                allowedHeaders: config.security.cors.allowedHeaders,
                exposedHeaders: config.security.cors.exposedHeaders,
                maxAge: config.security.cors.maxAge,
                preflightContinue: config.security.cors.preflightContinue || false,
                optionsSuccessStatus: config.security.cors.optionsSuccessStatus || 204
            }));
        } else {
            logger.warn('CORS is disabled - this may cause issues with frontend communication');
        }

        this.app.use(express.json({ 
            limit: config.app.uploadLimit || '10mb',
            verify: (req, res, buf) => {
                req.rawBody = buf.toString('utf8');
            }
        }));
        this.app.use(express.urlencoded({ 
            extended: true, 
            limit: config.app.uploadLimit || '10mb' 
        }));

        if (config.security.sanitize.enabled) {
            this.app.use(mongoSanitize({
                replaceWith: '_',
                onSanitize: ({ req, key }) => {
                    logger.warn(`Sanitized prohibited character in ${key}`);
                }
            }));
        }

        this.app.use(cookieParser(config.security.cookieSecret));

        this.app.use(compression({
            filter: (req, res) => {
                if (req.headers['x-no-compression']) {
                    return false;
                }
                return compression.filter(req, res);
            },
            level: 6
        }));

        this.app.use(methodOverride('_method'));
        this.app.use(methodOverride('X-HTTP-Method-Override'));

        this.app.use('/uploads', express.static(path.join(process.cwd(), 'uploads'), {
            maxAge: config.app.env === 'production' ? '7d' : 0,
            etag: true,
            lastModified: true
        }));
        this.app.use('/public', express.static(path.join(process.cwd(), 'public'), {
            maxAge: config.app.env === 'production' ? '30d' : 0
        }));

        if (config.security.session.enabled) {
            const sessionManager = new SessionManager();
            this.app.use(sessionManager.getSessionMiddleware());
        }

        if (config.app.env !== 'test') {
            this.app.use(morgan(config.app.env === 'production' ? 'combined' : 'dev', {
                stream: { write: message => logger.info(message.trim()) }
            }));
        }

        this.app.use(flash());

        this.app.use((req, res, next) => {
            req.requestTime = new Date().toISOString();
            req.requestId = require('crypto').randomBytes(16).toString('hex');
            res.setHeader('X-Request-ID', req.requestId);
            next();
        });
    }

    /**
     * Setup application routes
     */
    setupRoutes() {
        const apiPrefix = config.app.apiPrefix || '/api';
        const apiVersion = config.app.apiVersion || 'v1';
        // const baseApiPath = `${apiPrefix}`; // Uncomment if you want to use the base path without versioning
        const baseApiPath = `${apiPrefix}/${apiVersion}`;

        // Health & Status Routes (Always first for monitoring)
        this.app.get('/health', (req, res) => {
            const dbHealth = Database.getHealthStatus();
            res.status(200).json({
                status: 'ok',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                environment: config.app.env,
                version: config.app.version,
                database: {
                    connected: dbHealth.isConnected,
                    totalConnections: dbHealth.totalConnections,
                    multiTenant: dbHealth.multiTenantEnabled,
                    strategy: dbHealth.strategy
                },
                tenant: req.tenantId || null
            });
        });

        // 2. Authentication Routes (Security first)
        this.app.use(`${baseApiPath}/auth`, authRoutes);
        // 3. User Management Routes (Core Identity)
        this.app.use(`${baseApiPath}/users`, userRoutes);
        // 4. Organization Management Routes (Tenant Management)
        this.app.use(`${baseApiPath}/organizations`, organizationRoutes);
        // 4.5 Role Conversion Routes (Prospect to Client, Admin Role Management)
        this.app.use(`${baseApiPath}/role-conversion`, roleConversionRoutes);
        // 5. Core Business Domain Routes
        this.app.use(`${baseApiPath}/core-business`, coreBusiness);
        // 6. Hosted Organizations Domain Routes
        this.app.use(`${baseApiPath}/hosted-organizations`, hostedOrganizations);
        // 7. Recruitment Services Domain Routes
        // this.app.use(`${baseApiPath}/recruitment-services`, recruitmentServices);
        // 8. External APIs Domain Routes
        // this.app.use(`${baseApiPath}/external-apis`, externalAPIs);

        // 9. Admin Routes (Platform administration - if exists)
        // if (adminRoutes) {
        //     this.app.use(`${baseApiPath}/admin`, adminRoutes);
        // }

        // // 10. Webhook Routes (External callbacks - if exists)
        // if (webhookRoutes) {
        //     this.app.use(`${baseApiPath}/webhooks`, webhookRoutes);
        // }

        // Development-only routes for testing authentication and tenant context
        if (config.app.env === 'development') {
            this.app.get('/test-auth', 
                this.authManager.authenticate('jwt', { session: false }), 
                (req, res) => {
                    res.json({ 
                        message: 'Authenticated!', 
                        user: req.user,
                        tenant: req.tenantId || null
                    });
                }
            );

            this.app.get('/test-tenant', (req, res) => {
                res.json({
                    tenantId: req.tenantId || null,
                    hasTenantConnection: !!req.tenantConnection,
                    multiTenantEnabled: Database.multiTenant.enabled,
                    strategy: Database.multiTenant.strategy,
                    extractedFromHost: this.extractTenantFromDomain(req.hostname)
                });
            });
        }

        this.app.get('/', (req, res) => {
            res.status(200).json({
                name: config.app.name || 'Consulting Platform API',
                description: 'Enterprise Consulting Platform API',
                version: config.app.version || '3.0.0',
                documentation: `${config.app.url}/docs`,
                status: 'operational',
                endpoints: {
                    health: '/health',
                    api: `${apiPrefix}/${apiVersion}`
                },
                multiTenant: {
                    enabled: Database.multiTenant.enabled,
                    strategy: Database.multiTenant.strategy
                },
                tenant: req.tenantId || null
            });
        });

        this.app.all('*', (req, res, next) => {
            next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
        });
    }

    /**
     * Setup error handling middleware
     */
    setupErrorHandling() {
        this.app.use(notFoundHandler);
        this.app.use(errorHandler.handle);
    }

    /**
     * Start the application
     */
    async start() {
        try {
            // Log system startup
            await AuditService.log({
                type: AuditEventTypes.SYSTEM_STARTUP,
                action: 'system_startup',
                category: 'system',
                systemGenerated: true,
                target: {
                    type: 'application',
                    id: config.app.name,
                    metadata: {
                        version: config.app.version,
                        environment: config.app.env,
                        nodeVersion: process.version,
                        platform: process.platform
                    }
                }
            });

            await Database.initialize();
            
            const dbHealth = Database.getHealthStatus();
            logger.info('Database manager initialized successfully', {
                multiTenantEnabled: dbHealth.multiTenantEnabled,
                strategy: dbHealth.strategy,
                totalConnections: dbHealth.totalConnections,
                activeConnections: dbHealth.activeConnections.length
            });

            await this.initialize();
            logger.info('Application initialized successfully');

            return this.app;
        } catch (error) {
            logger.error('Failed to start application', { error });
            
            // Log startup failure
            await AuditService.log({
                type: AuditEventTypes.SYSTEM_STARTUP,
                action: 'system_startup',
                category: 'system',
                result: 'failure',
                severity: 'critical',
                systemGenerated: true,
                target: {
                    type: 'application',
                    id: config.app.name
                },
                error: {
                    message: error.message,
                    stack: error.stack
                }
            });
            
            throw error;
        }
    }

    /**
     * Stop the application
     */
    async stop() {
        try {
            logger.info('Stopping application...');
            this.isShuttingDown = true;
            
            // Log system shutdown
            await AuditService.log({
                type: AuditEventTypes.SYSTEM_SHUTDOWN,
                action: 'system_shutdown',
                category: 'system',
                systemGenerated: true,
                target: {
                    type: 'application',
                    id: config.app.name,
                    metadata: {
                        uptime: process.uptime(),
                        gracefulShutdown: true
                    }
                }
            });
            
            // Flush any remaining audit logs
            await AuditService.flush();
            
            logger.info('Application stopped successfully');
        } catch (error) {
            logger.error('Error stopping application', { error });
            throw error;
        }
    }

    /**
     * Get authentication manager instance
     */
    getAuthManager() {
        return this.authManager;
    }
}

const application = new Application();

module.exports = application;