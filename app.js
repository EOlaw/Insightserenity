/**
 * @file Application Setup
 * @description Express application configuration and setup
 * @version 3.0.0
 */
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const passport = require('passport');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const flash = require('express-flash');
const methodOverride = require('method-override');
const mongoSanitize = require('express-mongo-sanitize');

// Core imports from shared folder
const config = require('./server/shared/config/config');
const logger = require('./server/shared/utils/logger');
const SessionManager = require('./server/shared/security/session-manager');
const Database = require('./server/shared/config/database');
const { AppError } = require('./server/shared/utils/app-error');

// Import the production-grade authentication strategy manager
const AuthStrategiesManager = require('./shared/security/passport/strategies/auth-strategy-index');

// Import routes
const docsRoute = require('./modules/documentation/docs-route');
const authRoutes = require('./modules/auth/routes/auth-routes');
const userRoutes = require('./modules/users/routes/user-routes');
const teamRoutes = require('./modules/teams/routes/team-routes');
const departmentRoutes = require('./modules/departments/routes/department-routes');
const organizationRoutes = require('./modules/organizations/routes/organization-routes');
const projectRoutes = require('./modules/projects/routes/project-routes');
const caseStudyRoutes = require('./modules/case-studies/routes/case-study-routes');
const newsletterRoutes = require('./modules/newsletter/routes/newsletter-routes');
const blogRoutes = require('./modules/blog/routes/blog-routes');
const eventRoutes = require('./modules/events/routes/event-routes');
const serviceRoutes = require('./modules/services/routes/service-routes');
const contactFormRoutes = require('./modules/marketing/routes/contact-form-routes');

// Middleware imports
const errorHandler = require('./shared/middleware/error-handler');
const notFoundHandler = require('./shared/middleware/not-found-handler');

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
        await this.setupAuthentication();
        this.setupRoutes();
        this.setupErrorHandling();
    }

    /**
     * Setup authentication strategies
     */
    async setupAuthentication() {
        try {
            // Initialize authentication strategies with session support based on config
            await this.authManager.initialize(this.app, {
                enableSessions: config.security.session.enabled
            });
            
            logger.info('Authentication strategies initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize authentication', { error });
            throw error;
        }

        // Make user available in views
        this.app.use((req, res, next) => {
            res.locals.user = req.user;
            res.locals.isAuthenticated = req.isAuthenticated();
            next();
        });

        // Note: Serialization is already handled in AuthStrategies.initialize()
    }

    /**
     * Setup application middleware
     * @returns {void}
     * @description Configures middleware for security, logging, parsing, and more
     */
    setupMiddleware() {
        // Trust proxy for production deployments
        if (config.app.env === 'production') {
            this.app.set('trust proxy', 1);
        }

        // Secure HTTP headers with Helmet
        if (config.security.helmet.enabled) {
            this.app.use(helmet({
                contentSecurityPolicy: config.app.env === 'production' ? undefined : false,
                crossOriginEmbedderPolicy: false,
                ...config.security.helmet
            }));
        }

        // Enhanced CORS configuration with detailed logging and debugging
        if (config.security.cors.enabled) {
            // Log the current CORS configuration for debugging
            logger.info('CORS Configuration Debug', {
                enabled: config.security.cors.enabled,
                origins: config.security.cors.origins,
                methods: config.security.cors.methods,
                allowCredentials: config.security.cors.allowCredentials,
                environment: config.app.env
            });

            this.app.use(cors({
                origin: (origin, callback) => {
                    // Allow requests with no origin (mobile apps, Postman, curl, etc.)
                    if (!origin) {
                        return callback(null, true);
                    }

                    // Ensure origins is an array
                    const allowedOrigins = Array.isArray(config.security.cors.origins) 
                        ? config.security.cors.origins 
                        : [config.security.cors.origins].filter(Boolean);

                    // Check if origin is in allowed list (with trimming for safety)
                    const trimmedAllowedOrigins = allowedOrigins.map(o => o.trim());
                    const trimmedIncomingOrigin = origin.trim();

                    if (trimmedAllowedOrigins.includes(trimmedIncomingOrigin)) {
                        return callback(null, true);
                    }

                    // Development environment fallback - be more permissive
                    if (config.app.env === 'development') {
                        // Allow localhost origins on any port for development
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

        // Body parsing middleware
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

        // Security middleware
        if (config.security.sanitize.enabled) {
            this.app.use(mongoSanitize({
                replaceWith: '_',
                onSanitize: ({ req, key }) => {
                    logger.warn(`Sanitized prohibited character in ${key}`);
                }
            }));
        }

        // Parse cookies
        this.app.use(cookieParser(config.security.cookieSecret));

        // Response compression
        this.app.use(compression({
            filter: (req, res) => {
                if (req.headers['x-no-compression']) {
                    return false;
                }
                return compression.filter(req, res);
            },
            level: 6
        }));

        // Method override for REST APIs
        this.app.use(methodOverride('_method'));
        this.app.use(methodOverride('X-HTTP-Method-Override'));

        // Static file serving
        this.app.use('/uploads', express.static(path.join(process.cwd(), 'uploads'), {
            maxAge: config.app.env === 'production' ? '7d' : 0,
            etag: true,
            lastModified: true
        }));
        this.app.use('/public', express.static(path.join(process.cwd(), 'public'), {
            maxAge: config.app.env === 'production' ? '30d' : 0
        }));

        // Session configuration
        if (config.security.session.enabled) {
            const sessionManager = new SessionManager();
            this.app.use(sessionManager.createSession());
        }

        // Request logging
        if (config.app.env !== 'test') {
            this.app.use(morgan(config.app.env === 'production' ? 'combined' : 'dev', {
                stream: { write: message => logger.info(message.trim()) }
            }));
        }

        // Flash messages
        this.app.use(flash());

        // Custom middleware for request tracking
        this.app.use((req, res, next) => {
            req.requestTime = new Date().toISOString();
            req.requestId = require('crypto').randomBytes(16).toString('hex');
            res.setHeader('X-Request-ID', req.requestId);
            next();
        });
    }

    /**
     * Setup application routes
     * @returns {void}
     * @description Configures all application routes with versioning
     */
    setupRoutes() {
        const apiPrefix = config.app.apiPrefix || '/api';
        const apiVersion = config.app.apiVersion || 'v1';
        const baseApiPath = `${apiPrefix}/${apiVersion}`;

        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.status(200).json({
                status: 'ok',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                environment: config.app.env,
                version: config.app.version
            });
        });

        // Documentation route
        this.app.use('/docs', docsRoute);

        // Create API router || Uncomment if you want to mount all routes under a single router
        // This is useful if you want to apply middleware or versioning at the router level
        // const apiRouter = express.Router();

        // API routes with versioning
        this.app.use(`${baseApiPath}/auth`, authRoutes);
        this.app.use(`${baseApiPath}/users`, userRoutes);
        this.app.use(`${baseApiPath}/teams`, teamRoutes);
        this.app.use(`${baseApiPath}/departments`, departmentRoutes);
        this.app.use(`${baseApiPath}/organizations`, organizationRoutes);
        this.app.use(`${baseApiPath}/projects`, projectRoutes);
        this.app.use(`${baseApiPath}/case-studies`, caseStudyRoutes);
        this.app.use(`${baseApiPath}/newsletter`, newsletterRoutes);
        this.app.use(`${baseApiPath}/blog`, blogRoutes);
        this.app.use(`${baseApiPath}/events`, eventRoutes);
        this.app.use(`${baseApiPath}/services`, serviceRoutes);
        this.app.use(`${baseApiPath}/contact`, contactFormRoutes);

        // Mount versioned API
        // this.app.use(`${apiPrefix}/${apiVersion}`, apiRouter);

        // Test routes for authentication (development only)
        if (config.app.env === 'development') {
            this.app.get('/test-auth', 
                this.authManager.authenticate('jwt', { session: false }), 
                (req, res) => {
                    res.json({ 
                        message: 'Authenticated!', 
                        user: req.user 
                    });
                }
            );
        }

        // Root route
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
                }
            });
        });

        // Handle undefined routes
        this.app.all('*', (req, res, next) => {
            next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
        });
    }

    /**
     * Setup error handling middleware
     * @returns {void}
     * @description Configures global error handling for the application
     */
    setupErrorHandling() {
        // 404 handler
        this.app.use(notFoundHandler);

        // Global error handler
        this.app.use(errorHandler);
    }

    /**
     * Start the application
     * @returns {Promise<Express.Application>}
     * @description Starts the Express application and connects to the database
     */
    async start() {
        try {
            // Connect to the database
            await Database.connect();
            logger.info('Database connected successfully');

            // Initialize the application
            await this.initialize();
            logger.info('Application initialized successfully');

            return this.app;
        } catch (error) {
            logger.error('Failed to start application', { error });
            throw error;
        }
    }

    /**
     * Get authentication manager instance
     * @returns {AuthStrategiesManager}
     */
    getAuthManager() {
        return this.authManager;
    }
}

// Create and export a singleton instance
const application = new Application();

module.exports = application;