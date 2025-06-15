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
const config = require('./shared/config/config');
const logger = require('./shared/utils/logger');
const SessionManager = require('./shared/security/session-manager');
const Database = require('./shared/config/database');
const { AppError } = require('./shared/utils/app-error');

// Authentication strategy from shared/security/passport
const PassportConfig = require('./shared/security/passport/passport-config');

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
        this.passportConfig = new PassportConfig();
    }

    /**
     * Initialize the application
     */
    async initialize() {
        this.setupMiddleware();
        await this.setupPassport();
        this.setupRoutes();
        this.setupErrorHandling();
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
            maxAge: config.app.env === 'production' ? '30d' : 0,
            etag: true,
            lastModified: true
        }));

        // Request logging
        if (config.logging.enabled) {
            this.app.use(logger.httpLoggerMiddleware());
            
            if (config.app.env === 'development') {
                this.app.use(morgan('dev'));
            }
        }

        // Session management
        const sessionMiddleware = SessionManager.createSessionMiddleware({
            useDatabase: config.session.store === 'mongodb',
            secure: config.app.env === 'production'
        });
        this.app.use(sessionMiddleware);

        // Flash messages
        this.app.use(flash());
        
        // Make flash messages available to all views
        this.app.use((req, res, next) => {
            res.locals.success = req.flash('success');
            res.locals.error = req.flash('error');
            res.locals.info = req.flash('info');
            res.locals.warning = req.flash('warning');
            next();
        });

        // Session security middleware
        this.app.use(SessionManager.createSessionSecurityMiddleware());
        this.app.use(SessionManager.createSessionActivityMiddleware());
        
        // Idle timeout middleware
        if (config.session.idleTimeout) {
            this.app.use(SessionManager.createIdleSessionTimeoutMiddleware(
                config.session.idleTimeout / 60000 // Convert to minutes
            ));
        }

        // Track connections for graceful shutdown
        this.app.use((req, res, next) => {
            this.connections.add(res);
            res.on('finish', () => {
                this.connections.delete(res);
            });
            next();
        });
    }

    /**
     * Setup Passport authentication strategies
     * @returns {Promise<void>}
     * @description Initializes Passport strategies for authentication
     */
    async setupPassport() {
        try {
            // Initialize Passport with the application
            await this.passportConfig.initialize(this.app);
            logger.info('Authentication strategies initialized successfully');
        } catch (error) {
            logger.error('Failed to configure authentication strategies', {
                error: error.message
            });
            throw error;
        }

        // Make user available in views
        this.app.use((req, res, next) => {
            res.locals.user = req.user;
            res.locals.isAuthenticated = req.isAuthenticated();
            next();
        });
    }

    /**
     * Setup application routes
     * @returns {void}
     * @description Configures API routes for the application
     */
    setupRoutes() {
        // API version
        const apiVersion = config.app.apiVersion || 'v1';
        const apiPrefix = config.app.apiPrefix || '/api';

        // Create API router
        const apiRouter = express.Router();

        // Mount API routes
        // 1. Core Authentication & User Management
        apiRouter.use('/auth', authRoutes);
        apiRouter.use('/users', userRoutes);
        // 2. Organizational Structure
        apiRouter.use('/teams', teamRoutes);
        apiRouter.use('/departments', departmentRoutes);
        apiRouter.use('/organizations', organizationRoutes);
        apiRouter.use('/projects', projectRoutes);
        // 3. Services & Offerings
        apiRouter.use('/services', serviceRoutes);
        apiRouter.use('/events', eventRoutes);
        apiRouter.use('/case-studies', caseStudyRoutes);
        // 4. Marketing & Content Management
        apiRouter.use('/blog', blogRoutes);
        apiRouter.use('/newsletter', newsletterRoutes);
        // 5. Contact/Communication & Feedback
        apiRouter.use('/contact', contactFormRoutes);

        // Mount versioned API
        this.app.use(`${apiPrefix}/${apiVersion}`, apiRouter);

        // Documentation route (accessible at /docs)
        this.app.use('/docs', docsRoute);

        // Health check endpoint
        this.app.get('/health', (req, res) => {
            const dbStatus = Database.getStatus();
            const memoryUsage = process.memoryUsage();
            
            res.status(dbStatus.ready ? 200 : 503).json({
                status: dbStatus.ready ? 'healthy' : 'unhealthy',
                timestamp: new Date().toISOString(),
                service: {
                    name: config.app.name,
                    version: config.app.version || '3.0.0',
                    environment: config.app.env,
                    uptime: process.uptime()
                },
                database: {
                    status: dbStatus.status,
                    ready: dbStatus.ready,
                    message: dbStatus.message
                },
                memory: {
                    rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
                    heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
                    heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`
                }
            });
        });

        // Session check endpoint
        this.app.get('/session-check', (req, res) => {
            res.json({
                isAuthenticated: req.isAuthenticated(),
                session: {
                    id: req.sessionID,
                    cookie: req.session.cookie
                },
                user: req.user ? {
                    id: req.user._id || req.user.id,
                    email: req.user.email,
                    name: req.user.fullName || req.user.name || 'N/A',
                    role: req.user.role
                } : null
            });
        });

        // Session debug endpoint (development only)
        if (config.app.env === 'development') {
            this.app.get('/session-debug', (req, res) => {
                res.json({
                    authenticated: req.isAuthenticated(),
                    session: req.session,
                    sessionID: req.sessionID,
                    cookies: req.cookies,
                    signedCookies: req.signedCookies,
                    user: req.user
                });
            });
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
            logger.error('Failed to start application', {
                error: error.message,
                stack: error.stack
            });
            throw error;
        }
    }

    /**
     * Stop the application gracefully
     * @returns {Promise<void>}
     */
    async stop() {
        if (this.isShuttingDown) {
            logger.warn('Application is already shutting down');
            return;
        }

        this.isShuttingDown = true;
        logger.info('Stopping application gracefully');

        try {
            // Close all active connections
            for (const connection of this.connections) {
                connection.end();
            }

            // Close database connection
            await Database.close();
            logger.info('Database connection closed');

            // Cleanup any other resources
            logger.info('Application stopped successfully');
        } catch (error) {
            logger.error('Error during application shutdown', {
                error: error.message
            });
            throw error;
        }
    }
}

// Create and export application instance
module.exports = new Application();