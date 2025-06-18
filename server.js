/**
 * @file Server Configuration
 * @description Centralized server configuration and initialization with multi-tenant database support
 * @version 3.0.0
 */

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const app = require('./app');
const config = require('./server/shared/config/config');
const Database = require('./server/shared/database/database');
const logger = require('./server/shared/utils/logger');

/**
 * Server class to handle server initialization and management
 */
class Server {
    constructor() {
        this.server = null;
        this.isShuttingDown = false;
    }

    /**
     * Initialize and start the server
     * @returns {Promise<http.Server|https.Server>} The server instance
     * @throws {Error} If server initialization fails
     */
    async start() {
        try {
            const expressApp = await app.start();
            
            if (!expressApp) {
                throw new Error('Failed to initialize Express application');
            }

            const dbHealth = Database.getHealthStatus();
            logger.info('Database health status', {
                isConnected: dbHealth.isConnected,
                totalConnections: dbHealth.totalConnections,
                multiTenantEnabled: dbHealth.multiTenantEnabled,
                strategy: dbHealth.strategy,
                activeConnections: dbHealth.activeConnections.map(conn => ({
                    name: conn.name,
                    state: conn.state,
                    database: conn.dbName
                }))
            });

            logger.info('Application initialized successfully', { 
                appName: config.app.name,
                environment: config.app.env,
                databaseStrategy: dbHealth.multiTenantEnabled ? dbHealth.strategy : 'single',
                totalDatabaseConnections: dbHealth.totalConnections
            });

            if (config.security.ssl.enabled) {
                const sslVerified = this.verifySslCertificates();
                if (!sslVerified) {
                    logger.warn('SSL verification failed, falling back to HTTP');
                    config.security.ssl.enabled = false;
                }
            }

            if (config.app.env === 'production' && config.security.ssl.enabled) {
                this.server = this.createHttpsServer(expressApp);
            } else if (config.security.ssl.enabled) {
                this.server = this.createHttpsServer(expressApp);
            } else {
                this.server = this.createHttpServer(expressApp);
            }

            await this.listen();
            this.setupGracefulShutdown();
            this.setupErrorHandlers();

            return this.server;
        } catch (error) {
            logger.error('Failed to start server', { 
                error: error.message,
                stack: error.stack 
            });
            throw error;
        }
    }

    /**
     * Create HTTP server
     * @param {Express.Application} app - Express application
     * @returns {http.Server} HTTP server instance
     */
    createHttpServer(app) {
        return http.createServer(app);
    }

    /**
     * Create HTTPS server with enhanced error handling
     * @param {Express.Application} app - Express application
     * @returns {https.Server} HTTPS server instance
     */
    createHttpsServer(app) {
        try {
            const keyFileName = config.security.ssl.keyPath || 'localhost-key.pem';
            const certFileName = config.security.ssl.certPath || 'localhost.pem';
            
            let keyPath = path.resolve(process.cwd(), keyFileName);
            let certPath = path.resolve(process.cwd(), certFileName);
            
            if (!fs.existsSync(keyPath)) {
                keyPath = path.resolve(__dirname, keyFileName);
            }
            if (!fs.existsSync(certPath)) {
                certPath = path.resolve(__dirname, certFileName);
            }
            
            if (!fs.existsSync(keyPath)) {
                throw new Error(`SSL key file not found at: ${keyPath}`);
            }
            
            if (!fs.existsSync(certPath)) {
                throw new Error(`SSL certificate file not found at: ${certPath}`);
            }

            const sslOptions = {
                key: fs.readFileSync(keyPath),
                cert: fs.readFileSync(certPath)
            };

            if (config.security.ssl.ca) {
                const caPath = path.resolve(process.cwd(), config.security.ssl.ca);
                if (fs.existsSync(caPath)) {
                    sslOptions.ca = fs.readFileSync(caPath);
                }
            }

            logger.info('HTTPS server configured successfully', {
                keyPath: keyPath,
                certPath: certPath,
                hasCA: !!sslOptions.ca
            });

            return https.createServer(sslOptions, app);
        } catch (error) {
            logger.error('Failed to load SSL certificates', { 
                error: error.message,
                keyPath: config.security.ssl.keyPath,
                certPath: config.security.ssl.certPath
            });
            
            if (config.app.env === 'production') {
                throw error;
            }
            
            logger.warn('Falling back to HTTP server in development');
            return this.createHttpServer(app);
        }
    }

    /**
     * Verify SSL certificates exist before starting server
     */
    verifySslCertificates() {
        if (!config.security.ssl.enabled) {
            logger.info('SSL is disabled, skipping certificate verification');
            return true;
        }

        const keyFileName = config.security.ssl.keyPath || 'localhost-key.pem';
        const certFileName = config.security.ssl.certPath || 'localhost.pem';
        
        const keyPath = path.resolve(process.cwd(), keyFileName);
        const certPath = path.resolve(process.cwd(), certFileName);
        
        logger.info('Checking SSL certificates...', {
            keyPath: keyPath,
            certPath: certPath,
            workingDirectory: process.cwd()
        });
        
        const keyExists = fs.existsSync(keyPath);
        const certExists = fs.existsSync(certPath);
        
        if (!keyExists) {
            logger.error(`SSL key file not found: ${keyPath}`);
        }
        
        if (!certExists) {
            logger.error(`SSL certificate file not found: ${certPath}`);
        }
        
        if (keyExists && certExists) {
            logger.info('SSL certificates found and verified');
            return true;
        }
        
        return false;
    }

    /**
     * Start server listening
     * @returns {Promise<void>}
     */
    listen() {
        return new Promise((resolve, reject) => {
            const port = config.app.port || 5001;
            const host = config.app.host || '0.0.0.0';

            this.server.listen(port, host, () => {
                const protocol = this.server instanceof https.Server ? 'HTTPS' : 'HTTP';
                const dbHealth = Database.getHealthStatus();
                
                logger.info(`${config.app.name} server started`, {
                    protocol,
                    host,
                    port,
                    url: `${protocol.toLowerCase()}://${host}:${port}`,
                    environment: config.app.env,
                    nodeVersion: process.version,
                    multiTenant: {
                        enabled: dbHealth.multiTenantEnabled,
                        strategy: dbHealth.strategy,
                        connections: dbHealth.totalConnections
                    }
                });
                resolve();
            });

            this.server.on('error', (error) => {
                if (error.code === 'EADDRINUSE') {
                    logger.error(`Port ${port} is already in use`, { port });
                } else if (error.code === 'EACCES') {
                    logger.error(`Port ${port} requires elevated privileges`, { port });
                } else {
                    logger.error('Server error', { 
                        error: error.message,
                        code: error.code 
                    });
                }
                reject(error);
            });
        });
    }

    /**
     * Setup graceful shutdown handlers with multi-tenant database cleanup
     */
    setupGracefulShutdown() {
        const shutdown = async (signal) => {
            if (this.isShuttingDown) {
                logger.warn('Shutdown already in progress');
                return;
            }

            this.isShuttingDown = true;
            logger.info(`Received ${signal}, starting graceful shutdown`);

            try {
                await this.closeServer();

                const dbHealth = Database.getHealthStatus();
                logger.info('Closing database connections', {
                    totalConnections: dbHealth.totalConnections,
                    activeConnections: dbHealth.activeConnections.length,
                    multiTenant: dbHealth.multiTenantEnabled
                });
                
                await Database.close();

                if (app.stop) {
                    await app.stop();
                }

                logger.info('Graceful shutdown completed successfully', {
                    signal,
                    uptime: process.uptime(),
                    environment: config.app.env
                });
                process.exit(0);
            } catch (error) {
                logger.error('Error during shutdown', { 
                    error: error.message,
                    signal,
                    stack: error.stack
                });
                process.exit(1);
            }
        };

        process.on('SIGINT', () => shutdown('SIGINT'));
        process.on('SIGTERM', () => shutdown('SIGTERM'));

        if (process.platform === 'win32') {
            const readline = require('readline').createInterface({
                input: process.stdin,
                output: process.stdout
            });

            readline.on('SIGINT', () => {
                process.emit('SIGINT');
            });
        }
    }

    /**
     * Setup error handlers
     */
    setupErrorHandlers() {
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught Exception - System will exit', { 
                error: error.message,
                stack: error.stack,
                pid: process.pid
            });
            
            setTimeout(() => {
                process.exit(1);
            }, 1000);
        });

        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Promise Rejection', { 
                reason: reason instanceof Error ? reason.message : reason,
                stack: reason instanceof Error ? reason.stack : undefined,
                promise: promise.toString()
            });

            if (reason instanceof Error && reason.message.includes('database')) {
                logger.error('Database-related unhandled rejection detected', {
                    dbHealth: Database.getHealthStatus()
                });
            }
        });

        process.on('warning', (warning) => {
            if (warning.name === 'DeprecationWarning') {
                logger.warn('Deprecation Warning', { 
                    name: warning.name,
                    message: warning.message,
                    code: warning.code
                });
            } else {
                logger.warn('Process Warning', { 
                    name: warning.name,
                    message: warning.message,
                    stack: warning.stack 
                });
            }
        });

        process.on('SIGPIPE', () => {
            logger.warn('Received SIGPIPE - broken pipe detected');
        });
    }

    /**
     * Close the server
     * @returns {Promise<void>}
     */
    closeServer() {
        return new Promise((resolve, reject) => {
            if (!this.server) {
                resolve();
                return;
            }

            const timeout = setTimeout(() => {
                logger.error('Forceful server shutdown due to timeout');
                reject(new Error('Server close timeout'));
            }, 30000);

            this.server.close((error) => {
                clearTimeout(timeout);
                
                if (error) {
                    logger.error('Error closing server', { error: error.message });
                    reject(error);
                } else {
                    logger.info('HTTP/HTTPS server closed successfully');
                    resolve();
                }
            });

            if (this.server.connections) {
                this.server.connections.forEach((connection) => {
                    connection.destroy();
                });
            }
        });
    }

    /**
     * Get server health status
     * @returns {Object} Server and database health information
     */
    getHealthStatus() {
        const dbHealth = Database.getHealthStatus();
        
        return {
            server: {
                running: !!this.server,
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                environment: config.app.env,
                nodeVersion: process.version
            },
            database: dbHealth,
            timestamp: new Date().toISOString()
        };
    }
}

const server = new Server();

if (require.main === module) {
    server.start().catch((error) => {
        logger.error('Failed to start server', { 
            error: error.message,
            stack: error.stack 
        });
        process.exit(1);
    });
}

module.exports = server;