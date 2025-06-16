// server/shared/database/database.js
/**
 * @file Database Configuration
 * @description MongoDB database configuration and connection management
 * @version 3.1.0
 */

const mongoose = require('mongoose');

const config = require('../config/config');
const logger = require('../utils/logger');

/**
 * Database Manager Class
 * @class DatabaseManager
 */
class DatabaseManager {
  constructor() {
    this.connections = new Map();
    this.isInitialized = false;
    this.isShuttingDown = false;
    this.url = config.database.uri;
    
    // Updated connection options compatible with current MongoDB driver
    this.options = {
      maxPoolSize: parseInt(process.env.DB_POOL_SIZE, 10) || 10,
      serverSelectionTimeoutMS: parseInt(process.env.DB_TIMEOUT, 10) || 30000,
      socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT, 10) || 60000,
      heartbeatFrequencyMS: parseInt(process.env.DB_HEARTBEAT_FREQUENCY, 10) || 30000,
      maxIdleTimeMS: parseInt(process.env.DB_MAX_IDLE_TIME, 10) || 30000,
      family: 4 // Use IPv4, skip trying IPv6
    };
    
    // Multi-tenant database configuration
    this.multiTenant = {
      enabled: process.env.ENABLE_MULTI_TENANT_DB === 'true',
      strategy: process.env.TENANT_DB_STRATEGY || 'shared',
      prefix: process.env.TENANT_DB_PREFIX || 'tenant_'
    };
    
    // Database names for different segments
    this.databases = {
      main: process.env.MAIN_DB_NAME || 'insightserenity',
      recruitment: process.env.RECRUITMENT_DB_NAME || 'insightserenity_recruitment',
      analytics: process.env.ANALYTICS_DB_NAME || 'insightserenity_analytics'
    };
    
    // Connection retry configuration
    this.retry = {
      maxAttempts: parseInt(process.env.DB_RETRY_ATTEMPTS, 10) || 3,
      interval: parseInt(process.env.DB_RETRY_INTERVAL, 10) || 2000,
      backoffMultiplier: parseFloat(process.env.DB_RETRY_BACKOFF, 10) || 1.5
    };
    
    // Performance monitoring
    this.performance = {
      slowQueryThreshold: parseInt(process.env.DB_SLOW_QUERY_MS, 10) || 1000,
      explainEnabled: process.env.DB_EXPLAIN_ENABLED === 'true',
      profilingLevel: parseInt(process.env.DB_PROFILING_LEVEL, 10) || 0
    };
    
    // Track connection state
    this.connectionState = {
      isConnected: false,
      lastConnectionTime: null,
      connectionAttempts: 0,
      lastError: null
    };
  }
  
  /**
   * Initialize database connection
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.isInitialized) {
      return;
    }
    
    try {
      await this.connect();
      this.setupGlobalHandlers();
      this.isInitialized = true;
      
      logger.info('Database manager initialized successfully');
    } catch (error) {
      logger.error('Database initialization failed', { 
        error: error.message,
        attempts: this.connectionState.connectionAttempts 
      });
      throw error;
    }
  }
  
  /**
   * Connect to MongoDB with retry logic
   * @param {string} dbName - Database name
   * @returns {Promise<mongoose.Connection>}
   */
  async connect(dbName = null) {
    const connectionKey = dbName || 'main';
    
    if (this.connections.has(connectionKey)) {
      const existingConnection = this.connections.get(connectionKey);
      if (existingConnection.readyState === 1) {
        return existingConnection;
      }
    }
    
    const connectionString = this.getConnectionString(dbName);
    let attempts = 0;
    let lastError;
    
    while (attempts < this.retry.maxAttempts) {
      try {
        this.connectionState.connectionAttempts++;
        attempts++;
        
        logger.info(`Attempting database connection (${attempts}/${this.retry.maxAttempts})`);
        
        const connection = await mongoose.createConnection(connectionString, this.options);
        
        // Set up connection event handlers
        this.setupConnectionHandlers(connection, connectionKey);
        
        // Store connection
        this.connections.set(connectionKey, connection);
        
        this.connectionState.isConnected = true;
        this.connectionState.lastConnectionTime = new Date();
        this.connectionState.lastError = null;
        
        logger.info(`Database connected successfully: ${connectionKey}`);
        
        return connection;
      } catch (error) {
        lastError = error;
        this.connectionState.lastError = error.message;
        
        logger.warn(`Database connection attempt ${attempts} failed`, {
          error: error.message,
          connectionKey,
          attemptsRemaining: this.retry.maxAttempts - attempts
        });
        
        if (attempts < this.retry.maxAttempts) {
          const delay = this.retry.interval * Math.pow(this.retry.backoffMultiplier, attempts - 1);
          logger.info(`Retrying database connection in ${delay}ms`);
          await this.sleep(delay);
        }
      }
    }
    
    this.connectionState.isConnected = false;
    throw new Error(`Failed to connect to database after ${attempts} attempts: ${lastError.message}`);
  }
  
  /**
   * Get connection string for specific database
   * @param {string} dbName - Database name
   * @returns {string} Connection string
   */
  getConnectionString(dbName = null) {
    if (!dbName) {
      return this.url;
    }
    
    try {
      const url = new URL(this.url);
      const pathParts = url.pathname.split('/');
      pathParts[pathParts.length - 1] = dbName;
      url.pathname = pathParts.join('/');
      return url.toString();
    } catch (error) {
      logger.error('Error building connection string', { error: error.message, dbName });
      return this.url;
    }
  }
  
  /**
   * Set up connection event handlers
   * @param {mongoose.Connection} connection - Mongoose connection
   * @param {string} connectionKey - Connection identifier
   */
  setupConnectionHandlers(connection, connectionKey) {
    connection.on('connected', () => {
      console.log(`✓ Database connected: ${connectionKey}`);
      this.connectionState.isConnected = true;
      this.connectionState.lastConnectionTime = new Date();
    });
    
    connection.on('error', (error) => {
      console.error(`✗ Database error (${connectionKey}):`, error.message);
      this.connectionState.lastError = error.message;
      
      // Log detailed error for debugging
      logger.error('Database connection error', {
        connectionKey,
        error: error.message,
        errorCode: error.code,
        stack: error.stack
      });
    });
    
    connection.on('disconnected', () => {
      console.log(`✗ Database disconnected: ${connectionKey}`);
      this.connectionState.isConnected = false;
      
      // Attempt to reconnect if not shutting down
      if (!this.isShuttingDown) {
        logger.warn('Database disconnected, attempting to reconnect', { connectionKey });
        setTimeout(() => {
          this.reconnect(connectionKey);
        }, 5000);
      }
    });
    
    connection.on('reconnected', () => {
      console.log(`✓ Database reconnected: ${connectionKey}`);
      this.connectionState.isConnected = true;
      this.connectionState.lastConnectionTime = new Date();
    });
    
    connection.on('close', () => {
      console.log(`✓ Database connection closed: ${connectionKey}`);
      this.connections.delete(connectionKey);
    });
  }
  
  /**
   * Setup global MongoDB/Mongoose handlers
   */
  setupGlobalHandlers() {
    // Configure Mongoose settings (remove deprecated options)
    mongoose.set('strictQuery', true);
    
    // Only set debug if explicitly enabled
    if (process.env.DB_DEBUG === 'true') {
      mongoose.set('debug', true);
    }
    
    // Global error handler
    mongoose.connection.on('error', (error) => {
      logger.error('Global mongoose error', { error: error.message });
    });
    
    // Add performance monitoring if enabled
    if (this.performance.slowQueryThreshold > 0) {
      this.setupSlowQueryMonitoring();
    }
  }
  
  /**
   * Setup slow query monitoring
   */
  setupSlowQueryMonitoring() {
    const threshold = this.performance.slowQueryThreshold;
    
    mongoose.plugin(function slowQueryPlugin(schema) {
      schema.pre(/^find/, function() {
        this._startTime = Date.now();
      });
      
      schema.post(/^find/, function() {
        if (this._startTime) {
          const duration = Date.now() - this._startTime;
          if (duration > threshold) {
            logger.warn('Slow query detected', {
              collection: this.mongooseCollection.name,
              operation: this.op,
              duration,
              filter: this.getFilter()
            });
          }
        }
      });
    });
  }
  
  /**
   * Reconnect to database
   * @param {string} connectionKey - Connection identifier
   */
  async reconnect(connectionKey) {
    try {
      const existingConnection = this.connections.get(connectionKey);
      if (existingConnection) {
        await existingConnection.close();
      }
      
      await this.connect(connectionKey === 'main' ? null : connectionKey);
    } catch (error) {
      logger.error('Database reconnection failed', {
        connectionKey,
        error: error.message
      });
    }
  }
  
  /**
   * Get main database connection
   * @returns {mongoose.Connection}
   */
  getConnection(dbName = null) {
    const connectionKey = dbName || 'main';
    return this.connections.get(connectionKey);
  }
  
  /**
   * Get all active connections
   * @returns {Map}
   */
  getAllConnections() {
    return this.connections;
  }
  
  /**
   * Get connection health status
   * @returns {Object}
   */
  getHealthStatus() {
    const mainConnection = this.getConnection();
    const activeConnections = Array.from(this.connections.entries()).map(([key, conn]) => ({
      name: key,
      state: this.getReadyStateText(conn.readyState),
      host: conn.host,
      port: conn.port,
      dbName: conn.name
    }));
    
    return {
      isConnected: this.connectionState.isConnected,
      mainConnectionState: mainConnection ? this.getReadyStateText(mainConnection.readyState) : 'not_connected',
      lastConnectionTime: this.connectionState.lastConnectionTime,
      connectionAttempts: this.connectionState.connectionAttempts,
      lastError: this.connectionState.lastError,
      activeConnections,
      totalConnections: this.connections.size
    };
  }
  
  /**
   * Get readable connection state
   * @param {number} readyState - Mongoose connection ready state
   * @returns {string}
   */
  getReadyStateText(readyState) {
    const states = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting',
      4: 'invalid'
    };
    return states[readyState] || 'unknown';
  }
  
  /**
   * Close all database connections
   * @returns {Promise<void>}
   */
  async close() {
    this.isShuttingDown = true;
    
    try {
      logger.info('Closing database connections', { 
        totalConnections: this.connections.size 
      });
      
      const closePromises = Array.from(this.connections.entries()).map(async ([key, connection]) => {
        try {
          if (connection.readyState === 1) {
            await connection.close();
            logger.info(`Database connection closed: ${key}`);
          }
        } catch (error) {
          logger.error(`Error closing database connection: ${key}`, { 
            error: error.message 
          });
        }
      });
      
      await Promise.all(closePromises);
      
      this.connections.clear();
      this.connectionState.isConnected = false;
      this.isInitialized = false;
      
      logger.info('All database connections closed successfully');
    } catch (error) {
      logger.error('Error during database shutdown', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Sleep utility function
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<void>}
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  /**
   * Get tenant-specific database connection
   * @param {string} tenantId - Tenant identifier
   * @returns {Promise<mongoose.Connection>}
   */
  async getTenantConnection(tenantId) {
    if (!this.multiTenant.enabled) {
      throw new Error('Multi-tenant database is not enabled');
    }
    
    if (this.multiTenant.strategy === 'separate') {
      const dbName = `${this.multiTenant.prefix}${tenantId}`;
      return this.connect(dbName);
    }
    
    return this.getConnection();
  }
}

// Create and export singleton instance
const databaseManager = new DatabaseManager();

// Export both the instance and methods for compatibility
module.exports = databaseManager;
module.exports.DatabaseManager = DatabaseManager;

// Only initialize if not being required by another module during startup
process.nextTick(() => {
  if (!databaseManager.isInitialized) {
    databaseManager.initialize().catch((error) => {
      console.error('Database initialization failed:', error.message);
    });
  }
});