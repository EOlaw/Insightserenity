/**
 * @file Database Configuration - Multi-Tenant Support with Connection Fix
 * @description MongoDB database configuration supporting both single and multi-tenant architectures
 * @version 3.1.1 - Fixed connection stability issues
 */

const mongoose = require('mongoose');

const config = require('../config/config');
const logger = require('../utils/logger');

/**
 * Database Manager Class - Multi-tenant with proper model binding and connection stability
 * @class DatabaseManager
 */
class DatabaseManager {
  constructor() {
    this.connections = new Map();
    this.models = new Map();
    this.connectionStates = new Map(); // Track per-connection state
    this.reconnectionTimeouts = new Map(); // Track active reconnection timeouts
    this.isInitialized = false;
    this.isShuttingDown = false;
    this.url = config.database.uri;
    
    // Improved connection options for stability during idle periods
    this.options = {
      maxPoolSize: parseInt(process.env.DB_POOL_SIZE, 10) || 10,
      minPoolSize: 2, // Maintain minimum connections
      serverSelectionTimeoutMS: parseInt(process.env.DB_TIMEOUT, 10) || 30000,
      socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT, 10) || 45000,
      heartbeatFrequencyMS: parseInt(process.env.DB_HEARTBEAT_FREQUENCY, 10) || 10000, // More frequent heartbeats
      maxIdleTimeMS: parseInt(process.env.DB_MAX_IDLE_TIME, 10) || 300000, // 5 minutes instead of 30 seconds
      family: 4,
      // Connection pool settings
      maxConnecting: 2,
      directConnection: false,
      // Retry settings
      retryWrites: true,
      retryReads: true,
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
    
    // Global connection state
    this.globalConnectionState = {
      isConnected: false,
      lastConnectionTime: null,
      connectionAttempts: 0,
      lastError: null
    };
  }

  /**
   * Initialize connection state tracking for a specific connection
   * @param {string} connectionKey - Connection identifier
   */
  initializeConnectionState(connectionKey) {
    if (!this.connectionStates.has(connectionKey)) {
      this.connectionStates.set(connectionKey, {
        isConnected: false,
        isConnecting: false,
        lastConnectionTime: null,
        connectionAttempts: 0,
        lastError: null,
        reconnectionInProgress: false
      });
    }
  }

  /**
   * Clean up event handlers from an existing connection
   * @param {mongoose.Connection} connection - Mongoose connection
   * @param {string} connectionKey - Connection identifier
   */
  cleanupConnectionHandlers(connection, connectionKey) {
    if (!connection) return;
    
    try {
      // Remove all listeners to prevent memory leaks
      connection.removeAllListeners('connected');
      connection.removeAllListeners('error');
      connection.removeAllListeners('disconnected');
      connection.removeAllListeners('reconnected');
      connection.removeAllListeners('close');
      
      // Increase max listeners to prevent warnings
      connection.setMaxListeners(20);
      
      logger.debug(`Cleaned up event handlers for connection: ${connectionKey}`);
    } catch (error) {
      logger.warn(`Error cleaning up connection handlers for ${connectionKey}`, { 
        error: error.message 
      });
    }
  }

  /**
   * Set up connection event handlers with proper cleanup
   * @param {mongoose.Connection} connection - Mongoose connection
   * @param {string} connectionKey - Connection identifier
   */
  setupConnectionHandlers(connection, connectionKey) {
    // First clean up any existing handlers
    this.cleanupConnectionHandlers(connection, connectionKey);
    
    // Initialize connection state
    this.initializeConnectionState(connectionKey);
    const state = this.connectionStates.get(connectionKey);

    connection.on('connected', () => {
      console.log(`✓ Database connected: ${connectionKey}`);
      state.isConnected = true;
      state.isConnecting = false;
      state.lastConnectionTime = new Date();
      state.reconnectionInProgress = false;
      this.globalConnectionState.isConnected = true;
      this.globalConnectionState.lastConnectionTime = new Date();
      
      // Clear any pending reconnection timeout
      if (this.reconnectionTimeouts.has(connectionKey)) {
        clearTimeout(this.reconnectionTimeouts.get(connectionKey));
        this.reconnectionTimeouts.delete(connectionKey);
      }
    });
    
    connection.on('error', (error) => {
      console.error(`✗ Database error (${connectionKey}):`, error.message);
      state.lastError = error.message;
      this.globalConnectionState.lastError = error.message;
      
      logger.error('Database connection error', {
        connectionKey,
        error: error.message,
        errorCode: error.code,
        stack: error.stack
      });
    });
    
    connection.on('disconnected', () => {
      console.log(`✗ Database disconnected: ${connectionKey}`);
      state.isConnected = false;
      this.updateGlobalConnectionState();
      
      if (!this.isShuttingDown && !state.reconnectionInProgress) {
        logger.warn('Database disconnected, attempting to reconnect', { connectionKey });
        state.reconnectionInProgress = true;
        
        // Use exponential backoff for reconnection attempts
        const delay = Math.min(5000 * Math.pow(2, state.connectionAttempts), 30000);
        
        const timeoutId = setTimeout(() => {
          this.reconnect(connectionKey);
        }, delay);
        
        this.reconnectionTimeouts.set(connectionKey, timeoutId);
      }
    });
    
    connection.on('reconnected', () => {
      console.log(`✓ Database reconnected: ${connectionKey}`);
      state.isConnected = true;
      state.isConnecting = false;
      state.lastConnectionTime = new Date();
      state.reconnectionInProgress = false;
      state.connectionAttempts = 0; // Reset attempt counter on successful reconnection
      this.globalConnectionState.isConnected = true;
      this.globalConnectionState.lastConnectionTime = new Date();
    });
    
    connection.on('close', () => {
      console.log(`✓ Database connection closed: ${connectionKey}`);
      state.isConnected = false;
      state.isConnecting = false;
      state.reconnectionInProgress = false;
      
      // Clear reconnection timeout if exists
      if (this.reconnectionTimeouts.has(connectionKey)) {
        clearTimeout(this.reconnectionTimeouts.get(connectionKey));
        this.reconnectionTimeouts.delete(connectionKey);
      }
      
      this.connections.delete(connectionKey);
      
      // Clean up associated models
      const modelsToDelete = [];
      for (const [modelKey] of this.models) {
        if (modelKey.startsWith(`${connectionKey}:`)) {
          modelsToDelete.push(modelKey);
        }
      }
      modelsToDelete.forEach(key => this.models.delete(key));
      
      this.updateGlobalConnectionState();
    });
  }

  /**
   * Update global connection state based on individual connection states
   */
  updateGlobalConnectionState() {
    const states = Array.from(this.connectionStates.values());
    this.globalConnectionState.isConnected = states.some(state => state.isConnected);
  }
  
  /**
   * Setup global MongoDB/Mongoose handlers
   */
  setupGlobalHandlers() {
    mongoose.set('strictQuery', true);
    
    // Increase max listeners globally to prevent warnings
    mongoose.connection.setMaxListeners(25);
    
    if (process.env.DB_DEBUG === 'true') {
      mongoose.set('debug', true);
    }
    
    mongoose.connection.on('error', (error) => {
      logger.error('Global mongoose error', { error: error.message });
    });
    
    // Handle process termination gracefully
    process.on('SIGINT', () => this.handleGracefulShutdown());
    process.on('SIGTERM', () => this.handleGracefulShutdown());
    
    if (this.performance.slowQueryThreshold > 0) {
      this.setupSlowQueryMonitoring();
    }
  }

  /**
   * Handle graceful shutdown
   */
  async handleGracefulShutdown() {
    logger.info('Received termination signal, starting graceful shutdown');
    await this.close();
    process.exit(0);
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
   * Initialize database connection
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.isInitialized) {
      return;
    }
    
    try {
      // Initialize main connection first
      await this.connect();
      this.setupGlobalHandlers();
      
      // Initialize additional databases if multi-tenant is enabled
      if (this.multiTenant.enabled && this.multiTenant.strategy === 'separate') {
        await this.initializeAdditionalDatabases();
      }
      
      this.isInitialized = true;
      logger.info('Database manager initialized successfully');
    } catch (error) {
      logger.error('Database initialization failed', { 
        error: error.message,
        attempts: this.globalConnectionState.connectionAttempts 
      });
      throw error;
    }
  }
  
  /**
   * Connect to MongoDB with proper model binding
   * @param {string} dbName - Database name
   * @returns {Promise<mongoose.Connection>}
   */
  async connect(dbName = null) {
    const connectionKey = dbName || 'main';
    
    // Initialize connection state
    this.initializeConnectionState(connectionKey);
    const state = this.connectionStates.get(connectionKey);
    
    // Check if connection already exists and is active
    if (this.connections.has(connectionKey)) {
      const existingConnection = this.connections.get(connectionKey);
      if (existingConnection.readyState === 1) {
        return existingConnection;
      }
    }
    
    // Check if connection attempt is already in progress
    if (state.isConnecting) {
      logger.debug(`Connection attempt already in progress for ${connectionKey}`);
      return new Promise((resolve, reject) => {
        const checkConnection = () => {
          const conn = this.connections.get(connectionKey);
          if (conn && conn.readyState === 1) {
            resolve(conn);
          } else if (!state.isConnecting) {
            reject(new Error(`Connection attempt failed for ${connectionKey}`));
          } else {
            setTimeout(checkConnection, 100);
          }
        };
        checkConnection();
      });
    }
    
    state.isConnecting = true;
    const connectionString = this.getConnectionString(dbName);
    let attempts = 0;
    let lastError;
    
    while (attempts < this.retry.maxAttempts) {
      try {
        state.connectionAttempts++;
        this.globalConnectionState.connectionAttempts++;
        attempts++;
        
        logger.info(`Attempting database connection (${attempts}/${this.retry.maxAttempts})`, {
          connectionKey,
          dbName: dbName || 'default'
        });
        
        let connection;
        
        if (connectionKey === 'main' && !dbName) {
          // For main connection, use default mongoose connection
          await mongoose.connect(connectionString, this.options);
          connection = mongoose.connection;
        } else {
          // For additional databases, create separate connections
          connection = await mongoose.createConnection(connectionString, this.options);
        }
        
        // Set up connection event handlers
        this.setupConnectionHandlers(connection, connectionKey);
        
        // Store connection
        this.connections.set(connectionKey, connection);
        
        state.isConnected = true;
        state.isConnecting = false;
        state.lastConnectionTime = new Date();
        state.lastError = null;
        state.reconnectionInProgress = false;
        
        this.globalConnectionState.isConnected = true;
        this.globalConnectionState.lastConnectionTime = new Date();
        this.globalConnectionState.lastError = null;
        
        logger.info(`Database connected successfully: ${connectionKey}`);
        
        return connection;
      } catch (error) {
        lastError = error;
        state.lastError = error.message;
        this.globalConnectionState.lastError = error.message;
        
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
    
    state.isConnecting = false;
    state.isConnected = false;
    this.updateGlobalConnectionState();
    throw new Error(`Failed to connect to database after ${attempts} attempts: ${lastError.message}`);
  }
  
  /**
   * Initialize additional databases for multi-tenant setup
   */
  async initializeAdditionalDatabases() {
    try {
      // Connect to predefined databases
      for (const [key, dbName] of Object.entries(this.databases)) {
        if (key !== 'main') {
          await this.connect(dbName);
        }
      }
      
      logger.info('Additional databases initialized for multi-tenant setup');
    } catch (error) {
      logger.error('Failed to initialize additional databases', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Get model for specific connection
   * @param {string} modelName - Name of the model
   * @param {mongoose.Schema} schema - Mongoose schema
   * @param {string} connectionKey - Connection identifier
   * @returns {mongoose.Model} Model bound to specific connection
   */
  getModel(modelName, schema, connectionKey = 'main') {
    const modelKey = `${connectionKey}:${modelName}`;
    
    if (this.models.has(modelKey)) {
      return this.models.get(modelKey);
    }
    
    const connection = this.connections.get(connectionKey);
    if (!connection) {
      throw new Error(`Connection ${connectionKey} not found`);
    }
    
    let model;
    if (connectionKey === 'main') {
      // For main connection, use default mongoose model
      model = mongoose.model(modelName, schema);
    } else {
      // For other connections, bind model to specific connection
      model = connection.model(modelName, schema);
    }
    
    this.models.set(modelKey, model);
    return model;
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
  
  /**
   * Reconnect to database
   * @param {string} connectionKey - Connection identifier
   */
  async reconnect(connectionKey) {
    const state = this.connectionStates.get(connectionKey);
    if (!state) {
      logger.error(`No state found for connection ${connectionKey}`);
      return;
    }
    
    if (state.reconnectionInProgress) {
      logger.debug(`Reconnection already in progress for ${connectionKey}`);
      return;
    }
    
    try {
      state.reconnectionInProgress = true;
      
      const existingConnection = this.connections.get(connectionKey);
      if (existingConnection) {
        this.cleanupConnectionHandlers(existingConnection, connectionKey);
        await existingConnection.close();
      }
      
      await this.connect(connectionKey === 'main' ? null : connectionKey);
    } catch (error) {
      logger.error('Database reconnection failed', {
        connectionKey,
        error: error.message
      });
      state.reconnectionInProgress = false;
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
      database: conn.name
    }));
    
    return {
      isConnected: this.globalConnectionState.isConnected,
      totalConnections: this.connections.size,
      multiTenantEnabled: this.multiTenant.enabled,
      strategy: this.multiTenant.strategy,
      activeConnections
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
        totalConnections: this.connections.size,
        activeConnections: this.connections.size,
        multiTenant: this.multiTenant.enabled
      });
      
      // Clear all reconnection timeouts
      for (const [key, timeoutId] of this.reconnectionTimeouts) {
        clearTimeout(timeoutId);
        logger.debug(`Cleared reconnection timeout for ${key}`);
      }
      this.reconnectionTimeouts.clear();
      
      const closePromises = Array.from(this.connections.entries()).map(async ([key, connection]) => {
        try {
          if (connection.readyState === 1) {
            this.cleanupConnectionHandlers(connection, key);
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
      this.models.clear();
      this.connectionStates.clear();
      this.globalConnectionState.isConnected = false;
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
}

// Create and export singleton instance
const databaseManager = new DatabaseManager();

module.exports = databaseManager;
module.exports.DatabaseManager = DatabaseManager;