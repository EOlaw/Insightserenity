// server/shared/config/database.js
// Project: Insight Serenity - Database Configuration
/**
 * @file Database Configuration
 * @description MongoDB database configuration and connection settings
 * @version 3.0.0
 */

const mongoose = require('mongoose');

/**
 * Database Configuration Class
 * @class DatabaseConfig
 */
class DatabaseConfig {
  constructor() {
    this.url = process.env.MONGODB_URI || 'mongodb://localhost:27017/insightserenity';
    this.options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: parseInt(process.env.DB_POOL_SIZE, 10) || 10,
      serverSelectionTimeoutMS: parseInt(process.env.DB_TIMEOUT, 10) || 5000,
      socketTimeoutMS: parseInt(process.env.DB_SOCKET_TIMEOUT, 10) || 45000,
      family: 4 // Use IPv4, skip trying IPv6
    };
    
    // Multi-tenant database configuration
    this.multiTenant = {
      enabled: process.env.ENABLE_MULTI_TENANT_DB === 'true',
      strategy: process.env.TENANT_DB_STRATEGY || 'shared', // 'shared' or 'separate'
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
      maxAttempts: parseInt(process.env.DB_RETRY_ATTEMPTS, 10) || 5,
      interval: parseInt(process.env.DB_RETRY_INTERVAL, 10) || 5000,
      backoffMultiplier: parseFloat(process.env.DB_RETRY_BACKOFF, 10) || 1.5
    };
    
    // Encryption settings for sensitive data
    this.encryption = {
      enabled: process.env.DB_ENCRYPTION_ENABLED === 'true',
      keyId: process.env.DB_ENCRYPTION_KEY_ID,
      kmsProvider: process.env.DB_KMS_PROVIDER || 'local',
      localKey: process.env.DB_ENCRYPTION_LOCAL_KEY
    };
    
    // Query performance settings
    this.performance = {
      slowQueryThreshold: parseInt(process.env.DB_SLOW_QUERY_MS, 10) || 100,
      explainEnabled: process.env.DB_EXPLAIN_ENABLED === 'true',
      profilingLevel: parseInt(process.env.DB_PROFILING_LEVEL, 10) || 0
    };
    
    // Backup configuration
    this.backup = {
      enabled: process.env.DB_BACKUP_ENABLED === 'true',
      schedule: process.env.DB_BACKUP_SCHEDULE || '0 2 * * *', // Daily at 2 AM
      retention: parseInt(process.env.DB_BACKUP_RETENTION_DAYS, 10) || 30,
      location: process.env.DB_BACKUP_LOCATION || 's3'
    };
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
    
    const url = new URL(this.url);
    const pathParts = url.pathname.split('/');
    pathParts[pathParts.length - 1] = dbName;
    url.pathname = pathParts.join('/');
    
    return url.toString();
  }
  
  /**
   * Get connection options with authentication
   * @returns {Object} Mongoose connection options
   */
  getConnectionOptions() {
    const options = { ...this.options };
    
    // Add authentication if provided
    if (process.env.DB_USERNAME && process.env.DB_PASSWORD) {
      options.auth = {
        username: process.env.DB_USERNAME,
        password: process.env.DB_PASSWORD
      };
      
      if (process.env.DB_AUTH_SOURCE) {
        options.authSource = process.env.DB_AUTH_SOURCE;
      }
    }
    
    // Add SSL/TLS options for production
    if (process.env.NODE_ENV === 'production') {
      options.ssl = process.env.DB_SSL === 'true';
      options.sslValidate = process.env.DB_SSL_VALIDATE !== 'false';
      
      if (process.env.DB_SSL_CA) {
        options.sslCA = process.env.DB_SSL_CA;
      }
    }
    
    // Add replica set configuration
    if (process.env.DB_REPLICA_SET) {
      options.replicaSet = process.env.DB_REPLICA_SET;
      options.readPreference = process.env.DB_READ_PREFERENCE || 'primaryPreferred';
    }
    
    return options;
  }
  
  /**
   * Create connection with retry logic
   * @param {string} dbName - Database name
   * @returns {Promise<mongoose.Connection>} Mongoose connection
   */
  async createConnection(dbName = null) {
    const connectionString = this.getConnectionString(dbName);
    const options = this.getConnectionOptions();
    
    let attempts = 0;
    let lastError;
    
    while (attempts < this.retry.maxAttempts) {
      try {
        const connection = await mongoose.createConnection(connectionString, options);
        
        // Set up connection event handlers
        this.setupConnectionHandlers(connection, dbName);
        
        return connection;
      } catch (error) {
        lastError = error;
        attempts++;
        
        if (attempts < this.retry.maxAttempts) {
          const delay = this.retry.interval * Math.pow(this.retry.backoffMultiplier, attempts - 1);
          console.log(`Database connection attempt ${attempts} failed. Retrying in ${delay}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    throw new Error(`Failed to connect to database after ${attempts} attempts: ${lastError.message}`);
  }
  
  /**
   * Set up connection event handlers
   * @param {mongoose.Connection} connection - Mongoose connection
   * @param {string} dbName - Database name
   */
  setupConnectionHandlers(connection, dbName) {
    const dbIdentifier = dbName || 'main';
    
    connection.on('connected', () => {
      console.log(`✓ Database connected: ${dbIdentifier}`);
    });
    
    connection.on('error', (error) => {
      console.error(`✗ Database error (${dbIdentifier}):`, error.message);
    });
    
    connection.on('disconnected', () => {
      console.log(`✗ Database disconnected: ${dbIdentifier}`);
    });
    
    // Graceful shutdown
    process.on('SIGINT', async () => {
      await connection.close();
      console.log(`Database connection closed: ${dbIdentifier}`);
    });
  }
  
  /**
   * Configure mongoose plugins and settings
   * @param {mongoose} mongooseInstance - Mongoose instance
   */
  configureMongoose(mongooseInstance) {
    // Set default options
    mongooseInstance.set('strictQuery', true);
    mongooseInstance.set('debug', process.env.DB_DEBUG === 'true');
    
    // Add custom error messages
    mongooseInstance.Error.messages.general.required = 'Field `{PATH}` is required';
    mongooseInstance.Error.messages.String.minlength = 'Field `{PATH}` must be at least {MINLENGTH} characters';
    mongooseInstance.Error.messages.String.maxlength = 'Field `{PATH}` must be at most {MAXLENGTH} characters';
    
    // Add global plugins
    if (this.performance.slowQueryThreshold > 0) {
      mongooseInstance.plugin(this.createSlowQueryPlugin());
    }
    
    // Add encryption plugin if enabled
    if (this.encryption.enabled) {
      mongooseInstance.plugin(this.createEncryptionPlugin());
    }
  }
  
  /**
   * Create slow query logging plugin
   * @returns {Function} Mongoose plugin
   */
  createSlowQueryPlugin() {
    const threshold = this.performance.slowQueryThreshold;
    
    return function slowQueryPlugin(schema) {
      schema.pre(/^find/, function() {
        this._startTime = Date.now();
      });
      
      schema.post(/^find/, function() {
        if (this._startTime) {
          const duration = Date.now() - this._startTime;
          if (duration > threshold) {
            console.warn(`Slow query detected (${duration}ms):`, {
              collection: this.mongooseCollection.name,
              operation: this.op,
              duration,
              filter: this.getFilter()
            });
          }
        }
      });
    };
  }
  
  /**
   * Create encryption plugin for sensitive fields
   * @returns {Function} Mongoose plugin
   */
  createEncryptionPlugin() {
    // This would implement field-level encryption
    // Simplified for this example
    return function encryptionPlugin(schema) {
      // Add encryption logic here
    };
  }
  
  /**
   * Get tenant-specific database connection
   * @param {string} tenantId - Tenant identifier
   * @returns {Promise<mongoose.Connection>} Tenant connection
   */
  async getTenantConnection(tenantId) {
    if (!this.multiTenant.enabled) {
      throw new Error('Multi-tenant database is not enabled');
    }
    
    if (this.multiTenant.strategy === 'separate') {
      const dbName = `${this.multiTenant.prefix}${tenantId}`;
      return this.createConnection(dbName);
    }
    
    // For shared strategy, return main connection
    return this.createConnection();
  }
}

// Create and export singleton instance
module.exports = new DatabaseConfig();