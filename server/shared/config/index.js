// server/shared/config/index.js
/**
 * @file Configuration Index
 * @description Central configuration management for the platform
 * @version 3.0.0
 */

const path = require('path');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config({ path: path.join(__dirname, '../../../.env') });

// Import individual configurations
const database = require('../database/database');
const redis = require('./redis');
const environment = require('./environment');
const constants = require('./constants');

/**
 * Configuration Manager Class
 * @class ConfigManager
 */
class ConfigManager {
  constructor() {
    this.env = process.env.NODE_ENV || 'development';
    this.isDevelopment = this.env === 'development';
    this.isProduction = this.env === 'production';
    this.isTest = this.env === 'test';
    
    // Core configurations
    this.server = {
      port: parseInt(process.env.PORT, 10) || 3000,
      host: process.env.HOST || '0.0.0.0',
      url: process.env.APP_URL || `http://localhost:${this.port}`,
      apiPrefix: process.env.API_PREFIX || '/api/v1'
    };
    
    this.auth = {
      jwtSecret: process.env.JWT_SECRET || 'your-jwt-secret-key',
      jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key',
      accessTokenExpiry: process.env.ACCESS_TOKEN_EXPIRY || '15m',
      refreshTokenExpiry: process.env.REFRESH_TOKEN_EXPIRY || '7d',
      sessionSecret: process.env.SESSION_SECRET || 'your-session-secret',
      bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 10,
      passwordResetExpiry: parseInt(process.env.PASSWORD_RESET_EXPIRY, 10) || 3600000, // 1 hour
      emailVerificationExpiry: parseInt(process.env.EMAIL_VERIFICATION_EXPIRY, 10) || 86400000 // 24 hours
    };
    
    this.oauth = {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackUrl: `${this.server.url}/api/auth/google/callback`
      },
      github: {
        clientId: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackUrl: `${this.server.url}/api/auth/github/callback`
      },
      linkedin: {
        clientId: process.env.LINKEDIN_CLIENT_ID,
        clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
        callbackUrl: `${this.server.url}/api/auth/linkedin/callback`
      }
    };
    
    this.email = {
      provider: process.env.EMAIL_PROVIDER || 'smtp',
      from: {
        name: process.env.EMAIL_FROM_NAME || 'InsightSerenity Platform',
        address: process.env.EMAIL_FROM_ADDRESS || 'noreply@insightserenity.com'
      },
      smtp: {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT, 10) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      },
      sendgrid: {
        apiKey: process.env.SENDGRID_API_KEY
      }
    };
    
    this.payment = {
      stripe: {
        secretKey: process.env.STRIPE_SECRET_KEY,
        publishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
        webhookSecret: process.env.STRIPE_WEBHOOK_SECRET,
        apiVersion: '2023-10-16'
      },
      paypal: {
        clientId: process.env.PAYPAL_CLIENT_ID,
        clientSecret: process.env.PAYPAL_CLIENT_SECRET,
        mode: process.env.PAYPAL_MODE || 'sandbox'
      }
    };
    
    this.storage = {
      provider: process.env.STORAGE_PROVIDER || 'local',
      local: {
        uploadDir: path.join(__dirname, '../../../uploads'),
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE, 10) || 10485760, // 10MB
        allowedMimeTypes: process.env.ALLOWED_MIME_TYPES?.split(',') || [
          'image/jpeg',
          'image/png',
          'image/gif',
          'application/pdf',
          'application/msword',
          'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]
      },
      s3: {
        bucket: process.env.AWS_S3_BUCKET,
        region: process.env.AWS_S3_REGION || 'us-east-1',
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    };
    
    this.security = {
      corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
      rateLimiting: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 900000, // 15 minutes
        max: parseInt(process.env.RATE_LIMIT_MAX, 10) || 100
      },
      encryption: {
        algorithm: 'aes-256-gcm',
        keyDerivation: 'pbkdf2',
        iterations: 100000
      },
      sessionRotationMinutes: parseInt(process.env.SESSION_ROTATION_MINUTES, 10) || 60,
      maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5,
      lockoutDuration: parseInt(process.env.LOCKOUT_DURATION, 10) || 1800000 // 30 minutes
    };
    
    this.features = {
      multiTenancy: process.env.ENABLE_MULTI_TENANCY === 'true',
      recruitment: process.env.ENABLE_RECRUITMENT === 'true',
      twoFactorAuth: process.env.ENABLE_2FA === 'true',
      emailVerification: process.env.REQUIRE_EMAIL_VERIFICATION === 'true',
      apiDocumentation: process.env.ENABLE_API_DOCS === 'true',
      maintenanceMode: process.env.MAINTENANCE_MODE === 'true'
    };
    
    this.logging = {
      level: process.env.LOG_LEVEL || (this.isDevelopment ? 'debug' : 'info'),
      format: process.env.LOG_FORMAT || 'json',
      transports: process.env.LOG_TRANSPORTS?.split(',') || ['console', 'file'],
      filePath: process.env.LOG_FILE_PATH || path.join(__dirname, '../../../logs')
    };
    
    // Import sub-configurations
    this.database = database;
    this.redis = redis;
    this.environment = environment;
    this.constants = constants;
  }
  
  /**
   * Validate critical configuration
   * @throws {Error} If critical configuration is missing
   */
  validate() {
    const criticalConfigs = [
      { name: 'JWT_SECRET', value: this.auth.jwtSecret },
      { name: 'DATABASE_URL', value: this.database.url },
      { name: 'SESSION_SECRET', value: this.auth.sessionSecret }
    ];
    
    const missing = criticalConfigs.filter(config => !config.value);
    
    if (missing.length > 0) {
      const missingNames = missing.map(m => m.name).join(', ');
      throw new Error(`Missing critical configuration: ${missingNames}`);
    }
    
    // Validate OAuth configs if features are enabled
    if (this.oauth.google.clientId && (!this.oauth.google.clientSecret)) {
      throw new Error('Google OAuth: Client secret required when client ID is provided');
    }
    
    return true;
  }
  
  /**
   * Get configuration for specific environment
   * @param {string} key - Configuration key
   * @returns {any} Configuration value
   */
  get(key) {
    const keys = key.split('.');
    let value = this;
    
    for (const k of keys) {
      value = value[k];
      if (value === undefined) {
        return undefined;
      }
    }
    
    return value;
  }
  
  /**
   * Check if feature is enabled
   * @param {string} feature - Feature name
   * @returns {boolean} Whether feature is enabled
   */
  isFeatureEnabled(feature) {
    return this.features[feature] === true;
  }
  
  /**
   * Get environment-specific value
   * @param {Object} values - Environment-specific values
   * @returns {any} Value for current environment
   */
  getEnvironmentValue(values) {
    return values[this.env] || values.default;
  }
}

// Create and export singleton instance
const config = new ConfigManager();

// Validate configuration in non-test environments
if (process.env.NODE_ENV !== 'test') {
  try {
    config.validate();
  } catch (error) {
    console.error('Configuration validation failed:', error.message);
    process.exit(1);
  }
}

module.exports = config;