// server/shared/config/environment.js
/**
 * @file Environment Configuration
 * @description Environment-specific settings and feature flags
 * @version 3.0.0
 */

/**
 * Environment Configuration Class
 * @class EnvironmentConfig
 */
class EnvironmentConfig {
  constructor() {
    this.current = process.env.NODE_ENV || 'development';
    this.isDevelopment = this.current === 'development';
    this.isProduction = this.current === 'production';
    this.isStaging = this.current === 'staging';
    this.isTest = this.current === 'test';
    
    // Environment-specific settings
    this.settings = {
      development: {
        name: 'Development',
        debug: true,
        logLevel: 'debug',
        errorStack: true,
        apiDocs: true,
        seedData: true,
        mockServices: true,
        hotReload: true,
        sourceMap: true,
        cors: {
          origin: true,
          credentials: true
        },
        cache: {
          enabled: false,
          duration: 0
        },
        email: {
          sandbox: true,
          interceptAddress: 'dev@insightserenity.com'
        },
        payment: {
          sandbox: true,
          testMode: true
        },
        features: {
          debugPanel: true,
          apiExplorer: true,
          performanceMonitoring: false,
          errorTracking: false
        }
      },
      
      staging: {
        name: 'Staging',
        debug: false,
        logLevel: 'info',
        errorStack: true,
        apiDocs: true,
        seedData: false,
        mockServices: false,
        hotReload: false,
        sourceMap: false,
        cors: {
          origin: [
            'https://staging.insightserenity.com',
            'https://staging-app.insightserenity.com'
          ],
          credentials: true
        },
        cache: {
          enabled: true,
          duration: 300 // 5 minutes
        },
        email: {
          sandbox: true,
          interceptAddress: 'staging@insightserenity.com'
        },
        payment: {
          sandbox: true,
          testMode: true
        },
        features: {
          debugPanel: true,
          apiExplorer: true,
          performanceMonitoring: true,
          errorTracking: true
        }
      },
      
      production: {
        name: 'Production',
        debug: false,
        logLevel: 'error',
        errorStack: false,
        apiDocs: false,
        seedData: false,
        mockServices: false,
        hotReload: false,
        sourceMap: false,
        cors: {
          origin: [
            'https://insightserenity.com',
            'https://app.insightserenity.com',
            'https://www.insightserenity.com'
          ],
          credentials: true
        },
        cache: {
          enabled: true,
          duration: 3600 // 1 hour
        },
        email: {
          sandbox: false,
          interceptAddress: null
        },
        payment: {
          sandbox: false,
          testMode: false
        },
        features: {
          debugPanel: false,
          apiExplorer: false,
          performanceMonitoring: true,
          errorTracking: true
        }
      },
      
      test: {
        name: 'Test',
        debug: false,
        logLevel: 'error',
        errorStack: true,
        apiDocs: false,
        seedData: true,
        mockServices: true,
        hotReload: false,
        sourceMap: true,
        cors: {
          origin: true,
          credentials: true
        },
        cache: {
          enabled: false,
          duration: 0
        },
        email: {
          sandbox: true,
          interceptAddress: 'test@insightserenity.com'
        },
        payment: {
          sandbox: true,
          testMode: true
        },
        features: {
          debugPanel: false,
          apiExplorer: false,
          performanceMonitoring: false,
          errorTracking: false
        }
      }
    };
    
    // Deployment information
    this.deployment = {
      version: process.env.APP_VERSION || '1.0.0',
      commit: process.env.GIT_COMMIT || 'unknown',
      branch: process.env.GIT_BRANCH || 'unknown',
      buildNumber: process.env.BUILD_NUMBER || 'unknown',
      buildDate: process.env.BUILD_DATE || new Date().toISOString(),
      deployedAt: process.env.DEPLOYED_AT || new Date().toISOString(),
      deployedBy: process.env.DEPLOYED_BY || 'unknown'
    };
    
    // Service URLs
    this.services = {
      api: this.getServiceUrl('API_URL', '/api'),
      web: this.getServiceUrl('WEB_URL', ''),
      cdn: this.getServiceUrl('CDN_URL', '/static'),
      websocket: this.getServiceUrl('WEBSOCKET_URL', '/ws'),
      recruitment: this.getServiceUrl('RECRUITMENT_URL', '/recruitment'),
      analytics: this.getServiceUrl('ANALYTICS_URL', '/analytics')
    };
    
    // External service endpoints
    this.external = {
      sentry: {
        dsn: process.env.SENTRY_DSN,
        environment: this.current,
        enabled: this.isProduction || this.isStaging
      },
      cloudinary: {
        cloudName: process.env.CLOUDINARY_CLOUD_NAME,
        apiKey: process.env.CLOUDINARY_API_KEY,
        apiSecret: process.env.CLOUDINARY_API_SECRET
      },
      googleAnalytics: {
        trackingId: process.env.GA_TRACKING_ID,
        enabled: this.isProduction
      },
      intercom: {
        appId: process.env.INTERCOM_APP_ID,
        enabled: this.isProduction || this.isStaging
      },
      mixpanel: {
        token: process.env.MIXPANEL_TOKEN,
        enabled: this.isProduction
      }
    };
    
    // Feature flags
    this.features = {
      // Authentication features
      socialLogin: this.getFeatureFlag('FEATURE_SOCIAL_LOGIN', true),
      twoFactorAuth: this.getFeatureFlag('FEATURE_2FA', true),
      passwordlessLogin: this.getFeatureFlag('FEATURE_PASSWORDLESS', false),
      biometricAuth: this.getFeatureFlag('FEATURE_BIOMETRIC', false),
      
      // Platform features
      multiTenancy: this.getFeatureFlag('FEATURE_MULTI_TENANCY', true),
      customDomains: this.getFeatureFlag('FEATURE_CUSTOM_DOMAINS', true),
      whiteLabeling: this.getFeatureFlag('FEATURE_WHITE_LABEL', true),
      apiAccess: this.getFeatureFlag('FEATURE_API_ACCESS', true),
      
      // Recruitment features
      recruitmentModule: this.getFeatureFlag('FEATURE_RECRUITMENT', true),
      candidateMatching: this.getFeatureFlag('FEATURE_CANDIDATE_MATCHING', true),
      aiScreening: this.getFeatureFlag('FEATURE_AI_SCREENING', false),
      videoInterviews: this.getFeatureFlag('FEATURE_VIDEO_INTERVIEWS', false),
      
      // Billing features
      subscriptions: this.getFeatureFlag('FEATURE_SUBSCRIPTIONS', true),
      usageBasedBilling: this.getFeatureFlag('FEATURE_USAGE_BILLING', true),
      multiCurrency: this.getFeatureFlag('FEATURE_MULTI_CURRENCY', false),
      invoicing: this.getFeatureFlag('FEATURE_INVOICING', true),
      
      // Communication features
      inAppMessaging: this.getFeatureFlag('FEATURE_IN_APP_MESSAGING', true),
      emailNotifications: this.getFeatureFlag('FEATURE_EMAIL_NOTIFICATIONS', true),
      smsNotifications: this.getFeatureFlag('FEATURE_SMS_NOTIFICATIONS', false),
      pushNotifications: this.getFeatureFlag('FEATURE_PUSH_NOTIFICATIONS', false),
      
      // Analytics features
      advancedAnalytics: this.getFeatureFlag('FEATURE_ADVANCED_ANALYTICS', true),
      customReports: this.getFeatureFlag('FEATURE_CUSTOM_REPORTS', true),
      dataExport: this.getFeatureFlag('FEATURE_DATA_EXPORT', true),
      realTimeMetrics: this.getFeatureFlag('FEATURE_REAL_TIME_METRICS', false),
      
      // Beta features
      betaFeatures: this.getFeatureFlag('FEATURE_BETA', false),
      experimentalApi: this.getFeatureFlag('FEATURE_EXPERIMENTAL_API', false)
    };
    
    // Maintenance mode
    this.maintenance = {
      enabled: process.env.MAINTENANCE_MODE === 'true',
      message: process.env.MAINTENANCE_MESSAGE || 'We are currently performing scheduled maintenance. Please check back soon.',
      allowedIPs: process.env.MAINTENANCE_ALLOWED_IPS?.split(',') || [],
      estimatedEndTime: process.env.MAINTENANCE_END_TIME
    };
  }
  
  /**
   * Get current environment settings
   * @returns {Object} Environment settings
   */
  get() {
    return this.settings[this.current] || this.settings.development;
  }
  
  /**
   * Get specific setting for current environment
   * @param {string} key - Setting key
   * @returns {any} Setting value
   */
  getSetting(key) {
    const settings = this.get();
    return key.split('.').reduce((obj, k) => obj?.[k], settings);
  }
  
  /**
   * Get service URL based on environment
   * @param {string} envVar - Environment variable name
   * @param {string} defaultPath - Default path
   * @returns {string} Service URL
   */
  getServiceUrl(envVar, defaultPath) {
    const baseUrl = process.env[envVar] || process.env.APP_URL || 'http://localhost:3000';
    return `${baseUrl}${defaultPath}`;
  }
  
  /**
   * Get feature flag value
   * @param {string} flag - Feature flag name
   * @param {boolean} defaultValue - Default value
   * @returns {boolean} Feature flag value
   */
  getFeatureFlag(flag, defaultValue = false) {
    const value = process.env[flag];
    if (value === undefined) return defaultValue;
    return value === 'true';
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
   * Check if in maintenance mode
   * @param {string} ip - Client IP address
   * @returns {boolean} Whether in maintenance mode
   */
  isInMaintenance(ip = null) {
    if (!this.maintenance.enabled) return false;
    
    // Check if IP is in allowed list
    if (ip && this.maintenance.allowedIPs.includes(ip)) {
      return false;
    }
    
    // Check if maintenance has ended
    if (this.maintenance.estimatedEndTime) {
      const endTime = new Date(this.maintenance.estimatedEndTime);
      if (new Date() > endTime) {
        return false;
      }
    }
    
    return true;
  }
  
  /**
   * Get environment info for health checks
   * @returns {Object} Environment information
   */
  getInfo() {
    return {
      environment: this.current,
      name: this.get().name,
      version: this.deployment.version,
      commit: this.deployment.commit,
      branch: this.deployment.branch,
      buildNumber: this.deployment.buildNumber,
      buildDate: this.deployment.buildDate,
      features: Object.keys(this.features).filter(f => this.features[f]),
      maintenance: this.maintenance.enabled
    };
  }
  
  /**
   * Validate environment configuration
   * @throws {Error} If configuration is invalid
   */
  validate() {
    const requiredEnvVars = {
      production: [
        'DATABASE_URL',
        'REDIS_HOST',
        'JWT_SECRET',
        'SESSION_SECRET',
        'STRIPE_SECRET_KEY',
        'STRIPE_WEBHOOK_SECRET',
        'EMAIL_FROM_ADDRESS',
        'SENTRY_DSN'
      ],
      staging: [
        'DATABASE_URL',
        'JWT_SECRET',
        'SESSION_SECRET'
      ]
    };
    
    const required = requiredEnvVars[this.current] || [];
    const missing = required.filter(varName => !process.env[varName]);
    
    if (missing.length > 0) {
      throw new Error(`Missing required environment variables for ${this.current}: ${missing.join(', ')}`);
    }
    
    return true;
  }
}

// Create and export singleton instance
module.exports = new EnvironmentConfig();