// server/shared/security/middleware/cors-config.js
/**
 * @file CORS Configuration Middleware
 * @description Cross-Origin Resource Sharing configuration for multi-tenant platform
 * @version 3.0.0
 */

const cors = require('cors');

const config = require('../../config');
const { AppError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

/**
 * CORS Configuration Manager Class
 * @class CORSConfigManager
 */
class CORSConfigManager {
  constructor() {
    this.allowedOrigins = this.buildAllowedOrigins();
    this.credentials = true;
    this.maxAge = 86400; // 24 hours
  }
  
  /**
   * Build allowed origins list
   * @returns {Array<string|RegExp>} Allowed origins
   */
  buildAllowedOrigins() {
    const origins = [];
    
    // Add configured origins
    if (config.security.corsOrigins) {
      origins.push(...config.security.corsOrigins);
    }
    
    // Production origins
    if (config.isProduction || config.isStaging) {
      origins.push(
        'https://insightserenity.com',
        'https://www.insightserenity.com',
        'https://app.insightserenity.com',
        'https://api.insightserenity.com'
      );
    }
    
    // Staging origins
    if (config.isStaging) {
      origins.push(
        'https://staging.insightserenity.com',
        'https://staging-app.insightserenity.com',
        'https://staging-api.insightserenity.com'
      );
    }
    
    // Development origins
    if (config.isDevelopment) {
      origins.push(
        'http://localhost:3000',
        'http://localhost:3001',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:3001'
      );
    }
    
    // Dynamic subdomain pattern for hosted organizations
    origins.push(
      /^https:\/\/[a-z0-9-]+\.insightserenity\.com$/,
      /^https:\/\/[a-z0-9-]+\.app\.insightserenity\.com$/
    );
    
    // Custom domains for white-label organizations
    if (process.env.ALLOWED_CUSTOM_DOMAINS) {
      const customDomains = process.env.ALLOWED_CUSTOM_DOMAINS.split(',');
      origins.push(...customDomains.map(domain => `https://${domain.trim()}`));
    }
    
    return origins;
  }
  
  /**
   * Origin validator function
   * @param {string} origin - Request origin
   * @param {Function} callback - CORS callback
   */
  originValidator(origin, callback) {
    // Allow requests with no origin (same-origin, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }
    
    // Check against allowed origins
    const isAllowed = this.allowedOrigins.some(allowed => {
      if (allowed instanceof RegExp) {
        return allowed.test(origin);
      }
      return allowed === origin;
    });
    
    if (isAllowed) {
      callback(null, true);
    } else {
      // Check if it's a custom domain for an organization
      this.checkCustomDomain(origin)
        .then(isValid => {
          if (isValid) {
            callback(null, true);
          } else {
            logger.warn('CORS: Origin not allowed', { origin });
            callback(new AppError('Not allowed by CORS', 403, 'CORS_ERROR'));
          }
        })
        .catch(error => {
          logger.error('CORS: Error checking custom domain', { origin, error });
          callback(new AppError('CORS validation error', 500, 'CORS_ERROR'));
        });
    }
  }
  
  /**
   * Check if origin is a valid custom domain
   * @param {string} origin - Origin to check
   * @returns {Promise<boolean>} Is valid custom domain
   */
  async checkCustomDomain(origin) {
    try {
      // Extract domain from origin
      const url = new URL(origin);
      const domain = url.hostname;
      
      // Check against database of approved custom domains
      // This would query the Organization model for custom domains
      // For now, returning false as placeholder
      
      // TODO: Implement actual database check
      // const Organization = require('../../models/Organization');
      // const org = await Organization.findOne({ 
      //   'customDomain.domain': domain,
      //   'customDomain.verified': true,
      //   active: true
      // });
      
      return false;
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Create CORS options
   * @returns {Object} CORS options
   */
  createOptions() {
    return {
      origin: this.originValidator.bind(this),
      credentials: this.credentials,
      maxAge: this.maxAge,
      
      // Allowed methods
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      
      // Allowed headers
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Requested-With',
        'X-API-Key',
        'X-Organization-ID',
        'X-Tenant-ID',
        'X-CSRF-Token',
        'X-Upload-Content-Type',
        'X-Upload-Content-Length',
        'Accept',
        'Accept-Language',
        'Accept-Encoding',
        'Cache-Control',
        'Pragma'
      ],
      
      // Exposed headers
      exposedHeaders: [
        'X-Total-Count',
        'X-Page-Count',
        'X-Current-Page',
        'X-Per-Page',
        'X-RateLimit-Limit',
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset',
        'X-Request-ID',
        'X-Organization-Context',
        'X-API-Version',
        'Content-Disposition',
        'Content-Length',
        'ETag',
        'Last-Modified'
      ],
      
      // Handle preflight
      preflightContinue: false,
      optionsSuccessStatus: 204
    };
  }
  
  /**
   * Create CORS middleware for public routes
   * @returns {Function} CORS middleware
   */
  createPublicCORS() {
    return cors({
      origin: true, // Allow all origins for public endpoints
      credentials: false,
      methods: ['GET', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Accept'],
      maxAge: this.maxAge
    });
  }
  
  /**
   * Create CORS middleware for webhook endpoints
   * @returns {Function} CORS middleware
   */
  createWebhookCORS() {
    return cors({
      origin: true, // Webhooks can come from anywhere
      credentials: false,
      methods: ['POST', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'X-Webhook-Signature',
        'X-Webhook-ID',
        'X-Webhook-Timestamp'
      ],
      maxAge: 300 // 5 minutes for webhooks
    });
  }
  
  /**
   * Create dynamic CORS middleware
   * @returns {Function} Express middleware
   */
  createDynamicCORS() {
    return async (req, res, next) => {
      // Skip CORS for same-origin requests
      if (!req.get('origin')) {
        return next();
      }
      
      try {
        // Get organization context
        const organizationId = req.get('X-Organization-ID') || 
                              req.params.organizationId ||
                              req.query.organizationId;
        
        if (organizationId) {
          // Check organization-specific CORS settings
          const corsSettings = await this.getOrganizationCORS(organizationId);
          
          if (corsSettings) {
            const dynamicOptions = {
              ...this.createOptions(),
              origin: (origin, callback) => {
                const isAllowed = corsSettings.allowedOrigins.includes(origin) ||
                                corsSettings.allowedOrigins.includes('*');
                callback(null, isAllowed);
              }
            };
            
            return cors(dynamicOptions)(req, res, next);
          }
        }
        
        // Fall back to default CORS
        next();
      } catch (error) {
        logger.error('Dynamic CORS error', { error, organizationId });
        next();
      }
    };
  }
  
  /**
   * Get organization-specific CORS settings
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} CORS settings
   */
  async getOrganizationCORS(organizationId) {
    // TODO: Implement actual database lookup
    // This would fetch from Organization model
    
    // Placeholder implementation
    return null;
  }
  
  /**
   * Create CORS error handler
   * @returns {Function} Express error middleware
   */
  createErrorHandler() {
    return (err, req, res, next) => {
      if (err && err.message === 'Not allowed by CORS') {
        return res.status(403).json({
          success: false,
          error: {
            message: 'Cross-Origin Request Blocked',
            code: 'CORS_ERROR',
            origin: req.get('origin')
          }
        });
      }
      next(err);
    };
  }
  
  /**
   * Create preflight handler for complex requests
   * @returns {Function} Express middleware
   */
  createPreflightHandler() {
    return (req, res, next) => {
      if (req.method === 'OPTIONS') {
        // Log preflight requests in development
        if (config.isDevelopment) {
          logger.debug('CORS Preflight Request', {
            origin: req.get('origin'),
            method: req.get('access-control-request-method'),
            headers: req.get('access-control-request-headers')
          });
        }
        
        // Set Vary header for caching
        res.vary('Origin');
        res.vary('Access-Control-Request-Method');
        res.vary('Access-Control-Request-Headers');
        
        // Handle preflight
        res.sendStatus(204);
      } else {
        next();
      }
    };
  }
  
  /**
   * Create CORS middleware for specific route patterns
   * @param {Object} options - Route-specific options
   * @returns {Function} CORS middleware
   */
  createRouteCORS(options = {}) {
    const {
      origins = this.allowedOrigins,
      methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
      allowedHeaders = null,
      exposedHeaders = null,
      credentials = true,
      maxAge = this.maxAge
    } = options;
    
    return cors({
      origin: (origin, callback) => {
        if (!origin || origins.includes('*')) {
          return callback(null, true);
        }
        
        const isAllowed = origins.some(allowed => {
          if (allowed instanceof RegExp) {
            return allowed.test(origin);
          }
          return allowed === origin;
        });
        
        callback(null, isAllowed);
      },
      credentials,
      methods,
      allowedHeaders: allowedHeaders || this.createOptions().allowedHeaders,
      exposedHeaders: exposedHeaders || this.createOptions().exposedHeaders,
      maxAge
    });
  }
}

// Create singleton instance
const corsManager = new CORSConfigManager();

// Export middleware functions
module.exports = {
  // Main CORS middleware
  cors: cors(corsManager.createOptions()),
  
  // Specialized CORS middleware                                                                        
  publicCORS: corsManager.createPublicCORS(),
  webhookCORS: corsManager.createWebhookCORS(),
  dynamicCORS: corsManager.createDynamicCORS(),
  
  // Handlers
  preflightHandler: corsManager.createPreflightHandler(),
  errorHandler: corsManager.createErrorHandler(),
  
  // Factory function for custom CORS
  createRouteCORS: corsManager.createRouteCORS.bind(corsManager),
  
  // Direct access to options
  options: corsManager.createOptions()
};