// /server/shared/security/middleware/helmet-middleware.js

/**
 * @file Helmet Middleware
 * @description Security headers middleware wrapper that integrates with security-headers
 * @version 1.0.0
 */

const securityHeaders = require('./security-headers');
const logger = require('../../utils/logger');

/**
 * Apply helmet middleware with environment-specific configuration
 */
const applyHelmet = (options = {}) => {
  const env = process.env.NODE_ENV || 'development';
  
  // Environment-specific configurations
  const envConfig = {
    development: {
      contentSecurityPolicy: false, // Disable CSP in development for hot reloading
      hsts: false // Disable HSTS in development
    },
    staging: {
      contentSecurityPolicy: {
        reportOnly: true // Report-only mode in staging
      }
    },
    production: {
      // Use all defaults in production
    }
  };
  
  const config = {
    ...envConfig[env],
    ...options
  };
  
  return (req, res, next) => {
    // Skip security headers for health check endpoints
    if (req.path === '/health' || req.path === '/api/health') {
      return next();
    }
    
    // Apply security headers
    securityHeaders.securityHeaders(req, res, next);
  };
};

/**
 * Helmet middleware for API routes
 */
const apiHelmet = (req, res, next) => {
  // Apply API-specific headers first
  securityHeaders.apiHeaders(req, res, () => {
    // Then apply general security headers
    securityHeaders.securityHeaders(req, res, next);
  });
};

/**
 * Helmet middleware for download routes
 */
const downloadHelmet = (req, res, next) => {
  // Apply download-specific headers first
  securityHeaders.downloadHeaders(req, res, () => {
    // Then apply general security headers
    securityHeaders.securityHeaders(req, res, next);
  });
};

/**
 * Helmet middleware with CSP nonce support
 */
const helmetWithNonce = [
  securityHeaders.securityHeaders,
  securityHeaders.nonceMiddleware,
  securityHeaders.additionalHeaders
];

/**
 * Comprehensive security headers middleware
 */
const comprehensiveHelmet = (req, res, next) => {
  const middlewares = securityHeaders.all;
  let index = 0;
  
  const runNext = (err) => {
    if (err) return next(err);
    
    const middleware = middlewares[index++];
    if (!middleware) return next();
    
    try {
      middleware(req, res, runNext);
    } catch (error) {
      logger.error('Helmet middleware error', {
        error: error.message,
        middleware: index - 1,
        path: req.path
      });
      next(error);
    }
  };
  
  runNext();
};

/**
 * Report URI handler for CSP and CT violations
 */
const reportHandler = (type = 'csp') => {
  return (req, res, next) => {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
    
    const report = req.body;
    
    logger.warn(`${type.toUpperCase()} Violation Report`, {
      type,
      report,
      userAgent: req.get('user-agent'),
      ip: req.ip,
      referer: req.get('referer')
    });
    
    // Send metrics if monitoring is enabled
    if (process.env.MONITORING_ENABLED === 'true') {
      // TODO: Send to monitoring service
    }
    
    res.status(204).end();
  };
};

module.exports = {
  // Main middleware
  helmet: applyHelmet(),
  
  // Environment-specific
  developmentHelmet: applyHelmet({ 
    contentSecurityPolicy: false,
    hsts: false 
  }),
  productionHelmet: comprehensiveHelmet,
  
  // Route-specific
  apiHelmet,
  downloadHelmet,
  helmetWithNonce,
  
  // Report handlers
  cspReportHandler: reportHandler('csp'),
  ctReportHandler: reportHandler('ct'),
  
  // Direct access to components
  nonce: securityHeaders.nonceMiddleware,
  additionalHeaders: securityHeaders.additionalHeaders,
  errorHandler: securityHeaders.errorHandler
};