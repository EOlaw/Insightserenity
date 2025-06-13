// server/shared/security/middleware/security-headers.js
/**
 * @file Security Headers Middleware
 * @description Comprehensive security headers for protection against common attacks
 * @version 3.0.0
 */

const helmet = require('helmet');
const crypto = require('crypto');
const config = require('../../config');
const logger = require('../../utils/logger');

/**
 * Security Headers Manager Class
 * @class SecurityHeadersManager
 */
class SecurityHeadersManager {
  constructor() {
    this.nonce = new Map();
    this.trustedHosts = this.getTrustedHosts();
  }
  
  /**
   * Get trusted hosts from configuration
   * @returns {Array<string>} Trusted hosts
   */
  getTrustedHosts() {
    const hosts = [
      'insightserenity.com',
      'www.insightserenity.com',
      'app.insightserenity.com',
      'api.insightserenity.com'
    ];
    
    if (config.isDevelopment) {
      hosts.push('localhost:3000', 'localhost:3001', '127.0.0.1:3000');
    }
    
    if (config.isStaging) {
      hosts.push('staging.insightserenity.com', 'staging-app.insightserenity.com');
    }
    
    return hosts;
  }
  
  /**
   * Generate CSP nonce
   * @returns {string} CSP nonce
   */
  generateNonce() {
    return crypto.randomBytes(16).toString('base64');
  }
  
  /**
   * Create Content Security Policy
   * @returns {Object} CSP configuration
   */
  createCSPConfig() {
    const directives = {
      defaultSrc: ["'self'"],
      
      scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Will be replaced with nonce
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com',
        'https://www.google-analytics.com',
        'https://www.googletagmanager.com'
      ],
      
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com',
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com'
      ],
      
      fontSrc: [
        "'self'",
        'https://fonts.gstatic.com',
        'data:'
      ],
      
      imgSrc: [
        "'self'",
        'data:',
        'blob:',
        'https:',
        '*.insightserenity.com'
      ],
      
      connectSrc: [
        "'self'",
        'wss://*.insightserenity.com',
        'https://api.insightserenity.com',
        'https://www.google-analytics.com',
        'https://sentry.io'
      ],
      
      mediaSrc: ["'self'", 'blob:'],
      
      objectSrc: ["'none'"],
      
      childSrc: ["'self'", 'blob:'],
      
      frameSrc: [
        "'self'",
        'https://www.youtube.com',
        'https://player.vimeo.com',
        'https://checkout.stripe.com'
      ],
      
      workerSrc: ["'self'", 'blob:'],
      
      formAction: ["'self'"],
      
      frameAncestors: ["'self'"],
      
      baseUri: ["'self'"],
      
      manifestSrc: ["'self'"],
      
      upgradeInsecureRequests: config.isProduction ? [] : null
    };
    
    // Add report URI in production
    if (config.isProduction && process.env.CSP_REPORT_URI) {
      directives.reportUri = [process.env.CSP_REPORT_URI];
      directives.reportTo = 'csp-endpoint';
    }
    
    return {
      directives,
      reportOnly: config.isDevelopment
    };
  }
  
  /**
   * Create Permissions Policy
   * @returns {string} Permissions policy string
   */
  createPermissionsPolicy() {
    const policies = {
      accelerometer: [],
      'ambient-light-sensor': [],
      autoplay: ['self'],
      battery: [],
      camera: [],
      'cross-origin-isolated': ['self'],
      'display-capture': [],
      'document-domain': [],
      'encrypted-media': ['self'],
      'execution-while-not-rendered': ['self'],
      'execution-while-out-of-viewport': ['self'],
      fullscreen: ['self'],
      geolocation: [],
      gyroscope: [],
      'layout-animations': ['self'],
      'legacy-image-formats': [],
      magnetometer: [],
      microphone: [],
      midi: [],
      'navigation-override': [],
      'oversized-images': ['self'],
      payment: ['self', 'https://checkout.stripe.com'],
      'picture-in-picture': ['self'],
      'publickey-credentials-get': ['self'],
      'screen-wake-lock': [],
      'sync-xhr': [],
      usb: [],
      'web-share': ['self'],
      'xr-spatial-tracking': []
    };
    
    return Object.entries(policies)
      .map(([directive, allowList]) => {
        const value = allowList.length === 0 ? '()' : `(${allowList.join(' ')})`;
        return `${directive}=${value}`;
      })
      .join(', ');
  }
  
  /**
   * Create main security headers middleware
   * @returns {Function} Express middleware
   */
  createMiddleware() {
    // Configure helmet with custom options
    const helmetConfig = {
      contentSecurityPolicy: this.createCSPConfig(),
      
      crossOriginEmbedderPolicy: config.isProduction,
      
      crossOriginOpenerPolicy: {
        policy: 'same-origin'
      },
      
      crossOriginResourcePolicy: {
        policy: 'cross-origin'
      },
      
      dnsPrefetchControl: {
        allow: false
      },
      
      expectCt: config.isProduction ? {
        enforce: true,
        maxAge: 86400,
        reportUri: process.env.CT_REPORT_URI
      } : false,
      
      frameguard: {
        action: 'deny'
      },
      
      hidePoweredBy: true,
      
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      },
      
      ieNoOpen: true,
      
      noSniff: true,
      
      originAgentCluster: true,
      
      permittedCrossDomainPolicies: {
        permittedPolicies: 'none'
      },
      
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
      },
      
      xssFilter: true
    };
    
    return helmet(helmetConfig);
  }
  
  /**
   * Create nonce middleware for CSP
   * @returns {Function} Express middleware
   */
  createNonceMiddleware() {
    return (req, res, next) => {
      // Generate nonce for this request
      const nonce = this.generateNonce();
      
      // Store nonce in res.locals
      res.locals.nonce = nonce;
      
      // Override CSP header to include nonce
      const csp = res.getHeader('Content-Security-Policy') || 
                  res.getHeader('Content-Security-Policy-Report-Only') || '';
      
      if (csp) {
        const updatedCsp = csp.toString()
          .replace(/'unsafe-inline'/g, `'nonce-${nonce}'`);
        
        if (config.isDevelopment) {
          res.setHeader('Content-Security-Policy-Report-Only', updatedCsp);
        } else {
          res.setHeader('Content-Security-Policy', updatedCsp);
        }
      }
      
      next();
    };
  }
  
  /**
   * Create additional security headers middleware
   * @returns {Function} Express middleware
   */
  createAdditionalHeaders() {
    return (req, res, next) => {
      // Permissions Policy
      res.setHeader('Permissions-Policy', this.createPermissionsPolicy());
      
      // Additional security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
      
      // CORP headers for cross-origin isolation
      if (config.isProduction) {
        res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
        res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
        res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
      }
      
      // Report-To header for CSP and other reporting
      if (config.isProduction && process.env.REPORT_TO_ENDPOINT) {
        res.setHeader('Report-To', JSON.stringify({
          group: 'csp-endpoint',
          max_age: 10886400,
          endpoints: [{
            url: process.env.REPORT_TO_ENDPOINT
          }]
        }));
      }
      
      // Clear-Site-Data header for logout
      if (req.path === '/api/auth/logout' && req.method === 'POST') {
        res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"');
      }
      
      // Expect-CT for certificate transparency
      if (config.isProduction) {
        res.setHeader('Expect-CT', 'max-age=86400, enforce');
      }
      
      next();
    };
  }
  
  /**
   * Create API-specific security headers
   * @returns {Function} Express middleware
   */
  createAPIHeaders() {
    return (req, res, next) => {
      // API versioning header
      res.setHeader('X-API-Version', config.constants.API.VERSIONS.V1);
      
      // Rate limit headers (will be overridden by rate limiter)
      res.setHeader('X-RateLimit-Limit', '1000');
      res.setHeader('X-RateLimit-Remaining', '1000');
      res.setHeader('X-RateLimit-Reset', new Date(Date.now() + 3600000).toISOString());
      
      // Request ID header
      if (res.locals.requestId) {
        res.setHeader('X-Request-ID', res.locals.requestId);
      }
      
      // CORS headers for API
      if (req.path.startsWith('/api/')) {
        const origin = req.get('origin');
        
        if (this.isAllowedOrigin(origin)) {
          res.setHeader('Access-Control-Allow-Origin', origin);
          res.setHeader('Access-Control-Allow-Credentials', 'true');
          res.setHeader('Access-Control-Max-Age', '86400');
          res.setHeader('Vary', 'Origin');
        }
      }
      
      next();
    };
  }
  
  /**
   * Check if origin is allowed
   * @param {string} origin - Request origin
   * @returns {boolean} Is allowed
   */
  isAllowedOrigin(origin) {
    if (!origin) return false;
    
    try {
      const url = new URL(origin);
      return this.trustedHosts.includes(url.host) ||
             config.security.corsOrigins.includes(origin);
    } catch {
      return false;
    }
  }
  
  /**
   * Create security headers for file downloads
   * @returns {Function} Express middleware
   */
  createDownloadHeaders() {
    return (req, res, next) => {
      // Only apply to download routes
      if (!req.path.includes('/download/') && !req.path.includes('/export/')) {
        return next();
      }
      
      // Prevent XSS via file downloads
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Download-Options', 'noopen');
      res.setHeader('Content-Security-Policy', "default-src 'none'");
      res.setHeader('Content-Disposition', 'attachment');
      
      // Cache control for downloads
      res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      
      next();
    };
  }
  
  /**
   * Security headers error handler
   * @returns {Function} Express error middleware
   */
  createErrorHandler() {
    return (err, req, res, next) => {
      // Log CSP violations
      if (req.path === '/api/csp-report') {
        logger.warn('CSP Violation', {
          report: req.body,
          userAgent: req.get('user-agent'),
          ip: req.ip
        });
        return res.status(204).end();
      }
      
      // Log Expect-CT violations
      if (req.path === '/api/ct-report') {
        logger.error('Certificate Transparency Violation', {
          report: req.body,
          userAgent: req.get('user-agent'),
          ip: req.ip
        });
        return res.status(204).end();
      }
      
      next(err);
    };
  }
}

// Create singleton instance
const securityHeadersManager = new SecurityHeadersManager();

// Export middleware functions
module.exports = {
  // Main security headers middleware
  securityHeaders: securityHeadersManager.createMiddleware(),
  
  // Additional middleware
  nonceMiddleware: securityHeadersManager.createNonceMiddleware(),
  additionalHeaders: securityHeadersManager.createAdditionalHeaders(),
  apiHeaders: securityHeadersManager.createAPIHeaders(),
  downloadHeaders: securityHeadersManager.createDownloadHeaders(),
  errorHandler: securityHeadersManager.createErrorHandler(),
  
  // Combined middleware
  all: [
    securityHeadersManager.createMiddleware(),
    securityHeadersManager.createNonceMiddleware(),
    securityHeadersManager.createAdditionalHeaders(),
    securityHeadersManager.createAPIHeaders()
  ]
};