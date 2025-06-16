// /server/shared/middleware/request-logger.js

/**
 * @file Request Logger Middleware
 * @description Comprehensive request logging middleware
 * @version 1.0.0
 */

const morgan = require('morgan');
const onFinished = require('on-finished');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');

const config = require('../config');
const { sanitizeForLogging } = require('../security/services/encryption-service');
const logger = require('../utils/logger');

/**
 * Request Logger Class
 */
class RequestLogger {
  constructor() {
    this.skipPaths = [
      '/health',
      '/api/health',
      '/metrics',
      '/favicon.ico',
      '/robots.txt'
    ];
    
    this.sensitiveHeaders = [
      'authorization',
      'cookie',
      'x-api-key',
      'x-csrf-token'
    ];
    
    this.sensitiveFields = [
      'password',
      'token',
      'secret',
      'apiKey',
      'creditCard',
      'ssn'
    ];
  }
  
  /**
   * Create Morgan token definitions
   */
  setupMorganTokens() {
    // Request ID
    morgan.token('id', (req) => req.id);
    
    // User ID
    morgan.token('user-id', (req) => req.user?.id || 'anonymous');
    
    // Organization ID
    morgan.token('org-id', (req) => req.organizationId || '-');
    
    // Response time in milliseconds
    morgan.token('response-time-ms', (req, res) => {
      if (!req._startTime) return '-';
      const diff = process.hrtime(req._startTime);
      return Math.round(diff[0] * 1000 + diff[1] / 1000000);
    });
    
    // Request body size
    morgan.token('req-size', (req) => req.headers['content-length'] || '0');
    
    // Response body size
    morgan.token('res-size', (req, res) => res.get('content-length') || '0');
    
    // API version
    morgan.token('api-version', (req) => {
      const version = req.originalUrl.match(/\/api\/(v\d+)/);
      return version ? version[1] : '-';
    });
    
    // Client IP
    morgan.token('client-ip', (req) => {
      return req.ip || req.connection.remoteAddress;
    });
    
    // User agent
    morgan.token('user-agent-short', (req) => {
      const ua = req.get('user-agent');
      if (!ua) return '-';
      
      // Extract browser/app name
      const match = ua.match(/(Chrome|Safari|Firefox|Edge|Opera|Postman|Insomnia)\/[\d.]+/);
      return match ? match[1] : 'Other';
    });
  }
  
  /**
   * Create custom format string
   */
  getFormat(type = 'combined') {
    const formats = {
      tiny: ':method :url :status :response-time-ms ms',
      short: ':client-ip :method :url :status :response-time-ms ms - :res[content-length]',
      combined: ':id :client-ip :user-id ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time-ms ms',
      detailed: ':id :client-ip :user-id :org-id ":method :url HTTP/:http-version" :status :req-size :res-size ":referrer" ":user-agent-short" :response-time-ms ms :api-version',
      json: JSON.stringify({
        id: ':id',
        timestamp: ':date[iso]',
        method: ':method',
        url: ':url',
        status: ':status',
        responseTime: ':response-time-ms',
        clientIp: ':client-ip',
        userId: ':user-id',
        organizationId: ':org-id',
        userAgent: ':user-agent',
        apiVersion: ':api-version',
        requestSize: ':req-size',
        responseSize: ':res-size'
      })
    };
    
    return formats[type] || formats.combined;
  }
  
  /**
   * Create Morgan middleware
   */
  createMorganMiddleware(options = {}) {
    this.setupMorganTokens();
    
    const {
      format = config.isDevelopment ? 'short' : 'detailed',
      skip = (req) => this.shouldSkipLogging(req),
      stream = {
        write: (message) => logger.http(message.trim())
      }
    } = options;
    
    return morgan(this.getFormat(format), { skip, stream });
  }
  
  /**
   * Create custom logging middleware
   */
  createCustomMiddleware(options = {}) {
    return async (req, res, next) => {
      // Skip if should skip
      if (this.shouldSkipLogging(req)) {
        return next();
      }
      
      // Add request ID
      req.id = req.id || req.get('X-Request-ID') || uuidv4();
      res.set('X-Request-ID', req.id);
      
      // Start timer
      req._startTime = process.hrtime();
      req._startAt = Date.now();
      
      // Log request
      this.logRequest(req);
      
      // Capture original methods
      const originalSend = res.send;
      const originalJson = res.json;
      
      // Override send method
      res.send = function(data) {
        res._body = data;
        return originalSend.apply(res, arguments);
      };
      
      // Override json method
      res.json = function(data) {
        res._body = data;
        return originalJson.apply(res, arguments);
      };
      
      // Log response when finished
      onFinished(res, () => {
        this.logResponse(req, res);
      });
      
      next();
    };
  }
  
  /**
   * Log request details
   */
  logRequest(req) {
    const logData = {
      id: req.id,
      timestamp: new Date().toISOString(),
      type: 'request',
      method: req.method,
      url: req.originalUrl,
      path: req.path,
      query: this.sanitizeData(req.query),
      headers: this.sanitizeHeaders(req.headers),
      body: this.sanitizeData(req.body),
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent'),
      userId: req.user?.id,
      organizationId: req.organizationId,
      apiVersion: req.apiVersion
    };
    
    // Log level based on method
    const level = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? 'info' : 'debug';
    
    logger.log(level, 'Incoming request', logData);
  }
  
  /**
   * Log response details
   */
  logResponse(req, res) {
    const responseTime = this.calculateResponseTime(req._startTime);
    
    const logData = {
      id: req.id,
      timestamp: new Date().toISOString(),
      type: 'response',
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      statusMessage: res.statusMessage,
      responseTime: `${responseTime}ms`,
      responseSize: res.get('content-length') || 0,
      headers: this.sanitizeHeaders(res.getHeaders()),
      userId: req.user?.id,
      organizationId: req.organizationId
    };
    
    // Add error details if error response
    if (res.statusCode >= 400 && res._body) {
      try {
        const errorBody = typeof res._body === 'string' ? JSON.parse(res._body) : res._body;
        logData.error = errorBody.error || errorBody.message;
      } catch (e) {
        // Not JSON, ignore
      }
    }
    
    // Determine log level based on status code
    let level = 'info';
    if (res.statusCode >= 500) {
      level = 'error';
    } else if (res.statusCode >= 400) {
      level = 'warn';
    } else if (res.statusCode >= 300) {
      level = 'info';
    }
    
    logger.log(level, 'Request completed', logData);
    
    // Log slow requests
    if (responseTime > 1000) {
      logger.warn('Slow request detected', {
        id: req.id,
        url: req.originalUrl,
        responseTime: `${responseTime}ms`,
        threshold: '1000ms'
      });
    }
  }
  
  /**
   * Calculate response time
   */
  calculateResponseTime(startTime) {
    if (!startTime) return 0;
    const diff = process.hrtime(startTime);
    return Math.round(diff[0] * 1000 + diff[1] / 1000000);
  }
  
  /**
   * Check if should skip logging
   */
  shouldSkipLogging(req) {
    // Skip health checks and static files
    return this.skipPaths.some(path => req.path.startsWith(path));
  }
  
  /**
   * Sanitize headers for logging
   */
  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    
    this.sensitiveHeaders.forEach(header => {
      if (sanitized[header]) {
        sanitized[header] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }
  
  /**
   * Sanitize data for logging
   */
  sanitizeData(data) {
    if (!data || typeof data !== 'object') {
      return data;
    }
    
    return sanitizeForLogging(data, this.sensitiveFields);
  }
  
  /**
   * Create access log middleware
   */
  createAccessLogMiddleware() {
    const accessLogStream = winston.createLogger({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
      transports: [
        new winston.transports.File({
          filename: 'logs/access.log',
          maxsize: 10485760, // 10MB
          maxFiles: 5
        })
      ]
    });
    
    return morgan('combined', {
      stream: {
        write: (message) => accessLogStream.info(message.trim())
      }
    });
  }
  
  /**
   * Create error log middleware
   */
  createErrorLogMiddleware() {
    return (err, req, res, next) => {
      const errorData = {
        id: req.id,
        timestamp: new Date().toISOString(),
        type: 'error',
        method: req.method,
        url: req.originalUrl,
        status: err.status || 500,
        error: {
          message: err.message,
          stack: config.isDevelopment ? err.stack : undefined,
          code: err.code,
          details: err.details
        },
        userId: req.user?.id,
        organizationId: req.organizationId,
        ip: req.ip,
        userAgent: req.get('user-agent')
      };
      
      logger.error('Request error', errorData);
      
      next(err);
    };
  }
  
  /**
   * Create audit log middleware
   */
  createAuditLogMiddleware(options = {}) {
    const {
      events = ['POST', 'PUT', 'PATCH', 'DELETE'],
      excludePaths = ['/api/auth/refresh', '/api/health']
    } = options;
    
    return async (req, res, next) => {
      // Skip if not an auditable event
      if (!events.includes(req.method)) {
        return next();
      }
      
      // Skip excluded paths
      if (excludePaths.some(path => req.path.startsWith(path))) {
        return next();
      }
      
      // Store original methods
      const originalSend = res.send;
      const originalJson = res.json;
      
      // Override methods to capture response
      res.send = function(data) {
        res._auditData = data;
        return originalSend.apply(res, arguments);
      };
      
      res.json = function(data) {
        res._auditData = data;
        return originalJson.apply(res, arguments);
      };
      
      // Log audit event when finished
      onFinished(res, () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          this.logAuditEvent(req, res);
        }
      });
      
      next();
    };
  }
  
  /**
   * Log audit event
   */
  async logAuditEvent(req, res) {
    const auditData = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      requestId: req.id,
      userId: req.user?.id,
      userEmail: req.user?.email,
      organizationId: req.organizationId,
      action: `${req.method} ${req.path}`,
      resource: this.extractResource(req.path),
      resourceId: req.params.id,
      changes: req.body,
      result: res._auditData,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      status: 'success'
    };
    
    logger.info('Audit event', auditData);
    
    // Also save to audit log storage if configured
    if (config.features.auditLogStorage) {
      // Save to database or external service
    }
  }
  
  /**
   * Extract resource from path
   */
  extractResource(path) {
    const match = path.match(/\/api\/v\d+\/([^\/]+)/);
    return match ? match[1] : 'unknown';
  }
}

// Create singleton instance
const requestLogger = new RequestLogger();

module.exports = {
  // Main middleware
  morgan: requestLogger.createMorganMiddleware(),
  custom: requestLogger.createCustomMiddleware(),
  
  // Specialized middleware
  accessLog: requestLogger.createAccessLogMiddleware(),
  errorLog: requestLogger.createErrorLogMiddleware(),
  auditLog: requestLogger.createAuditLogMiddleware(),
  
  // Combined middleware
  all: [
    requestLogger.createCustomMiddleware(),
    requestLogger.createMorganMiddleware()
  ],
  
  // Instance for custom configuration
  RequestLogger
};