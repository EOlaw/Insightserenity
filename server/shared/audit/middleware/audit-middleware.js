/**
 * @file Audit Middleware
 * @description Express middleware for automatic audit logging
 * @version 1.0.0
 */

const AuditService = require('../services/audit-service');
const { AuditEventTypes } = require('../services/audit-event-types');
const logger = require('../../utils/logger');

/**
 * Audit configuration for routes
 */
const auditConfig = {
  // Authentication routes
  'POST /api/auth/login': {
    successEvent: AuditEventTypes.USER_LOGIN,
    failureEvent: AuditEventTypes.USER_LOGIN_FAILED,
    extractTarget: (req) => ({ type: 'user', id: req.body.email })
  },
  'POST /api/auth/logout': {
    successEvent: AuditEventTypes.USER_LOGOUT,
    extractTarget: (req) => ({ type: 'session', id: req.session?.id })
  },
  'POST /api/auth/password-reset': {
    successEvent: AuditEventTypes.PASSWORD_RESET_REQUESTED,
    extractTarget: (req) => ({ type: 'user', id: req.body.email })
  },
  
  // User management routes
  'POST /api/users': {
    successEvent: AuditEventTypes.USER_CREATED,
    extractTarget: (req, res) => ({ type: 'user', id: res.locals.createdUserId })
  },
  'PUT /api/users/:id': {
    successEvent: AuditEventTypes.USER_UPDATED,
    extractTarget: (req) => ({ type: 'user', id: req.params.id })
  },
  'DELETE /api/users/:id': {
    successEvent: AuditEventTypes.USER_DELETED,
    extractTarget: (req) => ({ type: 'user', id: req.params.id })
  },
  
  // Data access patterns
  'GET /api/*/export': {
    successEvent: AuditEventTypes.DATA_EXPORTED,
    extractTarget: (req) => ({ 
      type: req.path.split('/')[2], 
      id: 'bulk' 
    })
  },
  'GET /api/*/*': {
    successEvent: AuditEventTypes.DATA_VIEWED,
    skipAudit: (req) => req.method === 'GET' && !req.path.includes('sensitive')
  },
  'POST /api/*/*': {
    successEvent: AuditEventTypes.DATA_CREATED
  },
  'PUT /api/*/*': {
    successEvent: AuditEventTypes.DATA_UPDATED
  },
  'DELETE /api/*/*': {
    successEvent: AuditEventTypes.DATA_DELETED
  }
};

/**
 * Extract client information from request
 * @param {Object} req - Express request
 * @returns {Object} Client information
 */
function extractClientInfo(req) {
  return {
    ipAddress: req.ip || req.connection.remoteAddress,
    userAgent: req.get('user-agent'),
    sessionId: req.session?.id || req.get('x-session-id'),
    location: req.geoip || {} // If using geoip middleware
  };
}

/**
 * Extract actor information from request
 * @param {Object} req - Express request
 * @returns {Object} Actor information
 */
function extractActorInfo(req) {
  const user = req.user || {};
  return {
    userId: user._id || user.id,
    userEmail: user.email,
    userRole: user.role,
    organizationId: user.organizationId || req.organization?._id
  };
}

/**
 * Get audit configuration for route
 * @param {string} method - HTTP method
 * @param {string} path - Request path
 * @returns {Object|null} Audit configuration
 */
function getAuditConfig(method, path) {
  const routeKey = `${method} ${path}`;
  
  // Direct match
  if (auditConfig[routeKey]) {
    return auditConfig[routeKey];
  }
  
  // Pattern matching
  for (const [pattern, config] of Object.entries(auditConfig)) {
    const regex = new RegExp(
      '^' + pattern
        .replace(/\*/g, '[^/]+')
        .replace(/:\w+/g, '[^/]+') + '$'
    );
    
    if (regex.test(routeKey)) {
      return config;
    }
  }
  
  return null;
}

/**
 * Calculate response duration
 * @param {Array} startTime - Process.hrtime() result
 * @returns {number} Duration in milliseconds
 */
function calculateDuration(startTime) {
  const [seconds, nanoseconds] = process.hrtime(startTime);
  return seconds * 1000 + nanoseconds / 1000000;
}

/**
 * Extract changes from request
 * @param {Object} req - Express request
 * @param {Object} originalData - Original data before changes
 * @returns {Object} Changes object
 */
function extractChanges(req, originalData) {
  if (!originalData || !req.body) {
    return null;
  }
  
  const changes = {
    before: {},
    after: {},
    fields: []
  };
  
  // Compare fields
  const allKeys = new Set([
    ...Object.keys(originalData),
    ...Object.keys(req.body)
  ]);
  
  for (const key of allKeys) {
    if (originalData[key] !== req.body[key]) {
      changes.before[key] = originalData[key];
      changes.after[key] = req.body[key];
      changes.fields.push(key);
    }
  }
  
  return changes.fields.length > 0 ? changes : null;
}

/**
 * Main audit middleware
 * @param {Object} options - Middleware options
 * @returns {Function} Express middleware
 */
function auditMiddleware(options = {}) {
  const {
    enabled = true,
    skipRoutes = [],
    sensitiveFields = ['password', 'token', 'secret', 'key'],
    includeRequestBody = false,
    includeResponseBody = false
  } = options;
  
  return async (req, res, next) => {
    if (!enabled) {
      return next();
    }
    
    // Skip if route is in skip list
    if (skipRoutes.some(route => req.path.startsWith(route))) {
      return next();
    }
    
    // Get audit configuration for this route
    const config = getAuditConfig(req.method, req.path);
    if (!config || (config.skipAudit && config.skipAudit(req))) {
      return next();
    }
    
    // Start timing
    const startTime = process.hrtime();
    
    // Store original data for change tracking
    res.locals.auditOriginalData = null;
    
    // Override res.json to capture response
    const originalJson = res.json;
    res.json = function(data) {
      res.locals.responseData = data;
      return originalJson.call(this, data);
    };
    
    // Set up response handler
    res.on('finish', async () => {
      try {
        const duration = calculateDuration(startTime);
        const statusCode = res.statusCode;
        const isSuccess = statusCode >= 200 && statusCode < 400;
        
        // Determine event type
        const eventType = isSuccess 
          ? config.successEvent 
          : (config.failureEvent || config.successEvent);
        
        if (!eventType) return;
        
        // Build audit event
        const auditEvent = {
          type: eventType,
          action: eventType,
          result: isSuccess ? 'success' : 'failure',
          
          // Actor information
          ...extractActorInfo(req),
          ...extractClientInfo(req),
          
          // Target information
          target: config.extractTarget 
            ? config.extractTarget(req, res)
            : extractDefaultTarget(req),
          
          // Context
          endpoint: req.path,
          method: req.method,
          duration,
          statusCode,
          
          // Request ID for correlation
          requestId: req.id || req.get('x-request-id'),
          correlationId: req.correlationId || req.get('x-correlation-id'),
          
          // Source
          source: 'api'
        };
        
        // Add request body if configured (with sensitive field filtering)
        if (includeRequestBody && req.body) {
          auditEvent.requestBody = filterSensitiveData(req.body, sensitiveFields);
        }
        
        // Add response data if configured
        if (includeResponseBody && res.locals.responseData) {
          auditEvent.responseData = filterSensitiveData(
            res.locals.responseData, 
            sensitiveFields
          );
        }
        
        // Add changes if available
        if (res.locals.auditOriginalData) {
          auditEvent.changes = extractChanges(req, res.locals.auditOriginalData);
        }
        
        // Add error information for failures
        if (!isSuccess && res.locals.error) {
          auditEvent.error = {
            message: res.locals.error.message,
            code: res.locals.error.code
          };
        }
        
        // Log the audit event
        await AuditService.log(auditEvent);
        
      } catch (error) {
        logger.error('Audit middleware error', {
          error: error.message,
          path: req.path,
          method: req.method
        });
      }
    });
    
    next();
  };
}

/**
 * Extract default target from request
 * @param {Object} req - Express request
 * @returns {Object} Target information
 */
function extractDefaultTarget(req) {
  const pathParts = req.path.split('/').filter(Boolean);
  
  if (pathParts.length >= 3) {
    return {
      type: pathParts[1], // e.g., 'users', 'organizations'
      id: pathParts[2]
    };
  }
  
  return {
    type: pathParts[1] || 'unknown',
    id: req.params.id || 'unknown'
  };
}

/**
 * Filter sensitive data from object
 * @param {Object} data - Data to filter
 * @param {Array<string>} sensitiveFields - Fields to remove
 * @returns {Object} Filtered data
 */
function filterSensitiveData(data, sensitiveFields) {
  if (!data || typeof data !== 'object') {
    return data;
  }
  
  const filtered = Array.isArray(data) ? [...data] : { ...data };
  
  for (const field of sensitiveFields) {
    if (Array.isArray(filtered)) {
      filtered.forEach(item => {
        if (item && typeof item === 'object') {
          delete item[field];
        }
      });
    } else {
      delete filtered[field];
    }
  }
  
  return filtered;
}

/**
 * Middleware to capture original data for updates
 * @param {string} model - Model name
 * @param {string} idParam - Request parameter containing ID
 * @returns {Function} Express middleware
 */
function captureOriginalData(model, idParam = 'id') {
  return async (req, res, next) => {
    try {
      const Model = require(`../models/${model}.model`);
      const id = req.params[idParam];
      
      if (id && (req.method === 'PUT' || req.method === 'PATCH')) {
        const original = await Model.findById(id).lean();
        if (original) {
          res.locals.auditOriginalData = original;
        }
      }
      
      next();
    } catch (error) {
      logger.error('Failed to capture original data', {
        error: error.message,
        model,
        id: req.params[idParam]
      });
      next();
    }
  };
}

/**
 * Audit specific action middleware
 * @param {string} eventType - Event type to log
 * @param {Object} options - Additional options
 * @returns {Function} Express middleware
 */
function auditAction(eventType, options = {}) {
  return async (req, res, next) => {
    try {
      const auditEvent = {
        type: eventType,
        action: options.action || eventType,
        result: 'success',
        
        ...extractActorInfo(req),
        ...extractClientInfo(req),
        
        target: options.extractTarget 
          ? options.extractTarget(req, res)
          : extractDefaultTarget(req),
        
        endpoint: req.path,
        method: req.method,
        
        requestId: req.id || req.get('x-request-id'),
        source: 'api',
        
        ...options.additionalData
      };
      
      await AuditService.log(auditEvent);
      
    } catch (error) {
      logger.error('Audit action middleware error', {
        error: error.message,
        eventType
      });
    }
    
    next();
  };
}

module.exports = {
  auditMiddleware,
  captureOriginalData,
  auditAction,
  extractActorInfo,
  extractClientInfo
};