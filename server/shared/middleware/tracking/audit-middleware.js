/**
 * @file Audit Middleware
 * @description Audit logging middleware for compliance and security tracking
 * @version 1.0.0
 */

const auditService = require('../../security/services/audit-service');
const logger = require('../../utils/logger');

/**
 * Audit log middleware
 * Records user actions for compliance and security purposes
 */
const auditLog = (action, options = {}) => {
  return async (req, res, next) => {
    try {
      const {
        category = 'user_action',
        severity = 'medium',
        includeRequestBody = false,
        includeResponseBody = false,
        condition = () => true,
        extractTarget = (req) => ({
          type: extractResourceType(req.path),
          id: req.params.id,
          name: req.body?.name || req.params.id
        }),
        extractChanges = (req, res) => ({
          before: req.originalData || null,
          after: req.body || null,
          fields: req.body ? Object.keys(req.body) : []
        })
      } = options;

      // Check if audit logging should be applied
      if (!condition(req)) {
        return next();
      }

      // Store original response methods to capture data
      const originalJson = res.json;
      const originalSend = res.send;
      let responseData = null;

      // Override response methods if needed
      if (includeResponseBody) {
        res.json = function(data) {
          responseData = data;
          return originalJson.call(res, data);
        };

        res.send = function(data) {
          responseData = data;
          return originalSend.call(res, data);
        };
      }

      // Log audit event after response is sent
      res.on('finish', async () => {
        // Only log successful operations by default
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            const auditData = {
              type: action,
              category,
              action: `${req.method} ${req.path}`,
              result: 'success',
              severity,
              
              // Actor information
              userId: req.user?.id,
              userEmail: req.user?.email,
              userRole: req.user?.role?.primary,
              organizationId: req.user?.organizationId || req.organizationId,
              ipAddress: req.ip,
              userAgent: req.get('user-agent'),
              sessionId: req.sessionID,

              // Target information
              target: extractTarget(req),

              // Changes
              changes: extractChanges(req, res),

              // Request context
              metadata: {
                requestId: req.id,
                correlationId: req.correlationId,
                method: req.method,
                path: req.path,
                url: req.originalUrl,
                timestamp: new Date().toISOString(),
                environment: process.env.NODE_ENV
              }
            };

            // Include request body if specified
            if (includeRequestBody && req.body) {
              auditData.metadata.requestBody = sanitizeRequestBody(req.body);
            }

            // Include response body if specified
            if (includeResponseBody && responseData) {
              auditData.metadata.responseBody = sanitizeResponseBody(responseData);
            }

            // Add organization context if available
            if (req.organizationId || req.params.id) {
              auditData.target.organizationId = req.organizationId || req.params.id;
            }

            // Log the audit event
            await auditService.log(auditData);

            logger.debug('Audit event logged', {
              action,
              userId: req.user?.id,
              target: auditData.target,
              requestId: req.id
            });

          } catch (error) {
            logger.error('Audit logging error', {
              error: error.message,
              action,
              userId: req.user?.id,
              url: req.originalUrl
            });
          }
        } else {
          // Log failed operations with different result
          try {
            const auditData = {
              type: action,
              category: 'security',
              action: `${req.method} ${req.path}`,
              result: 'failure',
              severity: 'high',
              
              userId: req.user?.id,
              userEmail: req.user?.email,
              organizationId: req.user?.organizationId || req.organizationId,
              ipAddress: req.ip,
              userAgent: req.get('user-agent'),

              target: extractTarget(req),

              metadata: {
                requestId: req.id,
                statusCode: res.statusCode,
                method: req.method,
                path: req.path,
                url: req.originalUrl,
                timestamp: new Date().toISOString()
              }
            };

            await auditService.log(auditData);
          } catch (error) {
            logger.error('Failed operation audit logging error', {
              error: error.message,
              statusCode: res.statusCode
            });
          }
        }
      });

      next();
    } catch (error) {
      logger.error('Audit middleware error', {
        error: error.message,
        action,
        url: req.originalUrl
      });
      next(); // Continue without auditing on error
    }
  };
};

/**
 * Audit authentication events
 */
const auditAuth = (action, options = {}) => {
  return auditLog(action, {
    category: 'authentication',
    severity: 'medium',
    extractTarget: (req) => ({
      type: 'user',
      id: req.user?.id || req.body?.email,
      name: req.user?.email || req.body?.email
    }),
    ...options
  });
};

/**
 * Audit authorization events
 */
const auditAuthz = (action, options = {}) => {
  return auditLog(action, {
    category: 'authorization',
    severity: 'medium',
    extractTarget: (req) => ({
      type: extractResourceType(req.path),
      id: req.params.id,
      name: req.params.id
    }),
    ...options
  });
};

/**
 * Audit data modification events
 */
const auditDataChange = (action, options = {}) => {
  return auditLog(action, {
    category: 'data_modification',
    severity: 'medium',
    includeRequestBody: true,
    extractChanges: (req, res) => {
      const fields = req.body ? Object.keys(req.body) : [];
      return {
        before: req.originalData || null,
        after: req.body || null,
        fields
      };
    },
    ...options
  });
};

/**
 * Audit security events
 */
const auditSecurity = (action, options = {}) => {
  return auditLog(action, {
    category: 'security',
    severity: 'high',
    includeRequestBody: true,
    ...options
  });
};

/**
 * Audit compliance events
 */
const auditCompliance = (action, options = {}) => {
  return auditLog(action, {
    category: 'compliance',
    severity: 'high',
    includeRequestBody: true,
    includeResponseBody: true,
    ...options
  });
};

/**
 * Extract resource type from URL path
 */
function extractResourceType(path) {
  const match = path.match(/\/api\/v\d+\/([^\/]+)/);
  if (match) {
    return match[1].replace(/s$/, ''); // Remove plural 's'
  }
  
  // Handle nested resources
  const segments = path.split('/').filter(segment => segment && !segment.match(/^v\d+$/) && segment !== 'api');
  return segments[0] || 'unknown';
}

/**
 * Sanitize request body for audit logging
 */
function sanitizeRequestBody(body) {
  const sanitized = { ...body };
  
  // Remove sensitive fields
  const sensitiveFields = ['password', 'secret', 'token', 'apiKey', 'privateKey'];
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  return sanitized;
}

/**
 * Sanitize response body for audit logging
 */
function sanitizeResponseBody(body) {
  if (typeof body !== 'object' || !body) {
    return body;
  }

  const sanitized = { ...body };
  
  // Remove sensitive fields from response
  const sensitiveFields = ['password', 'secret', 'token', 'apiKey', 'privateKey'];
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
    
    // Handle nested data
    if (sanitized.data && typeof sanitized.data === 'object') {
      if (sanitized.data[field]) {
        sanitized.data[field] = '[REDACTED]';
      }
    }
  });

  return sanitized;
}

/**
 * Store original data middleware
 * Captures the current state before modifications for audit trails
 */
const storeOriginalData = (Model, keyField = 'id') => {
  return async (req, res, next) => {
    try {
      if (req.params[keyField] && (req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE')) {
        const originalData = await Model.findById(req.params[keyField]).lean();
        req.originalData = originalData;
      }
      next();
    } catch (error) {
      logger.error('Store original data error', {
        error: error.message,
        model: Model.modelName,
        id: req.params[keyField]
      });
      next(); // Continue without storing original data on error
    }
  };
};

module.exports = {
  auditLog,
  auditAuth,
  auditAuthz,
  auditDataChange,
  auditSecurity,
  auditCompliance,
  storeOriginalData
};