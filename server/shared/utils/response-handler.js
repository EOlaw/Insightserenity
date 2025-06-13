// server/shared/utils/response-handler.js
/**
 * @file Response Handler Utility
 * @description Standardized API response formatting and handling
 * @version 3.0.0
 */

const logger = require('./logger');

/**
 * Response Handler Class
 * @class ResponseHandler
 */
class ResponseHandler {
  /**
   * Send success response
   * @param {Object} res - Express response object
   * @param {any} data - Response data
   * @param {string} message - Success message
   * @param {number} statusCode - HTTP status code
   * @param {Object} meta - Additional metadata
   */
  static success(res, data = null, message = 'Success', statusCode = 200, meta = {}) {
    const response = {
      success: true,
      message,
      data
    };
    
    // Add metadata if provided
    if (Object.keys(meta).length > 0) {
      response.meta = meta;
    }
    
    // Add request ID if available
    if (res.locals.requestId) {
      response.requestId = res.locals.requestId;
    }
    
    // Log successful response
    logger.debug('API Response', {
      statusCode,
      message,
      requestId: res.locals.requestId,
      userId: res.locals.user?.id
    });
    
    return res.status(statusCode).json(response);
  }
  
  /**
   * Send error response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {number} statusCode - HTTP status code
   * @param {string} code - Error code
   * @param {any} details - Error details
   */
  static error(res, message = 'An error occurred', statusCode = 500, code = 'ERROR', details = null) {
    const response = {
      success: false,
      error: {
        message,
        code
      }
    };
    
    // Add error details if provided
    if (details) {
      response.error.details = details;
    }
    
    // Add request ID if available
    if (res.locals.requestId) {
      response.requestId = res.locals.requestId;
    }
    
    // Log error response
    logger.warn('API Error Response', {
      statusCode,
      message,
      code,
      requestId: res.locals.requestId,
      userId: res.locals.user?.id
    });
    
    return res.status(statusCode).json(response);
  }
  
  /**
   * Send paginated response
   * @param {Object} res - Express response object
   * @param {Array} data - Array of items
   * @param {Object} pagination - Pagination details
   * @param {string} message - Success message
   * @param {Object} additionalMeta - Additional metadata
   */
  static paginated(res, data, pagination, message = 'Success', additionalMeta = {}) {
    const {
      page = 1,
      limit = 20,
      total = 0,
      pages = 1
    } = pagination;
    
    const meta = {
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(total),
        pages: parseInt(pages),
        hasNext: page < pages,
        hasPrev: page > 1
      },
      ...additionalMeta
    };
    
    return this.success(res, data, message, 200, meta);
  }
  
  /**
   * Send created response
   * @param {Object} res - Express response object
   * @param {any} data - Created resource data
   * @param {string} message - Success message
   * @param {Object} meta - Additional metadata
   */
  static created(res, data, message = 'Resource created successfully', meta = {}) {
    return this.success(res, data, message, 201, meta);
  }
  
  /**
   * Send updated response
   * @param {Object} res - Express response object
   * @param {any} data - Updated resource data
   * @param {string} message - Success message
   * @param {Object} meta - Additional metadata
   */
  static updated(res, data, message = 'Resource updated successfully', meta = {}) {
    return this.success(res, data, message, 200, meta);
  }
  
  /**
   * Send deleted response
   * @param {Object} res - Express response object
   * @param {string} message - Success message
   * @param {Object} meta - Additional metadata
   */
  static deleted(res, message = 'Resource deleted successfully', meta = {}) {
    return this.success(res, null, message, 200, meta);
  }
  
  /**
   * Send no content response
   * @param {Object} res - Express response object
   */
  static noContent(res) {
    return res.status(204).send();
  }
  
  /**
   * Send validation error response
   * @param {Object} res - Express response object
   * @param {Array} errors - Validation errors
   * @param {string} message - Error message
   */
  static validationError(res, errors, message = 'Validation failed') {
    const formattedErrors = errors.map(error => ({
      field: error.param || error.field,
      message: error.msg || error.message,
      value: error.value
    }));
    
    return this.error(res, message, 400, 'VALIDATION_ERROR', formattedErrors);
  }
  
  /**
   * Send unauthorized response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {string} code - Error code
   */
  static unauthorized(res, message = 'Authentication required', code = 'UNAUTHORIZED') {
    return this.error(res, message, 401, code);
  }
  
  /**
   * Send forbidden response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {string} code - Error code
   */
  static forbidden(res, message = 'Access denied', code = 'FORBIDDEN') {
    return this.error(res, message, 403, code);
  }
  
  /**
   * Send not found response
   * @param {Object} res - Express response object
   * @param {string} resource - Resource type
   * @param {string} id - Resource ID
   */
  static notFound(res, resource = 'Resource', id = null) {
    const message = id ? `${resource} with ID ${id} not found` : `${resource} not found`;
    return this.error(res, message, 404, 'NOT_FOUND');
  }
  
  /**
   * Send conflict response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {string} field - Conflicting field
   */
  static conflict(res, message = 'Resource already exists', field = null) {
    const details = field ? { field } : null;
    return this.error(res, message, 409, 'CONFLICT', details);
  }
  
  /**
   * Send too many requests response
   * @param {Object} res - Express response object
   * @param {number} retryAfter - Retry after seconds
   * @param {string} message - Error message
   */
  static tooManyRequests(res, retryAfter = null, message = 'Too many requests') {
    if (retryAfter) {
      res.set('Retry-After', retryAfter);
    }
    return this.error(res, message, 429, 'RATE_LIMIT_EXCEEDED', { retryAfter });
  }
  
  /**
   * Send server error response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {Error} error - Original error object
   */
  static serverError(res, message = 'Internal server error', error = null) {
    // Log the actual error
    if (error) {
      logger.error('Server Error', {
        message: error.message,
        stack: error.stack,
        requestId: res.locals.requestId,
        userId: res.locals.user?.id
      });
    }
    
    // Don't expose internal error details in production
    const errorMessage = process.env.NODE_ENV === 'production' ? 
      'Internal server error' : 
      message;
    
    return this.error(res, errorMessage, 500, 'SERVER_ERROR');
  }
  
  /**
   * Send file response
   * @param {Object} res - Express response object
   * @param {Buffer|Stream} file - File buffer or stream
   * @param {string} filename - File name
   * @param {string} contentType - MIME type
   * @param {Object} options - Additional options
   */
  static file(res, file, filename, contentType, options = {}) {
    const {
      inline = false,
      cache = true,
      maxAge = 86400 // 1 day
    } = options;
    
    // Set headers
    res.set({
      'Content-Type': contentType,
      'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="${filename}"`,
      'X-Content-Type-Options': 'nosniff'
    });
    
    // Set cache headers
    if (cache) {
      res.set({
        'Cache-Control': `private, max-age=${maxAge}`,
        'Expires': new Date(Date.now() + maxAge * 1000).toUTCString()
      });
    } else {
      res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      });
    }
    
    // Send file
    if (Buffer.isBuffer(file)) {
      res.send(file);
    } else {
      // Assume it's a stream
      file.pipe(res);
    }
  }
  
  /**
   * Send CSV response
   * @param {Object} res - Express response object
   * @param {Array} data - Data array
   * @param {string} filename - CSV filename
   * @param {Array} headers - CSV headers
   */
  static csv(res, data, filename = 'export.csv', headers = null) {
    const csv = require('csv-stringify');
    
    res.set({
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'X-Content-Type-Options': 'nosniff'
    });
    
    const stringifier = csv({
      header: true,
      columns: headers
    });
    
    stringifier.pipe(res);
    
    data.forEach(row => stringifier.write(row));
    stringifier.end();
  }
  
  /**
   * Send JSON file download response
   * @param {Object} res - Express response object
   * @param {Object} data - JSON data
   * @param {string} filename - JSON filename
   */
  static jsonFile(res, data, filename = 'export.json') {
    const jsonString = JSON.stringify(data, null, 2);
    const buffer = Buffer.from(jsonString, 'utf-8');
    
    return this.file(res, buffer, filename, 'application/json', {
      inline: false,
      cache: false
    });
  }
  
  /**
   * Send redirect response
   * @param {Object} res - Express response object
   * @param {string} url - Redirect URL
   * @param {number} statusCode - HTTP status code (301 or 302)
   */
  static redirect(res, url, statusCode = 302) {
    logger.debug('Redirect Response', {
      url,
      statusCode,
      requestId: res.locals.requestId
    });
    
    return res.redirect(statusCode, url);
  }
  
  /**
   * Send health check response
   * @param {Object} res - Express response object
   * @param {Object} health - Health status object
   */
  static health(res, health) {
    const statusCode = health.status === 'healthy' ? 200 : 503;
    
    return res.status(statusCode).json({
      status: health.status,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      services: health.services || {},
      version: process.env.APP_VERSION || '1.0.0'
    });
  }
  
  /**
   * Create response middleware
   * @returns {Function} Express middleware
   */
  static middleware() {
    return (req, res, next) => {
      // Attach response methods to res object
      res.success = (data, message, meta) => 
        this.success(res, data, message, 200, meta);
      
      res.created = (data, message, meta) => 
        this.created(res, data, message, meta);
      
      res.updated = (data, message, meta) => 
        this.updated(res, data, message, meta);
      
      res.deleted = (message, meta) => 
        this.deleted(res, message, meta);
      
      res.paginated = (data, pagination, message, meta) => 
        this.paginated(res, data, pagination, message, meta);
      
      res.validationError = (errors, message) => 
        this.validationError(res, errors, message);
      
      res.unauthorized = (message, code) => 
        this.unauthorized(res, message, code);
      
      res.forbidden = (message, code) => 
        this.forbidden(res, message, code);
      
      res.notFound = (resource, id) => 
        this.notFound(res, resource, id);
      
      res.conflict = (message, field) => 
        this.conflict(res, message, field);
      
      res.serverError = (message, error) => 
        this.serverError(res, message, error);
      
      next();
    };
  }
}

// Export response handler and individual methods
module.exports = ResponseHandler;