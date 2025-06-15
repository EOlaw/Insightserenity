// /server/shared/utils/helpers/response-helper.js

/**
 * @file Response Helper
 * @description Standardized API response utilities
 * @version 1.0.0
 */

const constants = require('../../config/constants');
const logger = require('../logger');

/**
 * Response Helper Class
 */
class ResponseHelper {
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
      data,
      ...meta,
      timestamp: new Date().toISOString()
    };
    
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
  static error(res, message = 'An error occurred', statusCode = 500, code = null, details = null) {
    const response = {
      success: false,
      error: {
        message,
        code: code || `E${statusCode}`,
        ...(details && { details })
      },
      timestamp: new Date().toISOString()
    };
    
    // Log error if it's a server error
    if (statusCode >= 500) {
      logger.error('Server error response:', response);
    }
    
    return res.status(statusCode).json(response);
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
      value: error.value,
      location: error.location
    }));
    
    return this.error(res, message, 400, constants.ERROR_CODES.VALIDATION_FAILED, formattedErrors);
  }
  
  /**
   * Send unauthorized response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {string} code - Error code
   */
  static unauthorized(res, message = 'Authentication required', code = constants.ERROR_CODES.INVALID_CREDENTIALS) {
    return this.error(res, message, 401, code);
  }
  
  /**
   * Send forbidden response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {string} code - Error code
   */
  static forbidden(res, message = 'Access denied', code = constants.ERROR_CODES.INSUFFICIENT_PERMISSIONS) {
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
    return this.error(res, message, 404, constants.ERROR_CODES.RESOURCE_NOT_FOUND);
  }
  
  /**
   * Send conflict response
   * @param {Object} res - Express response object
   * @param {string} message - Error message
   * @param {string} field - Conflicting field
   */
  static conflict(res, message = 'Resource already exists', field = null) {
    const details = field ? { field, reason: 'duplicate' } : null;
    return this.error(res, message, 409, constants.ERROR_CODES.DUPLICATE_ENTRY, details);
  }
  
  /**
   * Send rate limit response
   * @param {Object} res - Express response object
   * @param {number} retryAfter - Retry after seconds
   * @param {string} message - Error message
   */
  static tooManyRequests(res, retryAfter = 60, message = 'Too many requests') {
    res.set('Retry-After', retryAfter);
    return this.error(res, message, 429, 'RATE_LIMIT_EXCEEDED', {
      retryAfter,
      retryAfterDate: new Date(Date.now() + retryAfter * 1000).toISOString()
    });
  }
  
  /**
   * Send paginated response
   * @param {Object} res - Express response object
   * @param {Array} data - Data array
   * @param {Object} pagination - Pagination info
   * @param {string} message - Success message
   */
  static paginated(res, data, pagination, message = 'Success') {
    const {
      page = 1,
      limit = 20,
      total = 0,
      totalPages = 0
    } = pagination;
    
    const meta = {
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(total),
        totalPages: parseInt(totalPages),
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    };
    
    // Add pagination headers
    res.set({
      'X-Total-Count': total.toString(),
      'X-Page-Count': totalPages.toString(),
      'X-Current-Page': page.toString(),
      'X-Per-Page': limit.toString()
    });
    
    return this.success(res, data, message, 200, meta);
  }
  
  /**
   * Send file response
   * @param {Object} res - Express response object
   * @param {Buffer|Stream} file - File content
   * @param {string} filename - File name
   * @param {string} contentType - Content type
   * @param {Object} options - Additional options
   */
  static file(res, file, filename, contentType, options = {}) {
    const {
      inline = false,
      cache = true
    } = options;
    
    // Set headers
    res.set({
      'Content-Type': contentType,
      'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename="${filename}"`,
      'X-Content-Type-Options': 'nosniff'
    });
    
    if (cache) {
      res.set({
        'Cache-Control': 'private, max-age=86400',
        'ETag': `"${require('crypto').createHash('md5').update(filename).digest('hex')}"`
      });
    } else {
      res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      });
    }
    
    return res.send(file);
  }
  
  /**
   * Send streaming response
   * @param {Object} res - Express response object
   * @param {Stream} stream - Data stream
   * @param {string} contentType - Content type
   * @param {Object} options - Additional options
   */
  static stream(res, stream, contentType = 'application/octet-stream', options = {}) {
    const {
      filename,
      contentLength
    } = options;
    
    // Set headers
    res.set({
      'Content-Type': contentType,
      'Transfer-Encoding': 'chunked',
      'X-Content-Type-Options': 'nosniff'
    });
    
    if (filename) {
      res.set('Content-Disposition', `attachment; filename="${filename}"`);
    }
    
    if (contentLength) {
      res.set('Content-Length', contentLength.toString());
    }
    
    // Handle stream errors
    stream.on('error', (error) => {
      logger.error('Stream error:', error);
      if (!res.headersSent) {
        this.error(res, 'Stream error occurred', 500);
      }
    });
    
    // Pipe stream to response
    stream.pipe(res);
  }
  
  /**
   * Send accepted response (for async operations)
   * @param {Object} res - Express response object
   * @param {Object} data - Response data with operation ID
   * @param {string} message - Success message
   */
  static accepted(res, data, message = 'Request accepted for processing') {
    const response = {
      operationId: data.operationId || data.id,
      statusUrl: data.statusUrl,
      estimatedCompletionTime: data.estimatedCompletionTime
    };
    
    return this.success(res, response, message, 202);
  }
  
  /**
   * Send partial content response
   * @param {Object} res - Express response object
   * @param {any} data - Partial data
   * @param {Object} range - Range information
   */
  static partialContent(res, data, range) {
    const { start, end, total } = range;
    
    res.set({
      'Content-Range': `bytes ${start}-${end}/${total}`,
      'Accept-Ranges': 'bytes',
      'Content-Length': (end - start + 1).toString()
    });
    
    return res.status(206).send(data);
  }
  
  /**
   * Send redirect response
   * @param {Object} res - Express response object
   * @param {string} url - Redirect URL
   * @param {boolean} permanent - Is permanent redirect
   */
  static redirect(res, url, permanent = false) {
    return res.redirect(permanent ? 301 : 302, url);
  }
  
  /**
   * Send custom response
   * @param {Object} res - Express response object
   * @param {number} statusCode - HTTP status code
   * @param {Object} body - Response body
   * @param {Object} headers - Additional headers
   */
  static custom(res, statusCode, body, headers = {}) {
    Object.entries(headers).forEach(([key, value]) => {
      res.set(key, value);
    });
    
    return res.status(statusCode).json(body);
  }
  
  /**
   * Handle async route errors
   * @param {Function} fn - Async route handler
   * @returns {Function} Wrapped route handler
   */
  static asyncHandler(fn) {
    return (req, res, next) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }
  
  /**
   * Create response handler middleware
   * @returns {Function} Express middleware
   */
  static middleware() {
    return (req, res, next) => {
      // Attach response methods to res object
      res.success = (data, message, meta) => this.success(res, data, message, 200, meta);
      res.created = (data, message, meta) => this.created(res, data, message, meta);
      res.updated = (data, message, meta) => this.updated(res, data, message, meta);
      res.deleted = (message, meta) => this.deleted(res, message, meta);
      res.noContent = () => this.noContent(res);
      res.error = (message, statusCode, code, details) => this.error(res, message, statusCode, code, details);
      res.validationError = (errors, message) => this.validationError(res, errors, message);
      res.unauthorized = (message, code) => this.unauthorized(res, message, code);
      res.forbidden = (message, code) => this.forbidden(res, message, code);
      res.notFound = (resource, id) => this.notFound(res, resource, id);
      res.conflict = (message, field) => this.conflict(res, message, field);
      res.tooManyRequests = (retryAfter, message) => this.tooManyRequests(res, retryAfter, message);
      res.paginated = (data, pagination, message) => this.paginated(res, data, pagination, message);
      res.accepted = (data, message) => this.accepted(res, data, message);
      
      next();
    };
  }
}

module.exports = ResponseHelper;