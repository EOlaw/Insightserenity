// /server/shared/middleware/error-handler.js

/**
 * @file Error Handler Middleware
 * @description Global error handling middleware with ResponseHelper integration
 * @version 1.1.0
 */

const config = require('../config');
const logger = require('../utils/logger');
const { AppError } = require('../utils/app-error');
const ResponseHelper = require('../utils/helpers/response-helper');
const errorCodes = require('../utils/constants/error-codes');

/**
 * Error Handler Class
 */
class ErrorHandler {
  constructor() {
    this.isDevelopment = config.isDevelopment;
    this.isProduction = config.isProduction;
    
    // Error type handlers
    this.errorHandlers = new Map([
      ['ValidationError', this.handleValidationError],
      ['CastError', this.handleCastError],
      ['MongoError', this.handleMongoError],
      ['JsonWebTokenError', this.handleJWTError],
      ['TokenExpiredError', this.handleJWTError],
      ['MulterError', this.handleMulterError],
      ['AxiosError', this.handleAxiosError]
    ]);
  }
  
  /**
   * Main error handling middleware
   */
  handle() {
    return (err, req, res, next) => {
      // Don't handle if response already sent
      if (res.headersSent) {
        return next(err);
      }
      
      // Log error
      this.logError(err, req);
      
      // Process error
      const processedError = this.processError(err);
      
      // Send error response using ResponseHelper
      this.sendErrorResponse(processedError, req, res);
    };
  }
  
  /**
   * Process error based on type
   */
  processError(err) {
    // If already an AppError, return as is
    if (err instanceof AppError) {
      return err;
    }
    
    // Check for specific error handlers
    const handler = this.errorHandlers.get(err.constructor.name);
    if (handler) {
      return handler.call(this, err);
    }
    
    // Check for common error patterns
    if (err.name === 'ValidationError') {
      return this.handleValidationError(err);
    }
    
    if (err.name === 'CastError') {
      return this.handleCastError(err);
    }
    
    if (err.code === 11000) {
      return this.handleDuplicateKeyError(err);
    }
    
    // Default to internal server error
    return new AppError(
      this.isProduction ? 'Something went wrong' : err.message,
      500,
      errorCodes.SYSTEM.INTERNAL_SERVER_ERROR
    );
  }
  
  /**
   * Handle validation errors
   */
  handleValidationError(err) {
    const errors = [];
    
    // Mongoose validation error
    if (err.errors) {
      Object.values(err.errors).forEach(error => {
        errors.push({
          field: error.path,
          message: error.message,
          value: error.value
        });
      });
    }
    
    // Joi validation error
    if (err.details) {
      err.details.forEach(detail => {
        errors.push({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context.value
        });
      });
    }
    
    return new AppError(
      'Validation failed',
      400,
      errorCodes.VALIDATION.VALIDATION_FAILED,
      errors
    );
  }
  
  /**
   * Handle cast errors (invalid ObjectId, etc.)
   */
  handleCastError(err) {
    const message = `Invalid ${err.path}: ${err.value}`;
    return new AppError(
      message,
      400,
      errorCodes.VALIDATION.INVALID_FORMAT
    );
  }
  
  /**
   * Handle MongoDB errors
   */
  handleMongoError(err) {
    // Duplicate key error
    if (err.code === 11000) {
      return this.handleDuplicateKeyError(err);
    }
    
    // Other MongoDB errors
    return new AppError(
      'Database operation failed',
      500,
      errorCodes.SYSTEM.DATABASE_ERROR
    );
  }
  
  /**
   * Handle duplicate key errors
   */
  handleDuplicateKeyError(err) {
    const field = Object.keys(err.keyValue)[0];
    const message = `${field} already exists`;
    
    return new AppError(
      message,
      409,
      errorCodes.BUSINESS.DUPLICATE_ENTRY,
      { field, value: err.keyValue[field] }
    );
  }
  
  /**
   * Handle JWT errors
   */
  handleJWTError(err) {
    if (err.name === 'JsonWebTokenError') {
      return new AppError(
        'Invalid token',
        401,
        errorCodes.AUTH.TOKEN_INVALID
      );
    }
    
    if (err.name === 'TokenExpiredError') {
      return new AppError(
        'Token has expired',
        401,
        errorCodes.AUTH.TOKEN_EXPIRED
      );
    }
    
    return new AppError(
      'Authentication failed',
      401,
      errorCodes.AUTH.INVALID_CREDENTIALS
    );
  }
  
  /**
   * Handle Multer errors
   */
  handleMulterError(err) {
    const errorMap = {
      'LIMIT_FILE_SIZE': {
        message: 'File too large',
        code: errorCodes.FILE.FILE_TOO_LARGE
      },
      'LIMIT_FILE_COUNT': {
        message: 'Too many files',
        code: errorCodes.FILE.FILE_UPLOAD_FAILED
      },
      'LIMIT_FIELD_KEY': {
        message: 'Field name too long',
        code: errorCodes.VALIDATION.LENGTH_EXCEEDED
      },
      'LIMIT_FIELD_VALUE': {
        message: 'Field value too long',
        code: errorCodes.VALIDATION.LENGTH_EXCEEDED
      },
      'LIMIT_UNEXPECTED_FILE': {
        message: 'Unexpected file field',
        code: errorCodes.FILE.FILE_UPLOAD_FAILED
      }
    };
    
    const error = errorMap[err.code] || {
      message: 'File upload failed',
      code: errorCodes.FILE.FILE_UPLOAD_FAILED
    };
    
    return new AppError(error.message, 400, error.code);
  }
  
  /**
   * Handle Axios errors
   */
  handleAxiosError(err) {
    if (err.response) {
      // Request made and server responded with error
      return new AppError(
        err.response.data?.message || 'External service error',
        err.response.status,
        errorCodes.EXTERNAL.EXTERNAL_SERVICE_ERROR
      );
    } else if (err.request) {
      // Request made but no response received
      return new AppError(
        'External service not responding',
        503,
        errorCodes.EXTERNAL.EXTERNAL_SERVICE_UNAVAILABLE
      );
    } else {
      // Something else happened
      return new AppError(
        'External service request failed',
        500,
        errorCodes.EXTERNAL.EXTERNAL_SERVICE_ERROR
      );
    }
  }
  
  /**
   * Log error details
   */
  logError(err, req) {
    const errorData = {
      id: req.id,
      timestamp: new Date().toISOString(),
      error: {
        name: err.name,
        message: err.message,
        code: err.code,
        statusCode: err.statusCode || 500,
        stack: err.stack
      },
      request: {
        method: req.method,
        url: req.originalUrl,
        headers: this.sanitizeHeaders(req.headers),
        body: this.sanitizeBody(req.body),
        query: req.query,
        params: req.params
      },
      user: {
        id: req.user?.id,
        email: req.user?.email,
        role: req.user?.role
      },
      context: {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        organizationId: req.organizationId
      }
    };
    
    // Log based on error severity
    if (err.statusCode >= 500 || !err.statusCode) {
      logger.error('Unhandled error', errorData);
    } else {
      logger.warn('Request error', errorData);
    }
  }
  
  /**
   * Sanitize sensitive headers for logging
   */
  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];
    
    sensitiveHeaders.forEach(header => {
      if (sanitized[header]) {
        sanitized[header] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }
  
  /**
   * Sanitize sensitive body data for logging
   */
  sanitizeBody(body) {
    if (!body || typeof body !== 'object') return body;
    
    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'authorization'];
    
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });
    
    return sanitized;
  }
  
  /**
   * Send error response using ResponseHelper
   */
  sendErrorResponse(error, req, res) {
    const statusCode = error.statusCode || 500;
    const errorCode = error.code || `E${statusCode}`;
    
    // Prepare additional details for development environment
    const details = {
      ...(error.details && { details: error.details }),
      ...(this.isDevelopment && {
        stack: error.stack,
        originalError: {
          name: error.name,
          message: error.message
        }
      }),
      path: req.originalUrl,
      requestId: req.id,
      timestamp: new Date().toISOString()
    };
    
    // Use ResponseHelper for consistent error responses
    return ResponseHelper.error(res, error.message, statusCode, errorCode, details);
  }
  
  /**
   * Not found handler using ResponseHelper
   */
  notFound() {
    return (req, res, next) => {
      const message = `Cannot ${req.method} ${req.originalUrl}`;
      const details = {
        method: req.method,
        path: req.originalUrl,
        timestamp: new Date().toISOString(),
        requestId: req.id
      };
      
      // Use ResponseHelper for consistent 404 responses
      return ResponseHelper.notFound(res, 'Route', req.originalUrl);
    };
  }
  
  /**
   * Async handler wrapper
   */
  asyncHandler(fn) {
    return (req, res, next) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }
  
  /**
   * Create error boundary middleware
   */
  errorBoundary() {
    return async (err, req, res, next) => {
      try {
        this.handle()(err, req, res, next);
      } catch (handlerError) {
        // If error handler itself fails, send basic error response using ResponseHelper
        logger.error('Error handler failed', {
          originalError: err,
          handlerError: handlerError,
          requestId: req.id
        });
        
        // Fallback to ResponseHelper for consistent error format
        return ResponseHelper.error(
          res,
          'Internal server error occurred while processing error',
          500,
          'HANDLER_ERROR'
        );
      }
    };
  }
  
  /**
   * Validation error formatter for express-validator
   */
  validationFormatter({ location, msg, param, value, nestedErrors }) {
    return {
      field: param,
      message: msg,
      location,
      value,
      ...(nestedErrors && { errors: nestedErrors })
    };
  }
  
  /**
   * Handle express-validator errors specifically
   */
  handleValidationErrors() {
    return (req, res, next) => {
      const { validationResult } = require('express-validator');
      const errors = validationResult(req);
      
      if (!errors.isEmpty()) {
        const formattedErrors = errors.array().map(this.validationFormatter);
        return ResponseHelper.validationError(res, formattedErrors);
      }
      
      next();
    };
  }
  
  /**
   * Create error for specific scenarios using ResponseHelper patterns
   */
  static createError(type, details = {}) {
    const errorTemplates = {
      unauthorized: {
        message: 'Authentication required',
        statusCode: 401,
        code: errorCodes.AUTH.INVALID_CREDENTIALS
      },
      forbidden: {
        message: 'Access denied',
        statusCode: 403,
        code: errorCodes.AUTH.INSUFFICIENT_PERMISSIONS
      },
      notFound: {
        message: 'Resource not found',
        statusCode: 404,
        code: errorCodes.BUSINESS.RESOURCE_NOT_FOUND
      },
      conflict: {
        message: 'Resource already exists',
        statusCode: 409,
        code: errorCodes.BUSINESS.DUPLICATE_ENTRY
      },
      tooManyRequests: {
        message: 'Too many requests',
        statusCode: 429,
        code: errorCodes.SYSTEM.RATE_LIMIT_EXCEEDED
      },
      serverError: {
        message: 'Internal server error',
        statusCode: 500,
        code: errorCodes.SYSTEM.INTERNAL_SERVER_ERROR
      }
    };
    
    const template = errorTemplates[type] || errorTemplates.serverError;
    
    return new AppError(
      details.message || template.message,
      details.statusCode || template.statusCode,
      details.code || template.code,
      details.details
    );
  }
  
  /**
   * Quick response methods using ResponseHelper
   */
  static responses = {
    unauthorized: (res, message, code) => ResponseHelper.unauthorized(res, message, code),
    forbidden: (res, message, code) => ResponseHelper.forbidden(res, message, code),
    notFound: (res, resource, id) => ResponseHelper.notFound(res, resource, id),
    conflict: (res, message, field) => ResponseHelper.conflict(res, message, field),
    tooManyRequests: (res, retryAfter, message) => ResponseHelper.tooManyRequests(res, retryAfter, message),
    validationError: (res, errors, message) => ResponseHelper.validationError(res, errors, message)
  };
}

// Create singleton instance
const errorHandler = new ErrorHandler();

module.exports = {
  // Main middleware
  handle: errorHandler.handle(),
  notFound: errorHandler.notFound(),
  asyncHandler: errorHandler.asyncHandler,
  errorBoundary: errorHandler.errorBoundary(),
  handleValidationErrors: errorHandler.handleValidationErrors(),
  
  // Error creation helpers
  createError: ErrorHandler.createError,
  
  // Quick response methods
  responses: ErrorHandler.responses,
  
  // Validation formatter
  validationFormatter: errorHandler.validationFormatter,
  
  // Class export for testing
  ErrorHandler
};