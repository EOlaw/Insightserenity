// server/shared/utils/app-error.js
/**
 * @file Application Error Utility
 * @description Custom error classes for consistent error handling
 * @version 3.0.0
 */

const constants = require('../config/constants');

/**
 * Base Application Error Class
 * @class AppError
 * @extends Error
 */
class AppError extends Error {
  constructor(message, statusCode = 500, code = null, details = null) {
    super(message);
    
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    
    // Capture stack trace
    Error.captureStackTrace(this, this.constructor);
  }
  
  /**
   * Convert error to JSON format
   * @returns {Object} Error object
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      details: this.details,
      timestamp: this.timestamp,
      ...(process.env.NODE_ENV === 'development' && { stack: this.stack })
    };
  }
}

/**
 * Validation Error Class
 * @class ValidationError
 * @extends AppError
 */
class ValidationError extends AppError {
  constructor(message, errors = []) {
    super(message, 400, 'VALIDATION_ERROR', errors);
    this.errors = errors;
  }
}

/**
 * Authentication Error Class
 * @class AuthenticationError
 * @extends AppError
 */
class AuthenticationError extends AppError {
  constructor(message = 'Authentication failed', code = 'AUTH_FAILED') {
    super(message, 401, code);
  }
}

/**
 * Authorization Error Class
 * @class AuthorizationError
 * @extends AppError
 */
class AuthorizationError extends AppError {
  constructor(message = 'Access denied', code = 'ACCESS_DENIED') {
    super(message, 403, code);
  }
}

/**
 * Not Found Error Class
 * @class NotFoundError
 * @extends AppError
 */
class NotFoundError extends AppError {
  constructor(resource = 'Resource', id = null) {
    const message = id ? `${resource} with ID ${id} not found` : `${resource} not found`;
    super(message, 404, 'NOT_FOUND', { resource, id });
  }
}

/**
 * Conflict Error Class
 * @class ConflictError
 * @extends AppError
 */
class ConflictError extends AppError {
  constructor(message, field = null) {
    super(message, 409, 'CONFLICT', { field });
  }
}

/**
 * Rate Limit Error Class
 * @class RateLimitError
 * @extends AppError
 */
class RateLimitError extends AppError {
  constructor(retryAfter = null) {
    super('Too many requests', 429, 'RATE_LIMIT_EXCEEDED', { retryAfter });
    this.retryAfter = retryAfter;
  }
}

/**
 * Database Error Class
 * @class DatabaseError
 * @extends AppError
 */
class DatabaseError extends AppError {
  constructor(message = 'Database operation failed', originalError = null) {
    super(message, 500, 'DATABASE_ERROR');
    this.originalError = originalError;
  }
}

/**
 * External Service Error Class
 * @class ExternalServiceError
 * @extends AppError
 */
class ExternalServiceError extends AppError {
  constructor(service, message = 'External service error', originalError = null) {
    super(`${service}: ${message}`, 502, 'EXTERNAL_SERVICE_ERROR', { service });
    this.service = service;
    this.originalError = originalError;
  }
}

/**
 * Business Logic Error Class
 * @class BusinessError
 * @extends AppError
 */
class BusinessError extends AppError {
  constructor(message, code = 'BUSINESS_ERROR', details = null) {
    super(message, 422, code, details);
  }
}

/**
 * Payment Error Class
 * @class PaymentError
 * @extends AppError
 */
class PaymentError extends AppError {
  constructor(message, code = 'PAYMENT_ERROR', details = null) {
    super(message, 402, code, details);
  }
}

/**
 * Subscription Error Class
 * @class SubscriptionError
 * @extends AppError
 */
class SubscriptionError extends AppError {
  constructor(message, code = 'SUBSCRIPTION_ERROR', details = null) {
    super(message, 403, code, details);
  }
}

/**
 * Token Error Class
 * @class TokenError
 * @extends AppError
 */
class TokenError extends AppError {
  constructor(message = 'Invalid token', code = 'TOKEN_INVALID') {
    super(message, 401, code);
  }
}

/**
 * Error Factory Class
 * @class ErrorFactory
 */
class ErrorFactory {
  /**
   * Create error from database error
   * @param {Error} error - Database error
   * @returns {AppError} Application error
   */
  static fromDatabase(error) {
    // Handle MongoDB duplicate key error
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern)[0];
      return new ConflictError(`${field} already exists`, field);
    }
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(err => ({
        field: err.path,
        message: err.message,
        value: err.value
      }));
      return new ValidationError('Validation failed', errors);
    }
    
    // Handle cast errors
    if (error.name === 'CastError') {
      return new ValidationError(`Invalid ${error.path}: ${error.value}`);
    }
    
    // Default database error
    return new DatabaseError(error.message, error);
  }
  
  /**
   * Create error from external API response
   * @param {string} service - Service name
   * @param {Object} response - API response
   * @returns {AppError} Application error
   */
  static fromExternalAPI(service, response) {
    if (response.status === 429) {
      const retryAfter = response.headers?.['retry-after'];
      return new RateLimitError(retryAfter);
    }
    
    const message = response.data?.message || response.statusText || 'External service error';
    return new ExternalServiceError(service, message);
  }
  
  /**
   * Create error from JWT error
   * @param {Error} error - JWT error
   * @returns {AppError} Application error
   */
  static fromJWT(error) {
    if (error.name === 'TokenExpiredError') {
      return new TokenError('Token has expired', 'TOKEN_EXPIRED');
    }
    
    if (error.name === 'JsonWebTokenError') {
      return new TokenError('Invalid token', 'TOKEN_INVALID');
    }
    
    if (error.name === 'NotBeforeError') {
      return new TokenError('Token not active yet', 'TOKEN_NOT_ACTIVE');
    }
    
    return new TokenError();
  }
  
  /**
   * Create error from validation result
   * @param {Array} errors - Validation errors
   * @returns {ValidationError} Validation error
   */
  static fromValidation(errors) {
    const formattedErrors = errors.map(error => ({
      field: error.param || error.field,
      message: error.msg || error.message,
      value: error.value
    }));
    
    return new ValidationError('Validation failed', formattedErrors);
  }
}

/**
 * Error Handler Middleware
 * @param {Error} error - Error object
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 * @param {Function} next - Next middleware
 */
const errorHandler = (error, req, res, next) => {
  // Log error
  const logger = require('./logger');
  
  // Convert non-operational errors
  let appError = error;
  
  if (!(error instanceof AppError)) {
    // Convert known error types
    if (error.name === 'ValidationError' || error.name === 'CastError') {
      appError = ErrorFactory.fromDatabase(error);
    } else if (error.name === 'UnauthorizedError') {
      appError = new AuthenticationError(error.message);
    } else {
      // Unknown error
      appError = new AppError(
        process.env.NODE_ENV === 'production' ? 'Internal server error' : error.message,
        500,
        'INTERNAL_ERROR'
      );
      appError.isOperational = false;
    }
  }
  
  // Log error details
  const errorLog = {
    error: {
      message: appError.message,
      code: appError.code,
      statusCode: appError.statusCode,
      isOperational: appError.isOperational,
      stack: appError.stack
    },
    request: {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body,
      query: req.query,
      params: req.params,
      ip: req.ip,
      user: req.user?.id
    }
  };
  
  if (appError.isOperational) {
    logger.warn('Operational error', errorLog);
  } else {
    logger.error('Programming error', errorLog);
  }
  
  // Send error response
  const response = {
    success: false,
    error: {
      message: appError.message,
      code: appError.code
    }
  };
  
  // Add additional error details in development
  if (process.env.NODE_ENV === 'development') {
    response.error.details = appError.details;
    response.error.stack = appError.stack;
  }
  
  // Add validation errors
  if (appError instanceof ValidationError) {
    response.error.errors = appError.errors;
  }
  
  // Add retry header for rate limit errors
  if (appError instanceof RateLimitError && appError.retryAfter) {
    res.set('Retry-After', appError.retryAfter);
  }
  
  res.status(appError.statusCode).json(response);
};

/**
 * Handle unhandled promise rejections
 */
process.on('unhandledRejection', (reason, promise) => {
  const logger = require('./logger');
  logger.error('Unhandled Promise Rejection', {
    reason: reason?.stack || reason,
    promise
  });
  
  if (process.env.NODE_ENV === 'production') {
    // Gracefully shutdown in production
    process.exit(1);
  }
});

/**
 * Handle uncaught exceptions
 */
process.on('uncaughtException', (error) => {
  const logger = require('./logger');
  logger.error('Uncaught Exception', {
    error: error.stack || error
  });
  
  // Always exit on uncaught exceptions
  process.exit(1);
});

module.exports = {
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  DatabaseError,
  ExternalServiceError,
  BusinessError,
  PaymentError,
  SubscriptionError,
  TokenError,
  ErrorFactory,
  errorHandler
};