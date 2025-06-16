// /server/shared/security/middleware/cors-middleware.js

/**
 * @file CORS Middleware
 * @description CORS middleware wrapper that integrates with the cors-config
 * @version 1.0.0
 */

const { AppError } = require('../../utils/app-error');
const logger = require('../../utils/logger');

const corsConfig = require('./cors-config');

/**
 * Apply CORS middleware based on route type
 */
const applyCORS = (type = 'default') => {
  switch (type) {
    case 'public':
      return corsConfig.publicCORS;
    case 'webhook':
      return corsConfig.webhookCORS;
    case 'dynamic':
      return corsConfig.dynamicCORS;
    case 'api':
      return corsConfig.createRouteCORS({
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        credentials: true
      });
    default:
      return corsConfig.cors;
  }
};

/**
 * CORS middleware with logging
 */
const corsWithLogging = (req, res, next) => {
  const origin = req.get('origin');
  const method = req.method;
  
  // Log CORS requests in development
  if (process.env.NODE_ENV === 'development' && origin) {
    logger.debug('CORS Request', {
      origin,
      method,
      path: req.path,
      headers: req.headers
    });
  }
  
  // Apply default CORS
  corsConfig.cors(req, res, (err) => {
    if (err) {
      logger.error('CORS Error', { 
        error: err.message, 
        origin,
        method,
        path: req.path 
      });
      return next(new AppError('CORS policy violation', 403, 'CORS_ERROR'));
    }
    next();
  });
};

/**
 * Strict CORS for sensitive endpoints
 */
const strictCORS = corsConfig.createRouteCORS({
  origins: [
    'https://insightserenity.com',
    'https://www.insightserenity.com',
    'https://app.insightserenity.com'
  ],
  methods: ['GET', 'POST'],
  credentials: true,
  maxAge: 3600 // 1 hour
});

/**
 * CORS for file uploads
 */
const uploadCORS = corsConfig.createRouteCORS({
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Upload-Content-Type',
    'X-Upload-Content-Length',
    'X-File-Name'
  ],
  exposedHeaders: [
    'X-Upload-Id',
    'X-File-Id',
    'Location'
  ]
});

module.exports = {
  // Main middleware
  cors: corsWithLogging,
  
  // Type-specific middleware
  applyCORS,
  publicCORS: corsConfig.publicCORS,
  webhookCORS: corsConfig.webhookCORS,
  dynamicCORS: corsConfig.dynamicCORS,
  strictCORS,
  uploadCORS,
  
  // Handlers
  preflightHandler: corsConfig.preflightHandler,
  errorHandler: corsConfig.errorHandler
};