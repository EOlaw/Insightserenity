/**
 * @file Logger Utility
 * @description Centralized logging service with structured format and multiple transports
 */

const winston = require('winston');
const { format, transports } = winston;
const path = require('path');
const config = require('../config/config');
require('winston-daily-rotate-file');

// Custom format for console output with colors
const consoleFormat = format.combine(
  format.colorize(),
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  format.printf(({ timestamp, level, message, ...meta }) => {
    const metaString = Object.keys(meta).length ? `\n${JSON.stringify(meta, null, 2)}` : '';
    return `${timestamp} ${level}: ${message}${metaString}`;
  })
);

// Production format for structured logging
const productionFormat = format.combine(
  format.timestamp(),
  format.json()
);

// Common format including error stack traces
const errorStackFormat = format(info => {
  if (info.error instanceof Error) {
    info.errorDetails = {
      name: info.error.name,
      message: info.error.message,
      stack: info.error.stack
    };
    // Remove the error object to avoid circular references
    delete info.error;
  }
  return info;
});

// Create the transports array based on configuration
const loggerTransports = [];

// Always add console transport with appropriate format
if (config.app.env === 'production') {
  loggerTransports.push(
    new transports.Console({
      level: config.logging.level,
      format: productionFormat
    })
  );
} else {
  loggerTransports.push(
    new transports.Console({
      level: config.logging.level,
      format: consoleFormat
    })
  );
}

// Add file transport if enabled
if (config.logging.file.enabled) {
  // Create log directory if it doesn't exist
  const fs = require('fs');
  if (!fs.existsSync(config.logging.file.path)) {
    fs.mkdirSync(config.logging.file.path, { recursive: true });
  }
  
  // Add rotating file transport
  loggerTransports.push(
    new transports.DailyRotateFile({
      filename: path.join(
        config.logging.file.path, 
        config.logging.file.filename
      ),
      datePattern: 'YYYY-MM-DD',
      maxSize: config.logging.file.maxSize,
      maxFiles: config.logging.file.maxFiles,
      level: config.logging.level,
      format: productionFormat
    })
  );
  
  // Add separate error log file
  loggerTransports.push(
    new transports.DailyRotateFile({
      filename: path.join(
        config.logging.file.path,
        'error-%DATE%.log'
      ),
      datePattern: 'YYYY-MM-DD',
      maxSize: config.logging.file.maxSize,
      maxFiles: config.logging.file.maxFiles,
      level: 'error',
      format: productionFormat
    })
  );
}

// Create the logger
const logger = winston.createLogger({
  level: config.logging.level,
  defaultMeta: { 
    service: config.app.name,
    environment: config.app.env
  },
  format: format.combine(
    errorStackFormat(),
    format.timestamp(),
    format.json()
  ),
  transports: loggerTransports,
  // Don't exit on error
  exitOnError: false
});

// Add request logging helper
logger.logRequest = (req, options = {}) => {
  // Skip logging for health checks and static assets
  if (req.path === '/health' || req.path === '/favicon.ico' || req.path.startsWith('/public/')) {
    return;
  }
  
  const logLevel = options.level || 'debug';
  
  logger[logLevel]('HTTP Request', {
    request: {
      method: req.method,
      url: req.originalUrl || req.url,
      path: req.path,
      query: req.query,
      params: req.params,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      // Only log body for non-GET requests
      body: req.method !== 'GET' ? req.body : undefined
    },
    userId: req.user?.id,
    sessionId: req.sessionID
  });
};

// Add response logging helper
logger.logResponse = (req, res, options = {}) => {
  // Skip logging for health checks and static assets
  if (req.path === '/health' || req.path === '/favicon.ico' || req.path.startsWith('/public/')) {
    return;
  }
  
  const logLevel = options.level || 'debug';
  
  logger[logLevel]('HTTP Response', {
    request: {
      method: req.method,
      url: req.originalUrl || req.url,
      path: req.path
    },
    response: {
      statusCode: res.statusCode,
      statusMessage: res.statusMessage,
      responseTime: options.responseTime
    },
    userId: req.user?.id,
    sessionId: req.sessionID
  });
};

// Add middleware for HTTP request/response logging
logger.httpLoggerMiddleware = () => {
  return (req, res, next) => {
    // Record request start time
    req._startTime = Date.now();
    
    // Log request
    logger.logRequest(req);
    
    // Log response when finished
    res.on('finish', () => {
      const responseTime = Date.now() - req._startTime;
      
      // Determine log level based on status code
      let level = 'debug';
      if (res.statusCode >= 500) level = 'error';
      else if (res.statusCode >= 400) level = 'warn';
      
      logger.logResponse(req, res, { level, responseTime });
    });
    
    next();
  };
};

module.exports = logger;