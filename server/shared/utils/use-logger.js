// server/shared/utils/logger.js

// Use this file to manage logging across the application when ready for production...
/**
 * @file Logger Utility
 * @description Centralized logging system with Winston
 * @version 3.0.0
 */

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const fs = require('fs');

// Safe config loading
let config;
try {
  config = require('../config/config');
} catch (error) {
  // Fallback config if main config is not available
  config = {
    env: process.env.NODE_ENV || 'development',
    isDevelopment: process.env.NODE_ENV === 'development',
    isProduction: process.env.NODE_ENV === 'production',
    isTest: process.env.NODE_ENV === 'test',
    logging: {
      level: process.env.LOG_LEVEL || 'info',
      transports: ['console', 'file']
    },
    external: {
      sentry: {
        enabled: false,
        dsn: null
      }
    }
  };
}

/**
 * Logger Manager Class
 * @class LoggerManager
 */
class LoggerManager {
  constructor() {
    this.logDir = path.join(__dirname, '../../../logs');
    this.ensureLogDirectory();
    
    // Create default logger instance
    this.logger = this.createLogger();
    
    // Store child loggers for different modules
    this.childLoggers = new Map();
  }
  
  /**
   * Ensure log directory exists
   */
  ensureLogDirectory() {
    try {
      if (!fs.existsSync(this.logDir)) {
        fs.mkdirSync(this.logDir, { recursive: true });
      }
    } catch (error) {
      // Continue without file logging if directory creation fails
      console.warn('Could not create log directory:', error.message);
    }
  }
  
  /**
   * Create Winston logger instance
   * @param {Object} options - Logger options
   * @returns {winston.Logger} Winston logger
   */
  createLogger(options = {}) {
    const {
      service = 'insightserenity',
      level = config.logging?.level || 'info',
      defaultMeta = {}
    } = options;
    
    // Define custom log levels
    const customLevels = {
      levels: {
        error: 0,
        warn: 1,
        info: 2,
        http: 3,
        verbose: 4,
        debug: 5,
        silly: 6
      },
      colors: {
        error: 'red',
        warn: 'yellow',
        info: 'green',
        http: 'magenta',
        verbose: 'cyan',
        debug: 'blue',
        silly: 'grey'
      }
    };
    
    winston.addColors(customLevels.colors);
    
    // Create formatters
    const formatters = this.createFormatters();
    
    // Create transports
    const transports = this.createTransports(service);
    
    // Create logger instance
    const logger = winston.createLogger({
      levels: customLevels.levels,
      level,
      format: formatters.combined,
      defaultMeta: {
        service,
        environment: config.env || 'development',
        ...defaultMeta
      },
      transports,
      exitOnError: false
    });
    
    // Add stream for Morgan HTTP logging
    logger.stream = {
      write: (message) => {
        logger.http(message.trim());
      }
    };
    
    return logger;
  }
  
  /**
   * Create log formatters
   * @returns {Object} Formatters object
   */
  createFormatters() {
    const { combine, timestamp, errors, splat, json, printf, colorize, metadata } = winston.format;
    
    // Custom formatter for readable console output
    const consoleFormat = printf(({ level, message, timestamp, service, ...metadata }) => {
      let meta = '';
      if (Object.keys(metadata).length > 0) {
        // Filter out unnecessary metadata
        const { error, ...cleanMeta } = metadata;
        if (Object.keys(cleanMeta).length > 0) {
          meta = `\n${JSON.stringify(cleanMeta, null, 2)}`;
        }
        if (error) {
          meta += `\n${error.stack || error}`;
        }
      }
      return `${timestamp} [${service}] ${level}: ${message}${meta}`;
    });
    
    // JSON formatter for production
    const jsonFormat = combine(
      timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      errors({ stack: true }),
      splat(),
      metadata({ fillExcept: ['message', 'level', 'timestamp', 'service'] }),
      json()
    );
    
    // Console formatter for development
    const devFormat = combine(
      colorize({ all: true }),
      timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      errors({ stack: true }),
      splat(),
      consoleFormat
    );
    
    return {
      json: jsonFormat,
      console: devFormat,
      combined: (config.isDevelopment) ? devFormat : jsonFormat
    };
  }
  
  /**
   * Create logger transports
   * @param {string} service - Service name
   * @returns {Array} Array of transports
   */
  createTransports(service) {
    const transports = [];
    
    // Console transport
    if (config.logging?.transports?.includes('console') !== false) {
      transports.push(new winston.transports.Console({
        handleExceptions: true,
        handleRejections: true
      }));
    }
    
    // File transports for production
    if (config.logging?.transports?.includes('file') && !config.isTest && fs.existsSync(this.logDir)) {
      try {
        // Error log file
        transports.push(new DailyRotateFile({
          filename: path.join(this.logDir, `${service}-error-%DATE%.log`),
          datePattern: 'YYYY-MM-DD',
          level: 'error',
          handleExceptions: true,
          handleRejections: true,
          maxSize: '20m',
          maxFiles: '14d',
          format: winston.format.json()
        }));
        
        // Combined log file
        transports.push(new DailyRotateFile({
          filename: path.join(this.logDir, `${service}-combined-%DATE%.log`),
          datePattern: 'YYYY-MM-DD',
          handleExceptions: true,
          handleRejections: true,
          maxSize: '20m',
          maxFiles: '7d',
          format: winston.format.json()
        }));
        
        // Audit log file for security events
        transports.push(new DailyRotateFile({
          filename: path.join(this.logDir, `${service}-audit-%DATE%.log`),
          datePattern: 'YYYY-MM-DD',
          level: 'info',
          maxSize: '20m',
          maxFiles: '30d',
          format: winston.format.json(),
          filter: winston.format((info) => {
            return info.audit === true ? info : false;
          })()
        }));
      } catch (error) {
        console.warn('Could not create file transports:', error.message);
      }
    }
    
    // Add external transports for production
    if (config.isProduction) {
      // Add Sentry transport if configured
      if (config.external?.sentry?.enabled && config.external?.sentry?.dsn) {
        try {
          const Sentry = require('winston-transport-sentry-node').default;
          transports.push(new Sentry({
            sentry: {
              dsn: config.external.sentry.dsn,
              environment: config.env
            },
            level: 'error'
          }));
        } catch (error) {
          console.warn('Could not initialize Sentry transport:', error.message);
        }
      }
      
      // Add CloudWatch transport if configured
      if (process.env.AWS_CLOUDWATCH_ENABLED === 'true') {
        try {
          const CloudWatchTransport = require('winston-cloudwatch');
          transports.push(new CloudWatchTransport({
            logGroupName: process.env.AWS_CLOUDWATCH_GROUP || 'insightserenity',
            logStreamName: `${service}-${config.env}`,
            awsRegion: process.env.AWS_REGION || 'us-east-1',
            messageFormatter: ({ level, message, ...meta }) => {
              return `[${level}] ${message} ${JSON.stringify(meta)}`;
            }
          }));
        } catch (error) {
          console.warn('Could not initialize CloudWatch transport:', error.message);
        }
      }
    }
    
    return transports;
  }
  
  /**
   * Get or create child logger for module
   * @param {string} module - Module name
   * @param {Object} defaultMeta - Default metadata
   * @returns {winston.Logger} Child logger
   */
  getModuleLogger(module, defaultMeta = {}) {
    if (!this.childLoggers.has(module)) {
      const childLogger = this.logger.child({
        module,
        ...defaultMeta
      });
      this.childLoggers.set(module, childLogger);
    }
    return this.childLoggers.get(module);
  }
  
  /**
   * Log audit event
   * @param {string} action - Action performed
   * @param {Object} details - Event details
   */
  audit(action, details) {
    this.logger.info('Audit Event', {
      audit: true,
      action,
      timestamp: new Date().toISOString(),
      ...details
    });
  }
  
  /**
   * Log performance metric
   * @param {string} operation - Operation name
   * @param {number} duration - Duration in milliseconds
   * @param {Object} metadata - Additional metadata
   */
  performance(operation, duration, metadata = {}) {
    this.logger.info('Performance Metric', {
      performance: true,
      operation,
      duration,
      timestamp: new Date().toISOString(),
      ...metadata
    });
  }
  
  /**
   * Create HTTP request logger middleware
   * @returns {Function} Express middleware
   */
  createRequestLogger() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Log request
      this.logger.http('Incoming Request', {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('user-agent')
      });
      
      // Log response
      const originalSend = res.send;
      res.send = function(data) {
        res.send = originalSend;
        
        const duration = Date.now() - startTime;
        const logData = {
          method: req.method,
          url: req.url,
          statusCode: res.statusCode,
          duration,
          contentLength: res.get('content-length')
        };
        
        if (res.statusCode >= 400) {
          loggerManager.logger.warn('Request Error', logData);
        } else {
          loggerManager.logger.http('Request Completed', logData);
        }
        
        return res.send(data);
      };
      
      next();
    };
  }
  
  /**
   * Create error logger middleware
   * @returns {Function} Express middleware
   */
  createErrorLogger() {
    return (err, req, res, next) => {
      const errorData = {
        message: err.message,
        stack: err.stack,
        statusCode: err.statusCode || 500,
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.user?.id,
        organizationId: req.organization?.id
      };
      
      if (err.statusCode >= 500 || !err.statusCode) {
        this.logger.error('Server Error', errorData);
      } else {
        this.logger.warn('Client Error', errorData);
      }
      
      next(err);
    };
  }
}

// Create singleton instance
const loggerManager = new LoggerManager();

// Export main logger with proper method exposure
module.exports = {
  // Expose all Winston logger methods directly
  error: (...args) => loggerManager.logger.error(...args),
  warn: (...args) => loggerManager.logger.warn(...args),
  info: (...args) => loggerManager.logger.info(...args),
  http: (...args) => loggerManager.logger.http(...args),
  verbose: (...args) => loggerManager.logger.verbose(...args),
  debug: (...args) => loggerManager.logger.debug(...args),
  silly: (...args) => loggerManager.logger.silly(...args),
  log: (...args) => loggerManager.logger.log(...args),
  
  // Additional utility methods
  getModuleLogger: loggerManager.getModuleLogger.bind(loggerManager),
  audit: loggerManager.audit.bind(loggerManager),
  performance: loggerManager.performance.bind(loggerManager),
  createRequestLogger: loggerManager.createRequestLogger.bind(loggerManager),
  createErrorLogger: loggerManager.createErrorLogger.bind(loggerManager),
  
  // Direct access to logger instance
  logger: loggerManager.logger,
  
  // Stream for HTTP logging
  stream: loggerManager.logger.stream
};