/**
 * @file Admin Logger Utilities
 * @description Enhanced logging utilities for administrative operations with structured logging
 * @version 1.0.0
 */

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');
const crypto = require('crypto');
const config = require('../../../config/config');
const AdminHelpers = require('./admin-helpers');

/**
 * Admin Logger Class
 * @class AdminLogger
 */
class AdminLogger {
  /**
   * Initialize admin logger configurations
   */
  static initialize() {
    // Log levels for admin operations
    this.levels = {
      emergency: 0,  // System is unusable
      alert: 1,      // Action must be taken immediately
      critical: 2,   // Critical conditions
      error: 3,      // Error conditions
      warning: 4,    // Warning conditions
      notice: 5,     // Normal but significant conditions
      info: 6,       // Informational messages
      debug: 7       // Debug-level messages
    };

    // Level colors for console output
    this.colors = {
      emergency: 'red bold',
      alert: 'red underline',
      critical: 'red',
      error: 'red',
      warning: 'yellow',
      notice: 'cyan',
      info: 'green',
      debug: 'gray'
    };

    // Log categories
    this.categories = {
      authentication: 'AUTH',
      authorization: 'AUTHZ',
      dataAccess: 'DATA',
      configuration: 'CONFIG',
      security: 'SEC',
      performance: 'PERF',
      audit: 'AUDIT',
      system: 'SYS',
      user: 'USER',
      organization: 'ORG',
      billing: 'BILL',
      integration: 'INT'
    };

    // Create logger instance
    this.logger = this.createLogger();
    
    // Performance tracking
    this.performanceMetrics = new Map();
    
    // Log aggregation
    this.logAggregation = new Map();
    
    // Alert thresholds
    this.alertThresholds = {
      errorRate: 10, // errors per minute
      responseTime: 5000, // milliseconds
      memoryUsage: 90, // percentage
      cpuUsage: 80 // percentage
    };
  }

  /**
   * Create Winston logger instance
   * @returns {Object} Winston logger
   */
  static createLogger() {
    const logDir = path.join(process.cwd(), 'logs', 'admin');

    // Custom format for admin logs
    const adminFormat = winston.format.combine(
      winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss.SSS'
      }),
      winston.format.errors({ stack: true }),
      winston.format.metadata({
        fillExcept: ['message', 'level', 'timestamp', 'label']
      }),
      winston.format.json()
    );

    // Console format for development
    const consoleFormat = winston.format.combine(
      winston.format.colorize({ colors: this.colors }),
      winston.format.timestamp({
        format: 'HH:mm:ss.SSS'
      }),
      winston.format.printf(({ timestamp, level, message, metadata }) => {
        const category = metadata?.category || 'GENERAL';
        const user = metadata?.userId ? `[${metadata.userId}]` : '';
        return `${timestamp} [${category}] ${level}: ${message} ${user}`;
      })
    );

    // Transport configurations
    const transports = [];

    // Console transport
    if (config.app.env !== 'test') {
      transports.push(new winston.transports.Console({
        format: consoleFormat,
        level: config.logging.level || 'info'
      }));
    }

    // File transports for different log levels
    if (config.logging.file.enabled) {
      // Combined log file
      transports.push(new DailyRotateFile({
        filename: path.join(logDir, 'admin-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        maxSize: '20m',
        maxFiles: '30d',
        format: adminFormat,
        level: 'info'
      }));

      // Error log file
      transports.push(new DailyRotateFile({
        filename: path.join(logDir, 'admin-error-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        maxSize: '20m',
        maxFiles: '90d',
        format: adminFormat,
        level: 'error'
      }));

      // Security log file
      transports.push(new DailyRotateFile({
        filename: path.join(logDir, 'admin-security-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        maxSize: '20m',
        maxFiles: '180d',
        format: adminFormat,
        filter: (log) => log.metadata?.category === 'security'
      }));

      // Audit log file
      transports.push(new DailyRotateFile({
        filename: path.join(logDir, 'admin-audit-%DATE%.log'),
        datePattern: 'YYYY-MM-DD',
        maxSize: '50m',
        maxFiles: '365d',
        format: adminFormat,
        filter: (log) => log.metadata?.category === 'audit'
      }));
    }

    return winston.createLogger({
      levels: this.levels,
      format: adminFormat,
      transports,
      exitOnError: false
    });
  }

  /**
   * Log admin message with context
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} context - Additional context
   */
  static log(level, message, context = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      logId: crypto.randomUUID(),
      environment: config.app.env,
      service: 'admin',
      ...context
    };

    // Sanitize sensitive data
    const sanitizedContext = AdminHelpers.maskSensitiveData(logEntry);

    // Track aggregation
    this.updateAggregation(level, sanitizedContext.category);

    // Check alert conditions
    this.checkAlertConditions(level, message, sanitizedContext);

    // Log the message
    this.logger.log(level, message, { metadata: sanitizedContext });

    // Store critical logs for analysis
    if (['emergency', 'alert', 'critical'].includes(level)) {
      this.storeCriticalLog(level, message, sanitizedContext);
    }
  }

  /**
   * Convenience methods for each log level
   */
  static emergency(message, context) {
    this.log('emergency', message, { ...context, severity: 'emergency' });
  }

  static alert(message, context) {
    this.log('alert', message, { ...context, severity: 'alert' });
  }

  static critical(message, context) {
    this.log('critical', message, { ...context, severity: 'critical' });
  }

  static error(message, context) {
    this.log('error', message, { ...context, severity: 'error' });
  }

  static warning(message, context) {
    this.log('warning', message, { ...context, severity: 'warning' });
  }

  static notice(message, context) {
    this.log('notice', message, { ...context, severity: 'notice' });
  }

  static info(message, context) {
    this.log('info', message, { ...context, severity: 'info' });
  }

  static debug(message, context) {
    this.log('debug', message, { ...context, severity: 'debug' });
  }

  /**
   * Log admin operation with timing
   * @param {string} operation - Operation name
   * @param {Function} fn - Operation function
   * @param {Object} context - Operation context
   * @returns {any} Operation result
   */
  static async logOperation(operation, fn, context = {}) {
    const startTime = Date.now();
    const operationId = crypto.randomUUID();

    this.info(`Admin operation started: ${operation}`, {
      ...context,
      operationId,
      operation,
      category: context.category || 'operation'
    });

    try {
      const result = await fn();
      const duration = Date.now() - startTime;

      this.info(`Admin operation completed: ${operation}`, {
        ...context,
        operationId,
        operation,
        duration,
        result: 'success',
        category: context.category || 'operation'
      });

      // Track performance
      this.trackPerformance(operation, duration);

      return result;
    } catch (error) {
      const duration = Date.now() - startTime;

      this.error(`Admin operation failed: ${operation}`, {
        ...context,
        operationId,
        operation,
        duration,
        result: 'failure',
        error: {
          message: error.message,
          code: error.code,
          stack: config.app.env === 'development' ? error.stack : undefined
        },
        category: context.category || 'operation'
      });

      throw error;
    }
  }

  /**
   * Log security event
   * @param {string} eventType - Security event type
   * @param {Object} details - Event details
   */
  static logSecurityEvent(eventType, details) {
    const securityEvents = {
      unauthorized_access: 'critical',
      permission_violation: 'warning',
      suspicious_activity: 'alert',
      authentication_failure: 'warning',
      data_breach_attempt: 'emergency',
      rate_limit_exceeded: 'notice',
      ip_blocked: 'warning',
      mfa_failure: 'warning'
    };

    const level = securityEvents[eventType] || 'warning';

    this.log(level, `Security event: ${eventType}`, {
      ...details,
      category: 'security',
      eventType,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Log data access
   * @param {Object} accessDetails - Access details
   */
  static logDataAccess(accessDetails) {
    const {
      userId,
      resource,
      action,
      resourceId,
      filters,
      result
    } = accessDetails;

    this.info('Admin data access', {
      userId,
      resource,
      action,
      resourceId,
      filters: AdminHelpers.maskSensitiveData(filters || {}),
      result,
      category: 'dataAccess',
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Log configuration change
   * @param {Object} changeDetails - Change details
   */
  static logConfigChange(changeDetails) {
    const {
      userId,
      setting,
      previousValue,
      newValue,
      reason
    } = changeDetails;

    this.notice('Admin configuration changed', {
      userId,
      setting,
      previousValue: AdminHelpers.maskSensitiveData(previousValue),
      newValue: AdminHelpers.maskSensitiveData(newValue),
      reason,
      category: 'configuration',
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Create structured log entry
   * @param {string} action - Action performed
   * @param {Object} details - Action details
   * @returns {Object} Structured log entry
   */
  static createLogEntry(action, details) {
    return {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      action,
      environment: config.app.env,
      service: 'admin',
      version: config.app.version,
      details: AdminHelpers.maskSensitiveData(details)
    };
  }

  /**
   * Track performance metrics
   * @param {string} operation - Operation name
   * @param {number} duration - Operation duration
   */
  static trackPerformance(operation, duration) {
    let metrics = this.performanceMetrics.get(operation) || {
      count: 0,
      totalDuration: 0,
      minDuration: Infinity,
      maxDuration: 0,
      recentDurations: []
    };

    metrics.count++;
    metrics.totalDuration += duration;
    metrics.minDuration = Math.min(metrics.minDuration, duration);
    metrics.maxDuration = Math.max(metrics.maxDuration, duration);
    
    // Keep last 100 durations for percentile calculations
    metrics.recentDurations.push(duration);
    if (metrics.recentDurations.length > 100) {
      metrics.recentDurations.shift();
    }

    metrics.averageDuration = metrics.totalDuration / metrics.count;

    this.performanceMetrics.set(operation, metrics);

    // Alert on slow operations
    if (duration > this.alertThresholds.responseTime) {
      this.alert(`Slow admin operation detected: ${operation}`, {
        operation,
        duration,
        threshold: this.alertThresholds.responseTime,
        category: 'performance'
      });
    }
  }

  /**
   * Update log aggregation
   * @param {string} level - Log level
   * @param {string} category - Log category
   */
  static updateAggregation(level, category = 'general') {
    const now = Date.now();
    const minute = Math.floor(now / 60000) * 60000;
    const key = `${minute}:${level}:${category}`;

    const count = this.logAggregation.get(key) || 0;
    this.logAggregation.set(key, count + 1);

    // Clean old entries
    for (const [k] of this.logAggregation.entries()) {
      const timestamp = parseInt(k.split(':')[0]);
      if (now - timestamp > 3600000) { // 1 hour
        this.logAggregation.delete(k);
      }
    }
  }

  /**
   * Check alert conditions
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} context - Log context
   */
  static checkAlertConditions(level, message, context) {
    // Check error rate
    if (['error', 'critical', 'alert', 'emergency'].includes(level)) {
      const now = Date.now();
      const minute = Math.floor(now / 60000) * 60000;
      let errorCount = 0;

      for (const [key, count] of this.logAggregation.entries()) {
        const [timestamp, logLevel] = key.split(':');
        if (parseInt(timestamp) === minute && ['error', 'critical', 'alert', 'emergency'].includes(logLevel)) {
          errorCount += count;
        }
      }

      if (errorCount > this.alertThresholds.errorRate) {
        this.sendAlert('high_error_rate', {
          errorCount,
          threshold: this.alertThresholds.errorRate,
          minute: new Date(minute).toISOString()
        });
      }
    }
  }

  /**
   * Store critical log for analysis
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} context - Log context
   */
  static storeCriticalLog(level, message, context) {
    // This would integrate with a critical log storage system
    const criticalLog = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      level,
      message,
      context,
      analyzed: false
    };

    // In production, this would send to a monitoring service
    if (config.app.env === 'production') {
      // Send to monitoring service
      this.debug('Critical log stored for analysis', { logId: criticalLog.id });
    }
  }

  /**
   * Send alert notification
   * @param {string} alertType - Alert type
   * @param {Object} details - Alert details
   */
  static sendAlert(alertType, details) {
    // This would integrate with alerting service
    this.alert(`Admin alert triggered: ${alertType}`, {
      alertType,
      details,
      category: 'alert',
      notificationSent: true
    });
  }

  /**
   * Get performance statistics
   * @param {string} operation - Operation name (optional)
   * @returns {Object} Performance statistics
   */
  static getPerformanceStats(operation = null) {
    if (operation) {
      const metrics = this.performanceMetrics.get(operation);
      if (!metrics) return null;

      // Calculate percentiles
      const sorted = [...metrics.recentDurations].sort((a, b) => a - b);
      const p50 = sorted[Math.floor(sorted.length * 0.5)];
      const p95 = sorted[Math.floor(sorted.length * 0.95)];
      const p99 = sorted[Math.floor(sorted.length * 0.99)];

      return {
        operation,
        count: metrics.count,
        average: Math.round(metrics.averageDuration),
        min: metrics.minDuration,
        max: metrics.maxDuration,
        p50,
        p95,
        p99
      };
    }

    // Return all operation stats
    const allStats = {};
    for (const [op, metrics] of this.performanceMetrics.entries()) {
      allStats[op] = this.getPerformanceStats(op);
    }
    return allStats;
  }

  /**
   * Get log statistics
   * @param {number} minutes - Time window in minutes
   * @returns {Object} Log statistics
   */
  static getLogStats(minutes = 60) {
    const now = Date.now();
    const cutoff = now - (minutes * 60000);
    const stats = {
      byLevel: {},
      byCategory: {},
      total: 0
    };

    for (const [key, count] of this.logAggregation.entries()) {
      const [timestamp, level, category] = key.split(':');
      if (parseInt(timestamp) >= cutoff) {
        stats.byLevel[level] = (stats.byLevel[level] || 0) + count;
        stats.byCategory[category] = (stats.byCategory[category] || 0) + count;
        stats.total += count;
      }
    }

    return stats;
  }

  /**
   * Search logs
   * @param {Object} criteria - Search criteria
   * @returns {Promise<Array>} Matching logs
   */
  static async searchLogs(criteria) {
    // This would integrate with log storage system
    const {
      startDate,
      endDate,
      level,
      category,
      userId,
      keyword,
      limit = 100
    } = criteria;

    this.debug('Searching admin logs', {
      criteria,
      category: 'search'
    });

    // In production, this would query the log storage
    return [];
  }

  /**
   * Export logs
   * @param {Object} exportOptions - Export options
   * @returns {Promise<string>} Export file path
   */
  static async exportLogs(exportOptions) {
    const {
      format = 'json',
      startDate,
      endDate,
      categories,
      levels
    } = exportOptions;

    const exportId = crypto.randomUUID();
    
    this.info('Admin logs export initiated', {
      exportId,
      format,
      startDate,
      endDate,
      categories,
      levels,
      category: 'export'
    });

    // In production, this would create the export
    return `/exports/admin-logs-${exportId}.${format}`;
  }

  /**
   * Clear old logs
   * @param {number} retentionDays - Days to retain logs
   */
  static async clearOldLogs(retentionDays) {
    this.notice('Clearing old admin logs', {
      retentionDays,
      category: 'maintenance'
    });

    // Clear performance metrics older than retention period
    const cutoff = Date.now() - (retentionDays * 24 * 60 * 60 * 1000);
    
    // In production, this would clean up log files
    this.info('Old admin logs cleared', {
      retentionDays,
      category: 'maintenance'
    });
  }
}

// Initialize on module load
AdminLogger.initialize();

// Add colors to Winston
winston.addColors(AdminLogger.colors);

module.exports = AdminLogger;