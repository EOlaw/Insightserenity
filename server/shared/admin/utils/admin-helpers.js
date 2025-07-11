/**
 * @file Admin Helper Utilities
 * @description Common helper functions for administrative operations
 * @version 1.0.0
 */

const crypto = require('crypto');
const moment = require('moment');
const config = require('../../../config/config');
const logger = require('../../../utils/logger');

/**
 * Admin Helper Utilities Class
 * @class AdminHelpers
 */
class AdminHelpers {
  /**
   * Generate admin session ID
   * @returns {string} Session ID
   */
  static generateAdminSessionId() {
    return `adm_ses_${crypto.randomBytes(16).toString('hex')}`;
  }

  /**
   * Generate admin API key
   * @returns {Object} API key and secret
   */
  static generateAdminApiKey() {
    const key = `adm_${crypto.randomBytes(16).toString('hex')}`;
    const secret = crypto.randomBytes(32).toString('hex');
    
    return {
      key,
      secret,
      hash: crypto.createHash('sha256').update(secret).digest('hex')
    };
  }

  /**
   * Generate admin operation ID for tracking
   * @param {string} operation - Operation type
   * @returns {string} Operation ID
   */
  static generateOperationId(operation) {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(4).toString('hex');
    return `op_${operation}_${timestamp}_${random}`;
  }

  /**
   * Format admin response with metadata
   * @param {Object} data - Response data
   * @param {Object} metadata - Additional metadata
   * @returns {Object} Formatted response
   */
  static formatAdminResponse(data, metadata = {}) {
    return {
      success: true,
      data,
      metadata: {
        timestamp: new Date().toISOString(),
        responseId: crypto.randomUUID(),
        ...metadata
      }
    };
  }

  /**
   * Format admin error response
   * @param {Error} error - Error object
   * @param {Object} metadata - Additional metadata
   * @returns {Object} Formatted error response
   */
  static formatAdminError(error, metadata = {}) {
    const errorResponse = {
      success: false,
      error: {
        message: error.message,
        code: error.code || 'ADMIN_ERROR',
        type: error.name || 'Error',
        statusCode: error.statusCode || 500
      },
      metadata: {
        timestamp: new Date().toISOString(),
        errorId: crypto.randomUUID(),
        ...metadata
      }
    };

    // Add stack trace in development
    if (config.app.env === 'development') {
      errorResponse.error.stack = error.stack;
    }

    return errorResponse;
  }

  /**
   * Parse admin query filters
   * @param {Object} query - Request query parameters
   * @returns {Object} Parsed filters
   */
  static parseAdminFilters(query) {
    const filters = {};
    const excludeKeys = ['page', 'limit', 'sort', 'fields', 'populate'];

    // Parse standard filters
    Object.keys(query).forEach(key => {
      if (excludeKeys.includes(key)) return;

      const value = query[key];

      // Handle special filter operators
      if (key.endsWith('_gte')) {
        const field = key.replace('_gte', '');
        filters[field] = { ...filters[field], $gte: this.parseFilterValue(value) };
      } else if (key.endsWith('_lte')) {
        const field = key.replace('_lte', '');
        filters[field] = { ...filters[field], $lte: this.parseFilterValue(value) };
      } else if (key.endsWith('_gt')) {
        const field = key.replace('_gt', '');
        filters[field] = { ...filters[field], $gt: this.parseFilterValue(value) };
      } else if (key.endsWith('_lt')) {
        const field = key.replace('_lt', '');
        filters[field] = { ...filters[field], $lt: this.parseFilterValue(value) };
      } else if (key.endsWith('_ne')) {
        const field = key.replace('_ne', '');
        filters[field] = { $ne: this.parseFilterValue(value) };
      } else if (key.endsWith('_in')) {
        const field = key.replace('_in', '');
        filters[field] = { $in: value.split(',').map(v => this.parseFilterValue(v.trim())) };
      } else if (key.endsWith('_nin')) {
        const field = key.replace('_nin', '');
        filters[field] = { $nin: value.split(',').map(v => this.parseFilterValue(v.trim())) };
      } else if (key.endsWith('_regex')) {
        const field = key.replace('_regex', '');
        filters[field] = { $regex: value, $options: 'i' };
      } else if (key.endsWith('_exists')) {
        const field = key.replace('_exists', '');
        filters[field] = { $exists: value === 'true' };
      } else {
        filters[key] = this.parseFilterValue(value);
      }
    });

    return filters;
  }

  /**
   * Parse filter value
   * @param {string} value - Filter value
   * @returns {any} Parsed value
   */
  static parseFilterValue(value) {
    // Boolean
    if (value === 'true') return true;
    if (value === 'false') return false;

    // Null
    if (value === 'null') return null;

    // Number
    if (/^\d+$/.test(value)) return parseInt(value, 10);
    if (/^\d+\.\d+$/.test(value)) return parseFloat(value);

    // Date
    if (/^\d{4}-\d{2}-\d{2}/.test(value)) {
      const date = new Date(value);
      if (!isNaN(date.getTime())) return date;
    }

    // Default to string
    return value;
  }

  /**
   * Build sort object from query
   * @param {string} sortString - Sort parameter
   * @returns {Object} MongoDB sort object
   */
  static buildSortObject(sortString) {
    if (!sortString) return { createdAt: -1 };

    const sort = {};
    const fields = sortString.split(',');

    fields.forEach(field => {
      if (field.startsWith('-')) {
        sort[field.substring(1)] = -1;
      } else {
        sort[field] = 1;
      }
    });

    return sort;
  }

  /**
   * Sanitize admin input
   * @param {Object} data - Input data
   * @param {Array} allowedFields - Allowed fields
   * @returns {Object} Sanitized data
   */
  static sanitizeAdminInput(data, allowedFields = []) {
    const sanitized = {};

    // If no allowed fields specified, return all non-system fields
    if (allowedFields.length === 0) {
      Object.keys(data).forEach(key => {
        if (!key.startsWith('_') && !['id', 'createdAt', 'updatedAt'].includes(key)) {
          sanitized[key] = data[key];
        }
      });
    } else {
      // Only include allowed fields
      allowedFields.forEach(field => {
        if (data[field] !== undefined) {
          sanitized[field] = data[field];
        }
      });
    }

    return sanitized;
  }

  /**
   * Calculate date ranges for admin reports
   * @param {string} period - Period type
   * @param {Date} customStart - Custom start date
   * @param {Date} customEnd - Custom end date
   * @returns {Object} Date range
   */
  static calculateDateRange(period, customStart, customEnd) {
    const now = new Date();
    let startDate, endDate;

    switch (period) {
      case 'today':
        startDate = moment().startOf('day').toDate();
        endDate = moment().endOf('day').toDate();
        break;
      
      case 'yesterday':
        startDate = moment().subtract(1, 'day').startOf('day').toDate();
        endDate = moment().subtract(1, 'day').endOf('day').toDate();
        break;
      
      case 'last7days':
        startDate = moment().subtract(7, 'days').startOf('day').toDate();
        endDate = now;
        break;
      
      case 'last30days':
        startDate = moment().subtract(30, 'days').startOf('day').toDate();
        endDate = now;
        break;
      
      case 'thisMonth':
        startDate = moment().startOf('month').toDate();
        endDate = moment().endOf('month').toDate();
        break;
      
      case 'lastMonth':
        startDate = moment().subtract(1, 'month').startOf('month').toDate();
        endDate = moment().subtract(1, 'month').endOf('month').toDate();
        break;
      
      case 'thisQuarter':
        startDate = moment().startOf('quarter').toDate();
        endDate = moment().endOf('quarter').toDate();
        break;
      
      case 'lastQuarter':
        startDate = moment().subtract(1, 'quarter').startOf('quarter').toDate();
        endDate = moment().subtract(1, 'quarter').endOf('quarter').toDate();
        break;
      
      case 'thisYear':
        startDate = moment().startOf('year').toDate();
        endDate = moment().endOf('year').toDate();
        break;
      
      case 'lastYear':
        startDate = moment().subtract(1, 'year').startOf('year').toDate();
        endDate = moment().subtract(1, 'year').endOf('year').toDate();
        break;
      
      case 'custom':
        startDate = customStart ? new Date(customStart) : moment().subtract(30, 'days').toDate();
        endDate = customEnd ? new Date(customEnd) : now;
        break;
      
      default:
        startDate = moment().subtract(30, 'days').toDate();
        endDate = now;
    }

    return {
      startDate,
      endDate,
      period,
      days: moment(endDate).diff(moment(startDate), 'days') + 1
    };
  }

  /**
   * Generate admin report filename
   * @param {string} reportType - Type of report
   * @param {string} format - File format
   * @returns {string} Filename
   */
  static generateReportFilename(reportType, format = 'csv') {
    const timestamp = moment().format('YYYYMMDD_HHmmss');
    const sanitizedType = reportType.toLowerCase().replace(/[^a-z0-9]/g, '_');
    return `admin_report_${sanitizedType}_${timestamp}.${format}`;
  }

  /**
   * Format bytes for display
   * @param {number} bytes - Number of bytes
   * @param {number} decimals - Decimal places
   * @returns {string} Formatted size
   */
  static formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  /**
   * Calculate percentage change
   * @param {number} oldValue - Previous value
   * @param {number} newValue - New value
   * @returns {Object} Change details
   */
  static calculateChange(oldValue, newValue) {
    const change = newValue - oldValue;
    const percentageChange = oldValue !== 0 ? (change / oldValue) * 100 : 0;

    return {
      absolute: change,
      percentage: Math.round(percentageChange * 100) / 100,
      direction: change > 0 ? 'increase' : change < 0 ? 'decrease' : 'no_change',
      formatted: `${percentageChange > 0 ? '+' : ''}${percentageChange.toFixed(2)}%`
    };
  }

  /**
   * Validate admin operation context
   * @param {Object} context - Operation context
   * @returns {Object} Validation result
   */
  static validateOperationContext(context) {
    const errors = [];

    if (!context.userId) {
      errors.push('User ID is required for admin operations');
    }

    if (!context.adminRole) {
      errors.push('Admin role is required');
    }

    if (!context.sessionId) {
      errors.push('Session ID is required for audit trail');
    }

    const sensitiveOperations = ['delete', 'bulk_update', 'export', 'impersonate'];
    if (sensitiveOperations.includes(context.operation) && !context.reason) {
      errors.push(`Reason is required for ${context.operation} operations`);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Build admin breadcrumb trail
   * @param {Array} segments - URL segments
   * @returns {Array} Breadcrumb items
   */
  static buildBreadcrumbs(segments) {
    const breadcrumbs = [
      { label: 'Admin', path: '/admin' }
    ];

    let currentPath = '/admin';
    
    segments.forEach((segment, index) => {
      if (!segment) return;

      currentPath += `/${segment}`;
      
      // Format label
      const label = segment
        .split('-')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');

      breadcrumbs.push({
        label,
        path: currentPath,
        isCurrent: index === segments.length - 1
      });
    });

    return breadcrumbs;
  }

  /**
   * Generate admin activity summary
   * @param {Array} activities - Activity logs
   * @param {string} period - Time period
   * @returns {Object} Activity summary
   */
  static generateActivitySummary(activities, period = 'day') {
    const summary = {
      total: activities.length,
      byType: {},
      byUser: {},
      byHour: {},
      byResult: { success: 0, failure: 0 },
      criticalEvents: []
    };

    activities.forEach(activity => {
      // By type
      summary.byType[activity.type] = (summary.byType[activity.type] || 0) + 1;

      // By user
      if (activity.userId) {
        summary.byUser[activity.userId] = (summary.byUser[activity.userId] || 0) + 1;
      }

      // By hour
      const hour = moment(activity.timestamp).format('HH');
      summary.byHour[hour] = (summary.byHour[hour] || 0) + 1;

      // By result
      if (activity.result === 'success') {
        summary.byResult.success++;
      } else {
        summary.byResult.failure++;
      }

      // Critical events
      if (activity.severity === 'critical' || activity.severity === 'high') {
        summary.criticalEvents.push({
          type: activity.type,
          timestamp: activity.timestamp,
          userId: activity.userId,
          message: activity.message
        });
      }
    });

    // Calculate success rate
    summary.successRate = summary.total > 0 
      ? Math.round((summary.byResult.success / summary.total) * 100) 
      : 0;

    // Sort critical events by timestamp
    summary.criticalEvents.sort((a, b) => 
      new Date(b.timestamp) - new Date(a.timestamp)
    );

    return summary;
  }

  /**
   * Check if operation requires elevated privileges
   * @param {string} operation - Operation name
   * @returns {boolean} Requires elevation
   */
  static requiresElevatedPrivileges(operation) {
    const elevatedOperations = [
      'system_config_change',
      'user_impersonation',
      'emergency_access',
      'bulk_deletion',
      'security_policy_change',
      'audit_export',
      'platform_maintenance'
    ];

    return elevatedOperations.includes(operation);
  }

  /**
   * Mask sensitive data for logs
   * @param {any} data - Data to mask
   * @param {Array} fields - Fields to mask
   * @returns {any} Masked data
   */
  static maskSensitiveData(data, fields = []) {
    if (!data || typeof data !== 'object') return data;

    const defaultSensitiveFields = [
      'password', 'token', 'secret', 'apiKey', 'creditCard',
      'ssn', 'bankAccount', 'phoneNumber', 'email'
    ];

    const allFields = [...defaultSensitiveFields, ...fields];
    const masked = JSON.parse(JSON.stringify(data));

    const maskObject = (obj) => {
      Object.keys(obj).forEach(key => {
        const lowerKey = key.toLowerCase();
        
        if (allFields.some(field => lowerKey.includes(field.toLowerCase()))) {
          if (typeof obj[key] === 'string') {
            // Keep first and last 2 characters for reference
            if (obj[key].length > 4) {
              obj[key] = obj[key].substring(0, 2) + '***' + obj[key].slice(-2);
            } else {
              obj[key] = '***';
            }
          } else {
            obj[key] = '[MASKED]';
          }
        } else if (obj[key] && typeof obj[key] === 'object') {
          maskObject(obj[key]);
        }
      });
    };

    maskObject(masked);
    return masked;
  }

  /**
   * Generate admin notification message
   * @param {string} type - Notification type
   * @param {Object} data - Notification data
   * @returns {Object} Notification object
   */
  static generateNotification(type, data) {
    const templates = {
      user_created: {
        title: 'New User Created',
        message: `User ${data.email} was created by admin ${data.adminName}`,
        severity: 'info'
      },
      user_suspended: {
        title: 'User Suspended',
        message: `User ${data.email} was suspended. Reason: ${data.reason}`,
        severity: 'warning'
      },
      security_alert: {
        title: 'Security Alert',
        message: `${data.event}: ${data.description}`,
        severity: 'critical'
      },
      system_maintenance: {
        title: 'System Maintenance',
        message: `Maintenance ${data.status} by ${data.adminName}`,
        severity: 'info'
      },
      bulk_operation: {
        title: 'Bulk Operation Completed',
        message: `${data.operation} affected ${data.count} records`,
        severity: 'info'
      }
    };

    const template = templates[type] || {
      title: 'Admin Notification',
      message: JSON.stringify(data),
      severity: 'info'
    };

    return {
      id: crypto.randomUUID(),
      type,
      ...template,
      timestamp: new Date(),
      data,
      read: false
    };
  }

  /**
   * Validate resource limits
   * @param {Object} current - Current usage
   * @param {Object} limits - Resource limits
   * @returns {Object} Validation result
   */
  static validateResourceLimits(current, limits) {
    const violations = [];
    
    Object.keys(limits).forEach(resource => {
      if (current[resource] >= limits[resource]) {
        violations.push({
          resource,
          current: current[resource],
          limit: limits[resource],
          percentage: Math.round((current[resource] / limits[resource]) * 100)
        });
      }
    });

    return {
      withinLimits: violations.length === 0,
      violations,
      warnings: violations.filter(v => v.percentage >= 80 && v.percentage < 100)
    };
  }

  /**
   * Format duration for display
   * @param {number} milliseconds - Duration in milliseconds
   * @returns {string} Formatted duration
   */
  static formatDuration(milliseconds) {
    const duration = moment.duration(milliseconds);
    
    if (duration.days() > 0) {
      return `${duration.days()}d ${duration.hours()}h ${duration.minutes()}m`;
    } else if (duration.hours() > 0) {
      return `${duration.hours()}h ${duration.minutes()}m ${duration.seconds()}s`;
    } else if (duration.minutes() > 0) {
      return `${duration.minutes()}m ${duration.seconds()}s`;
    } else if (duration.seconds() > 0) {
      return `${duration.seconds()}.${Math.floor(duration.milliseconds() / 100)}s`;
    } else {
      return `${duration.milliseconds()}ms`;
    }
  }
}

module.exports = AdminHelpers;