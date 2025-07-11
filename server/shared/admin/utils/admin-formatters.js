/**
 * @file Admin Formatter Utilities
 * @description Data formatting utilities for administrative interfaces and reports
 * @version 1.0.0
 */

const moment = require('moment-timezone');
const numeral = require('numeral');
const crypto = require('crypto');
const config = require('../../../config/config');
const logger = require('../../../utils/logger');

/**
 * Admin Formatter Utilities Class
 * @class AdminFormatters
 */
class AdminFormatters {
  /**
   * Initialize formatter configurations
   */
  static initialize() {
    // Date/time format configurations
    this.dateFormats = {
      full: 'YYYY-MM-DD HH:mm:ss',
      date: 'YYYY-MM-DD',
      time: 'HH:mm:ss',
      short: 'MM/DD/YYYY',
      long: 'MMMM Do YYYY, h:mm:ss a',
      relative: 'fromNow',
      iso: 'YYYY-MM-DDTHH:mm:ss.SSSZ',
      audit: 'YYYY-MM-DD HH:mm:ss.SSS Z',
      filename: 'YYYYMMDD_HHmmss'
    };

    // Number format configurations
    this.numberFormats = {
      currency: '$0,0.00',
      percentage: '0.00%',
      integer: '0,0',
      decimal: '0,0.00',
      bytes: '0.0 b',
      abbreviated: '0.0a',
      ordinal: '0o'
    };

    // Status color mappings
    this.statusColors = {
      active: '#28a745',
      inactive: '#6c757d',
      pending: '#ffc107',
      suspended: '#dc3545',
      archived: '#343a40',
      success: '#28a745',
      warning: '#ffc107',
      error: '#dc3545',
      info: '#17a2b8'
    };

    // Priority mappings
    this.priorityLabels = {
      critical: { label: 'Critical', color: '#dc3545', weight: 5 },
      high: { label: 'High', color: '#fd7e14', weight: 4 },
      medium: { label: 'Medium', color: '#ffc107', weight: 3 },
      low: { label: 'Low', color: '#28a745', weight: 2 },
      minimal: { label: 'Minimal', color: '#6c757d', weight: 1 }
    };
  }

  /**
   * Format date/time values
   * @param {Date|string|number} value - Date value
   * @param {string} format - Format type or custom format
   * @param {string} timezone - Timezone (optional)
   * @returns {string} Formatted date
   */
  static formatDate(value, format = 'full', timezone = null) {
    if (!value) return 'N/A';

    try {
      const date = moment(value);
      if (!date.isValid()) return 'Invalid Date';

      // Apply timezone if specified
      if (timezone) {
        date.tz(timezone);
      }

      // Handle relative format
      if (format === 'relative' || format === 'fromNow') {
        return date.fromNow();
      }

      // Use predefined or custom format
      const formatString = this.dateFormats[format] || format;
      return date.format(formatString);
    } catch (error) {
      logger.error('Date formatting error', { error: error.message, value, format });
      return 'Format Error';
    }
  }

  /**
   * Format number values
   * @param {number|string} value - Number value
   * @param {string} format - Format type
   * @param {Object} options - Additional options
   * @returns {string} Formatted number
   */
  static formatNumber(value, format = 'integer', options = {}) {
    if (value === null || value === undefined) return 'N/A';

    try {
      const num = parseFloat(value);
      if (isNaN(num)) return 'Invalid Number';

      // Handle special formats
      if (format === 'bytes') {
        return this.formatBytes(num, options.decimals);
      }

      if (format === 'duration') {
        return this.formatDuration(num);
      }

      if (format === 'percentage' && options.decimal) {
        return numeral(num / 100).format(this.numberFormats.percentage);
      }

      // Use predefined or custom format
      const formatString = this.numberFormats[format] || format;
      return numeral(num).format(formatString);
    } catch (error) {
      logger.error('Number formatting error', { error: error.message, value, format });
      return 'Format Error';
    }
  }

  /**
   * Format currency values
   * @param {number} value - Currency value
   * @param {string} currency - Currency code
   * @param {Object} options - Format options
   * @returns {string} Formatted currency
   */
  static formatCurrency(value, currency = 'USD', options = {}) {
    if (value === null || value === undefined) return 'N/A';

    try {
      const {
        locale = 'en-US',
        minimumFractionDigits = 2,
        maximumFractionDigits = 2
      } = options;

      const formatter = new Intl.NumberFormat(locale, {
        style: 'currency',
        currency,
        minimumFractionDigits,
        maximumFractionDigits
      });

      return formatter.format(value);
    } catch (error) {
      logger.error('Currency formatting error', { error: error.message, value, currency });
      return this.formatNumber(value, 'currency');
    }
  }

  /**
   * Format user display information
   * @param {Object} user - User object
   * @param {Object} options - Display options
   * @returns {string} Formatted user display
   */
  static formatUser(user, options = {}) {
    if (!user) return 'Unknown User';

    const {
      showId = false,
      showEmail = true,
      showRole = true,
      format = 'full'
    } = options;

    try {
      const parts = [];

      // Name
      const name = user.displayName || `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'Unnamed User';
      parts.push(name);

      // Email
      if (showEmail && user.email) {
        parts.push(`<${user.email}>`);
      }

      // Role
      if (showRole && user.role) {
        const roleDisplay = user.role.primary || user.role;
        parts.push(`[${this.formatRole(roleDisplay)}]`);
      }

      // ID
      if (showId && user._id) {
        parts.push(`(${this.formatId(user._id)})`);
      }

      return parts.join(' ');
    } catch (error) {
      logger.error('User formatting error', { error: error.message, userId: user._id });
      return user.email || user._id || 'Unknown User';
    }
  }

  /**
   * Format role display
   * @param {string} role - Role identifier
   * @returns {string} Formatted role
   */
  static formatRole(role) {
    const roleDisplayMap = {
      super_admin: 'Super Admin',
      platform_admin: 'Platform Admin',
      organization_admin: 'Organization Admin',
      security_admin: 'Security Admin',
      admin: 'Admin',
      manager: 'Manager',
      client: 'Client',
      prospect: 'Prospect',
      user: 'User'
    };

    return roleDisplayMap[role] || role.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  /**
   * Format status with styling
   * @param {string} status - Status value
   * @param {Object} options - Display options
   * @returns {Object} Formatted status
   */
  static formatStatus(status, options = {}) {
    const {
      includeIcon = true,
      uppercase = false,
      customColors = {}
    } = options;

    const colors = { ...this.statusColors, ...customColors };
    const color = colors[status] || '#6c757d';

    const iconMap = {
      active: '✓',
      inactive: '○',
      pending: '⏳',
      suspended: '⚠',
      archived: '📁',
      success: '✓',
      warning: '⚠',
      error: '✗',
      info: 'ℹ'
    };

    const displayText = uppercase ? status.toUpperCase() : this.capitalize(status);
    const icon = includeIcon ? iconMap[status] || '•' : '';

    return {
      text: displayText,
      color,
      icon,
      html: `<span style="color: ${color}">${icon} ${displayText}</span>`,
      badge: `<span class="badge" style="background-color: ${color}">${displayText}</span>`
    };
  }

  /**
   * Format table data for display
   * @param {Array} data - Table data
   * @param {Object} columns - Column definitions
   * @param {Object} options - Display options
   * @returns {Array} Formatted table data
   */
  static formatTableData(data, columns, options = {}) {
    const {
      sortBy = null,
      sortOrder = 'asc',
      page = 1,
      limit = 20
    } = options;

    try {
      let formattedData = data.map(row => {
        const formattedRow = {};
        
        Object.keys(columns).forEach(key => {
          const column = columns[key];
          const value = this.getNestedValue(row, key);
          
          formattedRow[key] = this.formatCellValue(value, column);
        });
        
        return formattedRow;
      });

      // Apply sorting
      if (sortBy && columns[sortBy]) {
        formattedData = this.sortData(formattedData, sortBy, sortOrder);
      }

      // Apply pagination
      if (limit > 0) {
        const start = (page - 1) * limit;
        const end = start + limit;
        formattedData = formattedData.slice(start, end);
      }

      return formattedData;
    } catch (error) {
      logger.error('Table formatting error', { error: error.message });
      return data;
    }
  }

  /**
   * Format cell value based on column type
   * @param {any} value - Cell value
   * @param {Object} column - Column definition
   * @returns {string} Formatted value
   */
  static formatCellValue(value, column) {
    if (value === null || value === undefined) {
      return column.defaultValue || '-';
    }

    switch (column.type) {
      case 'date':
        return this.formatDate(value, column.format || 'short');
      
      case 'number':
        return this.formatNumber(value, column.format || 'integer');
      
      case 'currency':
        return this.formatCurrency(value, column.currency || 'USD');
      
      case 'boolean':
        return value ? '✓' : '✗';
      
      case 'status':
        return this.formatStatus(value).html;
      
      case 'array':
        return Array.isArray(value) ? value.join(', ') : value;
      
      case 'object':
        return column.accessor ? this.getNestedValue(value, column.accessor) : JSON.stringify(value);
      
      case 'custom':
        return column.formatter ? column.formatter(value) : value;
      
      default:
        return String(value);
    }
  }

  /**
   * Format report data
   * @param {Object} data - Report data
   * @param {string} reportType - Report type
   * @returns {Object} Formatted report
   */
  static formatReport(data, reportType) {
    const timestamp = new Date();
    
    const report = {
      metadata: {
        title: this.formatReportTitle(reportType),
        generatedAt: this.formatDate(timestamp, 'full'),
        generatedBy: data.generatedBy || 'System',
        reportId: this.generateReportId(reportType),
        parameters: data.parameters || {}
      },
      summary: this.formatReportSummary(data),
      data: this.formatReportData(data, reportType),
      charts: this.prepareChartData(data, reportType)
    };

    return report;
  }

  /**
   * Format error for display
   * @param {Error} error - Error object
   * @param {Object} options - Display options
   * @returns {Object} Formatted error
   */
  static formatError(error, options = {}) {
    const {
      includeStack = config.app.env === 'development',
      includeMetadata = true
    } = options;

    const formatted = {
      message: error.message || 'An error occurred',
      code: error.code || 'UNKNOWN_ERROR',
      type: error.name || 'Error',
      timestamp: this.formatDate(new Date(), 'full')
    };

    if (includeMetadata && error.metadata) {
      formatted.metadata = error.metadata;
    }

    if (includeStack && error.stack) {
      formatted.stack = this.formatStackTrace(error.stack);
    }

    return formatted;
  }

  /**
   * Format activity log entry
   * @param {Object} activity - Activity log entry
   * @returns {Object} Formatted activity
   */
  static formatActivity(activity) {
    return {
      timestamp: this.formatDate(activity.timestamp, 'full'),
      relativeTime: this.formatDate(activity.timestamp, 'relative'),
      user: this.formatUser(activity.user, { showEmail: false }),
      action: this.formatAction(activity.action),
      target: this.formatTarget(activity.target),
      result: this.formatStatus(activity.result),
      details: activity.metadata || {}
    };
  }

  /**
   * Format file size
   * @param {number} bytes - File size in bytes
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
   * Format duration
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

  /**
   * Format ID for display
   * @param {string} id - MongoDB ObjectId or UUID
   * @param {Object} options - Display options
   * @returns {string} Formatted ID
   */
  static formatId(id, options = {}) {
    const {
      truncate = true,
      length = 8,
      showPrefix = true
    } = options;

    if (!id) return 'N/A';

    const idString = String(id);
    
    if (truncate && idString.length > length) {
      const prefix = showPrefix ? idString.substring(0, 3) + '...' : '';
      const suffix = idString.substring(idString.length - length);
      return prefix + suffix;
    }

    return idString;
  }

  /**
   * Format address
   * @param {Object} address - Address object
   * @param {Object} options - Display options
   * @returns {string} Formatted address
   */
  static formatAddress(address, options = {}) {
    const {
      singleLine = false,
      includeCountry = true
    } = options;

    if (!address) return 'N/A';

    const parts = [
      address.street1,
      address.street2,
      address.city,
      address.state,
      address.postalCode,
      includeCountry ? address.country : null
    ].filter(Boolean);

    return singleLine ? parts.join(', ') : parts.join('\n');
  }

  /**
   * Format percentage
   * @param {number} value - Decimal value
   * @param {Object} options - Display options
   * @returns {string} Formatted percentage
   */
  static formatPercentage(value, options = {}) {
    const {
      decimals = 2,
      includeSign = false
    } = options;

    if (value === null || value === undefined) return 'N/A';

    const percentage = (value * 100).toFixed(decimals);
    const sign = includeSign && value > 0 ? '+' : '';
    
    return `${sign}${percentage}%`;
  }

  /**
   * Format list for display
   * @param {Array} items - List items
   * @param {Object} options - Display options
   * @returns {string} Formatted list
   */
  static formatList(items, options = {}) {
    const {
      separator = ', ',
      maxItems = 5,
      moreText = 'more'
    } = options;

    if (!Array.isArray(items) || items.length === 0) {
      return 'None';
    }

    if (items.length <= maxItems) {
      return items.join(separator);
    }

    const visibleItems = items.slice(0, maxItems);
    const remainingCount = items.length - maxItems;
    
    return `${visibleItems.join(separator)} and ${remainingCount} ${moreText}`;
  }

  /**
   * Helper methods
   */

  static capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
  }

  static getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  static sortData(data, key, order = 'asc') {
    return [...data].sort((a, b) => {
      const aVal = a[key];
      const bVal = b[key];
      
      if (aVal === null || aVal === undefined) return 1;
      if (bVal === null || bVal === undefined) return -1;
      
      if (aVal < bVal) return order === 'asc' ? -1 : 1;
      if (aVal > bVal) return order === 'asc' ? 1 : -1;
      return 0;
    });
  }

  static formatReportTitle(reportType) {
    return reportType
      .split('_')
      .map(word => this.capitalize(word))
      .join(' ') + ' Report';
  }

  static generateReportId(reportType) {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(4).toString('hex');
    return `${reportType}_${timestamp}_${random}`;
  }

  static formatReportSummary(data) {
    return {
      totalRecords: data.total || 0,
      dateRange: {
        start: this.formatDate(data.startDate, 'date'),
        end: this.formatDate(data.endDate, 'date')
      },
      filters: data.filters || {},
      aggregations: data.aggregations || {}
    };
  }

  static formatReportData(data, reportType) {
    // Implement specific formatting based on report type
    return data.results || data;
  }

  static prepareChartData(data, reportType) {
    // Prepare data for chart visualization
    return {
      labels: [],
      datasets: [],
      options: {}
    };
  }

  static formatStackTrace(stack) {
    return stack
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.startsWith('at'))
      .map(line => ({
        function: line.match(/at (.+?) \(/)?.[1] || 'anonymous',
        location: line.match(/\((.+?)\)/)?.[1] || line
      }));
  }

  static formatAction(action) {
    const actionMap = {
      create: 'Created',
      update: 'Updated',
      delete: 'Deleted',
      read: 'Viewed',
      login: 'Logged in',
      logout: 'Logged out'
    };
    
    return actionMap[action] || this.capitalize(action);
  }

  static formatTarget(target) {
    if (!target) return 'N/A';
    
    return {
      type: this.capitalize(target.type),
      id: this.formatId(target.id),
      name: target.name || 'Unnamed'
    };
  }

  /**
   * Format markdown table
   * @param {Array} data - Table data
   * @param {Array} headers - Table headers
   * @returns {string} Markdown table
   */
  static formatMarkdownTable(data, headers) {
    if (!data || data.length === 0) {
      return 'No data available';
    }

    const headerRow = `| ${headers.join(' | ')} |`;
    const separatorRow = `| ${headers.map(() => '---').join(' | ')} |`;
    
    const dataRows = data.map(row => {
      const cells = headers.map(header => {
        const value = row[header] || '-';
        return String(value).replace(/\|/g, '\\|');
      });
      return `| ${cells.join(' | ')} |`;
    });

    return [headerRow, separatorRow, ...dataRows].join('\n');
  }

  /**
   * Format JSON for display
   * @param {Object} obj - Object to format
   * @param {Object} options - Display options
   * @returns {string} Formatted JSON
   */
  static formatJSON(obj, options = {}) {
    const {
      indent = 2,
      maxDepth = 10,
      sortKeys = false
    } = options;

    try {
      if (sortKeys) {
        obj = this.sortObjectKeys(obj);
      }
      
      return JSON.stringify(obj, null, indent);
    } catch (error) {
      return '[Circular Reference]';
    }
  }

  static sortObjectKeys(obj) {
    if (Array.isArray(obj)) {
      return obj.map(item => this.sortObjectKeys(item));
    } else if (obj !== null && typeof obj === 'object') {
      return Object.keys(obj)
        .sort()
        .reduce((result, key) => {
          result[key] = this.sortObjectKeys(obj[key]);
          return result;
        }, {});
    }
    return obj;
  }
}

// Initialize on module load
AdminFormatters.initialize();

module.exports = AdminFormatters;