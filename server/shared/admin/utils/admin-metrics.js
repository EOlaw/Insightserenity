/**
 * @file Admin Metrics Utilities
 * @description Performance and usage metrics tracking for administrative operations
 * @version 1.0.0
 */

const crypto = require('crypto');
const os = require('os');
const { CacheService } = require('../../../services/cache-service');
const AdminLogger = require('./admin-logger');
const AdminFormatters = require('./admin-formatters');
const config = require('../../../config/config');

/**
 * Admin Metrics Class
 * @class AdminMetrics
 */
class AdminMetrics {
  /**
   * Initialize metrics tracking
   */
  static initialize() {
    this.cache = new CacheService('admin:metrics');
    
    // Metric types
    this.metricTypes = {
      COUNTER: 'counter',
      GAUGE: 'gauge',
      HISTOGRAM: 'histogram',
      SUMMARY: 'summary'
    };
    
    // Metric storage
    this.metrics = new Map();
    this.timeSeries = new Map();
    this.aggregations = new Map();
    
    // Collection intervals
    this.intervals = {
      realtime: 1000,     // 1 second
      minute: 60000,      // 1 minute
      hour: 3600000,      // 1 hour
      day: 86400000       // 1 day
    };
    
    // System metrics collection
    this.systemMetrics = {
      cpu: [],
      memory: [],
      disk: [],
      network: []
    };
    
    // Performance thresholds
    this.thresholds = {
      responseTime: {
        excellent: 100,
        good: 500,
        acceptable: 1000,
        poor: 3000
      },
      errorRate: {
        excellent: 0.01,
        good: 0.05,
        acceptable: 0.10,
        poor: 0.20
      },
      availability: {
        excellent: 0.999,
        good: 0.995,
        acceptable: 0.99,
        poor: 0.95
      }
    };
    
    // Start metric collection
    this.startCollection();
  }

  /**
   * Start metric collection intervals
   */
  static startCollection() {
    // Collect system metrics every minute
    setInterval(() => {
      this.collectSystemMetrics();
    }, this.intervals.minute);
    
    // Aggregate metrics every hour
    setInterval(() => {
      this.aggregateMetrics('hour');
    }, this.intervals.hour);
    
    // Clean old metrics daily
    setInterval(() => {
      this.cleanOldMetrics();
    }, this.intervals.day);
  }

  /**
   * Track metric value
   * @param {string} name - Metric name
   * @param {number} value - Metric value
   * @param {Object} options - Metric options
   */
  static track(name, value, options = {}) {
    const {
      type = this.metricTypes.COUNTER,
      tags = {},
      unit = 'count',
      timestamp = Date.now()
    } = options;
    
    const metric = this.getOrCreateMetric(name, type, unit);
    
    switch (type) {
      case this.metricTypes.COUNTER:
        this.incrementCounter(metric, value, tags, timestamp);
        break;
      
      case this.metricTypes.GAUGE:
        this.updateGauge(metric, value, tags, timestamp);
        break;
      
      case this.metricTypes.HISTOGRAM:
        this.recordHistogram(metric, value, tags, timestamp);
        break;
      
      case this.metricTypes.SUMMARY:
        this.recordSummary(metric, value, tags, timestamp);
        break;
    }
    
    // Store time series data
    this.storeTimeSeries(name, value, tags, timestamp);
  }

  /**
   * Track admin operation metrics
   * @param {string} operation - Operation name
   * @param {Object} metrics - Operation metrics
   */
  static trackOperation(operation, metrics) {
    const {
      duration,
      success,
      userId,
      resource,
      action
    } = metrics;
    
    // Track operation duration
    this.track(`admin.operation.duration`, duration, {
      type: this.metricTypes.HISTOGRAM,
      tags: { operation, resource, action },
      unit: 'milliseconds'
    });
    
    // Track operation count
    this.track(`admin.operation.count`, 1, {
      type: this.metricTypes.COUNTER,
      tags: { operation, resource, action, result: success ? 'success' : 'failure' }
    });
    
    // Track user activity
    if (userId) {
      this.track(`admin.user.activity`, 1, {
        type: this.metricTypes.COUNTER,
        tags: { userId, operation }
      });
    }
    
    // Check performance thresholds
    this.checkPerformanceThresholds(operation, duration);
  }

  /**
   * Track error metrics
   * @param {Error} error - Error object
   * @param {Object} context - Error context
   */
  static trackError(error, context = {}) {
    const {
      operation,
      userId,
      severity = 'error'
    } = context;
    
    // Track error count
    this.track('admin.errors.count', 1, {
      type: this.metricTypes.COUNTER,
      tags: {
        errorType: error.name,
        errorCode: error.code || 'UNKNOWN',
        operation,
        severity
      }
    });
    
    // Track error rate
    this.updateErrorRate(operation);
    
    // Log error metric
    AdminLogger.error('Admin error tracked', {
      error: error.message,
      operation,
      userId,
      metric: 'error_tracking'
    });
  }

  /**
   * Track security metrics
   * @param {string} event - Security event
   * @param {Object} details - Event details
   */
  static trackSecurity(event, details = {}) {
    const {
      userId,
      ip,
      result,
      risk = 'medium'
    } = details;
    
    // Track security event
    this.track('admin.security.events', 1, {
      type: this.metricTypes.COUNTER,
      tags: { event, result, risk }
    });
    
    // Track by user if available
    if (userId) {
      this.track('admin.security.user_events', 1, {
        type: this.metricTypes.COUNTER,
        tags: { userId, event }
      });
    }
    
    // Track by IP if available
    if (ip) {
      this.track('admin.security.ip_events', 1, {
        type: this.metricTypes.COUNTER,
        tags: { ip, event }
      });
    }
  }

  /**
   * Get or create metric
   * @param {string} name - Metric name
   * @param {string} type - Metric type
   * @param {string} unit - Metric unit
   * @returns {Object} Metric object
   */
  static getOrCreateMetric(name, type, unit) {
    let metric = this.metrics.get(name);
    
    if (!metric) {
      metric = {
        name,
        type,
        unit,
        createdAt: Date.now(),
        values: [],
        tags: new Map(),
        statistics: {
          count: 0,
          sum: 0,
          min: Infinity,
          max: -Infinity,
          mean: 0,
          lastValue: null,
          lastUpdate: null
        }
      };
      
      this.metrics.set(name, metric);
    }
    
    return metric;
  }

  /**
   * Increment counter metric
   * @param {Object} metric - Metric object
   * @param {number} value - Increment value
   * @param {Object} tags - Metric tags
   * @param {number} timestamp - Timestamp
   */
  static incrementCounter(metric, value, tags, timestamp) {
    metric.statistics.count += value;
    metric.statistics.sum += value;
    metric.statistics.lastValue = value;
    metric.statistics.lastUpdate = timestamp;
    
    // Update tag-specific counters
    const tagKey = this.generateTagKey(tags);
    const tagCounter = metric.tags.get(tagKey) || 0;
    metric.tags.set(tagKey, tagCounter + value);
  }

  /**
   * Update gauge metric
   * @param {Object} metric - Metric object
   * @param {number} value - Gauge value
   * @param {Object} tags - Metric tags
   * @param {number} timestamp - Timestamp
   */
  static updateGauge(metric, value, tags, timestamp) {
    metric.statistics.lastValue = value;
    metric.statistics.lastUpdate = timestamp;
    metric.statistics.count++;
    
    // Track min/max
    metric.statistics.min = Math.min(metric.statistics.min, value);
    metric.statistics.max = Math.max(metric.statistics.max, value);
    
    // Update running average
    metric.statistics.sum += value;
    metric.statistics.mean = metric.statistics.sum / metric.statistics.count;
    
    // Store recent values for percentile calculations
    metric.values.push({ value, timestamp, tags });
    if (metric.values.length > 1000) {
      metric.values.shift();
    }
  }

  /**
   * Record histogram metric
   * @param {Object} metric - Metric object
   * @param {number} value - Value to record
   * @param {Object} tags - Metric tags
   * @param {number} timestamp - Timestamp
   */
  static recordHistogram(metric, value, tags, timestamp) {
    this.updateGauge(metric, value, tags, timestamp);
    
    // Calculate histogram buckets
    if (!metric.buckets) {
      metric.buckets = this.createHistogramBuckets(metric.unit);
    }
    
    // Update bucket counts
    for (const bucket of metric.buckets) {
      if (value <= bucket.upperBound) {
        bucket.count++;
      }
    }
  }

  /**
   * Record summary metric
   * @param {Object} metric - Metric object
   * @param {number} value - Value to record
   * @param {Object} tags - Metric tags
   * @param {number} timestamp - Timestamp
   */
  static recordSummary(metric, value, tags, timestamp) {
    this.updateGauge(metric, value, tags, timestamp);
    
    // Calculate percentiles
    if (metric.values.length >= 10) {
      const sortedValues = metric.values
        .map(v => v.value)
        .sort((a, b) => a - b);
      
      metric.statistics.percentiles = {
        p50: this.calculatePercentile(sortedValues, 0.50),
        p75: this.calculatePercentile(sortedValues, 0.75),
        p90: this.calculatePercentile(sortedValues, 0.90),
        p95: this.calculatePercentile(sortedValues, 0.95),
        p99: this.calculatePercentile(sortedValues, 0.99)
      };
    }
  }

  /**
   * Store time series data
   * @param {string} name - Metric name
   * @param {number} value - Metric value
   * @param {Object} tags - Metric tags
   * @param {number} timestamp - Timestamp
   */
  static storeTimeSeries(name, value, tags, timestamp) {
    const seriesKey = `${name}:${this.generateTagKey(tags)}`;
    let series = this.timeSeries.get(seriesKey);
    
    if (!series) {
      series = {
        name,
        tags,
        points: []
      };
      this.timeSeries.set(seriesKey, series);
    }
    
    // Add data point
    series.points.push({ timestamp, value });
    
    // Keep only recent points (last 24 hours)
    const cutoff = timestamp - (24 * 60 * 60 * 1000);
    series.points = series.points.filter(p => p.timestamp > cutoff);
  }

  /**
   * Collect system metrics
   */
  static async collectSystemMetrics() {
    try {
      // CPU usage
      const cpuUsage = process.cpuUsage();
      const cpuPercent = (cpuUsage.user + cpuUsage.system) / 1000000; // Convert to seconds
      
      this.track('admin.system.cpu', cpuPercent, {
        type: this.metricTypes.GAUGE,
        unit: 'percentage'
      });
      
      // Memory usage
      const memUsage = process.memoryUsage();
      const totalMem = os.totalmem();
      const memPercent = (memUsage.heapUsed / totalMem) * 100;
      
      this.track('admin.system.memory', memPercent, {
        type: this.metricTypes.GAUGE,
        unit: 'percentage'
      });
      
      this.track('admin.system.memory.heap', memUsage.heapUsed, {
        type: this.metricTypes.GAUGE,
        unit: 'bytes'
      });
      
      // System load average
      const loadAvg = os.loadavg();
      this.track('admin.system.load', loadAvg[0], {
        type: this.metricTypes.GAUGE,
        tags: { interval: '1min' }
      });
      
      // Connection count
      const connections = process._getActiveHandles().length;
      this.track('admin.system.connections', connections, {
        type: this.metricTypes.GAUGE
      });
      
    } catch (error) {
      AdminLogger.error('Failed to collect system metrics', { error: error.message });
    }
  }

  /**
   * Get metric statistics
   * @param {string} name - Metric name
   * @param {Object} options - Query options
   * @returns {Object} Metric statistics
   */
  static getMetricStats(name, options = {}) {
    const {
      tags = {},
      startTime,
      endTime,
      aggregation = 'none'
    } = options;
    
    const metric = this.metrics.get(name);
    if (!metric) return null;
    
    // Filter by time range if specified
    let values = metric.values;
    if (startTime || endTime) {
      values = values.filter(v => {
        const inRange = (!startTime || v.timestamp >= startTime) &&
                       (!endTime || v.timestamp <= endTime);
        return inRange;
      });
    }
    
    // Filter by tags if specified
    if (Object.keys(tags).length > 0) {
      values = values.filter(v => {
        return Object.entries(tags).every(([key, value]) => v.tags[key] === value);
      });
    }
    
    // Calculate statistics
    const stats = this.calculateStatistics(values.map(v => v.value));
    
    return {
      name: metric.name,
      type: metric.type,
      unit: metric.unit,
      ...stats,
      sampleCount: values.length,
      timeRange: {
        start: values[0]?.timestamp,
        end: values[values.length - 1]?.timestamp
      }
    };
  }

  /**
   * Get time series data
   * @param {string} name - Metric name
   * @param {Object} options - Query options
   * @returns {Array} Time series data
   */
  static getTimeSeries(name, options = {}) {
    const {
      tags = {},
      startTime = Date.now() - 3600000, // Last hour
      endTime = Date.now(),
      interval = 'minute',
      aggregation = 'avg'
    } = options;
    
    const seriesKey = `${name}:${this.generateTagKey(tags)}`;
    const series = this.timeSeries.get(seriesKey);
    
    if (!series) return [];
    
    // Filter by time range
    const points = series.points.filter(p => 
      p.timestamp >= startTime && p.timestamp <= endTime
    );
    
    // Aggregate if requested
    if (interval !== 'none') {
      return this.aggregateTimeSeries(points, interval, aggregation);
    }
    
    return points;
  }

  /**
   * Get dashboard metrics
   * @returns {Object} Dashboard metrics
   */
  static getDashboardMetrics() {
    const now = Date.now();
    const hourAgo = now - 3600000;
    const dayAgo = now - 86400000;
    
    return {
      overview: {
        totalOperations: this.getMetricValue('admin.operation.count') || 0,
        activeUsers: this.getActiveUserCount(),
        errorRate: this.calculateErrorRate(),
        avgResponseTime: this.getAverageResponseTime()
      },
      performance: {
        responseTime: this.getMetricStats('admin.operation.duration', { startTime: hourAgo }),
        throughput: this.calculateThroughput(hourAgo, now),
        availability: this.calculateAvailability()
      },
      system: {
        cpu: this.getMetricValue('admin.system.cpu'),
        memory: this.getMetricValue('admin.system.memory'),
        load: this.getMetricValue('admin.system.load'),
        connections: this.getMetricValue('admin.system.connections')
      },
      security: {
        failedLogins: this.getMetricValue('admin.security.events', { tags: { event: 'login_failed' } }),
        blockedIPs: this.getMetricValue('admin.security.events', { tags: { event: 'ip_blocked' } }),
        suspiciousActivities: this.getMetricValue('admin.security.events', { tags: { risk: 'high' } })
      },
      trends: {
        hourly: this.getHourlyTrends(),
        daily: this.getDailyTrends()
      }
    };
  }

  /**
   * Generate metric report
   * @param {Object} options - Report options
   * @returns {Object} Metric report
   */
  static generateReport(options = {}) {
    const {
      startDate = new Date(Date.now() - 86400000), // Last 24 hours
      endDate = new Date(),
      metrics = ['operations', 'performance', 'errors', 'security'],
      format = 'summary'
    } = options;
    
    const report = {
      metadata: {
        generatedAt: new Date(),
        period: {
          start: startDate,
          end: endDate
        },
        format
      },
      metrics: {}
    };
    
    // Collect requested metrics
    if (metrics.includes('operations')) {
      report.metrics.operations = this.getOperationMetrics(startDate, endDate);
    }
    
    if (metrics.includes('performance')) {
      report.metrics.performance = this.getPerformanceMetrics(startDate, endDate);
    }
    
    if (metrics.includes('errors')) {
      report.metrics.errors = this.getErrorMetrics(startDate, endDate);
    }
    
    if (metrics.includes('security')) {
      report.metrics.security = this.getSecurityMetrics(startDate, endDate);
    }
    
    // Add insights
    report.insights = this.generateInsights(report.metrics);
    
    return report;
  }

  /**
   * Helper methods
   */

  static generateTagKey(tags) {
    return Object.entries(tags)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}:${v}`)
      .join(',');
  }

  static createHistogramBuckets(unit) {
    const buckets = [];
    
    if (unit === 'milliseconds') {
      // Response time buckets
      const bounds = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
      bounds.forEach(bound => {
        buckets.push({ upperBound: bound, count: 0 });
      });
    } else {
      // Generic buckets
      for (let i = 1; i <= 10; i++) {
        buckets.push({ upperBound: i * 10, count: 0 });
      }
    }
    
    return buckets;
  }

  static calculatePercentile(sortedArray, percentile) {
    const index = Math.ceil(sortedArray.length * percentile) - 1;
    return sortedArray[index];
  }

  static calculateStatistics(values) {
    if (values.length === 0) {
      return {
        count: 0,
        sum: 0,
        min: null,
        max: null,
        mean: null,
        median: null,
        stdDev: null
      };
    }
    
    const sorted = [...values].sort((a, b) => a - b);
    const sum = values.reduce((a, b) => a + b, 0);
    const mean = sum / values.length;
    
    // Calculate standard deviation
    const squareDiffs = values.map(value => Math.pow(value - mean, 2));
    const avgSquareDiff = squareDiffs.reduce((a, b) => a + b, 0) / values.length;
    const stdDev = Math.sqrt(avgSquareDiff);
    
    return {
      count: values.length,
      sum,
      min: sorted[0],
      max: sorted[sorted.length - 1],
      mean,
      median: sorted[Math.floor(sorted.length / 2)],
      stdDev
    };
  }

  static aggregateTimeSeries(points, interval, aggregation) {
    const intervalMs = this.intervals[interval] || 60000;
    const aggregated = new Map();
    
    // Group points by interval
    points.forEach(point => {
      const bucket = Math.floor(point.timestamp / intervalMs) * intervalMs;
      
      if (!aggregated.has(bucket)) {
        aggregated.set(bucket, []);
      }
      
      aggregated.get(bucket).push(point.value);
    });
    
    // Apply aggregation function
    const result = [];
    for (const [timestamp, values] of aggregated.entries()) {
      let value;
      
      switch (aggregation) {
        case 'sum':
          value = values.reduce((a, b) => a + b, 0);
          break;
        case 'avg':
          value = values.reduce((a, b) => a + b, 0) / values.length;
          break;
        case 'min':
          value = Math.min(...values);
          break;
        case 'max':
          value = Math.max(...values);
          break;
        case 'count':
          value = values.length;
          break;
        default:
          value = values[values.length - 1]; // Last value
      }
      
      result.push({ timestamp, value });
    }
    
    return result.sort((a, b) => a.timestamp - b.timestamp);
  }

  static getMetricValue(name, options = {}) {
    const metric = this.metrics.get(name);
    if (!metric) return null;
    
    if (Object.keys(options.tags || {}).length > 0) {
      const tagKey = this.generateTagKey(options.tags);
      return metric.tags.get(tagKey) || 0;
    }
    
    return metric.statistics.lastValue;
  }

  static getActiveUserCount() {
    const metric = this.metrics.get('admin.user.activity');
    if (!metric) return 0;
    
    // Count unique users in last hour
    const hourAgo = Date.now() - 3600000;
    const recentActivity = metric.values.filter(v => v.timestamp > hourAgo);
    const uniqueUsers = new Set(recentActivity.map(v => v.tags.userId));
    
    return uniqueUsers.size;
  }

  static calculateErrorRate() {
    const operations = this.getMetricValue('admin.operation.count') || 0;
    const errors = this.getMetricValue('admin.errors.count') || 0;
    
    return operations > 0 ? (errors / operations) : 0;
  }

  static getAverageResponseTime() {
    const metric = this.metrics.get('admin.operation.duration');
    return metric?.statistics.mean || 0;
  }

  static calculateThroughput(startTime, endTime) {
    const metric = this.metrics.get('admin.operation.count');
    if (!metric) return 0;
    
    const operations = metric.values.filter(v => 
      v.timestamp >= startTime && v.timestamp <= endTime
    );
    
    const duration = (endTime - startTime) / 1000; // Convert to seconds
    return operations.length / duration;
  }

  static calculateAvailability() {
    // Calculate based on successful operations vs total
    const total = this.getMetricValue('admin.operation.count') || 0;
    const failures = this.getMetricValue('admin.operation.count', { tags: { result: 'failure' } }) || 0;
    
    return total > 0 ? ((total - failures) / total) : 1;
  }

  static checkPerformanceThresholds(operation, duration) {
    const threshold = this.thresholds.responseTime;
    let level = 'excellent';
    
    if (duration > threshold.poor) level = 'poor';
    else if (duration > threshold.acceptable) level = 'acceptable';
    else if (duration > threshold.good) level = 'good';
    
    if (level === 'poor' || level === 'acceptable') {
      AdminLogger.warning('Performance threshold exceeded', {
        operation,
        duration,
        level,
        threshold: threshold[level]
      });
    }
  }

  static updateErrorRate(operation) {
    const errorRate = this.calculateErrorRate();
    
    if (errorRate > this.thresholds.errorRate.poor) {
      AdminLogger.alert('High error rate detected', {
        errorRate,
        threshold: this.thresholds.errorRate.poor,
        operation
      });
    }
  }

  static getHourlyTrends() {
    const trends = [];
    const now = Date.now();
    
    for (let i = 23; i >= 0; i--) {
      const hourStart = now - (i * 3600000);
      const hourEnd = hourStart + 3600000;
      
      trends.push({
        hour: new Date(hourStart).getHours(),
        operations: this.getOperationsInRange(hourStart, hourEnd),
        errors: this.getErrorsInRange(hourStart, hourEnd),
        avgResponseTime: this.getAvgResponseTimeInRange(hourStart, hourEnd)
      });
    }
    
    return trends;
  }

  static getDailyTrends() {
    const trends = [];
    const now = Date.now();
    
    for (let i = 6; i >= 0; i--) {
      const dayStart = now - (i * 86400000);
      const dayEnd = dayStart + 86400000;
      
      trends.push({
        date: AdminFormatters.formatDate(dayStart, 'date'),
        operations: this.getOperationsInRange(dayStart, dayEnd),
        errors: this.getErrorsInRange(dayStart, dayEnd),
        avgResponseTime: this.getAvgResponseTimeInRange(dayStart, dayEnd)
      });
    }
    
    return trends;
  }

  static getOperationsInRange(startTime, endTime) {
    const metric = this.metrics.get('admin.operation.count');
    if (!metric) return 0;
    
    return metric.values.filter(v => 
      v.timestamp >= startTime && v.timestamp <= endTime
    ).length;
  }

  static getErrorsInRange(startTime, endTime) {
    const metric = this.metrics.get('admin.errors.count');
    if (!metric) return 0;
    
    return metric.values.filter(v => 
      v.timestamp >= startTime && v.timestamp <= endTime
    ).length;
  }

  static getAvgResponseTimeInRange(startTime, endTime) {
    const metric = this.metrics.get('admin.operation.duration');
    if (!metric) return 0;
    
    const values = metric.values
      .filter(v => v.timestamp >= startTime && v.timestamp <= endTime)
      .map(v => v.value);
    
    if (values.length === 0) return 0;
    
    return values.reduce((a, b) => a + b, 0) / values.length;
  }

  static getOperationMetrics(startDate, endDate) {
    const startTime = startDate.getTime();
    const endTime = endDate.getTime();
    
    return {
      total: this.getOperationsInRange(startTime, endTime),
      byType: this.getOperationsByType(startTime, endTime),
      topUsers: this.getTopUsers(startTime, endTime),
      hourlyDistribution: this.getHourlyDistribution(startTime, endTime)
    };
  }

  static getPerformanceMetrics(startDate, endDate) {
    const metric = this.metrics.get('admin.operation.duration');
    if (!metric) return {};
    
    const values = metric.values
      .filter(v => v.timestamp >= startDate.getTime() && v.timestamp <= endDate.getTime())
      .map(v => v.value);
    
    return this.calculateStatistics(values);
  }

  static getErrorMetrics(startDate, endDate) {
    const startTime = startDate.getTime();
    const endTime = endDate.getTime();
    
    return {
      total: this.getErrorsInRange(startTime, endTime),
      rate: this.calculateErrorRate(),
      byType: this.getErrorsByType(startTime, endTime),
      topOperations: this.getTopErrorOperations(startTime, endTime)
    };
  }

  static getSecurityMetrics(startDate, endDate) {
    const metric = this.metrics.get('admin.security.events');
    if (!metric) return {};
    
    const events = metric.values.filter(v => 
      v.timestamp >= startDate.getTime() && v.timestamp <= endDate.getTime()
    );
    
    return {
      total: events.length,
      byType: this.groupByTag(events, 'event'),
      byRisk: this.groupByTag(events, 'risk'),
      timeline: this.createTimeline(events)
    };
  }

  static generateInsights(metrics) {
    const insights = [];
    
    // Performance insights
    if (metrics.performance?.mean > this.thresholds.responseTime.acceptable) {
      insights.push({
        type: 'performance',
        severity: 'warning',
        message: `Average response time (${Math.round(metrics.performance.mean)}ms) exceeds acceptable threshold`,
        recommendation: 'Consider optimizing slow operations or scaling resources'
      });
    }
    
    // Error insights
    if (metrics.errors?.rate > this.thresholds.errorRate.good) {
      insights.push({
        type: 'reliability',
        severity: 'warning',
        message: `Error rate (${(metrics.errors.rate * 100).toFixed(2)}%) is above normal levels`,
        recommendation: 'Investigate recent errors and implement fixes'
      });
    }
    
    // Security insights
    if (metrics.security?.byRisk?.high > 10) {
      insights.push({
        type: 'security',
        severity: 'alert',
        message: `${metrics.security.byRisk.high} high-risk security events detected`,
        recommendation: 'Review security logs and strengthen access controls'
      });
    }
    
    return insights;
  }

  static groupByTag(values, tagName) {
    const groups = {};
    
    values.forEach(v => {
      const tagValue = v.tags[tagName] || 'unknown';
      groups[tagValue] = (groups[tagValue] || 0) + 1;
    });
    
    return groups;
  }

  static createTimeline(events) {
    // Group events by hour
    const timeline = {};
    
    events.forEach(event => {
      const hour = new Date(event.timestamp).getHours();
      timeline[hour] = (timeline[hour] || 0) + 1;
    });
    
    return timeline;
  }

  static cleanOldMetrics() {
    const cutoff = Date.now() - (7 * 24 * 60 * 60 * 1000); // 7 days
    
    // Clean metric values
    for (const metric of this.metrics.values()) {
      metric.values = metric.values.filter(v => v.timestamp > cutoff);
    }
    
    // Clean time series
    for (const series of this.timeSeries.values()) {
      series.points = series.points.filter(p => p.timestamp > cutoff);
    }
    
    AdminLogger.info('Old metrics cleaned', {
      cutoffDate: new Date(cutoff),
      category: 'maintenance'
    });
  }

  // Placeholder methods for complex aggregations
  static getOperationsByType(startTime, endTime) {
    return {};
  }

  static getTopUsers(startTime, endTime) {
    return [];
  }

  static getHourlyDistribution(startTime, endTime) {
    return {};
  }

  static getErrorsByType(startTime, endTime) {
    return {};
  }

  static getTopErrorOperations(startTime, endTime) {
    return [];
  }
}

// Initialize on module load
AdminMetrics.initialize();

module.exports = AdminMetrics;