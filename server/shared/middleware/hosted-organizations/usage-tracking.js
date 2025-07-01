/**
 * @file Usage Tracking Middleware
 * @description Middleware for tracking resource usage in hosted organizations
 * @version 1.0.0
 */

const logger = require('../../utils/logger');
const OrganizationTenantService = require('../../../organization-tenants/services/organization-tenant-service');
const { EventEmitter } = require('../../utils/events/event-emitter');

/**
 * Track usage for various resources
 * @param {Object} options - Usage tracking options
 * @param {string|array} options.resources - Resource types to track
 * @param {boolean} options.realtime - Whether to update usage in real-time (default: false)
 * @param {boolean} options.batch - Whether to batch usage updates (default: true)
 * @returns {Function} Express middleware function
 */
const trackUsage = (options = {}) => {
  const {
    resources = ['api_calls'],
    realtime = false,
    batch = true
  } = options;

  const resourcesToTrack = Array.isArray(resources) ? resources : [resources];

  return async (req, res, next) => {
    try {
      // Skip tracking for certain conditions
      if (shouldSkipUsageTracking(req)) {
        return next();
      }

      // Ensure tenant context exists
      if (!req.tenant) {
        return next();
      }

      // Track request start time
      req.usageTracking = {
        startTime: Date.now(),
        resources: resourcesToTrack,
        tenant: req.tenant
      };

      // Override res.end to capture response information
      const originalEnd = res.end;
      res.end = function(chunk, encoding) {
        // Call original end function
        originalEnd.call(this, chunk, encoding);

        // Track usage after response
        setImmediate(() => {
          trackRequestUsage(req, res, options);
        });
      };

      next();

    } catch (error) {
      logger.error('Usage tracking middleware error', {
        error: error.message,
        stack: error.stack,
        tenantId: req.tenant?._id,
        path: req.path,
        method: req.method
      });
      next();
    }
  };
};

/**
 * Track usage for a completed request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Object} options - Tracking options
 */
async function trackRequestUsage(req, res, options) {
  try {
    if (!req.usageTracking || !req.tenant) {
      return;
    }

    const endTime = Date.now();
    const duration = endTime - req.usageTracking.startTime;
    const usageData = calculateUsageMetrics(req, res, duration);

    // Track each resource type
    for (const resource of req.usageTracking.resources) {
      const increment = getResourceIncrement(resource, usageData);
      
      if (increment > 0) {
        if (options.realtime) {
          // Update usage immediately
          await updateUsageRealtime(req.tenant._id, resource, increment, usageData);
        } else if (options.batch) {
          // Queue for batch processing
          queueUsageUpdate(req.tenant._id, resource, increment, usageData);
        }
      }
    }

    // Emit usage event for analytics
    EventEmitter.emit('usage:tracked', {
      tenantId: req.tenant._id,
      organizationId: req.tenant.organizationId,
      path: req.path,
      method: req.method,
      statusCode: res.statusCode,
      duration,
      usageData,
      timestamp: new Date()
    });

    logger.debug('Usage tracked', {
      tenantId: req.tenant._id,
      path: req.path,
      method: req.method,
      statusCode: res.statusCode,
      duration,
      resources: req.usageTracking.resources
    });

  } catch (error) {
    logger.error('Error tracking request usage', {
      error: error.message,
      tenantId: req.tenant?._id,
      path: req.path,
      method: req.method
    });
  }
}

/**
 * Calculate usage metrics from request/response
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {number} duration - Request duration in milliseconds
 * @returns {Object} Usage metrics
 */
function calculateUsageMetrics(req, res, duration) {
  // Get request size
  const requestSize = getRequestSize(req);
  
  // Get response size
  const responseSize = getResponseSize(res);
  
  // Calculate bandwidth
  const bandwidth = requestSize + responseSize;

  return {
    requestSize,
    responseSize,
    bandwidth,
    duration,
    statusCode: res.statusCode,
    success: res.statusCode >= 200 && res.statusCode < 400,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    timestamp: new Date()
  };
}

/**
 * Get increment value for a specific resource
 * @param {string} resource - Resource type
 * @param {Object} usageData - Usage metrics
 * @returns {number} Increment value
 */
function getResourceIncrement(resource, usageData) {
  switch (resource) {
    case 'api_calls':
      return usageData.success ? 1 : 0; // Only count successful calls
    case 'bandwidth':
      return usageData.bandwidth;
    case 'storage':
      // Storage increments are typically handled separately
      return 0;
    case 'requests':
      return 1;
    case 'errors':
      return usageData.success ? 0 : 1;
    default:
      return 1;
  }
}

/**
 * Update usage in real-time
 * @param {string} tenantId - Tenant ID
 * @param {string} resource - Resource type
 * @param {number} increment - Amount to increment
 * @param {Object} usageData - Additional usage data
 */
async function updateUsageRealtime(tenantId, resource, increment, usageData) {
  try {
    await OrganizationTenantService.updateResourceUsage(tenantId, resource, increment, 'increment');
    
    logger.debug('Real-time usage updated', {
      tenantId,
      resource,
      increment
    });
  } catch (error) {
    logger.error('Error updating real-time usage', {
      error: error.message,
      tenantId,
      resource,
      increment
    });
  }
}

/**
 * Queue usage update for batch processing
 * @param {string} tenantId - Tenant ID
 * @param {string} resource - Resource type
 * @param {number} increment - Amount to increment
 * @param {Object} usageData - Additional usage data
 */
function queueUsageUpdate(tenantId, resource, increment, usageData) {
  // In a production environment, this would use a queue system like Redis, RabbitMQ, etc.
  // For now, we'll use a simple in-memory queue with periodic processing
  
  if (!global.usageQueue) {
    global.usageQueue = [];
    startBatchProcessor();
  }

  global.usageQueue.push({
    tenantId,
    resource,
    increment,
    usageData,
    timestamp: Date.now()
  });
}

/**
 * Start batch processor for usage updates
 */
function startBatchProcessor() {
  const BATCH_INTERVAL = 30000; // 30 seconds
  const MAX_BATCH_SIZE = 100;

  setInterval(async () => {
    if (!global.usageQueue || global.usageQueue.length === 0) {
      return;
    }

    const batch = global.usageQueue.splice(0, MAX_BATCH_SIZE);
    await processBatchUsageUpdates(batch);
  }, BATCH_INTERVAL);
}

/**
 * Process batch usage updates
 * @param {Array} batch - Batch of usage updates
 */
async function processBatchUsageUpdates(batch) {
  try {
    // Group updates by tenant and resource
    const groupedUpdates = batch.reduce((acc, update) => {
      const key = `${update.tenantId}:${update.resource}`;
      if (!acc[key]) {
        acc[key] = {
          tenantId: update.tenantId,
          resource: update.resource,
          totalIncrement: 0,
          count: 0
        };
      }
      acc[key].totalIncrement += update.increment;
      acc[key].count += 1;
      return acc;
    }, {});

    // Process each grouped update
    for (const update of Object.values(groupedUpdates)) {
      try {
        await OrganizationTenantService.updateResourceUsage(
          update.tenantId,
          update.resource,
          update.totalIncrement,
          'increment'
        );

        logger.debug('Batch usage updated', {
          tenantId: update.tenantId,
          resource: update.resource,
          totalIncrement: update.totalIncrement,
          count: update.count
        });
      } catch (error) {
        logger.error('Error in batch usage update', {
          error: error.message,
          tenantId: update.tenantId,
          resource: update.resource
        });
      }
    }

    logger.info('Batch usage updates processed', {
      batchSize: batch.length,
      groupedUpdates: Object.keys(groupedUpdates).length
    });

  } catch (error) {
    logger.error('Error processing batch usage updates', {
      error: error.message,
      batchSize: batch.length
    });
  }
}

/**
 * Check if usage tracking should be skipped
 * @param {Object} req - Express request object
 * @returns {boolean} Whether to skip tracking
 */
function shouldSkipUsageTracking(req) {
  // Skip for health checks and internal routes
  const skipPaths = ['/health', '/ping', '/metrics'];
  if (skipPaths.some(path => req.path.startsWith(path))) {
    return true;
  }

  // Skip for OPTIONS requests
  if (req.method === 'OPTIONS') {
    return true;
  }

  return false;
}

/**
 * Get request size in bytes
 * @param {Object} req - Express request object
 * @returns {number} Request size in bytes
 */
function getRequestSize(req) {
  // Get content length from headers
  const contentLength = req.get('Content-Length');
  if (contentLength) {
    return parseInt(contentLength, 10);
  }

  // Estimate based on body size
  if (req.body) {
    try {
      return Buffer.byteLength(JSON.stringify(req.body), 'utf8');
    } catch (error) {
      return 0;
    }
  }

  return 0;
}

/**
 * Get response size in bytes
 * @param {Object} res - Express response object
 * @returns {number} Response size in bytes
 */
function getResponseSize(res) {
  // Try to get from response headers
  const contentLength = res.get('Content-Length');
  if (contentLength) {
    return parseInt(contentLength, 10);
  }

  // If not available, return 0 (would need response body capture for accurate measurement)
  return 0;
}

// Pre-configured middleware for common tracking scenarios
const trackAPIUsage = trackUsage({ resources: ['api_calls'], batch: true });
const trackBandwidthUsage = trackUsage({ resources: ['bandwidth'], batch: true });
const trackAllUsage = trackUsage({ resources: ['api_calls', 'bandwidth', 'requests'], batch: true });

module.exports = {
  trackUsage,
  trackAPIUsage,
  trackBandwidthUsage,
  trackAllUsage,
  calculateUsageMetrics,
  updateUsageRealtime,
  queueUsageUpdate,
  shouldSkipUsageTracking
};