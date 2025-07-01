/**
 * @file Analytics Middleware
 * @description Event tracking and analytics collection middleware
 * @version 1.0.0
 */

const logger = require('../../utils/logger');

/**
 * Analytics Service
 * Handles event tracking and metrics collection
 */
class AnalyticsService {
  constructor() {
    this.eventQueue = [];
    this.batchSize = 50;
    this.flushInterval = 10000; // 10 seconds
    
    this.startBatchProcessor();
  }

  /**
   * Track analytics event
   */
  async track(eventData) {
    try {
      const event = {
        id: this.generateEventId(),
        timestamp: new Date().toISOString(),
        ...eventData
      };

      // Add to queue for batch processing
      this.eventQueue.push(event);

      // Immediate logging for debug purposes
      logger.debug('Analytics event tracked', event);

      // Flush if queue is full
      if (this.eventQueue.length >= this.batchSize) {
        await this.flush();
      }

      return event.id;
    } catch (error) {
      logger.error('Analytics tracking error', {
        error: error.message,
        eventData
      });
    }
  }

  /**
   * Start batch processor
   */
  startBatchProcessor() {
    setInterval(async () => {
      if (this.eventQueue.length > 0) {
        await this.flush();
      }
    }, this.flushInterval);

    // Handle process shutdown
    process.on('SIGINT', async () => {
      await this.flush();
    });
  }

  /**
   * Flush events to storage
   */
  async flush() {
    if (this.eventQueue.length === 0) return;

    const batch = this.eventQueue.splice(0, this.batchSize);

    try {
      // Log batch for now - in production, send to analytics service
      logger.info('Analytics batch processed', {
        count: batch.length,
        events: batch.map(e => ({ id: e.id, event: e.event, category: e.category }))
      });

      // Future: Send to external analytics service
      // await this.sendToAnalyticsService(batch);
    } catch (error) {
      logger.error('Analytics batch processing error', {
        error: error.message,
        count: batch.length
      });

      // Re-queue failed events
      this.eventQueue.unshift(...batch);
    }
  }

  /**
   * Generate unique event ID
   */
  generateEventId() {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Create singleton analytics service
const analyticsService = new AnalyticsService();

/**
 * Track analytics middleware
 * Records user interactions and system events
 */
const trackAnalytics = (eventName, options = {}) => {
  return async (req, res, next) => {
    try {
      const {
        category = 'user_action',
        includeRequestData = false,
        includeResponseData = false,
        customProperties = {},
        condition = () => true
      } = options;

      // Check if tracking should be applied
      if (!condition(req)) {
        return next();
      }

      // Prepare event data
      const eventData = {
        event: eventName,
        category,
        user: {
          id: req.user?.id,
          email: req.user?.email,
          role: req.user?.role?.primary,
          organizationId: req.user?.organizationId
        },
        request: {
          method: req.method,
          path: req.path,
          url: req.originalUrl,
          ip: req.ip,
          userAgent: req.get('user-agent'),
          sessionId: req.sessionID
        },
        organization: {
          id: req.organizationId || req.params.id,
          tenantId: req.tenantId
        },
        metadata: {
          requestId: req.id,
          correlationId: req.correlationId,
          environment: process.env.NODE_ENV,
          version: process.env.APP_VERSION
        },
        properties: {
          ...customProperties,
          ...(typeof customProperties === 'function' ? customProperties(req) : {})
        }
      };

      // Include request data if specified
      if (includeRequestData) {
        eventData.request.body = req.body;
        eventData.request.params = req.params;
        eventData.request.query = req.query;
      }

      // Store original response methods to capture response data
      if (includeResponseData) {
        const originalJson = res.json;
        const originalSend = res.send;

        res.json = function(data) {
          eventData.response = {
            statusCode: res.statusCode,
            data: data
          };
          return originalJson.call(res, data);
        };

        res.send = function(data) {
          eventData.response = {
            statusCode: res.statusCode,
            data: data
          };
          return originalSend.call(res, data);
        };
      }

      // Track the event after response is sent
      res.on('finish', async () => {
        // Add response timing
        if (req._startAt) {
          const duration = Date.now() - req._startAt;
          eventData.performance = {
            responseTime: duration,
            statusCode: res.statusCode
          };
        }

        // Only track successful requests by default
        if (res.statusCode < 400) {
          await analyticsService.track(eventData);
        }
      });

      next();
    } catch (error) {
      logger.error('Analytics middleware error', {
        error: error.message,
        eventName,
        url: req.originalUrl
      });
      next(); // Continue without tracking on error
    }
  };
};

/**
 * Track page view
 */
const trackPageView = (options = {}) => {
  return trackAnalytics('page_view', {
    category: 'page_view',
    ...options
  });
};

/**
 * Track API call
 */
const trackApiCall = (options = {}) => {
  return trackAnalytics('api_call', {
    category: 'api_usage',
    includeRequestData: true,
    ...options
  });
};

/**
 * Track user action
 */
const trackUserAction = (actionName, options = {}) => {
  return trackAnalytics(actionName, {
    category: 'user_action',
    ...options
  });
};

/**
 * Track system event
 */
const trackSystemEvent = (eventName, options = {}) => {
  return trackAnalytics(eventName, {
    category: 'system_event',
    ...options
  });
};

/**
 * Track performance metrics
 */
const trackPerformance = (options = {}) => {
  return async (req, res, next) => {
    const startTime = process.hrtime.bigint();
    req._startAt = Date.now();

    res.on('finish', async () => {
      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds

      const performanceData = {
        event: 'performance_metric',
        category: 'performance',
        properties: {
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          responseTime: duration,
          memoryUsage: process.memoryUsage(),
          ...options
        },
        user: {
          id: req.user?.id,
          organizationId: req.user?.organizationId
        },
        request: {
          url: req.originalUrl,
          ip: req.ip
        }
      };

      await analyticsService.track(performanceData);
    });

    next();
  };
};

/**
 * Track conversion events
 */
const trackConversion = (conversionType, options = {}) => {
  return trackAnalytics(`conversion_${conversionType}`, {
    category: 'conversion',
    includeRequestData: true,
    ...options
  });
};

/**
 * Track error events
 */
const trackError = (options = {}) => {
  return (err, req, res, next) => {
    const errorData = {
      event: 'error_occurred',
      category: 'error',
      properties: {
        errorType: err.name,
        errorMessage: err.message,
        statusCode: err.statusCode || 500,
        stack: err.stack,
        ...options
      },
      user: {
        id: req.user?.id,
        organizationId: req.user?.organizationId
      },
      request: {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userAgent: req.get('user-agent')
      }
    };

    analyticsService.track(errorData);
    next(err);
  };
};

module.exports = {
  trackAnalytics,
  trackPageView,
  trackApiCall,
  trackUserAction,
  trackSystemEvent,
  trackPerformance,
  trackConversion,
  trackError,
  analyticsService
};