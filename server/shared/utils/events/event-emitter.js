/**
 * @file Event Emitter Service
 * @description Global event emitter for platform-wide event handling
 * @version 1.0.0
 */

const EventEmitter = require('events');
const logger = require('../logger');

class PlatformEventEmitter extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(100); // Increase default limit
    this.eventHandlers = new Map();
  }

  /**
   * Emit an event with logging
   * @param {string} eventName - Event name
   * @param {Object} data - Event data
   */
  emit(eventName, data = {}) {
    logger.debug(`Event emitted: ${eventName}`, {
      event: eventName,
      dataKeys: Object.keys(data)
    });
    
    super.emit(eventName, data);
    
    // Also emit a wildcard event for global listeners
    super.emit('*', { eventName, data });
  }

  /**
   * Register an event handler with error handling
   * @param {string} eventName - Event name
   * @param {Function} handler - Event handler function
   * @param {Object} options - Handler options
   */
  on(eventName, handler, options = {}) {
    const { 
      once = false, 
      priority = 0,
      timeout = 30000 
    } = options;

    const wrappedHandler = async (data) => {
      const startTime = Date.now();
      
      try {
        // Add timeout to handler
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error(`Event handler timeout: ${eventName}`)), timeout);
        });
        
        await Promise.race([
          handler(data),
          timeoutPromise
        ]);
        
        const duration = Date.now() - startTime;
        
        logger.debug(`Event handled: ${eventName}`, {
          event: eventName,
          duration,
          handlerName: handler.name || 'anonymous'
        });
      } catch (error) {
        logger.error(`Event handler error: ${eventName}`, {
          event: eventName,
          error: error.message,
          stack: error.stack
        });
        
        // Emit error event
        this.emit('error', {
          eventName,
          error,
          handler: handler.name || 'anonymous'
        });
      }
    };

    // Store handler metadata
    if (!this.eventHandlers.has(eventName)) {
      this.eventHandlers.set(eventName, []);
    }
    
    this.eventHandlers.get(eventName).push({
      handler: wrappedHandler,
      original: handler,
      priority,
      once
    });

    // Sort handlers by priority
    this.eventHandlers.get(eventName).sort((a, b) => b.priority - a.priority);

    // Register with EventEmitter
    if (once) {
      super.once(eventName, wrappedHandler);
    } else {
      super.on(eventName, wrappedHandler);
    }

    return this;
  }

  /**
   * Remove an event handler
   * @param {string} eventName - Event name
   * @param {Function} handler - Original handler function
   */
  off(eventName, handler) {
    const handlers = this.eventHandlers.get(eventName);
    
    if (handlers) {
      const index = handlers.findIndex(h => h.original === handler);
      
      if (index !== -1) {
        const wrappedHandler = handlers[index].handler;
        handlers.splice(index, 1);
        
        if (handlers.length === 0) {
          this.eventHandlers.delete(eventName);
        }
        
        super.removeListener(eventName, wrappedHandler);
      }
    }
    
    return this;
  }

  /**
   * Get all registered event names
   * @returns {Array<string>} - List of event names
   */
  getEventNames() {
    return Array.from(this.eventHandlers.keys());
  }

  /**
   * Get handler count for an event
   * @param {string} eventName - Event name
   * @returns {number} - Handler count
   */
  getHandlerCount(eventName) {
    const handlers = this.eventHandlers.get(eventName);
    return handlers ? handlers.length : 0;
  }

  /**
   * Clear all handlers for an event
   * @param {string} eventName - Event name
   */
  clearEvent(eventName) {
    this.removeAllListeners(eventName);
    this.eventHandlers.delete(eventName);
    return this;
  }

  /**
   * Clear all event handlers
   */
  clearAll() {
    this.removeAllListeners();
    this.eventHandlers.clear();
    return this;
  }
}

// Platform Event Names
const EVENTS = {
  // Organization Events
  ORGANIZATION_CREATED: 'organization:created',
  ORGANIZATION_UPDATED: 'organization:updated',
  ORGANIZATION_DELETED: 'organization:deleted',
  ORGANIZATION_LOCKED: 'organization:locked',
  ORGANIZATION_UNLOCKED: 'organization:unlocked',
  
  // Subscription Events
  SUBSCRIPTION_CREATED: 'subscription:created',
  SUBSCRIPTION_UPDATED: 'subscription:updated',
  SUBSCRIPTION_CANCELLED: 'subscription:cancelled',
  SUBSCRIPTION_EXPIRED: 'subscription:expired',
  SUBSCRIPTION_RENEWED: 'subscription:renewed',
  
  // User Events
  USER_CREATED: 'user:created',
  USER_UPDATED: 'user:updated',
  USER_DELETED: 'user:deleted',
  USER_LOGIN: 'user:login',
  USER_LOGOUT: 'user:logout',
  USER_PASSWORD_CHANGED: 'user:password:changed',
  
  // Team Events
  MEMBER_ADDED: 'team:member:added',
  MEMBER_REMOVED: 'team:member:removed',
  MEMBER_ROLE_CHANGED: 'team:member:role:changed',
  
  // Project Events
  PROJECT_CREATED: 'project:created',
  PROJECT_UPDATED: 'project:updated',
  PROJECT_COMPLETED: 'project:completed',
  PROJECT_CANCELLED: 'project:cancelled',
  
  // Integration Events
  INTEGRATION_CONNECTED: 'integration:connected',
  INTEGRATION_DISCONNECTED: 'integration:disconnected',
  INTEGRATION_ERROR: 'integration:error',
  INTEGRATION_SYNCED: 'integration:synced',
  
  // System Events
  SYSTEM_STARTUP: 'system:startup',
  SYSTEM_SHUTDOWN: 'system:shutdown',
  SYSTEM_ERROR: 'system:error',
  SYSTEM_MAINTENANCE: 'system:maintenance',
  
  // Usage Events
  LIMIT_EXCEEDED: 'usage:limit:exceeded',
  LIMIT_WARNING: 'usage:limit:warning',
  USAGE_RESET: 'usage:reset',
  
  // Security Events
  SECURITY_ALERT: 'security:alert',
  SECURITY_BREACH: 'security:breach',
  SECURITY_LOGIN_FAILED: 'security:login:failed',
  SECURITY_2FA_ENABLED: 'security:2fa:enabled',
  
  // Notification Events
  EMAIL_SENT: 'notification:email:sent',
  EMAIL_FAILED: 'notification:email:failed',
  SMS_SENT: 'notification:sms:sent',
  SMS_FAILED: 'notification:sms:failed',
  
  // Analytics Events
  ANALYTICS_TRACKED: 'analytics:tracked',
  ANALYTICS_ERROR: 'analytics:error'
};

// Create singleton instance
const eventEmitter = new PlatformEventEmitter();

// Register global error handler
eventEmitter.on('error', (errorData) => {
  logger.error('Global event error', errorData);
});

module.exports = {
  EventEmitter: eventEmitter,
  EVENTS
};