/**
 * @file Admin Base Service
 * @description Base service class providing common functionality for all administrative services
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const EventEmitter = require('events');

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { AppError, ValidationError, NotFoundError, AuthorizationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { CacheService } = require('../../../shared/services/cache-service');

// Import admin models
const AdminActionLog = require('../models/admin-action-log-model');
const AdminSession = require('../models/admin-session-model');
const AdminPreference = require('../models/admin-preference-model');
const AdminNotification = require('../models/admin-notification-model');

// Import admin configurations
const { AdminSecurityManager } = require('../config/admin-security-config');
const { AdminLimitManager } = require('../config/admin-limits-config');
const { AdminFeatureManager } = require('../config/admin-features-config');

// Import admin constants
const { AdminPermissions } = require('../constants/admin-permissions');
const { AdminActions } = require('../constants/admin-actions');
const { AdminRoles } = require('../constants/admin-roles');

/**
 * Admin Base Service Class
 * Provides common functionality for all administrative services
 */
class AdminBaseService extends EventEmitter {
  constructor(serviceName) {
    super();
    
    this.serviceName = serviceName;
    this.cache = new CacheService(`admin:${serviceName}`);
    this.metrics = {
      operationsCount: 0,
      errorsCount: 0,
      lastOperation: null,
      startTime: new Date()
    };
    
    // Initialize service configurations
    this.initializeService();
  }
  
  /**
   * Initialize service configurations
   * @private
   */
  initializeService() {
    logger.info(`Initializing admin service: ${this.serviceName}`, {
      service: this.serviceName,
      timestamp: new Date()
    });
    
    // Set up error handling
    this.on('error', this.handleServiceError.bind(this));
    
    // Set up metrics collection
    this.setupMetricsCollection();
  }
  
  /**
   * Set up metrics collection
   * @private
   */
  setupMetricsCollection() {
    this.on('operation:start', (operation) => {
      this.metrics.operationsCount++;
      this.metrics.lastOperation = {
        name: operation,
        startTime: new Date()
      };
    });
    
    this.on('operation:complete', (operation, duration) => {
      if (this.metrics.lastOperation && this.metrics.lastOperation.name === operation) {
        this.metrics.lastOperation.duration = duration;
        this.metrics.lastOperation.status = 'completed';
      }
    });
    
    this.on('operation:error', (operation, error) => {
      this.metrics.errorsCount++;
      if (this.metrics.lastOperation && this.metrics.lastOperation.name === operation) {
        this.metrics.lastOperation.error = error.message;
        this.metrics.lastOperation.status = 'failed';
      }
    });
  }
  
  /**
   * Execute operation with common error handling and logging
   * @param {string} operationName - Name of the operation
   * @param {Function} operation - Operation function to execute
   * @param {Object} context - Operation context
   * @returns {Promise<*>} Operation result
   */
  async executeOperation(operationName, operation, context = {}) {
    const startTime = new Date();
    this.emit('operation:start', operationName);
    
    try {
      // Validate operation context
      this.validateOperationContext(context);
      
      // Check permissions
      await this.checkOperationPermissions(operationName, context);
      
      // Check rate limits
      await this.checkRateLimits(operationName, context);
      
      // Execute the operation
      const result = await operation();
      
      // Log successful operation
      await this.logOperation(operationName, context, result, 'success');
      
      const duration = new Date() - startTime;
      this.emit('operation:complete', operationName, duration);
      
      return result;
      
    } catch (error) {
      // Log failed operation
      await this.logOperation(operationName, context, null, 'failure', error);
      
      this.emit('operation:error', operationName, error);
      
      logger.error(`Admin operation failed: ${operationName}`, {
        service: this.serviceName,
        operation: operationName,
        error: error.message,
        userId: context.userId,
        duration: new Date() - startTime
      });
      
      throw error;
    }
  }
  
  /**
   * Validate operation context
   * @param {Object} context - Operation context
   * @throws {ValidationError} If context is invalid
   */
  validateOperationContext(context) {
    if (!context.userId) {
      throw new ValidationError('User ID is required in operation context');
    }
    
    if (!context.sessionId) {
      throw new ValidationError('Session ID is required in operation context');
    }
    
    if (!context.requestContext) {
      throw new ValidationError('Request context is required for operation');
    }
  }
  
  /**
   * Check operation permissions
   * @param {string} operationName - Name of the operation
   * @param {Object} context - Operation context
   * @throws {AuthorizationError} If user lacks permissions
   */
  async checkOperationPermissions(operationName, context) {
    const { user, requiredPermissions } = context;
    
    if (!user) {
      throw new AuthorizationError('User information required for permission check');
    }
    
    // Get operation-specific permissions
    const permissions = requiredPermissions || this.getRequiredPermissions(operationName);
    
    if (permissions && permissions.length > 0) {
      const hasPermission = permissions.some(permission => 
        this.checkUserPermission(user, permission)
      );
      
      if (!hasPermission) {
        throw new AuthorizationError(`Insufficient permissions for operation: ${operationName}`);
      }
    }
    
    // Check additional security requirements
    const securityValidation = AdminSecurityManager.validateSecurityRequirements(
      operationName, 
      user, 
      context
    );
    
    if (!securityValidation.passed) {
      throw new AuthorizationError('Additional security requirements not met', {
        requirements: securityValidation.requirements
      });
    }
  }
  
  /**
   * Check rate limits for operation
   * @param {string} operationName - Name of the operation
   * @param {Object} context - Operation context
   * @throws {AppError} If rate limit exceeded
   */
  async checkRateLimits(operationName, context) {
    const { user } = context;
    const userRole = user.role?.primary || 'default';
    
    const rateLimit = AdminLimitManager.getRateLimit(operationName, userRole);
    
    if (rateLimit) {
      const key = `rate_limit:${operationName}:${user._id}`;
      const current = await this.cache.get(key) || 0;
      
      if (current >= rateLimit.max) {
        throw new AppError(
          `Rate limit exceeded for operation: ${operationName}`,
          429,
          'RATE_LIMIT_EXCEEDED'
        );
      }
      
      // Increment rate limit counter
      await this.cache.set(key, current + 1, { ttl: rateLimit.windowMs });
    }
  }
  
  /**
   * Get required permissions for operation
   * @param {string} operationName - Name of the operation
   * @returns {Array} Required permissions
   */
  getRequiredPermissions(operationName) {
    // Define operation to permission mappings
    const operationPermissions = {
      'user.create': [AdminPermissions.USER.CREATE],
      'user.update': [AdminPermissions.USER.UPDATE],
      'user.delete': [AdminPermissions.USER.DELETE],
      'organization.create': [AdminPermissions.ORGANIZATION.MANAGE],
      'organization.delete': [AdminPermissions.ORGANIZATION.DELETE],
      'system.backup': [AdminPermissions.SYSTEM.BACKUP.CREATE],
      'system.maintenance': [AdminPermissions.SYSTEM.MAINTENANCE.ENABLE],
      'security.audit': [AdminPermissions.SECURITY.AUDIT.VIEW]
    };
    
    return operationPermissions[operationName] || [];
  }
  
  /**
   * Check if user has specific permission
   * @param {Object} user - User object
   * @param {string} permission - Permission to check
   * @returns {boolean} Has permission
   */
  checkUserPermission(user, permission) {
    if (!user.permissions) return false;
    
    // Check direct permission
    if (user.permissions.includes(permission)) return true;
    
    // Check wildcard permissions
    const permissionParts = permission.split('.');
    for (let i = permissionParts.length; i > 0; i--) {
      const wildcardPerm = permissionParts.slice(0, i).join('.') + '.*';
      if (user.permissions.includes(wildcardPerm)) return true;
    }
    
    return false;
  }
  
  /**
   * Log administrative operation
   * @param {string} operationName - Name of the operation
   * @param {Object} context - Operation context
   * @param {*} result - Operation result
   * @param {string} status - Operation status
   * @param {Error} error - Error if operation failed
   */
  async logOperation(operationName, context, result, status, error = null) {
    try {
      const logData = {
        action: operationName,
        category: this.getOperationCategory(operationName),
        actor: {
          userId: context.userId,
          username: context.user?.username,
          email: context.user?.email,
          role: context.user?.role?.primary,
          isSystemAction: false
        },
        requestContext: {
          method: context.requestContext.method,
          url: context.requestContext.url,
          sourceIP: context.requestContext.sourceIP,
          userAgent: context.requestContext.userAgent,
          sessionId: context.sessionId
        },
        target: this.buildOperationTarget(operationName, context, result),
        changes: this.buildChangeDetails(operationName, context, result),
        security: this.buildSecurityContext(context),
        result: {
          status,
          message: status === 'success' ? 'Operation completed successfully' : error?.message,
          errorCode: error?.code,
          errorDetails: error ? { name: error.name, message: error.message } : null,
          duration: context.duration
        },
        metadata: {
          environment: config.nodeEnv || 'development',
          service: this.serviceName,
          customFields: context.metadata || {}
        }
      };
      
      await AdminActionLog.logAction(logData);
      
    } catch (logError) {
      logger.error('Failed to log admin operation', {
        operation: operationName,
        logError: logError.message,
        originalError: error?.message
      });
    }
  }
  
  /**
   * Get operation category
   * @param {string} operationName - Name of the operation
   * @returns {string} Operation category
   */
  getOperationCategory(operationName) {
    const categoryMap = {
      'user.': 'user',
      'organization.': 'organization',
      'system.': 'system',
      'security.': 'security',
      'billing.': 'billing',
      'api.': 'api'
    };
    
    for (const [prefix, category] of Object.entries(categoryMap)) {
      if (operationName.startsWith(prefix)) {
        return category;
      }
    }
    
    return 'platform';
  }
  
  /**
   * Build operation target information
   * @param {string} operationName - Name of the operation
   * @param {Object} context - Operation context
   * @param {*} result - Operation result
   * @returns {Object} Target information
   */
  buildOperationTarget(operationName, context, result) {
    const target = {
      resourceType: this.getResourceType(operationName),
      resourceId: context.targetId || result?.id || 'unknown',
      resourceName: context.targetName || result?.name,
      organizationId: context.user?.organization?.current,
      tenantId: context.tenantId
    };
    
    return target;
  }
  
  /**
   * Get resource type from operation name
   * @param {string} operationName - Name of the operation
   * @returns {string} Resource type
   */
  getResourceType(operationName) {
    const resourceMap = {
      'user.': 'user',
      'organization.': 'organization',
      'system.': 'system',
      'security.': 'audit_log',
      'billing.': 'billing',
      'backup.': 'backup',
      'notification.': 'notification'
    };
    
    for (const [prefix, resource] of Object.entries(resourceMap)) {
      if (operationName.startsWith(prefix)) {
        return resource;
      }
    }
    
    return 'system';
  }
  
  /**
   * Build change details for operation
   * @param {string} operationName - Name of the operation
   * @param {Object} context - Operation context
   * @param {*} result - Operation result
   * @returns {Object} Change details
   */
  buildChangeDetails(operationName, context, result) {
    const changes = {
      changeType: this.getChangeType(operationName),
      fieldChanges: context.fieldChanges || [],
      bulkOperation: context.bulkOperation || { enabled: false }
    };
    
    return changes;
  }
  
  /**
   * Get change type from operation name
   * @param {string} operationName - Name of the operation
   * @returns {string} Change type
   */
  getChangeType(operationName) {
    if (operationName.includes('create')) return 'create';
    if (operationName.includes('update')) return 'update';
    if (operationName.includes('delete')) return 'delete';
    if (operationName.includes('read') || operationName.includes('get')) return 'read';
    if (operationName.includes('execute')) return 'execute';
    
    return 'execute';
  }
  
  /**
   * Build security context for operation
   * @param {Object} context - Operation context
   * @returns {Object} Security context
   */
  buildSecurityContext(context) {
    return {
      authenticationMethod: context.authMethod || 'password',
      mfaVerified: context.mfaVerified || false,
      permissionsUsed: context.permissionsUsed || [],
      roleAtTimeOfAction: context.user?.role?.primary,
      elevatedPrivileges: context.elevatedPrivileges || false,
      breakGlassAccess: context.breakGlassAccess || false,
      impersonationActive: context.impersonationActive || false,
      riskLevel: this.calculateOperationRisk(context),
      requiresApproval: context.requiresApproval || false,
      approvalStatus: context.approvalStatus || 'not_required'
    };
  }
  
  /**
   * Calculate operation risk level
   * @param {Object} context - Operation context
   * @returns {string} Risk level
   */
  calculateOperationRisk(context) {
    let riskScore = 0;
    
    // Base risk factors
    if (context.elevatedPrivileges) riskScore += 20;
    if (context.breakGlassAccess) riskScore += 40;
    if (context.impersonationActive) riskScore += 30;
    if (!context.mfaVerified) riskScore += 15;
    
    // Network risk factors
    if (context.requestContext?.sourceIP) {
      // This would typically integrate with threat intelligence
      // For now, we'll use basic heuristics
      const ip = context.requestContext.sourceIP;
      if (ip.includes('192.168.') || ip.includes('10.') || ip.includes('172.')) {
        riskScore -= 5; // Lower risk for internal IPs
      } else {
        riskScore += 5; // Higher risk for external IPs
      }
    }
    
    // Determine risk level
    if (riskScore >= 60) return 'critical';
    if (riskScore >= 40) return 'high';
    if (riskScore >= 20) return 'medium';
    return 'low';
  }
  
  /**
   * Handle service errors
   * @param {Error} error - Service error
   * @private
   */
  handleServiceError(error) {
    logger.error(`Service error in ${this.serviceName}`, {
      service: this.serviceName,
      error: error.message,
      stack: error.stack
    });
    
    // Emit metric event
    this.metrics.errorsCount++;
  }
  
  /**
   * Get service metrics
   * @returns {Object} Service metrics
   */
  getMetrics() {
    return {
      ...this.metrics,
      uptime: new Date() - this.metrics.startTime,
      errorRate: this.metrics.errorsCount / this.metrics.operationsCount || 0
    };
  }
  
  /**
   * Check if feature is enabled for user
   * @param {string} featurePath - Feature path
   * @param {Object} user - User object
   * @returns {boolean} Feature enabled
   */
  isFeatureEnabled(featurePath, user) {
    return AdminFeatureManager.isFeatureEnabled(featurePath, user);
  }
  
  /**
   * Get user preferences
   * @param {string} userId - User ID
   * @returns {Promise<Object>} User preferences
   */
  async getUserPreferences(userId) {
    const cacheKey = `user_preferences:${userId}`;
    let preferences = await this.cache.get(cacheKey);
    
    if (!preferences) {
      preferences = await AdminPreference.findOne({ userId });
      if (preferences) {
        await this.cache.set(cacheKey, preferences, { ttl: 300000 }); // 5 minutes
      }
    }
    
    return preferences;
  }
  
  /**
   * Send notification to admin users
   * @param {Object} notificationData - Notification data
   * @returns {Promise<Object>} Created notification
   */
  async sendNotification(notificationData) {
    return AdminNotification.createAndSend(notificationData);
  }
  
  /**
   * Validate session
   * @param {string} sessionId - Session ID
   * @returns {Promise<Object>} Session object
   * @throws {AuthenticationError} If session is invalid
   */
  async validateSession(sessionId) {
    const session = await AdminSession.findOne({
      sessionId,
      status: { $in: ['active', 'idle'] },
      expiresAt: { $gt: new Date() }
    });
    
    if (!session) {
      throw new AuthenticationError('Invalid or expired session');
    }
    
    if (!session.isValid()) {
      throw new AuthenticationError('Session validation failed');
    }
    
    return session;
  }
  
  /**
   * Start database transaction
   * @returns {Promise<Object>} Transaction session
   */
  async startTransaction() {
    const session = await mongoose.startSession();
    session.startTransaction();
    return session;
  }
  
  /**
   * Commit database transaction
   * @param {Object} session - Transaction session
   */
  async commitTransaction(session) {
    await session.commitTransaction();
    session.endSession();
  }
  
  /**
   * Abort database transaction
   * @param {Object} session - Transaction session
   */
  async abortTransaction(session) {
    await session.abortTransaction();
    session.endSession();
  }
  
  /**
   * Paginate query results
   * @param {Object} query - Mongoose query
   * @param {Object} options - Pagination options
   * @returns {Promise<Object>} Paginated results
   */
  async paginate(query, options = {}) {
    const {
      page = 1,
      limit = 25,
      sort = { createdAt: -1 },
      populate = null
    } = options;
    
    const skip = (page - 1) * limit;
    
    let queryBuilder = query.skip(skip).limit(limit).sort(sort);
    
    if (populate) {
      if (Array.isArray(populate)) {
        populate.forEach(pop => queryBuilder = queryBuilder.populate(pop));
      } else {
        queryBuilder = queryBuilder.populate(populate);
      }
    }
    
    const [results, total] = await Promise.all([
      queryBuilder.exec(),
      query.model.countDocuments(query.getQuery())
    ]);
    
    return {
      data: results,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1
      }
    };
  }
  
  /**
   * Clean up service resources
   * @returns {Promise<void>}
   */
  async cleanup() {
    logger.info(`Cleaning up admin service: ${this.serviceName}`);
    
    // Clear cache
    await this.cache.clear();
    
    // Remove all event listeners
    this.removeAllListeners();
    
    // Log final metrics
    logger.info(`Service ${this.serviceName} cleanup complete`, {
      finalMetrics: this.getMetrics()
    });
  }
}

module.exports = AdminBaseService;