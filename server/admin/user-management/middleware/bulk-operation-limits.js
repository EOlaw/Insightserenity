// server/admin/user-management/middleware/bulk-operation-limits.js
/**
 * @file Bulk Operation Limits Middleware
 * @description Middleware for enforcing bulk operation limits and rate limiting
 * @version 1.0.0
 */

const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const mongoose = require('mongoose');

// Models
const BulkOperation = require('../../../shared/admin/models/bulk-operation-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Utilities
const { AppError, ValidationError, TooManyRequestsError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const CacheService = require('../../../shared/utils/cache-service');
const MetricsService = require('../../../shared/utils/metrics-service');

// Constants
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

// Configuration
const config = require('../../../config');

/**
 * Check concurrent bulk operations limit
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkConcurrentOperations = async (req, res, next) => {
  try {
    const adminUser = req.adminUser;
    
    // Get active operations count for this admin
    const activeOperations = await BulkOperation.countDocuments({
      adminUserId: adminUser.id,
      status: { $in: ['pending', 'processing', 'queued'] }
    });

    // Check limit
    const limit = await getOperationLimit(adminUser, 'concurrent');
    
    if (activeOperations >= limit) {
      logger.warn('Concurrent bulk operations limit exceeded', {
        adminId: adminUser.id,
        activeOperations,
        limit
      });

      // Record attempt
      await AdminActionLog.create({
        adminUserId: adminUser.id,
        action: 'BULK_OPERATION_LIMIT_EXCEEDED',
        category: 'RATE_LIMIT',
        severity: 'MEDIUM',
        data: {
          limitType: 'concurrent',
          activeOperations,
          limit
        }
      });

      throw new TooManyRequestsError(
        `Maximum concurrent bulk operations limit (${limit}) reached. ` +
        'Please wait for existing operations to complete.'
      );
    }

    // Store count in request for potential use
    req.activeOperations = activeOperations;
    
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Check daily bulk operations limit
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkDailyOperationLimit = async (req, res, next) => {
  try {
    const adminUser = req.adminUser;
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Get today's operations count
    const todayOperations = await BulkOperation.countDocuments({
      adminUserId: adminUser.id,
      createdAt: { $gte: today }
    });

    // Check limit
    const limit = await getOperationLimit(adminUser, 'daily');
    
    if (todayOperations >= limit) {
      logger.warn('Daily bulk operations limit exceeded', {
        adminId: adminUser.id,
        todayOperations,
        limit
      });

      // Record attempt
      await AdminActionLog.create({
        adminUserId: adminUser.id,
        action: 'BULK_OPERATION_LIMIT_EXCEEDED',
        category: 'RATE_LIMIT',
        severity: 'MEDIUM',
        data: {
          limitType: 'daily',
          todayOperations,
          limit
        }
      });

      throw new TooManyRequestsError(
        `Daily bulk operations limit (${limit}) reached. ` +
        'Please try again tomorrow.'
      );
    }

    // Store count in request
    req.dailyOperations = todayOperations;
    
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Check operation size limits
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkOperationSizeLimit = async (req, res, next) => {
  try {
    const { userIds, filters } = req.body;
    const operationType = getOperationType(req.path);
    
    // Check user IDs count if provided
    if (userIds && Array.isArray(userIds)) {
      const limit = AdminLimits.BULK_OPERATIONS[`MAX_${operationType.toUpperCase()}_USERS`] || 
                   AdminLimits.BULK_OPERATIONS.MAX_DEFAULT_USERS;
      
      if (userIds.length > limit) {
        throw new ValidationError(
          `Operation size exceeds maximum limit of ${limit} users`
        );
      }
    }

    // If using filters, estimate count
    if (filters) {
      const estimatedCount = await estimateFilteredUsersCount(filters);
      const limit = AdminLimits.BULK_OPERATIONS[`MAX_${operationType.toUpperCase()}_USERS`] || 
                   AdminLimits.BULK_OPERATIONS.MAX_DEFAULT_USERS;
      
      if (estimatedCount > limit) {
        throw new ValidationError(
          `Estimated operation size (${estimatedCount}) exceeds maximum limit of ${limit} users. ` +
          'Please refine your filters.'
        );
      }
      
      // Store estimate in request
      req.estimatedUserCount = estimatedCount;
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Rate limiter for bulk operations
 * Different limits based on operation type
 */
const createBulkOperationRateLimiter = (operationType) => {
  const limits = {
    import: { windowMs: 3600000, max: 5 }, // 5 imports per hour
    update: { windowMs: 900000, max: 10 }, // 10 updates per 15 minutes
    delete: { windowMs: 3600000, max: 3 }, // 3 deletes per hour
    export: { windowMs: 600000, max: 5 }, // 5 exports per 10 minutes
    email: { windowMs: 1800000, max: 5 }, // 5 email campaigns per 30 minutes
    default: { windowMs: 900000, max: 10 } // 10 operations per 15 minutes
  };

  const limit = limits[operationType] || limits.default;

  // Create Redis store if Redis is enabled
  const store = config.redis.enabled ? 
    new RedisStore({
      client: CacheService.getRedisClient(),
      prefix: `bulk_ops_limit:${operationType}:`
    }) : undefined;

  return rateLimit({
    windowMs: limit.windowMs,
    max: limit.max,
    message: `Too many ${operationType} operations. Please try again later.`,
    standardHeaders: true,
    legacyHeaders: false,
    store,
    keyGenerator: (req) => `${req.adminUser.id}:${operationType}`,
    handler: async (req, res) => {
      // Log rate limit hit
      logger.warn('Bulk operation rate limit exceeded', {
        adminId: req.adminUser.id,
        operationType,
        ip: req.ip
      });

      // Record in metrics
      await MetricsService.recordMetric('bulk_operation_rate_limit', {
        adminId: req.adminUser.id,
        operationType
      });

      res.status(429).json({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: `Too many ${operationType} operations. Please try again later.`,
          retryAfter: res.getHeader('Retry-After')
        }
      });
    }
  });
};

/**
 * Check resource usage before bulk operation
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const checkResourceAvailability = async (req, res, next) => {
  try {
    // Check system resources
    const systemResources = await checkSystemResources();
    
    if (!systemResources.available) {
      logger.error('Insufficient system resources for bulk operation', {
        adminId: req.adminUser.id,
        resources: systemResources
      });

      throw new AppError(
        'System resources are currently limited. Please try again later.',
        503
      );
    }

    // Check database load
    const dbLoad = await checkDatabaseLoad();
    
    if (dbLoad.isHigh) {
      logger.warn('High database load detected', {
        adminId: req.adminUser.id,
        load: dbLoad
      });

      // For non-critical operations, delay or reject
      const operationType = getOperationType(req.path);
      
      if (['delete', 'import'].includes(operationType)) {
        throw new AppError(
          'Database is under high load. Please try again in a few minutes.',
          503
        );
      }
    }

    // Check queue depth
    const queueDepth = await checkQueueDepth();
    
    if (queueDepth > AdminLimits.QUEUE.MAX_DEPTH) {
      throw new AppError(
        'Processing queue is full. Please try again later.',
        503
      );
    }

    // Store resource info in request
    req.systemResources = {
      ...systemResources,
      dbLoad: dbLoad.current,
      queueDepth
    };

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Validate bulk operation permissions
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const validateBulkPermissions = async (req, res, next) => {
  try {
    const adminUser = req.adminUser;
    const operationType = getOperationType(req.path);
    
    // Map operation types to required permissions
    const permissionMap = {
      import: AdminPermissions.USER_MANAGEMENT.BULK_IMPORT,
      update: AdminPermissions.USER_MANAGEMENT.BULK_UPDATE,
      delete: AdminPermissions.USER_MANAGEMENT.BULK_DELETE,
      export: AdminPermissions.USER_MANAGEMENT.EXPORT,
      email: AdminPermissions.USER_MANAGEMENT.BULK_EMAIL,
      'assign-role': AdminPermissions.USER_MANAGEMENT.BULK_UPDATE,
      'assign-organization': AdminPermissions.USER_MANAGEMENT.BULK_UPDATE,
      'reset-passwords': AdminPermissions.USER_MANAGEMENT.BULK_UPDATE
    };

    const requiredPermission = permissionMap[operationType];
    
    if (!requiredPermission) {
      throw new AppError('Unknown bulk operation type', 400);
    }

    // Check permission
    const hasPermission = await checkAdminPermission(adminUser, requiredPermission);
    
    if (!hasPermission) {
      logger.warn('Insufficient permissions for bulk operation', {
        adminId: adminUser.id,
        operationType,
        requiredPermission
      });

      throw new AppError('Insufficient permissions for this bulk operation', 403);
    }

    // Additional checks for sensitive operations
    if (operationType === 'delete' && req.body.options?.hardDelete) {
      const hasHardDeletePermission = await checkAdminPermission(
        adminUser, 
        AdminPermissions.USER_MANAGEMENT.HARD_DELETE
      );
      
      if (!hasHardDeletePermission) {
        throw new AppError('Insufficient permissions for hard delete operation', 403);
      }
    }

    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Track bulk operation metrics
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const trackBulkOperationMetrics = async (req, res, next) => {
  const startTime = Date.now();
  const operationType = getOperationType(req.path);

  // Store original end function
  const originalEnd = res.end;

  // Override end function to capture metrics
  res.end = function(...args) {
    // Call original end
    originalEnd.apply(res, args);

    // Calculate duration
    const duration = Date.now() - startTime;

    // Record metrics asynchronously
    setImmediate(async () => {
      try {
        await MetricsService.recordMetric('bulk_operation', {
          adminId: req.adminUser.id,
          operationType,
          duration,
          statusCode: res.statusCode,
          success: res.statusCode < 400,
          userCount: req.body.userIds?.length || req.estimatedUserCount || 0
        });

        // Update admin's bulk operation stats
        await updateAdminBulkOperationStats(req.adminUser.id, operationType, {
          success: res.statusCode < 400,
          duration,
          userCount: req.body.userIds?.length || req.estimatedUserCount || 0
        });
      } catch (error) {
        logger.error('Failed to record bulk operation metrics', {
          error: error.message,
          adminId: req.adminUser.id,
          operationType
        });
      }
    });
  };

  next();
};

/**
 * Helper function to get operation limit for admin
 * @param {Object} adminUser - Admin user
 * @param {string} limitType - Type of limit (concurrent, daily)
 * @returns {Promise<number>} Operation limit
 */
async function getOperationLimit(adminUser, limitType) {
  // Check for custom limits based on admin role or organization
  const cacheKey = `bulk_limit:${limitType}:${adminUser.id}`;
  const cached = await CacheService.get(cacheKey);
  
  if (cached) {
    return cached;
  }

  // Default limits
  let limit = AdminLimits.BULK_OPERATIONS[`MAX_${limitType.toUpperCase()}_OPERATIONS`] || 10;

  // Check for enhanced limits based on role
  if (adminUser.role?.permissions?.includes('enhanced_bulk_operations')) {
    limit = limit * 2;
  }

  // Check for organization-specific limits
  if (adminUser.organization?.settings?.bulkOperationLimits?.[limitType]) {
    limit = adminUser.organization.settings.bulkOperationLimits[limitType];
  }

  // Cache for 5 minutes
  await CacheService.set(cacheKey, limit, 300);

  return limit;
}

/**
 * Helper function to get operation type from request path
 * @param {string} path - Request path
 * @returns {string} Operation type
 */
function getOperationType(path) {
  const pathSegments = path.split('/');
  const bulkIndex = pathSegments.indexOf('bulk');
  
  if (bulkIndex !== -1 && pathSegments[bulkIndex + 1]) {
    return pathSegments[bulkIndex + 1];
  }
  
  return 'unknown';
}

/**
 * Helper function to estimate filtered users count
 * @param {Object} filters - User filters
 * @returns {Promise<number>} Estimated count
 */
async function estimateFilteredUsersCount(filters) {
  // Build query from filters
  const query = {};
  
  if (filters.status) query.status = filters.status;
  if (filters.role) query['role.primary'] = filters.role;
  if (filters.organization) query['organization.current'] = filters.organization;
  if (filters.createdAfter) query.createdAt = { $gte: new Date(filters.createdAfter) };
  if (filters.lastActiveAfter) query.lastActiveAt = { $gte: new Date(filters.lastActiveAfter) };

  // Use count with limit for estimation
  const User = require('../../../shared/users/models/user-model');
  const count = await User.countDocuments(query).limit(10000);
  
  return count;
}

/**
 * Helper function to check system resources
 * @returns {Promise<Object>} Resource availability
 */
async function checkSystemResources() {
  const memoryUsage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();
  
  // Check memory threshold (80% of heap)
  const heapUsedPercent = (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
  
  return {
    available: heapUsedPercent < 80,
    memory: {
      heapUsedPercent,
      heapTotal: memoryUsage.heapTotal,
      heapUsed: memoryUsage.heapUsed
    },
    cpu: cpuUsage
  };
}

/**
 * Helper function to check database load
 * @returns {Promise<Object>} Database load status
 */
async function checkDatabaseLoad() {
  try {
    const adminDb = mongoose.connection.db.admin();
    const serverStatus = await adminDb.serverStatus();
    
    // Check connection pool usage
    const currentConnections = serverStatus.connections?.current || 0;
    const availableConnections = serverStatus.connections?.available || 100;
    const connectionUsage = (currentConnections / availableConnections) * 100;
    
    return {
      isHigh: connectionUsage > 70,
      current: connectionUsage,
      connections: {
        current: currentConnections,
        available: availableConnections
      }
    };
  } catch (error) {
    logger.error('Failed to check database load', { error: error.message });
    return { isHigh: false, current: 0 };
  }
}

/**
 * Helper function to check queue depth
 * @returns {Promise<number>} Current queue depth
 */
async function checkQueueDepth() {
  try {
    const QueueService = require('../../../shared/utils/queue-service');
    const queues = ['bulk-user-import', 'bulk-user-update', 'bulk-user-delete', 'bulk-email-send'];
    
    let totalDepth = 0;
    for (const queueName of queues) {
      const queue = await QueueService.getQueue(queueName);
      if (queue) {
        const counts = await queue.getJobCounts();
        totalDepth += counts.waiting + counts.active;
      }
    }
    
    return totalDepth;
  } catch (error) {
    logger.error('Failed to check queue depth', { error: error.message });
    return 0;
  }
}

/**
 * Helper function to check admin permission
 * @param {Object} adminUser - Admin user
 * @param {string} permission - Required permission
 * @returns {Promise<boolean>} Has permission
 */
async function checkAdminPermission(adminUser, permission) {
  // Check direct permission
  if (adminUser.permissions?.includes(permission)) {
    return true;
  }

  // Check role-based permissions
  if (adminUser.role?.permissions?.includes(permission)) {
    return true;
  }

  // Check wildcard permissions
  const permissionParts = permission.split('.');
  for (let i = permissionParts.length - 1; i > 0; i--) {
    const wildcardPermission = permissionParts.slice(0, i).join('.') + '.*';
    if (adminUser.permissions?.includes(wildcardPermission) || 
        adminUser.role?.permissions?.includes(wildcardPermission)) {
      return true;
    }
  }

  return false;
}

/**
 * Helper function to update admin bulk operation stats
 * @param {string} adminId - Admin ID
 * @param {string} operationType - Operation type
 * @param {Object} stats - Operation stats
 */
async function updateAdminBulkOperationStats(adminId, operationType, stats) {
  try {
    const key = `admin_bulk_stats:${adminId}:${operationType}`;
    const current = await CacheService.get(key) || {
      total: 0,
      successful: 0,
      totalDuration: 0,
      totalUsers: 0
    };

    current.total++;
    if (stats.success) current.successful++;
    current.totalDuration += stats.duration;
    current.totalUsers += stats.userCount;

    // Store for 24 hours
    await CacheService.set(key, current, 86400);
  } catch (error) {
    logger.error('Failed to update admin bulk operation stats', {
      error: error.message,
      adminId,
      operationType
    });
  }
}

// Export middleware functions
module.exports = {
  checkConcurrentOperations,
  checkDailyOperationLimit,
  checkOperationSizeLimit,
  createBulkOperationRateLimiter,
  checkResourceAvailability,
  validateBulkPermissions,
  trackBulkOperationMetrics
};