/**
 * @file Pagination Middleware
 * @description Dedicated pagination middleware for API endpoints
 * @version 1.0.0
 */

const { PaginationHelper } = require('../../utils/helpers/pagination-helper');
const logger = require('../../utils/logger');
const { ValidationError } = require('../../utils/app-error');

/**
 * Parse pagination parameters middleware
 * Extracts and validates pagination parameters from request query
 */
const parsePagination = (options = {}) => {
  return (req, res, next) => {
    try {
      const {
        defaultPage = 1,
        defaultLimit = 20,
        maxLimit = 100,
        minLimit = 1,
        allowUnlimited = false
      } = options;

      // Parse pagination parameters using existing helper
      const paginationParams = PaginationHelper.parseParams(req.query, {
        defaultPage,
        defaultLimit,
        maxLimit,
        minLimit
      });

      // Handle unlimited pagination for admin users
      if (allowUnlimited && req.query.unlimited === 'true') {
        if (req.user?.role?.primary === 'super_admin' || req.user?.role?.primary === 'admin') {
          paginationParams.limit = 0; // 0 indicates no limit
          paginationParams.unlimited = true;
        } else {
          logger.warn('Unauthorized unlimited pagination attempt', {
            userId: req.user?.id,
            userRole: req.user?.role?.primary,
            url: req.originalUrl
          });
        }
      }

      // Validate pagination parameters
      PaginationHelper.validateParams(paginationParams);

      // Attach pagination configuration to request
      req.pagination = {
        ...paginationParams,
        enabled: true,
        type: 'offset' // default pagination type
      };

      logger.debug('Pagination parameters parsed', {
        pagination: req.pagination,
        url: req.originalUrl
      });

      next();
    } catch (error) {
      logger.error('Pagination parsing error', {
        error: error.message,
        query: req.query,
        url: req.originalUrl
      });

      if (error instanceof ValidationError) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid pagination parameters',
          errors: error.errors
        });
      }

      return res.status(400).json({
        status: 'error',
        message: 'Pagination parameter validation failed',
        details: error.message
      });
    }
  };
};

/**
 * Cursor-based pagination middleware
 * Handles cursor-based pagination for large datasets
 */
const parseCursorPagination = (options = {}) => {
  return (req, res, next) => {
    try {
      const {
        defaultLimit = 20,
        maxLimit = 100,
        cursorField = 'id',
        sortOrder = 'asc'
      } = options;

      const limit = Math.min(
        parseInt(req.query.limit) || defaultLimit,
        maxLimit
      );

      const cursor = req.query.cursor || null;
      const direction = req.query.direction || 'forward';

      // Validate cursor direction
      if (!['forward', 'backward'].includes(direction)) {
        return res.status(400).json({
          status: 'error',
          message: 'Invalid cursor direction. Must be "forward" or "backward"'
        });
      }

      req.pagination = {
        type: 'cursor',
        limit,
        cursor,
        direction,
        cursorField,
        sortOrder,
        enabled: true
      };

      logger.debug('Cursor pagination parameters parsed', {
        pagination: req.pagination,
        url: req.originalUrl
      });

      next();
    } catch (error) {
      logger.error('Cursor pagination parsing error', {
        error: error.message,
        query: req.query
      });

      return res.status(400).json({
        status: 'error',
        message: 'Invalid cursor pagination parameters',
        details: error.message
      });
    }
  };
};

/**
 * Add pagination response helpers to response object
 */
const addPaginationHelpers = (req, res, next) => {
  /**
   * Send paginated response with metadata
   */
  res.paginate = (data, total, additionalMeta = {}) => {
    const { pagination } = req;

    if (!pagination || !pagination.enabled) {
      return res.json({
        status: 'success',
        data,
        count: Array.isArray(data) ? data.length : 1,
        ...additionalMeta
      });
    }

    if (pagination.type === 'cursor') {
      return res.paginateCursor(data, additionalMeta);
    }

    // Handle unlimited pagination
    if (pagination.unlimited) {
      return res.json({
        status: 'success',
        data,
        pagination: {
          unlimited: true,
          total: Array.isArray(data) ? data.length : 1
        },
        ...additionalMeta
      });
    }

    // Standard offset-based pagination
    const metadata = PaginationHelper.calculateMetadata(
      total,
      pagination.page,
      pagination.limit
    );

    const links = PaginationHelper.createLinks(
      req.originalUrl.split('?')[0],
      metadata,
      req.query
    );

    return res.json({
      status: 'success',
      data,
      pagination: {
        ...metadata,
        params: {
          page: pagination.page,
          limit: pagination.limit,
          sortBy: pagination.sortBy,
          sortOrder: pagination.sortOrder
        }
      },
      links,
      ...additionalMeta
    });
  };

  /**
   * Send cursor-based paginated response
   */
  res.paginateCursor = (data, additionalMeta = {}) => {
    const { pagination } = req;
    const items = Array.isArray(data) ? data : [data];

    let nextCursor = null;
    let prevCursor = null;
    let hasMore = false;

    if (items.length > 0) {
      const lastItem = items[items.length - 1];
      const firstItem = items[0];

      // Generate next cursor
      if (items.length === pagination.limit) {
        hasMore = true;
        nextCursor = lastItem[pagination.cursorField];
      }

      // Generate previous cursor for backward navigation
      if (pagination.cursor) {
        prevCursor = firstItem[pagination.cursorField];
      }
    }

    return res.json({
      status: 'success',
      data: items,
      pagination: {
        type: 'cursor',
        hasMore,
        hasPrevious: !!pagination.cursor,
        count: items.length,
        limit: pagination.limit,
        cursor: {
          next: nextCursor,
          previous: prevCursor,
          current: pagination.cursor
        }
      },
      ...additionalMeta
    });
  };

  /**
   * Send infinite scroll response
   */
  res.infiniteScroll = (data, additionalMeta = {}) => {
    const { pagination } = req;
    const items = Array.isArray(data) ? data : [data];

    const hasMore = items.length === pagination.limit;
    let lastId = null;
    let lastValue = null;

    if (items.length > 0 && hasMore) {
      const lastItem = items[items.length - 1];
      lastId = lastItem.id || lastItem._id;
      lastValue = lastItem[pagination.sortBy] || lastItem.createdAt;
    }

    return res.json({
      status: 'success',
      data: items,
      scroll: {
        hasMore,
        count: items.length,
        lastId,
        lastValue,
        sortBy: pagination.sortBy
      },
      ...additionalMeta
    });
  };

  next();
};

/**
 * Apply pagination to MongoDB query
 */
const applyMongodbPagination = (query, req) => {
  const { pagination } = req;

  if (!pagination || !pagination.enabled || pagination.unlimited) {
    return query;
  }

  if (pagination.type === 'cursor') {
    return applyCursorPagination(query, pagination);
  }

  // Standard offset-based pagination
  return query
    .skip(pagination.offset)
    .limit(pagination.limit)
    .sort({ [pagination.sortBy]: pagination.mongoSortOrder });
};

/**
 * Apply cursor-based pagination to MongoDB query
 */
const applyCursorPagination = (query, pagination) => {
  const { cursor, cursorField, sortOrder, limit, direction } = pagination;

  if (cursor) {
    const operator = direction === 'forward' 
      ? (sortOrder === 'asc' ? '$gt' : '$lt')
      : (sortOrder === 'asc' ? '$lt' : '$gt');
    
    query = query.where(cursorField)[operator](cursor);
  }

  const sortDirection = direction === 'forward' 
    ? (sortOrder === 'asc' ? 1 : -1)
    : (sortOrder === 'asc' ? -1 : 1);

  return query
    .sort({ [cursorField]: sortDirection })
    .limit(limit);
};

/**
 * Validate pagination access based on user permissions
 */
const validatePaginationAccess = (options = {}) => {
  return (req, res, next) => {
    const {
      maxLimitForRole = {
        guest: 10,
        member: 50,
        admin: 200,
        super_admin: 1000
      },
      requireAuthForLargeLimits = true,
      largeLimit = 100
    } = options;

    const { pagination } = req;
    const userRole = req.user?.role?.primary || 'guest';

    // Check authentication requirement for large limits
    if (requireAuthForLargeLimits && pagination.limit > largeLimit && !req.user) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required for large pagination limits'
      });
    }

    // Apply role-based limit restrictions
    const maxAllowedLimit = maxLimitForRole[userRole] || maxLimitForRole.guest;
    if (pagination.limit > maxAllowedLimit) {
      logger.warn('Pagination limit exceeded for user role', {
        userId: req.user?.id,
        userRole,
        requestedLimit: pagination.limit,
        maxAllowed: maxAllowedLimit
      });

      pagination.limit = maxAllowedLimit;
    }

    next();
  };
};

/**
 * Performance optimization middleware for large datasets
 */
const optimizeForLargeDatasets = (options = {}) => {
  return (req, res, next) => {
    const {
      countThreshold = 10000,
      estimateCount = true,
      maxCountLimit = 1000000
    } = options;

    const { pagination } = req;

    // Add optimization hints to request
    req.paginationOptimization = {
      useEstimatedCount: estimateCount && pagination.limit > countThreshold,
      skipTotalCount: pagination.page > 100, // Skip count for deep pagination
      maxCountLimit,
      useIndex: true,
      projection: req.query.fields ? req.query.fields.split(',') : null
    };

    // Add performance timing
    req.paginationStartTime = process.hrtime.bigint();

    // Log performance metrics after response
    res.on('finish', () => {
      if (req.paginationStartTime) {
        const duration = Number(process.hrtime.bigint() - req.paginationStartTime) / 1000000;
        
        logger.debug('Pagination performance', {
          duration: `${duration.toFixed(2)}ms`,
          page: pagination.page,
          limit: pagination.limit,
          optimization: req.paginationOptimization
        });
      }
    });

    next();
  };
};

module.exports = {
  parsePagination,
  parseCursorPagination,
  addPaginationHelpers,
  applyMongodbPagination,
  applyCursorPagination,
  validatePaginationAccess,
  optimizeForLargeDatasets
};