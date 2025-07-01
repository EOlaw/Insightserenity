/**
 * @file Query Middleware
 * @description Middleware for handling query parameters, sorting, filtering, and field selection
 * @version 2.0.0
 */

const logger = require('../../utils/logger');

/**
 * Parse query options middleware
 * Handles sorting, filtering, field selection, and search parameters
 * Note: Pagination is handled by dedicated pagination middleware
 */
const parseQueryOptions = (options = {}) => {
  return (req, res, next) => {
    try {
      const {
        allowedSortFields = [],
        allowedFilterFields = [],
        defaultSortBy = 'createdAt',
        defaultSortOrder = 'desc',
        allowTextSearch = true,
        allowDateRanges = true,
        allowFieldSelection = true
      } = options;

      // Parse sorting parameters
      const sortBy = req.query.sortBy || req.query.sort || defaultSortBy;
      const sortOrder = req.query.sortOrder || req.query.order || defaultSortOrder;
      
      // Validate sort fields if restricted
      if (allowedSortFields.length > 0 && !allowedSortFields.includes(sortBy)) {
        return res.status(400).json({
          status: 'error',
          message: `Invalid sort field. Allowed fields: ${allowedSortFields.join(', ')}`
        });
      }

      // Parse filter parameters
      const filters = {};
      Object.keys(req.query).forEach(key => {
        if (key.startsWith('filter.') || key.startsWith('where.')) {
          const filterKey = key.replace(/^(filter\.|where\.)/, '');
          
          // Validate filter fields if restricted
          if (allowedFilterFields.length > 0 && !allowedFilterFields.includes(filterKey)) {
            return;
          }
          
          filters[filterKey] = req.query[key];
        }
      });

      // Parse search query
      const search = allowTextSearch ? (req.query.search || req.query.q || '') : '';

      // Parse field selection
      let fields = { include: [], exclude: [] };
      if (allowFieldSelection) {
        fields.include = req.query.fields ? req.query.fields.split(',').map(f => f.trim()) : [];
        fields.exclude = req.query.exclude ? req.query.exclude.split(',').map(f => f.trim()) : [];
      }

      // Parse date ranges
      let dateRange = {};
      if (allowDateRanges) {
        if (req.query.startDate) {
          dateRange.startDate = new Date(req.query.startDate);
        }
        if (req.query.endDate) {
          dateRange.endDate = new Date(req.query.endDate);
        }
      }

      // Attach parsed options to request
      req.queryOptions = {
        sort: {
          field: sortBy,
          order: sortOrder,
          mongoSort: { [sortBy]: sortOrder === 'asc' ? 1 : -1 }
        },
        filters,
        search,
        fields,
        dateRange
      };

      logger.debug('Query options parsed', {
        url: req.originalUrl,
        sort: req.queryOptions.sort,
        filterCount: Object.keys(filters).length,
        hasSearch: !!search,
        hasDateRange: !!(dateRange.startDate || dateRange.endDate)
      });

      next();
    } catch (error) {
      logger.error('Query parsing error', {
        error: error.message,
        query: req.query,
        url: req.originalUrl
      });
      
      return res.status(400).json({
        status: 'error',
        message: 'Invalid query parameters',
        details: error.message
      });
    }
  };
};

/**
 * Build MongoDB query from parsed options
 * Constructs query object for database operations
 */
const buildMongoQuery = (queryOptions) => {
  const { filters, search, dateRange } = queryOptions;
  const query = {};

  // Apply filter conditions
  Object.keys(filters).forEach(key => {
    const value = filters[key];
    
    // Handle different filter operators
    if (value.includes(',')) {
      // Multiple values - use $in operator
      query[key] = { $in: value.split(',').map(v => v.trim()) };
    } else if (value.startsWith('>=')) {
      query[key] = { $gte: parseValue(value.substring(2)) };
    } else if (value.startsWith('<=')) {
      query[key] = { $lte: parseValue(value.substring(2)) };
    } else if (value.startsWith('>')) {
      query[key] = { $gt: parseValue(value.substring(1)) };
    } else if (value.startsWith('<')) {
      query[key] = { $lt: parseValue(value.substring(1)) };
    } else if (value.startsWith('!')) {
      query[key] = { $ne: parseValue(value.substring(1)) };
    } else if (value.startsWith('~')) {
      // Regular expression match
      query[key] = { $regex: value.substring(1), $options: 'i' };
    } else {
      query[key] = parseValue(value);
    }
  });

  // Apply text search
  if (search) {
    query.$text = { $search: search };
  }

  // Apply date range filters
  if (dateRange.startDate || dateRange.endDate) {
    query.createdAt = {};
    if (dateRange.startDate) {
      query.createdAt.$gte = dateRange.startDate;
    }
    if (dateRange.endDate) {
      query.createdAt.$lte = dateRange.endDate;
    }
  }

  return query;
};

/**
 * Build field projection for MongoDB
 * Creates projection object for field selection
 */
const buildFieldProjection = (queryOptions) => {
  const { fields } = queryOptions;
  const projection = {};

  // Include specific fields
  if (fields.include.length > 0) {
    fields.include.forEach(field => {
      projection[field] = 1;
    });
  }

  // Exclude specific fields
  if (fields.exclude.length > 0) {
    fields.exclude.forEach(field => {
      projection[field] = 0;
    });
  }

  return Object.keys(projection).length > 0 ? projection : null;
};

/**
 * Apply query options to Mongoose query
 * Applies sorting and field projection to database query
 */
const applyQueryOptions = (mongooseQuery, queryOptions) => {
  const { sort } = queryOptions;

  // Apply sorting
  mongooseQuery.sort(sort.mongoSort);

  // Apply field projection
  const projection = buildFieldProjection(queryOptions);
  if (projection) {
    mongooseQuery.select(projection);
  }

  return mongooseQuery;
};

/**
 * Parse filter value to appropriate type
 * Converts string values to appropriate data types
 */
const parseValue = (value) => {
  // Try to parse as number
  if (!isNaN(value) && !isNaN(parseFloat(value))) {
    return parseFloat(value);
  }
  
  // Try to parse as boolean
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (value === 'null') return null;
  
  // Return as string
  return value;
};

/**
 * Validate query parameters middleware
 * Ensures query parameters meet security and performance requirements
 */
const validateQueryParams = (options = {}) => {
  return (req, res, next) => {
    const {
      maxFilters = 10,
      maxFieldSelections = 20,
      allowedOperators = ['>=', '<=', '>', '<', '!', '~'],
      maxSearchLength = 100
    } = options;

    try {
      // Count filter parameters
      const filterCount = Object.keys(req.query).filter(key => 
        key.startsWith('filter.') || key.startsWith('where.')
      ).length;

      if (filterCount > maxFilters) {
        return res.status(400).json({
          status: 'error',
          message: `Too many filters. Maximum allowed: ${maxFilters}`
        });
      }

      // Validate search query length
      const searchQuery = req.query.search || req.query.q || '';
      if (searchQuery.length > maxSearchLength) {
        return res.status(400).json({
          status: 'error',
          message: `Search query too long. Maximum length: ${maxSearchLength}`
        });
      }

      // Validate field selections
      const fields = req.query.fields ? req.query.fields.split(',') : [];
      if (fields.length > maxFieldSelections) {
        return res.status(400).json({
          status: 'error',
          message: `Too many field selections. Maximum allowed: ${maxFieldSelections}`
        });
      }

      next();
    } catch (error) {
      logger.error('Query validation error', {
        error: error.message,
        url: req.originalUrl
      });

      return res.status(400).json({
        status: 'error',
        message: 'Query parameter validation failed'
      });
    }
  };
};

module.exports = {
  parseQueryOptions,
  buildMongoQuery,
  buildFieldProjection,
  applyQueryOptions,
  validateQueryParams
};