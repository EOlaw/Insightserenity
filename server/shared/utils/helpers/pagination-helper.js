// /server/shared/utils/helpers/pagination-helper.js

/**
 * @file Pagination Helper
 * @description Pagination utilities for API responses and database queries
 * @version 1.0.0
 */

const constants = require('../../config/constants');
const { ValidationError } = require('../app-error');

/**
 * Pagination Helper Class
 */
class PaginationHelper {
  /**
   * Parse pagination parameters from request
   * @param {Object} query - Request query object
   * @param {Object} options - Parsing options
   * @returns {Object} Parsed pagination parameters
   */
  static parseParams(query = {}, options = {}) {
    const {
      defaultPage = constants.API.PAGINATION.DEFAULT_PAGE,
      defaultLimit = constants.API.PAGINATION.DEFAULT_LIMIT,
      maxLimit = constants.API.PAGINATION.MAX_LIMIT,
      minLimit = constants.API.PAGINATION.MIN_LIMIT
    } = options;
    
    // Parse page
    let page = parseInt(query.page) || defaultPage;
    if (page < 1) {
      page = 1;
    }
    
    // Parse limit
    let limit = parseInt(query.limit) || defaultLimit;
    if (limit < minLimit) {
      limit = minLimit;
    } else if (limit > maxLimit) {
      limit = maxLimit;
    }
    
    // Calculate offset
    const offset = (page - 1) * limit;
    
    // Parse sort parameters
    const sortBy = query.sortBy || query.sort || 'createdAt';
    const sortOrder = query.sortOrder || query.order || 'desc';
    
    // Normalize sort order
    const normalizedSortOrder = ['asc', '1'].includes(sortOrder.toLowerCase()) ? 'asc' : 'desc';
    const mongoSortOrder = normalizedSortOrder === 'asc' ? 1 : -1;
    
    return {
      page,
      limit,
      offset,
      sortBy,
      sortOrder: normalizedSortOrder,
      mongoSortOrder,
      skip: offset,
      take: limit // For Prisma compatibility
    };
  }
  
  /**
   * Calculate pagination metadata
   * @param {number} total - Total number of items
   * @param {number} page - Current page
   * @param {number} limit - Items per page
   * @returns {Object} Pagination metadata
   */
  static calculateMetadata(total, page, limit) {
    const totalPages = Math.ceil(total / limit) || 1;
    const hasNext = page < totalPages;
    const hasPrev = page > 1;
    const nextPage = hasNext ? page + 1 : null;
    const prevPage = hasPrev ? page - 1 : null;
    
    return {
      total,
      page,
      limit,
      totalPages,
      hasNext,
      hasPrev,
      nextPage,
      prevPage,
      from: total > 0 ? (page - 1) * limit + 1 : 0,
      to: total > 0 ? Math.min(page * limit, total) : 0
    };
  }
  
  /**
   * Create MongoDB pagination query
   * @param {Object} Model - Mongoose model
   * @param {Object} filter - Query filter
   * @param {Object} params - Pagination parameters
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Paginated results
   */
  static async paginateMongoose(Model, filter = {}, params = {}, options = {}) {
    const {
      page = 1,
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc',
      populate = '',
      select = '',
      lean = true
    } = params;
    
    const skip = (page - 1) * limit;
    const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
    
    // Execute queries in parallel
    const [data, total] = await Promise.all([
      Model.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .populate(populate)
        .select(select)
        .lean(lean),
      Model.countDocuments(filter)
    ]);
    
    const metadata = this.calculateMetadata(total, page, limit);
    
    return {
      data,
      ...metadata
    };
  }
  
  /**
   * Create pagination aggregation pipeline
   * @param {Array} pipeline - Base aggregation pipeline
   * @param {Object} params - Pagination parameters
   * @returns {Array} Paginated aggregation pipeline
   */
  static createAggregationPipeline(pipeline = [], params = {}) {
    const {
      page = 1,
      limit = 20,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = params;
    
    const skip = (page - 1) * limit;
    const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
    
    return [
      ...pipeline,
      {
        $facet: {
          metadata: [
            { $count: 'total' }
          ],
          data: [
            { $sort: sort },
            { $skip: skip },
            { $limit: limit }
          ]
        }
      },
      {
        $project: {
          data: 1,
          total: { $arrayElemAt: ['$metadata.total', 0] }
        }
      }
    ];
  }
  
  /**
   * Create SQL pagination query
   * @param {string} baseQuery - Base SQL query
   * @param {Object} params - Pagination parameters
   * @returns {Object} Paginated SQL query parts
   */
  static createSQLPagination(baseQuery, params = {}) {
    const {
      page = 1,
      limit = 20,
      sortBy = 'created_at',
      sortOrder = 'DESC'
    } = params;
    
    const offset = (page - 1) * limit;
    const orderBy = `ORDER BY ${sortBy} ${sortOrder.toUpperCase()}`;
    const limitClause = `LIMIT ${limit} OFFSET ${offset}`;
    
    return {
      dataQuery: `${baseQuery} ${orderBy} ${limitClause}`,
      countQuery: `SELECT COUNT(*) as total FROM (${baseQuery}) as count_query`,
      orderBy,
      limitClause,
      limit,
      offset
    };
  }
  
  /**
   * Create cursor-based pagination
   * @param {Array} data - Data array
   * @param {Object} params - Cursor parameters
   * @returns {Object} Cursor pagination result
   */
  static createCursorPagination(data, params = {}) {
    const {
      limit = 20,
      cursor = null,
      cursorField = 'id',
      direction = 'next'
    } = params;
    
    let filteredData = data;
    
    if (cursor) {
      const cursorIndex = data.findIndex(item => item[cursorField] === cursor);
      
      if (cursorIndex !== -1) {
        if (direction === 'next') {
          filteredData = data.slice(cursorIndex + 1);
        } else {
          filteredData = data.slice(0, cursorIndex);
        }
      }
    }
    
    const hasMore = filteredData.length > limit;
    const paginatedData = filteredData.slice(0, limit);
    
    const nextCursor = hasMore && paginatedData.length > 0
      ? paginatedData[paginatedData.length - 1][cursorField]
      : null;
    
    const prevCursor = cursor || (paginatedData.length > 0
      ? paginatedData[0][cursorField]
      : null);
    
    return {
      data: paginatedData,
      cursor: {
        next: nextCursor,
        prev: prevCursor,
        hasNext: hasMore,
        hasPrev: cursor !== null
      }
    };
  }
  
  /**
   * Create pagination links
   * @param {string} baseUrl - Base URL
   * @param {Object} metadata - Pagination metadata
   * @param {Object} query - Additional query parameters
   * @returns {Object} Pagination links
   */
  static createLinks(baseUrl, metadata, query = {}) {
    const { page, totalPages, hasNext, hasPrev } = metadata;
    
    const createUrl = (pageNum) => {
      const params = new URLSearchParams({ ...query, page: pageNum });
      return `${baseUrl}?${params.toString()}`;
    };
    
    const links = {
      self: createUrl(page),
      first: createUrl(1),
      last: createUrl(totalPages)
    };
    
    if (hasNext) {
      links.next = createUrl(page + 1);
    }
    
    if (hasPrev) {
      links.prev = createUrl(page - 1);
    }
    
    return links;
  }
  
  /**
   * Create page range for UI
   * @param {number} currentPage - Current page number
   * @param {number} totalPages - Total number of pages
   * @param {number} maxButtons - Maximum number of page buttons
   * @returns {Array} Array of page numbers
   */
  static createPageRange(currentPage, totalPages, maxButtons = 7) {
    if (totalPages <= maxButtons) {
      return Array.from({ length: totalPages }, (_, i) => i + 1);
    }
    
    const halfButtons = Math.floor(maxButtons / 2);
    let start = Math.max(1, currentPage - halfButtons);
    let end = Math.min(totalPages, currentPage + halfButtons);
    
    if (currentPage <= halfButtons) {
      end = maxButtons;
    } else if (currentPage >= totalPages - halfButtons) {
      start = totalPages - maxButtons + 1;
    }
    
    const range = [];
    for (let i = start; i <= end; i++) {
      range.push(i);
    }
    
    return range;
  }
  
  /**
   * Validate pagination parameters
   * @param {Object} params - Pagination parameters
   * @throws {ValidationError} If parameters are invalid
   */
  static validateParams(params) {
    const errors = [];
    
    if (params.page && (isNaN(params.page) || params.page < 1)) {
      errors.push({
        field: 'page',
        message: 'Page must be a positive integer'
      });
    }
    
    if (params.limit) {
      if (isNaN(params.limit) || params.limit < 1) {
        errors.push({
          field: 'limit',
          message: 'Limit must be a positive integer'
        });
      } else if (params.limit > constants.API.PAGINATION.MAX_LIMIT) {
        errors.push({
          field: 'limit',
          message: `Limit cannot exceed ${constants.API.PAGINATION.MAX_LIMIT}`
        });
      }
    }
    
    if (errors.length > 0) {
      throw new ValidationError('Invalid pagination parameters', errors);
    }
  }
  
  /**
   * Middleware for pagination
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  static middleware(options = {}) {
    return (req, res, next) => {
      try {
        // Parse pagination parameters
        const params = this.parseParams(req.query, options);
        
        // Validate parameters
        this.validateParams(params);
        
        // Attach to request
        req.pagination = params;
        
        // Attach paginate method to response
        res.paginate = (data, total) => {
          const metadata = this.calculateMetadata(total, params.page, params.limit);
          const links = this.createLinks(req.originalUrl.split('?')[0], metadata, req.query);
          
          return res.json({
            success: true,
            data,
            pagination: metadata,
            links
          });
        };
        
        next();
      } catch (error) {
        next(error);
      }
    };
  }
  
  /**
   * Create infinite scroll response
   * @param {Array} data - Data array
   * @param {Object} params - Scroll parameters
   * @returns {Object} Infinite scroll response
   */
  static createInfiniteScroll(data, params = {}) {
    const {
      limit = 20,
      lastId = null,
      lastValue = null,
      sortField = 'createdAt'
    } = params;
    
    let filteredData = data;
    
    if (lastId && lastValue) {
      const lastIndex = data.findIndex(item => item.id === lastId);
      if (lastIndex !== -1) {
        filteredData = data.slice(lastIndex + 1);
      }
    }
    
    const hasMore = filteredData.length > limit;
    const items = filteredData.slice(0, limit);
    
    const response = {
      items,
      hasMore,
      count: items.length
    };
    
    if (hasMore && items.length > 0) {
      const lastItem = items[items.length - 1];
      response.lastId = lastItem.id;
      response.lastValue = lastItem[sortField];
    }
    
    return response;
  }
  
  /**
   * Create keyset pagination for large datasets
   * @param {Object} Model - Database model
   * @param {Object} params - Keyset parameters
   * @returns {Promise<Object>} Keyset pagination result
   */
  static async keysetPaginate(Model, params = {}) {
    const {
      limit = 20,
      after = null,
      before = null,
      sortBy = 'id',
      sortOrder = 'asc'
    } = params;
    
    let query = {};
    
    if (after) {
      query[sortBy] = sortOrder === 'asc' ? { $gt: after } : { $lt: after };
    } else if (before) {
      query[sortBy] = sortOrder === 'asc' ? { $lt: before } : { $gt: before };
    }
    
    const data = await Model.find(query)
      .sort({ [sortBy]: sortOrder === 'asc' ? 1 : -1 })
      .limit(limit + 1);
    
    const hasMore = data.length > limit;
    const items = hasMore ? data.slice(0, -1) : data;
    
    const result = {
      data: items,
      pageInfo: {
        hasNextPage: hasMore,
        hasPreviousPage: after !== null || before !== null
      }
    };
    
    if (items.length > 0) {
      result.pageInfo.startCursor = items[0][sortBy];
      result.pageInfo.endCursor = items[items.length - 1][sortBy];
    }
    
    return result;
  }
}

module.exports = PaginationHelper;