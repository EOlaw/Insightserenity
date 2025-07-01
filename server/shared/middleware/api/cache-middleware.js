/**
 * @file Cache Middleware
 * @description Caching middleware for API responses and cache management
 * @version 1.0.0
 */

const { CacheService } = require('../../services/cache-service');
const logger = require('../../utils/logger');

/**
 * Cache response middleware
 * Caches successful API responses
 */
const cacheResponse = (options = {}) => {
  return async (req, res, next) => {
    try {
      const {
        ttl = 300, // 5 minutes default
        keyGenerator = (req) => `route:${req.method}:${req.originalUrl}`,
        condition = (req) => req.method === 'GET',
        varyBy = [],
        tags = [],
        excludeHeaders = ['authorization', 'cookie', 'x-api-key']
      } = options;

      // Check if caching should be applied
      if (!condition(req)) {
        return next();
      }

      // Generate cache key
      let cacheKey = typeof keyGenerator === 'function' 
        ? keyGenerator(req) 
        : keyGenerator;

      // Add vary-by parameters to key
      if (varyBy.length > 0) {
        const varyValues = varyBy.map(field => {
          if (field.startsWith('header.')) {
            return req.get(field.substring(7));
          } else if (field.startsWith('query.')) {
            return req.query[field.substring(6)];
          } else if (field.startsWith('user.')) {
            return req.user?.[field.substring(5)];
          }
          return req[field];
        }).filter(Boolean);
        
        if (varyValues.length > 0) {
          cacheKey += `:${varyValues.join(':')}`;
        }
      }

      // Try to get from cache
      const cached = await CacheService.get(cacheKey);
      if (cached) {
        res.set({
          'X-Cache': 'HIT',
          'X-Cache-Key': cacheKey,
          'X-Cache-TTL': await CacheService.ttl(cacheKey)
        });
        
        logger.debug('Cache hit', { key: cacheKey, url: req.originalUrl });
        return res.json(cached);
      }

      // Store original json method
      const originalJson = res.json;
      
      // Override json method to cache response
      res.json = function(data) {
        res.set({
          'X-Cache': 'MISS',
          'X-Cache-Key': cacheKey
        });
        
        // Cache successful responses only
        if (res.statusCode >= 200 && res.statusCode < 300) {
          CacheService.set(cacheKey, data, ttl)
            .then(() => {
              // Tag the cache entry if tags provided
              if (tags.length > 0) {
                return CacheService.tag(cacheKey, tags);
              }
            })
            .catch(err => {
              logger.error('Response caching error', {
                error: err.message,
                key: cacheKey
              });
            });
          
          logger.debug('Response cached', { 
            key: cacheKey, 
            ttl, 
            url: req.originalUrl 
          });
        }
        
        // Call original json method
        return originalJson.call(res, data);
      };

      next();
    } catch (error) {
      logger.error('Cache middleware error', {
        error: error.message,
        url: req.originalUrl
      });
      next(); // Continue without caching on error
    }
  };
};

/**
 * Clear organization cache middleware
 * Removes cached data related to an organization
 */
const clearOrganizationCache = (req, res, next) => {
  // Store organization ID for later cache clearing
  const organizationId = req.params.id || req.organizationId || req.user?.organizationId;
  
  if (organizationId) {
    req.cacheClearing = {
      organizationId,
      patterns: [
        `route:*:/api/v*/organizations/${organizationId}*`,
        `route:*:/api/v*/hosted-organizations/organizations/${organizationId}*`,
        `organization:${organizationId}:*`,
        `org:${organizationId}:*`
      ]
    };
  }

  // Store original methods to clear cache after successful response
  const originalJson = res.json;
  const originalSend = res.send;

  const clearCache = async () => {
    if (req.cacheClearing && res.statusCode >= 200 && res.statusCode < 300) {
      try {
        const { patterns } = req.cacheClearing;
        
        for (const pattern of patterns) {
          await CacheService.delPattern(pattern);
        }
        
        logger.debug('Organization cache cleared', {
          organizationId,
          patterns
        });
      } catch (error) {
        logger.error('Cache clearing error', {
          error: error.message,
          organizationId
        });
      }
    }
  };

  // Override response methods
  res.json = function(data) {
    clearCache();
    return originalJson.call(res, data);
  };

  res.send = function(data) {
    clearCache();
    return originalSend.call(res, data);
  };

  next();
};

/**
 * Clear cache by pattern middleware
 */
const clearCachePattern = (patternGenerator) => {
  return (req, res, next) => {
    const originalJson = res.json;
    const originalSend = res.send;

    const clearCache = async () => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        try {
          const pattern = typeof patternGenerator === 'function'
            ? patternGenerator(req)
            : patternGenerator;
          
          await CacheService.delPattern(pattern);
          
          logger.debug('Cache pattern cleared', { pattern });
        } catch (error) {
          logger.error('Cache pattern clearing error', {
            error: error.message,
            pattern
          });
        }
      }
    };

    res.json = function(data) {
      clearCache();
      return originalJson.call(res, data);
    };

    res.send = function(data) {
      clearCache();
      return originalSend.call(res, data);
    };

    next();
  };
};

/**
 * Clear cache by tags middleware
 */
const clearCacheTags = (tagsGenerator) => {
  return (req, res, next) => {
    const originalJson = res.json;
    const originalSend = res.send;

    const clearCache = async () => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        try {
          const tags = typeof tagsGenerator === 'function'
            ? tagsGenerator(req)
            : tagsGenerator;
          
          for (const tag of tags) {
            await CacheService.invalidateTag(tag);
          }
          
          logger.debug('Cache tags invalidated', { tags });
        } catch (error) {
          logger.error('Cache tags clearing error', {
            error: error.message,
            tags
          });
        }
      }
    };

    res.json = function(data) {
      clearCache();
      return originalJson.call(res, data);
    };

    res.send = function(data) {
      clearCache();
      return originalSend.call(res, data);
    };

    next();
  };
};

/**
 * Cache headers middleware
 * Adds appropriate cache headers to responses
 */
const cacheHeaders = (options = {}) => {
  return (req, res, next) => {
    const {
      maxAge = 300, // 5 minutes
      mustRevalidate = false,
      noCache = false,
      privateCache = false
    } = options;

    if (noCache) {
      res.set({
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      });
    } else {
      const cacheControl = [
        privateCache ? 'private' : 'public',
        `max-age=${maxAge}`,
        mustRevalidate ? 'must-revalidate' : ''
      ].filter(Boolean).join(', ');

      res.set({
        'Cache-Control': cacheControl,
        'ETag': `"${Date.now()}"`,
        'Last-Modified': new Date().toUTCString()
      });
    }

    next();
  };
};

/**
 * Conditional GET support middleware
 */
const conditionalGet = (req, res, next) => {
  const ifNoneMatch = req.get('If-None-Match');
  const ifModifiedSince = req.get('If-Modified-Since');

  // Store original json method
  const originalJson = res.json;

  res.json = function(data) {
    const etag = res.get('ETag');
    const lastModified = res.get('Last-Modified');

    // Check If-None-Match
    if (ifNoneMatch && etag && ifNoneMatch === etag) {
      return res.status(304).end();
    }

    // Check If-Modified-Since
    if (ifModifiedSince && lastModified) {
      const modifiedSince = new Date(ifModifiedSince);
      const lastMod = new Date(lastModified);
      
      if (modifiedSince >= lastMod) {
        return res.status(304).end();
      }
    }

    return originalJson.call(res, data);
  };

  next();
};

module.exports = {
  cacheResponse,
  clearOrganizationCache,
  clearCachePattern,
  clearCacheTags,
  cacheHeaders,
  conditionalGet
};