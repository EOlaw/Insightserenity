// /server/shared/middleware/not-found-handler.js

/**
 * @file Not Found Handler Middleware
 * @description Handles 404 errors for unmatched routes with ResponseHelper integration
 * @version 1.1.0
 */

const { AppError } = require('../utils/app-error');
const errorCodes = require('../utils/constants/error-codes');
const ResponseHelper = require('../utils/helpers/response-helper');
const logger = require('../utils/logger');

/**
 * Not Found Handler Class
 */
class NotFoundHandler {
  /**
   * Handle 404 errors for unmatched routes
   * @param {import('express').Request} req - Express request object
   * @param {import('express').Response} res - Express response object
   * @param {import('express').NextFunction} next - Express next function
   */
  static handle(req, res, next) {
    const message = `Cannot ${req.method} ${req.originalUrl || 'unknown route'}`;
    
    // Log the 404 error for monitoring
    logger.warn('Route not found', {
      method: req.method,
      url: req.originalUrl,
      userAgent: req.get('user-agent'),
      ip: req.ip,
      timestamp: new Date().toISOString(),
      requestId: req.id
    });
    
    // Create AppError for processing by error handler
    const error = new AppError(
      message,
      404,
      errorCodes.BUSINESS.RESOURCE_NOT_FOUND,
      {
        method: req.method,
        path: req.originalUrl,
        availableRoutes: NotFoundHandler.getAvailableRoutes(req)
      }
    );
    
    next(error);
  }
  
  /**
   * Direct 404 response using ResponseHelper (alternative approach)
   * @param {import('express').Request} req - Express request object
   * @param {import('express').Response} res - Express response object
   */
  static handleDirect(req, res) {
    const message = `Route ${req.originalUrl} not found`;
    
    // Log the 404 error
    logger.warn('Route not found (direct response)', {
      method: req.method,
      url: req.originalUrl,
      userAgent: req.get('user-agent'),
      ip: req.ip,
      timestamp: new Date().toISOString(),
      requestId: req.id
    });
    
    // Use ResponseHelper for consistent 404 response
    return ResponseHelper.notFound(res, 'Route', req.originalUrl);
  }
  
  /**
   * Enhanced 404 handler with suggestions
   * @param {import('express').Request} req - Express request object
   * @param {import('express').Response} res - Express response object
   * @param {import('express').NextFunction} next - Express next function
   */
  static handleWithSuggestions(req, res, next) {
    const requestedPath = req.originalUrl;
    const suggestions = NotFoundHandler.getSimilarRoutes(requestedPath, req);
    
    // Log with suggestions
    logger.warn('Route not found with suggestions', {
      method: req.method,
      url: requestedPath,
      suggestions,
      userAgent: req.get('user-agent'),
      ip: req.ip,
      timestamp: new Date().toISOString(),
      requestId: req.id
    });
    
    const message = `Cannot ${req.method} ${requestedPath}`;
    const details = {
      method: req.method,
      path: requestedPath,
      suggestions: suggestions.length > 0 ? suggestions : undefined,
      helpMessage: 'Check the URL and try again, or refer to the API documentation'
    };
    
    const error = new AppError(
      message,
      404,
      errorCodes.BUSINESS.RESOURCE_NOT_FOUND,
      details
    );
    
    next(error);
  }
  
  /**
   * API-specific 404 handler
   * @param {import('express').Request} req - Express request object
   * @param {import('express').Response} res - Express response object
   */
  static handleAPI(req, res) {
    const apiVersion = req.baseUrl?.match(/\/api\/(v\d+)/)?.[1] || 'v1';
    const endpoint = req.originalUrl;
    
    logger.warn('API endpoint not found', {
      method: req.method,
      endpoint,
      apiVersion,
      userAgent: req.get('user-agent'),
      ip: req.ip,
      timestamp: new Date().toISOString(),
      requestId: req.id
    });
    
    const details = {
      endpoint,
      apiVersion,
      method: req.method,
      documentation: `/docs/api/${apiVersion}`,
      supportedMethods: NotFoundHandler.getSupportedMethods(req.route?.path),
      timestamp: new Date().toISOString()
    };
    
    return ResponseHelper.error(
      res,
      `API endpoint ${endpoint} not found`,
      404,
      errorCodes.BUSINESS.RESOURCE_NOT_FOUND,
      details
    );
  }
  
  /**
   * Get available routes for debugging (development only)
   * @param {import('express').Request} req - Express request object
   * @returns {Array|null} Available routes or null in production
   */
  static getAvailableRoutes(req) {
    // Only provide route hints in development
    if (process.env.NODE_ENV === 'production') {
      return null;
    }
    
    try {
      const app = req.app;
      const routes = [];
      
      // Extract routes from Express app
      app._router?.stack?.forEach(layer => {
        if (layer.route) {
          const methods = Object.keys(layer.route.methods).join(', ').toUpperCase();
          routes.push(`${methods} ${layer.route.path}`);
        }
      });
      
      return routes.slice(0, 10); // Limit to first 10 routes
    } catch (error) {
      logger.error('Error extracting available routes', { error: error.message });
      return null;
    }
  }
  
  /**
   * Get similar routes using simple string matching
   * @param {string} requestedPath - The requested path
   * @param {import('express').Request} req - Express request object
   * @returns {Array} Array of similar routes
   */
  static getSimilarRoutes(requestedPath, req) {
    if (process.env.NODE_ENV === 'production') {
      return [];
    }
    
    try {
      const availableRoutes = NotFoundHandler.getAvailableRoutes(req) || [];
      const suggestions = [];
      
      availableRoutes.forEach(route => {
        const routePath = route.split(' ')[1]; // Extract path from "METHOD /path"
        
        // Simple similarity check
        if (routePath && NotFoundHandler.calculateSimilarity(requestedPath, routePath) > 0.5) {
          suggestions.push(route);
        }
      });
      
      return suggestions.slice(0, 3); // Limit to 3 suggestions
    } catch (error) {
      logger.error('Error generating route suggestions', { error: error.message });
      return [];
    }
  }
  
  /**
   * Calculate string similarity (simple implementation)
   * @param {string} str1 - First string
   * @param {string} str2 - Second string
   * @returns {number} Similarity score between 0 and 1
   */
  static calculateSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;
    
    if (longer.length === 0) {
      return 1.0;
    }
    
    const editDistance = NotFoundHandler.getEditDistance(longer, shorter);
    return (longer.length - editDistance) / longer.length;
  }
  
  /**
   * Calculate edit distance between two strings
   * @param {string} str1 - First string
   * @param {string} str2 - Second string
   * @returns {number} Edit distance
   */
  static getEditDistance(str1, str2) {
    const matrix = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));
    
    for (let i = 0; i <= str1.length; i++) {
      matrix[0][i] = i;
    }
    
    for (let j = 0; j <= str2.length; j++) {
      matrix[j][0] = j;
    }
    
    for (let j = 1; j <= str2.length; j++) {
      for (let i = 1; i <= str1.length; i++) {
        const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[j][i] = Math.min(
          matrix[j][i - 1] + 1, // deletion
          matrix[j - 1][i] + 1, // insertion
          matrix[j - 1][i - 1] + indicator // substitution
        );
      }
    }
    
    return matrix[str2.length][str1.length];
  }
  
  /**
   * Get supported HTTP methods for a route path
   * @param {string} routePath - Route path
   * @returns {Array} Supported methods
   */
  static getSupportedMethods(routePath) {
    // This is a simplified implementation
    // In a real scenario, you'd check the actual route definitions
    const commonMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    return routePath ? commonMethods : [];
  }
  
  /**
   * Middleware factory for different 404 handling strategies
   * @param {string} strategy - Handling strategy ('simple', 'direct', 'enhanced', 'api')
   * @returns {Function} Express middleware
   */
  static middleware(strategy = 'simple') {
    const strategies = {
      simple: NotFoundHandler.handle,
      direct: NotFoundHandler.handleDirect,
      enhanced: NotFoundHandler.handleWithSuggestions,
      api: NotFoundHandler.handleAPI
    };
    
    const handler = strategies[strategy] || strategies.simple;
    
    return (req, res, next) => {
      // Add request ID if not present
      if (!req.id) {
        req.id = require('crypto').randomUUID();
      }
      
      return handler(req, res, next);
    };
  }
}

// Export default handler and alternatives
module.exports = NotFoundHandler.handle;
module.exports.NotFoundHandler = NotFoundHandler;
module.exports.direct = NotFoundHandler.handleDirect;
module.exports.enhanced = NotFoundHandler.handleWithSuggestions;
module.exports.api = NotFoundHandler.handleAPI;
module.exports.middleware = NotFoundHandler.middleware;