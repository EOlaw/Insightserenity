/**
 * @file Tenant Detection Middleware
 * @description Middleware for detecting and setting tenant context in hosted organizations
 * @version 1.0.0
 */

const logger = require('../../utils/logger');
const { AppError } = require('../../utils/app-error');
const OrganizationTenantService = require('../../../organization-tenants/services/organization-tenant-service');

/**
 * Detect tenant context for hosted organizations
 * Extracts tenant information from various sources and sets it in request context
 */
// const detectTenant = async (req, res, next) => {
//   try {
//     // Skip tenant detection for certain routes
//     const skipPaths = [
//       '/health', 
//       '/ping', 
//       '/metrics',
//       '/api/v1/hosted-organizations'
//     ];
//     // Add debugging
//     console.log('=== TENANT DETECTION DEBUG ===');
//     console.log('req.path:', req.path);
//     console.log('req.originalUrl:', req.originalUrl);
//     console.log('skipPaths:', skipPaths);
//     console.log('should skip:', skipPaths.some(path => req.path.startsWith(path)));
//     console.log('=== END DEBUG ===');
//     if (skipPaths.some(path => req.path.startsWith(path))) {
//       console.log('SKIPPING tenant detection for path:', req.path);
//       return next();
//     }

//     // Extract tenant ID from multiple sources (priority order)
//     const tenantId = extractTenantId(req);
    
//     if (!tenantId) {
//       // No tenant context found - continue without setting tenant
//       logger.debug('No tenant context detected', {
//         path: req.path,
//         method: req.method,
//         headers: {
//           'x-tenant-id': req.headers['x-tenant-id'],
//           'x-organization-id': req.headers['x-organization-id'],
//           host: req.headers.host
//         }
//       });
//       return next();
//     }

//     // Add this check before calling getTenantById
//     if (req.path.startsWith('/api/v1/hosted-organizations')) {
//       logger.debug('Skipping tenant validation for hosted organization creation');
//       return next();
//     }

//     // Validate and load tenant information
//     try {
//       const tenant = await OrganizationTenantService.getTenantById(tenantId, {
//         includeInactive: false,
//         lean: true
//       });

//       if (!tenant) {
//         logger.warn('Invalid tenant ID provided', {
//           tenantId,
//           path: req.path,
//           method: req.method,
//           userId: req.user?._id
//         });
//         return next(new AppError('Invalid tenant context', 400));
//       }

//       // Check tenant status
//       if (tenant.status !== 'active') {
//         logger.warn('Inactive tenant access attempt', {
//           tenantId,
//           status: tenant.status,
//           path: req.path,
//           userId: req.user?._id
//         });
//         return next(new AppError('Tenant is not active', 403));
//       }

//       // Set tenant context in request
//       req.tenantId = tenantId;
//       req.tenant = tenant;
//       req.organizationId = tenant.organizationId;

//       // Set response headers for client reference
//       res.setHeader('X-Tenant-ID', tenantId);
//       res.setHeader('X-Organization-ID', tenant.organizationId);

//       logger.debug('Tenant context established', {
//         tenantId,
//         organizationId: tenant.organizationId,
//         tenantName: tenant.name,
//         status: tenant.status,
//         path: req.path,
//         method: req.method
//       });

//     } catch (error) {
//       logger.error('Error loading tenant context', {
//         tenantId,
//         error: error.message,
//         path: req.path,
//         method: req.method
//       });
//       return next(new AppError('Failed to load tenant context', 500));
//     }
    
//     next();
//   } catch (error) {
//     logger.error('Tenant detection middleware error', {
//       error: error.message,
//       stack: error.stack,
//       path: req.path,
//       method: req.method
//     });
//     next(); // Continue without tenant context rather than failing the request
//   }
// };

const detectTenant = async (req, res, next) => {
  try {
    // Skip tenant detection for certain routes
    const skipPaths = [
      '/health', 
      '/ping', 
      '/metrics',
      '/api/v1/hosted-organizations'
    ];

    // Use originalUrl for proper path checking within router context
    const shouldSkip = skipPaths.some(path => req.originalUrl.startsWith(path));
    
    // Enhanced debugging for development
    logger.debug('Tenant detection path analysis', {
      path: req.path,
      originalUrl: req.originalUrl,
      method: req.method,
      shouldSkip: shouldSkip,
      host: req.get('host')
    });

    if (shouldSkip) {
      logger.debug('Skipping tenant detection', { 
        originalUrl: req.originalUrl,
        reason: 'Path matches skip patterns'
      });
      return next();
    }

    // Extract tenant ID from multiple sources with priority order
    const tenantId = extractTenantId(req);
    
    if (!tenantId) {
      // No tenant context found - continue without setting tenant
      logger.debug('No tenant context detected', {
        path: req.path,
        originalUrl: req.originalUrl,
        method: req.method,
        extractionSources: {
          'x-tenant-id': req.headers['x-tenant-id'],
          'x-organization-id': req.headers['x-organization-id'],
          host: req.headers.host,
          subdomain: extractTenantFromSubdomain(req),
          queryParam: req.query.tenantId
        }
      });
      return next();
    }

    logger.debug('Tenant ID extracted, validating tenant', { 
      tenantId, 
      originalUrl: req.originalUrl 
    });

    // Validate and load tenant information
    try {
      const tenant = await OrganizationTenantService.getTenantById(tenantId, {
        includeInactive: false,
        lean: true
      });

      if (!tenant) {
        logger.warn('Invalid tenant ID provided', {
          tenantId,
          path: req.path,
          originalUrl: req.originalUrl,
          method: req.method,
          userId: req.user?._id
        });
        return next(new AppError('Invalid tenant context', 400));
      }

      // Check tenant status for active operations
      if (tenant.status !== 'active') {
        logger.warn('Inactive tenant access attempt', {
          tenantId,
          status: tenant.status,
          path: req.path,
          originalUrl: req.originalUrl,
          userId: req.user?._id
        });
        return next(new AppError('Tenant is not active', 403));
      }

      // Set tenant context in request object
      req.tenantId = tenantId;
      req.tenant = tenant;
      req.organizationId = tenant.organizationId;

      // Set response headers for client reference
      res.setHeader('X-Tenant-ID', tenantId);
      res.setHeader('X-Organization-ID', tenant.organizationId);

      logger.debug('Tenant context established', {
        tenantId,
        organizationId: tenant.organizationId,
        tenantName: tenant.name,
        status: tenant.status,
        path: req.path,
        originalUrl: req.originalUrl,
        method: req.method
      });

    } catch (error) {
      logger.error('Error loading tenant context', {
        tenantId,
        error: error.message,
        errorType: error.constructor.name,
        path: req.path,
        originalUrl: req.originalUrl,
        method: req.method
      });

      // For development environments, continue without tenant context rather than failing
      if (process.env.NODE_ENV === 'development') {
        logger.warn('Development mode: Continuing without tenant context due to error', {
          tenantId,
          error: error.message
        });
        return next();
      }

      return next(new AppError('Failed to load tenant context', 500));
    }
    
    next();

  } catch (error) {
    logger.error('Tenant detection middleware error', {
      error: error.message,
      stack: error.stack,
      path: req.path,
      originalUrl: req.originalUrl,
      method: req.method
    });

    // In development, continue without tenant context to prevent blocking requests
    if (process.env.NODE_ENV === 'development') {
      logger.warn('Development mode: Bypassing tenant detection due to middleware error');
      return next();
    }

    // In production, this should be handled more strictly
    next(error);
  }
};

/**
 * Extract tenant ID from request using multiple strategies
 * @param {Object} req - Express request object
 * @returns {string|null} - Tenant ID or null if not found
 */
function extractTenantId(req) {
  // Priority 1: Explicit header
  if (req.headers['x-tenant-id']) {
    return req.headers['x-tenant-id'];
  }

  // Priority 2: Organization ID header (map to tenant)
  if (req.headers['x-organization-id']) {
    return req.headers['x-organization-id'];
  }

  // Priority 3: Query parameter
  if (req.query.tenantId) {
    return req.query.tenantId;
  }

  // Priority 4: Route parameter
  if (req.params.tenantId) {
    return req.params.tenantId;
  }

  // Priority 5: Subdomain extraction
  const subdomainTenant = extractTenantFromSubdomain(req);
  if (subdomainTenant) {
    return subdomainTenant;
  }

  // Priority 6: Custom domain extraction
  const domainTenant = extractTenantFromDomain(req);
  if (domainTenant) {
    return domainTenant;
  }

  return null;
}

/**
 * Extract tenant from subdomain
 * @param {Object} req - Express request object
 * @returns {string|null} - Tenant ID or null
 */
// function extractTenantFromSubdomain(req) {
//   const host = req.get('host');
//   if (!host) return null;

//   const subdomain = host.split('.')[0];
  
//   // Skip common subdomains that aren't tenant identifiers
//   const skipSubdomains = ['www', 'api', 'app', 'admin', 'localhost', 'staging', 'dev'];
  
//   if (subdomain && !skipSubdomains.includes(subdomain.toLowerCase())) {
//     return subdomain.toLowerCase();
//   }
  
//   return null;
// }
function extractTenantFromSubdomain(req) {
  const host = req.get('host');
  if (!host) return null;

  // Handle localhost and IP addresses in development
  if (host.startsWith('localhost') || host.startsWith('127.0.0.1') || /^\d+\.\d+\.\d+\.\d+/.test(host)) {
    return null;
  }

  const parts = host.split('.');
  
  // Need at least 2 parts for a valid subdomain (subdomain.domain.com)
  if (parts.length < 2) {
    return null;
  }

  const subdomain = parts[0];
  
  // Skip common subdomains that aren't tenant identifiers
  const skipSubdomains = ['www', 'api', 'app', 'admin', 'staging', 'dev', 'mail', 'ftp'];
  
  if (subdomain && !skipSubdomains.includes(subdomain.toLowerCase())) {
    return subdomain.toLowerCase();
  }
  
  return null;
}

/**
 * Extract tenant from custom domain mapping
 * @param {Object} req - Express request object
 * @returns {string|null} - Tenant ID or null
 */
function extractTenantFromDomain(req) {
  const hostname = req.hostname;
  if (!hostname) return null;

  // This would typically involve a database lookup for custom domain mappings
  // For now, return null as custom domains require additional implementation
  // TODO: Implement custom domain to tenant mapping
  return null;
}

/**
 * Require tenant context middleware
 * Ensures that a valid tenant context exists before proceeding
 */
const requireTenantContext = (req, res, next) => {
  if (!req.tenantId || !req.tenant) {
    logger.warn('Route requires tenant context but none found', {
      path: req.path,
      method: req.method,
      userId: req.user?._id,
      headers: {
        'x-tenant-id': req.headers['x-tenant-id'],
        'x-organization-id': req.headers['x-organization-id']
      }
    });
    
    return next(new AppError('Tenant context is required for this operation', 400));
  }
  
  next();
};

module.exports = {
  detectTenant,
  requireTenantContext,
  extractTenantId,
  extractTenantFromSubdomain,
  extractTenantFromDomain
};