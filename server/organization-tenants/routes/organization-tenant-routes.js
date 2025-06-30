/**
 * @file Organization Tenant Routes
 * @description API routes for multi-tenant organization management
 * @version 1.0.0
 */

const express = require('express');

// Controllers
const OrganizationTenantController = require('../controllers/organization-tenant-controller');

// Shared Middleware
const { authenticate, requireAuth } = require('../../../shared/middleware/auth/auth-middleware');
const { 
  restrictTo, 
  checkPermission,
  requirePlatformAdmin,
  requireTenantOwner,
  requireTenantAdmin
} = require('../../../shared/middleware/auth/authorization-middleware');

// Validation
const {
  validateTenantCreate,
  validateTenantUpdate,
  validateSubscriptionUpdate,
  validateDomainAdd,
  validateSecuritySettings,
  validateResourceLimits,
  validateSearchQuery
} = require('../validation/organization-tenant-validation');

// Custom Middleware
const { 
  detectTenantContext,
  requireTenantContext,
  validateTenantAccess
} = require('../middleware/tenant-context-middleware');

// Rate Limiting
const { createRateLimiter } = require('../../../shared/security/middleware/rate-limiter');

// Create rate limiters
const tenantCreateLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 tenant creations per hour
  message: 'Too many tenant creation attempts'
});

const sensitiveOperationLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: 'Too many sensitive operation attempts'
});

const router = express.Router();

/**
 * Public Routes
 */
router.get('/health', OrganizationTenantController.healthCheck);

/**
 * All routes below require authentication
 */
router.use(authenticate);

/**
 * Tenant Context Routes
 * These routes work with the current tenant context
 */
router.get('/current',
  detectTenantContext,
  requireTenantContext,
  OrganizationTenantController.getCurrentTenant
);

router.patch('/current/settings',
  detectTenantContext,
  requireTenantContext,
  requireTenantAdmin,
  OrganizationTenantController.updateSettings
);

router.patch('/current/security',
  detectTenantContext,
  requireTenantContext,
  requireTenantOwner,
  requireAuth({ verify2FA: true }),
  sensitiveOperationLimiter,
  validateSecuritySettings,
  OrganizationTenantController.updateSecuritySettings
);

router.patch('/current/branding',
  detectTenantContext,
  requireTenantContext,
  requireTenantAdmin,
  OrganizationTenantController.updateBranding
);

/**
 * Search and Statistics Routes
 */
router.get('/search',
  requirePlatformAdmin,
  validateSearchQuery,
  OrganizationTenantController.searchTenants
);

router.get('/statistics',
  requirePlatformAdmin,
  OrganizationTenantController.getTenantStatistics
);

/**
 * Tenant by Code Route
 */
router.get('/code/:code',
  OrganizationTenantController.getTenantByCode
);

/**
 * Owner-based Routes
 */
router.get('/owner/:ownerId',
  OrganizationTenantController.getTenantsByOwner
);

/**
 * Main Tenant CRUD Routes
 */
router.route('/')
  .post(
    requirePlatformAdmin,
    tenantCreateLimiter,
    validateTenantCreate,
    OrganizationTenantController.createTenant
  );

router.route('/:id')
  .get(
    validateTenantAccess,
    OrganizationTenantController.getTenantById
  )
  .patch(
    validateTenantAccess,
    requireTenantAdmin,
    validateTenantUpdate,
    OrganizationTenantController.updateTenant
  );

/**
 * Tenant Lifecycle Management
 */
router.post('/:id/activate',
  requirePlatformAdmin,
  sensitiveOperationLimiter,
  OrganizationTenantController.activateTenant
);

router.post('/:id/suspend',
  requirePlatformAdmin,
  sensitiveOperationLimiter,
  OrganizationTenantController.suspendTenant
);

/**
 * Subscription Management
 */
router.route('/:id/subscription')
  .post(
    validateTenantAccess,
    requireTenantOwner,
    sensitiveOperationLimiter,
    validateSubscriptionUpdate,
    OrganizationTenantController.updateSubscription
  );

/**
 * Domain Management
 */
router.route('/:id/domains')
  .post(
    validateTenantAccess,
    requireTenantOwner,
    sensitiveOperationLimiter,
    validateDomainAdd,
    OrganizationTenantController.addCustomDomain
  );

router.post('/:id/domains/:domain/verify',
  validateTenantAccess,
  requireTenantOwner,
  OrganizationTenantController.verifyCustomDomain
);

/**
 * Usage and Limits
 */
router.get('/:id/usage',
  validateTenantAccess,
  OrganizationTenantController.getTenantUsage
);

router.patch('/:id/limits',
  requirePlatformAdmin,
  validateResourceLimits,
  OrganizationTenantController.updateResourceLimits
);

/**
 * Settings Management
 */
router.patch('/:id/settings',
  validateTenantAccess,
  requireTenantAdmin,
  OrganizationTenantController.updateSettings
);

router.patch('/:id/security',
  validateTenantAccess,
  requireTenantOwner,
  requireAuth({ verify2FA: true }),
  sensitiveOperationLimiter,
  validateSecuritySettings,
  OrganizationTenantController.updateSecuritySettings
);

router.patch('/:id/branding',
  validateTenantAccess,
  requireTenantAdmin,
  OrganizationTenantController.updateBranding
);

/**
 * Data Export
 */
router.get('/:id/export',
  validateTenantAccess,
  requireTenantOwner,
  createRateLimiter({
    windowMs: 24 * 60 * 60 * 1000, // 24 hours
    max: 5, // 5 exports per day
    message: 'Export limit exceeded'
  }),
  OrganizationTenantController.exportTenantData
);

/**
 * Platform Admin Only Routes
 */
router.use('/admin', requirePlatformAdmin);

// Get all tenants (admin view)
router.get('/admin/all',
  OrganizationTenantController.searchTenants
);

// Get tenants requiring attention
router.get('/admin/attention-required',
  async (req, res, next) => {
    req.query.flags = JSON.stringify({ requiresAttention: true });
    next();
  },
  OrganizationTenantController.searchTenants
);

// Get suspended tenants
router.get('/admin/suspended',
  async (req, res, next) => {
    req.query.status = 'suspended';
    next();
  },
  OrganizationTenantController.searchTenants
);

// Get trial tenants expiring soon
router.get('/admin/trials-expiring',
  async (req, res, next) => {
    const threeDaysFromNow = new Date();
    threeDaysFromNow.setDate(threeDaysFromNow.getDate() + 3);
    
    req.query.status = 'trial';
    req.query.trialEndsBefore = threeDaysFromNow.toISOString();
    next();
  },
  OrganizationTenantController.searchTenants
);

/**
 * Error handling middleware
 */
router.use((err, req, res, next) => {
  if (err.name === 'CastError') {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid tenant ID format'
    });
  }
  
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return res.status(400).json({
      status: 'error',
      message: `A tenant with this ${field} already exists`
    });
  }
  
  next(err);
});

/**
 * 404 handler
 */
router.all('*', (req, res) => {
  res.status(404).json({
    status: 'error',
    message: `Organization tenant route ${req.originalUrl} not found`
  });
});

module.exports = router;