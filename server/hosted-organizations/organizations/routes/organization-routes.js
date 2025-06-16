/**
 * @file Hosted Organization Routes
 * @description API routes for hosted organization management
 * @version 2.0.0
 */

const express = require('express');


// Shared Middleware
const { authenticate, requireAuth } = require('../../../shared/auth/middleware/auth-middleware');
const { 
  restrictTo, 
  checkOrganizationContext,
  requireOrganizationOwner,
  requireOrganizationAdmin
} = require('../../../shared/auth/middleware/authorization-middleware');
const HostedOrganizationController = require('../controllers/organization-controller');

// // Validation Middleware
// const {
//   validateOrganizationCreate,
//   validateOrganizationUpdate,
//   validateSubscriptionUpdate,
//   validateTeamMember,
//   validateDomain,
//   validateSecuritySettings
// } = require('../validation/organizationValidation');

// // Rate Limiting
// const {
//   createRateLimiter,
//   organizationLimiter,
//   sensitiveOperationLimiter
// } = require('../../../shared/security/middleware/rateLimiter');

// // Other Middleware
// const { 
//   parseQueryOptions,
//   handlePagination 
// } = require('../../../shared/utils/middleware/queryMiddleware');
// const { 
//   cacheResponse, 
//   clearOrganizationCache 
// } = require('../../../shared/utils/middleware/cacheMiddleware');
// const { 
//   trackAnalytics 
// } = require('../../../shared/analytics/middleware/analyticsMiddleware');
// const { 
//   detectOrganization 
// } = require('../middleware/organizationDetection');

const router = express.Router();

/**
 * Public Health Check
 */
router.get('/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    service: 'hosted-organizations',
    timestamp: new Date().toISOString()
  });
});

/**
 * All routes below require authentication
 */
router.use(authenticate);

/**
 * Organization Detection for Multi-tenant Context
 * Applied to routes that need organization context
 */
// router.use([
//   '/current',
//   '/:id/team',
//   '/:id/analytics',
//   '/:id/usage',
//   '/:id/settings',
//   '/:id/security',
//   '/:id/branding',
//   '/:id/domains'
// ], detectOrganization);

/**
 * Current Organization (Multi-tenant context)
 */
router.route('/current')
  .get(
    // checkOrganizationContext,
    // cacheResponse(300), // 5 minutes
    HostedOrganizationController.getCurrentOrganization
  );

/**
 * Search Organizations
 */
router.route('/search')
  .get(
    // restrictTo('admin', 'super_admin', 'partner', 'consultant'),
    // parseQueryOptions,
    // cacheResponse(600), // 10 minutes
    HostedOrganizationController.searchOrganizations
  );

/**
 * Main Organization CRUD
 */
router.route('/')
  .post(
    // organizationLimiter,
    // validateOrganizationCreate,
    // trackAnalytics('organization:create'),
    HostedOrganizationController.createOrganization
  );

router.route('/:id')
  .get(
    // parseQueryOptions,
    // cacheResponse(300), // 5 minutes
    HostedOrganizationController.getOrganizationById
  )
  .patch(
    // checkOrganizationContext,
    // requireOrganizationAdmin,
    // validateOrganizationUpdate,
    // clearOrganizationCache,
    // trackAnalytics('organization:update'),
    HostedOrganizationController.updateOrganization
  );

/**
 * Subscription Management
 */
router.route('/:id/subscription')
  .post(
    // checkOrganizationContext,
    // requireOrganizationOwner,
    // sensitiveOperationLimiter,
    // validateSubscriptionUpdate,
    // clearOrganizationCache,
    // trackAnalytics('subscription:update'),
    HostedOrganizationController.updateSubscription
  )
  .delete(
    // checkOrganizationContext,
    // requireOrganizationOwner,
    // sensitiveOperationLimiter,
    // trackAnalytics('subscription:cancel'),
    HostedOrganizationController.cancelSubscription
  );

/**
 * Team Management
 */
router.route('/:id/team/members')
  .get(
    // checkOrganizationContext,
    // cacheResponse(300), // 5 minutes
    HostedOrganizationController.getTeamMembers
  )
  .post(
    // checkOrganizationContext,
    // requireOrganizationAdmin,
    // validateTeamMember,
    // clearOrganizationCache,
    // trackAnalytics('team:member:add'),
    HostedOrganizationController.addTeamMember
  );

router.route('/:id/team/members/:userId')
  .delete(
    // checkOrganizationContext,
    // requireOrganizationAdmin,
    // clearOrganizationCache,
    // trackAnalytics('team:member:remove'),
    HostedOrganizationController.removeTeamMember
  );

/**
 * Branding & Customization
 */
router.route('/:id/branding')
  .patch(
    // checkOrganizationContext,
    // requireOrganizationAdmin,
    // clearOrganizationCache,
    // trackAnalytics('branding:update'),
    HostedOrganizationController.updateBranding
  );

/**
 * Domain Management
 */
router.route('/:id/domains')
  .post(
    // checkOrganizationContext,
    // requireOrganizationOwner,
    // sensitiveOperationLimiter,
    // validateDomain,
    // clearOrganizationCache,
    // trackAnalytics('domain:add'),
    HostedOrganizationController.addCustomDomain
  );

router.route('/:id/domains/:domain/verify')
  .post(
    // checkOrganizationContext,
    // requireOrganizationOwner,
    // trackAnalytics('domain:verify'),
    HostedOrganizationController.verifyCustomDomain
  );

/**
 * Analytics & Usage
 */
router.route('/:id/analytics')
  .get(
    // checkOrganizationContext,
    // parseQueryOptions,
    // cacheResponse(3600), // 1 hour
    HostedOrganizationController.getOrganizationAnalytics
  );

router.route('/:id/usage')
  .get(
    // checkOrganizationContext,
    // cacheResponse(600), // 10 minutes
    HostedOrganizationController.getOrganizationUsage
  );

/**
 * Settings
 */
router.route('/:id/settings')
  .patch(
    // checkOrganizationContext,
    // requireOrganizationAdmin,
    // clearOrganizationCache,
    // trackAnalytics('settings:update'),
    HostedOrganizationController.updateSettings
  );

/**
 * Security Settings
 */
router.route('/:id/security')
  .patch(
    // checkOrganizationContext,
    // requireOrganizationOwner,
    // requireAuth({ verify2FA: true }), // Require 2FA for security changes
    // sensitiveOperationLimiter,
    // validateSecuritySettings,
    // clearOrganizationCache,
    // trackAnalytics('security:update'),
    HostedOrganizationController.updateSecuritySettings
  );

/**
 * Admin Routes
 * Restricted to platform administrators
 */
// router.use('/admin', 
//   // restrictTo('admin', 'super_admin')
// );

router.route('/admin/all')
  .get(
    // parseQueryOptions,
    // handlePagination,
    // cacheResponse(300), // 5 minutes
    HostedOrganizationController.adminGetAllOrganizations
  );

router.route('/admin/at-risk')
  .get(
    // cacheResponse(600), // 10 minutes
    HostedOrganizationController.adminGetOrganizationsAtRisk
  );

router.route('/:id/admin/lock')
  .post(
    // trackAnalytics('admin:organization:lock'),
    HostedOrganizationController.adminLockOrganization
  );

router.route('/:id/admin/unlock')
  .post(
    // trackAnalytics('admin:organization:unlock'),
    HostedOrganizationController.adminUnlockOrganization
  );

router.route('/:id/admin/feature')
  .post(
    // trackAnalytics('admin:organization:feature'),
    HostedOrganizationController.adminFeatureOrganization
  );

/**
 * System Routes
 * Restricted to super administrators
 */
// router.use('/system', 
//   // restrictTo('super_admin')
// );

router.route('/system/reset-usage')
  .post(
    // sensitiveOperationLimiter,
    // trackAnalytics('system:usage:reset'),
    HostedOrganizationController.systemResetMonthlyUsage
  );


/**
 * Error handling middleware
 */
router.use((err, req, res, next) => {
  if (err.name === 'CastError') {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid organization ID format'
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
    message: `Organization route ${req.originalUrl} not found`
  });
});

module.exports = router;