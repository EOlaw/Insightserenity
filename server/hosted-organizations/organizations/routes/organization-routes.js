/**
 * @file Hosted Organization Routes
 * @description API routes for hosted organization management with tenant integration
 * @version 3.1.0
 */

const express = require('express');

// Controllers
const HostedOrganizationController = require('../controllers/organization-controller');

// Authentication & Authorization Middleware
const { authenticate, requireAuth } = require('../../../shared/middleware/auth/auth-middleware');
const { 
  restrictTo, 
  checkOrganizationContext,
  requireOrganizationOwner,
  requireOrganizationAdmin,
  requireOrganizationMember
} = require('../../../shared/middleware/auth/authorization-middleware');

// Tenant Middleware
const {
  detectTenantContext,
  requireTenantContext,
  validateTenantAccess,
  checkResourceLimit
} = require('../../../organization-tenants/middleware/tenant-context-middleware');

// Validation Middleware
const {
  validateOrganizationCreate,
  validateOrganizationUpdate,
  validateSubscriptionUpdate,
  validateTeamMember,
  validateDomain,
  validateInvitationAccept
} = require('../../../shared/utils/validation/hosted-organizations/organization-validation');

// API Middleware - Updated Structure
const { 
  parseQueryOptions,
  validateQueryParams 
} = require('../../../shared/middleware/api/query-middleware');

const {
  parsePagination,
  addPaginationHelpers,
  validatePaginationAccess
} = require('../../../shared/middleware/api/pagination-middleware');

const { 
  cacheResponse, 
  clearOrganizationCache 
} = require('../../../shared/middleware/api/cache-middleware');

// Security Middleware - Updated Structure
const {
  organizationLimiter,
  sensitiveOperationLimiter,
  createOrganizationRateLimiter,
  adminBypass
} = require('../../../shared/middleware/security/rate-limiter-middleware');

// Tracking Middleware - Updated Structure
const { 
  trackAnalytics 
} = require('../../../shared/middleware/tracking/analytics-middleware');

const {
  auditLog
} = require('../../../shared/middleware/tracking/audit-middleware');

const { 
  validateSubscription,
  requireActiveSubscription,
  requirePaidSubscription 
} = require('../../../shared/middleware/hosted-organizations/subscription-validation');

const logger = require('../../../shared/utils/logger');

const router = express.Router();

/**
 * Public Routes
 */

// Health check
router.get('/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    service: 'hosted-organizations',
    timestamp: new Date().toISOString()
  });
});

// Accept invitation (can be accessed without full auth if valid token provided)
router.post('/invitations/accept',
  validateInvitationAccept,
  HostedOrganizationController.acceptInvitation
);

/**
 * All routes below require authentication
 */
router.use(authenticate());

/**
 * Organization Management Routes
 */

// List user's organizations (no subscription required - users need to see their options)
router.get('/',
  organizationLimiter,
  parseQueryOptions({ 
    allowedSortFields: ['name', 'createdAt', 'updatedAt', 'type'],
    allowedFilterFields: ['status', 'tier', 'type', 'subscription'],
    defaultSortBy: 'createdAt',
    defaultSortOrder: 'desc'
  }),
  parsePagination({ defaultLimit: 20, maxLimit: 100 }),
  addPaginationHelpers,
  cacheResponse({ ttl: 300 }), // 5 minutes
  HostedOrganizationController.listUserOrganizations
);

// Create new organization (creates tenant infrastructure too)
router.post('/',
  // authenticate(),
  sensitiveOperationLimiter,
  validateOrganizationCreate,
  auditLog('organization.create'),
  HostedOrganizationController.createOrganization
);

// All routes below this point require active subscription
router.use(requireActiveSubscription); // Ensure active subscription for organization operations

// Get current organization (requires tenant context)
router.get('/current',
  requireAuth,
  detectTenantContext,
  requireTenantContext,
  requireOrganizationMember,
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getCurrentOrganization
);

// Get organization by ID
router.get('/:id',
  requireAuth,
  parseQueryOptions(),
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getOrganizationById
);

// Update organization
router.patch('/:id',
  requireAuth,
  requireOrganizationAdmin,
  validateOrganizationUpdate,
  clearOrganizationCache,
  auditLog('organization.update'),
  HostedOrganizationController.updateOrganization
);

// Delete organization (soft delete)
router.delete('/:id',
  requireAuth,
  requireOrganizationOwner,
  sensitiveOperationLimiter,
  auditLog('organization.delete'),
  HostedOrganizationController.deleteOrganization
);

/**
 * Team Management Routes
 */

// Get team members
router.get('/:id/team',
  requireAuth,
  requireOrganizationMember,
  parseQueryOptions({
    allowedSortFields: ['name', 'role', 'joinedAt', 'status'],
    allowedFilterFields: ['role', 'status', 'department', 'permissions'],
    defaultSortBy: 'joinedAt',
    defaultSortOrder: 'desc'
  }),
  parsePagination({ defaultLimit: 50, maxLimit: 200 }),
  validatePaginationAccess(),
  addPaginationHelpers,
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getTeamMembers
);

// Add team member
router.post('/:id/team/members',
  requireAuth,
  requireOrganizationAdmin,
  detectTenantContext,
  checkResourceLimit('users'), // Check tenant resource limits
  createOrganizationRateLimiter({ points: 20, duration: 3600 }),
  validateTeamMember,
  clearOrganizationCache,
  auditLog('organization.team.add'),
  HostedOrganizationController.addTeamMember
);

// Update team member
router.patch('/:id/team/members/:memberId',
  requireAuth,
  requireOrganizationAdmin,
  validateTeamMember,
  clearOrganizationCache,
  auditLog('organization.team.update'),
  HostedOrganizationController.updateTeamMember
);

// Remove team member
router.delete('/:id/team/members/:memberId',
  requireAuth,
  requireOrganizationAdmin,
  clearOrganizationCache,
  auditLog('organization.team.remove'),
  HostedOrganizationController.removeTeamMember
);

// Resend invitation
router.post('/:id/team/invitations/:invitationId/resend',
  requireAuth,
  requireOrganizationAdmin,
  organizationLimiter,
  HostedOrganizationController.resendInvitation
);

// Revoke invitation
router.delete('/:id/team/invitations/:invitationId',
  requireAuth,
  requireOrganizationAdmin,
  clearOrganizationCache,
  HostedOrganizationController.revokeInvitation
);

/**
 * Subscription & Billing Routes
 */

// Get subscription details
router.get('/:id/subscription',
  requireAuth,
  requireOrganizationMember,
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getSubscription
);

// Update subscription
router.put('/:id/subscription',
  requireAuth,
  requireOrganizationOwner,
  sensitiveOperationLimiter,
  validateSubscriptionUpdate,
  clearOrganizationCache,
  auditLog('organization.subscription.update'),
  HostedOrganizationController.updateSubscription
);

// Cancel subscription
router.post('/:id/subscription/cancel',
  requireAuth,
  requireOrganizationOwner,
  sensitiveOperationLimiter,
  auditLog('organization.subscription.cancel'),
  HostedOrganizationController.cancelSubscription
);

// Get billing history
router.get('/:id/billing/history',
  requireAuth,
  requireOrganizationAdmin,
  parseQueryOptions({
    allowedSortFields: ['date', 'amount', 'status', 'type'],
    allowedFilterFields: ['status', 'type', 'paymentMethod'],
    defaultSortBy: 'date',
    defaultSortOrder: 'desc'
  }),
  parsePagination({ defaultLimit: 20, maxLimit: 100 }),
  addPaginationHelpers,
  HostedOrganizationController.getBillingHistory
);

/**
 * Domain Management Routes
 */

// Get domains
router.get('/:id/domains',
  requireAuth,
  requireOrganizationMember,
  parseQueryOptions({
    allowedSortFields: ['domain', 'status', 'createdAt'],
    allowedFilterFields: ['status', 'verified'],
    defaultSortBy: 'createdAt'
  }),
  parsePagination({ defaultLimit: 20, maxLimit: 50 }),
  addPaginationHelpers,
  cacheResponse({ ttl: 600 }), // 10 minutes
  HostedOrganizationController.getDomains
);

// Add custom domain
router.post('/:id/domains',
  requireAuth,
  requireOrganizationAdmin,
  detectTenantContext,
  checkResourceLimit('customDomains'),
  validateDomain,
  clearOrganizationCache,
  auditLog('organization.domain.add'),
  HostedOrganizationController.addDomain
);

// Verify domain
router.post('/:id/domains/verify',
  requireAuth,
  requireOrganizationAdmin,
  validateDomain,
  HostedOrganizationController.verifyDomain
);

// Remove domain
router.delete('/:id/domains/:domainId',
  requireAuth,
  requireOrganizationAdmin,
  clearOrganizationCache,
  auditLog('organization.domain.remove'),
  HostedOrganizationController.removeDomain
);

/**
 * Resource Usage & Analytics Routes
 */

// Get resource usage
router.get('/:id/usage',
  requireAuth,
  requireOrganizationMember,
  detectTenantContext,
  parseQueryOptions({
    allowedFilterFields: ['metric', 'period', 'resourceType'],
    allowedSortFields: ['timestamp', 'value', 'metric'],
    defaultSortBy: 'timestamp',
    defaultSortOrder: 'desc'
  }),
  parsePagination({ defaultLimit: 100, maxLimit: 500 }),
  addPaginationHelpers,
  cacheResponse({ ttl: 60 }), // 1 minute
  HostedOrganizationController.getResourceUsage
);

// Get organization statistics
router.get('/:id/stats',
  requireAuth,
  requireOrganizationMember,
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getOrganizationStats
);

// Get analytics
router.get('/:id/analytics',
  requireAuth,
  requireOrganizationMember,
  parseQueryOptions({
    allowedFilterFields: ['metric', 'dimension', 'period', 'granularity'],
    allowedSortFields: ['timestamp', 'value', 'metric'],
    defaultSortBy: 'timestamp',
    defaultSortOrder: 'desc'
  }),
  parsePagination({ defaultLimit: 1000, maxLimit: 5000 }),
  validatePaginationAccess({
    maxLimitForRole: {
      member: 1000,
      admin: 3000,
      owner: 5000
    }
  }),
  addPaginationHelpers,
  trackAnalytics('organization.analytics.view'),
  HostedOrganizationController.getAnalytics
);

/**
 * Security & Compliance Routes
 */

// Get security settings
router.get('/:id/security',
  requireAuth,
  requireOrganizationAdmin,
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getSecuritySettings
);

// Update security settings
router.put('/:id/security',
  requireAuth,
  requireOrganizationOwner,
  sensitiveOperationLimiter,
  clearOrganizationCache,
  auditLog('organization.security.update'),
  HostedOrganizationController.updateSecuritySettings
);

// Get audit logs
router.get('/:id/audit-logs',
  requireAuth,
  requireOrganizationAdmin,
  parseQueryOptions({
    allowedFilterFields: ['action', 'actor', 'severity', 'category', 'result'],
    allowedSortFields: ['timestamp', 'severity', 'action', 'category'],
    defaultSortBy: 'timestamp',
    defaultSortOrder: 'desc'
  }),
  parsePagination({ defaultLimit: 50, maxLimit: 500 }),
  validatePaginationAccess({
    maxLimitForRole: {
      admin: 500,
      owner: 1000,
      super_admin: 2000
    }
  }),
  addPaginationHelpers,
  HostedOrganizationController.getAuditLogs
);

// Export organization data
router.post('/:id/export',
  requireAuth,
  requireOrganizationOwner,
  sensitiveOperationLimiter,
  auditLog('organization.data.export'),
  HostedOrganizationController.exportOrganizationData
);

/**
 * Integration Routes
 */

// Get integrations
router.get('/:id/integrations',
  requireAuth,
  requireOrganizationMember,
  parseQueryOptions({
    allowedFilterFields: ['status', 'type', 'category'],
    allowedSortFields: ['name', 'status', 'lastSync', 'createdAt'],
    defaultSortBy: 'name'
  }),
  parsePagination({ defaultLimit: 20, maxLimit: 100 }),
  addPaginationHelpers,
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getIntegrations
);

// Configure integration
router.put('/:id/integrations/:integration',
  requireAuth,
  requireOrganizationAdmin,
  clearOrganizationCache,
  auditLog('organization.integration.configure'),
  HostedOrganizationController.configureIntegration
);

// Remove integration
router.delete('/:id/integrations/:integration',
  requireAuth,
  requireOrganizationAdmin,
  clearOrganizationCache,
  auditLog('organization.integration.remove'),
  HostedOrganizationController.removeIntegration
);

/**
 * Preferences & Settings Routes
 */

// Get preferences
router.get('/:id/preferences',
  requireAuth,
  requireOrganizationMember,
  cacheResponse({ ttl: 600 }),
  HostedOrganizationController.getPreferences
);

// Update preferences
router.put('/:id/preferences',
  requireAuth,
  requireOrganizationAdmin,
  clearOrganizationCache,
  HostedOrganizationController.updatePreferences
);

// Get branding
router.get('/:id/branding',
  requireAuth,
  requireOrganizationMember,
  cacheResponse({ ttl: 3600 }), // 1 hour
  HostedOrganizationController.getBranding
);

// Update branding
router.put('/:id/branding',
  requireAuth,
  requireOrganizationAdmin,
  clearOrganizationCache,
  auditLog('organization.branding.update'),
  HostedOrganizationController.updateBranding
);

/**
 * Super Admin Routes
 */

// Get all organizations (platform admin only)
router.get('/admin/all',
  requireAuth,
  restrictTo('super_admin'),
  adminBypass, // Bypass rate limiting for admin users
  parseQueryOptions({
    allowedSortFields: ['name', 'createdAt', 'tier', 'status', 'memberCount'],
    allowedFilterFields: ['status', 'tier', 'type', 'subscription'],
    defaultSortBy: 'createdAt',
    defaultSortOrder: 'desc'
  }),
  parsePagination({ defaultLimit: 50, maxLimit: 500 }),
  validatePaginationAccess({
    maxLimitForRole: {
      super_admin: 1000
    }
  }),
  addPaginationHelpers,
  HostedOrganizationController.getAllOrganizations
);

// Get organization metrics (platform admin only)
router.get('/admin/metrics',
  requireAuth,
  restrictTo('super_admin'),
  adminBypass,
  cacheResponse({ ttl: 300 }),
  HostedOrganizationController.getPlatformMetrics
);

// Suspend organization (platform admin only)
router.post('/:id/suspend',
  requireAuth,
  restrictTo('super_admin'),
  sensitiveOperationLimiter,
  auditLog('organization.suspend'),
  HostedOrganizationController.suspendOrganization
);

// Reactivate organization (platform admin only)
router.post('/:id/reactivate',
  requireAuth,
  restrictTo('super_admin'),
  sensitiveOperationLimiter,
  auditLog('organization.reactivate'),
  HostedOrganizationController.reactivateOrganization
);

/**
 * Error Handler
 */
router.use((err, req, res, next) => {
  logger.error('Organization route error', {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    userId: req.user?._id
  });
  next(err);
});

module.exports = router;