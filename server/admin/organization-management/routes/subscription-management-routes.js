// server/admin/organization-management/routes/subscription-management-routes.js
/**
 * @file Subscription Management Routes
 * @description Routes for managing organization subscriptions and billing
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const SubscriptionManagementController = require('../controllers/subscription-management-controller');

// Middleware
const { requireOrganizationManagementPermission, verifyOrganizationScope, requireElevatedPrivileges, trackOrganizationManagementAction, validateSubscriptionOperation } = require('../middleware/organization-access');
const { adminRateLimiter } = require('../../../shared/admin/middleware/admin-rate-limiting');
const { cacheMiddleware } = require('../../../shared/admin/middleware/admin-cache-middleware');
const { subscriptionValidation } = require('../middleware/subscription-validation');

// Validation
const { middleware: subscriptionValidationMiddleware } = require('../validation/subscription-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * @route   GET /api/admin/subscriptions
 * @desc    List all subscriptions with advanced filtering
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_SUBSCRIPTIONS permission
 */
router.get(
  '/',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_SUBSCRIPTIONS),
  subscriptionValidationMiddleware.validateListSubscriptions,
  cacheMiddleware('subscriptions_list', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_subscriptions_list'),
  adminRateLimiter('subscriptionList'),
  SubscriptionManagementController.listSubscriptions
);

/**
 * @route   GET /api/admin/subscriptions/:subscriptionId
 * @desc    Get subscription details
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_SUBSCRIPTIONS permission
 */
router.get(
  '/:subscriptionId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_SUBSCRIPTIONS),
  validateSubscriptionOperation,
  cacheMiddleware('subscription_detail', 600), // 10 minutes cache
  trackOrganizationManagementAction('view_subscription_detail'),
  adminRateLimiter('subscriptionView'),
  SubscriptionManagementController.getSubscriptionDetail
);

/**
 * @route   POST /api/admin/subscriptions/create
 * @desc    Create new subscription for organization
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.CREATE_SUBSCRIPTION permission
 */
router.post(
  '/create',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.CREATE_SUBSCRIPTION),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  subscriptionValidationMiddleware.validateCreateSubscription,
  trackOrganizationManagementAction('create_subscription'),
  adminRateLimiter('subscriptionCreate'),
  SubscriptionManagementController.createSubscription
);

/**
 * @route   PUT /api/admin/subscriptions/:subscriptionId/plan
 * @desc    Change subscription plan
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.CHANGE_PLAN permission
 */
router.put(
  '/:subscriptionId/plan',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.CHANGE_PLAN),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateSubscriptionOperation,
  subscriptionValidation,
  subscriptionValidationMiddleware.validateChangePlan,
  trackOrganizationManagementAction('change_subscription_plan'),
  adminRateLimiter('planChange'),
  SubscriptionManagementController.changeSubscriptionPlan
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/cancel
 * @desc    Cancel subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.CANCEL_SUBSCRIPTION permission
 */
router.post(
  '/:subscriptionId/cancel',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.CANCEL_SUBSCRIPTION),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateCancelSubscription,
  trackOrganizationManagementAction('cancel_subscription'),
  adminRateLimiter('subscriptionCancel'),
  SubscriptionManagementController.cancelSubscription
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/reactivate
 * @desc    Reactivate cancelled subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.REACTIVATE_SUBSCRIPTION permission
 */
router.post(
  '/:subscriptionId/reactivate',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.REACTIVATE_SUBSCRIPTION),
  requireElevatedPrivileges({ requireMFA: true }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateReactivateSubscription,
  trackOrganizationManagementAction('reactivate_subscription'),
  adminRateLimiter('subscriptionReactivate'),
  SubscriptionManagementController.reactivateSubscription
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/discount
 * @desc    Apply discount to subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.APPLY_DISCOUNT permission
 */
router.post(
  '/:subscriptionId/discount',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.APPLY_DISCOUNT),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateApplyDiscount,
  trackOrganizationManagementAction('apply_discount'),
  adminRateLimiter('discountApply'),
  SubscriptionManagementController.applyDiscount
);

/**
 * @route   DELETE /api/admin/subscriptions/:subscriptionId/discount/:discountId
 * @desc    Remove discount from subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.APPLY_DISCOUNT permission
 */
router.delete(
  '/:subscriptionId/discount/:discountId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.APPLY_DISCOUNT),
  requireElevatedPrivileges({ requireMFA: true }),
  validateSubscriptionOperation,
  trackOrganizationManagementAction('remove_discount'),
  adminRateLimiter('discountRemove'),
  SubscriptionManagementController.removeDiscount
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/credit
 * @desc    Add credit to subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_CREDITS permission
 */
router.post(
  '/:subscriptionId/credit',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_CREDITS),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateAddCredit,
  trackOrganizationManagementAction('add_credit'),
  adminRateLimiter('creditAdd'),
  SubscriptionManagementController.addCredit
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/refund
 * @desc    Process refund for subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.PROCESS_REFUND permission
 */
router.post(
  '/:subscriptionId/refund',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.PROCESS_REFUND),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true,
    requireRecentAuth: true
  }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateProcessRefund,
  trackOrganizationManagementAction('process_refund'),
  adminRateLimiter('refundProcess'),
  SubscriptionManagementController.processRefund
);

/**
 * @route   GET /api/admin/subscriptions/:subscriptionId/invoices
 * @desc    Get subscription invoices
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_BILLING permission
 */
router.get(
  '/:subscriptionId/invoices',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_BILLING),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateGetInvoices,
  cacheMiddleware('subscription_invoices', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_invoices'),
  adminRateLimiter('invoiceView'),
  SubscriptionManagementController.getSubscriptionInvoices
);

/**
 * @route   GET /api/admin/subscriptions/:subscriptionId/payment-history
 * @desc    Get payment history for subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_BILLING permission
 */
router.get(
  '/:subscriptionId/payment-history',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_BILLING),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateGetPaymentHistory,
  cacheMiddleware('payment_history', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_payment_history'),
  adminRateLimiter('paymentHistoryView'),
  SubscriptionManagementController.getPaymentHistory
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/payment-method
 * @desc    Update payment method
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.UPDATE_PAYMENT_METHOD permission
 */
router.post(
  '/:subscriptionId/payment-method',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.UPDATE_PAYMENT_METHOD),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateUpdatePaymentMethod,
  trackOrganizationManagementAction('update_payment_method'),
  adminRateLimiter('paymentMethodUpdate'),
  SubscriptionManagementController.updatePaymentMethod
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/trial-extension
 * @desc    Extend trial period
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.EXTEND_TRIAL permission
 */
router.post(
  '/:subscriptionId/trial-extension',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.EXTEND_TRIAL),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateExtendTrial,
  trackOrganizationManagementAction('extend_trial'),
  adminRateLimiter('trialExtend'),
  SubscriptionManagementController.extendTrial
);

/**
 * @route   GET /api/admin/subscriptions/:subscriptionId/usage
 * @desc    Get subscription usage metrics
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_USAGE permission
 */
router.get(
  '/:subscriptionId/usage',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_USAGE),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateGetUsage,
  cacheMiddleware('subscription_usage', 300), // 5 minutes cache
  trackOrganizationManagementAction('view_subscription_usage'),
  adminRateLimiter('usageView'),
  SubscriptionManagementController.getSubscriptionUsage
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/usage-limits
 * @desc    Set custom usage limits
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.SET_USAGE_LIMITS permission
 */
router.post(
  '/:subscriptionId/usage-limits',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.SET_USAGE_LIMITS),
  requireElevatedPrivileges({ requireMFA: true }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateSetUsageLimits,
  trackOrganizationManagementAction('set_usage_limits'),
  adminRateLimiter('usageLimitUpdate'),
  SubscriptionManagementController.setUsageLimits
);

/**
 * @route   POST /api/admin/subscriptions/:subscriptionId/addon
 * @desc    Add addon to subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_ADDONS permission
 */
router.post(
  '/:subscriptionId/addon',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_ADDONS),
  requireElevatedPrivileges({ requireMFA: true }),
  validateSubscriptionOperation,
  subscriptionValidationMiddleware.validateAddAddon,
  trackOrganizationManagementAction('add_addon'),
  adminRateLimiter('addonAdd'),
  SubscriptionManagementController.addAddon
);

/**
 * @route   DELETE /api/admin/subscriptions/:subscriptionId/addon/:addonId
 * @desc    Remove addon from subscription
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.MANAGE_ADDONS permission
 */
router.delete(
  '/:subscriptionId/addon/:addonId',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_ADDONS),
  requireElevatedPrivileges({ requireMFA: true }),
  validateSubscriptionOperation,
  trackOrganizationManagementAction('remove_addon'),
  adminRateLimiter('addonRemove'),
  SubscriptionManagementController.removeAddon
);

/**
 * @route   GET /api/admin/subscriptions/revenue-analytics
 * @desc    Get revenue analytics across all subscriptions
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.VIEW_REVENUE permission
 */
router.get(
  '/revenue-analytics',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_REVENUE),
  subscriptionValidationMiddleware.validateRevenueAnalytics,
  cacheMiddleware('revenue_analytics', 1800), // 30 minutes cache
  trackOrganizationManagementAction('view_revenue_analytics'),
  adminRateLimiter('analyticsView'),
  SubscriptionManagementController.getRevenueAnalytics
);

/**
 * @route   POST /api/admin/subscriptions/bulk/plan-change
 * @desc    Bulk change subscription plans
 * @access  Admin - Requires ORGANIZATION_MANAGEMENT.BULK_PLAN_CHANGE permission
 */
router.post(
  '/bulk/plan-change',
  requireOrganizationManagementPermission(AdminPermissions.ORGANIZATION_MANAGEMENT.BULK_PLAN_CHANGE),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  subscriptionValidationMiddleware.validateBulkPlanChange,
  trackOrganizationManagementAction('bulk_plan_change'),
  adminRateLimiter('bulkPlanChange'),
  SubscriptionManagementController.bulkChangePlans
);

module.exports = router;