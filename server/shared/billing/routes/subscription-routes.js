// server/shared/billing/routes/subscription-routes.js
/**
 * @file Subscription Routes
 * @description API routes for subscription management
 * @version 3.0.0
 */

const express = require('express');
const router = express.Router();
const SubscriptionController = require('../controllers/subscription-controller');
const { authenticate } = require('../../auth/middleware/authenticate');
const { authorize } = require('../../auth/middleware/authorize');
const { validate } = require('../../utils/validation/validator');
const { body, param, query } = require('express-validator');
const rateLimit = require('../../auth/middleware/rate-limit');
const constants = require('../../config/constants');

/**
 * Validation rules
 */
const validationRules = {
  createSubscription: [
    body('planId')
      .notEmpty().withMessage('Plan ID is required')
      .isMongoId().withMessage('Invalid plan ID format'),
    body('billingCycle')
      .notEmpty().withMessage('Billing cycle is required')
      .isIn(['monthly', 'quarterly', 'yearly']).withMessage('Invalid billing cycle'),
    body('paymentMethod.type')
      .notEmpty().withMessage('Payment method type is required')
      .isIn(['card', 'bank_account', 'paypal']).withMessage('Invalid payment method type'),
    body('discountCode')
      .optional()
      .isString().withMessage('Discount code must be a string')
      .trim(),
    body('referralCode')
      .optional()
      .isString().withMessage('Referral code must be a string')
      .trim()
  ],
  
  updateSubscription: [
    param('subscriptionId')
      .isMongoId().withMessage('Invalid subscription ID format'),
    body('action')
      .notEmpty().withMessage('Action is required')
      .isIn([
        'upgrade', 'downgrade', 'change_billing_cycle', 
        'update_payment_method', 'add_addon', 'remove_addon', 
        'pause', 'resume', 'cancel'
      ]).withMessage('Invalid action'),
    body('data')
      .optional()
      .isObject().withMessage('Data must be an object')
  ],
  
  cancelSubscription: [
    param('subscriptionId')
      .isMongoId().withMessage('Invalid subscription ID format'),
    body('reason')
      .notEmpty().withMessage('Cancellation reason is required')
      .isIn([
        'too_expensive', 'missing_features', 'not_using', 
        'switching_competitor', 'technical_issues', 
        'customer_service', 'other'
      ]).withMessage('Invalid cancellation reason'),
    body('feedback')
      .optional()
      .isString().withMessage('Feedback must be a string')
      .isLength({ max: 1000 }).withMessage('Feedback must not exceed 1000 characters'),
    body('immediate')
      .optional()
      .isBoolean().withMessage('Immediate must be a boolean'),
    body('wouldRecommend')
      .optional()
      .isInt({ min: 1, max: 10 }).withMessage('Would recommend must be between 1 and 10')
  ],
  
  pauseSubscription: [
    param('subscriptionId')
      .isMongoId().withMessage('Invalid subscription ID format'),
    body('resumeDate')
      .optional()
      .isISO8601().withMessage('Invalid resume date format')
      .custom(value => new Date(value) > new Date()).withMessage('Resume date must be in the future'),
    body('reason')
      .optional()
      .isString().withMessage('Reason must be a string')
      .isLength({ max: 500 }).withMessage('Reason must not exceed 500 characters')
  ],
  
  addUsage: [
    param('subscriptionId')
      .isMongoId().withMessage('Invalid subscription ID format'),
    body('metric')
      .notEmpty().withMessage('Metric is required')
      .isIn(['users', 'storage', 'projects', 'apiCalls']).withMessage('Invalid metric'),
    body('amount')
      .notEmpty().withMessage('Amount is required')
      .isNumeric().withMessage('Amount must be numeric')
      .custom(value => value > 0).withMessage('Amount must be positive')
  ],
  
  previewChange: [
    param('subscriptionId')
      .isMongoId().withMessage('Invalid subscription ID format'),
    body('newPlanId')
      .notEmpty().withMessage('New plan ID is required')
      .isMongoId().withMessage('Invalid plan ID format'),
    body('billingCycle')
      .optional()
      .isIn(['monthly', 'quarterly', 'yearly']).withMessage('Invalid billing cycle')
  ]
};

/**
 * Rate limiting configurations
 */
const rateLimits = {
  read: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests, please try again later'
  }),
  
  write: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    message: 'Too many subscription modifications, please try again later'
  }),
  
  create: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: 'Too many subscription creation attempts, please try again later'
  })
};

/**
 * Routes
 */

// Get subscription plans (public route with higher rate limit)
router.get(
  '/subscription-plans',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200
  }),
  validate([
    query('category')
      .optional()
      .isIn(['individual', 'team', 'organization']).withMessage('Invalid category'),
    query('targetAudience')
      .optional()
      .isIn(['consultants', 'organizations', 'job_seekers', 'recruiters', 'all'])
      .withMessage('Invalid target audience'),
    query('currency')
      .optional()
      .isIn(['USD', 'EUR', 'GBP', 'CAD', 'AUD']).withMessage('Invalid currency')
  ]),
  SubscriptionController.getSubscriptionPlans
);

// Get specific subscription plan
router.get(
  '/subscription-plans/:planId',
  rateLimits.read,
  validate([
    param('planId').isMongoId().withMessage('Invalid plan ID format')
  ]),
  SubscriptionController.getSubscriptionPlanById
);

// Authenticated routes
router.use(authenticate);

// Get user's subscriptions
router.get(
  '/subscriptions',
  rateLimits.read,
  validate([
    query('includeExpired')
      .optional()
      .isBoolean().withMessage('Include expired must be boolean')
  ]),
  SubscriptionController.getUserSubscriptions
);

// Create new subscription
router.post(
  '/subscriptions',
  rateLimits.create,
  validate(validationRules.createSubscription),
  SubscriptionController.createSubscription
);

// Get subscription details
router.get(
  '/subscriptions/:subscriptionId',
  rateLimits.read,
  validate([
    param('subscriptionId').isMongoId().withMessage('Invalid subscription ID format')
  ]),
  SubscriptionController.getSubscriptionById
);

// Update subscription
router.put(
  '/subscriptions/:subscriptionId',
  rateLimits.write,
  validate(validationRules.updateSubscription),
  SubscriptionController.updateSubscription
);

// Cancel subscription
router.post(
  '/subscriptions/:subscriptionId/cancel',
  rateLimits.write,
  validate(validationRules.cancelSubscription),
  SubscriptionController.cancelSubscription
);

// Pause subscription
router.post(
  '/subscriptions/:subscriptionId/pause',
  rateLimits.write,
  validate(validationRules.pauseSubscription),
  SubscriptionController.pauseSubscription
);

// Resume subscription
router.post(
  '/subscriptions/:subscriptionId/resume',
  rateLimits.write,
  validate([
    param('subscriptionId').isMongoId().withMessage('Invalid subscription ID format')
  ]),
  SubscriptionController.resumeSubscription
);

// Get subscription usage
router.get(
  '/subscriptions/:subscriptionId/usage',
  rateLimits.read,
  validate([
    param('subscriptionId').isMongoId().withMessage('Invalid subscription ID format')
  ]),
  SubscriptionController.getSubscriptionUsage
);

// Add usage to subscription
router.post(
  '/subscriptions/:subscriptionId/usage',
  rateLimits.write,
  validate(validationRules.addUsage),
  SubscriptionController.addUsage
);

// Preview subscription change
router.post(
  '/subscriptions/:subscriptionId/preview-change',
  rateLimits.read,
  validate(validationRules.previewChange),
  SubscriptionController.previewSubscriptionChange
);

// Admin routes
router.get(
  '/subscriptions/admin/expiring',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.read,
  validate([
    query('days')
      .optional()
      .isInt({ min: 1, max: 90 }).withMessage('Days must be between 1 and 90')
  ]),
  asyncHandler(async (req, res) => {
    const Subscription = require('../models/subscription-model');
    const subscriptions = await Subscription.getExpiringSoon(req.query.days || 7);
    
    res.status(200).json({
      status: 'success',
      data: { subscriptions, count: subscriptions.length }
    });
  })
);

router.get(
  '/subscriptions/admin/statistics',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.read,
  validate([
    query('startDate').optional().isISO8601().withMessage('Invalid start date'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date')
  ]),
  asyncHandler(async (req, res) => {
    const BillingService = require('../services/billing-service');
    const stats = await BillingService.getSubscriptionStatistics(req.query);
    
    res.status(200).json({
      status: 'success',
      data: { statistics: stats }
    });
  })
);

// Process recurring subscriptions (cron job endpoint)
router.post(
  '/subscriptions/admin/process-recurring',
  authorize(['super_admin', 'platform_admin']),
  rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 2 // Only allow 2 calls per hour
  }),
  asyncHandler(async (req, res) => {
    const BillingService = require('../services/billing-service');
    const results = await BillingService.processRecurringSubscriptions();
    
    res.status(200).json({
      status: 'success',
      data: results,
      message: 'Recurring subscriptions processed'
    });
  })
);

// Export router
module.exports = router;