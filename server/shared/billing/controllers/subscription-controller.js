// server/shared/billing/controllers/subscription-controller.js
/**
 * @file Subscription Controller
 * @description Controller for handling subscription-related API endpoints
 * @version 3.0.0
 */

const constants = require('../../config/constants');
const { ValidationError, NotFoundError } = require('../../utils/app-error');
const { asyncHandler } = require('../../utils/async-handler');
const logger = require('../../utils/logger');
const BillingService = require('../services/billing-service');

/**
 * Subscription Controller Class
 * @class SubscriptionController
 */
class SubscriptionController {
  /**
   * Get all available subscription plans
   * @route GET /api/v1/billing/subscription-plans
   */
  static getSubscriptionPlans = asyncHandler(async (req, res) => {
    const { 
      category, 
      targetAudience, 
      userType,
      currency = 'USD' 
    } = req.query;
    
    const filters = {
      category,
      targetAudience,
      userType: userType || req.user?.type,
      currency
    };
    
    const plans = await BillingService.getSubscriptionPlans(filters);
    
    return res.status(200).json({
      status: 'success',
      data: {
        plans,
        count: plans.length
      }
    });
  });
  
  /**
   * Get subscription plan details
   * @route GET /api/v1/billing/subscription-plans/:planId
   */
  static getSubscriptionPlanById = asyncHandler(async (req, res) => {
    const { planId } = req.params;
    
    if (!planId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid plan ID format');
    }
    
    const plan = await BillingService.getSubscriptionPlanById(planId);
    
    return res.status(200).json({
      status: 'success',
      data: { plan }
    });
  });
  
  /**
   * Create new subscription
   * @route POST /api/v1/billing/subscriptions
   */
  static createSubscription = asyncHandler(async (req, res) => {
    const {
      planId,
      billingCycle,
      paymentMethod,
      discountCode,
      referralCode
    } = req.body;
    
    // Validate required fields
    if (!planId || !billingCycle || !paymentMethod) {
      throw new ValidationError('Plan ID, billing cycle, and payment method are required');
    }
    
    // Validate billing cycle
    const validCycles = ['monthly', 'quarterly', 'yearly'];
    if (!validCycles.includes(billingCycle)) {
      throw new ValidationError('Invalid billing cycle');
    }
    
    // Validate payment method
    if (!paymentMethod.type || !['card', 'bank_account', 'paypal'].includes(paymentMethod.type)) {
      throw new ValidationError('Invalid payment method type');
    }
    
    const subscriptionData = {
      userId: req.user._id,
      planId,
      billingCycle,
      paymentMethod,
      discountCode,
      referralCode
    };
    
    const context = {
      userId: req.user._id,
      source: req.headers['x-source'] || 'website',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    };
    
    const result = await BillingService.createSubscription(subscriptionData, context);
    
    return res.status(201).json({
      status: 'success',
      data: {
        subscription: result.subscription,
        invoice: result.invoice,
        payment: result.payment ? {
          id: result.payment._id,
          status: result.payment.status,
          amount: result.payment.amount
        } : null
      },
      message: 'Subscription created successfully'
    });
  });
  
  /**
   * Get user's subscriptions
   * @route GET /api/v1/billing/subscriptions
   */
  static getUserSubscriptions = asyncHandler(async (req, res) => {
    const { includeExpired = false } = req.query;
    
    const subscriptions = await BillingService.getUserSubscriptions(
      req.user._id,
      { includeExpired: includeExpired === 'true' }
    );
    
    return res.status(200).json({
      status: 'success',
      data: {
        subscriptions,
        count: subscriptions.length
      }
    });
  });
  
  /**
   * Get subscription details
   * @route GET /api/v1/billing/subscriptions/:subscriptionId
   */
  static getSubscriptionById = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    const Subscription = require('../models/subscription-model');
    const subscription = await Subscription.findById(subscriptionId)
      .populate('planId')
      .populate('addons.addonId');
    
    if (!subscription) {
      throw new NotFoundError('Subscription not found');
    }
    
    // Check ownership
    if (subscription.userId.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    return res.status(200).json({
      status: 'success',
      data: { subscription }
    });
  });
  
  /**
   * Update subscription (upgrade/downgrade/modify)
   * @route PUT /api/v1/billing/subscriptions/:subscriptionId
   */
  static updateSubscription = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    const { action, data } = req.body;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    const validActions = [
      'upgrade', 
      'downgrade', 
      'change_billing_cycle', 
      'update_payment_method', 
      'add_addon', 
      'remove_addon', 
      'pause', 
      'resume', 
      'cancel'
    ];
    
    if (!action || !validActions.includes(action)) {
      throw new ValidationError('Invalid or missing action');
    }
    
    const context = {
      userId: req.user._id,
      isAdmin: req.user.isAdmin,
      ipAddress: req.ip
    };
    
    const updatedSubscription = await BillingService.updateSubscription(
      subscriptionId,
      { action, data },
      context
    );
    
    return res.status(200).json({
      status: 'success',
      data: { subscription: updatedSubscription },
      message: `Subscription ${action} successful`
    });
  });
  
  /**
   * Cancel subscription
   * @route POST /api/v1/billing/subscriptions/:subscriptionId/cancel
   */
  static cancelSubscription = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    const { 
      immediate = false, 
      reason, 
      feedback,
      wouldRecommend,
      competitor 
    } = req.body;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    if (!reason) {
      throw new ValidationError('Cancellation reason is required');
    }
    
    const context = {
      userId: req.user._id,
      isAdmin: req.user.isAdmin,
      ipAddress: req.ip
    };
    
    const cancelledSubscription = await BillingService.updateSubscription(
      subscriptionId,
      {
        action: 'cancel',
        data: {
          immediate,
          reason,
          feedback,
          wouldRecommend,
          competitor
        }
      },
      context
    );
    
    return res.status(200).json({
      status: 'success',
      data: { subscription: cancelledSubscription },
      message: immediate ? 'Subscription cancelled immediately' : 'Subscription will be cancelled at the end of the current period'
    });
  });
  
  /**
   * Pause subscription
   * @route POST /api/v1/billing/subscriptions/:subscriptionId/pause
   */
  static pauseSubscription = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    const { resumeDate, reason } = req.body;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    const context = {
      userId: req.user._id,
      isAdmin: req.user.isAdmin,
      ipAddress: req.ip
    };
    
    const pausedSubscription = await BillingService.updateSubscription(
      subscriptionId,
      {
        action: 'pause',
        data: { resumeDate, reason }
      },
      context
    );
    
    return res.status(200).json({
      status: 'success',
      data: { subscription: pausedSubscription },
      message: 'Subscription paused successfully'
    });
  });
  
  /**
   * Resume paused subscription
   * @route POST /api/v1/billing/subscriptions/:subscriptionId/resume
   */
  static resumeSubscription = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    const context = {
      userId: req.user._id,
      isAdmin: req.user.isAdmin,
      ipAddress: req.ip
    };
    
    const resumedSubscription = await BillingService.updateSubscription(
      subscriptionId,
      { action: 'resume' },
      context
    );
    
    return res.status(200).json({
      status: 'success',
      data: { subscription: resumedSubscription },
      message: 'Subscription resumed successfully'
    });
  });
  
  /**
   * Get subscription usage
   * @route GET /api/v1/billing/subscriptions/:subscriptionId/usage
   */
  static getSubscriptionUsage = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    const Subscription = require('../models/subscription-model');
    const subscription = await Subscription.findById(subscriptionId)
      .select('usage limits')
      .populate('planId', 'limits');
    
    if (!subscription) {
      throw new NotFoundError('Subscription not found');
    }
    
    // Check ownership
    if (subscription.userId.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    // Calculate usage percentages
    const usageData = {
      users: {
        current: subscription.usage.users.current,
        limit: subscription.usage.users.limit,
        percentage: subscription.getUsagePercentage('users'),
        overage: subscription.usage.users.overage
      },
      storage: {
        current: subscription.usage.storage.current,
        limit: subscription.usage.storage.limit,
        percentage: subscription.getUsagePercentage('storage'),
        overage: subscription.usage.storage.overage
      },
      projects: {
        current: subscription.usage.projects.current,
        limit: subscription.usage.projects.limit,
        percentage: subscription.getUsagePercentage('projects'),
        overage: subscription.usage.projects.overage
      },
      apiCalls: {
        current: subscription.usage.apiCalls.current,
        limit: subscription.usage.apiCalls.limit,
        percentage: subscription.getUsagePercentage('apiCalls'),
        overage: subscription.usage.apiCalls.overage,
        resetDate: subscription.usage.apiCalls.resetDate
      },
      customMetrics: subscription.usage.customMetrics,
      lastUpdated: subscription.usage.lastUpdated
    };
    
    return res.status(200).json({
      status: 'success',
      data: { usage: usageData }
    });
  });
  
  /**
   * Add usage to subscription
   * @route POST /api/v1/billing/subscriptions/:subscriptionId/usage
   */
  static addUsage = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    const { metric, amount } = req.body;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    if (!metric || !amount) {
      throw new ValidationError('Metric and amount are required');
    }
    
    const Subscription = require('../models/subscription-model');
    const subscription = await Subscription.findById(subscriptionId);
    
    if (!subscription) {
      throw new NotFoundError('Subscription not found');
    }
    
    // Check ownership or admin
    if (subscription.userId.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    await subscription.addUsage(metric, amount);
    
    return res.status(200).json({
      status: 'success',
      data: { 
        usage: subscription.usage[metric],
        overageCharges: subscription.calculateOverageCharges()
      },
      message: 'Usage recorded successfully'
    });
  });
  
  /**
   * Preview subscription change
   * @route POST /api/v1/billing/subscriptions/:subscriptionId/preview-change
   */
  static previewSubscriptionChange = asyncHandler(async (req, res) => {
    const { subscriptionId } = req.params;
    const { newPlanId, billingCycle } = req.body;
    
    if (!subscriptionId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid subscription ID format');
    }
    
    if (!newPlanId) {
      throw new ValidationError('New plan ID is required');
    }
    
    const Subscription = require('../models/subscription-model');
    const SubscriptionPlan = require('../models/subscription-plan-model');
    
    const [subscription, newPlan] = await Promise.all([
      Subscription.findById(subscriptionId).populate('planId'),
      SubscriptionPlan.findById(newPlanId)
    ]);
    
    if (!subscription || !newPlan) {
      throw new NotFoundError('Subscription or plan not found');
    }
    
    // Check ownership
    if (subscription.userId.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    // Calculate prorated amount
    const isUpgrade = newPlan.pricing.monthly.amount > subscription.planId.pricing.monthly.amount;
    const proratedAmount = await BillingService.calculateProratedAmount(
      subscription,
      newPlan,
      isUpgrade ? 'upgrade' : 'downgrade'
    );
    
    const preview = {
      currentPlan: {
        name: subscription.planId.name,
        price: subscription.billing.amount.total,
        cycle: subscription.billing.cycle
      },
      newPlan: {
        name: newPlan.name,
        price: newPlan.getPriceForCycle(billingCycle || subscription.billing.cycle).amount,
        cycle: billingCycle || subscription.billing.cycle
      },
      changeType: isUpgrade ? 'upgrade' : 'downgrade',
      proratedAmount,
      effectiveDate: isUpgrade ? new Date() : subscription.dates.currentPeriodEnd,
      features: {
        added: newPlan.features.filter(f => 
          !subscription.planId.features.find(cf => cf.key === f.key)
        ),
        removed: subscription.planId.features.filter(f => 
          !newPlan.features.find(nf => nf.key === f.key)
        )
      }
    };
    
    return res.status(200).json({
      status: 'success',
      data: { preview }
    });
  });
}

module.exports = SubscriptionController;