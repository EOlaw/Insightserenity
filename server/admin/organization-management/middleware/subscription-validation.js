// server/admin/organization-management/middleware/subscription-validation.js
/**
 * @file Subscription Validation Middleware
 * @description Middleware for validating subscription operations and billing constraints
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const moment = require('moment');

// Models
const Subscription = require('../../../shared/billing/models/subscription-model');
const SubscriptionPlan = require('../../../shared/billing/models/subscription-plan-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const Payment = require('../../../shared/billing/models/payment-model');
const Invoice = require('../../../shared/billing/models/invoice-model');

// Services
const CacheService = require('../../../shared/utils/cache-service');
const PermissionService = require('../../../shared/users/services/permission-service');

// Utilities
const { AppError, ValidationError, ForbiddenError, ConflictError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { formatCurrency } = require('../../../shared/utils/billing-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminRoles = require('../../../shared/admin/constants/admin-roles');

// Configuration
const config = require('../../../config');
const constants = require('../../../shared/config/constants');

/**
 * Subscription Validation Middleware Class
 * @class SubscriptionValidationMiddleware
 */
class SubscriptionValidationMiddleware {
  constructor() {
    this.cache = new CacheService();
    this.cachePrefix = 'sub-validation';
    this.cacheTTL = 300; // 5 minutes
    
    // Plan hierarchy for upgrade/downgrade validation
    this.planHierarchy = ['trial', 'starter', 'growth', 'professional', 'enterprise'];
    
    // Billing constraints
    this.billingConstraints = {
      maxRefundAmount: 10000, // $10,000
      maxCreditAmount: 5000, // $5,000
      minSubscriptionAmount: 0, // Free plans allowed
      refundWindowDays: 30,
      maxDiscountPercentage: 100, // Allow 100% discounts
      maxTrialExtensionDays: 30
    };
  }

  /**
   * Validate subscription exists and is active
   * @param {Object} options - Validation options
   * @returns {Function} Middleware function
   */
  validateActiveSubscription(options = {}) {
    return async (req, res, next) => {
      try {
        const organizationId = req.params.organizationId || req.params.id || req.body.organizationId;
        
        if (!organizationId || !mongoose.isValidObjectId(organizationId)) {
          throw new ValidationError('Valid organization ID is required');
        }
        
        // Check cache
        const cacheKey = `${this.cachePrefix}:active:${organizationId}`;
        const cached = await this.cache.get(cacheKey);
        
        if (cached && !options.skipCache) {
          req.subscription = cached;
          return next();
        }
        
        // Get active subscription
        const subscription = await Subscription.findOne({
          organizationId,
          status: { $in: options.allowedStatuses || ['active', 'trialing', 'past_due'] }
        }).populate('planId').lean();
        
        if (!subscription) {
          throw new ConflictError('No active subscription found for this organization');
        }
        
        // Additional status checks
        if (options.requireActive && subscription.status !== 'active') {
          throw new ConflictError(`Subscription must be active. Current status: ${subscription.status}`);
        }
        
        if (options.excludePastDue && subscription.status === 'past_due') {
          throw new ConflictError('Operation not allowed for past due subscriptions');
        }
        
        // Store subscription info
        req.subscription = subscription;
        
        // Cache the subscription
        await this.cache.set(cacheKey, subscription, this.cacheTTL);
        
        next();
      } catch (error) {
        logger.error('Subscription validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Validate plan change operation
   * @param {Object} options - Plan change options
   * @returns {Function} Middleware function
   */
  validatePlanChange(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const { planId, effectiveDate, reason } = req.body;
        const organizationId = req.params.organizationId || req.params.id;
        
        if (!planId) {
          throw new ValidationError('Target plan ID is required');
        }
        
        if (!reason && !options.skipReasonCheck) {
          throw new ValidationError('Reason for plan change is required');
        }
        
        // Get current subscription
        const currentSubscription = await Subscription.findOne({
          organizationId,
          status: { $in: ['active', 'trialing', 'past_due'] }
        }).populate('planId').lean();
        
        if (!currentSubscription) {
          throw new ConflictError('No active subscription found');
        }
        
        // Get target plan
        const targetPlan = await SubscriptionPlan.findById(planId).lean();
        if (!targetPlan || !targetPlan.active) {
          throw new ValidationError('Invalid or inactive target plan');
        }
        
        // Validate plan change
        const validation = await this._validatePlanChange(
          currentSubscription,
          targetPlan,
          adminUser,
          options
        );
        
        if (!validation.allowed) {
          throw new ConflictError(validation.reason);
        }
        
        // Check effective date
        if (effectiveDate) {
          const effectiveMoment = moment(effectiveDate);
          if (effectiveMoment.isBefore(moment().startOf('day'))) {
            throw new ValidationError('Effective date cannot be in the past');
          }
          
          if (effectiveMoment.isAfter(moment().add(90, 'days'))) {
            throw new ValidationError('Effective date cannot be more than 90 days in the future');
          }
        }
        
        // Store validation result
        req.planChangeValidation = {
          currentPlan: currentSubscription.planId,
          targetPlan,
          isUpgrade: validation.isUpgrade,
          isDowngrade: validation.isDowngrade,
          requiresPayment: validation.requiresPayment,
          proration: validation.proration,
          restrictions: validation.restrictions
        };
        
        next();
      } catch (error) {
        logger.error('Plan change validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Validate refund request
   * @param {Object} options - Refund validation options
   * @returns {Function} Middleware function
   */
  validateRefundRequest(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const { paymentId, amount, reason } = req.body;
        const organizationId = req.params.organizationId || req.params.id;
        
        if (!paymentId) {
          throw new ValidationError('Payment ID is required for refund');
        }
        
        if (!amount || amount <= 0) {
          throw new ValidationError('Valid refund amount is required');
        }
        
        if (!reason) {
          throw new ValidationError('Refund reason is required');
        }
        
        // Get payment
        const payment = await Payment.findById(paymentId).lean();
        if (!payment) {
          throw new ValidationError('Payment not found');
        }
        
        if (payment.organizationId.toString() !== organizationId) {
          throw new ForbiddenError('Payment does not belong to this organization');
        }
        
        // Validate refund eligibility
        const validation = await this._validateRefund(payment, amount, adminUser, options);
        
        if (!validation.allowed) {
          throw new ConflictError(validation.reason);
        }
        
        // Check admin permissions for high-value refunds
        if (amount > 1000 && adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
          const hasPermission = await PermissionService.checkPermission(
            adminUser._id,
            AdminPermissions.SUPER_ADMIN.HIGH_VALUE_OPERATIONS
          );
          
          if (!hasPermission) {
            throw new ForbiddenError('High-value refunds require additional permissions');
          }
        }
        
        req.refundValidation = {
          payment,
          amount,
          maxRefundable: validation.maxRefundable,
          isPartial: amount < payment.amount,
          requiresApproval: validation.requiresApproval
        };
        
        next();
      } catch (error) {
        logger.error('Refund validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Validate discount application
   * @param {Object} options - Discount validation options
   * @returns {Function} Middleware function
   */
  validateDiscountApplication(options = {}) {
    return async (req, res, next) => {
      try {
        const { type, value, duration, description } = req.body;
        const organizationId = req.params.organizationId || req.params.id;
        
        // Validate discount type
        const validTypes = ['percentage', 'fixed', 'trial_extension'];
        if (!validTypes.includes(type)) {
          throw new ValidationError(`Invalid discount type. Must be one of: ${validTypes.join(', ')}`);
        }
        
        // Validate discount value
        if (type === 'percentage') {
          if (value < 0 || value > this.billingConstraints.maxDiscountPercentage) {
            throw new ValidationError(`Percentage discount must be between 0 and ${this.billingConstraints.maxDiscountPercentage}`);
          }
        } else if (type === 'fixed') {
          if (value <= 0) {
            throw new ValidationError('Fixed discount amount must be positive');
          }
        }
        
        // Validate duration
        const validDurations = ['once', 'repeating', 'forever'];
        if (!validDurations.includes(duration)) {
          throw new ValidationError(`Invalid duration. Must be one of: ${validDurations.join(', ')}`);
        }
        
        if (duration === 'repeating' && !req.body.durationInMonths) {
          throw new ValidationError('Duration in months is required for repeating discounts');
        }
        
        // Check existing discounts
        const subscription = await Subscription.findOne({
          organizationId,
          status: { $in: ['active', 'trialing'] }
        }).lean();
        
        if (!subscription) {
          throw new ConflictError('No active subscription found');
        }
        
        // Check for conflicting discounts
        const activeDiscounts = (subscription.discounts || []).filter(d => 
          !d.endsAt || moment(d.endsAt).isAfter(moment())
        );
        
        if (activeDiscounts.length > 0 && !options.allowMultiple) {
          throw new ConflictError('Organization already has active discounts');
        }
        
        req.discountValidation = {
          subscription,
          existingDiscounts: activeDiscounts,
          newDiscount: { type, value, duration, description }
        };
        
        next();
      } catch (error) {
        logger.error('Discount validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Validate credit application
   * @param {Object} options - Credit validation options
   * @returns {Function} Middleware function
   */
  validateCreditApplication(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const { amount, reason, expiresAt } = req.body;
        
        if (!amount || amount <= 0) {
          throw new ValidationError('Credit amount must be positive');
        }
        
        if (amount > this.billingConstraints.maxCreditAmount) {
          // Check for override permission
          const hasOverride = await PermissionService.checkPermission(
            adminUser._id,
            AdminPermissions.SUPER_ADMIN.BILLING_OVERRIDES
          );
          
          if (!hasOverride) {
            throw new ValidationError(`Credit amount exceeds maximum allowed: ${formatCurrency(this.billingConstraints.maxCreditAmount)}`);
          }
        }
        
        if (!reason) {
          throw new ValidationError('Reason for credit is required');
        }
        
        if (expiresAt) {
          const expiryMoment = moment(expiresAt);
          if (expiryMoment.isBefore(moment())) {
            throw new ValidationError('Credit expiry date cannot be in the past');
          }
          
          if (expiryMoment.isAfter(moment().add(1, 'year'))) {
            throw new ValidationError('Credit expiry date cannot be more than 1 year in the future');
          }
        }
        
        req.creditValidation = {
          amount,
          reason,
          expiresAt,
          requiresApproval: amount > 1000
        };
        
        next();
      } catch (error) {
        logger.error('Credit validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Validate billing override
   * @param {Object} options - Override validation options
   * @returns {Function} Middleware function
   */
  validateBillingOverride(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const overrideData = req.body;
        
        // Only super admins can apply billing overrides
        if (adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
          const hasPermission = await PermissionService.checkPermission(
            adminUser._id,
            AdminPermissions.SUPER_ADMIN.BILLING_OVERRIDES
          );
          
          if (!hasPermission) {
            throw new ForbiddenError('Billing overrides require super admin permissions');
          }
        }
        
        // Validate override data
        if (overrideData.customPricing) {
          if (overrideData.customPricing.amount < 0) {
            throw new ValidationError('Custom pricing amount cannot be negative');
          }
        }
        
        if (overrideData.paymentTerms) {
          const validTerms = ['immediate', 'net15', 'net30', 'net60', 'custom'];
          if (!validTerms.includes(overrideData.paymentTerms)) {
            throw new ValidationError(`Invalid payment terms. Must be one of: ${validTerms.join(', ')}`);
          }
        }
        
        if (overrideData.exemptions) {
          const validExemptions = ['late_fees', 'setup_fees', 'overage_charges', 'taxes'];
          const invalidExemptions = overrideData.exemptions.filter(e => !validExemptions.includes(e));
          
          if (invalidExemptions.length > 0) {
            throw new ValidationError(`Invalid exemptions: ${invalidExemptions.join(', ')}`);
          }
        }
        
        req.billingOverrideValidation = {
          overrideData,
          requiresDocumentation: true,
          auditLevel: 'high'
        };
        
        next();
      } catch (error) {
        logger.error('Billing override validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Validate subscription cancellation
   * @param {Object} options - Cancellation validation options
   * @returns {Function} Middleware function
   */
  validateSubscriptionCancellation(options = {}) {
    return async (req, res, next) => {
      try {
        const { immediate, reason, feedback } = req.body;
        const organizationId = req.params.organizationId || req.params.id;
        
        if (!reason) {
          throw new ValidationError('Cancellation reason is required');
        }
        
        // Get subscription
        const subscription = await Subscription.findOne({
          organizationId,
          status: { $in: ['active', 'trialing', 'past_due'] }
        }).populate('planId').lean();
        
        if (!subscription) {
          throw new ConflictError('No active subscription to cancel');
        }
        
        // Check for outstanding balance
        const outstandingBalance = await this._getOutstandingBalance(organizationId);
        if (outstandingBalance > 0 && !options.allowWithBalance) {
          throw new ConflictError(`Cannot cancel subscription with outstanding balance: ${formatCurrency(outstandingBalance)}`);
        }
        
        // Check for active commitments
        if (subscription.commitment && subscription.commitment.endDate) {
          const commitmentEnd = moment(subscription.commitment.endDate);
          if (commitmentEnd.isAfter(moment())) {
            throw new ConflictError(`Subscription has active commitment until ${commitmentEnd.format('YYYY-MM-DD')}`);
          }
        }
        
        // Calculate refund if immediate cancellation
        let refundAmount = 0;
        if (immediate && subscription.billing.cycle !== 'trial') {
          refundAmount = await this._calculateCancellationRefund(subscription);
        }
        
        req.cancellationValidation = {
          subscription,
          immediate,
          refundAmount,
          hasOutstandingBalance: outstandingBalance > 0,
          outstandingBalance
        };
        
        next();
      } catch (error) {
        logger.error('Cancellation validation failed:', error);
        next(error);
      }
    };
  }

  /**
   * Check subscription limits
   * @param {Object} options - Limit check options
   * @returns {Function} Middleware function
   */
  checkSubscriptionLimits(options = {}) {
    return async (req, res, next) => {
      try {
        const organizationId = req.params.organizationId || req.params.id;
        const operation = options.operation || req.body.operation;
        
        // Get subscription with plan details
        const subscription = await Subscription.findOne({
          organizationId,
          status: { $in: ['active', 'trialing'] }
        }).populate('planId').lean();
        
        if (!subscription) {
          throw new ConflictError('No active subscription found');
        }
        
        const plan = subscription.planId;
        if (!plan) {
          throw new AppError('Subscription plan not found', 500);
        }
        
        // Check specific limits based on operation
        const limitCheck = await this._checkOperationLimits(
          subscription,
          plan,
          operation,
          req.body
        );
        
        if (!limitCheck.allowed) {
          throw new ConflictError(limitCheck.reason);
        }
        
        req.subscriptionLimits = {
          plan: plan.name,
          limits: plan.limits,
          usage: limitCheck.currentUsage,
          remaining: limitCheck.remaining
        };
        
        next();
      } catch (error) {
        logger.error('Subscription limit check failed:', error);
        next(error);
      }
    };
  }

  // Private helper methods

  async _validatePlanChange(currentSubscription, targetPlan, adminUser, options) {
    const currentPlanIndex = this.planHierarchy.indexOf(currentSubscription.planId.slug);
    const targetPlanIndex = this.planHierarchy.indexOf(targetPlan.slug);
    
    const isUpgrade = targetPlanIndex > currentPlanIndex;
    const isDowngrade = targetPlanIndex < currentPlanIndex;
    
    // Check if downgrade is allowed
    if (isDowngrade && !options.allowDowngrade) {
      // Check admin permission for downgrades
      const hasDowngradePermission = await PermissionService.checkPermission(
        adminUser._id,
        AdminPermissions.ORGANIZATION_MANAGEMENT.FORCE_DOWNGRADE
      );
      
      if (!hasDowngradePermission) {
        return {
          allowed: false,
          reason: 'Downgrades require special permission'
        };
      }
    }
    
    // Check for active commitment
    if (currentSubscription.commitment && currentSubscription.commitment.endDate) {
      const commitmentEnd = moment(currentSubscription.commitment.endDate);
      if (commitmentEnd.isAfter(moment()) && isDowngrade) {
        return {
          allowed: false,
          reason: `Cannot downgrade during active commitment period (ends ${commitmentEnd.format('YYYY-MM-DD')})`
        };
      }
    }
    
    // Calculate proration
    const proration = await this._calculateProration(currentSubscription, targetPlan);
    
    return {
      allowed: true,
      isUpgrade,
      isDowngrade,
      requiresPayment: proration.amountDue > 0,
      proration,
      restrictions: []
    };
  }

  async _validateRefund(payment, refundAmount, adminUser, options) {
    // Check if payment is refundable
    if (payment.status !== 'succeeded') {
      return {
        allowed: false,
        reason: 'Only successful payments can be refunded'
      };
    }
    
    // Check refund window
    const paymentAge = moment().diff(payment.createdAt, 'days');
    if (paymentAge > this.billingConstraints.refundWindowDays && !options.overrideWindow) {
      return {
        allowed: false,
        reason: `Refund window of ${this.billingConstraints.refundWindowDays} days has passed`
      };
    }
    
    // Check already refunded amount
    const alreadyRefunded = payment.amountRefunded || 0;
    const maxRefundable = payment.amount - alreadyRefunded;
    
    if (refundAmount > maxRefundable) {
      return {
        allowed: false,
        reason: `Maximum refundable amount is ${formatCurrency(maxRefundable)}`
      };
    }
    
    // Check total refund limit
    if (refundAmount > this.billingConstraints.maxRefundAmount) {
      return {
        allowed: false,
        reason: `Refund amount exceeds maximum limit of ${formatCurrency(this.billingConstraints.maxRefundAmount)}`
      };
    }
    
    return {
      allowed: true,
      maxRefundable,
      requiresApproval: refundAmount > 500 || paymentAge > 14
    };
  }

  async _getOutstandingBalance(organizationId) {
    const unpaidInvoices = await Invoice.find({
      organizationId,
      status: { $in: ['open', 'past_due'] }
    }).lean();
    
    return unpaidInvoices.reduce((total, invoice) => {
      const paid = invoice.amountPaid || 0;
      const due = invoice.total - paid;
      return total + due;
    }, 0);
  }

  async _calculateCancellationRefund(subscription) {
    if (subscription.billing.cycle === 'monthly') {
      // Calculate days remaining in period
      const periodEnd = moment(subscription.currentPeriodEnd);
      const today = moment();
      const daysRemaining = periodEnd.diff(today, 'days');
      const totalDays = moment(subscription.currentPeriodEnd).diff(subscription.currentPeriodStart, 'days');
      
      const dailyRate = subscription.billing.amount.total / totalDays;
      return Math.max(0, dailyRate * daysRemaining);
    }
    
    // For annual subscriptions, calculate monthly
    if (subscription.billing.cycle === 'yearly') {
      const periodEnd = moment(subscription.currentPeriodEnd);
      const today = moment();
      const monthsRemaining = periodEnd.diff(today, 'months');
      
      const monthlyRate = subscription.billing.amount.total / 12;
      return Math.max(0, monthlyRate * monthsRemaining);
    }
    
    return 0;
  }

  async _calculateProration(currentSubscription, targetPlan) {
    const now = moment();
    const periodEnd = moment(currentSubscription.currentPeriodEnd);
    const daysRemaining = periodEnd.diff(now, 'days');
    const totalDays = moment(currentSubscription.currentPeriodEnd).diff(currentSubscription.currentPeriodStart, 'days');
    
    // Current plan credit
    const currentDailyRate = currentSubscription.billing.amount.total / totalDays;
    const unusedCredit = currentDailyRate * daysRemaining;
    
    // New plan cost
    const newPlanAmount = targetPlan.pricing[currentSubscription.billing.cycle] || targetPlan.pricing.monthly;
    const newDailyRate = newPlanAmount / totalDays;
    const newPlanCost = newDailyRate * daysRemaining;
    
    return {
      unusedCredit,
      newPlanCost,
      amountDue: Math.max(0, newPlanCost - unusedCredit),
      creditBalance: Math.max(0, unusedCredit - newPlanCost)
    };
  }

  async _checkOperationLimits(subscription, plan, operation, data) {
    // This would check various limits based on the operation
    // For example: user limits, storage limits, API calls, etc.
    
    const limits = plan.limits || {};
    const usage = subscription.usage || {};
    
    // Example limit checks
    if (operation === 'add_users') {
      const currentUsers = usage.users || 0;
      const maxUsers = limits.users || Infinity;
      const requestedUsers = data.count || 1;
      
      if (currentUsers + requestedUsers > maxUsers) {
        return {
          allowed: false,
          reason: `Adding ${requestedUsers} users would exceed plan limit of ${maxUsers} users`
        };
      }
    }
    
    return {
      allowed: true,
      currentUsage: usage,
      remaining: {
        users: (limits.users || Infinity) - (usage.users || 0),
        storage: (limits.storageGB || Infinity) - (usage.storageGB || 0),
        apiCalls: (limits.apiCallsPerMonth || Infinity) - (usage.apiCalls || 0)
      }
    };
  }
}

module.exports = new SubscriptionValidationMiddleware();