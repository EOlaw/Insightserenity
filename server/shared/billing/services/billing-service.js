// server/shared/billing/services/billing-service.js
/**
 * @file Billing Service
 * @description Comprehensive billing service handling all billing operations
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const SubscriptionPlan = require('../models/subscription-plan-model');
const Subscription = require('../models/subscription-model');
const Invoice = require('../models/invoice-model');
const Payment = require('../models/payment-model');
const User = require('../../users/models/user-model');
const logger = require('../../utils/logger');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  PaymentError 
} = require('../../utils/app-error');
const EmailService = require('../../notifications/services/email-service');
const PaymentGatewayService = require('./payment-gateway-service');
const TaxService = require('./tax-service');
const AuditService = require('../../security/services/audit-service');
const CacheService = require('../../utils/cache-service');
const config = require('../../config');

/**
 * Billing Service Class
 * @class BillingService
 */
class BillingService {
  /**
   * Get all subscription plans
   * @param {Object} filters - Filter options
   * @returns {Promise<Array>} Subscription plans
   */
  static async getSubscriptionPlans(filters = {}) {
    try {
      const cacheKey = `plans:${JSON.stringify(filters)}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached) {
        return cached;
      }
      
      const plans = await SubscriptionPlan.getActivePlans(filters);
      
      // Cache for 1 hour
      await CacheService.set(cacheKey, plans, 3600);
      
      return plans;
      
    } catch (error) {
      logger.error('Get subscription plans error', { error, filters });
      throw error;
    }
  }
  
  /**
   * Get subscription plan by ID
   * @param {string} planId - Plan ID
   * @returns {Promise<Object>} Subscription plan
   */
  static async getSubscriptionPlanById(planId) {
    try {
      const plan = await SubscriptionPlan.findById(planId);
      
      if (!plan) {
        throw new NotFoundError('Subscription plan not found');
      }
      
      if (!plan.isAvailable()) {
        throw new ValidationError('Subscription plan is not available');
      }
      
      return plan;
      
    } catch (error) {
      logger.error('Get subscription plan by ID error', { error, planId });
      throw error;
    }
  }
  
  /**
   * Create subscription
   * @param {Object} subscriptionData - Subscription data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created subscription
   */
  static async createSubscription(subscriptionData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const { userId, planId, billingCycle, paymentMethod, discountCode } = subscriptionData;
      
      // Get user and plan
      const [user, plan] = await Promise.all([
        User.findById(userId),
        SubscriptionPlan.findById(planId)
      ]);
      
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      if (!plan || !plan.isAvailable()) {
        throw new NotFoundError('Subscription plan not found or unavailable');
      }
      
      // Check for existing active subscription
      const existingSubscription = await Subscription.findOne({
        userId,
        status: { $in: ['active', 'trial'] }
      });
      
      if (existingSubscription) {
        throw new ConflictError('User already has an active subscription');
      }
      
      // Get pricing for billing cycle
      const pricing = plan.getPriceForCycle(billingCycle);
      if (!pricing) {
        throw new ValidationError(`Invalid billing cycle: ${billingCycle}`);
      }
      
      // Apply discount if provided
      let discountAmount = 0;
      let appliedDiscount = null;
      
      if (discountCode) {
        appliedDiscount = await this.validateAndApplyDiscount(discountCode, pricing.amount);
        discountAmount = appliedDiscount.amount;
      }
      
      // Calculate tax
      const taxAmount = await TaxService.calculateTax({
        amount: pricing.amount - discountAmount,
        userId,
        type: 'subscription'
      });
      
      // Create subscription
      const subscription = new Subscription({
        userId,
        organizationId: user.organization?.current,
        planId,
        type: plan.category === 'organization' ? 'organization' : 'individual',
        status: plan.trial.enabled ? 'trial' : 'pending',
        
        billing: {
          cycle: billingCycle,
          amount: {
            base: pricing.amount,
            discount: discountAmount,
            tax: taxAmount,
            total: pricing.amount - discountAmount + taxAmount + pricing.setupFee
          },
          currency: plan.pricing.currency,
          paymentMethod: paymentMethod.type,
          paymentDetails: this.extractPaymentDetails(paymentMethod)
        },
        
        dates: {
          started: new Date(),
          currentPeriodStart: new Date(),
          currentPeriodEnd: this.calculatePeriodEnd(new Date(), billingCycle),
          nextBillingDate: plan.trial.enabled ? 
            this.calculateTrialEnd(plan.trial) : 
            this.calculatePeriodEnd(new Date(), billingCycle)
        },
        
        trial: plan.trial.enabled ? {
          isActive: true,
          type: 'standard',
          duration: plan.trial.duration,
          features: plan.trial.features
        } : undefined,
        
        usage: {
          users: { limit: plan.limits.users?.included || 1 },
          storage: { limit: plan.limits.storage?.amount || 10 },
          projects: { limit: plan.limits.projects?.max || 5 },
          apiCalls: { limit: plan.limits.apiCalls?.monthly || 10000 }
        },
        
        metadata: {
          source: context.source || 'website',
          referralCode: subscriptionData.referralCode
        }
      });
      
      if (appliedDiscount) {
        subscription.discounts.push(appliedDiscount);
      }
      
      await subscription.save({ session });
      
      // Process initial payment if not trial
      let payment = null;
      if (!plan.trial.enabled) {
        payment = await this.processSubscriptionPayment(subscription, paymentMethod, { session });
        
        if (payment.status === 'succeeded') {
          subscription.status = 'active';
          subscription.paymentSummary.lastPaymentDate = new Date();
          subscription.paymentSummary.lastPaymentAmount = payment.amount.value;
          await subscription.save({ session });
        } else {
          throw new PaymentError('Initial payment failed');
        }
      }
      
      // Create initial invoice
      const invoice = await this.createSubscriptionInvoice(subscription, { session });
      
      // Update plan subscription count
      await SubscriptionPlan.updateSubscriptionCount(planId, 1);
      
      // Update user subscription info
      user.subscription = {
        plan: plan.type,
        status: subscription.status,
        startDate: subscription.dates.started,
        endDate: subscription.dates.currentPeriodEnd
      };
      await user.save({ session });
      
      await session.commitTransaction();
      
      // Send welcome email
      await this.sendSubscriptionWelcomeEmail(user, plan, subscription);
      
      // Audit log
      await AuditService.log({
        type: 'subscription_created',
        action: 'create_subscription',
        category: 'billing',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'subscription',
          id: subscription._id.toString()
        },
        metadata: {
          planId,
          billingCycle,
          amount: subscription.billing.amount.total
        }
      });
      
      return {
        subscription,
        invoice,
        payment
      };
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Create subscription error', { error });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Update subscription
   * @param {string} subscriptionId - Subscription ID
   * @param {Object} updateData - Update data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated subscription
   */
  static async updateSubscription(subscriptionId, updateData, context) {
    try {
      const subscription = await Subscription.findById(subscriptionId)
        .populate('planId');
      
      if (!subscription) {
        throw new NotFoundError('Subscription not found');
      }
      
      // Check permissions
      if (subscription.userId.toString() !== context.userId && !context.isAdmin) {
        throw new ForbiddenError('Insufficient permissions');
      }
      
      const { action, data } = updateData;
      
      switch (action) {
        case 'upgrade':
          return await this.upgradeSubscription(subscription, data, context);
          
        case 'downgrade':
          return await this.downgradeSubscription(subscription, data, context);
          
        case 'change_billing_cycle':
          return await this.changeBillingCycle(subscription, data, context);
          
        case 'update_payment_method':
          return await this.updatePaymentMethod(subscription, data, context);
          
        case 'add_addon':
          return await this.addAddon(subscription, data, context);
          
        case 'remove_addon':
          return await this.removeAddon(subscription, data, context);
          
        case 'pause':
          return await this.pauseSubscription(subscription, data, context);
          
        case 'resume':
          return await this.resumeSubscription(subscription, context);
          
        case 'cancel':
          return await this.cancelSubscription(subscription, data, context);
          
        default:
          throw new ValidationError(`Invalid action: ${action}`);
      }
      
    } catch (error) {
      logger.error('Update subscription error', { error, subscriptionId });
      throw error;
    }
  }
  
  /**
   * Upgrade subscription
   * @param {Object} subscription - Current subscription
   * @param {Object} upgradeData - Upgrade data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Upgraded subscription
   */
  static async upgradeSubscription(subscription, upgradeData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const { planId } = upgradeData;
      
      const newPlan = await SubscriptionPlan.findById(planId);
      if (!newPlan || !newPlan.isAvailable()) {
        throw new NotFoundError('Target plan not found or unavailable');
      }
      
      // Check if upgrade is allowed
      if (!subscription.planId.canUpgradeTo(planId)) {
        throw new ValidationError('Upgrade to this plan is not allowed');
      }
      
      // Calculate prorated amount
      const proratedAmount = await this.calculateProratedAmount(
        subscription,
        newPlan,
        'upgrade'
      );
      
      // Update subscription
      const oldPlanId = subscription.planId._id;
      subscription.planId = planId;
      subscription.billing.amount = {
        base: newPlan.getPriceForCycle(subscription.billing.cycle).amount,
        discount: subscription.billing.amount.discount,
        tax: 0, // Recalculate
        total: 0 // Recalculate
      };
      
      await subscription.recalculateBilling();
      
      // Add history entry
      subscription.history.push({
        event: 'upgraded',
        timestamp: new Date(),
        fromPlan: oldPlanId,
        toPlan: planId,
        actor: context.userId
      });
      
      await subscription.save({ session });
      
      // Process upgrade payment
      if (proratedAmount > 0) {
        const payment = await this.processUpgradePayment(
          subscription,
          proratedAmount,
          { session }
        );
        
        if (payment.status !== 'succeeded') {
          throw new PaymentError('Upgrade payment failed');
        }
      }
      
      // Update plan subscription counts
      await SubscriptionPlan.updateSubscriptionCount(oldPlanId, -1);
      await SubscriptionPlan.updateSubscriptionCount(planId, 1);
      
      await session.commitTransaction();
      
      // Send upgrade confirmation
      await this.sendUpgradeConfirmation(subscription);
      
      // Audit log
      await AuditService.log({
        type: 'subscription_upgraded',
        action: 'upgrade_subscription',
        category: 'billing',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'subscription',
          id: subscription._id.toString()
        },
        metadata: {
          fromPlan: oldPlanId,
          toPlan: planId,
          proratedAmount
        }
      });
      
      return subscription;
      
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Cancel subscription
   * @param {Object} subscription - Subscription to cancel
   * @param {Object} cancellationData - Cancellation data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Cancelled subscription
   */
  static async cancelSubscription(subscription, cancellationData, context) {
    try {
      const { immediate = false, reason, feedback } = cancellationData;
      
      if (subscription.status === 'cancelled') {
        throw new ValidationError('Subscription is already cancelled');
      }
      
      // Process cancellation
      await subscription.cancel(immediate, {
        reason,
        feedback,
        requestedBy: context.userId
      });
      
      // Cancel recurring payment
      if (subscription.external.stripeSubscriptionId) {
        await PaymentGatewayService.cancelSubscription(
          'stripe',
          subscription.external.stripeSubscriptionId
        );
      }
      
      // Send cancellation email
      await this.sendCancellationEmail(subscription);
      
      // Audit log
      await AuditService.log({
        type: 'subscription_cancelled',
        action: 'cancel_subscription',
        category: 'billing',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'subscription',
          id: subscription._id.toString()
        },
        metadata: {
          immediate,
          reason,
          effectiveDate: subscription.dates.cancellationEffective
        }
      });
      
      return subscription;
      
    } catch (error) {
      logger.error('Cancel subscription error', { error });
      throw error;
    }
  }
  
  /**
   * Get user subscriptions
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} User subscriptions
   */
  static async getUserSubscriptions(userId, options = {}) {
    try {
      const { includeExpired = false, populate = true } = options;
      
      const query = { userId };
      
      if (!includeExpired) {
        query.status = { $ne: 'expired' };
      }
      
      let subscriptions = Subscription.find(query);
      
      if (populate) {
        subscriptions = subscriptions.populate('planId');
      }
      
      return await subscriptions.sort({ createdAt: -1 });
      
    } catch (error) {
      logger.error('Get user subscriptions error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Process subscription payment
   * @param {Object} subscription - Subscription
   * @param {Object} paymentMethod - Payment method
   * @param {Object} options - Processing options
   * @returns {Promise<Object>} Payment result
   */
  static async processSubscriptionPayment(subscription, paymentMethod, options = {}) {
    try {
      const payment = new Payment({
        userId: subscription.userId,
        organizationId: subscription.organizationId,
        subscriptionId: subscription._id,
        type: 'payment',
        status: 'pending',
        
        amount: {
          value: subscription.billing.amount.total,
          currency: subscription.billing.currency
        },
        
        method: {
          type: paymentMethod.type,
          ...this.extractPaymentDetails(paymentMethod)
        },
        
        gateway: {
          provider: this.getGatewayProvider(paymentMethod.type)
        },
        
        source: {
          type: options.source || 'recurring',
          ipAddress: options.ipAddress
        }
      });
      
      await payment.save(options.session);
      
      // Process payment through gateway
      try {
        const result = await PaymentGatewayService.processPayment(payment, paymentMethod);
        
        if (result.success) {
          await payment.markAsSucceeded(result.response);
        } else {
          await payment.markAsFailed(result.error);
        }
        
      } catch (error) {
        await payment.markAsFailed({
          code: 'gateway_error',
          message: error.message
        });
        throw error;
      }
      
      return payment;
      
    } catch (error) {
      logger.error('Process subscription payment error', { error });
      throw error;
    }
  }
  
  /**
   * Create subscription invoice
   * @param {Object} subscription - Subscription
   * @param {Object} options - Creation options
   * @returns {Promise<Object>} Created invoice
   */
  static async createSubscriptionInvoice(subscription, options = {}) {
    try {
      await subscription.populate('userId planId');
      
      const invoice = new Invoice({
        userId: subscription.userId._id,
        organizationId: subscription.organizationId,
        subscriptionId: subscription._id,
        type: 'subscription',
        status: subscription.status === 'trial' ? 'draft' : 'pending',
        
        dates: {
          issued: new Date(),
          due: subscription.dates.nextBillingDate || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          period: {
            start: subscription.dates.currentPeriodStart,
            end: subscription.dates.currentPeriodEnd
          }
        },
        
        billingInfo: {
          customer: {
            name: subscription.userId.fullName,
            email: subscription.userId.email,
            customerId: subscription.userId._id.toString()
          },
          address: subscription.userId.contact?.address || {}
        },
        
        financials: {
          subtotal: subscription.billing.amount.base,
          discount: { total: subscription.billing.amount.discount },
          tax: { total: subscription.billing.amount.tax },
          total: subscription.billing.amount.total,
          due: subscription.billing.amount.total,
          currency: subscription.billing.currency
        }
      });
      
      // Add line items
      invoice.addItem({
        type: 'subscription',
        name: `${subscription.planId.name} - ${subscription.billing.cycle} subscription`,
        description: `${subscription.dates.currentPeriodStart.toDateString()} - ${subscription.dates.currentPeriodEnd.toDateString()}`,
        quantity: { amount: 1 },
        rate: { amount: subscription.billing.amount.base },
        period: {
          start: subscription.dates.currentPeriodStart,
          end: subscription.dates.currentPeriodEnd
        }
      });
      
      // Add discount if applicable
      if (subscription.billing.amount.discount > 0) {
        const discount = subscription.discounts[0];
        invoice.addItem({
          type: 'discount',
          name: 'Discount',
          description: discount?.description || 'Promotional discount',
          quantity: { amount: 1 },
          rate: { amount: -subscription.billing.amount.discount }
        });
      }
      
      // Add tax if applicable
      if (subscription.billing.amount.tax > 0) {
        invoice.addItem({
          type: 'tax',
          name: 'Tax',
          quantity: { amount: 1 },
          rate: { amount: subscription.billing.amount.tax }
        });
      }
      
      await invoice.save(options.session);
      
      return invoice;
      
    } catch (error) {
      logger.error('Create subscription invoice error', { error });
      throw error;
    }
  }
  
  /**
   * Process recurring subscriptions
   * @returns {Promise<Object>} Processing results
   */
  static async processRecurringSubscriptions() {
    try {
      const results = {
        processed: 0,
        succeeded: 0,
        failed: 0,
        errors: []
      };
      
      // Get subscriptions due for billing
      const dueSubscriptions = await Subscription.find({
        status: 'active',
        'renewal.auto': true,
        'dates.nextBillingDate': { $lte: new Date() }
      }).populate('userId planId');
      
      logger.info(`Processing ${dueSubscriptions.length} recurring subscriptions`);
      
      for (const subscription of dueSubscriptions) {
        try {
          // Create invoice
          const invoice = await this.createSubscriptionInvoice(subscription);
          
          // Process payment
          const payment = await this.processSubscriptionPayment(
            subscription,
            {
              type: subscription.billing.paymentMethod,
              ...subscription.billing.paymentDetails
            }
          );
          
          if (payment.status === 'succeeded') {
            // Update subscription dates
            subscription.dates.currentPeriodStart = subscription.dates.currentPeriodEnd;
            subscription.dates.currentPeriodEnd = this.calculatePeriodEnd(
              subscription.dates.currentPeriodEnd,
              subscription.billing.cycle
            );
            subscription.dates.nextBillingDate = subscription.dates.currentPeriodEnd;
            
            // Update payment summary
            subscription.paymentSummary.totalPaid += payment.amount.value;
            subscription.paymentSummary.lastPaymentDate = new Date();
            subscription.paymentSummary.lastPaymentAmount = payment.amount.value;
            
            // Add to history
            subscription.history.push({
              event: 'renewed',
              timestamp: new Date()
            });
            
            await subscription.save();
            
            // Update invoice
            await invoice.applyPayment({
              amount: payment.amount.value,
              method: payment.method.type,
              transactionId: payment.gateway.transactionId
            });
            
            results.succeeded++;
          } else {
            // Handle failed payment
            subscription.status = 'past_due';
            subscription.billing.retry.attempts++;
            subscription.billing.retry.lastAttempt = new Date();
            subscription.billing.retry.nextAttempt = new Date(
              Date.now() + 24 * 60 * 60 * 1000 // Retry in 24 hours
            );
            
            subscription.paymentSummary.failedPayments++;
            
            await subscription.save();
            
            results.failed++;
            results.errors.push({
              subscriptionId: subscription._id,
              error: 'Payment failed'
            });
            
            // Send payment failure notification
            await this.sendPaymentFailureNotification(subscription);
          }
          
          results.processed++;
          
        } catch (error) {
          logger.error('Process recurring subscription error', {
            error,
            subscriptionId: subscription._id
          });
          
          results.failed++;
          results.errors.push({
            subscriptionId: subscription._id,
            error: error.message
          });
        }
      }
      
      logger.info('Recurring subscription processing completed', results);
      
      return results;
      
    } catch (error) {
      logger.error('Process recurring subscriptions error', { error });
      throw error;
    }
  }
  
  /**
   * Get billing statistics
   * @param {Object} filters - Filter options
   * @returns {Promise<Object>} Billing statistics
   */
  static async getBillingStatistics(filters = {}) {
    try {
      const [
        subscriptionStats,
        invoiceStats,
        paymentStats
      ] = await Promise.all([
        this.getSubscriptionStatistics(filters),
        Invoice.calculateRevenue(filters),
        Payment.getStatistics(filters)
      ]);
      
      return {
        subscriptions: subscriptionStats,
        revenue: invoiceStats,
        payments: paymentStats,
        summary: {
          mrr: subscriptionStats.mrr,
          arr: subscriptionStats.mrr * 12,
          averageRevenuePerUser: invoiceStats.avgInvoiceValue,
          churnRate: subscriptionStats.churnRate,
          paymentSuccessRate: paymentStats.successRate
        }
      };
      
    } catch (error) {
      logger.error('Get billing statistics error', { error, filters });
      throw error;
    }
  }
  
  /**
   * Get subscription statistics
   * @param {Object} filters - Filter options
   * @returns {Promise<Object>} Subscription statistics
   */
  static async getSubscriptionStatistics(filters = {}) {
    const match = { status: { $in: ['active', 'trial'] } };
    
    if (filters.startDate) {
      match.createdAt = { $gte: filters.startDate };
    }
    
    const stats = await Subscription.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          totalActive: { $sum: 1 },
          mrr: {
            $sum: {
              $cond: [
                { $eq: ['$billing.cycle', 'monthly'] },
                '$billing.amount.total',
                {
                  $cond: [
                    { $eq: ['$billing.cycle', 'yearly'] },
                    { $divide: ['$billing.amount.total', 12] },
                    { $divide: ['$billing.amount.total', 3] } // Quarterly
                  ]
                }
              ]
            }
          },
          trialCount: {
            $sum: { $cond: [{ $eq: ['$status', 'trial'] }, 1, 0] }
          }
        }
      }
    ]);
    
    const churnStats = await Subscription.aggregate([
      {
        $match: {
          status: 'cancelled',
          'dates.cancelledAt': {
            $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
          }
        }
      },
      { $count: 'churned' }
    ]);
    
    const result = stats[0] || { totalActive: 0, mrr: 0, trialCount: 0 };
    const churnedCount = churnStats[0]?.churned || 0;
    
    result.churnRate = result.totalActive > 0 ? 
      (churnedCount / result.totalActive) * 100 : 0;
    
    return result;
  }
  
  /**
   * Helper Methods
   */
  
  static extractPaymentDetails(paymentMethod) {
    const details = {};
    
    switch (paymentMethod.type) {
      case 'card':
        details.lastFourDigits = paymentMethod.lastFourDigits;
        details.brand = paymentMethod.brand;
        details.expiryMonth = paymentMethod.expiryMonth;
        details.expiryYear = paymentMethod.expiryYear;
        break;
        
      case 'bank_account':
        details.bankName = paymentMethod.bankName;
        details.lastFourDigits = paymentMethod.lastFourDigits;
        break;
        
      case 'paypal':
        details.paypalEmail = paymentMethod.email;
        break;
    }
    
    return details;
  }
  
  static calculatePeriodEnd(startDate, cycle) {
    const date = new Date(startDate);
    
    switch (cycle) {
      case 'monthly':
        date.setMonth(date.getMonth() + 1);
        break;
      case 'quarterly':
        date.setMonth(date.getMonth() + 3);
        break;
      case 'yearly':
        date.setFullYear(date.getFullYear() + 1);
        break;
    }
    
    return date;
  }
  
  static calculateTrialEnd(trialConfig) {
    const date = new Date();
    
    switch (trialConfig.duration.unit) {
      case 'days':
        date.setDate(date.getDate() + trialConfig.duration.value);
        break;
      case 'weeks':
        date.setDate(date.getDate() + (trialConfig.duration.value * 7));
        break;
      case 'months':
        date.setMonth(date.getMonth() + trialConfig.duration.value);
        break;
    }
    
    return date;
  }
  
  static getGatewayProvider(paymentType) {
    const providerMap = {
      card: 'stripe',
      bank_account: 'stripe',
      paypal: 'paypal'
    };
    
    return providerMap[paymentType] || 'manual';
  }
  
  static async validateAndApplyDiscount(code, amount) {
    // This would validate discount code and return discount details
    // Placeholder implementation
    return {
      code,
      type: 'percentage',
      value: 10,
      amount: amount * 0.1,
      description: '10% off promotion'
    };
  }
  
  static async calculateProratedAmount(subscription, newPlan, type) {
    const daysRemaining = subscription.daysRemaining;
    const totalDays = Math.ceil(
      (subscription.dates.currentPeriodEnd - subscription.dates.currentPeriodStart) / 
      (1000 * 60 * 60 * 24)
    );
    
    const currentDailyRate = subscription.billing.amount.total / totalDays;
    const newDailyRate = newPlan.getPriceForCycle(subscription.billing.cycle).amount / totalDays;
    
    if (type === 'upgrade') {
      return Math.max(0, (newDailyRate - currentDailyRate) * daysRemaining);
    } else {
      return Math.max(0, (currentDailyRate - newDailyRate) * daysRemaining);
    }
  }
  
  /**
   * Email Notification Methods
   */
  
  static async sendSubscriptionWelcomeEmail(user, plan, subscription) {
    await EmailService.sendEmail({
      to: user.email,
      subject: `Welcome to ${plan.name}!`,
      template: 'subscription-welcome',
      data: {
        firstName: user.firstName,
        planName: plan.name,
        features: plan.features.filter(f => f.highlighted),
        trialEnd: subscription.trial?.isActive ? subscription.dates.trialEnd : null,
        dashboardUrl: `${config.client.url}/billing`
      }
    });
  }
  
  static async sendPaymentFailureNotification(subscription) {
    await subscription.populate('userId planId');
    
    await EmailService.sendEmail({
      to: subscription.userId.email,
      subject: 'Payment Failed - Action Required',
      template: 'payment-failed',
      data: {
        firstName: subscription.userId.firstName,
        planName: subscription.planId.name,
        amount: subscription.billing.amount.total,
        retryDate: subscription.billing.retry.nextAttempt,
        updatePaymentUrl: `${config.client.url}/billing/payment-methods`
      }
    });
  }
}

module.exports = BillingService;