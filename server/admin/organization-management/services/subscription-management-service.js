// server/admin/organization-management/services/subscription-management-service.js
/**
 * @file Subscription Management Service
 * @description Service for managing organization subscriptions, billing, and plan changes
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const moment = require('moment');
const Stripe = require('stripe');

// Core Models
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const OrganizationTenant = require('../../../organization-tenants/models/organization-tenant-model');
const Subscription = require('../../../shared/billing/models/subscription-model');
const SubscriptionPlan = require('../../../shared/billing/models/subscription-plan-model');
const Invoice = require('../../../shared/billing/models/invoice-model');
const Payment = require('../../../shared/billing/models/payment-model');
const PaymentMethod = require('../../../shared/billing/models/payment-method-model');
const UsageRecord = require('../../../shared/billing/models/usage-record-model');
const CreditTransaction = require('../../../shared/billing/models/credit-transaction-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const InvoiceService = require('../../../shared/billing/services/invoice-service');
const PaymentService = require('../../../shared/billing/services/payment-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError, ConflictError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const { formatCurrency, calculateProration } = require('../../../shared/utils/billing-helpers');

// Configuration
const config = require('../../../config');
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');
const constants = require('../../../shared/config/constants');

// Initialize Stripe
const stripe = new Stripe(config.payment.stripe.secretKey);

/**
 * Subscription Management Service Class
 * @class SubscriptionManagementService
 * @extends AdminBaseService
 */
class SubscriptionManagementService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'SubscriptionManagementService';
    this.cachePrefix = 'admin-subscription';
    this.auditCategory = 'SUBSCRIPTION_MANAGEMENT';
    this.requiredPermission = AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_SUBSCRIPTIONS;
    
    // Subscription management configuration
    this.planHierarchy = ['trial', 'starter', 'growth', 'professional', 'enterprise'];
    
    this.discountTypes = {
      PERCENTAGE: 'percentage',
      FIXED: 'fixed',
      TRIAL_EXTENSION: 'trial_extension',
      VOLUME: 'volume',
      LOYALTY: 'loyalty'
    };
    
    this.adjustmentReasons = {
      GOODWILL: 'goodwill',
      SERVICE_ISSUE: 'service_issue',
      PRICING_ERROR: 'pricing_error',
      PROMOTIONAL: 'promotional',
      RETENTION: 'retention',
      COMPENSATION: 'compensation'
    };
    
    // Billing thresholds
    this.billingThresholds = {
      creditWarning: 100, // Warn when credits below $100
      overdueGracePeriod: 7, // Days before suspension
      retriesBeforeSuspension: 3,
      refundWindow: 30 // Days
    };
  }

  /**
   * Get organization subscription details
   * @param {String} organizationId - Organization ID
   * @param {Object} options - Additional options
   * @param {Object} adminUser - Admin user making the request
   * @returns {Promise<Object>} Subscription details
   */
  async getSubscriptionDetails(organizationId, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_SUBSCRIPTIONS);
      
      const organization = await HostedOrganization.findById(organizationId)
        .populate('tenantRef')
        .lean();
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Get current subscription
      const subscription = await Subscription.findOne({
        organizationId,
        status: { $in: ['active', 'trialing', 'past_due'] }
      })
        .populate('planId')
        .lean();
      
      if (!subscription) {
        throw new NotFoundError('No active subscription found');
      }
      
      // Build comprehensive subscription data
      const subscriptionDetails = {
        subscription: {
          ...subscription,
          plan: await this._getEnhancedPlanDetails(subscription.planId)
        },
        billing: await this._getBillingDetails(organizationId, subscription),
        usage: options.includeUsage ? await this._getUsageDetails(organizationId, subscription) : null,
        history: options.includeHistory ? await this._getSubscriptionHistory(organizationId) : null,
        paymentMethods: options.includePaymentMethods ? await this._getPaymentMethods(organization) : null,
        upcomingInvoice: options.includeUpcoming ? await this._getUpcomingInvoice(subscription) : null,
        credits: await this._getCreditBalance(organizationId),
        discounts: await this._getActiveDiscounts(subscription),
        metadata: {
          mrr: this._calculateMRR(subscription),
          ltv: await this._calculateLTV(organizationId),
          churnRisk: await this._assessChurnRisk(organization, subscription),
          upgradeOptions: await this._getUpgradeOptions(subscription)
        }
      };
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.VIEWED_DETAILS, adminUser, {
        organizationId,
        subscriptionId: subscription._id
      });
      
      return subscriptionDetails;
    } catch (error) {
      logger.error('Error getting subscription details:', error);
      throw error;
    }
  }

  /**
   * Change organization subscription plan
   * @param {String} organizationId - Organization ID
   * @param {Object} planChange - Plan change details
   * @param {Object} adminUser - Admin user making the change
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Updated subscription
   */
  async changeSubscriptionPlan(organizationId, planChange, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.CHANGE_SUBSCRIPTION_PLAN);
      
      const [organization, currentSubscription] = await Promise.all([
        HostedOrganization.findById(organizationId).session(session),
        Subscription.findOne({
          organizationId,
          status: { $in: ['active', 'trialing', 'past_due'] }
        }).populate('planId').session(session)
      ]);
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      if (!currentSubscription) {
        throw new NotFoundError('No active subscription found');
      }
      
      // Get new plan details
      const newPlan = await SubscriptionPlan.findById(planChange.planId).session(session);
      if (!newPlan) {
        throw new NotFoundError('Plan not found');
      }
      
      // Validate plan change
      await this._validatePlanChange(currentSubscription, newPlan, planChange);
      
      // Calculate proration if applicable
      let proration = null;
      if (planChange.prorate && !options.skipProration) {
        proration = await this._calculatePlanChangeProration(
          currentSubscription,
          newPlan,
          planChange.effectiveDate || new Date()
        );
      }
      
      // Update subscription
      const previousPlan = currentSubscription.planId;
      currentSubscription.planId = newPlan._id;
      currentSubscription.previousPlanId = previousPlan._id;
      
      // Update billing details
      currentSubscription.billing = {
        ...currentSubscription.billing,
        amount: {
          base: newPlan.pricing[currentSubscription.billing.cycle],
          discount: currentSubscription.billing.amount.discount || 0,
          tax: 0, // Will be recalculated
          total: 0 // Will be recalculated
        }
      };
      
      // Recalculate totals
      const taxAmount = await this._calculateTax(currentSubscription, organization);
      currentSubscription.billing.amount.tax = taxAmount;
      currentSubscription.billing.amount.total = 
        currentSubscription.billing.amount.base - 
        currentSubscription.billing.amount.discount + 
        taxAmount;
      
      // Add plan change to history
      currentSubscription.planHistory = currentSubscription.planHistory || [];
      currentSubscription.planHistory.push({
        fromPlan: previousPlan._id,
        toPlan: newPlan._id,
        changedAt: new Date(),
        changedBy: adminUser._id,
        reason: planChange.reason || 'Admin initiated',
        proration: proration ? {
          amount: proration.amount,
          credits: proration.credits,
          charges: proration.charges
        } : null
      });
      
      // Update next billing date if changing billing cycle
      if (planChange.changeBillingCycle) {
        currentSubscription.billing.cycle = planChange.newBillingCycle;
        currentSubscription.nextBillingDate = this._calculateNextBillingDate(
          planChange.newBillingCycle,
          planChange.effectiveDate || new Date()
        );
      }
      
      await currentSubscription.save({ session });
      
      // Update organization and tenant
      await this._updateOrganizationForPlanChange(
        organization,
        currentSubscription,
        newPlan,
        adminUser,
        session
      );
      
      // Apply proration if calculated
      if (proration) {
        await this._applyProration(organizationId, proration, adminUser, session);
      }
      
      // Create change invoice if immediate payment required
      if (planChange.chargeImmediately && proration?.charges > 0) {
        await this._createPlanChangeInvoice(
          organization,
          currentSubscription,
          proration,
          adminUser,
          session
        );
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearSubscriptionCaches(organizationId);
      
      // Send notifications
      if (!options.skipNotifications) {
        await this._sendPlanChangeNotifications(
          organization,
          previousPlan,
          newPlan,
          currentSubscription,
          adminUser
        );
      }
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.PLAN_CHANGED, adminUser, {
        organizationId,
        organizationName: organization.name,
        previousPlan: previousPlan.name,
        newPlan: newPlan.name,
        proration: proration?.amount
      }, 'high');
      
      return currentSubscription;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error changing subscription plan:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Cancel organization subscription
   * @param {String} organizationId - Organization ID
   * @param {Object} cancellationDetails - Cancellation details
   * @param {Object} adminUser - Admin user performing cancellation
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Cancellation result
   */
  async cancelSubscription(organizationId, cancellationDetails, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.CANCEL_SUBSCRIPTION);
      
      const [organization, subscription] = await Promise.all([
        HostedOrganization.findById(organizationId).session(session),
        Subscription.findOne({
          organizationId,
          status: { $in: ['active', 'trialing', 'past_due'] }
        }).session(session)
      ]);
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      if (!subscription) {
        throw new NotFoundError('No active subscription found');
      }
      
      // Determine cancellation type
      const cancellationType = cancellationDetails.immediate ? 'immediate' : 'end_of_period';
      const cancellationDate = cancellationType === 'immediate' 
        ? new Date() 
        : subscription.currentPeriodEnd;
      
      // Update subscription
      subscription.status = cancellationType === 'immediate' ? 'canceled' : 'canceling';
      subscription.canceledAt = new Date();
      subscription.canceledBy = adminUser._id;
      subscription.cancellationReason = cancellationDetails.reason;
      subscription.cancellationFeedback = cancellationDetails.feedback;
      subscription.scheduledCancellation = cancellationType === 'end_of_period' ? {
        date: cancellationDate,
        reason: cancellationDetails.reason
      } : null;
      
      await subscription.save({ session });
      
      // Handle immediate cancellation
      if (cancellationType === 'immediate') {
        // Calculate refund if applicable
        if (cancellationDetails.issueRefund) {
          const refundAmount = await this._calculateCancellationRefund(
            subscription,
            cancellationDetails
          );
          
          if (refundAmount > 0) {
            await this._processCancellationRefund(
              organization,
              subscription,
              refundAmount,
              cancellationDetails,
              adminUser,
              session
            );
          }
        }
        
        // Update organization status
        organization.subscription.status = 'canceled';
        organization.subscription.canceledAt = new Date();
        await organization.save({ session });
        
        // Update tenant
        const tenant = await OrganizationTenant.findById(organization.tenantRef).session(session);
        if (tenant) {
          tenant.subscription.status = TENANT_CONSTANTS.SUBSCRIPTION_STATUS.CANCELED;
          tenant.lifecycleStage = TENANT_CONSTANTS.LIFECYCLE_STAGES.CHURNED;
          await tenant.save({ session });
        }
      }
      
      // Create cancellation record
      const cancellationRecord = {
        subscriptionId: subscription._id,
        organizationId,
        type: cancellationType,
        date: cancellationDate,
        reason: cancellationDetails.reason,
        feedback: cancellationDetails.feedback,
        retentionOffered: cancellationDetails.retentionOffer || null,
        refundIssued: cancellationDetails.issueRefund || false,
        performedBy: adminUser._id
      };
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearSubscriptionCaches(organizationId);
      
      // Send notifications
      if (!options.skipNotifications) {
        await this._sendCancellationNotifications(
          organization,
          subscription,
          cancellationRecord,
          adminUser
        );
      }
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.CANCELED, adminUser, {
        organizationId,
        organizationName: organization.name,
        cancellationType,
        reason: cancellationDetails.reason
      }, 'high');
      
      return {
        success: true,
        cancellationType,
        cancellationDate,
        refundIssued: cancellationDetails.issueRefund || false,
        message: `Subscription ${cancellationType === 'immediate' ? 'canceled immediately' : 'scheduled for cancellation'}`
      };
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error canceling subscription:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Reactivate canceled subscription
   * @param {String} organizationId - Organization ID
   * @param {Object} reactivationDetails - Reactivation details
   * @param {Object} adminUser - Admin user performing reactivation
   * @returns {Promise<Object>} Reactivated subscription
   */
  async reactivateSubscription(organizationId, reactivationDetails, adminUser) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.REACTIVATE_SUBSCRIPTION);
      
      const [organization, subscription] = await Promise.all([
        HostedOrganization.findById(organizationId).session(session),
        Subscription.findOne({
          organizationId,
          status: { $in: ['canceled', 'canceling'] }
        }).sort('-canceledAt').session(session)
      ]);
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      if (!subscription) {
        throw new NotFoundError('No canceled subscription found');
      }
      
      // Check if reactivation is allowed
      const daysSinceCancellation = moment().diff(subscription.canceledAt, 'days');
      if (daysSinceCancellation > 90 && !adminUser.permissions.includes('override_reactivation_limit')) {
        throw new ValidationError('Subscription has been canceled for too long to reactivate');
      }
      
      // Determine new plan
      const planId = reactivationDetails.planId || subscription.planId;
      const plan = await SubscriptionPlan.findById(planId).session(session);
      
      if (!plan) {
        throw new NotFoundError('Plan not found');
      }
      
      // Update subscription
      subscription.status = 'active';
      subscription.planId = planId;
      subscription.reactivatedAt = new Date();
      subscription.reactivatedBy = adminUser._id;
      subscription.currentPeriodStart = new Date();
      subscription.currentPeriodEnd = this._calculateNextBillingDate(
        subscription.billing.cycle,
        new Date()
      );
      subscription.canceledAt = null;
      subscription.canceledBy = null;
      subscription.scheduledCancellation = null;
      
      // Add reactivation to history
      subscription.reactivationHistory = subscription.reactivationHistory || [];
      subscription.reactivationHistory.push({
        reactivatedAt: new Date(),
        reactivatedBy: adminUser._id,
        previousStatus: 'canceled',
        daysCanceled: daysSinceCancellation,
        reason: reactivationDetails.reason
      });
      
      await subscription.save({ session });
      
      // Update organization
      organization.subscription.status = 'active';
      organization.subscription.canceledAt = null;
      organization.subscription.reactivatedAt = new Date();
      await organization.save({ session });
      
      // Update tenant
      const tenant = await OrganizationTenant.findById(organization.tenantRef).session(session);
      if (tenant) {
        tenant.subscription.status = TENANT_CONSTANTS.SUBSCRIPTION_STATUS.ACTIVE;
        tenant.lifecycleStage = TENANT_CONSTANTS.LIFECYCLE_STAGES.ACTIVE;
        tenant.status = TENANT_CONSTANTS.TENANT_STATUS.ACTIVE;
        await tenant.save({ session });
      }
      
      // Apply any promotional offers
      if (reactivationDetails.applyPromotion) {
        await this._applyReactivationPromotion(
          subscription,
          reactivationDetails.promotion,
          adminUser,
          session
        );
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearSubscriptionCaches(organizationId);
      
      // Send notifications
      await this._sendReactivationNotifications(
        organization,
        subscription,
        adminUser
      );
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.REACTIVATED, adminUser, {
        organizationId,
        organizationName: organization.name,
        daysCanceled: daysSinceCancellation,
        newPlan: plan.name
      }, 'high');
      
      return subscription;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error reactivating subscription:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Apply discount to subscription
   * @param {String} organizationId - Organization ID
   * @param {Object} discountDetails - Discount details
   * @param {Object} adminUser - Admin user applying discount
   * @returns {Promise<Object>} Updated subscription
   */
  async applyDiscount(organizationId, discountDetails, adminUser) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.APPLY_DISCOUNTS);
      
      const [organization, subscription] = await Promise.all([
        HostedOrganization.findById(organizationId).session(session),
        Subscription.findOne({
          organizationId,
          status: { $in: ['active', 'trialing'] }
        }).session(session)
      ]);
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      if (!subscription) {
        throw new NotFoundError('No active subscription found');
      }
      
      // Validate discount
      await this._validateDiscount(discountDetails, subscription);
      
      // Create discount record
      const discount = {
        id: crypto.randomBytes(16).toString('hex'),
        type: discountDetails.type,
        value: discountDetails.value,
        duration: discountDetails.duration, // 'once', 'repeating', 'forever'
        durationInMonths: discountDetails.durationInMonths,
        description: discountDetails.description,
        appliedAt: new Date(),
        appliedBy: adminUser._id,
        startsAt: discountDetails.startsAt || new Date(),
        endsAt: this._calculateDiscountEndDate(discountDetails),
        usageCount: 0,
        maxUsage: discountDetails.duration === 'repeating' ? discountDetails.durationInMonths : null
      };
      
      // Add discount to subscription
      subscription.discounts = subscription.discounts || [];
      subscription.discounts.push(discount);
      
      // Recalculate billing amount
      const discountAmount = this._calculateDiscountAmount(
        subscription.billing.amount.base,
        discount
      );
      
      subscription.billing.amount.discount = discountAmount;
      subscription.billing.amount.total = 
        subscription.billing.amount.base - 
        discountAmount + 
        subscription.billing.amount.tax;
      
      await subscription.save({ session });
      
      // Create adjustment record
      await this._createBillingAdjustment(
        organizationId,
        'discount',
        discountAmount,
        discountDetails.description,
        adminUser,
        session
      );
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearSubscriptionCaches(organizationId);
      
      // Send notifications
      await this._sendDiscountNotifications(
        organization,
        subscription,
        discount,
        adminUser
      );
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.DISCOUNT_APPLIED, adminUser, {
        organizationId,
        organizationName: organization.name,
        discountType: discount.type,
        discountValue: discount.value,
        duration: discount.duration
      });
      
      return subscription;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error applying discount:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Add credits to organization account
   * @param {String} organizationId - Organization ID
   * @param {Object} creditDetails - Credit details
   * @param {Object} adminUser - Admin user adding credits
   * @returns {Promise<Object>} Credit transaction
   */
  async addCredits(organizationId, creditDetails, adminUser) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_CREDITS);
      
      const organization = await HostedOrganization.findById(organizationId).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Validate credit amount
      if (creditDetails.amount <= 0) {
        throw new ValidationError('Credit amount must be positive');
      }
      
      if (creditDetails.amount > 10000 && !adminUser.permissions.includes('high_value_credits')) {
        throw new ForbiddenError('Insufficient permissions for high-value credit');
      }
      
      // Create credit transaction
      const creditTransaction = new CreditTransaction({
        organizationId,
        type: 'credit',
        amount: creditDetails.amount,
        currency: creditDetails.currency || 'USD',
        description: creditDetails.description,
        reason: creditDetails.reason,
        category: this.adjustmentReasons[creditDetails.reason] || 'other',
        appliedBy: adminUser._id,
        expiresAt: creditDetails.expiresAt,
        metadata: {
          adminAction: true,
          originalRequest: creditDetails,
          approvalRequired: creditDetails.amount > 1000,
          approved: true,
          approvedBy: adminUser._id,
          approvedAt: new Date()
        }
      });
      
      await creditTransaction.save({ session });
      
      // Update organization credit balance
      organization.billing = organization.billing || {};
      organization.billing.creditBalance = 
        (organization.billing.creditBalance || 0) + creditDetails.amount;
      
      await organization.save({ session });
      
      await session.commitTransaction();
      
      // Send notifications
      await this._sendCreditNotifications(
        organization,
        creditTransaction,
        adminUser
      );
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.CREDITS_ADDED, adminUser, {
        organizationId,
        organizationName: organization.name,
        amount: creditDetails.amount,
        reason: creditDetails.reason
      }, 'high');
      
      return {
        transaction: creditTransaction,
        newBalance: organization.billing.creditBalance
      };
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error adding credits:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Process refund for organization
   * @param {String} organizationId - Organization ID
   * @param {Object} refundDetails - Refund details
   * @param {Object} adminUser - Admin user processing refund
   * @returns {Promise<Object>} Refund result
   */
  async processRefund(organizationId, refundDetails, adminUser) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.PROCESS_REFUNDS);
      
      // Additional permission check for high-value refunds
      if (refundDetails.amount > 1000) {
        await this.checkPermission(adminUser, AdminPermissions.SUPER_ADMIN.HIGH_VALUE_OPERATIONS);
      }
      
      const organization = await HostedOrganization.findById(organizationId).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Get the payment to refund
      const payment = await Payment.findById(refundDetails.paymentId).session(session);
      if (!payment) {
        throw new NotFoundError('Payment not found');
      }
      
      if (payment.organizationId.toString() !== organizationId) {
        throw new ForbiddenError('Payment does not belong to this organization');
      }
      
      // Validate refund
      await this._validateRefund(payment, refundDetails);
      
      // Process refund through payment provider
      let refundResult;
      if (payment.provider === 'stripe') {
        refundResult = await this._processStripeRefund(payment, refundDetails);
      } else {
        throw new ValidationError(`Refund not supported for provider: ${payment.provider}`);
      }
      
      // Create refund record
      const refund = {
        id: refundResult.id,
        paymentId: payment._id,
        amount: refundDetails.amount,
        currency: payment.currency,
        reason: refundDetails.reason,
        status: refundResult.status,
        provider: payment.provider,
        providerRefundId: refundResult.providerRefundId,
        processedAt: new Date(),
        processedBy: adminUser._id,
        metadata: refundDetails.metadata
      };
      
      // Update payment record
      payment.refunds = payment.refunds || [];
      payment.refunds.push(refund);
      payment.amountRefunded = (payment.amountRefunded || 0) + refundDetails.amount;
      payment.status = payment.amountRefunded >= payment.amount ? 'refunded' : 'partially_refunded';
      
      await payment.save({ session });
      
      // Update invoice if applicable
      if (payment.invoiceId) {
        const invoice = await Invoice.findById(payment.invoiceId).session(session);
        if (invoice) {
          invoice.amountRefunded = (invoice.amountRefunded || 0) + refundDetails.amount;
          await invoice.save({ session });
        }
      }
      
      // Create credit transaction for partial refunds
      if (refundDetails.issueAsCredit) {
        await this.addCredits(
          organizationId,
          {
            amount: refundDetails.amount,
            description: `Refund for payment ${payment.referenceNumber}`,
            reason: 'refund'
          },
          adminUser
        );
      }
      
      await session.commitTransaction();
      
      // Send notifications
      await this._sendRefundNotifications(
        organization,
        payment,
        refund,
        adminUser
      );
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.REFUND_PROCESSED, adminUser, {
        organizationId,
        organizationName: organization.name,
        paymentId: payment._id,
        amount: refundDetails.amount,
        reason: refundDetails.reason
      }, 'critical');
      
      return {
        success: true,
        refund,
        payment,
        message: `Refund of ${formatCurrency(refundDetails.amount, payment.currency)} processed successfully`
      };
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error processing refund:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Override billing for organization
   * @param {String} organizationId - Organization ID
   * @param {Object} overrideDetails - Override details
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Override result
   */
  async overrideBilling(organizationId, overrideDetails, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.SUPER_ADMIN.BILLING_OVERRIDES);
      
      const organization = await HostedOrganization.findById(organizationId);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      const subscription = await Subscription.findOne({
        organizationId,
        status: { $in: ['active', 'trialing', 'past_due'] }
      });
      
      if (!subscription) {
        throw new NotFoundError('No active subscription found');
      }
      
      // Apply overrides
      const overrides = {
        customPricing: overrideDetails.customPricing,
        billingCycleOverride: overrideDetails.billingCycle,
        paymentTerms: overrideDetails.paymentTerms,
        invoicingOverride: overrideDetails.invoicing,
        exemptions: overrideDetails.exemptions || []
      };
      
      subscription.billingOverrides = overrides;
      subscription.hasCustomTerms = true;
      
      // Add override history
      subscription.overrideHistory = subscription.overrideHistory || [];
      subscription.overrideHistory.push({
        appliedAt: new Date(),
        appliedBy: adminUser._id,
        overrides,
        reason: overrideDetails.reason,
        expiresAt: overrideDetails.expiresAt
      });
      
      await subscription.save();
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.BILLING_OVERRIDE_APPLIED, adminUser, {
        organizationId,
        organizationName: organization.name,
        overrides: Object.keys(overrides)
      }, 'critical');
      
      return {
        success: true,
        subscription,
        message: 'Billing overrides applied successfully'
      };
    } catch (error) {
      logger.error('Error applying billing override:', error);
      throw error;
    }
  }

  /**
   * Get subscription analytics
   * @param {Object} filters - Analytics filters
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Subscription analytics
   */
  async getSubscriptionAnalytics(filters = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS);
      
      const dateRange = this._getDateRange(filters.period || 'month');
      
      // Aggregate subscription metrics
      const [
        revenue,
        churn,
        growth,
        planDistribution,
        paymentMetrics
      ] = await Promise.all([
        this._calculateRevenueMetrics(dateRange, filters),
        this._calculateChurnMetrics(dateRange, filters),
        this._calculateGrowthMetrics(dateRange, filters),
        this._calculatePlanDistribution(filters),
        this._calculatePaymentMetrics(dateRange, filters)
      ]);
      
      const analytics = {
        period: filters.period || 'month',
        dateRange,
        revenue,
        churn,
        growth,
        planDistribution,
        paymentMetrics,
        trends: await this._calculateSubscriptionTrends(dateRange, filters),
        forecasts: await this._generateForecasts(revenue, growth, churn),
        generatedAt: new Date()
      };
      
      // Log action
      await this.logAction(AdminEvents.SUBSCRIPTION.ANALYTICS_VIEWED, adminUser, {
        filters,
        period: analytics.period
      });
      
      return analytics;
    } catch (error) {
      logger.error('Error getting subscription analytics:', error);
      throw error;
    }
  }

  // Private helper methods

  async _getEnhancedPlanDetails(planId) {
    const plan = await SubscriptionPlan.findById(planId).lean();
    
    if (!plan) return null;
    
    // Add usage statistics
    const activeSubscriptions = await Subscription.countDocuments({
      planId: plan._id,
      status: { $in: ['active', 'trialing'] }
    });
    
    return {
      ...plan,
      statistics: {
        activeSubscriptions,
        popularityRank: await this._getPlanPopularityRank(plan._id),
        averageLifetime: await this._getAveragePlanLifetime(plan._id),
        conversionRate: await this._getPlanConversionRate(plan._id)
      }
    };
  }

  async _getBillingDetails(organizationId, subscription) {
    const thirtyDaysAgo = moment().subtract(30, 'days').toDate();
    
    const [payments, invoices] = await Promise.all([
      Payment.find({
        organizationId,
        createdAt: { $gte: thirtyDaysAgo }
      }).sort('-createdAt').limit(10).lean(),
      
      Invoice.find({
        organizationId,
        createdAt: { $gte: thirtyDaysAgo }
      }).sort('-createdAt').limit(10).lean()
    ]);
    
    return {
      recentPayments: payments,
      recentInvoices: invoices,
      nextBillingDate: subscription.currentPeriodEnd,
      billingCycle: subscription.billing.cycle,
      paymentMethod: await this._getPrimaryPaymentMethod(organizationId),
      outstandingBalance: await this._getOutstandingBalance(organizationId)
    };
  }

  async _calculateMRR(subscription) {
    if (subscription.status !== 'active') return 0;
    
    const baseAmount = subscription.billing.amount.total;
    
    // Convert to monthly if needed
    if (subscription.billing.cycle === 'yearly') {
      return baseAmount / 12;
    }
    
    return baseAmount;
  }

  async _calculateLTV(organizationId) {
    // Get all historical payments
    const payments = await Payment.find({
      organizationId,
      status: 'succeeded'
    }).lean();
    
    const totalRevenue = payments.reduce((sum, payment) => sum + payment.amount, 0);
    
    // Get subscription age
    const organization = await HostedOrganization.findById(organizationId).lean();
    const ageInMonths = moment().diff(organization.createdAt, 'months');
    
    // Calculate average monthly revenue
    const averageMonthlyRevenue = ageInMonths > 0 ? totalRevenue / ageInMonths : 0;
    
    // Estimate based on average customer lifetime (24 months default)
    const estimatedLifetime = 24;
    const estimatedLTV = averageMonthlyRevenue * estimatedLifetime;
    
    return {
      historical: totalRevenue,
      estimated: estimatedLTV,
      averageMonthlyRevenue,
      customerAgeMonths: ageInMonths
    };
  }

  async _assessChurnRisk(organization, subscription) {
    const riskFactors = [];
    let riskScore = 0;
    
    // Check payment failures
    const recentPaymentFailures = await Payment.countDocuments({
      organizationId: organization._id,
      status: 'failed',
      createdAt: { $gte: moment().subtract(90, 'days').toDate() }
    });
    
    if (recentPaymentFailures > 2) {
      riskScore += 30;
      riskFactors.push('Multiple payment failures');
    }
    
    // Check usage trends
    const usageTrend = await this._getUsageTrend(organization._id);
    if (usageTrend.trend === 'declining') {
      riskScore += 25;
      riskFactors.push('Declining usage');
    }
    
    // Check support tickets
    const recentTickets = await this._getRecentSupportTickets(organization._id);
    if (recentTickets.unresolved > 5) {
      riskScore += 20;
      riskFactors.push('Multiple unresolved support issues');
    }
    
    // Check login activity
    const lastActivity = organization.metrics?.usage?.lastActivity;
    const daysSinceActivity = lastActivity ? moment().diff(lastActivity, 'days') : 999;
    
    if (daysSinceActivity > 30) {
      riskScore += 25;
      riskFactors.push('No activity in 30+ days');
    }
    
    return {
      score: Math.min(riskScore, 100),
      level: riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : 'low',
      factors: riskFactors,
      recommendations: this._getChurnPreventionRecommendations(riskScore, riskFactors)
    };
  }

  async _validatePlanChange(currentSubscription, newPlan, changeDetails) {
    // Check if downgrade is allowed
    const currentPlanIndex = this.planHierarchy.indexOf(currentSubscription.planId.slug);
    const newPlanIndex = this.planHierarchy.indexOf(newPlan.slug);
    
    if (newPlanIndex < currentPlanIndex && !changeDetails.allowDowngrade) {
      throw new ValidationError('Downgrade not allowed without explicit permission');
    }
    
    // Check if plan change is too frequent
    const lastPlanChange = currentSubscription.planHistory?.slice(-1)[0];
    if (lastPlanChange) {
      const daysSinceLastChange = moment().diff(lastPlanChange.changedAt, 'days');
      if (daysSinceLastChange < 7 && !changeDetails.overrideFrequencyLimit) {
        throw new ValidationError('Plan changes too frequent. Please wait before changing again.');
      }
    }
    
    // Validate custom pricing if applicable
    if (changeDetails.customPricing) {
      if (!changeDetails.customPricing.amount || changeDetails.customPricing.amount < 0) {
        throw new ValidationError('Invalid custom pricing amount');
      }
    }
  }

  async _calculatePlanChangeProration(currentSubscription, newPlan, effectiveDate) {
    const now = effectiveDate || new Date();
    const periodStart = currentSubscription.currentPeriodStart;
    const periodEnd = currentSubscription.currentPeriodEnd;
    
    // Calculate days remaining in current period
    const totalDays = moment(periodEnd).diff(periodStart, 'days');
    const remainingDays = moment(periodEnd).diff(now, 'days');
    const usedDays = totalDays - remainingDays;
    
    // Calculate prorated amounts
    const currentPlanDailyRate = currentSubscription.billing.amount.total / totalDays;
    const newPlanDailyRate = newPlan.pricing[currentSubscription.billing.cycle] / totalDays;
    
    const unusedCredit = currentPlanDailyRate * remainingDays;
    const newPlanCharge = newPlanDailyRate * remainingDays;
    
    return {
      credits: unusedCredit,
      charges: newPlanCharge,
      amount: newPlanCharge - unusedCredit,
      details: {
        totalDays,
        usedDays,
        remainingDays,
        currentPlanDailyRate,
        newPlanDailyRate
      }
    };
  }

  async _processStripeRefund(payment, refundDetails) {
    try {
      const refund = await stripe.refunds.create({
        payment_intent: payment.providerPaymentId,
        amount: Math.round(refundDetails.amount * 100), // Convert to cents
        reason: refundDetails.reason,
        metadata: {
          organizationId: payment.organizationId.toString(),
          adminUserId: refundDetails.processedBy,
          internalReason: refundDetails.internalReason
        }
      });
      
      return {
        id: refund.id,
        status: refund.status,
        providerRefundId: refund.id
      };
    } catch (error) {
      logger.error('Stripe refund error:', error);
      throw new AppError('Failed to process refund through payment provider', 500);
    }
  }

  async _calculateRevenueMetrics(dateRange, filters) {
    const matchStage = {
      createdAt: { $gte: dateRange.start, $lte: dateRange.end },
      status: 'succeeded'
    };
    
    if (filters.organizationId) {
      matchStage.organizationId = filters.organizationId;
    }
    
    const revenue = await Payment.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$createdAt' }
          },
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    const totalRevenue = revenue.reduce((sum, day) => sum + day.total, 0);
    const averageDailyRevenue = totalRevenue / revenue.length || 0;
    
    return {
      total: totalRevenue,
      daily: revenue,
      average: averageDailyRevenue,
      growth: await this._calculateRevenueGrowth(dateRange)
    };
  }

  async _getChurnPreventionRecommendations(riskScore, riskFactors) {
    const recommendations = [];
    
    if (riskScore >= 70) {
      recommendations.push({
        priority: 'urgent',
        action: 'Schedule immediate retention call',
        description: 'High churn risk detected. Immediate intervention recommended.'
      });
    }
    
    if (riskFactors.includes('Multiple payment failures')) {
      recommendations.push({
        priority: 'high',
        action: 'Update payment method',
        description: 'Reach out to update payment information and prevent service disruption.'
      });
    }
    
    if (riskFactors.includes('Declining usage')) {
      recommendations.push({
        priority: 'medium',
        action: 'Offer training or onboarding session',
        description: 'Re-engage customer with product value and features.'
      });
    }
    
    return recommendations;
  }

  async _clearSubscriptionCaches(organizationId) {
    const patterns = [
      `${this.cachePrefix}:${organizationId}:*`,
      `subscription:${organizationId}:*`,
      `billing:${organizationId}:*`
    ];
    
    await Promise.all(patterns.map(pattern => this.cache.deletePattern(pattern)));
  }
}

module.exports = new SubscriptionManagementService();