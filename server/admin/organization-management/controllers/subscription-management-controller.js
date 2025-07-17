// server/admin/organization-management/controllers/subscription-management-controller.js
/**
 * @file Subscription Management Controller
 * @description Controller for managing organization subscriptions and billing
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const SubscriptionManagementService = require('../services/subscription-management-service');
const OrganizationAnalyticsService = require('../services/organization-analytics-service');
const AdminOrganizationService = require('../services/admin-organization-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizer');
const ResponseFormatter = require('../../../shared/utils/response-formatter');

// Validation
const {
  validatePlanChange,
  validateSubscriptionCancel,
  validateReactivation,
  validateDiscount,
  validateCredit,
  validateRefund,
  validateBillingOverride,
  validatePaymentMethodUpdate
} = require('../validation/subscription-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * Subscription Management Controller Class
 * @class SubscriptionManagementController
 */
class SubscriptionManagementController {
  /**
   * Get subscription details
   * @route GET /api/admin/subscriptions/:organizationId
   * @access Admin
   */
  getSubscriptionDetails = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const options = {
        includeUsage: req.query.includeUsage === 'true',
        includeHistory: req.query.includeHistory === 'true',
        includePaymentMethods: req.query.includePaymentMethods === 'true',
        includeUpcoming: req.query.includeUpcoming === 'true'
      };
      
      const subscriptionDetails = await SubscriptionManagementService.getSubscriptionDetails(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          subscriptionDetails,
          'Subscription details retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getSubscriptionDetails:', error);
      next(error);
    }
  });

  /**
   * Change subscription plan
   * @route POST /api/admin/subscriptions/:organizationId/change-plan
   * @access Admin - Platform Admin or higher
   */
  changeSubscriptionPlan = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate plan change request
      const { error, value } = validatePlanChange(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const planChange = sanitizeBody(value);
      
      const options = {
        skipProration: req.body.skipProration || false,
        skipNotifications: req.body.skipNotifications || false,
        applyCredits: req.body.applyCredits !== false,
        effectiveImmediately: req.body.effectiveImmediately || false
      };
      
      const updatedSubscription = await SubscriptionManagementService.changeSubscriptionPlan(
        organizationId,
        planChange,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          updatedSubscription,
          'Subscription plan changed successfully'
        )
      );
    } catch (error) {
      logger.error('Error in changeSubscriptionPlan:', error);
      next(error);
    }
  });

  /**
   * Cancel subscription
   * @route POST /api/admin/subscriptions/:organizationId/cancel
   * @access Admin - Platform Admin or higher
   */
  cancelSubscription = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate cancellation request
      const { error, value } = validateSubscriptionCancel(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const cancellationDetails = sanitizeBody(value);
      
      const options = {
        skipNotifications: req.body.skipNotifications || false,
        preserveData: req.body.preserveData !== false,
        allowReactivation: req.body.allowReactivation !== false
      };
      
      const result = await SubscriptionManagementService.cancelSubscription(
        organizationId,
        cancellationDetails,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Subscription cancelled successfully'
        )
      );
    } catch (error) {
      logger.error('Error in cancelSubscription:', error);
      next(error);
    }
  });

  /**
   * Reactivate subscription
   * @route POST /api/admin/subscriptions/:organizationId/reactivate
   * @access Admin - Platform Admin or higher
   */
  reactivateSubscription = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate reactivation request
      const { error, value } = validateReactivation(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const reactivationDetails = sanitizeBody(value);
      
      const subscription = await SubscriptionManagementService.reactivateSubscription(
        organizationId,
        reactivationDetails,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          subscription,
          'Subscription reactivated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in reactivateSubscription:', error);
      next(error);
    }
  });

  /**
   * Apply discount to subscription
   * @route POST /api/admin/subscriptions/:organizationId/apply-discount
   * @access Admin - Platform Admin or higher
   */
  applyDiscount = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate discount details
      const { error, value } = validateDiscount(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const discountDetails = sanitizeBody(value);
      
      const subscription = await SubscriptionManagementService.applyDiscount(
        organizationId,
        discountDetails,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          subscription,
          'Discount applied successfully'
        )
      );
    } catch (error) {
      logger.error('Error in applyDiscount:', error);
      next(error);
    }
  });

  /**
   * Remove discount from subscription
   * @route DELETE /api/admin/subscriptions/:organizationId/discount/:discountId
   * @access Admin - Platform Admin or higher
   */
  removeDiscount = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId, discountId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const subscription = await SubscriptionManagementService.removeDiscount(
        organizationId,
        discountId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          subscription,
          'Discount removed successfully'
        )
      );
    } catch (error) {
      logger.error('Error in removeDiscount:', error);
      next(error);
    }
  });

  /**
   * Add credits to organization
   * @route POST /api/admin/subscriptions/:organizationId/add-credits
   * @access Admin - Platform Admin or higher
   */
  addCredits = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate credit details
      const { error, value } = validateCredit(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const creditDetails = sanitizeBody(value);
      
      const result = await SubscriptionManagementService.addCredits(
        organizationId,
        creditDetails,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Credits added successfully'
        )
      );
    } catch (error) {
      logger.error('Error in addCredits:', error);
      next(error);
    }
  });

  /**
   * Process refund
   * @route POST /api/admin/subscriptions/:organizationId/refund
   * @access Admin - Platform Admin or higher, Super Admin for high-value
   */
  processRefund = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate refund details
      const { error, value } = validateRefund(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const refundDetails = sanitizeBody(value);
      
      const result = await SubscriptionManagementService.processRefund(
        organizationId,
        refundDetails,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Refund processed successfully'
        )
      );
    } catch (error) {
      logger.error('Error in processRefund:', error);
      next(error);
    }
  });

  /**
   * Override billing settings
   * @route POST /api/admin/subscriptions/:organizationId/billing-override
   * @access Admin - Super Admin only
   */
  overrideBilling = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate billing override
      const { error, value } = validateBillingOverride(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const overrideDetails = sanitizeBody(value);
      
      const result = await SubscriptionManagementService.overrideBilling(
        organizationId,
        overrideDetails,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Billing override applied successfully'
        )
      );
    } catch (error) {
      logger.error('Error in overrideBilling:', error);
      next(error);
    }
  });

  /**
   * Get subscription analytics
   * @route GET /api/admin/subscriptions/analytics
   * @access Admin
   */
  getSubscriptionAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      const filters = {
        period: query.period || 'month',
        startDate: query.startDate,
        endDate: query.endDate,
        planType: query.planType,
        organizationId: query.organizationId,
        includeChurn: query.includeChurn !== 'false',
        includeForecasts: query.includeForecasts === 'true'
      };
      
      const analytics = await SubscriptionManagementService.getSubscriptionAnalytics(
        filters,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          analytics,
          'Subscription analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getSubscriptionAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get payment history
   * @route GET /api/admin/subscriptions/:organizationId/payments
   * @access Admin
   */
  getPaymentHistory = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      const query = sanitizeQuery(req.query);
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const filters = {
        startDate: query.startDate,
        endDate: query.endDate,
        status: query.status,
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 20
      };
      
      const payments = await SubscriptionManagementService.getPaymentHistory(
        organizationId,
        filters,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          payments,
          'Payment history retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getPaymentHistory:', error);
      next(error);
    }
  });

  /**
   * Get invoices
   * @route GET /api/admin/subscriptions/:organizationId/invoices
   * @access Admin
   */
  getInvoices = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      const query = sanitizeQuery(req.query);
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const filters = {
        status: query.status,
        startDate: query.startDate,
        endDate: query.endDate,
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 20
      };
      
      const invoices = await SubscriptionManagementService.getInvoices(
        organizationId,
        filters,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          invoices,
          'Invoices retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getInvoices:', error);
      next(error);
    }
  });

  /**
   * Generate invoice
   * @route POST /api/admin/subscriptions/:organizationId/generate-invoice
   * @access Admin - Platform Admin or higher
   */
  generateInvoice = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const invoiceConfig = {
        items: req.body.items,
        description: req.body.description,
        dueDate: req.body.dueDate,
        sendEmail: req.body.sendEmail !== false
      };
      
      const invoice = await SubscriptionManagementService.generateInvoice(
        organizationId,
        invoiceConfig,
        req.user
      );
      
      res.status(201).json(
        ResponseFormatter.success(
          invoice,
          'Invoice generated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in generateInvoice:', error);
      next(error);
    }
  });

  /**
   * Update payment method
   * @route PUT /api/admin/subscriptions/:organizationId/payment-method
   * @access Admin - Platform Admin or higher
   */
  updatePaymentMethod = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate payment method update
      const { error, value } = validatePaymentMethodUpdate(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const paymentMethodDetails = sanitizeBody(value);
      
      const result = await SubscriptionManagementService.updatePaymentMethod(
        organizationId,
        paymentMethodDetails,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Payment method updated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in updatePaymentMethod:', error);
      next(error);
    }
  });

  /**
   * Retry failed payment
   * @route POST /api/admin/subscriptions/:organizationId/retry-payment
   * @access Admin - Platform Admin or higher
   */
  retryFailedPayment = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      const { paymentId } = req.body;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      if (!paymentId) {
        throw new ValidationError('Payment ID is required');
      }
      
      const result = await SubscriptionManagementService.retryFailedPayment(
        organizationId,
        paymentId,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Payment retry initiated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in retryFailedPayment:', error);
      next(error);
    }
  });

  /**
   * Extend trial period
   * @route POST /api/admin/subscriptions/:organizationId/extend-trial
   * @access Admin - Platform Admin or higher
   */
  extendTrial = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      const { days, reason } = req.body;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      if (!days || days < 1 || days > 30) {
        throw new ValidationError('Trial extension must be between 1 and 30 days');
      }
      
      const result = await SubscriptionManagementService.extendTrial(
        organizationId,
        days,
        reason,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Trial period extended successfully'
        )
      );
    } catch (error) {
      logger.error('Error in extendTrial:', error);
      next(error);
    }
  });

  /**
   * Get subscription history
   * @route GET /api/admin/subscriptions/:organizationId/history
   * @access Admin
   */
  getSubscriptionHistory = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      const query = sanitizeQuery(req.query);
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const options = {
        includePlanChanges: query.includePlanChanges !== 'false',
        includeStatusChanges: query.includeStatusChanges !== 'false',
        includePayments: query.includePayments === 'true',
        startDate: query.startDate,
        endDate: query.endDate
      };
      
      const history = await SubscriptionManagementService.getSubscriptionHistory(
        organizationId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          history,
          'Subscription history retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getSubscriptionHistory:', error);
      next(error);
    }
  });

  /**
   * Get credit balance and transactions
   * @route GET /api/admin/subscriptions/:organizationId/credits
   * @access Admin
   */
  getCreditTransactions = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      const query = sanitizeQuery(req.query);
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const filters = {
        type: query.type,
        startDate: query.startDate,
        endDate: query.endDate,
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 20
      };
      
      const credits = await SubscriptionManagementService.getCreditTransactions(
        organizationId,
        filters,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          credits,
          'Credit transactions retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getCreditTransactions:', error);
      next(error);
    }
  });

  /**
   * Bulk update subscriptions
   * @route POST /api/admin/subscriptions/bulk/update
   * @access Admin - Super Admin only
   */
  bulkUpdateSubscriptions = asyncHandler(async (req, res, next) => {
    try {
      const { organizationIds, updates } = req.body;
      
      if (!Array.isArray(organizationIds) || organizationIds.length === 0) {
        throw new ValidationError('Organization IDs array is required');
      }
      
      // Validate all organization IDs
      organizationIds.forEach(id => {
        if (!mongoose.isValidObjectId(id)) {
          throw new ValidationError(`Invalid organization ID: ${id}`);
        }
      });
      
      const options = {
        skipFailures: req.body.skipFailures || false,
        applyDiscounts: req.body.applyDiscounts || false,
        notifyUsers: req.body.notifyUsers !== false
      };
      
      const results = await SubscriptionManagementService.bulkUpdateSubscriptions(
        organizationIds,
        updates,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          results,
          'Bulk subscription update completed'
        )
      );
    } catch (error) {
      logger.error('Error in bulkUpdateSubscriptions:', error);
      next(error);
    }
  });

  /**
   * Get subscription revenue report
   * @route GET /api/admin/subscriptions/revenue-report
   * @access Admin
   */
  getRevenueReport = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      const reportConfig = {
        period: query.period || 'month',
        startDate: query.startDate,
        endDate: query.endDate,
        groupBy: query.groupBy || 'day',
        includePlans: query.includePlans === 'true',
        includeChurn: query.includeChurn === 'true',
        includeForecasts: query.includeForecasts === 'true'
      };
      
      const report = await SubscriptionManagementService.getRevenueReport(
        reportConfig,
        req.user
      );
      
      // Handle export formats
      if (query.format === 'csv') {
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="revenue_report_${Date.now()}.csv"`);
        res.send(report.csvData);
      } else {
        res.status(200).json(
          ResponseFormatter.success(
            report,
            'Revenue report generated successfully'
          )
        );
      }
    } catch (error) {
      logger.error('Error in getRevenueReport:', error);
      next(error);
    }
  });

  /**
   * Get dunning management overview
   * @route GET /api/admin/subscriptions/dunning
   * @access Admin
   */
  getDunningOverview = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      const filters = {
        status: query.status,
        stage: query.stage,
        daysOverdue: query.daysOverdue ? parseInt(query.daysOverdue) : null,
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 20
      };
      
      const dunning = await SubscriptionManagementService.getDunningOverview(
        filters,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          dunning,
          'Dunning overview retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getDunningOverview:', error);
      next(error);
    }
  });

  /**
   * Process dunning action
   * @route POST /api/admin/subscriptions/:organizationId/dunning-action
   * @access Admin - Platform Admin or higher
   */
  processDunningAction = asyncHandler(async (req, res, next) => {
    try {
      const { organizationId } = req.params;
      const { action, notes } = req.body;
      
      if (!mongoose.isValidObjectId(organizationId)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const validActions = ['retry_payment', 'send_reminder', 'escalate', 'suspend', 'cancel'];
      if (!validActions.includes(action)) {
        throw new ValidationError('Invalid dunning action');
      }
      
      const result = await SubscriptionManagementService.processDunningAction(
        organizationId,
        action,
        notes,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Dunning action processed successfully'
        )
      );
    } catch (error) {
      logger.error('Error in processDunningAction:', error);
      next(error);
    }
  });
}

module.exports = new SubscriptionManagementController();