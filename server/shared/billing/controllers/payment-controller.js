// server/shared/billing/controllers/payment-controller.js
/**
 * @file Payment Controller
 * @description Controller for handling payment-related API endpoints
 * @version 3.0.0
 */

const Payment = require('../models/payment-model');
const BillingService = require('../services/billing-service');
const PaymentGatewayService = require('../services/payment-gateway-service');
const { ValidationError, NotFoundError, ForbiddenError } = require('../../utils/app-error');
const { asyncHandler } = require('../../utils/async-handler');
const logger = require('../../utils/logger');
const constants = require('../../config/constants');

/**
 * Payment Controller Class
 * @class PaymentController
 */
class PaymentController {
  /**
   * Get user's payment history
   * @route GET /api/v1/billing/payments
   */
  static getPayments = asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 20,
      status,
      type,
      startDate,
      endDate,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;
    
    const query = {
      userId: req.user._id
    };
    
    // Add filters
    if (status) query.status = status;
    if (type) query.type = type;
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const skip = (page - 1) * limit;
    const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
    
    const [payments, total] = await Promise.all([
      Payment.find(query)
        .sort(sort)
        .limit(parseInt(limit))
        .skip(skip)
        .populate('invoiceId', 'invoiceNumber')
        .populate('subscriptionId', 'planId'),
      Payment.countDocuments(query)
    ]);
    
    return res.status(200).json({
      status: 'success',
      data: {
        payments,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      }
    });
  });
  
  /**
   * Get payment details
   * @route GET /api/v1/billing/payments/:paymentId
   */
  static getPaymentById = asyncHandler(async (req, res) => {
    const { paymentId } = req.params;
    
    if (!paymentId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid payment ID format');
    }
    
    const payment = await Payment.findById(paymentId)
      .populate('userId', 'firstName lastName email')
      .populate('invoiceId')
      .populate('subscriptionId');
    
    if (!payment) {
      throw new NotFoundError('Payment not found');
    }
    
    // Check ownership or admin
    if (payment.userId._id.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    return res.status(200).json({
      status: 'success',
      data: { payment }
    });
  });
  
  /**
   * Process one-time payment
   * @route POST /api/v1/billing/payments
   */
  static processPayment = asyncHandler(async (req, res) => {
    const {
      amount,
      currency = 'USD',
      paymentMethod,
      description,
      invoiceId,
      metadata
    } = req.body;
    
    // Validate required fields
    if (!amount || amount <= 0) {
      throw new ValidationError('Valid amount is required');
    }
    
    if (!paymentMethod || !paymentMethod.type) {
      throw new ValidationError('Payment method is required');
    }
    
    // Create payment record
    const payment = new Payment({
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      invoiceId,
      type: 'payment',
      status: 'pending',
      amount: {
        value: amount,
        currency
      },
      method: {
        type: paymentMethod.type,
        ...BillingService.extractPaymentDetails(paymentMethod)
      },
      gateway: {
        provider: BillingService.getGatewayProvider(paymentMethod.type)
      },
      source: {
        type: 'manual',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      },
      customer: {
        name: `${req.user.firstName} ${req.user.lastName}`,
        email: req.user.email
      },
      metadata: {
        ...metadata,
        notes: description
      }
    });
    
    await payment.save();
    
    // Process payment through gateway
    try {
      await payment.process();
      const result = await PaymentGatewayService.processPayment(payment, paymentMethod);
      
      if (result.success) {
        await payment.markAsSucceeded(result.response);
        
        // Update invoice if linked
        if (invoiceId) {
          const Invoice = require('../models/invoice-model');
          const invoice = await Invoice.findById(invoiceId);
          if (invoice) {
            await invoice.applyPayment({
              amount: payment.amount.value,
              method: payment.method.type,
              transactionId: payment.gateway.transactionId
            });
          }
        }
        
        return res.status(200).json({
          status: 'success',
          data: { 
            payment: {
              id: payment._id,
              status: payment.status,
              amount: payment.amount,
              receiptUrl: result.response.receiptUrl
            }
          },
          message: 'Payment processed successfully'
        });
      } else if (result.requiresAction) {
        payment.status = 'requires_action';
        await payment.save();
        
        return res.status(200).json({
          status: 'requires_action',
          data: {
            payment: {
              id: payment._id,
              status: payment.status,
              clientSecret: result.clientSecret
            }
          },
          message: result.error.message
        });
      } else {
        await payment.markAsFailed(result.error);
        
        return res.status(400).json({
          status: 'error',
          message: result.error.message,
          error: result.error
        });
      }
    } catch (error) {
      await payment.markAsFailed({
        code: 'processing_error',
        message: error.message
      });
      
      throw error;
    }
  });
  
  /**
   * Confirm payment (for 3D Secure or additional authentication)
   * @route POST /api/v1/billing/payments/:paymentId/confirm
   */
  static confirmPayment = asyncHandler(async (req, res) => {
    const { paymentId } = req.params;
    const { paymentIntentId } = req.body;
    
    if (!paymentId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid payment ID format');
    }
    
    const payment = await Payment.findById(paymentId);
    
    if (!payment) {
      throw new NotFoundError('Payment not found');
    }
    
    // Check ownership
    if (payment.userId.toString() !== req.user._id.toString()) {
      throw new ForbiddenError('Access denied');
    }
    
    if (payment.status !== 'requires_action') {
      throw new ValidationError('Payment does not require confirmation');
    }
    
    // Confirm payment with gateway
    try {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
      
      if (paymentIntent.status === 'succeeded') {
        await payment.markAsSucceeded({
          transactionId: paymentIntent.id,
          status: 'succeeded',
          amount: paymentIntent.amount / 100,
          currency: paymentIntent.currency
        });
        
        return res.status(200).json({
          status: 'success',
          data: { payment },
          message: 'Payment confirmed successfully'
        });
      } else {
        throw new Error('Payment confirmation failed');
      }
    } catch (error) {
      await payment.markAsFailed({
        code: 'confirmation_failed',
        message: error.message
      });
      
      throw error;
    }
  });
  
  /**
   * Process refund
   * @route POST /api/v1/billing/payments/:paymentId/refund
   */
  static processRefund = asyncHandler(async (req, res) => {
    const { paymentId } = req.params;
    const { amount, reason, description } = req.body;
    
    if (!paymentId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid payment ID format');
    }
    
    if (!reason) {
      throw new ValidationError('Refund reason is required');
    }
    
    const payment = await Payment.findById(paymentId);
    
    if (!payment) {
      throw new NotFoundError('Payment not found');
    }
    
    // Check if user can refund (admin or within refund period)
    const refundPeriodDays = 30;
    const daysSincePayment = Math.floor((Date.now() - payment.createdAt) / (1000 * 60 * 60 * 24));
    
    if (!req.user.isAdmin && daysSincePayment > refundPeriodDays) {
      throw new ForbiddenError('Refund period has expired');
    }
    
    if (!payment.isRefundable) {
      throw new ValidationError('Payment is not refundable');
    }
    
    const refundData = {
      amount,
      reason,
      description,
      requestedBy: req.user._id
    };
    
    // Process refund through service
    try {
      const refundResult = await PaymentGatewayService.processRefund(payment, refundData);
      
      if (refundResult.success) {
        await payment.processRefund({
          ...refundData,
          refundId: refundResult.refundId
        });
        
        // Update invoice if linked
        if (payment.invoiceId) {
          const Invoice = require('../models/invoice-model');
          const invoice = await Invoice.findById(payment.invoiceId);
          if (invoice) {
            invoice.status = amount >= payment.amount.value ? 'refunded' : 'partial';
            await invoice.save();
          }
        }
        
        return res.status(200).json({
          status: 'success',
          data: { 
            payment,
            refund: {
              id: refundResult.refundId,
              amount: refundResult.amount,
              status: refundResult.status
            }
          },
          message: 'Refund processed successfully'
        });
      } else {
        throw new Error(refundResult.error?.message || 'Refund processing failed');
      }
    } catch (error) {
      logger.error('Refund processing error', { error, paymentId });
      throw error;
    }
  });
  
  /**
   * Get payment methods
   * @route GET /api/v1/billing/payment-methods
   */
  static getPaymentMethods = asyncHandler(async (req, res) => {
    // This would typically fetch saved payment methods from Stripe or other gateway
    const paymentMethods = [];
    
    // If user has Stripe customer ID, fetch their saved methods
    if (req.user.external?.stripeCustomerId) {
      try {
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        const methods = await stripe.paymentMethods.list({
          customer: req.user.external.stripeCustomerId,
          type: 'card'
        });
        
        paymentMethods.push(...methods.data.map(method => ({
          id: method.id,
          type: 'card',
          brand: method.card.brand,
          last4: method.card.last4,
          expMonth: method.card.exp_month,
          expYear: method.card.exp_year,
          isDefault: method.id === req.user.defaultPaymentMethod
        })));
      } catch (error) {
        logger.error('Error fetching payment methods', { error });
      }
    }
    
    return res.status(200).json({
      status: 'success',
      data: { 
        paymentMethods,
        count: paymentMethods.length
      }
    });
  });
  
  /**
   * Add payment method
   * @route POST /api/v1/billing/payment-methods
   */
  static addPaymentMethod = asyncHandler(async (req, res) => {
    const { paymentMethodId, type = 'card', setAsDefault = false } = req.body;
    
    if (!paymentMethodId) {
      throw new ValidationError('Payment method ID is required');
    }
    
    try {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      
      // Create or get Stripe customer
      let customerId = req.user.external?.stripeCustomerId;
      
      if (!customerId) {
        const customer = await PaymentGatewayService.createCustomer('stripe', {
          userId: req.user._id,
          email: req.user.email,
          name: `${req.user.firstName} ${req.user.lastName}`,
          phone: req.user.phone
        });
        
        customerId = customer.customerId;
        
        // Save customer ID to user
        req.user.external = req.user.external || {};
        req.user.external.stripeCustomerId = customerId;
        await req.user.save();
      }
      
      // Attach payment method to customer
      await stripe.paymentMethods.attach(paymentMethodId, {
        customer: customerId
      });
      
      // Set as default if requested
      if (setAsDefault) {
        await stripe.customers.update(customerId, {
          invoice_settings: {
            default_payment_method: paymentMethodId
          }
        });
        
        req.user.defaultPaymentMethod = paymentMethodId;
        await req.user.save();
      }
      
      return res.status(201).json({
        status: 'success',
        message: 'Payment method added successfully'
      });
    } catch (error) {
      logger.error('Add payment method error', { error });
      throw new ValidationError(error.message);
    }
  });
  
  /**
   * Remove payment method
   * @route DELETE /api/v1/billing/payment-methods/:paymentMethodId
   */
  static removePaymentMethod = asyncHandler(async (req, res) => {
    const { paymentMethodId } = req.params;
    
    try {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      
      // Detach payment method
      await stripe.paymentMethods.detach(paymentMethodId);
      
      // Update user if this was default
      if (req.user.defaultPaymentMethod === paymentMethodId) {
        req.user.defaultPaymentMethod = null;
        await req.user.save();
      }
      
      return res.status(200).json({
        status: 'success',
        message: 'Payment method removed successfully'
      });
    } catch (error) {
      logger.error('Remove payment method error', { error });
      throw new ValidationError(error.message);
    }
  });
  
  /**
   * Get payment statistics
   * @route GET /api/v1/billing/payments/statistics
   */
  static getPaymentStatistics = asyncHandler(async (req, res) => {
    const { startDate, endDate } = req.query;
    
    const filters = {
      userId: req.user._id
    };
    
    if (startDate) filters.startDate = new Date(startDate);
    if (endDate) filters.endDate = new Date(endDate);
    
    const stats = await Payment.getStatistics(filters);
    
    return res.status(200).json({
      status: 'success',
      data: { statistics: stats }
    });
  });
  
  /**
   * Handle payment webhook
   * @route POST /api/v1/billing/webhooks/:provider
   */
  static handleWebhook = asyncHandler(async (req, res) => {
    const { provider } = req.params;
    const { headers, body: rawBody } = req;
    
    // Validate webhook
    const validation = await PaymentGatewayService.validateWebhook(
      provider,
      headers,
      rawBody
    );
    
    if (!validation.valid) {
      logger.warn('Invalid webhook received', { provider, error: validation.error });
      return res.status(400).json({
        status: 'error',
        message: 'Invalid webhook signature'
      });
    }
    
    const event = validation.event;
    
    try {
      switch (event.type) {
        case 'payment_intent.succeeded':
          await this.handlePaymentSucceeded(event.data.object);
          break;
          
        case 'payment_intent.payment_failed':
          await this.handlePaymentFailed(event.data.object);
          break;
          
        case 'charge.refunded':
          await this.handleRefundProcessed(event.data.object);
          break;
          
        case 'charge.dispute.created':
          await this.handleDisputeCreated(event.data.object);
          break;
          
        case 'invoice.payment_succeeded':
          await this.handleInvoicePaymentSucceeded(event.data.object);
          break;
          
        case 'invoice.payment_failed':
          await this.handleInvoicePaymentFailed(event.data.object);
          break;
          
        case 'subscription.updated':
          await this.handleSubscriptionUpdated(event.data.object);
          break;
          
        case 'subscription.deleted':
          await this.handleSubscriptionDeleted(event.data.object);
          break;
          
        default:
          logger.info('Unhandled webhook event', { type: event.type });
      }
      
      return res.status(200).json({ received: true });
      
    } catch (error) {
      logger.error('Webhook processing error', { error, event });
      return res.status(500).json({
        status: 'error',
        message: 'Webhook processing failed'
      });
    }
  });
  
  /**
   * Webhook handlers
   */
  static async handlePaymentSucceeded(paymentIntent) {
    const payment = await Payment.getByGatewayTransactionId(
      paymentIntent.id,
      'stripe'
    );
    
    if (payment && payment.status !== 'succeeded') {
      await payment.markAsSucceeded({
        transactionId: paymentIntent.id,
        status: 'succeeded',
        amount: paymentIntent.amount / 100,
        currency: paymentIntent.currency,
        receiptUrl: paymentIntent.charges.data[0]?.receipt_url
      });
    }
  }
  
  static async handlePaymentFailed(paymentIntent) {
    const payment = await Payment.getByGatewayTransactionId(
      paymentIntent.id,
      'stripe'
    );
    
    if (payment && payment.status !== 'failed') {
      await payment.markAsFailed({
        code: paymentIntent.last_payment_error?.code,
        message: paymentIntent.last_payment_error?.message
      });
    }
  }
  
  static async handleRefundProcessed(charge) {
    const payment = await Payment.getByGatewayTransactionId(
      charge.payment_intent,
      'stripe'
    );
    
    if (payment && charge.refunded) {
      const refundAmount = charge.amount_refunded / 100;
      payment.refund.processedAt = new Date();
      payment.refund.amount = refundAmount;
      
      if (refundAmount >= payment.amount.value) {
        payment.status = 'refunded';
      }
      
      await payment.save();
    }
  }
  
  static async handleDisputeCreated(dispute) {
    const payment = await Payment.getByGatewayTransactionId(
      dispute.payment_intent,
      'stripe'
    );
    
    if (payment) {
      await payment.addDispute({
        status: dispute.status,
        reason: dispute.reason,
        amount: dispute.amount / 100,
        currency: dispute.currency,
        dueBy: new Date(dispute.evidence_details.due_by * 1000)
      });
    }
  }
  
  static async handleInvoicePaymentSucceeded(invoice) {
    // Handle subscription renewal payments
    logger.info('Invoice payment succeeded', { invoiceId: invoice.id });
  }
  
  static async handleInvoicePaymentFailed(invoice) {
    // Handle subscription payment failures
    logger.warn('Invoice payment failed', { invoiceId: invoice.id });
  }
  
  static async handleSubscriptionUpdated(subscription) {
    // Handle subscription updates from gateway
    logger.info('Subscription updated', { subscriptionId: subscription.id });
  }
  
  static async handleSubscriptionDeleted(subscription) {
    // Handle subscription cancellations from gateway
    logger.info('Subscription deleted', { subscriptionId: subscription.id });
  }
}

module.exports = PaymentController;