// server/shared/billing/services/payment-gateway-service.js
/**
 * @file Payment Gateway Service
 * @description Service for handling payment gateway integrations (Stripe, PayPal, etc.)
 * @version 3.0.0
 */

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const paypal = require('@paypal/checkout-server-sdk');
const logger = require('../../utils/logger');
const { PaymentError } = require('../../utils/app-error');
const config = require('../../config');

// PayPal Environment Configuration
const paypalEnvironment = process.env.NODE_ENV === 'production'
  ? new paypal.core.LiveEnvironment(
      process.env.PAYPAL_CLIENT_ID,
      process.env.PAYPAL_CLIENT_SECRET
    )
  : new paypal.core.SandboxEnvironment(
      process.env.PAYPAL_CLIENT_ID,
      process.env.PAYPAL_CLIENT_SECRET
    );

const paypalClient = new paypal.core.PayPalHttpClient(paypalEnvironment);

/**
 * Payment Gateway Service Class
 * @class PaymentGatewayService
 */
class PaymentGatewayService {
  /**
   * Process payment through appropriate gateway
   * @param {Object} payment - Payment object
   * @param {Object} paymentMethod - Payment method details
   * @returns {Promise<Object>} Processing result
   */
  static async processPayment(payment, paymentMethod) {
    try {
      const gateway = payment.gateway.provider;
      
      switch (gateway) {
        case 'stripe':
          return await this.processStripePayment(payment, paymentMethod);
          
        case 'paypal':
          return await this.processPayPalPayment(payment, paymentMethod);
          
        case 'manual':
          return await this.processManualPayment(payment, paymentMethod);
          
        default:
          throw new PaymentError(`Unsupported payment gateway: ${gateway}`);
      }
      
    } catch (error) {
      logger.error('Process payment error', { error, paymentId: payment._id });
      
      return {
        success: false,
        error: {
          code: error.code || 'payment_processing_error',
          message: error.message || 'Payment processing failed',
          details: error.details
        }
      };
    }
  }
  
  /**
   * Process Stripe payment
   * @param {Object} payment - Payment object
   * @param {Object} paymentMethod - Payment method details
   * @returns {Promise<Object>} Stripe payment result
   */
  static async processStripePayment(payment, paymentMethod) {
    try {
      let paymentIntent;
      
      // Create or retrieve payment intent
      if (payment.gateway.transactionId) {
        paymentIntent = await stripe.paymentIntents.retrieve(
          payment.gateway.transactionId
        );
      } else {
        // Create payment intent
        const params = {
          amount: Math.round(payment.amount.value * 100), // Convert to cents
          currency: payment.amount.currency.toLowerCase(),
          payment_method: paymentMethod.stripePaymentMethodId,
          confirmation_method: 'automatic',
          confirm: true,
          description: `Payment for subscription ${payment.subscriptionId}`,
          metadata: {
            paymentId: payment._id.toString(),
            userId: payment.userId.toString(),
            subscriptionId: payment.subscriptionId?.toString()
          },
          receipt_email: payment.customer.email,
          capture_method: 'automatic'
        };
        
        // Add customer ID if available
        if (payment.external?.stripeCustomerId) {
          params.customer = payment.external.stripeCustomerId;
        }
        
        // Add statement descriptor
        params.statement_descriptor = config.billing.statementDescriptor || 'INSIGHTSERENITY';
        
        paymentIntent = await stripe.paymentIntents.create(params);
      }
      
      // Handle payment intent status
      if (paymentIntent.status === 'succeeded') {
        return {
          success: true,
          response: {
            transactionId: paymentIntent.id,
            status: 'succeeded',
            amount: paymentIntent.amount / 100,
            currency: paymentIntent.currency,
            receiptUrl: paymentIntent.charges.data[0]?.receipt_url,
            raw: paymentIntent
          }
        };
      } else if (paymentIntent.status === 'requires_action') {
        return {
          success: false,
          requiresAction: true,
          clientSecret: paymentIntent.client_secret,
          error: {
            code: 'requires_authentication',
            message: '3D Secure authentication required'
          }
        };
      } else {
        return {
          success: false,
          error: {
            code: paymentIntent.status,
            message: 'Payment intent not successful',
            details: paymentIntent.last_payment_error
          }
        };
      }
      
    } catch (error) {
      logger.error('Stripe payment error', { error });
      
      return {
        success: false,
        error: {
          code: error.code || 'stripe_error',
          message: error.message,
          type: error.type,
          declineCode: error.decline_code
        }
      };
    }
  }
  
  /**
   * Process PayPal payment
   * @param {Object} payment - Payment object
   * @param {Object} paymentMethod - Payment method details
   * @returns {Promise<Object>} PayPal payment result
   */
  static async processPayPalPayment(payment, paymentMethod) {
    try {
      // Create order request
      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer("return=representation");
      request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: payment.amount.currency,
            value: payment.amount.value.toFixed(2)
          },
          description: `Payment for subscription ${payment.subscriptionId}`,
          reference_id: payment._id.toString(),
          custom_id: payment.userId.toString()
        }],
        application_context: {
          brand_name: 'Insightserenity',
          landing_page: 'NO_PREFERENCE',
          user_action: 'PAY_NOW',
          return_url: `${config.client.url}/billing/payment/success`,
          cancel_url: `${config.client.url}/billing/payment/cancel`
        }
      });
      
      // Create the order
      const order = await paypalClient.execute(request);
      
      // If order is approved, capture the payment
      if (paymentMethod.orderId && order.result.status === 'APPROVED') {
        const captureRequest = new paypal.orders.OrdersCaptureRequest(paymentMethod.orderId);
        captureRequest.requestBody({});
        
        const capture = await paypalClient.execute(captureRequest);
        
        if (capture.result.status === 'COMPLETED') {
          return {
            success: true,
            response: {
              transactionId: capture.result.id,
              status: 'succeeded',
              amount: parseFloat(capture.result.purchase_units[0].amount.value),
              currency: capture.result.purchase_units[0].amount.currency_code,
              payerId: capture.result.payer.payer_id,
              raw: capture.result
            }
          };
        }
      }
      
      return {
        success: false,
        error: {
          code: 'paypal_capture_failed',
          message: 'Failed to capture PayPal payment'
        }
      };
      
    } catch (error) {
      logger.error('PayPal payment error', { error });
      
      return {
        success: false,
        error: {
          code: error.statusCode || 'paypal_error',
          message: error.message
        }
      };
    }
  }
  
  /**
   * Process manual payment
   * @param {Object} payment - Payment object
   * @param {Object} paymentMethod - Payment method details
   * @returns {Promise<Object>} Manual payment result
   */
  static async processManualPayment(payment, paymentMethod) {
    // Manual payments are processed outside the system
    return {
      success: true,
      response: {
        transactionId: `MANUAL_${Date.now()}`,
        status: 'pending_verification',
        method: paymentMethod.type,
        reference: paymentMethod.reference,
        notes: paymentMethod.notes
      }
    };
  }
  
  /**
   * Create customer in payment gateway
   * @param {string} gateway - Gateway provider
   * @param {Object} customerData - Customer data
   * @returns {Promise<Object>} Customer creation result
   */
  static async createCustomer(gateway, customerData) {
    try {
      switch (gateway) {
        case 'stripe':
          return await this.createStripeCustomer(customerData);
          
        case 'paypal':
          // PayPal doesn't require customer creation
          return { customerId: null };
          
        default:
          throw new PaymentError(`Unsupported gateway for customer creation: ${gateway}`);
      }
      
    } catch (error) {
      logger.error('Create customer error', { error, gateway });
      throw error;
    }
  }
  
  /**
   * Create Stripe customer
   * @param {Object} customerData - Customer data
   * @returns {Promise<Object>} Stripe customer
   */
  static async createStripeCustomer(customerData) {
    const customer = await stripe.customers.create({
      email: customerData.email,
      name: customerData.name,
      phone: customerData.phone,
      address: customerData.address ? {
        line1: customerData.address.street1,
        line2: customerData.address.street2,
        city: customerData.address.city,
        state: customerData.address.state,
        postal_code: customerData.address.postalCode,
        country: customerData.address.country
      } : undefined,
      metadata: {
        userId: customerData.userId,
        organizationId: customerData.organizationId
      }
    });
    
    return {
      customerId: customer.id,
      raw: customer
    };
  }
  
  /**
   * Create subscription in payment gateway
   * @param {string} gateway - Gateway provider
   * @param {Object} subscriptionData - Subscription data
   * @returns {Promise<Object>} Gateway subscription
   */
  static async createSubscription(gateway, subscriptionData) {
    try {
      switch (gateway) {
        case 'stripe':
          return await this.createStripeSubscription(subscriptionData);
          
        case 'paypal':
          return await this.createPayPalSubscription(subscriptionData);
          
        default:
          throw new PaymentError(`Unsupported gateway for subscriptions: ${gateway}`);
      }
      
    } catch (error) {
      logger.error('Create gateway subscription error', { error, gateway });
      throw error;
    }
  }
  
  /**
   * Create Stripe subscription
   * @param {Object} subscriptionData - Subscription data
   * @returns {Promise<Object>} Stripe subscription
   */
  static async createStripeSubscription(subscriptionData) {
    const subscription = await stripe.subscriptions.create({
      customer: subscriptionData.customerId,
      items: [{
        price: subscriptionData.priceId
      }],
      payment_behavior: 'default_incomplete',
      expand: ['latest_invoice.payment_intent'],
      metadata: {
        subscriptionId: subscriptionData.internalSubscriptionId,
        userId: subscriptionData.userId
      },
      trial_period_days: subscriptionData.trialDays || 0,
      payment_settings: {
        payment_method_types: ['card'],
        save_default_payment_method: 'on_subscription'
      }
    });
    
    return {
      subscriptionId: subscription.id,
      status: subscription.status,
      clientSecret: subscription.latest_invoice.payment_intent?.client_secret,
      raw: subscription
    };
  }
  
  /**
   * Create PayPal subscription
   * @param {Object} subscriptionData - Subscription data
   * @returns {Promise<Object>} PayPal subscription
   */
  static async createPayPalSubscription(subscriptionData) {
    // PayPal subscription creation would go here
    // This is a placeholder as PayPal subscriptions require different setup
    return {
      subscriptionId: `PAYPAL_SUB_${Date.now()}`,
      status: 'pending'
    };
  }
  
  /**
   * Cancel subscription in payment gateway
   * @param {string} gateway - Gateway provider
   * @param {string} subscriptionId - Gateway subscription ID
   * @param {Object} options - Cancellation options
   * @returns {Promise<Object>} Cancellation result
   */
  static async cancelSubscription(gateway, subscriptionId, options = {}) {
    try {
      switch (gateway) {
        case 'stripe':
          return await this.cancelStripeSubscription(subscriptionId, options);
          
        case 'paypal':
          return await this.cancelPayPalSubscription(subscriptionId, options);
          
        default:
          throw new PaymentError(`Unsupported gateway for cancellation: ${gateway}`);
      }
      
    } catch (error) {
      logger.error('Cancel gateway subscription error', { error, gateway, subscriptionId });
      throw error;
    }
  }
  
  /**
   * Cancel Stripe subscription
   * @param {string} subscriptionId - Stripe subscription ID
   * @param {Object} options - Cancellation options
   * @returns {Promise<Object>} Cancellation result
   */
  static async cancelStripeSubscription(subscriptionId, options) {
    const canceledSubscription = await stripe.subscriptions.update(
      subscriptionId,
      {
        cancel_at_period_end: !options.immediate,
        cancellation_details: {
          reason: options.reason || 'customer_request',
          comment: options.comment
        }
      }
    );
    
    if (options.immediate) {
      await stripe.subscriptions.del(subscriptionId);
    }
    
    return {
      success: true,
      canceledAt: canceledSubscription.canceled_at,
      cancelAtPeriodEnd: canceledSubscription.cancel_at_period_end
    };
  }
  
  /**
   * Cancel PayPal subscription
   * @param {string} subscriptionId - PayPal subscription ID
   * @param {Object} options - Cancellation options
   * @returns {Promise<Object>} Cancellation result
   */
  static async cancelPayPalSubscription(subscriptionId, options) {
    // PayPal subscription cancellation would go here
    return {
      success: true,
      canceledAt: new Date()
    };
  }
  
  /**
   * Process refund
   * @param {Object} payment - Original payment
   * @param {Object} refundData - Refund data
   * @returns {Promise<Object>} Refund result
   */
  static async processRefund(payment, refundData) {
    try {
      const gateway = payment.gateway.provider;
      
      switch (gateway) {
        case 'stripe':
          return await this.processStripeRefund(payment, refundData);
          
        case 'paypal':
          return await this.processPayPalRefund(payment, refundData);
          
        default:
          throw new PaymentError(`Unsupported gateway for refunds: ${gateway}`);
      }
      
    } catch (error) {
      logger.error('Process refund error', { error, paymentId: payment._id });
      throw error;
    }
  }
  
  /**
   * Process Stripe refund
   * @param {Object} payment - Original payment
   * @param {Object} refundData - Refund data
   * @returns {Promise<Object>} Stripe refund result
   */
  static async processStripeRefund(payment, refundData) {
    const refund = await stripe.refunds.create({
      payment_intent: payment.gateway.transactionId,
      amount: refundData.amount ? Math.round(refundData.amount * 100) : undefined,
      reason: refundData.reason || 'requested_by_customer',
      metadata: {
        paymentId: payment._id.toString(),
        refundReason: refundData.reason,
        refundedBy: refundData.requestedBy
      }
    });
    
    return {
      success: true,
      refundId: refund.id,
      amount: refund.amount / 100,
      status: refund.status,
      raw: refund
    };
  }
  
  /**
   * Process PayPal refund
   * @param {Object} payment - Original payment
   * @param {Object} refundData - Refund data
   * @returns {Promise<Object>} PayPal refund result
   */
  static async processPayPalRefund(payment, refundData) {
    // PayPal refund processing would go here
    return {
      success: true,
      refundId: `PAYPAL_REFUND_${Date.now()}`,
      amount: refundData.amount || payment.amount.value,
      status: 'completed'
    };
  }
  
  /**
   * Validate webhook
   * @param {string} gateway - Gateway provider
   * @param {Object} headers - Request headers
   * @param {Object} body - Request body
   * @returns {Promise<Object>} Validation result
   */
  static async validateWebhook(gateway, headers, body) {
    try {
      switch (gateway) {
        case 'stripe':
          return await this.validateStripeWebhook(headers, body);
          
        case 'paypal':
          return await this.validatePayPalWebhook(headers, body);
          
        default:
          throw new PaymentError(`Unsupported gateway for webhooks: ${gateway}`);
      }
      
    } catch (error) {
      logger.error('Validate webhook error', { error, gateway });
      return { valid: false, error: error.message };
    }
  }
  
  /**
   * Validate Stripe webhook
   * @param {Object} headers - Request headers
   * @param {Object} body - Request body
   * @returns {Promise<Object>} Validation result
   */
  static async validateStripeWebhook(headers, body) {
    const signature = headers['stripe-signature'];
    const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
    
    try {
      const event = stripe.webhooks.constructEvent(
        body,
        signature,
        endpointSecret
      );
      
      return {
        valid: true,
        event
      };
    } catch (error) {
      return {
        valid: false,
        error: error.message
      };
    }
  }
  
  /**
   * Validate PayPal webhook
   * @param {Object} headers - Request headers
   * @param {Object} body - Request body
   * @returns {Promise<Object>} Validation result
   */
  static async validatePayPalWebhook(headers, body) {
    // PayPal webhook validation would go here
    return {
      valid: true,
      event: body
    };
  }
}

module.exports = PaymentGatewayService;