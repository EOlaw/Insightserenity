// server/shared/billing/routes/payment-routes.js
/**
 * @file Payment Routes
 * @description API routes for payment management and processing
 * @version 3.0.0
 */

const express = require('express');

const router = express.Router();
const { body, param, query } = require('express-validator');

const { authenticate } = require('../../auth/middleware/authenticate');
const { authorize } = require('../../auth/middleware/authorize');
const rateLimit = require('../../auth/middleware/rate-limit');
const constants = require('../../config/constants');
const { validate } = require('../../utils/validation/validator');
const PaymentController = require('../controllers/payment-controller');
const RefundController = require('../controllers/refund-controller');

/**
 * Validation rules
 */
const validationRules = {
  processPayment: [
    body('amount')
      .notEmpty().withMessage('Amount is required')
      .isFloat({ min: 0.01 }).withMessage('Amount must be greater than 0')
      .custom(value => value <= 999999.99).withMessage('Amount exceeds maximum allowed'),
    body('currency')
      .optional()
      .isIn(['USD', 'EUR', 'GBP', 'CAD', 'AUD']).withMessage('Invalid currency'),
    body('paymentMethod')
      .notEmpty().withMessage('Payment method is required')
      .isObject().withMessage('Payment method must be an object'),
    body('paymentMethod.type')
      .notEmpty().withMessage('Payment method type is required')
      .isIn(['card', 'bank_account', 'paypal', 'check', 'wire_transfer'])
      .withMessage('Invalid payment method type'),
    body('description')
      .optional()
      .isString().withMessage('Description must be a string')
      .isLength({ max: 500 }).withMessage('Description must not exceed 500 characters'),
    body('invoiceId')
      .optional()
      .isMongoId().withMessage('Invalid invoice ID format')
  ],
  
  confirmPayment: [
    param('paymentId')
      .isMongoId().withMessage('Invalid payment ID format'),
    body('paymentIntentId')
      .notEmpty().withMessage('Payment intent ID is required')
      .isString().withMessage('Payment intent ID must be a string')
  ],
  
  processRefund: [
    param('paymentId')
      .isMongoId().withMessage('Invalid payment ID format'),
    body('amount')
      .optional()
      .isFloat({ min: 0.01 }).withMessage('Refund amount must be greater than 0'),
    body('reason')
      .notEmpty().withMessage('Refund reason is required')
      .isIn([
        'duplicate', 'fraudulent', 'requested_by_customer',
        'product_not_received', 'product_unacceptable',
        'subscription_cancelled', 'other'
      ]).withMessage('Invalid refund reason'),
    body('description')
      .optional()
      .isString().withMessage('Description must be a string')
      .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
  ],
  
  addPaymentMethod: [
    body('paymentMethodId')
      .notEmpty().withMessage('Payment method ID is required')
      .isString().withMessage('Payment method ID must be a string'),
    body('type')
      .optional()
      .isIn(['card', 'bank_account']).withMessage('Invalid payment method type'),
    body('setAsDefault')
      .optional()
      .isBoolean().withMessage('Set as default must be boolean')
  ],
  
  getPayments: [
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('status')
      .optional()
      .isIn(['pending', 'processing', 'succeeded', 'failed', 'cancelled', 'refunded', 'disputed'])
      .withMessage('Invalid status'),
    query('type')
      .optional()
      .isIn(['payment', 'refund', 'partial_refund', 'chargeback', 'adjustment', 'credit'])
      .withMessage('Invalid type'),
    query('startDate')
      .optional()
      .isISO8601().withMessage('Invalid start date format'),
    query('endDate')
      .optional()
      .isISO8601().withMessage('Invalid end date format')
      .custom((value, { req }) => {
        if (req.query.startDate && new Date(value) < new Date(req.query.startDate)) {
          throw new Error('End date must be after start date');
        }
        return true;
      })
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
  
  payment: rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: 'Too many payment attempts, please try again later'
  }),
  
  refund: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: 'Too many refund requests, please try again later'
  }),
  
  webhook: rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100,
    skipSuccessfulRequests: true
  })
};

/**
 * Webhook routes (no authentication required)
 */
router.post(
  '/webhooks/:provider',
  rateLimits.webhook,
  express.raw({ type: 'application/json' }), // Raw body for webhook validation
  PaymentController.handleWebhook
);

/**
 * Authenticated routes
 */
router.use(authenticate);

// Get payment history
router.get(
  '/payments',
  rateLimits.read,
  validate(validationRules.getPayments),
  PaymentController.getPayments
);

// Get payment details
router.get(
  '/payments/:paymentId',
  rateLimits.read,
  validate([
    param('paymentId').isMongoId().withMessage('Invalid payment ID format')
  ]),
  PaymentController.getPaymentById
);

// Process one-time payment
router.post(
  '/payments',
  rateLimits.payment,
  validate(validationRules.processPayment),
  PaymentController.processPayment
);

// Confirm payment (3D Secure)
router.post(
  '/payments/:paymentId/confirm',
  rateLimits.payment,
  validate(validationRules.confirmPayment),
  PaymentController.confirmPayment
);

// Process refund
router.post(
  '/payments/:paymentId/refund',
  rateLimits.refund,
  validate(validationRules.processRefund),
  PaymentController.processRefund
);

// Get payment methods
router.get(
  '/payment-methods',
  rateLimits.read,
  PaymentController.getPaymentMethods
);

// Add payment method
router.post(
  '/payment-methods',
  rateLimits.payment,
  validate(validationRules.addPaymentMethod),
  PaymentController.addPaymentMethod
);

// Remove payment method
router.delete(
  '/payment-methods/:paymentMethodId',
  rateLimits.payment,
  validate([
    param('paymentMethodId')
      .notEmpty().withMessage('Payment method ID is required')
      .isString().withMessage('Payment method ID must be a string')
  ]),
  PaymentController.removePaymentMethod
);

// Get payment statistics
router.get(
  '/payments/statistics',
  rateLimits.read,
  validate([
    query('startDate').optional().isISO8601().withMessage('Invalid start date'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date')
  ]),
  PaymentController.getPaymentStatistics
);

/**
 * Refund routes
 */

// Get refunds
router.get(
  '/refunds',
  rateLimits.read,
  validate([
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('status')
      .optional()
      .isIn(['pending', 'processing', 'succeeded', 'failed', 'cancelled'])
      .withMessage('Invalid status')
  ]),
  RefundController.getRefunds
);

// Request refund
router.post(
  '/refunds',
  rateLimits.refund,
  validate([
    body('paymentId')
      .notEmpty().withMessage('Payment ID is required')
      .isMongoId().withMessage('Invalid payment ID format'),
    body('amount')
      .optional()
      .isFloat({ min: 0.01 }).withMessage('Amount must be greater than 0'),
    body('reason')
      .notEmpty().withMessage('Reason is required')
      .isIn([
        'duplicate', 'fraudulent', 'requested_by_customer',
        'product_not_received', 'product_unacceptable',
        'subscription_cancelled', 'other'
      ]).withMessage('Invalid reason'),
    body('description')
      .optional()
      .isString().withMessage('Description must be a string')
      .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
  ]),
  RefundController.requestRefund
);

// Get refund details
router.get(
  '/refunds/:refundId',
  rateLimits.read,
  validate([
    param('refundId').isMongoId().withMessage('Invalid refund ID format')
  ]),
  RefundController.getRefundById
);

// Get refund policy
router.get(
  '/refunds/policy',
  rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 50
  }),
  RefundController.getRefundPolicy
);

// Get refund statistics
router.get(
  '/refunds/statistics',
  rateLimits.read,
  validate([
    query('startDate').optional().isISO8601().withMessage('Invalid start date'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date')
  ]),
  RefundController.getRefundStatistics
);

/**
 * Admin routes
 */

// Cancel refund (admin only)
router.post(
  '/refunds/:refundId/cancel',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.refund,
  validate([
    param('refundId').isMongoId().withMessage('Invalid refund ID format'),
    body('reason')
      .notEmpty().withMessage('Cancellation reason is required')
      .isString().withMessage('Reason must be a string')
  ]),
  RefundController.cancelRefund
);

// Process batch refunds (admin only)
router.post(
  '/refunds/batch',
  authorize(['super_admin', 'platform_admin']),
  rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 2
  }),
  validate([
    body('refunds')
      .isArray({ min: 1, max: 100 }).withMessage('Refunds must be an array with 1-100 items'),
    body('refunds.*.paymentId')
      .notEmpty().withMessage('Payment ID is required')
      .isMongoId().withMessage('Invalid payment ID format'),
    body('refunds.*.amount')
      .optional()
      .isFloat({ min: 0.01 }).withMessage('Amount must be greater than 0'),
    body('refunds.*.reason')
      .optional()
      .isIn([
        'duplicate', 'fraudulent', 'requested_by_customer',
        'product_not_received', 'product_unacceptable',
        'subscription_cancelled', 'other'
      ]).withMessage('Invalid reason')
  ]),
  RefundController.processBatchRefunds
);

// Get payments for retry (admin only)
router.get(
  '/payments/admin/retry-queue',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.read,
  asyncHandler(async (req, res) => {
    const Payment = require('../models/payment-model');
    const payments = await Payment.getPaymentsForRetry();
    
    res.status(200).json({
      status: 'success',
      data: { payments, count: payments.length }
    });
  })
);

// Retry failed payment (admin only)
router.post(
  '/payments/:paymentId/retry',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.payment,
  validate([
    param('paymentId').isMongoId().withMessage('Invalid payment ID format')
  ]),
  asyncHandler(async (req, res) => {
    const { paymentId } = req.params;
    const Payment = require('../models/payment-model');
    const PaymentGatewayService = require('../services/payment-gateway-service');
    
    const payment = await Payment.findById(paymentId);
    if (!payment) {
      throw new NotFoundError('Payment not found');
    }
    
    if (!payment.requiresRetry) {
      throw new ValidationError('Payment does not require retry');
    }
    
    payment.processing.attemptCount++;
    await payment.save();
    
    const result = await PaymentGatewayService.processPayment(payment, {
      type: payment.method.type,
      ...payment.method
    });
    
    if (result.success) {
      await payment.markAsSucceeded(result.response);
    } else {
      await payment.markAsFailed(result.error, payment.processing.attemptCount < payment.processing.maxRetries);
    }
    
    res.status(200).json({
      status: 'success',
      data: { payment },
      message: result.success ? 'Payment retry successful' : 'Payment retry failed'
    });
  })
);

// Export router
module.exports = router;