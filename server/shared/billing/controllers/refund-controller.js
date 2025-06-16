// server/shared/billing/controllers/refund-controller.js
/**
 * @file Refund Controller
 * @description Controller for handling refund-related API endpoints
 * @version 3.0.0
 */

const Payment = require('../models/payment-model');
const Invoice = require('../models/invoice-model');
const Subscription = require('../models/subscription-model');
const PaymentGatewayService = require('../services/payment-gateway-service');
const { ValidationError, NotFoundError, ForbiddenError } = require('../../utils/app-error');
const { asyncHandler } = require('../../utils/async-handler');
const logger = require('../../utils/logger');
const constants = require('../../config/constants');
const EmailService = require('../../services/email-service');
const AuditService = require('../../security/services/audit-service');
const config = require('../../config');

/**
 * Refund Controller Class
 * @class RefundController
 */
class RefundController {
  /**
   * Get refund requests
   * @route GET /api/v1/billing/refunds
   */
  static getRefunds = asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 20,
      status,
      startDate,
      endDate,
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;
    
    const query = {
      type: { $in: ['refund', 'partial_refund'] }
    };
    
    // Filter by user unless admin
    if (!req.user.isAdmin) {
      query.userId = req.user._id;
    }
    
    // Add filters
    if (status) query.status = status;
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) query.createdAt.$lte = new Date(endDate);
    }
    
    const skip = (page - 1) * limit;
    const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
    
    const [refunds, total] = await Promise.all([
      Payment.find(query)
        .sort(sort)
        .limit(parseInt(limit))
        .skip(skip)
        .populate('userId', 'firstName lastName email')
        .populate('invoiceId', 'invoiceNumber'),
      Payment.countDocuments(query)
    ]);
    
    // Calculate summary
    const summary = await Payment.aggregate([
      { $match: query },
      {
        $group: {
          _id: null,
          totalRefunded: { 
            $sum: {
              $cond: [
                { $eq: ['$status', 'succeeded'] },
                '$amount.value',
                0
              ]
            }
          },
          pendingRefunds: {
            $sum: {
              $cond: [
                { $in: ['$status', ['pending', 'processing']] },
                '$amount.value',
                0
              ]
            }
          },
          count: { $sum: 1 }
        }
      }
    ]);
    
    return res.status(200).json({
      status: 'success',
      data: {
        refunds,
        summary: summary[0] || {
          totalRefunded: 0,
          pendingRefunds: 0,
          count: 0
        },
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
   * Request refund for payment
   * @route POST /api/v1/billing/refunds
   */
  static requestRefund = asyncHandler(async (req, res) => {
    const {
      paymentId,
      amount,
      reason,
      description,
      evidence
    } = req.body;
    
    // Validate required fields
    if (!paymentId) {
      throw new ValidationError('Payment ID is required');
    }
    
    if (!reason) {
      throw new ValidationError('Refund reason is required');
    }
    
    // Validate reason
    const validReasons = [
      'duplicate',
      'fraudulent',
      'requested_by_customer',
      'product_not_received',
      'product_unacceptable',
      'subscription_cancelled',
      'other'
    ];
    
    if (!validReasons.includes(reason)) {
      throw new ValidationError('Invalid refund reason');
    }
    
    // Get original payment
    const originalPayment = await Payment.findById(paymentId)
      .populate('userId', 'firstName lastName email');
    
    if (!originalPayment) {
      throw new NotFoundError('Payment not found');
    }
    
    // Check ownership
    if (originalPayment.userId._id.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    // Check if payment is refundable
    if (!originalPayment.isRefundable) {
      throw new ValidationError('Payment is not eligible for refund');
    }
    
    // Validate refund amount
    const maxRefundable = originalPayment.amount.value - (originalPayment.refund.amount || 0);
    const refundAmount = amount || maxRefundable;
    
    if (refundAmount > maxRefundable) {
      throw new ValidationError(`Maximum refundable amount is ${maxRefundable}`);
    }
    
    if (refundAmount <= 0) {
      throw new ValidationError('Invalid refund amount');
    }
    
    // Check refund policy (30 days by default)
    const refundPeriodDays = config.billing.refundPeriodDays || 30;
    const daysSincePayment = Math.floor((Date.now() - originalPayment.createdAt) / (1000 * 60 * 60 * 24));
    
    if (!req.user.isAdmin && daysSincePayment > refundPeriodDays) {
      throw new ValidationError(`Refund period of ${refundPeriodDays} days has expired`);
    }
    
    try {
      // Process refund through gateway
      const refundResult = await PaymentGatewayService.processRefund(originalPayment, {
        amount: refundAmount,
        reason,
        description,
        requestedBy: req.user._id
      });
      
      if (refundResult.success) {
        // Update original payment
        await originalPayment.processRefund({
          amount: refundAmount,
          reason,
          description,
          requestedBy: req.user._id,
          refundId: refundResult.refundId
        });
        
        // Create refund payment record
        const refundPayment = new Payment({
          userId: originalPayment.userId._id,
          organizationId: originalPayment.organizationId,
          invoiceId: originalPayment.invoiceId,
          type: refundAmount >= originalPayment.amount.value ? 'refund' : 'partial_refund',
          status: 'succeeded',
          
          amount: {
            value: refundAmount,
            currency: originalPayment.amount.currency
          },
          
          method: originalPayment.method,
          
          gateway: {
            provider: originalPayment.gateway.provider,
            transactionId: refundResult.refundId
          },
          
          refund: {
            amount: refundAmount,
            reason,
            description,
            requestedAt: new Date(),
            requestedBy: req.user._id,
            processedAt: new Date(),
            refundId: refundResult.refundId,
            metadata: {
              originalPaymentId: originalPayment._id,
              evidence
            }
          },
          
          metadata: {
            originalPaymentId: originalPayment._id,
            notes: `Refund for payment ${originalPayment.paymentId}`
          }
        });
        
        await refundPayment.save();
        
        // Update related invoice if exists
        if (originalPayment.invoiceId) {
          const invoice = await Invoice.findById(originalPayment.invoiceId);
          if (invoice) {
            if (refundAmount >= originalPayment.amount.value) {
              invoice.status = 'refunded';
            }
            invoice.financials.paid = Math.max(0, invoice.financials.paid - refundAmount);
            invoice.financials.due = invoice.financials.total - invoice.financials.paid;
            
            invoice.history.push({
              event: 'refunded',
              timestamp: new Date(),
              actor: req.user._id,
              details: {
                amount: refundAmount,
                reason
              }
            });
            
            await invoice.save();
          }
        }
        
        // Handle subscription refunds
        if (originalPayment.subscriptionId) {
          await this.handleSubscriptionRefund(
            originalPayment.subscriptionId,
            refundAmount,
            reason
          );
        }
        
        // Send refund confirmation email
        await this.sendRefundConfirmationEmail(originalPayment.userId, {
          refundAmount,
          originalAmount: originalPayment.amount.value,
          reason,
          refundId: refundResult.refundId,
          paymentDate: originalPayment.createdAt
        });
        
        // Audit log
        await AuditService.log({
          type: 'refund_processed',
          action: 'process_refund',
          category: 'billing',
          result: 'success',
          userId: req.user._id,
          target: {
            type: 'payment',
            id: originalPayment._id.toString()
          },
          metadata: {
            refundAmount,
            reason,
            refundId: refundResult.refundId
          }
        });
        
        return res.status(200).json({
          status: 'success',
          data: {
            refund: refundPayment,
            originalPayment
          },
          message: 'Refund processed successfully'
        });
      } else {
        throw new Error(refundResult.error?.message || 'Refund processing failed');
      }
      
    } catch (error) {
      logger.error('Refund processing error', { error, paymentId });
      
      // Create failed refund record
      const failedRefund = new Payment({
        userId: originalPayment.userId._id,
        organizationId: originalPayment.organizationId,
        type: 'refund',
        status: 'failed',
        
        amount: {
          value: refundAmount,
          currency: originalPayment.amount.currency
        },
        
        refund: {
          amount: refundAmount,
          reason,
          description,
          requestedAt: new Date(),
          requestedBy: req.user._id,
          metadata: {
            originalPaymentId: originalPayment._id,
            error: error.message
          }
        },
        
        processing: {
          failedAt: new Date()
        }
      });
      
      await failedRefund.save();
      
      throw error;
    }
  });
  
  /**
   * Get refund details
   * @route GET /api/v1/billing/refunds/:refundId
   */
  static getRefundById = asyncHandler(async (req, res) => {
    const { refundId } = req.params;
    
    if (!refundId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid refund ID format');
    }
    
    const refund = await Payment.findById(refundId)
      .populate('userId', 'firstName lastName email')
      .populate('invoiceId', 'invoiceNumber')
      .populate('refund.requestedBy', 'firstName lastName');
    
    if (!refund || !['refund', 'partial_refund'].includes(refund.type)) {
      throw new NotFoundError('Refund not found');
    }
    
    // Check ownership or admin
    if (refund.userId._id.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    // Get original payment
    const originalPayment = await Payment.findById(refund.metadata.originalPaymentId);
    
    return res.status(200).json({
      status: 'success',
      data: {
        refund,
        originalPayment
      }
    });
  });
  
  /**
   * Cancel refund request (admin only)
   * @route POST /api/v1/billing/refunds/:refundId/cancel
   */
  static cancelRefund = asyncHandler(async (req, res) => {
    const { refundId } = req.params;
    const { reason } = req.body;
    
    if (!req.user.isAdmin) {
      throw new ForbiddenError('Only administrators can cancel refunds');
    }
    
    if (!refundId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid refund ID format');
    }
    
    if (!reason) {
      throw new ValidationError('Cancellation reason is required');
    }
    
    const refund = await Payment.findById(refundId);
    
    if (!refund || !['refund', 'partial_refund'].includes(refund.type)) {
      throw new NotFoundError('Refund not found');
    }
    
    if (refund.status !== 'pending') {
      throw new ValidationError('Only pending refunds can be cancelled');
    }
    
    refund.status = 'cancelled';
    refund.history.push({
      event: 'cancelled',
      timestamp: new Date(),
      actor: req.user._id,
      reason
    });
    
    await refund.save();
    
    return res.status(200).json({
      status: 'success',
      data: { refund },
      message: 'Refund cancelled successfully'
    });
  });
  
  /**
   * Get refund policy
   * @route GET /api/v1/billing/refunds/policy
   */
  static getRefundPolicy = asyncHandler(async (req, res) => {
    const policy = {
      standard: {
        period: config.billing.refundPeriodDays || 30,
        conditions: [
          'Full refund available within 7 days of purchase',
          'Partial refunds available within 30 days',
          'No refunds after 30 days except for technical issues',
          'Subscription refunds are prorated based on unused time'
        ],
        excludedItems: [
          'Setup fees',
          'Custom development work',
          'Completed services',
          'Downloaded digital products'
        ]
      },
      subscription: {
        cancellation: 'Immediate or end of billing period',
        proration: true,
        minimumCommitment: 'None for monthly plans, 30 days for annual plans',
        trialRefund: 'Full refund if cancelled during trial period'
      },
      process: {
        timeframe: '5-10 business days',
        methods: ['Original payment method', 'Account credit'],
        documentation: 'May be required for amounts over $500'
      }
    };
    
    return res.status(200).json({
      status: 'success',
      data: { policy }
    });
  });
  
  /**
   * Process batch refunds (admin only)
   * @route POST /api/v1/billing/refunds/batch
   */
  static processBatchRefunds = asyncHandler(async (req, res) => {
    const { refunds } = req.body;
    
    if (!req.user.isAdmin) {
      throw new ForbiddenError('Only administrators can process batch refunds');
    }
    
    if (!Array.isArray(refunds) || refunds.length === 0) {
      throw new ValidationError('Refunds array is required');
    }
    
    if (refunds.length > 100) {
      throw new ValidationError('Maximum 100 refunds per batch');
    }
    
    const results = {
      successful: [],
      failed: [],
      total: refunds.length
    };
    
    for (const refundRequest of refunds) {
      try {
        const { paymentId, amount, reason } = refundRequest;
        
        const originalPayment = await Payment.findById(paymentId);
        if (!originalPayment) {
          results.failed.push({
            paymentId,
            error: 'Payment not found'
          });
          continue;
        }
        
        const refundResult = await PaymentGatewayService.processRefund(originalPayment, {
          amount: amount || originalPayment.amount.value,
          reason: reason || 'batch_refund',
          requestedBy: req.user._id
        });
        
        if (refundResult.success) {
          await originalPayment.processRefund({
            amount: amount || originalPayment.amount.value,
            reason: reason || 'batch_refund',
            requestedBy: req.user._id,
            refundId: refundResult.refundId
          });
          
          results.successful.push({
            paymentId,
            refundId: refundResult.refundId,
            amount: amount || originalPayment.amount.value
          });
        } else {
          results.failed.push({
            paymentId,
            error: refundResult.error?.message || 'Refund failed'
          });
        }
        
      } catch (error) {
        results.failed.push({
          paymentId: refundRequest.paymentId,
          error: error.message
        });
      }
    }
    
    // Audit log
    await AuditService.log({
      type: 'batch_refund_processed',
      action: 'process_batch_refund',
      category: 'billing',
      result: 'completed',
      userId: req.user._id,
      metadata: results
    });
    
    return res.status(200).json({
      status: 'success',
      data: results,
      message: `Batch refund completed: ${results.successful.length} successful, ${results.failed.length} failed`
    });
  });
  
  /**
   * Get refund statistics
   * @route GET /api/v1/billing/refunds/statistics
   */
  static getRefundStatistics = asyncHandler(async (req, res) => {
    const { startDate, endDate } = req.query;
    
    const match = {
      type: { $in: ['refund', 'partial_refund'] },
      status: 'succeeded'
    };
    
    if (!req.user.isAdmin) {
      match.userId = req.user._id;
    }
    
    if (startDate || endDate) {
      match.createdAt = {};
      if (startDate) match.createdAt.$gte = new Date(startDate);
      if (endDate) match.createdAt.$lte = new Date(endDate);
    }
    
    const [
      refundsByReason,
      refundsByMonth,
      refundSummary
    ] = await Promise.all([
      // Refunds by reason
      Payment.aggregate([
        { $match: match },
        {
          $group: {
            _id: '$refund.reason',
            count: { $sum: 1 },
            totalAmount: { $sum: '$refund.amount' }
          }
        },
        { $sort: { count: -1 } }
      ]),
      
      // Refunds by month
      Payment.aggregate([
        { $match: match },
        {
          $group: {
            _id: {
              year: { $year: '$createdAt' },
              month: { $month: '$createdAt' }
            },
            count: { $sum: 1 },
            totalAmount: { $sum: '$refund.amount' }
          }
        },
        { $sort: { '_id.year': -1, '_id.month': -1 } },
        { $limit: 12 }
      ]),
      
      // Overall summary
      Payment.aggregate([
        { $match: match },
        {
          $group: {
            _id: null,
            totalRefunds: { $sum: 1 },
            totalAmount: { $sum: '$refund.amount' },
            avgRefundAmount: { $avg: '$refund.amount' },
            fullRefunds: {
              $sum: {
                $cond: [{ $eq: ['$type', 'refund'] }, 1, 0]
              }
            },
            partialRefunds: {
              $sum: {
                $cond: [{ $eq: ['$type', 'partial_refund'] }, 1, 0]
              }
            }
          }
        }
      ])
    ]);
    
    return res.status(200).json({
      status: 'success',
      data: {
        byReason: refundsByReason,
        byMonth: refundsByMonth.reverse(),
        summary: refundSummary[0] || {
          totalRefunds: 0,
          totalAmount: 0,
          avgRefundAmount: 0,
          fullRefunds: 0,
          partialRefunds: 0
        }
      }
    });
  });
  
  /**
   * Helper method to handle subscription refunds
   */
  static async handleSubscriptionRefund(subscriptionId, refundAmount, reason) {
    try {
      const subscription = await Subscription.findById(subscriptionId);
      
      if (!subscription) {
        return;
      }
      
      // Update payment summary
      subscription.paymentSummary.totalPaid = Math.max(
        0,
        subscription.paymentSummary.totalPaid - refundAmount
      );
      
      // Add to history
      subscription.history.push({
        event: 'refunded',
        timestamp: new Date(),
        details: {
          amount: refundAmount,
          reason
        }
      });
      
      // Cancel subscription if full refund and active
      if (reason === 'subscription_cancelled' && subscription.status === 'active') {
        subscription.status = 'cancelled';
        subscription.dates.cancelledAt = new Date();
        subscription.dates.cancellationEffective = new Date();
      }
      
      await subscription.save();
      
    } catch (error) {
      logger.error('Handle subscription refund error', { error, subscriptionId });
    }
  }
  
  /**
   * Helper method to send refund confirmation email
   */
  static async sendRefundConfirmationEmail(user, refundData) {
    try {
      await EmailService.sendEmail({
        to: user.email,
        subject: 'Refund Processed Successfully',
        template: 'refund-confirmation',
        data: {
          firstName: user.firstName,
          refundAmount: refundData.refundAmount,
          originalAmount: refundData.originalAmount,
          refundId: refundData.refundId,
          reason: refundData.reason,
          paymentDate: refundData.paymentDate,
          processingTime: '5-10 business days'
        }
      });
    } catch (error) {
      logger.error('Send refund confirmation email error', { error });
    }
  }
}

module.exports = RefundController;