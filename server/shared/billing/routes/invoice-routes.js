// server/shared/billing/routes/invoice-routes.js
/**
 * @file Invoice Routes
 * @description API routes for invoice management
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
const InvoiceController = require('../controllers/invoice-controller');

/**
 * Validation rules
 */
const validationRules = {
  createInvoice: [
    body('customerId')
      .notEmpty().withMessage('Customer ID is required')
      .isMongoId().withMessage('Invalid customer ID format'),
    body('type')
      .optional()
      .isIn(['subscription', 'one_time', 'addon', 'overage', 'manual', 'credit_note', 'proforma'])
      .withMessage('Invalid invoice type'),
    body('dueDate')
      .optional()
      .isISO8601().withMessage('Invalid due date format')
      .custom(value => new Date(value) >= new Date()).withMessage('Due date cannot be in the past'),
    body('items')
      .isArray({ min: 1 }).withMessage('At least one item is required'),
    body('items.*.name')
      .notEmpty().withMessage('Item name is required')
      .isString().withMessage('Item name must be a string'),
    body('items.*.rate')
      .notEmpty().withMessage('Item rate is required')
      .isFloat({ min: 0 }).withMessage('Item rate must be a positive number'),
    body('items.*.quantity')
      .optional()
      .isFloat({ min: 0.01 }).withMessage('Item quantity must be greater than 0'),
    body('items.*.description')
      .optional()
      .isString().withMessage('Item description must be a string')
      .isLength({ max: 500 }).withMessage('Item description must not exceed 500 characters'),
    body('sendImmediately')
      .optional()
      .isBoolean().withMessage('Send immediately must be boolean')
  ],
  
  updateInvoice: [
    param('invoiceId')
      .isMongoId().withMessage('Invalid invoice ID format'),
    body('dates.due')
      .optional()
      .isISO8601().withMessage('Invalid due date format'),
    body('items')
      .optional()
      .isArray().withMessage('Items must be an array'),
    body('content.headerNote')
      .optional()
      .isString().withMessage('Header note must be a string')
      .isLength({ max: 1000 }).withMessage('Header note must not exceed 1000 characters'),
    body('content.footerNote')
      .optional()
      .isString().withMessage('Footer note must be a string')
      .isLength({ max: 1000 }).withMessage('Footer note must not exceed 1000 characters')
  ],
  
  sendInvoice: [
    param('invoiceId')
      .isMongoId().withMessage('Invalid invoice ID format'),
    body('method')
      .optional()
      .isIn(['email', 'sms', 'print']).withMessage('Invalid send method'),
    body('recipient')
      .optional()
      .isEmail().withMessage('Invalid recipient email'),
    body('cc')
      .optional()
      .custom(value => {
        if (Array.isArray(value)) {
          return value.every(email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email));
        }
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      }).withMessage('Invalid CC email addresses'),
    body('message')
      .optional()
      .isString().withMessage('Message must be a string')
      .isLength({ max: 1000 }).withMessage('Message must not exceed 1000 characters')
  ],
  
  recordPayment: [
    param('invoiceId')
      .isMongoId().withMessage('Invalid invoice ID format'),
    body('amount')
      .notEmpty().withMessage('Amount is required')
      .isFloat({ min: 0.01 }).withMessage('Amount must be greater than 0'),
    body('method')
      .notEmpty().withMessage('Payment method is required')
      .isIn(['card', 'bank_transfer', 'paypal', 'check', 'cash', 'crypto', 'other'])
      .withMessage('Invalid payment method'),
    body('reference')
      .optional()
      .isString().withMessage('Reference must be a string')
      .isLength({ max: 200 }).withMessage('Reference must not exceed 200 characters'),
    body('date')
      .optional()
      .isISO8601().withMessage('Invalid date format')
  ],
  
  getInvoices: [
    query('page')
      .optional()
      .isInt({ min: 1 }).withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100'),
    query('status')
      .optional()
      .isIn(['draft', 'pending', 'sent', 'viewed', 'paid', 'partial', 'overdue', 'cancelled', 'refunded', 'disputed', 'written_off'])
      .withMessage('Invalid status'),
    query('type')
      .optional()
      .isIn(['subscription', 'one_time', 'addon', 'overage', 'manual', 'credit_note', 'proforma'])
      .withMessage('Invalid type'),
    query('startDate')
      .optional()
      .isISO8601().withMessage('Invalid start date format'),
    query('endDate')
      .optional()
      .isISO8601().withMessage('Invalid end date format')
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
    max: 30,
    message: 'Too many invoice operations, please try again later'
  }),
  
  download: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 50,
    message: 'Too many download requests, please try again later'
  }),
  
  send: rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 20,
    message: 'Too many send requests, please try again later'
  })
};

/**
 * Routes
 */
router.use(authenticate);

// Get invoices
router.get(
  '/invoices',
  rateLimits.read,
  validate(validationRules.getInvoices),
  InvoiceController.getInvoices
);

// Get invoice details
router.get(
  '/invoices/:invoiceId',
  rateLimits.read,
  validate([
    param('invoiceId').isMongoId().withMessage('Invalid invoice ID format')
  ]),
  InvoiceController.getInvoiceById
);

// Create invoice (admin or authorized users)
router.post(
  '/invoices',
  authorize([
    'super_admin',
    'platform_admin',
    'manager',
    'senior_manager',
    'director',
    'partner'
  ]),
  rateLimits.write,
  validate(validationRules.createInvoice),
  InvoiceController.createInvoice
);

// Update invoice (admin or creator only)
router.put(
  '/invoices/:invoiceId',
  rateLimits.write,
  validate(validationRules.updateInvoice),
  InvoiceController.updateInvoice
);

// Send invoice
router.post(
  '/invoices/:invoiceId/send',
  rateLimits.send,
  validate(validationRules.sendInvoice),
  InvoiceController.sendInvoice
);

// Download invoice
router.get(
  '/invoices/:invoiceId/download',
  rateLimits.download,
  validate([
    param('invoiceId').isMongoId().withMessage('Invalid invoice ID format'),
    query('format')
      .optional()
      .isIn(['pdf', 'tax']).withMessage('Invalid format')
  ]),
  InvoiceController.downloadInvoice
);

// Record manual payment (admin only)
router.post(
  '/invoices/:invoiceId/payments',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.write,
  validate(validationRules.recordPayment),
  InvoiceController.recordPayment
);

// Cancel invoice
router.post(
  '/invoices/:invoiceId/cancel',
  rateLimits.write,
  validate([
    param('invoiceId').isMongoId().withMessage('Invalid invoice ID format'),
    body('reason')
      .notEmpty().withMessage('Cancellation reason is required')
      .isString().withMessage('Reason must be a string')
      .isLength({ max: 500 }).withMessage('Reason must not exceed 500 characters')
  ]),
  InvoiceController.cancelInvoice
);

// Write off invoice (admin only)
router.post(
  '/invoices/:invoiceId/write-off',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.write,
  validate([
    param('invoiceId').isMongoId().withMessage('Invalid invoice ID format'),
    body('reason')
      .notEmpty().withMessage('Write-off reason is required')
      .isString().withMessage('Reason must be a string')
      .isLength({ max: 500 }).withMessage('Reason must not exceed 500 characters')
  ]),
  InvoiceController.writeOffInvoice
);

// Send reminder
router.post(
  '/invoices/:invoiceId/remind',
  rateLimits.send,
  validate([
    param('invoiceId').isMongoId().withMessage('Invalid invoice ID format'),
    body('message')
      .optional()
      .isString().withMessage('Message must be a string')
      .isLength({ max: 1000 }).withMessage('Message must not exceed 1000 characters')
  ]),
  InvoiceController.sendReminder
);

// Get overdue invoices
router.get(
  '/invoices/overdue',
  rateLimits.read,
  validate([
    query('daysOverdue')
      .optional()
      .isInt({ min: 0, max: 365 }).withMessage('Days overdue must be between 0 and 365')
  ]),
  InvoiceController.getOverdueInvoices
);

// Get invoice statistics
router.get(
  '/invoices/statistics',
  rateLimits.read,
  validate([
    query('startDate').optional().isISO8601().withMessage('Invalid start date'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date'),
    query('groupBy')
      .optional()
      .isIn(['day', 'week', 'month', 'quarter', 'year'])
      .withMessage('Invalid grouping option')
  ]),
  InvoiceController.getInvoiceStatistics
);

/**
 * Admin routes
 */

// Get all invoices (admin only)
router.get(
  '/invoices/admin/all',
  authorize(['super_admin', 'platform_admin']),
  rateLimits.read,
  validate([
    query('userId').optional().isMongoId().withMessage('Invalid user ID format'),
    query('organizationId').optional().isMongoId().withMessage('Invalid organization ID format'),
    ...validationRules.getInvoices
  ]),
  asyncHandler(async (req, res) => {
    const Invoice = require('../models/invoice-model');
    const { userId, organizationId, ...filters } = req.query;
    
    const query = {};
    if (userId) query.userId = userId;
    if (organizationId) query.organizationId = organizationId;
    if (filters.status) query.status = filters.status;
    if (filters.type) query.type = filters.type;
    
    const invoices = await Invoice.find(query)
      .populate('userId', 'firstName lastName email')
      .populate('organizationId', 'name')
      .sort({ 'dates.issued': -1 })
      .limit(parseInt(filters.limit) || 50);
    
    res.status(200).json({
      status: 'success',
      data: { invoices, count: invoices.length }
    });
  })
);

// Generate tax report (admin only)
router.get(
  '/invoices/admin/tax-report',
  authorize(['super_admin', 'platform_admin', 'director', 'partner']),
  rateLimits.read,
  validate([
    query('startDate')
      .notEmpty().withMessage('Start date is required')
      .isISO8601().withMessage('Invalid start date'),
    query('endDate')
      .notEmpty().withMessage('End date is required')
      .isISO8601().withMessage('Invalid end date')
  ]),
  asyncHandler(async (req, res) => {
    const TaxService = require('../services/tax-service');
    const report = await TaxService.getTaxReport(req.query);
    
    res.status(200).json({
      status: 'success',
      data: { report }
    });
  })
);

// Process overdue invoice reminders (cron job endpoint)
router.post(
  '/invoices/admin/process-reminders',
  authorize(['super_admin', 'platform_admin']),
  rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 2
  }),
  asyncHandler(async (req, res) => {
    const Invoice = require('../models/invoice-model');
    const EmailService = require('../../services/email-service');
    
    // Get invoices needing reminders
    const invoices = await Invoice.find({
      status: { $in: ['pending', 'sent', 'viewed'] },
      'reminders.enabled': true,
      $or: [
        // Due date reminders
        {
          'dates.due': {
            $gte: new Date(),
            $lte: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
          },
          'reminders.schedule.sent': false
        },
        // Overdue reminders
        {
          'dates.due': { $lt: new Date() },
          'reminders.overdue.sent': false
        }
      ]
    }).populate('userId');
    
    let sent = 0;
    let failed = 0;
    
    for (const invoice of invoices) {
      try {
        await EmailService.sendEmail({
          to: invoice.billingInfo.customer.email,
          subject: invoice.isOverdue 
            ? `Overdue: Invoice ${invoice.invoiceNumber}`
            : `Reminder: Invoice ${invoice.invoiceNumber} due soon`,
          template: 'invoice-reminder',
          data: {
            firstName: invoice.userId.firstName,
            invoiceNumber: invoice.invoiceNumber,
            amount: invoice.financials.due,
            dueDate: invoice.dates.due,
            isOverdue: invoice.isOverdue,
            daysOverdue: invoice.daysOverdue
          }
        });
        
        // Update reminder status
        invoice.reminders.lastSent = new Date();
        invoice.reminders.totalSent++;
        await invoice.save();
        
        sent++;
      } catch (error) {
        console.error('Failed to send reminder:', error);
        failed++;
      }
    }
    
    res.status(200).json({
      status: 'success',
      data: {
        processed: invoices.length,
        sent,
        failed
      },
      message: 'Invoice reminders processed'
    });
  })
);

// Export router
module.exports = router;