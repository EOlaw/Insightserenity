// server/shared/billing/controllers/invoice-controller.js
/**
 * @file Invoice Controller
 * @description Controller for handling invoice-related API endpoints
 * @version 3.0.0
 */

const Invoice = require('../models/invoice-model');
const BillingService = require('../services/billing-service');
const TaxService = require('../services/tax-service');
const { ValidationError, NotFoundError, ForbiddenError } = require('../../utils/app-error');
const { asyncHandler } = require('../../utils/async-handler');
const logger = require('../../utils/logger');
const constants = require('../../config/constants');
const PDFService = require('../../utils/pdf-service');
const EmailService = require('../../services/email-service');

/**
 * Invoice Controller Class
 * @class InvoiceController
 */
class InvoiceController {
  /**
   * Get user's invoices
   * @route GET /api/v1/billing/invoices
   */
  static getInvoices = asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 20,
      status,
      type,
      startDate,
      endDate,
      sortBy = 'dates.issued',
      sortOrder = 'desc'
    } = req.query;
    
    const query = {
      userId: req.user._id
    };
    
    // Add filters
    if (status) query.status = status;
    if (type) query.type = type;
    if (startDate || endDate) {
      query['dates.issued'] = {};
      if (startDate) query['dates.issued'].$gte = new Date(startDate);
      if (endDate) query['dates.issued'].$lte = new Date(endDate);
    }
    
    const skip = (page - 1) * limit;
    const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
    
    const [invoices, total] = await Promise.all([
      Invoice.find(query)
        .sort(sort)
        .limit(parseInt(limit))
        .skip(skip)
        .populate('subscriptionId', 'planId')
        .select('-history -metadata.views'),
      Invoice.countDocuments(query)
    ]);
    
    // Calculate summary
    const summary = await Invoice.aggregate([
      { $match: query },
      {
        $group: {
          _id: null,
          totalAmount: { $sum: '$financials.total' },
          totalPaid: { $sum: '$financials.paid' },
          totalDue: { $sum: '$financials.due' },
          overdueAmount: {
            $sum: {
              $cond: [
                { $eq: ['$status', 'overdue'] },
                '$financials.due',
                0
              ]
            }
          }
        }
      }
    ]);
    
    return res.status(200).json({
      status: 'success',
      data: {
        invoices,
        summary: summary[0] || {
          totalAmount: 0,
          totalPaid: 0,
          totalDue: 0,
          overdueAmount: 0
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
   * Get invoice details
   * @route GET /api/v1/billing/invoices/:invoiceId
   */
  static getInvoiceById = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    const invoice = await Invoice.findById(invoiceId)
      .populate('userId', 'firstName lastName email')
      .populate('subscriptionId')
      .populate('payment.transactions.actor', 'firstName lastName');
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    // Check ownership or admin
    if (invoice.userId._id.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    // Mark as viewed if first time
    if (invoice.status === 'sent') {
      await invoice.markAsViewed({
        email: req.user.email,
        id: req.user._id,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    }
    
    return res.status(200).json({
      status: 'success',
      data: { invoice }
    });
  });
  
  /**
   * Create manual invoice
   * @route POST /api/v1/billing/invoices
   */
  static createInvoice = asyncHandler(async (req, res) => {
    const {
      customerId,
      type = 'manual',
      dueDate,
      items,
      notes,
      terms,
      sendImmediately = false
    } = req.body;
    
    // Validate required fields
    if (!customerId || !items || !Array.isArray(items) || items.length === 0) {
      throw new ValidationError('Customer ID and items are required');
    }
    
    // Validate due date
    const dueDateObj = new Date(dueDate || Date.now() + 30 * 24 * 60 * 60 * 1000);
    if (dueDateObj < new Date()) {
      throw new ValidationError('Due date cannot be in the past');
    }
    
    // Get customer details
    const User = require('../../users/models/user-model');
    const customer = await User.findById(customerId);
    
    if (!customer) {
      throw new NotFoundError('Customer not found');
    }
    
    // Create invoice
    const invoice = new Invoice({
      userId: customerId,
      organizationId: customer.organization?.current,
      type,
      status: 'draft',
      
      dates: {
        issued: new Date(),
        due: dueDateObj
      },
      
      billingInfo: {
        customer: {
          name: `${customer.firstName} ${customer.lastName}`,
          email: customer.email,
          phone: customer.phone,
          customerId: customer._id.toString()
        },
        company: customer.company ? {
          name: customer.company.name,
          taxId: customer.company.taxId,
          vatNumber: customer.company.vatNumber
        } : undefined,
        address: customer.billingAddress || customer.contact?.address || {}
      },
      
      content: {
        headerNote: notes?.header,
        footerNote: notes?.footer,
        terms: terms || 'Payment is due within 30 days of invoice date.',
        customerMessage: notes?.customer
      },
      
      metadata: {
        createdBy: req.user._id,
        source: 'manual'
      }
    });
    
    // Add items and calculate totals
    let subtotal = 0;
    let taxTotal = 0;
    
    for (const item of items) {
      // Validate item
      if (!item.name || !item.rate || item.rate <= 0) {
        throw new ValidationError('Each item must have a name and valid rate');
      }
      
      const quantity = item.quantity || 1;
      const amount = quantity * item.rate;
      
      // Calculate tax if applicable
      let taxAmount = 0;
      if (item.taxable !== false) {
        const taxRate = await TaxService.getTaxRate(
          {
            country: invoice.billingInfo.address.country,
            state: invoice.billingInfo.address.state,
            city: invoice.billingInfo.address.city
          },
          'manual'
        );
        
        taxAmount = amount * taxRate;
      }
      
      invoice.addItem({
        type: item.type || 'fee',
        name: item.name,
        description: item.description,
        quantity: { amount: quantity, unit: item.unit || 'unit' },
        rate: { amount: item.rate, unit: item.unit || 'unit' },
        tax: taxAmount > 0 ? {
          rate: taxRate * 100,
          amount: taxAmount,
          inclusive: false
        } : undefined
      });
      
      subtotal += amount;
      taxTotal += taxAmount;
    }
    
    await invoice.save();
    
    // Send immediately if requested
    if (sendImmediately) {
      await invoice.send({
        method: 'email',
        recipient: customer.email
      });
      
      await this.sendInvoiceEmail(invoice, customer);
    }
    
    return res.status(201).json({
      status: 'success',
      data: { invoice },
      message: sendImmediately ? 'Invoice created and sent' : 'Invoice created successfully'
    });
  });
  
  /**
   * Update invoice
   * @route PUT /api/v1/billing/invoices/:invoiceId
   */
  static updateInvoice = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    const updates = req.body;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    const invoice = await Invoice.findById(invoiceId);
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    // Check permissions
    if (!req.user.isAdmin && invoice.metadata.createdBy?.toString() !== req.user._id.toString()) {
      throw new ForbiddenError('Access denied');
    }
    
    // Only allow updates to draft invoices
    if (invoice.status !== 'draft') {
      throw new ValidationError('Only draft invoices can be updated');
    }
    
    // Update allowed fields
    const allowedUpdates = [
      'dates.due',
      'billingInfo',
      'content',
      'display',
      'payment.terms',
      'payment.instructions'
    ];
    
    allowedUpdates.forEach(field => {
      if (updates[field] !== undefined) {
        invoice.set(field, updates[field]);
      }
    });
    
    // Update items if provided
    if (updates.items && Array.isArray(updates.items)) {
      invoice.items = [];
      for (const item of updates.items) {
        invoice.addItem(item);
      }
    }
    
    // Update metadata
    invoice.metadata.version++;
    invoice.metadata.previousVersions.push({
      version: invoice.metadata.version - 1,
      modifiedAt: new Date(),
      modifiedBy: req.user._id,
      changes: updates
    });
    
    await invoice.save();
    
    return res.status(200).json({
      status: 'success',
      data: { invoice },
      message: 'Invoice updated successfully'
    });
  });
  
  /**
   * Send invoice
   * @route POST /api/v1/billing/invoices/:invoiceId/send
   */
  static sendInvoice = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    const { 
      method = 'email', 
      recipient,
      cc,
      message 
    } = req.body;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    const invoice = await Invoice.findById(invoiceId)
      .populate('userId', 'firstName lastName email');
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    // Check permissions
    if (!req.user.isAdmin && invoice.userId._id.toString() !== req.user._id.toString()) {
      throw new ForbiddenError('Access denied');
    }
    
    // Send invoice
    await invoice.send({
      method,
      recipient: recipient || invoice.billingInfo.customer.email
    });
    
    // Send email
    if (method === 'email') {
      await this.sendInvoiceEmail(invoice, invoice.userId, {
        cc,
        customMessage: message
      });
    }
    
    return res.status(200).json({
      status: 'success',
      message: 'Invoice sent successfully'
    });
  });
  
  /**
   * Download invoice as PDF
   * @route GET /api/v1/billing/invoices/:invoiceId/download
   */
  static downloadInvoice = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    const { format = 'pdf' } = req.query;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    const invoice = await Invoice.findById(invoiceId)
      .populate('userId', 'firstName lastName email')
      .populate('subscriptionId');
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    // Check ownership or admin
    if (invoice.userId._id.toString() !== req.user._id.toString() && !req.user.isAdmin) {
      throw new ForbiddenError('Access denied');
    }
    
    // Generate PDF
    if (format === 'pdf') {
      const pdfBuffer = await PDFService.generateInvoicePDF(invoice);
      
      // Log download
      invoice.metadata.downloads.push({
        downloadedAt: new Date(),
        downloadedBy: req.user._id,
        format: 'pdf'
      });
      await invoice.save();
      
      res.set({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="invoice-${invoice.invoiceNumber}.pdf"`,
        'Content-Length': pdfBuffer.length
      });
      
      return res.send(pdfBuffer);
    }
    
    // Generate tax invoice data
    if (format === 'tax') {
      const taxData = await TaxService.generateTaxInvoiceData(invoice);
      
      return res.status(200).json({
        status: 'success',
        data: { taxInvoice: taxData }
      });
    }
    
    throw new ValidationError('Invalid format specified');
  });
  
  /**
   * Record manual payment
   * @route POST /api/v1/billing/invoices/:invoiceId/payments
   */
  static recordPayment = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    const {
      amount,
      method,
      reference,
      date
    } = req.body;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    if (!amount || amount <= 0) {
      throw new ValidationError('Valid payment amount is required');
    }
    
    if (!method) {
      throw new ValidationError('Payment method is required');
    }
    
    const invoice = await Invoice.findById(invoiceId);
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    // Check permissions (admin only for manual payments)
    if (!req.user.isAdmin) {
      throw new ForbiddenError('Only administrators can record manual payments');
    }
    
    // Apply payment
    const appliedAmount = await invoice.applyPayment({
      amount,
      method,
      reference,
      date: date ? new Date(date) : new Date()
    });
    
    return res.status(200).json({
      status: 'success',
      data: { 
        invoice,
        payment: {
          applied: appliedAmount,
          remaining: invoice.financials.due
        }
      },
      message: 'Payment recorded successfully'
    });
  });
  
  /**
   * Cancel invoice
   * @route POST /api/v1/billing/invoices/:invoiceId/cancel
   */
  static cancelInvoice = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    const { reason } = req.body;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    if (!reason) {
      throw new ValidationError('Cancellation reason is required');
    }
    
    const invoice = await Invoice.findById(invoiceId);
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    // Check permissions
    if (!req.user.isAdmin && invoice.metadata.createdBy?.toString() !== req.user._id.toString()) {
      throw new ForbiddenError('Access denied');
    }
    
    await invoice.cancel(reason, req.user._id);
    
    return res.status(200).json({
      status: 'success',
      data: { invoice },
      message: 'Invoice cancelled successfully'
    });
  });
  
  /**
   * Write off invoice
   * @route POST /api/v1/billing/invoices/:invoiceId/write-off
   */
  static writeOffInvoice = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    const { reason } = req.body;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    if (!reason) {
      throw new ValidationError('Write-off reason is required');
    }
    
    // Only admins can write off invoices
    if (!req.user.isAdmin) {
      throw new ForbiddenError('Only administrators can write off invoices');
    }
    
    const invoice = await Invoice.findById(invoiceId);
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    await invoice.writeOff(reason, req.user._id);
    
    return res.status(200).json({
      status: 'success',
      data: { invoice },
      message: 'Invoice written off successfully'
    });
  });
  
  /**
   * Get overdue invoices
   * @route GET /api/v1/billing/invoices/overdue
   */
  static getOverdueInvoices = asyncHandler(async (req, res) => {
    const { daysOverdue = 0 } = req.query;
    
    let query = {
      userId: req.user._id,
      status: { $in: ['pending', 'sent', 'viewed', 'overdue'] },
      'financials.due': { $gt: 0 }
    };
    
    // Admin can see all overdue invoices
    if (req.user.isAdmin) {
      delete query.userId;
    }
    
    const invoices = await Invoice.getOverdueInvoices(parseInt(daysOverdue));
    
    const overdueInvoices = invoices.filter(invoice => {
      if (!req.user.isAdmin && invoice.userId.toString() !== req.user._id.toString()) {
        return false;
      }
      return true;
    });
    
    return res.status(200).json({
      status: 'success',
      data: {
        invoices: overdueInvoices,
        count: overdueInvoices.length,
        totalOverdue: overdueInvoices.reduce((sum, inv) => sum + inv.financials.due, 0)
      }
    });
  });
  
  /**
   * Get invoice revenue statistics
   * @route GET /api/v1/billing/invoices/statistics
   */
  static getInvoiceStatistics = asyncHandler(async (req, res) => {
    const { startDate, endDate, groupBy = 'month' } = req.query;
    
    const filters = {};
    
    if (!req.user.isAdmin) {
      filters.userId = req.user._id;
    }
    
    if (startDate) filters.startDate = new Date(startDate);
    if (endDate) filters.endDate = new Date(endDate);
    
    const revenue = await Invoice.calculateRevenue(filters);
    
    // Get additional statistics
    const statusBreakdown = await Invoice.aggregate([
      { 
        $match: {
          ...filters.userId ? { userId: filters.userId } : {},
          'dates.issued': {
            ...(filters.startDate ? { $gte: filters.startDate } : {}),
            ...(filters.endDate ? { $lte: filters.endDate } : {})
          }
        }
      },
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 },
          total: { $sum: '$financials.total' }
        }
      }
    ]);
    
    return res.status(200).json({
      status: 'success',
      data: {
        revenue,
        statusBreakdown,
        period: {
          start: filters.startDate,
          end: filters.endDate
        }
      }
    });
  });
  
  /**
   * Send reminder for invoice
   * @route POST /api/v1/billing/invoices/:invoiceId/remind
   */
  static sendReminder = asyncHandler(async (req, res) => {
    const { invoiceId } = req.params;
    const { message } = req.body;
    
    if (!invoiceId.match(constants.REGEX.MONGO_ID)) {
      throw new ValidationError('Invalid invoice ID format');
    }
    
    const invoice = await Invoice.findById(invoiceId)
      .populate('userId', 'firstName lastName email');
    
    if (!invoice) {
      throw new NotFoundError('Invoice not found');
    }
    
    // Check permissions
    if (!req.user.isAdmin && invoice.userId._id.toString() !== req.user._id.toString()) {
      throw new ForbiddenError('Access denied');
    }
    
    // Check if invoice needs reminder
    if (['paid', 'cancelled', 'refunded'].includes(invoice.status)) {
      throw new ValidationError('Cannot send reminder for this invoice status');
    }
    
    // Send reminder email
    await EmailService.sendEmail({
      to: invoice.billingInfo.customer.email,
      subject: `Payment Reminder: Invoice ${invoice.invoiceNumber}`,
      template: 'invoice-reminder',
      data: {
        firstName: invoice.userId.firstName,
        invoiceNumber: invoice.invoiceNumber,
        amount: invoice.financials.due,
        currency: invoice.financials.currency,
        dueDate: invoice.dates.due,
        isOverdue: invoice.isOverdue,
        daysOverdue: invoice.daysOverdue,
        customMessage: message,
        paymentUrl: `${config.client.url}/billing/invoices/${invoice._id}`
      }
    });
    
    // Update reminder tracking
    invoice.reminders.lastSent = new Date();
    invoice.reminders.totalSent++;
    
    if (invoice.isOverdue) {
      const daysOverdue = invoice.daysOverdue;
      const overdueReminder = invoice.reminders.overdue.find(r => r.daysAfter === daysOverdue);
      if (overdueReminder) {
        overdueReminder.sent = true;
        overdueReminder.sentAt = new Date();
      }
    }
    
    await invoice.save();
    
    return res.status(200).json({
      status: 'success',
      message: 'Reminder sent successfully'
    });
  });
  
  /**
   * Helper method to send invoice email
   */
  static async sendInvoiceEmail(invoice, recipient, options = {}) {
    const pdfBuffer = await PDFService.generateInvoicePDF(invoice);
    
    await EmailService.sendEmail({
      to: recipient.email,
      cc: options.cc,
      subject: `Invoice ${invoice.invoiceNumber} from Insightserenity`,
      template: 'invoice',
      data: {
        firstName: recipient.firstName,
        invoiceNumber: invoice.invoiceNumber,
        amount: invoice.financials.total,
        currency: invoice.financials.currency,
        dueDate: invoice.dates.due,
        customMessage: options.customMessage,
        viewUrl: `${config.client.url}/billing/invoices/${invoice._id}`,
        payUrl: `${config.client.url}/billing/pay/${invoice._id}`
      },
      attachments: [{
        filename: `invoice-${invoice.invoiceNumber}.pdf`,
        content: pdfBuffer,
        contentType: 'application/pdf'
      }]
    });
  }
}

module.exports = InvoiceController;