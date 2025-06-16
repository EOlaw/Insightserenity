// server/shared/billing/models/invoice-model.js
/**
 * @file Invoice Model
 * @description Model for billing invoices
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const config = require('../../config');
const constants = require('../../config/constants');

/**
 * Invoice Schema
 */
const invoiceSchema = new mongoose.Schema({
  // References
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  
  organizationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Organization',
    index: true
  },
  
  subscriptionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Subscription',
    index: true
  },
  
  // Invoice Identification
  invoiceNumber: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  
  referenceNumber: {
    type: String,
    unique: true,
    sparse: true
  },
  
  // Invoice Type and Status
  type: {
    type: String,
    enum: constants.BILLING.INVOICE_TYPES_ENUM,
    required: true
  },
  
  status: {
    type: String,
    enum: constants.BILLING.INVOICE_STATUS_EXTENDED_ENUM,
    default: 'draft',
    index: true
  },
  
  // Dates
  dates: {
    issued: {
      type: Date,
      required: true,
      default: Date.now
    },
    
    due: {
      type: Date,
      required: true,
      index: true
    },
    
    paid: Date,
    
    sent: Date,
    viewed: Date,
    reminded: Date,
    
    period: {
      start: Date,
      end: Date
    },
    
    serviceDates: {
      start: Date,
      end: Date
    }
  },
  
  // Billing Information
  billingInfo: {
    // Customer Details
    customer: {
      name: { type: String, required: true },
      email: { type: String, required: true },
      phone: String,
      customerId: String
    },
    
    // Company Details
    company: {
      name: String,
      registrationNumber: String,
      taxId: String,
      vatNumber: String
    },
    
    // Billing Address
    address: {
      attention: String,
      street1: { type: String, required: true },
      street2: String,
      city: { type: String, required: true },
      state: String,
      country: { type: String, required: true },
      postalCode: String
    },
    
    // Shipping Address (if different)
    shippingAddress: {
      name: String,
      attention: String,
      street1: String,
      street2: String,
      city: String,
      state: String,
      country: String,
      postalCode: String
    }
  },
  
  // Line Items
  items: [{
    // Item Details
    type: {
      type: String,
      enum: constants.BILLING.INVOICE_ITEM_TYPES_ENUM
    },
    
    category: String,
    code: String,
    name: { type: String, required: true },
    description: String,
    
    // Quantities and Pricing
    quantity: {
      amount: { type: Number, default: 1 },
      unit: { type: String, default: 'unit' }
    },
    
    rate: {
      amount: { type: Number, required: true },
      unit: String
    },
    
    // Amounts
    amount: { type: Number, required: true },
    
    discount: {
      type: { type: String, enum: constants.BILLING.DISCOUNT_TYPES_ENUM },
      value: Number,
      amount: Number
    },
    
    tax: {
      rate: Number,
      amount: Number,
      name: String,
      inclusive: { type: Boolean, default: false }
    },
    
    total: { type: Number, required: true },
    
    // Additional Info
    period: {
      start: Date,
      end: Date
    },
    
    metadata: {
      subscriptionId: mongoose.Schema.Types.ObjectId,
      addonId: mongoose.Schema.Types.ObjectId,
      usageRecordId: mongoose.Schema.Types.ObjectId,
      customFields: mongoose.Schema.Types.Mixed
    }
  }],
  
  // Financial Summary
  financials: {
    // Base Amounts
    subtotal: {
      type: Number,
      required: true,
      min: 0
    },
    
    // Discounts
    discount: {
      total: { type: Number, default: 0 },
      items: [{
        type: { type: String, enum: constants.BILLING.DISCOUNT_TYPES_ENUM },
        code: String,
        description: String,
        amount: Number
      }]
    },
    
    // Taxes
    tax: {
      total: { type: Number, default: 0 },
      items: [{
        name: String,
        rate: Number,
        amount: Number,
        taxableAmount: Number
      }]
    },
    
    // Final Amounts
    total: {
      type: Number,
      required: true,
      min: 0
    },
    
    paid: {
      type: Number,
      default: 0,
      min: 0
    },
    
    due: {
      type: Number,
      required: true,
      min: 0
    },
    
    credit: {
      applied: { type: Number, default: 0 },
      remaining: { type: Number, default: 0 }
    },
    
    // Currency
    currency: {
      type: String,
      enum: constants.BILLING.CURRENCIES_ENUM,
      default: 'USD',
      uppercase: true
    },
    
    exchangeRate: {
      rate: Number,
      from: String,
      to: String,
      date: Date
    }
  },
  
  // Payment Information
  payment: {
    method: {
      type: String,
      enum: constants.BILLING.PAYMENT_METHOD_TYPES_ENUM
    },
    
    terms: {
      type: String,
      enum: constants.BILLING.PAYMENT_TERMS_ENUM,
      default: 'net_30'
    },
    
    customTerms: {
      days: Number,
      description: String
    },
    
    instructions: String,
    reference: String,
    
    // Transaction Details
    transactions: [{
      date: Date,
      amount: Number,
      method: String,
      reference: String,
      gateway: String,
      transactionId: String,
      status: String,
      failureReason: String
    }]
  },
  
  // Notes and Messages
  content: {
    // Header/Footer Content
    headerNote: String,
    footerNote: String,
    
    // Terms and Conditions
    terms: String,
    
    // Internal Notes
    internalNotes: [{
      note: String,
      addedBy: mongoose.Schema.Types.ObjectId,
      addedAt: Date
    }],
    
    // Customer Messages
    customerMessage: String,
    thankYouMessage: String
  },
  
  // Attachments
  attachments: [{
    name: String,
    type: String,
    size: Number,
    url: String,
    uploadedBy: mongoose.Schema.Types.ObjectId,
    uploadedAt: Date
  }],
  
  // Reminders and Follow-ups
  reminders: {
    enabled: { type: Boolean, default: true },
    
    schedule: [{
      daysBefore: Number,
      sent: { type: Boolean, default: false },
      sentAt: Date,
      method: String,
      status: String
    }],
    
    overdue: [{
      daysAfter: Number,
      sent: { type: Boolean, default: false },
      sentAt: Date,
      method: String,
      status: String
    }],
    
    lastSent: Date,
    totalSent: { type: Number, default: 0 }
  },
  
  // Compliance and Legal
  compliance: {
    // Tax Compliance
    taxExempt: { type: Boolean, default: false },
    taxExemptionReason: String,
    taxExemptionCertificate: String,
    
    // Regulatory
    requiresSignature: { type: Boolean, default: false },
    signedBy: String,
    signedAt: Date,
    signatureData: String,
    
    // Audit Trail
    approved: {
      required: { type: Boolean, default: false },
      by: mongoose.Schema.Types.ObjectId,
      at: Date,
      notes: String
    }
  },
  
  // External Integrations
  external: {
    stripeInvoiceId: String,
    paypalInvoiceId: String,
    quickbooksInvoiceId: String,
    xeroInvoiceId: String,
    freshbooksInvoiceId: String,
    customIntegrations: mongoose.Schema.Types.Mixed
  },
  
  // Display Settings
  display: {
    template: {
      type: String,
      enum: constants.BILLING.INVOICE_TEMPLATE_TYPES_ENUM,
      default: 'default'
    },
    
    branding: {
      logo: String,
      color: String,
      font: String
    },
    
    language: {
      type: String,
      default: 'en'
    },
    
    showPaymentInstructions: { type: Boolean, default: true },
    showRemittanceSlip: { type: Boolean, default: false },
    showCustomerNotes: { type: Boolean, default: true }
  },
  
  // Metadata
  metadata: {
    // Creation Info
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    
    source: {
      type: String,
      enum: constants.BILLING.INVOICE_SOURCE_TYPES_ENUM,
      default: 'system'
    },
    
    // Analytics
    views: [{
      viewedAt: Date,
      viewedBy: String, // Can be email for non-users
      ipAddress: String,
      userAgent: String
    }],
    
    downloads: [{
      downloadedAt: Date,
      downloadedBy: mongoose.Schema.Types.ObjectId,
      format: String
    }],
    
    // Custom Fields
    customFields: mongoose.Schema.Types.Mixed,
    tags: [String],
    
    // Version Control
    version: { type: Number, default: 1 },
    previousVersions: [{
      version: Number,
      modifiedAt: Date,
      modifiedBy: mongoose.Schema.Types.ObjectId,
      changes: mongoose.Schema.Types.Mixed
    }]
  },
  
  // Events and History
  history: [{
    event: {
      type: String,
      enum: constants.BILLING.INVOICE_EVENT_TYPES_ENUM
    },
    timestamp: { type: Date, default: Date.now },
    actor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    details: mongoose.Schema.Types.Mixed,
    ipAddress: String
  }]
}, {
  timestamps: true,
  collection: 'invoices'
});

/**
 * Virtual Properties
 */

// Indexes
invoiceSchema.index({ status: 1, 'dates.due': 1 });
invoiceSchema.index({ 'billingInfo.customer.email': 1 });
invoiceSchema.index({ 'dates.issued': -1 });
invoiceSchema.index({ type: 1, status: 1 });
invoiceSchema.index({ 'external.stripeInvoiceId': 1 });

// Virtual for is overdue
invoiceSchema.virtual('isOverdue').get(function() {
  return this.status === 'pending' && 
         this.dates.due < new Date() && 
         this.financials.due > 0;
});


// Virtual for days overdue
invoiceSchema.virtual('daysOverdue').get(function() {
  if (!this.isOverdue) return 0;
  
  const days = Math.floor((new Date() - this.dates.due) / (1000 * 60 * 60 * 24));
  return Math.max(0, days);
});

// Virtual for payment status
invoiceSchema.virtual('paymentStatus').get(function() {
  if (this.financials.paid >= this.financials.total) return 'paid';
  if (this.financials.paid > 0) return 'partial';
  if (this.isOverdue) return 'overdue';
  return 'pending';
});

/**
 * Instance Methods
 */

// Calculate totals
invoiceSchema.methods.calculateTotals = function() {
  let subtotal = 0;
  let taxTotal = 0;
  let discountTotal = 0;
  
  // Calculate from line items
  this.items.forEach(item => {
    if (item.type === 'discount') {
      discountTotal += Math.abs(item.total);
    } else if (item.type === 'tax') {
      taxTotal += item.total;
    } else {
      subtotal += item.amount;
      if (item.discount) {
        discountTotal += item.discount.amount || 0;
      }
      if (item.tax && !item.tax.inclusive) {
        taxTotal += item.tax.amount || 0;
      }
    }
  });
  
  // Update financials
  this.financials.subtotal = subtotal;
  this.financials.discount.total = discountTotal;
  this.financials.tax.total = taxTotal;
  this.financials.total = Math.max(0, subtotal - discountTotal + taxTotal);
  this.financials.due = Math.max(0, this.financials.total - this.financials.paid - this.financials.credit.applied);
};

// Add line item
invoiceSchema.methods.addItem = function(item) {
  // Calculate item total
  const amount = item.quantity.amount * item.rate.amount;
  let discountAmount = 0;
  let taxAmount = 0;
  
  if (item.discount) {
    if (item.discount.type === 'percentage') {
      discountAmount = amount * (item.discount.value / 100);
    } else {
      discountAmount = item.discount.value;
    }
  }
  
  const discountedAmount = amount - discountAmount;
  
  if (item.tax && item.tax.rate) {
    taxAmount = discountedAmount * (item.tax.rate / 100);
  }
  
  item.amount = amount;
  item.discount.amount = discountAmount;
  item.tax.amount = taxAmount;
  item.total = item.tax.inclusive ? discountedAmount : discountedAmount + taxAmount;
  
  this.items.push(item);
  this.calculateTotals();
};

// Apply payment
invoiceSchema.methods.applyPayment = function(payment) {
  if (payment.amount <= 0) {
    throw new Error('Payment amount must be positive');
  }
  
  const maxPayment = this.financials.due;
  const appliedAmount = Math.min(payment.amount, maxPayment);
  
  this.financials.paid += appliedAmount;
  this.financials.due = Math.max(0, this.financials.total - this.financials.paid);
  
  // Add payment transaction
  this.payment.transactions.push({
    date: payment.date || new Date(),
    amount: appliedAmount,
    method: payment.method,
    reference: payment.reference,
    gateway: payment.gateway,
    transactionId: payment.transactionId,
    status: 'completed'
  });
  
  // Update status
  if (this.financials.due === 0) {
    this.status = 'paid';
    this.dates.paid = new Date();
  } else if (this.financials.paid > 0) {
    this.status = 'partial';
  }
  
  // Add to history
  this.history.push({
    event: this.financials.due === 0 ? 'paid' : 'partial_payment',
    details: payment
  });
  
  return appliedAmount;
};

// Send invoice
invoiceSchema.methods.send = async function(options = {}) {
  if (this.status === 'draft') {
    this.status = 'pending';
  }
  
  this.dates.sent = new Date();
  
  // Add to history
  this.history.push({
    event: 'sent',
    details: {
      method: options.method || 'email',
      recipient: options.recipient || this.billingInfo.customer.email
    }
  });
  
  return this.save();
};

// Mark as viewed
invoiceSchema.methods.markAsViewed = function(viewer = {}) {
  if (!this.dates.viewed) {
    this.dates.viewed = new Date();
    this.status = this.status === 'sent' ? 'viewed' : this.status;
  }
  
  this.metadata.views.push({
    viewedAt: new Date(),
    viewedBy: viewer.email || viewer.id,
    ipAddress: viewer.ipAddress,
    userAgent: viewer.userAgent
  });
  
  return this.save();
};

// Cancel invoice
invoiceSchema.methods.cancel = function(reason, actor) {
  if (['paid', 'refunded', 'cancelled'].includes(this.status)) {
    throw new Error(`Cannot cancel invoice with status: ${this.status}`);
  }
  
  this.status = 'cancelled';
  
  this.history.push({
    event: 'cancelled',
    actor,
    details: { reason }
  });
  
  return this.save();
};

// Write off invoice
invoiceSchema.methods.writeOff = function(reason, actor) {
  if (this.status !== 'overdue') {
    throw new Error('Can only write off overdue invoices');
  }
  
  this.status = 'written_off';
  
  this.history.push({
    event: 'written_off',
    actor,
    details: { 
      reason,
      amount: this.financials.due
    }
  });
  
  return this.save();
};

/**
 * Static Methods
 */

// Generate invoice number
invoiceSchema.statics.generateInvoiceNumber = async function(prefix = 'INV') {
  const date = new Date();
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  
  // Find the latest invoice for this month
  const latestInvoice = await this.findOne({
    invoiceNumber: new RegExp(`^${prefix}-${year}${month}`)
  }).sort({ invoiceNumber: -1 });
  
  let sequence = 1;
  if (latestInvoice) {
    const match = latestInvoice.invoiceNumber.match(/(\d{4})$/);
    if (match) {
      sequence = parseInt(match[1]) + 1;
    }
  }
  
  return `${prefix}-${year}${month}${String(sequence).padStart(4, '0')}`;
};

// Get overdue invoices
invoiceSchema.statics.getOverdueInvoices = async function(daysOverdue = 0) {
  const overdueDate = new Date();
  overdueDate.setDate(overdueDate.getDate() - daysOverdue);
  
  return this.find({
    status: { $in: ['pending', 'sent', 'viewed'] },
    'dates.due': { $lt: overdueDate },
    'financials.due': { $gt: 0 }
  });
};

// Get invoices by date range
invoiceSchema.statics.getByDateRange = async function(startDate, endDate, filters = {}) {
  const query = {
    'dates.issued': {
      $gte: startDate,
      $lte: endDate
    }
  };
  
  if (filters.status) query.status = filters.status;
  if (filters.type) query.type = filters.type;
  if (filters.userId) query.userId = filters.userId;
  if (filters.organizationId) query.organizationId = filters.organizationId;
  
  return this.find(query).sort({ 'dates.issued': -1 });
};

// Calculate revenue statistics
invoiceSchema.statics.calculateRevenue = async function(filters = {}) {
  const match = { status: 'paid' };
  
  if (filters.startDate) {
    match['dates.paid'] = { $gte: filters.startDate };
  }
  if (filters.endDate) {
    match['dates.paid'] = { ...match['dates.paid'], $lte: filters.endDate };
  }
  if (filters.type) match.type = filters.type;
  
  const result = await this.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        total: { $sum: '$financials.total' },
        paid: { $sum: '$financials.paid' },
        count: { $sum: 1 },
        avgInvoiceValue: { $avg: '$financials.total' }
      }
    }
  ]);
  
  return result[0] || { total: 0, paid: 0, count: 0, avgInvoiceValue: 0 };
};

// Pre-save middleware
invoiceSchema.pre('save', async function(next) {
  // Generate invoice number if not present
  if (!this.invoiceNumber && this.isNew) {
    this.invoiceNumber = await this.constructor.generateInvoiceNumber();
  }
  
  // Recalculate totals
  this.calculateTotals();
  
  // Update status based on payment
  if (this.financials.paid >= this.financials.total && this.status !== 'refunded') {
    this.status = 'paid';
    if (!this.dates.paid) {
      this.dates.paid = new Date();
    }
  }
  
  // Check if overdue
  if (this.status === 'pending' && this.dates.due < new Date() && this.financials.due > 0) {
    this.status = 'overdue';
  }
  
  next();
});

// Create and export model
const Invoice = mongoose.model('Invoice', invoiceSchema);

module.exports = Invoice;