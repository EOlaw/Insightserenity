// server/shared/billing/models/payment-model.js
/**
 * @file Payment Model
 * @description Model for payment transactions
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const config = require('../../config');
const constants = require('../../config/constants');

/**
 * Payment Schema
 */
const paymentSchema = new mongoose.Schema({
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
  
  invoiceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Invoice',
    index: true
  },
  
  subscriptionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Subscription',
    index: true
  },
  
  // Payment Identification
  paymentId: {
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
  
  // Payment Details
  type: {
    type: String,
    enum: constants.BILLING.PAYMENT_TYPES_ENUM,
    default: 'payment',
    required: true
  },
  
  status: {
    type: String,
    enum: constants.BILLING.PAYMENT_STATUS_ENUM,
    required: true,
    default: 'pending',
    index: true
  },
  
  // Financial Information
  amount: {
    value: {
      type: Number,
      required: true,
      min: 0
    },
    
    currency: {
      type: String,
      enum: constants.BILLING.CURRENCIES_ENUM,
      required: true,
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
  
  fees: {
    processing: {
      amount: { type: Number, default: 0 },
      percentage: Number,
      fixed: Number
    },
    
    gateway: {
      amount: { type: Number, default: 0 },
      percentage: Number,
      fixed: Number
    },
    
    platform: {
      amount: { type: Number, default: 0 },
      percentage: Number,
      fixed: Number
    },
    
    total: { type: Number, default: 0 },
    
    breakdown: [{
      type: String,
      description: String,
      amount: Number
    }]
  },
  
  netAmount: {
    type: Number,
    required: true
  },
  
  // Payment Method
  method: {
    type: {
      type: String,
      enum: constants.BILLING.PAYMENT_METHOD_TYPES_ENUM,
      required: true
    },
    
    // Card Details
    card: {
      brand: {
        type: String,
        enum: constants.BILLING.CARD_BRANDS_ENUM
      },
      lastFourDigits: String,
      expiryMonth: Number,
      expiryYear: Number,
      holderName: String,
      fingerprint: String, // For duplicate detection
      country: String,
      funding: {
        type: String,
        enum: constants.BILLING.CARD_FUNDING_TYPES_ENUM
      },
      threeDSecure: {
        used: Boolean,
        version: String,
        succeeded: Boolean
      }
    },
    
    // Bank Account Details
    bankAccount: {
      accountType: {
        type: String,
        enum: constants.BILLING.BANK_ACCOUNT_TYPES_ENUM
      },
      lastFourDigits: String,
      routingNumber: String,
      bankName: String,
      accountHolderName: String,
      accountHolderType: {
        type: String,
        enum: constants.BILLING.ACCOUNT_HOLDER_TYPES_ENUM
      }
    },
    
    // PayPal Details
    paypal: {
      email: String,
      payerId: String,
      payerStatus: String
    },
    
    // Cryptocurrency Details
    crypto: {
      type: {
        type: String,
        enum: constants.BILLING.CRYPTO_TYPES_ENUM
      },
      address: String,
      transactionHash: String,
      network: String,
      confirmations: Number
    },
    
    // Check Details
    check: {
      number: String,
      bankName: String,
      memo: String
    },
    
    // Wire Transfer Details
    wireTransfer: {
      referenceNumber: String,
      bankName: String,
      swiftCode: String
    }
  },
  
  // Gateway Information
  gateway: {
    provider: {
      type: String,
      enum: constants.BILLING.GATEWAY_PROVIDERS_ENUM,
      required: true
    },
    
    transactionId: {
      type: String,
      index: true
    },
    
    customerId: String,
    paymentMethodId: String,
    
    response: {
      raw: mongoose.Schema.Types.Mixed,
      code: String,
      message: String,
      avsCheck: String,
      cvcCheck: String,
      riskScore: Number,
      riskLevel: String
    },
    
    webhookId: String,
    idempotencyKey: String
  },
  
  // Processing Information
  processing: {
    attemptCount: {
      type: Number,
      default: 1
    },
    
    attempts: [{
      attemptNumber: Number,
      timestamp: Date,
      status: String,
      errorCode: String,
      errorMessage: String,
      gatewayResponse: mongoose.Schema.Types.Mixed
    }],
    
    startedAt: Date,
    completedAt: Date,
    failedAt: Date,
    
    retryAfter: Date,
    maxRetries: {
      type: Number,
      default: 3
    }
  },
  
  // Refund Information
  refund: {
    amount: Number,
    reason: {
      type: String,
      enum: constants.BILLING.REFUND_REASONS_ENUM
    },
    
    description: String,
    requestedAt: Date,
    requestedBy: mongoose.Schema.Types.ObjectId,
    approvedBy: mongoose.Schema.Types.ObjectId,
    
    processedAt: Date,
    refundId: String,
    
    partial: {
      isPartial: { type: Boolean, default: false },
      remainingAmount: Number
    },
    
    metadata: mongoose.Schema.Types.Mixed
  },
  
  // Dispute/Chargeback Information
  dispute: {
    status: {
      type: String,
      enum: constants.BILLING.DISPUTE_STATUS_ENUM
    },
    
    reason: {
      type: String,
      enum: constants.BILLING.DISPUTE_REASONS_ENUM
    },
    
    amount: Number,
    currency: String,
    
    createdAt: Date,
    dueBy: Date,
    
    evidence: {
      submitted: Boolean,
      submittedAt: Date,
      documents: [{
        type: String,
        url: String,
        description: String
      }],
      customerCommunication: String,
      receipt: String,
      serviceDocumentation: String,
      shippingDocumentation: String,
      uncategorizedText: String
    },
    
    outcome: {
      status: String,
      reason: String,
      settledAt: Date
    }
  },
  
  // Source Information
  source: {
    type: {
      type: String,
      enum: constants.BILLING.PAYMENT_SOURCE_TYPES_ENUM,
      default: 'checkout'
    },
    
    ipAddress: String,
    userAgent: String,
    
    location: {
      country: String,
      state: String,
      city: String,
      postalCode: String,
      coordinates: {
        latitude: Number,
        longitude: Number
      }
    },
    
    device: {
      id: String,
      type: String,
      os: String,
      browser: String
    }
  },
  
  // Customer Information
  customer: {
    name: String,
    email: String,
    phone: String,
    
    billingAddress: {
      street1: String,
      street2: String,
      city: String,
      state: String,
      country: String,
      postalCode: String
    },
    
    shippingAddress: {
      name: String,
      street1: String,
      street2: String,
      city: String,
      state: String,
      country: String,
      postalCode: String
    },
    
    taxId: String,
    customerId: String
  },
  
  // Compliance and Risk
  compliance: {
    // PCI Compliance
    pci: {
      compliant: { type: Boolean, default: true },
      version: String,
      validatedAt: Date
    },
    
    // AML/KYC
    aml: {
      checked: Boolean,
      status: String,
      checkedAt: Date,
      provider: String
    },
    
    // Risk Assessment
    risk: {
      score: Number,
      level: {
        type: String,
        enum: constants.BILLING.RISK_LEVELS_ENUM
      },
      
      factors: [{
        factor: String,
        weight: Number,
        details: String
      }],
      
      rules: [{
        rule: String,
        triggered: Boolean,
        action: String
      }],
      
      manualReview: {
        required: Boolean,
        reviewedBy: mongoose.Schema.Types.ObjectId,
        reviewedAt: Date,
        decision: String,
        notes: String
      }
    },
    
    // Tax
    tax: {
      collected: Boolean,
      amount: Number,
      rate: Number,
      jurisdiction: String,
      exemptionReason: String
    }
  },
  
  // Notifications
  notifications: {
    customer: {
      receipt: {
        sent: { type: Boolean, default: false },
        sentAt: Date,
        method: String,
        status: String
      },
      
      refund: {
        sent: Boolean,
        sentAt: Date,
        method: String,
        status: String
      }
    },
    
    admin: {
      failure: {
        sent: Boolean,
        sentAt: Date,
        recipients: [String]
      },
      
      dispute: {
        sent: Boolean,
        sentAt: Date,
        recipients: [String]
      },
      
      highRisk: {
        sent: Boolean,
        sentAt: Date,
        recipients: [String]
      }
    }
  },
  
  // Metadata
  metadata: {
    // Order/Cart Information
    order: {
      orderId: String,
      items: [{
        name: String,
        quantity: Number,
        price: Number
      }],
      shippingMethod: String,
      trackingNumber: String
    },
    
    // Custom Fields
    customFields: mongoose.Schema.Types.Mixed,
    tags: [String],
    notes: String,
    
    // Integration Data
    externalReferences: [{
      system: String,
      id: String,
      type: String
    }],
    
    // Analytics
    attribution: {
      source: String,
      medium: String,
      campaign: String,
      content: String,
      term: String
    }
  },
  
  // Reconciliation
  reconciliation: {
    status: {
      type: String,
      enum: constants.BILLING.RECONCILIATION_STATUS_ENUM,
      default: 'pending'
    },
    
    matchedAt: Date,
    matchedBy: mongoose.Schema.Types.ObjectId,
    
    bankTransaction: {
      id: String,
      date: Date,
      amount: Number,
      reference: String
    },
    
    discrepancy: {
      amount: Number,
      reason: String,
      resolvedAt: Date,
      resolvedBy: mongoose.Schema.Types.ObjectId
    }
  },
  
  // Audit Trail
  history: [{
    event: {
      type: String,
      enum: constants.AUTH.LOGIN_HISTORY_EVENT_TYPES_ENUM
    },
    timestamp: { type: Date, default: Date.now },
    actor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    changes: mongoose.Schema.Types.Mixed,
    reason: String,
    ipAddress: String
  }]
}, {
  timestamps: true,
  collection: 'payments'
});

// Indexes
paymentSchema.index({ status: 1, createdAt: -1 });
paymentSchema.index({ 'gateway.transactionId': 1 });
paymentSchema.index({ 'method.type': 1, status: 1 });
paymentSchema.index({ 'processing.retryAfter': 1 });
paymentSchema.index({ createdAt: -1 });

// Virtual for processing duration
paymentSchema.virtual('processingDuration').get(function() {
  if (!this.processing.startedAt || !this.processing.completedAt) return null;
  
  return this.processing.completedAt - this.processing.startedAt;
});

// Virtual for is successful
paymentSchema.virtual('isSuccessful').get(function() {
  return this.status === 'succeeded';
});

// Virtual for is refundable
paymentSchema.virtual('isRefundable').get(function() {
  return this.status === 'succeeded' && 
         this.type === 'payment' &&
         (!this.refund.amount || this.refund.amount < this.amount.value);
});

// Virtual for requires retry
paymentSchema.virtual('requiresRetry').get(function() {
  return this.status === 'failed' && 
         this.processing.attemptCount < this.processing.maxRetries &&
         (!this.processing.retryAfter || this.processing.retryAfter <= new Date());
});

/**
 * Instance Methods
 */

// Process payment
paymentSchema.methods.process = async function() {
  if (this.status !== 'pending') {
    throw new Error(`Cannot process payment with status: ${this.status}`);
  }
  
  this.status = 'processing';
  this.processing.startedAt = new Date();
  
  // Add to history
  this.history.push({
    event: 'processed',
    timestamp: new Date()
  });
  
  return this.save();
};

// Mark as succeeded
paymentSchema.methods.markAsSucceeded = function(gatewayResponse) {
  this.status = 'succeeded';
  this.processing.completedAt = new Date();
  
  if (gatewayResponse) {
    this.gateway.response = {
      raw: gatewayResponse,
      code: gatewayResponse.code || 'success',
      message: gatewayResponse.message || 'Payment successful'
    };
  }
  
  // Calculate net amount
  this.netAmount = this.amount.value - this.fees.total;
  
  // Add to history
  this.history.push({
    event: 'succeeded',
    timestamp: new Date(),
    changes: { status: 'succeeded' }
  });
  
  // Continuing payment-model.js...

  return this.save();
};

// Mark as failed
paymentSchema.methods.markAsFailed = function(error, canRetry = true) {
  this.status = 'failed';
  this.processing.failedAt = new Date();
  
  // Record attempt
  this.processing.attempts.push({
    attemptNumber: this.processing.attemptCount,
    timestamp: new Date(),
    status: 'failed',
    errorCode: error.code,
    errorMessage: error.message,
    gatewayResponse: error.gatewayResponse
  });
  
  // Set retry if applicable
  if (canRetry && this.processing.attemptCount < this.processing.maxRetries) {
    const retryDelay = Math.pow(2, this.processing.attemptCount) * 60000; // Exponential backoff
    this.processing.retryAfter = new Date(Date.now() + retryDelay);
  }
  
  // Add to history
  this.history.push({
    event: 'failed',
    timestamp: new Date(),
    changes: { 
      status: 'failed',
      error: error.message
    }
  });
  
  return this.save();
};

// Process refund
paymentSchema.methods.processRefund = async function(refundData) {
  if (!this.isRefundable) {
    throw new Error('Payment is not refundable');
  }
  
  const maxRefundable = this.amount.value - (this.refund.amount || 0);
  const refundAmount = refundData.amount || maxRefundable;
  
  if (refundAmount > maxRefundable) {
    throw new Error(`Maximum refundable amount is ${maxRefundable}`);
  }
  
  this.refund = {
    ...this.refund,
    amount: (this.refund.amount || 0) + refundAmount,
    reason: refundData.reason,
    description: refundData.description,
    requestedAt: new Date(),
    requestedBy: refundData.requestedBy,
    partial: {
      isPartial: refundAmount < this.amount.value,
      remainingAmount: this.amount.value - refundAmount
    }
  };
  
  if (refundAmount >= this.amount.value) {
    this.status = 'refunded';
    this.type = 'refund';
  }
  
  // Add to history
  this.history.push({
    event: 'refunded',
    timestamp: new Date(),
    actor: refundData.requestedBy,
    changes: { 
      refundAmount,
      totalRefunded: this.refund.amount
    }
  });
  
  return this.save();
};

// Add dispute
paymentSchema.methods.addDispute = function(disputeData) {
  if (this.status !== 'succeeded') {
    throw new Error('Can only dispute successful payments');
  }
  
  this.status = 'disputed';
  this.dispute = {
    ...disputeData,
    createdAt: new Date()
  };
  
  // Add to history
  this.history.push({
    event: 'disputed',
    timestamp: new Date(),
    changes: { 
      status: 'disputed',
      disputeReason: disputeData.reason
    }
  });
  
  return this.save();
};

// Calculate fees
paymentSchema.methods.calculateFees = function() {
  let totalFees = 0;
  
  // Processing fee
  if (this.fees.processing.percentage) {
    this.fees.processing.amount = this.amount.value * (this.fees.processing.percentage / 100);
  }
  if (this.fees.processing.fixed) {
    this.fees.processing.amount += this.fees.processing.fixed;
  }
  totalFees += this.fees.processing.amount;
  
  // Gateway fee
  if (this.fees.gateway.percentage) {
    this.fees.gateway.amount = this.amount.value * (this.fees.gateway.percentage / 100);
  }
  if (this.fees.gateway.fixed) {
    this.fees.gateway.amount += this.fees.gateway.fixed;
  }
  totalFees += this.fees.gateway.amount;
  
  // Platform fee
  if (this.fees.platform.percentage) {
    this.fees.platform.amount = this.amount.value * (this.fees.platform.percentage / 100);
  }
  if (this.fees.platform.fixed) {
    this.fees.platform.amount += this.fees.platform.fixed;
  }
  totalFees += this.fees.platform.amount;
  
  this.fees.total = totalFees;
  this.netAmount = this.amount.value - totalFees;
};

/**
 * Static Methods
 */

// Generate payment ID
paymentSchema.statics.generatePaymentId = async function(prefix = 'PAY') {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${prefix}_${timestamp}${random}`.toUpperCase();
};

// Get payments for retry
paymentSchema.statics.getPaymentsForRetry = async function() {
  return this.find({
    status: 'failed',
    'processing.retryAfter': { $lte: new Date() },
    'processing.attemptCount': { $lt: '$processing.maxRetries' }
  });
};

// Get payment statistics
paymentSchema.statics.getStatistics = async function(filters = {}) {
  const match = {};
  
  if (filters.startDate) {
    match.createdAt = { $gte: filters.startDate };
  }
  if (filters.endDate) {
    match.createdAt = { ...match.createdAt, $lte: filters.endDate };
  }
  if (filters.status) match.status = filters.status;
  if (filters.type) match.type = filters.type;
  
  const stats = await this.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        totalCount: { $sum: 1 },
        successCount: {
          $sum: { $cond: [{ $eq: ['$status', 'succeeded'] }, 1, 0] }
        },
        failedCount: {
          $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
        },
        totalAmount: {
          $sum: { $cond: [{ $eq: ['$status', 'succeeded'] }, '$amount.value', 0] }
        },
        totalFees: {
          $sum: { $cond: [{ $eq: ['$status', 'succeeded'] }, '$fees.total', 0] }
        },
        totalNet: {
          $sum: { $cond: [{ $eq: ['$status', 'succeeded'] }, '$netAmount', 0] }
        },
        avgAmount: {
          $avg: { $cond: [{ $eq: ['$status', 'succeeded'] }, '$amount.value', null] }
        },
        refundedAmount: {
          $sum: { $cond: [{ $eq: ['$status', 'refunded'] }, '$refund.amount', 0] }
        }
      }
    },
    {
      $project: {
        _id: 0,
        totalCount: 1,
        successCount: 1,
        failedCount: 1,
        successRate: {
          $multiply: [{ $divide: ['$successCount', '$totalCount'] }, 100]
        },
        totalAmount: 1,
        totalFees: 1,
        totalNet: 1,
        avgAmount: { $round: ['$avgAmount', 2] },
        refundedAmount: 1
      }
    }
  ]);
  
  return stats[0] || {
    totalCount: 0,
    successCount: 0,
    failedCount: 0,
    successRate: 0,
    totalAmount: 0,
    totalFees: 0,
    totalNet: 0,
    avgAmount: 0,
    refundedAmount: 0
  };
};

// Get payment by gateway transaction ID
paymentSchema.statics.getByGatewayTransactionId = async function(transactionId, gateway) {
  return this.findOne({
    'gateway.transactionId': transactionId,
    'gateway.provider': gateway
  });
};

// Pre-save middleware
paymentSchema.pre('save', async function(next) {
  // Generate payment ID if not present
  if (!this.paymentId && this.isNew) {
    this.paymentId = await this.constructor.generatePaymentId();
  }
  
  // Calculate fees and net amount
  if (this.isModified('amount') || this.isModified('fees')) {
    this.calculateFees();
  }
  
  // Update processing attempt count
  if (this.isModified('processing.attempts')) {
    this.processing.attemptCount = this.processing.attempts.length;
  }
  
  next();
});

// Create and export model
const Payment = mongoose.model('Payment', paymentSchema);

module.exports = Payment;