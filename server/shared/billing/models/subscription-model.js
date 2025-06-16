// server/shared/billing/models/subscription-model.js
/**
 * @file Subscription Model
 * @description Model for user and organization subscriptions
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const config = require('../../config');
const constants = require('../../config/constants');

/**
 * Subscription Schema
 */
const subscriptionSchema = new mongoose.Schema({
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
  
  planId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'SubscriptionPlan',
    required: true
  },
  
  // Subscription Type
  type: {
    type: String,
    enum: constants.BILLING.SUBSCRIPTION_TYPES_ENUM,
    required: true
  },
  
  // Status
  status: {
    type: String,
    enum: constants.BILLING.SUBSCRIPTION_STATUS_ENUM,
    required: true,
    default: 'pending',
    index: true
  },
  
  // Billing Configuration
  billing: {
    cycle: {
      type: String,
      enum: constants.BILLING.SUBSCRIPTION_BILLING_CYCLES_ENUM,
      required: true
    },
    
    amount: {
      base: { type: Number, required: true },
      discount: { type: Number, default: 0 },
      tax: { type: Number, default: 0 },
      total: { type: Number, required: true }
    },
    
    currency: {
      type: String,
      enum: constants.BILLING.CURRENCIES_ENUM,
      default: 'USD',
      uppercase: true
    },
    
    paymentMethod: {
      type: String,
      enum: constants.BILLING.PAYMENT_METHOD_TYPES_ENUM,
      required: true
    },
    
    paymentDetails: {
      lastFourDigits: String,
      brand: String,
      expiryMonth: Number,
      expiryYear: Number,
      bankName: String,
      paypalEmail: String
    },
    
    invoicing: {
      enabled: { type: Boolean, default: true },
      email: String,
      frequency: {
        type: String,
        enum: ['immediate', 'monthly', 'cycle_end']
      },
      includeDetails: { type: Boolean, default: true }
    },
    
    retry: {
      enabled: { type: Boolean, default: true },
      attempts: { type: Number, default: 0 },
      maxAttempts: { type: Number, default: 3 },
      lastAttempt: Date,
      nextAttempt: Date
    }
  },
  
  // Subscription Dates
  dates: {
    started: {
      type: Date,
      required: true
    },
    
    currentPeriodStart: {
      type: Date,
      required: true
    },
    
    currentPeriodEnd: {
      type: Date,
      required: true,
      index: true
    },
    
    nextBillingDate: {
      type: Date,
      index: true
    },
    
    trialStart: Date,
    trialEnd: Date,
    
    pausedAt: Date,
    resumeAt: Date,
    
    cancelledAt: Date,
    cancellationEffective: Date,
    
    expiresAt: Date
  },
  
  // Trial Information
  trial: {
    isActive: { type: Boolean, default: false },
    type: {
      type: String,
      enum: constants.BILLING.TRIAL_TYPES_ENUM
    },
    duration: {
      value: Number,
      unit: {
        type: String,
        enum: constants.BILLING.TRIAL_DURATION_UNITS_ENUM
      }
    },
    features: {
      full: { type: Boolean, default: true },
      limitations: [String]
    },
    converted: { type: Boolean, default: false },
    conversionDate: Date,
    extendedBy: [{
      days: Number,
      reason: String,
      grantedBy: mongoose.Schema.Types.ObjectId,
      grantedAt: Date
    }]
  },
  
  // Renewal Configuration
  renewal: {
    auto: { type: Boolean, default: true },
    reminder: {
      enabled: { type: Boolean, default: true },
      daysBefore: { type: Number, default: 7 },
      sent: { type: Boolean, default: false },
      sentAt: Date
    },
    locked: { type: Boolean, default: false }, // Prevent auto-cancellation
    lockedReason: String
  },
  
  // Usage Tracking
  usage: {
    users: {
      current: { type: Number, default: 1 },
      limit: Number,
      overage: { type: Number, default: 0 },
      overageRate: Number
    },
    
    storage: {
      current: { type: Number, default: 0 }, // in MB
      limit: Number, // in GB
      overage: { type: Number, default: 0 },
      overageRate: Number
    },
    
    projects: {
      current: { type: Number, default: 0 },
      limit: Number,
      overage: { type: Number, default: 0 },
      overageRate: Number
    },
    
    apiCalls: {
      current: { type: Number, default: 0 },
      limit: Number,
      overage: { type: Number, default: 0 },
      overageRate: Number,
      resetDate: Date
    },
    
    customMetrics: [{
      metric: String,
      current: Number,
      limit: Number,
      unit: String,
      overage: Number,
      overageRate: Number
    }],
    
    lastUpdated: Date
  },
  
  // Discounts and Promotions
  discounts: [{
    code: String,
    type: {
      type: String,
      enum: constants.BILLING.DISCOUNT_FEATURE_TYPES_ENUM
    },
    value: Number,
    description: String,
    source: {
      type: String,
      enum: constants.BILLING.DISCOUNT_SOURCES_ENUM
    },
    appliedAt: Date,
    appliedBy: mongoose.Schema.Types.ObjectId,
    validFrom: Date,
    validUntil: Date,
    recurring: { type: Boolean, default: false },
    remainingUses: Number,
    conditions: mongoose.Schema.Types.Mixed
  }],
  
  // Add-ons
  addons: [{
    addonId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Addon'
    },
    name: String,
    quantity: { type: Number, default: 1 },
    price: {
      unit: Number,
      total: Number,
      currency: String
    },
    billing: {
      cycle: String,
      nextBillingDate: Date
    },
    status: {
      type: String,
      enum: constants.BILLING.ADDON_STATUS_ENUM,
      default: 'active'
    },
    startDate: Date,
    endDate: Date,
    usage: mongoose.Schema.Types.Mixed
  }],
  
  // Payment History Summary
  paymentSummary: {
    totalPaid: { type: Number, default: 0 },
    lastPaymentDate: Date,
    lastPaymentAmount: Number,
    failedPayments: { type: Number, default: 0 },
    outstandingBalance: { type: Number, default: 0 },
    credits: { type: Number, default: 0 }
  },
  
  // Cancellation Details
  cancellation: {
    reason: {
      type: String,
      enum: constants.BILLING.CANCELLATION_REASONS_ENUM
    },
    feedback: String,
    competitor: String,
    wouldRecommend: Number, // 1-10 scale
    requestedBy: mongoose.Schema.Types.ObjectId,
    processedBy: mongoose.Schema.Types.ObjectId,
    preventedBy: mongoose.Schema.Types.ObjectId,
    preventionReason: String,
    retentionOffer: mongoose.Schema.Types.Mixed
  },
  
  // External References
  external: {
    stripeSubscriptionId: String,
    stripeCustomerId: String,
    stripePaymentMethodId: String,
    paypalSubscriptionId: String,
    paypalAgreementId: String,
    chargebeeSubscriptionId: String,
    quickbooksCustomerId: String
  },
  
  // Custom Features/Overrides
  customizations: {
    features: [{
      key: String,
      value: mongoose.Schema.Types.Mixed,
      grantedBy: mongoose.Schema.Types.ObjectId,
      grantedAt: Date,
      expiresAt: Date,
      reason: String
    }],
    
    limits: [{
      resource: String,
      limit: Number,
      grantedBy: mongoose.Schema.Types.ObjectId,
      grantedAt: Date,
      expiresAt: Date,
      reason: String
    }],
    
    pricing: {
      override: { type: Boolean, default: false },
      customAmount: Number,
      reason: String,
      approvedBy: mongoose.Schema.Types.ObjectId,
      validUntil: Date
    }
  },
  
  // Notifications
  notifications: {
    preferences: {
      renewal: { type: Boolean, default: true },
      usage: { type: Boolean, default: true },
      billing: { type: Boolean, default: true },
      updates: { type: Boolean, default: true }
    },
    
    sent: [{
      type: String,
      subject: String,
      sentAt: Date,
      channel: {
        type: String,
        enum: constants.NOTIFICATION.CHANNELS_ENUM
      },
      status: String,
      error: String
    }]
  },
  
  // Metadata
  metadata: {
    source: {
      type: String,
      enum: constants.BILLING.INVOICE_SOURCE_TYPES_ENUM
    },
    campaign: String,
    referrer: String,
    referralCode: String,
    salesRep: mongoose.Schema.Types.ObjectId,
    partner: String,
    
    migrated: {
      from: String,
      date: Date,
      by: mongoose.Schema.Types.ObjectId
    },
    
    tags: [String],
    notes: [{
      content: String,
      addedBy: mongoose.Schema.Types.ObjectId,
      addedAt: Date,
      type: {
        type: String,
        enum: constants.BILLING.NOTE_TYPES_ENUM
      }
    }],
    
    customFields: mongoose.Schema.Types.Mixed
  },
  
  // History and Events
  history: [{
    event: {
      type: String,
      enum: constants.BILLING.SUBSCRIPTION_EVENT_TYPES_ENUM
    },
    timestamp: { type: Date, default: Date.now },
    details: mongoose.Schema.Types.Mixed,
    previousValue: mongoose.Schema.Types.Mixed,
    newValue: mongoose.Schema.Types.Mixed,
    actor: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    reason: String,
    ipAddress: String
  }]
}, {
  timestamps: true,
  collection: 'subscriptions'
});

// Indexes
subscriptionSchema.index({ userId: 1, status: 1 });
subscriptionSchema.index({ organizationId: 1, status: 1 });
subscriptionSchema.index({ status: 1, 'dates.nextBillingDate': 1 });
subscriptionSchema.index({ 'external.stripeSubscriptionId': 1 });
subscriptionSchema.index({ 'dates.currentPeriodEnd': 1 });
subscriptionSchema.index({ 'trial.isActive': 1, 'dates.trialEnd': 1 });

// Virtual for days remaining
subscriptionSchema.virtual('daysRemaining').get(function() {
  if (this.status !== 'active' && this.status !== 'trial') return 0;
  
  const endDate = this.status === 'trial' ? this.dates.trialEnd : this.dates.currentPeriodEnd;
  if (!endDate) return 0;
  
  const days = Math.ceil((endDate - new Date()) / (1000 * 60 * 60 * 24));
  return Math.max(0, days);
});

// Virtual for is expired
subscriptionSchema.virtual('isExpired').get(function() {
  return this.status === 'expired' || 
         (this.dates.expiresAt && this.dates.expiresAt < new Date());
});

// Virtual for needs payment
subscriptionSchema.virtual('needsPayment').get(function() {
  return this.status === 'past_due' || 
         this.paymentSummary.outstandingBalance > 0;
});

/**
 * Instance Methods
 */

// Check if subscription is active
subscriptionSchema.methods.isActive = function() {
  return ['active', 'trial'].includes(this.status) && !this.isExpired;
};

// Check feature availability
subscriptionSchema.methods.hasFeature = async function(featureKey) {
  // Check custom features first
  const customFeature = this.customizations.features.find(f => 
    f.key === featureKey && (!f.expiresAt || f.expiresAt > new Date())
  );
  
  if (customFeature) {
    return customFeature.value === true || customFeature.value > 0;
  }
  
  // Check plan features
  await this.populate('planId');
  return this.planId.hasFeature(featureKey);
};

// Get usage percentage
subscriptionSchema.methods.getUsagePercentage = function(metric) {
  const usage = this.usage[metric];
  if (!usage || !usage.limit) return 0;
  
  return Math.round((usage.current / usage.limit) * 100);
};

// Check if over limit
subscriptionSchema.methods.isOverLimit = function(metric) {
  const usage = this.usage[metric];
  if (!usage || !usage.limit) return false;
  
  return usage.current > usage.limit;
};

// Calculate overage charges
subscriptionSchema.methods.calculateOverageCharges = function() {
  let total = 0;
  
  Object.keys(this.usage).forEach(metric => {
    const usage = this.usage[metric];
    if (usage.overage > 0 && usage.overageRate) {
      total += usage.overage * usage.overageRate;
    }
  });
  
  this.usage.customMetrics?.forEach(metric => {
    if (metric.overage > 0 && metric.overageRate) {
      total += metric.overage * metric.overageRate;
    }
  });
  
  return total;
};

// Add usage
subscriptionSchema.methods.addUsage = async function(metric, amount = 1) {
  if (!this.usage[metric]) {
    throw new Error(`Unknown usage metric: ${metric}`);
  }
  
  this.usage[metric].current += amount;
  
  // Calculate overage if exceeded limit
  if (this.usage[metric].limit && this.usage[metric].current > this.usage[metric].limit) {
    this.usage[metric].overage = this.usage[metric].current - this.usage[metric].limit;
  }
  
  this.usage.lastUpdated = new Date();
  return this.save();
};

// Apply discount
subscriptionSchema.methods.applyDiscount = function(discount) {
  // Validate discount
  if (discount.validFrom && discount.validFrom > new Date()) {
    throw new Error('Discount is not yet valid');
  }
  
  if (discount.validUntil && discount.validUntil < new Date()) {
    throw new Error('Discount has expired');
  }
  
  // Check if discount already applied
  const existingDiscount = this.discounts.find(d => d.code === discount.code);
  if (existingDiscount) {
    throw new Error('Discount already applied');
  }
  
  this.discounts.push(discount);
  
  // Recalculate billing amount
  this.recalculateBilling();
  
  // Add to history
  this.history.push({
    event: 'discount_applied',
    details: discount,
    actor: discount.appliedBy
  });
  
  return this.save();
};

// Recalculate billing
subscriptionSchema.methods.recalculateBilling = async function() {
  await this.populate('planId');
  
  const baseAmount = this.planId.getPriceForCycle(this.billing.cycle).amount;
  let discountAmount = 0;
  
  // Apply active discounts
  this.discounts.forEach(discount => {
    if (!discount.validUntil || discount.validUntil > new Date()) {
      if (discount.type === 'percentage') {
        discountAmount += baseAmount * (discount.value / 100);
      } else if (discount.type === 'fixed') {
        discountAmount += discount.value;
      }
    }
  });
  
  // Add addon costs
  let addonTotal = 0;
  this.addons.forEach(addon => {
    if (addon.status === 'active') {
      addonTotal += addon.price.total;
    }
  });
  
  this.billing.amount = {
    base: baseAmount + addonTotal,
    discount: discountAmount,
    tax: 0, // Calculate based on location
    total: Math.max(0, baseAmount + addonTotal - discountAmount)
  };
};

// Pause subscription
subscriptionSchema.methods.pause = function(resumeDate, reason) {
  if (this.status !== 'active') {
    throw new Error('Can only pause active subscriptions');
  }
  
  this.status = 'paused';
  this.dates.pausedAt = new Date();
  this.dates.resumeAt = resumeDate;
  
  this.history.push({
    event: 'paused',
    reason,
    details: { resumeDate }
  });
  
  return this.save();
};

// Resume subscription
subscriptionSchema.methods.resume = function() {
  if (this.status !== 'paused') {
    throw new Error('Can only resume paused subscriptions');
  }
  
  this.status = 'active';
  this.dates.pausedAt = null;
  this.dates.resumeAt = null;
  
  // Extend current period by paused duration
  const pausedDuration = new Date() - this.dates.pausedAt;
  this.dates.currentPeriodEnd = new Date(this.dates.currentPeriodEnd.getTime() + pausedDuration);
  this.dates.nextBillingDate = new Date(this.dates.nextBillingDate.getTime() + pausedDuration);
  
  this.history.push({
    event: 'resumed'
  });
  
  return this.save();
};

// Cancel subscription
subscriptionSchema.methods.cancel = function(immediate = false, cancellation) {
  if (['cancelled', 'expired'].includes(this.status)) {
    throw new Error('Subscription is already cancelled');
  }
  
  this.status = 'cancelled';
  this.dates.cancelledAt = new Date();
  
  if (immediate) {
    this.dates.cancellationEffective = new Date();
    this.status = 'expired';
  } else {
    this.dates.cancellationEffective = this.dates.currentPeriodEnd;
  }
  
  this.renewal.auto = false;
  this.cancellation = cancellation;
  
  this.history.push({
    event: 'cancelled',
    details: cancellation
  });
  
  return this.save();
};

/**
 * Static Methods
 */

// Get active subscriptions for user
subscriptionSchema.statics.getActiveForUser = async function(userId) {
  return this.find({
    userId,
    status: { $in: ['active', 'trial'] }
  }).populate('planId');
};

// Get subscriptions expiring soon
subscriptionSchema.statics.getExpiringSoon = async function(days = 7) {
  const future = new Date();
  future.setDate(future.getDate() + days);
  
  return this.find({
    status: { $in: ['active', 'trial'] },
    $or: [
      { 'dates.currentPeriodEnd': { $lte: future, $gte: new Date() } },
      { 'dates.trialEnd': { $lte: future, $gte: new Date() } }
    ]
  });
};

// Get subscriptions needing payment retry
subscriptionSchema.statics.getNeedingPaymentRetry = async function() {
  return this.find({
    status: 'past_due',
    'billing.retry.enabled': true,
    'billing.retry.attempts': { $lt: '$billing.retry.maxAttempts' },
    $or: [
      { 'billing.retry.nextAttempt': { $lte: new Date() } },
      { 'billing.retry.nextAttempt': null }
    ]
  });
};

// Pre-save middleware
subscriptionSchema.pre('save', function(next) {
  // Update payment summary
  if (this.isModified('paymentSummary') || this.isModified('billing')) {
    this.paymentSummary.outstandingBalance = Math.max(0, 
      this.billing.amount.total - this.paymentSummary.totalPaid
    );
  }
  
  // Check and update status based on dates
  if (this.status === 'trial' && this.dates.trialEnd < new Date()) {
    this.status = this.trial.converted ? 'active' : 'expired';
  }
  
  if (this.status === 'active' && this.dates.currentPeriodEnd < new Date() && !this.renewal.auto) {
    this.status = 'expired';
  }
  
  next();
});

// Create and export model
const Subscription = mongoose.model('Subscription', subscriptionSchema);

module.exports = Subscription;