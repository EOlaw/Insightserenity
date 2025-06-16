// server/shared/billing/models/subscription-plan-model.js
/**
 * @file Subscription Plan Model
 * @description Model for subscription plan configurations
 * @version 3.0.0
 */

const mongoose = require('mongoose');

const config = require('../../config');
const constants = require('../../config/constants');

/**
 * Subscription Plan Schema
 */
const subscriptionPlanSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: true,
    trim: true,
    unique: true
  },
  
  slug: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    index: true
  },
  
  description: {
    short: {
      type: String,
      required: true,
      maxlength: 200
    },
    full: {
      type: String,
      maxlength: 2000
    },
    features: [String]
  },
  
  // Plan Type and Category
  type: {
    type: String,
    enum: constants.BILLING.PLAN_TYPES_ENUM,
    required: true,
    index: true
  },
  
  category: {
    type: String,
    enum: constants.BILLING.PLAN_CATEGORIES_ENUM,
    required: true
  },
  
  targetAudience: {
    type: String,
    enum: constants.BILLING.TARGET_AUDIENCES_ENUM,
    required: true
  },
  
  // Pricing Configuration
  pricing: {
    currency: {
      type: String,
      enum: constants.BILLING.CURRENCIES_ENUM,
      default: 'USD',
      uppercase: true
    },
    
    monthly: {
      amount: {
        type: Number,
        required: true,
        min: 0
      },
      originalAmount: Number,
      setupFee: {
        type: Number,
        default: 0
      },
      discount: {
        percentage: { type: Number, min: 0, max: 100 },
        amount: Number,
        validUntil: Date
      }
    },
    
    quarterly: {
      amount: Number,
      originalAmount: Number,
      setupFee: { type: Number, default: 0 },
      savings: Number,
      savingsPercentage: Number,
      discount: {
        percentage: { type: Number, min: 0, max: 100 },
        amount: Number,
        validUntil: Date
      }
    },
    
    yearly: {
      amount: Number,
      originalAmount: Number,
      setupFee: { type: Number, default: 0 },
      savings: Number,
      savingsPercentage: Number,
      monthlyEquivalent: Number,
      discount: {
        percentage: { type: Number, min: 0, max: 100 },
        amount: Number,
        validUntil: Date
      }
    },
    
    custom: {
      enabled: { type: Boolean, default: false },
      startingPrice: Number,
      contactRequired: { type: Boolean, default: true },
      notes: String
    },
    
    taxInclusive: {
      type: Boolean,
      default: false
    }
  },
  
  // Features and Limits
  features: [{
    category: {
      type: String,
      enum: constants.BILLING.FEATURE_CATEGORIES_ENUM
    },
    name: {
      type: String,
      required: true
    },
    key: {
      type: String,
      required: true
    },
    description: String,
    value: mongoose.Schema.Types.Mixed,
    type: {
      type: String,
      enum: constants.BILLING.FEATURE_VALUE_TYPES_ENUM
    },
    unit: String,
    displayValue: String,
    highlighted: { type: Boolean, default: false },
    beta: { type: Boolean, default: false }
  }],
  
  limits: {
    users: {
      min: { type: Number, default: 1 },
      max: Number,
      included: Number,
      overagePrice: Number
    },
    storage: {
      amount: Number, // in GB
      unit: { type: String, default: 'GB' },
      overagePrice: Number // per GB
    },
    projects: {
      max: Number,
      overagePrice: Number
    },
    apiCalls: {
      monthly: Number,
      daily: Number,
      perMinute: Number,
      overagePrice: Number // per 1000 calls
    },
    organizations: Number,
    customDomains: Number,
    emailsPerMonth: Number,
    teamMembers: Number,
    clients: Number,
    candidates: Number,
    jobPostings: Number
  },
  
  // Support Configuration
  support: {
    level: {
      type: String,
      enum: constants.BILLING.SUPPORT_LEVELS_ENUM,
      required: true
    },
    responseTime: {
      value: Number,
      unit: { 
        type: String, 
        enum: constants.BILLING.TIME_UNITS_ENUM 
      }
    },
    availability: {
      type: String,
      enum: constants.BILLING.SUPPORT_AVAILABILITY_ENUM
    },
    channels: [{
      type: String,
      enum: constants.BILLING.SUPPORT_CHANNELS_ENUM
    }],
    includedHours: Number,
    additionalHourPrice: Number
  },
  
  // Trial Configuration
  trial: {
    enabled: { type: Boolean, default: false },
    duration: {
      value: { type: Number, default: 14 },
      unit: {
        type: String,
        enum: constants.BILLING.TRIAL_DURATION_UNITS_ENUM,
        default: 'days'
      }
    },
    features: {
      full: { type: Boolean, default: true },
      limited: [String]
    },
    creditCardRequired: { type: Boolean, default: false },
    autoConvert: { type: Boolean, default: true },
    reminderDays: [Number] // Days before trial end to send reminders
  },
  
  // Display and Marketing
  display: {
    order: { type: Number, default: 0 },
    visibility: {
      type: String,
      enum: constants.BILLING.PLAN_VISIBILITY_ENUM,
      default: 'public'
    },
    recommended: { type: Boolean, default: false },
    popular: { type: Boolean, default: false },
    enterprise: { type: Boolean, default: false },
    badge: {
      text: String,
      color: String,
      icon: String
    },
    styling: {
      color: String,
      accentColor: String,
      icon: String,
      headerImage: String
    }
  },
  
  // Availability and Restrictions
  availability: {
    startDate: Date,
    endDate: Date,
    countries: {
      include: [String], // ISO country codes
      exclude: [String]
    },
    userTypes: [{
      type: String,
      enum: constants.USER.TYPES_ENUM
    }],
    maxSubscriptions: Number,
    currentSubscriptions: { type: Number, default: 0 },
    waitlist: {
      enabled: { type: Boolean, default: false },
      current: { type: Number, default: 0 }
    }
  },
  
  // Upgrade/Downgrade Rules
  migration: {
    allowUpgrade: { type: Boolean, default: true },
    allowDowngrade: { type: Boolean, default: true },
    upgradePlans: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SubscriptionPlan'
    }],
    downgradePlans: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'SubscriptionPlan'
    }],
    prorateUpgrade: { type: Boolean, default: true },
    prorateDowngrade: { type: Boolean, default: true },
    downgradeRestrictions: String
  },
  
  // Add-ons
  addons: [{
    addonId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Addon'
    },
    required: { type: Boolean, default: false },
    included: { type: Boolean, default: false }
  }],
  
  // Compliance and Legal
  compliance: {
    dataRetention: {
      days: Number,
      description: String
    },
    gdprCompliant: { type: Boolean, default: true },
    hipaaCompliant: { type: Boolean, default: false },
    soc2Compliant: { type: Boolean, default: false },
    iso27001Compliant: { type: Boolean, default: false }
  },
  
  // External Integrations
  external: {
    stripeProductId: String,
    stripePriceIds: {
      monthly: String,
      quarterly: String,
      yearly: String
    },
    paypalPlanId: String,
    chargebeeItemId: String,
    quickbooksItemId: String
  },
  
  // Status and Lifecycle
  status: {
    type: String,
    enum: constants.BILLING.PLAN_STATUS_ENUM,
    default: 'draft',
    index: true
  },
  
  lifecycle: {
    launchedAt: Date,
    deprecatedAt: Date,
    sunsetAt: Date,
    archivedAt: Date
  },
  
  // Analytics and Metrics
  metrics: {
    totalSubscriptions: { type: Number, default: 0 },
    activeSubscriptions: { type: Number, default: 0 },
    churnRate: { type: Number, default: 0 },
    averageRevenue: { type: Number, default: 0 },
    conversionRate: { type: Number, default: 0 }
  },
  
  // Metadata
  metadata: {
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    lastModifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    tags: [String],
    notes: String,
    customFields: mongoose.Schema.Types.Mixed,
    version: { type: Number, default: 1 }
  }
}, {
  timestamps: true,
  collection: 'subscription_plans'
});

// Indexes
subscriptionPlanSchema.index({ type: 1, status: 1 });
subscriptionPlanSchema.index({ 'pricing.monthly.amount': 1 });
subscriptionPlanSchema.index({ 'display.order': 1 });
subscriptionPlanSchema.index({ 'availability.startDate': 1, 'availability.endDate': 1 });

// Virtual for display price
subscriptionPlanSchema.virtual('displayPrice').get(function() {
  if (this.type === 'free') return 'Free';
  if (this.type === 'custom') return 'Contact Us';
  
  const monthlyPrice = this.pricing.monthly.amount;
  const currency = this.pricing.currency;
  
  return `${currency} ${monthlyPrice}/mo`;
});

// Virtual for feature count
subscriptionPlanSchema.virtual('featureCount').get(function() {
  return this.features.filter(f => f.value === true || f.value > 0).length;
});

/**
 * Instance Methods
 */

// Check if plan is available
subscriptionPlanSchema.methods.isAvailable = function() {
  if (this.status !== 'active') return false;
  
  const now = new Date();
  if (this.availability.startDate && now < this.availability.startDate) return false;
  if (this.availability.endDate && now > this.availability.endDate) return false;
  
  if (this.availability.maxSubscriptions && 
      this.availability.currentSubscriptions >= this.availability.maxSubscriptions) {
    return false;
  }
  
  return true;
};

// Get price for billing cycle
subscriptionPlanSchema.methods.getPriceForCycle = function(cycle) {
  if (!this.pricing[cycle]) return null;
  
  return {
    amount: this.pricing[cycle].amount,
    setupFee: this.pricing[cycle].setupFee || 0,
    total: (this.pricing[cycle].amount || 0) + (this.pricing[cycle].setupFee || 0),
    currency: this.pricing.currency
  };
};

// Check feature availability
subscriptionPlanSchema.methods.hasFeature = function(featureKey) {
  const feature = this.features.find(f => f.key === featureKey);
  if (!feature) return false;
  
  if (feature.type === 'boolean') return feature.value === true;
  if (feature.type === 'number') return feature.value > 0;
  return true;
};

// Get feature limit
subscriptionPlanSchema.methods.getFeatureLimit = function(featureKey) {
  const feature = this.features.find(f => f.key === featureKey);
  return feature ? feature.value : null;
};

// Check if upgrade is allowed
subscriptionPlanSchema.methods.canUpgradeTo = function(targetPlanId) {
  if (!this.migration.allowUpgrade) return false;
  
  return this.migration.upgradePlans.some(
    planId => planId.toString() === targetPlanId.toString()
  );
};

// Check if downgrade is allowed
subscriptionPlanSchema.methods.canDowngradeTo = function(targetPlanId) {
  if (!this.migration.allowDowngrade) return false;
  
  return this.migration.downgradePlans.some(
    planId => planId.toString() === targetPlanId.toString()
  );
};

/**
 * Static Methods
 */

// Get active plans
subscriptionPlanSchema.statics.getActivePlans = async function(options = {}) {
  const query = {
    status: 'active',
    'display.visibility': { $in: ['public', 'beta'] }
  };
  
  if (options.category) {
    query.category = options.category;
  }
  
  if (options.targetAudience) {
    query.targetAudience = { $in: [options.targetAudience, 'all'] };
  }
  
  if (options.userType) {
    query['availability.userTypes'] = { $in: [options.userType] };
  }
  
  return this.find(query)
    .sort('display.order pricing.monthly.amount')
    .lean();
};

// Get plan by slug
subscriptionPlanSchema.statics.getBySlug = async function(slug) {
  return this.findOne({ slug, status: { $ne: 'draft' } });
};

// Get recommended plan
subscriptionPlanSchema.statics.getRecommendedPlan = async function(criteria) {
  const query = {
    status: 'active',
    'display.visibility': 'public'
  };
  
  if (criteria.userType) {
    query.targetAudience = { $in: [criteria.userType, 'all'] };
  }
  
  if (criteria.teamSize) {
    query['limits.users.max'] = { $gte: criteria.teamSize };
  }
  
  const plans = await this.find(query)
    .sort('-display.recommended -display.popular pricing.monthly.amount')
    .limit(1);
  
  return plans[0];
};

// Update subscription count
subscriptionPlanSchema.statics.updateSubscriptionCount = async function(planId, increment = 1) {
  return this.findByIdAndUpdate(
    planId,
    {
      $inc: {
        'availability.currentSubscriptions': increment,
        'metrics.totalSubscriptions': increment > 0 ? increment : 0,
        'metrics.activeSubscriptions': increment
      }
    },
    { new: true }
  );
};

// Pre-save middleware
subscriptionPlanSchema.pre('save', function(next) {
  // Generate slug if not provided
  if (!this.slug && this.name) {
    this.slug = this.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
  }
  
  // Calculate quarterly savings
  if (this.pricing.quarterly?.amount && this.pricing.monthly?.amount) {
    const monthlyTotal = this.pricing.monthly.amount * 3;
    const quarterlySavings = monthlyTotal - this.pricing.quarterly.amount;
    this.pricing.quarterly.savings = quarterlySavings;
    this.pricing.quarterly.savingsPercentage = (quarterlySavings / monthlyTotal) * 100;
  }
  
  // Calculate yearly savings
  if (this.pricing.yearly?.amount && this.pricing.monthly?.amount) {
    const monthlyTotal = this.pricing.monthly.amount * 12;
    const yearlySavings = monthlyTotal - this.pricing.yearly.amount;
    this.pricing.yearly.savings = yearlySavings;
    this.pricing.yearly.savingsPercentage = (yearlySavings / monthlyTotal) * 100;
    this.pricing.yearly.monthlyEquivalent = this.pricing.yearly.amount / 12;
  }
  
  next();
});

// Create and export model
const SubscriptionPlan = mongoose.model('SubscriptionPlan', subscriptionPlanSchema);

module.exports = SubscriptionPlan;