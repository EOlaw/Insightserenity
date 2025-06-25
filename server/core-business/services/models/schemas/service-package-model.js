// server/core-business/services/models/schemas/service-package-model.js
/**
 * @file Service Package Model
 * @description Model for bundled service packages
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../../shared/config/config');
const constants = require('../../../../shared/config/constants');

/**
 * Package Item Schema
 */
const packageItemSchema = new Schema({
  service: {
    type: Schema.Types.ObjectId,
    ref: 'Service',
    required: true
  },
  quantity: {
    type: Number,
    default: 1,
    min: 1
  },
  customization: {
    duration: {
      value: Number,
      unit: String
    },
    deliverables: [String],
    excludedDeliverables: [String],
    additionalRequirements: [String]
  },
  pricing: {
    override: Boolean,
    customPrice: Number,
    discountPercentage: Number
  },
  order: {
    type: Number,
    default: 0
  },
  isMandatory: {
    type: Boolean,
    default: true
  }
}, { _id: false });

/**
 * Service Package Schema
 */
const servicePackageSchema = new Schema({
  // Basic Information
  packageId: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^PKG-[A-Z0-9]{6,10}$/.test(v);
      },
      message: 'Package ID must follow format: PKG-XXXXXX'
    }
  },
  
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: 3,
    maxlength: 100
  },
  
  slug: {
    type: String,
    unique: true,
    lowercase: true,
    trim: true
  },
  
  description: {
    short: {
      type: String,
      required: true,
      maxlength: 200
    },
    full: {
      type: String,
      required: true,
      maxlength: 3000
    },
    benefits: [String],
    idealFor: [String]
  },
  
  // Package Type
  type: {
    type: String,
    enum: ['bundle', 'solution', 'starter', 'professional', 'enterprise', 'custom'],
    required: true
  },
  
  category: {
    primary: {
      type: String,
      required: true
    },
    tags: [String]
  },
  
  // Services Included
  services: [packageItemSchema],
  
  // Pricing
  pricing: {
    model: {
      type: String,
      enum: ['fixed', 'tiered', 'volume', 'custom'],
      default: 'fixed'
    },
    basePrice: {
      type: Number,
      required: true,
      min: 0
    },
    currency: {
      type: String,
      enum: constants.BILLING.CURRENCIES_ENUM,
      default: 'USD'
    },
    tiers: [{
      name: String,
      minQuantity: Number,
      maxQuantity: Number,
      pricePerUnit: Number,
      fixedPrice: Number
    }],
    savings: {
      amount: Number,
      percentage: Number
    },
    billingCycle: {
      type: String,
      enum: ['one_time', 'monthly', 'quarterly', 'yearly', 'custom']
    },
    setupFee: {
      amount: Number,
      waivable: Boolean,
      conditions: String
    }
  },
  
  // Duration and Validity
  duration: {
    value: Number,
    unit: {
      type: String,
      enum: ['days', 'weeks', 'months', 'years']
    },
    isFlexible: Boolean
  },
  
  validity: {
    startDate: Date,
    endDate: Date,
    isLimited: Boolean,
    maxPurchases: Number,
    purchaseCount: {
      type: Number,
      default: 0
    }
  },
  
  // Terms and Conditions
  terms: {
    minimumCommitment: {
      value: Number,
      unit: String
    },
    cancellationPolicy: String,
    refundPolicy: String,
    customTerms: [String]
  },
  
  // Target Audience
  targetAudience: {
    segments: [{
      type: String,
      enum: ['startup', 'smb', 'enterprise', 'nonprofit', 'government', 'individual']
    }],
    industries: [String],
    requirements: [String]
  },
  
  // Status
  status: {
    type: String,
    enum: ['draft', 'active', 'inactive', 'expired', 'archived'],
    default: 'draft'
  },
  
  // Metrics
  metrics: {
    soldCount: {
      type: Number,
      default: 0
    },
    activeSubscriptions: {
      type: Number,
      default: 0
    },
    totalRevenue: {
      type: Number,
      default: 0
    },
    averageRating: {
      type: Number,
      min: 0,
      max: 5,
      default: 0
    },
    conversionRate: {
      type: Number,
      min: 0,
      max: 100
    }
  },
  
  // Marketing
  marketing: {
    featured: {
      type: Boolean,
      default: false
    },
    priority: {
      type: Number,
      default: 0
    },
    promotions: [{
      code: String,
      discount: {
        type: String,
        value: Number
      },
      validFrom: Date,
      validUntil: Date,
      maxUses: Number,
      currentUses: {
        type: Number,
        default: 0
      }
    }],
    badges: [{
      type: String,
      enum: ['bestseller', 'new', 'limited', 'popular', 'recommended']
    }]
  },
  
  // Organization
  organization: {
    type: Schema.Types.ObjectId,
    ref: 'Organization',
    required: true
  },
  
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  managers: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  
  // Images and Media
  media: {
    thumbnail: {
      url: String,
      publicId: String
    },
    images: [{
      url: String,
      publicId: String,
      caption: String,
      order: Number
    }],
    brochure: {
      url: String,
      publicId: String
    }
  }
}, {
  timestamps: true,
  collection: 'service_packages'
});

// Indexes
servicePackageSchema.index({ packageId: 1 });
servicePackageSchema.index({ slug: 1 });
servicePackageSchema.index({ organization: 1, status: 1 });
servicePackageSchema.index({ 'pricing.basePrice': 1 });
servicePackageSchema.index({ status: 1, 'marketing.featured': -1 });

// Pre-save middleware
servicePackageSchema.pre('save', async function(next) {
  try {
    // Generate package ID if not provided
    if (this.isNew && !this.packageId) {
      const count = await mongoose.model('ServicePackage').countDocuments();
      const paddedCount = String(count + 1).padStart(6, '0');
      this.packageId = `PKG-${paddedCount}`;
    }
    
    // Generate slug from name if not provided
    if (!this.slug) {
      this.slug = this.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
      
      // Ensure unique slug
      let slugExists = await mongoose.model('ServicePackage').findOne({ 
        slug: this.slug,
        _id: { $ne: this._id }
      });
      
      if (slugExists) {
        this.slug = `${this.slug}-${Date.now()}`;
      }
    }
    
    // Calculate savings if not set
    if (this.services.length > 0 && !this.pricing.savings) {
      await this.populate('services.service');
      
      const individualTotal = this.services.reduce((sum, item) => {
        const servicePrice = item.service.pricing.basePrice;
        const itemPrice = item.pricing.customPrice || servicePrice;
        return sum + (itemPrice * item.quantity);
      }, 0);
      
      if (individualTotal > this.pricing.basePrice) {
        this.pricing.savings = {
          amount: individualTotal - this.pricing.basePrice,
          percentage: ((individualTotal - this.pricing.basePrice) / individualTotal) * 100
        };
      }
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Methods

/**
 * Calculate total package price
 */
servicePackageSchema.methods.calculateTotalPrice = function(quantity = 1) {
  let price = 0;
  
  switch (this.pricing.model) {
    case 'fixed':
      price = this.pricing.basePrice * quantity;
      break;
      
    case 'tiered':
      const tier = this.pricing.tiers.find(t => 
        quantity >= t.minQuantity && 
        (!t.maxQuantity || quantity <= t.maxQuantity)
      );
      if (tier) {
        price = tier.fixedPrice || (tier.pricePerUnit * quantity);
      } else {
        price = this.pricing.basePrice * quantity;
      }
      break;
      
    case 'volume':
      // Volume discount calculation
      price = this.pricing.basePrice * quantity;
      if (quantity >= 10) price *= 0.9;  // 10% off for 10+
      if (quantity >= 25) price *= 0.85; // 15% off for 25+
      if (quantity >= 50) price *= 0.8;  // 20% off for 50+
      break;
      
    default:
      price = this.pricing.basePrice * quantity;
  }
  
  // Add setup fee if applicable
  if (this.pricing.setupFee?.amount && !this.pricing.setupFee.waivable) {
    price += this.pricing.setupFee.amount;
  }
  
  return {
    subtotal: this.pricing.basePrice * quantity,
    discount: (this.pricing.basePrice * quantity) - price,
    setupFee: this.pricing.setupFee?.amount || 0,
    total: price,
    currency: this.pricing.currency
  };
};

/**
 * Check if package is available
 */
servicePackageSchema.methods.isAvailable = function() {
  if (this.status !== 'active') return false;
  
  // Check validity dates
  const now = new Date();
  if (this.validity.startDate && now < this.validity.startDate) return false;
  if (this.validity.endDate && now > this.validity.endDate) return false;
  
  // Check purchase limit
  if (this.validity.isLimited && this.validity.purchaseCount >= this.validity.maxPurchases) {
    return false;
  }
  
  return true;
};

/**
 * Apply promotion code
 */
servicePackageSchema.methods.applyPromotion = function(code) {
  const promotion = this.marketing.promotions.find(p => 
    p.code === code &&
    new Date() >= p.validFrom &&
    new Date() <= p.validUntil &&
    (!p.maxUses || p.currentUses < p.maxUses)
  );
  
  if (!promotion) {
    return null;
  }
  
  return {
    valid: true,
    discount: {
      type: promotion.discount.type,
      value: promotion.discount.value
    }
  };
};

// Create model
const ServicePackage = mongoose.model('ServicePackage', servicePackageSchema);

module.exports = ServicePackage;