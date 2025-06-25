// server/core-business/services/models/services-model.js
/**
 * @file Service Model
 * @description Comprehensive service model for business services management
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

/**
 * Service Pricing Schema
 */
const servicePricingSchema = new Schema({
  basePrice: {
    type: Number,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    enum: constants.BILLING.CURRENCIES_ENUM,
    default: 'USD',
    uppercase: true
  },
  billingCycle: {
    type: String,
    enum: ['one_time', 'hourly', 'daily', 'weekly', 'monthly', 'quarterly', 'yearly', 'custom'],
    required: true
  },
  customBillingDays: {
    type: Number,
    min: 1,
    max: 365
  },
  discounts: [{
    name: String,
    type: {
      type: String,
      enum: ['percentage', 'fixed'],
      required: true
    },
    value: {
      type: Number,
      required: true,
      min: 0
    },
    conditions: {
      minQuantity: Number,
      minDuration: Number,
      customerType: [String],
      validFrom: Date,
      validUntil: Date
    },
    active: {
      type: Boolean,
      default: true
    }
  }],
  taxable: {
    type: Boolean,
    default: true
  },
  taxRate: {
    type: Number,
    min: 0,
    max: 100
  }
}, { _id: false });

/**
 * Service Deliverable Schema
 */
const serviceDeliverableSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: String,
  type: {
    type: String,
    enum: ['document', 'report', 'presentation', 'code', 'design', 'data', 'other'],
    required: true
  },
  format: String,
  estimatedDeliveryDays: {
    type: Number,
    min: 0
  },
  isRequired: {
    type: Boolean,
    default: true
  },
  order: {
    type: Number,
    default: 0
  }
}, { _id: false });

/**
 * Service Requirement Schema
 */
const serviceRequirementSchema = new Schema({
  type: {
    type: String,
    enum: ['skill', 'certification', 'experience', 'tool', 'resource', 'other'],
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: String,
  level: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced', 'expert']
  },
  isMandatory: {
    type: Boolean,
    default: true
  },
  alternatives: [String]
}, { _id: false });

/**
 * Service SLA Schema
 */
const serviceSLASchema = new Schema({
  responseTime: {
    value: Number,
    unit: {
      type: String,
      enum: ['minutes', 'hours', 'days'],
      default: 'hours'
    }
  },
  resolutionTime: {
    value: Number,
    unit: {
      type: String,
      enum: ['hours', 'days', 'weeks'],
      default: 'days'
    }
  },
  availability: {
    percentage: {
      type: Number,
      min: 0,
      max: 100,
      default: 99
    },
    businessHoursOnly: {
      type: Boolean,
      default: false
    }
  },
  supportLevel: {
    type: String,
    enum: ['basic', 'standard', 'premium', 'enterprise'],
    default: 'standard'
  },
  penalties: [{
    condition: String,
    penalty: String,
    maxPenalty: Number
  }]
}, { _id: false });

/**
 * Service Schema Definition
 */
const serviceSchema = new Schema({
  // Basic Information
  serviceId: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^SRV-[A-Z0-9]{6,10}$/.test(v);
      },
      message: 'Service ID must follow format: SRV-XXXXXX'
    }
  },
  
  name: {
    type: String,
    required: [true, 'Service name is required'],
    trim: true,
    minlength: [3, 'Service name must be at least 3 characters'],
    maxlength: [100, 'Service name cannot exceed 100 characters']
  },
  
  slug: {
    type: String,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^[a-z0-9-]+$/.test(v);
      },
      message: 'Slug can only contain lowercase letters, numbers, and hyphens'
    }
  },
  
  category: {
    primary: {
      type: String,
      required: true,
      enum: ['consulting', 'development', 'design', 'marketing', 'support', 'training', 'analytics', 'research', 'other']
    },
    secondary: [String],
    tags: [{
      type: String,
      lowercase: true,
      trim: true
    }]
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
      maxlength: 5000
    },
    highlights: [String],
    targetAudience: String
  },
  
  // Service Type and Delivery
  type: {
    type: String,
    enum: ['fixed_scope', 'time_and_materials', 'retainer', 'subscription', 'milestone_based'],
    required: true
  },
  
  deliveryMethod: {
    type: String,
    enum: ['onsite', 'remote', 'hybrid', 'self_service'],
    required: true
  },
  
  duration: {
    estimated: {
      min: Number,
      max: Number,
      unit: {
        type: String,
        enum: ['hours', 'days', 'weeks', 'months'],
        default: 'days'
      }
    },
    isFlexible: {
      type: Boolean,
      default: false
    }
  },
  
  // Pricing
  pricing: servicePricingSchema,
  
  // Deliverables
  deliverables: [serviceDeliverableSchema],
  
  // Requirements
  requirements: {
    provider: [serviceRequirementSchema],
    client: [serviceRequirementSchema]
  },
  
  // SLA
  sla: serviceSLASchema,
  
  // Team and Resources
  team: {
    minSize: {
      type: Number,
      default: 1,
      min: 1
    },
    maxSize: Number,
    roles: [{
      role: {
        type: String,
        required: true
      },
      count: {
        type: Number,
        default: 1,
        min: 1
      },
      level: {
        type: String,
        enum: ['junior', 'mid', 'senior', 'lead', 'expert']
      },
      responsibilities: [String],
      isOptional: {
        type: Boolean,
        default: false
      }
    }]
  },
  
  // Process and Methodology
  process: {
    methodology: {
      type: String,
      enum: ['agile', 'waterfall', 'hybrid', 'lean', 'custom']
    },
    phases: [{
      name: {
        type: String,
        required: true
      },
      description: String,
      duration: {
        estimated: Number,
        unit: String
      },
      deliverables: [String],
      order: Number
    }],
    qualityChecks: [{
      name: String,
      description: String,
      frequency: String,
      responsible: String
    }]
  },
  
  // Availability and Capacity
  availability: {
    status: {
      type: String,
      enum: ['available', 'limited', 'booked', 'discontinued', 'coming_soon'],
      default: 'available'
    },
    capacity: {
      current: {
        type: Number,
        default: 0,
        min: 0
      },
      maximum: Number,
      unit: String
    },
    leadTime: {
      value: Number,
      unit: {
        type: String,
        enum: ['days', 'weeks', 'months']
      }
    },
    blackoutDates: [{
      startDate: Date,
      endDate: Date,
      reason: String
    }]
  },
  
  // Status and Lifecycle
  status: {
    type: String,
    enum: ['draft', 'pending_approval', 'active', 'inactive', 'deprecated', 'archived'],
    default: 'draft',
    index: true
  },
  
  lifecycle: {
    introducedAt: Date,
    activeFrom: Date,
    activeUntil: Date,
    deprecatedAt: Date,
    sunsetDate: Date,
    replacedBy: {
      type: Schema.Types.ObjectId,
      ref: 'Service'
    }
  },
  
  // Performance Metrics
  metrics: {
    deliveredCount: {
      type: Number,
      default: 0,
      min: 0
    },
    activeProjects: {
      type: Number,
      default: 0,
      min: 0
    },
    totalRevenue: {
      type: Number,
      default: 0,
      min: 0
    },
    averageRating: {
      type: Number,
      min: 0,
      max: 5,
      default: 0
    },
    totalRatings: {
      type: Number,
      default: 0,
      min: 0
    },
    completionRate: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    averageDeliveryTime: {
      value: Number,
      unit: String
    },
    clientSatisfaction: {
      type: Number,
      min: 0,
      max: 100
    }
  },
  
  // Related Entities
  relatedServices: [{
    service: {
      type: Schema.Types.ObjectId,
      ref: 'Service'
    },
    type: {
      type: String,
      enum: ['prerequisite', 'complement', 'upgrade', 'alternative']
    },
    description: String
  }],
  
  packages: [{
    type: Schema.Types.ObjectId,
    ref: 'ServicePackage'
  }],
  
  // Organization and Ownership
  organization: {
    type: Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  
  owner: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  managers: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  
  // Documents and Resources
  documents: [{
    type: {
      type: String,
      enum: ['brochure', 'proposal_template', 'contract_template', 'sow_template', 'case_study', 'whitepaper', 'other']
    },
    name: String,
    description: String,
    url: String,
    uploadedAt: {
      type: Date,
      default: Date.now
    },
    uploadedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    version: String,
    isPublic: {
      type: Boolean,
      default: false
    }
  }],
  
  // Compliance and Certifications
  compliance: {
    certifications: [{
      name: String,
      issuer: String,
      certificateNumber: String,
      validFrom: Date,
      validUntil: Date,
      documentUrl: String
    }],
    standards: [String],
    regulations: [String],
    dataHandling: {
      classification: {
        type: String,
        enum: ['public', 'internal', 'confidential', 'restricted']
      },
      retention: {
        period: Number,
        unit: String
      },
      encryption: Boolean,
      gdprCompliant: Boolean
    }
  },
  
  // Reviews and Feedback
  reviews: [{
    client: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    project: {
      type: Schema.Types.ObjectId,
      ref: 'Project'
    },
    rating: {
      type: Number,
      required: true,
      min: 1,
      max: 5
    },
    feedback: {
      positive: String,
      improvement: String,
      recommendation: Boolean
    },
    reviewedAt: {
      type: Date,
      default: Date.now
    },
    verified: {
      type: Boolean,
      default: false
    }
  }],
  
  // Metadata
  metadata: {
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    lastModifiedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    version: {
      type: Number,
      default: 1
    },
    changeLog: [{
      version: Number,
      changes: String,
      changedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      changedAt: {
        type: Date,
        default: Date.now
      }
    }],
    customFields: Schema.Types.Mixed,
    internalNotes: [{
      note: String,
      addedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      addedAt: {
        type: Date,
        default: Date.now
      },
      type: {
        type: String,
        enum: ['general', 'technical', 'business', 'risk', 'improvement']
      }
    }]
  }
}, {
  timestamps: true,
  collection: 'services'
});

// Indexes
serviceSchema.index({ name: 1, organization: 1 });
serviceSchema.index({ slug: 1 });
serviceSchema.index({ 'category.primary': 1, status: 1 });
serviceSchema.index({ 'pricing.basePrice': 1 });
serviceSchema.index({ 'availability.status': 1 });
serviceSchema.index({ 'metrics.averageRating': -1 });
serviceSchema.index({ status: 1, 'lifecycle.activeFrom': 1, 'lifecycle.activeUntil': 1 });

// Virtual for full service code
serviceSchema.virtual('fullCode').get(function() {
  return `${this.serviceId}-${this.organization}`;
});

// Virtual for active status
serviceSchema.virtual('isActive').get(function() {
  return this.status === 'active' && 
         this.availability.status !== 'discontinued' &&
         (!this.lifecycle.activeUntil || this.lifecycle.activeUntil > new Date());
});

// Pre-save middleware
serviceSchema.pre('save', async function(next) {
  try {
    // Generate service ID if not provided
    if (this.isNew && !this.serviceId) {
      const count = await mongoose.model('Service').countDocuments();
      const paddedCount = String(count + 1).padStart(6, '0');
      this.serviceId = `SRV-${paddedCount}`;
    }
    
    // Generate slug from name if not provided
    if (!this.slug) {
      this.slug = this.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
      
      // Ensure unique slug
      let slugExists = await mongoose.model('Service').findOne({ 
        slug: this.slug,
        _id: { $ne: this._id }
      });
      
      if (slugExists) {
        this.slug = `${this.slug}-${Date.now()}`;
      }
    }
    
    // Update change log
    if (!this.isNew) {
      this.metadata.version += 1;
      this.metadata.lastModifiedBy = this.metadata.lastModifiedBy || this.metadata.createdBy;
    }
    
    // Calculate average rating
    if (this.reviews && this.reviews.length > 0) {
      const totalRating = this.reviews.reduce((sum, review) => sum + review.rating, 0);
      this.metrics.averageRating = totalRating / this.reviews.length;
      this.metrics.totalRatings = this.reviews.length;
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance Methods

/**
 * Check if service is available for booking
 */
serviceSchema.methods.isAvailable = function() {
  if (!this.isActive) return false;
  
  if (this.availability.status !== 'available') {
    return this.availability.status === 'limited';
  }
  
  // Check capacity if defined
  if (this.availability.capacity.maximum) {
    return this.availability.capacity.current < this.availability.capacity.maximum;
  }
  
  return true;
};

/**
 * Calculate price with discounts
 */
serviceSchema.methods.calculatePrice = function(options = {}) {
  const { quantity = 1, duration = 1, customerType, date = new Date() } = options;
  
  let baseAmount = this.pricing.basePrice * quantity;
  
  // Apply duration multiplier for time-based billing
  if (['hourly', 'daily', 'weekly', 'monthly'].includes(this.pricing.billingCycle)) {
    baseAmount *= duration;
  }
  
  // Apply applicable discounts
  let totalDiscount = 0;
  
  for (const discount of this.pricing.discounts) {
    if (!discount.active) continue;
    
    // Check conditions
    if (discount.conditions.minQuantity && quantity < discount.conditions.minQuantity) continue;
    if (discount.conditions.minDuration && duration < discount.conditions.minDuration) continue;
    if (discount.conditions.customerType?.length && !discount.conditions.customerType.includes(customerType)) continue;
    if (discount.conditions.validFrom && date < discount.conditions.validFrom) continue;
    if (discount.conditions.validUntil && date > discount.conditions.validUntil) continue;
    
    // Apply discount
    if (discount.type === 'percentage') {
      totalDiscount += baseAmount * (discount.value / 100);
    } else {
      totalDiscount += discount.value;
    }
  }
  
  const discountedAmount = Math.max(0, baseAmount - totalDiscount);
  
  // Apply tax if applicable
  let tax = 0;
  if (this.pricing.taxable && this.pricing.taxRate) {
    tax = discountedAmount * (this.pricing.taxRate / 100);
  }
  
  return {
    baseAmount,
    discount: totalDiscount,
    subtotal: discountedAmount,
    tax,
    total: discountedAmount + tax,
    currency: this.pricing.currency
  };
};

/**
 * Check if user can manage this service
 */
serviceSchema.methods.canBeManaged = function(userId) {
  return this.owner.toString() === userId.toString() ||
         this.managers.some(m => m.toString() === userId.toString());
};

/**
 * Add review to service
 */
serviceSchema.methods.addReview = async function(reviewData) {
  this.reviews.push(reviewData);
  
  // Recalculate average rating
  const totalRating = this.reviews.reduce((sum, review) => sum + review.rating, 0);
  this.metrics.averageRating = totalRating / this.reviews.length;
  this.metrics.totalRatings = this.reviews.length;
  
  return this.save();
};

/**
 * Update service availability
 */
serviceSchema.methods.updateAvailability = async function(status, capacity = null) {
  this.availability.status = status;
  
  if (capacity !== null) {
    this.availability.capacity.current = capacity;
  }
  
  return this.save();
};

/**
 * Check service requirements
 */
serviceSchema.methods.checkRequirements = function(providedRequirements = {}) {
  const missing = [];
  const warnings = [];
  
  // Check provider requirements
  for (const req of this.requirements.provider) {
    if (req.isMandatory && !providedRequirements.provider?.[req.type]?.includes(req.name)) {
      if (req.alternatives?.length) {
        const hasAlternative = req.alternatives.some(alt => 
          providedRequirements.provider?.[req.type]?.includes(alt)
        );
        if (!hasAlternative) {
          missing.push({
            type: 'provider',
            requirement: req,
            message: `Missing required ${req.type}: ${req.name} or alternatives`
          });
        }
      } else {
        missing.push({
          type: 'provider',
          requirement: req,
          message: `Missing required ${req.type}: ${req.name}`
        });
      }
    } else if (!req.isMandatory && !providedRequirements.provider?.[req.type]?.includes(req.name)) {
      warnings.push({
        type: 'provider',
        requirement: req,
        message: `Optional ${req.type} not met: ${req.name}`
      });
    }
  }
  
  // Check client requirements
  for (const req of this.requirements.client) {
    if (req.isMandatory && !providedRequirements.client?.[req.type]?.includes(req.name)) {
      missing.push({
        type: 'client',
        requirement: req,
        message: `Client must provide ${req.type}: ${req.name}`
      });
    }
  }
  
  return {
    isValid: missing.length === 0,
    missing,
    warnings
  };
};

// Static Methods

/**
 * Find services by category
 */
serviceSchema.statics.findByCategory = function(category, options = {}) {
  const query = {
    $or: [
      { 'category.primary': category },
      { 'category.secondary': category }
    ],
    status: 'active'
  };
  
  if (options.organization) {
    query.organization = options.organization;
  }
  
  return this.find(query)
    .populate('owner', 'firstName lastName email')
    .populate('organization', 'name slug')
    .sort(options.sort || '-metrics.averageRating');
};

/**
 * Find available services
 */
serviceSchema.statics.findAvailable = function(filters = {}) {
  const query = {
    status: 'active',
    'availability.status': { $in: ['available', 'limited'] }
  };
  
  if (filters.category) {
    query['category.primary'] = filters.category;
  }
  
  if (filters.deliveryMethod) {
    query.deliveryMethod = filters.deliveryMethod;
  }
  
  if (filters.maxPrice) {
    query['pricing.basePrice'] = { $lte: filters.maxPrice };
  }
  
  if (filters.organization) {
    query.organization = filters.organization;
  }
  
  return this.find(query)
    .populate('owner', 'firstName lastName')
    .populate('organization', 'name')
    .sort(filters.sort || '-metrics.averageRating');
};

/**
 * Search services
 */
serviceSchema.statics.searchServices = async function(searchTerm, options = {}) {
  const searchRegex = new RegExp(searchTerm, 'i');
  
  const query = {
    $and: [
      {
        $or: [
          { name: searchRegex },
          { 'description.short': searchRegex },
          { 'description.full': searchRegex },
          { 'category.tags': searchRegex }
        ]
      }
    ]
  };
  
  if (options.status) {
    query.$and.push({ status: options.status });
  } else {
    query.$and.push({ status: { $ne: 'archived' } });
  }
  
  if (options.organization) {
    query.$and.push({ organization: options.organization });
  }
  
  const services = await this.find(query)
    .select('serviceId name slug description.short category pricing.basePrice metrics.averageRating availability.status')
    .populate('organization', 'name')
    .limit(options.limit || 20)
    .sort(options.sort || '-metrics.averageRating');
  
  return services;
};

/**
 * Get service statistics
 */
serviceSchema.statics.getStatistics = async function(organizationId) {
  const stats = await this.aggregate([
    {
      $match: {
        organization: mongoose.Types.ObjectId(organizationId)
      }
    },
    {
      $group: {
        _id: null,
        totalServices: { $sum: 1 },
        activeServices: {
          $sum: {
            $cond: [{ $eq: ['$status', 'active'] }, 1, 0]
          }
        },
        totalRevenue: { $sum: '$metrics.totalRevenue' },
        averageRating: { $avg: '$metrics.averageRating' },
        totalProjects: { $sum: '$metrics.deliveredCount' },
        byCategory: {
          $push: {
            category: '$category.primary',
            count: 1
          }
        },
        byStatus: {
          $push: {
            status: '$status',
            count: 1
          }
        }
      }
    },
    {
      $project: {
        totalServices: 1,
        activeServices: 1,
        totalRevenue: 1,
        averageRating: { $round: ['$averageRating', 2] },
        totalProjects: 1,
        utilizationRate: {
          $multiply: [
            { $divide: ['$activeServices', '$totalServices'] },
            100
          ]
        }
      }
    }
  ]);
  
  return stats[0] || {
    totalServices: 0,
    activeServices: 0,
    totalRevenue: 0,
    averageRating: 0,
    totalProjects: 0,
    utilizationRate: 0
  };
};

/**
 * Update service metrics
 */
serviceSchema.statics.updateMetrics = async function(serviceId, updates) {
  return this.findByIdAndUpdate(
    serviceId,
    { 
      $inc: updates,
      $set: { 'metadata.lastModifiedBy': updates.modifiedBy }
    },
    { new: true }
  );
};

// Pre-remove middleware
serviceSchema.pre('remove', async function(next) {
  try {
    // Check if service is in use
    const Project = mongoose.model('Project');
    const activeProjects = await Project.countDocuments({
      'services.service': this._id,
      status: { $in: ['active', 'in_progress'] }
    });
    
    if (activeProjects > 0) {
      throw new AppError(
        'Cannot delete service with active projects',
        400,
        'SERVICE_IN_USE'
      );
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Create and export model
const Service = mongoose.model('Service', serviceSchema);

module.exports = Service;