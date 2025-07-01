/**
 * @file Organization Tenant Model
 * @description Schema definition for multi-tenant organizations
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const slugify = require('slugify');

const { AppError } = require('../../shared/utils/app-error');
const { TENANT_CONSTANTS } = require('../constants/tenant-constants');

// Import Schema Modules
const tenantSettingsSchema = require('./schemas/tenant-settings-schema');
const resourceLimitsSchema = require('./schemas/resource-limits-schema');
const billingInfoSchema = require('./schemas/billing-info-schema');

/**
 * Organization Tenant Schema
 */
const organizationTenantSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Organization name is required'],
    trim: true,
    maxlength: [100, 'Organization name cannot exceed 100 characters']
  },
  
  slug: {
    type: String,
    unique: true,
    lowercase: true,
    index: true
  },
  
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  // Tenant Identification
  tenantId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  
  tenantCode: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    match: [/^[A-Z0-9]{3,10}$/, 'Tenant code must be 3-10 uppercase alphanumeric characters']
  },
  
  // Contact Information
  contactEmail: {
    type: String,
    required: [true, 'Contact email is required'],
    lowercase: true,
    match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address']
  },
  
  contactPhone: {
    type: String,
    match: [/^\+?[1-9]\d{1,14}$/, 'Please provide a valid phone number']
  },
  
  website: {
    type: String,
    match: [/^https?:\/\/.+/, 'Please provide a valid URL']
  },
  
  // Business Information
  businessType: {
    type: String,
    enum: TENANT_CONSTANTS.BUSINESS_TYPES,
    default: 'corporation'
  },
  
  industry: {
    type: String,
    enum: TENANT_CONSTANTS.INDUSTRIES
  },
  
  size: {
    type: String,
    enum: TENANT_CONSTANTS.COMPANY_SIZES,
    default: 'small'
  },
  
  // Status and Lifecycle
  status: {
    type: String,
    enum: TENANT_CONSTANTS.TENANT_STATUS,
    default: 'pending'
  },
  
  lifecycleStage: {
    type: String,
    enum: TENANT_CONSTANTS.LIFECYCLE_STAGES,
    default: 'trial'
  },
  
  activatedAt: Date,
  suspendedAt: Date,
  terminatedAt: Date,
  
  // Subscription Information
  subscription: {
    plan: {
      type: String,
      enum: Object.values(TENANT_CONSTANTS.SUBSCRIPTION_PLANS),
      default: TENANT_CONSTANTS.SUBSCRIPTION_PLANS.TRIAL
    },
    status: {
      type: String,
      enum: Object.values(TENANT_CONSTANTS.SUBSCRIPTION_STATUS),
      default: TENANT_CONSTANTS.SUBSCRIPTION_STATUS.TRIAL
    },
    startDate: { type: Date, default: Date.now },
    endDate: Date,
    trialEndsAt: Date,
    autoRenew: { type: Boolean, default: true },
    customTerms: { type: mongoose.Schema.Types.Mixed }
  },
  
  // Resource Management (imported schema)
  resourceLimits: resourceLimitsSchema,
  
  // Billing (imported schema)
  billing: billingInfoSchema,
  
  // Settings (imported schema)
  settings: tenantSettingsSchema,
  
  // Branding
  branding: {
    logo: {
      light: String,
      dark: String,
      favicon: String
    },
    colors: {
      primary: { type: String, default: '#3B82F6' },
      secondary: { type: String, default: '#10B981' },
      accent: { type: String, default: '#F59E0B' },
      background: { type: String, default: '#FFFFFF' },
      text: { type: String, default: '#1F2937' }
    },
    customCSS: String,
    emailTemplates: {
      header: String,
      footer: String
    }
  },
  
  // Custom Domains
  domains: [{
    domain: {
      type: String,
      lowercase: true,
      unique: true,
      sparse: true
    },
    isPrimary: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    verifiedAt: Date,
    sslEnabled: { type: Boolean, default: false },
    sslCertificateId: String,
    addedAt: { type: Date, default: Date.now }
  }],
  
  // Database Information
  database: {
    strategy: {
      type: String,
      enum: TENANT_CONSTANTS.DATABASE_STRATEGIES,
      default: 'shared'
    },
    name: String,
    connectionString: {
      type: String,
      select: false
    },
    encryptionKey: {
      type: String,
      select: false
    },
    migrationVersion: { type: Number, default: 1 }
  },
  
  // Team Members
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  admins: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  
  memberCount: {
    type: Number,
    default: 0
  },
  
  // Metadata
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  
  tags: [String],
  
  // Analytics
  analytics: {
    lastActivity: Date,
    totalLogins: { type: Number, default: 0 },
    totalApiCalls: { type: Number, default: 0 },
    totalStorage: { type: Number, default: 0 },
    monthlyActiveUsers: { type: Number, default: 0 }
  },
  
  // Compliance
  compliance: {
    gdprEnabled: { type: Boolean, default: false },
    dataLocation: {
      type: String,
      enum: TENANT_CONSTANTS.DATA_LOCATIONS,
      default: 'us'
    },
    certifications: [String],
    lastAuditDate: Date,
    complianceOfficer: {
      name: String,
      email: String
    }
  },
  
  // Flags
  flags: {
    isActive: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },
    isLocked: { type: Boolean, default: false },
    isFeatured: { type: Boolean, default: false },
    requiresAttention: { type: Boolean, default: false },
    hasCustomContract: { type: Boolean, default: false }
  },
  
  // System Fields
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  
  notes: [{
    content: String,
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    createdAt: { type: Date, default: Date.now },
    isInternal: { type: Boolean, default: true }
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Indexes
 */
organizationTenantSchema.index({ tenantId: 1 });
organizationTenantSchema.index({ tenantCode: 1 });
organizationTenantSchema.index({ slug: 1 });
organizationTenantSchema.index({ status: 1 });
organizationTenantSchema.index({ 'subscription.plan': 1 });
organizationTenantSchema.index({ 'subscription.status': 1 });
organizationTenantSchema.index({ owner: 1 });
organizationTenantSchema.index({ createdAt: -1 });
organizationTenantSchema.index({ 'analytics.lastActivity': -1 });
organizationTenantSchema.index({ 'domains.domain': 1 });
organizationTenantSchema.index({ tags: 1 });

/**
 * Virtual Properties
 */
organizationTenantSchema.virtual('isTrialing').get(function() {
  return this.subscription.status === 'trial' && 
         this.subscription.trialEndsAt > new Date();
});

organizationTenantSchema.virtual('daysUntilTrialEnd').get(function() {
  if (!this.isTrialing) return null;
  const days = Math.ceil((this.subscription.trialEndsAt - new Date()) / (1000 * 60 * 60 * 24));
  return days > 0 ? days : 0;
});

organizationTenantSchema.virtual('storageUsedGB').get(function() {
  return (this.resourceLimits.storage.currentBytes / (1024 * 1024 * 1024)).toFixed(2);
});

organizationTenantSchema.virtual('storageUsagePercent').get(function() {
  if (this.resourceLimits.storage.maxGB === -1) return 0;
  return Math.round((this.storageUsedGB / this.resourceLimits.storage.maxGB) * 100);
});

organizationTenantSchema.virtual('primaryDomain').get(function() {
  const primary = this.domains.find(d => d.isPrimary && d.isVerified);
  return primary ? primary.domain : null;
});

/**
 * Pre-save Middleware
 */
organizationTenantSchema.pre('save', async function(next) {
  try {
    // Generate slug if not provided
    if (!this.slug && this.name) {
      this.slug = slugify(this.name, { lower: true, strict: true });
      
      // Ensure slug uniqueness
      let suffix = 0;
      let uniqueSlug = this.slug;
      while (await mongoose.model('OrganizationTenant').findOne({ slug: uniqueSlug, _id: { $ne: this._id } })) {
        suffix++;
        uniqueSlug = `${this.slug}-${suffix}`;
      }
      this.slug = uniqueSlug;
    }
    
    // Generate tenant ID if not provided
    if (!this.tenantId && this.isNew) {
      this.tenantId = `org_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }
    
    // Set trial end date for new trials
    if (this.isNew && this.subscription.status === 'trial' && !this.subscription.trialEndsAt) {
      this.subscription.trialEndsAt = new Date(Date.now() + TENANT_CONSTANTS.TRIAL_DURATION_DAYS * 24 * 60 * 60 * 1000);
    }
    
    // Update lifecycle stage based on status
    if (this.isModified('status')) {
      switch (this.status) {
        case 'active':
          if (!this.activatedAt) this.activatedAt = new Date();
          break;
        case 'suspended':
          this.suspendedAt = new Date();
          break;
        case 'terminated':
          this.terminatedAt = new Date();
          break;
      }
    }
    
    // Encrypt sensitive data
    if (this.isModified('database.connectionString') && this.database.connectionString) {
      // Encrypt connection string (implement encryption service)
      // this.database.connectionString = await EncryptionService.encrypt(this.database.connectionString);
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Instance Methods
 */

/**
 * Check if tenant has access to a specific feature
 * @param {string} feature - Feature name
 * @returns {boolean} - Whether tenant has access
 */
organizationTenantSchema.methods.hasFeature = function(feature) {
  if (this.subscription.plan === 'enterprise' || this.flags.hasCustomContract) {
    return true;
  }
  
  return this.settings.features[feature] === true;
};

/**
 * Check if tenant has reached a resource limit
 * @param {string} resource - Resource type
 * @returns {boolean} - Whether limit is reached
 */
organizationTenantSchema.methods.hasReachedLimit = function(resource) {
  const limit = this.resourceLimits[resource];
  if (!limit || limit.max === -1) return false;
  
  return limit.current >= limit.max;
};

/**
 * Update resource usage
 * @param {string} resource - Resource type
 * @param {number} delta - Change in usage (positive or negative)
 * @returns {Promise<void>}
 */
organizationTenantSchema.methods.updateResourceUsage = async function(resource, delta) {
  const limit = this.resourceLimits[resource];
  if (!limit) throw new AppError(`Invalid resource type: ${resource}`, 400);
  
  limit.current = Math.max(0, limit.current + delta);
  
  // Check if limit exceeded
  if (limit.max !== -1 && limit.current > limit.max) {
    throw new AppError(`Resource limit exceeded for ${resource}`, 403);
  }
  
  await this.save();
};

/**
 * Add a custom domain
 * @param {string} domain - Domain name
 * @returns {Promise<Object>} - Added domain object
 */
organizationTenantSchema.methods.addDomain = async function(domain) {
  // Check domain limit
  if (this.hasReachedLimit('customDomains')) {
    throw new AppError('Custom domain limit reached', 403);
  }
  
  // Check if domain already exists
  if (this.domains.some(d => d.domain === domain.toLowerCase())) {
    throw new AppError('Domain already exists', 400);
  }
  
  // Generate verification token
  const verificationToken = require('crypto').randomBytes(32).toString('hex');
  
  const newDomain = {
    domain: domain.toLowerCase(),
    verificationToken,
    isPrimary: this.domains.length === 0
  };
  
  this.domains.push(newDomain);
  await this.updateResourceUsage('customDomains', 1);
  
  return newDomain;
};

/**
 * Verify a domain
 * @param {string} domain - Domain name
 * @returns {Promise<boolean>} - Verification success
 */
organizationTenantSchema.methods.verifyDomain = async function(domain) {
  const domainObj = this.domains.find(d => d.domain === domain.toLowerCase());
  if (!domainObj) {
    throw new AppError('Domain not found', 404);
  }
  
  // Implement actual domain verification logic here
  // This is a placeholder
  domainObj.isVerified = true;
  domainObj.verifiedAt = new Date();
  
  await this.save();
  return true;
};

/**
 * Suspend tenant
 * @param {string} reason - Suspension reason
 * @returns {Promise<void>}
 */
organizationTenantSchema.methods.suspend = async function(reason) {
  this.status = 'suspended';
  this.flags.isActive = false;
  
  if (reason) {
    this.notes.push({
      content: `Tenant suspended: ${reason}`,
      isInternal: true
    });
  }
  
  await this.save();
};

/**
 * Reactivate tenant
 * @returns {Promise<void>}
 */
organizationTenantSchema.methods.reactivate = async function() {
  if (this.status === 'terminated') {
    throw new AppError('Cannot reactivate terminated tenant', 400);
  }
  
  this.status = 'active';
  this.flags.isActive = true;
  this.suspendedAt = null;
  
  this.notes.push({
    content: 'Tenant reactivated',
    isInternal: true
  });
  
  await this.save();
};

/**
 * Static Methods
 */

/**
 * Find tenant by domain
 * @param {string} domain - Domain name
 * @returns {Promise<Object>} - Tenant document
 */
organizationTenantSchema.statics.findByDomain = async function(domain) {
  return this.findOne({
    'domains.domain': domain.toLowerCase(),
    'domains.isVerified': true,
    status: 'active'
  });
};

/**
 * Find active tenants
 * @param {Object} filter - Additional filters
 * @returns {Promise<Array>} - Array of tenants
 */
organizationTenantSchema.statics.findActive = async function(filter = {}) {
  return this.find({
    ...filter,
    status: 'active',
    'flags.isActive': true
  });
};

/**
 * Get tenant statistics
 * @returns {Promise<Object>} - Statistics object
 */
organizationTenantSchema.statics.getStatistics = async function() {
  const stats = await this.aggregate([
    {
      $facet: {
        byStatus: [
          { $group: { _id: '$status', count: { $sum: 1 } } }
        ],
        byPlan: [
          { $group: { _id: '$subscription.plan', count: { $sum: 1 } } }
        ],
        bySize: [
          { $group: { _id: '$size', count: { $sum: 1 } } }
        ],
        totals: [
          {
            $group: {
              _id: null,
              total: { $sum: 1 },
              active: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
              trial: { $sum: { $cond: [{ $eq: ['$subscription.status', 'trial'] }, 1, 0] } },
              suspended: { $sum: { $cond: [{ $eq: ['$status', 'suspended'] }, 1, 0] } }
            }
          }
        ]
      }
    }
  ]);
  
  return stats[0];
};

/**
 * Plugins
 */
organizationTenantSchema.plugin(require('mongoose-lean-virtuals'));

/**
 * Export Model
 */
module.exports = mongoose.model('OrganizationTenant', organizationTenantSchema);