/**
 * @file Hosted Organization Model
 * @description MongoDB model for organizations with full multi-tenant integration
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const validator = require('validator');
const slugify = require('slugify');
const { generateUniqueId } = require('../../../shared/utils/helpers/id-generator-helper');
const { ORGANIZATION_CONSTANTS } = require('../../../shared/utils/constants/organization-constants');
const Schema = mongoose.Schema;

/**
 * Hosted Organization Schema
 * Organizations that use our platform with tenant infrastructure integration
 */
const hostedOrganizationSchema = new Schema({
  // Tenant Infrastructure Reference
  tenantRef: {
    type: Schema.Types.ObjectId,
    ref: 'OrganizationTenant',
    required: true,
    index: true
  },
  tenantId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  tenantCode: {
    type: String,
    required: true,
    index: true
  },
  
  // Unique Platform Identifiers
  platformId: {
    type: String,
    unique: true,
    required: true,
    default: () => generateUniqueId('ORG')
  },
  
  // Core Organization Identity
  name: {
    type: String,
    required: [true, 'Organization name is required'],
    trim: true,
    minlength: [2, 'Organization name must be at least 2 characters'],
    maxlength: [100, 'Organization name cannot exceed 100 characters']
  },
  displayName: {
    type: String,
    trim: true,
    maxlength: 100
  },
  legalName: {
    type: String,
    trim: true,
    maxlength: 200
  },
  slug: {
    type: String,
    unique: true,
    lowercase: true,
    index: true
  },
  
  // Business Information
  businessInfo: {
    registrationNumber: String,
    taxId: String,
    vatNumber: String,
    businessType: {
      type: String,
      enum: ORGANIZATION_CONSTANTS.BUSINESS_TYPES
    },
    industry: {
      primary: {
        code: String,
        name: String,
        category: String
      },
      secondary: [{
        code: String,
        name: String,
        category: String
      }]
    },
    founded: {
      year: Number,
      date: Date
    }
  },
  
  // Platform Configuration (synced with tenant)
  platformConfig: {
    tier: {
      type: String,
      enum: ['starter', 'growth', 'professional', 'enterprise', 'custom'],
      required: true,
      default: 'starter'
    },
    features: {
      type: Map,
      of: Boolean,
      default: new Map()
    },
    modules: {
      projects: { type: Boolean, default: true },
      crm: { type: Boolean, default: false },
      invoicing: { type: Boolean, default: false },
      analytics: { type: Boolean, default: true },
      integrations: { type: Boolean, default: false }
    }
  },
  
  // Resource Usage (tracked by tenant but cached here)
  resourceUsage: {
    users: {
      current: { type: Number, default: 0 },
      lastUpdated: Date
    },
    storage: {
      currentBytes: { type: Number, default: 0 },
      lastUpdated: Date
    },
    apiCalls: {
      currentMonth: { type: Number, default: 0 },
      lastReset: Date
    },
    projects: {
      current: { type: Number, default: 0 },
      lastUpdated: Date
    }
  },
  
  // Subscription & Billing (synced with tenant)
  subscription: {
    status: {
      type: String,
      enum: ['trial', 'active', 'past_due', 'canceled', 'suspended'],
      default: 'trial',
      required: true
    },
    plan: {
      id: String,
      name: String,
      interval: { type: String, enum: ['monthly', 'yearly'] },
      amount: Number,
      currency: { type: String, default: 'USD' }
    },
    currentPeriod: {
      start: Date,
      end: Date
    },
    trialEnd: Date,
    canceledAt: Date,
    suspendedAt: Date,
    billingCycle: {
      type: String,
      enum: ['monthly', 'quarterly', 'annual'],
      default: 'monthly'
    },
    nextBillingDate: Date,
    paymentMethod: {
      type: { type: String },
      last4: String,
      brand: String
    }
  },
  
  // Contact & Location
  headquarters: {
    address: {
      street1: String,
      street2: String,
      city: String,
      state: String,
      country: String,
      postalCode: String,
      coordinates: {
        type: { type: String, enum: ['Point'] },
        coordinates: [Number]
      }
    },
    phone: String,
    email: {
      type: String,
      validate: [validator.isEmail, 'Please provide a valid email']
    },
    timezone: {
      type: String,
      default: 'UTC'
    }
  },
  
  // Branding & Customization
  branding: {
    logo: {
      url: String,
      publicId: String
    },
    favicon: {
      url: String,
      publicId: String
    },
    colors: {
      primary: { type: String, default: '#1976d2' },
      secondary: { type: String, default: '#dc004e' },
      accent: { type: String, default: '#9c27b0' },
      text: {
        primary: { type: String, default: '#212121' },
        secondary: { type: String, default: '#757575' }
      },
      background: {
        default: { type: String, default: '#ffffff' },
        paper: { type: String, default: '#f5f5f5' }
      }
    },
    customCss: String,
    emailTemplates: {
      header: String,
      footer: String,
      signature: String
    }
  },
  
  // Domains (primary managed by tenant)
  domains: {
    subdomain: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      validate: {
        validator: function(v) {
          return /^[a-z0-9-]+$/.test(v);
        },
        message: 'Subdomain can only contain lowercase letters, numbers, and hyphens'
      }
    },
    customDomains: [{
      domain: {
        type: String,
        lowercase: true
      },
      isPrimary: { type: Boolean, default: false },
      sslEnabled: { type: Boolean, default: false },
      addedAt: { type: Date, default: Date.now }
    }]
  },
  
  // Team Management
  team: {
    owner: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    admins: [{
      user: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      addedAt: { type: Date, default: Date.now },
      addedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      }
    }],
    members: [{
      user: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      role: {
        type: String,
        enum: ['member', 'developer', 'analyst', 'manager'],
        default: 'member'
      },
      department: String,
      title: String,
      permissions: [String],
      joinedAt: { type: Date, default: Date.now },
      invitedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      lastActiveAt: Date
    }],
    invitations: [{
      email: {
        type: String,
        required: true,
        validate: [validator.isEmail, 'Please provide a valid email']
      },
      role: {
        type: String,
        enum: ['admin', 'member', 'developer', 'analyst', 'manager'],
        default: 'member'
      },
      token: String,
      expiresAt: Date,
      sentAt: { type: Date, default: Date.now },
      sentBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      status: {
        type: String,
        enum: ['pending', 'accepted', 'expired', 'revoked'],
        default: 'pending'
      }
    }]
  },
  
  // Integrations
  integrations: {
    slack: {
      enabled: Boolean,
      workspaceId: String,
      webhookUrl: String,
      channels: [{
        id: String,
        name: String,
        notifications: [String]
      }]
    },
    github: {
      enabled: Boolean,
      organizationName: String,
      accessToken: { type: String, select: false },
      repositories: [String]
    },
    google: {
      enabled: Boolean,
      domain: String,
      clientId: String,
      serviceAccount: { type: String, select: false }
    },
    stripe: {
      enabled: Boolean,
      accountId: String,
      customerId: String,
      subscriptionId: String
    }
  },
  
  // Security & Compliance
  security: {
    twoFactorRequired: { type: Boolean, default: false },
    ipWhitelist: [String],
    passwordPolicy: {
      minLength: { type: Number, default: 8 },
      requireUppercase: { type: Boolean, default: true },
      requireNumbers: { type: Boolean, default: true },
      requireSpecialChars: { type: Boolean, default: true },
      expirationDays: Number,
      preventReuse: { type: Number, default: 3 }
    },
    sessionTimeout: { type: Number, default: 7200 }, // 2 hours in seconds
    ssoEnabled: Boolean,
    ssoProvider: String,
    dataRetentionDays: { type: Number, default: 365 },
    auditLogRetentionDays: { type: Number, default: 730 }
  },
  
  // Preferences
  preferences: {
    defaultLanguage: { type: String, default: 'en' },
    dateFormat: { type: String, default: 'MM/DD/YYYY' },
    timeFormat: { type: String, default: '12h' },
    currency: { type: String, default: 'USD' },
    fiscalYearStart: { type: Number, min: 1, max: 12, default: 1 },
    weekStart: { type: Number, min: 0, max: 6, default: 0 }, // 0 = Sunday
    notifications: {
      email: {
        projectUpdates: { type: Boolean, default: true },
        teamUpdates: { type: Boolean, default: true },
        billing: { type: Boolean, default: true },
        security: { type: Boolean, default: true }
      },
      inApp: {
        projectUpdates: { type: Boolean, default: true },
        teamUpdates: { type: Boolean, default: true },
        mentions: { type: Boolean, default: true }
      }
    }
  },
  
  // Metrics & Analytics
  metrics: {
    health: {
      score: { type: Number, min: 0, max: 100 },
      factors: {
        usage: Number,
        engagement: Number,
        growth: Number,
        retention: Number
      },
      lastCalculated: Date
    },
    usage: {
      dailyActiveUsers: [{ date: Date, count: Number }],
      monthlyActiveUsers: { type: Number, default: 0 },
      totalLogins: { type: Number, default: 0 },
      lastActivity: Date
    },
    performance: {
      avgResponseTime: Number,
      uptime: Number,
      errorRate: Number
    }
  },
  
  // Status & Lifecycle
  status: {
    active: { type: Boolean, default: true },
    verified: { type: Boolean, default: false },
    locked: { type: Boolean, default: false },
    archived: { type: Boolean, default: false },
    deletionRequested: { type: Boolean, default: false },
    deletionScheduledFor: Date
  },
  
  // Metadata
  metadata: {
    source: String,
    referrer: String,
    campaign: String,
    tags: [String],
    customAttributes: {
      type: Map,
      of: Schema.Types.Mixed
    },
    notes: [{
      content: String,
      createdBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      createdAt: { type: Date, default: Date.now }
    }]
  },
  
  // System fields
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Indexes
 */
hostedOrganizationSchema.index({ 'subscription.status': 1, 'status.active': 1 });
hostedOrganizationSchema.index({ 'team.owner': 1, 'status.active': 1 });
hostedOrganizationSchema.index({ 'domains.subdomain': 1 });
hostedOrganizationSchema.index({ 'domains.customDomains.domain': 1 });
hostedOrganizationSchema.index({ tenantId: 1, 'status.active': 1 });
hostedOrganizationSchema.index({ name: 'text', displayName: 'text' });

/**
 * Virtual Fields
 */
hostedOrganizationSchema.virtual('url').get(function() {
  if (this.domains.customDomains?.some(d => d.isPrimary)) {
    const primary = this.domains.customDomains.find(d => d.isPrimary);
    return `https://${primary.domain}`;
  }
  return `https://${this.domains.subdomain}.${process.env.APP_DOMAIN || 'platform.com'}`;
});

hostedOrganizationSchema.virtual('memberCount').get(function() {
  return (this.team.admins?.length || 0) + (this.team.members?.length || 0) + 1; // +1 for owner
});

hostedOrganizationSchema.virtual('isInTrial').get(function() {
  return this.subscription.status === 'trial' && 
         this.subscription.trialEnd && 
         new Date() < new Date(this.subscription.trialEnd);
});

hostedOrganizationSchema.virtual('daysLeftInTrial').get(function() {
  if (!this.isInTrial) return 0;
  const now = new Date();
  const trialEnd = new Date(this.subscription.trialEnd);
  return Math.max(0, Math.ceil((trialEnd - now) / (1000 * 60 * 60 * 24)));
});

/**
 * Pre-save Middleware
 */
hostedOrganizationSchema.pre('save', async function(next) {
  // Generate slug from name if not provided
  if (!this.slug && this.name) {
    this.slug = slugify(this.name, { lower: true, strict: true });
    
    // Ensure slug is unique
    const existing = await this.constructor.findOne({ 
      slug: this.slug,
      _id: { $ne: this._id }
    });
    
    if (existing) {
      this.slug = `${this.slug}-${Date.now().toString(36)}`;
    }
  }
  
  // Set display name if not provided
  if (!this.displayName) {
    this.displayName = this.name;
  }
  
  // Generate subdomain if not provided
  if (!this.domains.subdomain && this.slug) {
    this.domains.subdomain = this.slug;
  }
  
  next();
});

/**
 * Methods
 */

/**
 * Check if user is admin
 */
hostedOrganizationSchema.methods.isAdmin = function(userId) {
  const userIdStr = userId.toString();
  return this.team.owner.toString() === userIdStr ||
         this.team.admins.some(admin => admin.user.toString() === userIdStr);
};

/**
 * Check if user is member
 */
hostedOrganizationSchema.methods.isMember = function(userId) {
  const userIdStr = userId.toString();
  return this.isAdmin(userId) ||
         this.team.members.some(member => member.user.toString() === userIdStr);
};

/**
 * Get user role
 */
hostedOrganizationSchema.methods.getUserRole = function(userId) {
  const userIdStr = userId.toString();
  
  if (this.team.owner.toString() === userIdStr) return 'owner';
  if (this.team.admins.some(admin => admin.user.toString() === userIdStr)) return 'admin';
  
  const member = this.team.members.find(m => m.user.toString() === userIdStr);
  return member ? member.role : null;
};

/**
 * Check resource limit
 */
hostedOrganizationSchema.methods.checkResourceLimit = async function(resource, increment = 1) {
  const OrganizationTenant = mongoose.model('OrganizationTenant');
  const tenant = await OrganizationTenant.findById(this.tenantRef);
  
  if (!tenant) {
    throw new Error('Tenant reference not found');
  }
  
  // Use the method that actually exists
  if (tenant.hasReachedLimit(resource)) {
    return false; // Already at limit
  }
  
  // Check if adding increment would exceed limit
  const currentLimit = tenant.resourceLimits[resource];
  if (currentLimit && currentLimit.max !== -1) {
    const newUsage = currentLimit.current + increment;
    if (newUsage > currentLimit.max) {
      return false; // Would exceed limit
    }
  }
  
  return true; // Can add the resource
};

/**
 * Update resource usage
 */
hostedOrganizationSchema.methods.updateResourceUsage = async function(resource, value, operation = 'set') {
  // Initialize resourceUsage if it doesn't exist
  if (!this.resourceUsage) {
    this.resourceUsage = {};
  }
  
  // Initialize the specific resource if it doesn't exist
  if (!this.resourceUsage[resource]) {
    this.resourceUsage[resource] = { current: 0 };
  }
  
  // Update the resource usage based on operation
  switch(operation) {
    case 'increment':
      this.resourceUsage[resource].current += value;
      break;
    case 'decrement':
      this.resourceUsage[resource].current = Math.max(0, this.resourceUsage[resource].current - value);
      break;
    default:
      this.resourceUsage[resource].current = value;
  }
  
  // Update timestamp
  this.resourceUsage[resource].lastUpdated = new Date();
  
  // Also update in tenant
  const OrganizationTenant = mongoose.model('OrganizationTenant');
  await OrganizationTenant.findByIdAndUpdate(this.tenantRef, {
    [`resourceLimits.${resource}.current`]: this.resourceUsage[resource].current
  });
  
  return this.save();
};

/**
 * Static Methods
 */

/**
 * Find organizations by owner
 */
hostedOrganizationSchema.statics.findByOwner = function(userId, options = {}) {
  const query = {
    'team.owner': userId,
    'status.active': true
  };
  
  if (options.includeInactive) {
    delete query['status.active'];
  }
  
  return this.find(query)
    .populate(options.populate || 'tenantRef')
    .sort(options.sort || '-createdAt');
};

/**
 * Find organizations by member
 */
hostedOrganizationSchema.statics.findByMember = function(userId, options = {}) {
  const query = {
    $or: [
      { 'team.owner': userId },
      { 'team.admins.user': userId },
      { 'team.members.user': userId }
    ],
    'status.active': true
  };
  
  if (options.includeInactive) {
    delete query['status.active'];
  }
  
  return this.find(query)
    .populate(options.populate || 'tenantRef')
    .sort(options.sort || '-createdAt');
};

/**
 * Static helper methods for handling organizations with potential method issues
 */

/**
 * Check organization membership with fallback logic
 * @param {Object} organization - Organization document or plain object
 * @param {string} userId - User ID to check
 * @returns {boolean} - Whether user is a member
 */
hostedOrganizationSchema.statics.checkMembership = function(organization, userId) {
  if (!organization || !userId) {
    return false;
  }

  // Try to use the instance method first if available
  if (typeof organization.isMember === 'function') {
    try {
      return organization.isMember(userId);
    } catch (methodError) {
      // Log the error if logger is available, otherwise continue silently
      if (typeof logger !== 'undefined') {
        logger.warn('isMember method failed, using fallback', {
          organizationId: organization._id,
          userId,
          error: methodError.message
        });
      }
    }
  }
  
  // Fallback implementation for populated and unpopulated references
  const userIdStr = userId.toString();
  
  // Check if user is owner
  const ownerId = organization.team?.owner?._id || organization.team?.owner;
  if (ownerId?.toString() === userIdStr) {
    return true;
  }
  
  // Check if user is admin
  const isAdmin = organization.team?.admins?.some(admin => {
    const adminUserId = admin.user?._id || admin.user;
    return adminUserId?.toString() === userIdStr;
  });
  if (isAdmin) {
    return true;
  }
  
  // Check if user is member
  const isMember = organization.team?.members?.some(member => {
    const memberUserId = member.user?._id || member.user;
    return memberUserId?.toString() === userIdStr;
  });
  
  return isMember;
};

/**
 * Get user role in organization with fallback logic
 * @param {Object} organization - Organization document or plain object
 * @param {string} userId - User ID
 * @returns {string|null} - User role or null if not a member
 */
hostedOrganizationSchema.statics.getUserRole = function(organization, userId) {
  if (!organization || !userId) {
    return null;
  }

  // Try to use the instance method first if available
  if (typeof organization.getUserRole === 'function') {
    try {
      return organization.getUserRole(userId);
    } catch (methodError) {
      // Log the error if logger is available, otherwise continue silently
      if (typeof logger !== 'undefined') {
        logger.warn('getUserRole method failed, using fallback', {
          organizationId: organization._id,
          userId,
          error: methodError.message
        });
      }
    }
  }
  
  // Fallback implementation for populated and unpopulated references
  const userIdStr = userId.toString();
  
  // Check if user is owner
  const ownerId = organization.team?.owner?._id || organization.team?.owner;
  if (ownerId?.toString() === userIdStr) {
    return 'owner';
  }
  
  // Check if user is admin
  const isAdmin = organization.team?.admins?.some(admin => {
    const adminUserId = admin.user?._id || admin.user;
    return adminUserId?.toString() === userIdStr;
  });
  if (isAdmin) {
    return 'admin';
  }
  
  // Check if user is member and get their specific role
  const memberRecord = organization.team?.members?.find(member => {
    const memberUserId = member.user?._id || member.user;
    return memberUserId?.toString() === userIdStr;
  });
  
  return memberRecord?.role || (memberRecord ? 'member' : null);
};

/**
 * Enhanced membership check that also validates user organizations array
 * @param {Object} organization - Organization document or plain object
 * @param {Object} user - User document with organizations array
 * @returns {boolean} - Whether user is a member through any method
 */
hostedOrganizationSchema.statics.checkMembershipExtended = function(organization, user) {
  if (!organization || !user) {
    return false;
  }

  // First check team-based membership
  const isTeamMember = this.checkMembership(organization, user._id);
  if (isTeamMember) {
    return true;
  }

  // Also check user's organizations array as fallback
  const belongsToOrg = user.organizations?.some(org => 
    org.organizationId?.toString() === organization._id?.toString() && org.active
  );

  return belongsToOrg;
};

/**
 * Plugins
 */
hostedOrganizationSchema.plugin(require('mongoose-lean-virtuals'));

/**
 * Export Model
 */
const HostedOrganization = mongoose.model('HostedOrganization', hostedOrganizationSchema);
module.exports = HostedOrganization;