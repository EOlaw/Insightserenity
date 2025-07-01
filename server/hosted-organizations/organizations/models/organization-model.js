// /**
//  * @file Hosted Organization Model
//  * @description MongoDB model for organizations hosted on the platform with multi-tenancy support
//  * @version 2.0.1 - Fixed duplicate index definitions
//  */

// const mongoose = require('mongoose');
// const validator = require('validator');
// const slugify = require('slugify');
// const { generateUniqueId } = require('../../../shared/utils/helpers/id-generator-helper');
// const { ORGANIZATION_CONSTANTS } = require('../../../shared/utils/constants/organization-constants');
// const Schema = mongoose.Schema;

// /**
//  * Hosted Organization Schema
//  * Organizations that use our platform to run their business
//  */
// const hostedOrganizationSchema = new Schema({
//   // Unique Platform Identifiers
//   platformId: {
//     type: String,
//     unique: true,
//     required: true,
//     // index: true, // COMMENTED OUT - defined in schema.index() below
//     default: () => generateUniqueId('ORG')
//   },
//   tenantId: {
//     type: String,
//     unique: true,
//     sparse: true
//     // index: true // COMMENTED OUT - will be defined below if needed
//   },
  
//   // Core Organization Identity
//   name: {
//     type: String,
//     required: [true, 'Organization name is required'],
//     trim: true,
//     minlength: [2, 'Organization name must be at least 2 characters'],
//     maxlength: [100, 'Organization name cannot exceed 100 characters']
//     // index: true // COMMENTED OUT - will be defined below if needed
//   },
//   displayName: {
//     type: String,
//     trim: true,
//     maxlength: 100
//   },
//   legalName: {
//     type: String,
//     trim: true,
//     maxlength: 200
//   },
//   slug: {
//     type: String,
//     unique: true,
//     lowercase: true
//     // index: true // COMMENTED OUT - unique already creates index
//   },
  
//   // Business Information
//   businessInfo: {
//     registrationNumber: String,
//     taxId: String,
//     vatNumber: String,
//     businessType: {
//       type: String,
//       enum: ORGANIZATION_CONSTANTS.BUSINESS_TYPES
//     },
//     industry: {
//       primary: {
//         code: String,
//         name: String,
//         category: String
//       },
//       secondary: [{
//         code: String,
//         name: String,
//         category: String
//       }]
//     },
//     founded: {
//       year: Number,
//       date: Date
//     }
//   },
  
//   // Platform Configuration
//   platformConfig: {
//     tier: {
//       type: String,
//       enum: ['starter', 'growth', 'professional', 'enterprise', 'custom'],
//       required: true,
//       default: 'starter'
//     },
//     features: {
//       type: Map,
//       of: Boolean,
//       default: new Map()
//     },
//     limits: {
//       users: { type: Number, default: 5 },
//       storage: { type: Number, default: 5368709120 }, // 5GB in bytes
//       apiCalls: { type: Number, default: 10000 },
//       projects: { type: Number, default: 10 },
//       customDomains: { type: Number, default: 1 }
//     },
//     modules: {
//       projects: { type: Boolean, default: true },
//       crm: { type: Boolean, default: false },
//       invoicing: { type: Boolean, default: false },
//       analytics: { type: Boolean, default: true },
//       integrations: { type: Boolean, default: false }
//     }
//   },
  
//   // Subscription & Billing
//   subscription: {
//     status: {
//       type: String,
//       enum: ['trial', 'active', 'past_due', 'canceled', 'suspended'],
//       default: 'trial',
//       required: true
//       // index: true // COMMENTED OUT - defined in schema.index() below
//     },
//     plan: {
//       id: String,
//       name: String,
//       interval: { type: String, enum: ['monthly', 'yearly'] },
//       amount: Number,
//       currency: { type: String, default: 'USD' }
//     },
//     currentPeriod: {
//       start: Date,
//       end: Date
//     },
//     trialEnd: Date,
//     canceledAt: Date,
//     suspendedAt: Date,
//     billingCycle: {
//       type: String,
//       enum: ['monthly', 'quarterly', 'annual'],
//       default: 'monthly'
//     },
//     nextBillingDate: Date,
//     paymentMethod: {
//       type: { type: String },
//       last4: String,
//       brand: String
//     }
//   },
  
//   // Contact & Location
//   headquarters: {
//     address: {
//       street1: String,
//       street2: String,
//       city: String,
//       state: String,
//       country: String,
//       postalCode: String,
//       coordinates: {
//         type: { type: String, enum: ['Point'] },
//         coordinates: [Number]
//       }
//     },
//     phone: String,
//     email: {
//       type: String,
//       validate: [validator.isEmail, 'Please provide a valid email']
//     },
//     timezone: {
//       type: String,
//       default: 'UTC'
//     }
//   },
  
//   // Branding & Customization
//   branding: {
//     logo: {
//       url: String,
//       publicId: String
//     },
//     favicon: {
//       url: String,
//       publicId: String
//     },
//     colors: {
//       primary: { type: String, default: '#1a73e8' },
//       secondary: { type: String, default: '#34a853' },
//       accent: { type: String, default: '#fbbc04' },
//       background: { type: String, default: '#ffffff' },
//       text: { type: String, default: '#202124' }
//     },
//     customCSS: String
//   },
  
//   // Domain Configuration
//   domains: {
//     subdomain: {
//       type: String,
//       unique: true,
//       sparse: true,
//       lowercase: true,
//       validate: {
//         validator: function(v) {
//           return /^[a-z0-9-]+$/.test(v);
//         },
//         message: 'Subdomain can only contain lowercase letters, numbers, and hyphens'
//       }
//       // Note: This field does NOT have index: true, so the duplicate warning
//       // must be coming from somewhere else in the codebase
//     },
//     customDomains: [{
//       domain: String,
//       verified: { type: Boolean, default: false },
//       verificationCode: String,
//       sslEnabled: { type: Boolean, default: false },
//       addedAt: Date,
//       verifiedAt: Date
//     }]
//   },
  
//   // Team & Access Management
//   owner: {
//     type: Schema.Types.ObjectId,
//     ref: 'User',
//     required: true
//     // index: true // COMMENTED OUT - defined in schema.index() below
//   },
//   team: {
//     admins: [{
//       user: { type: Schema.Types.ObjectId, ref: 'User' },
//       addedAt: { type: Date, default: Date.now },
//       addedBy: { type: Schema.Types.ObjectId, ref: 'User' }
//     }],
//     totalMembers: { type: Number, default: 1 },
//     activeMembers: { type: Number, default: 1 }
//   },
  
//   // Usage & Analytics
//   usage: {
//     currentMonth: {
//       apiCalls: { type: Number, default: 0 },
//       storage: { type: Number, default: 0 },
//       bandwidth: { type: Number, default: 0 }
//     },
//     historical: [{
//       month: Date,
//       apiCalls: Number,
//       storage: Number,
//       bandwidth: Number,
//       cost: Number
//     }]
//   },
  
//   // Platform Metrics
//   metrics: {
//     healthScore: {
//       type: Number,
//       min: 0,
//       max: 100,
//       default: 50
//     },
//     engagementLevel: {
//       type: String,
//       enum: ['low', 'medium', 'high', 'very_high'],
//       default: 'medium'
//     },
//     lastActivity: Date,
//     totalProjects: { type: Number, default: 0 },
//     totalRevenue: { type: Number, default: 0 },
//     churnRisk: {
//       score: { type: Number, min: 0, max: 100 },
//       factors: [String]
//     }
//   },
  
//   // Security & Compliance
//   security: {
//     twoFactorRequired: { type: Boolean, default: false },
//     ipWhitelist: [String],
//     ssoEnabled: { type: Boolean, default: false },
//     ssoProvider: String,
//     passwordPolicy: {
//       minLength: { type: Number, default: 8 },
//       requireUppercase: { type: Boolean, default: true },
//       requireNumbers: { type: Boolean, default: true },
//       requireSpecialChars: { type: Boolean, default: true }
//     },
//     dataRetention: {
//       enabled: { type: Boolean, default: false },
//       days: { type: Number, default: 365 }
//     }
//   },
  
//   // Integrations
//   integrations: {
//     enabled: [{
//       type: { type: String },
//       name: String,
//       config: Schema.Types.Mixed,
//       connectedAt: Date,
//       lastSync: Date,
//       status: { type: String, enum: ['active', 'error', 'paused'] }
//     }]
//   },
  
//   // Settings & Preferences
//   settings: {
//     locale: { type: String, default: 'en-US' },
//     currency: { type: String, default: 'USD' },
//     dateFormat: { type: String, default: 'MM/DD/YYYY' },
//     timeFormat: { type: String, default: '12h' },
//     weekStart: { type: Number, default: 0 }, // 0 = Sunday
//     fiscalYearStart: { type: Number, default: 1 }, // January
//     notifications: {
//       email: {
//         systemUpdates: { type: Boolean, default: true },
//         billing: { type: Boolean, default: true },
//         security: { type: Boolean, default: true },
//         marketing: { type: Boolean, default: false }
//       },
//       inApp: {
//         enabled: { type: Boolean, default: true }
//       }
//     }
//   },
  
//   // Platform Metadata
//   metadata: {
//     source: {
//       type: String,
//       enum: ['direct', 'partner', 'referral', 'organic', 'paid'],
//       default: 'direct'
//     },
//     referralCode: String,
//     partnerId: { type: Schema.Types.ObjectId, ref: 'Partner' },
//     tags: [String],
//     customFields: {
//       type: Map,
//       of: Schema.Types.Mixed
//     }
//   },
  
//   // Status Flags
//   status: {
//     active: { 
//       type: Boolean, 
//       default: true 
//       // index: true // COMMENTED OUT - defined in schema.index() below
//     },
//     verified: { type: Boolean, default: false },
//     featured: { type: Boolean, default: false },
//     beta: { type: Boolean, default: false },
//     locked: { type: Boolean, default: false },
//     lockedReason: String,
//     deletedAt: Date
//   },
  
//   // Audit Fields
//   createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
//   lastModifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
//   onboardingCompletedAt: Date,
//   firstProjectCreatedAt: Date,
//   lastLoginAt: Date
// }, {
//   timestamps: true,
//   toJSON: { virtuals: true },
//   toObject: { virtuals: true }
// });

// // CORRECTED: Define indexes only here to avoid duplicates
// hostedOrganizationSchema.index({ platformId: 1 });
// hostedOrganizationSchema.index({ tenantId: 1 }, { sparse: true });
// hostedOrganizationSchema.index({ name: 1 });
// hostedOrganizationSchema.index({ owner: 1 });
// hostedOrganizationSchema.index({ 'status.active': 1 });
// hostedOrganizationSchema.index({ 'subscription.status': 1 });

// // Existing compound indexes
// hostedOrganizationSchema.index({ 'status.active': 1, 'subscription.status': 1 });
// hostedOrganizationSchema.index({ 'domains.subdomain': 1 });
// hostedOrganizationSchema.index({ 'subscription.nextBillingDate': 1 });
// hostedOrganizationSchema.index({ 'metrics.healthScore': -1 });
// hostedOrganizationSchema.index({ 'usage.currentMonth.apiCalls': -1 });
// hostedOrganizationSchema.index({ createdAt: -1 });

// // Text search index
// hostedOrganizationSchema.index({
//   name: 'text',
//   displayName: 'text',
//   'businessInfo.industry.primary.name': 'text'
// });

// // Virtual Properties
// hostedOrganizationSchema.virtual('url').get(function() {
//   if (this.domains.customDomains && this.domains.customDomains.length > 0) {
//     const verifiedDomain = this.domains.customDomains.find(d => d.verified);
//     if (verifiedDomain) {
//       return `https://${verifiedDomain.domain}`;
//     }
//   }
//   if (this.domains.subdomain) {
//     return `https://${this.domains.subdomain}.${process.env.PLATFORM_DOMAIN}`;
//   }
//   return null;
// });

// hostedOrganizationSchema.virtual('isTrialing').get(function() {
//   return this.subscription.status === 'trial' && 
//          this.subscription.trialEnd && 
//          this.subscription.trialEnd > new Date();
// });

// hostedOrganizationSchema.virtual('daysUntilBilling').get(function() {
//   if (!this.subscription.nextBillingDate) return null;
//   const days = Math.ceil((this.subscription.nextBillingDate - new Date()) / (1000 * 60 * 60 * 24));
//   return days > 0 ? days : 0;
// });

// hostedOrganizationSchema.virtual('usagePercentage').get(function() {
//   const usage = {};
//   if (this.platformConfig.limits.users > 0) {
//     usage.users = (this.team.activeMembers / this.platformConfig.limits.users) * 100;
//   }
//   if (this.platformConfig.limits.storage > 0) {
//     usage.storage = (this.usage.currentMonth.storage / this.platformConfig.limits.storage) * 100;
//   }
//   if (this.platformConfig.limits.apiCalls > 0) {
//     usage.apiCalls = (this.usage.currentMonth.apiCalls / this.platformConfig.limits.apiCalls) * 100;
//   }
//   return usage;
// });

// // Pre-save Middleware
// hostedOrganizationSchema.pre('save', async function(next) {
//   try {
//     // Generate slug if not provided
//     if (!this.slug && this.isNew) {
//       const baseSlug = slugify(this.name.toLowerCase(), { 
//         replacement: '-',
//         strict: true 
//       });
      
//       let slug = baseSlug;
//       let counter = 1;
      
//       while (await this.constructor.findOne({ slug })) {
//         slug = `${baseSlug}-${counter}`;
//         counter++;
//       }
      
//       this.slug = slug;
//     }
    
//     // Generate subdomain from slug if not set
//     if (!this.domains.subdomain && this.isNew) {
//       this.domains.subdomain = this.slug;
//     }
    
//     // Set display name if not provided
//     if (!this.displayName) {
//       this.displayName = this.name;
//     }
    
//     // Update health score
//     if (this.isModified('metrics') || this.isModified('usage') || this.isModified('subscription')) {
//       this.calculateHealthScore();
//     }
    
//     next();
//   } catch (error) {
//     next(error);
//   }
// });

// // Instance Methods
// hostedOrganizationSchema.methods.calculateHealthScore = function() {
//   let score = 50; // Base score
  
//   // Subscription status (20 points)
//   if (this.subscription.status === 'active') score += 20;
//   else if (this.subscription.status === 'trial') score += 10;
  
//   // Usage patterns (20 points)
//   const daysSinceLastActivity = this.metrics.lastActivity ? 
//     (Date.now() - this.metrics.lastActivity) / (1000 * 60 * 60 * 24) : 999;
//   if (daysSinceLastActivity < 7) score += 20;
//   else if (daysSinceLastActivity < 30) score += 10;
  
//   // Team size (10 points)
//   if (this.team.activeMembers > 5) score += 10;
//   else if (this.team.activeMembers > 1) score += 5;
  
//   // Projects (10 points)
//   if (this.metrics.totalProjects > 10) score += 10;
//   else if (this.metrics.totalProjects > 3) score += 5;
  
//   // Revenue generation (10 points)
//   if (this.metrics.totalRevenue > 10000) score += 10;
//   else if (this.metrics.totalRevenue > 1000) score += 5;
  
//   // Deductions
//   if (this.subscription.status === 'past_due') score -= 15;
//   if (this.subscription.status === 'suspended') score -= 25;
//   if (this.status.locked) score -= 20;
  
//   this.metrics.healthScore = Math.max(0, Math.min(100, score));
  
//   // Update engagement level
//   if (score >= 80) this.metrics.engagementLevel = 'very_high';
//   else if (score >= 60) this.metrics.engagementLevel = 'high';
//   else if (score >= 40) this.metrics.engagementLevel = 'medium';
//   else this.metrics.engagementLevel = 'low';
  
//   // Calculate churn risk
//   this.calculateChurnRisk();
// };

// hostedOrganizationSchema.methods.calculateChurnRisk = function() {
//   let riskScore = 0;
//   const factors = [];
  
//   // No recent activity
//   const daysSinceLastActivity = this.metrics.lastActivity ? 
//     (Date.now() - this.metrics.lastActivity) / (1000 * 60 * 60 * 24) : 999;
//   if (daysSinceLastActivity > 30) {
//     riskScore += 30;
//     factors.push('no_recent_activity');
//   }
  
//   // Low engagement
//   if (this.metrics.engagementLevel === 'low') {
//     riskScore += 25;
//     factors.push('low_engagement');
//   }
  
//   // Billing issues
//   if (this.subscription.status === 'past_due') {
//     riskScore += 20;
//     factors.push('payment_issues');
//   }
  
//   // No projects
//   if (this.metrics.totalProjects === 0) {
//     riskScore += 15;
//     factors.push('no_projects');
//   }
  
//   // Single user
//   if (this.team.activeMembers === 1) {
//     riskScore += 10;
//     factors.push('single_user');
//   }
  
//   this.metrics.churnRisk = {
//     score: Math.min(100, riskScore),
//     factors
//   };
// };

// hostedOrganizationSchema.methods.canPerformAction = function(action, userId) {
//   // Owner can do everything
//   if (this.owner.toString() === userId.toString()) {
//     return true;
//   }
  
//   // Check if user is admin
//   const isAdmin = this.team.admins.some(
//     admin => admin.user.toString() === userId.toString()
//   );
  
//   // Define action permissions
//   const adminActions = [
//     'manage_team', 'manage_billing', 'manage_integrations', 
//     'view_analytics', 'manage_settings'
//   ];
  
//   if (adminActions.includes(action) && isAdmin) {
//     return true;
//   }
  
//   return false;
// };

// hostedOrganizationSchema.methods.checkUsageLimit = function(resource) {
//   const limits = this.platformConfig.limits;
//   const usage = this.usage.currentMonth;
  
//   switch (resource) {
//     case 'users':
//       return this.team.activeMembers < limits.users;
//     case 'storage':
//       return usage.storage < limits.storage;
//     case 'apiCalls':
//       return usage.apiCalls < limits.apiCalls;
//     case 'projects':
//       return this.metrics.totalProjects < limits.projects;
//     default:
//       return true;
//   }
// };

// hostedOrganizationSchema.methods.incrementUsage = async function(resource, amount = 1) {
//   const field = `usage.currentMonth.${resource}`;
//   this[field] = (this[field] || 0) + amount;
  
//   // Check if limit exceeded
//   if (!this.checkUsageLimit(resource)) {
//     // Emit event for limit exceeded
//     this.constructor.emit('limitExceeded', {
//       organization: this._id,
//       resource,
//       limit: this.platformConfig.limits[resource],
//       usage: this.usage.currentMonth[resource]
//     });
//   }
  
//   await this.save();
// };

// // Static Methods
// hostedOrganizationSchema.statics.findBySubdomain = function(subdomain) {
//   return this.findOne({ 
//     'domains.subdomain': subdomain.toLowerCase(),
//     'status.active': true 
//   });
// };

// hostedOrganizationSchema.statics.findByCustomDomain = function(domain) {
//   return this.findOne({
//     'domains.customDomains': {
//       $elemMatch: {
//         domain: domain.toLowerCase(),
//         verified: true
//       }
//     },
//     'status.active': true
//   });
// };

// hostedOrganizationSchema.statics.searchOrganizations = async function(query, filters = {}) {
//   const searchQuery = {
//     'status.active': true
//   };
  
//   // Text search
//   if (query) {
//     searchQuery.$text = { $search: query };
//   }
  
//   // Apply filters
//   if (filters.tier) {
//     searchQuery['platformConfig.tier'] = filters.tier;
//   }
  
//   if (filters.industry) {
//     searchQuery['businessInfo.industry.primary.name'] = new RegExp(filters.industry, 'i');
//   }
  
//   if (filters.minHealthScore) {
//     searchQuery['metrics.healthScore'] = { $gte: filters.minHealthScore };
//   }
  
//   if (filters.subscriptionStatus) {
//     searchQuery['subscription.status'] = filters.subscriptionStatus;
//   }
  
//   return this.find(searchQuery)
//     .sort({ 'metrics.healthScore': -1, createdAt: -1 })
//     .limit(filters.limit || 20);
// };

// hostedOrganizationSchema.statics.getExpiringTrials = function(daysAhead = 3) {
//   const futureDate = new Date();
//   futureDate.setDate(futureDate.getDate() + daysAhead);
  
//   return this.find({
//     'subscription.status': 'trial',
//     'subscription.trialEnd': {
//       $gte: new Date(),
//       $lte: futureDate
//     },
//     'status.active': true
//   });
// };

// hostedOrganizationSchema.statics.getOrganizationsAtRisk = function() {
//   return this.find({
//     'status.active': true,
//     $or: [
//       { 'metrics.churnRisk.score': { $gte: 70 } },
//       { 'subscription.status': 'past_due' },
//       { 'metrics.engagementLevel': 'low' }
//     ]
//   }).sort({ 'metrics.churnRisk.score': -1 });
// };

// hostedOrganizationSchema.statics.updateMonthlyUsage = async function() {
//   const startOfMonth = new Date();
//   startOfMonth.setDate(1);
//   startOfMonth.setHours(0, 0, 0, 0);
  
//   // Archive current month usage to historical
//   const organizations = await this.find({ 'status.active': true });
  
//   for (const org of organizations) {
//     if (org.usage.currentMonth.apiCalls > 0 || 
//         org.usage.currentMonth.storage > 0 || 
//         org.usage.currentMonth.bandwidth > 0) {
      
//       org.usage.historical.push({
//         month: new Date(startOfMonth.getTime() - 1), // Last day of previous month
//         apiCalls: org.usage.currentMonth.apiCalls,
//         storage: org.usage.currentMonth.storage,
//         bandwidth: org.usage.currentMonth.bandwidth,
//         cost: 0 // Calculate based on usage and plan
//       });
      
//       // Reset current month
//       org.usage.currentMonth = {
//         apiCalls: 0,
//         storage: org.usage.currentMonth.storage, // Storage carries over
//         bandwidth: 0
//       };
      
//       // Keep only last 12 months
//       if (org.usage.historical.length > 12) {
//         org.usage.historical = org.usage.historical.slice(-12);
//       }
      
//       await org.save();
//     }
//   }
// };

// // Plugins
// hostedOrganizationSchema.plugin(require('mongoose-lean-virtuals'));

// const HostedOrganization = mongoose.model('HostedOrganization', hostedOrganizationSchema);

// module.exports = HostedOrganization;