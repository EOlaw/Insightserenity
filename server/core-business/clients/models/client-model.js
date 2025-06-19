/**
 * @file Client Model - Advanced
 * @description Comprehensive model for managing consulting clients with advanced features
 * @version 2.0.0
 */

const mongoose = require('mongoose');
const slugify = require('slugify');
const { encrypt, decrypt } = require('../../../shared/security/services/encryption-service');
const Schema = mongoose.Schema;

/**
 * Contact Person Sub-schema
 */
const contactPersonSchema = new Schema({
  isPrimary: { type: Boolean, default: false },
  title: {
    type: String,
    enum: ['Mr', 'Mrs', 'Ms', 'Dr', 'Prof', 'Sir', 'Lady', 'Lord'],
    required: true
  },
  firstName: { 
    type: String, 
    required: true,
    trim: true,
    minlength: [2, 'First name must be at least 2 characters']
  },
  lastName: { 
    type: String, 
    required: true,
    trim: true,
    minlength: [2, 'Last name must be at least 2 characters']
  },
  position: { 
    type: String, 
    required: true,
    trim: true 
  },
  department: { type: String, trim: true },
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
  },
  phone: {
    primary: { type: String, required: true },
    secondary: { type: String },
    mobile: { type: String }
  },
  preferences: {
    communicationMethod: {
      type: String,
      enum: ['email', 'phone', 'video_call', 'in_person'],
      default: 'email'
    },
    bestTimeToContact: {
      timezone: { type: String, default: 'UTC' },
      days: [{
        type: String,
        enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
      }],
      timeSlots: [{
        start: String, // HH:MM format
        end: String
      }]
    },
    language: { type: String, default: 'en' },
    doNotContact: { type: Boolean, default: false }
  },
  notes: { type: String, maxlength: 1000 },
  lastContactedAt: Date,
  linkedInProfile: String,
  active: { type: Boolean, default: true }
}, { _id: true });

/**
 * Client Schema
 * Advanced schema for managing consulting client organizations
 */
const clientSchema = new Schema({
  // Core Client Information
  name: { 
    type: String, 
    required: true, 
    trim: true,
    minlength: [2, 'Client name must be at least 2 characters'],
    maxlength: [200, 'Client name cannot exceed 200 characters']
  },
  legalName: { 
    type: String, 
    trim: true,
    maxlength: [200, 'Legal name cannot exceed 200 characters']
  },
  slug: { 
    type: String,
    unique: true, 
    trim: true,
    lowercase: true
  },
  code: {
    type: String,
    unique: true,
    uppercase: true,
    trim: true,
    match: [/^[A-Z0-9]{3,10}$/, 'Client code must be 3-10 alphanumeric characters']
  },
  
  // Company Details
  companyDetails: {
    type: {
      type: String,
      required: true,
      enum: ['corporation', 'llc', 'partnership', 'sole_proprietorship', 'nonprofit', 'government', 'educational', 'other']
    },
    registrationNumber: { 
      type: String,
      trim: true,
      sparse: true
    },
    taxId: { 
      type: String,
      set: function(value) {
        return value ? encrypt(value) : value;
      },
      get: function(value) {
        return value ? decrypt(value) : value;
      }
    },
    vatNumber: { type: String, trim: true },
    incorporationDate: Date,
    fiscalYearEnd: {
      month: { type: Number, min: 1, max: 12 },
      day: { type: Number, min: 1, max: 31 }
    },
    employeeCount: {
      range: {
        type: String,
        enum: ['1-10', '11-50', '51-200', '201-500', '501-1000', '1001-5000', '5001-10000', '10000+']
      },
      exact: Number,
      lastUpdated: Date
    },
    annualRevenue: {
      currency: { type: String, default: 'USD' },
      range: {
        type: String,
        enum: ['<1M', '1M-10M', '10M-50M', '50M-100M', '100M-500M', '500M-1B', '1B-5B', '5B+']
      },
      exact: {
        type: Number,
        set: function(value) {
          return value ? encrypt(value.toString()) : value;
        },
        get: function(value) {
          return value ? parseFloat(decrypt(value)) : value;
        }
      },
      lastUpdated: Date
    }
  },
  
  // Industry and Market
  industry: {
    primary: {
      type: String,
      required: true,
      enum: [
        'technology', 'healthcare', 'finance', 'manufacturing', 'retail', 'education',
        'energy', 'telecommunications', 'media', 'transportation', 'hospitality',
        'real_estate', 'construction', 'agriculture', 'pharmaceuticals', 'automotive',
        'aerospace', 'defense', 'consumer_goods', 'professional_services', 'other'
      ]
    },
    secondary: [{
      type: String,
      enum: [
        'technology', 'healthcare', 'finance', 'manufacturing', 'retail', 'education',
        'energy', 'telecommunications', 'media', 'transportation', 'hospitality',
        'real_estate', 'construction', 'agriculture', 'pharmaceuticals', 'automotive',
        'aerospace', 'defense', 'consumer_goods', 'professional_services', 'other'
      ]
    }],
    subSectors: [String],
    naicsCode: String,
    sicCode: String
  },
  
  // Geographical Information
  addresses: {
    headquarters: {
      street1: { type: String, required: true },
      street2: String,
      city: { type: String, required: true },
      state: String,
      postalCode: { type: String, required: true },
      country: { type: String, required: true },
      coordinates: {
        latitude: Number,
        longitude: Number
      }
    },
    billing: {
      sameAsHeadquarters: { type: Boolean, default: true },
      street1: String,
      street2: String,
      city: String,
      state: String,
      postalCode: String,
      country: String
    },
    shipping: [{
      label: String,
      street1: String,
      street2: String,
      city: String,
      state: String,
      postalCode: String,
      country: String,
      isDefault: { type: Boolean, default: false }
    }],
    offices: [{
      name: String,
      type: { type: String, enum: ['regional', 'branch', 'satellite', 'virtual'] },
      street1: String,
      street2: String,
      city: String,
      state: String,
      postalCode: String,
      country: String,
      phone: String,
      employeeCount: Number
    }]
  },
  
  // Contact Information
  contacts: {
    main: {
      phone: { type: String, required: true },
      fax: String,
      email: {
        type: String,
        required: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
      },
      website: {
        type: String,
        match: [/^https?:\/\/([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/, 'Please provide a valid URL']
      }
    },
    support: {
      phone: String,
      email: String,
      hours: String
    },
    emergency: {
      phone: String,
      email: String,
      available247: { type: Boolean, default: false }
    }
  },
  
  // Contact Persons
  contactPersons: [contactPersonSchema],
  
  // Business Relationship
  relationship: {
    status: {
      type: String,
      required: true,
      enum: ['prospect', 'lead', 'opportunity', 'active', 'inactive', 'dormant', 'lost', 'blacklisted'],
      default: 'prospect'
    },
    type: {
      type: String,
      required: true,
      enum: ['direct', 'channel_partner', 'referral', 'strategic_alliance', 'vendor', 'competitor'],
      default: 'direct'
    },
    tier: {
      type: String,
      enum: ['platinum', 'gold', 'silver', 'bronze', 'standard'],
      default: 'standard'
    },
    startDate: { type: Date, default: Date.now },
    renewalDate: Date,
    lastActivityDate: Date,
    healthScore: {
      score: { type: Number, min: 0, max: 100 },
      factors: {
        engagementLevel: { type: Number, min: 0, max: 100 },
        paymentHistory: { type: Number, min: 0, max: 100 },
        projectSuccess: { type: Number, min: 0, max: 100 },
        satisfactionScore: { type: Number, min: 0, max: 100 },
        growthPotential: { type: Number, min: 0, max: 100 }
      },
      lastCalculated: Date,
      trend: { type: String, enum: ['improving', 'stable', 'declining'] }
    },
    churnRisk: {
      level: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
      reasons: [String],
      mitigationActions: [{
        action: String,
        assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
        dueDate: Date,
        status: { type: String, enum: ['pending', 'in_progress', 'completed'] }
      }]
    }
  },
  
  // Account Management
  accountManagement: {
    accountManager: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    secondaryManager: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    salesRep: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    customerSuccessManager: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    technicalLead: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    team: [{
      member: { type: Schema.Types.ObjectId, ref: 'User' },
      role: String,
      responsibilities: [String],
      startDate: Date,
      endDate: Date
    }]
  },
  
  // Financial Information
  financial: {
    creditLimit: {
      amount: { type: Number, min: 0 },
      currency: { type: String, default: 'USD' }
    },
    creditTerms: {
      type: String,
      enum: ['prepaid', 'net15', 'net30', 'net45', 'net60', 'net90', 'custom'],
      default: 'net30'
    },
    customPaymentTerms: String,
    paymentMethods: [{
      type: { type: String, enum: ['bank_transfer', 'credit_card', 'check', 'ach', 'wire', 'crypto'] },
      isDefault: { type: Boolean, default: false },
      details: Schema.Types.Mixed // Encrypted in practice
    }],
    bankDetails: {
      bankName: String,
      accountName: String,
      accountNumber: {
        type: String,
        set: function(value) {
          return value ? encrypt(value) : value;
        },
        get: function(value) {
          return value ? decrypt(value) : value;
        }
      },
      routingNumber: {
        type: String,
        set: function(value) {
          return value ? encrypt(value) : value;
        },
        get: function(value) {
          return value ? decrypt(value) : value;
        }
      },
      swiftCode: String,
      iban: String
    },
    billingCycle: {
      type: String,
      enum: ['weekly', 'biweekly', 'monthly', 'quarterly', 'annually', 'project_based'],
      default: 'monthly'
    },
    invoiceDelivery: {
      method: { type: String, enum: ['email', 'portal', 'mail', 'api'], default: 'email' },
      emails: [String],
      format: { type: String, enum: ['pdf', 'xml', 'edi', 'custom'], default: 'pdf' }
    },
    taxExempt: { type: Boolean, default: false },
    taxExemptionCertificate: String,
    discounts: [{
      type: { type: String, enum: ['percentage', 'fixed', 'volume', 'loyalty'] },
      value: Number,
      applicableServices: [{ type: Schema.Types.ObjectId, ref: 'Service' }],
      validFrom: Date,
      validUntil: Date,
      conditions: String
    }]
  },
  
  // Contract and SLA
  contracts: {
    master: {
      number: String,
      signedDate: Date,
      effectiveDate: Date,
      expirationDate: Date,
      value: {
        amount: Number,
        currency: { type: String, default: 'USD' }
      },
      type: { type: String, enum: ['msa', 'sow', 'nda', 'mixed'] },
      autoRenew: { type: Boolean, default: false },
      renewalTerms: String,
      documentUrl: String
    },
    ndaSigned: { type: Boolean, default: false },
    ndaDate: Date,
    ndaExpiryDate: Date,
    sla: {
      responseTime: {
        critical: { value: Number, unit: String },
        high: { value: Number, unit: String },
        medium: { value: Number, unit: String },
        low: { value: Number, unit: String }
      },
      availability: Number, // Percentage
      supportHours: String,
      escalationMatrix: [{
        level: Number,
        contactPerson: String,
        contactMethod: String,
        responseTime: String
      }],
      penalties: [{
        breach: String,
        penalty: String
      }]
    }
  },
  
  // Projects and Engagement History
  projectStats: {
    totalProjects: { type: Number, default: 0 },
    activeProjects: { type: Number, default: 0 },
    completedProjects: { type: Number, default: 0 },
    totalValue: {
      amount: { type: Number, default: 0 },
      currency: { type: String, default: 'USD' }
    },
    averageProjectValue: { type: Number, default: 0 },
    averageProjectDuration: { type: Number, default: 0 }, // In days
    successRate: { type: Number, min: 0, max: 100 },
    lastProjectDate: Date
  },
  
  // Communication Preferences
  preferences: {
    communication: {
      language: { type: String, default: 'en' },
      timezone: { type: String, default: 'UTC' },
      preferredChannels: [{
        type: String,
        enum: ['email', 'phone', 'sms', 'whatsapp', 'slack', 'teams', 'portal']
      }],
      doNotContact: { type: Boolean, default: false },
      marketingOptIn: { type: Boolean, default: true },
      newsletterOptIn: { type: Boolean, default: true }
    },
    billing: {
      consolidatedInvoicing: { type: Boolean, default: false },
      invoiceGrouping: { type: String, enum: ['project', 'service', 'consultant', 'none'], default: 'project' },
      requiresPO: { type: Boolean, default: false },
      approvalRequired: { type: Boolean, default: false },
      approvalThreshold: Number
    },
    project: {
      reportingFrequency: { type: String, enum: ['daily', 'weekly', 'biweekly', 'monthly', 'on_demand'], default: 'weekly' },
      preferredMethodology: { type: String, enum: ['agile', 'waterfall', 'hybrid', 'custom'] },
      requiredDocumentation: [String],
      securityRequirements: [String]
    }
  },
  
  // Risk and Compliance
  compliance: {
    dueDiligence: {
      completed: { type: Boolean, default: false },
      completedDate: Date,
      nextReviewDate: Date,
      documents: [{
        type: String,
        uploadedDate: Date,
        expiryDate: Date,
        status: { type: String, enum: ['pending', 'approved', 'rejected', 'expired'] }
      }]
    },
    amlStatus: {
      verified: { type: Boolean, default: false },
      verifiedDate: Date,
      riskLevel: { type: String, enum: ['low', 'medium', 'high'] },
      notes: String
    },
    sanctions: {
      checked: { type: Boolean, default: false },
      checkedDate: Date,
      clearStatus: { type: Boolean, default: true },
      notes: String
    },
    gdprConsent: {
      given: { type: Boolean, default: false },
      date: Date,
      version: String,
      withdrawnDate: Date
    },
    dataProcessingAgreement: {
      signed: { type: Boolean, default: false },
      signedDate: Date,
      version: String
    }
  },
  
  // Internal Notes and Tags
  internal: {
    rating: {
      overall: { type: Number, min: 1, max: 5 },
      payment: { type: Number, min: 1, max: 5 },
      communication: { type: Number, min: 1, max: 5 },
      loyalty: { type: Number, min: 1, max: 5 }
    },
    notes: [{
      content: { type: String, required: true },
      type: { type: String, enum: ['general', 'financial', 'relationship', 'technical', 'warning'] },
      visibility: { type: String, enum: ['private', 'team', 'company'], default: 'team' },
      author: { type: Schema.Types.ObjectId, ref: 'User' },
      createdAt: { type: Date, default: Date.now },
      isPinned: { type: Boolean, default: false }
    }],
    tags: [{
      type: String,
      trim: true,
      lowercase: true
    }],
    customFields: Schema.Types.Mixed
  },
  
  // Integration Information
  integrations: {
    crm: {
      system: { type: String, enum: ['salesforce', 'hubspot', 'dynamics', 'pipedrive', 'custom'] },
      externalId: String,
      syncEnabled: { type: Boolean, default: false },
      lastSyncDate: Date,
      syncErrors: [{
        date: Date,
        error: String,
        resolved: { type: Boolean, default: false }
      }]
    },
    accounting: {
      system: { type: String, enum: ['quickbooks', 'xero', 'sage', 'netsuite', 'custom'] },
      customerId: String,
      syncEnabled: { type: Boolean, default: false },
      lastSyncDate: Date
    },
    erp: {
      system: String,
      customerId: String,
      syncEnabled: { type: Boolean, default: false }
    }
  },
  
  // Analytics and Metrics
  analytics: {
    lifetimeValue: {
      amount: { type: Number, default: 0 },
      currency: { type: String, default: 'USD' },
      lastCalculated: Date
    },
    acquisitionCost: {
      amount: Number,
      currency: { type: String, default: 'USD' }
    },
    profitability: {
      margin: Number, // Percentage
      lastCalculated: Date
    },
    engagementScore: {
      score: { type: Number, min: 0, max: 100 },
      lastCalculated: Date,
      factors: {
        projectFrequency: Number,
        communicationFrequency: Number,
        paymentTimeliness: Number,
        referrals: Number
      }
    },
    nps: {
      score: { type: Number, min: -100, max: 100 },
      surveyDate: Date,
      response: String
    }
  },
  
  // Document Management
  documents: [{
    name: { type: String, required: true },
    type: {
      type: String,
      enum: ['contract', 'proposal', 'invoice', 'report', 'compliance', 'correspondence', 'other'],
      required: true
    },
    description: String,
    url: String,
    uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    uploadedAt: { type: Date, default: Date.now },
    size: Number,
    mimeType: String,
    tags: [String],
    confidential: { type: Boolean, default: false },
    expiryDate: Date,
    version: { type: Number, default: 1 }
  }],
  
  // Status and Metadata
  status: {
    isActive: { type: Boolean, default: true },
    suspendedAt: Date,
    suspendedReason: String,
    suspendedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    blacklisted: { type: Boolean, default: false },
    blacklistReason: String,
    blacklistedAt: Date,
    blacklistedBy: { type: Schema.Types.ObjectId, ref: 'User' }
  },
  
  // Audit Fields
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  importedFrom: {
    system: String,
    id: String,
    date: Date
  },
  mergedFrom: [{
    clientId: { type: Schema.Types.ObjectId, ref: 'Client' },
    mergedAt: Date,
    mergedBy: { type: Schema.Types.ObjectId, ref: 'User' }
  }],
  
  // Data Quality
  dataQuality: {
    completeness: { type: Number, min: 0, max: 100 },
    lastAssessed: Date,
    missingFields: [String],
    validationErrors: [{
      field: String,
      error: String,
      severity: { type: String, enum: ['low', 'medium', 'high'] }
    }]
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Indexes for performance optimization
 */
clientSchema.index({ slug: 1 });
clientSchema.index({ code: 1 });
clientSchema.index({ 'companyDetails.registrationNumber': 1 });
clientSchema.index({ 'relationship.status': 1 });
clientSchema.index({ 'relationship.tier': 1 });
clientSchema.index({ 'industry.primary': 1 });
clientSchema.index({ 'addresses.headquarters.country': 1 });
clientSchema.index({ 'addresses.headquarters.city': 1 });
clientSchema.index({ 'accountManagement.accountManager': 1 });
clientSchema.index({ 'contactPersons.email': 1 });
clientSchema.index({ 'contacts.main.email': 1 });
clientSchema.index({ 'status.isActive': 1 });
clientSchema.index({ createdAt: -1 });
clientSchema.index({ 'analytics.lifetimeValue.amount': -1 });
clientSchema.index({ 'relationship.healthScore.score': -1 });

/**
 * Compound indexes for complex queries
 */
clientSchema.index({ 
  'relationship.status': 1, 
  'status.isActive': 1,
  'analytics.lifetimeValue.amount': -1 
});

clientSchema.index({ 
  'industry.primary': 1,
  'addresses.headquarters.country': 1,
  'relationship.tier': 1
});

/**
 * Text index for search functionality
 */
clientSchema.index({
  name: 'text',
  legalName: 'text',
  'contactPersons.firstName': 'text',
  'contactPersons.lastName': 'text',
  'contactPersons.email': 'text',
  'internal.tags': 'text'
});

/**
 * Pre-save middleware
 */
clientSchema.pre('save', async function(next) {
  try {
    // Generate slug
    if (this.isModified('name') || !this.slug) {
      const baseSlug = slugify(this.name, {
        lower: true,
        strict: true,
        remove: /[*+~.()'"!:@]/g
      });
      
      let slug = baseSlug;
      let counter = 1;
      
      while (await this.constructor.findOne({ slug, _id: { $ne: this._id } })) {
        slug = `${baseSlug}-${counter}`;
        counter++;
      }
      
      this.slug = slug;
    }
    
    // Generate client code if not provided
    if (!this.code) {
      const prefix = this.name.substring(0, 3).toUpperCase();
      const randomNum = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
      let code = `${prefix}${randomNum}`;
      
      while (await this.constructor.findOne({ code })) {
        const newRandomNum = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
        code = `${prefix}${newRandomNum}`;
      }
      
      this.code = code;
    }
    
    // Set legal name to company name if not provided
    if (!this.legalName) {
      this.legalName = this.name;
    }
    
    // Copy headquarters to billing if same
    if (this.addresses.billing.sameAsHeadquarters) {
      this.addresses.billing = {
        ...this.addresses.headquarters,
        sameAsHeadquarters: true
      };
    }
    
    // Ensure only one primary contact person
    const primaryContacts = this.contactPersons.filter(cp => cp.isPrimary);
    if (primaryContacts.length > 1) {
      primaryContacts.forEach((cp, index) => {
        if (index > 0) cp.isPrimary = false;
      });
    }
    
    // Calculate health score
    if (this.isModified('relationship') || this.isModified('analytics') || this.isModified('projectStats')) {
      this.calculateHealthScore();
    }
    
    // Calculate data quality score
    this.calculateDataQuality();
    
    // Update last activity date
    if (this.isModified() && !this.isNew) {
      this.relationship.lastActivityDate = new Date();
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Calculate client health score
 */
clientSchema.methods.calculateHealthScore = function() {
  const factors = this.relationship.healthScore.factors;
  
  // Calculate engagement level based on recent activity
  const daysSinceLastActivity = this.relationship.lastActivityDate 
    ? (Date.now() - this.relationship.lastActivityDate) / (1000 * 60 * 60 * 24)
    : 365;
  
  factors.engagementLevel = Math.max(0, 100 - (daysSinceLastActivity * 0.5));
  
  // Payment history (would need payment data in practice)
  factors.paymentHistory = 80; // Placeholder
  
  // Project success based on success rate
  factors.projectSuccess = this.projectStats.successRate || 50;
  
  // Satisfaction score from NPS
  if (this.analytics.nps.score !== undefined) {
    factors.satisfactionScore = (this.analytics.nps.score + 100) / 2;
  } else {
    factors.satisfactionScore = 50;
  }
  
  // Growth potential based on company size and industry
  const sizeScore = ['1001-5000', '5001-10000', '10000+'].includes(this.companyDetails.employeeCount.range) ? 80 : 50;
  const revenueScore = ['100M-500M', '500M-1B', '1B-5B', '5B+'].includes(this.companyDetails.annualRevenue.range) ? 80 : 50;
  factors.growthPotential = (sizeScore + revenueScore) / 2;
  
  // Calculate overall score
  const weights = {
    engagementLevel: 0.25,
    paymentHistory: 0.2,
    projectSuccess: 0.25,
    satisfactionScore: 0.2,
    growthPotential: 0.1
  };
  
  let totalScore = 0;
  for (const [factor, weight] of Object.entries(weights)) {
    totalScore += (factors[factor] || 0) * weight;
  }
  
  this.relationship.healthScore.score = Math.round(totalScore);
  this.relationship.healthScore.lastCalculated = new Date();
  
  // Determine trend (would need historical data in practice)
  if (totalScore >= 70) {
    this.relationship.healthScore.trend = 'improving';
  } else if (totalScore >= 50) {
    this.relationship.healthScore.trend = 'stable';
  } else {
    this.relationship.healthScore.trend = 'declining';
  }
  
  // Update churn risk
  if (totalScore < 30) {
    this.relationship.churnRisk.level = 'critical';
  } else if (totalScore < 50) {
    this.relationship.churnRisk.level = 'high';
  } else if (totalScore < 70) {
    this.relationship.churnRisk.level = 'medium';
  } else {
    this.relationship.churnRisk.level = 'low';
  }
};

/**
 * Calculate data quality score
 */
clientSchema.methods.calculateDataQuality = function() {
  const requiredFields = [
    'name',
    'companyDetails.type',
    'industry.primary',
    'addresses.headquarters.street1',
    'addresses.headquarters.city',
    'addresses.headquarters.country',
    'contacts.main.phone',
    'contacts.main.email',
    'accountManagement.accountManager'
  ];
  
  const importantFields = [
    'legalName',
    'companyDetails.registrationNumber',
    'companyDetails.employeeCount.range',
    'companyDetails.annualRevenue.range',
    'contactPersons',
    'contracts.master.number',
    'financial.creditTerms'
  ];
  
  let filledRequired = 0;
  let filledImportant = 0;
  const missingFields = [];
  
  // Check required fields
  requiredFields.forEach(field => {
    if (this.get(field)) {
      filledRequired++;
    } else {
      missingFields.push(field);
    }
  });
  
  // Check important fields
  importantFields.forEach(field => {
    if (field === 'contactPersons' && this.contactPersons.length > 0) {
      filledImportant++;
    } else if (field !== 'contactPersons' && this.get(field)) {
      filledImportant++;
    } else {
      missingFields.push(field);
    }
  });
  
  // Calculate completeness score
  const requiredScore = (filledRequired / requiredFields.length) * 70;
  const importantScore = (filledImportant / importantFields.length) * 30;
  
  this.dataQuality.completeness = Math.round(requiredScore + importantScore);
  this.dataQuality.lastAssessed = new Date();
  this.dataQuality.missingFields = missingFields;
};

/**
 * Virtual properties
 */
clientSchema.virtual('displayName').get(function() {
  return this.legalName || this.name;
});

clientSchema.virtual('fullAddress').get(function() {
  const addr = this.addresses.headquarters;
  return `${addr.street1}${addr.street2 ? ', ' + addr.street2 : ''}, ${addr.city}, ${addr.state || ''} ${addr.postalCode}, ${addr.country}`;
});

clientSchema.virtual('primaryContact').get(function() {
  return this.contactPersons.find(cp => cp.isPrimary) || this.contactPersons[0];
});

clientSchema.virtual('isHighValue').get(function() {
  return this.relationship.tier === 'platinum' || this.relationship.tier === 'gold';
});

clientSchema.virtual('requiresAttention').get(function() {
  return this.relationship.churnRisk.level === 'high' || 
         this.relationship.churnRisk.level === 'critical' ||
         this.relationship.healthScore.score < 50;
});

/**
 * Instance methods
 */
clientSchema.methods.addContactPerson = function(contactData) {
  // If this is the first contact, make it primary
  if (this.contactPersons.length === 0) {
    contactData.isPrimary = true;
  }
  
  this.contactPersons.push(contactData);
  return this.save();
};

clientSchema.methods.updateHealthScore = async function() {
  this.calculateHealthScore();
  return this.save();
};

clientSchema.methods.recordActivity = async function(activityType, description) {
  this.relationship.lastActivityDate = new Date();
  
  // Add to activity log if you have one
  // this.activityLog.push({ type: activityType, description, date: new Date() });
  
  return this.save();
};

clientSchema.methods.suspend = async function(reason, userId) {
  this.status.isActive = false;
  this.status.suspendedAt = new Date();
  this.status.suspendedReason = reason;
  this.status.suspendedBy = userId;
  
  return this.save();
};

clientSchema.methods.reactivate = async function() {
  this.status.isActive = true;
  this.status.suspendedAt = null;
  this.status.suspendedReason = null;
  this.status.suspendedBy = null;
  
  return this.save();
};

clientSchema.methods.blacklist = async function(reason, userId) {
  this.status.blacklisted = true;
  this.status.blacklistReason = reason;
  this.status.blacklistedAt = new Date();
  this.status.blacklistedBy = userId;
  this.status.isActive = false;
  
  return this.save();
};

clientSchema.methods.canBeContactedBy = function(userId) {
  // Check if user is part of the account team
  const isAccountManager = this.accountManagement.accountManager?.toString() === userId.toString();
  const isSecondaryManager = this.accountManagement.secondaryManager?.toString() === userId.toString();
  const isTeamMember = this.accountManagement.team.some(tm => 
    tm.member.toString() === userId.toString() && (!tm.endDate || tm.endDate > new Date())
  );
  
  return isAccountManager || isSecondaryManager || isTeamMember;
};

clientSchema.methods.calculateLifetimeValue = async function() {
  // This would aggregate all project values
  // For now, using projectStats.totalValue
  this.analytics.lifetimeValue.amount = this.projectStats.totalValue.amount;
  this.analytics.lifetimeValue.lastCalculated = new Date();
  
  return this.save();
};

/**
 * Static methods
 */
clientSchema.statics.findByStatus = function(status, options = {}) {
  const query = this.find({ 'relationship.status': status });
  
  if (options.isActive !== undefined) {
    query.where('status.isActive', options.isActive);
  }
  
  if (options.tier) {
    query.where('relationship.tier', options.tier);
  }
  
  return query.exec();
};

clientSchema.statics.findHighRiskClients = function() {
  return this.find({
    'status.isActive': true,
    $or: [
      { 'relationship.churnRisk.level': { $in: ['high', 'critical'] } },
      { 'relationship.healthScore.score': { $lt: 50 } }
    ]
  }).populate('accountManagement.accountManager', 'firstName lastName email');
};

clientSchema.statics.findByAccountManager = function(userId) {
  return this.find({
    $or: [
      { 'accountManagement.accountManager': userId },
      { 'accountManagement.secondaryManager': userId },
      { 'accountManagement.team.member': userId }
    ],
    'status.isActive': true
  });
};

clientSchema.statics.searchClients = function(searchTerm, filters = {}) {
  const query = { 'status.isActive': true };
  
  if (searchTerm) {
    query.$text = { $search: searchTerm };
  }
  
  if (filters.industry) {
    query['industry.primary'] = filters.industry;
  }
  
  if (filters.country) {
    query['addresses.headquarters.country'] = filters.country;
  }
  
  if (filters.tier) {
    query['relationship.tier'] = filters.tier;
  }
  
  if (filters.status) {
    query['relationship.status'] = filters.status;
  }
  
  if (filters.minRevenue) {
    // This would need more complex logic for revenue ranges
  }
  
  return this.find(query);
};

/**
 * Middleware for populating references
 */
clientSchema.pre(/^find/, function() {
  // Only populate if specifically requested
  if (this.options._populate !== false) {
    this.populate({
      path: 'accountManagement.accountManager',
      select: 'firstName lastName email profile.avatar'
    });
  }
});

/**
 * Ensure data integrity
 */
clientSchema.pre('save', function(next) {
  // Ensure financial data encryption
  if (this.isModified('financial.bankDetails') && !this.financial.bankDetails.accountNumber?.startsWith('enc:')) {
    // Trigger encryption (handled by setter)
    this.financial.bankDetails = this.financial.bankDetails;
  }
  
  next();
});

const Client = mongoose.model('Client', clientSchema);

module.exports = Client;