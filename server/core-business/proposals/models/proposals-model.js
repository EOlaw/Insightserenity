// server/core-business/proposals/models/proposals-model.js
/**
 * @file Proposal Model
 * @description Comprehensive proposal model for business proposal management
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

// Import schemas
const { proposalSectionSchema } = require('./schemas/proposal-section-schema');
const { proposalPricingSchema } = require('./schemas/proposal-pricing-schema');
const { proposalTimelineSchema } = require('./schemas/proposal-timeline-schema');
const { proposalTermsSchema } = require('./schemas/proposal-terms-schema');
const { proposalApprovalSchema } = require('./schemas/proposal-approval-schema');
const { proposalRevisionSchema } = require('./schemas/proposal-revision-schema');
const { proposalAnalyticsSchema } = require('./schemas/proposal-analytics-schema');

/**
 * Proposal Schema Definition
 */
const proposalSchema = new Schema({
  // Basic Information
  proposalId: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^PRP-[A-Z0-9]{6,10}$/.test(v);
      },
      message: 'Proposal ID must follow format: PRP-XXXXXX'
    }
  },
  
  title: {
    type: String,
    required: [true, 'Proposal title is required'],
    trim: true,
    minlength: [5, 'Proposal title must be at least 5 characters'],
    maxlength: [200, 'Proposal title cannot exceed 200 characters']
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
  
  version: {
    type: String,
    default: '1.0',
    required: true,
    validate: {
      validator: function(v) {
        return /^\d+\.\d+$/.test(v);
      },
      message: 'Version must follow format: X.Y'
    }
  },
  
  // Type and Category
  type: {
    type: String,
    required: true,
    enum: ['service', 'project', 'retainer', 'partnership', 'custom'],
    default: 'service'
  },
  
  category: {
    type: String,
    required: true,
    enum: [
      'consulting', 'implementation', 'assessment', 'audit',
      'training', 'support', 'development', 'design',
      'strategy', 'transformation', 'other'
    ]
  },
  
  // Client Information
  client: {
    organization: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true
    },
    contact: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    additionalContacts: [{
      user: { type: Schema.Types.ObjectId, ref: 'User' },
      role: String,
      isPrimary: { type: Boolean, default: false }
    }],
    requirements: {
      budget: {
        min: Number,
        max: Number,
        currency: { type: String, default: 'USD' }
      },
      timeline: {
        startDate: Date,
        endDate: Date,
        isFlexible: { type: Boolean, default: false }
      },
      specialRequirements: [String]
    }
  },
  
  // Proposal Content
  executiveSummary: {
    type: String,
    required: [true, 'Executive summary is required'],
    minlength: [100, 'Executive summary must be at least 100 characters'],
    maxlength: [5000, 'Executive summary cannot exceed 5000 characters']
  },
  
  sections: [proposalSectionSchema],
  
  // Services and Deliverables
  services: [{
    service: {
      type: Schema.Types.ObjectId,
      ref: 'Service'
    },
    customService: {
      name: String,
      description: String
    },
    quantity: {
      type: Number,
      default: 1
    },
    customization: {
      requirements: [String],
      modifications: [String]
    }
  }],
  
  deliverables: [{
    name: {
      type: String,
      required: true
    },
    description: String,
    category: String,
    timeline: {
      duration: Number,
      unit: {
        type: String,
        enum: ['days', 'weeks', 'months'],
        default: 'days'
      }
    },
    dependencies: [String],
    acceptanceCriteria: [String]
  }],
  
  // Pricing and Financial
  pricing: proposalPricingSchema,
  
  // Timeline and Schedule
  timeline: proposalTimelineSchema,
  
  // Team and Resources
  team: {
    lead: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    members: [{
      user: { type: Schema.Types.ObjectId, ref: 'User' },
      role: String,
      allocation: Number,
      rate: {
        amount: Number,
        currency: String,
        unit: { type: String, enum: ['hour', 'day', 'month'] }
      }
    }],
    consultants: [{
      user: { type: Schema.Types.ObjectId, ref: 'User' },
      expertise: [String],
      allocation: Number,
      rate: {
        amount: Number,
        currency: String,
        unit: { type: String, enum: ['hour', 'day', 'month'] }
      }
    }]
  },
  
  // Terms and Conditions
  terms: proposalTermsSchema,
  
  // Status and Workflow
  status: {
    type: String,
    required: true,
    enum: [
      'draft', 'internal_review', 'pending_approval', 'approved',
      'sent', 'viewed', 'under_negotiation', 'accepted',
      'rejected', 'expired', 'withdrawn', 'converted'
    ],
    default: 'draft'
  },
  
  workflow: {
    currentStage: {
      type: String,
      enum: ['creation', 'review', 'approval', 'delivery', 'negotiation', 'closing']
    },
    stages: [{
      name: String,
      status: {
        type: String,
        enum: ['pending', 'in_progress', 'completed', 'skipped']
      },
      startedAt: Date,
      completedAt: Date,
      completedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      comments: String
    }]
  },
  
  // Approval Process
  approval: proposalApprovalSchema,
  
  // Documents and Attachments
  documents: [{
    type: {
      type: String,
      enum: ['proposal_doc', 'presentation', 'contract', 'sow', 'reference', 'other'],
      required: true
    },
    name: String,
    description: String,
    url: String,
    publicId: String,
    size: Number,
    mimeType: String,
    uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    uploadedAt: { type: Date, default: Date.now },
    version: String,
    isPublic: { type: Boolean, default: false }
  }],
  
  // Client Interactions
  interactions: {
    sent: {
      date: Date,
      method: { type: String, enum: ['email', 'portal', 'print', 'other'] },
      sentBy: { type: Schema.Types.ObjectId, ref: 'User' },
      recipients: [{
        email: String,
        name: String,
        opened: { type: Boolean, default: false },
        openedAt: Date
      }]
    },
    views: [{
      viewedBy: String, // Email or identifier
      viewedAt: Date,
      duration: Number, // Seconds
      sections: [String], // Sections viewed
      device: String,
      location: {
        ip: String,
        country: String,
        city: String
      }
    }],
    feedback: [{
      from: String,
      date: Date,
      type: { type: String, enum: ['comment', 'question', 'concern', 'approval'] },
      section: String,
      content: String,
      resolved: { type: Boolean, default: false },
      resolvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      resolvedAt: Date
    }]
  },
  
  // Revisions
  revisions: [proposalRevisionSchema],
  
  // Analytics and Tracking
  analytics: proposalAnalyticsSchema,
  
  // Related Entities
  relatedProposals: [{
    proposal: { type: Schema.Types.ObjectId, ref: 'Proposal' },
    relationship: {
      type: String,
      enum: ['parent', 'child', 'alternative', 'renewal', 'extension']
    }
  }],
  
  project: {
    type: Schema.Types.ObjectId,
    ref: 'Project'
  },
  
  contract: {
    type: Schema.Types.ObjectId,
    ref: 'Contract'
  },
  
  // Validity and Expiration
  validity: {
    startDate: {
      type: Date,
      default: Date.now
    },
    endDate: {
      type: Date,
      required: true
    },
    extensionAllowed: {
      type: Boolean,
      default: true
    },
    extensions: [{
      extendedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      extendedAt: Date,
      newEndDate: Date,
      reason: String
    }]
  },
  
  // Tags and Categories
  tags: [{
    type: String,
    trim: true,
    lowercase: true
  }],
  
  customFields: {
    type: Map,
    of: Schema.Types.Mixed
  },
  
  // Metadata
  metadata: {
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    organization: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true
    },
    lastModifiedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    template: {
      type: Schema.Types.ObjectId,
      ref: 'ProposalTemplate'
    },
    source: {
      type: String,
      enum: ['manual', 'template', 'cloned', 'imported', 'api'],
      default: 'manual'
    },
    language: {
      type: String,
      default: 'en'
    },
    internalNotes: String,
    competitorAnalysis: {
      competitors: [String],
      strengths: [String],
      differentiators: [String]
    }
  }
}, {
  timestamps: true,
  collection: 'proposals'
});

// Indexes
proposalSchema.index({ proposalId: 1 });
proposalSchema.index({ slug: 1 });
proposalSchema.index({ 'client.organization': 1 });
proposalSchema.index({ status: 1 });
proposalSchema.index({ type: 1, category: 1 });
proposalSchema.index({ 'metadata.organization': 1 });
proposalSchema.index({ 'metadata.createdBy': 1 });
proposalSchema.index({ createdAt: -1 });
proposalSchema.index({ 'validity.endDate': 1 });
proposalSchema.index({ 'pricing.total': 1 });
proposalSchema.index({ tags: 1 });

// Compound indexes
proposalSchema.index({ status: 1, 'metadata.organization': 1 });
proposalSchema.index({ 'client.organization': 1, status: 1 });
proposalSchema.index({ type: 1, status: 1, createdAt: -1 });

// Text search index
proposalSchema.index({ 
  title: 'text', 
  executiveSummary: 'text',
  'sections.content': 'text'
});

// Virtual fields
proposalSchema.virtual('isExpired').get(function() {
  return this.validity.endDate < new Date();
});

proposalSchema.virtual('daysUntilExpiration').get(function() {
  const days = Math.ceil((this.validity.endDate - new Date()) / (1000 * 60 * 60 * 24));
  return days;
});

proposalSchema.virtual('totalValue').get(function() {
  return this.pricing?.total || 0;
});

proposalSchema.virtual('isActive').get(function() {
  const activeStatuses = ['sent', 'viewed', 'under_negotiation'];
  return activeStatuses.includes(this.status);
});

// Instance methods
proposalSchema.methods.generateProposalId = async function() {
  const timestamp = Date.now().toString(36).toUpperCase();
  const randomStr = Math.random().toString(36).substring(2, 6).toUpperCase();
  this.proposalId = `PRP-${timestamp}${randomStr}`;
  return this.proposalId;
};

proposalSchema.methods.generateSlug = function() {
  const baseSlug = this.title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .substring(0, 50);
  
  const timestamp = Date.now().toString(36);
  this.slug = `${baseSlug}-${timestamp}`;
  return this.slug;
};

proposalSchema.methods.canEdit = function(userId, userRole) {
  // Check if user can edit this proposal
  if (userRole === 'super_admin') return true;
  if (this.status === 'accepted' || this.status === 'rejected') return false;
  if (this.metadata.createdBy.equals(userId)) return true;
  if (this.team.lead && this.team.lead.equals(userId)) return true;
  
  return false;
};

proposalSchema.methods.canView = function(userId, userRole, organizationId) {
  // Check if user can view this proposal
  if (userRole === 'super_admin') return true;
  if (this.metadata.organization.equals(organizationId)) return true;
  if (this.metadata.createdBy.equals(userId)) return true;
  if (this.team.members.some(m => m.user.equals(userId))) return true;
  
  return false;
};

proposalSchema.methods.recordView = async function(viewData) {
  this.interactions.views.push({
    viewedBy: viewData.viewedBy,
    viewedAt: new Date(),
    duration: viewData.duration || 0,
    sections: viewData.sections || [],
    device: viewData.device,
    location: viewData.location
  });
  
  // Update analytics
  this.analytics.views.total += 1;
  this.analytics.views.lastViewedAt = new Date();
  
  if (!this.analytics.views.firstViewedAt) {
    this.analytics.views.firstViewedAt = new Date();
  }
  
  await this.save();
};

proposalSchema.methods.addRevision = async function(revisionData, userId) {
  const revision = {
    version: this.version,
    changes: revisionData.changes,
    changedBy: userId,
    reason: revisionData.reason,
    sections: revisionData.sections || []
  };
  
  this.revisions.push(revision);
  
  // Increment version
  const [major, minor] = this.version.split('.');
  this.version = revisionData.isMajor ? 
    `${parseInt(major) + 1}.0` : 
    `${major}.${parseInt(minor) + 1}`;
  
  await this.save();
  return revision;
};

proposalSchema.methods.updateStatus = async function(newStatus, userId, comment) {
  const oldStatus = this.status;
  this.status = newStatus;
  
  // Add to workflow stages
  this.workflow.stages.push({
    name: `Status: ${oldStatus} → ${newStatus}`,
    status: 'completed',
    completedAt: new Date(),
    completedBy: userId,
    comments: comment
  });
  
  // Update analytics
  if (newStatus === 'sent') {
    this.analytics.sentAt = new Date();
  } else if (newStatus === 'accepted') {
    this.analytics.conversion.convertedAt = new Date();
    this.analytics.conversion.isConverted = true;
    if (this.analytics.sentAt) {
      this.analytics.conversion.daysToConvert = 
        Math.ceil((new Date() - this.analytics.sentAt) / (1000 * 60 * 60 * 24));
    }
  }
  
  await this.save();
  return this;
};

// Static methods
proposalSchema.statics.findByOrganization = async function(organizationId, options = {}) {
  const query = { 'metadata.organization': organizationId };
  
  if (options.status) {
    query.status = options.status;
  }
  
  if (options.type) {
    query.type = options.type;
  }
  
  return this.find(query)
    .populate(options.populate || [])
    .sort(options.sort || { createdAt: -1 })
    .limit(options.limit || 50)
    .skip(options.skip || 0);
};

proposalSchema.statics.getExpiringProposals = async function(days = 7) {
  const futureDate = new Date();
  futureDate.setDate(futureDate.getDate() + days);
  
  return this.find({
    'validity.endDate': {
      $gte: new Date(),
      $lte: futureDate
    },
    status: { $in: ['sent', 'viewed', 'under_negotiation'] }
  });
};

proposalSchema.statics.getConversionMetrics = async function(organizationId, dateRange) {
  const match = {
    'metadata.organization': organizationId
  };
  
  if (dateRange) {
    match.createdAt = {
      $gte: dateRange.start,
      $lte: dateRange.end
    };
  }
  
  return this.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        sent: {
          $sum: { $cond: [{ $in: ['$status', ['sent', 'viewed', 'under_negotiation', 'accepted', 'rejected']] }, 1, 0] }
        },
        accepted: {
          $sum: { $cond: [{ $eq: ['$status', 'accepted'] }, 1, 0] }
        },
        rejected: {
          $sum: { $cond: [{ $eq: ['$status', 'rejected'] }, 1, 0] }
        },
        totalValue: {
          $sum: { $cond: [{ $eq: ['$status', 'accepted'] }, '$pricing.total', 0] }
        },
        avgDaysToConvert: {
          $avg: '$analytics.conversion.daysToConvert'
        }
      }
    },
    {
      $project: {
        _id: 0,
        total: 1,
        sent: 1,
        accepted: 1,
        rejected: 1,
        totalValue: 1,
        conversionRate: {
          $cond: [
            { $gt: ['$sent', 0] },
            { $multiply: [{ $divide: ['$accepted', '$sent'] }, 100] },
            0
          ]
        },
        avgDaysToConvert: { $round: ['$avgDaysToConvert', 1] }
      }
    }
  ]);
};

// Pre-save middleware
proposalSchema.pre('save', async function(next) {
  // Generate proposal ID if not exists
  if (this.isNew && !this.proposalId) {
    await this.generateProposalId();
  }
  
  // Generate slug if not exists
  if (this.isNew && !this.slug) {
    this.generateSlug();
  }
  
  // Update pricing calculations
  if (this.isModified('pricing.items')) {
    this.pricing.subtotal = this.pricing.items.reduce((sum, item) => sum + item.total, 0);
    this.pricing.taxAmount = this.pricing.subtotal * (this.pricing.taxRate / 100);
    this.pricing.total = this.pricing.subtotal + this.pricing.taxAmount - (this.pricing.discount || 0);
  }
  
  // Update last modified
  this.metadata.lastModifiedAt = new Date();
  
  next();
});

// Create and export model
const Proposal = mongoose.model('Proposal', proposalSchema);

module.exports = Proposal;