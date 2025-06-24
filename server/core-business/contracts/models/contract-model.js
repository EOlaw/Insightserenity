// server/core-business/contracts/models/contract-model.js
/**
 * @file Contract Model
 * @description Mongoose model for comprehensive contract management
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

/**
 * Payment Schedule Schema
 */
const paymentScheduleSchema = new Schema({
  milestoneId: {
    type: Schema.Types.ObjectId,
    ref: 'ContractMilestone'
  },
  amount: {
    type: Number,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    required: true,
    uppercase: true,
    default: 'USD'
  },
  dueDate: {
    type: Date,
    required: true
  },
  invoiceDate: Date,
  paymentTerms: {
    type: String,
    enum: ['net_15', 'net_30', 'net_45', 'net_60', 'net_90', 'immediate', 'custom'],
    default: 'net_30'
  },
  status: {
    type: String,
    enum: ['pending', 'invoiced', 'paid', 'overdue', 'cancelled'],
    default: 'pending'
  },
  invoiceNumber: String,
  paymentDate: Date,
  paymentReference: String,
  notes: String
}, {
  _id: true,
  timestamps: true
});

/**
 * Contract Milestone Schema
 */
const milestoneSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: String,
  type: {
    type: String,
    enum: ['deliverable', 'phase', 'payment', 'review', 'approval'],
    default: 'deliverable'
  },
  dueDate: {
    type: Date,
    required: true
  },
  completedDate: Date,
  status: {
    type: String,
    enum: ['not_started', 'in_progress', 'completed', 'approved', 'rejected', 'cancelled'],
    default: 'not_started'
  },
  deliverables: [{
    name: String,
    description: String,
    status: {
      type: String,
      enum: ['pending', 'submitted', 'approved', 'rejected'],
      default: 'pending'
    },
    submittedDate: Date,
    approvedDate: Date,
    approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    attachments: [{
      fileName: String,
      fileUrl: String,
      fileSize: Number,
      uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      uploadedAt: { type: Date, default: Date.now }
    }]
  }],
  dependencies: [{
    type: Schema.Types.ObjectId,
    ref: 'ContractMilestone'
  }],
  assignedTo: [{
    type: Schema.Types.ObjectId,
    ref: 'User'
  }],
  approvers: [{
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    approvedAt: Date,
    comments: String,
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending'
    }
  }]
}, {
  _id: true,
  timestamps: true
});

/**
 * Amendment Schema
 */
const amendmentSchema = new Schema({
  amendmentNumber: {
    type: String,
    required: true
  },
  effectiveDate: {
    type: Date,
    required: true
  },
  type: {
    type: String,
    enum: ['scope_change', 'timeline_extension', 'budget_increase', 'terms_modification', 'other'],
    required: true
  },
  description: {
    type: String,
    required: true
  },
  changes: {
    scope: String,
    timeline: {
      originalEndDate: Date,
      newEndDate: Date
    },
    budget: {
      originalAmount: Number,
      additionalAmount: Number,
      newTotalAmount: Number
    },
    terms: [String]
  },
  justification: String,
  requestedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  approvalStatus: {
    type: String,
    enum: ['draft', 'pending_approval', 'approved', 'rejected'],
    default: 'draft'
  },
  approvers: [{
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    role: String,
    approvedAt: Date,
    comments: String,
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending'
    }
  }],
  attachments: [{
    fileName: String,
    fileUrl: String,
    fileType: String,
    uploadedAt: { type: Date, default: Date.now }
  }]
}, {
  _id: true,
  timestamps: true
});

/**
 * Contract Schema
 */
const contractSchema = new Schema({
  // Basic Information
  contractNumber: {
    type: String,
    unique: true,
    required: true,
    uppercase: true,
    index: true
  },
  title: {
    type: String,
    required: [true, 'Contract title is required'],
    trim: true,
    maxlength: [200, 'Contract title cannot exceed 200 characters']
  },
  description: {
    type: String,
    maxlength: [2000, 'Description cannot exceed 2000 characters']
  },
  type: {
    type: String,
    enum: ['sales', 'purchase', 'service', 'employment', 'nda', 'partnership', 'license', 'maintenance', 'subscription', 'other'],
    required: true,
    index: true
  },
  category: {
    type: String,
    enum: ['fixed_price', 'time_and_materials', 'retainer', 'milestone_based', 'subscription', 'revenue_share'],
    required: true
  },
  
  // Parties
  parties: {
    primaryParty: {
      type: {
        type: String,
        enum: ['organization', 'client', 'vendor', 'partner'],
        required: true
      },
      entityId: {
        type: Schema.Types.ObjectId,
        refPath: 'parties.primaryParty.entityType',
        required: true
      },
      entityType: {
        type: String,
        enum: ['Organization', 'Client', 'Vendor', 'Partner'],
        required: true
      },
      signatory: {
        name: String,
        title: String,
        email: String,
        phone: String
      }
    },
    counterparty: {
      type: {
        type: String,
        enum: ['client', 'vendor', 'partner', 'employee', 'contractor'],
        required: true
      },
      entityId: {
        type: Schema.Types.ObjectId,
        refPath: 'parties.counterparty.entityType'
      },
      entityType: {
        type: String,
        enum: ['Client', 'Vendor', 'Partner', 'User']
      },
      name: String, // For external parties not in system
      signatory: {
        name: String,
        title: String,
        email: String,
        phone: String
      }
    },
    thirdParties: [{
      name: String,
      role: String,
      contact: {
        name: String,
        email: String,
        phone: String
      }
    }]
  },
  
  // Contract Value and Financial Terms
  financials: {
    totalValue: {
      type: Number,
      required: true,
      min: 0
    },
    currency: {
      type: String,
      required: true,
      uppercase: true,
      default: 'USD'
    },
    paymentSchedule: [paymentScheduleSchema],
    billingFrequency: {
      type: String,
      enum: ['one_time', 'monthly', 'quarterly', 'semi_annual', 'annual', 'milestone_based', 'custom']
    },
    discounts: [{
      type: {
        type: String,
        enum: ['percentage', 'fixed_amount', 'volume_based']
      },
      value: Number,
      description: String,
      conditions: String
    }],
    penalties: {
      lateDelivery: {
        type: Number,
        unit: {
          type: String,
          enum: ['percentage_per_day', 'fixed_per_day', 'percentage_total']
        }
      },
      earlyTermination: {
        type: Number,
        conditions: String
      }
    },
    retentionPercentage: Number,
    taxInclusive: {
      type: Boolean,
      default: false
    }
  },
  
  // Timeline
  timeline: {
    startDate: {
      type: Date,
      required: true
    },
    endDate: {
      type: Date,
      required: true
    },
    executionDate: Date,
    effectiveDate: Date,
    noticePeriod: {
      value: Number,
      unit: {
        type: String,
        enum: ['days', 'weeks', 'months'],
        default: 'days'
      }
    },
    renewalTerms: {
      autoRenew: {
        type: Boolean,
        default: false
      },
      renewalPeriod: {
        value: Number,
        unit: {
          type: String,
          enum: ['months', 'years']
        }
      },
      renewalNoticePeriod: {
        value: Number,
        unit: {
          type: String,
          enum: ['days', 'weeks', 'months'],
          default: 'days'
        }
      },
      maxRenewals: Number
    }
  },
  
  // Milestones and Deliverables
  milestones: [milestoneSchema],
  
  // Terms and Conditions
  terms: {
    paymentTerms: String,
    deliveryTerms: String,
    warrantyPeriod: {
      value: Number,
      unit: {
        type: String,
        enum: ['days', 'months', 'years']
      }
    },
    liabilityLimitation: String,
    intellectualProperty: {
      ownership: {
        type: String,
        enum: ['client', 'vendor', 'shared', 'work_for_hire']
      },
      licenses: [String]
    },
    confidentiality: {
      period: {
        value: Number,
        unit: {
          type: String,
          enum: ['months', 'years', 'perpetual']
        }
      },
      exceptions: [String]
    },
    governingLaw: String,
    disputeResolution: {
      type: String,
      enum: ['negotiation', 'mediation', 'arbitration', 'litigation'],
      location: String
    },
    forceMAjeure: Boolean,
    customTerms: [{
      clause: String,
      description: String
    }]
  },
  
  // Risk and Compliance
  riskAssessment: {
    level: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'low'
    },
    factors: [{
      category: {
        type: String,
        enum: ['financial', 'operational', 'legal', 'reputational', 'strategic']
      },
      description: String,
      impact: {
        type: String,
        enum: ['low', 'medium', 'high']
      },
      probability: {
        type: String,
        enum: ['low', 'medium', 'high']
      },
      mitigation: String
    }],
    lastAssessedDate: Date,
    assessedBy: { type: Schema.Types.ObjectId, ref: 'User' }
  },
  
  compliance: {
    regulatoryRequirements: [{
      regulation: String,
      requirements: [String],
      status: {
        type: String,
        enum: ['compliant', 'non_compliant', 'in_progress', 'not_applicable'],
        default: 'in_progress'
      }
    }],
    certifications: [{
      name: String,
      required: Boolean,
      obtained: Boolean,
      expiryDate: Date
    }],
    auditTrail: [{
      action: String,
      performedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      performedAt: { type: Date, default: Date.now },
      details: String
    }]
  },
  
  // Workflow and Approvals
  workflow: {
    currentStage: {
      type: String,
      enum: ['draft', 'internal_review', 'legal_review', 'negotiation', 'pending_approval', 'approved', 'executed', 'active', 'expired', 'terminated', 'renewed'],
      default: 'draft',
      index: true
    },
    stages: [{
      stage: String,
      status: {
        type: String,
        enum: ['pending', 'in_progress', 'completed', 'skipped'],
        default: 'pending'
      },
      startedAt: Date,
      completedAt: Date,
      completedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      comments: String
    }],
    approvalChain: [{
      role: {
        type: String,
        enum: ['legal', 'finance', 'operations', 'executive', 'department_head', 'project_manager'],
        required: true
      },
      approver: { type: Schema.Types.ObjectId, ref: 'User' },
      status: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'conditionally_approved'],
        default: 'pending'
      },
      approvedAt: Date,
      comments: String,
      conditions: [String]
    }],
    currentApprover: { type: Schema.Types.ObjectId, ref: 'User' },
    escalationPath: [{
      level: Number,
      approver: { type: Schema.Types.ObjectId, ref: 'User' },
      escalateAfterDays: Number
    }]
  },
  
  // Documents and Attachments
  documents: {
    mainContract: {
      fileName: String,
      fileUrl: String,
      version: String,
      uploadedAt: Date,
      uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' }
    },
    attachments: [{
      type: {
        type: String,
        enum: ['sow', 'purchase_order', 'invoice', 'amendment', 'correspondence', 'supporting_doc', 'other']
      },
      fileName: String,
      fileUrl: String,
      fileSize: Number,
      description: String,
      uploadedAt: { type: Date, default: Date.now },
      uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' }
    }],
    versions: [{
      versionNumber: String,
      fileName: String,
      fileUrl: String,
      changes: String,
      uploadedAt: { type: Date, default: Date.now },
      uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' }
    }]
  },
  
  // Amendments and Change Orders
  amendments: [amendmentSchema],
  
  // Relationships
  relationships: {
    parentContract: { type: Schema.Types.ObjectId, ref: 'Contract' },
    childContracts: [{ type: Schema.Types.ObjectId, ref: 'Contract' }],
    relatedProjects: [{ type: Schema.Types.ObjectId, ref: 'Project' }],
    relatedPurchaseOrders: [{
      poNumber: String,
      amount: Number,
      date: Date
    }]
  },
  
  // Performance and Metrics
  performance: {
    slaMetrics: [{
      metric: String,
      target: String,
      unit: String,
      measurementFrequency: {
        type: String,
        enum: ['daily', 'weekly', 'monthly', 'quarterly']
      },
      currentValue: Schema.Types.Mixed,
      status: {
        type: String,
        enum: ['meeting', 'at_risk', 'breached'],
        default: 'meeting'
      }
    }],
    kpis: [{
      name: String,
      target: Number,
      actual: Number,
      unit: String,
      lastMeasured: Date
    }],
    satisfactionScore: {
      type: Number,
      min: 0,
      max: 100
    },
    deliveryPerformance: {
      onTimeDelivery: Number,
      qualityScore: Number,
      defectRate: Number
    }
  },
  
  // Notifications and Alerts
  notifications: {
    renewalAlert: {
      enabled: { type: Boolean, default: true },
      daysBefore: { type: Number, default: 90 },
      recipients: [{ type: Schema.Types.ObjectId, ref: 'User' }]
    },
    expiryAlert: {
      enabled: { type: Boolean, default: true },
      daysBefore: { type: Number, default: 30 },
      recipients: [{ type: Schema.Types.ObjectId, ref: 'User' }]
    },
    milestoneAlert: {
      enabled: { type: Boolean, default: true },
      daysBefore: { type: Number, default: 7 },
      recipients: [{ type: Schema.Types.ObjectId, ref: 'User' }]
    },
    paymentAlert: {
      enabled: { type: Boolean, default: true },
      daysBefore: { type: Number, default: 7 },
      recipients: [{ type: Schema.Types.ObjectId, ref: 'User' }]
    }
  },
  
  // Access Control
  access: {
    owner: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    managers: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }],
    viewers: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }],
    department: {
      type: Schema.Types.ObjectId,
      ref: 'Department'
    },
    visibility: {
      type: String,
      enum: ['private', 'department', 'organization', 'public'],
      default: 'department'
    }
  },
  
  // Status and Metadata
  status: {
    isActive: {
      type: Boolean,
      default: true
    },
    terminationReason: String,
    terminationDate: Date,
    terminatedBy: { type: Schema.Types.ObjectId, ref: 'User' }
  },
  
  metadata: {
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    updatedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    lastReviewDate: Date,
    nextReviewDate: Date,
    tags: [{
      type: String,
      trim: true,
      lowercase: true
    }],
    customFields: Schema.Types.Mixed,
    notes: [{
      content: String,
      author: { type: Schema.Types.ObjectId, ref: 'User' },
      createdAt: { type: Date, default: Date.now },
      visibility: {
        type: String,
        enum: ['private', 'team', 'all'],
        default: 'team'
      }
    }]
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Indexes
 */
contractSchema.index({ contractNumber: 1 }, { unique: true });
contractSchema.index({ 'workflow.currentStage': 1, 'timeline.endDate': 1 });
contractSchema.index({ 'parties.primaryParty.entityId': 1 });
contractSchema.index({ 'parties.counterparty.entityId': 1 });
contractSchema.index({ type: 1, category: 1 });
contractSchema.index({ 'timeline.startDate': 1, 'timeline.endDate': 1 });
contractSchema.index({ 'access.owner': 1 });
contractSchema.index({ 'metadata.tags': 1 });
contractSchema.index({ title: 'text', description: 'text' });

/**
 * Virtual Fields
 */
contractSchema.virtual('daysToExpiry').get(function() {
  if (!this.timeline.endDate) return null;
  const today = new Date();
  const diffTime = this.timeline.endDate - today;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return diffDays;
});

contractSchema.virtual('isExpired').get(function() {
  return this.timeline.endDate < new Date() && this.workflow.currentStage !== 'renewed';
});

contractSchema.virtual('totalPaidAmount').get(function() {
  return this.financials.paymentSchedule
    .filter(p => p.status === 'paid')
    .reduce((sum, p) => sum + p.amount, 0);
});

contractSchema.virtual('outstandingAmount').get(function() {
  return this.financials.totalValue - this.totalPaidAmount;
});

contractSchema.virtual('completionPercentage').get(function() {
  if (!this.milestones || this.milestones.length === 0) return 0;
  const completed = this.milestones.filter(m => m.status === 'completed').length;
  return Math.round((completed / this.milestones.length) * 100);
});

/**
 * Pre-save Middleware
 */
contractSchema.pre('save', async function(next) {
  try {
    // Generate contract number if not provided
    if (!this.contractNumber && this.isNew) {
      this.contractNumber = await this.generateContractNumber();
    }
    
    // Update payment schedule status
    if (this.financials.paymentSchedule) {
      const today = new Date();
      this.financials.paymentSchedule.forEach(payment => {
        if (payment.status === 'pending' && payment.dueDate < today) {
          payment.status = 'overdue';
        }
      });
    }
    
    // Auto-update workflow stage based on dates
    if (this.timeline.endDate < new Date() && this.workflow.currentStage === 'active') {
      this.workflow.currentStage = 'expired';
    }
    
    // Set next review date if not set
    if (!this.metadata.nextReviewDate && this.workflow.currentStage === 'active') {
      const reviewDate = new Date();
      reviewDate.setMonth(reviewDate.getMonth() + 3); // Review every 3 months
      this.metadata.nextReviewDate = reviewDate;
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Methods
 */

/**
 * Generate unique contract number
 */
contractSchema.methods.generateContractNumber = async function() {
  const year = new Date().getFullYear();
  const typePrefix = this.type.substring(0, 3).toUpperCase();
  
  // Find the last contract of this type this year
  const lastContract = await this.constructor
    .findOne({
      contractNumber: new RegExp(`^${typePrefix}-${year}-`),
    })
    .sort({ contractNumber: -1 });
  
  let sequence = 1;
  if (lastContract) {
    const lastNumber = parseInt(lastContract.contractNumber.split('-')[2]);
    sequence = lastNumber + 1;
  }
  
  return `${typePrefix}-${year}-${sequence.toString().padStart(4, '0')}`;
};

/**
 * Add milestone
 */
contractSchema.methods.addMilestone = function(milestoneData) {
  this.milestones.push({
    ...milestoneData,
    status: 'not_started'
  });
  
  logger.info('Contract milestone added', {
    contractId: this._id,
    contractNumber: this.contractNumber,
    milestoneName: milestoneData.name
  });
  
  return this.milestones[this.milestones.length - 1];
};

/**
 * Update milestone status
 */
contractSchema.methods.updateMilestoneStatus = function(milestoneId, status, userId) {
  const milestone = this.milestones.id(milestoneId);
  if (!milestone) {
    throw new AppError('Milestone not found', 404);
  }
  
  milestone.status = status;
  if (status === 'completed') {
    milestone.completedDate = new Date();
  }
  
  logger.info('Contract milestone updated', {
    contractId: this._id,
    milestoneId,
    newStatus: status,
    updatedBy: userId
  });
  
  return milestone;
};

/**
 * Add amendment
 */
contractSchema.methods.addAmendment = function(amendmentData, userId) {
  const amendmentNumber = `AMD-${this.contractNumber}-${this.amendments.length + 1}`;
  
  const amendment = {
    ...amendmentData,
    amendmentNumber,
    requestedBy: userId
  };
  
  this.amendments.push(amendment);
  
  logger.info('Contract amendment added', {
    contractId: this._id,
    contractNumber: this.contractNumber,
    amendmentNumber
  });
  
  return this.amendments[this.amendments.length - 1];
};

/**
 * Check if user has access
 */
contractSchema.methods.canUserAccess = function(userId, action = 'view') {
  const userIdStr = userId.toString();
  
  // Owner has full access
  if (this.access.owner.toString() === userIdStr) return true;
  
  // Check managers for edit access
  if (action === 'edit' || action === 'manage') {
    return this.access.managers.some(m => m.toString() === userIdStr);
  }
  
  // Check viewers for view access
  if (action === 'view') {
    return this.access.viewers.some(v => v.toString() === userIdStr) ||
           this.access.managers.some(m => m.toString() === userIdStr);
  }
  
  return false;
};

/**
 * Calculate risk score
 */
contractSchema.methods.calculateRiskScore = function() {
  let riskScore = 0;
  let factorCount = 0;
  
  const impactWeights = { low: 1, medium: 2, high: 3 };
  const probabilityWeights = { low: 1, medium: 2, high: 3 };
  
  this.riskAssessment.factors.forEach(factor => {
    const impact = impactWeights[factor.impact] || 1;
    const probability = probabilityWeights[factor.probability] || 1;
    riskScore += (impact * probability);
    factorCount++;
  });
  
  // Additional risk factors
  if (this.isExpired) riskScore += 5;
  if (this.daysToExpiry && this.daysToExpiry < 30) riskScore += 3;
  if (this.financials.totalValue > 1000000) riskScore += 2;
  if (this.compliance.regulatoryRequirements.some(r => r.status === 'non_compliant')) riskScore += 5;
  
  // Calculate risk level
  const avgScore = factorCount > 0 ? riskScore / factorCount : riskScore;
  
  if (avgScore <= 3) this.riskAssessment.level = 'low';
  else if (avgScore <= 6) this.riskAssessment.level = 'medium';
  else if (avgScore <= 9) this.riskAssessment.level = 'high';
  else this.riskAssessment.level = 'critical';
  
  this.riskAssessment.lastAssessedDate = new Date();
  
  return this.riskAssessment.level;
};

/**
 * Get contract summary
 */
contractSchema.methods.getSummary = function() {
  return {
    id: this._id,
    contractNumber: this.contractNumber,
    title: this.title,
    type: this.type,
    value: this.financials.totalValue,
    currency: this.financials.currency,
    counterparty: this.parties.counterparty.name || 'Unknown',
    status: this.workflow.currentStage,
    startDate: this.timeline.startDate,
    endDate: this.timeline.endDate,
    daysToExpiry: this.daysToExpiry,
    completionPercentage: this.completionPercentage,
    riskLevel: this.riskAssessment.level
  };
};

/**
 * Check if contract should renew
 */
contractSchema.methods.shouldAutoRenew = function() {
  if (!this.timeline.renewalTerms.autoRenew) return false;
  if (this.workflow.currentStage !== 'active') return false;
  if (!this.daysToExpiry) return false;
  
  const noticePeriodDays = this.timeline.renewalTerms.renewalNoticePeriod.value || 30;
  return this.daysToExpiry <= noticePeriodDays;
};

/**
 * Process renewal
 */
contractSchema.methods.processRenewal = async function(userId) {
  if (!this.shouldAutoRenew()) {
    throw new AppError('Contract is not eligible for auto-renewal', 400);
  }
  
  // Check max renewals
  const currentRenewals = this.amendments.filter(a => a.type === 'timeline_extension').length;
  if (this.timeline.renewalTerms.maxRenewals && currentRenewals >= this.timeline.renewalTerms.maxRenewals) {
    throw new AppError('Maximum number of renewals reached', 400);
  }
  
  // Calculate new dates
  const newStartDate = new Date(this.timeline.endDate);
  newStartDate.setDate(newStartDate.getDate() + 1);
  
  const renewalPeriod = this.timeline.renewalTerms.renewalPeriod;
  const newEndDate = new Date(newStartDate);
  
  if (renewalPeriod.unit === 'months') {
    newEndDate.setMonth(newEndDate.getMonth() + renewalPeriod.value);
  } else if (renewalPeriod.unit === 'years') {
    newEndDate.setFullYear(newEndDate.getFullYear() + renewalPeriod.value);
  }
  
  // Create renewal amendment
  const renewalAmendment = {
    type: 'timeline_extension',
    effectiveDate: newStartDate,
    description: `Automatic renewal for ${renewalPeriod.value} ${renewalPeriod.unit}`,
    changes: {
      timeline: {
        originalEndDate: this.timeline.endDate,
        newEndDate: newEndDate
      }
    },
    requestedBy: userId,
    approvalStatus: 'approved'
  };
  
  this.addAmendment(renewalAmendment, userId);
  
  // Update contract dates
  this.timeline.startDate = newStartDate;
  this.timeline.endDate = newEndDate;
  this.workflow.currentStage = 'renewed';
  
  logger.info('Contract renewed', {
    contractId: this._id,
    contractNumber: this.contractNumber,
    newEndDate,
    renewedBy: userId
  });
  
  return this;
};

/**
 * Static Methods
 */

/**
 * Find expiring contracts
 */
contractSchema.statics.findExpiringContracts = async function(daysAhead = 90) {
  const futureDate = new Date();
  futureDate.setDate(futureDate.getDate() + daysAhead);
  
  return this.find({
    'timeline.endDate': {
      $gte: new Date(),
      $lte: futureDate
    },
    'workflow.currentStage': { $in: ['active', 'executed'] },
    'status.isActive': true
  }).populate('access.owner access.managers', 'firstName lastName email');
};

/**
 * Find contracts by party
 */
contractSchema.statics.findByParty = async function(partyId, partyType = 'any') {
  const query = {
    $or: []
  };
  
  if (partyType === 'any' || partyType === 'primary') {
    query.$or.push({ 'parties.primaryParty.entityId': partyId });
  }
  
  if (partyType === 'any' || partyType === 'counter') {
    query.$or.push({ 'parties.counterparty.entityId': partyId });
  }
  
  return this.find(query)
    .populate('access.owner', 'firstName lastName')
    .sort({ createdAt: -1 });
};

/**
 * Get contract statistics
 */
contractSchema.statics.getStatistics = async function(filter = {}) {
  const stats = await this.aggregate([
    { $match: { ...filter, 'status.isActive': true } },
    {
      $group: {
        _id: null,
        totalContracts: { $sum: 1 },
        totalValue: { $sum: '$financials.totalValue' },
        avgValue: { $avg: '$financials.totalValue' },
        byType: { $push: '$type' },
        byStage: { $push: '$workflow.currentStage' },
        expiringSoon: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $lte: ['$timeline.endDate', new Date(Date.now() + 90 * 24 * 60 * 60 * 1000)] },
                  { $gte: ['$timeline.endDate', new Date()] }
                ]
              },
              1,
              0
            ]
          }
        },
        highRisk: {
          $sum: {
            $cond: [
              { $in: ['$riskAssessment.level', ['high', 'critical']] },
              1,
              0
            ]
          }
        }
      }
    },
    {
      $project: {
        _id: 0,
        totalContracts: 1,
        totalValue: { $round: ['$totalValue', 2] },
        avgValue: { $round: ['$avgValue', 2] },
        expiringSoon: 1,
        highRisk: 1,
        typeDistribution: {
          $arrayToObject: {
            $map: {
              input: { $setUnion: ['$byType', []] },
              as: 'type',
              in: {
                k: '$$type',
                v: {
                  $size: {
                    $filter: {
                      input: '$byType',
                      cond: { $eq: ['$$this', '$$type'] }
                    }
                  }
                }
              }
            }
          }
        },
        stageDistribution: {
          $arrayToObject: {
            $map: {
              input: { $setUnion: ['$byStage', []] },
              as: 'stage',
              in: {
                k: '$$stage',
                v: {
                  $size: {
                    $filter: {
                      input: '$byStage',
                      cond: { $eq: ['$$this', '$$stage'] }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  ]);
  
  return stats[0] || {
    totalContracts: 0,
    totalValue: 0,
    avgValue: 0,
    expiringSoon: 0,
    highRisk: 0,
    typeDistribution: {},
    stageDistribution: {}
  };
};

const Contract = mongoose.model('Contract', contractSchema);

module.exports = Contract;