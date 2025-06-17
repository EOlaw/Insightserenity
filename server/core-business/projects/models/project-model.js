/**
 * @file Project Model - Advanced
 * @description Comprehensive model for managing consulting projects with advanced features
 * @version 2.0.0
 */

const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
const Schema = mongoose.Schema;

/**
 * Team Member Sub-schema
 */
const teamMemberSchema = new Schema({
  consultant: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  role: {
    type: String,
    required: true,
    enum: ['project_manager', 'lead_consultant', 'senior_consultant', 'consultant', 'analyst', 'specialist', 'advisor']
  },
  allocation: {
    percentage: { type: Number, min: 0, max: 100, required: true },
    hoursPerWeek: { type: Number, min: 0, max: 60 },
    startDate: { type: Date, required: true },
    endDate: Date
  },
  billable: { type: Boolean, default: true },
  hourlyRate: {
    amount: { type: Number, min: 0 },
    currency: { type: String, default: 'USD' }
  },
  responsibilities: [String],
  skills: [String],
  approvalStatus: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  approvedAt: Date,
  performance: {
    rating: { type: Number, min: 1, max: 5 },
    feedback: String,
    lastReviewDate: Date
  }
}, { _id: true, timestamps: true });

/**
 * Milestone Sub-schema
 */
const milestoneSchema = new Schema({
  name: { type: String, required: true },
  description: String,
  type: {
    type: String,
    enum: ['deliverable', 'payment', 'review', 'approval', 'phase_completion'],
    required: true
  },
  phase: String,
  plannedDate: { type: Date, required: true },
  actualDate: Date,
  status: {
    type: String,
    enum: ['pending', 'in_progress', 'completed', 'delayed', 'cancelled'],
    default: 'pending'
  },
  completion: { type: Number, min: 0, max: 100, default: 0 },
  dependencies: [{
    milestone: { type: Schema.Types.ObjectId },
    type: { type: String, enum: ['finish_to_start', 'start_to_start', 'finish_to_finish', 'start_to_finish'] }
  }],
  deliverables: [{
    name: String,
    description: String,
    status: { type: String, enum: ['pending', 'in_progress', 'submitted', 'approved', 'rejected'] },
    submittedAt: Date,
    approvedAt: Date,
    documents: [{ type: Schema.Types.ObjectId, ref: 'Document' }]
  }],
  payment: {
    amount: Number,
    currency: { type: String, default: 'USD' },
    invoiced: { type: Boolean, default: false },
    invoiceId: { type: Schema.Types.ObjectId, ref: 'Invoice' }
  },
  assignedTo: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  blockers: [{
    description: String,
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
    resolvedAt: Date
  }],
  comments: [{
    author: { type: Schema.Types.ObjectId, ref: 'User' },
    content: String,
    createdAt: { type: Date, default: Date.now }
  }]
}, { _id: true, timestamps: true });

/**
 * Budget Item Sub-schema
 */
const budgetItemSchema = new Schema({
  category: {
    type: String,
    required: true,
    enum: ['labor', 'travel', 'materials', 'subcontractor', 'software', 'equipment', 'other']
  },
  name: { type: String, required: true },
  description: String,
  plannedAmount: { type: Number, required: true, min: 0 },
  actualAmount: { type: Number, default: 0, min: 0 },
  unit: { type: String, enum: ['hours', 'days', 'units', 'fixed'] },
  quantity: Number,
  rate: Number,
  approved: { type: Boolean, default: false },
  approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  approvedAt: Date,
  notes: String
}, { _id: true });

/**
 * Risk Sub-schema
 */
const riskSchema = new Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  category: {
    type: String,
    enum: ['technical', 'financial', 'operational', 'strategic', 'compliance', 'reputational'],
    required: true
  },
  probability: {
    type: String,
    enum: ['very_low', 'low', 'medium', 'high', 'very_high'],
    required: true
  },
  impact: {
    type: String,
    enum: ['negligible', 'minor', 'moderate', 'major', 'severe'],
    required: true
  },
  status: {
    type: String,
    enum: ['identified', 'analyzing', 'mitigating', 'monitoring', 'closed'],
    default: 'identified'
  },
  mitigation: {
    strategy: String,
    actions: [{
      description: String,
      assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
      dueDate: Date,
      status: { type: String, enum: ['pending', 'in_progress', 'completed'] }
    }],
    contingencyPlan: String
  },
  identifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  identifiedAt: { type: Date, default: Date.now },
  reviewedAt: Date,
  closedAt: Date,
  riskScore: Number // Calculated from probability × impact
}, { _id: true, timestamps: true });

/**
 * Change Request Sub-schema
 */
const changeRequestSchema = new Schema({
  requestNumber: { type: String, unique: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  type: {
    type: String,
    enum: ['scope', 'timeline', 'budget', 'resource', 'technical', 'other'],
    required: true
  },
  impact: {
    scope: String,
    timeline: {
      days: Number,
      description: String
    },
    budget: {
      amount: Number,
      currency: { type: String, default: 'USD' },
      description: String
    },
    resources: String,
    risks: [String]
  },
  justification: { type: String, required: true },
  requestedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  requestedAt: { type: Date, default: Date.now },
  status: {
    type: String,
    enum: ['draft', 'submitted', 'under_review', 'approved', 'rejected', 'implemented'],
    default: 'draft'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  reviewers: [{
    reviewer: { type: Schema.Types.ObjectId, ref: 'User' },
    role: String,
    decision: { type: String, enum: ['pending', 'approved', 'rejected', 'needs_info'] },
    comments: String,
    reviewedAt: Date
  }],
  approvalRequired: { type: Boolean, default: true },
  implementationPlan: String,
  implementedAt: Date,
  documents: [{ type: Schema.Types.ObjectId, ref: 'Document' }]
}, { _id: true, timestamps: true });

/**
 * Communication Log Sub-schema
 */
const communicationLogSchema = new Schema({
  type: {
    type: String,
    enum: ['meeting', 'email', 'call', 'presentation', 'report', 'other'],
    required: true
  },
  subject: { type: String, required: true },
  date: { type: Date, required: true },
  duration: Number, // in minutes
  participants: [{
    person: { type: Schema.Types.ObjectId, ref: 'User' },
    external: {
      name: String,
      email: String,
      organization: String,
      role: String
    }
  }],
  summary: String,
  keyDecisions: [String],
  actionItems: [{
    description: String,
    assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
    dueDate: Date,
    status: { type: String, enum: ['pending', 'in_progress', 'completed'], default: 'pending' }
  }],
  attachments: [{
    name: String,
    url: String,
    type: String
  }],
  recordedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  visibility: {
    type: String,
    enum: ['internal', 'client_visible', 'public'],
    default: 'internal'
  }
}, { _id: true, timestamps: true });

/**
 * Project Schema
 * Advanced schema for managing consulting projects
 */
const projectSchema = new Schema({
  // Core Project Information
  projectId: {
    type: String,
    unique: true,
    required: true,
    default: function() {
      return `PRJ-${Date.now()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
    }
  },
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: [3, 'Project name must be at least 3 characters'],
    maxlength: [200, 'Project name cannot exceed 200 characters']
  },
  code: {
    type: String,
    unique: true,
    uppercase: true,
    trim: true,
    match: [/^[A-Z0-9-]{3,20}$/, 'Project code must be 3-20 alphanumeric characters']
  },
  description: {
    brief: {
      type: String,
      required: true,
      maxlength: [500, 'Brief description cannot exceed 500 characters']
    },
    detailed: {
      type: String,
      maxlength: [5000, 'Detailed description cannot exceed 5000 characters']
    },
    objectives: [String],
    scope: String,
    outOfScope: [String],
    assumptions: [String],
    constraints: [String]
  },
  
  // Client and Contract Information
  client: {
    type: Schema.Types.ObjectId,
    ref: 'Client',
    required: true
  },
  clientContact: {
    primary: { type: Schema.Types.ObjectId, ref: 'ClientContact' },
    additional: [{ type: Schema.Types.ObjectId, ref: 'ClientContact' }]
  },
  contract: {
    type: Schema.Types.ObjectId,
    ref: 'Contract'
  },
  proposal: {
    type: Schema.Types.ObjectId,
    ref: 'Proposal'
  },
  
  // Project Classification
  type: {
    type: String,
    required: true,
    enum: ['strategy', 'implementation', 'transformation', 'assessment', 'training', 'support', 'research', 'other']
  },
  category: {
    type: String,
    enum: ['fixed_fee', 'time_and_materials', 'retainer', 'milestone_based', 'hybrid']
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  complexity: {
    type: String,
    enum: ['simple', 'moderate', 'complex', 'highly_complex'],
    default: 'moderate'
  },
  industry: String,
  technologies: [String],
  methodologies: [{
    type: String,
    enum: ['agile', 'waterfall', 'hybrid', 'scrum', 'kanban', 'prince2', 'custom']
  }],
  
  // Timeline and Status
  status: {
    type: String,
    required: true,
    enum: ['draft', 'pending_approval', 'approved', 'active', 'on_hold', 'completed', 'cancelled', 'archived'],
    default: 'draft'
  },
  phase: {
    current: {
      type: String,
      enum: ['initiation', 'planning', 'execution', 'monitoring', 'closure']
    },
    history: [{
      phase: String,
      startDate: Date,
      endDate: Date,
      completedBy: { type: Schema.Types.ObjectId, ref: 'User' }
    }]
  },
  timeline: {
    estimatedStartDate: { type: Date, required: true },
    estimatedEndDate: { type: Date, required: true },
    actualStartDate: Date,
    actualEndDate: Date,
    originalEndDate: Date, // Track if timeline changes
    duration: {
      planned: Number, // in days
      actual: Number
    },
    extensions: [{
      requestDate: Date,
      days: Number,
      reason: String,
      approvedBy: { type: Schema.Types.ObjectId, ref: 'User' }
    }]
  },
  
  // Team and Resources
  team: {
    projectManager: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    sponsor: {
      internal: { type: Schema.Types.ObjectId, ref: 'User' },
      client: String
    },
    members: [teamMemberSchema],
    externalResources: [{
      name: String,
      company: String,
      role: String,
      contactInfo: {
        email: String,
        phone: String
      },
      startDate: Date,
      endDate: Date,
      costPerDay: Number
    }]
  },
  
  // Financial Management
  financial: {
    budget: {
      total: {
        amount: { type: Number, required: true, min: 0 },
        currency: { type: String, default: 'USD' }
      },
      breakdown: [budgetItemSchema],
      contingency: {
        percentage: { type: Number, min: 0, max: 50, default: 10 },
        amount: Number
      },
      approved: { type: Boolean, default: false },
      approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      approvedAt: Date
    },
    costs: {
      labor: { type: Number, default: 0 },
      expenses: { type: Number, default: 0 },
      total: { type: Number, default: 0 }
    },
    revenue: {
      recognized: { type: Number, default: 0 },
      invoiced: { type: Number, default: 0 },
      collected: { type: Number, default: 0 },
      outstanding: { type: Number, default: 0 }
    },
    profitability: {
      margin: Number, // percentage
      marginAmount: Number,
      isUnderBudget: Boolean,
      variancePercentage: Number
    },
    billing: {
      method: {
        type: String,
        enum: ['fixed_fee', 'hourly', 'daily', 'milestone', 'monthly_retainer', 'mixed']
      },
      frequency: {
        type: String,
        enum: ['upon_completion', 'milestone', 'monthly', 'bi_weekly', 'weekly']
      },
      terms: String,
      specialTerms: String
    }
  },
  
  // Project Execution
  milestones: [milestoneSchema],
  deliverables: [{
    name: { type: String, required: true },
    description: String,
    type: {
      type: String,
      enum: ['document', 'presentation', 'software', 'report', 'training', 'workshop', 'other']
    },
    dueDate: Date,
    submittedDate: Date,
    status: {
      type: String,
      enum: ['pending', 'in_progress', 'submitted', 'under_review', 'approved', 'rejected'],
      default: 'pending'
    },
    version: {
      current: { type: Number, default: 1 },
      history: [{
        version: Number,
        uploadedAt: Date,
        uploadedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        changes: String,
        fileUrl: String
      }]
    },
    assignedTo: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    reviewers: [{
      reviewer: { type: Schema.Types.ObjectId, ref: 'User' },
      status: { type: String, enum: ['pending', 'approved', 'rejected'] },
      comments: String,
      reviewedAt: Date
    }],
    acceptanceCriteria: [String],
    dependencies: [{ type: Schema.Types.ObjectId }],
    attachments: [{
      name: String,
      url: String,
      size: Number,
      uploadedAt: Date
    }]
  }],
  
  // Risk and Issue Management
  risks: [riskSchema],
  issues: [{
    title: { type: String, required: true },
    description: { type: String, required: true },
    type: {
      type: String,
      enum: ['bug', 'blocker', 'requirement_change', 'resource', 'technical', 'process'],
      required: true
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      required: true
    },
    status: {
      type: String,
      enum: ['open', 'investigating', 'in_progress', 'resolved', 'closed', 'wont_fix'],
      default: 'open'
    },
    reportedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    reportedAt: { type: Date, default: Date.now },
    assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
    resolution: {
      description: String,
      resolvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      resolvedAt: Date,
      verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      verifiedAt: Date
    },
    impactAnalysis: String,
    workaround: String,
    relatedRisks: [{ type: Schema.Types.ObjectId }],
    attachments: [{
      name: String,
      url: String
    }]
  }],
  
  // Change Management
  changeRequests: [changeRequestSchema],
  changeLog: [{
    date: { type: Date, default: Date.now },
    type: {
      type: String,
      enum: ['scope', 'timeline', 'budget', 'team', 'status', 'other']
    },
    description: String,
    oldValue: Schema.Types.Mixed,
    newValue: Schema.Types.Mixed,
    changedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    impact: String
  }],
  
  // Quality and Performance
  quality: {
    standards: [{
      name: String,
      description: String,
      criteria: [String],
      compliance: { type: Boolean, default: false }
    }],
    reviews: [{
      type: { type: String, enum: ['peer', 'client', 'internal', 'external'] },
      date: Date,
      reviewer: { type: Schema.Types.ObjectId, ref: 'User' },
      score: { type: Number, min: 1, max: 5 },
      comments: String,
      improvements: [String]
    }],
    metrics: {
      deliveryOnTime: { type: Number, min: 0, max: 100 },
      budgetAdherence: { type: Number, min: 0, max: 100 },
      clientSatisfaction: { type: Number, min: 0, max: 100 },
      teamSatisfaction: { type: Number, min: 0, max: 100 },
      qualityScore: { type: Number, min: 0, max: 100 }
    },
    certifications: [{
      name: String,
      body: String,
      obtained: Boolean,
      date: Date
    }]
  },
  
  // Communication and Collaboration
  communication: {
    plan: {
      stakeholderMatrix: [{
        stakeholder: String,
        role: String,
        influence: { type: String, enum: ['low', 'medium', 'high'] },
        interest: { type: String, enum: ['low', 'medium', 'high'] },
        communicationNeeds: String,
        frequency: String
      }],
      channels: [{
        type: { type: String, enum: ['email', 'slack', 'teams', 'meeting', 'report'] },
        purpose: String,
        frequency: String,
        participants: [String]
      }],
      reportingSchedule: [{
        reportType: String,
        frequency: { type: String, enum: ['daily', 'weekly', 'bi_weekly', 'monthly', 'quarterly'] },
        audience: [String],
        owner: { type: Schema.Types.ObjectId, ref: 'User' }
      }]
    },
    logs: [communicationLogSchema],
    clientPortalAccess: {
      enabled: { type: Boolean, default: false },
      url: String,
      permissions: [String]
    }
  },
  
  // Knowledge Management
  knowledge: {
    lessonsLearned: [{
      category: { type: String, enum: ['process', 'technical', 'communication', 'resource', 'other'] },
      description: String,
      impact: { type: String, enum: ['positive', 'negative', 'neutral'] },
      recommendation: String,
      applicableToFutureProjects: { type: Boolean, default: true },
      addedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      addedAt: { type: Date, default: Date.now }
    }],
    bestPractices: [{
      practice: String,
      context: String,
      benefits: String,
      implementation: String
    }],
    templates: [{
      name: String,
      description: String,
      category: String,
      fileUrl: String,
      createdFrom: String
    }],
    documentation: [{
      title: String,
      type: { type: String, enum: ['technical', 'process', 'user', 'training', 'other'] },
      url: String,
      version: String,
      lastUpdated: Date
    }]
  },
  
  // Integration and External Systems
  integrations: {
    jira: {
      enabled: { type: Boolean, default: false },
      projectKey: String,
      boardId: String,
      syncedAt: Date
    },
    slack: {
      enabled: { type: Boolean, default: false },
      channelId: String,
      webhookUrl: String
    },
    microsoftProject: {
      enabled: { type: Boolean, default: false },
      projectId: String,
      lastSync: Date
    },
    customIntegrations: [{
      name: String,
      type: String,
      config: Schema.Types.Mixed,
      active: { type: Boolean, default: true }
    }]
  },
  
  // Compliance and Governance
  compliance: {
    regulatoryRequirements: [{
      regulation: String,
      description: String,
      applicable: { type: Boolean, default: true },
      complianceStatus: { type: String, enum: ['compliant', 'non_compliant', 'in_progress', 'na'] },
      evidence: [String],
      lastAuditDate: Date
    }],
    dataPrivacy: {
      gdprCompliant: { type: Boolean, default: false },
      dataProcessingAgreement: { type: Boolean, default: false },
      privacyImpactAssessment: { type: Boolean, default: false },
      consentObtained: { type: Boolean, default: false }
    },
    security: {
      classificationLevel: { type: String, enum: ['public', 'internal', 'confidential', 'restricted'] },
      ndaSigned: { type: Boolean, default: false },
      securityClearanceRequired: { type: Boolean, default: false },
      accessControls: [{
        control: String,
        implemented: { type: Boolean, default: false },
        verifiedDate: Date
      }]
    },
    audits: [{
      type: { type: String, enum: ['internal', 'external', 'client', 'regulatory'] },
      date: Date,
      auditor: String,
      findings: [String],
      status: { type: String, enum: ['passed', 'failed', 'conditional'] },
      correctiveActions: [{
        action: String,
        dueDate: Date,
        completed: { type: Boolean, default: false }
      }]
    }]
  },
  
  // Metadata and System Fields
  tags: [String],
  customFields: Schema.Types.Mixed,
  visibility: {
    type: String,
    enum: ['private', 'team', 'organization', 'public'],
    default: 'team'
  },
  archived: {
    isArchived: { type: Boolean, default: false },
    archivedAt: Date,
    archivedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    archiveReason: String
  },
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  updatedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  deletedAt: Date,
  version: { type: Number, default: 1 }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Indexes for performance optimization
 */
projectSchema.index({ projectId: 1 });
projectSchema.index({ code: 1 });
projectSchema.index({ client: 1, status: 1 });
projectSchema.index({ 'team.projectManager': 1 });
projectSchema.index({ status: 1, 'timeline.estimatedEndDate': 1 });
projectSchema.index({ 'financial.profitability.margin': -1 });
projectSchema.index({ createdAt: -1 });
projectSchema.index({ 'milestones.plannedDate': 1 });
projectSchema.index({ tags: 1 });

/**
 * Compound indexes for complex queries
 */
projectSchema.index({ 
  status: 1, 
  priority: 1, 
  'timeline.estimatedEndDate': 1 
});

projectSchema.index({ 
  client: 1,
  'financial.revenue.outstanding': -1
});

/**
 * Text search index
 */
projectSchema.index({
  name: 'text',
  'description.brief': 'text',
  'description.detailed': 'text',
  tags: 'text'
});

/**
 * Virtual properties
 */
projectSchema.virtual('duration').get(function() {
  if (this.timeline.actualEndDate && this.timeline.actualStartDate) {
    return Math.ceil((this.timeline.actualEndDate - this.timeline.actualStartDate) / (1000 * 60 * 60 * 24));
  } else if (this.timeline.estimatedEndDate && this.timeline.estimatedStartDate) {
    return Math.ceil((this.timeline.estimatedEndDate - this.timeline.estimatedStartDate) / (1000 * 60 * 60 * 24));
  }
  return 0;
});

projectSchema.virtual('progress').get(function() {
  if (this.milestones.length === 0) return 0;
  
  const completedMilestones = this.milestones.filter(m => m.status === 'completed').length;
  return Math.round((completedMilestones / this.milestones.length) * 100);
});

projectSchema.virtual('budgetUtilization').get(function() {
  if (!this.financial.budget.total.amount) return 0;
  return Math.round((this.financial.costs.total / this.financial.budget.total.amount) * 100);
});

projectSchema.virtual('isOverBudget').get(function() {
  return this.financial.costs.total > this.financial.budget.total.amount;
});

projectSchema.virtual('isDelayed').get(function() {
  const now = new Date();
  return this.status === 'active' && 
         this.timeline.estimatedEndDate < now && 
         !this.timeline.actualEndDate;
});

projectSchema.virtual('healthScore').get(function() {
  let score = 100;
  
  // Budget health (30%)
  const budgetUtil = this.budgetUtilization;
  if (budgetUtil > 100) score -= 30;
  else if (budgetUtil > 90) score -= 15;
  
  // Timeline health (30%)
  if (this.isDelayed) score -= 30;
  else if (this.timeline.extensions.length > 2) score -= 15;
  
  // Risk health (20%)
  const highRisks = this.risks.filter(r => 
    r.status !== 'closed' && 
    (r.probability === 'high' || r.probability === 'very_high')
  ).length;
  if (highRisks > 3) score -= 20;
  else if (highRisks > 1) score -= 10;
  
  // Issue health (20%)
  const criticalIssues = this.issues.filter(i => 
    i.status === 'open' && i.severity === 'critical'
  ).length;
  if (criticalIssues > 0) score -= 20;
  else if (this.issues.filter(i => i.status === 'open').length > 5) score -= 10;
  
  return Math.max(0, score);
});

/**
 * Pre-save middleware
 */
projectSchema.pre('save', async function(next) {
  try {
    // Generate project code if not provided
    if (!this.code && this.name) {
      const nameWords = this.name.split(' ').filter(word => word.length > 2);
      const prefix = nameWords.map(word => word[0]).join('').toUpperCase().substring(0, 3);
      const year = new Date().getFullYear().toString().substring(2);
      const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
      
      let code = `${prefix}${year}${random}`;
      
      // Ensure uniqueness
      while (await this.constructor.findOne({ code })) {
        const newRandom = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        code = `${prefix}${year}${newRandom}`;
      }
      
      this.code = code;
    }
    
    // Calculate financial totals
    if (this.isModified('financial.costs')) {
      this.financial.costs.total = this.financial.costs.labor + this.financial.costs.expenses;
    }
    
    // Update profitability metrics
    if (this.isModified('financial')) {
      const revenue = this.financial.revenue.recognized || 0;
      const costs = this.financial.costs.total || 0;
      
      this.financial.profitability.marginAmount = revenue - costs;
      this.financial.profitability.margin = revenue > 0 
        ? Math.round((this.financial.profitability.marginAmount / revenue) * 100) 
        : 0;
      
      this.financial.profitability.isUnderBudget = costs <= this.financial.budget.total.amount;
      this.financial.profitability.variancePercentage = this.financial.budget.total.amount > 0
        ? Math.round(((costs - this.financial.budget.total.amount) / this.financial.budget.total.amount) * 100)
        : 0;
    }
    
    // Calculate risk scores
    this.risks.forEach(risk => {
      const probabilityMap = { very_low: 1, low: 2, medium: 3, high: 4, very_high: 5 };
      const impactMap = { negligible: 1, minor: 2, moderate: 3, major: 4, severe: 5 };
      
      risk.riskScore = probabilityMap[risk.probability] * impactMap[risk.impact];
    });
    
    // Update timeline actual dates based on status changes
    if (this.isModified('status')) {
      if (this.status === 'active' && !this.timeline.actualStartDate) {
        this.timeline.actualStartDate = new Date();
      } else if (this.status === 'completed' && !this.timeline.actualEndDate) {
        this.timeline.actualEndDate = new Date();
        this.timeline.duration.actual = Math.ceil(
          (this.timeline.actualEndDate - this.timeline.actualStartDate) / (1000 * 60 * 60 * 24)
        );
      }
    }
    
    // Generate change request numbers
    this.changeRequests.forEach(cr => {
      if (!cr.requestNumber) {
        cr.requestNumber = `CR-${this.code}-${Date.now().toString(36).toUpperCase()}`;
      }
    });
    
    // Update version on significant changes
    if (this.isModified('milestones') || this.isModified('financial.budget') || this.isModified('timeline')) {
      this.version += 1;
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Instance methods
 */
projectSchema.methods.addTeamMember = async function(memberData) {
  // Check for conflicts
  const hasConflict = this.team.members.some(member => 
    member.consultant.toString() === memberData.consultant.toString() &&
    member.allocation.startDate <= memberData.allocation.endDate &&
    member.allocation.endDate >= memberData.allocation.startDate
  );
  
  if (hasConflict) {
    throw new Error('Team member has overlapping allocation period');
  }
  
  this.team.members.push(memberData);
  return this.save();
};

projectSchema.methods.updateMilestoneStatus = async function(milestoneId, status) {
  const milestone = this.milestones.id(milestoneId);
  if (!milestone) {
    throw new Error('Milestone not found');
  }
  
  milestone.status = status;
  if (status === 'completed') {
    milestone.actualDate = new Date();
    milestone.completion = 100;
  }
  
  return this.save();
};

projectSchema.methods.calculateResourceUtilization = function() {
  const utilization = {};
  
  this.team.members.forEach(member => {
    const consultantId = member.consultant.toString();
    if (!utilization[consultantId]) {
      utilization[consultantId] = {
        totalHours: 0,
        billableHours: 0,
        allocation: member.allocation.percentage
      };
    }
    
    // Calculate based on allocation and duration
    const weeks = Math.ceil(
      (member.allocation.endDate - member.allocation.startDate) / (1000 * 60 * 60 * 24 * 7)
    );
    const hours = weeks * (member.allocation.hoursPerWeek || 40 * member.allocation.percentage / 100);
    
    utilization[consultantId].totalHours += hours;
    if (member.billable) {
      utilization[consultantId].billableHours += hours;
    }
  });
  
  return utilization;
};

projectSchema.methods.generateStatusReport = function() {
  return {
    projectId: this.projectId,
    name: this.name,
    status: this.status,
    health: this.healthScore,
    progress: this.progress,
    timeline: {
      startDate: this.timeline.actualStartDate || this.timeline.estimatedStartDate,
      endDate: this.timeline.estimatedEndDate,
      daysRemaining: Math.ceil((this.timeline.estimatedEndDate - new Date()) / (1000 * 60 * 60 * 24)),
      isDelayed: this.isDelayed
    },
    budget: {
      total: this.financial.budget.total.amount,
      spent: this.financial.costs.total,
      utilization: this.budgetUtilization,
      isOverBudget: this.isOverBudget
    },
    milestones: {
      total: this.milestones.length,
      completed: this.milestones.filter(m => m.status === 'completed').length,
      upcoming: this.milestones.filter(m => 
        m.status === 'pending' && 
        m.plannedDate <= new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
      ).map(m => ({ name: m.name, date: m.plannedDate }))
    },
    risks: {
      high: this.risks.filter(r => r.status !== 'closed' && r.riskScore >= 12).length,
      medium: this.risks.filter(r => r.status !== 'closed' && r.riskScore >= 6 && r.riskScore < 12).length,
      low: this.risks.filter(r => r.status !== 'closed' && r.riskScore < 6).length
    },
    issues: {
      open: this.issues.filter(i => i.status === 'open').length,
      critical: this.issues.filter(i => i.status === 'open' && i.severity === 'critical').length
    }
  };
};

projectSchema.methods.canBeAccessedBy = function(userId, userRole) {
  // Admin can access all
  if (userRole === 'admin') return true;
  
  // Project manager and creator have access
  if (this.team.projectManager.toString() === userId.toString() ||
      this.createdBy.toString() === userId.toString()) {
    return true;
  }
  
  // Team members have access
  const isTeamMember = this.team.members.some(member => 
    member.consultant.toString() === userId.toString() &&
    member.approvalStatus === 'approved'
  );
  
  return isTeamMember;
};

/**
 * Static methods
 */
projectSchema.statics.findByClient = function(clientId, options = {}) {
  const query = this.find({ client: clientId });
  
  if (options.status) {
    query.where('status', options.status);
  }
  
  if (options.dateRange) {
    query.where('timeline.estimatedStartDate').gte(options.dateRange.start);
    query.where('timeline.estimatedEndDate').lte(options.dateRange.end);
  }
  
  return query.populate('team.projectManager', 'firstName lastName')
              .sort('-createdAt');
};

projectSchema.statics.findActiveProjects = function(filters = {}) {
  const query = { 
    status: 'active',
    'timeline.actualEndDate': { $exists: false }
  };
  
  if (filters.projectManager) {
    query['team.projectManager'] = filters.projectManager;
  }
  
  if (filters.client) {
    query.client = filters.client;
  }
  
  if (filters.priority) {
    query.priority = filters.priority;
  }
  
  return this.find(query)
    .populate('client', 'name code')
    .populate('team.projectManager', 'firstName lastName email')
    .sort({ priority: -1, 'timeline.estimatedEndDate': 1 });
};

projectSchema.statics.getProjectMetrics = async function(dateRange) {
  const pipeline = [
    {
      $match: {
        createdAt: { $gte: dateRange.start, $lte: dateRange.end }
      }
    },
    {
      $group: {
        _id: null,
        totalProjects: { $sum: 1 },
        activeProjects: {
          $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
        },
        completedProjects: {
          $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
        },
        totalRevenue: { $sum: '$financial.revenue.recognized' },
        totalCosts: { $sum: '$financial.costs.total' },
        avgProjectDuration: { $avg: '$timeline.duration.actual' },
        avgBudgetUtilization: { $avg: '$budgetUtilization' },
        projectsByType: { $push: '$type' },
        projectsByStatus: { $push: '$status' }
      }
    }
  ];
  
  const results = await this.aggregate(pipeline);
  return results[0] || {};
};

const Project = mongoose.model('Project', projectSchema);

module.exports = Project;