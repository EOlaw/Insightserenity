// server/core-business/team/models/team-model.js
/**
 * @file Team Model
 * @description Mongoose model for team management with comprehensive features
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

/**
 * Team Member Schema
 */
const teamMemberSchema = new Schema({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  role: {
    type: String,
    enum: ['lead', 'co-lead', 'member', 'advisor', 'observer'],
    default: 'member',
    required: true
  },
  joinedAt: {
    type: Date,
    default: Date.now
  },
  leftAt: Date,
  allocation: {
    percentage: {
      type: Number,
      min: 0,
      max: 100,
      default: 100
    },
    hoursPerWeek: {
      type: Number,
      min: 0,
      max: 168
    },
    startDate: Date,
    endDate: Date
  },
  permissions: {
    canInviteMembers: { type: Boolean, default: false },
    canRemoveMembers: { type: Boolean, default: false },
    canEditTeam: { type: Boolean, default: false },
    canManageProjects: { type: Boolean, default: false },
    canViewReports: { type: Boolean, default: true },
    canManageResources: { type: Boolean, default: false }
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'on_leave', 'pending'],
    default: 'active'
  },
  metadata: {
    addedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    invitedAt: Date,
    acceptedAt: Date,
    lastActiveAt: Date,
    notes: String
  }
}, {
  _id: true,
  timestamps: true
});

/**
 * Team Schema
 */
const teamSchema = new Schema({
  // Basic Information
  name: {
    type: String,
    required: [true, 'Team name is required'],
    trim: true,
    minlength: [3, 'Team name must be at least 3 characters'],
    maxlength: [100, 'Team name cannot exceed 100 characters']
  },
  code: {
    type: String,
    unique: true,
    uppercase: true,
    sparse: true,
    index: true
  },
  description: {
    type: String,
    maxlength: [1000, 'Description cannot exceed 1000 characters']
  },
  type: {
    type: String,
    enum: ['project', 'department', 'functional', 'cross_functional', 'temporary', 'permanent'],
    required: true,
    default: 'project'
  },
  
  // Organization
  organization: {
    type: Schema.Types.ObjectId,
    ref: 'Organization',
    required: true,
    index: true
  },
  department: {
    type: Schema.Types.ObjectId,
    ref: 'Department'
  },
  parentTeam: {
    type: Schema.Types.ObjectId,
    ref: 'Team'
  },
  
  // Team Members
  members: [teamMemberSchema],
  
  // Team Settings
  settings: {
    visibility: {
      type: String,
      enum: ['public', 'private', 'organization'],
      default: 'organization'
    },
    joinApproval: {
      type: String,
      enum: ['open', 'approval_required', 'invite_only'],
      default: 'invite_only'
    },
    maxMembers: {
      type: Number,
      default: 50,
      min: 2,
      max: 500
    },
    allowGuests: {
      type: Boolean,
      default: false
    },
    autoArchive: {
      enabled: { type: Boolean, default: true },
      inactiveDays: { type: Number, default: 180 }
    },
    notifications: {
      newMember: { type: Boolean, default: true },
      memberLeft: { type: Boolean, default: true },
      projectUpdates: { type: Boolean, default: true },
      dailyDigest: { type: Boolean, default: false }
    }
  },
  
  // Team Goals and Objectives
  objectives: [{
    title: { type: String, required: true },
    description: String,
    targetDate: Date,
    status: {
      type: String,
      enum: ['not_started', 'in_progress', 'at_risk', 'completed', 'cancelled'],
      default: 'not_started'
    },
    progress: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    keyResults: [{
      metric: String,
      target: Schema.Types.Mixed,
      current: Schema.Types.Mixed,
      unit: String
    }],
    owner: { type: Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: Date
  }],
  
  // Projects and Workstreams
  projects: [{
    project: { type: Schema.Types.ObjectId, ref: 'Project' },
    role: String,
    allocation: Number,
    startDate: Date,
    endDate: Date,
    status: {
      type: String,
      enum: ['active', 'completed', 'on_hold', 'cancelled'],
      default: 'active'
    }
  }],
  
  // Resources and Tools
  resources: {
    channels: [{
      type: { type: String, enum: ['slack', 'teams', 'email', 'other'] },
      identifier: String,
      isPrimary: { type: Boolean, default: false }
    }],
    repositories: [{
      type: { type: String, enum: ['github', 'gitlab', 'bitbucket', 'azure_devops', 'other'] },
      url: String,
      name: String,
      isPrimary: { type: Boolean, default: false }
    }],
    documents: [{
      name: String,
      url: String,
      type: { type: String, enum: ['drive', 'sharepoint', 'confluence', 'notion', 'other'] },
      lastUpdated: Date
    }],
    tools: [{
      name: String,
      type: String,
      url: String,
      license: String
    }]
  },
  
  // Performance Metrics
  metrics: {
    productivity: {
      tasksCompleted: { type: Number, default: 0 },
      projectsDelivered: { type: Number, default: 0 },
      averageCompletionTime: Number,
      velocityTrend: [{
        period: Date,
        velocity: Number
      }]
    },
    quality: {
      defectRate: Number,
      customerSatisfaction: Number,
      internalQualityScore: Number
    },
    collaboration: {
      meetingEfficiency: Number,
      communicationScore: Number,
      knowledgeSharing: Number
    },
    health: {
      score: { type: Number, min: 0, max: 100 },
      factors: {
        workload: { type: Number, min: 0, max: 100 },
        morale: { type: Number, min: 0, max: 100 },
        clarity: { type: Number, min: 0, max: 100 },
        growth: { type: Number, min: 0, max: 100 },
        recognition: { type: Number, min: 0, max: 100 }
      },
      lastAssessed: Date
    }
  },
  
  // Status and Lifecycle
  status: {
    type: String,
    enum: ['active', 'inactive', 'archived', 'suspended'],
    default: 'active',
    index: true
  },
  lifecycle: {
    formationDate: {
      type: Date,
      default: Date.now
    },
    activationDate: Date,
    suspensionDate: Date,
    archivalDate: Date,
    plannedEndDate: Date,
    actualEndDate: Date
  },
  
  // Audit and Metadata
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
    lastActivityAt: {
      type: Date,
      default: Date.now
    },
    version: {
      type: Number,
      default: 1
    },
    tags: [{
      type: String,
      trim: true,
      lowercase: true
    }],
    customFields: Schema.Types.Mixed
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Indexes
 */
teamSchema.index({ organization: 1, status: 1 });
teamSchema.index({ 'members.user': 1 });
teamSchema.index({ code: 1 }, { unique: true, sparse: true });
teamSchema.index({ name: 'text', description: 'text' });
teamSchema.index({ 'metadata.tags': 1 });
teamSchema.index({ type: 1, status: 1 });
teamSchema.index({ 'projects.project': 1 });

/**
 * Virtual Fields
 */
teamSchema.virtual('memberCount').get(function() {
  return this.members.filter(m => m.status === 'active').length;
});

teamSchema.virtual('activeProjects').get(function() {
  return this.projects.filter(p => p.status === 'active').length;
});

teamSchema.virtual('teamLead').get(function() {
  const lead = this.members.find(m => m.role === 'lead' && m.status === 'active');
  return lead ? lead.user : null;
});

teamSchema.virtual('isActive').get(function() {
  return this.status === 'active';
});

/**
 * Pre-save Middleware
 */
teamSchema.pre('save', async function(next) {
  try {
    // Generate team code if not provided
    if (!this.code && this.isNew) {
      this.code = await this.generateUniqueCode();
    }
    
    // Update lifecycle dates
    if (this.isModified('status')) {
      const now = new Date();
      switch (this.status) {
        case 'active':
          if (!this.lifecycle.activationDate) {
            this.lifecycle.activationDate = now;
          }
          break;
        case 'suspended':
          this.lifecycle.suspensionDate = now;
          break;
        case 'archived':
          this.lifecycle.archivalDate = now;
          if (!this.lifecycle.actualEndDate) {
            this.lifecycle.actualEndDate = now;
          }
          break;
      }
    }
    
    // Update metadata
    this.metadata.lastActivityAt = new Date();
    if (this.isModified() && !this.isNew) {
      this.metadata.version += 1;
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
 * Generate unique team code
 */
teamSchema.methods.generateUniqueCode = async function() {
  const prefix = this.type.substring(0, 3).toUpperCase();
  let isUnique = false;
  let code;
  
  while (!isUnique) {
    const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
    code = `${prefix}-${random}`;
    const existing = await this.constructor.findOne({ code });
    if (!existing) {
      isUnique = true;
    }
  }
  
  return code;
};

/**
 * Add team member
 */
teamSchema.methods.addMember = async function(userId, role = 'member', addedBy, options = {}) {
  // Check if user is already a member
  const existingMember = this.members.find(m => 
    m.user.toString() === userId.toString() && m.status === 'active'
  );
  
  if (existingMember) {
    throw new AppError('User is already a team member', 400);
  }
  
  // Check team capacity
  if (this.members.filter(m => m.status === 'active').length >= this.settings.maxMembers) {
    throw new AppError('Team has reached maximum capacity', 400);
  }
  
  // Set permissions based on role
  const permissions = this.getDefaultPermissions(role);
  
  const newMember = {
    user: userId,
    role,
    permissions,
    allocation: options.allocation || { percentage: 100 },
    metadata: {
      addedBy,
      invitedAt: new Date(),
      acceptedAt: options.autoAccept ? new Date() : null
    },
    status: options.autoAccept ? 'active' : 'pending'
  };
  
  this.members.push(newMember);
  
  logger.info('Team member added', {
    teamId: this._id,
    userId,
    role,
    addedBy
  });
  
  return newMember;
};

/**
 * Remove team member
 */
teamSchema.methods.removeMember = async function(userId, removedBy, reason) {
  const memberIndex = this.members.findIndex(m => 
    m.user.toString() === userId.toString() && m.status === 'active'
  );
  
  if (memberIndex === -1) {
    throw new AppError('User is not a team member', 404);
  }
  
  const member = this.members[memberIndex];
  
  // Cannot remove the last team lead
  if (member.role === 'lead') {
    const otherLeads = this.members.filter(m => 
      m.role === 'lead' && 
      m.status === 'active' && 
      m.user.toString() !== userId.toString()
    );
    
    if (otherLeads.length === 0) {
      throw new AppError('Cannot remove the last team lead', 400);
    }
  }
  
  // Mark as inactive instead of removing
  member.status = 'inactive';
  member.leftAt = new Date();
  member.metadata.notes = reason;
  
  logger.info('Team member removed', {
    teamId: this._id,
    userId,
    removedBy,
    reason
  });
  
  return member;
};

/**
 * Update member role
 */
teamSchema.methods.updateMemberRole = async function(userId, newRole, updatedBy) {
  const member = this.members.find(m => 
    m.user.toString() === userId.toString() && m.status === 'active'
  );
  
  if (!member) {
    throw new AppError('User is not a team member', 404);
  }
  
  const oldRole = member.role;
  member.role = newRole;
  member.permissions = this.getDefaultPermissions(newRole);
  
  logger.info('Team member role updated', {
    teamId: this._id,
    userId,
    oldRole,
    newRole,
    updatedBy
  });
  
  return member;
};

/**
 * Get default permissions for role
 */
teamSchema.methods.getDefaultPermissions = function(role) {
  const permissionMap = {
    lead: {
      canInviteMembers: true,
      canRemoveMembers: true,
      canEditTeam: true,
      canManageProjects: true,
      canViewReports: true,
      canManageResources: true
    },
    co_lead: {
      canInviteMembers: true,
      canRemoveMembers: true,
      canEditTeam: true,
      canManageProjects: true,
      canViewReports: true,
      canManageResources: true
    },
    member: {
      canInviteMembers: false,
      canRemoveMembers: false,
      canEditTeam: false,
      canManageProjects: false,
      canViewReports: true,
      canManageResources: false
    },
    advisor: {
      canInviteMembers: false,
      canRemoveMembers: false,
      canEditTeam: false,
      canManageProjects: false,
      canViewReports: true,
      canManageResources: false
    },
    observer: {
      canInviteMembers: false,
      canRemoveMembers: false,
      canEditTeam: false,
      canManageProjects: false,
      canViewReports: true,
      canManageResources: false
    }
  };
  
  return permissionMap[role] || permissionMap.member;
};

/**
 * Check if user can perform action
 */
teamSchema.methods.canUserPerform = function(userId, action) {
  const member = this.members.find(m => 
    m.user.toString() === userId.toString() && m.status === 'active'
  );
  
  if (!member) return false;
  
  return member.permissions[action] || false;
};

/**
 * Calculate team health score
 */
teamSchema.methods.calculateHealthScore = async function() {
  const factors = {
    workload: 0,
    morale: 0,
    clarity: 0,
    growth: 0,
    recognition: 0
  };
  
  // Calculate workload based on member allocation
  const totalAllocation = this.members
    .filter(m => m.status === 'active')
    .reduce((sum, m) => sum + (m.allocation.percentage || 100), 0);
  const avgAllocation = totalAllocation / this.memberCount;
  factors.workload = Math.max(0, Math.min(100, 150 - avgAllocation));
  
  // Calculate based on objective completion
  const completedObjectives = this.objectives.filter(o => o.status === 'completed').length;
  const totalObjectives = this.objectives.length || 1;
  factors.clarity = (completedObjectives / totalObjectives) * 100;
  
  // Calculate based on activity
  const daysSinceActivity = Math.floor(
    (Date.now() - this.metadata.lastActivityAt) / (1000 * 60 * 60 * 24)
  );
  factors.morale = Math.max(0, Math.min(100, 100 - daysSinceActivity * 2));
  
  // Default values for growth and recognition (would be calculated from other data)
  factors.growth = 70;
  factors.recognition = 75;
  
  // Calculate overall score
  const weights = { workload: 0.2, morale: 0.25, clarity: 0.2, growth: 0.2, recognition: 0.15 };
  const score = Object.entries(factors).reduce((sum, [key, value]) => {
    return sum + (value * weights[key]);
  }, 0);
  
  this.metrics.health = {
    score: Math.round(score),
    factors,
    lastAssessed: new Date()
  };
  
  return this.metrics.health;
};

/**
 * Check if team should be archived
 */
teamSchema.methods.shouldAutoArchive = function() {
  if (!this.settings.autoArchive.enabled || this.status !== 'active') {
    return false;
  }
  
  const daysSinceActivity = Math.floor(
    (Date.now() - this.metadata.lastActivityAt) / (1000 * 60 * 60 * 24)
  );
  
  return daysSinceActivity >= this.settings.autoArchive.inactiveDays;
};

/**
 * Get team summary
 */
teamSchema.methods.getSummary = function() {
  return {
    id: this._id,
    name: this.name,
    code: this.code,
    type: this.type,
    memberCount: this.memberCount,
    activeProjects: this.activeProjects,
    healthScore: this.metrics.health.score,
    status: this.status,
    lead: this.teamLead
  };
};

/**
 * Static Methods
 */

/**
 * Find teams by user
 */
teamSchema.statics.findByUser = async function(userId, options = {}) {
  const query = {
    'members.user': userId,
    'members.status': 'active'
  };
  
  if (options.status) {
    query.status = options.status;
  }
  
  if (options.type) {
    query.type = options.type;
  }
  
  return this.find(query)
    .populate('members.user', 'firstName lastName email profile.avatar')
    .populate('organization', 'name')
    .sort({ 'metadata.lastActivityAt': -1 });
};

/**
 * Find teams by organization
 */
teamSchema.statics.findByOrganization = async function(organizationId, options = {}) {
  const query = {
    organization: organizationId
  };
  
  if (options.status) {
    query.status = options.status;
  }
  
  if (options.type) {
    query.type = options.type;
  }
  
  return this.find(query)
    .populate('members.user', 'firstName lastName email')
    .populate('department', 'name')
    .sort({ createdAt: -1 });
};

/**
 * Search teams
 */
teamSchema.statics.searchTeams = async function(searchTerm, filters = {}) {
  const query = {
    $and: [
      {
        $or: [
          { name: { $regex: searchTerm, $options: 'i' } },
          { code: { $regex: searchTerm, $options: 'i' } },
          { description: { $regex: searchTerm, $options: 'i' } },
          { 'metadata.tags': { $in: [searchTerm.toLowerCase()] } }
        ]
      }
    ]
  };
  
  // Apply filters
  if (filters.organization) {
    query.$and.push({ organization: filters.organization });
  }
  
  if (filters.type) {
    query.$and.push({ type: filters.type });
  }
  
  if (filters.status) {
    query.$and.push({ status: filters.status });
  }
  
  if (filters.userId) {
    query.$and.push({
      'members.user': filters.userId,
      'members.status': 'active'
    });
  }
  
  return this.find(query)
    .populate('members.user', 'firstName lastName email')
    .populate('organization', 'name')
    .limit(filters.limit || 20)
    .sort({ 'metadata.lastActivityAt': -1 });
};

const Team = mongoose.model('Team', teamSchema);

module.exports = Team;