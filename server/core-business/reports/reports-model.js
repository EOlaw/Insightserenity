// server/core-business/reports/models/reports-model.js
/**
 * @file Reports Model
 * @description Comprehensive reports model for business intelligence and analytics
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

// Import schemas
const { reportDataSourceSchema } = require('./schemas/report-datasource-schema');
const { reportParameterSchema } = require('./schemas/report-parameter-schema');
const { reportVisualizationSchema } = require('./schemas/report-visualization-schema');
const { reportScheduleSchema } = require('./schemas/report-schedule-schema');
const { reportAccessSchema } = require('./schemas/report-access-schema');
const { reportExportSchema } = require('./schemas/report-export-schema');

/**
 * Report Schema Definition
 */
const reportSchema = new Schema({
  // Basic Information
  reportId: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^RPT-[A-Z0-9]{6,10}$/.test(v);
      },
      message: 'Report ID must follow format: RPT-XXXXXX'
    }
  },
  
  name: {
    type: String,
    required: [true, 'Report name is required'],
    trim: true,
    minlength: [3, 'Report name must be at least 3 characters'],
    maxlength: [100, 'Report name cannot exceed 100 characters']
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
  
  description: {
    type: String,
    maxlength: [500, 'Description cannot exceed 500 characters']
  },
  
  // Report Type and Category
  type: {
    type: String,
    required: true,
    enum: [
      'dashboard',
      'detailed',
      'summary',
      'analytical',
      'operational',
      'strategic',
      'compliance',
      'custom'
    ]
  },
  
  category: {
    type: String,
    required: true,
    enum: [
      'financial',
      'project',
      'client',
      'service',
      'team',
      'performance',
      'compliance',
      'executive',
      'operational',
      'custom'
    ]
  },
  
  subCategory: {
    type: String,
    trim: true
  },
  
  // Data Configuration
  dataSources: [reportDataSourceSchema],
  
  parameters: [reportParameterSchema],
  
  filters: {
    predefined: [{
      name: String,
      field: String,
      operator: {
        type: String,
        enum: ['equals', 'contains', 'startsWith', 'endsWith', 'gt', 'gte', 'lt', 'lte', 'between', 'in', 'notIn']
      },
      value: Schema.Types.Mixed,
      isRequired: {
        type: Boolean,
        default: false
      }
    }],
    
    userDefined: {
      type: Boolean,
      default: true
    },
    
    defaultFilters: [{
      field: String,
      operator: String,
      value: Schema.Types.Mixed
    }]
  },
  
  // Query Configuration
  query: {
    type: {
      type: String,
      enum: ['aggregation', 'raw', 'custom', 'stored'],
      required: true
    },
    
    aggregation: {
      pipeline: [Schema.Types.Mixed],
      options: {
        allowDiskUse: Boolean,
        maxTimeMS: Number,
        collation: Schema.Types.Mixed
      }
    },
    
    raw: {
      collection: String,
      query: Schema.Types.Mixed,
      projection: Schema.Types.Mixed,
      sort: Schema.Types.Mixed,
      limit: Number,
      skip: Number
    },
    
    custom: {
      handler: String, // Function name in report service
      config: Schema.Types.Mixed
    },
    
    stored: {
      procedureName: String,
      parameters: [Schema.Types.Mixed]
    }
  },
  
  // Visualization Configuration
  visualizations: [reportVisualizationSchema],
  
  layout: {
    type: {
      type: String,
      enum: ['grid', 'flex', 'fixed', 'responsive'],
      default: 'responsive'
    },
    
    sections: [{
      id: String,
      name: String,
      order: Number,
      width: String,
      height: String,
      components: [{
        type: {
          type: String,
          enum: ['chart', 'table', 'metric', 'text', 'filter', 'export']
        },
        visualizationId: String,
        config: Schema.Types.Mixed,
        position: {
          x: Number,
          y: Number,
          w: Number,
          h: Number
        }
      }]
    }],
    
    theme: {
      type: String,
      enum: ['light', 'dark', 'custom'],
      default: 'light'
    },
    
    customStyles: Schema.Types.Mixed
  },
  
  // Scheduling Configuration
  schedule: reportScheduleSchema,
  
  // Access Control
  access: reportAccessSchema,
  
  // Export Configuration
  exportConfig: reportExportSchema,
  
  // Performance Configuration
  performance: {
    caching: {
      enabled: {
        type: Boolean,
        default: true
      },
      duration: {
        type: Number,
        default: 300 // 5 minutes
      },
      strategy: {
        type: String,
        enum: ['time-based', 'event-based', 'hybrid'],
        default: 'time-based'
      }
    },
    
    optimization: {
      indexHints: [String],
      partialExecution: Boolean,
      incrementalLoad: Boolean,
      preAggregation: Boolean
    },
    
    limits: {
      maxExecutionTime: {
        type: Number,
        default: 30000 // 30 seconds
      },
      maxDataPoints: {
        type: Number,
        default: 10000
      },
      maxExportRows: {
        type: Number,
        default: 50000
      }
    }
  },
  
  // Execution History
  executions: [{
    executionId: String,
    startTime: Date,
    endTime: Date,
    duration: Number,
    status: {
      type: String,
      enum: ['running', 'completed', 'failed', 'cancelled']
    },
    recordsProcessed: Number,
    exportFormat: String,
    exportSize: Number,
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    parameters: Schema.Types.Mixed,
    error: {
      message: String,
      code: String,
      stack: String
    }
  }],
  
  // Sharing and Collaboration
  sharing: {
    isPublic: {
      type: Boolean,
      default: false
    },
    
    publicUrl: String,
    publicToken: String,
    
    sharedWith: [{
      user: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      email: String,
      permissions: {
        type: String,
        enum: ['view', 'run', 'edit', 'admin']
      },
      sharedAt: Date,
      sharedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      expiresAt: Date
    }]
  },
  
  // Analytics and Usage
  analytics: {
    views: {
      type: Number,
      default: 0
    },
    
    runs: {
      type: Number,
      default: 0
    },
    
    exports: {
      type: Number,
      default: 0
    },
    
    lastViewedAt: Date,
    lastRunAt: Date,
    lastExportedAt: Date,
    
    averageExecutionTime: Number,
    
    userEngagement: [{
      user: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      views: Number,
      runs: Number,
      exports: Number,
      lastActivity: Date
    }]
  },
  
  // Status and Lifecycle
  status: {
    type: String,
    enum: ['draft', 'active', 'inactive', 'archived', 'deprecated'],
    default: 'draft'
  },
  
  version: {
    major: {
      type: Number,
      default: 1
    },
    minor: {
      type: Number,
      default: 0
    },
    patch: {
      type: Number,
      default: 0
    }
  },
  
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
    
    organization: {
      type: Schema.Types.ObjectId,
      ref: 'Organization',
      required: true
    },
    
    tags: [String],
    
    customFields: Schema.Types.Mixed,
    
    source: {
      type: String,
      enum: ['manual', 'template', 'import', 'api'],
      default: 'manual'
    },
    
    template: {
      type: Schema.Types.ObjectId,
      ref: 'ReportTemplate'
    },
    
    changeLog: [{
      action: String,
      changes: Schema.Types.Mixed,
      changedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      changedAt: Date,
      reason: String
    }]
  }
}, {
  timestamps: true,
  collection: 'reports'
});

// Indexes for performance
reportSchema.index({ reportId: 1 });
reportSchema.index({ slug: 1 });
reportSchema.index({ 'metadata.organization': 1, status: 1 });
reportSchema.index({ type: 1, category: 1 });
reportSchema.index({ 'schedule.isActive': 1, 'schedule.nextRunAt': 1 });
reportSchema.index({ 'sharing.isPublic': 1 });
reportSchema.index({ 'sharing.publicToken': 1 });
reportSchema.index({ 'metadata.tags': 1 });
reportSchema.index({ status: 1, createdAt: -1 });

// Compound indexes
reportSchema.index({ 'metadata.organization': 1, type: 1, category: 1 });
reportSchema.index({ 'access.roles': 1, status: 1 });
reportSchema.index({ 'analytics.lastRunAt': -1, status: 1 });

// Text search index
reportSchema.index({ name: 'text', description: 'text', 'metadata.tags': 'text' });

// TTL index for execution history
reportSchema.index({ 'executions.startTime': 1 }, { 
  expireAfterSeconds: 30 * 24 * 60 * 60 // 30 days
});

// Virtual fields
reportSchema.virtual('fullVersion').get(function() {
  return `${this.version.major}.${this.version.minor}.${this.version.patch}`;
});

reportSchema.virtual('isScheduled').get(function() {
  return this.schedule?.isActive && this.schedule?.frequency;
});

// Pre-save middleware
reportSchema.pre('save', async function(next) {
  try {
    // Auto-generate reportId if not provided
    if (this.isNew && !this.reportId) {
      const randomId = Math.random().toString(36).substring(2, 10).toUpperCase();
      this.reportId = `RPT-${randomId}`;
    }
    
    // Auto-generate slug from name if not provided
    if (!this.slug && this.name) {
      this.slug = this.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    }
    
    // Update version on modifications
    if (!this.isNew && this.isModified()) {
      this.version.patch += 1;
      if (this.version.patch >= 10) {
        this.version.patch = 0;
        this.version.minor += 1;
      }
      if (this.version.minor >= 10) {
        this.version.minor = 0;
        this.version.major += 1;
      }
    }
    
    // Clean up old execution history (keep last 100)
    if (this.executions.length > 100) {
      this.executions = this.executions.slice(-100);
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance methods
reportSchema.methods = {
  /**
   * Check if user has permission to access report
   * @param {string} userId - User ID
   * @param {string} action - Action to check
   * @returns {boolean} Has permission
   */
  hasPermission(userId, action = 'view') {
    // Check if user is creator
    if (this.metadata.createdBy.toString() === userId.toString()) {
      return true;
    }
    
    // Check if report is public and action is view
    if (this.sharing.isPublic && action === 'view') {
      return true;
    }
    
    // Check shared permissions
    const share = this.sharing.sharedWith.find(
      s => s.user?.toString() === userId.toString()
    );
    
    if (share) {
      const permissionLevels = { view: 1, run: 2, edit: 3, admin: 4 };
      const requiredLevel = permissionLevels[action] || 1;
      const userLevel = permissionLevels[share.permissions] || 0;
      return userLevel >= requiredLevel;
    }
    
    return false;
  },
  
  /**
   * Add execution record
   * @param {Object} execution - Execution details
   */
  addExecution(execution) {
    this.executions.push({
      executionId: `EXE-${Date.now()}`,
      startTime: new Date(),
      ...execution
    });
    
    // Update analytics
    this.analytics.runs += 1;
    this.analytics.lastRunAt = new Date();
    
    // Calculate average execution time
    const completedExecutions = this.executions.filter(
      e => e.status === 'completed' && e.duration
    );
    
    if (completedExecutions.length > 0) {
      const totalTime = completedExecutions.reduce((sum, e) => sum + e.duration, 0);
      this.analytics.averageExecutionTime = totalTime / completedExecutions.length;
    }
  },
  
  /**
   * Share report with user
   * @param {Object} shareData - Sharing details
   */
  shareWith(shareData) {
    const existingShare = this.sharing.sharedWith.findIndex(
      s => s.user?.toString() === shareData.user.toString()
    );
    
    if (existingShare >= 0) {
      this.sharing.sharedWith[existingShare] = {
        ...this.sharing.sharedWith[existingShare],
        ...shareData,
        sharedAt: new Date()
      };
    } else {
      this.sharing.sharedWith.push({
        ...shareData,
        sharedAt: new Date()
      });
    }
  },
  
  /**
   * Generate public sharing URL
   * @returns {string} Public URL
   */
  generatePublicUrl() {
    if (!this.sharing.publicToken) {
      this.sharing.publicToken = require('crypto')
        .randomBytes(32)
        .toString('hex');
    }
    
    this.sharing.publicUrl = `${config.app.url}/reports/public/${this.slug}?token=${this.sharing.publicToken}`;
    return this.sharing.publicUrl;
  }
};

// Static methods
reportSchema.statics = {
  /**
   * Find reports by organization with filters
   * @param {string} organizationId - Organization ID
   * @param {Object} filters - Filter options
   * @returns {Promise<Array>} Reports
   */
  async findByOrganization(organizationId, filters = {}) {
    const query = { 'metadata.organization': organizationId };
    
    if (filters.type) query.type = filters.type;
    if (filters.category) query.category = filters.category;
    if (filters.status) query.status = filters.status;
    if (filters.tags && filters.tags.length > 0) {
      query['metadata.tags'] = { $in: filters.tags };
    }
    
    return this.find(query)
      .populate('metadata.createdBy', 'firstName lastName email')
      .populate('metadata.lastModifiedBy', 'firstName lastName email')
      .sort({ createdAt: -1 });
  },
  
  /**
   * Find scheduled reports due for execution
   * @returns {Promise<Array>} Reports to execute
   */
  async findDueReports() {
    const now = new Date();
    
    return this.find({
      status: 'active',
      'schedule.isActive': true,
      'schedule.nextRunAt': { $lte: now }
    }).populate('metadata.organization', 'name settings');
  },
  
  /**
   * Get report statistics by organization
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Statistics
   */
  async getStatistics(organizationId) {
    const stats = await this.aggregate([
      {
        $match: { 'metadata.organization': new mongoose.Types.ObjectId(organizationId) }
      },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          byType: {
            $push: { type: '$type', status: '$status' }
          },
          byCategory: {
            $push: { category: '$category', status: '$status' }
          },
          totalRuns: { $sum: '$analytics.runs' },
          totalViews: { $sum: '$analytics.views' },
          totalExports: { $sum: '$analytics.exports' },
          activeReports: {
            $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
          },
          scheduledReports: {
            $sum: { $cond: ['$schedule.isActive', 1, 0] }
          }
        }
      }
    ]);
    
    return stats[0] || {
      total: 0,
      activeReports: 0,
      scheduledReports: 0,
      totalRuns: 0,
      totalViews: 0,
      totalExports: 0
    };
  }
};

// Create model
const Report = mongoose.model('Report', reportSchema);

module.exports = Report;