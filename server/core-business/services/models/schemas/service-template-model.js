// server/core-business/services/models/schemas/service-template-model.js
/**
 * @file Service Template Model
 * @description Model for reusable service templates
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../../shared/config/config');
const constants = require('../../../../shared/config/constants');

/**
 * Template Field Schema
 */
const templateFieldSchema = new Schema({
  fieldName: {
    type: String,
    required: true
  },
  fieldType: {
    type: String,
    enum: ['text', 'number', 'boolean', 'date', 'select', 'multiselect', 'object', 'array'],
    required: true
  },
  label: {
    type: String,
    required: true
  },
  description: String,
  placeholder: String,
  defaultValue: Schema.Types.Mixed,
  required: {
    type: Boolean,
    default: false
  },
  validation: {
    min: Number,
    max: Number,
    minLength: Number,
    maxLength: Number,
    pattern: String,
    options: [Schema.Types.Mixed],
    customValidator: String
  },
  category: {
    type: String,
    enum: ['basic', 'pricing', 'delivery', 'requirements', 'sla', 'team', 'process', 'compliance']
  },
  order: {
    type: Number,
    default: 0
  },
  conditionalDisplay: {
    dependsOn: String,
    condition: String,
    value: Schema.Types.Mixed
  }
}, { _id: false });

/**
 * Template Section Schema
 */
const templateSectionSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true
  },
  description: String,
  fields: [templateFieldSchema],
  order: {
    type: Number,
    default: 0
  },
  isCollapsible: {
    type: Boolean,
    default: true
  },
  isRequired: {
    type: Boolean,
    default: true
  }
}, { _id: false });

/**
 * Service Template Schema
 */
const serviceTemplateSchema = new Schema({
  // Basic Information
  templateId: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    validate: {
      validator: function(v) {
        return /^TPL-[A-Z0-9]{6,10}$/.test(v);
      },
      message: 'Template ID must follow format: TPL-XXXXXX'
    }
  },
  
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: 3,
    maxlength: 100
  },
  
  description: {
    type: String,
    required: true,
    maxlength: 500
  },
  
  // Template Configuration
  category: {
    type: String,
    required: true,
    enum: ['consulting', 'development', 'design', 'marketing', 'support', 'training', 'analytics', 'research', 'other']
  },
  
  serviceType: {
    type: String,
    enum: ['fixed_scope', 'time_and_materials', 'retainer', 'subscription', 'milestone_based'],
    required: true
  },
  
  industryFocus: [{
    type: String,
    enum: ['technology', 'healthcare', 'finance', 'retail', 'manufacturing', 'education', 'government', 'nonprofit', 'general']
  }],
  
  // Template Structure
  sections: [templateSectionSchema],
  
  // Predefined Values
  defaults: {
    pricing: {
      billingCycle: String,
      currency: String,
      taxable: Boolean,
      paymentTerms: String
    },
    delivery: {
      method: String,
      timeline: {
        value: Number,
        unit: String
      },
      milestones: [{
        name: String,
        percentage: Number,
        deliverables: [String]
      }]
    },
    requirements: {
      provider: [{
        type: String,
        items: [String]
      }],
      client: [{
        type: String,
        items: [String]
      }]
    },
    sla: {
      responseTime: {
        value: Number,
        unit: String
      },
      availability: Number,
      supportLevel: String
    },
    compliance: {
      standards: [String],
      certifications: [String],
      dataHandling: {
        classification: String,
        encryption: Boolean,
        retention: {
          period: Number,
          unit: String
        }
      }
    }
  },
  
  // Customization Rules
  customization: {
    allowFieldAddition: {
      type: Boolean,
      default: true
    },
    allowFieldRemoval: {
      type: Boolean,
      default: false
    },
    requiredSections: [String],
    maxCustomFields: {
      type: Number,
      default: 20
    },
    restrictedFields: [String]
  },
  
  // Usage and Versioning
  version: {
    number: {
      type: String,
      default: '1.0.0'
    },
    changelog: [{
      version: String,
      date: Date,
      changes: [String],
      author: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      }
    }],
    isLatest: {
      type: Boolean,
      default: true
    },
    previousVersion: {
      type: Schema.Types.ObjectId,
      ref: 'ServiceTemplate'
    }
  },
  
  // Governance
  governance: {
    approvalRequired: {
      type: Boolean,
      default: false
    },
    approvers: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }],
    lastApproved: {
      date: Date,
      by: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      }
    },
    complianceChecked: {
      type: Boolean,
      default: false
    },
    expiryDate: Date
  },
  
  // Status and Visibility
  status: {
    type: String,
    enum: ['draft', 'pending_approval', 'approved', 'active', 'deprecated', 'archived'],
    default: 'draft'
  },
  
  visibility: {
    scope: {
      type: String,
      enum: ['private', 'organization', 'public'],
      default: 'organization'
    },
    allowedOrganizations: [{
      type: Schema.Types.ObjectId,
      ref: 'Organization'
    }],
    allowedRoles: [String],
    allowedUsers: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }]
  },
  
  // Usage Metrics
  metrics: {
    usageCount: {
      type: Number,
      default: 0
    },
    lastUsed: Date,
    servicesCreated: [{
      service: {
        type: Schema.Types.ObjectId,
        ref: 'Service'
      },
      createdAt: Date,
      createdBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      }
    }],
    averageCompletionTime: {
      value: Number,
      unit: String
    },
    successRate: {
      type: Number,
      min: 0,
      max: 100
    }
  },
  
  // Examples and Documentation
  documentation: {
    overview: String,
    howToUse: String,
    bestPractices: [String],
    commonMistakes: [String],
    faqs: [{
      question: String,
      answer: String
    }],
    examples: [{
      name: String,
      description: String,
      data: Schema.Types.Mixed
    }],
    relatedTemplates: [{
      type: Schema.Types.ObjectId,
      ref: 'ServiceTemplate'
    }]
  },
  
  // Tags and Search
  tags: [{
    type: String,
    lowercase: true,
    trim: true
  }],
  
  keywords: [{
    type: String,
    lowercase: true
  }],
  
  // Organization and Ownership
  organization: {
    type: Schema.Types.ObjectId,
    ref: 'Organization',
    required: true
  },
  
  owner: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  
  contributors: [{
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    role: {
      type: String,
      enum: ['editor', 'reviewer', 'viewer']
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Metadata
  metadata: {
    source: {
      type: String,
      enum: ['created', 'imported', 'cloned', 'migrated']
    },
    originalTemplate: {
      type: Schema.Types.ObjectId,
      ref: 'ServiceTemplate'
    },
    importedFrom: String,
    customFields: Schema.Types.Mixed
  }
}, {
  timestamps: true,
  collection: 'service_templates'
});

// Indexes
serviceTemplateSchema.index({ templateId: 1 });
serviceTemplateSchema.index({ name: 1, organization: 1 });
serviceTemplateSchema.index({ category: 1, status: 1 });
serviceTemplateSchema.index({ 'visibility.scope': 1, status: 1 });
serviceTemplateSchema.index({ tags: 1 });
serviceTemplateSchema.index({ keywords: 1 });

// Pre-save middleware
serviceTemplateSchema.pre('save', async function(next) {
  try {
    // Generate template ID if not provided
    if (this.isNew && !this.templateId) {
      const count = await mongoose.model('ServiceTemplate').countDocuments();
      const paddedCount = String(count + 1).padStart(6, '0');
      this.templateId = `TPL-${paddedCount}`;
    }
    
    // Sort sections and fields by order
    if (this.sections && this.sections.length > 0) {
      this.sections.sort((a, b) => a.order - b.order);
      this.sections.forEach(section => {
        if (section.fields && section.fields.length > 0) {
          section.fields.sort((a, b) => a.order - b.order);
        }
      });
    }
    
    // Update version if modified
    if (!this.isNew && this.isModified() && !this.isModified('version')) {
      const currentVersion = this.version.number.split('.');
      currentVersion[2] = parseInt(currentVersion[2]) + 1; // Increment patch version
      this.version.number = currentVersion.join('.');
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Methods

/**
 * Create service from template
 */
serviceTemplateSchema.methods.createService = function(data = {}) {
  const serviceData = {
    name: data.name,
    category: {
      primary: this.category,
      secondary: data.category?.secondary || [],
      tags: data.category?.tags || this.tags
    },
    type: this.serviceType,
    // Apply defaults
    pricing: {
      ...this.defaults.pricing,
      ...data.pricing
    },
    deliveryMethod: this.defaults.delivery?.method || data.deliveryMethod,
    duration: this.defaults.delivery?.timeline || data.duration,
    requirements: {
      provider: this.defaults.requirements?.provider || [],
      client: this.defaults.requirements?.client || []
    },
    sla: this.defaults.sla || {},
    compliance: this.defaults.compliance || {},
    // Apply custom data
    ...data
  };
  
  // Process template fields
  this.sections.forEach(section => {
    section.fields.forEach(field => {
      if (data[field.fieldName] !== undefined) {
        serviceData[field.fieldName] = data[field.fieldName];
      } else if (field.defaultValue !== undefined) {
        serviceData[field.fieldName] = field.defaultValue;
      }
    });
  });
  
  return serviceData;
};

/**
 * Validate data against template
 */
serviceTemplateSchema.methods.validateData = function(data) {
  const errors = [];
  const warnings = [];
  
  this.sections.forEach(section => {
    if (section.isRequired) {
      section.fields.forEach(field => {
        const value = data[field.fieldName];
        
        // Check required fields
        if (field.required && (value === undefined || value === null || value === '')) {
          errors.push({
            field: field.fieldName,
            message: `${field.label} is required`
          });
        }
        
        // Validate field type
        if (value !== undefined) {
          if (field.fieldType === 'number' && typeof value !== 'number') {
            errors.push({
              field: field.fieldName,
              message: `${field.label} must be a number`
            });
          }
          
          // Validate constraints
          if (field.validation) {
            if (field.validation.min !== undefined && value < field.validation.min) {
              errors.push({
                field: field.fieldName,
                message: `${field.label} must be at least ${field.validation.min}`
              });
            }
            
            if (field.validation.max !== undefined && value > field.validation.max) {
              errors.push({
                field: field.fieldName,
                message: `${field.label} must be at most ${field.validation.max}`
              });
            }
            
            if (field.validation.pattern) {
              const regex = new RegExp(field.validation.pattern);
              if (!regex.test(value)) {
                errors.push({
                  field: field.fieldName,
                  message: `${field.label} format is invalid`
                });
              }
            }
            
            if (field.validation.options && !field.validation.options.includes(value)) {
              errors.push({
                field: field.fieldName,
                message: `${field.label} must be one of: ${field.validation.options.join(', ')}`
              });
            }
          }
        }
      });
    }
  });
  
  // Check for extra fields if not allowed
  if (!this.customization.allowFieldAddition) {
    const templateFields = new Set();
    this.sections.forEach(section => {
      section.fields.forEach(field => {
        templateFields.add(field.fieldName);
      });
    });
    
    Object.keys(data).forEach(key => {
      if (!templateFields.has(key) && !['name', 'description', 'organization'].includes(key)) {
        warnings.push({
          field: key,
          message: `Field ${key} is not defined in template`
        });
      }
    });
  }
  
  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
};

/**
 * Clone template
 */
serviceTemplateSchema.methods.cloneTemplate = function(options = {}) {
  const clonedData = this.toObject();
  
  // Remove unique identifiers
  delete clonedData._id;
  delete clonedData.templateId;
  delete clonedData.createdAt;
  delete clonedData.updatedAt;
  delete clonedData.metrics;
  delete clonedData.version.changelog;
  
  // Apply options
  return {
    ...clonedData,
    name: options.name || `${this.name} (Copy)`,
    status: 'draft',
    version: {
      number: '1.0.0',
      isLatest: true,
      previousVersion: this._id
    },
    metadata: {
      source: 'cloned',
      originalTemplate: this._id
    },
    ...options
  };
};

// Static methods

/**
 * Find templates by category
 */
serviceTemplateSchema.statics.findByCategory = function(category, options = {}) {
  const query = {
    category,
    status: 'active',
    'visibility.scope': { $in: ['public', 'organization'] }
  };
  
  if (options.organization) {
    query.$or = [
      { 'visibility.scope': 'public' },
      { 
        'visibility.scope': 'organization',
        $or: [
          { organization: options.organization },
          { 'visibility.allowedOrganizations': options.organization }
        ]
      }
    ];
  }
  
  return this.find(query)
    .populate('owner', 'firstName lastName')
    .sort(options.sort || '-metrics.usageCount');
};

/**
 * Increment usage count
 */
serviceTemplateSchema.statics.incrementUsage = async function(templateId, userId, serviceId) {
  return this.findByIdAndUpdate(
    templateId,
    {
      $inc: { 'metrics.usageCount': 1 },
      $set: { 'metrics.lastUsed': new Date() },
      $push: {
        'metrics.servicesCreated': {
          service: serviceId,
          createdAt: new Date(),
          createdBy: userId
        }
      }
    },
    { new: true }
  );
};

// Create model
const ServiceTemplate = mongoose.model('ServiceTemplate', serviceTemplateSchema);

module.exports = ServiceTemplate;