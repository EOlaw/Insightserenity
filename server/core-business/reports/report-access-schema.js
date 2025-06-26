// server/core-business/reports/models/schemas/report-access-schema.js
/**
 * @file Report Access Schema
 * @description Schema for report access control and permissions
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Report Access Schema
 */
const reportAccessSchema = new Schema({
  // Access Level
  level: {
    type: String,
    enum: ['public', 'organization', 'department', 'team', 'role', 'user', 'custom'],
    default: 'organization'
  },
  
  // Public Access Configuration
  publicAccess: {
    enabled: {
      type: Boolean,
      default: false
    },
    
    requireAuthentication: {
      type: Boolean,
      default: true
    },
    
    allowAnonymous: {
      type: Boolean,
      default: false
    },
    
    tokenRequired: {
      type: Boolean,
      default: true
    },
    
    expiresAt: Date,
    
    restrictions: {
      domains: [String],
      ipWhitelist: [String],
      countries: [String]
    }
  },
  
  // Role-based Access
  roles: [{
    role: String,
    permissions: {
      view: {
        type: Boolean,
        default: true
      },
      run: {
        type: Boolean,
        default: true
      },
      export: {
        type: Boolean,
        default: true
      },
      share: {
        type: Boolean,
        default: false
      },
      edit: {
        type: Boolean,
        default: false
      },
      delete: {
        type: Boolean,
        default: false
      },
      schedule: {
        type: Boolean,
        default: false
      }
    },
    dataFilters: [{
      field: String,
      operator: String,
      value: Schema.Types.Mixed
    }],
    parameterOverrides: Schema.Types.Mixed
  }],
  
  // Department Access
  departments: [{
    department: {
      type: Schema.Types.ObjectId,
      ref: 'Department'
    },
    permissions: {
      view: {
        type: Boolean,
        default: true
      },
      run: {
        type: Boolean,
        default: true
      },
      export: {
        type: Boolean,
        default: true
      },
      share: {
        type: Boolean,
        default: false
      }
    },
    includeSubDepartments: {
      type: Boolean,
      default: true
    }
  }],
  
  // Team Access
  teams: [{
    team: {
      type: Schema.Types.ObjectId,
      ref: 'Team'
    },
    permissions: {
      view: {
        type: Boolean,
        default: true
      },
      run: {
        type: Boolean,
        default: true
      },
      export: {
        type: Boolean,
        default: true
      },
      share: {
        type: Boolean,
        default: false
      }
    }
  }],
  
  // User-specific Access
  users: [{
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    permissions: {
      view: {
        type: Boolean,
        default: true
      },
      run: {
        type: Boolean,
        default: true
      },
      export: {
        type: Boolean,
        default: true
      },
      share: {
        type: Boolean,
        default: false
      },
      edit: {
        type: Boolean,
        default: false
      },
      delete: {
        type: Boolean,
        default: false
      },
      schedule: {
        type: Boolean,
        default: false
      },
      admin: {
        type: Boolean,
        default: false
      }
    },
    dataFilters: [{
      field: String,
      operator: String,
      value: Schema.Types.Mixed
    }],
    parameterOverrides: Schema.Types.Mixed,
    expiresAt: Date
  }],
  
  // Group Access
  groups: [{
    group: {
      type: Schema.Types.ObjectId,
      ref: 'Group'
    },
    permissions: {
      view: {
        type: Boolean,
        default: true
      },
      run: {
        type: Boolean,
        default: true
      },
      export: {
        type: Boolean,
        default: true
      },
      share: {
        type: Boolean,
        default: false
      }
    }
  }],
  
  // Data Security
  dataSecurity: {
    // Row-level Security
    rowLevelSecurity: {
      enabled: {
        type: Boolean,
        default: false
      },
      
      rules: [{
        name: String,
        description: String,
        filter: {
          field: String,
          operator: {
            type: String,
            enum: ['equals', 'notEquals', 'in', 'notIn', 'contains', 'startsWith', 'endsWith']
          },
          value: Schema.Types.Mixed,
          userAttribute: String, // e.g., 'department', 'team', 'region'
        },
        applyTo: {
          roles: [String],
          users: [{
            type: Schema.Types.ObjectId,
            ref: 'User'
          }]
        }
      }]
    },
    
    // Column-level Security
    columnLevelSecurity: {
      enabled: {
        type: Boolean,
        default: false
      },
      
      rules: [{
        columns: [String],
        action: {
          type: String,
          enum: ['hide', 'mask', 'encrypt']
        },
        maskPattern: String,
        applyTo: {
          roles: [String],
          users: [{
            type: Schema.Types.ObjectId,
            ref: 'User'
          }]
        }
      }]
    },
    
    // Data Classification
    classification: {
      level: {
        type: String,
        enum: ['public', 'internal', 'confidential', 'restricted', 'top_secret']
      },
      
      sensitiveFields: [{
        field: String,
        sensitivity: {
          type: String,
          enum: ['low', 'medium', 'high', 'critical']
        },
        handling: {
          type: String,
          enum: ['normal', 'encrypt', 'redact', 'audit']
        }
      }],
      
      complianceRequirements: [{
        type: String,
        enum: ['GDPR', 'HIPAA', 'PCI', 'SOX', 'ISO27001', 'CCPA']
      }]
    }
  },
  
  // Access Request Configuration
  accessRequest: {
    enabled: {
      type: Boolean,
      default: true
    },
    
    requireApproval: {
      type: Boolean,
      default: true
    },
    
    approvers: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }],
    
    approvalWorkflow: {
      type: {
        type: String,
        enum: ['single', 'sequential', 'parallel', 'custom']
      },
      steps: [{
        order: Number,
        approvers: [{
          type: Schema.Types.ObjectId,
          ref: 'User'
        }],
        minimumApprovals: Number,
        timeout: Number // Hours
      }]
    },
    
    autoApprove: {
      enabled: Boolean,
      conditions: [{
        field: String,
        operator: String,
        value: Schema.Types.Mixed
      }]
    },
    
    requestTemplate: {
      requireJustification: {
        type: Boolean,
        default: true
      },
      
      additionalFields: [{
        name: String,
        type: String,
        required: Boolean
      }],
      
      defaultDuration: Number, // Days
      maxDuration: Number
    }
  },
  
  // Audit Configuration
  audit: {
    enabled: {
      type: Boolean,
      default: true
    },
    
    logLevel: {
      type: String,
      enum: ['minimal', 'standard', 'detailed', 'full'],
      default: 'standard'
    },
    
    events: [{
      type: String,
      enum: ['view', 'run', 'export', 'share', 'edit', 'delete', 'permission_change']
    }],
    
    retentionDays: {
      type: Number,
      default: 365
    },
    
    alerting: {
      enabled: Boolean,
      rules: [{
        event: String,
        condition: Schema.Types.Mixed,
        recipients: [{
          type: Schema.Types.ObjectId,
          ref: 'User'
        }]
      }]
    }
  },
  
  // Inheritance Configuration
  inheritance: {
    enabled: {
      type: Boolean,
      default: true
    },
    
    from: {
      type: String,
      enum: ['organization', 'department', 'category', 'parent']
    },
    
    override: {
      type: Boolean,
      default: false
    },
    
    merge: {
      type: Boolean,
      default: true
    }
  },
  
  // Metadata
  lastReviewed: Date,
  
  reviewedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  
  nextReviewDate: Date,
  
  notes: String
}, {
  _id: false,
  timestamps: true
});

// Methods
reportAccessSchema.methods = {
  /**
   * Check if a user has specific permission
   * @param {string} userId - User ID
   * @param {string} permission - Permission to check
   * @param {Object} userContext - User context (roles, department, etc.)
   * @returns {boolean} Has permission
   */
  hasPermission(userId, permission, userContext = {}) {
    // Check user-specific permissions
    const userAccess = this.users.find(u => u.user?.toString() === userId);
    if (userAccess && userAccess.permissions[permission]) {
      return true;
    }
    
    // Check role-based permissions
    if (userContext.roles && this.roles.length > 0) {
      const roleAccess = this.roles.find(r => 
        userContext.roles.includes(r.role) && r.permissions[permission]
      );
      if (roleAccess) {
        return true;
      }
    }
    
    // Check department permissions
    if (userContext.department && this.departments.length > 0) {
      const deptAccess = this.departments.find(d => 
        d.department?.toString() === userContext.department && d.permissions[permission]
      );
      if (deptAccess) {
        return true;
      }
    }
    
    // Check team permissions
    if (userContext.teams && this.teams.length > 0) {
      const teamAccess = this.teams.find(t => 
        userContext.teams.includes(t.team?.toString()) && t.permissions[permission]
      );
      if (teamAccess) {
        return true;
      }
    }
    
    // Check public access
    if (this.publicAccess.enabled && permission === 'view') {
      return true;
    }
    
    return false;
  }
};

module.exports = { reportAccessSchema };