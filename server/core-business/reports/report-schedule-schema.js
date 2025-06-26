// server/core-business/reports/models/schemas/report-schedule-schema.js
/**
 * @file Report Schedule Schema
 * @description Schema for report scheduling configuration
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Report Schedule Schema
 */
const reportScheduleSchema = new Schema({
  // Schedule Status
  isActive: {
    type: Boolean,
    default: false
  },
  
  // Schedule Type
  frequency: {
    type: String,
    enum: ['once', 'hourly', 'daily', 'weekly', 'monthly', 'quarterly', 'yearly', 'custom'],
    required: function() {
      return this.isActive;
    }
  },
  
  // Time Configuration
  startDate: {
    type: Date,
    required: function() {
      return this.isActive;
    }
  },
  
  endDate: Date,
  
  timezone: {
    type: String,
    default: 'UTC'
  },
  
  // Frequency-specific Configuration
  hourlyConfig: {
    interval: {
      type: Number,
      min: 1,
      max: 23
    },
    minute: {
      type: Number,
      min: 0,
      max: 59,
      default: 0
    }
  },
  
  dailyConfig: {
    time: String, // HH:mm format
    everyNDays: {
      type: Number,
      default: 1
    },
    weekdaysOnly: {
      type: Boolean,
      default: false
    }
  },
  
  weeklyConfig: {
    daysOfWeek: [{
      type: Number,
      min: 0,
      max: 6
    }],
    time: String
  },
  
  monthlyConfig: {
    dayOfMonth: {
      type: Number,
      min: 1,
      max: 31
    },
    weekOfMonth: {
      type: Number,
      min: 1,
      max: 5
    },
    dayOfWeek: {
      type: Number,
      min: 0,
      max: 6
    },
    time: String,
    lastDayOfMonth: Boolean
  },
  
  quarterlyConfig: {
    quarter: [{
      type: Number,
      min: 1,
      max: 4
    }],
    dayOfQuarter: Number,
    time: String
  },
  
  yearlyConfig: {
    month: {
      type: Number,
      min: 0,
      max: 11
    },
    dayOfMonth: {
      type: Number,
      min: 1,
      max: 31
    },
    time: String
  },
  
  // Custom Cron Expression
  customConfig: {
    cronExpression: String,
    description: String
  },
  
  // Execution Window
  executionWindow: {
    start: String, // HH:mm
    end: String,   // HH:mm
    retryIfMissed: {
      type: Boolean,
      default: true
    }
  },
  
  // Recipients Configuration
  recipients: {
    users: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }],
    
    emails: [{
      email: {
        type: String,
        lowercase: true,
        trim: true
      },
      name: String
    }],
    
    groups: [{
      type: Schema.Types.ObjectId,
      ref: 'Group'
    }],
    
    roles: [String],
    
    dynamicRecipients: {
      enabled: Boolean,
      source: {
        type: String,
        enum: ['query', 'parameter', 'function']
      },
      query: Schema.Types.Mixed,
      parameter: String,
      function: String
    },
    
    cc: [String],
    bcc: [String]
  },
  
  // Delivery Configuration
  delivery: {
    method: {
      type: String,
      enum: ['email', 'webhook', 'storage', 'multiple'],
      default: 'email'
    },
    
    email: {
      subject: String,
      body: String,
      attachReport: {
        type: Boolean,
        default: true
      },
      embedInBody: Boolean,
      format: {
        type: String,
        enum: ['pdf', 'excel', 'csv', 'html'],
        default: 'pdf'
      },
      customTemplate: String
    },
    
    webhook: {
      url: String,
      method: {
        type: String,
        enum: ['POST', 'PUT'],
        default: 'POST'
      },
      headers: Schema.Types.Mixed,
      authentication: {
        type: {
          type: String,
          enum: ['none', 'basic', 'bearer', 'api_key']
        },
        credentials: Schema.Types.Mixed
      },
      retryOnFailure: {
        type: Boolean,
        default: true
      },
      maxRetries: {
        type: Number,
        default: 3
      }
    },
    
    storage: {
      provider: {
        type: String,
        enum: ['s3', 'azure', 'gcs', 'local', 'ftp']
      },
      path: String,
      filename: String,
      format: String,
      encryption: Boolean,
      retention: {
        days: Number,
        deleteAfter: Boolean
      }
    }
  },
  
  // Conditional Execution
  conditions: [{
    type: {
      type: String,
      enum: ['data_exists', 'threshold_met', 'change_detected', 'custom']
    },
    
    dataExists: {
      minimumRows: Number,
      checkQuery: Schema.Types.Mixed
    },
    
    threshold: {
      metric: String,
      operator: {
        type: String,
        enum: ['gt', 'gte', 'lt', 'lte', 'eq', 'ne']
      },
      value: Number
    },
    
    changeDetection: {
      field: String,
      percentageChange: Number,
      comparisonPeriod: String
    },
    
    custom: {
      expression: String,
      function: String
    }
  }],
  
  // Schedule Parameters
  parameters: Schema.Types.Mixed,
  
  // Error Handling
  errorHandling: {
    notifyOnError: {
      type: Boolean,
      default: true
    },
    
    errorRecipients: [{
      type: Schema.Types.ObjectId,
      ref: 'User'
    }],
    
    retryOnError: {
      type: Boolean,
      default: true
    },
    
    maxRetries: {
      type: Number,
      default: 3
    },
    
    retryDelay: {
      type: Number,
      default: 300 // 5 minutes
    },
    
    failureThreshold: {
      count: Number,
      action: {
        type: String,
        enum: ['disable', 'notify', 'escalate']
      }
    }
  },
  
  // Execution History
  lastRunAt: Date,
  lastSuccessAt: Date,
  lastFailureAt: Date,
  nextRunAt: Date,
  
  executionStats: {
    totalRuns: {
      type: Number,
      default: 0
    },
    successfulRuns: {
      type: Number,
      default: 0
    },
    failedRuns: {
      type: Number,
      default: 0
    },
    averageDuration: Number,
    lastDuration: Number
  },
  
  // Metadata
  createdBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  
  lastModifiedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  
  notes: String,
  
  tags: [String]
}, {
  _id: false,
  timestamps: true
});

// Pre-save middleware to calculate next run time
reportScheduleSchema.pre('save', function(next) {
  if (this.isActive && this.frequency) {
    // Calculate nextRunAt based on frequency and configuration
    const now = new Date();
    let nextRun = new Date();
    
    switch (this.frequency) {
      case 'once':
        nextRun = this.startDate;
        break;
        
      case 'hourly':
        const hours = this.hourlyConfig?.interval || 1;
        nextRun.setHours(nextRun.getHours() + hours);
        nextRun.setMinutes(this.hourlyConfig?.minute || 0);
        break;
        
      case 'daily':
        nextRun.setDate(nextRun.getDate() + (this.dailyConfig?.everyNDays || 1));
        if (this.dailyConfig?.time) {
          const [hours, minutes] = this.dailyConfig.time.split(':');
          nextRun.setHours(parseInt(hours), parseInt(minutes), 0, 0);
        }
        break;
        
      // Add more frequency calculations as needed
    }
    
    this.nextRunAt = nextRun > now ? nextRun : now;
  }
  
  next();
});

module.exports = { reportScheduleSchema };