// server/core-business/reports/models/schemas/report-datasource-schema.js
/**
 * @file Report DataSource Schema
 * @description Schema for report data source configuration
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Report DataSource Schema
 */
const reportDataSourceSchema = new Schema({
  // Data Source Identification
  name: {
    type: String,
    required: true,
    trim: true
  },
  
  alias: {
    type: String,
    trim: true
  },
  
  type: {
    type: String,
    required: true,
    enum: ['mongodb', 'api', 'file', 'external_db', 'computed', 'joined']
  },
  
  // MongoDB Configuration
  mongodb: {
    database: String,
    collection: String,
    pipeline: [Schema.Types.Mixed],
    query: Schema.Types.Mixed,
    projection: Schema.Types.Mixed,
    options: {
      readPreference: {
        type: String,
        enum: ['primary', 'primaryPreferred', 'secondary', 'secondaryPreferred', 'nearest']
      },
      maxTimeMS: Number,
      allowDiskUse: Boolean
    }
  },
  
  // API Configuration
  api: {
    endpoint: String,
    method: {
      type: String,
      enum: ['GET', 'POST', 'PUT', 'DELETE']
    },
    headers: Schema.Types.Mixed,
    authentication: {
      type: {
        type: String,
        enum: ['none', 'basic', 'bearer', 'api_key', 'oauth2']
      },
      credentials: {
        username: String,
        password: String,
        token: String,
        apiKey: String,
        oauth: {
          clientId: String,
          clientSecret: String,
          tokenUrl: String,
          scope: String
        }
      }
    },
    requestBody: Schema.Types.Mixed,
    queryParams: Schema.Types.Mixed,
    responseMapping: {
      dataPath: String,
      totalPath: String,
      errorPath: String
    },
    pagination: {
      type: {
        type: String,
        enum: ['offset', 'page', 'cursor']
      },
      pageParam: String,
      limitParam: String,
      pageSize: Number
    },
    timeout: {
      type: Number,
      default: 30000
    },
    retries: {
      type: Number,
      default: 3
    }
  },
  
  // File Configuration
  file: {
    path: String,
    format: {
      type: String,
      enum: ['csv', 'json', 'xml', 'excel', 'parquet']
    },
    encoding: {
      type: String,
      default: 'utf-8'
    },
    delimiter: String,
    hasHeaders: Boolean,
    sheet: String, // For Excel files
    columns: [{
      name: String,
      type: String,
      format: String
    }]
  },
  
  // External Database Configuration
  externalDb: {
    type: {
      type: String,
      enum: ['mysql', 'postgresql', 'mssql', 'oracle', 'redshift', 'bigquery']
    },
    connection: {
      host: String,
      port: Number,
      database: String,
      username: String,
      password: String,
      ssl: Boolean,
      options: Schema.Types.Mixed
    },
    query: String,
    storedProcedure: String,
    parameters: [Schema.Types.Mixed]
  },
  
  // Computed Field Configuration
  computed: {
    formula: String,
    dependencies: [String], // Other data source names
    language: {
      type: String,
      enum: ['javascript', 'sql', 'python'],
      default: 'javascript'
    },
    script: String
  },
  
  // Join Configuration
  joined: {
    primarySource: String,
    secondarySource: String,
    joinType: {
      type: String,
      enum: ['inner', 'left', 'right', 'full']
    },
    joinConditions: [{
      primaryField: String,
      secondaryField: String,
      operator: {
        type: String,
        enum: ['equals', 'notEquals', 'gt', 'gte', 'lt', 'lte']
      }
    }]
  },
  
  // Data Transformation
  transformations: [{
    type: {
      type: String,
      enum: ['map', 'filter', 'aggregate', 'pivot', 'unpivot', 'custom']
    },
    field: String,
    operation: String,
    parameters: Schema.Types.Mixed,
    script: String
  }],
  
  // Field Mapping
  fieldMappings: [{
    sourceField: String,
    targetField: String,
    dataType: {
      type: String,
      enum: ['string', 'number', 'boolean', 'date', 'array', 'object']
    },
    format: String,
    defaultValue: Schema.Types.Mixed,
    transformation: String
  }],
  
  // Caching Configuration
  cache: {
    enabled: {
      type: Boolean,
      default: false
    },
    duration: {
      type: Number,
      default: 300 // 5 minutes
    },
    key: String,
    invalidateOn: [String] // Events that invalidate cache
  },
  
  // Security and Access
  security: {
    encryption: {
      enabled: Boolean,
      algorithm: String
    },
    sensitiveFields: [String],
    accessControl: {
      roles: [String],
      users: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
      }]
    }
  },
  
  // Validation Rules
  validation: {
    required: [String],
    rules: [{
      field: String,
      rule: String,
      message: String
    }],
    skipInvalid: Boolean
  },
  
  // Error Handling
  errorHandling: {
    onError: {
      type: String,
      enum: ['fail', 'skip', 'default', 'retry'],
      default: 'fail'
    },
    defaultValues: Schema.Types.Mixed,
    retryAttempts: Number,
    retryDelay: Number
  },
  
  // Performance Settings
  performance: {
    batchSize: Number,
    parallel: Boolean,
    maxConcurrency: Number,
    timeout: Number
  },
  
  // Metadata
  isActive: {
    type: Boolean,
    default: true
  },
  
  order: {
    type: Number,
    default: 0
  },
  
  description: String,
  
  tags: [String]
}, {
  _id: false,
  timestamps: true
});

module.exports = { reportDataSourceSchema };