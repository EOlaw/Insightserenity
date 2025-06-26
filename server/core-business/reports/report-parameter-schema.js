// server/core-business/reports/models/schemas/report-parameter-schema.js
/**
 * @file Report Parameter Schema
 * @description Schema for report parameters and user inputs
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Report Parameter Schema
 */
const reportParameterSchema = new Schema({
  // Parameter Identification
  name: {
    type: String,
    required: true,
    trim: true
  },
  
  label: {
    type: String,
    required: true
  },
  
  description: String,
  
  // Parameter Type and Configuration
  type: {
    type: String,
    required: true,
    enum: [
      'text',
      'number',
      'date',
      'dateRange',
      'select',
      'multiSelect',
      'boolean',
      'user',
      'organization',
      'client',
      'project',
      'service'
    ]
  },
  
  dataType: {
    type: String,
    enum: ['string', 'number', 'date', 'boolean', 'array', 'object'],
    default: 'string'
  },
  
  // Input Configuration
  inputConfig: {
    placeholder: String,
    
    // For select/multiSelect
    options: [{
      value: Schema.Types.Mixed,
      label: String,
      group: String,
      metadata: Schema.Types.Mixed
    }],
    
    // Dynamic options
    dynamicOptions: {
      source: {
        type: String,
        enum: ['query', 'api', 'function']
      },
      query: Schema.Types.Mixed,
      endpoint: String,
      function: String,
      valueField: String,
      labelField: String,
      groupField: String,
      filters: Schema.Types.Mixed
    },
    
    // For number inputs
    min: Number,
    max: Number,
    step: Number,
    precision: Number,
    
    // For text inputs
    minLength: Number,
    maxLength: Number,
    pattern: String,
    
    // For date inputs
    minDate: Date,
    maxDate: Date,
    dateFormat: String,
    
    // UI Configuration
    rows: Number, // For textarea
    searchable: Boolean, // For select
    clearable: Boolean,
    multiple: Boolean
  },
  
  // Default Value
  defaultValue: Schema.Types.Mixed,
  
  defaultValueType: {
    type: String,
    enum: ['static', 'dynamic', 'user_attribute', 'context'],
    default: 'static'
  },
  
  dynamicDefault: {
    source: String,
    expression: String,
    userAttribute: String,
    contextField: String
  },
  
  // Validation Rules
  validation: {
    required: {
      type: Boolean,
      default: false
    },
    
    rules: [{
      type: {
        type: String,
        enum: ['min', 'max', 'pattern', 'custom', 'dependency']
      },
      value: Schema.Types.Mixed,
      message: String,
      expression: String
    }],
    
    customValidator: String
  },
  
  // Dependencies
  dependencies: [{
    parameter: String,
    condition: {
      type: String,
      enum: ['equals', 'notEquals', 'contains', 'in', 'notIn', 'exists']
    },
    value: Schema.Types.Mixed,
    action: {
      type: String,
      enum: ['show', 'hide', 'enable', 'disable', 'setValue', 'clearValue']
    },
    targetValue: Schema.Types.Mixed
  }],
  
  // Display Configuration
  display: {
    order: {
      type: Number,
      default: 0
    },
    
    section: String,
    
    width: {
      type: String,
      enum: ['full', 'half', 'third', 'quarter'],
      default: 'full'
    },
    
    hidden: {
      type: Boolean,
      default: false
    },
    
    advanced: {
      type: Boolean,
      default: false
    },
    
    tooltip: String,
    helpText: String,
    
    icon: String,
    
    showIf: {
      condition: String,
      expression: String
    }
  },
  
  // Parameter Usage
  usage: {
    inQuery: {
      type: Boolean,
      default: true
    },
    
    inFilters: {
      type: Boolean,
      default: true
    },
    
    inExport: {
      type: Boolean,
      default: true
    },
    
    inSchedule: {
      type: Boolean,
      default: true
    },
    
    bindTo: [String] // Data source fields to bind to
  },
  
  // Security
  security: {
    sensitive: {
      type: Boolean,
      default: false
    },
    
    encryption: Boolean,
    
    permissions: {
      view: [String], // Roles that can view
      edit: [String]  // Roles that can edit
    },
    
    audit: {
      type: Boolean,
      default: false
    }
  },
  
  // Formatting
  format: {
    type: {
      type: String,
      enum: ['none', 'currency', 'percentage', 'number', 'date', 'custom']
    },
    
    pattern: String,
    
    prefix: String,
    suffix: String,
    
    thousandsSeparator: Boolean,
    decimalPlaces: Number
  },
  
  // Metadata
  tags: [String],
  
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  _id: false,
  timestamps: true
});

module.exports = { reportParameterSchema };