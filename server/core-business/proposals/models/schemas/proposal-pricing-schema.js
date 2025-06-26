// server/core-business/proposals/models/schemas/proposal-pricing-schema.js
/**
 * @file Proposal Pricing Schema
 * @description Schema definition for proposal pricing and financial details
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Proposal Pricing Schema
 */
const proposalPricingSchema = new Schema({
  currency: {
    type: String,
    required: true,
    uppercase: true,
    default: 'USD',
    enum: ['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'INR', 'JPY', 'CNY']
  },
  
  model: {
    type: String,
    required: true,
    enum: ['fixed', 'hourly', 'retainer', 'milestone', 'subscription', 'hybrid'],
    default: 'fixed'
  },
  
  items: [{
    type: {
      type: String,
      enum: ['service', 'product', 'expense', 'discount', 'tax'],
      required: true
    },
    name: {
      type: String,
      required: true
    },
    description: String,
    category: String,
    quantity: {
      type: Number,
      required: true,
      min: 0,
      default: 1
    },
    unitPrice: {
      type: Number,
      required: true,
      min: 0
    },
    unit: {
      type: String,
      enum: ['hour', 'day', 'week', 'month', 'project', 'unit', 'license'],
      default: 'unit'
    },
    discount: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    discountType: {
      type: String,
      enum: ['percentage', 'fixed'],
      default: 'percentage'
    },
    total: {
      type: Number,
      required: true,
      min: 0
    },
    notes: String,
    isOptional: {
      type: Boolean,
      default: false
    },
    dependencies: [String]
  }],
  
  breakdown: {
    services: {
      type: Number,
      default: 0
    },
    products: {
      type: Number,
      default: 0
    },
    expenses: {
      type: Number,
      default: 0
    },
    recurring: {
      type: Number,
      default: 0
    }
  },
  
  subtotal: {
    type: Number,
    required: true,
    default: 0,
    min: 0
  },
  
  discount: {
    type: Number,
    default: 0,
    min: 0
  },
  
  discountType: {
    type: String,
    enum: ['percentage', 'fixed'],
    default: 'fixed'
  },
  
  taxRate: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  
  taxAmount: {
    type: Number,
    default: 0,
    min: 0
  },
  
  total: {
    type: Number,
    required: true,
    default: 0,
    min: 0
  },
  
  paymentTerms: {
    type: {
      type: String,
      enum: ['net_15', 'net_30', 'net_45', 'net_60', 'net_90', 'immediate', 'milestone', 'custom'],
      default: 'net_30'
    },
    customTerms: String,
    schedule: [{
      milestone: String,
      percentage: {
        type: Number,
        min: 0,
        max: 100
      },
      amount: Number,
      dueDate: Date,
      description: String
    }],
    lateFees: {
      enabled: {
        type: Boolean,
        default: false
      },
      percentage: {
        type: Number,
        min: 0,
        max: 100
      },
      gracePeriod: {
        type: Number,
        default: 0
      }
    }
  },
  
  validityPeriod: {
    type: Number,
    default: 30,
    min: 1
  },
  
  notes: String,
  
  alternatives: [{
    name: String,
    description: String,
    total: Number,
    savings: Number,
    features: [String]
  }]
}, {
  _id: false
});

module.exports = { proposalPricingSchema };