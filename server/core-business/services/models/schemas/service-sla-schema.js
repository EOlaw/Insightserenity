// server/core-business/services/models/schemas/service-sla-schema.js
/**
 * @file Service SLA Schema
 * @description Schema definition for service level agreements
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service SLA Schema
 */
const serviceSLASchema = new Schema({
  responseTime: {
    value: Number,
    unit: {
      type: String,
      enum: ['minutes', 'hours', 'days'],
      default: 'hours'
    }
  },
  resolutionTime: {
    value: Number,
    unit: {
      type: String,
      enum: ['hours', 'days', 'weeks'],
      default: 'days'
    }
  },
  availability: {
    percentage: {
      type: Number,
      min: 0,
      max: 100,
      default: 99
    },
    businessHoursOnly: {
      type: Boolean,
      default: false
    }
  },
  supportLevel: {
    type: String,
    enum: ['basic', 'standard', 'premium', 'enterprise'],
    default: 'standard'
  },
  penalties: [{
    condition: String,
    penalty: String,
    maxPenalty: Number
  }]
}, { _id: false });

module.exports = { serviceSLASchema };