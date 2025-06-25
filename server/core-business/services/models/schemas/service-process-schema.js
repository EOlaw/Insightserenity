// server/core-business/services/models/schemas/service-process-schema.js
/**
 * @file Service Process Schema
 * @description Schema definition for service process and methodology
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service Process Schema
 */
const serviceProcessSchema = new Schema({
  methodology: {
    type: String,
    enum: ['agile', 'waterfall', 'hybrid', 'lean', 'custom']
  },
  phases: [{
    name: {
      type: String,
      required: true
    },
    description: String,
    duration: {
      estimated: Number,
      unit: String
    },
    deliverables: [String],
    order: Number
  }],
  qualityChecks: [{
    name: String,
    description: String,
    frequency: String,
    responsible: String
  }]
}, { _id: false });

module.exports = { serviceProcessSchema };