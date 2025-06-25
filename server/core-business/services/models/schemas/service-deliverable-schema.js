// server/core-business/services/models/schemas/service-deliverable-schema.js
/**
 * @file Service Deliverable Schema
 * @description Schema definition for service deliverables
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service Deliverable Schema
 */
const serviceDeliverableSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: String,
  type: {
    type: String,
    enum: ['document', 'report', 'presentation', 'code', 'design', 'data', 'other'],
    required: true
  },
  format: String,
  estimatedDeliveryDays: {
    type: Number,
    min: 0
  },
  isRequired: {
    type: Boolean,
    default: true
  },
  order: {
    type: Number,
    default: 0
  }
}, { _id: false });

module.exports = { serviceDeliverableSchema };