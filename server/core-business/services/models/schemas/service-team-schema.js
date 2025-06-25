// server/core-business/services/models/schemas/service-team-schema.js
/**
 * @file Service Team Schema
 * @description Schema definition for service team structure
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service Team Schema
 */
const serviceTeamSchema = new Schema({
  minSize: {
    type: Number,
    default: 1,
    min: 1
  },
  maxSize: Number,
  roles: [{
    role: {
      type: String,
      required: true
    },
    count: {
      type: Number,
      default: 1,
      min: 1
    },
    level: {
      type: String,
      enum: ['junior', 'mid', 'senior', 'lead', 'expert']
    },
    responsibilities: [String],
    isOptional: {
      type: Boolean,
      default: false
    }
  }]
}, { _id: false });

module.exports = { serviceTeamSchema };