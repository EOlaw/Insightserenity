// server/core-business/services/models/schemas/service-requirement-schema.js
/**
 * @file Service Requirement Schema
 * @description Schema definition for service requirements
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service Requirement Schema
 */
const serviceRequirementSchema = new Schema({
  type: {
    type: String,
    enum: ['skill', 'certification', 'experience', 'tool', 'resource', 'other'],
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: String,
  level: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced', 'expert']
  },
  isMandatory: {
    type: Boolean,
    default: true
  },
  alternatives: [String]
}, { _id: false });

module.exports = { serviceRequirementSchema };