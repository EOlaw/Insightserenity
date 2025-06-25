// server/core-business/services/models/schemas/service-compliance-schema.js
/**
 * @file Service Compliance Schema
 * @description Schema definition for service compliance and certifications
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service Compliance Schema
 */
const serviceComplianceSchema = new Schema({
  certifications: [{
    name: String,
    issuer: String,
    certificateNumber: String,
    validFrom: Date,
    validUntil: Date,
    documentUrl: String
  }],
  standards: [String],
  regulations: [String],
  dataHandling: {
    classification: {
      type: String,
      enum: ['public', 'internal', 'confidential', 'restricted']
    },
    retention: {
      period: Number,
      unit: String
    },
    encryption: Boolean,
    gdprCompliant: Boolean
  }
}, { _id: false });

module.exports = { serviceComplianceSchema };