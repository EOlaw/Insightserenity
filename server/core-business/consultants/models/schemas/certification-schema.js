/**
 * @file Certification Schema
 * @description Schema for professional certifications and credentials
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const certificationSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  issuingOrganization: {
    type: String,
    required: true
  },
  credentialId: {
    type: String,
    trim: true
  },
  category: {
    type: String,
    required: true,
    enum: ['technical', 'project_management', 'industry', 'methodology', 'security', 'compliance', 'other']
  },
  level: {
    type: String,
    enum: ['foundation', 'associate', 'professional', 'expert', 'master']
  },
  issueDate: {
    type: Date,
    required: true
  },
  expiryDate: Date,
  isActive: {
    type: Boolean,
    default: true
  },
  renewalRequired: {
    type: Boolean,
    default: false
  },
  continuingEducation: {
    required: { type: Boolean, default: false },
    hoursRequired: Number,
    hoursCompleted: Number,
    deadline: Date
  },
  verificationUrl: String,
  documentUrl: String,
  cost: {
    exam: Number,
    training: Number,
    renewal: Number,
    currency: { type: String, default: 'USD' }
  },
  attempts: [{
    date: Date,
    passed: Boolean,
    score: Number,
    percentile: Number
  }],
  maintenanceActivities: [{
    activity: String,
    date: Date,
    credits: Number,
    verified: { type: Boolean, default: false }
  }],
  relatedSkills: [String],
  industryRecognition: {
    type: String,
    enum: ['low', 'medium', 'high', 'very_high']
  }
}, { _id: true, timestamps: true });

module.exports = certificationSchema;