/**
 * @file Change Request Schema
 * @description Schema for project change requests with approval workflow
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const changeRequestSchema = new Schema({
  requestNumber: { type: String, unique: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  type: {
    type: String,
    enum: ['scope', 'timeline', 'budget', 'resource', 'technical', 'other'],
    required: true
  },
  impact: {
    scope: String,
    timeline: {
      days: Number,
      description: String
    },
    budget: {
      amount: Number,
      currency: { type: String, default: 'USD' },
      description: String
    },
    resources: String,
    risks: [String]
  },
  justification: { type: String, required: true },
  requestedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  requestedAt: { type: Date, default: Date.now },
  status: {
    type: String,
    enum: ['draft', 'submitted', 'under_review', 'approved', 'rejected', 'implemented'],
    default: 'draft'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  reviewers: [{
    reviewer: { type: Schema.Types.ObjectId, ref: 'User' },
    role: String,
    decision: { type: String, enum: ['pending', 'approved', 'rejected', 'needs_info'] },
    comments: String,
    reviewedAt: Date
  }],
  approvalRequired: { type: Boolean, default: true },
  implementationPlan: String,
  implementedAt: Date,
  documents: [{ type: Schema.Types.ObjectId, ref: 'Document' }]
}, { _id: true, timestamps: true });

module.exports = changeRequestSchema;