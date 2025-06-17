/**
 * @file Risk Schema
 * @description Schema for project risk management with mitigation tracking
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const riskSchema = new Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  category: {
    type: String,
    enum: ['technical', 'financial', 'operational', 'strategic', 'compliance', 'reputational'],
    required: true
  },
  probability: {
    type: String,
    enum: ['very_low', 'low', 'medium', 'high', 'very_high'],
    required: true
  },
  impact: {
    type: String,
    enum: ['negligible', 'minor', 'moderate', 'major', 'severe'],
    required: true
  },
  status: {
    type: String,
    enum: ['identified', 'analyzing', 'mitigating', 'monitoring', 'closed'],
    default: 'identified'
  },
  mitigation: {
    strategy: String,
    actions: [{
      description: String,
      assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
      dueDate: Date,
      status: { type: String, enum: ['pending', 'in_progress', 'completed'] }
    }],
    contingencyPlan: String
  },
  identifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  identifiedAt: { type: Date, default: Date.now },
  reviewedAt: Date,
  closedAt: Date,
  riskScore: Number // Calculated from probability × impact
}, { _id: true, timestamps: true });

module.exports = riskSchema;