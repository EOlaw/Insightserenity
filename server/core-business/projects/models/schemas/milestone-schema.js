/**
 * @file Milestone Schema
 * @description Schema for project milestones with dependencies and deliverables
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const milestoneSchema = new Schema({
  name: { type: String, required: true },
  description: String,
  type: {
    type: String,
    enum: ['deliverable', 'payment', 'review', 'approval', 'phase_completion'],
    required: true
  },
  phase: String,
  plannedDate: { type: Date, required: true },
  actualDate: Date,
  status: {
    type: String,
    enum: ['pending', 'in_progress', 'completed', 'delayed', 'cancelled'],
    default: 'pending'
  },
  completion: { type: Number, min: 0, max: 100, default: 0 },
  dependencies: [{
    milestone: { type: Schema.Types.ObjectId },
    type: { type: String, enum: ['finish_to_start', 'start_to_start', 'finish_to_finish', 'start_to_finish'] }
  }],
  deliverables: [{
    name: String,
    description: String,
    status: { type: String, enum: ['pending', 'in_progress', 'submitted', 'approved', 'rejected'] },
    submittedAt: Date,
    approvedAt: Date,
    documents: [{ type: Schema.Types.ObjectId, ref: 'Document' }]
  }],
  payment: {
    amount: Number,
    currency: { type: String, default: 'USD' },
    invoiced: { type: Boolean, default: false },
    invoiceId: { type: Schema.Types.ObjectId, ref: 'Invoice' }
  },
  assignedTo: [{ type: Schema.Types.ObjectId, ref: 'User' }],
  blockers: [{
    description: String,
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
    resolvedAt: Date
  }],
  comments: [{
    author: { type: Schema.Types.ObjectId, ref: 'User' },
    content: String,
    createdAt: { type: Date, default: Date.now }
  }]
}, { _id: true, timestamps: true });

module.exports = milestoneSchema;