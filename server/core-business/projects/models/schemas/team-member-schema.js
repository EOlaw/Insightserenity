/**
 * @file Team Member Schema
 * @description Schema for project team members with allocation and performance tracking
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const teamMemberSchema = new Schema({
  consultant: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  role: {
    type: String,
    required: true,
    enum: ['project_manager', 'lead_consultant', 'senior_consultant', 'consultant', 'analyst', 'specialist', 'advisor']
  },
  allocation: {
    percentage: { type: Number, min: 0, max: 100, required: true },
    hoursPerWeek: { type: Number, min: 0, max: 60 },
    startDate: { type: Date, required: true },
    endDate: Date
  },
  billable: { type: Boolean, default: true },
  hourlyRate: {
    amount: { type: Number, min: 0 },
    currency: { type: String, default: 'USD' }
  },
  responsibilities: [String],
  skills: [String],
  approvalStatus: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  approvedAt: Date,
  performance: {
    rating: { type: Number, min: 1, max: 5 },
    feedback: String,
    lastReviewDate: Date
  }
}, { _id: true, timestamps: true });

module.exports = teamMemberSchema;