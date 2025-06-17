/**
 * @file Budget Item Schema
 * @description Schema for project budget items with approval tracking
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const budgetItemSchema = new Schema({
  category: {
    type: String,
    required: true,
    enum: ['labor', 'travel', 'materials', 'subcontractor', 'software', 'equipment', 'other']
  },
  name: { type: String, required: true },
  description: String,
  plannedAmount: { type: Number, required: true, min: 0 },
  actualAmount: { type: Number, default: 0, min: 0 },
  unit: { type: String, enum: ['hours', 'days', 'units', 'fixed'] },
  quantity: Number,
  rate: Number,
  approved: { type: Boolean, default: false },
  approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  approvedAt: Date,
  notes: String
}, { _id: true });

module.exports = budgetItemSchema;