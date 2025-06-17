/**
 * @file Communication Log Schema
 * @description Schema for tracking project communications and meetings
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const communicationLogSchema = new Schema({
  type: {
    type: String,
    enum: ['meeting', 'email', 'call', 'presentation', 'report', 'other'],
    required: true
  },
  subject: { type: String, required: true },
  date: { type: Date, required: true },
  duration: Number, // in minutes
  participants: [{
    person: { type: Schema.Types.ObjectId, ref: 'User' },
    external: {
      name: String,
      email: String,
      organization: String,
      role: String
    }
  }],
  summary: String,
  keyDecisions: [String],
  actionItems: [{
    description: String,
    assignedTo: { type: Schema.Types.ObjectId, ref: 'User' },
    dueDate: Date,
    status: { type: String, enum: ['pending', 'in_progress', 'completed'], default: 'pending' }
  }],
  attachments: [{
    name: String,
    url: String,
    type: String
  }],
  recordedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  visibility: {
    type: String,
    enum: ['internal', 'client_visible', 'public'],
    default: 'internal'
  }
}, { _id: true, timestamps: true });

module.exports = communicationLogSchema;