/**
 * @file Availability Schema
 * @description Schema for consultant availability and project allocation
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const availabilitySchema = new Schema({
  currentAssignment: {
    project: { type: Schema.Types.ObjectId, ref: 'Project' },
    client: { type: Schema.Types.ObjectId, ref: 'Client' },
    role: String,
    allocation: { type: Number, min: 0, max: 100 },
    startDate: Date,
    endDate: Date,
    billable: { type: Boolean, default: true },
    location: {
      type: String,
      enum: ['client_site', 'office', 'remote', 'hybrid']
    }
  },
  
  nextAvailable: Date,
  
  projects: [{
    project: { type: Schema.Types.ObjectId, ref: 'Project' },
    client: { type: Schema.Types.ObjectId, ref: 'Client' },
    allocation: { type: Number, min: 0, max: 100, required: true },
    startDate: { type: Date, required: true },
    endDate: Date,
    status: {
      type: String,
      enum: ['tentative', 'confirmed', 'active', 'completed', 'cancelled'],
      default: 'tentative'
    },
    billable: { type: Boolean, default: true },
    role: String,
    responsibilities: [String]
  }],
  
  calendar: [{
    date: { type: Date, required: true },
    type: {
      type: String,
      enum: ['working', 'leave', 'holiday', 'training', 'blocked', 'tentative']
    },
    availableHours: { type: Number, min: 0, max: 24, default: 8 },
    bookedHours: { type: Number, min: 0, max: 24, default: 0 },
    activities: [{
      type: String,
      hours: Number,
      project: { type: Schema.Types.ObjectId, ref: 'Project' },
      description: String
    }]
  }],
  
  preferences: {
    minimumNotice: { type: Number, default: 14 }, // days
    preferredAllocation: {
      min: { type: Number, default: 80 },
      max: { type: Number, default: 100 }
    },
    blockedClients: [{
      client: { type: Schema.Types.ObjectId, ref: 'Client' },
      reason: String,
      blockedUntil: Date
    }],
    preferredProjects: [String],
    workingHours: {
      start: { type: String, default: '09:00' },
      end: { type: String, default: '18:00' },
      timezone: { type: String, default: 'America/New_York' }
    }
  },
  
  upcomingTimeOff: [{
    type: {
      type: String,
      enum: ['vacation', 'sick', 'personal', 'training', 'conference']
    },
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    approved: { type: Boolean, default: false },
    coverage: { type: Schema.Types.ObjectId, ref: 'User' }
  }],
  
  summary: {
    utilizationPercentage: { type: Number, min: 0, max: 100 },
    billableHours: Number,
    nonBillableHours: Number,
    benchHours: Number,
    lastUpdated: { type: Date, default: Date.now }
  },
  
  forecast: [{
    month: { type: Date, required: true },
    plannedUtilization: { type: Number, min: 0, max: 100 },
    confirmedHours: Number,
    tentativeHours: Number,
    availableHours: Number,
    projects: [{
      project: { type: Schema.Types.ObjectId, ref: 'Project' },
      hours: Number,
      status: {
        type: String,
        enum: ['confirmed', 'tentative', 'proposed']
      }
    }]
  }]
}, { _id: false });

module.exports = availabilitySchema;