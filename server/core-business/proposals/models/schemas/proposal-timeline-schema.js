// server/core-business/proposals/models/schemas/proposal-timeline-schema.js
/**
 * @file Proposal Timeline Schema
 * @description Schema definition for proposal timeline and project phases
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Proposal Timeline Schema
 */
const proposalTimelineSchema = new Schema({
  startDate: {
    type: Date,
    required: true
  },
  
  endDate: {
    type: Date,
    required: true
  },
  
  duration: {
    value: {
      type: Number,
      required: true,
      min: 1
    },
    unit: {
      type: String,
      enum: ['days', 'weeks', 'months', 'quarters', 'years'],
      default: 'weeks'
    }
  },
  
  isFlexible: {
    type: Boolean,
    default: false
  },
  
  bufferTime: {
    value: {
      type: Number,
      default: 0
    },
    unit: {
      type: String,
      enum: ['days', 'weeks', 'months'],
      default: 'days'
    }
  },
  
  phases: [{
    name: {
      type: String,
      required: true
    },
    description: String,
    order: {
      type: Number,
      required: true
    },
    startDate: Date,
    endDate: Date,
    duration: {
      value: Number,
      unit: {
        type: String,
        enum: ['days', 'weeks', 'months'],
        default: 'weeks'
      }
    },
    deliverables: [{
      name: String,
      description: String,
      dueDate: Date
    }],
    milestones: [{
      name: String,
      date: Date,
      isCritical: {
        type: Boolean,
        default: false
      },
      paymentTrigger: {
        type: Boolean,
        default: false
      }
    }],
    resources: [{
      role: String,
      allocation: Number,
      skills: [String]
    }],
    dependencies: [{
      phase: String,
      type: {
        type: String,
        enum: ['finish_to_start', 'start_to_start', 'finish_to_finish', 'start_to_finish'],
        default: 'finish_to_start'
      },
      lagTime: {
        value: Number,
        unit: String
      }
    }],
    risks: [{
      description: String,
      impact: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical']
      },
      probability: {
        type: String,
        enum: ['low', 'medium', 'high']
      },
      mitigation: String
    }]
  }],
  
  criticalPath: [{
    phase: String,
    duration: Number,
    slack: Number
  }],
  
  constraints: [{
    type: {
      type: String,
      enum: ['deadline', 'resource', 'budget', 'dependency', 'external'],
      required: true
    },
    description: String,
    impact: String
  }],
  
  assumptions: [String],
  
  workingDays: {
    monday: { type: Boolean, default: true },
    tuesday: { type: Boolean, default: true },
    wednesday: { type: Boolean, default: true },
    thursday: { type: Boolean, default: true },
    friday: { type: Boolean, default: true },
    saturday: { type: Boolean, default: false },
    sunday: { type: Boolean, default: false }
  },
  
  holidays: [{
    date: Date,
    name: String,
    isObserved: {
      type: Boolean,
      default: true
    }
  }],
  
  notes: String
}, {
  _id: false
});

module.exports = { proposalTimelineSchema };