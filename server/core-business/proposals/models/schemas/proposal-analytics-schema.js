// server/core-business/proposals/models/schemas/proposal-analytics-schema.js
/**
 * @file Proposal Analytics Schema
 * @description Schema definition for proposal analytics and tracking metrics
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Proposal Analytics Schema
 */
const proposalAnalyticsSchema = new Schema({
  views: {
    total: {
      type: Number,
      default: 0
    },
    unique: {
      type: Number,
      default: 0
    },
    firstViewedAt: Date,
    lastViewedAt: Date,
    averageDuration: {
      type: Number,
      default: 0 // in seconds
    },
    bySection: [{
      section: String,
      views: Number,
      averageDuration: Number
    }],
    byDevice: {
      desktop: { type: Number, default: 0 },
      mobile: { type: Number, default: 0 },
      tablet: { type: Number, default: 0 }
    },
    byLocation: [{
      country: String,
      city: String,
      views: Number
    }]
  },
  
  engagement: {
    downloads: {
      total: { type: Number, default: 0 },
      documents: [{
        name: String,
        count: Number,
        lastDownloadedAt: Date
      }]
    },
    forwards: {
      count: { type: Number, default: 0 },
      recipients: [{
        email: String,
        forwardedAt: Date
      }]
    },
    prints: {
      count: { type: Number, default: 0 },
      lastPrintedAt: Date
    },
    shares: {
      internal: { type: Number, default: 0 },
      external: { type: Number, default: 0 }
    },
    timeOnProposal: {
      total: { type: Number, default: 0 }, // in seconds
      sessions: [{
        startTime: Date,
        endTime: Date,
        duration: Number,
        sectionsViewed: [String]
      }]
    }
  },
  
  interactions: {
    questions: {
      total: { type: Number, default: 0 },
      answered: { type: Number, default: 0 },
      avgResponseTime: Number // in hours
    },
    feedback: {
      positive: { type: Number, default: 0 },
      negative: { type: Number, default: 0 },
      neutral: { type: Number, default: 0 }
    },
    meetings: {
      scheduled: { type: Number, default: 0 },
      completed: { type: Number, default: 0 },
      outcomes: [{
        date: Date,
        outcome: String,
        notes: String
      }]
    }
  },
  
  conversion: {
    status: {
      type: String,
      enum: ['pending', 'won', 'lost', 'stalled'],
      default: 'pending'
    },
    isConverted: {
      type: Boolean,
      default: false
    },
    convertedAt: Date,
    daysToConvert: Number,
    lostReason: {
      category: {
        type: String,
        enum: ['price', 'competition', 'timing', 'scope', 'relationship', 'other']
      },
      details: String,
      competitor: String
    },
    winFactors: [String],
    decisionMakers: [{
      name: String,
      role: String,
      influence: {
        type: String,
        enum: ['champion', 'supporter', 'neutral', 'detractor']
      }
    }]
  },
  
  performance: {
    score: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    benchmarks: {
      industryAverage: Number,
      organizationAverage: Number,
      teamAverage: Number
    },
    strengths: [String],
    weaknesses: [String],
    recommendations: [String]
  },
  
  clientActivity: {
    lastActivity: Date,
    activityScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0
    },
    pattern: {
      type: String,
      enum: ['highly_engaged', 'moderately_engaged', 'low_engagement', 'no_engagement'],
      default: 'no_engagement'
    },
    keyActions: [{
      action: String,
      timestamp: Date,
      significance: {
        type: String,
        enum: ['low', 'medium', 'high']
      }
    }]
  },
  
  followUp: {
    scheduled: [{
      date: Date,
      type: {
        type: String,
        enum: ['email', 'call', 'meeting', 'reminder']
      },
      assignedTo: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      completed: {
        type: Boolean,
        default: false
      },
      outcome: String
    }],
    lastContactAt: Date,
    nextActionDue: Date,
    automatedReminders: {
      enabled: {
        type: Boolean,
        default: true
      },
      frequency: {
        value: Number,
        unit: {
          type: String,
          enum: ['days', 'weeks'],
          default: 'days'
        }
      },
      sentCount: {
        type: Number,
        default: 0
      }
    }
  },
  
  roi: {
    estimatedValue: Number,
    actualValue: Number,
    timeInvested: Number, // in hours
    resourcesCost: Number,
    profitMargin: Number,
    scorecard: {
      efficiency: Number,
      effectiveness: Number,
      impact: Number
    }
  },
  
  sentAt: Date,
  firstResponseAt: Date,
  lastUpdateAt: Date
}, {
  _id: false
});

module.exports = { proposalAnalyticsSchema };