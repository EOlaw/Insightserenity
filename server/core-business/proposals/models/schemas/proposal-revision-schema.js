// server/core-business/proposals/models/schemas/proposal-revision-schema.js
/**
 * @file Proposal Revision Schema
 * @description Schema definition for tracking proposal revisions and changes
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Proposal Revision Schema
 */
const proposalRevisionSchema = new Schema({
  version: {
    type: String,
    required: true
  },
  
  revisionNumber: {
    type: Number,
    required: true
  },
  
  type: {
    type: String,
    enum: ['minor', 'major', 'patch'],
    default: 'minor'
  },
  
  status: {
    type: String,
    enum: ['draft', 'review', 'approved', 'superseded'],
    default: 'draft'
  },
  
  changes: {
    summary: {
      type: String,
      required: true
    },
    sections: [{
      section: String,
      type: {
        type: String,
        enum: ['added', 'modified', 'removed'],
        required: true
      },
      description: String,
      before: Schema.Types.Mixed,
      after: Schema.Types.Mixed
    }],
    pricing: {
      changed: {
        type: Boolean,
        default: false
      },
      previousTotal: Number,
      newTotal: Number,
      percentageChange: Number,
      itemsAdded: [String],
      itemsRemoved: [String],
      itemsModified: [String]
    },
    timeline: {
      changed: {
        type: Boolean,
        default: false
      },
      previousDuration: {
        value: Number,
        unit: String
      },
      newDuration: {
        value: Number,
        unit: String
      },
      milestonesAffected: [String]
    },
    team: {
      changed: {
        type: Boolean,
        default: false
      },
      membersAdded: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
      }],
      membersRemoved: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
      }],
      rolesChanged: [{
        user: {
          type: Schema.Types.ObjectId,
          ref: 'User'
        },
        previousRole: String,
        newRole: String
      }]
    }
  },
  
  reason: {
    type: String,
    required: true
  },
  
  requestedBy: {
    type: {
      type: String,
      enum: ['client', 'internal', 'compliance', 'market'],
      required: true
    },
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    details: String
  },
  
  impact: {
    scope: {
      type: String,
      enum: ['minor', 'moderate', 'significant', 'critical'],
      default: 'minor'
    },
    areas: [{
      type: String,
      enum: ['pricing', 'timeline', 'deliverables', 'team', 'terms', 'approach']
    }],
    riskAssessment: String
  },
  
  review: {
    required: {
      type: Boolean,
      default: true
    },
    reviewedBy: [{
      user: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      reviewedAt: Date,
      decision: {
        type: String,
        enum: ['approved', 'rejected', 'needs_changes']
      },
      comments: String
    }],
    approvedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    approvedAt: Date
  },
  
  metadata: {
    createdBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    comparison: {
      enabled: {
        type: Boolean,
        default: true
      },
      highlightChanges: {
        type: Boolean,
        default: true
      },
      trackingId: String
    },
    notes: String
  }
}, {
  _id: true,
  timestamps: true
});

module.exports = { proposalRevisionSchema };