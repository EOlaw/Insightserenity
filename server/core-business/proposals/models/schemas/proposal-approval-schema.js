// server/core-business/proposals/models/schemas/proposal-approval-schema.js
/**
 * @file Proposal Approval Schema
 * @description Schema definition for proposal approval workflow
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Proposal Approval Schema
 */
const proposalApprovalSchema = new Schema({
  required: {
    type: Boolean,
    default: true
  },
  
  workflow: {
    type: {
      type: String,
      enum: ['linear', 'parallel', 'custom'],
      default: 'linear'
    },
    autoApprove: {
      enabled: {
        type: Boolean,
        default: false
      },
      conditions: {
        maxValue: Number,
        categories: [String],
        clients: [{
          type: Schema.Types.ObjectId,
          ref: 'Organization'
        }]
      }
    }
  },
  
  levels: [{
    level: {
      type: Number,
      required: true
    },
    name: String,
    type: {
      type: String,
      enum: ['individual', 'any_of', 'all_of', 'majority'],
      default: 'individual'
    },
    approvers: [{
      user: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      role: String,
      isRequired: {
        type: Boolean,
        default: true
      },
      delegatedTo: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      delegationReason: String
    }],
    minimumRequired: {
      type: Number,
      default: 1
    },
    deadline: {
      value: Number,
      unit: {
        type: String,
        enum: ['hours', 'days', 'weeks'],
        default: 'days'
      }
    },
    escalation: {
      enabled: {
        type: Boolean,
        default: false
      },
      to: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      },
      after: {
        value: Number,
        unit: String
      }
    }
  }],
  
  history: [{
    level: Number,
    approver: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    action: {
      type: String,
      enum: ['approved', 'rejected', 'requested_changes', 'delegated'],
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    comments: String,
    conditions: [String],
    attachments: [{
      name: String,
      url: String
    }],
    changes: [{
      field: String,
      oldValue: Schema.Types.Mixed,
      newValue: Schema.Types.Mixed
    }]
  }],
  
  currentLevel: {
    type: Number,
    default: 1
  },
  
  status: {
    type: String,
    enum: ['pending', 'in_progress', 'approved', 'rejected', 'expired'],
    default: 'pending'
  },
  
  finalApproval: {
    approvedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    approvedAt: Date,
    expiresAt: Date,
    conditions: [String],
    notes: String
  },
  
  rejection: {
    rejectedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    rejectedAt: Date,
    reason: String,
    canResubmit: {
      type: Boolean,
      default: true
    },
    resubmissionGuidance: String
  }
}, {
  _id: false
});

module.exports = { proposalApprovalSchema };