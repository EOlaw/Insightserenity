// server/core-business/proposals/models/schemas/proposal-section-schema.js
/**
 * @file Proposal Section Schema
 * @description Schema definition for proposal content sections
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Proposal Section Schema
 */
const proposalSectionSchema = new Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  
  type: {
    type: String,
    required: true,
    enum: [
      'overview', 'approach', 'methodology', 'deliverables',
      'timeline', 'team', 'case_study', 'testimonial',
      'terms', 'appendix', 'custom'
    ]
  },
  
  content: {
    type: String,
    required: true
  },
  
  order: {
    type: Number,
    required: true,
    default: 0
  },
  
  isVisible: {
    type: Boolean,
    default: true
  },
  
  formatting: {
    style: {
      type: String,
      enum: ['standard', 'emphasis', 'highlight', 'quote'],
      default: 'standard'
    },
    columns: {
      type: Number,
      min: 1,
      max: 3,
      default: 1
    }
  },
  
  subsections: [{
    title: String,
    content: String,
    order: Number,
    attachments: [{
      name: String,
      url: String,
      type: String
    }]
  }],
  
  media: [{
    type: {
      type: String,
      enum: ['image', 'video', 'chart', 'diagram'],
      required: true
    },
    url: String,
    caption: String,
    altText: String,
    placement: {
      type: String,
      enum: ['inline', 'left', 'right', 'center', 'full-width'],
      default: 'inline'
    }
  }],
  
  metadata: {
    isRequired: {
      type: Boolean,
      default: false
    },
    editableByClient: {
      type: Boolean,
      default: false
    },
    lastEditedBy: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    lastEditedAt: Date,
    version: {
      type: Number,
      default: 1
    }
  }
}, {
  _id: true,
  timestamps: true
});

module.exports = { proposalSectionSchema };