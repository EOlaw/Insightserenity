// server/core-business/services/models/schemas/service-review-schema.js
/**
 * @file Service Review Schema
 * @description Schema definition for service reviews and feedback
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service Review Schema
 */
const serviceReviewSchema = new Schema({
  client: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  project: {
    type: Schema.Types.ObjectId,
    ref: 'Project'
  },
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  feedback: {
    positive: String,
    improvement: String,
    recommendation: Boolean
  },
  reviewedAt: {
    type: Date,
    default: Date.now
  },
  verified: {
    type: Boolean,
    default: false
  }
}, { _id: false });

module.exports = { serviceReviewSchema };