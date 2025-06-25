// server/core-business/services/models/schemas/service-availability-schema.js
/**
 * @file Service Availability Schema
 * @description Schema definition for service availability and capacity
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Service Availability Schema
 */
const serviceAvailabilitySchema = new Schema({
  status: {
    type: String,
    enum: ['available', 'limited', 'booked', 'discontinued', 'coming_soon'],
    default: 'available'
  },
  capacity: {
    current: {
      type: Number,
      default: 0,
      min: 0
    },
    maximum: Number,
    unit: String
  },
  leadTime: {
    value: Number,
    unit: {
      type: String,
      enum: ['days', 'weeks', 'months']
    }
  },
  blackoutDates: [{
    startDate: Date,
    endDate: Date,
    reason: String
  }]
}, { _id: false });

module.exports = { serviceAvailabilitySchema };