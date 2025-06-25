// server/core-business/services/models/schemas/service-pricing-schema.js
/**
 * @file Service Pricing Schema
 * @description Schema definition for service pricing structure
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;
const constants = require('../../../../shared/config/constants');

/**
 * Service Pricing Schema
 */
const servicePricingSchema = new Schema({
  basePrice: {
    type: Number,
    required: true,
    min: 0
  },
  currency: {
    type: String,
    enum: constants.BILLING.CURRENCIES_ENUM,
    default: 'USD',
    uppercase: true
  },
  billingCycle: {
    type: String,
    enum: ['one_time', 'hourly', 'daily', 'weekly', 'monthly', 'quarterly', 'yearly', 'custom'],
    required: true
  },
  customBillingDays: {
    type: Number,
    min: 1,
    max: 365
  },
  discounts: [{
    name: String,
    type: {
      type: String,
      enum: ['percentage', 'fixed'],
      required: true
    },
    value: {
      type: Number,
      required: true,
      min: 0
    },
    conditions: {
      minQuantity: Number,
      minDuration: Number,
      customerType: [String],
      validFrom: Date,
      validUntil: Date
    },
    active: {
      type: Boolean,
      default: true
    }
  }],
  taxable: {
    type: Boolean,
    default: true
  },
  taxRate: {
    type: Number,
    min: 0,
    max: 100
  }
}, { _id: false });

module.exports = { servicePricingSchema };