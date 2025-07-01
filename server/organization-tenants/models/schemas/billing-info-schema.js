/**
 * @file Billing Information Schema
 * @description Schema definition for tenant billing and payment information
 * @version 1.0.0
 */

const mongoose = require('mongoose');

/**
 * Billing Information Schema
 * Manages payment processor integration, billing addresses, and financial account details
 */
const billingInfoSchema = new mongoose.Schema({
  customerId: { type: String }, // Stripe/payment processor customer ID
  subscriptionId: { type: String },
  paymentMethodId: { type: String },
  billingEmail: { type: String },
  billingAddress: {
    line1: String,
    line2: String,
    city: String,
    state: String,
    postalCode: String,
    country: String
  },
  taxId: { type: String },
  invoicePrefix: { type: String }
});

module.exports = billingInfoSchema;