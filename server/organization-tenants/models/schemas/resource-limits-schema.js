/**
 * @file Resource Limits Schema
 * @description Schema definition for tenant resource allocation and usage tracking
 * @version 1.0.0
 */

const mongoose = require('mongoose');

/**
 * Resource Limits Schema
 * Manages tenant resource quotas and current usage metrics across all platform services
 */
const resourceLimitsSchema = new mongoose.Schema({
  users: { 
    max: { type: Number, default: -1 }, // -1 means unlimited
    current: { type: Number, default: 0 }
  },
  storage: { 
    maxGB: { type: Number, default: -1 },
    currentBytes: { type: Number, default: 0 }
  },
  apiCalls: {
    maxPerMonth: { type: Number, default: -1 },
    currentMonth: { type: Number, default: 0 }
  },
  projects: {
    max: { type: Number, default: -1 },
    current: { type: Number, default: 0 }
  },
  customDomains: {
    max: { type: Number, default: 1 },
    current: { type: Number, default: 0 }
  }
});

module.exports = resourceLimitsSchema;