/**
 * @file Tenant Settings Schema
 * @description Schema definition for tenant configuration settings
 * @version 1.0.0
 */

const mongoose = require('mongoose');

/**
 * Tenant Settings Schema
 * Defines configuration options for tenant features, security, notifications, and data retention
 */
const tenantSettingsSchema = new mongoose.Schema({
  features: {
    multiLanguage: { type: Boolean, default: false },
    advancedAnalytics: { type: Boolean, default: false },
    customIntegrations: { type: Boolean, default: false },
    whiteLabel: { type: Boolean, default: false },
    sso: { type: Boolean, default: false },
    apiAccess: { type: Boolean, default: true },
    customReports: { type: Boolean, default: false },
    dataExport: { type: Boolean, default: true }
  },
  security: {
    enforceIPWhitelist: { type: Boolean, default: false },
    ipWhitelist: [{ type: String }],
    enforce2FA: { type: Boolean, default: false },
    passwordPolicy: {
      minLength: { type: Number, default: 8 },
      requireUppercase: { type: Boolean, default: true },
      requireLowercase: { type: Boolean, default: true },
      requireNumbers: { type: Boolean, default: true },
      requireSpecialChars: { type: Boolean, default: false },
      expiryDays: { type: Number, default: 0 } // 0 means no expiry
    },
    sessionTimeout: { type: Number, default: 1800 }, // 30 minutes in seconds
    maxLoginAttempts: { type: Number, default: 5 }
  },
  notifications: {
    email: {
      systemAlerts: { type: Boolean, default: true },
      usageAlerts: { type: Boolean, default: true },
      billingAlerts: { type: Boolean, default: true },
      securityAlerts: { type: Boolean, default: true }
    },
    webhook: {
      enabled: { type: Boolean, default: false },
      url: { type: String },
      secret: { type: String },
      events: [{ type: String }]
    }
  },
  dataRetention: {
    auditLogDays: { type: Number, default: 365 },
    activityLogDays: { type: Number, default: 90 },
    deletedDataDays: { type: Number, default: 30 }
  }
});

module.exports = tenantSettingsSchema;