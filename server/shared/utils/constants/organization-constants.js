/**
 * @file Organization Constants
 * @description Shared constants for organization-related functionality
 * @version 1.0.0
 */

const ORGANIZATION_CONSTANTS = {
  // Business Types
  BUSINESS_TYPES: [
    'corporation',
    'llc',
    'partnership',
    'sole_proprietorship',
    'non_profit',
    'government',
    'educational',
    'other'
  ],

  // Organization Types
  ORGANIZATION_TYPES: [
    'enterprise',
    'mid_market',
    'small_business',
    'startup',
    'non_profit',
    'government',
    'educational'
  ],

  // Subscription Plans
  SUBSCRIPTION_PLANS: {
    FREE: 'free',
    STARTER: 'starter',
    GROWTH: 'growth',
    PROFESSIONAL: 'professional',
    ENTERPRISE: 'enterprise',
    CUSTOM: 'custom'
  },

  // Subscription Status
  SUBSCRIPTION_STATUS: {
    TRIAL: 'trial',
    ACTIVE: 'active',
    PAST_DUE: 'past_due',
    CANCELED: 'canceled',
    SUSPENDED: 'suspended',
    PENDING: 'pending'
  },

  // Member Roles
  MEMBER_ROLES: {
    OWNER: 'owner',
    ADMIN: 'admin',
    MANAGER: 'manager',
    MEMBER: 'member',
    VIEWER: 'viewer',
    GUEST: 'guest'
  },

  // Role Permissions
  ROLE_PERMISSIONS: {
    owner: ['*'], // All permissions
    admin: [
      'read', 'write', 'delete', 
      'manage_members', 'manage_settings', 
      'view_analytics', 'manage_integrations'
    ],
    manager: [
      'read', 'write', 
      'manage_members', 'view_analytics'
    ],
    member: ['read', 'write'],
    viewer: ['read'],
    guest: ['read']
  },

  // Platform Tiers (for hosted organizations)
  PLATFORM_TIERS: {
    STARTER: {
      name: 'starter',
      displayName: 'Starter',
      maxUsers: 5,
      maxStorage: 5 * 1024 * 1024 * 1024, // 5GB
      maxProjects: 10,
      maxApiCalls: 10000,
      features: ['basic_analytics', 'email_support']
    },
    GROWTH: {
      name: 'growth',
      displayName: 'Growth',
      maxUsers: 20,
      maxStorage: 50 * 1024 * 1024 * 1024, // 50GB
      maxProjects: 50,
      maxApiCalls: 100000,
      features: ['advanced_analytics', 'priority_support', 'api_access', 'custom_branding']
    },
    PROFESSIONAL: {
      name: 'professional',
      displayName: 'Professional',
      maxUsers: 100,
      maxStorage: 500 * 1024 * 1024 * 1024, // 500GB
      maxProjects: 200,
      maxApiCalls: 1000000,
      features: ['advanced_analytics', 'phone_support', 'api_access', 'custom_branding', 'sso', 'advanced_security']
    },
    ENTERPRISE: {
      name: 'enterprise',
      displayName: 'Enterprise',
      maxUsers: -1, // Unlimited
      maxStorage: -1, // Unlimited
      maxProjects: -1, // Unlimited
      maxApiCalls: -1, // Unlimited
      features: ['all']
    }
  },

  // Engagement Levels
  ENGAGEMENT_LEVELS: {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    VERY_HIGH: 'very_high'
  },

  // Health Score Ranges
  HEALTH_SCORE_RANGES: {
    EXCELLENT: { min: 80, max: 100, label: 'excellent' },
    GOOD: { min: 60, max: 79, label: 'good' },
    FAIR: { min: 40, max: 59, label: 'fair' },
    POOR: { min: 0, max: 39, label: 'poor' }
  },

  // Risk Levels
  RISK_LEVELS: {
    LOW: 'low',
    MEDIUM: 'medium',
    HIGH: 'high',
    CRITICAL: 'critical'
  },

  // Activity Types
  ACTIVITY_TYPES: {
    CREATED: 'organization_created',
    UPDATED: 'organization_updated',
    MEMBER_ADDED: 'member_added',
    MEMBER_REMOVED: 'member_removed',
    SUBSCRIPTION_CHANGED: 'subscription_changed',
    SETTINGS_UPDATED: 'settings_updated',
    INTEGRATION_ADDED: 'integration_added',
    PROJECT_CREATED: 'project_created'
  },

  // Limits
  DEFAULT_LIMITS: {
    ORGANIZATION_NAME_MIN: 2,
    ORGANIZATION_NAME_MAX: 100,
    DESCRIPTION_MAX: 5000,
    CUSTOM_CSS_MAX: 50000,
    TAGS_MAX: 20,
    LOCATIONS_MAX: 50,
    CUSTOM_DOMAINS_MAX: 5
  },

  // Time Periods
  TIME_PERIODS: {
    TRIAL_DAYS: 14,
    INVOICE_DUE_DAYS: 30,
    DATA_RETENTION_DAYS: 365,
    PASSWORD_EXPIRY_DAYS: 90,
    INVITATION_EXPIRY_DAYS: 7,
    VERIFICATION_EXPIRY_HOURS: 24
  },

  // Regex Patterns
  PATTERNS: {
    SUBDOMAIN: /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/,
    DOMAIN: /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i,
    TAX_ID: /^[A-Z0-9-]+$/,
    SLUG: /^[a-z0-9]+(?:-[a-z0-9]+)*$/
  },

  // Error Messages
  ERROR_MESSAGES: {
    ORGANIZATION_NOT_FOUND: 'Organization not found',
    ORGANIZATION_INACTIVE: 'Organization is inactive',
    INSUFFICIENT_PERMISSIONS: 'Insufficient permissions to perform this action',
    LIMIT_EXCEEDED: 'Plan limit exceeded',
    INVALID_DOMAIN: 'Invalid domain format',
    DOMAIN_ALREADY_EXISTS: 'Domain is already in use',
    SUBSCRIPTION_REQUIRED: 'Active subscription required',
    OWNER_REQUIRED: 'Only organization owner can perform this action'
  },

  // Success Messages
  SUCCESS_MESSAGES: {
    ORGANIZATION_CREATED: 'Organization created successfully',
    ORGANIZATION_UPDATED: 'Organization updated successfully',
    MEMBER_ADDED: 'Member added successfully',
    MEMBER_REMOVED: 'Member removed successfully',
    SUBSCRIPTION_UPDATED: 'Subscription updated successfully',
    DOMAIN_VERIFIED: 'Domain verified successfully'
  }
};

module.exports = {
  ORGANIZATION_CONSTANTS
};