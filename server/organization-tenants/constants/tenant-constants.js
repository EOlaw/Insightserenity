/**
 * @file Tenant Constants
 * @description Constants for organization tenant management
 * @version 1.0.0
 */

const TENANT_CONSTANTS = {
  // Tenant Status
  TENANT_STATUS: {
    PENDING: 'pending',
    ACTIVE: 'active',
    SUSPENDED: 'suspended',
    TERMINATED: 'terminated',
    MIGRATING: 'migrating'
  },

  // Lifecycle Stages
  LIFECYCLE_STAGES: {
    TRIAL: 'trial',
    GROWTH: 'growth',
    ESTABLISHED: 'established',
    ENTERPRISE: 'enterprise',
    CHURNED: 'churned'
  },

  // Business Types
  BUSINESS_TYPES: [
    'corporation',
    'llc',
    'partnership',
    'sole_proprietorship',
    'non_profit',
    'government',
    'educational',
    'startup',
    'other'
  ],

  // Industries
  INDUSTRIES: [
    'technology',
    'healthcare',
    'finance',
    'retail',
    'manufacturing',
    'education',
    'consulting',
    'real_estate',
    'hospitality',
    'transportation',
    'media',
    'telecommunications',
    'energy',
    'agriculture',
    'construction',
    'legal',
    'non_profit',
    'government',
    'other'
  ],

  // Company Sizes
  COMPANY_SIZES: {
    MICRO: 'micro',        // 1-9 employees
    SMALL: 'small',        // 10-49 employees
    MEDIUM: 'medium',      // 50-249 employees
    LARGE: 'large',        // 250-999 employees
    ENTERPRISE: 'enterprise' // 1000+ employees
  },

  // Subscription Plans
  SUBSCRIPTION_PLANS: {
    TRIAL: 'trial',
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
    PENDING: 'pending',
    EXPIRED: 'expired'
  },

  // Database Strategies
  DATABASE_STRATEGIES: {
    SHARED: 'shared',          // Shared database with tenant isolation
    DEDICATED: 'dedicated',    // Dedicated database per tenant
    HYBRID: 'hybrid'          // Mix of shared and dedicated based on plan
  },

  // Data Locations
  DATA_LOCATIONS: {
    US: 'us',
    EU: 'eu',
    ASIA: 'asia',
    AUSTRALIA: 'australia',
    CANADA: 'canada'
  },

  // Feature Flags
  FEATURES: {
    MULTI_LANGUAGE: 'multiLanguage',
    ADVANCED_ANALYTICS: 'advancedAnalytics',
    CUSTOM_INTEGRATIONS: 'customIntegrations',
    WHITE_LABEL: 'whiteLabel',
    SSO: 'sso',
    API_ACCESS: 'apiAccess',
    CUSTOM_REPORTS: 'customReports',
    DATA_EXPORT: 'dataExport'
  },

  // Resource Types
  RESOURCE_TYPES: {
    USERS: 'users',
    STORAGE: 'storage',
    API_CALLS: 'apiCalls',
    PROJECTS: 'projects',
    CUSTOM_DOMAINS: 'customDomains'
  },

  // Event Types
  EVENT_TYPES: {
    TENANT_CREATED: 'tenant.created',
    TENANT_ACTIVATED: 'tenant.activated',
    TENANT_SUSPENDED: 'tenant.suspended',
    TENANT_TERMINATED: 'tenant.terminated',
    TENANT_UPGRADED: 'tenant.upgraded',
    TENANT_DOWNGRADED: 'tenant.downgraded',
    SUBSCRIPTION_RENEWED: 'subscription.renewed',
    SUBSCRIPTION_CANCELED: 'subscription.canceled',
    PAYMENT_SUCCEEDED: 'payment.succeeded',
    PAYMENT_FAILED: 'payment.failed',
    LIMIT_REACHED: 'limit.reached',
    DOMAIN_ADDED: 'domain.added',
    DOMAIN_VERIFIED: 'domain.verified',
    DOMAIN_REMOVED: 'domain.removed'
  },

  // Default Limits by Plan
  PLAN_LIMITS: {
    trial: {
      users: 5,
      storageGB: 1,
      apiCallsPerMonth: 1000,
      projects: 3,
      customDomains: 0,
      trialDays: 14
    },
    starter: {
      users: 10,
      storageGB: 10,
      apiCallsPerMonth: 10000,
      projects: 10,
      customDomains: 1
    },
    growth: {
      users: 50,
      storageGB: 100,
      apiCallsPerMonth: 100000,
      projects: 50,
      customDomains: 3
    },
    professional: {
      users: 200,
      storageGB: 500,
      apiCallsPerMonth: 1000000,
      projects: 200,
      customDomains: 10
    },
    enterprise: {
      users: -1,      // Unlimited
      storageGB: -1,  // Unlimited
      apiCallsPerMonth: -1,
      projects: -1,
      customDomains: -1
    }
  },

  // Trial Duration
  TRIAL_DURATION_DAYS: 14,

  // Cache Keys
  CACHE_KEYS: {
    TENANT_BY_ID: 'tenant:id:',
    TENANT_BY_CODE: 'tenant:code:',
    TENANT_BY_DOMAIN: 'tenant:domain:',
    TENANT_STATS: 'tenant:stats',
    TENANT_LIMITS: 'tenant:limits:',
    TENANT_USAGE: 'tenant:usage:'
  },

  // Cache TTL (in seconds)
  CACHE_TTL: {
    TENANT_DATA: 300,      // 5 minutes
    TENANT_STATS: 3600,    // 1 hour
    TENANT_USAGE: 60       // 1 minute
  },

  // Error Messages
  ERROR_MESSAGES: {
    TENANT_NOT_FOUND: 'Organization tenant not found',
    TENANT_SUSPENDED: 'Organization tenant is suspended',
    TENANT_TERMINATED: 'Organization tenant has been terminated',
    INVALID_TENANT_CODE: 'Invalid tenant code format',
    DUPLICATE_TENANT_CODE: 'Tenant code already exists',
    DUPLICATE_DOMAIN: 'Domain is already registered',
    DOMAIN_NOT_VERIFIED: 'Domain is not verified',
    LIMIT_EXCEEDED: 'Resource limit exceeded',
    SUBSCRIPTION_REQUIRED: 'Active subscription required',
    FEATURE_NOT_AVAILABLE: 'Feature not available in current plan',
    INVALID_PLAN: 'Invalid subscription plan',
    PAYMENT_REQUIRED: 'Payment information required',
    TRIAL_EXPIRED: 'Trial period has expired'
  },

  // Success Messages
  SUCCESS_MESSAGES: {
    TENANT_CREATED: 'Organization tenant created successfully',
    TENANT_UPDATED: 'Organization tenant updated successfully',
    TENANT_ACTIVATED: 'Organization tenant activated successfully',
    TENANT_SUSPENDED: 'Organization tenant suspended successfully',
    SUBSCRIPTION_UPDATED: 'Subscription updated successfully',
    DOMAIN_ADDED: 'Domain added successfully',
    DOMAIN_VERIFIED: 'Domain verified successfully',
    SETTINGS_UPDATED: 'Settings updated successfully',
    LIMITS_UPDATED: 'Resource limits updated successfully'
  },

  // Webhook Events
  WEBHOOK_EVENTS: {
    ALL: '*',
    TENANT: 'tenant.*',
    SUBSCRIPTION: 'subscription.*',
    PAYMENT: 'payment.*',
    USAGE: 'usage.*',
    SECURITY: 'security.*'
  },

  // Audit Actions
  AUDIT_ACTIONS: {
    CREATE: 'create',
    UPDATE: 'update',
    DELETE: 'delete',
    ACTIVATE: 'activate',
    SUSPEND: 'suspend',
    TERMINATE: 'terminate',
    UPGRADE: 'upgrade',
    DOWNGRADE: 'downgrade',
    LOGIN: 'login',
    LOGOUT: 'logout',
    EXPORT: 'export',
    IMPORT: 'import'
  }
};

module.exports = { TENANT_CONSTANTS };