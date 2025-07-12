/**
 * @file Admin Limits Constants
 * @description Administrative limits and thresholds for system operations and resource management
 * @version 1.0.0
 */

/**
 * Administrative operation limits
 * Define maximum values for various administrative operations
 */
const AdminLimits = {
  /**
   * Authentication and Session Limits
   */
  AUTH: {
    MAX_LOGIN_ATTEMPTS: 5,
    LOGIN_LOCKOUT_DURATION: 1800000, // 30 minutes in milliseconds
    MAX_CONCURRENT_SESSIONS: 3,
    SESSION_DURATION: 3600000, // 1 hour in milliseconds
    SESSION_IDLE_TIMEOUT: 1800000, // 30 minutes
    SESSION_ABSOLUTE_TIMEOUT: 28800000, // 8 hours
    ELEVATED_SESSION_DURATION: 300000, // 5 minutes
    MAX_API_KEYS_PER_USER: 5,
    API_KEY_LIFETIME: 31536000000, // 1 year
    PASSWORD_RESET_EXPIRY: 3600000, // 1 hour
    MFA_CODE_EXPIRY: 300000, // 5 minutes
    MFA_MAX_ATTEMPTS: 3,
    MFA_BACKUP_CODES: 8,
    DEVICE_TRUST_DURATION: 2592000000, // 30 days
    REFRESH_TOKEN_LIFETIME: 604800000 // 7 days
  },

  /**
   * Rate Limiting Configuration
   */
  RATE_LIMIT: {
    // Authentication endpoints
    LOGIN: {
      WINDOW_MS: 900000, // 15 minutes
      MAX_REQUESTS: 5,
      BLOCK_DURATION: 3600000 // 1 hour
    },
    PASSWORD_RESET: {
      WINDOW_MS: 3600000, // 1 hour
      MAX_REQUESTS: 3,
      BLOCK_DURATION: 7200000 // 2 hours
    },
    
    // Read operations
    READ: {
      WINDOW_MS: 60000, // 1 minute
      MAX_REQUESTS: 100,
      BLOCK_DURATION: 300000 // 5 minutes
    },
    LIST: {
      WINDOW_MS: 60000, // 1 minute
      MAX_REQUESTS: 50,
      BLOCK_DURATION: 300000 // 5 minutes
    },
    EXPORT: {
      WINDOW_MS: 3600000, // 1 hour
      MAX_REQUESTS: 10,
      BLOCK_DURATION: 3600000 // 1 hour
    },
    
    // Write operations
    CREATE: {
      WINDOW_MS: 60000, // 1 minute
      MAX_REQUESTS: 20,
      BLOCK_DURATION: 600000 // 10 minutes
    },
    UPDATE: {
      WINDOW_MS: 60000, // 1 minute
      MAX_REQUESTS: 30,
      BLOCK_DURATION: 600000 // 10 minutes
    },
    DELETE: {
      WINDOW_MS: 60000, // 1 minute
      MAX_REQUESTS: 10,
      BLOCK_DURATION: 1800000 // 30 minutes
    },
    
    // Bulk operations
    BULK: {
      WINDOW_MS: 3600000, // 1 hour
      MAX_REQUESTS: 5,
      BLOCK_DURATION: 7200000 // 2 hours
    },
    
    // System operations
    SYSTEM: {
      WINDOW_MS: 3600000, // 1 hour
      MAX_REQUESTS: 10,
      BLOCK_DURATION: 3600000 // 1 hour
    }
  },

  /**
   * Data Operation Limits
   */
  DATA: {
    MAX_PAGE_SIZE: 100,
    DEFAULT_PAGE_SIZE: 20,
    MAX_EXPORT_RECORDS: 50000,
    MAX_IMPORT_RECORDS: 10000,
    MAX_BULK_OPERATION_SIZE: 1000,
    MAX_BATCH_SIZE: 100,
    MAX_QUERY_DEPTH: 5,
    MAX_SEARCH_RESULTS: 1000,
    MAX_AGGREGATION_BUCKETS: 100,
    QUERY_TIMEOUT: 30000, // 30 seconds
    EXPORT_TIMEOUT: 300000, // 5 minutes
    IMPORT_TIMEOUT: 600000, // 10 minutes
    MAX_FILE_SIZE: 10485760, // 10MB
    MAX_ATTACHMENT_SIZE: 5242880, // 5MB
    MAX_CSV_ROWS: 100000,
    MAX_JSON_SIZE: 52428800 // 50MB
  },

  /**
   * User Management Limits
   */
  USER: {
    MAX_USERS_PER_ORG: 1000,
    MAX_ROLES_PER_USER: 5,
    MAX_PERMISSIONS_PER_ROLE: 100,
    MAX_CUSTOM_PERMISSIONS: 50,
    MAX_GROUPS_PER_USER: 20,
    MAX_SESSIONS_PER_USER: 10,
    MAX_DEVICES_PER_USER: 5,
    USERNAME_MIN_LENGTH: 3,
    USERNAME_MAX_LENGTH: 50,
    EMAIL_MAX_LENGTH: 254,
    PASSWORD_MIN_LENGTH: 12,
    PASSWORD_MAX_LENGTH: 128,
    PROFILE_FIELD_MAX_LENGTH: 500,
    BIO_MAX_LENGTH: 1000,
    MAX_AVATAR_SIZE: 2097152 // 2MB
  },

  /**
   * Organization Limits
   */
  ORGANIZATION: {
    MAX_ORGS_PER_USER: 10,
    MAX_PROJECTS_PER_ORG: 500,
    MAX_TEAMS_PER_ORG: 100,
    MAX_CUSTOM_DOMAINS: 5,
    MAX_WEBHOOKS: 20,
    MAX_API_KEYS: 50,
    NAME_MIN_LENGTH: 3,
    NAME_MAX_LENGTH: 100,
    SUBDOMAIN_MIN_LENGTH: 3,
    SUBDOMAIN_MAX_LENGTH: 63,
    DESCRIPTION_MAX_LENGTH: 1000,
    TRIAL_DURATION: 1209600000, // 14 days
    GRACE_PERIOD: 604800000, // 7 days
    MAX_STORAGE_GB: 1000,
    MAX_MONTHLY_API_CALLS: 10000000,
    MAX_TEAM_SIZE: 500
  },

  /**
   * Billing and Subscription Limits
   */
  BILLING: {
    MIN_CHARGE_AMOUNT: 0.01,
    MAX_CHARGE_AMOUNT: 999999.99,
    MAX_REFUND_DAYS: 180,
    MAX_PAYMENT_METHODS: 5,
    MAX_INVOICES_PER_REQUEST: 100,
    MAX_DISCOUNT_PERCENTAGE: 100,
    MAX_CREDIT_AMOUNT: 10000,
    INVOICE_DUE_DAYS: 30,
    DUNNING_MAX_ATTEMPTS: 4,
    SUBSCRIPTION_CHANGE_COOLDOWN: 86400000, // 24 hours
    MAX_SUBSCRIPTIONS_PER_ORG: 10,
    MAX_ADDONS: 20,
    TAX_CALCULATION_TIMEOUT: 5000, // 5 seconds
    PAYMENT_PROCESSING_TIMEOUT: 30000 // 30 seconds
  },

  /**
   * System and Performance Limits
   */
  SYSTEM: {
    MAX_CPU_USAGE_PERCENT: 80,
    MAX_MEMORY_USAGE_PERCENT: 85,
    MAX_DISK_USAGE_PERCENT: 90,
    MAX_CONCURRENT_JOBS: 10,
    MAX_JOB_QUEUE_SIZE: 1000,
    JOB_TIMEOUT: 600000, // 10 minutes
    MAX_LOG_SIZE_MB: 100,
    LOG_RETENTION_DAYS: 90,
    MAX_CACHE_SIZE_MB: 500,
    CACHE_TTL: 3600000, // 1 hour
    MAX_WEBHOOK_RETRIES: 3,
    WEBHOOK_TIMEOUT: 10000, // 10 seconds
    BACKUP_RETENTION_DAYS: 30,
    MAX_BACKUP_SIZE_GB: 100,
    MAINTENANCE_WINDOW_HOURS: 4,
    MAX_NOTIFICATION_QUEUE: 10000
  },

  /**
   * Security Limits
   */
  SECURITY: {
    MAX_IP_WHITELIST_ENTRIES: 100,
    MAX_IP_BLACKLIST_ENTRIES: 1000,
    IP_BLOCK_DURATION: 86400000, // 24 hours
    MAX_FAILED_ATTEMPTS_BEFORE_BLOCK: 10,
    SUSPICIOUS_ACTIVITY_THRESHOLD: 5,
    MAX_AUDIT_LOG_RETENTION_DAYS: 1095, // 3 years
    AUDIT_LOG_EXPORT_MAX_DAYS: 365,
    MAX_ENCRYPTION_KEYS: 10,
    KEY_ROTATION_INTERVAL: 7776000000, // 90 days
    MAX_CORS_ORIGINS: 10,
    MAX_TRUSTED_PROXIES: 5,
    SESSION_ENCRYPTION_KEY_LENGTH: 32,
    MAX_CERTIFICATE_SIZE: 10240, // 10KB
    SECURITY_SCAN_INTERVAL: 86400000, // 24 hours
    VULNERABILITY_CHECK_TIMEOUT: 60000 // 1 minute
  },

  /**
   * Reporting and Analytics Limits
   */
  REPORTING: {
    MAX_REPORT_ROWS: 100000,
    MAX_CHART_DATA_POINTS: 10000,
    MAX_CONCURRENT_REPORTS: 5,
    REPORT_GENERATION_TIMEOUT: 300000, // 5 minutes
    MAX_SCHEDULED_REPORTS: 50,
    MAX_CUSTOM_DASHBOARDS: 20,
    MAX_WIDGETS_PER_DASHBOARD: 20,
    DATA_RETENTION_DAYS: 365,
    MAX_METRIC_CARDINALITY: 1000,
    AGGREGATION_TIMEOUT: 60000, // 1 minute
    MAX_EXPORT_FORMATS: 5,
    MAX_EMAIL_RECIPIENTS: 50,
    REPORT_CACHE_TTL: 3600000 // 1 hour
  },

  /**
   * Support and Communication Limits
   */
  SUPPORT: {
    MAX_TICKETS_PER_USER: 100,
    MAX_TICKET_ATTACHMENTS: 10,
    MAX_TICKET_UPDATES: 1000,
    TICKET_INACTIVITY_DAYS: 30,
    MAX_ANNOUNCEMENT_LENGTH: 5000,
    MAX_BROADCAST_RECIPIENTS: 10000,
    MAX_EMAIL_BATCH_SIZE: 1000,
    EMAIL_RATE_LIMIT_PER_HOUR: 100,
    MAX_SMS_LENGTH: 160,
    SMS_RATE_LIMIT_PER_DAY: 50,
    MAX_NOTIFICATION_RETRY: 3,
    NOTIFICATION_EXPIRY: 2592000000, // 30 days
    MAX_TEMPLATE_SIZE: 102400, // 100KB
    MAX_TEMPLATES: 100
  },

  /**
   * Content Management Limits
   */
  CONTENT: {
    MAX_PAGES: 1000,
    MAX_PAGE_SIZE: 1048576, // 1MB
    MAX_MEDIA_FILES: 10000,
    MAX_MEDIA_SIZE: 104857600, // 100MB
    MAX_CATEGORIES: 100,
    MAX_TAGS: 1000,
    MAX_REVISIONS: 50,
    REVISION_RETENTION_DAYS: 90,
    MAX_CUSTOM_FIELDS: 50,
    FIELD_NAME_MAX_LENGTH: 50,
    FIELD_VALUE_MAX_LENGTH: 5000,
    MAX_NAVIGATION_DEPTH: 5,
    MAX_MENU_ITEMS: 100,
    CDN_CACHE_TTL: 86400000 // 24 hours
  }
};

/**
 * Dynamic limit adjustments based on plan/tier
 */
const PlanMultipliers = {
  STARTER: {
    USERS: 1,
    STORAGE: 1,
    API_CALLS: 1,
    FEATURES: 0.5
  },
  GROWTH: {
    USERS: 5,
    STORAGE: 10,
    API_CALLS: 10,
    FEATURES: 0.8
  },
  PROFESSIONAL: {
    USERS: 20,
    STORAGE: 50,
    API_CALLS: 100,
    FEATURES: 1
  },
  ENTERPRISE: {
    USERS: -1, // Unlimited
    STORAGE: -1, // Unlimited
    API_CALLS: -1, // Unlimited
    FEATURES: 1
  }
};

/**
 * Performance thresholds for monitoring
 */
const PerformanceThresholds = {
  RESPONSE_TIME: {
    EXCELLENT: 100, // ms
    GOOD: 500,
    ACCEPTABLE: 1000,
    POOR: 3000
  },
  ERROR_RATE: {
    EXCELLENT: 0.01, // 1%
    GOOD: 0.05, // 5%
    ACCEPTABLE: 0.1, // 10%
    POOR: 0.2 // 20%
  },
  AVAILABILITY: {
    EXCELLENT: 0.999, // 99.9%
    GOOD: 0.995, // 99.5%
    ACCEPTABLE: 0.99, // 99%
    POOR: 0.95 // 95%
  },
  THROUGHPUT: {
    EXCELLENT: 1000, // requests per second
    GOOD: 500,
    ACCEPTABLE: 100,
    POOR: 50
  }
};

/**
 * Resource allocation limits
 */
const ResourceLimits = {
  CPU: {
    MIN_CORES: 1,
    MAX_CORES: 32,
    BURST_MULTIPLIER: 2
  },
  MEMORY: {
    MIN_GB: 1,
    MAX_GB: 128,
    HEAP_PERCENTAGE: 0.75
  },
  STORAGE: {
    MIN_GB: 10,
    MAX_GB: 10000,
    IOPS_PER_GB: 3
  },
  NETWORK: {
    MIN_BANDWIDTH_MBPS: 100,
    MAX_BANDWIDTH_MBPS: 10000,
    MAX_CONNECTIONS: 10000
  }
};

/**
 * Helper function to get limit for user based on plan
 */
const getLimitForPlan = (limitPath, plan) => {
  const pathParts = limitPath.split('.');
  let limit = AdminLimits;
  
  // Navigate to the limit value
  for (const part of pathParts) {
    limit = limit[part];
    if (limit === undefined) return undefined;
  }
  
  // Apply plan multiplier if applicable
  const multiplier = PlanMultipliers[plan]?.FEATURES || 1;
  if (multiplier === -1) return -1; // Unlimited
  
  return typeof limit === 'number' ? Math.floor(limit * multiplier) : limit;
};

/**
 * Helper function to check if limit is exceeded
 */
const isLimitExceeded = (current, limit) => {
  if (limit === -1) return false; // Unlimited
  return current >= limit;
};

/**
 * Helper function to get remaining capacity
 */
const getRemainingCapacity = (current, limit) => {
  if (limit === -1) return -1; // Unlimited
  return Math.max(0, limit - current);
};

/**
 * Helper function to calculate usage percentage
 */
const getUsagePercentage = (current, limit) => {
  if (limit === -1 || limit === 0) return 0;
  return Math.min(100, Math.round((current / limit) * 100));
};

/**
 * Validation helpers for limits
 */
const LimitValidators = {
  isWithinLimit: (value, limitPath) => {
    const limit = getLimitForPlan(limitPath, 'PROFESSIONAL'); // Default to professional
    if (limit === -1) return true;
    return value <= limit;
  },
  
  validateBatchSize: (size) => {
    return size > 0 && size <= AdminLimits.DATA.MAX_BATCH_SIZE;
  },
  
  validatePageSize: (size) => {
    return size > 0 && size <= AdminLimits.DATA.MAX_PAGE_SIZE;
  },
  
  validateExportSize: (count) => {
    return count > 0 && count <= AdminLimits.DATA.MAX_EXPORT_RECORDS;
  }
};

module.exports = {
  AdminLimits,
  PlanMultipliers,
  PerformanceThresholds,
  ResourceLimits,
  LimitValidators,
  getLimitForPlan,
  isLimitExceeded,
  getRemainingCapacity,
  getUsagePercentage
};