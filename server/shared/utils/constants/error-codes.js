// /server/shared/utils/constants/error-codes.js

/**
 * @file Error Codes
 * @description Standardized error codes for the platform
 * @version 1.0.0
 */

/**
 * Error code structure:
 * - First digit: Category (1-9)
 * - Next 3 digits: Specific error (000-999)
 * 
 * Categories:
 * 1xxx - Authentication & Authorization
 * 2xxx - Validation & Input
 * 3xxx - Business Logic
 * 4xxx - Payment & Billing
 * 5xxx - System & Infrastructure
 * 6xxx - External Services
 * 7xxx - File & Media
 * 8xxx - Communication
 * 9xxx - Platform Specific
 */

module.exports = {
  /**
   * Authentication & Authorization Errors (1xxx)
   */
  AUTH: {
    // Authentication errors (10xx)
    INVALID_CREDENTIALS: 'E1000',
    TOKEN_EXPIRED: 'E1001',
    TOKEN_INVALID: 'E1002',
    TOKEN_MISSING: 'E1003',
    SESSION_EXPIRED: 'E1004',
    SESSION_INVALID: 'E1005',
    ACCOUNT_LOCKED: 'E1006',
    ACCOUNT_SUSPENDED: 'E1007',
    ACCOUNT_NOT_VERIFIED: 'E1008',
    ACCOUNT_DELETED: 'E1009',
    TWO_FACTOR_REQUIRED: 'E1010',
    TWO_FACTOR_INVALID: 'E1011',
    PASSWORD_EXPIRED: 'E1012',
    PASSWORD_RESET_REQUIRED: 'E1013',
    API_KEY_INVALID: 'E1014',
    API_KEY_EXPIRED: 'E1015',
    API_KEY_RATE_LIMITED: 'E1016',
    
    // Authorization errors (11xx)
    INSUFFICIENT_PERMISSIONS: 'E1100',
    RESOURCE_ACCESS_DENIED: 'E1101',
    ORGANIZATION_ACCESS_DENIED: 'E1102',
    ROLE_ACCESS_DENIED: 'E1103',
    FEATURE_ACCESS_DENIED: 'E1104',
    IP_ADDRESS_BLOCKED: 'E1105',
    COUNTRY_BLOCKED: 'E1106',
    SUBSCRIPTION_REQUIRED: 'E1107',
    TRIAL_EXPIRED: 'E1108',
    QUOTA_EXCEEDED: 'E1109'
  },
  
  /**
   * Validation & Input Errors (2xxx)
   */
  VALIDATION: {
    // General validation (20xx)
    VALIDATION_FAILED: 'E2000',
    REQUIRED_FIELD_MISSING: 'E2001',
    INVALID_FORMAT: 'E2002',
    VALUE_OUT_OF_RANGE: 'E2003',
    INVALID_TYPE: 'E2004',
    PATTERN_MISMATCH: 'E2005',
    LENGTH_EXCEEDED: 'E2006',
    LENGTH_TOO_SHORT: 'E2007',
    
    // Specific field validation (21xx)
    INVALID_EMAIL: 'E2100',
    INVALID_PHONE: 'E2101',
    INVALID_URL: 'E2102',
    INVALID_DATE: 'E2103',
    INVALID_TIME: 'E2104',
    INVALID_CURRENCY: 'E2105',
    INVALID_COUNTRY_CODE: 'E2106',
    INVALID_LANGUAGE_CODE: 'E2107',
    INVALID_TIMEZONE: 'E2108',
    INVALID_COLOR_CODE: 'E2109',
    
    // Password validation (22xx)
    PASSWORD_TOO_WEAK: 'E2200',
    PASSWORD_TOO_SHORT: 'E2201',
    PASSWORD_TOO_LONG: 'E2202',
    PASSWORD_NO_UPPERCASE: 'E2203',
    PASSWORD_NO_LOWERCASE: 'E2204',
    PASSWORD_NO_NUMBER: 'E2205',
    PASSWORD_NO_SPECIAL: 'E2206',
    PASSWORD_COMMON: 'E2207',
    PASSWORD_REUSED: 'E2208',
    PASSWORDS_DONT_MATCH: 'E2209'
  },
  
  /**
   * Business Logic Errors (3xxx)
   */
  BUSINESS: {
    // Resource errors (30xx)
    RESOURCE_NOT_FOUND: 'E3000',
    RESOURCE_ALREADY_EXISTS: 'E3001',
    RESOURCE_DELETED: 'E3002',
    RESOURCE_ARCHIVED: 'E3003',
    RESOURCE_LOCKED: 'E3004',
    RESOURCE_IN_USE: 'E3005',
    RESOURCE_LIMIT_REACHED: 'E3006',
    
    // Operation errors (31xx)
    OPERATION_NOT_ALLOWED: 'E3100',
    OPERATION_FAILED: 'E3101',
    OPERATION_TIMEOUT: 'E3102',
    OPERATION_CANCELLED: 'E3103',
    OPERATION_IN_PROGRESS: 'E3104',
    INVALID_STATE_TRANSITION: 'E3105',
    PREREQUISITE_NOT_MET: 'E3106',
    CIRCULAR_DEPENDENCY: 'E3107',
    
    // Conflict errors (32xx)
    DUPLICATE_ENTRY: 'E3200',
    CONFLICTING_UPDATE: 'E3201',
    VERSION_MISMATCH: 'E3202',
    STALE_DATA: 'E3203',
    CONCURRENT_MODIFICATION: 'E3204',
    
    // Organization specific (33xx)
    ORGANIZATION_NOT_FOUND: 'E3300',
    ORGANIZATION_SUSPENDED: 'E3301',
    ORGANIZATION_EXPIRED: 'E3302',
    ORGANIZATION_LIMIT_REACHED: 'E3303',
    INVALID_ORGANIZATION_TYPE: 'E3304',
    
    // User specific (34xx)
    USER_NOT_FOUND: 'E3400',
    USER_ALREADY_EXISTS: 'E3401',
    USER_NOT_IN_ORGANIZATION: 'E3402',
    USER_ALREADY_INVITED: 'E3403',
    INVITATION_EXPIRED: 'E3404',
    INVITATION_ALREADY_USED: 'E3405'
  },
  
  /**
   * Payment & Billing Errors (4xxx)
   */
  PAYMENT: {
    // Payment processing (40xx)
    PAYMENT_FAILED: 'E4000',
    PAYMENT_DECLINED: 'E4001',
    INSUFFICIENT_FUNDS: 'E4002',
    CARD_EXPIRED: 'E4003',
    INVALID_CARD: 'E4004',
    CARD_NOT_SUPPORTED: 'E4005',
    PAYMENT_METHOD_REQUIRED: 'E4006',
    PAYMENT_PROCESSING: 'E4007',
    PAYMENT_CANCELLED: 'E4008',
    
    // Subscription errors (41xx)
    SUBSCRIPTION_NOT_FOUND: 'E4100',
    SUBSCRIPTION_EXPIRED: 'E4101',
    SUBSCRIPTION_CANCELLED: 'E4102',
    SUBSCRIPTION_PAUSED: 'E4103',
    INVALID_SUBSCRIPTION_PLAN: 'E4104',
    DOWNGRADE_NOT_ALLOWED: 'E4105',
    BILLING_CYCLE_MISMATCH: 'E4106',
    
    // Invoice errors (42xx)
    INVOICE_NOT_FOUND: 'E4200',
    INVOICE_ALREADY_PAID: 'E4201',
    INVOICE_OVERDUE: 'E4202',
    INVOICE_DISPUTED: 'E4203',
    
    // Refund errors (43xx)
    REFUND_NOT_ALLOWED: 'E4300',
    REFUND_PERIOD_EXPIRED: 'E4301',
    REFUND_ALREADY_PROCESSED: 'E4302',
    PARTIAL_REFUND_EXCEEDED: 'E4303'
  },
  
  /**
   * System & Infrastructure Errors (5xxx)
   */
  SYSTEM: {
    // Server errors (50xx)
    INTERNAL_SERVER_ERROR: 'E5000',
    SERVICE_UNAVAILABLE: 'E5001',
    DATABASE_ERROR: 'E5002',
    CACHE_ERROR: 'E5003',
    QUEUE_ERROR: 'E5004',
    STORAGE_ERROR: 'E5005',
    NETWORK_ERROR: 'E5006',
    
    // Configuration errors (51xx)
    CONFIGURATION_ERROR: 'E5100',
    MISSING_CONFIGURATION: 'E5101',
    INVALID_CONFIGURATION: 'E5102',
    ENVIRONMENT_ERROR: 'E5103',
    
    // Resource errors (52xx)
    OUT_OF_MEMORY: 'E5200',
    DISK_FULL: 'E5201',
    CPU_LIMIT_EXCEEDED: 'E5202',
    RATE_LIMIT_EXCEEDED: 'E5203',
    CONNECTION_LIMIT_EXCEEDED: 'E5204',
    
    // Maintenance errors (53xx)
    MAINTENANCE_MODE: 'E5300',
    FEATURE_DISABLED: 'E5301',
    SERVICE_DEGRADED: 'E5302',
    SCHEDULED_DOWNTIME: 'E5303'
  },
  
  /**
   * External Service Errors (6xxx)
   */
  EXTERNAL: {
    // Third-party API errors (60xx)
    EXTERNAL_SERVICE_ERROR: 'E6000',
    EXTERNAL_SERVICE_TIMEOUT: 'E6001',
    EXTERNAL_SERVICE_UNAVAILABLE: 'E6002',
    EXTERNAL_API_LIMIT_EXCEEDED: 'E6003',
    EXTERNAL_API_KEY_INVALID: 'E6004',
    
    // OAuth errors (61xx)
    OAUTH_PROVIDER_ERROR: 'E6100',
    OAUTH_INVALID_GRANT: 'E6101',
    OAUTH_ACCESS_DENIED: 'E6102',
    OAUTH_INVALID_SCOPE: 'E6103',
    
    // Webhook errors (62xx)
    WEBHOOK_DELIVERY_FAILED: 'E6200',
    WEBHOOK_INVALID_SIGNATURE: 'E6201',
    WEBHOOK_TIMEOUT: 'E6202',
    WEBHOOK_INVALID_PAYLOAD: 'E6203',
    
    // Email service errors (63xx)
    EMAIL_DELIVERY_FAILED: 'E6300',
    EMAIL_BOUNCED: 'E6301',
    EMAIL_MARKED_AS_SPAM: 'E6302',
    EMAIL_INVALID_RECIPIENT: 'E6303',
    
    // SMS service errors (64xx)
    SMS_DELIVERY_FAILED: 'E6400',
    SMS_INVALID_NUMBER: 'E6401',
    SMS_CARRIER_ERROR: 'E6402',
    SMS_BLOCKED_NUMBER: 'E6403'
  },
  
  /**
   * File & Media Errors (7xxx)
   */
  FILE: {
    // Upload errors (70xx)
    FILE_UPLOAD_FAILED: 'E7000',
    FILE_TOO_LARGE: 'E7001',
    FILE_TYPE_NOT_ALLOWED: 'E7002',
    FILE_INFECTED: 'E7003',
    FILE_CORRUPTED: 'E7004',
    STORAGE_QUOTA_EXCEEDED: 'E7005',
    
    // Processing errors (71xx)
    FILE_PROCESSING_FAILED: 'E7100',
    IMAGE_PROCESSING_FAILED: 'E7101',
    VIDEO_PROCESSING_FAILED: 'E7102',
    DOCUMENT_PROCESSING_FAILED: 'E7103',
    UNSUPPORTED_FORMAT: 'E7104',
    
    // Access errors (72xx)
    FILE_NOT_FOUND: 'E7200',
    FILE_ACCESS_DENIED: 'E7201',
    FILE_EXPIRED: 'E7202',
    FILE_DELETED: 'E7203'
  },
  
  /**
   * Communication Errors (8xxx)
   */
  COMMUNICATION: {
    // Notification errors (80xx)
    NOTIFICATION_FAILED: 'E8000',
    NOTIFICATION_DISABLED: 'E8001',
    INVALID_NOTIFICATION_CHANNEL: 'E8002',
    NOTIFICATION_RATE_LIMITED: 'E8003',
    
    // Real-time errors (81xx)
    WEBSOCKET_ERROR: 'E8100',
    WEBSOCKET_CONNECTION_FAILED: 'E8101',
    WEBSOCKET_AUTH_FAILED: 'E8102',
    WEBSOCKET_MESSAGE_TOO_LARGE: 'E8103',
    
    // Chat/Messaging errors (82xx)
    MESSAGE_SEND_FAILED: 'E8200',
    MESSAGE_TOO_LONG: 'E8201',
    RECIPIENT_BLOCKED: 'E8202',
    CHANNEL_NOT_FOUND: 'E8203'
  },
  
  /**
   * Platform Specific Errors (9xxx)
   */
  PLATFORM: {
    // Recruitment errors (90xx)
    JOB_NOT_FOUND: 'E9000',
    JOB_EXPIRED: 'E9001',
    JOB_CLOSED: 'E9002',
    APPLICATION_ALREADY_EXISTS: 'E9003',
    APPLICATION_DEADLINE_PASSED: 'E9004',
    CANDIDATE_NOT_QUALIFIED: 'E9005',
    INTERVIEW_CONFLICT: 'E9006',
    
    // Project errors (91xx)
    PROJECT_NOT_FOUND: 'E9100',
    PROJECT_ARCHIVED: 'E9101',
    PROJECT_LIMIT_REACHED: 'E9102',
    INVALID_PROJECT_STATUS: 'E9103',
    PROJECT_MEMBER_EXISTS: 'E9104',
    
    // Analytics errors (92xx)
    REPORT_GENERATION_FAILED: 'E9200',
    INSUFFICIENT_DATA: 'E9201',
    INVALID_DATE_RANGE: 'E9202',
    METRIC_NOT_AVAILABLE: 'E9203',
    
    // Integration errors (93xx)
    INTEGRATION_NOT_FOUND: 'E9300',
    INTEGRATION_NOT_CONFIGURED: 'E9301',
    INTEGRATION_AUTH_FAILED: 'E9302',
    INTEGRATION_SYNC_FAILED: 'E9303'
  },
  
  /**
   * Helper function to get error details
   */
  getErrorDetails(code) {
    // Search through all categories
    for (const category of Object.values(this)) {
      if (typeof category === 'object') {
        for (const [key, value] of Object.entries(category)) {
          if (value === code) {
            return {
              code,
              key,
              category: Object.keys(this).find(k => this[k] === category),
              message: key.replace(/_/g, ' ').toLowerCase()
            };
          }
        }
      }
    }
    return null;
  }
};