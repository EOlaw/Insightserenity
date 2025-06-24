// server/shared/config/constants.js
/**
 * @file Constants Configuration
 * @description Application-wide constants and enumerations
 * @version 3.0.0
 */

/**
 * Application Constants
 * @namespace Constants
 */
const Constants = {
  /**
   * User-related constants
   */
  USER: {
    TYPES: {
      CORE_CONSULTANT: 'core_consultant',
      HOSTED_ORG_USER: 'hosted_org_user',
      RECRUITMENT_PARTNER: 'recruitment_partner',
      JOB_SEEKER: 'job_seeker',
      PLATFORM_ADMIN: 'platform_admin'
    },
    
    // Array version for Mongoose enums
    TYPES_ENUM: ['core_consultant', 'hosted_org_user', 'recruitment_partner', 'job_seeker', 'platform_admin'],
    
    ROLES: {
      // Core business roles
      CORE_BUSINESS: {
        CLIENT: 'client',
        PROSPECT: 'prospect',
        JUNIOR_CONSULTANT: 'junior_consultant',
        CONSULTANT: 'consultant',
        SENIOR_CONSULTANT: 'senior_consultant',
        PRINCIPAL_CONSULTANT: 'principal_consultant',
        MANAGER: 'manager',
        SENIOR_MANAGER: 'senior_manager',
        DIRECTOR: 'director',
        PARTNER: 'partner'
      },
      
      // Hosted organization roles
      HOSTED_ORGANIZATION: {
        ORG_OWNER: 'org_owner',
        ORG_ADMIN: 'org_admin',
        ORG_MANAGER: 'org_manager',
        ORG_MEMBER: 'org_member',
        ORG_VIEWER: 'org_viewer'
      },
      
      // Recruitment roles
      RECRUITMENT: {
        RECRUITMENT_ADMIN: 'recruitment_admin',
        RECRUITMENT_PARTNER: 'recruitment_partner',
        RECRUITER: 'recruiter',
        HIRING_MANAGER: 'hiring_manager',
        CANDIDATE: 'candidate'
      },
      
      // Platform roles
      PLATFORM: {
        SUPER_ADMIN: 'super_admin',
        PLATFORM_ADMIN: 'platform_admin',
        SUPPORT_AGENT: 'support_agent',
        CONTENT_MANAGER: 'content_manager'
      }
    },
    
    // Combined roles array for Mongoose enums
    ROLES_ENUM: [
      // Core business roles
      'client', 'prospect', 'junior_consultant', 'consultant', 'senior_consultant',
      'principal_consultant', 'manager', 'senior_manager', 'director', 'partner',
      // Hosted organization roles
      'org_owner', 'org_admin', 'org_manager', 'org_member', 'org_viewer',
      // Recruitment roles
      'recruitment_admin', 'recruitment_partner', 'recruiter', 'hiring_manager', 'candidate',
      // Platform roles
      'super_admin', 'platform_admin', 'support_agent', 'content_manager'
    ],
    
    // Separate role arrays by category
    CORE_BUSINESS_ROLES_ENUM: ['client', 'prospect', 'junior_consultant', 'consultant', 'senior_consultant',
                               'principal_consultant', 'manager', 'senior_manager', 'director', 'partner'],
    HOSTED_ORGANIZATION_ROLES_ENUM: ['org_owner', 'org_admin', 'org_manager', 'org_member', 'org_viewer'],
    RECRUITMENT_ROLES_ENUM: ['recruitment_admin', 'recruitment_partner', 'recruiter', 'hiring_manager', 'candidate'],
    PLATFORM_ROLES_ENUM: ['super_admin', 'platform_admin', 'support_agent', 'content_manager'],
    
    STATUS: {
      PENDING: 'pending',
      ACTIVE: 'active',
      INACTIVE: 'inactive',
      SUSPENDED: 'suspended',
      DELETED: 'deleted'
    },
    
    STATUS_ENUM: ['pending', 'active', 'inactive', 'suspended', 'deleted'],
    
    ACCOUNT_STATUS: {
      UNVERIFIED: 'unverified',
      VERIFIED: 'verified',
      LOCKED: 'locked',
      BANNED: 'banned'
    },
    
    ACCOUNT_STATUS_ENUM: ['unverified', 'verified', 'locked', 'banned']
  },
  
  /**
   * Organization-related constants
   */
  ORGANIZATION: {
    TYPES: {
      CORE_BUSINESS: 'core_business',
      HOSTED_BUSINESS: 'hosted_business',
      RECRUITMENT_PARTNER: 'recruitment_partner'
    },
    
    TYPES_ENUM: ['core_business', 'hosted_business', 'recruitment_partner'],
    
    STATUS: {
      PENDING_SETUP: 'pending_setup',
      ACTIVE: 'active',
      SUSPENDED: 'suspended',
      EXPIRED: 'expired',
      TERMINATED: 'terminated'
    },
    
    STATUS_ENUM: ['pending_setup', 'active', 'suspended', 'expired', 'terminated'],
    
    SUBSCRIPTION_TIERS: {
      TRIAL: 'trial',
      STARTER: 'starter',
      PROFESSIONAL: 'professional',
      ENTERPRISE: 'enterprise',
      CUSTOM: 'custom'
    },
    
    SUBSCRIPTION_TIERS_ENUM: ['trial', 'starter', 'professional', 'enterprise', 'custom'],
    
    SIZE_RANGES: {
      MICRO: '1-10',
      SMALL: '11-50',
      MEDIUM: '51-200',
      LARGE: '201-500',
      ENTERPRISE: '501-1000',
      CORPORATION: '1000+'
    },
    
    SIZE_RANGES_ENUM: ['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+']
  },
  
  /**
   * Authentication constants
   */
  AUTH: {
    TOKEN_TYPES: {
      ACCESS: 'access',
      REFRESH: 'refresh',
      RESET: 'reset',
      VERIFICATION: 'verification',
      INVITATION: 'invitation',
      API_KEY: 'api_key',
      TWO_FACTOR: 'two_factor'
    },
    
    TOKEN_TYPES_ENUM: ['access', 'refresh', 'reset', 'verification', 'invitation', 'api_key', 'two_factor'],
    
    PROVIDERS: {
      LOCAL: 'local',
      GOOGLE: 'google',
      GITHUB: 'github',
      LINKEDIN: 'linkedin',
      MICROSOFT: 'microsoft',
      SAML: 'saml',
      PASSKEY: 'passkey'
    },
    
    PROVIDERS_ENUM: ['local', 'google', 'github', 'linkedin', 'microsoft', 'saml', 'passkey'],
    
    TWO_FACTOR_METHODS: {
      TOTP: 'totp',
      SMS: 'sms',
      EMAIL: 'email',
      BACKUP_CODES: 'backup_codes'
    },
    
    TWO_FACTOR_METHODS_ENUM: ['totp', 'sms', 'email', 'backup_codes'],
    
    SESSION_TYPES: {
      WEB: 'web',
      API: 'api',
      MOBILE: 'mobile'
    },
    
    SESSION_TYPES_ENUM: ['web', 'api', 'mobile'],
    
    // Additional auth-specific enums for the auth model
    MFA_METHOD_TYPES_ENUM: ['totp', 'sms', 'email', 'backup_codes', 'push', 'biometric'],
    
    SUSPICIOUS_ACTIVITY_TYPES_ENUM: ['unusual_location', 'multiple_failed_attempts', 'password_spray', 
                                     'credential_stuffing', 'account_takeover_attempt'],
    
    LOGIN_HISTORY_EVENT_TYPES_ENUM: ['created', 'processed', 'succeeded', 'failed', 'refunded', 
                                     'disputed', 'cancelled', 'updated', 'reconciled'],
    
    SOURCE_TYPES_ENUM: ['web', 'mobile', 'api', 'admin', 'import', 'migration']
  },
  
  /**
   * Billing and payment constants
   */
  BILLING: {
    PAYMENT_METHODS: {
      CREDIT_CARD: 'credit_card',
      DEBIT_CARD: 'debit_card',
      BANK_ACCOUNT: 'bank_account',
      PAYPAL: 'paypal',
      WIRE_TRANSFER: 'wire_transfer',
      CHECK: 'check'
    },
    
    PAYMENT_METHODS_ENUM: ['credit_card', 'debit_card', 'bank_account', 'paypal', 'wire_transfer', 'check'],
    
    // Extended payment method types for payment model
    PAYMENT_METHOD_TYPES_ENUM: ['card', 'bank_account', 'paypal', 'crypto', 'check', 'wire_transfer', 'cash', 'credit_balance', 'other'],
    
    TRANSACTION_TYPES: {
      PAYMENT: 'payment',
      REFUND: 'refund',
      CREDIT: 'credit',
      DEBIT: 'debit',
      COMMISSION: 'commission',
      FEE: 'fee'
    },
    
    TRANSACTION_TYPES_ENUM: ['payment', 'refund', 'credit', 'debit', 'commission', 'fee'],
    
    // Extended transaction types for payment model
    PAYMENT_TYPES_ENUM: ['payment', 'refund', 'partial_refund', 'chargeback', 'adjustment', 'credit'],
    
    TRANSACTION_STATUS: {
      PENDING: 'pending',
      PROCESSING: 'processing',
      COMPLETED: 'completed',
      FAILED: 'failed',
      CANCELLED: 'cancelled',
      REFUNDED: 'refunded'
    },
    
    TRANSACTION_STATUS_ENUM: ['pending', 'processing', 'completed', 'failed', 'cancelled', 'refunded'],
    
    // Extended payment status for payment model
    PAYMENT_STATUS_ENUM: ['pending', 'processing', 'succeeded', 'failed', 'cancelled', 'refunded', 'disputed', 'requires_action'],
    
    INVOICE_STATUS: {
      DRAFT: 'draft',
      SENT: 'sent',
      VIEWED: 'viewed',
      PAID: 'paid',
      OVERDUE: 'overdue',
      CANCELLED: 'cancelled',
      REFUNDED: 'refunded'
    },
    
    INVOICE_STATUS_ENUM: ['draft', 'sent', 'viewed', 'paid', 'overdue', 'cancelled', 'refunded'],
    
    // Extended invoice status for invoice model
    INVOICE_STATUS_EXTENDED_ENUM: ['draft', 'pending', 'sent', 'viewed', 'paid', 'partial', 'overdue', 
                                   'cancelled', 'refunded', 'disputed', 'written_off'],
    
    // Invoice types
    INVOICE_TYPES_ENUM: ['subscription', 'one_time', 'addon', 'overage', 'manual', 'credit_note', 'proforma'],
    
    // Invoice item types
    INVOICE_ITEM_TYPES_ENUM: ['subscription', 'addon', 'usage', 'fee', 'discount', 'tax', 'credit', 'adjustment'],
    
    // Discount types
    DISCOUNT_TYPES_ENUM: ['percentage', 'fixed'],
    
    // Payment terms
    PAYMENT_TERMS_ENUM: ['immediate', 'net_15', 'net_30', 'net_45', 'net_60', 'custom'],
    
    BILLING_CYCLES: {
      MONTHLY: 'monthly',
      QUARTERLY: 'quarterly',
      SEMI_ANNUAL: 'semi_annual',
      ANNUAL: 'annual',
      CUSTOM: 'custom'
    },
    
    BILLING_CYCLES_ENUM: ['monthly', 'quarterly', 'semi_annual', 'annual', 'custom'],
    
    // Extended billing cycles for subscriptions
    SUBSCRIPTION_BILLING_CYCLES_ENUM: ['monthly', 'quarterly', 'yearly', 'lifetime', 'custom'],
    
    CURRENCIES: {
      USD: 'USD',
      EUR: 'EUR',
      GBP: 'GBP',
      CAD: 'CAD',
      AUD: 'AUD'
    },
    
    CURRENCIES_ENUM: ['USD', 'EUR', 'GBP', 'CAD', 'AUD'],
    
    // Payment card brands
    CARD_BRANDS_ENUM: ['visa', 'mastercard', 'amex', 'discover', 'diners', 'jcb', 'unionpay', 'other'],
    
    // Card funding types
    CARD_FUNDING_TYPES_ENUM: ['credit', 'debit', 'prepaid', 'unknown'],
    
    // Bank account types
    BANK_ACCOUNT_TYPES_ENUM: ['checking', 'savings'],
    
    // Account holder types
    ACCOUNT_HOLDER_TYPES_ENUM: ['individual', 'company'],
    
    // Cryptocurrency types
    CRYPTO_TYPES_ENUM: ['bitcoin', 'ethereum', 'litecoin', 'usdc', 'usdt', 'other'],
    
    // Payment gateway providers
    GATEWAY_PROVIDERS_ENUM: ['stripe', 'paypal', 'square', 'authorize_net', 'braintree', 'manual', 'other'],
    
    // Risk levels
    RISK_LEVELS_ENUM: ['low', 'medium', 'high', 'critical'],
    
    // Refund reasons
    REFUND_REASONS_ENUM: ['duplicate', 'fraudulent', 'requested_by_customer', 'product_not_received', 
                          'product_unacceptable', 'subscription_cancelled', 'other'],
    
    // Dispute statuses
    DISPUTE_STATUS_ENUM: ['warning_needs_response', 'warning_under_review', 'warning_closed', 
                          'needs_response', 'under_review', 'charge_refunded', 'won', 'lost'],
    
    // Dispute reasons
    DISPUTE_REASONS_ENUM: ['duplicate', 'fraudulent', 'subscription_canceled', 'product_unacceptable',
                           'product_not_received', 'unrecognized', 'credit_not_processed', 'general',
                           'incorrect_account_details', 'insufficient_funds', 'bank_cannot_process',
                           'debit_not_authorized', 'customer_initiated'],
    
    // Payment source types
    PAYMENT_SOURCE_TYPES_ENUM: ['checkout', 'recurring', 'manual', 'api', 'mobile', 'pos', 'import'],
    
    // Reconciliation statuses
    RECONCILIATION_STATUS_ENUM: ['pending', 'matched', 'unmatched', 'disputed', 'resolved'],
    
    // Subscription statuses
    SUBSCRIPTION_STATUS_ENUM: ['active', 'trial', 'past_due', 'paused', 'cancelled', 'expired', 'pending'],
    
    // Subscription types
    SUBSCRIPTION_TYPES_ENUM: ['individual', 'organization', 'team'],
    
    // Subscription plan types
    PLAN_TYPES_ENUM: ['free', 'basic', 'professional', 'enterprise', 'custom'],
    
    // Plan categories
    PLAN_CATEGORIES_ENUM: ['individual', 'team', 'organization', 'platform'],
    
    // Target audiences
    TARGET_AUDIENCES_ENUM: ['consultants', 'organizations', 'job_seekers', 'recruiters', 'all'],
    
    // Plan visibility
    PLAN_VISIBILITY_ENUM: ['public', 'hidden', 'beta', 'invite_only'],
    
    // Plan status
    PLAN_STATUS_ENUM: ['draft', 'active', 'inactive', 'deprecated', 'beta', 'sunset'],
    
    // Support levels
    SUPPORT_LEVELS_ENUM: ['community', 'email', 'priority', 'dedicated', 'phone', 'white_glove'],
    
    // Support availability
    SUPPORT_AVAILABILITY_ENUM: ['business_hours', 'extended', '24x5', '24x7'],
    
    // Support channels
    SUPPORT_CHANNELS_ENUM: ['email', 'chat', 'phone', 'slack', 'teams', 'dedicated_manager'],
    
    // Feature categories
    FEATURE_CATEGORIES_ENUM: ['core', 'advanced', 'support', 'integration', 'security', 'analytics'],
    
    // Feature value types
    FEATURE_VALUE_TYPES_ENUM: ['boolean', 'number', 'string', 'array'],
    
    // Trial duration units
    TRIAL_DURATION_UNITS_ENUM: ['days', 'weeks', 'months'],
    
    // Trial types
    TRIAL_TYPES_ENUM: ['standard', 'extended', 'special', 'promotional'],
    
    // Time units
    TIME_UNITS_ENUM: ['minutes', 'hours', 'days'],
    
    // Discount sources
    DISCOUNT_SOURCES_ENUM: ['promotion', 'loyalty', 'referral', 'partner', 'manual'],
    
    // Discount feature types
    DISCOUNT_FEATURE_TYPES_ENUM: ['percentage', 'fixed', 'trial_extension', 'feature_unlock'],
    
    // Addon statuses
    ADDON_STATUS_ENUM: ['active', 'pending', 'cancelled'],
    
    // Cancellation reasons
    CANCELLATION_REASONS_ENUM: ['too_expensive', 'missing_features', 'not_using', 'switching_competitor', 
                                'technical_issues', 'customer_service', 'other'],
    
    // Subscription event types
    SUBSCRIPTION_EVENT_TYPES_ENUM: ['created', 'activated', 'upgraded', 'downgraded', 'renewed', 
                                   'paused', 'resumed', 'cancelled', 'expired', 'reactivated',
                                   'payment_failed', 'payment_succeeded', 'addon_added', 'addon_removed',
                                   'discount_applied', 'limit_increased', 'trial_extended'],
    
    // Note types
    NOTE_TYPES_ENUM: ['general', 'support', 'billing', 'retention'],
    
    // Invoice event types
    INVOICE_EVENT_TYPES_ENUM: ['created', 'updated', 'sent', 'viewed', 'paid', 'partial_payment', 
                               'overdue', 'reminder_sent', 'disputed', 'written_off', 'cancelled', 
                               'refunded', 'credited'],
    
    // Invoice source types
    INVOICE_SOURCE_TYPES_ENUM: ['system', 'manual', 'api', 'recurring', 'import'],
    
    // Invoice template types
    INVOICE_TEMPLATE_TYPES_ENUM: ['default', 'modern', 'classic', 'minimal', 'detailed', 'custom'],
    
    // Invoice notification channels
    INVOICE_NOTIFICATION_CHANNELS_ENUM: ['email', 'sms', 'in_app', 'push']
  },
  
  /**
   * Notification constants
   */
  NOTIFICATION: {
    CHANNELS: {
      EMAIL: 'email',
      SMS: 'sms',
      PUSH: 'push',
      IN_APP: 'in_app',
      SLACK: 'slack',
      WEBHOOK: 'webhook'
    },
    
    CHANNELS_ENUM: ['email', 'sms', 'push', 'in_app', 'slack', 'webhook'],
    
    PRIORITIES: {
      LOW: 'low',
      MEDIUM: 'medium',
      HIGH: 'high',
      URGENT: 'urgent'
    },
    
    PRIORITIES_ENUM: ['low', 'medium', 'high', 'urgent'],
    
    CATEGORIES: {
      SYSTEM: 'system',
      SECURITY: 'security',
      BILLING: 'billing',
      PROJECT: 'project',
      RECRUITMENT: 'recruitment',
      ORGANIZATION: 'organization',
      MARKETING: 'marketing'
    },
    
    CATEGORIES_ENUM: ['system', 'security', 'billing', 'project', 'recruitment', 'organization', 'marketing'],
    
    STATUS: {
      PENDING: 'pending',
      QUEUED: 'queued',
      SENT: 'sent',
      DELIVERED: 'delivered',
      READ: 'read',
      FAILED: 'failed',
      BOUNCED: 'bounced'
    },
    
    STATUS_ENUM: ['pending', 'queued', 'sent', 'delivered', 'read', 'failed', 'bounced']
  },
  
  /**
   * Project constants (for core business)
   */
  PROJECT: {
    STATUS: {
      DRAFT: 'draft',
      PLANNING: 'planning',
      IN_PROGRESS: 'in_progress',
      ON_HOLD: 'on_hold',
      COMPLETED: 'completed',
      CANCELLED: 'cancelled',
      ARCHIVED: 'archived'
    },
    
    STATUS_ENUM: ['draft', 'planning', 'in_progress', 'on_hold', 'completed', 'cancelled', 'archived'],
    
    PRIORITY: {
      LOW: 'low',
      MEDIUM: 'medium',
      HIGH: 'high',
      CRITICAL: 'critical'
    },
    
    PRIORITY_ENUM: ['low', 'medium', 'high', 'critical'],
    
    PHASES: {
      INITIATION: 'initiation',
      PLANNING: 'planning',
      EXECUTION: 'execution',
      MONITORING: 'monitoring',
      CLOSURE: 'closure'
    },
    
    PHASES_ENUM: ['initiation', 'planning', 'execution', 'monitoring', 'closure']
  },
  
  /**
   * Recruitment constants
   */
  RECRUITMENT: {
    JOB_STATUS: {
      DRAFT: 'draft',
      ACTIVE: 'active',
      PAUSED: 'paused',
      FILLED: 'filled',
      CANCELLED: 'cancelled',
      EXPIRED: 'expired'
    },
    
    JOB_STATUS_ENUM: ['draft', 'active', 'paused', 'filled', 'cancelled', 'expired'],
    
    APPLICATION_STATUS: {
      SUBMITTED: 'submitted',
      REVIEWING: 'reviewing',
      SHORTLISTED: 'shortlisted',
      INTERVIEWING: 'interviewing',
      REFERENCE_CHECK: 'reference_check',
      OFFER_EXTENDED: 'offer_extended',
      HIRED: 'hired',
      REJECTED: 'rejected',
      WITHDRAWN: 'withdrawn'
    },
    
    APPLICATION_STATUS_ENUM: ['submitted', 'reviewing', 'shortlisted', 'interviewing', 'reference_check', 
                             'offer_extended', 'hired', 'rejected', 'withdrawn'],
    
    EMPLOYMENT_TYPES: {
      FULL_TIME: 'full_time',
      PART_TIME: 'part_time',
      CONTRACT: 'contract',
      TEMPORARY: 'temporary',
      INTERNSHIP: 'internship',
      FREELANCE: 'freelance'
    },
    
    EMPLOYMENT_TYPES_ENUM: ['full_time', 'part_time', 'contract', 'temporary', 'internship', 'freelance'],
    
    EXPERIENCE_LEVELS: {
      ENTRY: 'entry',
      JUNIOR: 'junior',
      MID: 'mid',
      SENIOR: 'senior',
      LEAD: 'lead',
      EXECUTIVE: 'executive'
    },
    
    EXPERIENCE_LEVELS_ENUM: ['entry', 'junior', 'mid', 'senior', 'lead', 'executive'],
    
    WORK_LOCATIONS: {
      ON_SITE: 'on_site',
      REMOTE: 'remote',
      HYBRID: 'hybrid'
    },
    
    WORK_LOCATIONS_ENUM: ['on_site', 'remote', 'hybrid']
  },
  
  /**
   * File and media constants
   */
  FILE: {
    TYPES: {
      DOCUMENT: 'document',
      IMAGE: 'image',
      VIDEO: 'video',
      AUDIO: 'audio',
      ARCHIVE: 'archive',
      OTHER: 'other'
    },
    
    TYPES_ENUM: ['document', 'image', 'video', 'audio', 'archive', 'other'],
    
    CATEGORIES: {
      PROFILE_PHOTO: 'profile_photo',
      RESUME: 'resume',
      COVER_LETTER: 'cover_letter',
      PORTFOLIO: 'portfolio',
      CONTRACT: 'contract',
      INVOICE: 'invoice',
      REPORT: 'report',
      PRESENTATION: 'presentation'
    },
    
    CATEGORIES_ENUM: ['profile_photo', 'resume', 'cover_letter', 'portfolio', 'contract', 'invoice', 'report', 'presentation'],
    
    MAX_SIZES: {
      IMAGE: 5 * 1024 * 1024, // 5MB
      DOCUMENT: 10 * 1024 * 1024, // 10MB
      VIDEO: 100 * 1024 * 1024, // 100MB
      DEFAULT: 10 * 1024 * 1024 // 10MB
    },

    // Add these new constants for file upload functionality
    ALLOWED_TYPES: {
      IMAGE: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'],
      DOCUMENT: [
        'application/pdf', 
        'application/msword', 
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/plain',
        'text/csv'
      ],
      VIDEO: ['video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo', 'video/webm'],
      AUDIO: ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4']
    },
    
    ALLOWED_EXTENSIONS: {
      IMAGE: ['.jpg', '.jpeg', '.png', '.webp', '.gif'],
      DOCUMENT: ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt', '.csv'],
      VIDEO: ['.mp4', '.mpeg', '.mov', '.avi', '.webm'],
      AUDIO: ['.mp3', '.wav', '.ogg', '.m4a']
    }
  },
  
  /**
   * API constants
   */
  API: {
    VERSIONS: {
      V1: 'v1',
      V2: 'v2'
    },
    
    VERSIONS_ENUM: ['v1', 'v2'],
    
    RATE_LIMITS: {
      PUBLIC: {
        WINDOW: 15 * 60 * 1000, // 15 minutes
        MAX: 100
      },
      AUTHENTICATED: {
        WINDOW: 15 * 60 * 1000, // 15 minutes
        MAX: 1000
      },
      PREMIUM: {
        WINDOW: 15 * 60 * 1000, // 15 minutes
        MAX: 10000
      }
    },
    
    RESPONSE_CODES: {
      SUCCESS: 200,
      CREATED: 201,
      ACCEPTED: 202,
      NO_CONTENT: 204,
      BAD_REQUEST: 400,
      UNAUTHORIZED: 401,
      FORBIDDEN: 403,
      NOT_FOUND: 404,
      CONFLICT: 409,
      UNPROCESSABLE: 422,
      TOO_MANY_REQUESTS: 429,
      SERVER_ERROR: 500,
      SERVICE_UNAVAILABLE: 503
    }
  },
  
  /**
   * Security constants
   */
  SECURITY: {
    PASSWORD: {
      MIN_LENGTH: 8,
      MAX_LENGTH: 128,
      REQUIRE_UPPERCASE: true,
      REQUIRE_LOWERCASE: true,
      REQUIRE_NUMBER: true,
      REQUIRE_SPECIAL: true,
      SPECIAL_CHARS: '@$!%*?&',
      HISTORY_COUNT: 5,
      EXPIRY_DAYS: 90
    },
    
    LOCKOUT: {
      MAX_ATTEMPTS: 5,
      DURATION: 30 * 60 * 1000, // 30 minutes
      RESET_WINDOW: 15 * 60 * 1000 // 15 minutes
    },
    
    TOKEN_EXPIRY: {
      ACCESS: 15 * 60, // 15 minutes
      REFRESH: 7 * 24 * 60 * 60, // 7 days
      RESET: 60 * 60, // 1 hour
      VERIFICATION: 24 * 60 * 60, // 24 hours
      INVITATION: 7 * 24 * 60 * 60 // 7 days
    },
    
    ENCRYPTION: {
      ALGORITHM: 'aes-256-gcm',
      KEY_LENGTH: 32,
      IV_LENGTH: 16,
      TAG_LENGTH: 16,
      SALT_LENGTH: 64,
      ITERATIONS: 100000
    }
  },
  
  /**
   * Regex patterns
   */
  REGEX: {
    EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    USERNAME: /^[a-zA-Z0-9_-]{3,30}$/,
    SLUG: /^[a-z0-9-]+$/,
    PHONE: /^\+?[1-9]\d{1,14}$/,
    URL: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/,
    MONGO_ID: /^[0-9a-fA-F]{24}$/,
    UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    JWT: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/
  },
  
  /**
   * Time constants (in milliseconds)
   */
  TIME: {
    SECOND: 1000,
    MINUTE: 60 * 1000,
    HOUR: 60 * 60 * 1000,
    DAY: 24 * 60 * 60 * 1000,
    WEEK: 7 * 24 * 60 * 60 * 1000,
    MONTH: 30 * 24 * 60 * 60 * 1000,
    YEAR: 365 * 24 * 60 * 60 * 1000
  }
};

// Freeze constants to prevent modification
function deepFreeze(obj) {
  Object.freeze(obj);
  Object.getOwnPropertyNames(obj).forEach(prop => {
    if (obj[prop] !== null && (typeof obj[prop] === 'object' || typeof obj[prop] === 'function')) {
      deepFreeze(obj[prop]);
    }
  });
  return obj;
}

module.exports = deepFreeze(Constants);