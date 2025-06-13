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
    
    STATUS: {
      PENDING: 'pending',
      ACTIVE: 'active',
      INACTIVE: 'inactive',
      SUSPENDED: 'suspended',
      DELETED: 'deleted'
    },
    
    ACCOUNT_STATUS: {
      UNVERIFIED: 'unverified',
      VERIFIED: 'verified',
      LOCKED: 'locked',
      BANNED: 'banned'
    }
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
    
    STATUS: {
      PENDING_SETUP: 'pending_setup',
      ACTIVE: 'active',
      SUSPENDED: 'suspended',
      EXPIRED: 'expired',
      TERMINATED: 'terminated'
    },
    
    SUBSCRIPTION_TIERS: {
      TRIAL: 'trial',
      STARTER: 'starter',
      PROFESSIONAL: 'professional',
      ENTERPRISE: 'enterprise',
      CUSTOM: 'custom'
    },
    
    SIZE_RANGES: {
      MICRO: '1-10',
      SMALL: '11-50',
      MEDIUM: '51-200',
      LARGE: '201-500',
      ENTERPRISE: '501-1000',
      CORPORATION: '1000+'
    }
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
      INVITATION: 'invitation'
    },
    
    PROVIDERS: {
      LOCAL: 'local',
      GOOGLE: 'google',
      GITHUB: 'github',
      LINKEDIN: 'linkedin',
      MICROSOFT: 'microsoft',
      SAML: 'saml',
      PASSKEY: 'passkey'
    },
    
    TWO_FACTOR_METHODS: {
      TOTP: 'totp',
      SMS: 'sms',
      EMAIL: 'email',
      BACKUP_CODES: 'backup_codes'
    },
    
    SESSION_TYPES: {
      WEB: 'web',
      API: 'api',
      MOBILE: 'mobile'
    }
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
    
    TRANSACTION_TYPES: {
      PAYMENT: 'payment',
      REFUND: 'refund',
      CREDIT: 'credit',
      DEBIT: 'debit',
      COMMISSION: 'commission',
      FEE: 'fee'
    },
    
    TRANSACTION_STATUS: {
      PENDING: 'pending',
      PROCESSING: 'processing',
      COMPLETED: 'completed',
      FAILED: 'failed',
      CANCELLED: 'cancelled',
      REFUNDED: 'refunded'
    },
    
    INVOICE_STATUS: {
      DRAFT: 'draft',
      SENT: 'sent',
      VIEWED: 'viewed',
      PAID: 'paid',
      OVERDUE: 'overdue',
      CANCELLED: 'cancelled',
      REFUNDED: 'refunded'
    },
    
    BILLING_CYCLES: {
      MONTHLY: 'monthly',
      QUARTERLY: 'quarterly',
      SEMI_ANNUAL: 'semi_annual',
      ANNUAL: 'annual',
      CUSTOM: 'custom'
    },
    
    CURRENCIES: {
      USD: 'USD',
      EUR: 'EUR',
      GBP: 'GBP',
      CAD: 'CAD',
      AUD: 'AUD'
    }
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
    
    PRIORITIES: {
      LOW: 'low',
      MEDIUM: 'medium',
      HIGH: 'high',
      URGENT: 'urgent'
    },
    
    CATEGORIES: {
      SYSTEM: 'system',
      SECURITY: 'security',
      BILLING: 'billing',
      PROJECT: 'project',
      RECRUITMENT: 'recruitment',
      ORGANIZATION: 'organization',
      MARKETING: 'marketing'
    },
    
    STATUS: {
      PENDING: 'pending',
      QUEUED: 'queued',
      SENT: 'sent',
      DELIVERED: 'delivered',
      READ: 'read',
      FAILED: 'failed',
      BOUNCED: 'bounced'
    }
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
    
    PRIORITY: {
      LOW: 'low',
      MEDIUM: 'medium',
      HIGH: 'high',
      CRITICAL: 'critical'
    },
    
    PHASES: {
      INITIATION: 'initiation',
      PLANNING: 'planning',
      EXECUTION: 'execution',
      MONITORING: 'monitoring',
      CLOSURE: 'closure'
    }
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
    
    EMPLOYMENT_TYPES: {
      FULL_TIME: 'full_time',
      PART_TIME: 'part_time',
      CONTRACT: 'contract',
      TEMPORARY: 'temporary',
      INTERNSHIP: 'internship',
      FREELANCE: 'freelance'
    },
    
    EXPERIENCE_LEVELS: {
      ENTRY: 'entry',
      JUNIOR: 'junior',
      MID: 'mid',
      SENIOR: 'senior',
      LEAD: 'lead',
      EXECUTIVE: 'executive'
    },
    
    WORK_LOCATIONS: {
      ON_SITE: 'on_site',
      REMOTE: 'remote',
      HYBRID: 'hybrid'
    }
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
    
    MAX_SIZES: {
      IMAGE: 5 * 1024 * 1024, // 5MB
      DOCUMENT: 10 * 1024 * 1024, // 10MB
      VIDEO: 100 * 1024 * 1024, // 100MB
      DEFAULT: 10 * 1024 * 1024 // 10MB
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