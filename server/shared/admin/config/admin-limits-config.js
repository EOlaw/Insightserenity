/**
 * @file Admin Limits Configuration
 * @description Rate limits, quotas, and resource constraints for administrative operations
 * @version 1.0.0
 */

const { AdminRoles } = require('../constants/admin-roles');
const { AdminActions } = require('../constants/admin-actions');

/**
 * Rate limiting configurations for administrative operations
 * Organized by operation type and admin role level
 */
const AdminRateLimits = {
  /**
   * Authentication and session rate limits
   * Prevents brute force attacks and excessive session creation
   */
  AUTHENTICATION: {
    // Login attempts
    LOGIN_ATTEMPTS: {
      super_admin: { max: 10, windowMs: 15 * 60 * 1000, blockDuration: 30 * 60 * 1000 }, // 10 attempts per 15min, block 30min
      platform_admin: { max: 8, windowMs: 15 * 60 * 1000, blockDuration: 45 * 60 * 1000 },
      organization_admin: { max: 6, windowMs: 15 * 60 * 1000, blockDuration: 60 * 60 * 1000 },
      default: { max: 5, windowMs: 15 * 60 * 1000, blockDuration: 60 * 60 * 1000 }
    },
    
    // Password reset requests
    PASSWORD_RESET: {
      super_admin: { max: 5, windowMs: 60 * 60 * 1000 }, // 5 per hour
      platform_admin: { max: 4, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 3, windowMs: 60 * 60 * 1000 },
      default: { max: 3, windowMs: 60 * 60 * 1000 }
    },
    
    // Session creation
    SESSION_CREATION: {
      super_admin: { max: 20, windowMs: 60 * 60 * 1000 }, // 20 sessions per hour
      platform_admin: { max: 15, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 10, windowMs: 60 * 60 * 1000 },
      default: { max: 8, windowMs: 60 * 60 * 1000 }
    },
    
    // MFA verification attempts
    MFA_VERIFICATION: {
      super_admin: { max: 10, windowMs: 15 * 60 * 1000 },
      platform_admin: { max: 8, windowMs: 15 * 60 * 1000 },
      organization_admin: { max: 6, windowMs: 15 * 60 * 1000 },
      default: { max: 5, windowMs: 15 * 60 * 1000 }
    }
  },

  /**
   * User management operation limits
   * Controls bulk operations and prevents abuse
   */
  USER_MANAGEMENT: {
    // User creation limits
    USER_CREATION: {
      super_admin: { max: 1000, windowMs: 60 * 60 * 1000, dailyMax: 5000 }, // 1000/hour, 5000/day
      platform_admin: { max: 500, windowMs: 60 * 60 * 1000, dailyMax: 2000 },
      organization_admin: { max: 100, windowMs: 60 * 60 * 1000, dailyMax: 500 },
      default: { max: 20, windowMs: 60 * 60 * 1000, dailyMax: 100 }
    },
    
    // User updates (including role changes)
    USER_UPDATES: {
      super_admin: { max: 2000, windowMs: 60 * 60 * 1000 },
      platform_admin: { max: 1000, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 500, windowMs: 60 * 60 * 1000 },
      default: { max: 100, windowMs: 60 * 60 * 1000 }
    },
    
    // User deletion (highly restricted)
    USER_DELETION: {
      super_admin: { max: 50, windowMs: 60 * 60 * 1000, dailyMax: 200 },
      platform_admin: { max: 20, windowMs: 60 * 60 * 1000, dailyMax: 100 },
      organization_admin: { max: 10, windowMs: 60 * 60 * 1000, dailyMax: 50 },
      default: { max: 5, windowMs: 60 * 60 * 1000, dailyMax: 20 }
    },
    
    // Bulk operations
    BULK_OPERATIONS: {
      super_admin: { max: 20, windowMs: 60 * 60 * 1000, batchSize: 1000 },
      platform_admin: { max: 15, windowMs: 60 * 60 * 1000, batchSize: 500 },
      organization_admin: { max: 10, windowMs: 60 * 60 * 1000, batchSize: 200 },
      default: { max: 5, windowMs: 60 * 60 * 1000, batchSize: 50 }
    },
    
    // User impersonation (extremely restricted)
    USER_IMPERSONATION: {
      super_admin: { max: 10, windowMs: 24 * 60 * 60 * 1000, sessionDuration: 60 * 60 * 1000 }, // 10/day, 1hr sessions
      platform_admin: { max: 5, windowMs: 24 * 60 * 60 * 1000, sessionDuration: 30 * 60 * 1000 }, // 5/day, 30min sessions
      organization_admin: { max: 0 }, // Not allowed
      default: { max: 0 }
    }
  },

  /**
   * Organization management limits
   * Controls organization-level operations
   */
  ORGANIZATION_MANAGEMENT: {
    // Organization creation
    ORGANIZATION_CREATION: {
      super_admin: { max: 100, windowMs: 60 * 60 * 1000, dailyMax: 500 },
      platform_admin: { max: 50, windowMs: 60 * 60 * 1000, dailyMax: 200 },
      organization_admin: { max: 0 }, // Cannot create orgs
      default: { max: 0 }
    },
    
    // Organization updates
    ORGANIZATION_UPDATES: {
      super_admin: { max: 500, windowMs: 60 * 60 * 1000 },
      platform_admin: { max: 200, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 100, windowMs: 60 * 60 * 1000 },
      default: { max: 20, windowMs: 60 * 60 * 1000 }
    },
    
    // Organization deletion (highly restricted)
    ORGANIZATION_DELETION: {
      super_admin: { max: 5, windowMs: 24 * 60 * 60 * 1000, requiresApproval: true },
      platform_admin: { max: 2, windowMs: 24 * 60 * 60 * 1000, requiresApproval: true },
      organization_admin: { max: 0 },
      default: { max: 0 }
    },
    
    // Member invitations
    MEMBER_INVITATIONS: {
      super_admin: { max: 1000, windowMs: 60 * 60 * 1000 },
      platform_admin: { max: 500, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 200, windowMs: 60 * 60 * 1000 },
      default: { max: 50, windowMs: 60 * 60 * 1000 }
    }
  },

  /**
   * System administration limits
   * Controls system-level operations and configurations
   */
  SYSTEM_ADMINISTRATION: {
    // Configuration changes
    CONFIG_UPDATES: {
      super_admin: { max: 50, windowMs: 60 * 60 * 1000, requiresApproval: false },
      platform_admin: { max: 0 }, // No config access
      system_admin: { max: 20, windowMs: 60 * 60 * 1000, requiresApproval: true },
      default: { max: 0 }
    },
    
    // Backup operations
    BACKUP_OPERATIONS: {
      super_admin: { max: 10, windowMs: 60 * 60 * 1000 },
      system_admin: { max: 5, windowMs: 60 * 60 * 1000 },
      default: { max: 0 }
    },
    
    // Maintenance mode toggles
    MAINTENANCE_MODE: {
      super_admin: { max: 5, windowMs: 24 * 60 * 60 * 1000, requiresApproval: true },
      system_admin: { max: 2, windowMs: 24 * 60 * 60 * 1000, requiresApproval: true },
      default: { max: 0 }
    }
  },

  /**
   * Security operation limits
   * Controls security-related administrative actions
   */
  SECURITY_OPERATIONS: {
    // Security policy updates
    POLICY_UPDATES: {
      super_admin: { max: 20, windowMs: 60 * 60 * 1000 },
      security_admin: { max: 10, windowMs: 60 * 60 * 1000, requiresApproval: true },
      default: { max: 0 }
    },
    
    // Audit log access
    AUDIT_LOG_ACCESS: {
      super_admin: { max: 1000, windowMs: 60 * 60 * 1000 },
      security_admin: { max: 500, windowMs: 60 * 60 * 1000 },
      platform_admin: { max: 200, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 100, windowMs: 60 * 60 * 1000 },
      default: { max: 0 }
    },
    
    // Emergency access grants
    EMERGENCY_ACCESS: {
      super_admin: { max: 3, windowMs: 24 * 60 * 60 * 1000, requiresMultipleApprovals: true },
      default: { max: 0 }
    }
  },

  /**
   * API and integration limits
   * Controls programmatic access rates
   */
  API_OPERATIONS: {
    // Admin API calls
    API_REQUESTS: {
      super_admin: { max: 10000, windowMs: 60 * 60 * 1000 }, // 10k/hour
      platform_admin: { max: 5000, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 2000, windowMs: 60 * 60 * 1000 },
      default: { max: 1000, windowMs: 60 * 60 * 1000 }
    },
    
    // Webhook configurations
    WEBHOOK_CONFIG: {
      super_admin: { max: 100, windowMs: 60 * 60 * 1000 },
      platform_admin: { max: 50, windowMs: 60 * 60 * 1000 },
      organization_admin: { max: 20, windowMs: 60 * 60 * 1000 },
      default: { max: 10, windowMs: 60 * 60 * 1000 }
    }
  }
};

/**
 * Resource quotas and constraints
 * Defines maximum resource usage per admin role
 */
const AdminResourceLimits = {
  /**
   * Concurrent session limits
   * Maximum number of active admin sessions
   */
  CONCURRENT_SESSIONS: {
    super_admin: 10,
    platform_admin: 8,
    organization_admin: 5,
    security_admin: 6,
    system_admin: 6,
    billing_admin: 4,
    default: 3
  },

  /**
   * Storage quotas for admin operations
   * Limits on data storage and file uploads
   */
  STORAGE_QUOTAS: {
    // Upload limits (in bytes)
    FILE_UPLOAD_SIZE: {
      super_admin: 100 * 1024 * 1024, // 100MB
      platform_admin: 50 * 1024 * 1024, // 50MB
      organization_admin: 25 * 1024 * 1024, // 25MB
      default: 10 * 1024 * 1024 // 10MB
    },
    
    // Bulk operation data limits
    BULK_DATA_SIZE: {
      super_admin: 500 * 1024 * 1024, // 500MB
      platform_admin: 200 * 1024 * 1024, // 200MB
      organization_admin: 100 * 1024 * 1024, // 100MB
      default: 50 * 1024 * 1024 // 50MB
    },
    
    // Report generation limits
    REPORT_SIZE: {
      super_admin: 1000 * 1024 * 1024, // 1GB
      platform_admin: 500 * 1024 * 1024, // 500MB
      organization_admin: 200 * 1024 * 1024, // 200MB
      default: 100 * 1024 * 1024 // 100MB
    }
  },

  /**
   * Query and search limits
   * Prevents resource exhaustion from large queries
   */
  QUERY_LIMITS: {
    // Maximum results per query
    MAX_RESULTS: {
      super_admin: 10000,
      platform_admin: 5000,
      organization_admin: 2000,
      default: 1000
    },
    
    // Query timeout (in milliseconds)
    QUERY_TIMEOUT: {
      super_admin: 300000, // 5 minutes
      platform_admin: 180000, // 3 minutes
      organization_admin: 120000, // 2 minutes
      default: 60000 // 1 minute
    },
    
    // Concurrent queries
    CONCURRENT_QUERIES: {
      super_admin: 20,
      platform_admin: 15,
      organization_admin: 10,
      default: 5
    }
  },

  /**
   * Export and backup limits
   * Controls data export operations
   */
  EXPORT_LIMITS: {
    // Maximum export size
    MAX_EXPORT_SIZE: {
      super_admin: 5000 * 1024 * 1024, // 5GB
      platform_admin: 2000 * 1024 * 1024, // 2GB
      organization_admin: 1000 * 1024 * 1024, // 1GB
      default: 500 * 1024 * 1024 // 500MB
    },
    
    // Concurrent exports
    CONCURRENT_EXPORTS: {
      super_admin: 10,
      platform_admin: 6,
      organization_admin: 4,
      default: 2
    },
    
    // Export retention (in days)
    EXPORT_RETENTION: {
      super_admin: 30,
      platform_admin: 14,
      organization_admin: 7,
      default: 3
    }
  }
};

/**
 * Time-based restrictions
 * Controls when certain operations can be performed
 */
const AdminTimeRestrictions = {
  /**
   * Critical operation windows
   * Defines when sensitive operations are allowed
   */
  CRITICAL_OPERATIONS: {
    // Organization deletion
    ORGANIZATION_DELETION: {
      allowedHours: [9, 10, 11, 14, 15, 16], // Business hours only
      excludedDays: [0, 6], // No weekends
      timezone: 'UTC',
      requiresApprovalWindow: 24 * 60 * 60 * 1000 // 24 hours
    },
    
    // System maintenance
    SYSTEM_MAINTENANCE: {
      allowedHours: [22, 23, 0, 1, 2, 3, 4, 5], // Night hours
      excludedDays: [], // Any day allowed
      timezone: 'UTC',
      maxDuration: 4 * 60 * 60 * 1000 // 4 hours max
    },
    
    // Emergency operations (no restrictions)
    EMERGENCY_OPERATIONS: {
      allowedHours: null, // Always allowed
      excludedDays: [],
      timezone: 'UTC'
    }
  },

  /**
   * Session duration limits
   * Maximum session lifetimes by role
   */
  SESSION_DURATIONS: {
    super_admin: 8 * 60 * 60 * 1000, // 8 hours
    platform_admin: 6 * 60 * 60 * 1000, // 6 hours
    organization_admin: 4 * 60 * 60 * 1000, // 4 hours
    security_admin: 6 * 60 * 60 * 1000, // 6 hours
    system_admin: 6 * 60 * 60 * 1000, // 6 hours
    billing_admin: 4 * 60 * 60 * 1000, // 4 hours
    default: 2 * 60 * 60 * 1000 // 2 hours
  },

  /**
   * Idle timeout restrictions
   * Automatic logout after inactivity
   */
  IDLE_TIMEOUTS: {
    super_admin: 60 * 60 * 1000, // 1 hour
    platform_admin: 45 * 60 * 1000, // 45 minutes
    organization_admin: 30 * 60 * 1000, // 30 minutes
    security_admin: 45 * 60 * 1000, // 45 minutes
    system_admin: 45 * 60 * 1000, // 45 minutes
    billing_admin: 30 * 60 * 1000, // 30 minutes
    default: 30 * 60 * 1000 // 30 minutes
  }
};

/**
 * Helper class for managing admin limits
 */
class AdminLimitManager {
  /**
   * Get rate limit for specific operation and role
   * @param {string} operation - Operation type
   * @param {string} role - Admin role
   * @returns {Object|null} Rate limit configuration
   */
  static getRateLimit(operation, role) {
    const [category, subcategory] = operation.split('.');
    const limits = AdminRateLimits[category.toUpperCase()];
    
    if (!limits || !limits[subcategory.toUpperCase()]) {
      return null;
    }
    
    const operationLimits = limits[subcategory.toUpperCase()];
    return operationLimits[role] || operationLimits.default;
  }
  
  /**
   * Get resource limit for specific resource and role
   * @param {string} resource - Resource type
   * @param {string} role - Admin role
   * @returns {number|null} Resource limit
   */
  static getResourceLimit(resource, role) {
    const [category, subcategory] = resource.split('.');
    const limits = AdminResourceLimits[category.toUpperCase()];
    
    if (!limits) return null;
    
    if (subcategory) {
      const subLimits = limits[subcategory.toUpperCase()];
      return subLimits ? (subLimits[role] || subLimits.default) : null;
    }
    
    return limits[role] || limits.default;
  }
  
  /**
   * Check if operation is allowed at current time
   * @param {string} operation - Operation type
   * @param {Date} currentTime - Current timestamp
   * @returns {boolean} Operation allowed
   */
  static isOperationAllowed(operation, currentTime = new Date()) {
    const restrictions = AdminTimeRestrictions.CRITICAL_OPERATIONS[operation];
    if (!restrictions) return true; // No restrictions
    
    // Check allowed hours
    if (restrictions.allowedHours) {
      const hour = currentTime.getUTCHours();
      if (!restrictions.allowedHours.includes(hour)) {
        return false;
      }
    }
    
    // Check excluded days
    if (restrictions.excludedDays) {
      const day = currentTime.getUTCDay();
      if (restrictions.excludedDays.includes(day)) {
        return false;
      }
    }
    
    return true;
  }
  
  /**
   * Get session limits for role
   * @param {string} role - Admin role
   * @returns {Object} Session limits
   */
  static getSessionLimits(role) {
    return {
      maxDuration: AdminTimeRestrictions.SESSION_DURATIONS[role] || 
                   AdminTimeRestrictions.SESSION_DURATIONS.default,
      idleTimeout: AdminTimeRestrictions.IDLE_TIMEOUTS[role] || 
                   AdminTimeRestrictions.IDLE_TIMEOUTS.default,
      maxConcurrent: AdminResourceLimits.CONCURRENT_SESSIONS[role] || 
                     AdminResourceLimits.CONCURRENT_SESSIONS.default
    };
  }
  
  /**
   * Calculate remaining quota for user
   * @param {string} userId - User ID
   * @param {string} resource - Resource type
   * @param {string} role - Admin role
   * @param {Object} usage - Current usage data
   * @returns {Object} Quota information
   */
  static calculateRemainingQuota(userId, resource, role, usage) {
    const limit = this.getResourceLimit(resource, role);
    if (!limit) return { unlimited: true };
    
    const used = usage[userId] || 0;
    const remaining = Math.max(0, limit - used);
    const percentUsed = (used / limit) * 100;
    
    return {
      limit,
      used,
      remaining,
      percentUsed,
      nearLimit: percentUsed > 80,
      atLimit: remaining === 0
    };
  }
}

module.exports = {
  AdminRateLimits,
  AdminResourceLimits,
  AdminTimeRestrictions,
  AdminLimitManager
};