/**
 * @file Admin Features Configuration
 * @description Feature toggles and capability configurations for administrative operations
 * @version 1.0.0
 */

const { AdminRoles } = require('../constants/admin-roles');
const { AdminPermissions } = require('../constants/admin-permissions');

/**
 * Feature flags for administrative functionality
 * Controls which features are available to different admin roles
 */
const AdminFeatures = {
  /**
   * Platform-wide features
   * Controls major platform capabilities
   */
  PLATFORM: {
    // Multi-tenancy features
    MULTI_TENANCY: {
      enabled: true,
      requiredRole: 'platform_admin',
      requiredPermissions: [AdminPermissions.PLATFORM.ORGANIZATIONS.ALL],
      beta: false,
      rolloutPercentage: 100
    },
    
    // Organization management
    ORGANIZATION_MANAGEMENT: {
      enabled: true,
      requiredRole: 'platform_admin',
      requiredPermissions: [AdminPermissions.PLATFORM.ORGANIZATIONS.ALL],
      features: {
        CREATE_ORGANIZATION: true,
        DELETE_ORGANIZATION: true,
        MERGE_ORGANIZATIONS: false, // Beta feature
        BULK_OPERATIONS: true,
        ORGANIZATION_TEMPLATES: true,
        CROSS_ORG_ANALYTICS: true
      }
    },
    
    // Global user management
    GLOBAL_USER_MANAGEMENT: {
      enabled: true,
      requiredRole: 'platform_admin',
      requiredPermissions: [AdminPermissions.PLATFORM.USERS.ALL],
      features: {
        IMPERSONATION: true,
        BULK_USER_OPERATIONS: true,
        CROSS_ORG_USER_SEARCH: true,
        GLOBAL_USER_ANALYTICS: true,
        USER_MIGRATION: false // Under development
      }
    },
    
    // Platform billing features
    BILLING_MANAGEMENT: {
      enabled: true,
      requiredRole: 'platform_admin',
      requiredPermissions: [AdminPermissions.PLATFORM.BILLING.ALL],
      features: {
        REVENUE_ANALYTICS: true,
        AUTOMATED_BILLING: true,
        CUSTOM_PRICING: true,
        BULK_REFUNDS: true,
        SUBSCRIPTION_MANAGEMENT: true,
        PAYMENT_PROCESSING: true
      }
    }
  },

  /**
   * Organization-level features
   * Controls organization-specific administrative capabilities
   */
  ORGANIZATION: {
    // Member management
    MEMBER_MANAGEMENT: {
      enabled: true,
      requiredRole: 'organization_admin',
      requiredPermissions: [AdminPermissions.ORGANIZATION.MEMBERS.ALL],
      features: {
        BULK_INVITE: true,
        ROLE_TEMPLATES: true,
        MEMBER_ANALYTICS: true,
        AUTOMATED_ONBOARDING: true,
        CUSTOM_ROLES: false // Premium feature
      }
    },
    
    // Organization settings
    SETTINGS_MANAGEMENT: {
      enabled: true,
      requiredRole: 'organization_admin',
      requiredPermissions: [AdminPermissions.ORGANIZATION.SETTINGS.ALL],
      features: {
        CUSTOM_BRANDING: true,
        SSO_CONFIGURATION: true,
        DOMAIN_MANAGEMENT: true,
        SECURITY_POLICIES: true,
        INTEGRATION_MANAGEMENT: true,
        WORKFLOW_AUTOMATION: false // Enterprise feature
      }
    },
    
    // Project management
    PROJECT_MANAGEMENT: {
      enabled: true,
      requiredRole: 'organization_admin',
      requiredPermissions: [AdminPermissions.ORGANIZATION.PROJECTS.ALL],
      features: {
        PROJECT_TEMPLATES: true,
        BULK_PROJECT_OPERATIONS: true,
        PROJECT_ANALYTICS: true,
        RESOURCE_ALLOCATION: true,
        CROSS_PROJECT_REPORTING: true
      }
    }
  },

  /**
   * Security features
   * Advanced security and compliance capabilities
   */
  SECURITY: {
    // Audit and compliance
    AUDIT_MANAGEMENT: {
      enabled: true,
      requiredRole: 'security_admin',
      requiredPermissions: [AdminPermissions.SECURITY.AUDIT.ALL],
      features: {
        REAL_TIME_MONITORING: true,
        AUTOMATED_ALERTS: true,
        COMPLIANCE_REPORTING: true,
        FORENSIC_ANALYSIS: false, // Requires special access
        DATA_RETENTION_POLICIES: true,
        AUDIT_TRAIL_EXPORT: true
      }
    },
    
    // Threat detection
    THREAT_DETECTION: {
      enabled: true,
      requiredRole: 'security_admin',
      requiredPermissions: [AdminPermissions.SECURITY.THREATS.ALL],
      features: {
        ANOMALY_DETECTION: true,
        BEHAVIORAL_ANALYSIS: true,
        THREAT_INTELLIGENCE: false, // Premium feature
        AUTOMATED_RESPONSE: false, // Under development
        SECURITY_SCORING: true
      }
    },
    
    // Access control
    ACCESS_CONTROL: {
      enabled: true,
      requiredRole: 'security_admin',
      requiredPermissions: [AdminPermissions.SECURITY.ACCESS.ALL],
      features: {
        CONDITIONAL_ACCESS: true,
        DEVICE_MANAGEMENT: true,
        SESSION_CONTROL: true,
        RISK_BASED_AUTH: true,
        ZERO_TRUST_MODEL: false // Enterprise feature
      }
    }
  },

  /**
   * System administration features
   * Technical system management capabilities
   */
  SYSTEM: {
    // Configuration management
    CONFIG_MANAGEMENT: {
      enabled: true,
      requiredRole: 'system_admin',
      requiredPermissions: [AdminPermissions.SYSTEM.CONFIG.ALL],
      features: {
        ENVIRONMENT_MANAGEMENT: true,
        CONFIGURATION_VERSIONING: true,
        AUTOMATED_DEPLOYMENT: false, // Requires additional setup
        ROLLBACK_CAPABILITIES: true,
        CONFIG_VALIDATION: true
      }
    },
    
    // Monitoring and observability
    MONITORING: {
      enabled: true,
      requiredRole: 'system_admin',
      requiredPermissions: [AdminPermissions.SYSTEM.MONITORING.ALL],
      features: {
        REAL_TIME_METRICS: true,
        CUSTOM_DASHBOARDS: true,
        ALERTING_SYSTEM: true,
        LOG_AGGREGATION: true,
        PERFORMANCE_ANALYTICS: true,
        PREDICTIVE_ANALYSIS: false // Premium feature
      }
    },
    
    // Backup and recovery
    BACKUP_MANAGEMENT: {
      enabled: true,
      requiredRole: 'system_admin',
      requiredPermissions: [AdminPermissions.SYSTEM.BACKUP.ALL],
      features: {
        AUTOMATED_BACKUPS: true,
        INCREMENTAL_BACKUPS: true,
        CROSS_REGION_REPLICATION: false, // Enterprise feature
        DISASTER_RECOVERY: true,
        BACKUP_ENCRYPTION: true,
        RESTORE_TESTING: false // Under development
      }
    }
  },

  /**
   * Advanced features requiring special access
   * High-privilege operations with additional restrictions
   */
  ADVANCED: {
    // Emergency operations
    EMERGENCY_ACCESS: {
      enabled: true,
      requiredRole: 'super_admin',
      requiredPermissions: [AdminPermissions.SUPER_ADMIN.EMERGENCY.ALL],
      restrictions: {
        requiresMultipleApprovals: true,
        timeboxed: true,
        auditRequired: true,
        breakGlassOnly: true
      },
      features: {
        EMERGENCY_OVERRIDE: true,
        SYSTEM_LOCKDOWN: true,
        FORCE_PASSWORD_RESET: true,
        EMERGENCY_COMMUNICATION: true
      }
    },
    
    // Impersonation capabilities
    USER_IMPERSONATION: {
      enabled: true,
      requiredRole: 'platform_admin',
      requiredPermissions: [AdminPermissions.PLATFORM.USERS.IMPERSONATE],
      restrictions: {
        requiresJustification: true,
        timeboxed: true,
        auditRequired: true,
        approvalRequired: true
      },
      features: {
        FULL_IMPERSONATION: true,
        VIEW_ONLY_MODE: true,
        SESSION_RECORDING: true,
        AUTOMATIC_LOGOUT: true
      }
    }
  }
};

/**
 * Feature rollout configurations
 * Controls gradual feature rollouts and A/B testing
 */
const FeatureRollouts = {
  // Beta features being tested
  BETA_FEATURES: {
    ORGANIZATION_MERGE: {
      percentage: 10,
      targetRoles: ['super_admin', 'platform_admin'],
      startDate: new Date('2025-01-01'),
      endDate: new Date('2025-06-01')
    },
    
    AI_ASSISTED_ADMIN: {
      percentage: 5,
      targetRoles: ['super_admin'],
      startDate: new Date('2025-02-01'),
      endDate: new Date('2025-08-01')
    },
    
    PREDICTIVE_ANALYTICS: {
      percentage: 25,
      targetRoles: ['platform_admin', 'organization_admin'],
      startDate: new Date('2025-01-15'),
      endDate: new Date('2025-07-15')
    }
  },
  
  // Features in development
  EXPERIMENTAL_FEATURES: {
    AUTOMATED_INCIDENT_RESPONSE: {
      percentage: 1,
      targetRoles: ['super_admin'],
      enabled: false
    },
    
    BLOCKCHAIN_AUDIT_TRAIL: {
      percentage: 0,
      targetRoles: ['super_admin'],
      enabled: false
    }
  }
};

/**
 * Feature dependencies
 * Defines which features require others to be enabled
 */
const FeatureDependencies = {
  'ORGANIZATION.MEMBER_MANAGEMENT.AUTOMATED_ONBOARDING': [
    'ORGANIZATION.SETTINGS_MANAGEMENT.WORKFLOW_AUTOMATION'
  ],
  
  'SECURITY.THREAT_DETECTION.AUTOMATED_RESPONSE': [
    'SECURITY.THREAT_DETECTION.ANOMALY_DETECTION',
    'SECURITY.AUDIT_MANAGEMENT.REAL_TIME_MONITORING'
  ],
  
  'SYSTEM.BACKUP_MANAGEMENT.RESTORE_TESTING': [
    'SYSTEM.BACKUP_MANAGEMENT.AUTOMATED_BACKUPS',
    'SYSTEM.MONITORING.REAL_TIME_METRICS'
  ],
  
  'ADVANCED.USER_IMPERSONATION.SESSION_RECORDING': [
    'SECURITY.AUDIT_MANAGEMENT.REAL_TIME_MONITORING'
  ]
};

/**
 * Helper functions for feature management
 */
class AdminFeatureManager {
  /**
   * Check if a feature is enabled for a user
   * @param {string} featurePath - Dot notation path to feature
   * @param {Object} user - User object with role information
   * @returns {boolean} Feature enabled status
   */
  static isFeatureEnabled(featurePath, user) {
    const feature = this.getFeatureByPath(featurePath);
    if (!feature) return false;
    
    // Check if feature is globally enabled
    if (!feature.enabled) return false;
    
    // Check role requirements
    if (feature.requiredRole && !this.hasRequiredRole(user, feature.requiredRole)) {
      return false;
    }
    
    // Check permission requirements
    if (feature.requiredPermissions && !this.hasRequiredPermissions(user, feature.requiredPermissions)) {
      return false;
    }
    
    // Check rollout percentage
    if (feature.rolloutPercentage && !this.isInRollout(user, feature.rolloutPercentage)) {
      return false;
    }
    
    // Check dependencies
    if (!this.checkDependencies(featurePath, user)) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Get feature configuration by path
   * @param {string} path - Dot notation path
   * @returns {Object|null} Feature configuration
   */
  static getFeatureByPath(path) {
    const parts = path.split('.');
    let current = AdminFeatures;
    
    for (const part of parts) {
      if (current[part]) {
        current = current[part];
      } else {
        return null;
      }
    }
    
    return current;
  }
  
  /**
   * Check if user has required role
   * @param {Object} user - User object
   * @param {string} requiredRole - Required role name
   * @returns {boolean} Has required role
   */
  static hasRequiredRole(user, requiredRole) {
    if (!user.role) return false;
    
    const userRole = user.role.primary || user.role.name;
    const role = AdminRoles[userRole.toUpperCase()];
    
    if (!role) return false;
    
    // Check exact match
    if (role.name === requiredRole) return true;
    
    // Check if user role level is sufficient
    const requiredRoleConfig = Object.values(AdminRoles)
      .find(r => r.name === requiredRole);
    
    if (requiredRoleConfig && role.level >= requiredRoleConfig.level) {
      return true;
    }
    
    return false;
  }
  
  /**
   * Check if user has required permissions
   * @param {Object} user - User object
   * @param {Array} requiredPermissions - Array of required permissions
   * @returns {boolean} Has all required permissions
   */
  static hasRequiredPermissions(user, requiredPermissions) {
    if (!user.permissions) return false;
    
    return requiredPermissions.every(permission => 
      user.permissions.includes(permission)
    );
  }
  
  /**
   * Check if user is in rollout percentage
   * @param {Object} user - User object
   * @param {number} percentage - Rollout percentage
   * @returns {boolean} Is in rollout
   */
  static isInRollout(user, percentage) {
    if (percentage >= 100) return true;
    
    // Use user ID hash to determine rollout inclusion
    const hash = this.hashString(user._id.toString());
    return (hash % 100) < percentage;
  }
  
  /**
   * Check feature dependencies
   * @param {string} featurePath - Feature path
   * @param {Object} user - User object
   * @returns {boolean} Dependencies satisfied
   */
  static checkDependencies(featurePath, user) {
    const dependencies = FeatureDependencies[featurePath];
    if (!dependencies) return true;
    
    return dependencies.every(dependency => 
      this.isFeatureEnabled(dependency, user)
    );
  }
  
  /**
   * Hash string for consistent percentage calculations
   * @param {string} str - String to hash
   * @returns {number} Hash value
   */
  static hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash);
  }
  
  /**
   * Get all enabled features for a user
   * @param {Object} user - User object
   * @returns {Array} Array of enabled feature paths
   */
  static getEnabledFeatures(user) {
    const enabledFeatures = [];
    
    const checkFeatures = (features, path = '') => {
      Object.entries(features).forEach(([key, value]) => {
        const currentPath = path ? `${path}.${key}` : key;
        
        if (value.enabled !== undefined) {
          // This is a feature configuration
          if (this.isFeatureEnabled(currentPath, user)) {
            enabledFeatures.push(currentPath);
          }
        } else if (typeof value === 'object') {
          // This is a feature category
          checkFeatures(value, currentPath);
        }
      });
    };
    
    checkFeatures(AdminFeatures);
    return enabledFeatures;
  }
}

module.exports = {
  AdminFeatures,
  FeatureRollouts,
  FeatureDependencies,
  AdminFeatureManager
};