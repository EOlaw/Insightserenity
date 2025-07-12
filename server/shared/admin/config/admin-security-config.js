/**
 * @file Admin Security Configuration
 * @description Security policies, configurations, and enforcement mechanisms for administrative operations
 * @version 1.0.0
 */

const { AdminRoles } = require('../constants/admin-roles');
const { AdminPermissions } = require('../constants/admin-permissions');
const { AdminActions } = require('../constants/admin-actions');

/**
 * Security policies for administrative operations
 * Defines security requirements and enforcement mechanisms
 */
const AdminSecurityPolicies = {
  /**
   * Authentication security policies
   * Controls how admin users authenticate and maintain sessions
   */
  AUTHENTICATION: {
    // Password policies for admin accounts
    PASSWORD_POLICY: {
      minLength: 14,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      preventReuse: 12, // Cannot reuse last 12 passwords
      maxAge: 90 * 24 * 60 * 60 * 1000, // 90 days
      complexityScore: 80, // Minimum complexity score
      preventCommonPasswords: true,
      preventPersonalInfo: true,
      requirePasswordRotation: true
    },

    // Multi-factor authentication requirements
    MFA_POLICY: {
      // MFA requirements by role
      required: {
        super_admin: true,
        platform_admin: true,
        organization_admin: true,
        security_admin: true,
        system_admin: true,
        billing_admin: false, // Optional for billing admin
        default: false
      },
      
      // Supported MFA methods (in order of preference)
      supportedMethods: [
        'webauthn', // Hardware security keys (preferred)
        'totp', // TOTP apps like Google Authenticator
        'sms', // SMS (fallback only)
        'backup_codes' // Emergency backup codes
      ],
      
      // Method requirements
      methodRequirements: {
        super_admin: ['webauthn'], // Must use hardware keys
        platform_admin: ['webauthn', 'totp'], // Hardware keys or TOTP
        organization_admin: ['totp', 'sms'], // TOTP or SMS
        security_admin: ['webauthn', 'totp'], // Hardware keys or TOTP
        system_admin: ['webauthn', 'totp'], // Hardware keys or TOTP
        default: ['totp', 'sms']
      },
      
      // Verification settings
      verificationWindow: 300000, // 5 minutes
      backupCodeCount: 10,
      recoveryProcess: {
        requiresApproval: true,
        approverRoles: ['super_admin', 'platform_admin'],
        maxRecoveryAttempts: 3,
        recoveryWindow: 24 * 60 * 60 * 1000 // 24 hours
      }
    },

    // Account lockout policies
    LOCKOUT_POLICY: {
      maxFailedAttempts: {
        super_admin: 5,
        platform_admin: 4,
        organization_admin: 3,
        default: 3
      },
      
      lockoutDuration: {
        super_admin: 30 * 60 * 1000, // 30 minutes
        platform_admin: 45 * 60 * 1000, // 45 minutes
        organization_admin: 60 * 60 * 1000, // 1 hour
        default: 60 * 60 * 1000
      },
      
      progressiveLockout: true, // Increase duration with repeated lockouts
      unlockMethods: ['time', 'admin_unlock', 'security_unlock'],
      notifyOnLockout: true,
      escalateRepeatedLockouts: true
    }
  },

  /**
   * Access control security policies
   * Controls how admin access is granted and monitored
   */
  ACCESS_CONTROL: {
    // Session security requirements
    SESSION_SECURITY: {
      // IP address validation
      ipValidation: {
        enabled: true,
        allowedChangeCount: 2, // Allow 2 IP changes per session
        requireReauthOnChange: true,
        whitelistEnabled: false, // IP whitelisting disabled by default
        geoLocationTracking: true,
        blockSuspiciousLocations: true
      },
      
      // Device fingerprinting
      deviceFingerprinting: {
        enabled: true,
        trackBrowserFingerprint: true,
        trackScreenResolution: true,
        trackTimezone: true,
        requireReauthOnNewDevice: true,
        deviceTrustDuration: 30 * 24 * 60 * 60 * 1000 // 30 days
      },
      
      // Session lifecycle
      sessionLifecycle: {
        maxConcurrentSessions: {
          super_admin: 5,
          platform_admin: 4,
          organization_admin: 3,
          default: 2
        },
        terminateOnSuspiciousActivity: true,
        requireRecentAuthForSensitive: true,
        recentAuthWindow: 30 * 60 * 1000, // 30 minutes
        sessionTokenRotation: true,
        tokenRotationInterval: 60 * 60 * 1000 // 1 hour
      }
    },

    // Privilege escalation controls
    PRIVILEGE_ESCALATION: {
      // Operations requiring escalation
      requiresEscalation: [
        AdminPermissions.SUPER_ADMIN.EMERGENCY.ALL,
        AdminPermissions.PLATFORM.ORGANIZATIONS.DELETE,
        AdminPermissions.SYSTEM.CONFIG.UPDATE,
        AdminPermissions.SECURITY.ACCESS.EMERGENCY,
        AdminPermissions.PLATFORM.USERS.IMPERSONATE
      ],
      
      // Escalation approval process
      approvalProcess: {
        requiresApproval: true,
        approverCount: 2, // Requires two approvals
        approverRoles: ['super_admin', 'platform_admin'],
        approvalWindow: 4 * 60 * 60 * 1000, // 4 hours
        autoExpiry: 2 * 60 * 60 * 1000, // 2 hours
        requiresJustification: true,
        notifyOnEscalation: true
      },
      
      // Break-glass procedures
      breakGlass: {
        enabled: true,
        allowedRoles: ['super_admin'],
        requiresJustification: true,
        autoRevoke: 30 * 60 * 1000, // 30 minutes
        notifyAllAdmins: true,
        auditRequired: true
      }
    },

    // Role-based access controls
    RBAC: {
      // Role assignment restrictions
      roleAssignment: {
        requiresApproval: {
          super_admin: ['super_admin'],
          platform_admin: ['super_admin', 'platform_admin'],
          organization_admin: ['super_admin', 'platform_admin'],
          security_admin: ['super_admin', 'security_admin'],
          system_admin: ['super_admin', 'system_admin'],
          billing_admin: ['super_admin', 'platform_admin']
        },
        
        // Maximum role assignments
        maxAssignments: {
          super_admin: 3, // Max 3 super admins
          platform_admin: 10,
          organization_admin: 50,
          security_admin: 5,
          system_admin: 8,
          billing_admin: 5
        },
        
        // Role inheritance controls
        inheritanceRules: {
          preventCircularInheritance: true,
          maxInheritanceDepth: 3,
          validatePermissionConflicts: true
        }
      }
    }
  },

  /**
   * Data protection and encryption policies
   * Controls how sensitive data is protected
   */
  DATA_PROTECTION: {
    // Encryption requirements
    ENCRYPTION: {
      // Data at rest
      dataAtRest: {
        algorithm: 'AES-256-GCM',
        keyRotationInterval: 90 * 24 * 60 * 60 * 1000, // 90 days
        requiresHSM: true, // Hardware Security Module for key storage
        encryptionScope: ['pii', 'credentials', 'audit_logs', 'configurations']
      },
      
      // Data in transit
      dataInTransit: {
        tlsVersion: 'TLS 1.3',
        certificatePinning: true,
        requiresMutualTLS: true,
        cipherSuites: [
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256',
          'TLS_AES_128_GCM_SHA256'
        ]
      },
      
      // Key management
      keyManagement: {
        keySize: 256,
        keyDerivationFunction: 'PBKDF2',
        keyStretchingIterations: 100000,
        keyEscrow: false, // No key escrow
        keyRecovery: 'split_knowledge', // Split knowledge recovery
        keyBackup: 'secure_vault'
      }
    },

    // Data classification and handling
    DATA_CLASSIFICATION: {
      // Classification levels
      levels: {
        PUBLIC: { level: 1, retention: '7_years', encryption: false },
        INTERNAL: { level: 2, retention: '5_years', encryption: true },
        CONFIDENTIAL: { level: 3, retention: '3_years', encryption: true },
        RESTRICTED: { level: 4, retention: '1_year', encryption: true },
        TOP_SECRET: { level: 5, retention: '6_months', encryption: true }
      },
      
      // Default classifications
      defaultClassifications: {
        admin_logs: 'CONFIDENTIAL',
        user_data: 'CONFIDENTIAL',
        system_configs: 'RESTRICTED',
        security_events: 'RESTRICTED',
        audit_trails: 'RESTRICTED',
        emergency_procedures: 'TOP_SECRET'
      },
      
      // Handling requirements
      handlingRequirements: {
        CONFIDENTIAL: {
          accessLogging: true,
          encryptionRequired: true,
          transmissionRestrictions: ['secure_channels'],
          storageRestrictions: ['encrypted_storage']
        },
        RESTRICTED: {
          accessLogging: true,
          encryptionRequired: true,
          needToKnowBasis: true,
          transmissionRestrictions: ['secure_channels', 'approved_recipients'],
          storageRestrictions: ['encrypted_storage', 'access_controlled']
        }
      }
    }
  },

  /**
   * Monitoring and threat detection policies
   * Controls security monitoring and incident response
   */
  THREAT_DETECTION: {
    // Anomaly detection settings
    ANOMALY_DETECTION: {
      // Behavioral analysis
      behavioralAnalysis: {
        enabled: true,
        baselineWindow: 30 * 24 * 60 * 60 * 1000, // 30 days
        sensitivityLevel: 'medium',
        machinelearningEnabled: true,
        
        // Monitored behaviors
        monitoredBehaviors: [
          'login_patterns',
          'access_patterns',
          'geographic_anomalies',
          'time_based_anomalies',
          'privilege_usage_patterns',
          'data_access_patterns'
        ],
        
        // Alert thresholds
        alertThresholds: {
          geographic_anomaly: 0.1, // 10% confidence threshold
          time_anomaly: 0.15, // 15% confidence threshold
          access_pattern_anomaly: 0.2, // 20% confidence threshold
          privilege_escalation: 0.05 // 5% confidence threshold (highly sensitive)
        }
      },
      
      // Real-time monitoring
      realTimeMonitoring: {
        enabled: true,
        checkInterval: 60000, // 1 minute
        alertLatency: 5000, // 5 seconds max alert latency
        
        // Monitored events
        monitoredEvents: [
          'failed_authentication',
          'privilege_escalation',
          'suspicious_api_usage',
          'bulk_operations',
          'configuration_changes',
          'emergency_access',
          'impersonation_activities'
        ]
      }
    },

    // Threat response automation
    THREAT_RESPONSE: {
      // Automated responses
      automatedResponses: {
        enabled: true,
        responseLatency: 10000, // 10 seconds max response time
        
        // Response actions
        responseActions: {
          suspend_session: {
            triggers: ['confirmed_compromise', 'high_risk_activity'],
            autoExecute: true,
            requiresApproval: false
          },
          
          lock_account: {
            triggers: ['multiple_failed_auth', 'suspicious_location'],
            autoExecute: true,
            requiresApproval: false
          },
          
          revoke_privileges: {
            triggers: ['privilege_abuse', 'policy_violation'],
            autoExecute: false,
            requiresApproval: true
          },
          
          emergency_notification: {
            triggers: ['security_incident', 'data_breach'],
            autoExecute: true,
            requiresApproval: false
          }
        }
      },
      
      // Incident escalation
      incidentEscalation: {
        enabled: true,
        escalationLevels: [
          {
            level: 1,
            threshold: 'low_risk',
            notify: ['security_team'],
            responseTime: 4 * 60 * 60 * 1000 // 4 hours
          },
          {
            level: 2,
            threshold: 'medium_risk',
            notify: ['security_team', 'security_admin'],
            responseTime: 60 * 60 * 1000 // 1 hour
          },
          {
            level: 3,
            threshold: 'high_risk',
            notify: ['security_team', 'security_admin', 'platform_admin'],
            responseTime: 15 * 60 * 1000 // 15 minutes
          },
          {
            level: 4,
            threshold: 'critical_risk',
            notify: ['all_admins', 'emergency_contacts'],
            responseTime: 5 * 60 * 1000 // 5 minutes
          }
        ]
      }
    }
  },

  /**
   * Compliance and audit policies
   * Controls compliance monitoring and audit requirements
   */
  COMPLIANCE: {
    // Audit logging requirements
    AUDIT_LOGGING: {
      // Required audit events
      requiredEvents: [
        'authentication_events',
        'authorization_events',
        'privilege_changes',
        'configuration_changes',
        'data_access_events',
        'security_events',
        'administrative_actions',
        'emergency_procedures'
      ],
      
      // Audit log retention
      retention: {
        authentication_events: 2 * 365 * 24 * 60 * 60 * 1000, // 2 years
        security_events: 7 * 365 * 24 * 60 * 60 * 1000, // 7 years
        administrative_actions: 5 * 365 * 24 * 60 * 60 * 1000, // 5 years
        emergency_procedures: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
        default: 3 * 365 * 24 * 60 * 60 * 1000 // 3 years
      },
      
      // Audit log protection
      protection: {
        tamperProofing: true,
        digitalSignatures: true,
        hashChaining: true,
        immutableStorage: true,
        encryptionRequired: true,
        accessRestricted: true
      }
    },

    // Compliance frameworks
    FRAMEWORKS: {
      // SOC 2 Type II compliance
      SOC2: {
        enabled: true,
        requirements: {
          security: true,
          availability: true,
          processing_integrity: true,
          confidentiality: true,
          privacy: false // Optional
        },
        auditFrequency: 'annual',
        nextAudit: new Date('2025-12-31')
      },
      
      // ISO 27001 compliance
      ISO27001: {
        enabled: true,
        certificationStatus: 'certified',
        lastAudit: new Date('2024-06-15'),
        nextAudit: new Date('2025-06-15'),
        surveillanceAudits: 'quarterly'
      },
      
      // GDPR compliance
      GDPR: {
        enabled: true,
        dataProtectionOfficer: true,
        privacyImpactAssessments: true,
        dataBreachNotification: {
          authorityNotification: 72 * 60 * 60 * 1000, // 72 hours
          individualNotification: 30 * 24 * 60 * 60 * 1000 // 30 days
        }
      },
      
      // CCPA compliance
      CCPA: {
        enabled: true,
        consumerRights: ['know', 'delete', 'opt_out', 'non_discrimination'],
        responseTimeframe: 45 * 24 * 60 * 60 * 1000 // 45 days
      }
    }
  }
};

/**
 * Security configuration settings
 * Technical configurations for security implementation
 */
const AdminSecurityConfig = {
  /**
   * Cryptographic settings
   * Encryption and hashing configurations
   */
  CRYPTOGRAPHY: {
    // Hashing configurations
    hashing: {
      passwords: {
        algorithm: 'bcrypt',
        rounds: 14,
        saltRounds: 12
      },
      
      tokens: {
        algorithm: 'SHA-256',
        iterations: 100000
      },
      
      fingerprints: {
        algorithm: 'SHA-512',
        salt: true
      }
    },
    
    // JWT configurations
    jwt: {
      algorithm: 'RS256',
      keySize: 2048,
      issuer: 'admin-system',
      audience: 'admin-users',
      expiration: {
        access_token: 15 * 60, // 15 minutes
        refresh_token: 7 * 24 * 60 * 60, // 7 days
        session_token: 8 * 60 * 60 // 8 hours
      },
      
      claims: {
        required: ['sub', 'iat', 'exp', 'iss', 'aud'],
        custom: ['role', 'permissions', 'session_id', 'device_id']
      }
    }
  },

  /**
   * Security headers configuration
   * HTTP security headers for admin interfaces
   */
  SECURITY_HEADERS: {
    // Content Security Policy
    csp: {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", "data:", "https:"],
      'connect-src': ["'self'"],
      'font-src': ["'self'"],
      'object-src': ["'none'"],
      'base-uri': ["'self'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"],
      'upgrade-insecure-requests': true
    },
    
    // Other security headers
    headers: {
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'X-XSS-Protection': '1; mode=block',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
    }
  },

  /**
   * Rate limiting configurations
   * Advanced rate limiting for security
   */
  RATE_LIMITING: {
    // Adaptive rate limiting
    adaptive: {
      enabled: true,
      baselineWindow: 60 * 60 * 1000, // 1 hour
      adaptationFactor: 0.8, // Reduce limits by 20% under attack
      recoveryTime: 30 * 60 * 1000, // 30 minutes recovery time
      
      // Threat-based adjustments
      threatAdjustments: {
        'under_attack': 0.1, // Reduce to 10% of normal limits
        'suspicious_activity': 0.5, // Reduce to 50% of normal limits
        'high_load': 0.7, // Reduce to 70% of normal limits
        'normal': 1.0 // Normal limits
      }
    },
    
    // Distributed rate limiting
    distributed: {
      enabled: true,
      coordinationService: 'redis',
      syncInterval: 5000, // 5 seconds
      fallbackMode: 'local' // Fallback to local limits if coordination fails
    }
  }
};

/**
 * Security validation rules
 * Rules for validating security compliance
 */
const AdminSecurityValidation = {
  /**
   * Input validation rules
   * Security validation for admin inputs
   */
  INPUT_VALIDATION: {
    // SQL injection prevention
    sqlInjection: {
      enabled: true,
      patterns: [
        /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)/i,
        /('|(\\x27)|(\\x2D)|-|\\x23|#)/,
        /((\%3D)|(=))[^\n]*((\%27)|(\\x27)|(')|(\-\-)|(\%3B)|(;))/i
      ],
      sanitization: true,
      blocking: true
    },
    
    // XSS prevention
    xssPrevention: {
      enabled: true,
      patterns: [
        /<script[^>]*>.*?<\/script>/gi,
        /<iframe[^>]*>.*?<\/iframe>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi
      ],
      sanitization: true,
      encoding: true
    },
    
    // Path traversal prevention
    pathTraversal: {
      enabled: true,
      patterns: [
        /\.\./,
        /\.\.\//,
        /\.\.\\/,
        /%2e%2e%2f/i,
        /%252e%252e%252f/i
      ],
      blocking: true
    }
  },

  /**
   * Content validation rules
   * Validation for uploaded content and files
   */
  CONTENT_VALIDATION: {
    // File upload validation
    fileUpload: {
      allowedExtensions: ['.pdf', '.doc', '.docx', '.txt', '.csv', '.xlsx'],
      maxFileSize: 50 * 1024 * 1024, // 50MB
      virusScanning: true,
      contentTypeValidation: true,
      
      // Executable file prevention
      blockedExtensions: [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.app', '.deb', '.pkg', '.dmg', '.iso'
      ],
      
      // Content scanning
      contentScanning: {
        malwareDetection: true,
        suspiciousPatterns: true,
        encryptedContent: 'block' // Block encrypted files
      }
    }
  }
};

/**
 * Helper class for security management
 */
class AdminSecurityManager {
  /**
   * Validate security requirements for operation
   * @param {string} operation - Operation being performed
   * @param {Object} user - User performing operation
   * @param {Object} context - Operation context
   * @returns {Object} Validation result
   */
  static validateSecurityRequirements(operation, user, context) {
    const requirements = this.getSecurityRequirements(operation);
    const validation = {
      passed: true,
      requirements: [],
      violations: []
    };
    
    // Check MFA requirements
    if (requirements.requiresMFA && !context.mfaVerified) {
      validation.passed = false;
      validation.requirements.push('mfa_verification');
    }
    
    // Check recent authentication
    if (requirements.requiresRecentAuth && !this.hasRecentAuth(context)) {
      validation.passed = false;
      validation.requirements.push('recent_authentication');
    }
    
    // Check approval requirements
    if (requirements.requiresApproval && !context.hasApproval) {
      validation.passed = false;
      validation.requirements.push('approval');
    }
    
    return validation;
  }
  
  /**
   * Get security requirements for operation
   * @param {string} operation - Operation type
   * @returns {Object} Security requirements
   */
  static getSecurityRequirements(operation) {
    // Define operation-specific requirements
    const operationRequirements = {
      [AdminActions.USER.IMPERSONATE_START]: {
        requiresMFA: true,
        requiresRecentAuth: true,
        requiresApproval: true,
        requiresJustification: true
      },
      
      [AdminActions.SYSTEM.CONFIG_UPDATE]: {
        requiresMFA: true,
        requiresRecentAuth: true,
        requiresApproval: true,
        requiresJustification: true
      },
      
      [AdminActions.ORGANIZATION.DELETE]: {
        requiresMFA: true,
        requiresRecentAuth: true,
        requiresApproval: true,
        requiresJustification: true,
        requiresTimeWindow: true
      }
    };
    
    return operationRequirements[operation] || {
      requiresMFA: false,
      requiresRecentAuth: false,
      requiresApproval: false
    };
  }
  
  /**
   * Check if user has recent authentication
   * @param {Object} context - Operation context
   * @returns {boolean} Has recent authentication
   */
  static hasRecentAuth(context) {
    if (!context.lastAuthTime) return false;
    
    const recentWindow = AdminSecurityPolicies.ACCESS_CONTROL.SESSION_SECURITY.sessionLifecycle.recentAuthWindow;
    const timeSinceAuth = Date.now() - context.lastAuthTime;
    
    return timeSinceAuth <= recentWindow;
  }
  
  /**
   * Generate security event for audit logging
   * @param {string} eventType - Type of security event
   * @param {Object} details - Event details
   * @returns {Object} Security event object
   */
  static generateSecurityEvent(eventType, details) {
    return {
      timestamp: new Date(),
      eventType,
      severity: this.getEventSeverity(eventType),
      details,
      sourceIp: details.sourceIp,
      userAgent: details.userAgent,
      sessionId: details.sessionId,
      userId: details.userId,
      fingerprint: this.generateEventFingerprint(eventType, details)
    };
  }
  
  /**
   * Get severity level for security event
   * @param {string} eventType - Event type
   * @returns {string} Severity level
   */
  static getEventSeverity(eventType) {
    const severityMap = {
      'failed_authentication': 'medium',
      'privilege_escalation': 'high',
      'suspicious_activity': 'high',
      'policy_violation': 'medium',
      'security_incident': 'critical',
      'emergency_access': 'critical',
      'data_breach': 'critical'
    };
    
    return severityMap[eventType] || 'low';
  }
  
  /**
   * Generate fingerprint for security event
   * @param {string} eventType - Event type
   * @param {Object} details - Event details
   * @returns {string} Event fingerprint
   */
  static generateEventFingerprint(eventType, details) {
    const crypto = require('crypto');
    const fingerprintData = `${eventType}-${details.userId}-${details.sourceIp}-${details.timestamp}`;
    return crypto.createHash('sha256').update(fingerprintData).digest('hex');
  }
}

module.exports = {
  AdminSecurityPolicies,
  AdminSecurityConfig,
  AdminSecurityValidation,
  AdminSecurityManager
};