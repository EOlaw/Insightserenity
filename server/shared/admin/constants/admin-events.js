/**
 * @file Admin Events Constants
 * @description Comprehensive definition of administrative event types for audit logging and monitoring
 * @version 1.0.0
 */

/**
 * Administrative event types for comprehensive audit logging
 * These events are used for:
 * - Audit trail creation
 * - Security monitoring
 * - Compliance reporting
 * - Activity analysis
 * - Alert triggering
 */
const AdminEvents = {
  /**
   * Authentication Events
   * Track all authentication-related activities
   */
  AUTHENTICATION: {
    LOGIN_SUCCESS: 'admin.auth.login_success',
    LOGIN_FAILURE: 'admin.auth.login_failure',
    LOGIN_BLOCKED: 'admin.auth.login_blocked',
    LOGOUT: 'admin.auth.logout',
    SESSION_CREATED: 'admin.auth.session_created',
    SESSION_EXPIRED: 'admin.auth.session_expired',
    SESSION_TERMINATED: 'admin.auth.session_terminated',
    SESSION_RENEWED: 'admin.auth.session_renewed',
    PASSWORD_CHANGED: 'admin.auth.password_changed',
    PASSWORD_RESET_REQUESTED: 'admin.auth.password_reset_requested',
    PASSWORD_RESET_COMPLETED: 'admin.auth.password_reset_completed',
    MFA_ENABLED: 'admin.auth.mfa_enabled',
    MFA_DISABLED: 'admin.auth.mfa_disabled',
    MFA_VERIFIED: 'admin.auth.mfa_verified',
    MFA_FAILED: 'admin.auth.mfa_failed',
    MFA_BACKUP_USED: 'admin.auth.mfa_backup_used',
    API_KEY_CREATED: 'admin.auth.api_key_created',
    API_KEY_USED: 'admin.auth.api_key_used',
    API_KEY_REVOKED: 'admin.auth.api_key_revoked',
    ELEVATION_REQUESTED: 'admin.auth.elevation_requested',
    ELEVATION_GRANTED: 'admin.auth.elevation_granted',
    ELEVATION_DENIED: 'admin.auth.elevation_denied'
  },

  /**
   * Authorization Events
   * Track permission and access control changes
   */
  AUTHORIZATION: {
    PERMISSION_GRANTED: 'admin.authz.permission_granted',
    PERMISSION_REVOKED: 'admin.authz.permission_revoked',
    PERMISSION_CHECKED: 'admin.authz.permission_checked',
    PERMISSION_DENIED: 'admin.authz.permission_denied',
    ROLE_ASSIGNED: 'admin.authz.role_assigned',
    ROLE_REMOVED: 'admin.authz.role_removed',
    ROLE_CREATED: 'admin.authz.role_created',
    ROLE_UPDATED: 'admin.authz.role_updated',
    ROLE_DELETED: 'admin.authz.role_deleted',
    ACCESS_DENIED: 'admin.authz.access_denied',
    RESOURCE_ACCESS_GRANTED: 'admin.authz.resource_access_granted',
    RESOURCE_ACCESS_DENIED: 'admin.authz.resource_access_denied',
    IMPERSONATION_STARTED: 'admin.authz.impersonation_started',
    IMPERSONATION_ENDED: 'admin.authz.impersonation_ended'
  },

  /**
   * User Management Events
   * Track user lifecycle and management activities
   */
  USER_MANAGEMENT: {
    USER_CREATED: 'admin.user.created',
    USER_UPDATED: 'admin.user.updated',
    USER_DELETED: 'admin.user.deleted',
    USER_SUSPENDED: 'admin.user.suspended',
    USER_REACTIVATED: 'admin.user.reactivated',
    USER_LOCKED: 'admin.user.locked',
    USER_UNLOCKED: 'admin.user.unlocked',
    USER_EMAIL_VERIFIED: 'admin.user.email_verified',
    USER_EMAIL_CHANGED: 'admin.user.email_changed',
    USER_PROFILE_UPDATED: 'admin.user.profile_updated',
    USER_SETTINGS_CHANGED: 'admin.user.settings_changed',
    USER_EXPORT_REQUESTED: 'admin.user.export_requested',
    USER_DATA_ANONYMIZED: 'admin.user.data_anonymized',
    BULK_USER_OPERATION: 'admin.user.bulk_operation',
    USER_MERGE_COMPLETED: 'admin.user.merge_completed'
  },

  /**
   * Organization Events
   * Track organization management activities
   */
  ORGANIZATION: {
    ORG_CREATED: 'admin.org.created',
    ORG_UPDATED: 'admin.org.updated',
    ORG_DELETED: 'admin.org.deleted',
    ORG_SUSPENDED: 'admin.org.suspended',
    ORG_REACTIVATED: 'admin.org.reactivated',
    ORG_PLAN_CHANGED: 'admin.org.plan_changed',
    ORG_LIMITS_UPDATED: 'admin.org.limits_updated',
    ORG_BILLING_UPDATED: 'admin.org.billing_updated',
    ORG_MEMBER_ADDED: 'admin.org.member_added',
    ORG_MEMBER_REMOVED: 'admin.org.member_removed',
    ORG_MEMBER_ROLE_CHANGED: 'admin.org.member_role_changed',
    ORG_OWNER_TRANSFERRED: 'admin.org.owner_transferred',
    ORG_DOMAIN_ADDED: 'admin.org.domain_added',
    ORG_DOMAIN_VERIFIED: 'admin.org.domain_verified',
    ORG_DOMAIN_REMOVED: 'admin.org.domain_removed',
    ORG_SSO_CONFIGURED: 'admin.org.sso_configured',
    ORG_SSO_DISABLED: 'admin.org.sso_disabled',
    ORG_MERGED: 'admin.org.merged',
    ORG_SPLIT: 'admin.org.split'
  },

  /**
   * System Events
   * Track system-level configuration and maintenance
   */
  SYSTEM: {
    CONFIG_CHANGED: 'admin.system.config_changed',
    CONFIG_EXPORTED: 'admin.system.config_exported',
    CONFIG_IMPORTED: 'admin.system.config_imported',
    MAINTENANCE_MODE_ENABLED: 'admin.system.maintenance_enabled',
    MAINTENANCE_MODE_DISABLED: 'admin.system.maintenance_disabled',
    BACKUP_STARTED: 'admin.system.backup_started',
    BACKUP_COMPLETED: 'admin.system.backup_completed',
    BACKUP_FAILED: 'admin.system.backup_failed',
    RESTORE_STARTED: 'admin.system.restore_started',
    RESTORE_COMPLETED: 'admin.system.restore_completed',
    RESTORE_FAILED: 'admin.system.restore_failed',
    CACHE_CLEARED: 'admin.system.cache_cleared',
    INDEX_REBUILT: 'admin.system.index_rebuilt',
    MIGRATION_STARTED: 'admin.system.migration_started',
    MIGRATION_COMPLETED: 'admin.system.migration_completed',
    MIGRATION_FAILED: 'admin.system.migration_failed',
    SERVICE_STARTED: 'admin.system.service_started',
    SERVICE_STOPPED: 'admin.system.service_stopped',
    SERVICE_RESTARTED: 'admin.system.service_restarted',
    HEALTH_CHECK_FAILED: 'admin.system.health_check_failed'
  },

  /**
   * Security Events
   * Track security-related incidents and changes
   */
  SECURITY: {
    THREAT_DETECTED: 'admin.security.threat_detected',
    THREAT_BLOCKED: 'admin.security.threat_blocked',
    SUSPICIOUS_ACTIVITY: 'admin.security.suspicious_activity',
    BRUTE_FORCE_DETECTED: 'admin.security.brute_force_detected',
    IP_BLOCKED: 'admin.security.ip_blocked',
    IP_UNBLOCKED: 'admin.security.ip_unblocked',
    IP_WHITELIST_UPDATED: 'admin.security.ip_whitelist_updated',
    RATE_LIMIT_EXCEEDED: 'admin.security.rate_limit_exceeded',
    POLICY_CREATED: 'admin.security.policy_created',
    POLICY_UPDATED: 'admin.security.policy_updated',
    POLICY_DELETED: 'admin.security.policy_deleted',
    POLICY_VIOLATION: 'admin.security.policy_violation',
    AUDIT_LOG_ACCESSED: 'admin.security.audit_log_accessed',
    AUDIT_LOG_EXPORTED: 'admin.security.audit_log_exported',
    AUDIT_LOG_DELETED: 'admin.security.audit_log_deleted',
    ENCRYPTION_KEY_ROTATED: 'admin.security.encryption_key_rotated',
    CERTIFICATE_UPDATED: 'admin.security.certificate_updated',
    VULNERABILITY_DETECTED: 'admin.security.vulnerability_detected',
    COMPLIANCE_SCAN_COMPLETED: 'admin.security.compliance_scan_completed',
    EMERGENCY_ACCESS_USED: 'admin.security.emergency_access_used'
  },

  /**
   * Billing Events
   * Track financial and subscription activities
   */
  BILLING: {
    PAYMENT_RECEIVED: 'admin.billing.payment_received',
    PAYMENT_FAILED: 'admin.billing.payment_failed',
    REFUND_ISSUED: 'admin.billing.refund_issued',
    CREDIT_APPLIED: 'admin.billing.credit_applied',
    INVOICE_GENERATED: 'admin.billing.invoice_generated',
    INVOICE_SENT: 'admin.billing.invoice_sent',
    INVOICE_PAID: 'admin.billing.invoice_paid',
    INVOICE_OVERDUE: 'admin.billing.invoice_overdue',
    SUBSCRIPTION_CREATED: 'admin.billing.subscription_created',
    SUBSCRIPTION_UPDATED: 'admin.billing.subscription_updated',
    SUBSCRIPTION_CANCELLED: 'admin.billing.subscription_cancelled',
    SUBSCRIPTION_EXPIRED: 'admin.billing.subscription_expired',
    PLAN_UPGRADED: 'admin.billing.plan_upgraded',
    PLAN_DOWNGRADED: 'admin.billing.plan_downgraded',
    TRIAL_STARTED: 'admin.billing.trial_started',
    TRIAL_EXTENDED: 'admin.billing.trial_extended',
    TRIAL_ENDED: 'admin.billing.trial_ended',
    PAYMENT_METHOD_ADDED: 'admin.billing.payment_method_added',
    PAYMENT_METHOD_REMOVED: 'admin.billing.payment_method_removed',
    DISCOUNT_APPLIED: 'admin.billing.discount_applied',
    TAX_RATE_UPDATED: 'admin.billing.tax_rate_updated'
  },

  /**
   * Support Events
   * Track support and customer service activities
   */
  SUPPORT: {
    TICKET_CREATED: 'admin.support.ticket_created',
    TICKET_ASSIGNED: 'admin.support.ticket_assigned',
    TICKET_ESCALATED: 'admin.support.ticket_escalated',
    TICKET_RESOLVED: 'admin.support.ticket_resolved',
    TICKET_CLOSED: 'admin.support.ticket_closed',
    CUSTOMER_CONTACTED: 'admin.support.customer_contacted',
    ACCOUNT_ACCESSED: 'admin.support.account_accessed',
    DEBUG_MODE_ENABLED: 'admin.support.debug_enabled',
    DEBUG_MODE_DISABLED: 'admin.support.debug_disabled',
    FEATURE_OVERRIDDEN: 'admin.support.feature_overridden',
    LIMIT_OVERRIDDEN: 'admin.support.limit_overridden',
    ANNOUNCEMENT_PUBLISHED: 'admin.support.announcement_published',
    MAINTENANCE_SCHEDULED: 'admin.support.maintenance_scheduled'
  },

  /**
   * Data Management Events
   * Track data operations and compliance activities
   */
  DATA: {
    DATA_EXPORTED: 'admin.data.exported',
    DATA_IMPORTED: 'admin.data.imported',
    DATA_DELETED: 'admin.data.deleted',
    DATA_ANONYMIZED: 'admin.data.anonymized',
    DATA_ARCHIVED: 'admin.data.archived',
    DATA_RESTORED: 'admin.data.restored',
    GDPR_REQUEST_RECEIVED: 'admin.data.gdpr_request_received',
    GDPR_REQUEST_PROCESSED: 'admin.data.gdpr_request_processed',
    RETENTION_POLICY_APPLIED: 'admin.data.retention_policy_applied',
    BULK_OPERATION_STARTED: 'admin.data.bulk_operation_started',
    BULK_OPERATION_COMPLETED: 'admin.data.bulk_operation_completed',
    BULK_OPERATION_FAILED: 'admin.data.bulk_operation_failed'
  },

  /**
   * Integration Events
   * Track third-party integration activities
   */
  INTEGRATION: {
    INTEGRATION_ENABLED: 'admin.integration.enabled',
    INTEGRATION_DISABLED: 'admin.integration.disabled',
    INTEGRATION_CONFIGURED: 'admin.integration.configured',
    INTEGRATION_FAILED: 'admin.integration.failed',
    WEBHOOK_CREATED: 'admin.integration.webhook_created',
    WEBHOOK_UPDATED: 'admin.integration.webhook_updated',
    WEBHOOK_DELETED: 'admin.integration.webhook_deleted',
    WEBHOOK_TRIGGERED: 'admin.integration.webhook_triggered',
    WEBHOOK_FAILED: 'admin.integration.webhook_failed',
    API_RATE_LIMIT_UPDATED: 'admin.integration.api_rate_limit_updated',
    API_ACCESS_GRANTED: 'admin.integration.api_access_granted',
    API_ACCESS_REVOKED: 'admin.integration.api_access_revoked'
  },

  /**
   * Reporting Events
   * Track reporting and analytics activities
   */
  REPORTING: {
    REPORT_GENERATED: 'admin.reporting.report_generated',
    REPORT_SCHEDULED: 'admin.reporting.report_scheduled',
    REPORT_EXPORTED: 'admin.reporting.report_exported',
    DASHBOARD_ACCESSED: 'admin.reporting.dashboard_accessed',
    METRIC_VIEWED: 'admin.reporting.metric_viewed',
    CUSTOM_QUERY_EXECUTED: 'admin.reporting.custom_query_executed',
    ANALYTICS_EXPORT_REQUESTED: 'admin.reporting.analytics_export_requested'
  }
};

/**
 * Event severity levels for monitoring and alerting
 */
const EventSeverity = {
  CRITICAL: 'critical',  // Immediate action required
  HIGH: 'high',         // Significant security or operational impact
  MEDIUM: 'medium',     // Notable but not immediately threatening
  LOW: 'low',          // Informational, routine operations
  INFO: 'info'         // General information logging
};

/**
 * Event metadata mapping
 * Defines properties for each event category
 */
const EventMetadata = {
  AUTHENTICATION: {
    severity: {
      LOGIN_FAILURE: EventSeverity.MEDIUM,
      LOGIN_BLOCKED: EventSeverity.HIGH,
      MFA_FAILED: EventSeverity.MEDIUM,
      SESSION_TERMINATED: EventSeverity.MEDIUM,
      API_KEY_REVOKED: EventSeverity.HIGH
    },
    retention: 90, // days
    alertThreshold: 5 // number of events before alert
  },
  AUTHORIZATION: {
    severity: {
      PERMISSION_DENIED: EventSeverity.HIGH,
      ACCESS_DENIED: EventSeverity.HIGH,
      IMPERSONATION_STARTED: EventSeverity.CRITICAL,
      ROLE_DELETED: EventSeverity.HIGH
    },
    retention: 365,
    alertThreshold: 3
  },
  USER_MANAGEMENT: {
    severity: {
      USER_DELETED: EventSeverity.HIGH,
      USER_SUSPENDED: EventSeverity.MEDIUM,
      USER_DATA_ANONYMIZED: EventSeverity.HIGH,
      BULK_USER_OPERATION: EventSeverity.HIGH
    },
    retention: 365,
    alertThreshold: 10
  },
  ORGANIZATION: {
    severity: {
      ORG_DELETED: EventSeverity.CRITICAL,
      ORG_SUSPENDED: EventSeverity.HIGH,
      ORG_OWNER_TRANSFERRED: EventSeverity.HIGH,
      ORG_MERGED: EventSeverity.CRITICAL
    },
    retention: 730, // 2 years
    alertThreshold: 5
  },
  SYSTEM: {
    severity: {
      CONFIG_CHANGED: EventSeverity.HIGH,
      BACKUP_FAILED: EventSeverity.CRITICAL,
      RESTORE_FAILED: EventSeverity.CRITICAL,
      MIGRATION_FAILED: EventSeverity.CRITICAL,
      HEALTH_CHECK_FAILED: EventSeverity.HIGH
    },
    retention: 365,
    alertThreshold: 1
  },
  SECURITY: {
    severity: {
      THREAT_DETECTED: EventSeverity.CRITICAL,
      BRUTE_FORCE_DETECTED: EventSeverity.CRITICAL,
      POLICY_VIOLATION: EventSeverity.HIGH,
      VULNERABILITY_DETECTED: EventSeverity.CRITICAL,
      EMERGENCY_ACCESS_USED: EventSeverity.CRITICAL
    },
    retention: 1095, // 3 years
    alertThreshold: 1
  },
  BILLING: {
    severity: {
      PAYMENT_FAILED: EventSeverity.MEDIUM,
      REFUND_ISSUED: EventSeverity.MEDIUM,
      SUBSCRIPTION_CANCELLED: EventSeverity.MEDIUM,
      INVOICE_OVERDUE: EventSeverity.MEDIUM
    },
    retention: 2190, // 6 years for financial records
    alertThreshold: 10
  },
  SUPPORT: {
    severity: {
      TICKET_ESCALATED: EventSeverity.MEDIUM,
      DEBUG_MODE_ENABLED: EventSeverity.HIGH,
      FEATURE_OVERRIDDEN: EventSeverity.HIGH,
      LIMIT_OVERRIDDEN: EventSeverity.HIGH
    },
    retention: 90,
    alertThreshold: 5
  },
  DATA: {
    severity: {
      DATA_DELETED: EventSeverity.HIGH,
      DATA_ANONYMIZED: EventSeverity.HIGH,
      GDPR_REQUEST_RECEIVED: EventSeverity.MEDIUM,
      BULK_OPERATION_FAILED: EventSeverity.HIGH
    },
    retention: 1095, // 3 years for compliance
    alertThreshold: 5
  },
  INTEGRATION: {
    severity: {
      INTEGRATION_FAILED: EventSeverity.MEDIUM,
      WEBHOOK_FAILED: EventSeverity.LOW,
      API_ACCESS_REVOKED: EventSeverity.MEDIUM
    },
    retention: 180,
    alertThreshold: 20
  },
  REPORTING: {
    severity: {
      CUSTOM_QUERY_EXECUTED: EventSeverity.MEDIUM,
      ANALYTICS_EXPORT_REQUESTED: EventSeverity.MEDIUM
    },
    retention: 90,
    alertThreshold: 50
  }
};

/**
 * Helper function to get event severity
 */
const getEventSeverity = (event) => {
  const [, category, eventName] = event.split('.');
  const categoryKey = category.toUpperCase();
  const eventKey = Object.keys(AdminEvents[categoryKey] || {})
    .find(key => AdminEvents[categoryKey][key] === event);
  
  if (!eventKey) return EventSeverity.INFO;
  
  return EventMetadata[categoryKey]?.severity?.[eventKey] || EventSeverity.INFO;
};

/**
 * Helper function to get event retention period
 */
const getEventRetention = (event) => {
  const [, category] = event.split('.');
  const categoryKey = category.toUpperCase();
  return EventMetadata[categoryKey]?.retention || 90;
};

/**
 * Helper function to check if event should trigger alert
 */
const shouldTriggerAlert = (event, count = 1) => {
  const [, category] = event.split('.');
  const categoryKey = category.toUpperCase();
  const threshold = EventMetadata[categoryKey]?.alertThreshold || 10;
  const severity = getEventSeverity(event);
  
  // Critical events always trigger alerts
  if (severity === EventSeverity.CRITICAL) return true;
  
  // Check threshold for other severities
  return count >= threshold;
};

/**
 * Event patterns for anomaly detection
 */
const EventPatterns = {
  SUSPICIOUS_AUTH: [
    AdminEvents.AUTHENTICATION.LOGIN_FAILURE,
    AdminEvents.AUTHENTICATION.MFA_FAILED,
    AdminEvents.AUTHORIZATION.ACCESS_DENIED
  ],
  DATA_EXFILTRATION: [
    AdminEvents.DATA.DATA_EXPORTED,
    AdminEvents.REPORTING.ANALYTICS_EXPORT_REQUESTED,
    AdminEvents.USER_MANAGEMENT.USER_EXPORT_REQUESTED
  ],
  PRIVILEGE_ESCALATION: [
    AdminEvents.AUTHORIZATION.ROLE_ASSIGNED,
    AdminEvents.AUTHORIZATION.PERMISSION_GRANTED,
    AdminEvents.AUTHENTICATION.ELEVATION_GRANTED
  ],
  SYSTEM_COMPROMISE: [
    AdminEvents.SECURITY.EMERGENCY_ACCESS_USED,
    AdminEvents.SYSTEM.CONFIG_CHANGED,
    AdminEvents.SECURITY.POLICY_DELETED
  ]
};

module.exports = {
  AdminEvents,
  EventSeverity,
  EventMetadata,
  EventPatterns,
  getEventSeverity,
  getEventRetention,
  shouldTriggerAlert
};