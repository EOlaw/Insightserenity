/**
 * @file Audit Event Types
 * @description Centralized audit event type definitions and constants
 * @version 1.0.0
 */

/**
 * Audit Event Categories
 */
const AuditCategories = {
  AUTHENTICATION: 'authentication',
  AUTHORIZATION: 'authorization',
  DATA_ACCESS: 'data_access',
  DATA_MODIFICATION: 'data_modification',
  CONFIGURATION: 'configuration',
  SECURITY: 'security',
  COMPLIANCE: 'compliance',
  SYSTEM: 'system'
};

/**
 * Audit Event Types
 */
const AuditEventTypes = {
  // Authentication Events
  USER_LOGIN: 'user_login',
  USER_LOGOUT: 'user_logout',
  USER_LOGIN_FAILED: 'user_login_failed',
  USER_LOCKED_OUT: 'user_locked_out',
  PASSWORD_RESET_REQUESTED: 'password_reset_requested',
  PASSWORD_RESET_COMPLETED: 'password_reset_completed',
  PASSWORD_CHANGED: 'password_changed',
  MFA_ENABLED: 'mfa_enabled',
  MFA_DISABLED: 'mfa_disabled',
  MFA_CHALLENGE_SUCCESS: 'mfa_challenge_success',
  MFA_CHALLENGE_FAILED: 'mfa_challenge_failed',
  PASSKEY_REGISTERED: 'passkey_registered',
  PASSKEY_REMOVED: 'passkey_removed',
  SESSION_CREATED: 'session_created',
  SESSION_TERMINATED: 'session_terminated',
  SESSION_EXPIRED: 'session_expired',
  
  // Authorization Events
  PERMISSION_GRANTED: 'permission_granted',
  PERMISSION_REVOKED: 'permission_revoked',
  ROLE_ASSIGNED: 'role_assigned',
  ROLE_REMOVED: 'role_removed',
  ACCESS_DENIED: 'access_denied',
  PRIVILEGE_ESCALATION_ATTEMPT: 'privilege_escalation_attempt',
  API_KEY_CREATED: 'api_key_created',
  API_KEY_REVOKED: 'api_key_revoked',
  
  // User Management Events
  USER_CREATED: 'user_created',
  USER_UPDATED: 'user_updated',
  USER_DELETED: 'user_deleted',
  USER_ACTIVATED: 'user_activated',
  USER_DEACTIVATED: 'user_deactivated',
  USER_INVITED: 'user_invited',
  USER_INVITATION_ACCEPTED: 'user_invitation_accepted',
  USER_EMAIL_VERIFIED: 'user_email_verified',
  USER_PROFILE_UPDATED: 'user_profile_updated',
  
  // Organization Events
  ORG_CREATED: 'organization_created',
  ORG_UPDATED: 'organization_updated',
  ORG_DELETED: 'organization_deleted',
  ORG_MEMBER_ADDED: 'organization_member_added',
  ORG_MEMBER_REMOVED: 'organization_member_removed',
  ORG_SETTINGS_CHANGED: 'organization_settings_changed',
  ORG_PLAN_UPGRADED: 'organization_plan_upgraded',
  ORG_PLAN_DOWNGRADED: 'organization_plan_downgraded',
  
  // Data Access Events
  DATA_VIEWED: 'data_viewed',
  DATA_SEARCHED: 'data_searched',
  DATA_EXPORTED: 'data_exported',
  DATA_DOWNLOADED: 'data_downloaded',
  REPORT_GENERATED: 'report_generated',
  BULK_DATA_ACCESSED: 'bulk_data_accessed',
  
  // Data Modification Events
  DATA_CREATED: 'data_created',
  DATA_UPDATED: 'data_updated',
  DATA_DELETED: 'data_deleted',
  DATA_IMPORTED: 'data_imported',
  DATA_RESTORED: 'data_restored',
  BULK_DATA_MODIFIED: 'bulk_data_modified',
  
  // Configuration Events
  CONFIG_CHANGED: 'configuration_changed',
  SETTINGS_UPDATED: 'settings_updated',
  INTEGRATION_ADDED: 'integration_added',
  INTEGRATION_REMOVED: 'integration_removed',
  WEBHOOK_CONFIGURED: 'webhook_configured',
  NOTIFICATION_SETTINGS_CHANGED: 'notification_settings_changed',
  
  // Security Events
  SECURITY_ALERT: 'security_alert',
  SUSPICIOUS_ACTIVITY: 'suspicious_activity',
  BRUTE_FORCE_DETECTED: 'brute_force_detected',
  IP_BLOCKED: 'ip_blocked',
  MALICIOUS_REQUEST_BLOCKED: 'malicious_request_blocked',
  VULNERABILITY_DETECTED: 'vulnerability_detected',
  ENCRYPTION_KEY_ROTATED: 'encryption_key_rotated',
  CERTIFICATE_RENEWED: 'certificate_renewed',
  
  // Compliance Events
  COMPLIANCE_CHECK_PASSED: 'compliance_check_passed',
  COMPLIANCE_CHECK_FAILED: 'compliance_check_failed',
  AUDIT_REPORT_GENERATED: 'audit_report_generated',
  DATA_RETENTION_APPLIED: 'data_retention_applied',
  DATA_PURGED: 'data_purged',
  CONSENT_GRANTED: 'consent_granted',
  CONSENT_REVOKED: 'consent_revoked',
  
  // System Events
  SYSTEM_STARTUP: 'system_startup',
  SYSTEM_SHUTDOWN: 'system_shutdown',
  SERVICE_STARTED: 'service_started',
  SERVICE_STOPPED: 'service_stopped',
  ERROR_OCCURRED: 'error_occurred',
  PERFORMANCE_ISSUE: 'performance_issue',
  BACKUP_COMPLETED: 'backup_completed',
  MAINTENANCE_PERFORMED: 'maintenance_performed',
  
  // Payment Events
  PAYMENT_PROCESSED: 'payment_processed',
  PAYMENT_FAILED: 'payment_failed',
  SUBSCRIPTION_CREATED: 'subscription_created',
  SUBSCRIPTION_CANCELLED: 'subscription_cancelled',
  REFUND_ISSUED: 'refund_issued',
  INVOICE_GENERATED: 'invoice_generated',
  
  // Communication Events
  EMAIL_SENT: 'email_sent',
  SMS_SENT: 'sms_sent',
  NOTIFICATION_SENT: 'notification_sent',
  WEBHOOK_TRIGGERED: 'webhook_triggered',
  WEBHOOK_FAILED: 'webhook_failed'
};

/**
 * Audit Event Severity Levels
 */
const AuditSeverity = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  CRITICAL: 'critical'
};

/**
 * Audit Event Results
 */
const AuditResults = {
  SUCCESS: 'success',
  FAILURE: 'failure',
  ERROR: 'error',
  BLOCKED: 'blocked'
};

/**
 * Event to Category Mapping
 */
const EventCategoryMap = {
  // Authentication
  [AuditEventTypes.USER_LOGIN]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.USER_LOGOUT]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.USER_LOGIN_FAILED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.USER_LOCKED_OUT]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.PASSWORD_RESET_REQUESTED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.PASSWORD_RESET_COMPLETED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.PASSWORD_CHANGED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.MFA_ENABLED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.MFA_DISABLED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.MFA_CHALLENGE_SUCCESS]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.MFA_CHALLENGE_FAILED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.PASSKEY_REGISTERED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.PASSKEY_REMOVED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.SESSION_CREATED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.SESSION_TERMINATED]: AuditCategories.AUTHENTICATION,
  [AuditEventTypes.SESSION_EXPIRED]: AuditCategories.AUTHENTICATION,
  
  // Authorization
  [AuditEventTypes.PERMISSION_GRANTED]: AuditCategories.AUTHORIZATION,
  [AuditEventTypes.PERMISSION_REVOKED]: AuditCategories.AUTHORIZATION,
  [AuditEventTypes.ROLE_ASSIGNED]: AuditCategories.AUTHORIZATION,
  [AuditEventTypes.ROLE_REMOVED]: AuditCategories.AUTHORIZATION,
  [AuditEventTypes.ACCESS_DENIED]: AuditCategories.AUTHORIZATION,
  [AuditEventTypes.PRIVILEGE_ESCALATION_ATTEMPT]: AuditCategories.AUTHORIZATION,
  [AuditEventTypes.API_KEY_CREATED]: AuditCategories.AUTHORIZATION,
  [AuditEventTypes.API_KEY_REVOKED]: AuditCategories.AUTHORIZATION,
  
  // Data Access
  [AuditEventTypes.DATA_VIEWED]: AuditCategories.DATA_ACCESS,
  [AuditEventTypes.DATA_SEARCHED]: AuditCategories.DATA_ACCESS,
  [AuditEventTypes.DATA_EXPORTED]: AuditCategories.DATA_ACCESS,
  [AuditEventTypes.DATA_DOWNLOADED]: AuditCategories.DATA_ACCESS,
  [AuditEventTypes.REPORT_GENERATED]: AuditCategories.DATA_ACCESS,
  [AuditEventTypes.BULK_DATA_ACCESSED]: AuditCategories.DATA_ACCESS,
  
  // Data Modification
  [AuditEventTypes.DATA_CREATED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.DATA_UPDATED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.DATA_DELETED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.DATA_IMPORTED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.DATA_RESTORED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.BULK_DATA_MODIFIED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.USER_CREATED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.USER_UPDATED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.USER_DELETED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.ORG_CREATED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.ORG_UPDATED]: AuditCategories.DATA_MODIFICATION,
  [AuditEventTypes.ORG_DELETED]: AuditCategories.DATA_MODIFICATION,
  
  // Configuration
  [AuditEventTypes.CONFIG_CHANGED]: AuditCategories.CONFIGURATION,
  [AuditEventTypes.SETTINGS_UPDATED]: AuditCategories.CONFIGURATION,
  [AuditEventTypes.INTEGRATION_ADDED]: AuditCategories.CONFIGURATION,
  [AuditEventTypes.INTEGRATION_REMOVED]: AuditCategories.CONFIGURATION,
  [AuditEventTypes.WEBHOOK_CONFIGURED]: AuditCategories.CONFIGURATION,
  [AuditEventTypes.NOTIFICATION_SETTINGS_CHANGED]: AuditCategories.CONFIGURATION,
  
  // Security
  [AuditEventTypes.SECURITY_ALERT]: AuditCategories.SECURITY,
  [AuditEventTypes.SUSPICIOUS_ACTIVITY]: AuditCategories.SECURITY,
  [AuditEventTypes.BRUTE_FORCE_DETECTED]: AuditCategories.SECURITY,
  [AuditEventTypes.IP_BLOCKED]: AuditCategories.SECURITY,
  [AuditEventTypes.MALICIOUS_REQUEST_BLOCKED]: AuditCategories.SECURITY,
  [AuditEventTypes.VULNERABILITY_DETECTED]: AuditCategories.SECURITY,
  [AuditEventTypes.ENCRYPTION_KEY_ROTATED]: AuditCategories.SECURITY,
  [AuditEventTypes.CERTIFICATE_RENEWED]: AuditCategories.SECURITY,
  
  // Compliance
  [AuditEventTypes.COMPLIANCE_CHECK_PASSED]: AuditCategories.COMPLIANCE,
  [AuditEventTypes.COMPLIANCE_CHECK_FAILED]: AuditCategories.COMPLIANCE,
  [AuditEventTypes.AUDIT_REPORT_GENERATED]: AuditCategories.COMPLIANCE,
  [AuditEventTypes.DATA_RETENTION_APPLIED]: AuditCategories.COMPLIANCE,
  [AuditEventTypes.DATA_PURGED]: AuditCategories.COMPLIANCE,
  [AuditEventTypes.CONSENT_GRANTED]: AuditCategories.COMPLIANCE,
  [AuditEventTypes.CONSENT_REVOKED]: AuditCategories.COMPLIANCE,
  
  // System
  [AuditEventTypes.SYSTEM_STARTUP]: AuditCategories.SYSTEM,
  [AuditEventTypes.SYSTEM_SHUTDOWN]: AuditCategories.SYSTEM,
  [AuditEventTypes.SERVICE_STARTED]: AuditCategories.SYSTEM,
  [AuditEventTypes.SERVICE_STOPPED]: AuditCategories.SYSTEM,
  [AuditEventTypes.ERROR_OCCURRED]: AuditCategories.SYSTEM,
  [AuditEventTypes.PERFORMANCE_ISSUE]: AuditCategories.SYSTEM,
  [AuditEventTypes.BACKUP_COMPLETED]: AuditCategories.SYSTEM,
  [AuditEventTypes.MAINTENANCE_PERFORMED]: AuditCategories.SYSTEM
};

/**
 * Default Severity Mapping
 */
const DefaultSeverityMap = {
  // Critical events
  [AuditEventTypes.SECURITY_ALERT]: AuditSeverity.CRITICAL,
  [AuditEventTypes.BRUTE_FORCE_DETECTED]: AuditSeverity.CRITICAL,
  [AuditEventTypes.PRIVILEGE_ESCALATION_ATTEMPT]: AuditSeverity.CRITICAL,
  [AuditEventTypes.MALICIOUS_REQUEST_BLOCKED]: AuditSeverity.CRITICAL,
  [AuditEventTypes.DATA_PURGED]: AuditSeverity.CRITICAL,
  
  // High severity events
  [AuditEventTypes.USER_LOCKED_OUT]: AuditSeverity.HIGH,
  [AuditEventTypes.ACCESS_DENIED]: AuditSeverity.HIGH,
  [AuditEventTypes.USER_DELETED]: AuditSeverity.HIGH,
  [AuditEventTypes.ORG_DELETED]: AuditSeverity.HIGH,
  [AuditEventTypes.DATA_DELETED]: AuditSeverity.HIGH,
  [AuditEventTypes.COMPLIANCE_CHECK_FAILED]: AuditSeverity.HIGH,
  [AuditEventTypes.PAYMENT_FAILED]: AuditSeverity.HIGH,
  
  // Medium severity events
  [AuditEventTypes.USER_LOGIN_FAILED]: AuditSeverity.MEDIUM,
  [AuditEventTypes.MFA_CHALLENGE_FAILED]: AuditSeverity.MEDIUM,
  [AuditEventTypes.CONFIG_CHANGED]: AuditSeverity.MEDIUM,
  [AuditEventTypes.SETTINGS_UPDATED]: AuditSeverity.MEDIUM,
  [AuditEventTypes.WEBHOOK_FAILED]: AuditSeverity.MEDIUM,
  
  // Low severity events
  [AuditEventTypes.USER_LOGIN]: AuditSeverity.LOW,
  [AuditEventTypes.DATA_VIEWED]: AuditSeverity.LOW,
  [AuditEventTypes.DATA_SEARCHED]: AuditSeverity.LOW,
  [AuditEventTypes.SESSION_CREATED]: AuditSeverity.LOW
};

module.exports = {
  AuditCategories,
  AuditEventTypes,
  AuditSeverity,
  AuditResults,
  EventCategoryMap,
  DefaultSeverityMap
};