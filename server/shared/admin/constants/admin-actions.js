/**
 * @file Admin Actions Constants
 * @description Comprehensive definition of administrative action types for audit logging and permission checks
 * @version 1.0.0
 */

/**
 * Administrative action types organized by category
 * These constants are used throughout the admin system for:
 * - Audit logging
 * - Permission checks
 * - Activity tracking
 * - Rate limiting
 * - Analytics
 */
const AdminActions = {
  /**
   * Authentication and Session Actions
   * Actions related to admin authentication and session management
   */
  AUTH: {
    LOGIN: 'admin.auth.login',
    LOGOUT: 'admin.auth.logout',
    LOGIN_FAILED: 'admin.auth.login_failed',
    PASSWORD_RESET: 'admin.auth.password_reset',
    PASSWORD_CHANGE: 'admin.auth.password_change',
    MFA_ENABLE: 'admin.auth.mfa_enable',
    MFA_DISABLE: 'admin.auth.mfa_disable',
    MFA_VERIFY: 'admin.auth.mfa_verify',
    MFA_FAILED: 'admin.auth.mfa_failed',
    SESSION_CREATE: 'admin.auth.session_create',
    SESSION_TERMINATE: 'admin.auth.session_terminate',
    SESSION_EXTEND: 'admin.auth.session_extend',
    ELEVATION_REQUEST: 'admin.auth.elevation_request',
    ELEVATION_GRANTED: 'admin.auth.elevation_granted',
    API_KEY_CREATE: 'admin.auth.api_key_create',
    API_KEY_REVOKE: 'admin.auth.api_key_revoke',
    DEVICE_TRUST: 'admin.auth.device_trust',
    DEVICE_UNTRUST: 'admin.auth.device_untrust'
  },

  /**
   * User Management Actions
   * Actions for managing platform users
   */
  USER: {
    CREATE: 'admin.user.create',
    READ: 'admin.user.read',
    UPDATE: 'admin.user.update',
    DELETE: 'admin.user.delete',
    SUSPEND: 'admin.user.suspend',
    REACTIVATE: 'admin.user.reactivate',
    ROLE_ASSIGN: 'admin.user.role_assign',
    ROLE_REMOVE: 'admin.user.role_remove',
    PERMISSION_GRANT: 'admin.user.permission_grant',
    PERMISSION_REVOKE: 'admin.user.permission_revoke',
    PASSWORD_RESET_FORCE: 'admin.user.password_reset_force',
    SESSION_TERMINATE_ALL: 'admin.user.session_terminate_all',
    IMPERSONATE_START: 'admin.user.impersonate_start',
    IMPERSONATE_END: 'admin.user.impersonate_end',
    UNLOCK: 'admin.user.unlock',
    EMAIL_VERIFY: 'admin.user.email_verify',
    BULK_CREATE: 'admin.user.bulk_create',
    BULK_UPDATE: 'admin.user.bulk_update',
    BULK_DELETE: 'admin.user.bulk_delete',
    EXPORT: 'admin.user.export',
    IMPORT: 'admin.user.import'
  },

  /**
   * Organization Management Actions
   * Actions for managing hosted organizations
   */
  ORGANIZATION: {
    CREATE: 'admin.organization.create',
    READ: 'admin.organization.read',
    UPDATE: 'admin.organization.update',
    DELETE: 'admin.organization.delete',
    SUSPEND: 'admin.organization.suspend',
    REACTIVATE: 'admin.organization.reactivate',
    BILLING_UPDATE: 'admin.organization.billing_update',
    PLAN_CHANGE: 'admin.organization.plan_change',
    LIMITS_UPDATE: 'admin.organization.limits_update',
    FEATURE_ENABLE: 'admin.organization.feature_enable',
    FEATURE_DISABLE: 'admin.organization.feature_disable',
    MEMBER_ADD: 'admin.organization.member_add',
    MEMBER_REMOVE: 'admin.organization.member_remove',
    MEMBER_ROLE_UPDATE: 'admin.organization.member_role_update',
    OWNER_TRANSFER: 'admin.organization.owner_transfer',
    DOMAIN_ADD: 'admin.organization.domain_add',
    DOMAIN_REMOVE: 'admin.organization.domain_remove',
    DOMAIN_VERIFY: 'admin.organization.domain_verify',
    SSO_CONFIGURE: 'admin.organization.sso_configure',
    SSO_DISABLE: 'admin.organization.sso_disable',
    EXPORT: 'admin.organization.export',
    IMPORT: 'admin.organization.import',
    MERGE: 'admin.organization.merge',
    SPLIT: 'admin.organization.split'
  },

  /**
   * Billing and Subscription Actions
   * Actions related to billing management
   */
  BILLING: {
    INVOICE_VIEW: 'admin.billing.invoice_view',
    INVOICE_CREATE: 'admin.billing.invoice_create',
    INVOICE_UPDATE: 'admin.billing.invoice_update',
    INVOICE_VOID: 'admin.billing.invoice_void',
    PAYMENT_METHOD_ADD: 'admin.billing.payment_method_add',
    PAYMENT_METHOD_REMOVE: 'admin.billing.payment_method_remove',
    PAYMENT_METHOD_UPDATE: 'admin.billing.payment_method_update',
    PAYMENT_PROCESS: 'admin.billing.payment_process',
    REFUND_ISSUE: 'admin.billing.refund_issue',
    CREDIT_APPLY: 'admin.billing.credit_apply',
    DISCOUNT_APPLY: 'admin.billing.discount_apply',
    DISCOUNT_REMOVE: 'admin.billing.discount_remove',
    SUBSCRIPTION_CREATE: 'admin.billing.subscription_create',
    SUBSCRIPTION_UPDATE: 'admin.billing.subscription_update',
    SUBSCRIPTION_CANCEL: 'admin.billing.subscription_cancel',
    SUBSCRIPTION_PAUSE: 'admin.billing.subscription_pause',
    SUBSCRIPTION_RESUME: 'admin.billing.subscription_resume',
    TRIAL_EXTEND: 'admin.billing.trial_extend',
    TRIAL_END: 'admin.billing.trial_end',
    CHARGE_OVERRIDE: 'admin.billing.charge_override',
    TAX_EXEMPT_SET: 'admin.billing.tax_exempt_set'
  },

  /**
   * System Configuration Actions
   * Actions for system-level configuration changes
   */
  SYSTEM: {
    CONFIG_READ: 'admin.system.config_read',
    CONFIG_UPDATE: 'admin.system.config_update',
    CONFIG_RESET: 'admin.system.config_reset',
    MAINTENANCE_START: 'admin.system.maintenance_start',
    MAINTENANCE_END: 'admin.system.maintenance_end',
    BACKUP_CREATE: 'admin.system.backup_create',
    BACKUP_RESTORE: 'admin.system.backup_restore',
    CACHE_CLEAR: 'admin.system.cache_clear',
    INDEX_REBUILD: 'admin.system.index_rebuild',
    MIGRATION_RUN: 'admin.system.migration_run',
    INTEGRATION_ENABLE: 'admin.system.integration_enable',
    INTEGRATION_DISABLE: 'admin.system.integration_disable',
    WEBHOOK_CREATE: 'admin.system.webhook_create',
    WEBHOOK_UPDATE: 'admin.system.webhook_update',
    WEBHOOK_DELETE: 'admin.system.webhook_delete',
    WEBHOOK_TEST: 'admin.system.webhook_test',
    FEATURE_FLAG_TOGGLE: 'admin.system.feature_flag_toggle',
    EMAIL_TEMPLATE_UPDATE: 'admin.system.email_template_update',
    CRON_JOB_UPDATE: 'admin.system.cron_job_update',
    LOG_LEVEL_CHANGE: 'admin.system.log_level_change'
  },

  /**
   * Security and Compliance Actions
   * Actions related to security administration
   */
  SECURITY: {
    AUDIT_LOG_READ: 'admin.security.audit_log_read',
    AUDIT_LOG_EXPORT: 'admin.security.audit_log_export',
    AUDIT_LOG_DELETE: 'admin.security.audit_log_delete',
    SECURITY_SCAN_RUN: 'admin.security.scan_run',
    VULNERABILITY_ACKNOWLEDGE: 'admin.security.vulnerability_acknowledge',
    THREAT_BLOCK: 'admin.security.threat_block',
    IP_WHITELIST_ADD: 'admin.security.ip_whitelist_add',
    IP_WHITELIST_REMOVE: 'admin.security.ip_whitelist_remove',
    IP_BLACKLIST_ADD: 'admin.security.ip_blacklist_add',
    IP_BLACKLIST_REMOVE: 'admin.security.ip_blacklist_remove',
    RATE_LIMIT_UPDATE: 'admin.security.rate_limit_update',
    POLICY_CREATE: 'admin.security.policy_create',
    POLICY_UPDATE: 'admin.security.policy_update',
    POLICY_DELETE: 'admin.security.policy_delete',
    COMPLIANCE_REPORT_GENERATE: 'admin.security.compliance_report_generate',
    GDPR_REQUEST_PROCESS: 'admin.security.gdpr_request_process',
    DATA_RETENTION_UPDATE: 'admin.security.data_retention_update',
    ENCRYPTION_KEY_ROTATE: 'admin.security.encryption_key_rotate',
    CERTIFICATE_INSTALL: 'admin.security.certificate_install',
    EMERGENCY_ACCESS_GRANT: 'admin.security.emergency_access_grant'
  },

  /**
   * Support and Customer Service Actions
   * Actions for support administration
   */
  SUPPORT: {
    TICKET_VIEW: 'admin.support.ticket_view',
    TICKET_ASSIGN: 'admin.support.ticket_assign',
    TICKET_ESCALATE: 'admin.support.ticket_escalate',
    TICKET_CLOSE: 'admin.support.ticket_close',
    CUSTOMER_CONTACT: 'admin.support.customer_contact',
    ACCOUNT_ACCESS: 'admin.support.account_access',
    DEBUG_MODE_ENABLE: 'admin.support.debug_mode_enable',
    DEBUG_MODE_DISABLE: 'admin.support.debug_mode_disable',
    FEATURE_OVERRIDE: 'admin.support.feature_override',
    LIMIT_OVERRIDE: 'admin.support.limit_override',
    ANNOUNCEMENT_CREATE: 'admin.support.announcement_create',
    ANNOUNCEMENT_UPDATE: 'admin.support.announcement_update',
    ANNOUNCEMENT_DELETE: 'admin.support.announcement_delete'
  },

  /**
   * Reporting and Analytics Actions
   * Actions for reports and data analysis
   */
  REPORTING: {
    REPORT_VIEW: 'admin.reporting.report_view',
    REPORT_CREATE: 'admin.reporting.report_create',
    REPORT_SCHEDULE: 'admin.reporting.report_schedule',
    REPORT_EXPORT: 'admin.reporting.report_export',
    DASHBOARD_ACCESS: 'admin.reporting.dashboard_access',
    METRIC_VIEW: 'admin.reporting.metric_view',
    ANALYTICS_QUERY: 'admin.reporting.analytics_query',
    DATA_EXPORT_REQUEST: 'admin.reporting.data_export_request',
    CUSTOM_QUERY_RUN: 'admin.reporting.custom_query_run'
  },

  /**
   * Content and Communication Actions
   * Actions for content management
   */
  CONTENT: {
    EMAIL_SEND: 'admin.content.email_send',
    EMAIL_TEMPLATE_CREATE: 'admin.content.email_template_create',
    EMAIL_TEMPLATE_UPDATE: 'admin.content.email_template_update',
    EMAIL_TEMPLATE_DELETE: 'admin.content.email_template_delete',
    SMS_SEND: 'admin.content.sms_send',
    NOTIFICATION_SEND: 'admin.content.notification_send',
    BROADCAST_CREATE: 'admin.content.broadcast_create',
    PAGE_CREATE: 'admin.content.page_create',
    PAGE_UPDATE: 'admin.content.page_update',
    PAGE_DELETE: 'admin.content.page_delete',
    ASSET_UPLOAD: 'admin.content.asset_upload',
    ASSET_DELETE: 'admin.content.asset_delete'
  }
};

/**
 * Action metadata defining properties for each action category
 */
const ActionMetadata = {
  AUTH: {
    category: 'Authentication',
    riskLevel: 'medium',
    requiresAudit: true,
    requiresMFA: ['API_KEY_CREATE', 'API_KEY_REVOKE', 'ELEVATION_GRANTED']
  },
  USER: {
    category: 'User Management',
    riskLevel: 'high',
    requiresAudit: true,
    requiresMFA: ['DELETE', 'IMPERSONATE_START', 'BULK_DELETE', 'ROLE_ASSIGN'],
    requiresReason: ['DELETE', 'SUSPEND', 'IMPERSONATE_START', 'BULK_DELETE']
  },
  ORGANIZATION: {
    category: 'Organization Management',
    riskLevel: 'high',
    requiresAudit: true,
    requiresMFA: ['DELETE', 'SUSPEND', 'OWNER_TRANSFER', 'MERGE'],
    requiresReason: ['DELETE', 'SUSPEND', 'MERGE', 'SPLIT']
  },
  BILLING: {
    category: 'Billing Management',
    riskLevel: 'critical',
    requiresAudit: true,
    requiresMFA: ['REFUND_ISSUE', 'CREDIT_APPLY', 'CHARGE_OVERRIDE'],
    requiresReason: ['REFUND_ISSUE', 'CREDIT_APPLY', 'DISCOUNT_APPLY', 'CHARGE_OVERRIDE']
  },
  SYSTEM: {
    category: 'System Configuration',
    riskLevel: 'critical',
    requiresAudit: true,
    requiresMFA: ['CONFIG_UPDATE', 'BACKUP_RESTORE', 'MIGRATION_RUN'],
    requiresReason: ['CONFIG_UPDATE', 'CONFIG_RESET', 'BACKUP_RESTORE', 'CACHE_CLEAR']
  },
  SECURITY: {
    category: 'Security Administration',
    riskLevel: 'critical',
    requiresAudit: true,
    requiresMFA: ['EMERGENCY_ACCESS_GRANT', 'POLICY_DELETE', 'ENCRYPTION_KEY_ROTATE'],
    requiresReason: ['AUDIT_LOG_DELETE', 'EMERGENCY_ACCESS_GRANT', 'POLICY_DELETE']
  },
  SUPPORT: {
    category: 'Support Operations',
    riskLevel: 'medium',
    requiresAudit: true,
    requiresMFA: ['FEATURE_OVERRIDE', 'LIMIT_OVERRIDE'],
    requiresReason: ['FEATURE_OVERRIDE', 'LIMIT_OVERRIDE', 'DEBUG_MODE_ENABLE']
  },
  REPORTING: {
    category: 'Reporting and Analytics',
    riskLevel: 'low',
    requiresAudit: true,
    requiresMFA: ['DATA_EXPORT_REQUEST', 'CUSTOM_QUERY_RUN'],
    requiresReason: ['DATA_EXPORT_REQUEST']
  },
  CONTENT: {
    category: 'Content Management',
    riskLevel: 'low',
    requiresAudit: true,
    requiresMFA: ['BROADCAST_CREATE'],
    requiresReason: ['PAGE_DELETE', 'BROADCAST_CREATE']
  }
};

/**
 * Helper function to get all actions as a flat array
 */
const getAllActions = () => {
  const actions = [];
  Object.values(AdminActions).forEach(category => {
    Object.values(category).forEach(action => {
      actions.push(action);
    });
  });
  return actions;
};

/**
 * Helper function to get action metadata
 */
const getActionMetadata = (action) => {
  const [, category, actionName] = action.split('.');
  const categoryKey = category.toUpperCase();
  const metadata = ActionMetadata[categoryKey];
  
  if (!metadata) return null;
  
  return {
    action,
    category: metadata.category,
    riskLevel: metadata.riskLevel,
    requiresAudit: metadata.requiresAudit,
    requiresMFA: metadata.requiresMFA?.includes(actionName.toUpperCase()),
    requiresReason: metadata.requiresReason?.includes(actionName.toUpperCase())
  };
};

/**
 * Helper function to check if action requires elevation
 */
const requiresElevation = (action) => {
  const metadata = getActionMetadata(action);
  return metadata && (metadata.riskLevel === 'critical' || metadata.requiresMFA);
};

/**
 * Helper function to get actions by risk level
 */
const getActionsByRiskLevel = (riskLevel) => {
  const actions = [];
  Object.entries(AdminActions).forEach(([categoryKey, category]) => {
    const metadata = ActionMetadata[categoryKey];
    if (metadata && metadata.riskLevel === riskLevel) {
      Object.values(category).forEach(action => {
        actions.push(action);
      });
    }
  });
  return actions;
};

/**
 * Export action groups for UI categorization
 */
const ActionGroups = {
  USER_LIFECYCLE: {
    label: 'User Lifecycle',
    actions: [
      AdminActions.USER.CREATE,
      AdminActions.USER.UPDATE,
      AdminActions.USER.SUSPEND,
      AdminActions.USER.REACTIVATE,
      AdminActions.USER.DELETE
    ]
  },
  ACCESS_CONTROL: {
    label: 'Access Control',
    actions: [
      AdminActions.USER.ROLE_ASSIGN,
      AdminActions.USER.PERMISSION_GRANT,
      AdminActions.USER.PERMISSION_REVOKE,
      AdminActions.ORGANIZATION.MEMBER_ROLE_UPDATE
    ]
  },
  FINANCIAL_OPERATIONS: {
    label: 'Financial Operations',
    actions: [
      AdminActions.BILLING.PAYMENT_PROCESS,
      AdminActions.BILLING.REFUND_ISSUE,
      AdminActions.BILLING.CREDIT_APPLY,
      AdminActions.BILLING.CHARGE_OVERRIDE
    ]
  },
  SYSTEM_MAINTENANCE: {
    label: 'System Maintenance',
    actions: [
      AdminActions.SYSTEM.MAINTENANCE_START,
      AdminActions.SYSTEM.BACKUP_CREATE,
      AdminActions.SYSTEM.CACHE_CLEAR,
      AdminActions.SYSTEM.INDEX_REBUILD
    ]
  },
  SECURITY_OPERATIONS: {
    label: 'Security Operations',
    actions: [
      AdminActions.SECURITY.THREAT_BLOCK,
      AdminActions.SECURITY.EMERGENCY_ACCESS_GRANT,
      AdminActions.SECURITY.ENCRYPTION_KEY_ROTATE,
      AdminActions.SECURITY.AUDIT_LOG_EXPORT
    ]
  }
};

module.exports = {
  AdminActions,
  ActionMetadata,
  ActionGroups,
  getAllActions,
  getActionMetadata,
  requiresElevation,
  getActionsByRiskLevel
};