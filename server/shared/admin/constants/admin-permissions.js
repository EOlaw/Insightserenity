/**
 * @file Admin Permissions Constants
 * @description Comprehensive definition of all administrative permissions in the system
 * @version 1.0.0
 */

/**
 * Administrative permissions organized by resource and action
 * Format: resource.action or resource.subresource.action
 */
const AdminPermissions = {
  /**
   * Super Admin Permissions
   * Complete system control - typically only for system owners
   */
  SUPER_ADMIN: {
    ALL: 'super_admin.*', // Grants all permissions in the system
    SYSTEM: 'super_admin.system.*',
    PLATFORM: 'super_admin.platform.*',
    EMERGENCY: 'super_admin.emergency.*',
    OVERRIDE: 'super_admin.override.*'
  },

  /**
   * Platform Management Permissions
   * For managing the entire platform across all organizations
   */
  PLATFORM: {
    // General platform management
    MANAGE: 'platform.manage',
    VIEW: 'platform.view',
    SETTINGS: 'platform.settings.*',
    
    // Organization management
    ORGANIZATIONS: {
      CREATE: 'platform.organizations.create',
      READ: 'platform.organizations.read',
      UPDATE: 'platform.organizations.update',
      DELETE: 'platform.organizations.delete',
      SUSPEND: 'platform.organizations.suspend',
      REACTIVATE: 'platform.organizations.reactivate',
      MERGE: 'platform.organizations.merge',
      SPLIT: 'platform.organizations.split',
      BILLING: 'platform.organizations.billing',
      LIMITS: 'platform.organizations.limits',
      ALL: 'platform.organizations.*'
    },
    
    // User management across platform
    USERS: {
      CREATE: 'platform.users.create',
      READ: 'platform.users.read',
      UPDATE: 'platform.users.update',
      DELETE: 'platform.users.delete',
      SUSPEND: 'platform.users.suspend',
      IMPERSONATE: 'platform.users.impersonate',
      ROLES: 'platform.users.roles',
      BULK: 'platform.users.bulk',
      EXPORT: 'platform.users.export',
      ALL: 'platform.users.*'
    },
    
    // Platform-wide billing
    BILLING: {
      READ: 'platform.billing.read',
      UPDATE: 'platform.billing.update',
      REFUNDS: 'platform.billing.refunds',
      CREDITS: 'platform.billing.credits',
      DISCOUNTS: 'platform.billing.discounts',
      REPORTS: 'platform.billing.reports',
      ALL: 'platform.billing.*'
    },
    
    // Platform analytics
    ANALYTICS: {
      VIEW: 'platform.analytics.view',
      EXPORT: 'platform.analytics.export',
      CUSTOM: 'platform.analytics.custom',
      ALL: 'platform.analytics.*'
    },
    
    // Platform settings
    SETTINGS: {
      READ: 'platform.settings.read',
      UPDATE: 'platform.settings.update',
      FEATURES: 'platform.settings.features',
      INTEGRATIONS: 'platform.settings.integrations',
      ALL: 'platform.settings.*'
    }
  },

  /**
   * Organization Management Permissions
   * For managing specific organizations
   */
  ORGANIZATION: {
    // General organization management
    MANAGE: 'organization.manage',
    VIEW: 'organization.view',
    UPDATE: 'organization.update',
    DELETE: 'organization.delete',
    
    // Member management
    MEMBERS: {
      INVITE: 'organization.members.invite',
      READ: 'organization.members.read',
      UPDATE: 'organization.members.update',
      REMOVE: 'organization.members.remove',
      ROLES: 'organization.members.roles',
      BULK: 'organization.members.bulk',
      ALL: 'organization.members.*'
    },
    
    // Organization billing
    BILLING: {
      READ: 'organization.billing.read',
      UPDATE: 'organization.billing.update',
      METHODS: 'organization.billing.methods',
      INVOICES: 'organization.billing.invoices',
      SUBSCRIPTION: 'organization.billing.subscription',
      ALL: 'organization.billing.*'
    },
    
    // Organization settings
    SETTINGS: {
      READ: 'organization.settings.read',
      UPDATE: 'organization.settings.update',
      SECURITY: 'organization.settings.security',
      DOMAINS: 'organization.settings.domains',
      SSO: 'organization.settings.sso',
      ALL: 'organization.settings.*'
    },
    
    // Projects within organization
    PROJECTS: {
      CREATE: 'organization.projects.create',
      READ: 'organization.projects.read',
      UPDATE: 'organization.projects.update',
      DELETE: 'organization.projects.delete',
      ARCHIVE: 'organization.projects.archive',
      ALL: 'organization.projects.*'
    },
    
    // Organization reports
    REPORTS: {
      VIEW: 'organization.reports.view',
      CREATE: 'organization.reports.create',
      EXPORT: 'organization.reports.export',
      SCHEDULE: 'organization.reports.schedule',
      ALL: 'organization.reports.*'
    },
    
    // API management
    API: {
      KEYS_CREATE: 'organization.api.keys_create',
      KEYS_READ: 'organization.api.keys_read',
      KEYS_REVOKE: 'organization.api.keys_revoke',
      WEBHOOKS: 'organization.api.webhooks',
      RATE_LIMITS: 'organization.api.rate_limits',
      ALL: 'organization.api.*'
    }
  },

  /**
   * User Management Permissions
   * For managing individual users
   */
  USER: {
    // Basic user operations
    CREATE: 'user.create',
    READ: 'user.read',
    UPDATE: 'user.update',
    DELETE: 'user.delete',
    
    // Advanced user operations
    SUSPEND: 'user.suspend',
    REACTIVATE: 'user.reactivate',
    UNLOCK: 'user.unlock',
    VERIFY: 'user.verify',
    
    // User roles and permissions
    ROLES: {
      ASSIGN: 'user.roles.assign',
      REMOVE: 'user.roles.remove',
      CUSTOM: 'user.roles.custom',
      ALL: 'user.roles.*'
    },
    
    // User sessions
    SESSIONS: {
      VIEW: 'user.sessions.view',
      TERMINATE: 'user.sessions.terminate',
      ALL: 'user.sessions.*'
    },
    
    // User security
    SECURITY: {
      PASSWORD_RESET: 'user.security.password_reset',
      MFA_MANAGE: 'user.security.mfa_manage',
      API_KEYS: 'user.security.api_keys',
      ALL: 'user.security.*'
    },
    
    // Bulk operations
    BULK: {
      CREATE: 'user.bulk.create',
      UPDATE: 'user.bulk.update',
      DELETE: 'user.bulk.delete',
      EXPORT: 'user.bulk.export',
      IMPORT: 'user.bulk.import',
      ALL: 'user.bulk.*'
    }
  },

  /**
   * System Administration Permissions
   * For system-level configuration and maintenance
   */
  SYSTEM: {
    // Configuration management
    CONFIG: {
      READ: 'system.config.read',
      UPDATE: 'system.config.update',
      RESET: 'system.config.reset',
      EXPORT: 'system.config.export',
      IMPORT: 'system.config.import',
      ALL: 'system.config.*'
    },
    
    // Maintenance operations
    MAINTENANCE: {
      ENABLE: 'system.maintenance.enable',
      DISABLE: 'system.maintenance.disable',
      SCHEDULE: 'system.maintenance.schedule',
      ALL: 'system.maintenance.*'
    },
    
    // System monitoring
    MONITORING: {
      VIEW: 'system.monitoring.view',
      ALERTS: 'system.monitoring.alerts',
      METRICS: 'system.monitoring.metrics',
      LOGS: 'system.monitoring.logs',
      ALL: 'system.monitoring.*'
    },
    
    // Backup and restore
    BACKUP: {
      CREATE: 'system.backup.create',
      RESTORE: 'system.backup.restore',
      DELETE: 'system.backup.delete',
      SCHEDULE: 'system.backup.schedule',
      ALL: 'system.backup.*'
    },
    
    // System integrations
    INTEGRATIONS: {
      MANAGE: 'system.integrations.manage',
      ENABLE: 'system.integrations.enable',
      DISABLE: 'system.integrations.disable',
      CONFIGURE: 'system.integrations.configure',
      ALL: 'system.integrations.*'
    },
    
    // Cache management
    CACHE: {
      VIEW: 'system.cache.view',
      CLEAR: 'system.cache.clear',
      CONFIGURE: 'system.cache.configure',
      ALL: 'system.cache.*'
    },
    
    // Jobs and queues
    JOBS: {
      VIEW: 'system.jobs.view',
      MANAGE: 'system.jobs.manage',
      RETRY: 'system.jobs.retry',
      CANCEL: 'system.jobs.cancel',
      ALL: 'system.jobs.*'
    }
  },

  /**
   * Security Administration Permissions
   * For security and compliance management
   */
  SECURITY: {
    // Audit logs
    AUDIT: {
      READ: 'security.audit.read',
      EXPORT: 'security.audit.export',
      DELETE: 'security.audit.delete',
      FORENSICS: 'security.audit.forensics',
      CONFIGURE: 'security.audit.configure',
      ALL: 'security.audit.*'
    },
    
    // Compliance management
    COMPLIANCE: {
      VIEW: 'security.compliance.view',
      REPORTS: 'security.compliance.reports',
      CONFIGURE: 'security.compliance.configure',
      AUDIT: 'security.compliance.audit',
      ALL: 'security.compliance.*'
    },
    
    // Threat management
    THREATS: {
      VIEW: 'security.threats.view',
      BLOCK: 'security.threats.block',
      INVESTIGATE: 'security.threats.investigate',
      RESPOND: 'security.threats.respond',
      ALL: 'security.threats.*'
    },
    
    // Access control
    ACCESS: {
      POLICIES: 'security.access.policies',
      IP_MANAGE: 'security.access.ip_manage',
      RATE_LIMITS: 'security.access.rate_limits',
      EMERGENCY: 'security.access.emergency',
      ALL: 'security.access.*'
    },
    
    // Security policies
    POLICIES: {
      CREATE: 'security.policies.create',
      READ: 'security.policies.read',
      UPDATE: 'security.policies.update',
      DELETE: 'security.policies.delete',
      ENFORCE: 'security.policies.enforce',
      ALL: 'security.policies.*'
    },
    
    // Encryption and keys
    ENCRYPTION: {
      KEYS_VIEW: 'security.encryption.keys_view',
      KEYS_ROTATE: 'security.encryption.keys_rotate',
      CONFIGURE: 'security.encryption.configure',
      ALL: 'security.encryption.*'
    }
  },

  /**
   * Billing Administration Permissions
   * For financial operations
   */
  BILLING: {
    // General billing
    READ: 'billing.read',
    UPDATE: 'billing.update',
    
    // Invoices
    INVOICES: {
      CREATE: 'billing.invoices.create',
      READ: 'billing.invoices.read',
      UPDATE: 'billing.invoices.update',
      VOID: 'billing.invoices.void',
      SEND: 'billing.invoices.send',
      ALL: 'billing.invoices.*'
    },
    
    // Payments
    PAYMENTS: {
      PROCESS: 'billing.payments.process',
      REFUND: 'billing.payments.refund',
      VOID: 'billing.payments.void',
      HISTORY: 'billing.payments.history',
      ALL: 'billing.payments.*'
    },
    
    // Subscriptions
    SUBSCRIPTIONS: {
      CREATE: 'billing.subscriptions.create',
      READ: 'billing.subscriptions.read',
      UPDATE: 'billing.subscriptions.update',
      CANCEL: 'billing.subscriptions.cancel',
      REACTIVATE: 'billing.subscriptions.reactivate',
      ALL: 'billing.subscriptions.*'
    },
    
    // Financial operations
    FINANCIAL: {
      CREDITS: 'billing.financial.credits',
      DISCOUNTS: 'billing.financial.discounts',
      TAXES: 'billing.financial.taxes',
      REPORTS: 'billing.financial.reports',
      ALL: 'billing.financial.*'
    }
  },

  /**
   * Support Administration Permissions
   * For customer support operations
   */
  SUPPORT: {
    // Ticket management
    TICKETS: {
      VIEW: 'support.tickets.view',
      ASSIGN: 'support.tickets.assign',
      UPDATE: 'support.tickets.update',
      ESCALATE: 'support.tickets.escalate',
      CLOSE: 'support.tickets.close',
      ALL: 'support.tickets.*'
    },
    
    // Customer access
    CUSTOMER: {
      VIEW: 'support.customer.view',
      CONTACT: 'support.customer.contact',
      ACCESS: 'support.customer.access',
      ASSIST: 'support.customer.assist',
      ALL: 'support.customer.*'
    },
    
    // Support tools
    TOOLS: {
      DEBUG: 'support.tools.debug',
      OVERRIDE: 'support.tools.override',
      SIMULATE: 'support.tools.simulate',
      ALL: 'support.tools.*'
    },
    
    // Communications
    COMMUNICATIONS: {
      ANNOUNCEMENTS: 'support.communications.announcements',
      BROADCASTS: 'support.communications.broadcasts',
      TEMPLATES: 'support.communications.templates',
      ALL: 'support.communications.*'
    }
  },

  /**
   * Reporting and Analytics Permissions
   * For data analysis and reporting
   */
  REPORTING: {
    // Reports
    REPORTS: {
      VIEW: 'reporting.reports.view',
      CREATE: 'reporting.reports.create',
      SCHEDULE: 'reporting.reports.schedule',
      EXPORT: 'reporting.reports.export',
      SHARE: 'reporting.reports.share',
      ALL: 'reporting.reports.*'
    },
    
    // Analytics
    ANALYTICS: {
      VIEW: 'reporting.analytics.view',
      QUERY: 'reporting.analytics.query',
      EXPORT: 'reporting.analytics.export',
      CUSTOM: 'reporting.analytics.custom',
      ALL: 'reporting.analytics.*'
    },
    
    // Dashboards
    DASHBOARDS: {
      VIEW: 'reporting.dashboards.view',
      CREATE: 'reporting.dashboards.create',
      UPDATE: 'reporting.dashboards.update',
      DELETE: 'reporting.dashboards.delete',
      SHARE: 'reporting.dashboards.share',
      ALL: 'reporting.dashboards.*'
    },
    
    // Metrics
    METRICS: {
      VIEW: 'reporting.metrics.view',
      CONFIGURE: 'reporting.metrics.configure',
      ALERTS: 'reporting.metrics.alerts',
      ALL: 'reporting.metrics.*'
    }
  },

  /**
   * Content Management Permissions
   * For managing content and communications
   */
  CONTENT: {
    // Email management
    EMAIL: {
      SEND: 'content.email.send',
      TEMPLATES: 'content.email.templates',
      CAMPAIGNS: 'content.email.campaigns',
      ALL: 'content.email.*'
    },
    
    // Notifications
    NOTIFICATIONS: {
      SEND: 'content.notifications.send',
      MANAGE: 'content.notifications.manage',
      TEMPLATES: 'content.notifications.templates',
      ALL: 'content.notifications.*'
    },
    
    // Pages and assets
    PAGES: {
      CREATE: 'content.pages.create',
      READ: 'content.pages.read',
      UPDATE: 'content.pages.update',
      DELETE: 'content.pages.delete',
      PUBLISH: 'content.pages.publish',
      ALL: 'content.pages.*'
    },
    
    // Media
    MEDIA: {
      UPLOAD: 'content.media.upload',
      VIEW: 'content.media.view',
      DELETE: 'content.media.delete',
      ORGANIZE: 'content.media.organize',
      ALL: 'content.media.*'
    }
  }
};

/**
 * Permission groups for easier management
 * Groups related permissions together
 */
const PermissionGroups = {
  // Read-only access
  VIEWER: [
    AdminPermissions.PLATFORM.VIEW,
    AdminPermissions.ORGANIZATION.VIEW,
    AdminPermissions.USER.READ,
    AdminPermissions.REPORTING.REPORTS.VIEW,
    AdminPermissions.REPORTING.ANALYTICS.VIEW
  ],
  
  // Basic administrative access
  BASIC_ADMIN: [
    ...PermissionGroups.VIEWER,
    AdminPermissions.USER.UPDATE,
    AdminPermissions.ORGANIZATION.MEMBERS.READ,
    AdminPermissions.SUPPORT.TICKETS.VIEW,
    AdminPermissions.SUPPORT.CUSTOMER.VIEW
  ],
  
  // User management
  USER_ADMIN: [
    AdminPermissions.USER.CREATE,
    AdminPermissions.USER.READ,
    AdminPermissions.USER.UPDATE,
    AdminPermissions.USER.SUSPEND,
    AdminPermissions.USER.REACTIVATE,
    AdminPermissions.USER.ROLES.ASSIGN,
    AdminPermissions.USER.ROLES.REMOVE,
    AdminPermissions.USER.SESSIONS.VIEW,
    AdminPermissions.USER.SESSIONS.TERMINATE
  ],
  
  // Organization management
  ORG_ADMIN: [
    AdminPermissions.ORGANIZATION.MANAGE,
    AdminPermissions.ORGANIZATION.VIEW,
    AdminPermissions.ORGANIZATION.UPDATE,
    AdminPermissions.ORGANIZATION.MEMBERS.ALL,
    AdminPermissions.ORGANIZATION.SETTINGS.ALL,
    AdminPermissions.ORGANIZATION.PROJECTS.ALL,
    AdminPermissions.ORGANIZATION.REPORTS.ALL
  ],
  
  // Security administration
  SECURITY_ADMIN: [
    AdminPermissions.SECURITY.AUDIT.ALL,
    AdminPermissions.SECURITY.COMPLIANCE.ALL,
    AdminPermissions.SECURITY.THREATS.ALL,
    AdminPermissions.SECURITY.ACCESS.ALL,
    AdminPermissions.SECURITY.POLICIES.ALL
  ],
  
  // Billing administration
  BILLING_ADMIN: [
    AdminPermissions.BILLING.READ,
    AdminPermissions.BILLING.UPDATE,
    AdminPermissions.BILLING.INVOICES.ALL,
    AdminPermissions.BILLING.PAYMENTS.ALL,
    AdminPermissions.BILLING.SUBSCRIPTIONS.ALL,
    AdminPermissions.BILLING.FINANCIAL.ALL
  ],
  
  // System administration
  SYSTEM_ADMIN: [
    AdminPermissions.SYSTEM.CONFIG.ALL,
    AdminPermissions.SYSTEM.MAINTENANCE.ALL,
    AdminPermissions.SYSTEM.MONITORING.ALL,
    AdminPermissions.SYSTEM.BACKUP.ALL,
    AdminPermissions.SYSTEM.INTEGRATIONS.ALL
  ],
  
  // Full platform administration
  PLATFORM_ADMIN: [
    AdminPermissions.PLATFORM.MANAGE,
    AdminPermissions.PLATFORM.ORGANIZATIONS.ALL,
    AdminPermissions.PLATFORM.USERS.ALL,
    AdminPermissions.PLATFORM.BILLING.ALL,
    AdminPermissions.PLATFORM.ANALYTICS.ALL,
    AdminPermissions.PLATFORM.SETTINGS.ALL
  ]
};

/**
 * Permission dependencies
 * Some permissions require others to function properly
 */
const PermissionDependencies = {
  [AdminPermissions.USER.DELETE]: [AdminPermissions.USER.READ],
  [AdminPermissions.USER.SUSPEND]: [AdminPermissions.USER.READ],
  [AdminPermissions.ORGANIZATION.DELETE]: [AdminPermissions.ORGANIZATION.VIEW],
  [AdminPermissions.BILLING.PAYMENTS.REFUND]: [AdminPermissions.BILLING.READ],
  [AdminPermissions.SYSTEM.CONFIG.UPDATE]: [AdminPermissions.SYSTEM.CONFIG.READ],
  [AdminPermissions.SECURITY.POLICIES.DELETE]: [AdminPermissions.SECURITY.POLICIES.READ]
};

/**
 * Helper function to get all permissions as flat array
 */
const getAllPermissions = () => {
  const permissions = [];
  
  const extractPermissions = (obj, prefix = '') => {
    Object.entries(obj).forEach(([key, value]) => {
      if (typeof value === 'string') {
        permissions.push(value);
      } else if (typeof value === 'object') {
        extractPermissions(value, prefix);
      }
    });
  };
  
  extractPermissions(AdminPermissions);
  return [...new Set(permissions)];
};

/**
 * Helper function to check if permission includes another
 */
const permissionIncludes = (permission, checkPermission) => {
  if (permission === checkPermission) return true;
  
  // Check wildcard permissions
  if (permission.endsWith('.*')) {
    const base = permission.slice(0, -2);
    return checkPermission.startsWith(base);
  }
  
  return false;
};

/**
 * Helper function to expand wildcard permission
 */
const expandWildcardPermission = (wildcardPermission) => {
  if (!wildcardPermission.endsWith('.*')) {
    return [wildcardPermission];
  }
  
  const base = wildcardPermission.slice(0, -2);
  const allPermissions = getAllPermissions();
  
  return allPermissions.filter(perm => perm.startsWith(base));
};

module.exports = {
  AdminPermissions,
  PermissionGroups,
  PermissionDependencies,
  getAllPermissions,
  permissionIncludes,
  expandWildcardPermission
};