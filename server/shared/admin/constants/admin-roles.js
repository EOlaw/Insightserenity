/**
 * @file Admin Roles Constants
 * @description Administrative role definitions with hierarchies and permission mappings
 * @version 1.0.0
 */

const { AdminPermissions, PermissionGroups } = require('./admin-permissions');

/**
 * Administrative role definitions
 * Each role includes metadata and associated permissions
 */
const AdminRoles = {
  /**
   * Super Administrator
   * Complete system control - typically reserved for system owners
   */
  SUPER_ADMIN: {
    name: 'super_admin',
    displayName: 'Super Administrator',
    description: 'Complete system control with unrestricted access to all features and data',
    level: 100, // Highest privilege level
    category: 'system',
    permissions: [AdminPermissions.SUPER_ADMIN.ALL],
    restrictions: {
      maxPerOrganization: 1,
      requiresMFA: true,
      requiresOwnerApproval: true,
      cannotSelfAssign: true
    },
    capabilities: {
      canImpersonate: true,
      canAccessEmergencyMode: true,
      canOverrideAllLimits: true,
      canAccessAllOrganizations: true,
      canModifySystemConfig: true,
      bypassesAllRestrictions: true
    }
  },

  /**
   * Platform Administrator
   * Manages the entire platform across all organizations
   */
  PLATFORM_ADMIN: {
    name: 'platform_admin',
    displayName: 'Platform Administrator',
    description: 'Platform-wide administration with access to all organizations and users',
    level: 90,
    category: 'platform',
    permissions: PermissionGroups.PLATFORM_ADMIN,
    inherits: [],
    restrictions: {
      maxPerOrganization: 3,
      requiresMFA: true,
      requiresAdminApproval: true
    },
    capabilities: {
      canImpersonate: true,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: true,
      canModifySystemConfig: false,
      canManageOrganizations: true,
      canViewBilling: true,
      canProcessRefunds: true
    }
  },

  /**
   * Organization Administrator
   * Full control over a specific organization
   */
  ORGANIZATION_ADMIN: {
    name: 'organization_admin',
    displayName: 'Organization Administrator',
    description: 'Complete administrative control within an organization',
    level: 80,
    category: 'organization',
    permissions: PermissionGroups.ORG_ADMIN,
    inherits: [],
    restrictions: {
      maxPerOrganization: 5,
      requiresMFA: true,
      scopedToOrganization: true
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: false,
      canModifySystemConfig: false,
      canManageOrganization: true,
      canManageMembers: true,
      canManageBilling: true,
      canConfigureSSO: true
    }
  },

  /**
   * Security Administrator
   * Manages security policies and compliance
   */
  SECURITY_ADMIN: {
    name: 'security_admin',
    displayName: 'Security Administrator',
    description: 'Security policy management, compliance monitoring, and threat response',
    level: 85,
    category: 'security',
    permissions: PermissionGroups.SECURITY_ADMIN,
    inherits: [],
    restrictions: {
      maxPerOrganization: 2,
      requiresMFA: true,
      requiresBackgroundCheck: true,
      auditAllActions: true
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: true,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: true,
      canModifySystemConfig: false,
      canViewAuditLogs: true,
      canManagePolicies: true,
      canInvestigateThreats: true,
      canRotateKeys: true
    }
  },

  /**
   * System Administrator
   * Technical system administration and maintenance
   */
  SYSTEM_ADMIN: {
    name: 'system_admin',
    displayName: 'System Administrator',
    description: 'System configuration, maintenance, and technical operations',
    level: 85,
    category: 'system',
    permissions: PermissionGroups.SYSTEM_ADMIN,
    inherits: [],
    restrictions: {
      maxPerOrganization: 3,
      requiresMFA: true,
      requiresTechnicalCertification: true
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: false,
      canModifySystemConfig: true,
      canPerformMaintenance: true,
      canManageBackups: true,
      canAccessSystemLogs: true,
      canManageIntegrations: true
    }
  },

  /**
   * Billing Administrator
   * Manages financial operations and billing
   */
  BILLING_ADMIN: {
    name: 'billing_admin',
    displayName: 'Billing Administrator',
    description: 'Financial operations, billing management, and payment processing',
    level: 75,
    category: 'billing',
    permissions: PermissionGroups.BILLING_ADMIN,
    inherits: [],
    restrictions: {
      maxPerOrganization: 2,
      requiresMFA: true,
      requiresFinancialApproval: true,
      dailyRefundLimit: 10000
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: false,
      canModifySystemConfig: false,
      canProcessPayments: true,
      canIssueRefunds: true,
      canManageSubscriptions: true,
      canApplyDiscounts: true
    }
  },

  /**
   * User Administrator
   * Manages user accounts and access
   */
  USER_ADMIN: {
    name: 'user_admin',
    displayName: 'User Administrator',
    description: 'User account management, role assignments, and access control',
    level: 70,
    category: 'user_management',
    permissions: PermissionGroups.USER_ADMIN,
    inherits: [],
    restrictions: {
      maxPerOrganization: 5,
      requiresMFA: false,
      cannotModifySuperAdmins: true
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: false,
      canModifySystemConfig: false,
      canCreateUsers: true,
      canSuspendUsers: true,
      canAssignRoles: true,
      canResetPasswords: true
    }
  },

  /**
   * Support Administrator
   * Customer support and assistance operations
   */
  SUPPORT_ADMIN: {
    name: 'support_admin',
    displayName: 'Support Administrator',
    description: 'Customer support operations, ticket management, and user assistance',
    level: 60,
    category: 'support',
    permissions: [
      AdminPermissions.SUPPORT.TICKETS.ALL,
      AdminPermissions.SUPPORT.CUSTOMER.ALL,
      AdminPermissions.SUPPORT.TOOLS.DEBUG,
      AdminPermissions.USER.READ,
      AdminPermissions.ORGANIZATION.VIEW
    ],
    inherits: [],
    restrictions: {
      maxPerOrganization: 10,
      requiresMFA: false,
      limitedDataAccess: true
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: false,
      canModifySystemConfig: false,
      canViewUserData: true,
      canAssistUsers: true,
      canEscalateIssues: true,
      canCreateAnnouncements: true
    }
  },

  /**
   * Auditor
   * Read-only access for compliance and auditing
   */
  AUDITOR: {
    name: 'auditor',
    displayName: 'Auditor',
    description: 'Read-only access to audit logs, reports, and compliance data',
    level: 50,
    category: 'compliance',
    permissions: [
      AdminPermissions.SECURITY.AUDIT.READ,
      AdminPermissions.SECURITY.AUDIT.EXPORT,
      AdminPermissions.SECURITY.COMPLIANCE.VIEW,
      AdminPermissions.SECURITY.COMPLIANCE.REPORTS,
      AdminPermissions.REPORTING.REPORTS.VIEW,
      AdminPermissions.REPORTING.ANALYTICS.VIEW
    ],
    inherits: [],
    restrictions: {
      maxPerOrganization: 5,
      requiresMFA: true,
      readOnlyAccess: true,
      cannotModifyData: true
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: true,
      canModifySystemConfig: false,
      canViewAuditLogs: true,
      canExportReports: true,
      canViewCompliance: true
    }
  },

  /**
   * Report Administrator
   * Manages reports and analytics
   */
  REPORT_ADMIN: {
    name: 'report_admin',
    displayName: 'Report Administrator',
    description: 'Create, manage, and distribute reports and analytics',
    level: 55,
    category: 'reporting',
    permissions: [
      AdminPermissions.REPORTING.REPORTS.ALL,
      AdminPermissions.REPORTING.ANALYTICS.ALL,
      AdminPermissions.REPORTING.DASHBOARDS.ALL,
      AdminPermissions.REPORTING.METRICS.VIEW
    ],
    inherits: [],
    restrictions: {
      maxPerOrganization: 5,
      requiresMFA: false,
      dataExportLimit: 100000 // records per export
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: false,
      canModifySystemConfig: false,
      canCreateReports: true,
      canScheduleReports: true,
      canExportData: true,
      canShareReports: true
    }
  },

  /**
   * Content Administrator
   * Manages content and communications
   */
  CONTENT_ADMIN: {
    name: 'content_admin',
    displayName: 'Content Administrator',
    description: 'Content management, email campaigns, and communication templates',
    level: 50,
    category: 'content',
    permissions: [
      AdminPermissions.CONTENT.EMAIL.ALL,
      AdminPermissions.CONTENT.NOTIFICATIONS.ALL,
      AdminPermissions.CONTENT.PAGES.ALL,
      AdminPermissions.CONTENT.MEDIA.ALL
    ],
    inherits: [],
    restrictions: {
      maxPerOrganization: 5,
      requiresMFA: false,
      contentApprovalRequired: true
    },
    capabilities: {
      canImpersonate: false,
      canAccessEmergencyMode: false,
      canOverrideAllLimits: false,
      canAccessAllOrganizations: false,
      canModifySystemConfig: false,
      canCreateContent: true,
      canPublishContent: true,
      canManageTemplates: true,
      canSendBroadcasts: true
    }
  }
};

/**
 * Role hierarchy definition
 * Defines which roles can manage other roles
 */
const RoleHierarchy = {
  [AdminRoles.SUPER_ADMIN.name]: {
    canAssign: Object.keys(AdminRoles),
    canRevoke: Object.keys(AdminRoles),
    canModify: Object.keys(AdminRoles)
  },
  [AdminRoles.PLATFORM_ADMIN.name]: {
    canAssign: [
      AdminRoles.ORGANIZATION_ADMIN.name,
      AdminRoles.USER_ADMIN.name,
      AdminRoles.BILLING_ADMIN.name,
      AdminRoles.SUPPORT_ADMIN.name,
      AdminRoles.REPORT_ADMIN.name,
      AdminRoles.CONTENT_ADMIN.name
    ],
    canRevoke: [
      AdminRoles.ORGANIZATION_ADMIN.name,
      AdminRoles.USER_ADMIN.name,
      AdminRoles.BILLING_ADMIN.name,
      AdminRoles.SUPPORT_ADMIN.name,
      AdminRoles.REPORT_ADMIN.name,
      AdminRoles.CONTENT_ADMIN.name
    ],
    canModify: []
  },
  [AdminRoles.ORGANIZATION_ADMIN.name]: {
    canAssign: [
      AdminRoles.USER_ADMIN.name,
      AdminRoles.SUPPORT_ADMIN.name,
      AdminRoles.REPORT_ADMIN.name,
      AdminRoles.CONTENT_ADMIN.name
    ],
    canRevoke: [
      AdminRoles.USER_ADMIN.name,
      AdminRoles.SUPPORT_ADMIN.name,
      AdminRoles.REPORT_ADMIN.name,
      AdminRoles.CONTENT_ADMIN.name
    ],
    canModify: []
  }
};

/**
 * Role compatibility matrix
 * Defines which roles can be held simultaneously
 */
const RoleCompatibility = {
  [AdminRoles.SUPER_ADMIN.name]: {
    compatible: [], // Super admin is exclusive
    incompatible: Object.keys(AdminRoles).filter(r => r !== AdminRoles.SUPER_ADMIN.name)
  },
  [AdminRoles.PLATFORM_ADMIN.name]: {
    compatible: [AdminRoles.SECURITY_ADMIN.name, AdminRoles.SYSTEM_ADMIN.name],
    incompatible: [AdminRoles.SUPER_ADMIN.name, AdminRoles.ORGANIZATION_ADMIN.name]
  },
  [AdminRoles.ORGANIZATION_ADMIN.name]: {
    compatible: [AdminRoles.BILLING_ADMIN.name, AdminRoles.USER_ADMIN.name],
    incompatible: [AdminRoles.SUPER_ADMIN.name, AdminRoles.PLATFORM_ADMIN.name]
  },
  [AdminRoles.SECURITY_ADMIN.name]: {
    compatible: [AdminRoles.PLATFORM_ADMIN.name, AdminRoles.AUDITOR.name],
    incompatible: [AdminRoles.SUPER_ADMIN.name]
  },
  [AdminRoles.SYSTEM_ADMIN.name]: {
    compatible: [AdminRoles.PLATFORM_ADMIN.name],
    incompatible: [AdminRoles.SUPER_ADMIN.name, AdminRoles.ORGANIZATION_ADMIN.name]
  }
};

/**
 * Role transition rules
 * Defines allowed role transitions and requirements
 */
const RoleTransitions = {
  TO_SUPER_ADMIN: {
    allowedFrom: [AdminRoles.PLATFORM_ADMIN.name],
    requirements: {
      approvalRequired: true,
      approverRole: AdminRoles.SUPER_ADMIN.name,
      coolingPeriod: 86400000, // 24 hours
      mfaRequired: true,
      reasonRequired: true
    }
  },
  TO_PLATFORM_ADMIN: {
    allowedFrom: [
      AdminRoles.ORGANIZATION_ADMIN.name,
      AdminRoles.SECURITY_ADMIN.name,
      AdminRoles.SYSTEM_ADMIN.name
    ],
    requirements: {
      approvalRequired: true,
      approverRole: AdminRoles.SUPER_ADMIN.name,
      coolingPeriod: 3600000, // 1 hour
      mfaRequired: true,
      reasonRequired: true
    }
  },
  FROM_ADMIN_ROLES: {
    allowedTo: ['user', 'manager'], // Non-admin roles
    requirements: {
      approvalRequired: true,
      coolingPeriod: 86400000, // 24 hours
      dataRetentionCheck: true,
      auditLogEntry: true
    }
  }
};

/**
 * Helper function to get role by name
 */
const getRoleByName = (roleName) => {
  return Object.values(AdminRoles).find(role => role.name === roleName);
};

/**
 * Helper function to get all permissions for a role
 */
const getRolePermissions = (roleName) => {
  const role = getRoleByName(roleName);
  if (!role) return [];
  
  let permissions = [...role.permissions];
  
  // Add inherited permissions
  if (role.inherits && role.inherits.length > 0) {
    role.inherits.forEach(inheritedRole => {
      const inherited = getRolePermissions(inheritedRole);
      permissions = [...permissions, ...inherited];
    });
  }
  
  // Remove duplicates
  return [...new Set(permissions)];
};

/**
 * Helper function to check if role can be assigned
 */
const canAssignRole = (assignerRole, targetRole) => {
  const hierarchy = RoleHierarchy[assignerRole];
  if (!hierarchy) return false;
  
  return hierarchy.canAssign.includes(targetRole);
};

/**
 * Helper function to check role compatibility
 */
const areRolesCompatible = (role1, role2) => {
  const compatibility = RoleCompatibility[role1];
  if (!compatibility) return false;
  
  return compatibility.compatible.includes(role2);
};

/**
 * Helper function to get role level
 */
const getRoleLevel = (roleName) => {
  const role = getRoleByName(roleName);
  return role ? role.level : 0;
};

/**
 * Helper function to sort roles by level
 */
const sortRolesByLevel = (roleNames) => {
  return roleNames.sort((a, b) => {
    return getRoleLevel(b) - getRoleLevel(a);
  });
};

/**
 * Helper function to validate role assignment
 */
const validateRoleAssignment = (user, roleName, assignedBy) => {
  const role = getRoleByName(roleName);
  if (!role) {
    return { valid: false, reason: 'Role does not exist' };
  }
  
  // Check if assigner can assign this role
  if (!canAssignRole(assignedBy.role, roleName)) {
    return { valid: false, reason: 'Insufficient privileges to assign this role' };
  }
  
  // Check role restrictions
  if (role.restrictions.requiresMFA && !user.mfaEnabled) {
    return { valid: false, reason: 'User must have MFA enabled for this role' };
  }
  
  // Check compatibility with existing roles
  const incompatibleRoles = user.roles.filter(userRole => 
    !areRolesCompatible(userRole, roleName)
  );
  
  if (incompatibleRoles.length > 0) {
    return { 
      valid: false, 
      reason: `Role incompatible with: ${incompatibleRoles.join(', ')}` 
    };
  }
  
  return { valid: true };
};

/**
 * Role groups for UI organization
 */
const RoleGroups = {
  SYSTEM_ROLES: {
    label: 'System Administration',
    roles: [
      AdminRoles.SUPER_ADMIN.name,
      AdminRoles.PLATFORM_ADMIN.name,
      AdminRoles.SYSTEM_ADMIN.name
    ]
  },
  ORGANIZATION_ROLES: {
    label: 'Organization Management',
    roles: [
      AdminRoles.ORGANIZATION_ADMIN.name,
      AdminRoles.USER_ADMIN.name,
      AdminRoles.BILLING_ADMIN.name
    ]
  },
  SECURITY_COMPLIANCE: {
    label: 'Security & Compliance',
    roles: [
      AdminRoles.SECURITY_ADMIN.name,
      AdminRoles.AUDITOR.name
    ]
  },
  OPERATIONAL_ROLES: {
    label: 'Operations',
    roles: [
      AdminRoles.SUPPORT_ADMIN.name,
      AdminRoles.REPORT_ADMIN.name,
      AdminRoles.CONTENT_ADMIN.name
    ]
  }
};

module.exports = {
  AdminRoles,
  RoleHierarchy,
  RoleCompatibility,
  RoleTransitions,
  RoleGroups,
  getRoleByName,
  getRolePermissions,
  canAssignRole,
  areRolesCompatible,
  getRoleLevel,
  sortRolesByLevel,
  validateRoleAssignment
};