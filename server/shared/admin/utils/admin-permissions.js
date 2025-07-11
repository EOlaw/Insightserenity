/**
 * @file Admin Permissions Utilities
 * @description Permission management and validation utilities for administrative operations
 * @version 1.0.0
 */

const AdminLogger = require('./admin-logger');
const config = require('../../../config/config');

/**
 * Admin Permissions Class
 * @class AdminPermissions
 */
class AdminPermissions {
  /**
   * Initialize permission configurations
   */
  static initialize() {
    // Define permission hierarchy
    this.permissionHierarchy = {
      // Super Admin Permissions - Complete system control
      'super_admin.*': {
        description: 'Complete system control',
        includes: [
          'platform.*',
          'organization.*',
          'security.*',
          'system.*',
          'billing.*',
          'user.*',
          'audit.*'
        ],
        risk: 'critical'
      },

      // Platform Administration
      'platform.*': {
        description: 'Platform-wide administration',
        includes: [
          'platform.manage',
          'platform.organizations.*',
          'platform.users.*',
          'platform.billing.*',
          'platform.settings.*',
          'platform.analytics.*'
        ],
        risk: 'high'
      },
      'platform.organizations.*': {
        description: 'Manage all organizations',
        includes: [
          'platform.organizations.create',
          'platform.organizations.read',
          'platform.organizations.update',
          'platform.organizations.delete',
          'platform.organizations.suspend',
          'platform.organizations.billing'
        ],
        risk: 'high'
      },
      'platform.users.*': {
        description: 'Manage all platform users',
        includes: [
          'platform.users.create',
          'platform.users.read',
          'platform.users.update',
          'platform.users.delete',
          'platform.users.impersonate',
          'platform.users.roles'
        ],
        risk: 'critical'
      },

      // Organization Administration
      'organization.*': {
        description: 'Organization-level administration',
        includes: [
          'organization.manage',
          'organization.users.*',
          'organization.billing.*',
          'organization.settings.*',
          'organization.projects.*',
          'organization.reports.*'
        ],
        risk: 'medium'
      },
      'organization.users.*': {
        description: 'Manage organization users',
        includes: [
          'organization.users.create',
          'organization.users.read',
          'organization.users.update',
          'organization.users.delete',
          'organization.users.roles',
          'organization.users.invite'
        ],
        risk: 'medium'
      },
      'organization.billing.*': {
        description: 'Manage organization billing',
        includes: [
          'organization.billing.read',
          'organization.billing.update',
          'organization.billing.methods',
          'organization.billing.invoices',
          'organization.billing.refunds'
        ],
        risk: 'high'
      },

      // Security Administration
      'security.*': {
        description: 'Security administration',
        includes: [
          'security.audit.*',
          'security.compliance.*',
          'security.threats.*',
          'security.access.*',
          'security.policies.*'
        ],
        risk: 'critical'
      },
      'security.audit.*': {
        description: 'Audit log management',
        includes: [
          'security.audit.read',
          'security.audit.export',
          'security.audit.delete',
          'security.audit.forensics'
        ],
        risk: 'high'
      },

      // System Administration
      'system.*': {
        description: 'System administration',
        includes: [
          'system.config.*',
          'system.maintenance.*',
          'system.monitoring.*',
          'system.backup.*',
          'system.integrations.*'
        ],
        risk: 'critical'
      },
      'system.config.*': {
        description: 'System configuration',
        includes: [
          'system.config.read',
          'system.config.update',
          'system.config.reset',
          'system.config.export'
        ],
        risk: 'critical'
      },

      // User Management
      'user.*': {
        description: 'User management',
        includes: [
          'user.read',
          'user.update',
          'user.delete',
          'user.roles',
          'user.sessions',
          'user.mfa'
        ],
        risk: 'medium'
      },

      // Billing Management
      'billing.*': {
        description: 'Billing management',
        includes: [
          'billing.read',
          'billing.update',
          'billing.refunds',
          'billing.subscriptions',
          'billing.invoices'
        ],
        risk: 'high'
      },

      // Audit Management
      'audit.*': {
        description: 'Audit management',
        includes: [
          'audit.read',
          'audit.export',
          'audit.analyze',
          'audit.report'
        ],
        risk: 'medium'
      }
    };

    // Define role permissions
    this.rolePermissions = {
      super_admin: ['super_admin.*'],
      
      platform_admin: [
        'platform.*',
        'organization.*',
        'user.*',
        'billing.read',
        'audit.*'
      ],
      
      organization_admin: [
        'organization.*',
        'user.read',
        'user.update',
        'audit.read',
        'billing.read'
      ],
      
      organization_manager: [
        'organization.users.read',
        'organization.users.invite',
        'organization.projects.*',
        'organization.reports.*',
        'user.read'
      ],
      
      security_admin: [
        'security.*',
        'audit.*',
        'user.read',
        'organization.read'
      ],
      
      system_admin: [
        'system.*',
        'platform.settings.read',
        'audit.read'
      ],
      
      billing_admin: [
        'billing.*',
        'organization.billing.*',
        'audit.read'
      ],
      
      support_admin: [
        'user.read',
        'user.sessions',
        'organization.read',
        'audit.read',
        'platform.users.read'
      ],
      
      auditor: [
        'audit.*',
        'security.audit.read',
        'security.compliance.read',
        'user.read',
        'organization.read'
      ]
    };

    // Define permission metadata
    this.permissionMetadata = {
      requiresMFA: [
        'super_admin.*',
        'platform.users.delete',
        'platform.users.impersonate',
        'system.config.*',
        'security.*',
        'billing.refunds'
      ],
      
      requiresElevation: [
        'super_admin.*',
        'platform.organizations.delete',
        'system.config.update',
        'security.access.*',
        'user.delete'
      ],
      
      requiresReason: [
        'platform.users.impersonate',
        'platform.organizations.suspend',
        'user.delete',
        'billing.refunds',
        'system.maintenance.*',
        'audit.delete'
      ],
      
      criticalOperations: [
        'platform.users.impersonate',
        'system.config.update',
        'security.access.emergency',
        'platform.organizations.delete',
        'audit.delete'
      ]
    };

    // Permission groups for UI
    this.permissionGroups = {
      userManagement: {
        label: 'User Management',
        permissions: [
          'user.read',
          'user.update',
          'user.delete',
          'user.roles',
          'user.sessions'
        ]
      },
      
      organizationManagement: {
        label: 'Organization Management',
        permissions: [
          'organization.manage',
          'organization.users.*',
          'organization.settings.*',
          'organization.billing.*'
        ]
      },
      
      platformAdministration: {
        label: 'Platform Administration',
        permissions: [
          'platform.manage',
          'platform.organizations.*',
          'platform.users.*',
          'platform.settings.*'
        ]
      },
      
      securityAdministration: {
        label: 'Security Administration',
        permissions: [
          'security.audit.*',
          'security.compliance.*',
          'security.threats.*',
          'security.policies.*'
        ]
      },
      
      systemAdministration: {
        label: 'System Administration',
        permissions: [
          'system.config.*',
          'system.maintenance.*',
          'system.monitoring.*',
          'system.backup.*'
        ]
      },
      
      billingManagement: {
        label: 'Billing Management',
        permissions: [
          'billing.read',
          'billing.update',
          'billing.refunds',
          'billing.subscriptions'
        ]
      }
    };
  }

  /**
   * Check if user has permission
   * @param {Object} user - User object
   * @param {string} permission - Required permission
   * @param {Object} context - Permission context
   * @returns {boolean} Has permission
   */
  static hasPermission(user, permission, context = {}) {
    if (!user || !permission) return false;

    try {
      // Super admin bypass
      if (user.role?.primary === 'super_admin') {
        AdminLogger.debug('Super admin permission bypass', {
          userId: user._id,
          permission,
          category: 'permissions'
        });
        return true;
      }

      // Get user's permissions
      const userPermissions = this.getUserPermissions(user);

      // Check direct permission match
      if (userPermissions.includes(permission)) {
        return true;
      }

      // Check wildcard permissions
      return this.checkWildcardPermissions(userPermissions, permission);
    } catch (error) {
      AdminLogger.error('Permission check error', {
        error: error.message,
        userId: user._id,
        permission
      });
      return false;
    }
  }

  /**
   * Check multiple permissions (AND logic)
   * @param {Object} user - User object
   * @param {Array} permissions - Required permissions
   * @param {Object} context - Permission context
   * @returns {boolean} Has all permissions
   */
  static hasAllPermissions(user, permissions, context = {}) {
    return permissions.every(permission => 
      this.hasPermission(user, permission, context)
    );
  }

  /**
   * Check multiple permissions (OR logic)
   * @param {Object} user - User object
   * @param {Array} permissions - Required permissions
   * @param {Object} context - Permission context
   * @returns {boolean} Has any permission
   */
  static hasAnyPermission(user, permissions, context = {}) {
    return permissions.some(permission => 
      this.hasPermission(user, permission, context)
    );
  }

  /**
   * Get user's permissions
   * @param {Object} user - User object
   * @returns {Array} User permissions
   */
  static getUserPermissions(user) {
    const permissions = new Set();

    // Get role-based permissions
    const rolePerms = this.rolePermissions[user.role?.primary] || [];
    rolePerms.forEach(perm => permissions.add(perm));

    // Add custom permissions if any
    if (user.permissions?.custom) {
      user.permissions.custom.forEach(perm => permissions.add(perm));
    }

    // Expand wildcard permissions
    const expandedPermissions = new Set();
    for (const perm of permissions) {
      if (perm.endsWith('.*')) {
        const expanded = this.expandWildcardPermission(perm);
        expanded.forEach(p => expandedPermissions.add(p));
      } else {
        expandedPermissions.add(perm);
      }
    }

    return Array.from(expandedPermissions);
  }

  /**
   * Get permission metadata
   * @param {string} permission - Permission
   * @returns {Object} Permission metadata
   */
  static getPermissionMetadata(permission) {
    const metadata = {
      permission,
      requiresMFA: this.permissionMetadata.requiresMFA.some(p => 
        this.matchesPattern(permission, p)
      ),
      requiresElevation: this.permissionMetadata.requiresElevation.some(p => 
        this.matchesPattern(permission, p)
      ),
      requiresReason: this.permissionMetadata.requiresReason.some(p => 
        this.matchesPattern(permission, p)
      ),
      isCritical: this.permissionMetadata.criticalOperations.includes(permission)
    };

    // Get risk level
    for (const [perm, config] of Object.entries(this.permissionHierarchy)) {
      if (this.matchesPattern(permission, perm)) {
        metadata.risk = config.risk;
        metadata.description = config.description;
        break;
      }
    }

    return metadata;
  }

  /**
   * Validate permission requirements
   * @param {Object} user - User object
   * @param {string} permission - Required permission
   * @param {Object} context - Request context
   * @returns {Object} Validation result
   */
  static validatePermissionRequirements(user, permission, context = {}) {
    const result = {
      allowed: false,
      requirements: [],
      metadata: {}
    };

    // Check basic permission
    if (!this.hasPermission(user, permission, context)) {
      result.requirements.push('insufficient_permissions');
      return result;
    }

    const metadata = this.getPermissionMetadata(permission);
    result.metadata = metadata;

    // Check MFA requirement
    if (metadata.requiresMFA && !context.mfaVerified) {
      result.requirements.push('mfa_required');
    }

    // Check elevation requirement
    if (metadata.requiresElevation && !context.elevatedPrivileges) {
      result.requirements.push('elevation_required');
    }

    // Check reason requirement
    if (metadata.requiresReason && !context.reason) {
      result.requirements.push('reason_required');
    }

    // Check organization context if needed
    if (permission.startsWith('organization.') && !context.organizationId) {
      result.requirements.push('organization_context_required');
    }

    result.allowed = result.requirements.length === 0;
    return result;
  }

  /**
   * Get permissions for role
   * @param {string} role - Role name
   * @returns {Array} Role permissions
   */
  static getRolePermissions(role) {
    const permissions = this.rolePermissions[role] || [];
    const expanded = new Set();

    // Expand all permissions
    permissions.forEach(perm => {
      if (perm.endsWith('.*')) {
        const expandedPerms = this.expandWildcardPermission(perm);
        expandedPerms.forEach(p => expanded.add(p));
      } else {
        expanded.add(perm);
      }
    });

    return Array.from(expanded);
  }

  /**
   * Compare permissions between roles
   * @param {string} role1 - First role
   * @param {string} role2 - Second role
   * @returns {Object} Comparison result
   */
  static compareRoles(role1, role2) {
    const perms1 = new Set(this.getRolePermissions(role1));
    const perms2 = new Set(this.getRolePermissions(role2));

    const unique1 = [];
    const unique2 = [];
    const common = [];

    for (const perm of perms1) {
      if (perms2.has(perm)) {
        common.push(perm);
      } else {
        unique1.push(perm);
      }
    }

    for (const perm of perms2) {
      if (!perms1.has(perm)) {
        unique2.push(perm);
      }
    }

    return {
      role1: {
        name: role1,
        total: perms1.size,
        unique: unique1
      },
      role2: {
        name: role2,
        total: perms2.size,
        unique: unique2
      },
      common: {
        total: common.length,
        permissions: common
      }
    };
  }

  /**
   * Generate permission matrix
   * @param {Array} roles - Roles to include
   * @returns {Object} Permission matrix
   */
  static generatePermissionMatrix(roles = null) {
    const allRoles = roles || Object.keys(this.rolePermissions);
    const allPermissions = new Set();
    const matrix = {};

    // Collect all permissions
    allRoles.forEach(role => {
      const perms = this.getRolePermissions(role);
      perms.forEach(p => allPermissions.add(p));
    });

    // Build matrix
    const sortedPermissions = Array.from(allPermissions).sort();
    
    allRoles.forEach(role => {
      const rolePerms = new Set(this.getRolePermissions(role));
      matrix[role] = {};
      
      sortedPermissions.forEach(perm => {
        matrix[role][perm] = rolePerms.has(perm);
      });
    });

    return {
      roles: allRoles,
      permissions: sortedPermissions,
      matrix
    };
  }

  /**
   * Suggest permissions for operation
   * @param {string} operation - Operation type
   * @param {string} resource - Resource type
   * @returns {Array} Suggested permissions
   */
  static suggestPermissions(operation, resource) {
    const suggestions = [];
    const operationMap = {
      create: ['create', 'write', 'manage'],
      read: ['read', 'view'],
      update: ['update', 'write', 'manage'],
      delete: ['delete', 'manage'],
      list: ['read', 'view'],
      export: ['export', 'read'],
      import: ['import', 'write', 'manage']
    };

    const actions = operationMap[operation] || [operation];
    
    actions.forEach(action => {
      suggestions.push(`${resource}.${action}`);
      suggestions.push(`${resource}.*`);
    });

    // Add parent permissions
    const resourceParts = resource.split('.');
    if (resourceParts.length > 1) {
      suggestions.push(`${resourceParts[0]}.*`);
    }

    return [...new Set(suggestions)];
  }

  /**
   * Check permission inheritance
   * @param {string} childPermission - Child permission
   * @param {string} parentPermission - Parent permission
   * @returns {boolean} Is inherited
   */
  static isInheritedFrom(childPermission, parentPermission) {
    // Direct inheritance
    if (parentPermission.endsWith('.*')) {
      const parentBase = parentPermission.slice(0, -2);
      return childPermission.startsWith(parentBase);
    }

    // Check hierarchy
    const hierarchy = this.permissionHierarchy[parentPermission];
    if (hierarchy?.includes) {
      return hierarchy.includes.some(perm => 
        this.isInheritedFrom(childPermission, perm)
      );
    }

    return false;
  }

  /**
   * Get permission dependencies
   * @param {string} permission - Permission
   * @returns {Array} Required permissions
   */
  static getPermissionDependencies(permission) {
    const dependencies = [];

    // Check if permission requires parent permissions
    const parts = permission.split('.');
    for (let i = parts.length - 1; i > 0; i--) {
      const parent = parts.slice(0, i).join('.');
      if (this.permissionHierarchy[parent]) {
        dependencies.push(parent);
      }
    }

    // Check for explicit dependencies
    if (permission === 'user.delete') {
      dependencies.push('user.read', 'user.update');
    }

    if (permission === 'billing.refunds') {
      dependencies.push('billing.read', 'billing.update');
    }

    return [...new Set(dependencies)];
  }

  /**
   * Helper methods
   */

  static expandWildcardPermission(wildcardPerm) {
    const expanded = [];
    const base = wildcardPerm.slice(0, -2); // Remove .*

    const hierarchy = this.permissionHierarchy[wildcardPerm];
    if (hierarchy?.includes) {
      hierarchy.includes.forEach(perm => {
        if (perm.endsWith('.*')) {
          expanded.push(...this.expandWildcardPermission(perm));
        } else {
          expanded.push(perm);
        }
      });
    }

    return expanded;
  }

  static checkWildcardPermissions(userPermissions, requiredPermission) {
    return userPermissions.some(userPerm => {
      if (userPerm.endsWith('.*')) {
        const base = userPerm.slice(0, -2);
        return requiredPermission.startsWith(base);
      }
      return false;
    });
  }

  static matchesPattern(permission, pattern) {
    if (pattern === permission) return true;
    
    if (pattern.endsWith('.*')) {
      const base = pattern.slice(0, -2);
      return permission.startsWith(base);
    }
    
    return false;
  }

  /**
   * Audit permission check
   * @param {Object} user - User object
   * @param {string} permission - Permission checked
   * @param {boolean} result - Check result
   * @param {Object} context - Check context
   */
  static auditPermissionCheck(user, permission, result, context = {}) {
    AdminLogger.info('Permission check performed', {
      userId: user._id,
      userRole: user.role?.primary,
      permission,
      result,
      context,
      category: 'permissions'
    });
  }

  /**
   * Get permission statistics
   * @param {Object} user - User object
   * @returns {Object} Permission statistics
   */
  static getPermissionStats(user) {
    const permissions = this.getUserPermissions(user);
    const metadata = permissions.map(p => this.getPermissionMetadata(p));

    return {
      total: permissions.length,
      byRisk: {
        critical: metadata.filter(m => m.risk === 'critical').length,
        high: metadata.filter(m => m.risk === 'high').length,
        medium: metadata.filter(m => m.risk === 'medium').length,
        low: metadata.filter(m => m.risk === 'low').length
      },
      requiresMFA: metadata.filter(m => m.requiresMFA).length,
      requiresElevation: metadata.filter(m => m.requiresElevation).length,
      requiresReason: metadata.filter(m => m.requiresReason).length
    };
  }

  /**
   * Export permissions configuration
   * @returns {Object} Permissions configuration
   */
  static exportConfiguration() {
    return {
      hierarchy: this.permissionHierarchy,
      roles: this.rolePermissions,
      metadata: this.permissionMetadata,
      groups: this.permissionGroups,
      exportedAt: new Date(),
      version: '1.0.0'
    };
  }

  /**
   * Validate permission name
   * @param {string} permission - Permission name
   * @returns {Object} Validation result
   */
  static validatePermissionName(permission) {
    const result = {
      valid: true,
      errors: []
    };

    // Check format
    if (!/^[a-z_]+(\.[a-z_]+)*(\.\*)?$/.test(permission)) {
      result.valid = false;
      result.errors.push('Invalid permission format. Use lowercase with dots (e.g., resource.action)');
    }

    // Check depth
    const parts = permission.split('.');
    if (parts.length > 4) {
      result.valid = false;
      result.errors.push('Permission depth exceeds maximum of 4 levels');
    }

    // Check reserved words
    const reserved = ['admin', 'root', 'god', 'master'];
    if (reserved.some(word => permission.includes(word))) {
      result.valid = false;
      result.errors.push('Permission contains reserved words');
    }

    return result;
  }
}

// Initialize on module load
AdminPermissions.initialize();

module.exports = AdminPermissions;