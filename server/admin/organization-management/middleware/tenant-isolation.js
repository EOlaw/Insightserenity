// server/admin/organization-management/middleware/tenant-isolation.js
/**
 * @file Tenant Isolation Middleware
 * @description Middleware for ensuring proper tenant data isolation and security
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

// Models
const OrganizationTenant = require('../../../organization-tenants/models/organization-tenant-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const User = require('../../../shared/users/models/user-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Services
const CacheService = require('../../../shared/utils/cache-service');
const DatabaseService = require('../../../shared/utils/database-service');
const EncryptionService = require('../../../shared/security/services/encryption-service');

// Utilities
const { AppError, ForbiddenError, NotFoundError, SecurityError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminRoles = require('../../../shared/admin/constants/admin-roles');

// Configuration
const config = require('../../../config');
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');

/**
 * Tenant Isolation Middleware Class
 * @class TenantIsolationMiddleware
 */
class TenantIsolationMiddleware {
  constructor() {
    this.cache = new CacheService();
    this.cachePrefix = 'tenant-isolation';
    this.cacheTTL = 600; // 10 minutes
    
    // Isolation strategies
    this.isolationStrategies = {
      DATABASE: 'database',
      SCHEMA: 'schema',
      ROW_LEVEL: 'row_level',
      HYBRID: 'hybrid'
    };
    
    // Security levels
    this.securityLevels = {
      STANDARD: 'standard',
      ENHANCED: 'enhanced',
      MAXIMUM: 'maximum'
    };
  }

  /**
   * Ensure tenant isolation for data access
   * @param {Object} options - Isolation options
   * @returns {Function} Middleware function
   */
  ensureTenantIsolation(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const tenantId = req.params.tenantId || req.headers['x-tenant-id'] || req.body.tenantId;
        
        if (!tenantId) {
          throw new AppError('Tenant ID is required for this operation', 400);
        }
        
        // Validate tenant ID format
        if (!this._isValidTenantId(tenantId)) {
          throw new AppError('Invalid tenant ID format', 400);
        }
        
        // Get tenant information
        const tenant = await this._getTenantInfo(tenantId);
        if (!tenant) {
          throw new NotFoundError('Tenant not found');
        }
        
        // Check tenant status
        if (!this._isTenantAccessible(tenant)) {
          throw new ForbiddenError('Tenant is not accessible');
        }
        
        // Verify admin access to tenant
        const hasAccess = await this._verifyAdminTenantAccess(adminUser, tenant, options);
        if (!hasAccess) {
          throw new ForbiddenError('No access to this tenant');
        }
        
        // Set up isolation context
        const isolationContext = await this._setupIsolationContext(tenant, adminUser);
        
        // Apply isolation strategy
        await this._applyIsolationStrategy(isolationContext, req);
        
        // Store context for downstream use
        req.tenantContext = {
          tenantId: tenant.tenantId,
          tenantCode: tenant.tenantCode,
          isolationStrategy: isolationContext.strategy,
          securityLevel: isolationContext.securityLevel,
          dataScope: isolationContext.dataScope,
          restrictions: isolationContext.restrictions
        };
        
        // Set tenant-specific headers
        res.setHeader('X-Tenant-ID', tenant.tenantId);
        res.setHeader('X-Tenant-Isolation', isolationContext.strategy);
        
        // Log tenant access
        await this._logTenantAccess(adminUser, tenant, 'admin_access');
        
        next();
      } catch (error) {
        logger.error('Tenant isolation error:', error);
        next(error);
      }
    };
  }

  /**
   * Validate cross-tenant operations
   * @param {Object} options - Validation options
   * @returns {Function} Middleware function
   */
  validateCrossTenantOperation(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const sourceTenantId = req.body.sourceTenantId;
        const targetTenantId = req.body.targetTenantId;
        
        if (!sourceTenantId || !targetTenantId) {
          throw new AppError('Source and target tenant IDs are required', 400);
        }
        
        if (sourceTenantId === targetTenantId) {
          throw new AppError('Source and target tenants must be different', 400);
        }
        
        // Verify admin has super admin role for cross-tenant operations
        if (adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
          const hasPermission = await this._checkCrossTenantPermission(adminUser);
          if (!hasPermission) {
            throw new ForbiddenError('Cross-tenant operations require elevated permissions');
          }
        }
        
        // Get both tenants
        const [sourceTenant, targetTenant] = await Promise.all([
          this._getTenantInfo(sourceTenantId),
          this._getTenantInfo(targetTenantId)
        ]);
        
        if (!sourceTenant || !targetTenant) {
          throw new NotFoundError('One or both tenants not found');
        }
        
        // Validate operation compatibility
        const compatibility = await this._validateTenantCompatibility(
          sourceTenant,
          targetTenant,
          options.operation
        );
        
        if (!compatibility.compatible) {
          throw new AppError(compatibility.reason, 400);
        }
        
        // Set up cross-tenant context
        req.crossTenantContext = {
          sourceTenant: {
            id: sourceTenant.tenantId,
            code: sourceTenant.tenantCode,
            strategy: sourceTenant.database.strategy
          },
          targetTenant: {
            id: targetTenant.tenantId,
            code: targetTenant.tenantCode,
            strategy: targetTenant.database.strategy
          },
          operation: options.operation,
          restrictions: compatibility.restrictions,
          requiresDataTransformation: compatibility.requiresDataTransformation
        };
        
        // Log cross-tenant operation
        await this._logCrossTenantOperation(adminUser, sourceTenant, targetTenant, options.operation);
        
        next();
      } catch (error) {
        logger.error('Cross-tenant validation error:', error);
        next(error);
      }
    };
  }

  /**
   * Enforce tenant data boundaries
   * @param {Object} options - Enforcement options
   * @returns {Function} Middleware function
   */
  enforceTenantBoundaries(options = {}) {
    return async (req, res, next) => {
      try {
        const tenantContext = req.tenantContext;
        
        if (!tenantContext) {
          throw new AppError('Tenant context not established', 500);
        }
        
        // Apply query filters based on tenant
        if (req.query) {
          req.query = this._applyTenantFilters(req.query, tenantContext);
        }
        
        // Apply body filters for write operations
        if (req.body && ['POST', 'PUT', 'PATCH'].includes(req.method)) {
          req.body = this._applyTenantDataValidation(req.body, tenantContext);
        }
        
        // Set up response interceptor to prevent data leakage
        const originalJson = res.json;
        res.json = function(data) {
          const filteredData = this._filterResponseData(data, tenantContext);
          return originalJson.call(this, filteredData);
        }.bind(this);
        
        // Monitor for boundary violations
        this._setupBoundaryMonitoring(req, res, tenantContext);
        
        next();
      } catch (error) {
        logger.error('Tenant boundary enforcement error:', error);
        next(error);
      }
    };
  }

  /**
   * Check tenant resource access
   * @param {Object} options - Resource access options
   * @returns {Function} Middleware function
   */
  checkTenantResourceAccess(options = {}) {
    return async (req, res, next) => {
      try {
        const tenantContext = req.tenantContext;
        const resourceType = options.resourceType || this._inferResourceType(req);
        const resourceId = req.params.resourceId || req.params.id;
        
        if (!tenantContext) {
          throw new AppError('Tenant context required for resource access', 500);
        }
        
        if (!resourceId) {
          // List operations - ensure tenant filtering
          req.tenantResourceFilter = {
            tenantId: tenantContext.tenantId,
            enforced: true
          };
          return next();
        }
        
        // Verify resource belongs to tenant
        const resourceBelongsToTenant = await this._verifyResourceOwnership(
          resourceType,
          resourceId,
          tenantContext.tenantId
        );
        
        if (!resourceBelongsToTenant) {
          throw new ForbiddenError('Resource does not belong to the specified tenant');
        }
        
        // Check additional access rules
        if (options.checkPermissions) {
          const hasResourceAccess = await this._checkResourcePermissions(
            req.user,
            resourceType,
            resourceId,
            req.method
          );
          
          if (!hasResourceAccess) {
            throw new ForbiddenError('Insufficient permissions for this resource');
          }
        }
        
        req.tenantResource = {
          type: resourceType,
          id: resourceId,
          tenantId: tenantContext.tenantId,
          verified: true
        };
        
        next();
      } catch (error) {
        logger.error('Tenant resource access error:', error);
        next(error);
      }
    };
  }

  /**
   * Validate tenant configuration changes
   * @param {Object} options - Configuration validation options
   * @returns {Function} Middleware function
   */
  validateTenantConfigChange(options = {}) {
    return async (req, res, next) => {
      try {
        const adminUser = req.user;
        const tenantId = req.params.tenantId;
        const configChanges = req.body;
        
        // Get current tenant configuration
        const tenant = await OrganizationTenant.findOne({ tenantId }).lean();
        if (!tenant) {
          throw new NotFoundError('Tenant not found');
        }
        
        // Check for restricted configuration changes
        const restrictedChanges = this._findRestrictedConfigChanges(
          tenant,
          configChanges,
          adminUser
        );
        
        if (restrictedChanges.length > 0) {
          throw new ForbiddenError(
            `Restricted configuration changes detected: ${restrictedChanges.join(', ')}`
          );
        }
        
        // Validate security implications
        const securityImpact = await this._assessSecurityImpact(
          tenant,
          configChanges
        );
        
        if (securityImpact.level === 'high' && adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
          throw new ForbiddenError('High-impact configuration changes require super admin approval');
        }
        
        // Check for breaking changes
        const breakingChanges = this._identifyBreakingChanges(tenant, configChanges);
        if (breakingChanges.length > 0) {
          req.configValidation = {
            hasBreakingChanges: true,
            breakingChanges,
            requiresDowntime: true,
            estimatedDowntime: this._estimateDowntime(breakingChanges)
          };
        }
        
        // Store validation results
        req.tenantConfigValidation = {
          tenant,
          changes: configChanges,
          securityImpact,
          breakingChanges,
          warnings: this._generateConfigWarnings(tenant, configChanges)
        };
        
        next();
      } catch (error) {
        logger.error('Tenant configuration validation error:', error);
        next(error);
      }
    };
  }

  /**
   * Monitor tenant isolation violations
   * @param {Object} options - Monitoring options
   * @returns {Function} Middleware function
   */
  monitorIsolationViolations(options = {}) {
    return async (req, res, next) => {
      try {
        const startTime = Date.now();
        const violationId = crypto.randomBytes(16).toString('hex');
        
        // Set up violation detection
        const violationMonitor = {
          id: violationId,
          tenantId: req.tenantContext?.tenantId,
          adminId: req.user?._id,
          path: req.path,
          method: req.method,
          violations: []
        };
        
        // Monitor request processing
        const originalSend = res.send;
        res.send = function(data) {
          const processingTime = Date.now() - startTime;
          
          // Check for violations
          if (violationMonitor.violations.length > 0) {
            this._handleIsolationViolations(violationMonitor);
          }
          
          // Log metrics
          this._logIsolationMetrics({
            ...violationMonitor,
            processingTime,
            success: res.statusCode < 400
          });
          
          return originalSend.call(this, data);
        }.bind(this);
        
        // Attach violation reporter
        req.reportIsolationViolation = (violation) => {
          violationMonitor.violations.push({
            type: violation.type,
            severity: violation.severity,
            details: violation.details,
            timestamp: new Date()
          });
        };
        
        next();
      } catch (error) {
        logger.error('Isolation monitoring error:', error);
        next(error);
      }
    };
  }

  // Private helper methods

  _isValidTenantId(tenantId) {
    // Validate tenant ID format
    const tenantIdPattern = /^[a-zA-Z0-9_-]+$/;
    return tenantIdPattern.test(tenantId);
  }

  async _getTenantInfo(tenantId) {
    // Check cache first
    const cacheKey = `${this.cachePrefix}:info:${tenantId}`;
    const cached = await this.cache.get(cacheKey);
    
    if (cached) {
      return cached;
    }
    
    // Find tenant by ID or code
    const tenant = await OrganizationTenant.findOne({
      $or: [
        { tenantId },
        { tenantCode: tenantId.toUpperCase() }
      ]
    }).lean();
    
    if (tenant) {
      await this.cache.set(cacheKey, tenant, this.cacheTTL);
    }
    
    return tenant;
  }

  _isTenantAccessible(tenant) {
    // Check if tenant is in accessible state
    const inaccessibleStatuses = [
      TENANT_CONSTANTS.TENANT_STATUS.TERMINATED,
      TENANT_CONSTANTS.TENANT_STATUS.MIGRATING
    ];
    
    return !inaccessibleStatuses.includes(tenant.status);
  }

  async _verifyAdminTenantAccess(adminUser, tenant, options) {
    // Super admins have access to all tenants
    if (adminUser.role?.type === AdminRoles.TYPES.SUPER_ADMIN) {
      return true;
    }
    
    // Check tenant-specific access
    if (tenant.admins?.includes(adminUser._id)) {
      return true;
    }
    
    // Check organization ownership
    const organization = await HostedOrganization.findOne({
      tenantRef: tenant._id
    }).lean();
    
    if (organization && organization.team.owner.toString() === adminUser._id.toString()) {
      return true;
    }
    
    // Check explicit permissions
    const hasPermission = adminUser.permissions?.some(p => 
      p.resource === 'tenant' && 
      p.resourceId === tenant._id.toString() &&
      p.actions.includes('admin_access')
    );
    
    return hasPermission;
  }

  async _setupIsolationContext(tenant, adminUser) {
    const strategy = tenant.database?.strategy || this.isolationStrategies.ROW_LEVEL;
    const securityLevel = tenant.security?.level || this.securityLevels.STANDARD;
    
    const context = {
      strategy,
      securityLevel,
      dataScope: this._determineDataScope(tenant, adminUser),
      restrictions: this._getIsolationRestrictions(tenant, securityLevel),
      encryption: tenant.security?.dataEncryption?.enabled || false
    };
    
    // Set up database connection for dedicated databases
    if (strategy === this.isolationStrategies.DATABASE) {
      context.databaseConnection = await this._getTenantDatabaseConnection(tenant);
    }
    
    return context;
  }

  async _applyIsolationStrategy(isolationContext, req) {
    switch (isolationContext.strategy) {
      case this.isolationStrategies.DATABASE:
        // Switch to tenant-specific database
        req.tenantDb = isolationContext.databaseConnection;
        break;
        
      case this.isolationStrategies.SCHEMA:
        // Set schema context
        req.tenantSchema = isolationContext.dataScope.schema;
        break;
        
      case this.isolationStrategies.ROW_LEVEL:
        // Apply row-level security filters
        req.tenantFilter = { tenantId: isolationContext.dataScope.tenantId };
        break;
        
      case this.isolationStrategies.HYBRID:
        // Apply combination of strategies
        req.tenantDb = isolationContext.databaseConnection;
        req.tenantFilter = { tenantId: isolationContext.dataScope.tenantId };
        break;
    }
  }

  _determineDataScope(tenant, adminUser) {
    return {
      tenantId: tenant.tenantId,
      organizationId: tenant.organizationId,
      schema: tenant.database?.schema,
      allowedCollections: this._getAllowedCollections(tenant, adminUser),
      dataClassification: tenant.compliance?.dataClassification || 'standard'
    };
  }

  _getIsolationRestrictions(tenant, securityLevel) {
    const restrictions = [];
    
    if (securityLevel === this.securityLevels.MAXIMUM) {
      restrictions.push('no_cross_tenant_queries');
      restrictions.push('encrypted_data_only');
      restrictions.push('audit_all_access');
    }
    
    if (securityLevel === this.securityLevels.ENHANCED) {
      restrictions.push('limited_cross_tenant');
      restrictions.push('sensitive_data_masked');
    }
    
    if (tenant.compliance?.gdprEnabled) {
      restrictions.push('gdpr_compliant_access');
      restrictions.push('data_minimization');
    }
    
    return restrictions;
  }

  async _getTenantDatabaseConnection(tenant) {
    const dbConfig = {
      uri: tenant.database.connectionString,
      options: {
        ...config.database.options,
        dbName: tenant.database.name
      }
    };
    
    // Get or create tenant database connection
    return await DatabaseService.getTenantConnection(tenant.tenantId, dbConfig);
  }

  _getAllowedCollections(tenant, adminUser) {
    const baseCollections = [
      'users',
      'organizations',
      'projects',
      'tasks',
      'invoices',
      'payments'
    ];
    
    // Add additional collections based on tenant features
    if (tenant.features?.analytics) {
      baseCollections.push('analytics', 'reports');
    }
    
    if (tenant.features?.advancedSecurity) {
      baseCollections.push('securitylogs', 'accesscontrol');
    }
    
    return baseCollections;
  }

  _applyTenantFilters(query, tenantContext) {
    return {
      ...query,
      tenantId: tenantContext.tenantId,
      _tenantFiltered: true
    };
  }

  _applyTenantDataValidation(data, tenantContext) {
    // Ensure tenant ID is set correctly
    if (data.tenantId && data.tenantId !== tenantContext.tenantId) {
      throw new SecurityError('Tenant ID mismatch detected');
    }
    
    return {
      ...data,
      tenantId: tenantContext.tenantId,
      _tenantValidated: true
    };
  }

  _filterResponseData(data, tenantContext) {
    // Remove any data that doesn't belong to the current tenant
    if (Array.isArray(data)) {
      return data.filter(item => 
        !item.tenantId || item.tenantId === tenantContext.tenantId
      );
    }
    
    if (data && typeof data === 'object' && data.tenantId) {
      if (data.tenantId !== tenantContext.tenantId) {
        throw new SecurityError('Response data tenant mismatch');
      }
    }
    
    return data;
  }

  _setupBoundaryMonitoring(req, res, tenantContext) {
    // Monitor for potential boundary violations
    const monitor = {
      tenantId: tenantContext.tenantId,
      startTime: Date.now(),
      violations: []
    };
    
    // Attach to request for tracking
    req._tenantBoundaryMonitor = monitor;
  }

  async _verifyResourceOwnership(resourceType, resourceId, tenantId) {
    // Map resource types to models
    const resourceModels = {
      user: User,
      organization: HostedOrganization,
      project: 'Project', // Would import actual model
      invoice: 'Invoice'
    };
    
    const Model = resourceModels[resourceType];
    if (!Model) {
      throw new AppError(`Unknown resource type: ${resourceType}`, 400);
    }
    
    const resource = await Model.findById(resourceId).select('tenantId organizationId').lean();
    
    if (!resource) {
      return false;
    }
    
    return resource.tenantId === tenantId;
  }

  async _checkResourcePermissions(adminUser, resourceType, resourceId, method) {
    const methodPermissions = {
      GET: 'read',
      POST: 'create',
      PUT: 'update',
      PATCH: 'update',
      DELETE: 'delete'
    };
    
    const requiredAction = methodPermissions[method] || 'read';
    
    return adminUser.permissions?.some(p =>
      p.resource === resourceType &&
      (p.resourceId === '*' || p.resourceId === resourceId) &&
      p.actions.includes(requiredAction)
    );
  }

  _inferResourceType(req) {
    const pathParts = req.path.split('/');
    const resourceTypes = ['users', 'organizations', 'projects', 'invoices', 'subscriptions'];
    
    return pathParts.find(part => resourceTypes.includes(part))?.slice(0, -1) || 'unknown';
  }

  async _validateTenantCompatibility(sourceTenant, targetTenant, operation) {
    const compatibility = {
      compatible: true,
      restrictions: [],
      requiresDataTransformation: false
    };
    
    // Check database strategy compatibility
    if (sourceTenant.database.strategy !== targetTenant.database.strategy) {
      if (operation === 'data_migration') {
        compatibility.requiresDataTransformation = true;
      } else {
        compatibility.compatible = false;
        compatibility.reason = 'Incompatible database strategies';
      }
    }
    
    // Check security level compatibility
    if (targetTenant.security.level === this.securityLevels.MAXIMUM &&
        sourceTenant.security.level !== this.securityLevels.MAXIMUM) {
      compatibility.restrictions.push('data_security_upgrade_required');
    }
    
    // Check compliance compatibility
    if (targetTenant.compliance?.gdprEnabled && !sourceTenant.compliance?.gdprEnabled) {
      compatibility.restrictions.push('gdpr_compliance_review_required');
    }
    
    return compatibility;
  }

  async _checkCrossTenantPermission(adminUser) {
    return adminUser.permissions?.some(p =>
      p.resource === 'system' &&
      p.actions.includes('cross_tenant_operations')
    );
  }

  _findRestrictedConfigChanges(tenant, configChanges, adminUser) {
    const restricted = [];
    
    // Database changes require super admin
    if (configChanges.database && adminUser.role?.type !== AdminRoles.TYPES.SUPER_ADMIN) {
      restricted.push('database configuration');
    }
    
    // Security downgrades are restricted
    if (configChanges.security?.level) {
      const securityLevels = Object.values(this.securityLevels);
      const currentIndex = securityLevels.indexOf(tenant.security.level);
      const newIndex = securityLevels.indexOf(configChanges.security.level);
      
      if (newIndex < currentIndex) {
        restricted.push('security level downgrade');
      }
    }
    
    // Compliance changes are restricted
    if (configChanges.compliance?.gdprEnabled === false && tenant.compliance?.gdprEnabled) {
      restricted.push('GDPR compliance cannot be disabled');
    }
    
    return restricted;
  }

  async _assessSecurityImpact(tenant, configChanges) {
    let impactLevel = 'low';
    const impacts = [];
    
    if (configChanges.security) {
      impactLevel = 'high';
      impacts.push('Security configuration change');
    }
    
    if (configChanges.database) {
      impactLevel = 'high';
      impacts.push('Database configuration change');
    }
    
    if (configChanges.integrations) {
      impactLevel = 'medium';
      impacts.push('Integration configuration change');
    }
    
    return {
      level: impactLevel,
      impacts,
      requiresReview: impactLevel === 'high',
      estimatedRisk: this._calculateRiskScore(impacts)
    };
  }

  _identifyBreakingChanges(tenant, configChanges) {
    const breakingChanges = [];
    
    if (configChanges.database?.strategy && configChanges.database.strategy !== tenant.database.strategy) {
      breakingChanges.push({
        type: 'database_strategy',
        description: 'Database strategy change requires data migration',
        severity: 'critical'
      });
    }
    
    if (configChanges.security?.encryption && !tenant.security?.encryption) {
      breakingChanges.push({
        type: 'encryption_enablement',
        description: 'Enabling encryption requires data re-encryption',
        severity: 'high'
      });
    }
    
    return breakingChanges;
  }

  _estimateDowntime(breakingChanges) {
    let totalMinutes = 0;
    
    breakingChanges.forEach(change => {
      switch (change.type) {
        case 'database_strategy':
          totalMinutes += 120; // 2 hours
          break;
        case 'encryption_enablement':
          totalMinutes += 60; // 1 hour
          break;
        default:
          totalMinutes += 30; // 30 minutes default
      }
    });
    
    return totalMinutes;
  }

  _generateConfigWarnings(tenant, configChanges) {
    const warnings = [];
    
    if (configChanges.resourceLimits) {
      Object.entries(configChanges.resourceLimits).forEach(([resource, newLimit]) => {
        const currentLimit = tenant.resourceLimits?.[resource];
        if (currentLimit && newLimit < currentLimit) {
          warnings.push(`Reducing ${resource} limit may affect existing usage`);
        }
      });
    }
    
    if (configChanges.features) {
      Object.entries(configChanges.features).forEach(([feature, enabled]) => {
        if (!enabled && tenant.features?.[feature]) {
          warnings.push(`Disabling ${feature} may affect dependent functionality`);
        }
      });
    }
    
    return warnings;
  }

  _calculateRiskScore(impacts) {
    const riskWeights = {
      'Security configuration change': 10,
      'Database configuration change': 9,
      'Integration configuration change': 5,
      'Feature change': 3
    };
    
    return impacts.reduce((score, impact) => {
      return score + (riskWeights[impact] || 1);
    }, 0);
  }

  async _logTenantAccess(adminUser, tenant, action) {
    try {
      const logEntry = new AdminActionLog({
        adminId: adminUser._id,
        action,
        category: 'tenant_access',
        targetType: 'tenant',
        targetId: tenant._id,
        targetName: tenant.tenantCode,
        metadata: {
          tenantId: tenant.tenantId,
          isolationStrategy: tenant.database?.strategy,
          securityLevel: tenant.security?.level
        },
        ipAddress: adminUser.lastLoginIP,
        userAgent: adminUser.lastUserAgent
      });
      
      await logEntry.save();
    } catch (error) {
      logger.error('Failed to log tenant access:', error);
    }
  }

  async _logCrossTenantOperation(adminUser, sourceTenant, targetTenant, operation) {
    try {
      const logEntry = new AdminActionLog({
        adminId: adminUser._id,
        action: `cross_tenant_${operation}`,
        category: 'cross_tenant_operation',
        targetType: 'tenant',
        metadata: {
          sourceTenant: {
            id: sourceTenant.tenantId,
            code: sourceTenant.tenantCode
          },
          targetTenant: {
            id: targetTenant.tenantId,
            code: targetTenant.tenantCode
          },
          operation
        },
        severity: 'high',
        ipAddress: adminUser.lastLoginIP,
        userAgent: adminUser.lastUserAgent
      });
      
      await logEntry.save();
    } catch (error) {
      logger.error('Failed to log cross-tenant operation:', error);
    }
  }

  async _handleIsolationViolations(violationMonitor) {
    logger.error('Tenant isolation violations detected:', violationMonitor);
    
    // Send alerts for critical violations
    const criticalViolations = violationMonitor.violations.filter(v => v.severity === 'critical');
    if (criticalViolations.length > 0) {
      // Send immediate alert
      // await AlertService.sendCriticalAlert('tenant_isolation_violation', violationMonitor);
    }
    
    // Log all violations
    await AdminActionLog.create({
      adminId: violationMonitor.adminId,
      action: 'isolation_violation',
      category: 'security_violation',
      severity: 'critical',
      metadata: violationMonitor
    });
  }

  async _logIsolationMetrics(metrics) {
    // Log metrics for monitoring and analysis
    // This would typically go to a metrics service
    logger.info('Tenant isolation metrics:', {
      tenantId: metrics.tenantId,
      processingTime: metrics.processingTime,
      violations: metrics.violations.length,
      success: metrics.success
    });
  }
}

module.exports = new TenantIsolationMiddleware();