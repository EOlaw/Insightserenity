// server/admin/organization-management/services/tenant-management-service.js
/**
 * @file Tenant Management Service
 * @description Service for managing organization tenant infrastructure and resources
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const moment = require('moment');
const fs = require('fs').promises;
const path = require('path');

// Core Models
const OrganizationTenant = require('../../../organization-tenants/models/organization-tenant-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const User = require('../../../shared/users/models/user-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');
const TenantDatabase = require('../../../organization-tenants/models/tenant-database-model');
const TenantConfiguration = require('../../../organization-tenants/models/tenant-configuration-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const AdminMaintenanceService = require('../../../shared/admin/services/admin-maintenance-service');
const MetricsService = require('../../../shared/monitoring/services/metrics-service');
const DatabaseService = require('../../../shared/utils/database-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError, ConflictError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const { encrypt, decrypt } = require('../../../shared/utils/encryption');
const { generateSecureToken } = require('../../../shared/utils/auth-helpers');

// Configuration
const config = require('../../../config');
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');

/**
 * Tenant Management Service Class
 * @class TenantManagementService
 * @extends AdminBaseService
 */
class TenantManagementService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'TenantManagementService';
    this.cachePrefix = 'admin-tenant';
    this.auditCategory = 'TENANT_MANAGEMENT';
    this.requiredPermission = AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_TENANTS;
    
    // Service configuration
    this.databaseStrategies = {
      SHARED: 'shared',
      DEDICATED: 'dedicated',
      HYBRID: 'hybrid'
    };
    
    // Resource monitoring thresholds
    this.resourceThresholds = {
      storage: {
        warning: 80, // 80% usage
        critical: 95 // 95% usage
      },
      apiCalls: {
        warning: 85,
        critical: 95
      },
      database: {
        connections: 80,
        size: 90
      }
    };
    
    // Migration strategies
    this.migrationStrategies = {
      INCREMENTAL: 'incremental',
      FULL: 'full',
      SELECTIVE: 'selective'
    };
  }

  /**
   * Get tenant details
   * @param {String} tenantId - Tenant ID
   * @param {Object} options - Additional options
   * @param {Object} adminUser - Admin user making the request
   * @returns {Promise<Object>} Tenant details
   */
  async getTenantDetails(tenantId, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_TENANT_DETAILS);
      
      // Get tenant with related data
      const tenant = await OrganizationTenant.findById(tenantId)
        .populate('owner', 'name email status')
        .populate('admins', 'name email')
        .lean();
      
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      // Get associated organization
      const organization = await HostedOrganization.findOne({ tenantRef: tenantId }).lean();
      
      // Enhance with additional data
      const enhancedTenant = {
        ...tenant,
        organization: organization ? {
          _id: organization._id,
          name: organization.name,
          status: organization.status
        } : null
      };
      
      // Add resource usage if requested
      if (options.includeUsage) {
        enhancedTenant.resourceUsage = await this._calculateResourceUsage(tenant);
      }
      
      // Add health status if requested
      if (options.includeHealth) {
        enhancedTenant.healthStatus = await this._getTenantHealth(tenant);
      }
      
      // Add configuration if requested
      if (options.includeConfiguration) {
        enhancedTenant.configuration = await this._getTenantConfiguration(tenantId);
      }
      
      // Add metrics if requested
      if (options.includeMetrics) {
        enhancedTenant.metrics = await this._getTenantMetrics(tenantId);
      }
      
      // Log action
      await this.logAction(AdminEvents.TENANT.VIEWED_DETAILS, adminUser, {
        tenantId,
        tenantCode: tenant.tenantCode
      });
      
      return enhancedTenant;
    } catch (error) {
      logger.error('Error getting tenant details:', error);
      throw error;
    }
  }

  /**
   * Update tenant configuration
   * @param {String} tenantId - Tenant ID
   * @param {Object} updates - Configuration updates
   * @param {Object} adminUser - Admin user making the update
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Updated tenant
   */
  async updateTenantConfiguration(tenantId, updates, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.UPDATE_TENANT_CONFIG);
      
      const tenant = await OrganizationTenant.findById(tenantId).session(session);
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      // Validate configuration updates
      await this._validateConfigurationUpdates(updates, tenant);
      
      // Track changes for audit
      const changes = this._trackConfigurationChanges(tenant, updates);
      
      // Apply updates based on type
      if (updates.settings) {
        Object.assign(tenant.settings, updates.settings);
      }
      
      if (updates.features) {
        tenant.features = { ...tenant.features, ...updates.features };
      }
      
      if (updates.integrations) {
        await this._updateIntegrations(tenant, updates.integrations, session);
      }
      
      if (updates.security) {
        await this._updateSecuritySettings(tenant, updates.security, session);
      }
      
      if (updates.customization) {
        tenant.customization = { ...tenant.customization, ...updates.customization };
      }
      
      tenant.updatedBy = adminUser._id;
      await tenant.save({ session });
      
      // Update configuration record
      await this._updateConfigurationRecord(tenantId, changes, adminUser, session);
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearTenantCaches(tenantId);
      
      // Notify if critical changes
      if (this._isCriticalConfigChange(changes)) {
        await this._notifyConfigurationChange(tenant, changes, adminUser);
      }
      
      // Log action
      await this.logAction(AdminEvents.TENANT.CONFIGURATION_UPDATED, adminUser, {
        tenantId,
        tenantCode: tenant.tenantCode,
        changes: Object.keys(changes)
      });
      
      return tenant;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error updating tenant configuration:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Update tenant resource limits
   * @param {String} tenantId - Tenant ID
   * @param {Object} newLimits - New resource limits
   * @param {Object} adminUser - Admin user making the update
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Updated tenant
   */
  async updateResourceLimits(tenantId, newLimits, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.UPDATE_RESOURCE_LIMITS);
      
      const tenant = await OrganizationTenant.findById(tenantId).session(session);
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      // Validate new limits
      await this._validateResourceLimits(newLimits, tenant);
      
      // Track changes
      const previousLimits = JSON.parse(JSON.stringify(tenant.resourceLimits));
      
      // Update limits
      if (newLimits.users !== undefined) {
        tenant.resourceLimits.users.max = newLimits.users;
      }
      
      if (newLimits.storage !== undefined) {
        tenant.resourceLimits.storage.maxGB = newLimits.storage;
      }
      
      if (newLimits.apiCalls !== undefined) {
        tenant.resourceLimits.apiCalls.max = newLimits.apiCalls;
      }
      
      if (newLimits.projects !== undefined) {
        tenant.resourceLimits.projects.max = newLimits.projects;
      }
      
      if (newLimits.customDomains !== undefined) {
        tenant.resourceLimits.customDomains.max = newLimits.customDomains;
      }
      
      if (newLimits.bandwidth !== undefined) {
        tenant.resourceLimits.bandwidth = {
          maxGB: newLimits.bandwidth,
          current: tenant.resourceLimits.bandwidth?.current || 0
        };
      }
      
      // Add limit change history
      tenant.limitHistory = tenant.limitHistory || [];
      tenant.limitHistory.push({
        changedAt: new Date(),
        changedBy: adminUser._id,
        previousLimits,
        newLimits: tenant.resourceLimits,
        reason: options.reason || 'Administrative adjustment'
      });
      
      await tenant.save({ session });
      
      // Update organization if needed
      const organization = await HostedOrganization.findOne({ tenantRef: tenantId }).session(session);
      if (organization) {
        organization.limits = {
          users: tenant.resourceLimits.users.max,
          storage: tenant.resourceLimits.storage.maxGB,
          apiCallsPerMonth: tenant.resourceLimits.apiCalls.max,
          projects: tenant.resourceLimits.projects.max,
          customDomains: tenant.resourceLimits.customDomains.max
        };
        await organization.save({ session });
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearTenantCaches(tenantId);
      
      // Send notifications
      if (!options.skipNotifications) {
        await this._sendLimitChangeNotifications(tenant, previousLimits, newLimits, adminUser);
      }
      
      // Log action
      await this.logAction(AdminEvents.TENANT.RESOURCE_LIMITS_UPDATED, adminUser, {
        tenantId,
        tenantCode: tenant.tenantCode,
        previousLimits,
        newLimits
      }, 'high');
      
      return tenant;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error updating resource limits:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Migrate tenant to different infrastructure
   * @param {String} tenantId - Tenant ID
   * @param {Object} migrationConfig - Migration configuration
   * @param {Object} adminUser - Admin user performing migration
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Migration result
   */
  async migrateTenant(tenantId, migrationConfig, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.SUPER_ADMIN.INFRASTRUCTURE_MANAGEMENT);
      
      const tenant = await OrganizationTenant.findById(tenantId).session(session);
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      // Validate migration configuration
      await this._validateMigrationConfig(migrationConfig, tenant);
      
      // Check if migration is already in progress
      if (tenant.migrationStatus?.inProgress) {
        throw new ConflictError('Migration already in progress for this tenant');
      }
      
      // Create migration record
      const migrationId = crypto.randomBytes(16).toString('hex');
      const migrationRecord = {
        id: migrationId,
        type: migrationConfig.type,
        from: {
          database: tenant.database.strategy,
          server: tenant.database.server,
          region: tenant.settings.dataLocation
        },
        to: {
          database: migrationConfig.targetDatabase || tenant.database.strategy,
          server: migrationConfig.targetServer || tenant.database.server,
          region: migrationConfig.targetRegion || tenant.settings.dataLocation
        },
        strategy: migrationConfig.strategy || this.migrationStrategies.INCREMENTAL,
        startedAt: new Date(),
        startedBy: adminUser._id,
        status: 'preparing',
        steps: []
      };
      
      // Update tenant migration status
      tenant.migrationStatus = {
        inProgress: true,
        migrationId,
        startedAt: new Date(),
        estimatedCompletion: this._estimateMigrationTime(tenant, migrationConfig)
      };
      
      await tenant.save({ session });
      
      // Put tenant in maintenance mode if required
      if (migrationConfig.requiresMaintenance) {
        await this._enableMaintenanceMode(tenant, 'migration', session);
      }
      
      await session.commitTransaction();
      
      // Start migration process asynchronously
      this._executeMigration(migrationId, tenant, migrationConfig, adminUser)
        .catch(error => {
          logger.error('Migration failed:', error);
          this._handleMigrationFailure(migrationId, tenant, error);
        });
      
      // Log action
      await this.logAction(AdminEvents.TENANT.MIGRATION_STARTED, adminUser, {
        tenantId,
        tenantCode: tenant.tenantCode,
        migrationId,
        migrationConfig
      }, 'critical');
      
      return {
        migrationId,
        status: 'started',
        estimatedCompletion: migrationRecord.to.estimatedCompletion,
        message: 'Tenant migration has been initiated'
      };
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error starting tenant migration:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Enable/disable maintenance mode for tenant
   * @param {String} tenantId - Tenant ID
   * @param {Boolean} enable - Enable or disable
   * @param {Object} maintenanceConfig - Maintenance configuration
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Updated tenant
   */
  async setMaintenanceMode(tenantId, enable, maintenanceConfig = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.MANAGE_MAINTENANCE);
      
      const tenant = await OrganizationTenant.findById(tenantId);
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      if (enable) {
        // Enable maintenance mode
        tenant.maintenanceMode = {
          enabled: true,
          startedAt: new Date(),
          startedBy: adminUser._id,
          reason: maintenanceConfig.reason || 'Scheduled maintenance',
          estimatedDuration: maintenanceConfig.estimatedDuration,
          allowedIPs: maintenanceConfig.allowedIPs || [],
          customMessage: maintenanceConfig.customMessage,
          notifyUsers: maintenanceConfig.notifyUsers !== false
        };
        
        // Notify users if requested
        if (tenant.maintenanceMode.notifyUsers) {
          await this._notifyMaintenanceMode(tenant, true, maintenanceConfig);
        }
      } else {
        // Disable maintenance mode
        if (!tenant.maintenanceMode?.enabled) {
          throw new ConflictError('Maintenance mode is not enabled');
        }
        
        // Archive maintenance record
        tenant.maintenanceHistory = tenant.maintenanceHistory || [];
        tenant.maintenanceHistory.push({
          ...tenant.maintenanceMode,
          endedAt: new Date(),
          endedBy: adminUser._id,
          actualDuration: new Date() - tenant.maintenanceMode.startedAt
        });
        
        tenant.maintenanceMode = {
          enabled: false,
          lastMaintenance: new Date()
        };
        
        // Notify users
        await this._notifyMaintenanceMode(tenant, false);
      }
      
      await tenant.save();
      
      // Update cache
      await this._updateMaintenanceCache(tenant);
      
      // Log action
      await this.logAction(
        enable ? AdminEvents.TENANT.MAINTENANCE_ENABLED : AdminEvents.TENANT.MAINTENANCE_DISABLED,
        adminUser,
        {
          tenantId,
          tenantCode: tenant.tenantCode,
          maintenanceConfig
        }
      );
      
      return tenant;
    } catch (error) {
      logger.error('Error setting maintenance mode:', error);
      throw error;
    }
  }

  /**
   * Monitor tenant health
   * @param {String} tenantId - Tenant ID
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Health status
   */
  async monitorTenantHealth(tenantId, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_TENANT_HEALTH);
      
      const tenant = await OrganizationTenant.findById(tenantId);
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      // Perform health checks
      const healthChecks = await Promise.all([
        this._checkDatabaseHealth(tenant),
        this._checkResourceHealth(tenant),
        this._checkServiceHealth(tenant),
        this._checkSecurityHealth(tenant),
        this._checkPerformanceHealth(tenant)
      ]);
      
      // Calculate overall health score
      const overallHealth = this._calculateOverallHealth(healthChecks);
      
      // Determine health status
      const healthStatus = {
        status: overallHealth.score >= 90 ? 'healthy' : 
                overallHealth.score >= 70 ? 'warning' : 'critical',
        score: overallHealth.score,
        checks: healthChecks,
        issues: overallHealth.issues,
        recommendations: overallHealth.recommendations,
        lastChecked: new Date()
      };
      
      // Update tenant health record
      tenant.healthStatus = {
        ...healthStatus,
        history: [
          ...(tenant.healthStatus?.history || []).slice(-99), // Keep last 100
          {
            timestamp: new Date(),
            score: overallHealth.score,
            status: healthStatus.status
          }
        ]
      };
      
      await tenant.save();
      
      // Alert if critical issues
      if (healthStatus.status === 'critical') {
        await this._alertCriticalHealth(tenant, healthStatus, adminUser);
      }
      
      // Log action
      await this.logAction(AdminEvents.TENANT.HEALTH_CHECKED, adminUser, {
        tenantId,
        tenantCode: tenant.tenantCode,
        healthStatus: healthStatus.status,
        score: healthStatus.score
      });
      
      return healthStatus;
    } catch (error) {
      logger.error('Error monitoring tenant health:', error);
      throw error;
    }
  }

  /**
   * Reset tenant data
   * @param {String} tenantId - Tenant ID
   * @param {Object} resetConfig - Reset configuration
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Reset result
   */
  async resetTenantData(tenantId, resetConfig, adminUser) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.SUPER_ADMIN.DESTRUCTIVE_OPERATIONS);
      
      const tenant = await OrganizationTenant.findById(tenantId).session(session);
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      // Validate reset configuration
      if (!resetConfig.confirmation || resetConfig.confirmation !== tenant.tenantCode) {
        throw new ValidationError('Invalid confirmation code');
      }
      
      // Create backup before reset
      const backupId = await this._createTenantBackup(tenant, adminUser);
      
      // Perform reset based on configuration
      const resetResult = {
        backupId,
        resetItems: [],
        startedAt: new Date()
      };
      
      if (resetConfig.resetUsers) {
        await this._resetTenantUsers(tenant, session);
        resetResult.resetItems.push('users');
      }
      
      if (resetConfig.resetData) {
        await this._resetTenantData(tenant, resetConfig.dataTypes, session);
        resetResult.resetItems.push('data');
      }
      
      if (resetConfig.resetConfiguration) {
        await this._resetTenantConfiguration(tenant, session);
        resetResult.resetItems.push('configuration');
      }
      
      if (resetConfig.resetLogs) {
        await this._resetTenantLogs(tenant, session);
        resetResult.resetItems.push('logs');
      }
      
      // Update tenant reset history
      tenant.resetHistory = tenant.resetHistory || [];
      tenant.resetHistory.push({
        resetAt: new Date(),
        resetBy: adminUser._id,
        resetConfig,
        backupId
      });
      
      await tenant.save({ session });
      
      await session.commitTransaction();
      
      resetResult.completedAt = new Date();
      resetResult.status = 'completed';
      
      // Clear all tenant caches
      await this._clearAllTenantCaches(tenantId);
      
      // Send notifications
      await this._sendResetNotifications(tenant, resetResult, adminUser);
      
      // Log action
      await this.logAction(AdminEvents.TENANT.DATA_RESET, adminUser, {
        tenantId,
        tenantCode: tenant.tenantCode,
        resetConfig,
        backupId
      }, 'critical');
      
      return resetResult;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error resetting tenant data:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Clone tenant configuration
   * @param {String} sourceTenantId - Source tenant ID
   * @param {String} targetTenantId - Target tenant ID
   * @param {Object} cloneConfig - Clone configuration
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Clone result
   */
  async cloneTenantConfiguration(sourceTenantId, targetTenantId, cloneConfig, adminUser) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.CLONE_TENANT_CONFIG);
      
      const [sourceTenant, targetTenant] = await Promise.all([
        OrganizationTenant.findById(sourceTenantId).session(session),
        OrganizationTenant.findById(targetTenantId).session(session)
      ]);
      
      if (!sourceTenant || !targetTenant) {
        throw new NotFoundError('Source or target tenant not found');
      }
      
      // Validate clone configuration
      await this._validateCloneConfig(cloneConfig, sourceTenant, targetTenant);
      
      const cloneResult = {
        clonedItems: [],
        skippedItems: [],
        startedAt: new Date()
      };
      
      // Clone settings
      if (cloneConfig.includeSettings) {
        targetTenant.settings = { ...sourceTenant.settings };
        cloneResult.clonedItems.push('settings');
      }
      
      // Clone features
      if (cloneConfig.includeFeatures) {
        targetTenant.features = { ...sourceTenant.features };
        cloneResult.clonedItems.push('features');
      }
      
      // Clone integrations
      if (cloneConfig.includeIntegrations) {
        targetTenant.integrations = sourceTenant.integrations.map(integration => ({
          ...integration,
          _id: undefined,
          configuredAt: new Date(),
          configuredBy: adminUser._id
        }));
        cloneResult.clonedItems.push('integrations');
      }
      
      // Clone security settings
      if (cloneConfig.includeSecurity) {
        targetTenant.security = { ...sourceTenant.security };
        cloneResult.clonedItems.push('security');
      }
      
      // Clone customization
      if (cloneConfig.includeCustomization) {
        targetTenant.customization = { ...sourceTenant.customization };
        cloneResult.clonedItems.push('customization');
      }
      
      // Clone resource limits (if allowed)
      if (cloneConfig.includeResourceLimits && adminUser.role.type === 'super_admin') {
        targetTenant.resourceLimits = { ...sourceTenant.resourceLimits };
        cloneResult.clonedItems.push('resourceLimits');
      } else if (cloneConfig.includeResourceLimits) {
        cloneResult.skippedItems.push({
          item: 'resourceLimits',
          reason: 'Insufficient permissions'
        });
      }
      
      targetTenant.updatedBy = adminUser._id;
      await targetTenant.save({ session });
      
      await session.commitTransaction();
      
      cloneResult.completedAt = new Date();
      cloneResult.status = 'completed';
      
      // Clear target tenant caches
      await this._clearTenantCaches(targetTenantId);
      
      // Log action
      await this.logAction(AdminEvents.TENANT.CONFIGURATION_CLONED, adminUser, {
        sourceTenantId,
        targetTenantId,
        cloneConfig,
        cloneResult
      });
      
      return cloneResult;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error cloning tenant configuration:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Get tenant resource usage report
   * @param {String} tenantId - Tenant ID
   * @param {Object} options - Report options
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Resource usage report
   */
  async getTenantResourceReport(tenantId, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_RESOURCE_USAGE);
      
      const tenant = await OrganizationTenant.findById(tenantId);
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }
      
      const reportPeriod = options.period || 'month';
      const startDate = this._getReportStartDate(reportPeriod);
      
      // Gather resource usage data
      const [
        storageUsage,
        apiUsage,
        bandwidthUsage,
        databaseUsage,
        userActivity
      ] = await Promise.all([
        this._getStorageUsage(tenantId, startDate),
        this._getApiUsage(tenantId, startDate),
        this._getBandwidthUsage(tenantId, startDate),
        this._getDatabaseUsage(tenantId, startDate),
        this._getUserActivity(tenantId, startDate)
      ]);
      
      // Calculate costs if applicable
      const costAnalysis = await this._calculateResourceCosts(tenant, {
        storage: storageUsage,
        api: apiUsage,
        bandwidth: bandwidthUsage
      });
      
      const report = {
        tenantId,
        tenantCode: tenant.tenantCode,
        period: reportPeriod,
        startDate,
        endDate: new Date(),
        usage: {
          storage: storageUsage,
          api: apiUsage,
          bandwidth: bandwidthUsage,
          database: databaseUsage,
          users: userActivity
        },
        limits: tenant.resourceLimits,
        utilization: this._calculateUtilization(tenant.resourceLimits, {
          storage: storageUsage,
          api: apiUsage,
          bandwidth: bandwidthUsage
        }),
        trends: await this._calculateUsageTrends(tenantId, reportPeriod),
        alerts: this._generateResourceAlerts(tenant, {
          storage: storageUsage,
          api: apiUsage,
          bandwidth: bandwidthUsage
        }),
        costAnalysis,
        recommendations: this._generateResourceRecommendations(tenant, {
          storage: storageUsage,
          api: apiUsage,
          bandwidth: bandwidthUsage,
          users: userActivity
        }),
        generatedAt: new Date(),
        generatedBy: adminUser._id
      };
      
      // Log action
      await this.logAction(AdminEvents.TENANT.RESOURCE_REPORT_GENERATED, adminUser, {
        tenantId,
        tenantCode: tenant.tenantCode,
        reportPeriod
      });
      
      return report;
    } catch (error) {
      logger.error('Error generating resource report:', error);
      throw error;
    }
  }

  // Private helper methods

  async _calculateResourceUsage(tenant) {
    const usage = {
      users: {
        current: tenant.resourceLimits.users.current,
        limit: tenant.resourceLimits.users.max,
        percentage: tenant.resourceLimits.users.max === -1 ? 0 :
          Math.round((tenant.resourceLimits.users.current / tenant.resourceLimits.users.max) * 100)
      },
      storage: {
        currentGB: (tenant.resourceLimits.storage.currentBytes / (1024 * 1024 * 1024)).toFixed(2),
        limitGB: tenant.resourceLimits.storage.maxGB,
        percentage: tenant.resourceLimits.storage.maxGB === -1 ? 0 :
          Math.round((tenant.resourceLimits.storage.currentBytes / (tenant.resourceLimits.storage.maxGB * 1024 * 1024 * 1024)) * 100)
      },
      apiCalls: {
        current: tenant.resourceLimits.apiCalls.current,
        limit: tenant.resourceLimits.apiCalls.max,
        percentage: tenant.resourceLimits.apiCalls.max === -1 ? 0 :
          Math.round((tenant.resourceLimits.apiCalls.current / tenant.resourceLimits.apiCalls.max) * 100),
        resetDate: tenant.resourceLimits.apiCalls.resetDate
      },
      projects: {
        current: tenant.resourceLimits.projects.current,
        limit: tenant.resourceLimits.projects.max,
        percentage: tenant.resourceLimits.projects.max === -1 ? 0 :
          Math.round((tenant.resourceLimits.projects.current / tenant.resourceLimits.projects.max) * 100)
      }
    };
    
    return usage;
  }

  async _getTenantHealth(tenant) {
    const healthChecks = {
      database: await this._checkDatabaseHealth(tenant),
      resources: await this._checkResourceHealth(tenant),
      services: await this._checkServiceHealth(tenant),
      security: await this._checkSecurityHealth(tenant),
      performance: await this._checkPerformanceHealth(tenant)
    };
    
    const overallScore = Object.values(healthChecks)
      .reduce((sum, check) => sum + check.score, 0) / Object.keys(healthChecks).length;
    
    return {
      overall: {
        score: Math.round(overallScore),
        status: overallScore >= 90 ? 'healthy' : overallScore >= 70 ? 'warning' : 'critical'
      },
      checks: healthChecks,
      lastChecked: new Date()
    };
  }

  async _checkDatabaseHealth(tenant) {
    try {
      // Check database connectivity
      const dbStats = await DatabaseService.getDatabaseStats(tenant.database.connectionString);
      
      const health = {
        name: 'Database Health',
        status: 'healthy',
        score: 100,
        metrics: {
          connectivity: true,
          responseTime: dbStats.responseTime,
          connections: dbStats.connections,
          size: dbStats.size
        },
        issues: []
      };
      
      // Check response time
      if (dbStats.responseTime > 1000) {
        health.score -= 20;
        health.issues.push({
          severity: 'warning',
          message: 'High database response time',
          value: `${dbStats.responseTime}ms`
        });
      }
      
      // Check connection pool
      if (dbStats.connections.active / dbStats.connections.max > 0.8) {
        health.score -= 15;
        health.issues.push({
          severity: 'warning',
          message: 'High connection pool usage',
          value: `${Math.round((dbStats.connections.active / dbStats.connections.max) * 100)}%`
        });
      }
      
      health.status = health.score >= 90 ? 'healthy' : health.score >= 70 ? 'warning' : 'critical';
      return health;
    } catch (error) {
      return {
        name: 'Database Health',
        status: 'critical',
        score: 0,
        error: error.message,
        issues: [{
          severity: 'critical',
          message: 'Database health check failed',
          error: error.message
        }]
      };
    }
  }

  async _checkResourceHealth(tenant) {
    const usage = await this._calculateResourceUsage(tenant);
    
    const health = {
      name: 'Resource Health',
      status: 'healthy',
      score: 100,
      metrics: usage,
      issues: []
    };
    
    // Check each resource type
    Object.entries(usage).forEach(([resource, data]) => {
      if (data.percentage >= this.resourceThresholds.storage.critical) {
        health.score -= 30;
        health.issues.push({
          severity: 'critical',
          message: `Critical ${resource} usage`,
          value: `${data.percentage}%`
        });
      } else if (data.percentage >= this.resourceThresholds.storage.warning) {
        health.score -= 15;
        health.issues.push({
          severity: 'warning',
          message: `High ${resource} usage`,
          value: `${data.percentage}%`
        });
      }
    });
    
    health.status = health.score >= 90 ? 'healthy' : health.score >= 70 ? 'warning' : 'critical';
    return health;
  }

  async _checkServiceHealth(tenant) {
    // Check various service endpoints
    const services = [
      { name: 'API', endpoint: `/api/v1/tenant/${tenant.tenantCode}/health` },
      { name: 'Auth', endpoint: `/api/v1/tenant/${tenant.tenantCode}/auth/health` },
      { name: 'Storage', endpoint: `/api/v1/tenant/${tenant.tenantCode}/storage/health` }
    ];
    
    const health = {
      name: 'Service Health',
      status: 'healthy',
      score: 100,
      services: [],
      issues: []
    };
    
    for (const service of services) {
      try {
        const startTime = Date.now();
        const response = await this._checkServiceEndpoint(service.endpoint);
        const responseTime = Date.now() - startTime;
        
        health.services.push({
          name: service.name,
          status: 'up',
          responseTime
        });
        
        if (responseTime > 500) {
          health.score -= 10;
          health.issues.push({
            severity: 'warning',
            message: `Slow ${service.name} response`,
            value: `${responseTime}ms`
          });
        }
      } catch (error) {
        health.score -= 25;
        health.services.push({
          name: service.name,
          status: 'down',
          error: error.message
        });
        health.issues.push({
          severity: 'critical',
          message: `${service.name} service is down`,
          error: error.message
        });
      }
    }
    
    health.status = health.score >= 90 ? 'healthy' : health.score >= 70 ? 'warning' : 'critical';
    return health;
  }

  async _checkSecurityHealth(tenant) {
    const health = {
      name: 'Security Health',
      status: 'healthy',
      score: 100,
      checks: {
        mfa: tenant.security.mfaRequired,
        ipWhitelisting: tenant.security.ipWhitelistEnabled,
        encryption: tenant.security.dataEncryption.enabled,
        passwordPolicy: tenant.security.passwordPolicy.enforced,
        sessionTimeout: tenant.security.sessionTimeout <= 7200000, // 2 hours
        lastSecurityAudit: tenant.security.lastSecurityAudit
      },
      issues: []
    };
    
    // Check security configurations
    if (!tenant.security.mfaRequired) {
      health.score -= 20;
      health.issues.push({
        severity: 'warning',
        message: 'MFA not required',
        recommendation: 'Enable MFA for enhanced security'
      });
    }
    
    if (!tenant.security.dataEncryption.enabled) {
      health.score -= 25;
      health.issues.push({
        severity: 'critical',
        message: 'Data encryption disabled',
        recommendation: 'Enable data encryption immediately'
      });
    }
    
    // Check last security audit
    const daysSinceAudit = tenant.security.lastSecurityAudit ?
      moment().diff(tenant.security.lastSecurityAudit, 'days') : 999;
    
    if (daysSinceAudit > 90) {
      health.score -= 15;
      health.issues.push({
        severity: 'warning',
        message: 'Security audit overdue',
        value: `${daysSinceAudit} days since last audit`
      });
    }
    
    health.status = health.score >= 90 ? 'healthy' : health.score >= 70 ? 'warning' : 'critical';
    return health;
  }

  async _checkPerformanceHealth(tenant) {
    // Get performance metrics
    const metrics = await MetricsService.getTenantMetrics(tenant.tenantId, {
      period: 'hour',
      metrics: ['responseTime', 'throughput', 'errorRate', 'cpu', 'memory']
    });
    
    const health = {
      name: 'Performance Health',
      status: 'healthy',
      score: 100,
      metrics: {
        avgResponseTime: metrics.avgResponseTime,
        p95ResponseTime: metrics.p95ResponseTime,
        throughput: metrics.throughput,
        errorRate: metrics.errorRate,
        cpuUsage: metrics.cpuUsage,
        memoryUsage: metrics.memoryUsage
      },
      issues: []
    };
    
    // Check response times
    if (metrics.p95ResponseTime > 2000) {
      health.score -= 20;
      health.issues.push({
        severity: 'warning',
        message: 'High P95 response time',
        value: `${metrics.p95ResponseTime}ms`
      });
    }
    
    // Check error rate
    if (metrics.errorRate > 5) {
      health.score -= 25;
      health.issues.push({
        severity: 'critical',
        message: 'High error rate',
        value: `${metrics.errorRate}%`
      });
    }
    
    // Check resource usage
    if (metrics.cpuUsage > 80) {
      health.score -= 15;
      health.issues.push({
        severity: 'warning',
        message: 'High CPU usage',
        value: `${metrics.cpuUsage}%`
      });
    }
    
    if (metrics.memoryUsage > 85) {
      health.score -= 15;
      health.issues.push({
        severity: 'warning',
        message: 'High memory usage',
        value: `${metrics.memoryUsage}%`
      });
    }
    
    health.status = health.score >= 90 ? 'healthy' : health.score >= 70 ? 'warning' : 'critical';
    return health;
  }

  async _clearTenantCaches(tenantId) {
    const cacheKeys = [
      `${this.cachePrefix}:${tenantId}:*`,
      `tenant:${tenantId}:*`,
      `organization:tenant:${tenantId}:*`
    ];
    
    await Promise.all(cacheKeys.map(pattern => this.cache.deletePattern(pattern)));
  }

  async _executeMigration(migrationId, tenant, config, adminUser) {
    try {
      // Implementation would include:
      // 1. Backup current data
      // 2. Provision new infrastructure
      // 3. Migrate data in batches
      // 4. Verify data integrity
      // 5. Update DNS/routing
      // 6. Cleanup old infrastructure
      
      logger.info('Migration execution started', { migrationId, tenantId: tenant._id });
      
      // This is a simplified version - actual implementation would be much more complex
      await this._updateMigrationStatus(migrationId, 'completed');
      
    } catch (error) {
      logger.error('Migration execution failed', { migrationId, error });
      throw error;
    }
  }

  _generateResourceRecommendations(tenant, usage) {
    const recommendations = [];
    
    // Storage recommendations
    if (usage.storage.percentage > 80) {
      recommendations.push({
        type: 'storage',
        priority: 'high',
        message: 'Consider upgrading storage capacity',
        suggestion: `Current usage is ${usage.storage.percentage}%. Recommend increasing storage limit by 50%.`
      });
    }
    
    // API usage recommendations
    if (usage.api.percentage > 90) {
      recommendations.push({
        type: 'api',
        priority: 'critical',
        message: 'API limit nearly reached',
        suggestion: 'Upgrade to a higher plan or purchase additional API calls.'
      });
    }
    
    // Performance recommendations
    if (usage.api.averageResponseTime > 1000) {
      recommendations.push({
        type: 'performance',
        priority: 'medium',
        message: 'Consider performance optimization',
        suggestion: 'High API response times detected. Consider caching or database optimization.'
      });
    }
    
    return recommendations;
  }
}

module.exports = new TenantManagementService();