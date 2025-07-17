// server/admin/organization-management/services/admin-organization-service.js
/**
 * @file Admin Organization Service
 * @description Comprehensive organization management service for administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const moment = require('moment');

// Core Models
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const OrganizationTenant = require('../../../organization-tenants/models/organization-tenant-model');
const User = require('../../../shared/users/models/user-model');
const Role = require('../../../shared/users/models/role-model');
const Subscription = require('../../../shared/billing/models/subscription-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const AdminBackupService = require('../../../shared/admin/services/admin-backup-service');
const PermissionService = require('../../../shared/users/services/permission-service');

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
 * Admin Organization Service Class
 * @class AdminOrganizationService
 * @extends AdminBaseService
 */
class AdminOrganizationService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'AdminOrganizationService';
    this.cachePrefix = 'admin-organization';
    this.auditCategory = 'ORGANIZATION_MANAGEMENT';
    this.requiredPermission = AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS;
    
    // Service-specific configuration
    this.searchableFields = ['name', 'displayName', 'email', 'tenantCode', 'tenantId'];
    this.sortableFields = ['name', 'createdAt', 'memberCount', 'subscription.status', 'metrics.usage.lastActivity'];
    this.populateFields = ['team.owner', 'team.admins.user', 'tenantRef'];
    
    // Bulk operation limits
    this.bulkLimits = {
      suspend: AdminLimits.BULK_OPERATIONS.ORGANIZATIONS.SUSPEND,
      activate: AdminLimits.BULK_OPERATIONS.ORGANIZATIONS.ACTIVATE,
      delete: AdminLimits.BULK_OPERATIONS.ORGANIZATIONS.DELETE,
      export: AdminLimits.BULK_OPERATIONS.ORGANIZATIONS.EXPORT
    };
  }

  /**
   * Get organizations with advanced filtering
   * @param {Object} query - Query parameters
   * @param {Object} options - Additional options
   * @param {Object} adminUser - Admin user making the request
   * @returns {Promise<Object>} Paginated organizations
   */
  async getOrganizations(query = {}, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS);
      
      // Build filter
      const filter = await this._buildOrganizationFilter(query);
      
      // Apply admin visibility rules
      const visibilityFilter = await this._applyVisibilityRules(filter, adminUser);
      
      // Build aggregation pipeline
      const pipeline = this._buildAggregationPipeline(visibilityFilter, query, options);
      
      // Execute query with caching
      const cacheKey = `${this.cachePrefix}:list:${AdminHelpers.generateCacheKey({ ...query, ...options })}`;
      const cached = await this.cache.get(cacheKey);
      
      if (cached && !options.skipCache) {
        return cached;
      }
      
      // Execute aggregation
      const [results] = await HostedOrganization.aggregate(pipeline);
      
      const response = {
        organizations: results.data || [],
        pagination: {
          total: results.total?.[0]?.count || 0,
          page: parseInt(query.page) || 1,
          limit: parseInt(query.limit) || 20,
          pages: Math.ceil((results.total?.[0]?.count || 0) / (parseInt(query.limit) || 20))
        },
        filters: query,
        sort: options.sort || '-createdAt'
      };
      
      // Cache results
      await this.cache.set(cacheKey, response, 300); // 5 minutes
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.VIEWED_LIST, adminUser, {
        count: response.organizations.length,
        filters: query
      });
      
      return response;
    } catch (error) {
      logger.error('Error getting organizations:', error);
      throw error;
    }
  }

  /**
   * Get single organization with detailed information
   * @param {String} organizationId - Organization ID
   * @param {Object} options - Additional options
   * @param {Object} adminUser - Admin user making the request
   * @returns {Promise<Object>} Organization details
   */
  async getOrganizationById(organizationId, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ORGANIZATIONS);
      
      // Get organization with all related data
      const organization = await HostedOrganization.findById(organizationId)
        .populate('team.owner', 'name email profilePicture status')
        .populate('team.admins.user', 'name email profilePicture')
        .populate('team.members.user', 'name email profilePicture')
        .populate('tenantRef')
        .lean();
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Check visibility permissions
      await this._checkOrganizationVisibility(organization, adminUser);
      
      // Enhance with additional data if requested
      if (options.includeAnalytics) {
        organization.analytics = await this._getOrganizationAnalytics(organizationId);
      }
      
      if (options.includeSubscription) {
        organization.subscriptionDetails = await this._getSubscriptionDetails(organizationId);
      }
      
      if (options.includeActivity) {
        organization.recentActivity = await this._getRecentActivity(organizationId);
      }
      
      if (options.includeCompliance) {
        organization.complianceStatus = await this._getComplianceStatus(organization);
      }
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.VIEWED_DETAILS, adminUser, {
        organizationId,
        organizationName: organization.name
      });
      
      return organization;
    } catch (error) {
      logger.error('Error getting organization:', error);
      throw error;
    }
  }

  /**
   * Create new organization (admin-initiated)
   * @param {Object} organizationData - Organization data
   * @param {Object} adminUser - Admin user creating the organization
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Created organization
   */
  async createOrganization(organizationData, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.CREATE_ORGANIZATION);
      
      // Validate organization data
      await this._validateOrganizationData(organizationData, 'create');
      
      // Check for duplicates
      await this._checkDuplicateOrganization(organizationData);
      
      // Set defaults and admin overrides
      const orgData = {
        ...organizationData,
        createdBy: adminUser._id,
        createdVia: 'admin_panel',
        status: {
          active: true,
          verified: options.autoVerify || false,
          suspended: false
        },
        metadata: {
          ...organizationData.metadata,
          createdByAdmin: true,
          adminId: adminUser._id,
          creationMethod: 'admin_panel'
        }
      };
      
      // Create tenant infrastructure first
      const tenantData = await this._prepareTenantData(orgData, adminUser);
      const tenant = await this._createTenant(tenantData, session);
      
      // Link tenant to organization
      orgData.tenantRef = tenant._id;
      orgData.tenantId = tenant.tenantId;
      orgData.tenantCode = tenant.tenantCode;
      
      // Create organization
      const organization = new HostedOrganization(orgData);
      await organization.save({ session });
      
      // Setup organization infrastructure
      await this._setupOrganizationInfrastructure(organization, tenant, session);
      
      // Send notifications
      if (!options.skipNotifications) {
        await this._sendOrganizationCreatedNotifications(organization, adminUser);
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearOrganizationCaches();
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.CREATED, adminUser, {
        organizationId: organization._id,
        organizationName: organization.name,
        ownerId: organization.team.owner
      });
      
      return organization;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error creating organization:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Update organization
   * @param {String} organizationId - Organization ID
   * @param {Object} updates - Update data
   * @param {Object} adminUser - Admin user making the update
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Updated organization
   */
  async updateOrganization(organizationId, updates, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.UPDATE_ORGANIZATION);
      
      // Get current organization
      const organization = await HostedOrganization.findById(organizationId).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Check update permissions for specific fields
      await this._checkUpdatePermissions(updates, adminUser);
      
      // Validate updates
      await this._validateOrganizationData(updates, 'update');
      
      // Track changes for audit
      const changes = this._trackChanges(organization, updates);
      
      // Apply updates with restrictions
      const allowedUpdates = this._filterAllowedUpdates(updates, adminUser);
      Object.assign(organization, allowedUpdates);
      
      // Handle special updates
      if (updates.status) {
        await this._handleStatusChange(organization, updates.status, adminUser, session);
      }
      
      if (updates.subscription) {
        await this._handleSubscriptionChange(organization, updates.subscription, adminUser, session);
      }
      
      if (updates.limits) {
        await this._handleLimitsChange(organization, updates.limits, adminUser, session);
      }
      
      organization.lastModifiedBy = adminUser._id;
      await organization.save({ session });
      
      // Update tenant if needed
      if (this._requiresTenantUpdate(updates)) {
        await this._updateTenant(organization.tenantRef, updates, session);
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearOrganizationCaches(organizationId);
      
      // Send notifications
      if (!options.skipNotifications && Object.keys(changes).length > 0) {
        await this._sendUpdateNotifications(organization, changes, adminUser);
      }
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.UPDATED, adminUser, {
        organizationId,
        organizationName: organization.name,
        changes
      });
      
      return organization;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error updating organization:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Suspend organization
   * @param {String} organizationId - Organization ID
   * @param {Object} reason - Suspension reason and details
   * @param {Object} adminUser - Admin user performing suspension
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Suspended organization
   */
  async suspendOrganization(organizationId, reason, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.SUSPEND_ORGANIZATION);
      
      const organization = await HostedOrganization.findById(organizationId).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      if (organization.status.suspended) {
        throw new ConflictError('Organization is already suspended');
      }
      
      // Validate suspension reason
      if (!reason || !reason.description) {
        throw new ValidationError('Suspension reason is required');
      }
      
      // Create suspension record
      const suspensionRecord = {
        suspendedAt: new Date(),
        suspendedBy: adminUser._id,
        reason: reason.description,
        category: reason.category || 'administrative',
        expectedDuration: reason.expectedDuration,
        autoLiftDate: reason.autoLiftDate,
        notes: reason.notes
      };
      
      // Update organization status
      organization.status.suspended = true;
      organization.status.suspensionDetails = suspensionRecord;
      organization.statusHistory.push({
        status: 'suspended',
        changedAt: new Date(),
        changedBy: adminUser._id,
        reason: reason.description
      });
      
      await organization.save({ session });
      
      // Suspend tenant
      const tenant = await OrganizationTenant.findById(organization.tenantRef).session(session);
      if (tenant) {
        tenant.status = TENANT_CONSTANTS.TENANT_STATUS.SUSPENDED;
        tenant.suspendedAt = new Date();
        await tenant.save({ session });
      }
      
      // Revoke active sessions
      if (!options.maintainSessions) {
        await this._revokeOrganizationSessions(organizationId, session);
      }
      
      // Notify affected users
      if (!options.skipNotifications) {
        await this._sendSuspensionNotifications(organization, suspensionRecord, adminUser);
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearOrganizationCaches(organizationId);
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.SUSPENDED, adminUser, {
        organizationId,
        organizationName: organization.name,
        reason: reason.description,
        category: reason.category
      }, 'high');
      
      return organization;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error suspending organization:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Reactivate suspended organization
   * @param {String} organizationId - Organization ID
   * @param {Object} adminUser - Admin user performing reactivation
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Reactivated organization
   */
  async reactivateOrganization(organizationId, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.ACTIVATE_ORGANIZATION);
      
      const organization = await HostedOrganization.findById(organizationId).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      if (!organization.status.suspended) {
        throw new ConflictError('Organization is not suspended');
      }
      
      // Update organization status
      organization.status.suspended = false;
      organization.status.reactivatedAt = new Date();
      organization.status.reactivatedBy = adminUser._id;
      
      // Archive suspension details
      if (organization.status.suspensionDetails) {
        organization.suspensionHistory = organization.suspensionHistory || [];
        organization.suspensionHistory.push({
          ...organization.status.suspensionDetails,
          liftedAt: new Date(),
          liftedBy: adminUser._id
        });
        organization.status.suspensionDetails = undefined;
      }
      
      organization.statusHistory.push({
        status: 'active',
        changedAt: new Date(),
        changedBy: adminUser._id,
        reason: 'Reactivated by administrator'
      });
      
      await organization.save({ session });
      
      // Reactivate tenant
      const tenant = await OrganizationTenant.findById(organization.tenantRef).session(session);
      if (tenant) {
        tenant.status = TENANT_CONSTANTS.TENANT_STATUS.ACTIVE;
        tenant.activatedAt = new Date();
        await tenant.save({ session });
      }
      
      // Notify users
      if (!options.skipNotifications) {
        await this._sendReactivationNotifications(organization, adminUser);
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearOrganizationCaches(organizationId);
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.REACTIVATED, adminUser, {
        organizationId,
        organizationName: organization.name
      });
      
      return organization;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error reactivating organization:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Delete organization (soft or hard delete)
   * @param {String} organizationId - Organization ID
   * @param {Object} adminUser - Admin user performing deletion
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Deletion result
   */
  async deleteOrganization(organizationId, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      const requiredPermission = options.hardDelete 
        ? AdminPermissions.SUPER_ADMIN.PERMANENT_DELETE 
        : AdminPermissions.ORGANIZATION_MANAGEMENT.DELETE_ORGANIZATION;
      
      await this.checkPermission(adminUser, requiredPermission);
      
      const organization = await HostedOrganization.findById(organizationId).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Create deletion record
      const deletionRecord = {
        deletedAt: new Date(),
        deletedBy: adminUser._id,
        reason: options.reason || 'Administrative action',
        type: options.hardDelete ? 'hard' : 'soft',
        backupCreated: false
      };
      
      // Create backup if requested
      if (options.createBackup) {
        const backupId = await this._createOrganizationBackup(organization, adminUser);
        deletionRecord.backupId = backupId;
        deletionRecord.backupCreated = true;
      }
      
      if (options.hardDelete) {
        // Hard delete - permanent removal
        await this._performHardDelete(organization, deletionRecord, session);
      } else {
        // Soft delete - mark as deleted
        await this._performSoftDelete(organization, deletionRecord, session);
      }
      
      await session.commitTransaction();
      
      // Clear all related caches
      await this._clearOrganizationCaches(organizationId);
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.DELETED, adminUser, {
        organizationId,
        organizationName: organization.name,
        deletionType: deletionRecord.type,
        backupCreated: deletionRecord.backupCreated
      }, 'critical');
      
      return {
        success: true,
        organizationId,
        deletionType: deletionRecord.type,
        backupId: deletionRecord.backupId,
        message: `Organization ${deletionRecord.type} deleted successfully`
      };
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error deleting organization:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Transfer organization ownership
   * @param {String} organizationId - Organization ID
   * @param {String} newOwnerId - New owner user ID
   * @param {Object} adminUser - Admin user performing transfer
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Updated organization
   */
  async transferOwnership(organizationId, newOwnerId, adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.TRANSFER_OWNERSHIP);
      
      const [organization, newOwner] = await Promise.all([
        HostedOrganization.findById(organizationId).session(session),
        User.findById(newOwnerId).session(session)
      ]);
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      if (!newOwner) {
        throw new NotFoundError('New owner not found');
      }
      
      if (!newOwner.status.active) {
        throw new ValidationError('New owner account must be active');
      }
      
      const oldOwnerId = organization.team.owner;
      
      // Validate new owner can accept ownership
      await this._validateOwnershipTransfer(organization, newOwner);
      
      // Update organization ownership
      organization.team.owner = newOwnerId;
      organization.ownershipHistory = organization.ownershipHistory || [];
      organization.ownershipHistory.push({
        previousOwner: oldOwnerId,
        newOwner: newOwnerId,
        transferredAt: new Date(),
        transferredBy: adminUser._id,
        reason: options.reason || 'Administrative transfer'
      });
      
      // Make new owner an admin if not already
      if (!organization.team.admins.some(admin => admin.user.toString() === newOwnerId)) {
        organization.team.admins.push({
          user: newOwnerId,
          addedAt: new Date(),
          addedBy: adminUser._id
        });
      }
      
      await organization.save({ session });
      
      // Update tenant ownership
      const tenant = await OrganizationTenant.findById(organization.tenantRef).session(session);
      if (tenant) {
        tenant.owner = newOwnerId;
        await tenant.save({ session });
      }
      
      // Notify affected parties
      if (!options.skipNotifications) {
        await this._sendOwnershipTransferNotifications(
          organization,
          oldOwnerId,
          newOwnerId,
          adminUser
        );
      }
      
      await session.commitTransaction();
      
      // Clear caches
      await this._clearOrganizationCaches(organizationId);
      
      // Log action
      await this.logAction(AdminEvents.ORGANIZATION.OWNERSHIP_TRANSFERRED, adminUser, {
        organizationId,
        organizationName: organization.name,
        previousOwnerId: oldOwnerId,
        newOwnerId,
        reason: options.reason
      }, 'high');
      
      return organization;
    } catch (error) {
      await session.abortTransaction();
      logger.error('Error transferring ownership:', error);
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Bulk suspend organizations
   * @param {Array} organizationIds - Organization IDs
   * @param {Object} reason - Suspension reason
   * @param {Object} adminUser - Admin user
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} Bulk operation result
   */
  async bulkSuspendOrganizations(organizationIds, reason, adminUser, options = {}) {
    try {
      // Check permissions and limits
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.BULK_OPERATIONS);
      await this.checkBulkLimit(organizationIds.length, this.bulkLimits.suspend);
      
      const results = {
        successful: [],
        failed: [],
        total: organizationIds.length
      };
      
      // Process in batches
      const batchSize = 10;
      for (let i = 0; i < organizationIds.length; i += batchSize) {
        const batch = organizationIds.slice(i, i + batchSize);
        
        await Promise.all(
          batch.map(async (orgId) => {
            try {
              await this.suspendOrganization(orgId, reason, adminUser, {
                ...options,
                skipNotifications: true // Handle notifications separately
              });
              results.successful.push(orgId);
            } catch (error) {
              results.failed.push({
                organizationId: orgId,
                error: error.message
              });
            }
          })
        );
      }
      
      // Send bulk notification
      if (!options.skipNotifications && results.successful.length > 0) {
        await this._sendBulkOperationNotifications(
          'suspension',
          results,
          reason,
          adminUser
        );
      }
      
      // Log bulk action
      await this.logAction(AdminEvents.ORGANIZATION.BULK_SUSPENDED, adminUser, {
        total: results.total,
        successful: results.successful.length,
        failed: results.failed.length,
        reason: reason.description
      }, 'high');
      
      return results;
    } catch (error) {
      logger.error('Error in bulk suspend:', error);
      throw error;
    }
  }

  // Private helper methods

  async _buildOrganizationFilter(query) {
    const filter = {};
    
    // Text search
    if (query.search) {
      filter.$or = this.searchableFields.map(field => ({
        [field]: { $regex: query.search, $options: 'i' }
      }));
    }
    
    // Status filters
    if (query.status) {
      if (query.status === 'active') {
        filter['status.active'] = true;
        filter['status.suspended'] = false;
      } else if (query.status === 'suspended') {
        filter['status.suspended'] = true;
      } else if (query.status === 'inactive') {
        filter['status.active'] = false;
      }
    }
    
    // Subscription filters
    if (query.subscriptionStatus) {
      filter['subscription.status'] = query.subscriptionStatus;
    }
    
    if (query.plan) {
      filter['subscription.plan.id'] = query.plan;
    }
    
    // Date range filters
    if (query.createdFrom || query.createdTo) {
      filter.createdAt = {};
      if (query.createdFrom) {
        filter.createdAt.$gte = new Date(query.createdFrom);
      }
      if (query.createdTo) {
        filter.createdAt.$lte = new Date(query.createdTo);
      }
    }
    
    // Size filters
    if (query.minMembers || query.maxMembers) {
      filter.memberCount = {};
      if (query.minMembers) {
        filter.memberCount.$gte = parseInt(query.minMembers);
      }
      if (query.maxMembers) {
        filter.memberCount.$lte = parseInt(query.maxMembers);
      }
    }
    
    // Verification status
    if (query.verified !== undefined) {
      filter['status.verified'] = query.verified === 'true';
    }
    
    // Industry filter
    if (query.industry) {
      filter['businessInfo.industry'] = query.industry;
    }
    
    // Country filter
    if (query.country) {
      filter['headquarters.address.country'] = query.country;
    }
    
    return filter;
  }

  async _applyVisibilityRules(filter, adminUser) {
    const visibilityFilter = { ...filter };
    
    // Super admins see everything
    if (adminUser.role.type === 'super_admin') {
      return visibilityFilter;
    }
    
    // Platform admins see non-enterprise organizations
    if (adminUser.role.type === 'platform_admin') {
      visibilityFilter['subscription.plan.id'] = { $ne: 'enterprise' };
    }
    
    // Support admins see only organizations with support tickets
    if (adminUser.role.type === 'support_admin') {
      visibilityFilter['flags.hasActiveSupport'] = true;
    }
    
    return visibilityFilter;
  }

  _buildAggregationPipeline(filter, query, options) {
    const page = parseInt(query.page) || 1;
    const limit = parseInt(query.limit) || 20;
    const skip = (page - 1) * limit;
    
    const pipeline = [
      { $match: filter },
      
      // Lookup tenant information
      {
        $lookup: {
          from: 'organizationtenants',
          localField: 'tenantRef',
          foreignField: '_id',
          as: 'tenant'
        }
      },
      
      // Calculate member count
      {
        $addFields: {
          memberCount: {
            $add: [
              1, // Owner
              { $size: { $ifNull: ['$team.admins', []] } },
              { $size: { $ifNull: ['$team.members', []] } }
            ]
          }
        }
      },
      
      // Sort
      { $sort: this._buildSortObject(options.sort || '-createdAt') },
      
      // Facet for pagination
      {
        $facet: {
          total: [{ $count: 'count' }],
          data: [
            { $skip: skip },
            { $limit: limit },
            
            // Populate owner
            {
              $lookup: {
                from: 'users',
                localField: 'team.owner',
                foreignField: '_id',
                as: 'ownerInfo'
              }
            },
            
            // Project final shape
            {
              $project: {
                name: 1,
                displayName: 1,
                slug: 1,
                tenantCode: 1,
                status: 1,
                subscription: 1,
                memberCount: 1,
                'team.owner': 1,
                'ownerInfo.name': 1,
                'ownerInfo.email': 1,
                createdAt: 1,
                'metrics.usage.lastActivity': 1,
                'tenant.resourceLimits': { $arrayElemAt: ['$tenant.resourceLimits', 0] }
              }
            }
          ]
        }
      }
    ];
    
    return pipeline;
  }

  _buildSortObject(sortString) {
    const sortObject = {};
    const fields = sortString.split(',');
    
    fields.forEach(field => {
      const isDescending = field.startsWith('-');
      const fieldName = isDescending ? field.substring(1) : field;
      sortObject[fieldName] = isDescending ? -1 : 1;
    });
    
    return sortObject;
  }

  async _checkOrganizationVisibility(organization, adminUser) {
    // Super admins can see everything
    if (adminUser.role.type === 'super_admin') {
      return true;
    }
    
    // Check specific visibility rules based on admin role
    if (adminUser.role.type === 'platform_admin' && 
        organization.subscription.plan.id === 'enterprise') {
      throw new ForbiddenError('Insufficient permissions to view enterprise organizations');
    }
    
    return true;
  }

  async _getOrganizationAnalytics(organizationId) {
    // Aggregate analytics data
    const [userStats, activityStats, resourceStats] = await Promise.all([
      this._getUserStatistics(organizationId),
      this._getActivityStatistics(organizationId),
      this._getResourceStatistics(organizationId)
    ]);
    
    return {
      users: userStats,
      activity: activityStats,
      resources: resourceStats,
      generatedAt: new Date()
    };
  }

  async _getUserStatistics(organizationId) {
    const organization = await HostedOrganization.findById(organizationId).lean();
    
    const activeUsers = await User.countDocuments({
      _id: {
        $in: [
          organization.team.owner,
          ...organization.team.admins.map(a => a.user),
          ...organization.team.members.map(m => m.user)
        ]
      },
      'status.active': true
    });
    
    return {
      total: 1 + organization.team.admins.length + organization.team.members.length,
      active: activeUsers,
      admins: organization.team.admins.length,
      members: organization.team.members.length,
      pendingInvitations: organization.team.invitations?.filter(i => i.status === 'pending').length || 0
    };
  }

  async _getActivityStatistics(organizationId) {
    const thirtyDaysAgo = moment().subtract(30, 'days').toDate();
    
    const activities = await AuditLog.aggregate([
      {
        $match: {
          organizationId: new mongoose.Types.ObjectId(organizationId),
          timestamp: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: '%Y-%m-%d', date: '$timestamp' }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    return {
      last30Days: activities,
      totalActions: activities.reduce((sum, day) => sum + day.count, 0),
      averagePerDay: Math.round(activities.reduce((sum, day) => sum + day.count, 0) / 30)
    };
  }

  async _getResourceStatistics(organizationId) {
    const organization = await HostedOrganization.findById(organizationId)
      .populate('tenantRef')
      .lean();
    
    const tenant = organization.tenantRef;
    
    return {
      storage: {
        used: tenant?.resourceLimits?.storage?.currentBytes || 0,
        limit: tenant?.resourceLimits?.storage?.maxGB || 0,
        percentage: tenant?.storageUsagePercent || 0
      },
      apiCalls: {
        used: tenant?.resourceLimits?.apiCalls?.current || 0,
        limit: tenant?.resourceLimits?.apiCalls?.max || 0,
        resetDate: tenant?.resourceLimits?.apiCalls?.resetDate
      },
      projects: {
        used: tenant?.resourceLimits?.projects?.current || 0,
        limit: tenant?.resourceLimits?.projects?.max || 0
      }
    };
  }

  async _createOrganizationBackup(organization, adminUser) {
    try {
      const backupData = {
        organization: organization.toObject(),
        tenant: await OrganizationTenant.findById(organization.tenantRef).lean(),
        users: await this._getOrganizationUsers(organization._id),
        metadata: {
          createdAt: new Date(),
          createdBy: adminUser._id,
          version: '1.0',
          includesData: true
        }
      };
      
      const backupId = await AdminBackupService.createBackup(
        'organization',
        organization._id,
        backupData,
        adminUser
      );
      
      return backupId;
    } catch (error) {
      logger.error('Error creating organization backup:', error);
      throw new AppError('Failed to create organization backup', 500);
    }
  }

  async _performSoftDelete(organization, deletionRecord, session) {
    // Mark organization as deleted
    organization.status.deleted = true;
    organization.status.deletedAt = deletionRecord.deletedAt;
    organization.status.deletedBy = deletionRecord.deletedBy;
    organization.deletionDetails = deletionRecord;
    
    await organization.save({ session });
    
    // Mark tenant as terminated
    const tenant = await OrganizationTenant.findById(organization.tenantRef).session(session);
    if (tenant) {
      tenant.status = TENANT_CONSTANTS.TENANT_STATUS.TERMINATED;
      tenant.terminatedAt = deletionRecord.deletedAt;
      await tenant.save({ session });
    }
    
    // Revoke all sessions
    await this._revokeOrganizationSessions(organization._id, session);
  }

  async _performHardDelete(organization, deletionRecord, session) {
    // Delete all related data
    await Promise.all([
      // Delete organization users' associations
      User.updateMany(
        {
          _id: {
            $in: [
              organization.team.owner,
              ...organization.team.admins.map(a => a.user),
              ...organization.team.members.map(m => m.user)
            ]
          }
        },
        {
          $pull: { organizations: organization._id }
        },
        { session }
      ),
      
      // Delete audit logs after backup
      AuditLog.deleteMany({ organizationId: organization._id }, { session }),
      
      // Delete tenant
      OrganizationTenant.findByIdAndDelete(organization.tenantRef, { session }),
      
      // Finally delete the organization
      HostedOrganization.findByIdAndDelete(organization._id, { session })
    ]);
  }

  async _clearOrganizationCaches(organizationId = null) {
    const patterns = [
      `${this.cachePrefix}:*`,
      'organization:*',
      'tenant:*'
    ];
    
    if (organizationId) {
      patterns.push(`organization:${organizationId}:*`);
    }
    
    await Promise.all(patterns.map(pattern => this.cache.deletePattern(pattern)));
  }

  _trackChanges(original, updates) {
    const changes = {};
    const trackFields = [
      'name', 'displayName', 'description', 'status', 'subscription',
      'limits', 'businessInfo', 'headquarters', 'platformConfig'
    ];
    
    trackFields.forEach(field => {
      if (updates[field] !== undefined && 
          JSON.stringify(original[field]) !== JSON.stringify(updates[field])) {
        changes[field] = {
          from: original[field],
          to: updates[field]
        };
      }
    });
    
    return changes;
  }
}

module.exports = new AdminOrganizationService();