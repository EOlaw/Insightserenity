/**
 * @file Hosted Organization Service - Complete Implementation
 * @description Business logic layer for hosted organization management with tenant integration
 * @version 3.1.0
 */

const mongoose = require('mongoose');
const { CacheService } = require('../../../shared/services/cache-service');
const { EmailService } = require('../../../shared/services/email-service');
const User = require('../../../shared/users/models/user-model');
const { AppError } = require('../../../shared/utils/app-error');
const { EventEmitter } = require('../../../shared/utils/events/event-emitter');
const logger = require('../../../shared/utils/logger');
const HostedOrganization = require('../models/organization-model');
const OrganizationTenant = require('../../../organization-tenants/models/organization-tenant-model')
const OrganizationTenantService = require('../../../organization-tenants/services/organization-tenant-service');
const { ORGANIZATION_CONSTANTS } = require('../../../shared/utils/constants/organization-constants');
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');

class HostedOrganizationService {
  /**
   * Create a new hosted organization with tenant infrastructure
   * @param {Object} organizationData - Organization data
   * @param {string} userId - ID of the user creating the organization
   * @returns {Promise<Object>} - Created organization with tenant
   */
  static async createOrganization(organizationData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Creating hosted organization with tenant', {
        organizationName: organizationData.name,
        userId,
        tier: organizationData.platformConfig?.tier || 'starter'
      });

      // Validate user exists
      const user = await User.findById(userId).session(session);
      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Check user's organization limit
      const existingOrgs = await HostedOrganization.countDocuments({
        'team.owner': userId,
        'status.active': true
      });

      if (existingOrgs >= (user.limits?.organizations || 3)) {
        throw new AppError('Organization limit reached for this user', 403);
      }

      // Prepare tenant configuration
      const tier = organizationData.platformConfig?.tier || 'starter';
      const tenantData = {
        name: organizationData.name,
        contactEmail: organizationData.headquarters?.email || user.email,
        contactPhone: organizationData.headquarters?.phone,
        website: organizationData.website,
        owner: userId,
        subscription: {
          plan: this._mapTierToPlan(tier),
          status: organizationData.subscription?.status || TENANT_CONSTANTS.SUBSCRIPTION_STATUS.TRIAL
        },
        database: {
          strategy: this._getDatabaseStrategy(tier)
        },
        businessInfo: organizationData.businessInfo || {},
        location: organizationData.headquarters?.address ? {
          country: organizationData.headquarters.address.country,
          state: organizationData.headquarters.address.state,
          city: organizationData.headquarters.address.city,
          timezone: organizationData.headquarters.timezone
        } : {}
      };

      // Create tenant infrastructure within the same transaction session
      const tenant = await OrganizationTenantService.createTenant(tenantData, userId, session);

      logger.info('Tenant created successfully within transaction', { 
        tenantId: tenant._id, 
        tenantCode: tenant.tenantCode,
        generatedTenantId: tenant.tenantId
      });

      // Prepare organization data structure using the tenant document directly
      const orgData = {
        ...organizationData,
        tenantRef: tenant._id,
        tenantId: tenant.tenantId,
        tenantCode: tenant.tenantCode,
        'team.owner': userId,
        createdBy: userId,
        'team.admins': [{
          user: userId,
          addedAt: new Date(),
          addedBy: userId
        }],
        'metrics.usage.lastActivity': new Date(),
        'domains.subdomain': organizationData.domains?.subdomain || tenant.tenantCode.toLowerCase()
      };

      // Synchronize subscription configuration from tenant
      orgData.subscription = {
        ...orgData.subscription,
        status: tenant.subscription.status,
        plan: {
          id: tenant.subscription.plan,
          name: tenant.subscription.plan,
          interval: organizationData.subscription?.plan?.interval || 'monthly'
        },
        trialEnd: tenant.subscription.trialEndsAt
      };

      // Apply default platform configuration based on tier
      if (!orgData.platformConfig) {
        orgData.platformConfig = this._getDefaultPlatformConfig(tier);
      }

      // Create organization document
      const organization = await HostedOrganization.create([orgData], { session });

      logger.info('Organization created successfully', { 
        organizationId: organization[0]._id,
        platformId: organization[0].platformId 
      });

      // CORRECTED: Update user organization associations with proper schema structure
      user.organization = user.organization || { organizations: [], current: null };
      user.organization.organizations = user.organization.organizations || [];

      user.organization.organizations.push({
        organizationId: organization[0]._id,  // Correct field name matching schema
        role: 'owner',
        department: null,
        joinedAt: new Date(),
        active: true
      });

      // Set as current organization if this is the user's first organization
      if (user.organization.organizations.filter(org => org.active).length === 1) {
        user.organization.current = organization[0]._id;
      }

      await user.save({ session });

      logger.info('User organization membership updated', {
        userId: user._id,
        organizationId: organization[0]._id,
        role: 'owner',
        isCurrentOrganization: user.organization.current?.toString() === organization[0]._id.toString()
      });

      // CORRECTED: Update tenant with organization reference and member count
      tenant.organizationRef = organization[0]._id;
      tenant.memberCount = 1; // Owner counts as first member
      tenant.flags.isActive = true; // Activate tenant since it now has members

      await tenant.save({ session });

      logger.info('Tenant updated with organization reference and member count', {
        tenantId: tenant._id,
        organizationId: organization[0]._id,
        memberCount: tenant.memberCount,
        isActive: tenant.flags.isActive
      });

      // Initialize default organization data
      await this._setupDefaultOrganizationData(organization[0], session);

      // Commit all changes atomically
      await session.commitTransaction();

      logger.info('Database transaction committed successfully', { 
        organizationId: organization[0]._id,
        tenantId: tenant._id,
        memberCount: tenant.memberCount
      });

      // Populate tenant reference for response
      await organization[0].populate('tenantRef');

      // Execute non-blocking post-creation operations
      setImmediate(async () => {
        try {
          // Emit organization creation event
          EventEmitter.emit('organization:created', {
            organizationId: organization[0]._id,
            tenantId: tenant._id,
            userId,
            tier: organization[0].platformConfig.tier
          });

          // Cache organization data
          await CacheService.set(
            `org:${organization[0]._id}`,
            organization[0].toObject(),
            3600
          );

          // Send welcome emails for the complete organization setup
          await this._sendOrganizationWelcomeEmail(organization[0], user);

          logger.debug('Post-creation tasks completed successfully');

        } catch (postCreationError) {
          logger.warn('Post-creation tasks failed (non-critical)', {
            error: postCreationError.message,
            organizationId: organization[0]._id
          });
        }
      });

      logger.info('Hosted organization created successfully', {
        organizationId: organization[0]._id,
        platformId: organization[0].platformId,
        tenantId: tenant.tenantId,
        subdomain: organization[0].domains?.subdomain,
        tier: organization[0].platformConfig?.tier,
        memberCount: tenant.memberCount
      });

      return organization[0];

    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Failed to create hosted organization', {
        error: {
          message: error.message,
          name: error.name,
          stack: error.stack,
          code: error.statusCode || error.code
        },
        userId,
        organizationName: organizationData.name,
        tier: organizationData.platformConfig?.tier
      });

      // Provide specific error handling for common failure scenarios
      if (error instanceof AppError) {
        throw error;
      } else if (error.name === 'ValidationError') {
        throw new AppError(`Organization validation failed: ${error.message}`, 400);
      } else if (error.name === 'MongoServerError' && error.code === 11000) {
        throw new AppError('Organization with this identifier already exists', 409);
      } else if (error.name === 'DocumentNotFoundError') {
        throw new AppError('Required document not found during organization creation', 500);
      } else if (error.message.includes('timeout')) {
        throw new AppError('Organization creation timed out. Please try again.', 408);
      } else {
        throw new AppError(`Failed to create organization: ${error.message}`, 500);
      }

    } finally {
      session.endSession();
    }
  }

  /**
   * Get organization by ID with tenant context
   * @param {string} organizationId - Organization ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - Organization with tenant
   */
  static async getOrganizationById(organizationId, options = {}) {
    try {
      // Check cache first
      const cacheKey = `org:${organizationId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached && !options.skipCache) {
        logger.debug('Organization retrieved from cache', { organizationId });
        return cached;
      }

      let query = HostedOrganization.findById(organizationId);

      // Always populate tenant reference
      query = query.populate('tenantRef');

      if (options.populate) {
        const populateFields = Array.isArray(options.populate) 
          ? options.populate 
          : options.populate.split(',').map(f => f.trim());
        
        populateFields.forEach(field => {
          if (field !== 'tenantRef') { // Already populated
            query = query.populate(field);
          }
        });
      }

      if (options.select) {
        query = query.select(options.select);
      }

      const organization = await query.lean({ virtuals: true });

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check if organization is active (unless explicitly including inactive)
      if (!options.includeInactive && !organization.status.active) {
        throw new AppError('Organization is not active', 403);
      }

      // Check tenant status
      if (organization.tenantRef && organization.tenantRef.status === TENANT_CONSTANTS.TENANT_STATUS.SUSPENDED) {
        throw new AppError('Organization tenant is suspended', 403);
      }

      // Cache the result
      if (!options.skipCache) {
        await CacheService.set(cacheKey, organization, 3600);
      }

      return organization;

    } catch (error) {
      logger.error('Failed to get organization by ID', {
        error: error.message,
        organizationId
      });
      throw error;
    }
  }

  /**
   * Get organization by tenant ID
   * @param {string} tenantId - Tenant ID
   * @returns {Promise<Object>} - Organization with instance methods
   */
  static async getOrganizationByTenantId(tenantId) {
    try {
      logger.debug('Fetching organization by tenant ID', { tenantId });
      
      // Remove .lean() to preserve Mongoose instance methods
      const organization = await HostedOrganization.findOne({ tenantId })
        .populate('tenantRef')
        .exec();

      if (!organization) {
        throw new AppError('Organization not found for tenant', 404);
      }

      // Verify that instance methods are available
      if (typeof organization.isMember !== 'function') {
        logger.error('Organization document missing instance methods', {
          tenantId,
          organizationId: organization._id,
          hasIsMember: typeof organization.isMember === 'function',
          isMongooseDocument: organization instanceof mongoose.Document
        });
        throw new AppError('Organization data integrity issue', 500);
      }

      logger.debug('Organization retrieved successfully', {
        tenantId,
        organizationId: organization._id,
        hasInstanceMethods: typeof organization.isMember === 'function'
      });

      return organization;
    } catch (error) {
      logger.error('Failed to get organization by tenant ID', {
        error: error.message,
        stack: error.stack,
        tenantId
      });
      throw error;
    }
  }

  /**
   * Check if user is a member of the organization using static helper methods
   * @param {Object} organization - Organization document or plain object
   * @param {Object} user - User document with organizations array
   * @returns {boolean} - Whether user is a member
   */
  static checkOrganizationMembership(organization, user) {
    try {
      return HostedOrganization.checkMembershipExtended(organization, user);
    } catch (error) {
      logger.error('Failed to check organization membership', {
        error: error.message,
        organizationId: organization?._id,
        userId: user?._id
      });
      return false;
    }
  }

  /**
   * Get user role in organization using static helper methods
   * @param {Object} organization - Organization document or plain object
   * @param {string} userId - User ID
   * @returns {string|null} - User role or null if not a member
   */
  static getOrganizationUserRole(organization, userId) {
    try {
      return HostedOrganization.getUserRole(organization, userId);
    } catch (error) {
      logger.error('Failed to get organization user role', {
        error: error.message,
        organizationId: organization?._id,
        userId
      });
      return null;
    }
  }

  /**
   * Check basic organization membership (without extended user array checking)
   * @param {Object} organization - Organization document or plain object
   * @param {string} userId - User ID to check
   * @returns {boolean} - Whether user is a member
   */
  static checkBasicMembership(organization, userId) {
    try {
      return HostedOrganization.checkMembership(organization, userId);
    } catch (error) {
      logger.error('Failed to check basic organization membership', {
        error: error.message,
        organizationId: organization?._id,
        userId
      });
      return false;
    }
  }

  /**
   * Get user organizations
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} - Organizations
   */
  static async getUserOrganizations(userId, options = {}) {
    try {
      const query = {
        $or: [
          { 'team.owner': userId },
          { 'team.admins.user': userId },
          { 'team.members.user': userId }
        ]
      };

      if (!options.includeInactive) {
        query['status.active'] = true;
      }

      let organizationQuery = HostedOrganization.find(query)
        .populate('tenantRef')
        .sort(options.sort || '-createdAt');

      if (options.limit) {
        organizationQuery = organizationQuery.limit(parseInt(options.limit));
      }

      if (options.skip) {
        organizationQuery = organizationQuery.skip(parseInt(options.skip));
      }

      const organizations = await organizationQuery.lean({ virtuals: true });

      return organizations;
    } catch (error) {
      logger.error('Failed to get user organizations', {
        error: error.message,
        userId
      });
      throw error;
    }
  }

  /**
   * Get user organizations with pagination support
   * @param {string} userId - User ID
   * @param {Object} options - Query options with pagination
   * @returns {Promise<Object>} - Organizations with total count
   */
  static async getUserOrganizationsWithPagination(userId, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'createdAt',
        sortOrder = 'desc',
        includeInactive = false
      } = options;

      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };

      // Build filter criteria
      const filter = {
        $or: [
          { 'team.owner': userId },
          { 'team.admins.user': userId },
          { 'team.members.user': userId }
        ]
      };

      if (!includeInactive) {
        filter['status.active'] = true;
      }

      // Execute parallel queries for data and count
      const [organizations, total] = await Promise.all([
        HostedOrganization.find(filter)
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .populate('tenantRef')
          .lean({ virtuals: true }),
        HostedOrganization.countDocuments(filter)
      ]);

      return {
        organizations,
        total,
        page,
        limit
      };

    } catch (error) {
      logger.error('Get user organizations with pagination error', { error, userId });
      throw error;
    }
  }

  /**
   * Update organization with tenant synchronization
   * @param {string} organizationId - Organization ID
   * @param {Object} updateData - Update data
   * @param {string} userId - ID of user performing update
   * @returns {Promise<Object>} - Updated organization
   */
  static async updateOrganization(organizationId, updateData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Updating organization', {
        organizationId,
        userId,
        fields: Object.keys(updateData)
      });

      const organization = await HostedOrganization.findById(organizationId)
        .populate('tenantRef')
        .session(session);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check permissions
      if (!organization.isAdmin(userId)) {
        throw new AppError('Insufficient permissions to update organization', 403);
      }

      // Handle special updates that need tenant synchronization
      const tenantUpdates = {};

      // Sync subscription changes
      if (updateData.subscription) {
        if (updateData.subscription.plan?.id) {
          tenantUpdates.subscription = {
            plan: updateData.subscription.plan.id,
            status: updateData.subscription.status
          };
        }
      }

      // Sync tier changes
      if (updateData.platformConfig?.tier) {
        tenantUpdates.subscription = {
          ...tenantUpdates.subscription,
          plan: this._mapTierToPlan(updateData.platformConfig.tier)
        };
      }

      // Sync contact email
      if (updateData.headquarters?.email) {
        tenantUpdates.contactEmail = updateData.headquarters.email;
      }

      // Update tenant if needed
      if (Object.keys(tenantUpdates).length > 0) {
        await OrganizationTenantService.updateTenant(
          organization.tenantRef._id,
          tenantUpdates,
          userId
        );
      }

      // Apply updates to organization
      Object.assign(organization, updateData);
      organization.updatedBy = userId;

      await organization.save({ session });

      // Update resource usage if team size changed
      if (updateData.team) {
        const newMemberCount = organization.memberCount;
        await organization.updateResourceUsage('users', newMemberCount, 'set');
      }

      await session.commitTransaction();

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      // Emit update event
      EventEmitter.emit('organization:updated', {
        organizationId,
        userId,
        changes: Object.keys(updateData)
      });

      logger.info('Organization updated successfully', { organizationId });

      return organization;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to update organization', {
        error: error.message,
        organizationId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Delete organization (soft delete) - FIXED VERSION
   * @param {string} organizationId - Organization ID
   * @param {string} userId - User performing deletion
   * @returns {Promise<Object>} - Deleted organization
   */
  static async deleteOrganization(organizationId, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Soft deleting organization', { organizationId, userId });

      const organization = await HostedOrganization.findById(organizationId)
        .populate('tenantRef')
        .session(session);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // ENHANCED OWNERSHIP VALIDATION WITH DEBUGGING
      const organizationOwnerId = organization.team.owner?.toString();
      const requestingUserId = userId.toString();

      logger.info('Organization deletion ownership validation', {
        organizationId,
        organizationOwnerId,
        requestingUserId,
        ownershipMatch: organizationOwnerId === requestingUserId,
        organizationName: organization.name,
        debugInfo: {
          hasOwner: !!organization.team.owner,
          ownerType: typeof organization.team.owner,
          teamStructure: {
            hasAdmins: !!organization.team.admins,
            adminCount: organization.team.admins?.length || 0,
            hasMembers: !!organization.team.members,
            memberCount: organization.team.members?.length || 0
          }
        }
      });

      // Check if requesting user is the owner
      const isOwner = organizationOwnerId === requestingUserId;

      // Also check if user is an admin (as fallback permission)
      const isAdmin = organization.team.admins?.some(admin => 
        admin.user?.toString() === requestingUserId
      );

      // Check if user has system admin privileges
      const User = require('../../../shared/users/models/user-model');
      const requestingUser = await User.findById(userId);
      const isSystemAdmin = ['admin', 'super_admin'].includes(requestingUser?.role?.primary);

      // Enhanced validation with multiple permission paths
      if (!isOwner && !isAdmin && !isSystemAdmin) {
        logger.warn('Organization deletion denied - insufficient permissions', {
          organizationId,
          userId,
          organizationOwnerId,
          isOwner,
          isAdmin,
          isSystemAdmin,
          userRole: requestingUser?.role?.primary,
          adminUsers: organization.team.admins?.map(admin => admin.user?.toString())
        });

        // Provide more specific error messages
        if (!organizationOwnerId) {
          throw new AppError('Organization has no designated owner. Contact support.', 500);
        } else {
          throw new AppError('Only the organization owner or admin can delete the organization', 403);
        }
      }

      // Log successful permission validation
      logger.info('Organization deletion permission granted', {
        organizationId,
        userId,
        permissionType: isOwner ? 'owner' : isAdmin ? 'admin' : 'system_admin'
      });

      // Mark organization as deleted
      organization.status.active = false;
      organization.status.archived = true;
      organization.status.deletionRequested = true;
      organization.status.deletionScheduledFor = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

      await organization.save({ session });

      // Suspend tenant
      if (organization.tenantRef) {
        await OrganizationTenantService.suspendTenant(organization.tenantRef._id, userId);
      }

      await session.commitTransaction();

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      // Emit event
      EventEmitter.emit('organization:deleted', {
        organizationId,
        userId,
        deletedBy: isOwner ? 'owner' : isAdmin ? 'admin' : 'system_admin'
      });

      logger.info('Organization deletion completed successfully', {
        organizationId,
        userId,
        scheduledDeletionDate: organization.status.deletionScheduledFor
      });

      return organization;

    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Failed to delete organization', {
        error: error.message,
        stack: error.stack,
        organizationId,
        userId,
        errorType: error.constructor.name
      });
      
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Get team members
   * @param {string} organizationId - Organization ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - Team members with pagination
   */
  static async getTeamMembers(organizationId, options = {}) {
    try {
      const organization = await HostedOrganization.findById(organizationId)
        .populate({
          path: 'team.owner',
          select: 'name email avatar profile'
        })
        .populate({
          path: 'team.admins.user',
          select: 'name email avatar profile'
        })
        .populate({
          path: 'team.members.user',
          select: 'name email avatar profile'
        });

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Compile all team members
      const allMembers = [];

      // Add owner
      if (organization.team.owner) {
        allMembers.push({
          user: organization.team.owner,
          role: 'owner',
          joinedAt: organization.createdAt,
          status: 'active'
        });
      }

      // Add admins
      organization.team.admins?.forEach(admin => {
        if (admin.user) {
          allMembers.push({
            user: admin.user,
            role: 'admin',
            joinedAt: admin.addedAt,
            addedBy: admin.addedBy,
            status: 'active'
          });
        }
      });

      // Add members
      organization.team.members?.forEach(member => {
        if (member.user) {
          allMembers.push({
            user: member.user,
            role: member.role,
            department: member.department,
            title: member.title,
            permissions: member.permissions,
            joinedAt: member.joinedAt,
            invitedBy: member.invitedBy,
            lastActiveAt: member.lastActiveAt,
            status: 'active'
          });
        }
      });

      // Add pending invitations
      organization.team.invitations?.forEach(invitation => {
        if (invitation.status === 'pending') {
          allMembers.push({
            email: invitation.email,
            role: invitation.role,
            status: 'pending',
            invitedAt: invitation.sentAt,
            invitedBy: invitation.sentBy,
            expiresAt: invitation.expiresAt
          });
        }
      });

      // Apply filtering and sorting
      let filteredMembers = allMembers;

      if (options.role) {
        filteredMembers = filteredMembers.filter(member => member.role === options.role);
      }

      if (options.status) {
        filteredMembers = filteredMembers.filter(member => member.status === options.status);
      }

      // Sort members
      const sortBy = options.sortBy || 'joinedAt';
      const sortOrder = options.sortOrder === 'asc' ? 1 : -1;
      
      filteredMembers.sort((a, b) => {
        const aValue = a[sortBy] || a.invitedAt;
        const bValue = b[sortBy] || b.invitedAt;
        return (aValue < bValue ? -1 : aValue > bValue ? 1 : 0) * sortOrder;
      });

      // Apply pagination
      const skip = parseInt(options.skip) || 0;
      const limit = parseInt(options.limit) || 50;
      const paginatedMembers = filteredMembers.slice(skip, skip + limit);

      return {
        members: paginatedMembers,
        total: filteredMembers.length,
        skip,
        limit,
        hasMore: skip + limit < filteredMembers.length
      };

    } catch (error) {
      logger.error('Failed to get team members', {
        error: error.message,
        organizationId
      });
      throw error;
    }
  }

  /**
   * Add team member with resource limit check
   * @param {string} organizationId - Organization ID
   * @param {Object} memberData - Member data
   * @param {string} addedBy - ID of user adding member
   * @returns {Promise<Object>} - Updated organization
   */
  static async addTeamMember(organizationId, memberData, addedBy) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Adding team member', {
        organizationId,
        memberEmail: memberData.email,
        role: memberData.role,
        addedBy
      });

      const organization = await HostedOrganization.findById(organizationId)
        .populate('tenantRef')
        .session(session);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check permissions
      if (!organization.isAdmin(addedBy)) {
        throw new AppError('Only admins can add team members', 403);
      }

      // Check resource limits via tenant
      const canAddUser = await organization.checkResourceLimit('users', 1);
      if (!canAddUser) {
        throw new AppError('User limit reached for current plan', 403);
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email: memberData.email });
      
      if (existingUser) {
        // Check if already a member
        if (organization.isMember(existingUser._id)) {
          throw new AppError('User is already a member of this organization', 409);
        }

        // Add as member
        if (memberData.role === 'admin') {
          organization.team.admins.push({
            user: existingUser._id,
            addedAt: new Date(),
            addedBy
          });
        } else {
          organization.team.members.push({
            user: existingUser._id,
            role: memberData.role || 'member',
            department: memberData.department,
            title: memberData.title,
            permissions: memberData.permissions || [],
            joinedAt: new Date(),
            invitedBy: addedBy
          });
        }

        // Update user's organizations
        existingUser.organizations = existingUser.organizations || [];
        existingUser.organizations.push({
          organization: organization._id,
          role: memberData.role || 'member',
          joinedAt: new Date()
        });
        await existingUser.save({ session });

      } else {
        // Create invitation
        const invitationToken = this._generateInvitationToken();
        
        organization.team.invitations.push({
          email: memberData.email,
          role: memberData.role || 'member',
          token: invitationToken,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          sentBy: addedBy
        });

        // Send invitation email
        await this._sendInvitationEmail(organization, memberData.email, invitationToken);
      }

      await organization.save({ session });

      // Update resource usage
      await organization.updateResourceUsage('users', organization.memberCount, 'set');

      await session.commitTransaction();

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      // Emit event
      EventEmitter.emit('organization:member:added', {
        organizationId,
        memberEmail: memberData.email,
        role: memberData.role,
        addedBy
      });

      logger.info('Team member added successfully', {
        organizationId,
        memberEmail: memberData.email
      });

      return organization;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to add team member', {
        error: error.message,
        organizationId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Update team member
   * @param {string} organizationId - Organization ID
   * @param {string} memberId - Member ID
   * @param {Object} updateData - Update data
   * @param {string} userId - User performing update
   * @returns {Promise<Object>} - Updated organization
   */
  static async updateTeamMember(organizationId, memberId, updateData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Updating team member', {
        organizationId,
        memberId,
        userId
      });

      const organization = await HostedOrganization.findById(organizationId).session(session);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check permissions
      if (!organization.isAdmin(userId)) {
        throw new AppError('Only admins can update team members', 403);
      }

      // Cannot modify owner
      if (organization.team.owner.toString() === memberId) {
        throw new AppError('Cannot modify organization owner', 400);
      }

      // Find and update member
      let memberFound = false;

      // Check in admins
      const adminIndex = organization.team.admins.findIndex(
        admin => admin.user.toString() === memberId
      );

      if (adminIndex !== -1) {
        // Update admin or convert to member
        if (updateData.role && updateData.role !== 'admin') {
          // Convert admin to member
          const admin = organization.team.admins[adminIndex];
          organization.team.admins.splice(adminIndex, 1);
          
          organization.team.members.push({
            user: admin.user,
            role: updateData.role,
            department: updateData.department,
            title: updateData.title,
            permissions: updateData.permissions || [],
            joinedAt: admin.addedAt,
            invitedBy: admin.addedBy
          });
        }
        memberFound = true;
      } else {
        // Check in members
        const memberIndex = organization.team.members.findIndex(
          member => member.user.toString() === memberId
        );

        if (memberIndex !== -1) {
          if (updateData.role === 'admin') {
            // Convert member to admin
            const member = organization.team.members[memberIndex];
            organization.team.members.splice(memberIndex, 1);
            
            organization.team.admins.push({
              user: member.user,
              addedAt: new Date(),
              addedBy: userId
            });
          } else {
            // Update member details
            const member = organization.team.members[memberIndex];
            if (updateData.role) member.role = updateData.role;
            if (updateData.department) member.department = updateData.department;
            if (updateData.title) member.title = updateData.title;
            if (updateData.permissions) member.permissions = updateData.permissions;
          }
          memberFound = true;
        }
      }

      if (!memberFound) {
        throw new AppError('Team member not found', 404);
      }

      await organization.save({ session });
      await session.commitTransaction();

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      // Emit event
      EventEmitter.emit('organization:member:updated', {
        organizationId,
        memberId,
        userId
      });

      return organization;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to update team member', {
        error: error.message,
        organizationId,
        memberId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Remove team member
   * @param {string} organizationId - Organization ID
   * @param {string} memberId - Member ID
   * @param {string} userId - User performing removal
   * @returns {Promise<Object>} - Updated organization
   */
  static async removeTeamMember(organizationId, memberId, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Removing team member', {
        organizationId,
        memberId,
        userId
      });

      const organization = await HostedOrganization.findById(organizationId).session(session);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Check permissions
      if (!organization.isAdmin(userId)) {
        throw new AppError('Only admins can remove team members', 403);
      }

      // Cannot remove owner
      if (organization.team.owner.toString() === memberId) {
        throw new AppError('Cannot remove organization owner', 400);
      }

      // Cannot remove yourself unless you're transferring ownership
      if (userId === memberId && organization.team.owner.toString() === userId) {
        throw new AppError('Owner cannot remove themselves without transferring ownership', 400);
      }

      // Remove from admins
      const adminIndex = organization.team.admins.findIndex(
        admin => admin.user.toString() === memberId
      );

      if (adminIndex !== -1) {
        organization.team.admins.splice(adminIndex, 1);
      } else {
        // Remove from members
        const memberIndex = organization.team.members.findIndex(
          member => member.user.toString() === memberId
        );

        if (memberIndex !== -1) {
          organization.team.members.splice(memberIndex, 1);
        } else {
          throw new AppError('Team member not found', 404);
        }
      }

      // Update user's organizations
      await User.findByIdAndUpdate(memberId, {
        $pull: {
          organizations: { organization: organization._id }
        }
      }).session(session);

      await organization.save({ session });

      // Update resource usage
      await organization.updateResourceUsage('users', organization.memberCount, 'set');

      await session.commitTransaction();

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      // Emit event
      EventEmitter.emit('organization:member:removed', {
        organizationId,
        memberId,
        userId
      });

      return organization;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to remove team member', {
        error: error.message,
        organizationId,
        memberId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Resend invitation
   * @param {string} organizationId - Organization ID
   * @param {string} invitationId - Invitation ID
   * @param {string} userId - User performing action
   * @returns {Promise<Object>} - Updated organization
   */
  static async resendInvitation(organizationId, invitationId, userId) {
    try {
      const organization = await HostedOrganization.findById(organizationId);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      if (!organization.isAdmin(userId)) {
        throw new AppError('Only admins can resend invitations', 403);
      }

      const invitation = organization.team.invitations.id(invitationId);

      if (!invitation) {
        throw new AppError('Invitation not found', 404);
      }

      if (invitation.status !== 'pending') {
        throw new AppError('Can only resend pending invitations', 400);
      }

      // Update invitation with new token and expiry
      invitation.token = this._generateInvitationToken();
      invitation.expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
      invitation.sentAt = new Date();
      invitation.sentBy = userId;

      await organization.save();

      // Send invitation email
      await this._sendInvitationEmail(organization, invitation.email, invitation.token);

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      return organization;

    } catch (error) {
      logger.error('Failed to resend invitation', {
        error: error.message,
        organizationId,
        invitationId
      });
      throw error;
    }
  }

  /**
   * Revoke invitation
   * @param {string} organizationId - Organization ID
   * @param {string} invitationId - Invitation ID
   * @param {string} userId - User performing action
   * @returns {Promise<Object>} - Updated organization
   */
  static async revokeInvitation(organizationId, invitationId, userId) {
    try {
      const organization = await HostedOrganization.findById(organizationId);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      if (!organization.isAdmin(userId)) {
        throw new AppError('Only admins can revoke invitations', 403);
      }

      const invitation = organization.team.invitations.id(invitationId);

      if (!invitation) {
        throw new AppError('Invitation not found', 404);
      }

      invitation.status = 'revoked';
      await organization.save();

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      return organization;

    } catch (error) {
      logger.error('Failed to revoke invitation', {
        error: error.message,
        organizationId,
        invitationId
      });
      throw error;
    }
  }

  /**
   * Accept invitation
   * @param {string} token - Invitation token
   * @param {string} userId - User ID accepting invitation
   * @returns {Promise<Object>} - Result with organization and role
   */
  static async acceptInvitation(token, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const organization = await HostedOrganization.findOne({
        'team.invitations.token': token,
        'team.invitations.status': 'pending',
        'team.invitations.expiresAt': { $gt: new Date() }
      }).session(session);

      if (!organization) {
        throw new AppError('Invalid or expired invitation', 400);
      }

      const invitation = organization.team.invitations.find(inv => inv.token === token);

      if (!invitation) {
        throw new AppError('Invitation not found', 404);
      }

      // Get user
      const user = await User.findById(userId).session(session);
      if (!user) {
        throw new AppError('User not found', 404);
      }

      // Check if user email matches invitation
      if (user.email !== invitation.email) {
        throw new AppError('User email does not match invitation', 400);
      }

      // Add user to organization
      if (invitation.role === 'admin') {
        organization.team.admins.push({
          user: userId,
          addedAt: new Date(),
          addedBy: invitation.sentBy
        });
      } else {
        organization.team.members.push({
          user: userId,
          role: invitation.role,
          joinedAt: new Date(),
          invitedBy: invitation.sentBy
        });
      }

      // Mark invitation as accepted
      invitation.status = 'accepted';

      // Update user's organizations
      user.organizations = user.organizations || [];
      user.organizations.push({
        organization: organization._id,
        role: invitation.role,
        joinedAt: new Date()
      });

      await Promise.all([
        organization.save({ session }),
        user.save({ session })
      ]);

      await session.commitTransaction();

      // Clear cache
      await CacheService.del(`org:${organization._id}`);

      return {
        organization,
        role: invitation.role
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to accept invitation', {
        error: error.message,
        token: token.substring(0, 10) + '...'
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Update subscription with tenant synchronization
   * @param {string} organizationId - Organization ID
   * @param {Object} subscriptionData - Subscription update data
   * @param {string} userId - User performing update
   * @returns {Promise<Object>} - Updated organization
   */
  static async updateSubscription(organizationId, subscriptionData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Updating organization subscription', {
        organizationId,
        newPlan: subscriptionData.plan?.id,
        userId
      });

      const organization = await HostedOrganization.findById(organizationId)
        .populate('tenantRef')
        .session(session);

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Only owner can change subscription
      if (organization.team.owner.toString() !== userId) {
        throw new AppError('Only the owner can change subscription', 403);
      }

      // Update tenant subscription first
      const tenantPlan = this._mapTierToPlan(subscriptionData.plan?.id);
      await OrganizationTenantService.updateSubscription(
        organization.tenantRef._id,
        tenantPlan,
        userId
      );

      // Update organization subscription
      organization.subscription = {
        ...organization.subscription,
        ...subscriptionData,
        status: subscriptionData.status || 'active'
      };

      // Update platform tier if plan changed
      if (subscriptionData.plan?.id) {
        organization.platformConfig.tier = subscriptionData.plan.id;
        
        // Update features based on new tier
        const newConfig = this._getDefaultPlatformConfig(subscriptionData.plan.id);
        organization.platformConfig.features = new Map(Object.entries(newConfig.features));
        organization.platformConfig.modules = newConfig.modules;
      }

      await organization.save({ session });
      await session.commitTransaction();

      // Clear cache
      await CacheService.del(`org:${organizationId}`);

      // Send confirmation email
      await this._sendSubscriptionUpdateEmail(organization);

      // Emit event
      EventEmitter.emit('organization:subscription:updated', {
        organizationId,
        oldPlan: organization.subscription.plan?.id,
        newPlan: subscriptionData.plan?.id,
        userId
      });

      logger.info('Subscription updated successfully', {
        organizationId,
        newPlan: subscriptionData.plan?.id
      });

      return organization;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to update subscription', {
        error: error.message,
        organizationId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Get organization statistics
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} - Organization statistics
   */
  static async getOrganizationStats(organizationId) {
    try {
      const organization = await HostedOrganization.findById(organizationId)
        .populate('tenantRef');

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Get tenant usage stats
      const tenantUsage = await OrganizationTenantService.getTenantUsage(organization.tenantRef._id);

      const stats = {
        general: {
          name: organization.name,
          tier: organization.platformConfig.tier,
          createdAt: organization.createdAt,
          daysActive: Math.floor((Date.now() - organization.createdAt) / (1000 * 60 * 60 * 24))
        },
        subscription: {
          status: organization.subscription.status,
          plan: organization.subscription.plan?.name,
          isInTrial: organization.isInTrial,
          daysLeftInTrial: organization.daysLeftInTrial,
          billingCycle: organization.subscription.billingCycle,
          nextBillingDate: organization.subscription.nextBillingDate
        },
        team: {
          totalMembers: organization.memberCount,
          owner: 1,
          admins: organization.team.admins?.length || 0,
          members: organization.team.members?.length || 0,
          pendingInvitations: organization.team.invitations?.filter(i => i.status === 'pending').length || 0
        },
        resources: {
          users: tenantUsage.users,
          storage: tenantUsage.storage,
          apiCalls: tenantUsage.apiCalls,
          projects: tenantUsage.projects
        },
        activity: {
          lastActivity: organization.metrics.usage.lastActivity,
          monthlyActiveUsers: organization.metrics.usage.monthlyActiveUsers,
          totalLogins: organization.metrics.usage.totalLogins,
          healthScore: organization.metrics.health.score
        }
      };

      return stats;

    } catch (error) {
      logger.error('Failed to get organization statistics', {
        error: error.message,
        organizationId
      });
      throw error;
    }
  }

  /**
   * Get resource usage
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} - Resource usage data
   */
  static async getResourceUsage(organizationId) {
    try {
      const organization = await HostedOrganization.findById(organizationId)
        .populate('tenantRef');

      if (!organization) {
        throw new AppError('Organization not found', 404);
      }

      // Get real-time usage from tenant
      const tenantUsage = await OrganizationTenantService.getTenantUsage(organization.tenantRef._id);

      return {
        current: tenantUsage,
        limits: organization.tenantRef.resourceLimits,
        organization: organization.resourceUsage
      };

    } catch (error) {
      logger.error('Failed to get resource usage', {
        error: error.message,
        organizationId
      });
      throw error;
    }
  }

  // Placeholder methods for additional functionality
  // These would be implemented based on specific business requirements

  static async getSubscription(organizationId) {
    try {
      const organization = await this.getOrganizationById(organizationId);
      return organization.subscription;
    } catch (error) {
      throw error;
    }
  }

  static async cancelSubscription(organizationId, userId) {
    try {
      return await this.updateSubscription(organizationId, { status: 'canceled', canceledAt: new Date() }, userId);
    } catch (error) {
      throw error;
    }
  }

  static async getBillingHistory(organizationId, options = {}) {
    try {
      // This would integrate with your billing provider (Stripe, etc.)
      // For now, return placeholder data
      return {
        transactions: [],
        total: 0
      };
    } catch (error) {
      throw error;
    }
  }

  static async getDomains(organizationId) {
    try {
      const organization = await this.getOrganizationById(organizationId);
      return organization.domains;
    } catch (error) {
      throw error;
    }
  }

  static async addDomain(organizationId, domainData, userId) {
    try {
      const updateData = {
        $push: {
          'domains.customDomains': {
            domain: domainData.domain,
            isPrimary: domainData.isPrimary || false,
            addedAt: new Date()
          }
        }
      };
      
      const organization = await HostedOrganization.findByIdAndUpdate(
        organizationId,
        updateData,
        { new: true }
      );

      await CacheService.del(`org:${organizationId}`);
      return organization;
    } catch (error) {
      throw error;
    }
  }

  static async removeDomain(organizationId, domainId, userId) {
    try {
      const organization = await HostedOrganization.findByIdAndUpdate(
        organizationId,
        { $pull: { 'domains.customDomains': { _id: domainId } } },
        { new: true }
      );

      await CacheService.del(`org:${organizationId}`);
      return organization;
    } catch (error) {
      throw error;
    }
  }

  static async verifyDomain(organizationId, domain, userId) {
    try {
      // Domain verification logic would go here
      return {
        verified: false,
        verificationRecords: []
      };
    } catch (error) {
      throw error;
    }
  }

  static async getAnalytics(organizationId, options = {}) {
    try {
      // Analytics implementation would go here
      return {
        data: [],
        summary: {}
      };
    } catch (error) {
      throw error;
    }
  }

  static async getSecuritySettings(organizationId) {
    try {
      const organization = await this.getOrganizationById(organizationId);
      return organization.security;
    } catch (error) {
      throw error;
    }
  }

  static async updateSecuritySettings(organizationId, securityData, userId) {
    try {
      return await this.updateOrganization(organizationId, { security: securityData }, userId);
    } catch (error) {
      throw error;
    }
  }

  static async getAuditLogs(organizationId, options = {}) {
    try {
      // Audit log implementation would go here
      return {
        logs: [],
        total: 0
      };
    } catch (error) {
      throw error;
    }
  }

  static async getIntegrations(organizationId) {
    try {
      const organization = await this.getOrganizationById(organizationId);
      return organization.integrations;
    } catch (error) {
      throw error;
    }
  }

  static async configureIntegration(organizationId, integration, configData, userId) {
    try {
      const updateData = {
        [`integrations.${integration}`]: {
          ...configData,
          enabled: true
        }
      };
      
      return await this.updateOrganization(organizationId, updateData, userId);
    } catch (error) {
      throw error;
    }
  }

  static async removeIntegration(organizationId, integration, userId) {
    try {
      const updateData = {
        [`integrations.${integration}.enabled`]: false
      };
      
      return await this.updateOrganization(organizationId, updateData, userId);
    } catch (error) {
      throw error;
    }
  }

  static async getPreferences(organizationId) {
    try {
      const organization = await this.getOrganizationById(organizationId);
      return organization.preferences;
    } catch (error) {
      throw error;
    }
  }

  static async updatePreferences(organizationId, preferencesData, userId) {
    try {
      return await this.updateOrganization(organizationId, { preferences: preferencesData }, userId);
    } catch (error) {
      throw error;
    }
  }

  static async getBranding(organizationId) {
    try {
      const organization = await this.getOrganizationById(organizationId);
      return organization.branding;
    } catch (error) {
      throw error;
    }
  }

  static async updateBranding(organizationId, brandingData, userId) {
    try {
      return await this.updateOrganization(organizationId, { branding: brandingData }, userId);
    } catch (error) {
      throw error;
    }
  }

  static async getAllOrganizations(options = {}) {
    try {
      let query = HostedOrganization.find();
      
      if (options.filters) {
        query = query.where(options.filters);
      }
      
      if (options.sort) {
        query = query.sort(options.sort);
      }
      
      if (options.skip) {
        query = query.skip(parseInt(options.skip));
      }
      
      if (options.limit) {
        query = query.limit(parseInt(options.limit));
      }
      
      return await query.populate('tenantRef').lean({ virtuals: true });
    } catch (error) {
      throw error;
    }
  }

  static async getPlatformMetrics() {
    try {
      const totalOrgs = await HostedOrganization.countDocuments({ 'status.active': true });
      const totalUsers = await HostedOrganization.aggregate([
        { $match: { 'status.active': true } },
        { $group: { _id: null, totalUsers: { $sum: '$resourceUsage.users.current' } } }
      ]);
      
      return {
        organizations: {
          total: totalOrgs,
          active: totalOrgs
        },
        users: {
          total: totalUsers[0]?.totalUsers || 0
        }
      };
    } catch (error) {
      throw error;
    }
  }

  static async suspendOrganization(organizationId, userId) {
    try {
      const updateData = {
        'status.active': false,
        'status.locked': true,
        suspendedAt: new Date(),
        suspendedBy: userId
      };
      
      return await this.updateOrganization(organizationId, updateData, userId);
    } catch (error) {
      throw error;
    }
  }

  static async reactivateOrganization(organizationId, userId) {
    try {
      const updateData = {
        'status.active': true,
        'status.locked': false,
        $unset: { suspendedAt: '', suspendedBy: '' }
      };
      
      return await this.updateOrganization(organizationId, updateData, userId);
    } catch (error) {
      throw error;
    }
  }

  static async exportOrganizationData(organizationId, format, userId) {
    try {
      // Export implementation would go here
      return {
        exportId: 'export-' + Date.now(),
        downloadUrl: '/exports/org-data.json',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      };
    } catch (error) {
      throw error;
    }
  }

  /**
   * Private Helper Methods
   */

  /**
   * Map organization tier to tenant plan
   */
  static _mapTierToPlan(tier) {
    const tierToPlanMap = {
      'starter': TENANT_CONSTANTS.SUBSCRIPTION_PLANS.STARTER,
      'growth': TENANT_CONSTANTS.SUBSCRIPTION_PLANS.GROWTH,
      'professional': TENANT_CONSTANTS.SUBSCRIPTION_PLANS.PROFESSIONAL,
      'enterprise': TENANT_CONSTANTS.SUBSCRIPTION_PLANS.ENTERPRISE,
      'custom': TENANT_CONSTANTS.SUBSCRIPTION_PLANS.ENTERPRISE
    };
    
    return tierToPlanMap[tier] || TENANT_CONSTANTS.SUBSCRIPTION_PLANS.STARTER;
  }

  /**
   * Get database strategy based on tier
   */
  static _getDatabaseStrategy(tier) {
    return ['enterprise', 'custom'].includes(tier) 
      ? TENANT_CONSTANTS.DATABASE_STRATEGIES.DEDICATED 
      : TENANT_CONSTANTS.DATABASE_STRATEGIES.SHARED;
  }

  /**
   * Get default platform configuration
   */
  static _getDefaultPlatformConfig(tier) {
    const configs = {
      starter: {
        tier: 'starter',
        features: {
          'api_access': true,
          'custom_branding': false,
          'advanced_analytics': false,
          'priority_support': false,
          'sso': false,
          'audit_logs': false,
          'custom_integrations': false,
          'white_label': false
        },
        modules: {
          projects: true,
          crm: false,
          invoicing: false,
          analytics: true,
          integrations: false
        }
      },
      growth: {
        tier: 'growth',
        features: {
          'api_access': true,
          'custom_branding': true,
          'advanced_analytics': false,
          'priority_support': false,
          'sso': false,
          'audit_logs': true,
          'custom_integrations': false,
          'white_label': false
        },
        modules: {
          projects: true,
          crm: true,
          invoicing: false,
          analytics: true,
          integrations: true
        }
      },
      professional: {
        tier: 'professional',
        features: {
          'api_access': true,
          'custom_branding': true,
          'advanced_analytics': true,
          'priority_support': true,
          'sso': true,
          'audit_logs': true,
          'custom_integrations': true,
          'white_label': false
        },
        modules: {
          projects: true,
          crm: true,
          invoicing: true,
          analytics: true,
          integrations: true
        }
      },
      enterprise: {
        tier: 'enterprise',
        features: {
          'api_access': true,
          'custom_branding': true,
          'advanced_analytics': true,
          'priority_support': true,
          'sso': true,
          'audit_logs': true,
          'custom_integrations': true,
          'white_label': true
        },
        modules: {
          projects: true,
          crm: true,
          invoicing: true,
          analytics: true,
          integrations: true
        }
      }
    };

    return configs[tier] || configs.starter;
  }

  /**
   * Setup default organization data
   */
  // static async _setupDefaultOrganizationData(organization, session) {
  //   // This is where you'd create default:
  //   // - Roles and permissions
  //   // - Project templates
  //   // - Email templates
  //   // - Notification settings
  //   // - etc.
    
  //   logger.debug('Setting up default organization data', {
  //     organizationId: organization._id
  //   });
  // }
  
  /**
   * Setup default organization data
   * @private
   */
  static async _setupDefaultOrganizationData(organization, session) {
    // Implementation for setting up default data
    // This should be lightweight and non-critical
    logger.debug('Setting up default organization data', { 
      organizationId: organization._id 
    });
    
    // Add any default setup logic here
    // Keep it simple to avoid transaction timeouts
  }

  /**
   * Generate invitation token
   */
  static _generateInvitationToken() {
    return require('crypto').randomBytes(32).toString('hex');
  }

  /**
   * Send welcome email
   */
  // static async _sendWelcomeEmail(organization, user) {
  //   try {
  //     await EmailService.send({
  //       to: user.email,
  //       subject: `Welcome to ${process.env.APP_NAME || 'Our Platform'}!`,
  //       template: 'organization-welcome',
  //       data: {
  //         userName: user.name,
  //         organizationName: organization.name,
  //         organizationUrl: organization.url,
  //         trialDays: organization.daysLeftInTrial,
  //         tier: organization.platformConfig.tier
  //       }
  //     });
  //   } catch (error) {
  //     logger.error('Failed to send welcome email', {
  //       error: error.message,
  //       organizationId: organization._id
  //     });
  //   }
  // }

  /**
   * Send welcome email
   * @private
   */
  static async _sendWelcomeEmail(organization, user) {
    try {
      if (EmailService && typeof EmailService.sendWelcomeOrganization === 'function') {
        await EmailService.sendWelcomeOrganization(user.email, {
          organizationName: organization.name,
          organizationUrl: organization.url || `https://${organization.domains?.subdomain}.yourdomain.com`,
          userName: user.name || user.email
        });
      }
    } catch (error) {
      logger.warn('Welcome email sending failed', {
        error: error.message,
        organizationId: organization._id,
        userEmail: user.email
      });
      // Don't throw - this is non-critical
    }
  }

  /**
   * Send organization-specific welcome email
   * @private
   */
  static async _sendOrganizationWelcomeEmail(organization, user) {
    try {
      if (EmailService && typeof EmailService.sendWelcomeOrganization === 'function') {
        await EmailService.sendWelcomeOrganization(user.email, {
          organizationName: organization.name,
          organizationUrl: organization.url || `https://${organization.domains?.subdomain}.yourdomain.com`,
          userName: user.name || user.email,
          tier: organization.platformConfig?.tier,
          trialDays: organization.daysLeftInTrial
        });
      }
    } catch (error) {
      logger.warn('Organization welcome email sending failed', {
        error: error.message,
        organizationId: organization._id,
        userEmail: user.email
      });
    }
  }

  /**
   * Send invitation email
   */
  static async _sendInvitationEmail(organization, email, token) {
    try {
      const inviteUrl = `${process.env.APP_URL}/invite?token=${token}`;
      
      await EmailService.send({
        to: email,
        subject: `You're invited to join ${organization.name}`,
        template: 'team-invitation',
        data: {
          organizationName: organization.name,
          inviteUrl,
          expiresIn: '7 days'
        }
      });
    } catch (error) {
      logger.error('Failed to send invitation email', {
        error: error.message,
        email,
        organizationId: organization._id
      });
    }
  }

  /**
   * Send subscription update email
   */
  static async _sendSubscriptionUpdateEmail(organization) {
    try {
      const owner = await User.findById(organization.team.owner);
      
      await EmailService.send({
        to: owner.email,
        subject: 'Your subscription has been updated',
        template: 'subscription-update',
        data: {
          userName: owner.name,
          organizationName: organization.name,
          newPlan: organization.subscription.plan?.name,
          billingCycle: organization.subscription.billingCycle
        }
      });
    } catch (error) {
      logger.error('Failed to send subscription update email', {
        error: error.message,
        organizationId: organization._id
      });
    }
  }
}

module.exports = HostedOrganizationService;