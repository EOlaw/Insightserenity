/**
 * @file Hosted Organization Service
 * @description Business logic layer for hosted organization management with tenant integration
 * @version 3.0.0
 */

const mongoose = require('mongoose');

const { CacheService } = require('../../../shared/services/cache-service');
const { EmailService } = require('../../../shared/services/email-service');
const User = require('../../../shared/users/models/user-model');
const { AppError } = require('../../../shared/utils/app-error');
const { EventEmitter } = require('../../../shared/utils/events/event-emitter');
const logger = require('../../../shared/utils/logger');
const HostedOrganization = require('../models/model');
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

      // Validate user
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

      // Step 1: Create the tenant infrastructure first
      const tenantData = {
        name: organizationData.name,
        contactEmail: organizationData.headquarters?.email || user.email,
        owner: userId,
        subscription: {
          plan: this._mapTierToPlan(organizationData.platformConfig?.tier || 'starter'),
          status: organizationData.subscription?.status || TENANT_CONSTANTS.SUBSCRIPTION_STATUS.TRIAL
        },
        database: {
          strategy: this._getDatabaseStrategy(organizationData.platformConfig?.tier)
        }
      };

      // Create tenant (this handles resource limits, database setup, etc.)
      const tenant = await OrganizationTenantService.createTenant(tenantData, userId);

      // Step 2: Create the organization linked to the tenant
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

      // Sync subscription info from tenant
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

      // Set default platform configuration based on tier
      if (!orgData.platformConfig) {
        orgData.platformConfig = this._getDefaultPlatformConfig(orgData.platformConfig?.tier || 'starter');
      }

      // Create organization
      const organization = await HostedOrganization.create([orgData], { session });

      // Update user's organization reference
      user.organizations = user.organizations || [];
      user.organizations.push({
        organization: organization[0]._id,
        role: 'owner',
        joinedAt: new Date()
      });
      await user.save({ session });

      // Step 3: Update tenant with organization reference
      tenant.organizationRef = organization[0]._id;
      await tenant.save({ session });

      // Setup default data
      await this._setupDefaultOrganizationData(organization[0], session);

      // Send welcome emails
      await this._sendWelcomeEmail(organization[0], user);

      await session.commitTransaction();

      // Emit events
      EventEmitter.emit('organization:created', {
        organizationId: organization[0]._id,
        tenantId: tenant._id,
        userId,
        tier: organization[0].platformConfig.tier
      });

      // Cache organization
      await CacheService.set(
        `org:${organization[0]._id}`,
        organization[0].toObject(),
        3600 // 1 hour
      );

      logger.info('Hosted organization created successfully', {
        organizationId: organization[0]._id,
        platformId: organization[0].platformId,
        tenantId: tenant.tenantId,
        subdomain: organization[0].domains.subdomain
      });

      // Populate tenant reference before returning
      await organization[0].populate('tenantRef');

      return organization[0];

    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Failed to create hosted organization', {
        error: error.message,
        userId,
        organizationName: organizationData.name
      });
      
      throw error;
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
  static async _setupDefaultOrganizationData(organization, session) {
    // This is where you'd create default:
    // - Roles and permissions
    // - Project templates
    // - Email templates
    // - Notification settings
    // - etc.
    
    logger.debug('Setting up default organization data', {
      organizationId: organization._id
    });
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
  static async _sendWelcomeEmail(organization, user) {
    try {
      await EmailService.send({
        to: user.email,
        subject: `Welcome to ${process.env.APP_NAME || 'Our Platform'}!`,
        template: 'organization-welcome',
        data: {
          userName: user.name,
          organizationName: organization.name,
          organizationUrl: organization.url,
          trialDays: organization.daysLeftInTrial,
          tier: organization.platformConfig.tier
        }
      });
    } catch (error) {
      logger.error('Failed to send welcome email', {
        error: error.message,
        organizationId: organization._id
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