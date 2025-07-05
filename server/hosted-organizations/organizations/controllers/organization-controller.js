/**
 * @file Hosted Organization Controller - Complete Implementation
 * @description HTTP request handlers for hosted organization management with tenant integration
 * @version 3.1.0
 */

const HostedOrganizationService = require('../services/organization-service');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { ORGANIZATION_CONSTANTS } = require('../../../shared/utils/constants/organization-constants');
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');

/**
 * Hosted Organization Controller Class
 * @class HostedOrganizationController
 */
class HostedOrganizationController {
  /**
   * Create a new hosted organization
   * @route POST /api/v1/hosted-organizations
   * @access Private
   */
  static createOrganization = async (req, res, next) => {
    try {
      logger.info('Create organization request received', {
        userId: req.user._id,
        organizationName: req.body.name,
        tier: req.body.platformConfig?.tier
      });

      // Validate required fields
      const requiredFields = ['name'];
      const missingFields = requiredFields.filter(field => !req.body[field]);
      
      if (missingFields.length > 0) {
        throw new AppError(`Missing required fields: ${missingFields.join(', ')}`, 400);
      }

      // Create organization with tenant
      const organization = await HostedOrganizationService.createOrganization(
        req.body,
        req.user._id
      );

      res.status(201).json({
        status: 'success',
        message: 'Organization created successfully',
        data: {
          organization: {
            _id: organization._id,
            platformId: organization.platformId,
            tenantId: organization.tenantId,
            tenantCode: organization.tenantCode,
            name: organization.name,
            slug: organization.slug,
            url: organization.url,
            tier: organization.platformConfig.tier,
            subscription: organization.subscription,
            owner: organization.team.owner,
            createdAt: organization.createdAt
          }
        },
        meta: {
          trialEndsAt: organization.subscription.trialEnd,
          platformUrl: organization.url,
          tenantStatus: organization.tenantRef?.status
        }
      });

    } catch (error) {
      logger.error('Create organization request failed', {
        error: error.message,
        userId: req.user._id,
        organizationName: req.body.name
      });
      next(error);
    }
  };

  /**
   * Get organization by ID
   * @route GET /api/v1/hosted-organizations/:id
   * @access Private - Organization member or admin
   */
  static getOrganizationById = async (req, res, next) => {
    try {
      logger.debug('Get organization by ID request', {
        userId: req.user._id,
        organizationId: req.params.id,
        tenantContext: req.tenant?.tenantId
      });

      const options = {
        populate: req.query.populate,
        includeInactive: req.user.role === 'super_admin',
        skipCache: req.query.skipCache === 'true'
      };

      const organization = await HostedOrganizationService.getOrganizationById(
        req.params.id,
        options
      );

      // Check access permissions
      if (!organization.isMember(req.user._id) && req.user.role !== 'super_admin') {
        throw new AppError('Access denied to this organization', 403);
      }

      // Check if tenant context matches (for multi-tenant isolation)
      if (req.tenant && organization.tenantId !== req.tenant.tenantId) {
        throw new AppError('Organization not found in current tenant context', 404);
      }

      res.status(200).json({
        status: 'success',
        data: {
          organization
        },
        meta: {
          tenantStatus: organization.tenantRef?.status,
          userRole: organization.getUserRole(req.user._id)
        }
      });

    } catch (error) {
      logger.error('Get organization by ID request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get current organization (from tenant context)
   * @route GET /api/v1/hosted-organizations/current
   * @access Private - Must have tenant context
   */
  static getCurrentOrganization = async (req, res, next) => {
    try {
      logger.debug('Get current organization request', {
        userId: req.user._id,
        tenantId: req.tenant?.tenantId
      });

      if (!req.tenant) {
        throw new AppError('No organization context found', 400);
      }

      // Get organization by tenant ID
      const organization = await HostedOrganizationService.getOrganizationByTenantId(
        req.tenant.tenantId
      );

      if (!organization.isMember(req.user._id)) {
        throw new AppError('You are not a member of this organization', 403);
      }

      res.status(200).json({
        status: 'success',
        data: {
          organization
        },
        meta: {
          tenantStatus: req.tenant.status,
          userRole: organization.getUserRole(req.user._id),
          resourceUsage: await HostedOrganizationService.getResourceUsage(organization._id)
        }
      });

    } catch (error) {
      logger.error('Get current organization request failed', {
        error: error.message,
        userId: req.user._id,
        tenantId: req.tenant?.tenantId
      });
      next(error);
    }
  };

  /**
   * Update organization
   * @route PATCH /api/v1/hosted-organizations/:id
   * @access Private - Organization admin
   */
  static updateOrganization = async (req, res, next) => {
    try {
      logger.info('Update organization request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        fields: Object.keys(req.body)
      });

      // Prevent updating sensitive fields directly
      const restrictedFields = ['tenantRef', 'tenantId', 'tenantCode', 'platformId', 'owner'];
      const attemptedRestricted = restrictedFields.filter(field => req.body[field]);
      
      if (attemptedRestricted.length > 0) {
        throw new AppError(`Cannot update restricted fields: ${attemptedRestricted.join(', ')}`, 400);
      }

      const organization = await HostedOrganizationService.updateOrganization(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Organization updated successfully',
        data: {
          organization
        }
      });

    } catch (error) {
      logger.error('Update organization request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Delete organization (soft delete)
   * @route DELETE /api/v1/hosted-organizations/:id
   * @access Private - Organization owner
   */
  static deleteOrganization = async (req, res, next) => {
    try {
      logger.info('Delete organization request received', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const organization = await HostedOrganizationService.deleteOrganization(
        req.params.id,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Organization scheduled for deletion',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            status: organization.status,
            deletionScheduledFor: organization.status.deletionScheduledFor
          }
        }
      });

    } catch (error) {
      logger.error('Delete organization request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * List user's organizations
   * @route GET /api/v1/hosted-organizations
   * @access Private
   */
  // static listUserOrganizations = async (req, res, next) => {
  //   try {
  //     logger.debug('List user organizations request', {
  //       userId: req.user._id,
  //       includeInactive: req.query.includeInactive,
  //       pagination: req.pagination
  //     });

  //     const options = {
  //       includeInactive: req.query.includeInactive === 'true',
  //       populate: req.query.populate,
  //       sort: req.query.sort || '-createdAt',
  //       limit: req.query.limit,
  //       skip: req.query.skip
  //     };

  //     const organizations = await HostedOrganizationService.getUserOrganizations(
  //       req.user._id,
  //       options
  //     );

  //     res.status(200).json({
  //       status: 'success',
  //       data: {
  //         organizations
  //       },
  //       meta: {
  //         count: organizations.length
  //       }
  //     });

  //   } catch (error) {
  //     logger.error('List user organizations request failed', {
  //       error: error.message,
  //       userId: req.user._id
  //     });
  //     next(error);
  //   }
  // };
  static listUserOrganizations = async (req, res, next) => {
    try {
      logger.debug('List user organizations request', {
        userId: req.user._id,
        includeInactive: req.query.includeInactive,
        pagination: req.pagination
      });

      const options = {
        includeInactive: req.query.includeInactive === 'true',
        populate: req.query.populate,
        // Use pagination middleware values instead of manual handling
        page: req.pagination.page,
        limit: req.pagination.limit,
        sortBy: req.pagination.sortBy,
        sortOrder: req.pagination.sortOrder
      };

      // Get both data and total count for pagination
      const result = await HostedOrganizationService.getUserOrganizationsWithPagination(
        req.user._id,
        options
      );

      // Use the pagination helper method provided by middleware
      res.paginate(result.organizations, result.total, {
        filters: {
          includeInactive: options.includeInactive
        }
      });

    } catch (error) {
      logger.error('List user organizations request failed', {
        error: error.message,
        userId: req.user._id
      });
      next(error);
    }
  };

  /**
   * Get team members
   * @route GET /api/v1/hosted-organizations/:id/team
   * @access Private - Organization member
   */
  static getTeamMembers = async (req, res, next) => {
    try {
      logger.debug('Get team members request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const options = {
        role: req.query.role,
        status: req.query.status,
        sortBy: req.query.sortBy,
        sortOrder: req.query.sortOrder,
        skip: req.query.skip,
        limit: req.query.limit
      };

      const result = await HostedOrganizationService.getTeamMembers(
        req.params.id,
        options
      );

      res.status(200).json({
        status: 'success',
        data: result,
        meta: {
          pagination: {
            total: result.total,
            skip: result.skip,
            limit: result.limit,
            hasMore: result.hasMore
          }
        }
      });

    } catch (error) {
      logger.error('Get team members request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Add team member
   * @route POST /api/v1/hosted-organizations/:id/team/members
   * @access Private - Organization admin
   */
  static addTeamMember = async (req, res, next) => {
    try {
      logger.info('Add team member request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        memberEmail: req.body.email
      });

      // Validate required fields
      if (!req.body.email) {
        throw new AppError('Email is required', 400);
      }

      // Validate email format
      const emailRegex = /^\S+@\S+\.\S+$/;
      if (!emailRegex.test(req.body.email)) {
        throw new AppError('Invalid email format', 400);
      }

      const organization = await HostedOrganizationService.addTeamMember(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Team member added successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            team: organization.team
          }
        }
      });

    } catch (error) {
      logger.error('Add team member request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update team member
   * @route PATCH /api/v1/hosted-organizations/:id/team/members/:memberId
   * @access Private - Organization admin
   */
  static updateTeamMember = async (req, res, next) => {
    try {
      logger.info('Update team member request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        memberId: req.params.memberId
      });

      const organization = await HostedOrganizationService.updateTeamMember(
        req.params.id,
        req.params.memberId,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Team member updated successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            team: organization.team
          }
        }
      });

    } catch (error) {
      logger.error('Update team member request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id,
        memberId: req.params.memberId
      });
      next(error);
    }
  };

  /**
   * Remove team member
   * @route DELETE /api/v1/hosted-organizations/:id/team/members/:memberId
   * @access Private - Organization admin
   */
  static removeTeamMember = async (req, res, next) => {
    try {
      logger.info('Remove team member request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        memberId: req.params.memberId
      });

      const organization = await HostedOrganizationService.removeTeamMember(
        req.params.id,
        req.params.memberId,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Team member removed successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            team: organization.team
          }
        }
      });

    } catch (error) {
      logger.error('Remove team member request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id,
        memberId: req.params.memberId
      });
      next(error);
    }
  };

  /**
   * Resend invitation
   * @route POST /api/v1/hosted-organizations/:id/team/invitations/:invitationId/resend
   * @access Private - Organization admin
   */
  static resendInvitation = async (req, res, next) => {
    try {
      logger.info('Resend invitation request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        invitationId: req.params.invitationId
      });

      const organization = await HostedOrganizationService.resendInvitation(
        req.params.id,
        req.params.invitationId,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Invitation resent successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name
          }
        }
      });

    } catch (error) {
      logger.error('Resend invitation request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id,
        invitationId: req.params.invitationId
      });
      next(error);
    }
  };

  /**
   * Revoke invitation
   * @route DELETE /api/v1/hosted-organizations/:id/team/invitations/:invitationId
   * @access Private - Organization admin
   */
  static revokeInvitation = async (req, res, next) => {
    try {
      logger.info('Revoke invitation request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        invitationId: req.params.invitationId
      });

      const organization = await HostedOrganizationService.revokeInvitation(
        req.params.id,
        req.params.invitationId,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Invitation revoked successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name
          }
        }
      });

    } catch (error) {
      logger.error('Revoke invitation request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id,
        invitationId: req.params.invitationId
      });
      next(error);
    }
  };

  /**
   * Accept invitation
   * @route POST /api/v1/hosted-organizations/invitations/accept
   * @access Public (with valid token)
   */
  static acceptInvitation = async (req, res, next) => {
    try {
      logger.info('Accept invitation request received', {
        token: req.body.token?.substring(0, 10) + '...',
        userId: req.user?._id
      });

      if (!req.body.token) {
        throw new AppError('Invitation token is required', 400);
      }

      const result = await HostedOrganizationService.acceptInvitation(
        req.body.token,
        req.user?._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Invitation accepted successfully',
        data: {
          organization: {
            _id: result.organization._id,
            name: result.organization.name,
            url: result.organization.url
          },
          role: result.role
        }
      });

    } catch (error) {
      logger.error('Accept invitation request failed', {
        error: error.message,
        token: req.body.token?.substring(0, 10) + '...'
      });
      next(error);
    }
  };

  /**
   * Get subscription details
   * @route GET /api/v1/hosted-organizations/:id/subscription
   * @access Private - Organization member
   */
  static getSubscription = async (req, res, next) => {
    try {
      logger.debug('Get subscription request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const subscription = await HostedOrganizationService.getSubscription(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          subscription
        }
      });

    } catch (error) {
      logger.error('Get subscription request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update subscription
   * @route PUT /api/v1/hosted-organizations/:id/subscription
   * @access Private - Organization owner
   */
  static updateSubscription = async (req, res, next) => {
    try {
      logger.info('Update subscription request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        newPlan: req.body.plan?.id
      });

      // Validate subscription data
      if (!req.body.plan?.id) {
        throw new AppError('Plan ID is required', 400);
      }

      const validPlans = ['starter', 'growth', 'professional', 'enterprise'];
      if (!validPlans.includes(req.body.plan.id)) {
        throw new AppError('Invalid plan ID', 400);
      }

      const organization = await HostedOrganizationService.updateSubscription(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Subscription updated successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            subscription: organization.subscription,
            platformConfig: organization.platformConfig
          }
        },
        meta: {
          resourceLimits: organization.tenantRef?.resourceLimits
        }
      });

    } catch (error) {
      logger.error('Update subscription request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Cancel subscription
   * @route POST /api/v1/hosted-organizations/:id/subscription/cancel
   * @access Private - Organization owner
   */
  static cancelSubscription = async (req, res, next) => {
    try {
      logger.info('Cancel subscription request received', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const organization = await HostedOrganizationService.cancelSubscription(
        req.params.id,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Subscription canceled successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            subscription: organization.subscription
          }
        }
      });

    } catch (error) {
      logger.error('Cancel subscription request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get billing history
   * @route GET /api/v1/hosted-organizations/:id/billing/history
   * @access Private - Organization admin
   */
  static getBillingHistory = async (req, res, next) => {
    try {
      logger.debug('Get billing history request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const options = {
        skip: req.query.skip,
        limit: req.query.limit,
        sortBy: req.query.sortBy,
        sortOrder: req.query.sortOrder
      };

      const billingHistory = await HostedOrganizationService.getBillingHistory(
        req.params.id,
        options
      );

      res.status(200).json({
        status: 'success',
        data: billingHistory
      });

    } catch (error) {
      logger.error('Get billing history request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get domains
   * @route GET /api/v1/hosted-organizations/:id/domains
   * @access Private - Organization member
   */
  static getDomains = async (req, res, next) => {
    try {
      logger.debug('Get domains request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const domains = await HostedOrganizationService.getDomains(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          domains
        }
      });

    } catch (error) {
      logger.error('Get domains request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Add custom domain
   * @route POST /api/v1/hosted-organizations/:id/domains
   * @access Private - Organization admin
   */
  static addDomain = async (req, res, next) => {
    try {
      logger.info('Add domain request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        domain: req.body.domain
      });

      if (!req.body.domain) {
        throw new AppError('Domain is required', 400);
      }

      const organization = await HostedOrganizationService.addDomain(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Domain added successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            domains: organization.domains
          }
        }
      });

    } catch (error) {
      logger.error('Add domain request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Verify domain
   * @route POST /api/v1/hosted-organizations/:id/domains/verify
   * @access Private - Organization admin
   */
  static verifyDomain = async (req, res, next) => {
    try {
      logger.info('Verify domain request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        domain: req.body.domain
      });

      if (!req.body.domain) {
        throw new AppError('Domain is required', 400);
      }

      const result = await HostedOrganizationService.verifyDomain(
        req.params.id,
        req.body.domain,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: result.verified ? 'Domain verified successfully' : 'Domain verification pending',
        data: {
          domain: req.body.domain,
          verified: result.verified,
          verificationRecords: result.verificationRecords
        }
      });

    } catch (error) {
      logger.error('Verify domain request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Remove domain
   * @route DELETE /api/v1/hosted-organizations/:id/domains/:domainId
   * @access Private - Organization admin
   */
  static removeDomain = async (req, res, next) => {
    try {
      logger.info('Remove domain request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        domainId: req.params.domainId
      });

      const organization = await HostedOrganizationService.removeDomain(
        req.params.id,
        req.params.domainId,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Domain removed successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            domains: organization.domains
          }
        }
      });

    } catch (error) {
      logger.error('Remove domain request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id,
        domainId: req.params.domainId
      });
      next(error);
    }
  };

  /**
   * Get resource usage
   * @route GET /api/v1/hosted-organizations/:id/usage
   * @access Private - Organization member
   */
  static getResourceUsage = async (req, res, next) => {
    try {
      logger.debug('Get resource usage request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      // Get organization to verify access
      const organization = await HostedOrganizationService.getOrganizationById(req.params.id);
      
      if (!organization.isMember(req.user._id)) {
        throw new AppError('Access denied', 403);
      }

      // Get usage from tenant service
      const usage = await HostedOrganizationService.getResourceUsage(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          usage
        }
      });

    } catch (error) {
      logger.error('Get resource usage request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get organization statistics
   * @route GET /api/v1/hosted-organizations/:id/stats
   * @access Private - Organization member
   */
  static getOrganizationStats = async (req, res, next) => {
    try {
      logger.debug('Get organization stats request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const stats = await HostedOrganizationService.getOrganizationStats(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          stats
        }
      });

    } catch (error) {
      logger.error('Get organization stats request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get analytics
   * @route GET /api/v1/hosted-organizations/:id/analytics
   * @access Private - Organization member
   */
  static getAnalytics = async (req, res, next) => {
    try {
      logger.debug('Get analytics request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const options = {
        metric: req.query.metric,
        period: req.query.period,
        granularity: req.query.granularity,
        skip: req.query.skip,
        limit: req.query.limit
      };

      const analytics = await HostedOrganizationService.getAnalytics(
        req.params.id,
        options
      );

      res.status(200).json({
        status: 'success',
        data: analytics
      });

    } catch (error) {
      logger.error('Get analytics request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get security settings
   * @route GET /api/v1/hosted-organizations/:id/security
   * @access Private - Organization admin
   */
  static getSecuritySettings = async (req, res, next) => {
    try {
      logger.debug('Get security settings request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const securitySettings = await HostedOrganizationService.getSecuritySettings(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          security: securitySettings
        }
      });

    } catch (error) {
      logger.error('Get security settings request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update security settings
   * @route PUT /api/v1/hosted-organizations/:id/security
   * @access Private - Organization owner
   */
  static updateSecuritySettings = async (req, res, next) => {
    try {
      logger.info('Update security settings request received', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const organization = await HostedOrganizationService.updateSecuritySettings(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Security settings updated successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            security: organization.security
          }
        }
      });

    } catch (error) {
      logger.error('Update security settings request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get audit logs
   * @route GET /api/v1/hosted-organizations/:id/audit-logs
   * @access Private - Organization admin
   */
  static getAuditLogs = async (req, res, next) => {
    try {
      logger.debug('Get audit logs request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const options = {
        action: req.query.action,
        actor: req.query.actor,
        severity: req.query.severity,
        skip: req.query.skip,
        limit: req.query.limit,
        sortBy: req.query.sortBy,
        sortOrder: req.query.sortOrder
      };

      const auditLogs = await HostedOrganizationService.getAuditLogs(
        req.params.id,
        options
      );

      res.status(200).json({
        status: 'success',
        data: auditLogs
      });

    } catch (error) {
      logger.error('Get audit logs request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get integrations
   * @route GET /api/v1/hosted-organizations/:id/integrations
   * @access Private - Organization member
   */
  static getIntegrations = async (req, res, next) => {
    try {
      logger.debug('Get integrations request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const integrations = await HostedOrganizationService.getIntegrations(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          integrations
        }
      });

    } catch (error) {
      logger.error('Get integrations request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Configure integration
   * @route PUT /api/v1/hosted-organizations/:id/integrations/:integration
   * @access Private - Organization admin
   */
  static configureIntegration = async (req, res, next) => {
    try {
      logger.info('Configure integration request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        integration: req.params.integration
      });

      const organization = await HostedOrganizationService.configureIntegration(
        req.params.id,
        req.params.integration,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Integration configured successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            integrations: organization.integrations
          }
        }
      });

    } catch (error) {
      logger.error('Configure integration request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id,
        integration: req.params.integration
      });
      next(error);
    }
  };

  /**
   * Remove integration
   * @route DELETE /api/v1/hosted-organizations/:id/integrations/:integration
   * @access Private - Organization admin
   */
  static removeIntegration = async (req, res, next) => {
    try {
      logger.info('Remove integration request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        integration: req.params.integration
      });

      const organization = await HostedOrganizationService.removeIntegration(
        req.params.id,
        req.params.integration,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Integration removed successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            integrations: organization.integrations
          }
        }
      });

    } catch (error) {
      logger.error('Remove integration request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id,
        integration: req.params.integration
      });
      next(error);
    }
  };

  /**
   * Get preferences
   * @route GET /api/v1/hosted-organizations/:id/preferences
   * @access Private - Organization member
   */
  static getPreferences = async (req, res, next) => {
    try {
      logger.debug('Get preferences request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const preferences = await HostedOrganizationService.getPreferences(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          preferences
        }
      });

    } catch (error) {
      logger.error('Get preferences request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update preferences
   * @route PUT /api/v1/hosted-organizations/:id/preferences
   * @access Private - Organization admin
   */
  static updatePreferences = async (req, res, next) => {
    try {
      logger.info('Update preferences request received', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const organization = await HostedOrganizationService.updatePreferences(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Preferences updated successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            preferences: organization.preferences
          }
        }
      });

    } catch (error) {
      logger.error('Update preferences request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get branding
   * @route GET /api/v1/hosted-organizations/:id/branding
   * @access Private - Organization member
   */
  static getBranding = async (req, res, next) => {
    try {
      logger.debug('Get branding request', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const branding = await HostedOrganizationService.getBranding(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          branding
        }
      });

    } catch (error) {
      logger.error('Get branding request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update branding
   * @route PUT /api/v1/hosted-organizations/:id/branding
   * @access Private - Organization admin
   */
  static updateBranding = async (req, res, next) => {
    try {
      logger.info('Update branding request received', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const organization = await HostedOrganizationService.updateBranding(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Branding updated successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            branding: organization.branding
          }
        }
      });

    } catch (error) {
      logger.error('Update branding request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Export organization data
   * @route POST /api/v1/hosted-organizations/:id/export
   * @access Private - Organization owner
   */
  static exportOrganizationData = async (req, res, next) => {
    try {
      logger.info('Export organization data request received', {
        userId: req.user._id,
        organizationId: req.params.id,
        format: req.body.format
      });

      const validFormats = ['json', 'csv', 'pdf'];
      if (!req.body.format || !validFormats.includes(req.body.format)) {
        throw new AppError('Valid format is required (json, csv, pdf)', 400);
      }

      const exportData = await HostedOrganizationService.exportOrganizationData(
        req.params.id,
        req.body.format,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Export initiated successfully',
        data: {
          exportId: exportData.exportId,
          downloadUrl: exportData.downloadUrl,
          expiresAt: exportData.expiresAt
        }
      });

    } catch (error) {
      logger.error('Export organization data request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Super Admin Methods
   */

  /**
   * Get all organizations (platform admin only)
   * @route GET /api/v1/hosted-organizations/admin/all
   * @access Private - Super admin
   */
  static getAllOrganizations = async (req, res, next) => {
    try {
      logger.debug('Get all organizations request (admin)', {
        userId: req.user._id
      });

      const options = {
        filters: req.query.filters ? JSON.parse(req.query.filters) : {},
        sort: req.query.sort,
        skip: req.query.skip,
        limit: req.query.limit
      };

      const organizations = await HostedOrganizationService.getAllOrganizations(options);

      res.status(200).json({
        status: 'success',
        data: {
          organizations
        },
        meta: {
          count: organizations.length
        }
      });

    } catch (error) {
      logger.error('Get all organizations request failed', {
        error: error.message,
        userId: req.user._id
      });
      next(error);
    }
  };

  /**
   * Get platform metrics (platform admin only)
   * @route GET /api/v1/hosted-organizations/admin/metrics
   * @access Private - Super admin
   */
  static getPlatformMetrics = async (req, res, next) => {
    try {
      logger.debug('Get platform metrics request (admin)', {
        userId: req.user._id
      });

      const metrics = await HostedOrganizationService.getPlatformMetrics();

      res.status(200).json({
        status: 'success',
        data: {
          metrics
        }
      });

    } catch (error) {
      logger.error('Get platform metrics request failed', {
        error: error.message,
        userId: req.user._id
      });
      next(error);
    }
  };

  /**
   * Suspend organization (platform admin only)
   * @route POST /api/v1/hosted-organizations/:id/suspend
   * @access Private - Super admin
   */
  static suspendOrganization = async (req, res, next) => {
    try {
      logger.info('Suspend organization request received (admin)', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const organization = await HostedOrganizationService.suspendOrganization(
        req.params.id,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Organization suspended successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            status: organization.status
          }
        }
      });

    } catch (error) {
      logger.error('Suspend organization request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Reactivate organization (platform admin only)
   * @route POST /api/v1/hosted-organizations/:id/reactivate
   * @access Private - Super admin
   */
  static reactivateOrganization = async (req, res, next) => {
    try {
      logger.info('Reactivate organization request received (admin)', {
        userId: req.user._id,
        organizationId: req.params.id
      });

      const organization = await HostedOrganizationService.reactivateOrganization(
        req.params.id,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Organization reactivated successfully',
        data: {
          organization: {
            _id: organization._id,
            name: organization.name,
            status: organization.status
          }
        }
      });

    } catch (error) {
      logger.error('Reactivate organization request failed', {
        error: error.message,
        userId: req.user._id,
        organizationId: req.params.id
      });
      next(error);
    }
  };
}

module.exports = HostedOrganizationController;