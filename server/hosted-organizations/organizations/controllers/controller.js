/**
 * @file Hosted Organization Controller
 * @description HTTP request handlers for hosted organization management with tenant integration
 * @version 3.0.0
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
   * List user's organizations
   * @route GET /api/v1/hosted-organizations
   * @access Private
   */
  static listUserOrganizations = async (req, res, next) => {
    try {
      logger.debug('List user organizations request', {
        userId: req.user._id,
        includeInactive: req.query.includeInactive
      });

      const options = {
        includeInactive: req.query.includeInactive === 'true',
        populate: req.query.populate,
        sort: req.query.sort || '-createdAt'
      };

      const organizations = await HostedOrganizationService.getUserOrganizations(
        req.user._id,
        options
      );

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
      logger.error('List user organizations request failed', {
        error: error.message,
        userId: req.user._id
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
}

module.exports = HostedOrganizationController;