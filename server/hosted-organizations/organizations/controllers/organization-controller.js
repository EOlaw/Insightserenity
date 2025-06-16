/**
 * @file Hosted Organization Controller
 * @description HTTP request handling for hosted organization management
 * @version 2.0.0
 */

const HostedOrganizationService = require('../services/organization-service');
// const { catchAsync } = require('../../../shared/utils/errors/catchAsync');
const { AppError } = require('../../../shared/utils/app-error');
const { validateRequest } = require('../../../shared/utils/validation/validator');
const { sanitizeInput } = require('../../../shared/security/sanitizer');
const logger = require('../../../shared/utils/logger');

class HostedOrganizationController {
  /**
   * Create a new hosted organization
   * @route POST /api/v1/hosted-organizations
   */
  static createOrganization = (async (req, res, next) => {
    logger.debug('Create hosted organization request', {
      userId: req.user._id,
      organizationName: req.body.name,
      tier: req.body.platformConfig?.tier
    });

    // Sanitize input
    const sanitizedData = sanitizeInput(req.body, [
      'name', 'displayName', 'businessInfo', 'headquarters', 
      'platformConfig', 'settings'
    ]);

    // Validate required fields
    const validationErrors = validateRequest(sanitizedData, {
      name: { required: true, minLength: 2, maxLength: 100 },
      'headquarters.timezone': { required: true },
      'platformConfig.tier': { 
        required: true, 
        enum: ['starter', 'growth', 'professional', 'enterprise'] 
      }
    });

    if (validationErrors.length > 0) {
      return next(new AppError(`Validation failed: ${validationErrors.join(', ')}`, 400));
    }

    // Create organization
    const organization = await HostedOrganizationService.createOrganization(
      sanitizedData,
      req.user._id
    );

    res.status(201).json({
      status: 'success',
      data: {
        organization: {
          id: organization._id,
          platformId: organization.platformId,
          name: organization.name,
          slug: organization.slug,
          subdomain: organization.domains.subdomain,
          url: organization.url,
          tier: organization.platformConfig.tier,
          subscription: organization.subscription,
          owner: organization.owner,
          createdAt: organization.createdAt
        }
      },
      meta: {
        trialEndsAt: organization.subscription.trialEnd,
        platformUrl: organization.url
      }
    });
  });

  /**
   * Get organization by ID
   * @route GET /api/v1/hosted-organizations/:id
   */
  static getOrganizationById = (async (req, res, next) => {
    logger.debug('Get organization by ID request', {
      userId: req.user._id,
      organizationId: req.params.id
    });

    const options = {
      populate: req.query.populate,
      includeInactive: req.user.role === 'super_admin'
    };

    const organization = await HostedOrganizationService.getOrganizationById(
      req.params.id,
      options
    );

    // Check access permissions
    if (!req.organization || req.organization._id.toString() !== organization._id.toString()) {
      if (!['admin', 'super_admin'].includes(req.user.role)) {
        return next(new AppError('Access denied', 403));
      }
    }

    res.status(200).json({
      status: 'success',
      data: {
        organization
      }
    });
  });

  /**
   * Update organization
   * @route PATCH /api/v1/hosted-organizations/:id
   */
  static updateOrganization = (async (req, res, next) => {
    logger.debug('Update organization request', {
      userId: req.user._id,
      organizationId: req.params.id,
      fields: Object.keys(req.body)
    });

    // Prevent updating system fields
    const restrictedFields = ['_id', 'platformId', 'owner', 'createdAt', 'slug'];
    restrictedFields.forEach(field => delete req.body[field]);

    // Sanitize input
    const sanitizedData = sanitizeInput(req.body, [
      'name', 'displayName', 'businessInfo', 'headquarters',
      'branding', 'settings', 'security'
    ]);

    const organization = await HostedOrganizationService.updateOrganization(
      req.params.id,
      sanitizedData,
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      data: {
        organization
      }
    });
  });

  /**
   * Search organizations
   * @route GET /api/v1/hosted-organizations/search
   */
  static searchOrganizations = (async (req, res, next) => {
    logger.debug('Search organizations request', {
      userId: req.user._id,
      filters: req.query
    });

    const filters = {};
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: Math.min(parseInt(req.query.limit) || 20, 100),
      sort: req.query.sort || '-createdAt',
      search: req.query.q || ''
    };

    // Apply filters
    if (req.query.tier) filters.tier = req.query.tier;
    if (req.query.status) filters.subscriptionStatus = req.query.status;
    if (req.query.industry) filters.industry = req.query.industry;
    if (req.query.minHealth) filters.minHealthScore = parseInt(req.query.minHealth);

    const result = await HostedOrganizationService.searchOrganizations(
      filters,
      options
    );

    res.status(200).json({
      status: 'success',
      results: result.organizations.length,
      data: {
        organizations: result.organizations
      },
      pagination: result.pagination
    });
  });

  /**
   * Get current organization (from subdomain/domain)
   * @route GET /api/v1/hosted-organizations/current
   */
  static getCurrentOrganization = (async (req, res, next) => {
    logger.debug('Get current organization request', {
      userId: req.user._id,
      organizationId: req.organization?._id
    });

    if (!req.organization) {
      return next(new AppError('No organization context found', 404));
    }

    res.status(200).json({
      status: 'success',
      data: {
        organization: req.organization
      }
    });
  });

  /**
   * Update organization subscription
   * @route POST /api/v1/hosted-organizations/:id/subscription
   */
  static updateSubscription = (async (req, res, next) => {
    logger.info('Update subscription request', {
      userId: req.user._id,
      organizationId: req.params.id,
      newPlan: req.body.plan?.name
    });

    const subscriptionData = {
      status: req.body.status,
      plan: req.body.plan,
      currentPeriod: req.body.currentPeriod,
      billingCycle: req.body.billingCycle
    };

    const organization = await HostedOrganizationService.updateSubscription(
      req.params.id,
      subscriptionData,
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      data: {
        organization: {
          id: organization._id,
          subscription: organization.subscription,
          platformConfig: organization.platformConfig
        }
      }
    });
  });

  /**
   * Cancel subscription
   * @route DELETE /api/v1/hosted-organizations/:id/subscription
   */
  static cancelSubscription = (async (req, res, next) => {
    logger.warn('Cancel subscription request', {
      userId: req.user._id,
      organizationId: req.params.id,
      reason: req.body.reason
    });

    const subscriptionData = {
      status: 'canceled',
      canceledAt: new Date()
    };

    const organization = await HostedOrganizationService.updateSubscription(
      req.params.id,
      subscriptionData,
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      message: 'Subscription cancelled successfully',
      data: {
        organization: {
          id: organization._id,
          subscription: organization.subscription
        }
      }
    });
  });

  /**
   * Add team member
   * @route POST /api/v1/hosted-organizations/:id/team/members
   */
  static addTeamMember = (async (req, res, next) => {
    logger.debug('Add team member request', {
      userId: req.user._id,
      organizationId: req.params.id,
      newMemberId: req.body.userId
    });

    if (!req.body.userId) {
      return next(new AppError('User ID is required', 400));
    }

    const organization = await HostedOrganizationService.addTeamMember(
      req.params.id,
      req.body.userId,
      req.body.role || 'member',
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      message: 'Team member added successfully',
      data: {
        organization: {
          id: organization._id,
          team: organization.team
        }
      }
    });
  });

  /**
   * Remove team member
   * @route DELETE /api/v1/hosted-organizations/:id/team/members/:userId
   */
  static removeTeamMember = (async (req, res, next) => {
    logger.debug('Remove team member request', {
      userId: req.user._id,
      organizationId: req.params.id,
      memberToRemove: req.params.userId
    });

    const organization = await HostedOrganizationService.removeTeamMember(
      req.params.id,
      req.params.userId,
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      message: 'Team member removed successfully',
      data: {
        organization: {
          id: organization._id,
          team: organization.team
        }
      }
    });
  });

  /**
   * Get team members
   * @route GET /api/v1/hosted-organizations/:id/team/members
   */
  static getTeamMembers = (async (req, res, next) => {
    logger.debug('Get team members request', {
      userId: req.user._id,
      organizationId: req.params.id
    });

    const organization = await HostedOrganizationService.getOrganizationById(
      req.params.id,
      { populate: 'team.admins.user owner' }
    );

    res.status(200).json({
      status: 'success',
      data: {
        team: {
          owner: organization.owner,
          admins: organization.team.admins,
          totalMembers: organization.team.totalMembers,
          activeMembers: organization.team.activeMembers
        }
      }
    });
  });

  /**
   * Update branding
   * @route PATCH /api/v1/hosted-organizations/:id/branding
   */
  static updateBranding = (async (req, res, next) => {
    logger.debug('Update branding request', {
      userId: req.user._id,
      organizationId: req.params.id
    });

    const brandingData = sanitizeInput(req.body, [
      'logo', 'favicon', 'colors', 'customCSS'
    ]);

    const organization = await HostedOrganizationService.updateBranding(
      req.params.id,
      brandingData,
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      data: {
        organization: {
          id: organization._id,
          branding: organization.branding
        }
      }
    });
  });

  /**
   * Add custom domain
   * @route POST /api/v1/hosted-organizations/:id/domains
   */
  static addCustomDomain = (async (req, res, next) => {
    logger.debug('Add custom domain request', {
      userId: req.user._id,
      organizationId: req.params.id,
      domain: req.body.domain
    });

    if (!req.body.domain) {
      return next(new AppError('Domain is required', 400));
    }

    // Validate domain format
    const domainRegex = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
    if (!domainRegex.test(req.body.domain)) {
      return next(new AppError('Invalid domain format', 400));
    }

    const result = await HostedOrganizationService.addCustomDomain(
      req.params.id,
      req.body.domain,
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      message: 'Custom domain added. Please verify ownership.',
      data: {
        domain: req.body.domain,
        verification: {
          method: result.verificationMethod,
          record: result.verificationRecord,
          value: result.verificationCode
        }
      }
    });
  });

  /**
   * Verify custom domain
   * @route POST /api/v1/hosted-organizations/:id/domains/:domain/verify
   */
  static verifyCustomDomain = (async (req, res, next) => {
    logger.debug('Verify custom domain request', {
      userId: req.user._id,
      organizationId: req.params.id,
      domain: req.params.domain
    });

    const isVerified = await HostedOrganizationService.verifyCustomDomain(
      req.params.id,
      req.params.domain
    );

    res.status(200).json({
      status: isVerified ? 'success' : 'pending',
      message: isVerified ? 'Domain verified successfully' : 'Domain verification pending',
      data: {
        domain: req.params.domain,
        verified: isVerified
      }
    });
  });

  /**
   * Get organization analytics
   * @route GET /api/v1/hosted-organizations/:id/analytics
   */
  static getOrganizationAnalytics = (async (req, res, next) => {
    logger.debug('Get organization analytics request', {
      userId: req.user._id,
      organizationId: req.params.id
    });

    const options = {
      period: req.query.period || 'last30days',
      includeHistory: req.query.includeHistory === 'true',
      includeProjections: req.query.includeProjections === 'true'
    };

    const analytics = await HostedOrganizationService.getOrganizationAnalytics(
      req.params.id,
      options
    );

    res.status(200).json({
      status: 'success',
      data: {
        analytics
      }
    });
  });

  /**
   * Get organization usage
   * @route GET /api/v1/hosted-organizations/:id/usage
   */
  static getOrganizationUsage = (async (req, res, next) => {
    logger.debug('Get organization usage request', {
      userId: req.user._id,
      organizationId: req.params.id
    });

    const organization = await HostedOrganizationService.getOrganizationById(
      req.params.id
    );

    res.status(200).json({
      status: 'success',
      data: {
        usage: {
          current: organization.usage.currentMonth,
          limits: organization.platformConfig.limits,
          percentage: organization.usagePercentage,
          historical: organization.usage.historical
        }
      }
    });
  });

  /**
   * Update organization settings
   * @route PATCH /api/v1/hosted-organizations/:id/settings
   */
  static updateSettings = (async (req, res, next) => {
    logger.debug('Update organization settings request', {
      userId: req.user._id,
      organizationId: req.params.id
    });

    const settingsData = sanitizeInput(req.body, [
      'locale', 'currency', 'dateFormat', 'timeFormat',
      'weekStart', 'fiscalYearStart', 'notifications'
    ]);

    const organization = await HostedOrganizationService.updateOrganization(
      req.params.id,
      { settings: settingsData },
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      data: {
        organization: {
          id: organization._id,
          settings: organization.settings
        }
      }
    });
  });

  /**
   * Update security settings
   * @route PATCH /api/v1/hosted-organizations/:id/security
   */
  static updateSecuritySettings = (async (req, res, next) => {
    logger.warn('Update security settings request', {
      userId: req.user._id,
      organizationId: req.params.id
    });

    const securityData = sanitizeInput(req.body, [
      'twoFactorRequired', 'ipWhitelist', 'passwordPolicy',
      'dataRetention'
    ]);

    const organization = await HostedOrganizationService.updateOrganization(
      req.params.id,
      { security: securityData },
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      data: {
        organization: {
          id: organization._id,
          security: organization.security
        }
      }
    });
  });

  // Admin Routes

  /**
   * Admin: Get all organizations
   * @route GET /api/v1/hosted-organizations/admin/all
   */
  static adminGetAllOrganizations = (async (req, res, next) => {
    logger.debug('Admin get all organizations request', {
      adminId: req.user._id
    });

    const filters = {};
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: Math.min(parseInt(req.query.limit) || 50, 200),
      sort: req.query.sort || '-createdAt'
    };

    // Admin can see inactive organizations
    if (req.query.includeInactive === 'true') {
      delete filters['status.active'];
    }

    const result = await HostedOrganizationService.searchOrganizations(
      filters,
      options
    );

    res.status(200).json({
      status: 'success',
      results: result.organizations.length,
      data: {
        organizations: result.organizations
      },
      pagination: result.pagination
    });
  });

  /**
   * Admin: Get organizations at risk
   * @route GET /api/v1/hosted-organizations/admin/at-risk
   */
  static adminGetOrganizationsAtRisk = (async (req, res, next) => {
    logger.debug('Admin get organizations at risk request', {
      adminId: req.user._id
    });

    const organizations = await HostedOrganizationService.getOrganizationsAtRisk();

    res.status(200).json({
      status: 'success',
      results: organizations.length,
      data: {
        organizations
      }
    });
  });

  /**
   * Admin: Lock organization
   * @route POST /api/v1/hosted-organizations/:id/admin/lock
   */
  static adminLockOrganization = (async (req, res, next) => {
    logger.warn('Admin lock organization request', {
      adminId: req.user._id,
      organizationId: req.params.id,
      reason: req.body.reason
    });

    if (!req.body.reason) {
      return next(new AppError('Lock reason is required', 400));
    }

    const organization = await HostedOrganizationService.updateOrganization(
      req.params.id,
      {
        'status.locked': true,
        'status.lockedReason': req.body.reason
      },
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      message: 'Organization locked successfully',
      data: {
        organization: {
          id: organization._id,
          name: organization.name,
          locked: organization.status.locked,
          lockedReason: organization.status.lockedReason
        }
      }
    });
  });

  /**
   * Admin: Unlock organization
   * @route POST /api/v1/hosted-organizations/:id/admin/unlock
   */
  static adminUnlockOrganization = (async (req, res, next) => {
    logger.info('Admin unlock organization request', {
      adminId: req.user._id,
      organizationId: req.params.id
    });

    const organization = await HostedOrganizationService.updateOrganization(
      req.params.id,
      {
        'status.locked': false,
        'status.lockedReason': null
      },
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      message: 'Organization unlocked successfully',
      data: {
        organization: {
          id: organization._id,
          name: organization.name,
          locked: organization.status.locked
        }
      }
    });
  });

  /**
   * Admin: Feature organization
   * @route POST /api/v1/hosted-organizations/:id/admin/feature
   */
  static adminFeatureOrganization = (async (req, res, next) => {
    logger.info('Admin feature organization request', {
      adminId: req.user._id,
      organizationId: req.params.id
    });

    const organization = await HostedOrganizationService.getOrganizationById(
      req.params.id
    );

    const newFeaturedStatus = !organization.status.featured;

    const updatedOrg = await HostedOrganizationService.updateOrganization(
      req.params.id,
      {
        'status.featured': newFeaturedStatus
      },
      req.user._id
    );

    res.status(200).json({
      status: 'success',
      message: `Organization ${newFeaturedStatus ? 'featured' : 'unfeatured'} successfully`,
      data: {
        organization: {
          id: updatedOrg._id,
          name: updatedOrg.name,
          featured: updatedOrg.status.featured
        }
      }
    });
  });

  /**
   * System: Process monthly usage reset
   * @route POST /api/v1/hosted-organizations/system/reset-usage
   */
  static systemResetMonthlyUsage = (async (req, res, next) => {
    logger.info('System reset monthly usage request', {
      adminId: req.user._id
    });

    await HostedOrganizationService.processMonthlyUsageReset();

    res.status(200).json({
      status: 'success',
      message: 'Monthly usage reset completed successfully'
    });
  });
}

module.exports = HostedOrganizationController;