/**
 * @file Organization Tenant Controller
 * @description HTTP request handlers for organization tenant management
 * @version 1.0.0
 */

const OrganizationTenantService = require('../services/organization-tenant-service');
const { AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { TENANT_CONSTANTS } = require('../constants/tenant-constants');

/**
 * Organization Tenant Controller Class
 * @class OrganizationTenantController
 */
class OrganizationTenantController {
  /**
   * Create a new organization tenant
   * @route POST /api/v1/organization-tenants
   * @access Private - Platform Admin
   */
  static createTenant = async (req, res, next) => {
    try {
      logger.info('Create tenant request received', {
        userId: req.user._id,
        tenantName: req.body.name
      });

      const tenant = await OrganizationTenantService.createTenant(
        req.body,
        req.user._id
      );

      res.status(201).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.TENANT_CREATED,
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Create tenant request failed', {
        error,
        userId: req.user._id
      });
      next(error);
    }
  };

  /**
   * Get tenant by ID
   * @route GET /api/v1/organization-tenants/:id
   * @access Private - Tenant Owner/Admin or Platform Admin
   */
  static getTenantById = async (req, res, next) => {
    try {
      logger.debug('Get tenant by ID request', {
        userId: req.user._id,
        tenantId: req.params.id
      });

      const options = {
        populate: req.query.populate?.split(',') || [],
        select: req.query.select,
        bypassCache: req.query.bypassCache === 'true'
      };

      const tenant = await OrganizationTenantService.getTenantById(
        req.params.id,
        options
      );

      res.status(200).json({
        status: 'success',
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Get tenant by ID request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get tenant by code
   * @route GET /api/v1/organization-tenants/code/:code
   * @access Private - Tenant Member or Platform Admin
   */
  static getTenantByCode = async (req, res, next) => {
    try {
      logger.debug('Get tenant by code request', {
        userId: req.user._id,
        tenantCode: req.params.code
      });

      const options = {
        populate: req.query.populate?.split(',') || [],
        select: req.query.select,
        bypassCache: req.query.bypassCache === 'true'
      };

      const tenant = await OrganizationTenantService.getTenantByCode(
        req.params.code,
        options
      );

      res.status(200).json({
        status: 'success',
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Get tenant by code request failed', {
        error,
        userId: req.user._id,
        tenantCode: req.params.code
      });
      next(error);
    }
  };

  /**
   * Get current tenant (from context)
   * @route GET /api/v1/organization-tenants/current
   * @access Private - Any authenticated user with tenant context
   */
  static getCurrentTenant = async (req, res, next) => {
    try {
      logger.debug('Get current tenant request', {
        userId: req.user._id,
        tenantId: req.tenantId
      });

      if (!req.tenantId) {
        throw new AppError('No tenant context found', 400);
      }

      const tenant = await OrganizationTenantService.getTenantById(
        req.tenantId,
        { populate: ['owner'] }
      );

      res.status(200).json({
        status: 'success',
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Get current tenant request failed', {
        error,
        userId: req.user._id
      });
      next(error);
    }
  };

  /**
   * Update tenant
   * @route PATCH /api/v1/organization-tenants/:id
   * @access Private - Tenant Owner/Admin or Platform Admin
   */
  static updateTenant = async (req, res, next) => {
    try {
      logger.info('Update tenant request received', {
        userId: req.user._id,
        tenantId: req.params.id
      });

      const tenant = await OrganizationTenantService.updateTenant(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.TENANT_UPDATED,
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Update tenant request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Activate tenant
   * @route POST /api/v1/organization-tenants/:id/activate
   * @access Private - Platform Admin
   */
  static activateTenant = async (req, res, next) => {
    try {
      logger.info('Activate tenant request received', {
        userId: req.user._id,
        tenantId: req.params.id
      });

      const tenant = await OrganizationTenantService.activateTenant(
        req.params.id,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.TENANT_ACTIVATED,
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Activate tenant request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Suspend tenant
   * @route POST /api/v1/organization-tenants/:id/suspend
   * @access Private - Platform Admin
   */
  static suspendTenant = async (req, res, next) => {
    try {
      logger.info('Suspend tenant request received', {
        userId: req.user._id,
        tenantId: req.params.id,
        reason: req.body.reason
      });

      const tenant = await OrganizationTenantService.suspendTenant(
        req.params.id,
        req.body.reason,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.TENANT_SUSPENDED,
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Suspend tenant request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Search tenants
   * @route GET /api/v1/organization-tenants/search
   * @access Private - Platform Admin
   */
  static searchTenants = async (req, res, next) => {
    try {
      logger.debug('Search tenants request', {
        userId: req.user._id,
        filters: req.query
      });

      const filters = {
        status: req.query.status,
        plan: req.query.plan,
        size: req.query.size,
        industry: req.query.industry,
        search: req.query.search,
        createdAfter: req.query.createdAfter,
        createdBefore: req.query.createdBefore,
        features: req.query.features ? JSON.parse(req.query.features) : undefined,
        flags: req.query.flags ? JSON.parse(req.query.flags) : undefined
      };

      const options = {
        page: parseInt(req.query.page) || 1,
        limit: parseInt(req.query.limit) || 20,
        sort: req.query.sort || '-createdAt',
        populate: req.query.populate?.split(',') || [],
        select: req.query.select
      };

      const results = await OrganizationTenantService.searchTenants(filters, options);

      res.status(200).json({
        status: 'success',
        data: results
      });

    } catch (error) {
      logger.error('Search tenants request failed', {
        error,
        userId: req.user._id
      });
      next(error);
    }
  };

  /**
   * Get tenant statistics
   * @route GET /api/v1/organization-tenants/statistics
   * @access Private - Platform Admin
   */
  static getTenantStatistics = async (req, res, next) => {
    try {
      logger.debug('Get tenant statistics request', {
        userId: req.user._id
      });

      const filters = {
        bypassCache: req.query.bypassCache === 'true'
      };

      const statistics = await OrganizationTenantService.getTenantStatistics(filters);

      res.status(200).json({
        status: 'success',
        data: {
          statistics
        }
      });

    } catch (error) {
      logger.error('Get tenant statistics request failed', {
        error,
        userId: req.user._id
      });
      next(error);
    }
  };

  /**
   * Update subscription
   * @route POST /api/v1/organization-tenants/:id/subscription
   * @access Private - Tenant Owner or Platform Admin
   */
  static updateSubscription = async (req, res, next) => {
    try {
      logger.info('Update subscription request received', {
        userId: req.user._id,
        tenantId: req.params.id,
        subscriptionData: req.body
      });

      const tenant = await OrganizationTenantService.updateSubscription(
        req.params.id,
        req.body,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.SUBSCRIPTION_UPDATED,
        data: {
          tenant
        }
      });

    } catch (error) {
      logger.error('Update subscription request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Add custom domain
   * @route POST /api/v1/organization-tenants/:id/domains
   * @access Private - Tenant Owner/Admin
   */
  static addCustomDomain = async (req, res, next) => {
    try {
      logger.info('Add custom domain request received', {
        userId: req.user._id,
        tenantId: req.params.id,
        domain: req.body.domain
      });

      const domain = await OrganizationTenantService.addCustomDomain(
        req.params.id,
        req.body.domain,
        req.user._id
      );

      res.status(201).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.DOMAIN_ADDED,
        data: {
          domain
        }
      });

    } catch (error) {
      logger.error('Add custom domain request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Verify custom domain
   * @route POST /api/v1/organization-tenants/:id/domains/:domain/verify
   * @access Private - Tenant Owner/Admin
   */
  static verifyCustomDomain = async (req, res, next) => {
    try {
      logger.info('Verify custom domain request received', {
        userId: req.user._id,
        tenantId: req.params.id,
        domain: req.params.domain
      });

      const isVerified = await OrganizationTenantService.verifyCustomDomain(
        req.params.id,
        req.params.domain
      );

      res.status(200).json({
        status: isVerified ? 'success' : 'pending',
        message: isVerified ? TENANT_CONSTANTS.SUCCESS_MESSAGES.DOMAIN_VERIFIED : 'Domain verification pending',
        data: {
          domain: req.params.domain,
          verified: isVerified
        }
      });

    } catch (error) {
      logger.error('Verify custom domain request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get tenant usage
   * @route GET /api/v1/organization-tenants/:id/usage
   * @access Private - Tenant Owner/Admin or Platform Admin
   */
  static getTenantUsage = async (req, res, next) => {
    try {
      logger.debug('Get tenant usage request', {
        userId: req.user._id,
        tenantId: req.params.id
      });

      const usage = await OrganizationTenantService.getTenantUsage(req.params.id);

      res.status(200).json({
        status: 'success',
        data: {
          usage
        }
      });

    } catch (error) {
      logger.error('Get tenant usage request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update settings
   * @route PATCH /api/v1/organization-tenants/:id/settings
   * @access Private - Tenant Owner/Admin
   */
  static updateSettings = async (req, res, next) => {
    try {
      logger.info('Update settings request received', {
        userId: req.user._id,
        tenantId: req.params.id
      });

      const updateData = {
        settings: req.body
      };

      const tenant = await OrganizationTenantService.updateTenant(
        req.params.id,
        updateData,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.SETTINGS_UPDATED,
        data: {
          settings: tenant.settings
        }
      });

    } catch (error) {
      logger.error('Update settings request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update security settings
   * @route PATCH /api/v1/organization-tenants/:id/security
   * @access Private - Tenant Owner
   */
  static updateSecuritySettings = async (req, res, next) => {
    try {
      logger.info('Update security settings request received', {
        userId: req.user._id,
        tenantId: req.params.id
      });

      const updateData = {
        'settings.security': req.body
      };

      const tenant = await OrganizationTenantService.updateTenant(
        req.params.id,
        updateData,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Security settings updated successfully',
        data: {
          security: tenant.settings.security
        }
      });

    } catch (error) {
      logger.error('Update security settings request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update branding
   * @route PATCH /api/v1/organization-tenants/:id/branding
   * @access Private - Tenant Admin
   */
  static updateBranding = async (req, res, next) => {
    try {
      logger.info('Update branding request received', {
        userId: req.user._id,
        tenantId: req.params.id
      });

      const updateData = {
        branding: req.body
      };

      const tenant = await OrganizationTenantService.updateTenant(
        req.params.id,
        updateData,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: 'Branding updated successfully',
        data: {
          branding: tenant.branding
        }
      });

    } catch (error) {
      logger.error('Update branding request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Update resource limits (Platform Admin only)
   * @route PATCH /api/v1/organization-tenants/:id/limits
   * @access Private - Platform Admin
   */
  static updateResourceLimits = async (req, res, next) => {
    try {
      logger.info('Update resource limits request received', {
        userId: req.user._id,
        tenantId: req.params.id,
        limits: req.body
      });

      const updateData = {
        resourceLimits: req.body
      };

      const tenant = await OrganizationTenantService.updateTenant(
        req.params.id,
        updateData,
        req.user._id
      );

      res.status(200).json({
        status: 'success',
        message: TENANT_CONSTANTS.SUCCESS_MESSAGES.LIMITS_UPDATED,
        data: {
          resourceLimits: tenant.resourceLimits
        }
      });

    } catch (error) {
      logger.error('Update resource limits request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Export tenant data
   * @route GET /api/v1/organization-tenants/:id/export
   * @access Private - Tenant Owner or Platform Admin
   */
  static exportTenantData = async (req, res, next) => {
    try {
      logger.info('Export tenant data request received', {
        userId: req.user._id,
        tenantId: req.params.id,
        format: req.query.format
      });

      // Implementation would depend on your export requirements
      // This is a placeholder
      const tenant = await OrganizationTenantService.getTenantById(
        req.params.id,
        { populate: ['owner', 'admins'] }
      );

      // Remove sensitive data
      delete tenant.database.connectionString;
      delete tenant.database.encryptionKey;

      const format = req.query.format || 'json';

      if (format === 'json') {
        res.status(200).json({
          status: 'success',
          data: {
            tenant,
            exportedAt: new Date(),
            exportedBy: req.user._id
          }
        });
      } else {
        // Handle other formats (CSV, PDF, etc.)
        throw new AppError('Export format not supported', 400);
      }

    } catch (error) {
      logger.error('Export tenant data request failed', {
        error,
        userId: req.user._id,
        tenantId: req.params.id
      });
      next(error);
    }
  };

  /**
   * Get tenants by owner
   * @route GET /api/v1/organization-tenants/owner/:ownerId
   * @access Private - Owner or Platform Admin
   */
  static getTenantsByOwner = async (req, res, next) => {
    try {
      logger.debug('Get tenants by owner request', {
        userId: req.user._id,
        ownerId: req.params.ownerId
      });

      // Verify access
      if (req.user._id.toString() !== req.params.ownerId && 
          !req.user.roles.includes('admin') && 
          !req.user.roles.includes('super_admin')) {
        throw new AppError('Access denied', 403);
      }

      const filters = { owner: req.params.ownerId };
      const options = {
        page: parseInt(req.query.page) || 1,
        limit: parseInt(req.query.limit) || 10,
        sort: req.query.sort || '-createdAt'
      };

      const results = await OrganizationTenantService.searchTenants(filters, options);

      res.status(200).json({
        status: 'success',
        data: results
      });

    } catch (error) {
      logger.error('Get tenants by owner request failed', {
        error,
        userId: req.user._id,
        ownerId: req.params.ownerId
      });
      next(error);
    }
  };

  /**
   * Health check
   * @route GET /api/v1/organization-tenants/health
   * @access Public
   */
  static healthCheck = async (req, res, next) => {
    try {
      res.status(200).json({
        status: 'success',
        service: 'organization-tenants',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    } catch (error) {
      next(error);
    }
  };
}

module.exports = OrganizationTenantController;