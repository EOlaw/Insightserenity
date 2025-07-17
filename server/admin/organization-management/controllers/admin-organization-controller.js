// server/admin/organization-management/controllers/admin-organization-controller.js
/**
 * @file Admin Organization Controller
 * @description Controller for handling administrative organization operations
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const AdminOrganizationService = require('../services/admin-organization-service');
const OrganizationAnalyticsService = require('../services/organization-analytics-service');
const TenantManagementService = require('../services/tenant-management-service');
const AuditService = require('../../../shared/security/services/audit-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizer');
const ResponseFormatter = require('../../../shared/utils/response-formatter');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');

// Validation
const {
  validateOrganizationCreate,
  validateOrganizationUpdate,
  validateSuspension,
  validateOwnershipTransfer,
  validateBulkOperation
} = require('../validation/organization-management-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');

/**
 * Admin Organization Controller Class
 * @class AdminOrganizationController
 */
class AdminOrganizationController {
  /**
   * Get organizations with advanced filtering
   * @route GET /api/admin/organizations
   * @access Admin
   */
  getOrganizations = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      // Extract query parameters
      const filters = {
        search: query.search,
        status: query.status,
        subscriptionStatus: query.subscriptionStatus,
        plan: query.plan,
        createdFrom: query.createdFrom,
        createdTo: query.createdTo,
        minMembers: query.minMembers,
        maxMembers: query.maxMembers,
        verified: query.verified,
        industry: query.industry,
        country: query.country,
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 20
      };
      
      const options = {
        sort: query.sort || '-createdAt',
        includeStats: query.includeStats === 'true',
        skipCache: query.skipCache === 'true'
      };
      
      // Get organizations
      const result = await AdminOrganizationService.getOrganizations(
        filters,
        options,
        req.user
      );
      
      // Format response
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Organizations retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getOrganizations:', error);
      next(error);
    }
  });

  /**
   * Get single organization details
   * @route GET /api/admin/organizations/:id
   * @access Admin
   */
  getOrganizationById = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const options = {
        includeAnalytics: req.query.includeAnalytics === 'true',
        includeSubscription: req.query.includeSubscription === 'true',
        includeActivity: req.query.includeActivity === 'true',
        includeCompliance: req.query.includeCompliance === 'true'
      };
      
      const organization = await AdminOrganizationService.getOrganizationById(
        id,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          organization,
          'Organization retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getOrganizationById:', error);
      next(error);
    }
  });

  /**
   * Create new organization
   * @route POST /api/admin/organizations
   * @access Admin - Platform Admin or higher
   */
  createOrganization = asyncHandler(async (req, res, next) => {
    try {
      // Validate request body
      const { error, value } = validateOrganizationCreate(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const organizationData = sanitizeBody(value);
      
      const options = {
        autoVerify: req.body.autoVerify || false,
        skipNotifications: req.body.skipNotifications || false,
        setupInfrastructure: req.body.setupInfrastructure !== false
      };
      
      // Create organization
      const organization = await AdminOrganizationService.createOrganization(
        organizationData,
        req.user,
        options
      );
      
      res.status(201).json(
        ResponseFormatter.success(
          organization,
          'Organization created successfully'
        )
      );
    } catch (error) {
      logger.error('Error in createOrganization:', error);
      next(error);
    }
  });

  /**
   * Update organization
   * @route PUT /api/admin/organizations/:id
   * @access Admin
   */
  updateOrganization = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate update data
      const { error, value } = validateOrganizationUpdate(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const updates = sanitizeBody(value);
      
      const options = {
        skipNotifications: req.body.skipNotifications || false,
        validateLimits: req.body.validateLimits !== false
      };
      
      const organization = await AdminOrganizationService.updateOrganization(
        id,
        updates,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          organization,
          'Organization updated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in updateOrganization:', error);
      next(error);
    }
  });

  /**
   * Suspend organization
   * @route POST /api/admin/organizations/:id/suspend
   * @access Admin - Platform Admin or higher
   */
  suspendOrganization = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate suspension details
      const { error, value } = validateSuspension(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const suspensionDetails = sanitizeBody(value);
      
      const options = {
        maintainSessions: req.body.maintainSessions || false,
        skipNotifications: req.body.skipNotifications || false
      };
      
      const organization = await AdminOrganizationService.suspendOrganization(
        id,
        suspensionDetails,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          organization,
          'Organization suspended successfully'
        )
      );
    } catch (error) {
      logger.error('Error in suspendOrganization:', error);
      next(error);
    }
  });

  /**
   * Reactivate organization
   * @route POST /api/admin/organizations/:id/reactivate
   * @access Admin
   */
  reactivateOrganization = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const options = {
        skipNotifications: req.body.skipNotifications || false,
        restoreSessions: req.body.restoreSessions || false
      };
      
      const organization = await AdminOrganizationService.reactivateOrganization(
        id,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          organization,
          'Organization reactivated successfully'
        )
      );
    } catch (error) {
      logger.error('Error in reactivateOrganization:', error);
      next(error);
    }
  });

  /**
   * Delete organization
   * @route DELETE /api/admin/organizations/:id
   * @access Admin - Super Admin for hard delete
   */
  deleteOrganization = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const options = {
        hardDelete: req.query.hardDelete === 'true',
        createBackup: req.body.createBackup !== false,
        reason: req.body.reason || 'Administrative action',
        skipNotifications: req.body.skipNotifications || false
      };
      
      const result = await AdminOrganizationService.deleteOrganization(
        id,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Organization deleted successfully'
        )
      );
    } catch (error) {
      logger.error('Error in deleteOrganization:', error);
      next(error);
    }
  });

  /**
   * Transfer organization ownership
   * @route POST /api/admin/organizations/:id/transfer-ownership
   * @access Admin - Platform Admin or higher
   */
  transferOwnership = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      // Validate transfer details
      const { error, value } = validateOwnershipTransfer(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const { newOwnerId, reason } = sanitizeBody(value);
      
      const options = {
        reason,
        skipNotifications: req.body.skipNotifications || false,
        validateNewOwner: req.body.validateNewOwner !== false
      };
      
      const organization = await AdminOrganizationService.transferOwnership(
        id,
        newOwnerId,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          organization,
          'Ownership transferred successfully'
        )
      );
    } catch (error) {
      logger.error('Error in transferOwnership:', error);
      next(error);
    }
  });

  /**
   * Bulk suspend organizations
   * @route POST /api/admin/organizations/bulk/suspend
   * @access Admin - Platform Admin or higher
   */
  bulkSuspend = asyncHandler(async (req, res, next) => {
    try {
      // Validate bulk operation
      const { error, value } = validateBulkOperation(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const { organizationIds, reason } = sanitizeBody(value);
      
      const options = {
        skipNotifications: req.body.skipNotifications || false,
        maintainSessions: req.body.maintainSessions || false
      };
      
      const result = await AdminOrganizationService.bulkSuspendOrganizations(
        organizationIds,
        reason,
        req.user,
        options
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Bulk suspension completed'
        )
      );
    } catch (error) {
      logger.error('Error in bulkSuspend:', error);
      next(error);
    }
  });

  /**
   * Bulk activate organizations
   * @route POST /api/admin/organizations/bulk/activate
   * @access Admin
   */
  bulkActivate = asyncHandler(async (req, res, next) => {
    try {
      // Validate bulk operation
      const { error, value } = validateBulkOperation(req.body);
      if (error) {
        throw new ValidationError(error.details[0].message);
      }
      
      const { organizationIds } = sanitizeBody(value);
      
      const options = {
        skipNotifications: req.body.skipNotifications || false
      };
      
      const results = {
        successful: [],
        failed: [],
        total: organizationIds.length
      };
      
      // Process activations
      for (const orgId of organizationIds) {
        try {
          await AdminOrganizationService.reactivateOrganization(
            orgId,
            req.user,
            options
          );
          results.successful.push(orgId);
        } catch (error) {
          results.failed.push({
            organizationId: orgId,
            error: error.message
          });
        }
      }
      
      res.status(200).json(
        ResponseFormatter.success(
          results,
          'Bulk activation completed'
        )
      );
    } catch (error) {
      logger.error('Error in bulkActivate:', error);
      next(error);
    }
  });

  /**
   * Export organizations
   * @route GET /api/admin/organizations/export
   * @access Admin
   */
  exportOrganizations = asyncHandler(async (req, res, next) => {
    try {
      const query = sanitizeQuery(req.query);
      
      const exportConfig = {
        format: query.format || 'csv',
        fields: query.fields ? query.fields.split(',') : null,
        filters: {
          status: query.status,
          plan: query.plan,
          createdFrom: query.createdFrom,
          createdTo: query.createdTo
        },
        includeRelated: query.includeRelated === 'true'
      };
      
      // Generate export
      const exportData = await AdminOrganizationService.exportOrganizations(
        exportConfig,
        req.user
      );
      
      // Set appropriate headers
      const filename = `organizations_export_${Date.now()}.${exportConfig.format}`;
      res.setHeader('Content-Type', exportData.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      
      // Send export data
      res.send(exportData.data);
    } catch (error) {
      logger.error('Error in exportOrganizations:', error);
      next(error);
    }
  });

  /**
   * Import organizations
   * @route POST /api/admin/organizations/import
   * @access Admin - Super Admin only
   */
  importOrganizations = asyncHandler(async (req, res, next) => {
    try {
      if (!req.file) {
        throw new ValidationError('Import file is required');
      }
      
      const importConfig = {
        file: req.file,
        format: req.body.format || 'csv',
        mapping: req.body.mapping ? JSON.parse(req.body.mapping) : null,
        options: {
          validateOnly: req.body.validateOnly === 'true',
          updateExisting: req.body.updateExisting === 'true',
          skipErrors: req.body.skipErrors === 'true'
        }
      };
      
      const result = await AdminOrganizationService.importOrganizations(
        importConfig,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Import completed'
        )
      );
    } catch (error) {
      logger.error('Error in importOrganizations:', error);
      next(error);
    }
  });

  /**
   * Get organization analytics
   * @route GET /api/admin/organizations/:id/analytics
   * @access Admin
   */
  getOrganizationAnalytics = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      const query = sanitizeQuery(req.query);
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const options = {
        period: query.period || 'month',
        startDate: query.startDate,
        endDate: query.endDate,
        metrics: query.metrics ? query.metrics.split(',') : null,
        forceRefresh: query.forceRefresh === 'true'
      };
      
      const analytics = await OrganizationAnalyticsService.getOrganizationAnalytics(
        id,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          analytics,
          'Analytics retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getOrganizationAnalytics:', error);
      next(error);
    }
  });

  /**
   * Get organization health check
   * @route GET /api/admin/organizations/:id/health
   * @access Admin
   */
  getOrganizationHealth = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const health = await TenantManagementService.monitorTenantHealth(
        id,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          health,
          'Health check completed'
        )
      );
    } catch (error) {
      logger.error('Error in getOrganizationHealth:', error);
      next(error);
    }
  });

  /**
   * Search organizations
   * @route POST /api/admin/organizations/search
   * @access Admin
   */
  searchOrganizations = asyncHandler(async (req, res, next) => {
    try {
      const searchConfig = sanitizeBody(req.body);
      
      const options = {
        fuzzy: searchConfig.fuzzy !== false,
        limit: searchConfig.limit || 20,
        fields: searchConfig.fields || ['name', 'email', 'tenantCode']
      };
      
      const results = await AdminOrganizationService.searchOrganizations(
        searchConfig.query,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          results,
          'Search completed'
        )
      );
    } catch (error) {
      logger.error('Error in searchOrganizations:', error);
      next(error);
    }
  });

  /**
   * Get organization activity log
   * @route GET /api/admin/organizations/:id/activity
   * @access Admin
   */
  getOrganizationActivity = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      const query = sanitizeQuery(req.query);
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const filters = {
        startDate: query.startDate,
        endDate: query.endDate,
        type: query.type,
        userId: query.userId,
        page: parseInt(query.page) || 1,
        limit: parseInt(query.limit) || 50
      };
      
      const activity = await AuditService.getOrganizationActivity(
        id,
        filters
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          activity,
          'Activity log retrieved successfully'
        )
      );
    } catch (error) {
      logger.error('Error in getOrganizationActivity:', error);
      next(error);
    }
  });

  /**
   * Clone organization
   * @route POST /api/admin/organizations/:id/clone
   * @access Admin - Super Admin only
   */
  cloneOrganization = asyncHandler(async (req, res, next) => {
    try {
      const { id } = req.params;
      
      if (!mongoose.isValidObjectId(id)) {
        throw new ValidationError('Invalid organization ID');
      }
      
      const cloneConfig = sanitizeBody(req.body);
      
      const options = {
        newName: cloneConfig.name,
        cloneData: cloneConfig.cloneData !== false,
        cloneUsers: cloneConfig.cloneUsers || false,
        cloneConfiguration: cloneConfig.cloneConfiguration !== false
      };
      
      const clonedOrganization = await AdminOrganizationService.cloneOrganization(
        id,
        options,
        req.user
      );
      
      res.status(201).json(
        ResponseFormatter.success(
          clonedOrganization,
          'Organization cloned successfully'
        )
      );
    } catch (error) {
      logger.error('Error in cloneOrganization:', error);
      next(error);
    }
  });

  /**
   * Merge organizations
   * @route POST /api/admin/organizations/merge
   * @access Admin - Super Admin only
   */
  mergeOrganizations = asyncHandler(async (req, res, next) => {
    try {
      const mergeConfig = sanitizeBody(req.body);
      
      if (!mergeConfig.sourceId || !mergeConfig.targetId) {
        throw new ValidationError('Source and target organization IDs are required');
      }
      
      const options = {
        mergeUsers: mergeConfig.mergeUsers !== false,
        mergeData: mergeConfig.mergeData !== false,
        mergeSubscriptions: mergeConfig.mergeSubscriptions || false,
        keepSource: mergeConfig.keepSource || false
      };
      
      const result = await AdminOrganizationService.mergeOrganizations(
        mergeConfig.sourceId,
        mergeConfig.targetId,
        options,
        req.user
      );
      
      res.status(200).json(
        ResponseFormatter.success(
          result,
          'Organizations merged successfully'
        )
      );
    } catch (error) {
      logger.error('Error in mergeOrganizations:', error);
      next(error);
    }
  });
}

module.exports = new AdminOrganizationController();