// server/admin/super-admin/controllers/role-management-controller.js
/**
 * @file Role Management Controller
 * @description Controller for system-wide role and permission management
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const RoleManagementService = require('../services/role-management-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ConflictError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const ResponseHandler = require('../../../shared/utils/response-handler');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');

// Validation
const { validateRequest } = require('../../../shared/middleware/validate-request');
const RoleManagementValidation = require('../validation/role-management-validation');

/**
 * Role Management Controller Class
 * @class RoleManagementController
 */
class RoleManagementController {
  /**
   * Get all roles
   * @route GET /api/admin/super-admin/roles
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getAllRoles(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        page = 1,
        limit = 20,
        search,
        category,
        includeSystem = 'true',
        includeCustom = 'true',
        sortBy = 'priority',
        sortOrder = 'asc'
      } = req.query;

      logger.info('Get all roles requested', {
        adminId: adminUser.id,
        filters: { search, category, includeSystem, includeCustom }
      });

      const result = await RoleManagementService.getAllRoles(adminUser, {
        page: parseInt(page),
        limit: parseInt(limit),
        search,
        category,
        includeSystem: includeSystem === 'true',
        includeCustom: includeCustom === 'true',
        sortBy,
        sortOrder
      });

      ResponseHandler.success(res, {
        message: 'Roles retrieved successfully',
        data: result.roles,
        pagination: result.pagination,
        metadata: result.metadata
      });

    } catch (error) {
      logger.error('Get all roles error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get role details
   * @route GET /api/admin/super-admin/roles/:roleId
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getRoleDetails(req, res, next) {
    try {
      const adminUser = req.user;
      const { roleId } = req.params;

      logger.info('Get role details requested', {
        adminId: adminUser.id,
        roleId
      });

      const roleDetails = await RoleManagementService.getRoleDetails(adminUser, roleId);

      ResponseHandler.success(res, {
        message: 'Role details retrieved successfully',
        data: roleDetails
      });

    } catch (error) {
      logger.error('Get role details error', {
        error: error.message,
        adminId: req.user?.id,
        roleId: req.params?.roleId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Create new role
   * @route POST /api/admin/super-admin/roles
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async createRole(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.createRole, req);

      const adminUser = req.user;
      const roleData = req.body;

      logger.info('Create role requested', {
        adminId: adminUser.id,
        roleName: roleData.name,
        category: roleData.category
      });

      const result = await RoleManagementService.createRole(adminUser, roleData);

      ResponseHandler.success(res, {
        message: result.message,
        data: result.role,
        metadata: {
          warnings: result.warnings
        }
      }, 201);

    } catch (error) {
      logger.error('Create role error', {
        error: error.message,
        adminId: req.user?.id,
        roleName: req.body?.name,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Update existing role
   * @route PUT /api/admin/super-admin/roles/:roleId
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async updateRole(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.updateRole, req);

      const adminUser = req.user;
      const { roleId } = req.params;
      const updateData = req.body;

      logger.info('Update role requested', {
        adminId: adminUser.id,
        roleId,
        updates: Object.keys(updateData)
      });

      const result = await RoleManagementService.updateRole(adminUser, roleId, updateData);

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          role: result.role,
          changes: result.changes,
          affectedUsers: result.affectedUsers
        }
      });

    } catch (error) {
      logger.error('Update role error', {
        error: error.message,
        adminId: req.user?.id,
        roleId: req.params?.roleId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Delete role
   * @route DELETE /api/admin/super-admin/roles/:roleId
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async deleteRole(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.deleteRole, req);

      const adminUser = req.user;
      const { roleId } = req.params;
      const { reassignTo, force = false, reason } = req.body;

      logger.warn('Delete role requested', {
        adminId: adminUser.id,
        roleId,
        reassignTo,
        force
      });

      const result = await RoleManagementService.deleteRole(adminUser, roleId, {
        reassignTo,
        force,
        reason
      });

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          deletedRole: result.deletedRole,
          reassignedUsers: result.reassignedUsers
        }
      });

    } catch (error) {
      logger.error('Delete role error', {
        error: error.message,
        adminId: req.user?.id,
        roleId: req.params?.roleId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Clone existing role
   * @route POST /api/admin/super-admin/roles/:roleId/clone
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async cloneRole(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.cloneRole, req);

      const adminUser = req.user;
      const { roleId } = req.params;
      const cloneData = req.body;

      logger.info('Clone role requested', {
        adminId: adminUser.id,
        sourceRoleId: roleId,
        newRoleName: cloneData.name
      });

      const result = await RoleManagementService.cloneRole(adminUser, roleId, cloneData);

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          role: result.role,
          source: result.source
        }
      }, 201);

    } catch (error) {
      logger.error('Clone role error', {
        error: error.message,
        adminId: req.user?.id,
        sourceRoleId: req.params?.roleId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Bulk assign role to users
   * @route POST /api/admin/super-admin/roles/:roleId/bulk-assign
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async bulkAssignRole(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.bulkAssignRole, req);

      const adminUser = req.user;
      const { roleId } = req.params;
      const { userIds, notifyUsers = true, reason, effectiveDate, expiryDate } = req.body;

      logger.warn('Bulk assign role requested', {
        adminId: adminUser.id,
        roleId,
        userCount: userIds.length
      });

      const result = await RoleManagementService.bulkAssignRole(
        adminUser,
        roleId,
        userIds,
        {
          notifyUsers,
          reason,
          effectiveDate,
          expiryDate
        }
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          role: result.role,
          results: result.results,
          summary: result.summary
        }
      }, 201);

    } catch (error) {
      logger.error('Bulk assign role error', {
        error: error.message,
        adminId: req.user?.id,
        roleId: req.params?.roleId,
        userCount: req.body?.userIds?.length,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get role permissions
   * @route GET /api/admin/super-admin/roles/:roleId/permissions
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getRolePermissions(req, res, next) {
    try {
      const adminUser = req.user;
      const { roleId } = req.params;
      const { format = 'tree', includeInherited = 'true' } = req.query;

      logger.info('Get role permissions requested', {
        adminId: adminUser.id,
        roleId,
        format
      });

      const permissions = await RoleManagementService.getRolePermissions(adminUser, roleId, {
        format,
        includeInherited: includeInherited === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Role permissions retrieved successfully',
        data: permissions
      });

    } catch (error) {
      logger.error('Get role permissions error', {
        error: error.message,
        adminId: req.user?.id,
        roleId: req.params?.roleId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Update role permissions
   * @route PUT /api/admin/super-admin/roles/:roleId/permissions
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async updateRolePermissions(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.updatePermissions, req);

      const adminUser = req.user;
      const { roleId } = req.params;
      const { permissions, operation = 'replace' } = req.body;

      logger.warn('Update role permissions requested', {
        adminId: adminUser.id,
        roleId,
        operation,
        permissionCount: permissions.length
      });

      const result = await RoleManagementService.updateRolePermissions(
        adminUser,
        roleId,
        permissions,
        operation
      );

      ResponseHandler.success(res, {
        message: 'Role permissions updated successfully',
        data: {
          role: result.role,
          changes: result.changes,
          affectedUsers: result.affectedUsers
        }
      });

    } catch (error) {
      logger.error('Update role permissions error', {
        error: error.message,
        adminId: req.user?.id,
        roleId: req.params?.roleId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get role assignment history
   * @route GET /api/admin/super-admin/roles/assignment-history
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getRoleAssignmentHistory(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        roleId,
        userId,
        startDate,
        endDate,
        page = 1,
        limit = 50
      } = req.query;

      logger.info('Get role assignment history requested', {
        adminId: adminUser.id,
        filters: { roleId, userId }
      });

      const history = await RoleManagementService.getRoleAssignmentHistory(adminUser, {
        roleId,
        userId,
        startDate: startDate ? new Date(startDate) : undefined,
        endDate: endDate ? new Date(endDate) : undefined,
        page: parseInt(page),
        limit: parseInt(limit)
      });

      ResponseHandler.success(res, {
        message: 'Assignment history retrieved successfully',
        data: history.history,
        pagination: history.pagination
      });

    } catch (error) {
      logger.error('Get role assignment history error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get available permissions
   * @route GET /api/admin/super-admin/permissions
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getAvailablePermissions(req, res, next) {
    try {
      const adminUser = req.user;
      const { category, search, format = 'list' } = req.query;

      logger.info('Get available permissions requested', {
        adminId: adminUser.id,
        category,
        search
      });

      const permissions = await RoleManagementService.getAvailablePermissions(adminUser, {
        category,
        search,
        format
      });

      ResponseHandler.success(res, {
        message: 'Permissions retrieved successfully',
        data: permissions
      });

    } catch (error) {
      logger.error('Get available permissions error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Create custom permission
   * @route POST /api/admin/super-admin/permissions
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async createPermission(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.createPermission, req);

      const adminUser = req.user;
      const permissionData = req.body;

      logger.info('Create permission requested', {
        adminId: adminUser.id,
        resource: permissionData.resource,
        actions: permissionData.actions
      });

      const permission = await RoleManagementService.createPermission(adminUser, permissionData);

      ResponseHandler.success(res, {
        message: 'Permission created successfully',
        data: permission
      }, 201);

    } catch (error) {
      logger.error('Create permission error', {
        error: error.message,
        adminId: req.user?.id,
        resource: req.body?.resource,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Analyze role usage
   * @route GET /api/admin/super-admin/roles/:roleId/analysis
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async analyzeRoleUsage(req, res, next) {
    try {
      const adminUser = req.user;
      const { roleId } = req.params;
      const { period = '30d', includeRecommendations = 'true' } = req.query;

      logger.info('Analyze role usage requested', {
        adminId: adminUser.id,
        roleId,
        period
      });

      const analysis = await RoleManagementService.analyzeRoleUsage(adminUser, roleId, {
        period,
        includeRecommendations: includeRecommendations === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Role analysis completed successfully',
        data: analysis
      });

    } catch (error) {
      logger.error('Analyze role usage error', {
        error: error.message,
        adminId: req.user?.id,
        roleId: req.params?.roleId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get role hierarchy
   * @route GET /api/admin/super-admin/roles/hierarchy
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getRoleHierarchy(req, res, next) {
    try {
      const adminUser = req.user;
      const { format = 'tree', includeUsers = 'false' } = req.query;

      logger.info('Get role hierarchy requested', {
        adminId: adminUser.id,
        format,
        includeUsers
      });

      const hierarchy = await RoleManagementService.getRoleHierarchy(adminUser, {
        format,
        includeUsers: includeUsers === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Role hierarchy retrieved successfully',
        data: hierarchy
      });

    } catch (error) {
      logger.error('Get role hierarchy error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Merge roles
   * @route POST /api/admin/super-admin/roles/merge
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async mergeRoles(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.mergeRoles, req);

      const adminUser = req.user;
      const { sourceRoles, targetRole, mergeOptions } = req.body;

      logger.warn('Merge roles requested', {
        adminId: adminUser.id,
        sourceRoles,
        targetRole
      });

      const result = await RoleManagementService.mergeRoles(
        adminUser,
        sourceRoles,
        targetRole,
        mergeOptions
      );

      ResponseHandler.success(res, {
        message: 'Roles merged successfully',
        data: result
      });

    } catch (error) {
      logger.error('Merge roles error', {
        error: error.message,
        adminId: req.user?.id,
        sourceRoles: req.body?.sourceRoles,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Export roles configuration
   * @route GET /api/admin/super-admin/roles/export
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async exportRoles(req, res, next) {
    try {
      const adminUser = req.user;
      const { 
        format = 'json',
        includePermissions = 'true',
        includeUsers = 'false',
        roleIds 
      } = req.query;

      logger.info('Export roles requested', {
        adminId: adminUser.id,
        format,
        roleCount: roleIds ? roleIds.split(',').length : 'all'
      });

      const exportData = await RoleManagementService.exportRoles(adminUser, {
        format,
        includePermissions: includePermissions === 'true',
        includeUsers: includeUsers === 'true',
        roleIds: roleIds ? roleIds.split(',') : null
      });

      if (req.query.download === 'true') {
        res.setHeader('Content-Type', exportData.contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${exportData.filename}"`);
        return res.send(exportData.data);
      }

      ResponseHandler.success(res, {
        message: 'Roles exported successfully',
        data: {
          filename: exportData.filename,
          size: exportData.size,
          downloadUrl: exportData.downloadUrl
        }
      });

    } catch (error) {
      logger.error('Export roles error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Import roles configuration
   * @route POST /api/admin/super-admin/roles/import
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async importRoles(req, res, next) {
    try {
      await validateRequest(RoleManagementValidation.importRoles, req);

      const adminUser = req.user;
      const { data, options = {} } = req.body;

      logger.warn('Import roles requested', {
        adminId: adminUser.id,
        options
      });

      const result = await RoleManagementService.importRoles(adminUser, data, options);

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          imported: result.imported,
          skipped: result.skipped,
          errors: result.errors,
          summary: result.summary
        }
      }, 201);

    } catch (error) {
      logger.error('Import roles error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Validate role configuration
   * @route POST /api/admin/super-admin/roles/validate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async validateRoleConfiguration(req, res, next) {
    try {
      const adminUser = req.user;
      const { roleData, checkConflicts = true } = req.body;

      logger.info('Validate role configuration requested', {
        adminId: adminUser.id,
        roleName: roleData.name
      });

      const validation = await RoleManagementService.validateRoleConfiguration(
        adminUser,
        roleData,
        { checkConflicts }
      );

      ResponseHandler.success(res, {
        message: 'Role configuration validated',
        data: validation
      });

    } catch (error) {
      logger.error('Validate role configuration error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }
}

module.exports = new RoleManagementController();