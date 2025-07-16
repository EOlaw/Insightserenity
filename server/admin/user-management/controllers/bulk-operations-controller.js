// server/admin/user-management/controllers/bulk-operations-controller.js
/**
 * @file Bulk Operations Controller
 * @description Controller for handling bulk user operations
 * @version 1.0.0
 */

// Services
const BulkOperationsService = require('../services/bulk-operations-service');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');

// Utilities
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizers');
const ResponseFormatter = require('../../../shared/utils/response-formatter');
const FileUploadHelper = require('../../../shared/utils/file-upload-helper');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Bulk Operations Controller Class
 */
class BulkOperationsController {
  /**
   * Initiate bulk user import
   * @route POST /api/admin/users/bulk/import
   */
  initiateUserImport = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    
    // Check for file upload
    if (!req.file) {
      throw new ValidationError('Import file is required');
    }

    // Validate file type
    const allowedMimeTypes = ['text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'];
    if (!allowedMimeTypes.includes(req.file.mimetype)) {
      throw new ValidationError('Invalid file type. Only CSV and Excel files are allowed');
    }

    // Check file size
    if (req.file.size > AdminLimits.FILE_UPLOAD.MAX_IMPORT_SIZE) {
      throw new ValidationError(`File size exceeds maximum limit of ${AdminLimits.FILE_UPLOAD.MAX_IMPORT_SIZE / 1024 / 1024}MB`);
    }

    // Parse import options from body
    const importData = sanitizeBody(req.body);
    
    // Validate mappings
    if (!importData.mappings || typeof importData.mappings !== 'object') {
      throw new ValidationError('Field mappings are required');
    }

    // Required field mappings
    const requiredMappings = ['email'];
    const missingMappings = requiredMappings.filter(field => !importData.mappings[field]);
    
    if (missingMappings.length > 0) {
      throw new ValidationError(`Missing required field mappings: ${missingMappings.join(', ')}`);
    }

    // Prepare import data
    const fileData = {
      originalName: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      content: req.file.buffer.toString('utf-8')
    };

    const options = {
      sendWelcomeEmails: importData.sendWelcomeEmails !== false,
      skipExisting: importData.skipExisting !== false,
      validateOnly: importData.validateOnly === true,
      defaultRole: importData.defaultRole,
      defaultOrganization: importData.defaultOrganization,
      generatePasswords: importData.generatePasswords !== false,
      requirePasswordChange: importData.requirePasswordChange !== false
    };

    // Validate default role if provided
    if (options.defaultRole && !AdminHelpers.isValidObjectId(options.defaultRole)) {
      throw new ValidationError('Invalid default role ID');
    }

    // Validate default organization if provided
    if (options.defaultOrganization && !AdminHelpers.isValidObjectId(options.defaultOrganization)) {
      throw new ValidationError('Invalid default organization ID');
    }

    // Initiate import
    const result = await BulkOperationsService.initiateUserImport(adminUser, {
      fileData,
      mappings: importData.mappings,
      options
    });

    res.status(202).json(
      ResponseFormatter.success(result, 'User import initiated successfully')
    );
  });

  /**
   * Execute bulk user update
   * @route POST /api/admin/users/bulk/update
   */
  executeBulkUpdate = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const updateData = sanitizeBody(req.body);

    // Validate input
    if (!updateData.userIds && !updateData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (updateData.userIds && !Array.isArray(updateData.userIds)) {
      throw new ValidationError('userIds must be an array');
    }

    if (updateData.userIds) {
      // Validate user IDs
      const invalidIds = updateData.userIds.filter(id => !AdminHelpers.isValidObjectId(id));
      if (invalidIds.length > 0) {
        throw new ValidationError(`Invalid user IDs: ${invalidIds.join(', ')}`);
      }

      // Check bulk operation limit
      if (updateData.userIds.length > AdminLimits.BULK_OPERATIONS.MAX_UPDATE_USERS) {
        throw new ValidationError(`Cannot update more than ${AdminLimits.BULK_OPERATIONS.MAX_UPDATE_USERS} users at once`);
      }
    }

    // Validate updates
    if (!updateData.updates || Object.keys(updateData.updates).length === 0) {
      throw new ValidationError('No updates specified');
    }

    // Validate specific update fields
    const allowedUpdateFields = ['status', 'role', 'organization', 'requirePasswordChange', 'requireMFA'];
    const invalidFields = Object.keys(updateData.updates).filter(field => !allowedUpdateFields.includes(field));
    
    if (invalidFields.length > 0) {
      throw new ValidationError(`Invalid update fields: ${invalidFields.join(', ')}`);
    }

    // Validate update values
    if (updateData.updates.status && !['active', 'suspended', 'locked'].includes(updateData.updates.status)) {
      throw new ValidationError('Invalid status value');
    }

    if (updateData.updates.role && !AdminHelpers.isValidObjectId(updateData.updates.role)) {
      throw new ValidationError('Invalid role ID');
    }

    if (updateData.updates.organization && !AdminHelpers.isValidObjectId(updateData.updates.organization)) {
      throw new ValidationError('Invalid organization ID');
    }

    // Execute bulk update
    const result = await BulkOperationsService.executeBulkUpdate(adminUser, updateData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Bulk update completed successfully')
    );
  });

  /**
   * Execute bulk user deletion
   * @route POST /api/admin/users/bulk/delete
   */
  executeBulkDelete = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const deleteData = sanitizeBody(req.body);

    // Validate input
    if (!deleteData.userIds && !deleteData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (deleteData.userIds && !Array.isArray(deleteData.userIds)) {
      throw new ValidationError('userIds must be an array');
    }

    if (deleteData.userIds) {
      // Validate user IDs
      const invalidIds = deleteData.userIds.filter(id => !AdminHelpers.isValidObjectId(id));
      if (invalidIds.length > 0) {
        throw new ValidationError(`Invalid user IDs: ${invalidIds.join(', ')}`);
      }

      // Check bulk operation limit
      if (deleteData.userIds.length > AdminLimits.BULK_OPERATIONS.MAX_DELETE_USERS) {
        throw new ValidationError(`Cannot delete more than ${AdminLimits.BULK_OPERATIONS.MAX_DELETE_USERS} users at once`);
      }

      // Prevent self-deletion
      if (deleteData.userIds.includes(adminUser.id)) {
        throw new ValidationError('Cannot delete your own account');
      }
    }

    // Validate deletion options
    if (!deleteData.options || !deleteData.options.reason) {
      throw new ValidationError('Deletion reason is required');
    }

    if (deleteData.options.reason.trim().length < 20) {
      throw new ValidationError('Deletion reason must be at least 20 characters');
    }

    // Execute bulk deletion
    const result = await BulkOperationsService.executeBulkDelete(adminUser, deleteData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Bulk deletion completed successfully')
    );
  });

  /**
   * Export users in bulk
   * @route POST /api/admin/users/bulk/export
   */
  exportUsers = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const exportData = sanitizeBody(req.body);

    // Validate export format
    const allowedFormats = ['csv', 'xlsx', 'json'];
    if (exportData.format && !allowedFormats.includes(exportData.format)) {
      throw new ValidationError(`Invalid export format. Allowed formats: ${allowedFormats.join(', ')}`);
    }

    // Validate fields if specified
    if (exportData.fields && !Array.isArray(exportData.fields)) {
      throw new ValidationError('Export fields must be an array');
    }

    // Check if requesting sensitive data
    if (exportData.options?.includeSensitive && 
        !await AdminHelpers.hasPermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_SENSITIVE)) {
      throw new ValidationError('Insufficient permissions to export sensitive data');
    }

    // Execute export
    const result = await BulkOperationsService.exportUsers(adminUser, exportData);

    // For immediate download
    if (!exportData.options?.asyncExport) {
      res.setHeader('Content-Type', result.exportDetails.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${result.exportDetails.fileName}"`);
      return res.redirect(result.exportDetails.fileUrl);
    }

    // For async export
    res.status(202).json(
      ResponseFormatter.success(result, 'Export initiated successfully')
    );
  });

  /**
   * Send bulk emails to users
   * @route POST /api/admin/users/bulk/email
   */
  sendBulkEmails = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const emailData = sanitizeBody(req.body);

    // Validate input
    if (!emailData.userIds && !emailData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (emailData.userIds && !Array.isArray(emailData.userIds)) {
      throw new ValidationError('userIds must be an array');
    }

    if (emailData.userIds) {
      // Check bulk operation limit
      if (emailData.userIds.length > AdminLimits.BULK_OPERATIONS.MAX_EMAIL_RECIPIENTS) {
        throw new ValidationError(`Cannot send emails to more than ${AdminLimits.BULK_OPERATIONS.MAX_EMAIL_RECIPIENTS} users at once`);
      }
    }

    // Validate email template
    if (!emailData.emailTemplate) {
      throw new ValidationError('Email template is required');
    }

    if (!emailData.emailTemplate.subject || !emailData.emailTemplate.content) {
      throw new ValidationError('Email template must include subject and content');
    }

    // Validate subject length
    if (emailData.emailTemplate.subject.length > 200) {
      throw new ValidationError('Email subject cannot exceed 200 characters');
    }

    // Validate content length
    if (emailData.emailTemplate.content.length > 50000) {
      throw new ValidationError('Email content cannot exceed 50,000 characters');
    }

    // Validate schedule date if provided
    if (emailData.options?.scheduleAt) {
      const scheduleDate = new Date(emailData.options.scheduleAt);
      if (scheduleDate <= new Date()) {
        throw new ValidationError('Schedule date must be in the future');
      }
      
      // Maximum 90 days in the future
      const maxScheduleDate = new Date();
      maxScheduleDate.setDate(maxScheduleDate.getDate() + 90);
      
      if (scheduleDate > maxScheduleDate) {
        throw new ValidationError('Cannot schedule emails more than 90 days in advance');
      }
    }

    // Send bulk emails
    const result = await BulkOperationsService.sendBulkEmails(adminUser, emailData);

    res.status(202).json(
      ResponseFormatter.success(result, 'Bulk email operation initiated successfully')
    );
  });

  /**
   * Bulk assign role to users
   * @route POST /api/admin/users/bulk/assign-role
   */
  bulkAssignRole = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const assignData = sanitizeBody(req.body);

    // Validate input
    if (!assignData.userIds && !assignData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (!assignData.roleId || !AdminHelpers.isValidObjectId(assignData.roleId)) {
      throw new ValidationError('Valid role ID is required');
    }

    if (assignData.userIds && !Array.isArray(assignData.userIds)) {
      throw new ValidationError('userIds must be an array');
    }

    // Execute role assignment
    const updateData = {
      userIds: assignData.userIds,
      filters: assignData.filters,
      updates: { role: assignData.roleId },
      options: {
        notifyUsers: assignData.notifyUsers !== false,
        skipProtectedAccounts: true
      }
    };

    const result = await BulkOperationsService.executeBulkUpdate(adminUser, updateData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Bulk role assignment completed successfully')
    );
  });

  /**
   * Bulk assign organization to users
   * @route POST /api/admin/users/bulk/assign-organization
   */
  bulkAssignOrganization = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const assignData = sanitizeBody(req.body);

    // Validate input
    if (!assignData.userIds && !assignData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (!assignData.organizationId || !AdminHelpers.isValidObjectId(assignData.organizationId)) {
      throw new ValidationError('Valid organization ID is required');
    }

    if (assignData.userIds && !Array.isArray(assignData.userIds)) {
      throw new ValidationError('userIds must be an array');
    }

    // Execute organization assignment
    const updateData = {
      userIds: assignData.userIds,
      filters: assignData.filters,
      updates: { organization: assignData.organizationId },
      options: {
        notifyUsers: assignData.notifyUsers !== false,
        skipProtectedAccounts: true
      }
    };

    const result = await BulkOperationsService.executeBulkUpdate(adminUser, updateData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Bulk organization assignment completed successfully')
    );
  });

  /**
   * Bulk reset passwords
   * @route POST /api/admin/users/bulk/reset-passwords
   */
  bulkResetPasswords = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const resetData = sanitizeBody(req.body);

    // Validate input
    if (!resetData.userIds && !resetData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (!resetData.reason || resetData.reason.trim().length < 10) {
      throw new ValidationError('Password reset reason required (minimum 10 characters)');
    }

    if (resetData.userIds && !Array.isArray(resetData.userIds)) {
      throw new ValidationError('userIds must be an array');
    }

    // Execute password reset
    const result = await BulkOperationsService.executeBulkPasswordReset(adminUser, resetData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Bulk password reset completed successfully')
    );
  });

  /**
   * Get bulk operation status
   * @route GET /api/admin/users/bulk/operations/:operationId
   */
  getOperationStatus = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { operationId } = req.params;

    // Validate operation ID
    if (!operationId || !AdminHelpers.isValidUUID(operationId)) {
      throw new ValidationError('Invalid operation ID');
    }

    // Get operation status
    const result = await BulkOperationsService.getOperationStatus(adminUser, operationId);

    res.status(200).json(
      ResponseFormatter.success(result, 'Operation status retrieved successfully')
    );
  });

  /**
   * Get bulk operations history
   * @route GET /api/admin/users/bulk/operations
   */
  getOperationsHistory = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    const options = {
      page: parseInt(queryParams.page) || 1,
      limit: Math.min(parseInt(queryParams.limit) || 20, AdminLimits.PAGINATION.MAX_LIMIT),
      type: queryParams.type,
      status: queryParams.status,
      startDate: queryParams.startDate,
      endDate: queryParams.endDate,
      sortBy: queryParams.sortBy || 'createdAt',
      sortOrder: queryParams.sortOrder || 'desc'
    };

    // Get operations history
    const result = await BulkOperationsService.getOperationsHistory(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'Operations history retrieved successfully')
    );
  });

  /**
   * Cancel bulk operation
   * @route POST /api/admin/users/bulk/operations/:operationId/cancel
   */
  cancelOperation = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { operationId } = req.params;

    // Validate operation ID
    if (!operationId || !AdminHelpers.isValidUUID(operationId)) {
      throw new ValidationError('Invalid operation ID');
    }

    // Cancel operation
    const result = await BulkOperationsService.cancelOperation(adminUser, operationId);

    res.status(200).json(
      ResponseFormatter.success(result, 'Operation cancelled successfully')
    );
  });

  /**
   * Retry failed bulk operation
   * @route POST /api/admin/users/bulk/operations/:operationId/retry
   */
  retryOperation = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { operationId } = req.params;
    const options = sanitizeBody(req.body);

    // Validate operation ID
    if (!operationId || !AdminHelpers.isValidUUID(operationId)) {
      throw new ValidationError('Invalid operation ID');
    }

    // Retry operation
    const result = await BulkOperationsService.retryOperation(adminUser, operationId, options);

    res.status(202).json(
      ResponseFormatter.success(result, 'Operation retry initiated successfully')
    );
  });

  /**
   * Download bulk operation results
   * @route GET /api/admin/users/bulk/operations/:operationId/download
   */
  downloadOperationResults = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { operationId } = req.params;

    // Validate operation ID
    if (!operationId || !AdminHelpers.isValidUUID(operationId)) {
      throw new ValidationError('Invalid operation ID');
    }

    // Get download URL
    const result = await BulkOperationsService.getOperationResultsDownload(adminUser, operationId);

    // Redirect to download URL
    res.redirect(result.downloadUrl);
  });

  /**
   * Get import template
   * @route GET /api/admin/users/bulk/import-template
   */
  getImportTemplate = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { format = 'csv' } = sanitizeQuery(req.query);

    // Validate format
    const allowedFormats = ['csv', 'xlsx'];
    if (!allowedFormats.includes(format)) {
      throw new ValidationError(`Invalid template format. Allowed formats: ${allowedFormats.join(', ')}`);
    }

    // Get template
    const template = await BulkOperationsService.getImportTemplate(format);

    res.setHeader('Content-Type', template.contentType);
    res.setHeader('Content-Disposition', `attachment; filename="user-import-template.${format}"`);
    res.send(template.data);
  });
}

module.exports = new BulkOperationsController();