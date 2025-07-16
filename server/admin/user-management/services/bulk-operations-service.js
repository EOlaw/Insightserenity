// server/admin/user-management/services/bulk-operations-service.js
/**
 * @file Bulk Operations Service
 * @description Service for handling bulk user operations with job queuing and progress tracking
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const csv = require('csv-parser');
const { Readable } = require('stream');
const crypto = require('crypto');

// Core Models
const User = require('../../../shared/users/models/user-model');
const UserProfile = require('../../../shared/users/models/user-profile-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const Role = require('../../../shared/users/models/role-model');
const BulkOperation = require('../../../shared/admin/models/bulk-operation-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AdminExportService = require('../../../shared/admin/services/admin-export-service');
const QueueService = require('../../../shared/utils/queue-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const ValidationService = require('../../../shared/utils/validation-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const { hashPassword } = require('../../../shared/utils/auth-helpers');
const { encrypt, decrypt } = require('../../../shared/utils/encryption');

// Configuration
const config = require('../../../config');

/**
 * Bulk Operations Service Class
 * @class BulkOperationsService
 * @extends AdminBaseService
 */
class BulkOperationsService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'BulkOperationsService';
    this.cachePrefix = 'bulk-ops';
    this.auditCategory = 'BULK_OPERATIONS';
    this.requiredPermission = AdminPermissions.USER_MANAGEMENT.BULK_OPERATIONS;
    
    // Operation configurations
    this.operationTypes = {
      IMPORT: 'import',
      UPDATE: 'update',
      DELETE: 'delete',
      EXPORT: 'export',
      EMAIL: 'email',
      ROLE_ASSIGN: 'role_assign',
      ORG_ASSIGN: 'org_assign',
      STATUS_CHANGE: 'status_change',
      PASSWORD_RESET: 'password_reset'
    };
    
    // Batch sizes for different operations
    this.batchSizes = {
      import: 100,
      update: 200,
      delete: 50,
      export: 1000,
      email: 50,
      default: 100
    };
  }

  /**
   * Initiate bulk user import
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} importData - Import configuration
   * @returns {Promise<Object>} Import job details
   */
  async initiateUserImport(adminUser, importData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.BULK_IMPORT);

      const {
        fileData,
        mappings,
        options = {}
      } = importData;

      const {
        sendWelcomeEmails = true,
        skipExisting = true,
        validateOnly = false,
        defaultRole = null,
        defaultOrganization = null,
        generatePasswords = true,
        requirePasswordChange = true
      } = options;

      // Validate file data
      if (!fileData || !fileData.content) {
        throw new ValidationError('Import file data is required');
      }

      // Parse CSV data
      const users = await this.parseImportFile(fileData, mappings);
      
      if (users.length === 0) {
        throw new ValidationError('No valid users found in import file');
      }

      if (users.length > AdminLimits.BULK_OPERATIONS.MAX_IMPORT_USERS) {
        throw new ValidationError(`Import exceeds maximum limit of ${AdminLimits.BULK_OPERATIONS.MAX_IMPORT_USERS} users`);
      }

      // Validate default role if provided
      let defaultRoleDoc = null;
      if (defaultRole) {
        defaultRoleDoc = await Role.findById(defaultRole).session(session);
        if (!defaultRoleDoc) {
          throw new ValidationError('Invalid default role specified');
        }
      }

      // Validate default organization if provided
      let defaultOrgDoc = null;
      if (defaultOrganization) {
        defaultOrgDoc = await HostedOrganization.findById(defaultOrganization).session(session);
        if (!defaultOrgDoc) {
          throw new ValidationError('Invalid default organization specified');
        }
      }

      // Create bulk operation record
      const operation = new BulkOperation({
        operationId: crypto.randomUUID(),
        type: this.operationTypes.IMPORT,
        adminUserId: adminUser.id,
        status: 'pending',
        totalRecords: users.length,
        processedRecords: 0,
        successfulRecords: 0,
        failedRecords: 0,
        configuration: {
          mappings,
          options,
          defaultRole: defaultRoleDoc?.name,
          defaultOrganization: defaultOrgDoc?.name
        },
        startedAt: new Date()
      });

      await operation.save({ session });

      // Perform validation if requested
      if (validateOnly) {
        const validationResults = await this.validateImportData(users, options);
        
        operation.status = 'completed';
        operation.completedAt = new Date();
        operation.results = {
          validationOnly: true,
          validationResults
        };
        
        await operation.save({ session });
        await session.commitTransaction();
        
        return {
          operationId: operation.operationId,
          validationOnly: true,
          results: validationResults
        };
      }

      // Queue the import job
      const jobId = await QueueService.addJob('bulk-user-import', {
        operationId: operation.operationId,
        adminUserId: adminUser.id,
        users,
        options: {
          ...options,
          defaultRoleId: defaultRoleDoc?._id,
          defaultOrganizationId: defaultOrgDoc?._id
        }
      }, {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 5000
        }
      });

      operation.jobId = jobId;
      await operation.save({ session });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.BULK_IMPORT_INITIATED, {
        operationId: operation.operationId,
        userCount: users.length,
        options
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        operationId: operation.operationId,
        jobId,
        status: 'queued',
        totalUsers: users.length,
        estimatedTime: this.estimateProcessingTime(users.length, 'import'),
        message: 'Bulk import job queued successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Initiate user import error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Execute bulk user update
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} updateData - Update configuration
   * @returns {Promise<Object>} Update operation result
   */
  async executeBulkUpdate(adminUser, updateData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.BULK_UPDATE);

      const {
        userIds,
        filters,
        updates,
        options = {}
      } = updateData;

      const {
        validateOnly = false,
        notifyUsers = false,
        skipProtectedAccounts = true
      } = options;

      // Validate input
      if (!userIds && !filters) {
        throw new ValidationError('Either userIds or filters must be provided');
      }

      if (!updates || Object.keys(updates).length === 0) {
        throw new ValidationError('No updates specified');
      }

      // Validate updates
      this.validateBulkUpdates(updates);

      // Get target users
      let targetUsers;
      if (userIds) {
        targetUsers = await User.find({
          _id: { $in: userIds },
          status: { $ne: 'deleted' }
        }).session(session);
      } else {
        const query = this.buildUserQueryFromFilters(filters);
        targetUsers = await User.find(query)
          .limit(AdminLimits.BULK_OPERATIONS.MAX_UPDATE_USERS)
          .session(session);
      }

      if (targetUsers.length === 0) {
        throw new ValidationError('No users found matching criteria');
      }

      // Filter protected accounts if needed
      if (skipProtectedAccounts) {
        targetUsers = targetUsers.filter(user => !user.security?.protectedAccount);
      }

      // Create operation record
      const operation = new BulkOperation({
        operationId: crypto.randomUUID(),
        type: this.operationTypes.UPDATE,
        adminUserId: adminUser.id,
        status: 'processing',
        totalRecords: targetUsers.length,
        processedRecords: 0,
        successfulRecords: 0,
        failedRecords: 0,
        configuration: {
          updates,
          options,
          filters: filters || { userIds }
        },
        startedAt: new Date()
      });

      await operation.save({ session });

      // Perform validation if requested
      if (validateOnly) {
        const validationResults = this.validateBulkUpdateTargets(targetUsers, updates);
        
        operation.status = 'completed';
        operation.completedAt = new Date();
        operation.results = {
          validationOnly: true,
          validationResults
        };
        
        await operation.save({ session });
        await session.commitTransaction();
        
        return {
          operationId: operation.operationId,
          validationOnly: true,
          results: validationResults
        };
      }

      // Process updates in batches
      const batchSize = this.batchSizes.update;
      const results = {
        successful: [],
        failed: [],
        errors: []
      };

      for (let i = 0; i < targetUsers.length; i += batchSize) {
        const batch = targetUsers.slice(i, i + batchSize);
        const batchResults = await this.processBulkUpdateBatch(
          batch, 
          updates, 
          adminUser, 
          session
        );

        results.successful.push(...batchResults.successful);
        results.failed.push(...batchResults.failed);
        results.errors.push(...batchResults.errors);

        // Update operation progress
        operation.processedRecords = i + batch.length;
        operation.successfulRecords = results.successful.length;
        operation.failedRecords = results.failed.length;
        await operation.save({ session });

        // Update progress in cache for real-time tracking
        await this.updateOperationProgress(operation.operationId, {
          processed: operation.processedRecords,
          successful: operation.successfulRecords,
          failed: operation.failedRecords
        });
      }

      // Finalize operation
      operation.status = 'completed';
      operation.completedAt = new Date();
      operation.results = {
        summary: {
          total: targetUsers.length,
          successful: results.successful.length,
          failed: results.failed.length
        },
        errors: results.errors
      };

      await operation.save({ session });

      // Send notifications if requested
      if (notifyUsers && results.successful.length > 0) {
        await this.queueBulkNotifications(results.successful, 'account_updated', {
          adminName: adminUser.profile?.firstName || adminUser.email,
          changes: Object.keys(updates)
        });
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.BULK_UPDATE_COMPLETED, {
        operationId: operation.operationId,
        totalUsers: targetUsers.length,
        successful: results.successful.length,
        failed: results.failed.length,
        updates: Object.keys(updates)
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        operationId: operation.operationId,
        status: 'completed',
        results: operation.results,
        message: `Bulk update completed: ${results.successful.length} successful, ${results.failed.length} failed`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Execute bulk update error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Execute bulk user deletion
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} deleteData - Deletion configuration
   * @returns {Promise<Object>} Deletion operation result
   */
  async executeBulkDelete(adminUser, deleteData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.BULK_DELETE);

      const {
        userIds,
        filters,
        options = {}
      } = deleteData;

      const {
        hardDelete = false,
        reason,
        skipProtectedAccounts = true,
        validateOnly = false
      } = options;

      if (!reason || reason.trim().length < 20) {
        throw new ValidationError('Detailed deletion reason required (minimum 20 characters)');
      }

      // Additional permission check for hard delete
      if (hardDelete) {
        await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.HARD_DELETE);
      }

      // Get target users
      let targetUsers;
      if (userIds) {
        targetUsers = await User.find({
          _id: { $in: userIds },
          status: { $ne: 'deleted' }
        })
        .populate('organization.owned')
        .session(session);
      } else {
        const query = this.buildUserQueryFromFilters(filters);
        targetUsers = await User.find(query)
          .populate('organization.owned')
          .limit(AdminLimits.BULK_OPERATIONS.MAX_DELETE_USERS)
          .session(session);
      }

      if (targetUsers.length === 0) {
        throw new ValidationError('No users found matching criteria');
      }

      // Filter protected accounts
      if (skipProtectedAccounts) {
        targetUsers = targetUsers.filter(user => 
          !user.security?.protectedAccount && 
          user.role?.primary !== 'super_admin'
        );
      }

      // Check for users with owned organizations
      const usersWithOwnedOrgs = targetUsers.filter(user => 
        user.organization?.owned?.length > 0
      );

      if (usersWithOwnedOrgs.length > 0) {
        throw new ValidationError(
          `${usersWithOwnedOrgs.length} users own organizations. ` +
          'Transfer ownership before bulk deletion.'
        );
      }

      // Create operation record
      const operation = new BulkOperation({
        operationId: crypto.randomUUID(),
        type: this.operationTypes.DELETE,
        adminUserId: adminUser.id,
        status: 'processing',
        totalRecords: targetUsers.length,
        processedRecords: 0,
        successfulRecords: 0,
        failedRecords: 0,
        configuration: {
          hardDelete,
          reason: encrypt(reason),
          options,
          filters: filters || { userIds }
        },
        startedAt: new Date()
      });

      await operation.save({ session });

      // Perform validation if requested
      if (validateOnly) {
        const validationResults = {
          totalUsers: targetUsers.length,
          deletable: targetUsers.length,
          protected: skipProtectedAccounts ? 
            (userIds?.length || 0) - targetUsers.length : 0,
          withOwnedOrgs: usersWithOwnedOrgs.length
        };
        
        operation.status = 'completed';
        operation.completedAt = new Date();
        operation.results = {
          validationOnly: true,
          validationResults
        };
        
        await operation.save({ session });
        await session.commitTransaction();
        
        return {
          operationId: operation.operationId,
          validationOnly: true,
          results: validationResults
        };
      }

      // Process deletions in batches
      const batchSize = this.batchSizes.delete;
      const results = {
        successful: [],
        failed: [],
        errors: []
      };

      for (let i = 0; i < targetUsers.length; i += batchSize) {
        const batch = targetUsers.slice(i, i + batchSize);
        const batchResults = await this.processBulkDeleteBatch(
          batch,
          {
            hardDelete,
            reason,
            adminUser
          },
          session
        );

        results.successful.push(...batchResults.successful);
        results.failed.push(...batchResults.failed);
        results.errors.push(...batchResults.errors);

        // Update operation progress
        operation.processedRecords = i + batch.length;
        operation.successfulRecords = results.successful.length;
        operation.failedRecords = results.failed.length;
        await operation.save({ session });

        // Update progress in cache
        await this.updateOperationProgress(operation.operationId, {
          processed: operation.processedRecords,
          successful: operation.successfulRecords,
          failed: operation.failedRecords
        });
      }

      // Finalize operation
      operation.status = 'completed';
      operation.completedAt = new Date();
      operation.results = {
        summary: {
          total: targetUsers.length,
          successful: results.successful.length,
          failed: results.failed.length
        },
        deletionType: hardDelete ? 'hard' : 'soft',
        errors: results.errors
      };

      await operation.save({ session });

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.BULK_DELETE_COMPLETED, {
        operationId: operation.operationId,
        totalUsers: targetUsers.length,
        successful: results.successful.length,
        failed: results.failed.length,
        deletionType: hardDelete ? 'hard' : 'soft',
        reason
      }, { session, critical: true, alertLevel: 'high' });

      await session.commitTransaction();

      return {
        operationId: operation.operationId,
        status: 'completed',
        results: operation.results,
        message: `Bulk deletion completed: ${results.successful.length} successful, ${results.failed.length} failed`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Execute bulk delete error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Export users in bulk
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} exportData - Export configuration
   * @returns {Promise<Object>} Export result
   */
  async exportUsers(adminUser, exportData) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.EXPORT);

      const {
        filters = {},
        fields = [],
        format = 'csv',
        options = {}
      } = exportData;

      const {
        includeDeleted = false,
        includeSensitive = false,
        chunkSize = 5000
      } = options;

      // Additional permission check for sensitive data
      if (includeSensitive) {
        await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_SENSITIVE);
      }

      // Build query
      const query = this.buildUserQueryFromFilters({
        ...filters,
        includeDeleted
      });

      // Count total users
      const totalCount = await User.countDocuments(query);

      if (totalCount === 0) {
        throw new ValidationError('No users found matching export criteria');
      }

      if (totalCount > AdminLimits.BULK_OPERATIONS.MAX_EXPORT_USERS) {
        throw new ValidationError(
          `Export exceeds maximum limit of ${AdminLimits.BULK_OPERATIONS.MAX_EXPORT_USERS} users`
        );
      }

      // Create operation record
      const operation = new BulkOperation({
        operationId: crypto.randomUUID(),
        type: this.operationTypes.EXPORT,
        adminUserId: adminUser.id,
        status: 'processing',
        totalRecords: totalCount,
        processedRecords: 0,
        configuration: {
          filters,
          fields: fields.length > 0 ? fields : this.getDefaultExportFields(includeSensitive),
          format,
          options
        },
        startedAt: new Date()
      });

      await operation.save();

      // Use AdminExportService for the actual export
      const exportResult = await AdminExportService.exportData({
        model: User,
        query,
        fields: operation.configuration.fields,
        format,
        options: {
          ...options,
          populateFields: [
            'role.primary',
            'organization.current',
            'profile'
          ],
          transformFunction: (user) => this.transformUserForExport(user, includeSensitive),
          chunkSize,
          onProgress: async (processed) => {
            operation.processedRecords = processed;
            await operation.save();
            await this.updateOperationProgress(operation.operationId, {
              processed,
              total: totalCount
            });
          }
        }
      });

      // Update operation with results
      operation.status = 'completed';
      operation.completedAt = new Date();
      operation.successfulRecords = totalCount;
      operation.results = {
        fileUrl: exportResult.fileUrl,
        fileName: exportResult.fileName,
        fileSize: exportResult.fileSize,
        expiresAt: exportResult.expiresAt
      };

      await operation.save();

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.BULK_EXPORT_COMPLETED, {
        operationId: operation.operationId,
        totalUsers: totalCount,
        format,
        includeSensitive,
        fileName: exportResult.fileName
      }, { critical: true });

      return {
        operationId: operation.operationId,
        status: 'completed',
        exportDetails: {
          totalRecords: totalCount,
          format,
          fileUrl: exportResult.fileUrl,
          fileName: exportResult.fileName,
          fileSize: exportResult.fileSize,
          expiresAt: exportResult.expiresAt
        },
        message: `Export completed successfully: ${totalCount} users exported`
      };

    } catch (error) {
      logger.error('Export users error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Send bulk emails to users
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} emailData - Email configuration
   * @returns {Promise<Object>} Email operation result
   */
  async sendBulkEmails(adminUser, emailData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.BULK_EMAIL);

      const {
        userIds,
        filters,
        emailTemplate,
        customData = {},
        options = {}
      } = emailData;

      const {
        scheduleAt = null,
        batchDelay = 1000, // milliseconds between batches
        trackOpens = true,
        trackClicks = true,
        validateOnly = false
      } = options;

      // Validate email template
      if (!emailTemplate || !emailTemplate.subject || !emailTemplate.content) {
        throw new ValidationError('Email template with subject and content is required');
      }

      // Get target users
      let targetUsers;
      if (userIds) {
        targetUsers = await User.find({
          _id: { $in: userIds },
          status: 'active',
          'auth.email.verified': true
        })
        .populate('profile')
        .session(session);
      } else {
        const query = {
          ...this.buildUserQueryFromFilters(filters),
          status: 'active',
          'auth.email.verified': true
        };
        
        targetUsers = await User.find(query)
          .populate('profile')
          .limit(AdminLimits.BULK_OPERATIONS.MAX_EMAIL_RECIPIENTS)
          .session(session);
      }

      if (targetUsers.length === 0) {
        throw new ValidationError('No active users with verified emails found');
      }

      // Create operation record
      const operation = new BulkOperation({
        operationId: crypto.randomUUID(),
        type: this.operationTypes.EMAIL,
        adminUserId: adminUser.id,
        status: scheduleAt ? 'scheduled' : 'processing',
        totalRecords: targetUsers.length,
        processedRecords: 0,
        successfulRecords: 0,
        failedRecords: 0,
        configuration: {
          emailTemplate: {
            subject: emailTemplate.subject,
            preview: emailTemplate.content.substring(0, 100) + '...'
          },
          customData,
          options,
          filters: filters || { userIds }
        },
        scheduledAt: scheduleAt,
        startedAt: scheduleAt ? null : new Date()
      });

      await operation.save({ session });

      // Perform validation if requested
      if (validateOnly) {
        const validationResults = {
          totalRecipients: targetUsers.length,
          estimatedSendTime: (targetUsers.length / this.batchSizes.email) * batchDelay / 1000, // seconds
          scheduledAt: scheduleAt
        };
        
        operation.status = 'completed';
        operation.completedAt = new Date();
        operation.results = {
          validationOnly: true,
          validationResults
        };
        
        await operation.save({ session });
        await session.commitTransaction();
        
        return {
          operationId: operation.operationId,
          validationOnly: true,
          results: validationResults
        };
      }

      // If scheduled, queue for later execution
      if (scheduleAt) {
        await QueueService.addJob('bulk-email-send', {
          operationId: operation.operationId,
          adminUserId: adminUser.id
        }, {
          delay: new Date(scheduleAt) - new Date(),
          attempts: 3
        });

        await session.commitTransaction();

        return {
          operationId: operation.operationId,
          status: 'scheduled',
          scheduledAt,
          totalRecipients: targetUsers.length,
          message: `Bulk email scheduled for ${new Date(scheduleAt).toLocaleString()}`
        };
      }

      // Process emails in batches
      const batchSize = this.batchSizes.email;
      const results = {
        sent: [],
        failed: [],
        errors: []
      };

      for (let i = 0; i < targetUsers.length; i += batchSize) {
        const batch = targetUsers.slice(i, i + batchSize);
        const batchResults = await this.processBulkEmailBatch(
          batch,
          emailTemplate,
          customData,
          {
            trackOpens,
            trackClicks,
            campaignId: operation.operationId
          }
        );

        results.sent.push(...batchResults.sent);
        results.failed.push(...batchResults.failed);
        results.errors.push(...batchResults.errors);

        // Update operation progress
        operation.processedRecords = i + batch.length;
        operation.successfulRecords = results.sent.length;
        operation.failedRecords = results.failed.length;
        await operation.save({ session });

        // Update progress in cache
        await this.updateOperationProgress(operation.operationId, {
          processed: operation.processedRecords,
          successful: operation.successfulRecords,
          failed: operation.failedRecords
        });

        // Delay between batches to avoid overwhelming email service
        if (i + batchSize < targetUsers.length) {
          await new Promise(resolve => setTimeout(resolve, batchDelay));
        }
      }

      // Finalize operation
      operation.status = 'completed';
      operation.completedAt = new Date();
      operation.results = {
        summary: {
          total: targetUsers.length,
          sent: results.sent.length,
          failed: results.failed.length
        },
        errors: results.errors
      };

      await operation.save({ session });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.BULK_EMAIL_SENT, {
        operationId: operation.operationId,
        totalRecipients: targetUsers.length,
        sent: results.sent.length,
        failed: results.failed.length,
        subject: emailTemplate.subject
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        operationId: operation.operationId,
        status: 'completed',
        results: operation.results,
        message: `Bulk email completed: ${results.sent.length} sent, ${results.failed.length} failed`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Send bulk emails error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get bulk operation status
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} operationId - Operation ID
   * @returns {Promise<Object>} Operation status and details
   */
  async getOperationStatus(adminUser, operationId) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW);

      const operation = await BulkOperation.findOne({
        operationId,
        adminUserId: adminUser.id
      }).lean();

      if (!operation) {
        throw new NotFoundError('Operation not found');
      }

      // Get real-time progress from cache if operation is active
      let realtimeProgress = null;
      if (['processing', 'queued'].includes(operation.status)) {
        realtimeProgress = await this.getOperationProgress(operationId);
      }

      // Calculate statistics
      const statistics = {
        duration: operation.completedAt ? 
          new Date(operation.completedAt) - new Date(operation.startedAt) : 
          Date.now() - new Date(operation.startedAt),
        successRate: operation.processedRecords > 0 ? 
          (operation.successfulRecords / operation.processedRecords * 100).toFixed(2) : 0,
        processingSpeed: operation.processedRecords > 0 && operation.startedAt ?
          (operation.processedRecords / ((Date.now() - new Date(operation.startedAt)) / 1000)).toFixed(2) : 0
      };

      return {
        operation: {
          ...operation,
          progress: realtimeProgress || {
            processed: operation.processedRecords,
            total: operation.totalRecords,
            percentage: operation.totalRecords > 0 ? 
              (operation.processedRecords / operation.totalRecords * 100).toFixed(2) : 0
          }
        },
        statistics,
        canCancel: ['pending', 'processing', 'queued'].includes(operation.status),
        canRetry: operation.status === 'failed' && operation.failedRecords > 0
      };

    } catch (error) {
      logger.error('Get operation status error', {
        error: error.message,
        adminId: adminUser.id,
        operationId,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Cancel bulk operation
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} operationId - Operation ID to cancel
   * @returns {Promise<Object>} Cancellation result
   */
  async cancelOperation(adminUser, operationId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.BULK_OPERATIONS);

      const operation = await BulkOperation.findOne({
        operationId,
        adminUserId: adminUser.id
      }).session(session);

      if (!operation) {
        throw new NotFoundError('Operation not found');
      }

      if (!['pending', 'processing', 'queued', 'scheduled'].includes(operation.status)) {
        throw new ValidationError('Operation cannot be cancelled in current status');
      }

      // Cancel job in queue if exists
      if (operation.jobId) {
        await QueueService.cancelJob(operation.jobId);
      }

      // Update operation status
      operation.status = 'cancelled';
      operation.cancelledAt = new Date();
      operation.cancelledBy = adminUser.id;
      operation.results = {
        ...operation.results,
        cancellationReason: 'Cancelled by administrator'
      };

      await operation.save({ session });

      // Clear any cached progress
      await this.clearOperationProgress(operationId);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.BULK_OPERATION_CANCELLED, {
        operationId,
        operationType: operation.type,
        processedBeforeCancellation: operation.processedRecords
      }, { session });

      await session.commitTransaction();

      return {
        operationId,
        status: 'cancelled',
        message: 'Operation cancelled successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Cancel operation error', {
        error: error.message,
        adminId: adminUser.id,
        operationId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Parse import file and map fields
   * @param {Object} fileData - File data
   * @param {Object} mappings - Field mappings
   * @returns {Promise<Array>} Parsed user data
   * @private
   */
  async parseImportFile(fileData, mappings) {
    const users = [];
    const errors = [];

    return new Promise((resolve, reject) => {
      const stream = Readable.from(fileData.content);
      
      stream
        .pipe(csv())
        .on('data', (row, index) => {
          try {
            const user = this.mapRowToUser(row, mappings);
            if (user) {
              users.push({ ...user, rowIndex: index + 2 }); // +2 for header and 0-index
            }
          } catch (error) {
            errors.push({
              row: index + 2,
              error: error.message,
              data: row
            });
          }
        })
        .on('end', () => {
          if (errors.length > 0) {
            logger.warn('Import file parsing errors', { errorCount: errors.length });
          }
          resolve(users);
        })
        .on('error', reject);
    });
  }

  /**
   * Process bulk update batch
   * @param {Array} users - User batch
   * @param {Object} updates - Updates to apply
   * @param {Object} adminUser - Admin user
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Batch results
   * @private
   */
  async processBulkUpdateBatch(users, updates, adminUser, session) {
    const results = {
      successful: [],
      failed: [],
      errors: []
    };

    for (const user of users) {
      try {
        const updateData = {};
        
        // Apply updates based on type
        if (updates.status) {
          updateData.status = updates.status;
        }
        
        if (updates.role) {
          const role = await Role.findById(updates.role).session(session);
          if (!role) throw new Error('Invalid role');
          updateData['role.primary'] = role._id;
        }
        
        if (updates.organization) {
          const org = await HostedOrganization.findById(updates.organization).session(session);
          if (!org) throw new Error('Invalid organization');
          updateData['organization.current'] = org._id;
        }
        
        if (updates.requirePasswordChange !== undefined) {
          updateData['auth.requirePasswordChange'] = updates.requirePasswordChange;
        }
        
        if (updates.requireMFA !== undefined) {
          updateData['security.requireMFA'] = updates.requireMFA;
        }

        // Apply update
        await User.findByIdAndUpdate(
          user._id,
          {
            $set: {
              ...updateData,
              'metadata.lastModifiedBy': adminUser.id,
              'metadata.lastModifiedAt': new Date()
            }
          },
          { session }
        );

        results.successful.push({
          userId: user._id,
          email: user.email
        });

      } catch (error) {
        results.failed.push({
          userId: user._id,
          email: user.email
        });
        results.errors.push({
          userId: user._id,
          email: user.email,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Process bulk delete batch
   * @param {Array} users - User batch
   * @param {Object} options - Delete options
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Batch results
   * @private
   */
  async processBulkDeleteBatch(users, options, session) {
    const results = {
      successful: [],
      failed: [],
      errors: []
    };

    const { hardDelete, reason, adminUser } = options;

    for (const user of users) {
      try {
        if (hardDelete) {
          // Remove all related data
          await Promise.all([
            UserProfile.deleteOne({ userId: user._id }, { session }),
            UserActivity.deleteMany({ userId: user._id }, { session }),
            UserSession.deleteMany({ userId: user._id }, { session }),
            LoginHistory.deleteMany({ userId: user._id }, { session })
          ]);

          // Remove user
          await User.deleteOne({ _id: user._id }, { session });
        } else {
          // Soft delete
          await User.findByIdAndUpdate(
            user._id,
            {
              $set: {
                status: 'deleted',
                'deletion.deletedAt': new Date(),
                'deletion.deletedBy': adminUser.id,
                'deletion.reason': encrypt(reason),
                email: `deleted_${user._id}@deleted.local`,
                'auth.password': null
              }
            },
            { session }
          );

          // Terminate sessions
          await UserSession.updateMany(
            { userId: user._id, isActive: true },
            {
              $set: {
                isActive: false,
                endedAt: new Date(),
                endReason: 'account_deleted'
              }
            },
            { session }
          );
        }

        results.successful.push({
          userId: user._id,
          email: user.email
        });

      } catch (error) {
        results.failed.push({
          userId: user._id,
          email: user.email
        });
        results.errors.push({
          userId: user._id,
          email: user.email,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Additional helper methods would continue here...
   */
}

module.exports = new BulkOperationsService();