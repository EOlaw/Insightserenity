// server/core-business/reports/services/reports-service.js
/**
 * @file Reports Service
 * @description Comprehensive reports service handling all report-related business logic
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const cron = require('node-cron');

const Report = require('../models/reports-model');
const User = require('../../../shared/users/models/user-model');
const Organization = require('../../../hosted-organizations/organizations/models/organization-model');

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const AuditService = require('../../../shared/security/services/audit-service');
const { CacheService } = require('../../../shared/services/cache-service');
const EmailService = require('../../../shared/services/email-service');
const FileService = require('../../../shared/services/file-service');
const NotificationService = require('../../../shared/services/notification-service');
const { QueueHelper } = require('../../../shared/utils/helpers/queue-helper');
const PDFGenerator = require('../../../shared/utils/helpers/pdf-generator');
const ExcelGenerator = require('../../../shared/utils/helpers/excel-generator');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  ForbiddenError,
  BusinessRuleError 
} = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

/**
 * Reports Service Class
 * @class ReportsService
 */
class ReportsService {
  /**
   * Create new report
   * @param {Object} reportData - Report data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created report
   */
  static async createReport(reportData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Creating new report', {
        name: reportData.name,
        type: reportData.type,
        userId: context.userId
      });

      // Validate required fields
      const requiredFields = ['name', 'type', 'category'];
      const missingFields = requiredFields.filter(field => !reportData[field]);
      
      if (missingFields.length > 0) {
        throw new ValidationError(`Missing required fields: ${missingFields.join(', ')}`);
      }

      // Validate user has permission to create reports
      const user = await User.findById(context.userId).session(session);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Set organization from context if not provided
      if (!reportData.metadata) {
        reportData.metadata = {};
      }
      reportData.metadata.organization = context.organizationId || user.organization?.current;
      reportData.metadata.createdBy = context.userId;

      // Validate organization exists
      const organization = await Organization.findById(reportData.metadata.organization).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }

      // Check organization report limits
      const reportStats = await Report.getStatistics(organization._id);
      if (organization.subscription?.limits?.maxReports && 
          reportStats.total >= organization.subscription.limits.maxReports) {
        throw new BusinessRuleError('Organization has reached maximum report limit');
      }

      // Generate report ID if not provided
      if (!reportData.reportId) {
        reportData.reportId = await this.generateReportId();
      }

      // Create report
      const report = new Report(reportData);
      await report.save({ session });

      // Create audit entry
      await AuditService.log({
        action: 'report.created',
        resourceType: 'report',
        resourceId: report._id,
        userId: context.userId,
        organizationId: reportData.metadata.organization,
        details: {
          reportId: report.reportId,
          name: report.name,
          type: report.type,
          category: report.category
        }
      });

      // Send notification
      await NotificationService.send({
        type: 'report_created',
        recipients: [context.userId],
        data: {
          reportId: report.reportId,
          reportName: report.name
        }
      });

      // Queue report for initial processing if needed
      if (report.status === 'active' && report.query) {
        await QueueHelper.addJob('report-processing', {
          reportId: report._id,
          action: 'initial_run'
        });
      }

      await session.commitTransaction();

      // Clear cache
      await CacheService.invalidate(`reports:org:${reportData.metadata.organization}`);

      logger.info('Report created successfully', { reportId: report._id });

      return report;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Create report error', { error, reportData });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Get report by ID
   * @param {string} reportId - Report ID
   * @param {Object} context - Request context
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Report
   */
  static async getReportById(reportId, context, options = {}) {
    try {
      const query = Report.findById(reportId);

      // Apply population
      if (options.populate) {
        const populateOptions = Array.isArray(options.populate) 
          ? options.populate 
          : [options.populate];
        
        populateOptions.forEach(opt => {
          query.populate(opt);
        });
      }

      const report = await query.lean();

      if (!report) {
        throw new NotFoundError('Report not found');
      }

      // Check access permission
      const hasAccess = await this.checkReportAccess(report, context.userId, 'view');
      if (!hasAccess) {
        throw new ForbiddenError('Access denied to this report');
      }

      // Update analytics
      await Report.findByIdAndUpdate(reportId, {
        $inc: { 'analytics.views': 1 },
        'analytics.lastViewedAt': new Date(),
        $push: {
          'analytics.userEngagement': {
            $each: [{
              user: context.userId,
              views: 1,
              lastActivity: new Date()
            }],
            $position: 0,
            $slice: 100
          }
        }
      });

      // Add execution status if requested
      if (options.includeExecutionStatus) {
        report.executionStatus = await this.getExecutionStatus(reportId);
      }

      return report;

    } catch (error) {
      logger.error('Get report error', { error, reportId });
      throw error;
    }
  }

  /**
   * Update report
   * @param {string} reportId - Report ID
   * @param {Object} updateData - Update data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated report
   */
  static async updateReport(reportId, updateData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const report = await Report.findById(reportId).session(session);
      
      if (!report) {
        throw new NotFoundError('Report not found');
      }

      // Check permission
      const hasAccess = await this.checkReportAccess(report, context.userId, 'edit');
      if (!hasAccess) {
        throw new ForbiddenError('Permission denied to update this report');
      }

      // Remove fields that shouldn't be updated directly
      const restrictedFields = ['reportId', 'metadata.createdBy', 'metadata.organization', 'analytics', 'executions'];
      restrictedFields.forEach(field => {
        const keys = field.split('.');
        let obj = updateData;
        for (let i = 0; i < keys.length - 1; i++) {
          if (obj[keys[i]]) {
            obj = obj[keys[i]];
          }
        }
        delete obj[keys[keys.length - 1]];
      });

      // Update metadata
      updateData.metadata = {
        ...report.metadata,
        lastModifiedBy: context.userId
      };

      // Handle schedule updates
      if (updateData.schedule) {
        await this.updateReportSchedule(report, updateData.schedule, session);
      }

      // Update report
      Object.assign(report, updateData);
      await report.save({ session });

      // Create audit entry
      await AuditService.log({
        action: 'report.updated',
        resourceType: 'report',
        resourceId: report._id,
        userId: context.userId,
        organizationId: report.metadata.organization,
        details: {
          changes: updateData
        }
      });

      // Add to change log
      report.metadata.changeLog.push({
        action: 'update',
        changes: updateData,
        changedBy: context.userId,
        changedAt: new Date()
      });

      await session.commitTransaction();

      // Clear cache
      await CacheService.invalidate(`report:${reportId}`);
      await CacheService.invalidate(`reports:org:${report.metadata.organization}`);

      return report;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Update report error', { error, reportId, updateData });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Execute report
   * @param {string} reportId - Report ID
   * @param {Object} parameters - Report parameters
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Execution result
   */
  static async executeReport(reportId, parameters = {}, context) {
    try {
      const report = await Report.findById(reportId);
      
      if (!report) {
        throw new NotFoundError('Report not found');
      }

      // Check permission
      const hasAccess = await this.checkReportAccess(report, context.userId, 'run');
      if (!hasAccess) {
        throw new ForbiddenError('Permission denied to run this report');
      }

      // Validate report is active
      if (report.status !== 'active') {
        throw new BusinessRuleError('Report is not active');
      }

      // Create execution record
      const executionId = `EXE-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
      const execution = {
        executionId,
        startTime: new Date(),
        status: 'running',
        user: context.userId,
        parameters
      };

      report.addExecution(execution);
      await report.save();

      // Check cache
      const cacheKey = `report:execution:${reportId}:${JSON.stringify(parameters)}`;
      const cachedResult = await CacheService.get(cacheKey);
      
      if (cachedResult && report.performance.caching.enabled) {
        logger.info('Returning cached report result', { reportId, executionId });
        return cachedResult;
      }

      // Queue report execution
      const job = await QueueHelper.addJob('report-execution', {
        reportId: report._id,
        executionId,
        parameters,
        userId: context.userId,
        organizationId: report.metadata.organization
      }, {
        priority: context.priority || 'normal',
        timeout: report.performance.limits.maxExecutionTime
      });

      // Wait for execution if synchronous
      if (context.synchronous) {
        const result = await this.waitForExecution(job.id, report.performance.limits.maxExecutionTime);
        
        // Cache result
        if (report.performance.caching.enabled) {
          await CacheService.set(cacheKey, result, report.performance.caching.duration);
        }

        return result;
      }

      // Return execution info for async execution
      return {
        executionId,
        jobId: job.id,
        status: 'queued',
        estimatedTime: this.estimateExecutionTime(report),
        checkUrl: `/api/reports/${reportId}/executions/${executionId}`
      };

    } catch (error) {
      logger.error('Execute report error', { error, reportId, parameters });
      throw error;
    }
  }

  /**
   * Export report
   * @param {string} reportId - Report ID
   * @param {string} format - Export format
   * @param {Object} options - Export options
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Export result
   */
  static async exportReport(reportId, format, options = {}, context) {
    try {
      const report = await Report.findById(reportId);
      
      if (!report) {
        throw new NotFoundError('Report not found');
      }

      // Check permission
      const hasAccess = await this.checkReportAccess(report, context.userId, 'export');
      if (!hasAccess) {
        throw new ForbiddenError('Permission denied to export this report');
      }

      // Validate format is supported
      const supportedFormat = report.exportConfig.formats.find(f => 
        f.type === format && f.enabled
      );
      
      if (!supportedFormat) {
        throw new ValidationError(`Export format ${format} is not supported for this report`);
      }

      // Execute report if needed
      let data;
      if (options.executeFirst) {
        const executionResult = await this.executeReport(reportId, options.parameters || {}, {
          ...context,
          synchronous: true
        });
        data = executionResult.data;
      } else {
        // Get last execution data
        const lastExecution = report.executions
          .filter(e => e.status === 'completed')
          .sort((a, b) => b.endTime - a.endTime)[0];
          
        if (!lastExecution) {
          throw new BusinessRuleError('No data available for export. Please run the report first.');
        }
        
        data = await this.getExecutionData(reportId, lastExecution.executionId);
      }

      // Generate export based on format
      let exportResult;
      switch (format) {
        case 'pdf':
          exportResult = await this.exportToPDF(report, data, supportedFormat.config.pdf, options);
          break;
        case 'excel':
          exportResult = await this.exportToExcel(report, data, supportedFormat.config.excel, options);
          break;
        case 'csv':
          exportResult = await this.exportToCSV(report, data, supportedFormat.config.csv, options);
          break;
        case 'json':
          exportResult = await this.exportToJSON(report, data, supportedFormat.config.json, options);
          break;
        default:
          throw new ValidationError(`Export handler not implemented for format: ${format}`);
      }

      // Update analytics
      await Report.findByIdAndUpdate(reportId, {
        $inc: { 'analytics.exports': 1 },
        'analytics.lastExportedAt': new Date()
      });

      // Create audit entry
      await AuditService.log({
        action: 'report.exported',
        resourceType: 'report',
        resourceId: report._id,
        userId: context.userId,
        organizationId: report.metadata.organization,
        details: {
          format,
          options,
          fileSize: exportResult.size
        }
      });

      return exportResult;

    } catch (error) {
      logger.error('Export report error', { error, reportId, format });
      throw error;
    }
  }

  /**
   * Share report
   * @param {string} reportId - Report ID
   * @param {Object} shareData - Sharing data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Share result
   */
  static async shareReport(reportId, shareData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const report = await Report.findById(reportId).session(session);
      
      if (!report) {
        throw new NotFoundError('Report not found');
      }

      // Check permission
      const hasAccess = await this.checkReportAccess(report, context.userId, 'share');
      if (!hasAccess) {
        throw new ForbiddenError('Permission denied to share this report');
      }

      const shareResult = {
        shared: [],
        failed: []
      };

      // Process each recipient
      for (const recipient of shareData.recipients) {
        try {
          let recipientUser;
          
          // Find or create recipient user
          if (recipient.userId) {
            recipientUser = await User.findById(recipient.userId).session(session);
          } else if (recipient.email) {
            recipientUser = await User.findOne({ email: recipient.email }).session(session);
          }

          if (!recipientUser && recipient.email) {
            // Send invitation email for non-users
            await this.sendReportInvitation(report, recipient.email, shareData, context);
            shareResult.shared.push({
              email: recipient.email,
              status: 'invited'
            });
            continue;
          }

          if (!recipientUser) {
            shareResult.failed.push({
              recipient,
              reason: 'User not found'
            });
            continue;
          }

          // Add sharing record
          report.shareWith({
            user: recipientUser._id,
            permissions: shareData.permissions || 'view',
            sharedBy: context.userId,
            expiresAt: shareData.expiresAt
          });

          // Send notification
          await NotificationService.send({
            type: 'report_shared',
            recipients: [recipientUser._id],
            data: {
              reportId: report.reportId,
              reportName: report.name,
              sharedBy: context.userId,
              permissions: shareData.permissions
            }
          });

          shareResult.shared.push({
            userId: recipientUser._id,
            email: recipientUser.email,
            status: 'shared'
          });

        } catch (error) {
          logger.error('Failed to share with recipient', { error, recipient });
          shareResult.failed.push({
            recipient,
            reason: error.message
          });
        }
      }

      // Handle public sharing
      if (shareData.makePublic) {
        report.sharing.isPublic = true;
        const publicUrl = report.generatePublicUrl();
        shareResult.publicUrl = publicUrl;
      }

      await report.save({ session });

      // Create audit entry
      await AuditService.log({
        action: 'report.shared',
        resourceType: 'report',
        resourceId: report._id,
        userId: context.userId,
        organizationId: report.metadata.organization,
        details: {
          recipients: shareResult.shared.length,
          failed: shareResult.failed.length,
          public: shareData.makePublic
        }
      });

      await session.commitTransaction();

      return shareResult;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Share report error', { error, reportId, shareData });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * List reports
   * @param {Object} filters - Filter criteria
   * @param {Object} context - Request context
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Reports list with pagination
   */
  static async listReports(filters = {}, context, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        sort = '-createdAt',
        search
      } = options;

      // Build query
      const query = {
        'metadata.organization': context.organizationId
      };

      // Apply filters
      if (filters.type) query.type = filters.type;
      if (filters.category) query.category = filters.category;
      if (filters.status) query.status = filters.status;
      if (filters.createdBy) query['metadata.createdBy'] = filters.createdBy;
      if (filters.tags && filters.tags.length > 0) {
        query['metadata.tags'] = { $in: filters.tags };
      }

      // Apply date filters
      if (filters.createdAfter || filters.createdBefore) {
        query.createdAt = {};
        if (filters.createdAfter) query.createdAt.$gte = new Date(filters.createdAfter);
        if (filters.createdBefore) query.createdAt.$lte = new Date(filters.createdBefore);
      }

      // Apply search
      if (search) {
        query.$text = { $search: search };
      }

      // Apply access control
      if (!context.isAdmin) {
        query.$or = [
          { 'metadata.createdBy': context.userId },
          { 'sharing.sharedWith.user': context.userId },
          { 'sharing.isPublic': true },
          { 'access.roles': { $in: context.roles || [] } }
        ];
      }

      // Execute query with pagination
      const skip = (page - 1) * limit;
      
      const [reports, total] = await Promise.all([
        Report.find(query)
          .populate('metadata.createdBy', 'firstName lastName email')
          .populate('metadata.lastModifiedBy', 'firstName lastName email')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        Report.countDocuments(query)
      ]);

      // Calculate pagination info
      const totalPages = Math.ceil(total / limit);
      const hasNext = page < totalPages;
      const hasPrev = page > 1;

      return {
        reports,
        pagination: {
          total,
          page,
          limit,
          totalPages,
          hasNext,
          hasPrev
        }
      };

    } catch (error) {
      logger.error('List reports error', { error, filters });
      throw error;
    }
  }

  /**
   * Delete report
   * @param {string} reportId - Report ID
   * @param {Object} context - Request context
   * @returns {Promise<void>}
   */
  static async deleteReport(reportId, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const report = await Report.findById(reportId).session(session);
      
      if (!report) {
        throw new NotFoundError('Report not found');
      }

      // Check permission
      const hasAccess = await this.checkReportAccess(report, context.userId, 'delete');
      if (!hasAccess) {
        throw new ForbiddenError('Permission denied to delete this report');
      }

      // Check if report has active schedules
      if (report.schedule?.isActive) {
        await this.disableReportSchedule(report._id);
      }

      // Archive instead of hard delete
      report.status = 'archived';
      report.metadata.changeLog.push({
        action: 'archive',
        changedBy: context.userId,
        changedAt: new Date(),
        reason: context.reason || 'User requested deletion'
      });

      await report.save({ session });

      // Create audit entry
      await AuditService.log({
        action: 'report.deleted',
        resourceType: 'report',
        resourceId: report._id,
        userId: context.userId,
        organizationId: report.metadata.organization,
        details: {
          reportId: report.reportId,
          name: report.name,
          reason: context.reason
        }
      });

      await session.commitTransaction();

      // Clear cache
      await CacheService.invalidate(`report:${reportId}`);
      await CacheService.invalidate(`reports:org:${report.metadata.organization}`);

    } catch (error) {
      await session.abortTransaction();
      logger.error('Delete report error', { error, reportId });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Clone report
   * @param {string} reportId - Report ID to clone
   * @param {Object} options - Clone options
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Cloned report
   */
  static async cloneReport(reportId, options = {}, context) {
    try {
      const sourceReport = await Report.findById(reportId).lean();
      
      if (!sourceReport) {
        throw new NotFoundError('Report not found');
      }

      // Check permission
      const hasAccess = await this.checkReportAccess(sourceReport, context.userId, 'view');
      if (!hasAccess) {
        throw new ForbiddenError('Permission denied to clone this report');
      }

      // Prepare clone data
      const cloneData = { ...sourceReport };
      
      // Remove unique and system fields
      delete cloneData._id;
      delete cloneData.reportId;
      delete cloneData.createdAt;
      delete cloneData.updatedAt;
      delete cloneData.executions;
      delete cloneData.analytics;
      delete cloneData.sharing;
      
      // Update metadata
      cloneData.name = options.name || `${sourceReport.name} (Copy)`;
      cloneData.slug = null; // Will be auto-generated
      cloneData.status = 'draft';
      cloneData.metadata = {
        ...cloneData.metadata,
        createdBy: context.userId,
        lastModifiedBy: context.userId,
        changeLog: [{
          action: 'cloned',
          changedBy: context.userId,
          changedAt: new Date(),
          reason: `Cloned from ${sourceReport.reportId}`
        }]
      };

      // Reset schedule if requested
      if (!options.includeSchedule) {
        cloneData.schedule = {
          isActive: false
        };
      }

      // Create the cloned report
      const clonedReport = await this.createReport(cloneData, context);

      return clonedReport;

    } catch (error) {
      logger.error('Clone report error', { error, reportId });
      throw error;
    }
  }

  // ===== Helper Methods =====

  /**
   * Generate unique report ID
   * @returns {Promise<string>} Report ID
   */
  static async generateReportId() {
    let reportId;
    let exists = true;
    
    while (exists) {
      const randomId = crypto.randomBytes(4).toString('hex').toUpperCase();
      reportId = `RPT-${randomId}`;
      exists = await Report.exists({ reportId });
    }
    
    return reportId;
  }

  /**
   * Check report access
   * @param {Object} report - Report document
   * @param {string} userId - User ID
   * @param {string} action - Action to check
   * @returns {Promise<boolean>} Has access
   */
  static async checkReportAccess(report, userId, action = 'view') {
    // Report creator always has full access
    if (report.metadata.createdBy.toString() === userId.toString()) {
      return true;
    }

    // Check report-level permissions
    if (report.hasPermission && typeof report.hasPermission === 'function') {
      return report.hasPermission(userId, action);
    }

    // Get user context for role-based checks
    const user = await User.findById(userId).lean();
    if (!user) return false;

    const userContext = {
      roles: [user.role.primary, ...(user.role.secondary || [])],
      department: user.profile.department,
      teams: user.teams || []
    };

    // Check access control rules
    return report.access.hasPermission(userId, action, userContext);
  }

  /**
   * Update report schedule
   * @param {Object} report - Report document
   * @param {Object} scheduleData - Schedule data
   * @param {Object} session - MongoDB session
   */
  static async updateReportSchedule(report, scheduleData, session) {
    // Cancel existing schedule if any
    if (report._scheduledJob) {
      report._scheduledJob.stop();
    }

    // Update schedule data
    report.schedule = { ...report.schedule, ...scheduleData };

    // Create new schedule if active
    if (scheduleData.isActive) {
      const cronExpression = this.buildCronExpression(scheduleData);
      
      const job = cron.schedule(cronExpression, async () => {
        try {
          await this.executeScheduledReport(report._id);
        } catch (error) {
          logger.error('Scheduled report execution failed', { error, reportId: report._id });
        }
      }, {
        scheduled: true,
        timezone: scheduleData.timezone || 'UTC'
      });

      report._scheduledJob = job;
    }
  }

  /**
   * Build cron expression from schedule configuration
   * @param {Object} schedule - Schedule configuration
   * @returns {string} Cron expression
   */
  static buildCronExpression(schedule) {
    switch (schedule.frequency) {
      case 'hourly':
        const interval = schedule.hourlyConfig?.interval || 1;
        const minute = schedule.hourlyConfig?.minute || 0;
        return `${minute} */${interval} * * *`;
        
      case 'daily':
        const [hour, min] = (schedule.dailyConfig?.time || '09:00').split(':');
        return `${min} ${hour} * * *`;
        
      case 'weekly':
        const days = schedule.weeklyConfig?.daysOfWeek?.join(',') || '1';
        const [wHour, wMin] = (schedule.weeklyConfig?.time || '09:00').split(':');
        return `${wMin} ${wHour} * * ${days}`;
        
      case 'monthly':
        const dayOfMonth = schedule.monthlyConfig?.dayOfMonth || 1;
        const [mHour, mMin] = (schedule.monthlyConfig?.time || '09:00').split(':');
        return `${mMin} ${mHour} ${dayOfMonth} * *`;
        
      case 'custom':
        return schedule.customConfig?.cronExpression;
        
      default:
        throw new ValidationError(`Invalid schedule frequency: ${schedule.frequency}`);
    }
  }

  /**
   * Execute scheduled report
   * @param {string} reportId - Report ID
   */
  static async executeScheduledReport(reportId) {
    try {
      const report = await Report.findById(reportId);
      if (!report || !report.schedule?.isActive) {
        return;
      }

      // Execute report
      const result = await this.executeReport(reportId, report.schedule.parameters || {}, {
        userId: report.schedule.createdBy,
        organizationId: report.metadata.organization,
        isScheduled: true,
        synchronous: true
      });

      // Process delivery
      await this.deliverScheduledReport(report, result);

      // Update next run time
      report.schedule.lastRunAt = new Date();
      report.schedule.executionStats.totalRuns += 1;
      report.schedule.executionStats.successfulRuns += 1;
      
      await report.save();

    } catch (error) {
      logger.error('Scheduled report execution error', { error, reportId });
      
      // Update failure stats
      await Report.findByIdAndUpdate(reportId, {
        'schedule.lastFailureAt': new Date(),
        $inc: {
          'schedule.executionStats.totalRuns': 1,
          'schedule.executionStats.failedRuns': 1
        }
      });

      // Handle failure threshold
      const report = await Report.findById(reportId);
      if (report.schedule.errorHandling?.failureThreshold?.count &&
          report.schedule.executionStats.failedRuns >= report.schedule.errorHandling.failureThreshold.count) {
        
        if (report.schedule.errorHandling.failureThreshold.action === 'disable') {
          report.schedule.isActive = false;
          await report.save();
        }
      }
    }
  }

  /**
   * Export report to PDF
   * @param {Object} report - Report document
   * @param {Object} data - Report data
   * @param {Object} config - PDF configuration
   * @param {Object} options - Export options
   * @returns {Promise<Object>} Export result
   */
  static async exportToPDF(report, data, config = {}, options = {}) {
    try {
      const pdfOptions = {
        format: config.pageSize || 'A4',
        orientation: config.orientation || 'portrait',
        margin: config.margins || { top: 10, right: 10, bottom: 10, left: 10 },
        displayHeaderFooter: config.includeHeader || config.includeFooter,
        headerTemplate: config.includeHeader ? this.buildPDFHeader(report) : '',
        footerTemplate: config.includeFooter ? this.buildPDFFooter(report, config) : '',
        printBackground: true
      };

      // Generate HTML content
      const htmlContent = await this.generateReportHTML(report, data, options);

      // Generate PDF
      const pdfBuffer = await PDFGenerator.generate(htmlContent, pdfOptions);

      // Apply security if configured
      if (config.encryption?.enabled) {
        // Apply PDF encryption/security
        // This would use a PDF library like pdf-lib or similar
      }

      // Store temporarily
      const filename = `${report.reportId}_${Date.now()}.pdf`;
      const filePath = await FileService.saveTemp(pdfBuffer, filename);

      return {
        format: 'pdf',
        filename,
        filePath,
        size: pdfBuffer.length,
        mimeType: 'application/pdf',
        url: await FileService.getSignedUrl(filePath)
      };

    } catch (error) {
      logger.error('Export to PDF error', { error, reportId: report._id });
      throw error;
    }
  }

  /**
   * Export report to Excel
   * @param {Object} report - Report document
   * @param {Object} data - Report data
   * @param {Object} config - Excel configuration
   * @param {Object} options - Export options
   * @returns {Promise<Object>} Export result
   */
  static async exportToExcel(report, data, config = {}, options = {}) {
    try {
      const workbook = await ExcelGenerator.createWorkbook();

      // Process each visualization as a sheet
      for (const viz of report.visualizations) {
        const sheetData = this.prepareDataForExcel(data, viz);
        const sheetConfig = config.sheetsConfig?.find(s => s.data === viz.id) || {};
        
        const sheet = await ExcelGenerator.addSheet(workbook, {
          name: sheetConfig.name || viz.name,
          data: sheetData,
          columns: this.getExcelColumns(viz),
          ...sheetConfig
        });

        // Apply styling
        if (config.styling) {
          await ExcelGenerator.applyStyles(sheet, config.styling);
        }
      }

      // Generate Excel buffer
      const excelBuffer = await ExcelGenerator.writeToBuffer(workbook);

      // Store temporarily
      const filename = `${report.reportId}_${Date.now()}.xlsx`;
      const filePath = await FileService.saveTemp(excelBuffer, filename);

      return {
        format: 'excel',
        filename,
        filePath,
        size: excelBuffer.length,
        mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        url: await FileService.getSignedUrl(filePath)
      };

    } catch (error) {
      logger.error('Export to Excel error', { error, reportId: report._id });
      throw error;
    }
  }

  /**
   * Get report statistics
   * @param {Object} filters - Filter criteria
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Statistics
   */
  static async getReportStatistics(filters = {}, context) {
    try {
      const stats = await Report.getStatistics(context.organizationId);
      
      // Add user-specific stats
      const userStats = await Report.aggregate([
        {
          $match: {
            'metadata.organization': new mongoose.Types.ObjectId(context.organizationId),
            'metadata.createdBy': new mongoose.Types.ObjectId(context.userId)
          }
        },
        {
          $group: {
            _id: null,
            created: { $sum: 1 },
            totalRuns: { $sum: '$analytics.runs' },
            totalViews: { $sum: '$analytics.views' }
          }
        }
      ]);

      return {
        ...stats,
        user: userStats[0] || { created: 0, totalRuns: 0, totalViews: 0 }
      };

    } catch (error) {
      logger.error('Get report statistics error', { error });
      throw error;
    }
  }
}

module.exports = ReportsService;