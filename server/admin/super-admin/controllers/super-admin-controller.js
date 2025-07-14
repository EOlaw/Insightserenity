// server/admin/super-admin/controllers/super-admin-controller.js
/**
 * @file Super Admin Controller
 * @description Controller for super administrator operations and system management
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const SuperAdminService = require('../services/super-admin-service');
const RoleManagementService = require('../services/role-management-service');
const SystemSettingsService = require('../services/system-settings-service');
const EmergencyAccessService = require('../services/emergency-access-service');
const AuditService = require('../../../shared/security/services/audit-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const ResponseHandler = require('../../../shared/utils/response-handler');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');

// Validation
const { validateRequest } = require('../../../shared/middleware/validate-request');
const SuperAdminValidation = require('../validation/super-admin-validation');

/**
 * Super Admin Controller Class
 * @class SuperAdminController
 */
class SuperAdminController {
  /**
   * Get system overview dashboard
   * @route GET /api/admin/super-admin/overview
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getSystemOverview(req, res, next) {
    try {
      const adminUser = req.user;
      const options = {
        skipCache: req.query.refresh === 'true',
        activityLimit: parseInt(req.query.activityLimit) || 20
      };

      logger.info('System overview requested', {
        adminId: adminUser.id,
        options
      });

      const overview = await SuperAdminService.getSystemOverview(adminUser, options);

      ResponseHandler.success(res, {
        message: 'System overview retrieved successfully',
        data: overview,
        metadata: {
          timestamp: new Date(),
          cached: !options.skipCache
        }
      });

    } catch (error) {
      logger.error('Get system overview error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get detailed system statistics
   * @route GET /api/admin/super-admin/statistics
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getSystemStatistics(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        endDate = new Date(),
        granularity = 'daily',
        metrics = 'all'
      } = req.query;

      // Validate date range
      if (new Date(startDate) > new Date(endDate)) {
        throw new ValidationError('Start date must be before end date');
      }

      logger.info('System statistics requested', {
        adminId: adminUser.id,
        dateRange: { startDate, endDate },
        granularity,
        metrics
      });

      const statistics = await SuperAdminService.getDetailedStatistics(adminUser, {
        startDate: new Date(startDate),
        endDate: new Date(endDate),
        granularity,
        metrics: metrics === 'all' ? null : metrics.split(',')
      });

      ResponseHandler.success(res, {
        message: 'System statistics retrieved successfully',
        data: statistics,
        metadata: {
          dateRange: { startDate, endDate },
          granularity,
          metricsIncluded: metrics
        }
      });

    } catch (error) {
      logger.error('Get system statistics error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Search system entities
   * @route GET /api/admin/super-admin/search
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async searchSystemEntities(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        query,
        types = 'users,organizations,roles',
        page = 1,
        limit = 20
      } = req.query;

      if (!query || query.trim().length < 2) {
        throw new ValidationError('Search query must be at least 2 characters');
      }

      logger.info('System search requested', {
        adminId: adminUser.id,
        query,
        types
      });

      const searchResults = await SuperAdminService.searchSystem(adminUser, {
        query: query.trim(),
        entityTypes: types.split(','),
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit)
        }
      });

      ResponseHandler.success(res, {
        message: 'Search completed successfully',
        data: searchResults,
        metadata: {
          query,
          types: types.split(','),
          resultCount: searchResults.totalResults
        }
      });

    } catch (error) {
      logger.error('Search system entities error', {
        error: error.message,
        adminId: req.user?.id,
        query: req.query.query,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Impersonate user
   * @route POST /api/admin/super-admin/impersonate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async impersonateUser(req, res, next) {
    try {
      await validateRequest(SuperAdminValidation.impersonateUser, req);

      const adminUser = req.user;
      const { userId, reason, duration, restrictions, requireMFA, notifyUser } = req.body;

      logger.warn('User impersonation requested', {
        adminId: adminUser.id,
        targetUserId: userId,
        reason: reason.substring(0, 50) + '...'
      });

      const impersonationResult = await SuperAdminService.impersonateUser(
        adminUser,
        userId,
        {
          reason,
          duration: duration || 3600,
          restrictions: restrictions || [],
          requireMFA: requireMFA !== false,
          notifyUser: notifyUser !== false
        }
      );

      // Set impersonation token in response header
      res.setHeader('X-Impersonation-Token', impersonationResult.accessToken);

      ResponseHandler.success(res, {
        message: 'User impersonation initiated successfully',
        data: {
          sessionId: impersonationResult.sessionId,
          targetUser: impersonationResult.targetUser,
          expiresAt: impersonationResult.expiresAt,
          restrictions: impersonationResult.restrictions,
          requireMFA: impersonationResult.requireMFA
        },
        metadata: {
          warning: 'All actions are being monitored and logged'
        }
      }, 201);

    } catch (error) {
      logger.error('Impersonate user error', {
        error: error.message,
        adminId: req.user?.id,
        targetUserId: req.body?.userId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * End impersonation session
   * @route POST /api/admin/super-admin/impersonate/:sessionId/end
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async endImpersonation(req, res, next) {
    try {
      const adminUser = req.user;
      const { sessionId } = req.params;

      logger.info('End impersonation requested', {
        adminId: adminUser.id,
        sessionId
      });

      const result = await SuperAdminService.endImpersonation(adminUser, sessionId);

      ResponseHandler.success(res, {
        message: 'Impersonation session ended successfully',
        data: result
      });

    } catch (error) {
      logger.error('End impersonation error', {
        error: error.message,
        adminId: req.user?.id,
        sessionId: req.params?.sessionId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Execute emergency action
   * @route POST /api/admin/super-admin/emergency-action
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async executeEmergencyAction(req, res, next) {
    try {
      await validateRequest(SuperAdminValidation.emergencyAction, req);

      const adminUser = req.user;
      const actionData = req.body;

      logger.critical('Emergency action requested', {
        adminId: adminUser.id,
        action: actionData.action,
        scope: actionData.scope
      });

      const result = await SuperAdminService.executeEmergencyAction(
        adminUser,
        actionData
      );

      // Handle confirmation requirement
      if (result.requiresConfirmation) {
        return ResponseHandler.success(res, {
          message: result.message,
          data: {
            requiresConfirmation: true,
            action: result.action
          }
        }, 202);
      }

      ResponseHandler.success(res, {
        message: 'Emergency action executed successfully',
        data: result,
        metadata: {
          severity: 'critical',
          notificationssSent: true
        }
      }, 201);

    } catch (error) {
      logger.error('Execute emergency action error', {
        error: error.message,
        adminId: req.user?.id,
        action: req.body?.action,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Modify system configuration
   * @route PUT /api/admin/super-admin/configuration
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async modifySystemConfiguration(req, res, next) {
    try {
      await validateRequest(SuperAdminValidation.modifyConfiguration, req);

      const adminUser = req.user;
      const configData = req.body;

      logger.warn('System configuration modification requested', {
        adminId: adminUser.id,
        category: configData.category,
        settingsCount: Object.keys(configData.settings).length
      });

      const result = await SuperAdminService.modifySystemConfiguration(
        adminUser,
        configData
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: result,
        metadata: {
          warning: result.testMode ? 
            'Configuration validated in test mode' : 
            'Configuration changes are now active'
        }
      });

    } catch (error) {
      logger.error('Modify system configuration error', {
        error: error.message,
        adminId: req.user?.id,
        category: req.body?.category,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get system health status
   * @route GET /api/admin/super-admin/health
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getSystemHealth(req, res, next) {
    try {
      const adminUser = req.user;
      const { detailed = 'false', components = 'all' } = req.query;

      logger.info('System health check requested', {
        adminId: adminUser.id,
        detailed,
        components
      });

      const healthStatus = await SuperAdminService.getSystemHealthStatus(adminUser, {
        detailed: detailed === 'true',
        components: components === 'all' ? null : components.split(',')
      });

      const statusCode = healthStatus.overallStatus === 'healthy' ? 200 : 
                        healthStatus.overallStatus === 'degraded' ? 206 : 503;

      ResponseHandler.success(res, {
        message: `System status: ${healthStatus.overallStatus}`,
        data: healthStatus
      }, statusCode);

    } catch (error) {
      logger.error('Get system health error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get admin activity logs
   * @route GET /api/admin/super-admin/activity-logs
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getAdminActivityLogs(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        adminId,
        action,
        startDate,
        endDate,
        severity,
        page = 1,
        limit = 50
      } = req.query;

      logger.info('Admin activity logs requested', {
        adminId: adminUser.id,
        filters: { adminId, action, severity }
      });

      const logs = await SuperAdminService.getAdminActivityLogs(adminUser, {
        filters: {
          adminId,
          action,
          startDate: startDate ? new Date(startDate) : undefined,
          endDate: endDate ? new Date(endDate) : undefined,
          severity
        },
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit)
        }
      });

      ResponseHandler.success(res, {
        message: 'Activity logs retrieved successfully',
        data: logs.logs,
        pagination: logs.pagination,
        metadata: {
          totalCritical: logs.statistics.critical,
          totalHigh: logs.statistics.high
        }
      });

    } catch (error) {
      logger.error('Get admin activity logs error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Generate system report
   * @route POST /api/admin/super-admin/reports/generate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async generateSystemReport(req, res, next) {
    try {
      await validateRequest(SuperAdminValidation.generateReport, req);

      const adminUser = req.user;
      const {
        reportType,
        dateRange,
        format = 'pdf',
        includeCharts = true,
        recipients = []
      } = req.body;

      logger.info('System report generation requested', {
        adminId: adminUser.id,
        reportType,
        format
      });

      const report = await SuperAdminService.generateSystemReport(adminUser, {
        reportType,
        dateRange,
        format,
        includeCharts,
        recipients
      });

      // If file download requested
      if (req.query.download === 'true') {
        res.setHeader('Content-Type', report.contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
        return res.send(report.data);
      }

      ResponseHandler.success(res, {
        message: 'System report generated successfully',
        data: {
          reportId: report.id,
          filename: report.filename,
          size: report.size,
          downloadUrl: report.downloadUrl,
          expiresAt: report.expiresAt
        },
        metadata: {
          recipientCount: recipients.length,
          format
        }
      }, 201);

    } catch (error) {
      logger.error('Generate system report error', {
        error: error.message,
        adminId: req.user?.id,
        reportType: req.body?.reportType,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Execute system maintenance
   * @route POST /api/admin/super-admin/maintenance
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async executeSystemMaintenance(req, res, next) {
    try {
      await validateRequest(SuperAdminValidation.systemMaintenance, req);

      const adminUser = req.user;
      const {
        maintenanceType,
        scheduledAt,
        duration,
        notification,
        tasks
      } = req.body;

      logger.warn('System maintenance requested', {
        adminId: adminUser.id,
        maintenanceType,
        scheduledAt
      });

      const maintenance = await SuperAdminService.scheduleSystemMaintenance(adminUser, {
        maintenanceType,
        scheduledAt: new Date(scheduledAt),
        duration,
        notification,
        tasks
      });

      ResponseHandler.success(res, {
        message: 'System maintenance scheduled successfully',
        data: maintenance,
        metadata: {
          warning: 'Users will be notified according to the notification settings'
        }
      }, 201);

    } catch (error) {
      logger.error('Execute system maintenance error', {
        error: error.message,
        adminId: req.user?.id,
        maintenanceType: req.body?.maintenanceType,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get platform analytics
   * @route GET /api/admin/super-admin/analytics
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getPlatformAnalytics(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        metric = 'all',
        period = '30d',
        groupBy = 'day',
        includeProjections = 'false'
      } = req.query;

      logger.info('Platform analytics requested', {
        adminId: adminUser.id,
        metric,
        period
      });

      const analytics = await SuperAdminService.getPlatformAnalytics(adminUser, {
        metrics: metric === 'all' ? null : metric.split(','),
        period,
        groupBy,
        includeProjections: includeProjections === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Platform analytics retrieved successfully',
        data: analytics,
        metadata: {
          period,
          dataPoints: analytics.dataPoints?.length || 0,
          lastUpdated: analytics.lastUpdated
        }
      });

    } catch (error) {
      logger.error('Get platform analytics error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Manage platform notifications
   * @route POST /api/admin/super-admin/notifications/broadcast
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async broadcastNotification(req, res, next) {
    try {
      await validateRequest(SuperAdminValidation.broadcastNotification, req);

      const adminUser = req.user;
      const {
        type,
        title,
        message,
        targetAudience,
        priority = 'medium',
        channels = ['in-app', 'email'],
        scheduledAt
      } = req.body;

      logger.info('Broadcast notification requested', {
        adminId: adminUser.id,
        type,
        targetAudience,
        priority
      });

      const broadcast = await NotificationService.createBroadcast({
        sender: adminUser,
        type,
        title,
        message,
        targetAudience,
        priority,
        channels,
        scheduledAt: scheduledAt ? new Date(scheduledAt) : null
      });

      ResponseHandler.success(res, {
        message: 'Broadcast notification created successfully',
        data: {
          broadcastId: broadcast.id,
          recipientCount: broadcast.recipientCount,
          scheduledAt: broadcast.scheduledAt,
          status: broadcast.status
        }
      }, 201);

    } catch (error) {
      logger.error('Broadcast notification error', {
        error: error.message,
        adminId: req.user?.id,
        type: req.body?.type,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Export system data
   * @route POST /api/admin/super-admin/export
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async exportSystemData(req, res, next) {
    try {
      await validateRequest(SuperAdminValidation.exportData, req);

      const adminUser = req.user;
      const {
        dataTypes,
        format = 'json',
        dateRange,
        includeMetadata = true,
        compress = true
      } = req.body;

      logger.warn('System data export requested', {
        adminId: adminUser.id,
        dataTypes,
        format
      });

      const exportResult = await SuperAdminService.exportSystemData(adminUser, {
        dataTypes,
        format,
        dateRange,
        includeMetadata,
        compress
      });

      // If direct download
      if (req.query.download === 'true') {
        res.setHeader('Content-Type', exportResult.contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${exportResult.filename}"`);
        if (compress) {
          res.setHeader('Content-Encoding', 'gzip');
        }
        return res.send(exportResult.data);
      }

      ResponseHandler.success(res, {
        message: 'System data export initiated',
        data: {
          exportId: exportResult.id,
          filename: exportResult.filename,
          size: exportResult.size,
          downloadUrl: exportResult.downloadUrl,
          expiresAt: exportResult.expiresAt
        }
      }, 201);

    } catch (error) {
      logger.error('Export system data error', {
        error: error.message,
        adminId: req.user?.id,
        dataTypes: req.body?.dataTypes,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get system audit summary
   * @route GET /api/admin/super-admin/audit-summary
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getAuditSummary(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        period = '7d',
        groupBy = 'action',
        includeRiskAnalysis = 'true'
      } = req.query;

      logger.info('Audit summary requested', {
        adminId: adminUser.id,
        period,
        groupBy
      });

      const summary = await AuditService.generateAuditSummary({
        period,
        groupBy,
        includeRiskAnalysis: includeRiskAnalysis === 'true',
        requester: adminUser
      });

      ResponseHandler.success(res, {
        message: 'Audit summary generated successfully',
        data: summary,
        metadata: {
          period,
          totalEvents: summary.totalEvents,
          criticalEvents: summary.criticalEvents
        }
      });

    } catch (error) {
      logger.error('Get audit summary error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }
}

module.exports = new SuperAdminController();