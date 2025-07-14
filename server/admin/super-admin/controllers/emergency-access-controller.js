// server/admin/super-admin/controllers/emergency-access-controller.js
/**
 * @file Emergency Access Controller
 * @description Controller for emergency access, break glass procedures, and critical operations
 * @version 1.0.0
 */

const mongoose = require('mongoose');

// Services
const EmergencyAccessService = require('../services/emergency-access-service');
const SuperAdminService = require('../services/super-admin-service');
const AuditService = require('../../../shared/security/services/audit-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const SecurityService = require('../../../shared/security/services/security-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const ResponseHandler = require('../../../shared/utils/response-handler');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');

// Validation
const { validateRequest } = require('../../../shared/middleware/validate-request');
const EmergencyAccessValidation = require('../validation/emergency-access-validation');

/**
 * Emergency Access Controller Class
 * @class EmergencyAccessController
 */
class EmergencyAccessController {
  /**
   * Request emergency access
   * @route POST /api/admin/super-admin/emergency-access/request
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async requestEmergencyAccess(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.requestAccess, req);

      const adminUser = req.user;
      const requestData = req.body;

      logger.critical('Emergency access requested', {
        adminId: adminUser.id,
        accessType: requestData.accessType,
        urgencyLevel: requestData.urgencyLevel,
        affectedSystems: requestData.affectedSystems
      });

      const result = await EmergencyAccessService.requestEmergencyAccess(
        adminUser,
        requestData
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          requestId: result.requestId,
          status: result.status,
          codeExpiresAt: result.codeExpiresAt,
          requireDualAuth: result.requireDualAuth,
          secondaryAdmin: result.secondaryAdmin
        },
        metadata: {
          severity: 'critical',
          monitoringActive: true
        }
      }, 201);

    } catch (error) {
      logger.error('Request emergency access error', {
        error: error.message,
        adminId: req.user?.id,
        accessType: req.body?.accessType,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Activate emergency access
   * @route POST /api/admin/super-admin/emergency-access/:requestId/activate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async activateEmergencyAccess(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.activateAccess, req);

      const adminUser = req.user;
      const { requestId } = req.params;
      const activationData = req.body;

      logger.critical('Emergency access activation requested', {
        adminId: adminUser.id,
        requestId,
        hasPrimaryCode: !!activationData.primaryCode,
        hasSecondaryCode: !!activationData.secondaryCode
      });

      const result = await EmergencyAccessService.activateEmergencyAccess(
        adminUser,
        requestId,
        activationData
      );

      // Set emergency access token in response header
      res.setHeader('X-Emergency-Access-Token', result.accessToken);

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          success: result.success,
          expiresAt: result.expiresAt,
          permissions: result.permissions,
          restrictions: result.restrictions,
          monitoringEnabled: result.monitoringEnabled
        },
        metadata: {
          warning: 'All actions under emergency access are monitored and logged',
          severity: 'critical'
        }
      });

    } catch (error) {
      logger.error('Activate emergency access error', {
        error: error.message,
        adminId: req.user?.id,
        requestId: req.params?.requestId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Revoke emergency access
   * @route POST /api/admin/super-admin/emergency-access/:requestId/revoke
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async revokeEmergencyAccess(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.revokeAccess, req);

      const adminUser = req.user;
      const { requestId } = req.params;
      const revokeData = req.body;

      logger.critical('Emergency access revocation requested', {
        adminId: adminUser.id,
        requestId,
        immediate: revokeData.immediate
      });

      const result = await EmergencyAccessService.revokeEmergencyAccess(
        adminUser,
        requestId,
        revokeData
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          success: result.success,
          revokedAt: result.revokedAt,
          incidentReport: result.incidentReport,
          actionsPerformed: result.actionsPerformed
        }
      });

    } catch (error) {
      logger.error('Revoke emergency access error', {
        error: error.message,
        adminId: req.user?.id,
        requestId: req.params?.requestId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get active emergency sessions
   * @route GET /api/admin/super-admin/emergency-access/active
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getActiveEmergencySessions(req, res, next) {
    try {
      const adminUser = req.user;
      const { includeExpired = 'false', includeActions = 'true' } = req.query;

      logger.info('Get active emergency sessions requested', {
        adminId: adminUser.id,
        includeExpired: includeExpired === 'true'
      });

      const result = await EmergencyAccessService.getActiveEmergencySessions(adminUser, {
        includeExpired: includeExpired === 'true',
        includeActions: includeActions === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Active emergency sessions retrieved successfully',
        data: {
          sessions: result.sessions,
          systemStatus: result.systemStatus,
          statistics: result.statistics
        }
      });

    } catch (error) {
      logger.error('Get active emergency sessions error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Create break glass access
   * @route POST /api/admin/super-admin/emergency-access/break-glass
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async createBreakGlassAccess(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.breakGlass, req);

      const adminUser = req.user;
      const breakGlassData = req.body;

      logger.critical('Break glass access requested', {
        adminId: adminUser.id,
        systems: breakGlassData.systems,
        hasVideoAuth: !!breakGlassData.videoAuthToken
      });

      const result = await EmergencyAccessService.createBreakGlassAccess(
        adminUser,
        breakGlassData
      );

      ResponseHandler.success(res, {
        message: result.message,
        data: {
          breakGlassId: result.breakGlassId,
          activated: result.activated,
          expiresAt: result.expiresAt,
          permissions: result.permissions,
          monitoringActive: result.monitoringActive,
          alertsSent: result.alertsSent
        },
        metadata: {
          severity: 'critical',
          warning: 'Break glass access is for extreme emergencies only'
        }
      }, 201);

    } catch (error) {
      logger.error('Create break glass access error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get emergency access audit trail
   * @route GET /api/admin/super-admin/emergency-access/:requestId/audit
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getEmergencyAccessAuditTrail(req, res, next) {
    try {
      const adminUser = req.user;
      const { requestId } = req.params;

      logger.info('Emergency access audit trail requested', {
        adminId: adminUser.id,
        requestId
      });

      const auditTrail = await EmergencyAccessService.getEmergencyAccessAuditTrail(
        adminUser,
        requestId
      );

      ResponseHandler.success(res, {
        message: 'Audit trail retrieved successfully',
        data: auditTrail
      });

    } catch (error) {
      logger.error('Get emergency access audit trail error', {
        error: error.message,
        adminId: req.user?.id,
        requestId: req.params?.requestId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Execute system bypass
   * @route POST /api/admin/super-admin/emergency-access/bypass
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async executeSystemBypass(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.systemBypass, req);

      const adminUser = req.user;
      const { bypassType, targets, duration, reason } = req.body;

      logger.critical('System bypass requested', {
        adminId: adminUser.id,
        bypassType,
        targetCount: targets.length
      });

      const result = await EmergencyAccessService.executeSystemBypass(adminUser, {
        bypassType,
        targets,
        duration,
        reason
      });

      ResponseHandler.success(res, {
        message: 'System bypass executed successfully',
        data: {
          bypassId: result.bypassId,
          affectedTargets: result.affectedTargets,
          expiresAt: result.expiresAt
        },
        metadata: {
          severity: 'critical',
          reversible: result.reversible
        }
      }, 201);

    } catch (error) {
      logger.error('Execute system bypass error', {
        error: error.message,
        adminId: req.user?.id,
        bypassType: req.body?.bypassType,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Unlock system resources
   * @route POST /api/admin/super-admin/emergency-access/unlock
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async unlockSystemResources(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.unlockResources, req);

      const adminUser = req.user;
      const { resourceType, resourceIds, reason, notifyAffected = true } = req.body;

      logger.warn('System resource unlock requested', {
        adminId: adminUser.id,
        resourceType,
        resourceCount: resourceIds.length
      });

      const result = await EmergencyAccessService.unlockSystemResources(adminUser, {
        resourceType,
        resourceIds,
        reason,
        notifyAffected
      });

      ResponseHandler.success(res, {
        message: 'System resources unlocked successfully',
        data: {
          unlockedCount: result.unlockedCount,
          failedUnlocks: result.failedUnlocks,
          notifications: result.notificationsSent
        }
      });

    } catch (error) {
      logger.error('Unlock system resources error', {
        error: error.message,
        adminId: req.user?.id,
        resourceType: req.body?.resourceType,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get emergency access statistics
   * @route GET /api/admin/super-admin/emergency-access/statistics
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getEmergencyAccessStatistics(req, res, next) {
    try {
      const adminUser = req.user;
      const {
        period = '30d',
        groupBy = 'type',
        includeDetails = 'false'
      } = req.query;

      logger.info('Emergency access statistics requested', {
        adminId: adminUser.id,
        period,
        groupBy
      });

      const statistics = await EmergencyAccessService.getEmergencyAccessStatistics(
        adminUser,
        {
          period,
          groupBy,
          includeDetails: includeDetails === 'true'
        }
      );

      ResponseHandler.success(res, {
        message: 'Emergency access statistics retrieved successfully',
        data: statistics
      });

    } catch (error) {
      logger.error('Get emergency access statistics error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Test emergency procedures
   * @route POST /api/admin/super-admin/emergency-access/test
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async testEmergencyProcedures(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.testProcedures, req);

      const adminUser = req.user;
      const { procedureType, testScenario, dryRun = true } = req.body;

      logger.info('Emergency procedure test requested', {
        adminId: adminUser.id,
        procedureType,
        testScenario,
        dryRun
      });

      const result = await EmergencyAccessService.testEmergencyProcedures(adminUser, {
        procedureType,
        testScenario,
        dryRun
      });

      ResponseHandler.success(res, {
        message: 'Emergency procedure test completed',
        data: {
          testId: result.testId,
          results: result.results,
          recommendations: result.recommendations
        },
        metadata: {
          dryRun,
          testDuration: result.duration
        }
      });

    } catch (error) {
      logger.error('Test emergency procedures error', {
        error: error.message,
        adminId: req.user?.id,
        procedureType: req.body?.procedureType,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Configure emergency contacts
   * @route PUT /api/admin/super-admin/emergency-access/contacts
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async configureEmergencyContacts(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.configureContacts, req);

      const adminUser = req.user;
      const { contacts, escalationChain, notificationSettings } = req.body;

      logger.info('Configure emergency contacts requested', {
        adminId: adminUser.id,
        contactCount: contacts.length
      });

      const result = await EmergencyAccessService.configureEmergencyContacts(adminUser, {
        contacts,
        escalationChain,
        notificationSettings
      });

      ResponseHandler.success(res, {
        message: 'Emergency contacts configured successfully',
        data: result
      });

    } catch (error) {
      logger.error('Configure emergency contacts error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Generate emergency access report
   * @route POST /api/admin/super-admin/emergency-access/reports/generate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async generateEmergencyAccessReport(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.generateReport, req);

      const adminUser = req.user;
      const {
        reportType,
        dateRange,
        includeRecommendations = true,
        format = 'pdf'
      } = req.body;

      logger.info('Emergency access report requested', {
        adminId: adminUser.id,
        reportType,
        format
      });

      const report = await EmergencyAccessService.generateEmergencyAccessReport(
        adminUser,
        {
          reportType,
          dateRange,
          includeRecommendations,
          format
        }
      );

      if (req.query.download === 'true') {
        res.setHeader('Content-Type', report.contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${report.filename}"`);
        return res.send(report.data);
      }

      ResponseHandler.success(res, {
        message: 'Emergency access report generated successfully',
        data: {
          reportId: report.id,
          filename: report.filename,
          size: report.size,
          downloadUrl: report.downloadUrl
        }
      }, 201);

    } catch (error) {
      logger.error('Generate emergency access report error', {
        error: error.message,
        adminId: req.user?.id,
        reportType: req.body?.reportType,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Review emergency access request
   * @route POST /api/admin/super-admin/emergency-access/:requestId/review
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async reviewEmergencyAccessRequest(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.reviewRequest, req);

      const adminUser = req.user;
      const { requestId } = req.params;
      const { decision, comments, conditions } = req.body;

      logger.info('Emergency access review requested', {
        adminId: adminUser.id,
        requestId,
        decision
      });

      const result = await EmergencyAccessService.reviewEmergencyAccessRequest(
        adminUser,
        requestId,
        {
          decision,
          comments,
          conditions
        }
      );

      ResponseHandler.success(res, {
        message: `Emergency access request ${decision}`,
        data: result
      });

    } catch (error) {
      logger.error('Review emergency access request error', {
        error: error.message,
        adminId: req.user?.id,
        requestId: req.params?.requestId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get emergency protocols
   * @route GET /api/admin/super-admin/emergency-access/protocols
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getEmergencyProtocols(req, res, next) {
    try {
      const adminUser = req.user;
      const { category, active = 'true' } = req.query;

      logger.info('Get emergency protocols requested', {
        adminId: adminUser.id,
        category,
        activeOnly: active === 'true'
      });

      const protocols = await EmergencyAccessService.getEmergencyProtocols(adminUser, {
        category,
        activeOnly: active === 'true'
      });

      ResponseHandler.success(res, {
        message: 'Emergency protocols retrieved successfully',
        data: protocols
      });

    } catch (error) {
      logger.error('Get emergency protocols error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Update emergency protocol
   * @route PUT /api/admin/super-admin/emergency-access/protocols/:protocolId
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async updateEmergencyProtocol(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.updateProtocol, req);

      const adminUser = req.user;
      const { protocolId } = req.params;
      const updateData = req.body;

      logger.info('Update emergency protocol requested', {
        adminId: adminUser.id,
        protocolId
      });

      const result = await EmergencyAccessService.updateEmergencyProtocol(
        adminUser,
        protocolId,
        updateData
      );

      ResponseHandler.success(res, {
        message: 'Emergency protocol updated successfully',
        data: result
      });

    } catch (error) {
      logger.error('Update emergency protocol error', {
        error: error.message,
        adminId: req.user?.id,
        protocolId: req.params?.protocolId,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Simulate emergency scenario
   * @route POST /api/admin/super-admin/emergency-access/simulate
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async simulateEmergencyScenario(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.simulateScenario, req);

      const adminUser = req.user;
      const { scenario, parameters, recordResults = true } = req.body;

      logger.info('Emergency scenario simulation requested', {
        adminId: adminUser.id,
        scenario,
        recordResults
      });

      const result = await EmergencyAccessService.simulateEmergencyScenario(adminUser, {
        scenario,
        parameters,
        recordResults
      });

      ResponseHandler.success(res, {
        message: 'Emergency scenario simulation completed',
        data: {
          simulationId: result.simulationId,
          results: result.results,
          insights: result.insights,
          recommendations: result.recommendations
        }
      });

    } catch (error) {
      logger.error('Simulate emergency scenario error', {
        error: error.message,
        adminId: req.user?.id,
        scenario: req.body?.scenario,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Get system recovery options
   * @route GET /api/admin/super-admin/emergency-access/recovery-options
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async getSystemRecoveryOptions(req, res, next) {
    try {
      const adminUser = req.user;
      const { systemComponent, severity } = req.query;

      logger.info('System recovery options requested', {
        adminId: adminUser.id,
        systemComponent,
        severity
      });

      const options = await EmergencyAccessService.getSystemRecoveryOptions(adminUser, {
        systemComponent,
        severity
      });

      ResponseHandler.success(res, {
        message: 'Recovery options retrieved successfully',
        data: options
      });

    } catch (error) {
      logger.error('Get system recovery options error', {
        error: error.message,
        adminId: req.user?.id,
        stack: error.stack
      });
      next(error);
    }
  }

  /**
   * Execute recovery procedure
   * @route POST /api/admin/super-admin/emergency-access/recovery/execute
   * @param {Object} req - Express request object
   * @param {Object} res - Express response object
   * @param {Function} next - Express next middleware
   */
  async executeRecoveryProcedure(req, res, next) {
    try {
      await validateRequest(EmergencyAccessValidation.executeRecovery, req);

      const adminUser = req.user;
      const { 
        recoveryType, 
        targetSystems, 
        backupId, 
        verificationRequired = true 
      } = req.body;

      logger.critical('Recovery procedure execution requested', {
        adminId: adminUser.id,
        recoveryType,
        targetSystems
      });

      const result = await EmergencyAccessService.executeRecoveryProcedure(adminUser, {
        recoveryType,
        targetSystems,
        backupId,
        verificationRequired
      });

      ResponseHandler.success(res, {
        message: 'Recovery procedure initiated',
        data: {
          recoveryId: result.recoveryId,
          status: result.status,
          estimatedCompletion: result.estimatedCompletion,
          affectedSystems: result.affectedSystems
        },
        metadata: {
          severity: 'critical',
          requiresMonitoring: true
        }
      }, 201);

    } catch (error) {
      logger.error('Execute recovery procedure error', {
        error: error.message,
        adminId: req.user?.id,
        recoveryType: req.body?.recoveryType,
        stack: error.stack
      });
      next(error);
    }
  }
}

module.exports = new EmergencyAccessController();