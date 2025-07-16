// server/admin/user-management/services/account-lifecycle-service.js
/**
 * @file Account Lifecycle Service
 * @description Service for managing user account lifecycle events, automation, and policies
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const moment = require('moment');

// Core Models
const User = require('../../../shared/users/models/user-model');
const UserProfile = require('../../../shared/users/models/user-profile-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const AccountLifecycleEvent = require('../../../shared/users/models/account-lifecycle-event-model');
const UserActivity = require('../../../shared/users/models/user-activity-model');
const UserSession = require('../../../shared/users/models/user-session-model');
const Subscription = require('../../../shared/billing/models/subscription-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const EmailService = require('../../../shared/services/email-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const QueueService = require('../../../shared/utils/queue-service');
const CacheService = require('../../../shared/utils/cache-service');
const AdminBackupService = require('../../../shared/admin/services/admin-backup-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const { encrypt, decrypt } = require('../../../shared/utils/encryption');

// Configuration
const config = require('../../../config');

/**
 * Account Lifecycle Service Class
 * @class AccountLifecycleService
 * @extends AdminBaseService
 */
class AccountLifecycleService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'AccountLifecycleService';
    this.cachePrefix = 'account-lifecycle';
    this.auditCategory = 'ACCOUNT_LIFECYCLE';
    this.requiredPermission = AdminPermissions.USER_MANAGEMENT.MANAGE_LIFECYCLE;
    
    // Lifecycle stages
    this.lifecycleStages = {
      ONBOARDING: 'onboarding',
      ACTIVE: 'active',
      INACTIVE: 'inactive',
      AT_RISK: 'at_risk',
      CHURNED: 'churned',
      REACTIVATED: 'reactivated',
      SUSPENDED: 'suspended',
      DELETED: 'deleted'
    };
    
    // Lifecycle policies
    this.defaultPolicies = {
      inactivityWarning: 60, // days
      inactivitySuspension: 90, // days
      inactivityDeletion: 365, // days
      trialExpiration: 14, // days
      passwordExpiration: 90, // days
      sessionTimeout: 24, // hours
      dataRetention: 730 // days (2 years)
    };
  }

  /**
   * Get account lifecycle overview
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Lifecycle overview data
   */
  async getLifecycleOverview(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_LIFECYCLE);

      const {
        timeRange = 'last30d',
        organizationId = null
      } = options;

      const cacheKey = this.generateCacheKey('overview', {
        timeRange,
        organizationId,
        timestamp: Math.floor(Date.now() / 3600000) // 1-hour cache
      });

      const cached = await CacheService.get(cacheKey);
      if (cached && !options.skipCache) {
        return cached;
      }

      const { startDate, endDate } = this.calculateDateRange(timeRange);
      const baseQuery = organizationId ? { 'organization.current': organizationId } : {};

      // Get lifecycle stage distribution
      const stageDistribution = await this.getStageDistribution(baseQuery);

      // Get lifecycle transitions
      const transitions = await this.getLifecycleTransitions(startDate, endDate, baseQuery);

      // Get at-risk accounts
      const atRiskAccounts = await this.identifyAtRiskAccounts(baseQuery);

      // Get automation statistics
      const automationStats = await this.getAutomationStatistics(startDate, endDate);

      // Get upcoming lifecycle events
      const upcomingEvents = await this.getUpcomingLifecycleEvents();

      // Calculate health metrics
      const healthMetrics = await this.calculateLifecycleHealth(baseQuery);

      const overview = {
        timestamp: new Date(),
        stageDistribution,
        transitions,
        atRiskAccounts: {
          total: atRiskAccounts.length,
          categories: this.categorizeAtRiskAccounts(atRiskAccounts),
          topReasons: await this.getTopRiskReasons(atRiskAccounts)
        },
        automation: automationStats,
        upcomingEvents,
        healthMetrics,
        policies: await this.getActivePolicies(organizationId)
      };

      // Cache for 1 hour
      await CacheService.set(cacheKey, overview, 3600);

      // Log access
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.LIFECYCLE_OVERVIEW_VIEWED, {
        timeRange,
        organizationId
      });

      return overview;

    } catch (error) {
      logger.error('Get lifecycle overview error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Configure lifecycle policies
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} policyData - Policy configuration
   * @returns {Promise<Object>} Policy update result
   */
  async configureLifecyclePolicies(adminUser, policyData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.CONFIGURE_POLICIES);

      const {
        organizationId = null,
        policies,
        applyToExisting = false,
        effectiveDate = new Date()
      } = policyData;

      // Validate policies
      const validatedPolicies = this.validateLifecyclePolicies(policies);

      // Get current policies for comparison
      const currentPolicies = await this.getActivePolicies(organizationId);

      // Create policy record
      const policyRecord = {
        id: crypto.randomUUID(),
        organizationId,
        policies: validatedPolicies,
        previousPolicies: currentPolicies,
        effectiveDate,
        createdBy: adminUser.id,
        createdAt: new Date()
      };

      // Save policies
      await this.savePolicies(policyRecord, session);

      // Apply to existing users if requested
      let affectedUsers = 0;
      if (applyToExisting) {
        affectedUsers = await this.applyPoliciesToExistingUsers(
          validatedPolicies,
          organizationId,
          session
        );
      }

      // Schedule policy enforcement jobs
      await this.schedulePolicyEnforcement(validatedPolicies, organizationId);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.LIFECYCLE_POLICIES_UPDATED, {
        policyId: policyRecord.id,
        organizationId,
        policies: Object.keys(validatedPolicies),
        applyToExisting,
        affectedUsers
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        policyId: policyRecord.id,
        policies: validatedPolicies,
        effectiveDate,
        affectedUsers,
        message: 'Lifecycle policies configured successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Configure lifecycle policies error', {
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
   * Manage account lifecycle transitions
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - User ID
   * @param {Object} transitionData - Transition details
   * @returns {Promise<Object>} Transition result
   */
  async transitionAccountLifecycle(adminUser, userId, transitionData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.MANAGE_LIFECYCLE);

      const {
        targetStage,
        reason,
        automated = false,
        notifyUser = true,
        metadata = {}
      } = transitionData;

      // Validate target stage
      if (!Object.values(this.lifecycleStages).includes(targetStage)) {
        throw new ValidationError('Invalid lifecycle stage');
      }

      // Find user
      const user = await User.findById(userId).session(session);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Get current lifecycle stage
      const currentStage = await this.getUserLifecycleStage(user);

      // Validate transition
      if (!this.isValidTransition(currentStage, targetStage)) {
        throw new ValidationError(`Invalid transition from ${currentStage} to ${targetStage}`);
      }

      // Create lifecycle event
      const lifecycleEvent = new AccountLifecycleEvent({
        userId: user._id,
        eventType: 'stage_transition',
        fromStage: currentStage,
        toStage: targetStage,
        reason,
        automated,
        initiatedBy: automated ? 'system' : adminUser.id,
        metadata: {
          ...metadata,
          userEmail: user.email,
          organizationId: user.organization?.current
        },
        timestamp: new Date()
      });

      await lifecycleEvent.save({ session });

      // Execute transition actions
      const transitionResult = await this.executeTransitionActions(
        user,
        currentStage,
        targetStage,
        {
          reason,
          adminUser,
          session
        }
      );

      // Update user lifecycle metadata
      user.lifecycle = {
        ...user.lifecycle,
        currentStage: targetStage,
        lastTransition: new Date(),
        history: [
          ...(user.lifecycle?.history || []),
          {
            stage: targetStage,
            enteredAt: new Date(),
            reason
          }
        ]
      };

      await user.save({ session });

      // Send notifications if requested
      if (notifyUser && transitionResult.notificationRequired) {
        await this.sendLifecycleNotification(user, {
          transition: { from: currentStage, to: targetStage },
          reason,
          actions: transitionResult.actions
        });
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.LIFECYCLE_TRANSITION, {
        userId,
        userEmail: user.email,
        fromStage: currentStage,
        toStage: targetStage,
        reason,
        automated
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        userId,
        transition: {
          from: currentStage,
          to: targetStage
        },
        actions: transitionResult.actions,
        timestamp: new Date(),
        message: `Account transitioned to ${targetStage} stage successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Transition account lifecycle error', {
        error: error.message,
        adminId: adminUser.id,
        userId,
        targetStage: transitionData.targetStage,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Execute account reactivation
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - User ID to reactivate
   * @param {Object} reactivationData - Reactivation details
   * @returns {Promise<Object>} Reactivation result
   */
  async reactivateAccount(adminUser, userId, reactivationData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.REACTIVATE);

      const {
        reason,
        resetPassword = false,
        extendTrial = false,
        trialDays = 0,
        offerIncentive = false,
        incentiveDetails = null,
        notifyUser = true
      } = reactivationData;

      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Reactivation reason required (minimum 10 characters)');
      }

      // Find user
      const user = await User.findById(userId)
        .populate('subscription')
        .session(session);

      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Validate user can be reactivated
      if (!['inactive', 'churned', 'suspended'].includes(user.status)) {
        throw new ValidationError('User account is not eligible for reactivation');
      }

      // Store original state
      const originalState = {
        status: user.status,
        subscription: user.subscription?.status
      };

      // Reactivate account
      user.status = 'active';
      user.reactivation = {
        reactivatedAt: new Date(),
        reactivatedBy: adminUser.id,
        reason,
        fromStatus: originalState.status
      };

      // Reset password if requested
      if (resetPassword) {
        const tempPassword = AdminHelpers.generateSecurePassword();
        user.auth.password = await AdminHelpers.hashPassword(tempPassword);
        user.auth.requirePasswordChange = true;
        
        // Store for notification
        reactivationData.tempPassword = tempPassword;
      }

      // Extend trial if requested
      if (extendTrial && trialDays > 0) {
        const trialEndDate = new Date();
        trialEndDate.setDate(trialEndDate.getDate() + trialDays);

        if (user.subscription) {
          user.subscription.status = 'trial';
          user.subscription.trialEndsAt = trialEndDate;
          await user.subscription.save({ session });
        }
      }

      // Apply incentive if offered
      if (offerIncentive && incentiveDetails) {
        await this.applyReactivationIncentive(user, incentiveDetails, session);
      }

      await user.save({ session });

      // Clear any suspension or deletion schedules
      await this.clearScheduledActions(userId, session);

      // Restore user data if soft deleted
      if (originalState.status === 'deleted') {
        await this.restoreUserData(userId, session);
      }

      // Create lifecycle event
      await AccountLifecycleEvent.create([{
        userId: user._id,
        eventType: 'reactivation',
        fromStage: this.mapStatusToStage(originalState.status),
        toStage: this.lifecycleStages.REACTIVATED,
        reason,
        initiatedBy: adminUser.id,
        metadata: {
          resetPassword,
          extendTrial,
          trialDays,
          offerIncentive,
          incentiveDetails
        },
        timestamp: new Date()
      }], { session });

      // Send notification if requested
      if (notifyUser) {
        await EmailService.sendAccountReactivationEmail({
          email: user.email,
          name: user.profile?.firstName || 'User',
          reason,
          tempPassword: reactivationData.tempPassword,
          trialExtended: extendTrial,
          trialDays,
          incentive: incentiveDetails,
          loginUrl: config.frontend.loginUrl
        });
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.ACCOUNT_REACTIVATED, {
        userId,
        userEmail: user.email,
        fromStatus: originalState.status,
        reason,
        actions: {
          resetPassword,
          extendTrial,
          offerIncentive
        }
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        userId,
        email: user.email,
        status: 'active',
        reactivatedAt: user.reactivation.reactivatedAt,
        actions: {
          passwordReset: resetPassword,
          trialExtended: extendTrial,
          incentiveApplied: offerIncentive
        },
        message: 'Account reactivated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Reactivate account error', {
        error: error.message,
        adminId: adminUser.id,
        userId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Schedule account deletion
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} deletionData - Deletion scheduling data
   * @returns {Promise<Object>} Scheduling result
   */
  async scheduleAccountDeletion(adminUser, deletionData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.SCHEDULE_DELETION);

      const {
        userIds,
        filters,
        deletionDate,
        deletionType = 'soft',
        reason,
        notifyUsers = true,
        notificationLeadTime = 30 // days
      } = deletionData;

      if (!reason || reason.trim().length < 20) {
        throw new ValidationError('Deletion reason required (minimum 20 characters)');
      }

      const scheduledDate = new Date(deletionDate);
      if (scheduledDate <= new Date()) {
        throw new ValidationError('Deletion date must be in the future');
      }

      // Get target users
      let targetUsers;
      if (userIds) {
        targetUsers = await User.find({
          _id: { $in: userIds },
          status: { $nin: ['deleted', 'active'] }
        }).session(session);
      } else if (filters) {
        const query = this.buildDeletionQuery(filters);
        targetUsers = await User.find(query)
          .limit(AdminLimits.BULK_OPERATIONS.MAX_DELETE_USERS)
          .session(session);
      } else {
        throw new ValidationError('Either userIds or filters must be provided');
      }

      if (targetUsers.length === 0) {
        throw new ValidationError('No eligible users found for deletion');
      }

      // Create deletion schedule
      const scheduleId = crypto.randomUUID();
      const scheduleRecord = {
        scheduleId,
        type: 'account_deletion',
        adminUserId: adminUser.id,
        targetUsers: targetUsers.map(u => ({
          userId: u._id,
          email: u.email,
          currentStatus: u.status
        })),
        scheduledFor: scheduledDate,
        deletionType,
        reason: encrypt(reason),
        notifyUsers,
        notificationLeadTime,
        status: 'scheduled',
        createdAt: new Date()
      };

      // Save schedule
      await this.saveSchedule(scheduleRecord, session);

      // Schedule notification jobs
      if (notifyUsers) {
        const notificationDate = new Date(scheduledDate);
        notificationDate.setDate(notificationDate.getDate() - notificationLeadTime);

        await QueueService.addJob('lifecycle-deletion-notice', {
          scheduleId,
          userIds: targetUsers.map(u => u._id),
          deletionDate: scheduledDate,
          deletionType
        }, {
          delay: notificationDate - new Date(),
          attempts: 3
        });
      }

      // Schedule deletion job
      await QueueService.addJob('lifecycle-account-deletion', {
        scheduleId,
        adminUserId: adminUser.id
      }, {
        delay: scheduledDate - new Date(),
        attempts: 3
      });

      // Update users with deletion schedule
      await User.updateMany(
        { _id: { $in: targetUsers.map(u => u._id) } },
        {
          $set: {
            'lifecycle.scheduledDeletion': {
              scheduleId,
              scheduledFor: scheduledDate,
              type: deletionType,
              scheduledBy: adminUser.id
            }
          }
        },
        { session }
      );

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.DELETION_SCHEDULED, {
        scheduleId,
        userCount: targetUsers.length,
        scheduledFor: scheduledDate,
        deletionType,
        reason
      }, { session, critical: true, alertLevel: 'high' });

      await session.commitTransaction();

      return {
        scheduleId,
        scheduledFor: scheduledDate,
        affectedUsers: targetUsers.length,
        deletionType,
        notificationDate: notifyUsers ? 
          new Date(scheduledDate.getTime() - notificationLeadTime * 24 * 60 * 60 * 1000) : null,
        message: `Account deletion scheduled for ${targetUsers.length} users`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Schedule account deletion error', {
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
   * Get lifecycle automation rules
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Automation rules
   */
  async getLifecycleAutomationRules(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_LIFECYCLE);

      const {
        organizationId = null,
        ruleType = null,
        isActive = null
      } = options;

      // Build query
      const query = {};
      if (organizationId) query.organizationId = organizationId;
      if (ruleType) query.type = ruleType;
      if (isActive !== null) query.isActive = isActive;

      // Get automation rules
      const rules = await this.fetchAutomationRules(query);

      // Get rule execution statistics
      const ruleStats = await this.getRuleExecutionStats(rules.map(r => r.id));

      // Enhance rules with statistics
      const enhancedRules = rules.map(rule => ({
        ...rule,
        statistics: ruleStats[rule.id] || {
          executions: 0,
          successful: 0,
          failed: 0,
          lastExecuted: null
        }
      }));

      // Get available triggers and actions
      const availableOptions = {
        triggers: this.getAvailableTriggers(),
        conditions: this.getAvailableConditions(),
        actions: this.getAvailableActions()
      };

      return {
        rules: enhancedRules,
        total: enhancedRules.length,
        active: enhancedRules.filter(r => r.isActive).length,
        availableOptions,
        limits: {
          maxRules: AdminLimits.LIFECYCLE.MAX_AUTOMATION_RULES,
          maxConditionsPerRule: AdminLimits.LIFECYCLE.MAX_CONDITIONS_PER_RULE,
          maxActionsPerRule: AdminLimits.LIFECYCLE.MAX_ACTIONS_PER_RULE
        }
      };

    } catch (error) {
      logger.error('Get lifecycle automation rules error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Create lifecycle automation rule
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} ruleData - Automation rule configuration
   * @returns {Promise<Object>} Created rule
   */
  async createLifecycleAutomationRule(adminUser, ruleData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.CREATE_AUTOMATION);

      const {
        name,
        description,
        trigger,
        conditions = [],
        actions,
        organizationId = null,
        isActive = true,
        priority = 50
      } = ruleData;

      // Validate rule configuration
      this.validateAutomationRule({ trigger, conditions, actions });

      // Check rule limits
      const existingRules = await this.countAutomationRules(organizationId);
      if (existingRules >= AdminLimits.LIFECYCLE.MAX_AUTOMATION_RULES) {
        throw new ValidationError('Maximum automation rules limit reached');
      }

      // Create rule
      const rule = {
        id: crypto.randomUUID(),
        name,
        description,
        trigger,
        conditions,
        actions,
        organizationId,
        isActive,
        priority,
        createdBy: adminUser.id,
        createdAt: new Date(),
        version: 1
      };

      // Save rule
      await this.saveAutomationRule(rule, session);

      // Register rule with automation engine
      if (isActive) {
        await this.registerAutomationRule(rule);
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.AUTOMATION_RULE_CREATED, {
        ruleId: rule.id,
        ruleName: name,
        trigger: trigger.type,
        actionCount: actions.length,
        isActive
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        rule,
        message: 'Lifecycle automation rule created successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Create lifecycle automation rule error', {
        error: error.message,
        adminId: adminUser.id,
        ruleName: ruleData.name,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get account retention analysis
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Retention analysis
   */
  async getAccountRetentionAnalysis(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS);

      const {
        startDate,
        endDate,
        cohortSize = 'month',
        segmentBy = null,
        includeChurnPrediction = true
      } = options;

      const start = new Date(startDate || Date.now() - 365 * 24 * 60 * 60 * 1000);
      const end = new Date(endDate || Date.now());

      // Generate retention cohorts
      const cohorts = await this.generateRetentionCohorts(start, end, cohortSize);

      // Calculate retention rates
      const retentionData = await this.calculateRetentionRates(cohorts);

      // Analyze churn patterns
      const churnAnalysis = await this.analyzeChurnPatterns(cohorts);

      // Segment analysis if requested
      let segmentedData = null;
      if (segmentBy) {
        segmentedData = await this.segmentRetentionAnalysis(cohorts, segmentBy);
      }

      // Generate churn predictions if requested
      let predictions = null;
      if (includeChurnPrediction) {
        predictions = await this.predictChurn(cohorts);
      }

      // Calculate key metrics
      const metrics = {
        averageRetention: this.calculateAverageRetention(retentionData),
        churnRate: this.calculateChurnRate(churnAnalysis),
        lifetimeValue: await this.calculateAverageLTV(cohorts),
        retentionHealth: this.assessRetentionHealth(retentionData)
      };

      return {
        period: { start, end },
        cohortSize,
        cohorts: cohorts.length,
        retentionData,
        churnAnalysis,
        metrics,
        segments: segmentedData,
        predictions,
        recommendations: this.generateRetentionRecommendations({
          retentionData,
          churnAnalysis,
          metrics
        })
      };

    } catch (error) {
      logger.error('Get account retention analysis error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get stage distribution
   * @param {Object} baseQuery - Base query
   * @returns {Promise<Object>} Stage distribution data
   * @private
   */
  async getStageDistribution(baseQuery) {
    const stages = await User.aggregate([
      {
        $match: {
          ...baseQuery,
          status: { $ne: 'deleted' }
        }
      },
      {
        $group: {
          _id: '$lifecycle.currentStage',
          count: { $sum: 1 }
        }
      }
    ]);

    // Ensure all stages are represented
    const distribution = {};
    Object.values(this.lifecycleStages).forEach(stage => {
      distribution[stage] = 0;
    });

    stages.forEach(stage => {
      if (stage._id) {
        distribution[stage._id] = stage.count;
      }
    });

    return distribution;
  }

  /**
   * Execute transition actions
   * @param {Object} user - User object
   * @param {string} fromStage - Current stage
   * @param {string} toStage - Target stage
   * @param {Object} context - Transition context
   * @returns {Promise<Object>} Transition result
   * @private
   */
  async executeTransitionActions(user, fromStage, toStage, context) {
    const actions = [];
    let notificationRequired = true;

    switch (toStage) {
      case this.lifecycleStages.SUSPENDED:
        // Terminate active sessions
        await UserSession.updateMany(
          { userId: user._id, isActive: true },
          {
            $set: {
              isActive: false,
              endedAt: new Date(),
              endReason: 'account_suspended'
            }
          },
          { session: context.session }
        );
        actions.push('Sessions terminated');
        break;

      case this.lifecycleStages.DELETED:
        // Anonymize user data
        await this.anonymizeUserData(user, context.session);
        actions.push('Data anonymized');
        
        // Cancel subscriptions
        if (user.subscription) {
          await Subscription.findByIdAndUpdate(
            user.subscription,
            { status: 'cancelled', cancelledAt: new Date() },
            { session: context.session }
          );
          actions.push('Subscription cancelled');
        }
        break;

      case this.lifecycleStages.ACTIVE:
        // Clear any suspension data
        user.suspension = null;
        actions.push('Suspension cleared');
        break;

      case this.lifecycleStages.AT_RISK:
        // Flag for retention campaigns
        user.marketing = {
          ...user.marketing,
          retentionCampaignEligible: true,
          riskScore: await this.calculateRiskScore(user)
        };
        actions.push('Flagged for retention');
        break;
    }

    return {
      actions,
      notificationRequired
    };
  }

  /**
   * Additional helper methods would continue here...
   */
}

module.exports = new AccountLifecycleService();