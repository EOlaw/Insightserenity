// server/admin/super-admin/services/super-admin-service.js
/**
 * @file Super Admin Service
 * @description Core service for super administrator operations with system-wide control
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Core Models
const User = require('../../../shared/users/models/user-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const Subscription = require('../../../shared/billing/models/subscription-model');
const Role = require('../../../shared/users/models/role-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');
const AdminSession = require('../../../shared/admin/models/admin-session-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const AdminMaintenanceService = require('../../../shared/admin/services/admin-maintenance-service');
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
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

/**
 * Super Admin Service Class
 * @class SuperAdminService
 * @extends AdminBaseService
 */
class SuperAdminService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'SuperAdminService';
    this.cachePrefix = 'super-admin';
    this.auditCategory = 'SUPER_ADMIN';
    this.requiredPermission = AdminPermissions.SUPER_ADMIN.FULL_ACCESS;
  }

  /**
   * Get comprehensive system overview
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} System overview data
   */
  async getSystemOverview(adminUser, options = {}) {
    try {
      await this.validateSuperAdminAccess(adminUser);

      const cacheKey = this.generateCacheKey('overview', { 
        adminId: adminUser.id,
        timestamp: Math.floor(Date.now() / 300000) // 5-minute cache segments
      });

      const cached = await CacheService.get(cacheKey);
      if (cached && !options.skipCache) {
        return cached;
      }

      // Parallel execution for performance
      const [
        userStats,
        organizationStats,
        subscriptionStats,
        systemHealth,
        securityMetrics,
        performanceMetrics,
        resourceUsage,
        revenueMetrics
      ] = await Promise.all([
        this.getUserStatistics(),
        this.getOrganizationStatistics(),
        this.getSubscriptionStatistics(),
        this.getSystemHealthMetrics(),
        this.getSecurityMetrics(),
        this.getPerformanceMetrics(),
        this.getResourceUsageMetrics(),
        this.getRevenueMetrics()
      ]);

      const overview = {
        timestamp: new Date(),
        summary: {
          totalUsers: userStats.total,
          totalOrganizations: organizationStats.total,
          monthlyRecurringRevenue: revenueMetrics.mrr,
          systemStatus: systemHealth.status
        },
        users: userStats,
        organizations: organizationStats,
        subscriptions: subscriptionStats,
        revenue: revenueMetrics,
        system: {
          health: systemHealth,
          security: securityMetrics,
          performance: performanceMetrics,
          resources: resourceUsage
        },
        alerts: await this.getSystemAlerts(),
        recentActivity: await this.getRecentSystemActivity(options.activityLimit || 20)
      };

      // Cache for 5 minutes
      await CacheService.set(cacheKey, overview, 300);

      await this.auditLog(adminUser, AdminEvents.SUPER_ADMIN.OVERVIEW_ACCESSED, {
        overview: 'system_overview',
        options
      });

      return overview;

    } catch (error) {
      logger.error('Get system overview error', { 
        error: error.message, 
        adminId: adminUser.id,
        stack: error.stack 
      });
      throw error;
    }
  }

  /**
   * Impersonate user for debugging and support
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} targetUserId - User ID to impersonate
   * @param {Object} impersonationData - Impersonation details
   * @returns {Promise<Object>} Impersonation session data
   */
  async impersonateUser(adminUser, targetUserId, impersonationData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateSuperAdminAccess(adminUser);

      const { 
        reason, 
        duration = 3600, 
        restrictions = [],
        requireMFA = true,
        notifyUser = true 
      } = impersonationData;

      // Validate input
      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Impersonation reason must be provided and detailed');
      }

      if (duration > AdminLimits.IMPERSONATION.MAX_DURATION) {
        throw new ValidationError(`Impersonation duration cannot exceed ${AdminLimits.IMPERSONATION.MAX_DURATION} seconds`);
      }

      // Check concurrent impersonation limit
      const activeImpersonations = await this.getActiveImpersonations(adminUser.id);
      if (activeImpersonations.length >= AdminLimits.IMPERSONATION.MAX_CONCURRENT) {
        throw new ValidationError('Maximum concurrent impersonation sessions reached');
      }

      // Find target user
      const targetUser = await User.findById(targetUserId)
        .populate('organization.current')
        .populate('role.primary')
        .session(session);

      if (!targetUser) {
        throw new NotFoundError('Target user not found');
      }

      // Security checks
      if (this.isSuperAdmin(targetUser)) {
        throw new ForbiddenError('Cannot impersonate another super administrator');
      }

      if (targetUser.security?.protectedAccount) {
        throw new ForbiddenError('Cannot impersonate protected account');
      }

      // Create impersonation session
      const impersonationSession = {
        id: crypto.randomUUID(),
        adminUserId: adminUser.id,
        adminEmail: adminUser.email,
        targetUserId: targetUser.id,
        targetEmail: targetUser.email,
        reason: encrypt(reason), // Encrypt sensitive reason
        restrictions,
        startTime: new Date(),
        expiresAt: new Date(Date.now() + duration * 1000),
        isActive: true,
        requireMFA,
        metadata: {
          adminIP: adminUser.lastLoginIP,
          adminUserAgent: adminUser.lastUserAgent,
          targetUserRole: targetUser.role?.primary?.name,
          targetUserOrganization: targetUser.organization.current?.name,
          impersonationContext: {
            supportTicket: impersonationData.ticketId,
            authorized: impersonationData.authorized || false
          }
        }
      };

      // Store impersonation session
      const adminSession = new AdminSession({
        sessionId: impersonationSession.id,
        adminUserId: adminUser.id,
        type: 'impersonation',
        data: impersonationSession,
        expiresAt: impersonationSession.expiresAt
      });

      await adminSession.save({ session });

      // Store in cache for quick lookup
      await CacheService.set(
        `impersonation:${impersonationSession.id}`,
        impersonationSession,
        duration
      );

      // Generate temporary access token
      const tempAccessToken = await this.generateImpersonationToken(
        impersonationSession,
        targetUser
      );

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.SUPER_ADMIN.USER_IMPERSONATION_STARTED, {
        targetUserId: targetUser.id,
        targetUserEmail: targetUser.email,
        reason: reason, // Store unencrypted for audit
        duration,
        sessionId: impersonationSession.id,
        restrictions,
        requireMFA
      }, { 
        session,
        critical: true,
        alertLevel: 'high'
      });

      // Send notifications
      if (notifyUser && !restrictions.includes('no_notification')) {
        await NotificationService.sendAdminNotification({
          type: 'impersonation_notice',
          userId: targetUser.id,
          priority: 'high',
          data: {
            adminName: adminUser.profile?.firstName || adminUser.email,
            reason: reason,
            startTime: impersonationSession.startTime,
            duration: duration / 60 // Convert to minutes
          }
        });
      }

      // Alert security team
      await this.alertSecurityTeam({
        event: 'user_impersonation',
        admin: adminUser.email,
        target: targetUser.email,
        reason
      });

      await session.commitTransaction();

      return {
        sessionId: impersonationSession.id,
        accessToken: tempAccessToken,
        targetUser: {
          id: targetUser.id,
          email: targetUser.email,
          name: `${targetUser.profile?.firstName || ''} ${targetUser.profile?.lastName || ''}`.trim(),
          organization: targetUser.organization.current?.name,
          role: targetUser.role?.primary?.name
        },
        expiresAt: impersonationSession.expiresAt,
        restrictions,
        requireMFA
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('User impersonation error', { 
        error: error.message, 
        adminId: adminUser.id,
        targetUserId,
        stack: error.stack 
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * End impersonation session
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} sessionId - Impersonation session ID
   * @returns {Promise<Object>} Session termination result
   */
  async endImpersonation(adminUser, sessionId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateSuperAdminAccess(adminUser);

      // Get session from database
      const adminSession = await AdminSession.findOne({
        sessionId,
        type: 'impersonation',
        isActive: true
      }).session(session);

      if (!adminSession) {
        throw new NotFoundError('Impersonation session not found or already ended');
      }

      const impersonationData = adminSession.data;

      if (impersonationData.adminUserId !== adminUser.id && !this.hasOverridePermission(adminUser)) {
        throw new ForbiddenError('Cannot end impersonation session created by another admin');
      }

      // End session
      adminSession.isActive = false;
      adminSession.endedAt = new Date();
      adminSession.endedBy = adminUser.id;
      await adminSession.save({ session });

      // Remove from cache
      await CacheService.delete(`impersonation:${sessionId}`);

      // Calculate duration
      const duration = adminSession.endedAt - impersonationData.startTime;

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SUPER_ADMIN.USER_IMPERSONATION_ENDED, {
        sessionId,
        targetUserId: impersonationData.targetUserId,
        duration: Math.round(duration / 1000), // seconds
        endedBy: adminUser.id === impersonationData.adminUserId ? 'self' : 'override'
      }, {
        session,
        critical: true
      });

      // Notify target user
      if (!impersonationData.restrictions.includes('no_notification')) {
        await NotificationService.sendAdminNotification({
          type: 'impersonation_ended',
          userId: impersonationData.targetUserId,
          data: {
            duration: Math.round(duration / 60000), // minutes
            endTime: adminSession.endedAt
          }
        });
      }

      await session.commitTransaction();

      return {
        sessionId,
        endedAt: adminSession.endedAt,
        duration: duration,
        endedBy: adminUser.email
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('End impersonation error', { 
        error: error.message, 
        adminId: adminUser.id,
        sessionId,
        stack: error.stack 
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Execute emergency system action
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} actionData - Emergency action parameters
   * @returns {Promise<Object>} Action execution result
   */
  async executeEmergencyAction(adminUser, actionData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateSuperAdminAccess(adminUser);

      const { 
        action,
        reason,
        scope = 'system',
        duration,
        parameters = {},
        requireConfirmation = true
      } = actionData;

      // Validate action
      if (!AdminEvents.SUPER_ADMIN.EMERGENCY_ACTIONS[action]) {
        throw new ValidationError('Invalid emergency action');
      }

      if (!reason || reason.trim().length < 20) {
        throw new ValidationError('Emergency action reason must be detailed (minimum 20 characters)');
      }

      // Check if action requires additional confirmation
      if (requireConfirmation && !actionData.confirmationCode) {
        // Generate and send confirmation code
        const confirmationCode = await this.generateConfirmationCode(adminUser, action);
        return {
          requiresConfirmation: true,
          message: 'Confirmation code sent to your registered email',
          action: action
        };
      }

      // Verify confirmation code if provided
      if (actionData.confirmationCode) {
        await this.verifyConfirmationCode(adminUser, action, actionData.confirmationCode);
      }

      const actionId = crypto.randomUUID();
      const timestamp = new Date();

      // Execute action based on type
      let result;
      switch (action) {
        case 'EMERGENCY_SHUTDOWN':
          result = await this.executeEmergencyShutdown(adminUser, {
            reason,
            scope,
            duration,
            ...parameters
          });
          break;

        case 'DISABLE_ALL_LOGINS':
          result = await this.disableAllLogins(adminUser, {
            reason,
            duration,
            excludeAdmins: parameters.excludeAdmins || true
          });
          break;

        case 'FORCE_LOGOUT_ALL':
          result = await this.forceLogoutAllUsers(adminUser, {
            reason,
            excludeAdmins: parameters.excludeAdmins || true
          });
          break;

        case 'ENABLE_MAINTENANCE_MODE':
          result = await AdminMaintenanceService.enableMaintenanceMode({
            reason,
            duration,
            allowedIPs: parameters.allowedIPs || [],
            customMessage: parameters.message
          });
          break;

        case 'EMERGENCY_BACKUP':
          result = await AdminBackupService.createEmergencyBackup({
            reason,
            includeAuditLogs: true,
            compress: true
          });
          break;

        case 'LOCK_DATABASE':
          result = await this.lockDatabase({
            reason,
            duration,
            readOnly: parameters.readOnly || true
          });
          break;

        default:
          throw new ValidationError(`Unhandled emergency action: ${action}`);
      }

      // Create action record
      const actionRecord = new AdminActionLog({
        actionId,
        adminUserId: adminUser.id,
        action: `EMERGENCY_${action}`,
        category: 'EMERGENCY',
        severity: 'CRITICAL',
        reason: encrypt(reason),
        scope,
        parameters: encrypt(JSON.stringify(parameters)),
        result: {
          success: true,
          data: result
        },
        timestamp
      });

      await actionRecord.save({ session });

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.SUPER_ADMIN.EMERGENCY_ACTION_EXECUTED, {
        actionId,
        action,
        reason,
        scope,
        duration,
        parameters: Object.keys(parameters) // Log parameter keys only
      }, {
        session,
        critical: true,
        alertLevel: 'critical'
      });

      // Alert all admins
      await this.alertAllAdmins({
        event: 'emergency_action',
        action,
        executedBy: adminUser.email,
        reason,
        timestamp
      });

      await session.commitTransaction();

      return {
        actionId,
        action,
        status: 'executed',
        timestamp,
        result: result
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Emergency action execution error', {
        error: error.message,
        adminId: adminUser.id,
        action: actionData.action,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Modify global system configuration
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} configData - Configuration changes
   * @returns {Promise<Object>} Configuration update result
   */
  async modifySystemConfiguration(adminUser, configData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateSuperAdminAccess(adminUser);

      const {
        category,
        settings,
        reason,
        effectiveDate = new Date(),
        testMode = false
      } = configData;

      // Validate configuration category
      const validCategories = [
        'security',
        'authentication',
        'performance',
        'features',
        'billing',
        'notifications',
        'maintenance',
        'api_limits'
      ];

      if (!validCategories.includes(category)) {
        throw new ValidationError(`Invalid configuration category: ${category}`);
      }

      // Create backup of current configuration
      const configBackup = await this.backupCurrentConfiguration(category);

      // Validate new settings
      await this.validateConfigurationSettings(category, settings);

      // Apply configuration changes
      const changes = [];
      for (const [key, value] of Object.entries(settings)) {
        const change = {
          key,
          oldValue: await this.getConfigValue(category, key),
          newValue: value,
          effectiveDate
        };

        if (!testMode) {
          await this.setConfigValue(category, key, value, { session });
        }

        changes.push(change);
      }

      // Create configuration change record
      const changeRecord = {
        id: crypto.randomUUID(),
        adminUserId: adminUser.id,
        category,
        changes,
        reason,
        effectiveDate,
        testMode,
        backupId: configBackup.id,
        timestamp: new Date()
      };

      if (!testMode) {
        // Store change record
        await AdminActionLog.create([{
          actionId: changeRecord.id,
          adminUserId: adminUser.id,
          action: 'SYSTEM_CONFIG_MODIFIED',
          category: 'CONFIGURATION',
          severity: 'HIGH',
          data: changeRecord
        }], { session });

        // Clear relevant caches
        await this.clearConfigurationCaches(category);
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SUPER_ADMIN.SYSTEM_CONFIG_MODIFIED, {
        category,
        changeCount: changes.length,
        testMode,
        reason
      }, {
        session,
        critical: true
      });

      await session.commitTransaction();

      return {
        configurationId: changeRecord.id,
        category,
        changes,
        testMode,
        effectiveDate,
        message: testMode ? 
          'Configuration validated successfully (test mode - no changes applied)' : 
          'Configuration updated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('System configuration modification error', {
        error: error.message,
        adminId: adminUser.id,
        category: configData.category,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get detailed user statistics
   * @returns {Promise<Object>} User statistics
   * @private
   */
  async getUserStatistics() {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const [
      totalUsers,
      activeUsers,
      newUsersMonth,
      newUsersWeek,
      verifiedUsers,
      trialUsers,
      paidUsers,
      suspendedUsers
    ] = await Promise.all([
      User.countDocuments({ status: { $ne: 'deleted' } }),
      User.countDocuments({ 
        status: 'active',
        lastActiveAt: { $gte: sevenDaysAgo }
      }),
      User.countDocuments({
        createdAt: { $gte: thirtyDaysAgo }
      }),
      User.countDocuments({
        createdAt: { $gte: sevenDaysAgo }
      }),
      User.countDocuments({
        'auth.email.verified': true
      }),
      User.countDocuments({ 
        'subscription.status': 'trial' 
      }),
      User.countDocuments({ 
        'subscription.status': 'active',
        'subscription.plan': { $nin: ['free', 'trial'] }
      }),
      User.countDocuments({ 
        status: 'suspended' 
      })
    ]);

    // Get user growth trend
    const growthTrend = await this.calculateGrowthTrend('users', 30);

    return {
      total: totalUsers,
      active: activeUsers,
      activePercentage: totalUsers > 0 ? ((activeUsers / totalUsers) * 100).toFixed(2) : 0,
      newThisMonth: newUsersMonth,
      newThisWeek: newUsersWeek,
      verified: verifiedUsers,
      verificationRate: totalUsers > 0 ? ((verifiedUsers / totalUsers) * 100).toFixed(2) : 0,
      trial: trialUsers,
      paid: paidUsers,
      suspended: suspendedUsers,
      growthTrend: growthTrend,
      segmentation: {
        byPlan: await this.getUserSegmentationByPlan(),
        bySource: await this.getUserSegmentationBySource()
      }
    };
  }

  /**
   * Get organization statistics
   * @returns {Promise<Object>} Organization statistics
   * @private
   */
  async getOrganizationStatistics() {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const [
      totalOrgs,
      activeOrgs,
      newOrgs,
      paidOrgs,
      trialOrgs,
      suspendedOrgs,
      orgsByPlan
    ] = await Promise.all([
      HostedOrganization.countDocuments({ 
        deleted: { $ne: true } 
      }),
      HostedOrganization.countDocuments({ 
        active: true,
        'subscription.status': { $in: ['active', 'trial'] }
      }),
      HostedOrganization.countDocuments({
        createdAt: { $gte: thirtyDaysAgo }
      }),
      HostedOrganization.countDocuments({
        'subscription.plan': { $nin: ['free', 'trial'] },
        'subscription.status': 'active'
      }),
      HostedOrganization.countDocuments({
        'subscription.status': 'trial'
      }),
      HostedOrganization.countDocuments({
        status: 'suspended'
      }),
      HostedOrganization.aggregate([
        {
          $group: {
            _id: '$subscription.plan',
            count: { $sum: 1 }
          }
        }
      ])
    ]);

    // Calculate average organization size
    const avgOrgSize = await HostedOrganization.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: 'organization.current',
          as: 'members'
        }
      },
      {
        $group: {
          _id: null,
          avgSize: { $avg: { $size: '$members' } }
        }
      }
    ]);

    return {
      total: totalOrgs,
      active: activeOrgs,
      activePercentage: totalOrgs > 0 ? ((activeOrgs / totalOrgs) * 100).toFixed(2) : 0,
      newThisMonth: newOrgs,
      paid: paidOrgs,
      paidPercentage: totalOrgs > 0 ? ((paidOrgs / totalOrgs) * 100).toFixed(2) : 0,
      trial: trialOrgs,
      suspended: suspendedOrgs,
      averageSize: avgOrgSize[0]?.avgSize || 0,
      byPlan: orgsByPlan.reduce((acc, item) => {
        acc[item._id || 'free'] = item.count;
        return acc;
      }, {}),
      growthTrend: await this.calculateGrowthTrend('organizations', 30)
    };
  }

  /**
   * Get subscription and revenue statistics
   * @returns {Promise<Object>} Subscription statistics
   * @private
   */
  async getSubscriptionStatistics() {
    const subscriptionStats = await Subscription.aggregate([
      {
        $facet: {
          byStatus: [
            {
              $group: {
                _id: '$status',
                count: { $sum: 1 },
                revenue: { $sum: '$billing.amount.total' }
              }
            }
          ],
          byPlan: [
            {
              $group: {
                _id: '$plan',
                count: { $sum: 1 },
                revenue: { $sum: '$billing.amount.total' }
              }
            }
          ],
          churnMetrics: [
            {
              $match: {
                status: 'cancelled',
                cancelledAt: {
                  $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
                }
              }
            },
            {
              $group: {
                _id: null,
                churned: { $sum: 1 },
                churnedRevenue: { $sum: '$billing.amount.total' }
              }
            }
          ],
          upcomingRenewals: [
            {
              $match: {
                status: 'active',
                nextBillingDate: {
                  $gte: new Date(),
                  $lte: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
                }
              }
            },
            {
              $group: {
                _id: null,
                count: { $sum: 1 },
                revenue: { $sum: '$billing.amount.total' }
              }
            }
          ]
        }
      }
    ]);

    const stats = {
      active: 0,
      trial: 0,
      cancelled: 0,
      pastDue: 0,
      totalRevenue: 0,
      byPlan: {},
      churn: {
        count: 0,
        revenue: 0,
        rate: 0
      },
      upcomingRenewals: {
        count: 0,
        revenue: 0
      }
    };

    // Process status stats
    subscriptionStats[0].byStatus.forEach(stat => {
      stats[stat._id] = stat.count;
      stats.totalRevenue += stat.revenue || 0;
    });

    // Process plan stats
    subscriptionStats[0].byPlan.forEach(stat => {
      stats.byPlan[stat._id] = {
        count: stat.count,
        revenue: stat.revenue || 0
      };
    });

    // Process churn metrics
    if (subscriptionStats[0].churnMetrics[0]) {
      stats.churn = {
        count: subscriptionStats[0].churnMetrics[0].churned,
        revenue: subscriptionStats[0].churnMetrics[0].churnedRevenue,
        rate: stats.active > 0 ? 
          ((subscriptionStats[0].churnMetrics[0].churned / stats.active) * 100).toFixed(2) : 0
      };
    }

    // Process upcoming renewals
    if (subscriptionStats[0].upcomingRenewals[0]) {
      stats.upcomingRenewals = {
        count: subscriptionStats[0].upcomingRenewals[0].count,
        revenue: subscriptionStats[0].upcomingRenewals[0].revenue
      };
    }

    return stats;
  }

  /**
   * Get revenue metrics
   * @returns {Promise<Object>} Revenue metrics
   * @private
   */
  async getRevenueMetrics() {
    const currentMonth = new Date();
    currentMonth.setDate(1);
    currentMonth.setHours(0, 0, 0, 0);

    const lastMonth = new Date(currentMonth);
    lastMonth.setMonth(lastMonth.getMonth() - 1);

    const [currentMonthRevenue, lastMonthRevenue, yearlyRevenue] = await Promise.all([
      Subscription.aggregate([
        {
          $match: {
            status: 'active',
            'billing.lastPaymentDate': { $gte: currentMonth }
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$billing.amount.total' }
          }
        }
      ]),
      Subscription.aggregate([
        {
          $match: {
            status: 'active',
            'billing.lastPaymentDate': { 
              $gte: lastMonth,
              $lt: currentMonth
            }
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$billing.amount.total' }
          }
        }
      ]),
      Subscription.aggregate([
        {
          $match: {
            status: 'active',
            billingCycle: 'yearly'
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$billing.amount.total' },
            count: { $sum: 1 }
          }
        }
      ])
    ]);

    // Calculate MRR
    const mrr = await this.calculateMRR();

    return {
      mrr: mrr.total,
      mrrGrowth: mrr.growth,
      currentMonth: currentMonthRevenue[0]?.total || 0,
      lastMonth: lastMonthRevenue[0]?.total || 0,
      monthOverMonthGrowth: this.calculatePercentageChange(
        lastMonthRevenue[0]?.total || 0,
        currentMonthRevenue[0]?.total || 0
      ),
      yearlyRevenue: yearlyRevenue[0]?.total || 0,
      yearlySubscriptions: yearlyRevenue[0]?.count || 0,
      averageRevenuePerUser: await this.calculateARPU(),
      lifetimeValue: await this.calculateLTV()
    };
  }

  /**
   * Get system health metrics
   * @returns {Promise<Object>} System health data
   * @private
   */
  async getSystemHealthMetrics() {
    const dbStatus = await this.checkDatabaseHealth();
    const cacheStatus = await this.checkCacheHealth();
    const queueStatus = await this.checkQueueHealth();

    return {
      status: this.determineOverallHealth([dbStatus, cacheStatus, queueStatus]),
      timestamp: new Date(),
      uptime: process.uptime(),
      services: {
        database: dbStatus,
        cache: cacheStatus,
        queue: queueStatus,
        email: await this.checkEmailServiceHealth(),
        storage: await this.checkStorageHealth()
      },
      system: {
        memory: process.memoryUsage(),
        cpu: await this.getCPUUsage(),
        disk: await this.getDiskUsage()
      },
      errors: {
        last24h: await this.getErrorCount(24),
        last1h: await this.getErrorCount(1)
      }
    };
  }

  /**
   * Get security metrics
   * @returns {Promise<Object>} Security metrics
   * @private
   */
  async getSecurityMetrics() {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const [
      failedLogins24h,
      blockedIPs,
      suspiciousActivities,
      criticalEvents,
      mfaAdoption
    ] = await Promise.all([
      AuditLog.countDocuments({
        action: 'auth.login.failed',
        timestamp: { $gte: oneDayAgo }
      }),
      CacheService.get('security:blocked_ips:count') || 0,
      AuditLog.countDocuments({
        'metadata.suspicious': true,
        timestamp: { $gte: oneDayAgo }
      }),
      AuditLog.countDocuments({
        severity: 'critical',
        timestamp: { $gte: oneWeekAgo }
      }),
      User.countDocuments({
        'auth.twoFactor.enabled': true
      })
    ]);

    const totalUsers = await User.countDocuments({ status: 'active' });

    return {
      threatLevel: this.calculateThreatLevel({
        failedLogins: failedLogins24h,
        blockedIPs,
        suspiciousActivities
      }),
      metrics: {
        failedLogins24h,
        blockedIPs,
        suspiciousActivities,
        criticalEvents
      },
      mfa: {
        enabled: mfaAdoption,
        adoptionRate: totalUsers > 0 ? ((mfaAdoption / totalUsers) * 100).toFixed(2) : 0
      },
      recentThreats: await this.getRecentSecurityThreats(),
      vulnerabilities: await this.checkKnownVulnerabilities()
    };
  }

  /**
   * Get performance metrics
   * @returns {Promise<Object>} Performance metrics
   * @private
   */
  async getPerformanceMetrics() {
    const metrics = await CacheService.get('performance:metrics:latest') || {};

    return {
      api: {
        averageResponseTime: metrics.avgResponseTime || 0,
        p95ResponseTime: metrics.p95ResponseTime || 0,
        p99ResponseTime: metrics.p99ResponseTime || 0,
        requestsPerMinute: metrics.rpm || 0,
        errorRate: metrics.errorRate || 0
      },
      database: {
        averageQueryTime: metrics.avgQueryTime || 0,
        slowQueries: metrics.slowQueries || 0,
        connectionPoolUsage: metrics.dbPoolUsage || 0
      },
      cache: {
        hitRate: metrics.cacheHitRate || 0,
        missRate: metrics.cacheMissRate || 0,
        evictionRate: metrics.cacheEvictionRate || 0
      },
      queue: {
        jobsProcessed: metrics.jobsProcessed || 0,
        jobsFailed: metrics.jobsFailed || 0,
        averageProcessingTime: metrics.avgJobTime || 0,
        queueDepth: metrics.queueDepth || 0
      }
    };
  }

  /**
   * Get resource usage metrics
   * @returns {Promise<Object>} Resource usage data
   * @private
   */
  async getResourceUsageMetrics() {
    const [storageUsage, bandwidthUsage, computeUsage] = await Promise.all([
      this.calculateStorageUsage(),
      this.calculateBandwidthUsage(),
      this.calculateComputeUsage()
    ]);

    return {
      storage: storageUsage,
      bandwidth: bandwidthUsage,
      compute: computeUsage,
      limits: {
        storage: config.platform.limits.storage,
        bandwidth: config.platform.limits.bandwidth,
        compute: config.platform.limits.compute
      }
    };
  }

  /**
   * Helper method to validate super admin access
   * @param {Object} user - User to validate
   * @throws {ForbiddenError} If user lacks super admin access
   * @private
   */
  async validateSuperAdminAccess(user) {
    if (!user || !this.isSuperAdmin(user)) {
      await this.auditLog(user, AdminEvents.SUPER_ADMIN.UNAUTHORIZED_ACCESS_ATTEMPT, {
        attemptedAction: 'super_admin_access',
        userRole: user?.role?.primary
      });
      throw new ForbiddenError('Super administrator access required');
    }

    // Additional security checks
    if (user.security?.requireMFA && !user.auth?.mfaVerified) {
      throw new ForbiddenError('MFA verification required for super admin actions');
    }

    // Check for valid admin session
    const validSession = await AdminSession.findOne({
      adminUserId: user.id,
      type: 'admin',
      isActive: true,
      expiresAt: { $gt: new Date() }
    });

    if (!validSession) {
      throw new ForbiddenError('Valid admin session required');
    }
  }

  /**
   * Check if user is super admin
   * @param {Object} user - User to check
   * @returns {boolean} Is super admin
   * @private
   */
  isSuperAdmin(user) {
    return user?.role?.primary === 'super_admin' || 
           user?.permissions?.system?.some(p => 
             p.resource === AdminPermissions.SUPER_ADMIN.FULL_ACCESS && 
             p.actions.includes('*')
           );
  }

  /**
   * Check if admin has override permission
   * @param {Object} user - User to check
   * @returns {boolean} Has override permission
   * @private
   */
  hasOverridePermission(user) {
    return user?.permissions?.system?.some(p => 
      p.resource === AdminPermissions.SUPER_ADMIN.OVERRIDE && 
      p.actions.includes('execute')
    );
  }

  /**
   * Generate impersonation token
   * @param {Object} session - Impersonation session
   * @param {Object} targetUser - Target user
   * @returns {Promise<string>} Temporary access token
   * @private
   */
  async generateImpersonationToken(session, targetUser) {
    // Implementation would generate a special JWT token
    // with impersonation metadata and restrictions
    return 'temporary-impersonation-token';
  }

  /**
   * Additional helper methods would continue here...
   */
}

module.exports = new SuperAdminService();