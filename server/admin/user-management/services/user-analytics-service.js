// server/admin/user-management/services/user-analytics-service.js
/**
 * @file User Analytics Service
 * @description Comprehensive analytics service for user data analysis and reporting
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const moment = require('moment');

// Core Models
const User = require('../../../shared/users/models/user-model');
const UserActivity = require('../../../shared/users/models/user-activity-model');
const LoginHistory = require('../../../shared/users/models/login-history-model');
const UserSession = require('../../../shared/users/models/user-session-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const Subscription = require('../../../shared/billing/models/subscription-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const CacheService = require('../../../shared/utils/cache-service');
const MetricsService = require('../../../shared/utils/metrics-service');
const ReportService = require('../../../shared/services/report-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const { calculatePercentageChange, calculateGrowthRate } = require('../../../shared/utils/analytics-helpers');

// Configuration
const config = require('../../../config');

/**
 * User Analytics Service Class
 * @class UserAnalyticsService
 * @extends AdminBaseService
 */
class UserAnalyticsService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'UserAnalyticsService';
    this.cachePrefix = 'user-analytics';
    this.auditCategory = 'USER_ANALYTICS';
    this.requiredPermission = AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS;
    
    // Analytics configuration
    this.defaultTimeRanges = {
      last24h: { hours: 24 },
      last7d: { days: 7 },
      last30d: { days: 30 },
      last90d: { days: 90 },
      last365d: { days: 365 }
    };
    
    // Cohort definitions
    this.cohortTypes = {
      SIGNUP: 'signup',
      FIRST_ACTION: 'first_action',
      SUBSCRIPTION: 'subscription',
      ORGANIZATION: 'organization'
    };
  }

  /**
   * Get comprehensive user analytics dashboard
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Analytics options
   * @returns {Promise<Object>} Analytics dashboard data
   */
  async getUserAnalyticsDashboard(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS);

      const {
        timeRange = 'last30d',
        organizationId = null,
        compareWithPrevious = true,
        includeForecasts = false
      } = options;

      const cacheKey = this.generateCacheKey('dashboard', {
        timeRange,
        organizationId,
        timestamp: Math.floor(Date.now() / 3600000) // 1-hour cache segments
      });

      const cached = await CacheService.get(cacheKey);
      if (cached && !options.skipCache) {
        return cached;
      }

      // Calculate date ranges
      const { startDate, endDate } = this.calculateDateRange(timeRange);
      const previousPeriod = compareWithPrevious ? 
        this.calculatePreviousPeriod(startDate, endDate) : null;

      // Build base query
      const baseQuery = organizationId ? 
        { 'organization.current': organizationId } : {};

      // Fetch analytics data in parallel
      const [
        overviewMetrics,
        growthMetrics,
        engagementMetrics,
        retentionMetrics,
        demographicMetrics,
        behaviorMetrics,
        subscriptionMetrics
      ] = await Promise.all([
        this.getOverviewMetrics(startDate, endDate, baseQuery, previousPeriod),
        this.getGrowthMetrics(startDate, endDate, baseQuery),
        this.getEngagementMetrics(startDate, endDate, baseQuery),
        this.getRetentionMetrics(startDate, endDate, baseQuery),
        this.getDemographicMetrics(baseQuery),
        this.getBehaviorMetrics(startDate, endDate, baseQuery),
        this.getSubscriptionMetrics(startDate, endDate, baseQuery)
      ]);

      // Build dashboard response
      const dashboard = {
        timeRange: {
          start: startDate,
          end: endDate,
          label: this.getTimeRangeLabel(timeRange)
        },
        overview: overviewMetrics,
        growth: growthMetrics,
        engagement: engagementMetrics,
        retention: retentionMetrics,
        demographics: demographicMetrics,
        behavior: behaviorMetrics,
        subscriptions: subscriptionMetrics,
        insights: await this.generateInsights({
          overview: overviewMetrics,
          growth: growthMetrics,
          engagement: engagementMetrics,
          retention: retentionMetrics
        }),
        generatedAt: new Date()
      };

      // Add forecasts if requested
      if (includeForecasts) {
        dashboard.forecasts = await this.generateForecasts(dashboard);
      }

      // Cache for 1 hour
      await CacheService.set(cacheKey, dashboard, 3600);

      // Log analytics access
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.ANALYTICS_VIEWED, {
        type: 'dashboard',
        timeRange,
        organizationId
      });

      return dashboard;

    } catch (error) {
      logger.error('Get user analytics dashboard error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get user growth analytics
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Growth analytics options
   * @returns {Promise<Object>} Growth analytics data
   */
  async getUserGrowthAnalytics(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS);

      const {
        startDate,
        endDate,
        granularity = 'day', // day, week, month
        segmentBy = null, // role, organization, source
        includeChurn = true
      } = options;

      // Validate date range
      const start = new Date(startDate || Date.now() - 30 * 24 * 60 * 60 * 1000);
      const end = new Date(endDate || Date.now());

      if (end < start) {
        throw new ValidationError('End date must be after start date');
      }

      // Get growth data
      const growthData = await this.aggregateGrowthData(start, end, granularity, segmentBy);

      // Calculate growth metrics
      const metrics = {
        totalNewUsers: growthData.reduce((sum, period) => sum + period.newUsers, 0),
        averageGrowthRate: this.calculateAverageGrowthRate(growthData),
        peakGrowthPeriod: this.findPeakGrowthPeriod(growthData),
        growthTrend: this.analyzeGrowthTrend(growthData),
        projectedGrowth: this.projectGrowth(growthData, 30) // 30-day projection
      };

      // Add churn analysis if requested
      if (includeChurn) {
        const churnData = await this.analyzeChurn(start, end, granularity);
        metrics.churn = {
          totalChurned: churnData.reduce((sum, period) => sum + period.churned, 0),
          averageChurnRate: this.calculateAverageChurnRate(churnData),
          netGrowth: metrics.totalNewUsers - churnData.reduce((sum, period) => sum + period.churned, 0)
        };
      }

      // Build response
      const response = {
        period: {
          start,
          end,
          granularity
        },
        data: growthData,
        metrics,
        segments: segmentBy ? await this.getGrowthSegments(start, end, segmentBy) : null,
        visualization: {
          chartType: 'line',
          series: this.formatGrowthChartData(growthData, includeChurn ? churnData : null)
        }
      };

      // Log analytics access
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.ANALYTICS_VIEWED, {
        type: 'growth',
        startDate: start,
        endDate: end,
        granularity,
        segmentBy
      });

      return response;

    } catch (error) {
      logger.error('Get user growth analytics error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get user engagement analytics
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Engagement analytics options
   * @returns {Promise<Object>} Engagement analytics data
   */
  async getUserEngagementAnalytics(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS);

      const {
        timeRange = 'last30d',
        engagementMetrics = ['dau', 'wau', 'mau', 'stickiness'],
        activityTypes = null,
        organizationId = null
      } = options;

      const { startDate, endDate } = this.calculateDateRange(timeRange);
      const baseQuery = organizationId ? { 'organization.current': organizationId } : {};

      // Calculate engagement metrics
      const metricsData = {};

      for (const metric of engagementMetrics) {
        switch (metric) {
          case 'dau': // Daily Active Users
            metricsData.dau = await this.calculateDAU(endDate, baseQuery);
            break;
          case 'wau': // Weekly Active Users
            metricsData.wau = await this.calculateWAU(endDate, baseQuery);
            break;
          case 'mau': // Monthly Active Users
            metricsData.mau = await this.calculateMAU(endDate, baseQuery);
            break;
          case 'stickiness':
            const dau = metricsData.dau || await this.calculateDAU(endDate, baseQuery);
            const mau = metricsData.mau || await this.calculateMAU(endDate, baseQuery);
            metricsData.stickiness = mau > 0 ? (dau / mau * 100).toFixed(2) : 0;
            break;
        }
      }

      // Get activity distribution
      const activityDistribution = await this.getActivityDistribution(
        startDate,
        endDate,
        baseQuery,
        activityTypes
      );

      // Get engagement trends
      const engagementTrends = await this.getEngagementTrends(
        startDate,
        endDate,
        baseQuery
      );

      // Get session analytics
      const sessionAnalytics = await this.getSessionAnalytics(
        startDate,
        endDate,
        baseQuery
      );

      // Build response
      const response = {
        period: {
          start: startDate,
          end: endDate
        },
        metrics: metricsData,
        activityDistribution,
        trends: engagementTrends,
        sessions: sessionAnalytics,
        insights: this.generateEngagementInsights(metricsData, activityDistribution)
      };

      // Log analytics access
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.ANALYTICS_VIEWED, {
        type: 'engagement',
        timeRange,
        metrics: engagementMetrics
      });

      return response;

    } catch (error) {
      logger.error('Get user engagement analytics error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get user retention analytics
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Retention analytics options
   * @returns {Promise<Object>} Retention analytics data
   */
  async getUserRetentionAnalytics(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS);

      const {
        cohortType = this.cohortTypes.SIGNUP,
        cohortPeriod = 'month', // day, week, month
        retentionPeriods = 12, // Number of periods to track
        startDate,
        endDate,
        segmentBy = null
      } = options;

      // Calculate cohort dates
      const cohortStartDate = new Date(startDate || Date.now() - retentionPeriods * 30 * 24 * 60 * 60 * 1000);
      const cohortEndDate = new Date(endDate || Date.now());

      // Generate cohorts
      const cohorts = await this.generateCohorts(
        cohortType,
        cohortPeriod,
        cohortStartDate,
        cohortEndDate
      );

      // Calculate retention for each cohort
      const retentionData = await this.calculateRetention(cohorts, retentionPeriods);

      // Calculate retention metrics
      const metrics = {
        averageRetention: this.calculateAverageRetention(retentionData),
        retentionCurve: this.generateRetentionCurve(retentionData),
        halfLife: this.calculateRetentionHalfLife(retentionData),
        ltv: await this.calculateCohortLTV(cohorts)
      };

      // Add segmentation if requested
      let segments = null;
      if (segmentBy) {
        segments = await this.segmentRetentionData(cohorts, retentionData, segmentBy);
      }

      // Build response
      const response = {
        cohortType,
        cohortPeriod,
        periods: retentionPeriods,
        cohorts: cohorts.map(cohort => ({
          id: cohort.id,
          label: cohort.label,
          size: cohort.users.length,
          startDate: cohort.startDate,
          endDate: cohort.endDate
        })),
        retention: retentionData,
        metrics,
        segments,
        visualization: {
          chartType: 'heatmap',
          data: this.formatRetentionHeatmap(retentionData)
        }
      };

      // Log analytics access
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.ANALYTICS_VIEWED, {
        type: 'retention',
        cohortType,
        cohortPeriod,
        periods: retentionPeriods
      });

      return response;

    } catch (error) {
      logger.error('Get user retention analytics error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get user behavior analytics
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Behavior analytics options
   * @returns {Promise<Object>} Behavior analytics data
   */
  async getUserBehaviorAnalytics(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS);

      const {
        timeRange = 'last30d',
        behaviorTypes = ['user_journey', 'feature_adoption', 'activity_patterns'],
        userId = null,
        organizationId = null
      } = options;

      const { startDate, endDate } = this.calculateDateRange(timeRange);
      
      // Build query
      const query = {};
      if (userId) query.userId = userId;
      if (organizationId) query['organization.current'] = organizationId;

      const behaviorData = {};

      // Analyze different behavior types
      for (const type of behaviorTypes) {
        switch (type) {
          case 'user_journey':
            behaviorData.userJourney = await this.analyzeUserJourney(
              startDate,
              endDate,
              query
            );
            break;
            
          case 'feature_adoption':
            behaviorData.featureAdoption = await this.analyzeFeatureAdoption(
              startDate,
              endDate,
              query
            );
            break;
            
          case 'activity_patterns':
            behaviorData.activityPatterns = await this.analyzeActivityPatterns(
              startDate,
              endDate,
              query
            );
            break;
            
          case 'conversion_funnel':
            behaviorData.conversionFunnel = await this.analyzeConversionFunnel(
              startDate,
              endDate,
              query
            );
            break;
        }
      }

      // Generate behavior insights
      const insights = await this.generateBehaviorInsights(behaviorData);

      // Build response
      const response = {
        period: {
          start: startDate,
          end: endDate
        },
        behaviors: behaviorData,
        insights,
        recommendations: await this.generateBehaviorRecommendations(behaviorData)
      };

      // Log analytics access
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.ANALYTICS_VIEWED, {
        type: 'behavior',
        timeRange,
        behaviorTypes,
        userId,
        organizationId
      });

      return response;

    } catch (error) {
      logger.error('Get user behavior analytics error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Generate custom user report
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} reportConfig - Report configuration
   * @returns {Promise<Object>} Generated report
   */
  async generateUserReport(adminUser, reportConfig) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.GENERATE_REPORTS);

      const {
        reportType,
        title,
        description,
        metrics,
        filters = {},
        format = 'pdf',
        schedule = null,
        recipients = []
      } = reportConfig;

      // Validate report configuration
      if (!reportType || !metrics || metrics.length === 0) {
        throw new ValidationError('Report type and metrics are required');
      }

      // Build report data
      const reportData = await this.buildReportData(reportType, metrics, filters);

      // Generate report using ReportService
      const report = await ReportService.generateReport({
        type: 'user_analytics',
        subType: reportType,
        title: title || `User ${reportType} Report`,
        description,
        data: reportData,
        format,
        metadata: {
          generatedBy: adminUser.id,
          filters,
          metrics
        }
      });

      // Schedule if requested
      if (schedule) {
        await this.scheduleReport({
          reportConfig,
          adminUserId: adminUser.id,
          recipients
        });
      }

      // Send to recipients if provided
      if (recipients.length > 0 && !schedule) {
        await this.distributeReport(report, recipients);
      }

      // Log report generation
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.REPORT_GENERATED, {
        reportId: report.id,
        reportType,
        format,
        scheduled: !!schedule,
        recipientCount: recipients.length
      }, { critical: true });

      return {
        reportId: report.id,
        url: report.url,
        format,
        expiresAt: report.expiresAt,
        scheduled: !!schedule,
        message: 'Report generated successfully'
      };

    } catch (error) {
      logger.error('Generate user report error', {
        error: error.message,
        adminId: adminUser.id,
        reportType: reportConfig.reportType,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get overview metrics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {Object} baseQuery - Base query
   * @param {Object} previousPeriod - Previous period for comparison
   * @returns {Promise<Object>} Overview metrics
   * @private
   */
  async getOverviewMetrics(startDate, endDate, baseQuery, previousPeriod) {
    const currentPeriodQuery = {
      ...baseQuery,
      createdAt: { $gte: startDate, $lte: endDate }
    };

    const [
      totalUsers,
      newUsers,
      activeUsers,
      verifiedUsers
    ] = await Promise.all([
      User.countDocuments({ ...baseQuery, status: { $ne: 'deleted' } }),
      User.countDocuments(currentPeriodQuery),
      User.countDocuments({
        ...baseQuery,
        lastActiveAt: { $gte: startDate, $lte: endDate }
      }),
      User.countDocuments({
        ...baseQuery,
        'auth.email.verified': true
      })
    ]);

    // Calculate previous period metrics if needed
    let comparison = null;
    if (previousPeriod) {
      const previousQuery = {
        ...baseQuery,
        createdAt: { $gte: previousPeriod.start, $lte: previousPeriod.end }
      };

      const [prevNewUsers, prevActiveUsers] = await Promise.all([
        User.countDocuments(previousQuery),
        User.countDocuments({
          ...baseQuery,
          lastActiveAt: { $gte: previousPeriod.start, $lte: previousPeriod.end }
        })
      ]);

      comparison = {
        newUsers: calculatePercentageChange(prevNewUsers, newUsers),
        activeUsers: calculatePercentageChange(prevActiveUsers, activeUsers)
      };
    }

    return {
      totalUsers,
      newUsers,
      activeUsers,
      verifiedUsers,
      verificationRate: totalUsers > 0 ? (verifiedUsers / totalUsers * 100).toFixed(2) : 0,
      activationRate: newUsers > 0 ? (activeUsers / newUsers * 100).toFixed(2) : 0,
      comparison
    };
  }

  /**
   * Get growth metrics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {Object} baseQuery - Base query
   * @returns {Promise<Object>} Growth metrics
   * @private
   */
  async getGrowthMetrics(startDate, endDate, baseQuery) {
    const pipeline = [
      {
        $match: {
          ...baseQuery,
          createdAt: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            day: { $dayOfMonth: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 }
      }
    ];

    const dailyGrowth = await User.aggregate(pipeline);

    // Calculate growth rate
    const growthRate = calculateGrowthRate(
      dailyGrowth.map(d => ({ date: new Date(d._id.year, d._id.month - 1, d._id.day), value: d.count }))
    );

    // Calculate cumulative growth
    let cumulative = 0;
    const cumulativeGrowth = dailyGrowth.map(day => {
      cumulative += day.count;
      return {
        date: new Date(day._id.year, day._id.month - 1, day._id.day),
        daily: day.count,
        cumulative
      };
    });

    return {
      dailyGrowth: dailyGrowth.map(d => ({
        date: new Date(d._id.year, d._id.month - 1, d._id.day),
        count: d.count
      })),
      cumulativeGrowth,
      averageDailyGrowth: (dailyGrowth.reduce((sum, d) => sum + d.count, 0) / dailyGrowth.length).toFixed(2),
      growthRate: growthRate.toFixed(2),
      trend: this.calculateTrend(dailyGrowth)
    };
  }

  /**
   * Get engagement metrics
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {Object} baseQuery - Base query
   * @returns {Promise<Object>} Engagement metrics
   * @private
   */
  async getEngagementMetrics(startDate, endDate, baseQuery) {
    // Get unique active users per day
    const activeUsersPipeline = [
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: {
            userId: '$userId',
            date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } }
          }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          uniqueUsers: { $sum: 1 }
        }
      },
      {
        $sort: { _id: 1 }
      }
    ];

    const dailyActiveUsers = await UserActivity.aggregate(activeUsersPipeline);

    // Calculate average session duration
    const sessionStats = await UserSession.aggregate([
      {
        $match: {
          createdAt: { $gte: startDate, $lte: endDate },
          endedAt: { $exists: true }
        }
      },
      {
        $project: {
          duration: { $subtract: ['$endedAt', '$createdAt'] }
        }
      },
      {
        $group: {
          _id: null,
          avgDuration: { $avg: '$duration' },
          totalSessions: { $sum: 1 }
        }
      }
    ]);

    // Get action frequency
    const actionFrequency = await UserActivity.aggregate([
      {
        $match: {
          timestamp: { $gte: startDate, $lte: endDate }
        }
      },
      {
        $group: {
          _id: '$action',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 10
      }
    ]);

    return {
      dailyActiveUsers: dailyActiveUsers.map(d => ({
        date: d._id,
        users: d.uniqueUsers
      })),
      averageDAU: (dailyActiveUsers.reduce((sum, d) => sum + d.uniqueUsers, 0) / dailyActiveUsers.length).toFixed(0),
      averageSessionDuration: sessionStats[0]?.avgDuration ? 
        (sessionStats[0].avgDuration / 1000 / 60).toFixed(2) + ' minutes' : 'N/A',
      totalSessions: sessionStats[0]?.totalSessions || 0,
      topActions: actionFrequency
    };
  }

  /**
   * Calculate Daily Active Users (DAU)
   * @param {Date} date - Date to calculate DAU for
   * @param {Object} baseQuery - Base query
   * @returns {Promise<number>} DAU count
   * @private
   */
  async calculateDAU(date, baseQuery) {
    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);

    const uniqueUsers = await UserActivity.distinct('userId', {
      ...baseQuery,
      timestamp: { $gte: startOfDay, $lte: endOfDay }
    });

    return uniqueUsers.length;
  }

  /**
   * Calculate Weekly Active Users (WAU)
   * @param {Date} date - End date of the week
   * @param {Object} baseQuery - Base query
   * @returns {Promise<number>} WAU count
   * @private
   */
  async calculateWAU(date, baseQuery) {
    const endDate = new Date(date);
    const startDate = new Date(date);
    startDate.setDate(startDate.getDate() - 7);

    const uniqueUsers = await UserActivity.distinct('userId', {
      ...baseQuery,
      timestamp: { $gte: startDate, $lte: endDate }
    });

    return uniqueUsers.length;
  }

  /**
   * Calculate Monthly Active Users (MAU)
   * @param {Date} date - End date of the month
   * @param {Object} baseQuery - Base query
   * @returns {Promise<number>} MAU count
   * @private
   */
  async calculateMAU(date, baseQuery) {
    const endDate = new Date(date);
    const startDate = new Date(date);
    startDate.setDate(startDate.getDate() - 30);

    const uniqueUsers = await UserActivity.distinct('userId', {
      ...baseQuery,
      timestamp: { $gte: startDate, $lte: endDate }
    });

    return uniqueUsers.length;
  }

  /**
   * Additional helper methods would continue here...
   */
}

module.exports = new UserAnalyticsService();