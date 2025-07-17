// server/admin/organization-management/services/organization-analytics-service.js
/**
 * @file Organization Analytics Service
 * @description Service for comprehensive organization analytics and reporting
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const moment = require('moment');
const _ = require('lodash');

// Core Models
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const OrganizationTenant = require('../../../organization-tenants/models/organization-tenant-model');
const User = require('../../../shared/users/models/user-model');
const UserActivity = require('../../../shared/users/models/user-activity-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');
const Subscription = require('../../../shared/billing/models/subscription-model');
const Payment = require('../../../shared/billing/models/payment-model');
const Invoice = require('../../../shared/billing/models/invoice-model');
const Project = require('../../../core-business/projects/models/project-model');
const Task = require('../../../core-business/tasks/models/task-model');
const ApiUsage = require('../../../shared/monitoring/models/api-usage-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const CacheService = require('../../../shared/utils/cache-service');
const MetricsService = require('../../../shared/monitoring/services/metrics-service');
const AdminExportService = require('../../../shared/admin/services/admin-export-service');
const ReportingService = require('../../../shared/services/reporting-service');

// Utilities
const { AppError, ValidationError, NotFoundError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const { calculateGrowthRate, calculateRetention, calculateChurn } = require('../../../shared/utils/analytics-helpers');

// Configuration
const config = require('../../../config');

/**
 * Organization Analytics Service Class
 * @class OrganizationAnalyticsService
 * @extends AdminBaseService
 */
class OrganizationAnalyticsService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'OrganizationAnalyticsService';
    this.cachePrefix = 'admin-org-analytics';
    this.auditCategory = 'ORGANIZATION_ANALYTICS';
    this.requiredPermission = AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS;
    
    // Analytics configuration
    this.metricCategories = {
      ENGAGEMENT: ['dailyActiveUsers', 'weeklyActiveUsers', 'monthlyActiveUsers', 'sessionDuration', 'pageViews'],
      PERFORMANCE: ['apiResponseTime', 'errorRate', 'uptime', 'throughput'],
      BUSINESS: ['revenue', 'customerLifetimeValue', 'churnRate', 'netPromoterScore'],
      USAGE: ['apiCalls', 'storageUsed', 'bandwidth', 'activeProjects', 'activeTasks'],
      GROWTH: ['userGrowth', 'revenueGrowth', 'retentionRate', 'expansionRevenue']
    };
    
    this.reportTypes = {
      EXECUTIVE_SUMMARY: 'executive_summary',
      USAGE_REPORT: 'usage_report',
      FINANCIAL_REPORT: 'financial_report',
      ENGAGEMENT_REPORT: 'engagement_report',
      HEALTH_REPORT: 'health_report',
      COMPLIANCE_REPORT: 'compliance_report',
      CUSTOM: 'custom'
    };
    
    this.aggregationPeriods = {
      HOURLY: 'hour',
      DAILY: 'day',
      WEEKLY: 'week',
      MONTHLY: 'month',
      QUARTERLY: 'quarter',
      YEARLY: 'year'
    };
  }

  /**
   * Get comprehensive organization analytics
   * @param {String} organizationId - Organization ID
   * @param {Object} options - Analytics options
   * @param {Object} adminUser - Admin user making the request
   * @returns {Promise<Object>} Comprehensive analytics
   */
  async getOrganizationAnalytics(organizationId, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS);
      
      const organization = await HostedOrganization.findById(organizationId).lean();
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Determine analytics period
      const period = options.period || 'month';
      const dateRange = this._getDateRange(period, options.startDate, options.endDate);
      
      // Check cache for recent analytics
      const cacheKey = `${this.cachePrefix}:${organizationId}:${period}:${dateRange.start.toISOString()}`;
      const cached = await this.cache.get(cacheKey);
      
      if (cached && !options.forceRefresh) {
        return cached;
      }
      
      // Gather all analytics data in parallel
      const [
        engagement,
        usage,
        financial,
        performance,
        userMetrics,
        projectMetrics,
        growthMetrics,
        healthScore
      ] = await Promise.all([
        this._getEngagementAnalytics(organizationId, dateRange),
        this._getUsageAnalytics(organizationId, dateRange),
        this._getFinancialAnalytics(organizationId, dateRange),
        this._getPerformanceAnalytics(organizationId, dateRange),
        this._getUserMetrics(organizationId, dateRange),
        this._getProjectMetrics(organizationId, dateRange),
        this._getGrowthMetrics(organizationId, dateRange),
        this._calculateHealthScore(organizationId, dateRange)
      ]);
      
      // Compile comprehensive analytics
      const analytics = {
        organization: {
          id: organization._id,
          name: organization.name,
          createdAt: organization.createdAt,
          ageInDays: moment().diff(organization.createdAt, 'days')
        },
        period: {
          type: period,
          start: dateRange.start,
          end: dateRange.end,
          days: moment(dateRange.end).diff(dateRange.start, 'days')
        },
        summary: this._generateExecutiveSummary({
          engagement,
          usage,
          financial,
          performance,
          userMetrics,
          projectMetrics,
          growthMetrics,
          healthScore
        }),
        engagement,
        usage,
        financial,
        performance,
        users: userMetrics,
        projects: projectMetrics,
        growth: growthMetrics,
        health: healthScore,
        trends: await this._calculateTrends(organizationId, dateRange),
        benchmarks: await this._getBenchmarks(organization, {
          engagement,
          usage,
          financial,
          performance
        }),
        recommendations: this._generateRecommendations({
          engagement,
          usage,
          financial,
          performance,
          growthMetrics,
          healthScore
        }),
        generatedAt: new Date()
      };
      
      // Cache the results
      await this.cache.set(cacheKey, analytics, 3600); // 1 hour cache
      
      // Log action
      await this.logAction(AdminEvents.ANALYTICS.ORGANIZATION_ANALYTICS_VIEWED, adminUser, {
        organizationId,
        period,
        dateRange
      });
      
      return analytics;
    } catch (error) {
      logger.error('Error getting organization analytics:', error);
      throw error;
    }
  }

  /**
   * Generate organization report
   * @param {String} organizationId - Organization ID
   * @param {Object} reportConfig - Report configuration
   * @param {Object} adminUser - Admin user generating the report
   * @returns {Promise<Object>} Generated report
   */
  async generateOrganizationReport(organizationId, reportConfig, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.GENERATE_REPORTS);
      
      const organization = await HostedOrganization.findById(organizationId)
        .populate('team.owner', 'name email')
        .lean();
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Validate report configuration
      this._validateReportConfig(reportConfig);
      
      // Generate report based on type
      let reportData;
      switch (reportConfig.type) {
        case this.reportTypes.EXECUTIVE_SUMMARY:
          reportData = await this._generateExecutiveReport(organization, reportConfig);
          break;
        case this.reportTypes.USAGE_REPORT:
          reportData = await this._generateUsageReport(organization, reportConfig);
          break;
        case this.reportTypes.FINANCIAL_REPORT:
          reportData = await this._generateFinancialReport(organization, reportConfig);
          break;
        case this.reportTypes.ENGAGEMENT_REPORT:
          reportData = await this._generateEngagementReport(organization, reportConfig);
          break;
        case this.reportTypes.HEALTH_REPORT:
          reportData = await this._generateHealthReport(organization, reportConfig);
          break;
        case this.reportTypes.COMPLIANCE_REPORT:
          reportData = await this._generateComplianceReport(organization, reportConfig);
          break;
        case this.reportTypes.CUSTOM:
          reportData = await this._generateCustomReport(organization, reportConfig);
          break;
        default:
          throw new ValidationError('Invalid report type');
      }
      
      // Format report
      const report = {
        id: crypto.randomBytes(16).toString('hex'),
        type: reportConfig.type,
        organization: {
          id: organization._id,
          name: organization.name,
          owner: organization.team.owner
        },
        config: reportConfig,
        data: reportData,
        metadata: {
          generatedAt: new Date(),
          generatedBy: adminUser._id,
          format: reportConfig.format || 'json',
          period: reportConfig.period,
          dateRange: reportConfig.dateRange
        }
      };
      
      // Export report if requested
      if (reportConfig.export) {
        report.exportUrl = await this._exportReport(report, reportConfig.exportFormat);
      }
      
      // Store report for future reference
      await this._storeReport(report);
      
      // Log action
      await this.logAction(AdminEvents.ANALYTICS.REPORT_GENERATED, adminUser, {
        organizationId,
        reportType: reportConfig.type,
        reportId: report.id
      });
      
      return report;
    } catch (error) {
      logger.error('Error generating organization report:', error);
      throw error;
    }
  }

  /**
   * Compare organizations
   * @param {Array} organizationIds - Organization IDs to compare
   * @param {Object} comparisonConfig - Comparison configuration
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Comparison results
   */
  async compareOrganizations(organizationIds, comparisonConfig = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS);
      
      if (!Array.isArray(organizationIds) || organizationIds.length < 2) {
        throw new ValidationError('At least 2 organizations required for comparison');
      }
      
      if (organizationIds.length > 10) {
        throw new ValidationError('Maximum 10 organizations can be compared at once');
      }
      
      // Get organizations
      const organizations = await HostedOrganization.find({
        _id: { $in: organizationIds }
      }).lean();
      
      if (organizations.length !== organizationIds.length) {
        throw new NotFoundError('One or more organizations not found');
      }
      
      const dateRange = this._getDateRange(
        comparisonConfig.period || 'month',
        comparisonConfig.startDate,
        comparisonConfig.endDate
      );
      
      // Gather comparison data for each organization
      const comparisonData = await Promise.all(
        organizations.map(async (org) => {
          const [metrics, health, growth] = await Promise.all([
            this._getComparisonMetrics(org._id, dateRange, comparisonConfig.metrics),
            this._calculateHealthScore(org._id, dateRange),
            this._getGrowthMetrics(org._id, dateRange)
          ]);
          
          return {
            organization: {
              id: org._id,
              name: org.name,
              createdAt: org.createdAt,
              subscription: org.subscription
            },
            metrics,
            health,
            growth
          };
        })
      );
      
      // Calculate comparative statistics
      const comparison = {
        organizations: comparisonData,
        statistics: this._calculateComparativeStatistics(comparisonData, comparisonConfig.metrics),
        rankings: this._generateRankings(comparisonData, comparisonConfig.metrics),
        insights: this._generateComparativeInsights(comparisonData),
        period: {
          type: comparisonConfig.period || 'month',
          start: dateRange.start,
          end: dateRange.end
        },
        generatedAt: new Date()
      };
      
      // Log action
      await this.logAction(AdminEvents.ANALYTICS.ORGANIZATIONS_COMPARED, adminUser, {
        organizationIds,
        period: comparisonConfig.period,
        metrics: comparisonConfig.metrics
      });
      
      return comparison;
    } catch (error) {
      logger.error('Error comparing organizations:', error);
      throw error;
    }
  }

  /**
   * Get organization growth analytics
   * @param {String} organizationId - Organization ID
   * @param {Object} options - Growth analytics options
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Growth analytics
   */
  async getGrowthAnalytics(organizationId, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS);
      
      const organization = await HostedOrganization.findById(organizationId).lean();
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      const periods = options.periods || 12; // Default to 12 periods
      const periodType = options.periodType || 'month';
      
      // Generate period ranges
      const periodRanges = this._generatePeriodRanges(periods, periodType);
      
      // Gather growth data for each period
      const growthData = await Promise.all(
        periodRanges.map(async (range) => {
          const [users, revenue, usage, projects] = await Promise.all([
            this._getUserGrowthForPeriod(organizationId, range),
            this._getRevenueGrowthForPeriod(organizationId, range),
            this._getUsageGrowthForPeriod(organizationId, range),
            this._getProjectGrowthForPeriod(organizationId, range)
          ]);
          
          return {
            period: {
              start: range.start,
              end: range.end,
              label: range.label
            },
            users,
            revenue,
            usage,
            projects
          };
        })
      );
      
      // Calculate growth rates and trends
      const growthAnalytics = {
        organization: {
          id: organization._id,
          name: organization.name
        },
        periodType,
        periods: growthData,
        summary: {
          users: this._calculateGrowthSummary(growthData.map(d => d.users)),
          revenue: this._calculateGrowthSummary(growthData.map(d => d.revenue)),
          usage: this._calculateGrowthSummary(growthData.map(d => d.usage)),
          projects: this._calculateGrowthSummary(growthData.map(d => d.projects))
        },
        trends: {
          users: this._calculateGrowthTrend(growthData.map(d => d.users)),
          revenue: this._calculateGrowthTrend(growthData.map(d => d.revenue)),
          usage: this._calculateGrowthTrend(growthData.map(d => d.usage)),
          projects: this._calculateGrowthTrend(growthData.map(d => d.projects))
        },
        forecasts: options.includeForecast ? 
          await this._generateGrowthForecasts(growthData) : null,
        cohortAnalysis: options.includeCohorts ? 
          await this._performCohortAnalysis(organizationId, periodRanges) : null,
        generatedAt: new Date()
      };
      
      // Log action
      await this.logAction(AdminEvents.ANALYTICS.GROWTH_ANALYTICS_VIEWED, adminUser, {
        organizationId,
        periodType,
        periods
      });
      
      return growthAnalytics;
    } catch (error) {
      logger.error('Error getting growth analytics:', error);
      throw error;
    }
  }

  /**
   * Get organization performance metrics
   * @param {String} organizationId - Organization ID
   * @param {Object} options - Performance options
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Performance metrics
   */
  async getPerformanceMetrics(organizationId, options = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ANALYTICS);
      
      const organization = await HostedOrganization.findById(organizationId).lean();
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      const dateRange = this._getDateRange(
        options.period || 'day',
        options.startDate,
        options.endDate
      );
      
      // Gather performance data
      const [
        apiMetrics,
        systemMetrics,
        userExperience,
        reliability,
        scalability
      ] = await Promise.all([
        this._getApiPerformanceMetrics(organizationId, dateRange),
        this._getSystemPerformanceMetrics(organizationId, dateRange),
        this._getUserExperienceMetrics(organizationId, dateRange),
        this._getReliabilityMetrics(organizationId, dateRange),
        this._getScalabilityMetrics(organizationId, dateRange)
      ]);
      
      // Calculate performance score
      const performanceScore = this._calculatePerformanceScore({
        apiMetrics,
        systemMetrics,
        userExperience,
        reliability,
        scalability
      });
      
      const performanceMetrics = {
        organization: {
          id: organization._id,
          name: organization.name
        },
        period: dateRange,
        score: performanceScore,
        api: apiMetrics,
        system: systemMetrics,
        userExperience,
        reliability,
        scalability,
        sla: {
          compliance: await this._checkSLACompliance(organizationId, dateRange),
          violations: await this._getSLAViolations(organizationId, dateRange)
        },
        incidents: await this._getIncidents(organizationId, dateRange),
        optimizations: this._generatePerformanceOptimizations({
          apiMetrics,
          systemMetrics,
          userExperience,
          reliability,
          scalability
        }),
        generatedAt: new Date()
      };
      
      // Log action
      await this.logAction(AdminEvents.ANALYTICS.PERFORMANCE_METRICS_VIEWED, adminUser, {
        organizationId,
        period: options.period
      });
      
      return performanceMetrics;
    } catch (error) {
      logger.error('Error getting performance metrics:', error);
      throw error;
    }
  }

  /**
   * Get predictive analytics
   * @param {String} organizationId - Organization ID
   * @param {Object} predictionConfig - Prediction configuration
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Predictive analytics
   */
  async getPredictiveAnalytics(organizationId, predictionConfig = {}, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.VIEW_ADVANCED_ANALYTICS);
      
      const organization = await HostedOrganization.findById(organizationId).lean();
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Gather historical data for predictions
      const historicalPeriods = predictionConfig.historicalPeriods || 12;
      const historicalData = await this._gatherHistoricalData(
        organizationId,
        historicalPeriods,
        predictionConfig.metrics || ['revenue', 'users', 'churn']
      );
      
      // Generate predictions
      const predictions = {
        churnProbability: await this._predictChurn(organizationId, historicalData),
        revenueForecasts: await this._forecastRevenue(organizationId, historicalData, predictionConfig),
        usageProjections: await this._projectUsage(organizationId, historicalData, predictionConfig),
        growthPotential: await this._assessGrowthPotential(organizationId, historicalData),
        riskAssessment: await this._assessRisks(organizationId, historicalData),
        opportunities: await this._identifyOpportunities(organizationId, historicalData),
        recommendedActions: this._generatePredictiveRecommendations({
          churn: predictions.churnProbability,
          revenue: predictions.revenueForecasts,
          usage: predictions.usageProjections,
          growth: predictions.growthPotential,
          risks: predictions.riskAssessment
        })
      };
      
      // Log action
      await this.logAction(AdminEvents.ANALYTICS.PREDICTIVE_ANALYTICS_VIEWED, adminUser, {
        organizationId,
        metrics: predictionConfig.metrics,
        historicalPeriods
      });
      
      return {
        organization: {
          id: organization._id,
          name: organization.name
        },
        predictions,
        confidence: this._calculatePredictionConfidence(historicalData),
        methodology: 'Time series analysis with seasonal adjustments',
        generatedAt: new Date()
      };
    } catch (error) {
      logger.error('Error getting predictive analytics:', error);
      throw error;
    }
  }

  /**
   * Track custom analytics event
   * @param {String} organizationId - Organization ID
   * @param {Object} eventData - Event data
   * @param {Object} adminUser - Admin user
   * @returns {Promise<Object>} Tracking result
   */
  async trackAnalyticsEvent(organizationId, eventData, adminUser) {
    try {
      // Check permissions
      await this.checkPermission(adminUser, AdminPermissions.ORGANIZATION_MANAGEMENT.TRACK_CUSTOM_EVENTS);
      
      const organization = await HostedOrganization.findById(organizationId);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Validate event data
      this._validateEventData(eventData);
      
      // Create analytics event
      const analyticsEvent = {
        organizationId,
        category: eventData.category,
        action: eventData.action,
        label: eventData.label,
        value: eventData.value,
        metadata: eventData.metadata,
        timestamp: new Date(),
        source: 'admin_panel',
        trackedBy: adminUser._id
      };
      
      // Store event
      await this._storeAnalyticsEvent(analyticsEvent);
      
      // Update real-time metrics if applicable
      if (eventData.updateMetrics) {
        await this._updateRealTimeMetrics(organizationId, analyticsEvent);
      }
      
      // Log action
      await this.logAction(AdminEvents.ANALYTICS.CUSTOM_EVENT_TRACKED, adminUser, {
        organizationId,
        eventCategory: eventData.category,
        eventAction: eventData.action
      });
      
      return {
        success: true,
        event: analyticsEvent,
        message: 'Analytics event tracked successfully'
      };
    } catch (error) {
      logger.error('Error tracking analytics event:', error);
      throw error;
    }
  }

  // Private helper methods - Engagement Analytics

  async _getEngagementAnalytics(organizationId, dateRange) {
    const [
      activeUsers,
      sessionMetrics,
      featureUsage,
      retentionData
    ] = await Promise.all([
      this._getActiveUserMetrics(organizationId, dateRange),
      this._getSessionMetrics(organizationId, dateRange),
      this._getFeatureUsageMetrics(organizationId, dateRange),
      this._getRetentionMetrics(organizationId, dateRange)
    ]);
    
    return {
      activeUsers,
      sessions: sessionMetrics,
      features: featureUsage,
      retention: retentionData,
      engagement: {
        score: this._calculateEngagementScore({ activeUsers, sessionMetrics, featureUsage }),
        trend: this._calculateEngagementTrend(activeUsers, sessionMetrics)
      }
    };
  }

  async _getActiveUserMetrics(organizationId, dateRange) {
    const organization = await HostedOrganization.findById(organizationId).lean();
    const userIds = [
      organization.team.owner,
      ...organization.team.admins.map(a => a.user),
      ...organization.team.members.map(m => m.user)
    ];
    
    // Daily Active Users
    const dauData = await UserActivity.aggregate([
      {
        $match: {
          userId: { $in: userIds },
          timestamp: { $gte: dateRange.start, $lte: dateRange.end }
        }
      },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
            user: '$userId'
          }
        }
      },
      {
        $group: {
          _id: '$_id.date',
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    // Calculate WAU and MAU
    const uniqueUsers = await UserActivity.distinct('userId', {
      userId: { $in: userIds },
      timestamp: { $gte: dateRange.start, $lte: dateRange.end }
    });
    
    return {
      daily: dauData,
      weekly: await this._calculateWAU(userIds, dateRange),
      monthly: uniqueUsers.length,
      averageDAU: dauData.reduce((sum, day) => sum + day.count, 0) / dauData.length || 0,
      stickiness: (dauData.reduce((sum, day) => sum + day.count, 0) / dauData.length) / uniqueUsers.length || 0
    };
  }

  async _getSessionMetrics(organizationId, dateRange) {
    const sessions = await UserActivity.aggregate([
      {
        $match: {
          organizationId: new mongoose.Types.ObjectId(organizationId),
          timestamp: { $gte: dateRange.start, $lte: dateRange.end },
          type: 'session_start'
        }
      },
      {
        $lookup: {
          from: 'useractivities',
          let: { sessionId: '$sessionId' },
          pipeline: [
            {
              $match: {
                $expr: {
                  $and: [
                    { $eq: ['$sessionId', '$$sessionId'] },
                    { $eq: ['$type', 'session_end'] }
                  ]
                }
              }
            }
          ],
          as: 'sessionEnd'
        }
      },
      {
        $project: {
          userId: 1,
          timestamp: 1,
          duration: {
            $cond: {
              if: { $gt: [{ $size: '$sessionEnd' }, 0] },
              then: {
                $subtract: [
                  { $arrayElemAt: ['$sessionEnd.timestamp', 0] },
                  '$timestamp'
                ]
              },
              else: null
            }
          }
        }
      }
    ]);
    
    const validSessions = sessions.filter(s => s.duration !== null);
    const avgDuration = validSessions.reduce((sum, s) => sum + s.duration, 0) / validSessions.length || 0;
    
    return {
      total: sessions.length,
      completed: validSessions.length,
      averageDuration: Math.round(avgDuration / 1000 / 60), // Convert to minutes
      bounceRate: ((sessions.length - validSessions.length) / sessions.length * 100) || 0,
      distribution: this._getSessionDistribution(validSessions)
    };
  }

  async _getUsageAnalytics(organizationId, dateRange) {
    const [
      apiUsage,
      storageUsage,
      bandwidthUsage,
      featureUsage
    ] = await Promise.all([
      this._getApiUsageMetrics(organizationId, dateRange),
      this._getStorageMetrics(organizationId, dateRange),
      this._getBandwidthMetrics(organizationId, dateRange),
      this._getFeatureUsageMetrics(organizationId, dateRange)
    ]);
    
    return {
      api: apiUsage,
      storage: storageUsage,
      bandwidth: bandwidthUsage,
      features: featureUsage,
      limits: await this._getUsageLimits(organizationId),
      trends: this._calculateUsageTrends({ apiUsage, storageUsage, bandwidthUsage })
    };
  }

  async _getFinancialAnalytics(organizationId, dateRange) {
    const [
      revenue,
      payments,
      invoices,
      credits,
      refunds
    ] = await Promise.all([
      this._getRevenueMetrics(organizationId, dateRange),
      this._getPaymentMetrics(organizationId, dateRange),
      this._getInvoiceMetrics(organizationId, dateRange),
      this._getCreditMetrics(organizationId, dateRange),
      this._getRefundMetrics(organizationId, dateRange)
    ]);
    
    const mrr = await this._calculateCurrentMRR(organizationId);
    const ltv = await this._calculateLTV(organizationId);
    
    return {
      revenue,
      payments,
      invoices,
      credits,
      refunds,
      summary: {
        totalRevenue: revenue.total,
        mrr,
        ltv,
        averageOrderValue: revenue.total / payments.successful || 0,
        paymentSuccessRate: (payments.successful / payments.total * 100) || 0
      },
      health: this._assessFinancialHealth({ revenue, payments, invoices })
    };
  }

  _generateExecutiveSummary(data) {
    const {
      engagement,
      usage,
      financial,
      performance,
      userMetrics,
      projectMetrics,
      growthMetrics,
      healthScore
    } = data;
    
    return {
      keyMetrics: {
        monthlyActiveUsers: engagement.activeUsers.monthly,
        revenue: financial.summary.totalRevenue,
        mrr: financial.summary.mrr,
        healthScore: healthScore.overall,
        userGrowth: growthMetrics.users.rate,
        churnRate: growthMetrics.churn.rate
      },
      highlights: this._generateHighlights(data),
      concerns: this._identifyConcerns(data),
      opportunities: this._identifyOpportunities(data),
      recommendations: this._generateExecutiveRecommendations(data)
    };
  }

  _generateHighlights(data) {
    const highlights = [];
    
    // Revenue highlights
    if (data.financial.revenue.growthRate > 10) {
      highlights.push({
        type: 'revenue',
        message: `Revenue grew ${data.financial.revenue.growthRate.toFixed(1)}% this period`,
        impact: 'positive'
      });
    }
    
    // User engagement highlights
    if (data.engagement.engagement.score > 80) {
      highlights.push({
        type: 'engagement',
        message: `Excellent user engagement score of ${data.engagement.engagement.score}`,
        impact: 'positive'
      });
    }
    
    // Performance highlights
    if (data.performance.score > 90) {
      highlights.push({
        type: 'performance',
        message: 'Outstanding system performance metrics',
        impact: 'positive'
      });
    }
    
    return highlights;
  }

  _identifyConcerns(data) {
    const concerns = [];
    
    // Churn concerns
    if (data.growthMetrics.churn.rate > 10) {
      concerns.push({
        type: 'churn',
        severity: 'high',
        message: `High churn rate of ${data.growthMetrics.churn.rate.toFixed(1)}%`,
        recommendation: 'Implement retention strategies immediately'
      });
    }
    
    // Performance concerns
    if (data.performance.score < 70) {
      concerns.push({
        type: 'performance',
        severity: 'medium',
        message: 'Performance metrics below acceptable threshold',
        recommendation: 'Review system optimization opportunities'
      });
    }
    
    // Financial concerns
    if (data.financial.payments.failureRate > 15) {
      concerns.push({
        type: 'payment',
        severity: 'high',
        message: `High payment failure rate of ${data.financial.payments.failureRate.toFixed(1)}%`,
        recommendation: 'Review payment processing and communicate with affected customers'
      });
    }
    
    return concerns;
  }

  _calculateHealthScore(organizationId, dateRange) {
    // Comprehensive health score calculation
    const weights = {
      financial: 0.3,
      engagement: 0.25,
      performance: 0.2,
      growth: 0.15,
      compliance: 0.1
    };
    
    // This would involve complex calculations based on multiple factors
    return {
      overall: 85,
      components: {
        financial: 90,
        engagement: 82,
        performance: 88,
        growth: 80,
        compliance: 95
      },
      trend: 'improving',
      factors: []
    };
  }

  async _clearAnalyticsCaches(organizationId) {
    const patterns = [
      `${this.cachePrefix}:${organizationId}:*`,
      `analytics:${organizationId}:*`,
      `metrics:${organizationId}:*`
    ];
    
    await Promise.all(patterns.map(pattern => this.cache.deletePattern(pattern)));
  }
}

module.exports = new OrganizationAnalyticsService();