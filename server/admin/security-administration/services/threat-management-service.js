// server/admin/security-administration/services/threat-management-service.js
/**
 * @file Admin Threat Management Service
 * @description Comprehensive threat detection and management service for administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const moment = require('moment');
const geoip = require('geoip-lite');

// Core Models
const ThreatDetection = require('../../../shared/security/models/threat-detection-model');
const ThreatIndicator = require('../../../shared/security/models/threat-indicator-model');
const ThreatIntelligence = require('../../../shared/security/models/threat-intelligence-model');
const ThreatEvent = require('../../../shared/security/models/threat-event-model');
const ThreatResponse = require('../../../shared/security/models/threat-response-model');
const SecurityIncident = require('../../../shared/security/models/security-incident-model');
const BlockedIP = require('../../../shared/security/models/blocked-ip-model');
const ThreatPattern = require('../../../shared/security/models/threat-pattern-model');
const ThreatActor = require('../../../shared/security/models/threat-actor-model');
const User = require('../../../shared/users/models/user-model');
const Organization = require('../../../shared/organizations/models/organization-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const SecurityService = require('./security-service');
const AuditService = require('./audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const AIService = require('../../../shared/services/ai-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const AdminSecurityConfig = require('../../../shared/admin/config/admin-security-config');

// Configuration
const config = require('../../../config');

/**
 * Admin Threat Management Service Class
 * @class ThreatManagementService
 * @extends AdminBaseService
 */
class ThreatManagementService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'AdminThreatManagementService';
    this.cachePrefix = 'admin-threat';
    this.auditCategory = 'THREAT_MANAGEMENT';
    this.requiredPermission = AdminPermissions.THREAT.VIEW;
  }

  /**
   * Get threat overview and current status
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Threat overview
   */
  static async getThreatOverview(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.VIEW);

      const {
        timeRange = '24h',
        includeIntelligence = true,
        includePatterns = true,
        includeActors = true,
        organizationId
      } = options;

      // Get cached overview if available
      const cacheKey = `${this.cachePrefix}:overview:${organizationId || 'global'}:${timeRange}`;
      const cached = await CacheService.get(cacheKey);
      if (cached) return cached;

      const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));

      // Gather threat data in parallel
      const [
        activeThreatCount,
        threatEvents,
        blockedIPs,
        threatLevel,
        topThreats,
        threatIntelligence,
        detectedPatterns,
        knownActors,
        recentIncidents
      ] = await Promise.all([
        this.getActiveThreatCount(startDate, organizationId),
        this.getThreatEventsSummary(startDate, organizationId),
        this.getBlockedIPsSummary(startDate),
        this.calculateCurrentThreatLevel(organizationId),
        this.getTopThreats(startDate, organizationId, 10),
        includeIntelligence ? this.getLatestThreatIntelligence() : null,
        includePatterns ? this.getDetectedPatterns(startDate, organizationId) : null,
        includeActors ? this.getKnownThreatActors(organizationId) : null,
        this.getRecentSecurityIncidents(startDate, organizationId, 5)
      ]);

      // Build overview
      const overview = {
        summary: {
          threatLevel: threatLevel.level,
          threatScore: threatLevel.score,
          activeThreats: activeThreatCount,
          blockedIPs: blockedIPs.total,
          incidents: recentIncidents.length,
          lastUpdated: new Date()
        },
        metrics: {
          events: threatEvents,
          topThreats,
          timeRange
        },
        intelligence: threatIntelligence,
        patterns: detectedPatterns,
        actors: knownActors,
        incidents: recentIncidents,
        recommendations: await this.generateThreatRecommendations({
          threatLevel,
          patterns: detectedPatterns,
          actors: knownActors
        })
      };

      // Cache overview
      await CacheService.set(cacheKey, overview, 60); // 1 minute cache

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.OVERVIEW_VIEWED, {
        organizationId,
        threatLevel: threatLevel.level,
        activeThreats: activeThreatCount
      });

      return overview;

    } catch (error) {
      logger.error('Get threat overview error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Manage threat detection rules
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} ruleData - Rule data
   * @returns {Promise<Object>} Rule management result
   */
  static async manageThreatRule(adminUser, ruleData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.MANAGE_RULES);

      const {
        action,
        ruleId,
        name,
        description,
        type,
        severity,
        conditions,
        actions,
        enabled = true,
        priority = 50,
        tags = []
      } = ruleData;

      let rule;
      let result = {};

      switch (action) {
        case 'create':
          // Validate rule structure
          const validationResult = await this.validateThreatRule({
            name,
            type,
            conditions,
            actions
          });

          if (!validationResult.valid) {
            throw new ValidationError(`Invalid rule: ${validationResult.error}`);
          }

          rule = await ThreatDetection.create([{
            name,
            description,
            type,
            severity,
            conditions,
            actions,
            enabled,
            priority,
            tags,
            createdBy: adminUser.id,
            statistics: {
              triggered: 0,
              blocked: 0,
              falsePositives: 0,
              lastTriggered: null
            }
          }], { session });
          rule = rule[0];

          // Deploy rule to detection engine
          await this.deployRule(rule, session);
          break;

        case 'update':
          rule = await ThreatDetection.findById(ruleId).session(session);
          if (!rule) {
            throw new NotFoundError('Threat rule not found');
          }

          // Update rule fields
          rule.name = name || rule.name;
          rule.description = description || rule.description;
          rule.severity = severity || rule.severity;
          rule.conditions = conditions || rule.conditions;
          rule.actions = actions || rule.actions;
          rule.enabled = enabled !== undefined ? enabled : rule.enabled;
          rule.priority = priority || rule.priority;
          rule.tags = tags || rule.tags;
          rule.updatedBy = adminUser.id;
          rule.updatedAt = new Date();

          await rule.save({ session });

          // Redeploy updated rule
          await this.redeployRule(rule, session);
          break;

        case 'disable':
          rule = await ThreatDetection.findByIdAndUpdate(
            ruleId,
            {
              $set: {
                enabled: false,
                disabledBy: adminUser.id,
                disabledAt: new Date()
              }
            },
            { new: true, session }
          );

          // Remove from active detection
          await this.undeployRule(rule, session);
          break;

        case 'enable':
          rule = await ThreatDetection.findByIdAndUpdate(
            ruleId,
            {
              $set: {
                enabled: true,
                enabledBy: adminUser.id,
                enabledAt: new Date()
              },
              $unset: { disabledAt: 1 }
            },
            { new: true, session }
          );

          // Add back to active detection
          await this.deployRule(rule, session);
          break;

        case 'test':
          rule = await ThreatDetection.findById(ruleId).session(session);
          if (!rule) {
            throw new NotFoundError('Threat rule not found');
          }

          result.testResult = await this.testThreatRule(rule, ruleData.testData);
          break;

        case 'delete':
          rule = await ThreatDetection.findById(ruleId).session(session);
          if (!rule) {
            throw new NotFoundError('Threat rule not found');
          }

          // Soft delete
          rule.deleted = true;
          rule.deletedBy = adminUser.id;
          rule.deletedAt = new Date();
          rule.enabled = false;
          await rule.save({ session });

          // Remove from detection engine
          await this.undeployRule(rule, session);
          break;
      }

      // Clear threat cache
      await this.clearThreatCache();

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.RULE_MANAGED, {
        action,
        ruleId: rule._id,
        ruleName: rule.name,
        ruleType: rule.type,
        severity: rule.severity
      }, { session });

      await session.commitTransaction();

      return {
        rule,
        action,
        result,
        message: `Threat rule ${action}d successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage threat rule error', {
        error: error.message,
        adminId: adminUser.id,
        ruleData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Investigate threat event
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} eventId - Threat event ID
   * @param {Object} options - Investigation options
   * @returns {Promise<Object>} Investigation result
   */
  static async investigateThreatEvent(adminUser, eventId, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.INVESTIGATE);

      const { deep = false, includeContext = true } = options;

      // Get threat event
      const threatEvent = await ThreatEvent.findById(eventId)
        .populate('detectedBy', 'name type')
        .populate('affectedUser', 'email profile.firstName profile.lastName')
        .populate('organizationId', 'name')
        .lean();

      if (!threatEvent) {
        throw new NotFoundError('Threat event not found');
      }

      // Start investigation
      const investigation = {
        event: threatEvent,
        context: {},
        analysis: {},
        relatedEvents: [],
        indicators: [],
        recommendations: []
      };

      // Get context if requested
      if (includeContext) {
        investigation.context = await this.getThreatContext(threatEvent);
      }

      // Perform analysis
      investigation.analysis = await this.analyzeThreatEvent(threatEvent, deep);

      // Find related events
      investigation.relatedEvents = await this.findRelatedThreatEvents(threatEvent);

      // Extract indicators
      investigation.indicators = await this.extractThreatIndicators(threatEvent);

      // Check against threat intelligence
      investigation.intelligenceMatches = await this.checkThreatIntelligence(
        investigation.indicators
      );

      // Generate recommendations
      investigation.recommendations = await this.generateInvestigationRecommendations(
        investigation
      );

      // Create investigation record
      const investigationRecord = await this.createInvestigationRecord(
        adminUser,
        threatEvent,
        investigation
      );

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.EVENT_INVESTIGATED, {
        eventId,
        threatType: threatEvent.type,
        severity: threatEvent.severity,
        investigationId: investigationRecord._id
      });

      return {
        investigation,
        investigationId: investigationRecord._id,
        summary: {
          riskLevel: investigation.analysis.riskScore,
          isOngoing: investigation.analysis.isOngoing,
          affectedSystems: investigation.analysis.affectedSystems?.length || 0,
          recommendedActions: investigation.recommendations.length
        }
      };

    } catch (error) {
      logger.error('Investigate threat event error', {
        error: error.message,
        adminId: adminUser.id,
        eventId,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Respond to threat
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} responseData - Response data
   * @returns {Promise<Object>} Response result
   */
  static async respondToThreat(adminUser, responseData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.RESPOND);

      const {
        threatId,
        threatType,
        responseType,
        actions = [],
        automate = false,
        notifyAffected = true,
        escalate = false,
        notes
      } = responseData;

      // Validate response type
      const validResponseTypes = ['block', 'quarantine', 'monitor', 'mitigate', 'custom'];
      if (!validResponseTypes.includes(responseType)) {
        throw new ValidationError('Invalid response type');
      }

      // Create response record
      const response = await ThreatResponse.create([{
        threatId,
        threatType,
        responseType,
        actions,
        automated: automate,
        initiatedBy: adminUser.id,
        status: 'in_progress',
        startTime: new Date()
      }], { session });

      const createdResponse = response[0];
      const actionResults = [];

      // Execute response actions
      for (const action of actions) {
        try {
          const result = await this.executeThreatResponseAction(
            action,
            threatId,
            adminUser,
            session
          );
          actionResults.push({
            action: action.type,
            success: true,
            result
          });
        } catch (error) {
          actionResults.push({
            action: action.type,
            success: false,
            error: error.message
          });
          
          // Continue with other actions unless critical
          if (action.critical) {
            throw error;
          }
        }
      }

      // Update response with results
      createdResponse.actionResults = actionResults;
      createdResponse.status = actionResults.every(r => r.success) ? 'completed' : 'partial';
      createdResponse.endTime = new Date();
      await createdResponse.save({ session });

      // Handle escalation if needed
      if (escalate) {
        await this.escalateThreat(threatId, adminUser.id, notes, session);
      }

      // Send notifications if requested
      if (notifyAffected) {
        await this.notifyAffectedParties(threatId, createdResponse, session);
      }

      // Update threat status
      await this.updateThreatStatus(threatId, 'responded', session);

      // Clear relevant caches
      await this.clearThreatCache();

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.RESPONSE_INITIATED, {
        threatId,
        responseId: createdResponse._id,
        responseType,
        actionsCount: actions.length,
        automated: automate
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        response: createdResponse,
        results: {
          executed: actionResults.filter(r => r.success).length,
          failed: actionResults.filter(r => !r.success).length,
          details: actionResults
        },
        message: 'Threat response executed successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Respond to threat error', {
        error: error.message,
        adminId: adminUser.id,
        responseData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Manage threat indicators
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} indicatorData - Indicator data
   * @returns {Promise<Object>} Indicator management result
   */
  static async manageThreatIndicator(adminUser, indicatorData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.MANAGE_INDICATORS);

      const {
        action,
        indicatorId,
        type,
        value,
        severity = 'medium',
        confidence = 50,
        source,
        description,
        tags = [],
        expiration
      } = indicatorData;

      let indicator;

      switch (action) {
        case 'add':
          // Check if indicator already exists
          const existing = await ThreatIndicator.findOne({
            type,
            value,
            active: true
          }).session(session);

          if (existing) {
            throw new ValidationError('Indicator already exists');
          }

          indicator = await ThreatIndicator.create([{
            type,
            value,
            severity,
            confidence,
            source: source || 'manual',
            description,
            tags,
            expiration: expiration ? new Date(expiration) : null,
            addedBy: adminUser.id,
            active: true,
            statistics: {
              hits: 0,
              lastSeen: null,
              falsePositives: 0
            }
          }], { session });
          indicator = indicator[0];

          // Add to active monitoring
          await this.addIndicatorToMonitoring(indicator, session);
          break;

        case 'update':
          indicator = await ThreatIndicator.findById(indicatorId).session(session);
          if (!indicator) {
            throw new NotFoundError('Threat indicator not found');
          }

          indicator.severity = severity || indicator.severity;
          indicator.confidence = confidence || indicator.confidence;
          indicator.description = description || indicator.description;
          indicator.tags = tags || indicator.tags;
          indicator.expiration = expiration ? new Date(expiration) : indicator.expiration;
          indicator.updatedBy = adminUser.id;
          indicator.updatedAt = new Date();

          await indicator.save({ session });

          // Update monitoring
          await this.updateIndicatorMonitoring(indicator, session);
          break;

        case 'remove':
          indicator = await ThreatIndicator.findById(indicatorId).session(session);
          if (!indicator) {
            throw new NotFoundError('Threat indicator not found');
          }

          indicator.active = false;
          indicator.removedBy = adminUser.id;
          indicator.removedAt = new Date();
          indicator.removalReason = indicatorData.reason;

          await indicator.save({ session });

          // Remove from monitoring
          await this.removeIndicatorFromMonitoring(indicator, session);
          break;

        case 'verify':
          indicator = await ThreatIndicator.findById(indicatorId).session(session);
          if (!indicator) {
            throw new NotFoundError('Threat indicator not found');
          }

          indicator.verified = true;
          indicator.verifiedBy = adminUser.id;
          indicator.verifiedAt = new Date();
          indicator.confidence = Math.min(indicator.confidence + 20, 100);

          await indicator.save({ session });
          break;
      }

      // Clear indicator cache
      await CacheService.delete(`${this.cachePrefix}:indicators`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.INDICATOR_MANAGED, {
        action,
        indicatorId: indicator._id,
        indicatorType: indicator.type,
        severity: indicator.severity
      }, { session });

      await session.commitTransaction();

      return {
        indicator,
        action,
        message: `Threat indicator ${action}ed successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage threat indicator error', {
        error: error.message,
        adminId: adminUser.id,
        indicatorData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Manage IP blocking
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} blockData - IP block data
   * @returns {Promise<Object>} Block management result
   */
  static async manageIPBlock(adminUser, blockData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.BLOCK_IPS);

      const {
        action,
        ip,
        ips = [],
        reason,
        duration,
        permanent = false,
        scope = 'global'
      } = blockData;

      const targetIPs = ip ? [ip] : ips;
      const results = {
        blocked: [],
        unblocked: [],
        failed: []
      };

      switch (action) {
        case 'block':
          for (const targetIP of targetIPs) {
            try {
              // Validate IP format
              if (!AdminHelpers.isValidIP(targetIP)) {
                results.failed.push({ ip: targetIP, reason: 'Invalid IP format' });
                continue;
              }

              // Check if already blocked
              const existingBlock = await BlockedIP.findOne({
                ip: targetIP,
                active: true
              }).session(session);

              if (existingBlock) {
                results.failed.push({ ip: targetIP, reason: 'Already blocked' });
                continue;
              }

              // Get GeoIP info
              const geoInfo = geoip.lookup(targetIP);

              // Create block record
              const block = await BlockedIP.create([{
                ip: targetIP,
                reason,
                permanent,
                duration: permanent ? null : (duration || 24 * 60 * 60 * 1000), // Default 24 hours
                expiresAt: permanent ? null : new Date(Date.now() + (duration || 24 * 60 * 60 * 1000)),
                scope,
                geoInfo: geoInfo ? {
                  country: geoInfo.country,
                  region: geoInfo.region,
                  city: geoInfo.city,
                  timezone: geoInfo.timezone
                } : null,
                blockedBy: adminUser.id,
                active: true
              }], { session });

              results.blocked.push(targetIP);

              // Apply block immediately
              await this.applyIPBlock(targetIP, block[0], session);
            } catch (error) {
              results.failed.push({ ip: targetIP, reason: error.message });
            }
          }
          break;

        case 'unblock':
          for (const targetIP of targetIPs) {
            try {
              const block = await BlockedIP.findOneAndUpdate(
                { ip: targetIP, active: true },
                {
                  $set: {
                    active: false,
                    unblockedBy: adminUser.id,
                    unblockedAt: new Date(),
                    unblockReason: reason
                  }
                },
                { session }
              );

              if (!block) {
                results.failed.push({ ip: targetIP, reason: 'Not found in blocklist' });
                continue;
              }

              results.unblocked.push(targetIP);

              // Remove block immediately
              await this.removeIPBlock(targetIP, session);
            } catch (error) {
              results.failed.push({ ip: targetIP, reason: error.message });
            }
          }
          break;
      }

      // Clear IP block cache
      await CacheService.delete(`${this.cachePrefix}:blocked-ips`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.IP_BLOCK_MANAGED, {
        action,
        ipsCount: targetIPs.length,
        blocked: results.blocked.length,
        unblocked: results.unblocked.length,
        failed: results.failed.length,
        permanent
      }, { session });

      await session.commitTransaction();

      return {
        action,
        results,
        summary: {
          total: targetIPs.length,
          successful: action === 'block' ? results.blocked.length : results.unblocked.length,
          failed: results.failed.length
        },
        message: `IP ${action} operation completed`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage IP block error', {
        error: error.message,
        adminId: adminUser.id,
        blockData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Analyze threat patterns
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} analysisOptions - Analysis options
   * @returns {Promise<Object>} Pattern analysis
   */
  static async analyzeThreatPatterns(adminUser, analysisOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.ANALYZE);

      const {
        timeRange = '7d',
        minOccurrences = 3,
        includeML = true,
        organizationId
      } = analysisOptions;

      const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));

      // Get threat events for analysis
      const query = {
        timestamp: { $gte: startDate }
      };
      if (organizationId) {
        query.organizationId = organizationId;
      }

      const threatEvents = await ThreatEvent.find(query)
        .select('type source target metadata timestamp severity')
        .lean();

      if (threatEvents.length === 0) {
        return {
          patterns: [],
          message: 'No threat events found for analysis'
        };
      }

      // Analyze patterns
      const patterns = await this.identifyPatterns(threatEvents, minOccurrences);

      // Apply ML analysis if requested
      let mlPatterns = null;
      if (includeML && AIService) {
        mlPatterns = await this.applyMLPatternAnalysis(threatEvents);
      }

      // Store significant patterns
      const significantPatterns = patterns.filter(p => p.confidence > 70);
      for (const pattern of significantPatterns) {
        await this.storeDetectedPattern(pattern, adminUser.id);
      }

      // Generate pattern insights
      const insights = await this.generatePatternInsights(patterns, mlPatterns);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.PATTERNS_ANALYZED, {
        timeRange,
        eventsAnalyzed: threatEvents.length,
        patternsFound: patterns.length,
        significantPatterns: significantPatterns.length
      });

      return {
        analysis: {
          timeRange,
          eventsAnalyzed: threatEvents.length,
          startDate,
          endDate: new Date()
        },
        patterns: patterns.map(p => ({
          ...p,
          risk: this.calculatePatternRisk(p)
        })),
        mlPatterns,
        insights,
        recommendations: await this.generatePatternRecommendations(patterns)
      };

    } catch (error) {
      logger.error('Analyze threat patterns error', {
        error: error.message,
        adminId: adminUser.id,
        analysisOptions,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get threat intelligence feed
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Feed options
   * @returns {Promise<Object>} Threat intelligence
   */
  static async getThreatIntelligence(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.VIEW_INTELLIGENCE);

      const {
        sources = ['all'],
        severity = null,
        limit = 50,
        includeIOCs = true
      } = options;

      // Get latest threat intelligence
      const query = {
        active: true,
        $or: [
          { expiration: null },
          { expiration: { $gt: new Date() } }
        ]
      };

      if (sources[0] !== 'all') {
        query.source = { $in: sources };
      }
      if (severity) {
        query.severity = severity;
      }

      const intelligence = await ThreatIntelligence.find(query)
        .sort({ publishedAt: -1 })
        .limit(limit)
        .populate('submittedBy', 'email')
        .lean();

      // Include IOCs if requested
      let iocs = null;
      if (includeIOCs) {
        iocs = await this.extractIOCsFromIntelligence(intelligence);
      }

      // Check correlation with internal data
      const correlations = await this.correlateWithInternalData(intelligence);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.INTELLIGENCE_ACCESSED, {
        sources,
        recordsAccessed: intelligence.length,
        includeIOCs
      });

      return {
        intelligence: intelligence.map(intel => ({
          ...intel,
          relevance: this.calculateIntelRelevance(intel, correlations[intel._id])
        })),
        iocs,
        correlations,
        sources: await this.getAvailableIntelSources(),
        lastUpdated: intelligence[0]?.publishedAt || new Date()
      };

    } catch (error) {
      logger.error('Get threat intelligence error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Generate threat report
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} reportOptions - Report options
   * @returns {Promise<Object>} Threat report
   */
  static async generateThreatReport(adminUser, reportOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.GENERATE_REPORTS);

      const {
        reportType = 'comprehensive',
        timeRange = '30d',
        format = 'detailed',
        organizationId,
        includePredictions = true
      } = reportOptions;

      const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));
      const endDate = new Date();

      // Gather report data based on type
      let reportData;
      switch (reportType) {
        case 'comprehensive':
          reportData = await this.gatherComprehensiveThreatData(
            startDate,
            endDate,
            organizationId
          );
          break;
        case 'executive':
          reportData = await this.gatherExecutiveThreatData(
            startDate,
            endDate,
            organizationId
          );
          break;
        case 'technical':
          reportData = await this.gatherTechnicalThreatData(
            startDate,
            endDate,
            organizationId
          );
          break;
        case 'incident':
          reportData = await this.gatherIncidentReportData(
            startDate,
            endDate,
            organizationId
          );
          break;
        default:
          throw new ValidationError('Invalid report type');
      }

      // Add predictions if requested
      if (includePredictions) {
        reportData.predictions = await this.generateThreatPredictions(reportData);
      }

      // Create report
      const report = {
        id: crypto.randomUUID(),
        type: reportType,
        generatedAt: new Date(),
        generatedBy: adminUser.id,
        timeRange: { start: startDate, end: endDate },
        organizationId,
        data: reportData,
        format
      };

      // Format report based on requested format
      const formattedReport = await this.formatThreatReport(report, format);

      // Store report
      await this.storeThreatReport(report);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.REPORT_GENERATED, {
        reportId: report.id,
        reportType,
        timeRange,
        organizationId
      });

      return formattedReport;

    } catch (error) {
      logger.error('Generate threat report error', {
        error: error.message,
        adminId: adminUser.id,
        reportOptions,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Configure automated threat response
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} automationData - Automation configuration
   * @returns {Promise<Object>} Configuration result
   */
  static async configureAutomatedResponse(adminUser, automationData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.THREAT.CONFIGURE_AUTOMATION);

      const {
        threatType,
        conditions,
        actions,
        enabled = true,
        requireApproval = false,
        notificationChannels = [],
        cooldownMinutes = 5
      } = automationData;

      // Validate automation rules
      const validation = await this.validateAutomationRules({
        conditions,
        actions,
        threatType
      });

      if (!validation.valid) {
        throw new ValidationError(`Invalid automation rules: ${validation.errors.join(', ')}`);
      }

      // Check for existing automation
      let automation = await ThreatDetection.findOne({
        type: 'automated_response',
        'metadata.threatType': threatType
      }).session(session);

      if (automation) {
        // Update existing
        automation.conditions = conditions;
        automation.actions = actions;
        automation.enabled = enabled;
        automation.metadata = {
          ...automation.metadata,
          requireApproval,
          notificationChannels,
          cooldownMinutes
        };
        automation.updatedBy = adminUser.id;
        automation.updatedAt = new Date();
      } else {
        // Create new
        automation = await ThreatDetection.create([{
          name: `Automated Response: ${threatType}`,
          type: 'automated_response',
          conditions,
          actions,
          enabled,
          priority: 100, // High priority for automated responses
          metadata: {
            threatType,
            requireApproval,
            notificationChannels,
            cooldownMinutes
          },
          createdBy: adminUser.id
        }], { session });
        automation = automation[0];
      }

      await automation.save({ session });

      // Deploy automation
      if (enabled) {
        await this.deployAutomation(automation, session);
      }

      // Clear automation cache
      await CacheService.delete(`${this.cachePrefix}:automations`);

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.THREAT.AUTOMATION_CONFIGURED, {
        automationId: automation._id,
        threatType,
        enabled,
        requireApproval
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        automation,
        message: 'Automated threat response configured successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Configure automated response error', {
        error: error.message,
        adminId: adminUser.id,
        automationData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  // ========== Private Helper Methods ==========

  /**
   * Get active threat count
   * @param {Date} startDate - Start date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<number>} Active threat count
   * @private
   */
  static async getActiveThreatCount(startDate, organizationId) {
    const query = {
      timestamp: { $gte: startDate },
      status: { $in: ['active', 'investigating', 'mitigating'] }
    };
    if (organizationId) {
      query.organizationId = organizationId;
    }
    return ThreatEvent.countDocuments(query);
  }

  /**
   * Get threat events summary
   * @param {Date} startDate - Start date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Events summary
   * @private
   */
  static async getThreatEventsSummary(startDate, organizationId) {
    const query = {
      timestamp: { $gte: startDate }
    };
    if (organizationId) {
      query.organizationId = organizationId;
    }

    const events = await ThreatEvent.aggregate([
      { $match: query },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 },
          critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
          high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } }
        }
      },
      { $sort: { count: -1 } }
    ]);

    const summary = {
      total: 0,
      byType: {},
      critical: 0,
      high: 0
    };

    events.forEach(event => {
      summary.total += event.count;
      summary.critical += event.critical;
      summary.high += event.high;
      summary.byType[event._id] = event.count;
    });

    return summary;
  }

  /**
   * Get blocked IPs summary
   * @param {Date} startDate - Start date
   * @returns {Promise<Object>} Blocked IPs summary
   * @private
   */
  static async getBlockedIPsSummary(startDate) {
    const [total, recent, permanent] = await Promise.all([
      BlockedIP.countDocuments({ active: true }),
      BlockedIP.countDocuments({ 
        active: true,
        blockedAt: { $gte: startDate }
      }),
      BlockedIP.countDocuments({ 
        active: true,
        permanent: true
      })
    ]);

    return { total, recent, permanent };
  }

  /**
   * Calculate current threat level
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Threat level
   * @private
   */
  static async calculateCurrentThreatLevel(organizationId) {
    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const last1h = new Date(Date.now() - 60 * 60 * 1000);

    const query = organizationId ? { organizationId } : {};

    const [
      recentCritical,
      recentHigh,
      activeIncidents,
      threatVelocity
    ] = await Promise.all([
      ThreatEvent.countDocuments({
        ...query,
        severity: 'critical',
        timestamp: { $gte: last24h }
      }),
      ThreatEvent.countDocuments({
        ...query,
        severity: 'high',
        timestamp: { $gte: last24h }
      }),
      SecurityIncident.countDocuments({
        ...query,
        status: { $in: ['open', 'investigating'] }
      }),
      this.calculateThreatVelocity(last1h, organizationId)
    ]);

    // Calculate threat score (0-100)
    let score = 0;
    score += recentCritical * 20;
    score += recentHigh * 10;
    score += activeIncidents * 15;
    score += threatVelocity.increase ? threatVelocity.percentage : 0;

    score = Math.min(score, 100);

    // Determine threat level
    let level;
    if (score >= 80) level = 'critical';
    else if (score >= 60) level = 'high';
    else if (score >= 40) level = 'medium';
    else if (score >= 20) level = 'low';
    else level = 'minimal';

    return {
      level,
      score,
      factors: {
        criticalEvents: recentCritical,
        highEvents: recentHigh,
        activeIncidents,
        velocity: threatVelocity
      }
    };
  }

  /**
   * Calculate threat velocity
   * @param {Date} startDate - Start date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Threat velocity
   * @private
   */
  static async calculateThreatVelocity(startDate, organizationId) {
    const query = organizationId ? { organizationId } : {};
    
    const currentPeriod = await ThreatEvent.countDocuments({
      ...query,
      timestamp: { $gte: startDate }
    });

    const previousPeriod = await ThreatEvent.countDocuments({
      ...query,
      timestamp: {
        $gte: new Date(startDate.getTime() - (Date.now() - startDate.getTime())),
        $lt: startDate
      }
    });

    const change = currentPeriod - previousPeriod;
    const percentage = previousPeriod > 0 
      ? Math.round((change / previousPeriod) * 100)
      : currentPeriod > 0 ? 100 : 0;

    return {
      current: currentPeriod,
      previous: previousPeriod,
      change,
      percentage,
      increase: change > 0,
      trend: change > 0 ? 'increasing' : change < 0 ? 'decreasing' : 'stable'
    };
  }

  /**
   * Get top threats
   * @param {Date} startDate - Start date
   * @param {string} organizationId - Organization ID
   * @param {number} limit - Result limit
   * @returns {Promise<Array>} Top threats
   * @private
   */
  static async getTopThreats(startDate, organizationId, limit = 10) {
    const query = {
      timestamp: { $gte: startDate }
    };
    if (organizationId) {
      query.organizationId = organizationId;
    }

    return ThreatEvent.aggregate([
      { $match: query },
      {
        $group: {
          _id: {
            type: '$type',
            source: '$source'
          },
          count: { $sum: 1 },
          lastSeen: { $max: '$timestamp' },
          severity: { $first: '$severity' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: limit },
      {
        $project: {
          _id: 0,
          type: '$_id.type',
          source: '$_id.source',
          count: 1,
          lastSeen: 1,
          severity: 1
        }
      }
    ]);
  }

  /**
   * Get latest threat intelligence
   * @returns {Promise<Array>} Latest intelligence
   * @private
   */
  static async getLatestThreatIntelligence() {
    return ThreatIntelligence.find({
      active: true,
      $or: [
        { expiration: null },
        { expiration: { $gt: new Date() } }
      ]
    })
      .sort({ publishedAt: -1 })
      .limit(10)
      .select('title severity source publishedAt tags')
      .lean();
  }

  /**
   * Get detected patterns
   * @param {Date} startDate - Start date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Array>} Detected patterns
   * @private
   */
  static async getDetectedPatterns(startDate, organizationId) {
    const query = {
      detectedAt: { $gte: startDate },
      active: true
    };
    if (organizationId) {
      query.organizationId = organizationId;
    }

    return ThreatPattern.find(query)
      .sort({ confidence: -1, occurrences: -1 })
      .limit(20)
      .lean();
  }

  /**
   * Get known threat actors
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Array>} Known actors
   * @private
   */
  static async getKnownThreatActors(organizationId) {
    const query = {
      active: true,
      $or: [
        { scope: 'global' },
        { targetedOrganizations: organizationId }
      ]
    };

    return ThreatActor.find(query)
      .sort({ threatLevel: -1, lastActivity: -1 })
      .limit(10)
      .select('name alias threatLevel capabilities lastActivity')
      .lean();
  }

  /**
   * Get recent security incidents
   * @param {Date} startDate - Start date
   * @param {string} organizationId - Organization ID
   * @param {number} limit - Result limit
   * @returns {Promise<Array>} Recent incidents
   * @private
   */
  static async getRecentSecurityIncidents(startDate, organizationId, limit = 5) {
    const query = {
      createdAt: { $gte: startDate }
    };
    if (organizationId) {
      query.organizationId = organizationId;
    }

    return SecurityIncident.find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('reportedBy', 'email')
      .select('type severity status createdAt affectedResources')
      .lean();
  }

  /**
   * Generate threat recommendations
   * @param {Object} data - Threat data
   * @returns {Promise<Array>} Recommendations
   * @private
   */
  static async generateThreatRecommendations(data) {
    const recommendations = [];

    // Based on threat level
    if (data.threatLevel.level === 'critical' || data.threatLevel.level === 'high') {
      recommendations.push({
        priority: 'urgent',
        title: 'Immediate Security Review Required',
        description: 'Critical threat level detected. Conduct immediate security review.',
        actions: [
          'Review all active threats',
          'Check security configurations',
          'Enable additional monitoring'
        ]
      });
    }

    // Based on patterns
    if (data.patterns && data.patterns.length > 0) {
      const persistentPatterns = data.patterns.filter(p => p.persistence > 0.7);
      if (persistentPatterns.length > 0) {
        recommendations.push({
          priority: 'high',
          title: 'Persistent Attack Patterns Detected',
          description: 'Multiple persistent attack patterns identified.',
          actions: [
            'Implement pattern-specific countermeasures',
            'Update security rules',
            'Consider threat hunting operations'
          ]
        });
      }
    }

    // Based on actors
    if (data.actors && data.actors.some(a => a.threatLevel === 'critical')) {
      recommendations.push({
        priority: 'high',
        title: 'High-Risk Threat Actors Active',
        description: 'Known high-risk threat actors detected.',
        actions: [
          'Review actor TTPs (Tactics, Techniques, Procedures)',
          'Implement actor-specific defenses',
          'Increase monitoring for associated indicators'
        ]
      });
    }

    return recommendations;
  }

  /**
   * Validate threat rule
   * @param {Object} rule - Rule to validate
   * @returns {Promise<Object>} Validation result
   * @private
   */
  static async validateThreatRule(rule) {
    const errors = [];

    // Validate required fields
    if (!rule.name || rule.name.trim().length < 3) {
      errors.push('Rule name must be at least 3 characters');
    }

    if (!rule.type) {
      errors.push('Rule type is required');
    }

    if (!rule.conditions || Object.keys(rule.conditions).length === 0) {
      errors.push('At least one condition is required');
    }

    if (!rule.actions || rule.actions.length === 0) {
      errors.push('At least one action is required');
    }

    // Validate conditions structure
    if (rule.conditions) {
      const validConditionTypes = ['match', 'threshold', 'frequency', 'pattern', 'composite'];
      for (const [key, condition] of Object.entries(rule.conditions)) {
        if (!validConditionTypes.includes(condition.type)) {
          errors.push(`Invalid condition type: ${condition.type}`);
        }
      }
    }

    // Validate actions structure
    if (rule.actions) {
      const validActionTypes = ['alert', 'block', 'quarantine', 'log', 'escalate', 'custom'];
      for (const action of rule.actions) {
        if (!validActionTypes.includes(action.type)) {
          errors.push(`Invalid action type: ${action.type}`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      error: errors.join(', ')
    };
  }

  /**
   * Deploy threat rule
   * @param {Object} rule - Rule to deploy
   * @param {Object} session - Database session
   * @private
   */
  static async deployRule(rule, session) {
    // Add rule to detection engine
    logger.info('Deploying threat rule', {
      ruleId: rule._id,
      ruleName: rule.name,
      ruleType: rule.type
    });

    // Implementation depends on detection engine
    // This is a placeholder for actual deployment logic
    return true;
  }

  /**
   * Redeploy threat rule
   * @param {Object} rule - Rule to redeploy
   * @param {Object} session - Database session
   * @private
   */
  static async redeployRule(rule, session) {
    await this.undeployRule(rule, session);
    await this.deployRule(rule, session);
  }

  /**
   * Undeploy threat rule
   * @param {Object} rule - Rule to undeploy
   * @param {Object} session - Database session
   * @private
   */
  static async undeployRule(rule, session) {
    // Remove rule from detection engine
    logger.info('Undeploying threat rule', {
      ruleId: rule._id,
      ruleName: rule.name
    });

    // Implementation depends on detection engine
    return true;
  }

  /**
   * Test threat rule
   * @param {Object} rule - Rule to test
   * @param {Object} testData - Test data
   * @returns {Promise<Object>} Test result
   * @private
   */
  static async testThreatRule(rule, testData) {
    const result = {
      passed: false,
      conditionResults: {},
      actionResults: [],
      errors: []
    };

    try {
      // Test conditions
      for (const [key, condition] of Object.entries(rule.conditions)) {
        try {
          const conditionResult = await this.evaluateCondition(condition, testData);
          result.conditionResults[key] = conditionResult;
        } catch (error) {
          result.errors.push(`Condition ${key}: ${error.message}`);
        }
      }

      // Check if all conditions passed
      result.passed = Object.values(result.conditionResults).every(r => r.matched);

      // Test actions if conditions passed
      if (result.passed) {
        for (const action of rule.actions) {
          try {
            const actionResult = await this.simulateAction(action, testData);
            result.actionResults.push(actionResult);
          } catch (error) {
            result.errors.push(`Action ${action.type}: ${error.message}`);
          }
        }
      }

    } catch (error) {
      result.errors.push(`Test failed: ${error.message}`);
    }

    return result;
  }

  /**
   * Evaluate condition
   * @param {Object} condition - Condition to evaluate
   * @param {Object} data - Test data
   * @returns {Promise<Object>} Evaluation result
   * @private
   */
  static async evaluateCondition(condition, data) {
    // Implementation depends on condition type
    return {
      matched: true,
      value: null,
      reason: 'Test evaluation'
    };
  }

  /**
   * Simulate action
   * @param {Object} action - Action to simulate
   * @param {Object} data - Test data
   * @returns {Promise<Object>} Simulation result
   * @private
   */
  static async simulateAction(action, data) {
    return {
      action: action.type,
      simulated: true,
      wouldExecute: true,
      impact: 'Test simulation'
    };
  }

  /**
   * Get threat context
   * @param {Object} threatEvent - Threat event
   * @returns {Promise<Object>} Threat context
   * @private
   */
  static async getThreatContext(threatEvent) {
    const context = {
      user: null,
      organization: null,
      previousEvents: [],
      relatedIncidents: [],
      geoLocation: null
    };

    // Get user context
    if (threatEvent.affectedUser) {
      context.user = await User.findById(threatEvent.affectedUser)
        .select('email profile role lastLogin')
        .lean();
    }

    // Get organization context
    if (threatEvent.organizationId) {
      context.organization = await Organization.findById(threatEvent.organizationId)
        .select('name plan security')
        .lean();
    }

    // Get previous events from same source
    context.previousEvents = await ThreatEvent.find({
      source: threatEvent.source,
      _id: { $ne: threatEvent._id }
    })
      .sort({ timestamp: -1 })
      .limit(10)
      .select('type severity timestamp')
      .lean();

    // Get related incidents
    context.relatedIncidents = await SecurityIncident.find({
      $or: [
        { 'metadata.threatEventId': threatEvent._id },
        { affectedResources: { $in: [threatEvent.target] } }
      ]
    })
      .select('type severity status createdAt')
      .lean();

    // Get geo location
    if (threatEvent.source && AdminHelpers.isValidIP(threatEvent.source)) {
      context.geoLocation = geoip.lookup(threatEvent.source);
    }

    return context;
  }

  /**
   * Analyze threat event
   * @param {Object} threatEvent - Threat event
   * @param {boolean} deep - Perform deep analysis
   * @returns {Promise<Object>} Analysis result
   * @private
   */
  static async analyzeThreatEvent(threatEvent, deep = false) {
    const analysis = {
      riskScore: 50,
      isOngoing: false,
      affectedSystems: [],
      attackVector: null,
      ttps: [], // Tactics, Techniques, Procedures
      timeline: []
    };

    // Calculate risk score
    const severityScores = {
      critical: 100,
      high: 75,
      medium: 50,
      low: 25
    };
    analysis.riskScore = severityScores[threatEvent.severity] || 50;

    // Check if ongoing
    const recentEvents = await ThreatEvent.countDocuments({
      source: threatEvent.source,
      timestamp: { $gte: new Date(Date.now() - 60 * 60 * 1000) } // Last hour
    });
    analysis.isOngoing = recentEvents > 1;

    // Identify affected systems
    if (threatEvent.target) {
      analysis.affectedSystems.push(threatEvent.target);
      
      // Find related targets
      const relatedTargets = await ThreatEvent.distinct('target', {
        source: threatEvent.source,
        timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      });
      analysis.affectedSystems.push(...relatedTargets);
    }

    // Determine attack vector
    analysis.attackVector = this.identifyAttackVector(threatEvent);

    // Map to MITRE ATT&CK if deep analysis
    if (deep) {
      analysis.ttps = await this.mapToMITRE(threatEvent);
      analysis.timeline = await this.buildThreatTimeline(threatEvent);
    }

    return analysis;
  }

  /**
   * Find related threat events
   * @param {Object} threatEvent - Threat event
   * @returns {Promise<Array>} Related events
   * @private
   */
  static async findRelatedThreatEvents(threatEvent) {
    const related = [];

    // Same source
    const sameSource = await ThreatEvent.find({
      source: threatEvent.source,
      _id: { $ne: threatEvent._id }
    })
      .sort({ timestamp: -1 })
      .limit(5)
      .select('type severity timestamp target')
      .lean();
    
    related.push(...sameSource.map(e => ({ ...e, relation: 'same_source' })));

    // Same target
    if (threatEvent.target) {
      const sameTarget = await ThreatEvent.find({
        target: threatEvent.target,
        _id: { $ne: threatEvent._id }
      })
        .sort({ timestamp: -1 })
        .limit(5)
        .select('type severity timestamp source')
        .lean();
      
      related.push(...sameTarget.map(e => ({ ...e, relation: 'same_target' })));
    }

    // Similar pattern
    if (threatEvent.metadata?.pattern) {
      const similarPattern = await ThreatEvent.find({
        'metadata.pattern': threatEvent.metadata.pattern,
        _id: { $ne: threatEvent._id }
      })
        .sort({ timestamp: -1 })
        .limit(5)
        .select('type severity timestamp source target')
        .lean();
      
      related.push(...similarPattern.map(e => ({ ...e, relation: 'similar_pattern' })));
    }

    return related;
  }

  /**
   * Extract threat indicators
   * @param {Object} threatEvent - Threat event
   * @returns {Promise<Array>} Extracted indicators
   * @private
   */
  static async extractThreatIndicators(threatEvent) {
    const indicators = [];

    // Extract IP indicators
    if (threatEvent.source && AdminHelpers.isValidIP(threatEvent.source)) {
      indicators.push({
        type: 'ip',
        value: threatEvent.source,
        context: 'threat_source'
      });
    }

    // Extract from metadata
    if (threatEvent.metadata) {
      // URLs
      const urlPattern = /https?:\/\/[^\s]+/g;
      const urls = JSON.stringify(threatEvent.metadata).match(urlPattern);
      if (urls) {
        urls.forEach(url => {
          indicators.push({
            type: 'url',
            value: url,
            context: 'extracted_from_metadata'
          });
        });
      }

      // File hashes
      const hashPattern = /\b[a-fA-F0-9]{32,64}\b/g;
      const hashes = JSON.stringify(threatEvent.metadata).match(hashPattern);
      if (hashes) {
        hashes.forEach(hash => {
          indicators.push({
            type: 'hash',
            value: hash,
            context: 'extracted_from_metadata'
          });
        });
      }

      // Email addresses
      const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
      const emails = JSON.stringify(threatEvent.metadata).match(emailPattern);
      if (emails) {
        emails.forEach(email => {
          indicators.push({
            type: 'email',
            value: email,
            context: 'extracted_from_metadata'
          });
        });
      }
    }

    return indicators;
  }

  /**
   * Check threat intelligence
   * @param {Array} indicators - Threat indicators
   * @returns {Promise<Array>} Intelligence matches
   * @private
   */
  static async checkThreatIntelligence(indicators) {
    const matches = [];

    for (const indicator of indicators) {
      const intelligenceMatches = await ThreatIntelligence.find({
        'indicators.type': indicator.type,
        'indicators.value': indicator.value,
        active: true
      })
        .select('title severity source confidence')
        .lean();

      if (intelligenceMatches.length > 0) {
        matches.push({
          indicator,
          intelligence: intelligenceMatches
        });
      }
    }

    return matches;
  }

  /**
   * Generate investigation recommendations
   * @param {Object} investigation - Investigation data
   * @returns {Promise<Array>} Recommendations
   * @private
   */
  static async generateInvestigationRecommendations(investigation) {
    const recommendations = [];

    // Based on risk score
    if (investigation.analysis.riskScore >= 75) {
      recommendations.push({
        priority: 'high',
        action: 'immediate_containment',
        description: 'High risk threat detected. Immediate containment recommended.',
        steps: [
          'Isolate affected systems',
          'Block threat source',
          'Preserve evidence'
        ]
      });
    }

    // Based on ongoing status
    if (investigation.analysis.isOngoing) {
      recommendations.push({
        priority: 'high',
        action: 'active_monitoring',
        description: 'Threat is ongoing. Enhanced monitoring required.',
        steps: [
          'Enable real-time monitoring',
          'Set up alerts for similar patterns',
          'Prepare incident response team'
        ]
      });
    }

    // Based on intelligence matches
    if (investigation.intelligenceMatches && investigation.intelligenceMatches.length > 0) {
      recommendations.push({
        priority: 'medium',
        action: 'intelligence_correlation',
        description: 'Threat matches known intelligence. Review related threats.',
        steps: [
          'Review intelligence reports',
          'Check for campaign indicators',
          'Update detection rules'
        ]
      });
    }

    return recommendations;
  }

  /**
   * Create investigation record
   * @param {Object} adminUser - Admin user
   * @param {Object} threatEvent - Threat event
   * @param {Object} investigation - Investigation data
   * @returns {Promise<Object>} Investigation record
   * @private
   */
  static async createInvestigationRecord(adminUser, threatEvent, investigation) {
    // Store investigation record
    return {
      _id: crypto.randomUUID(),
      threatEventId: threatEvent._id,
      investigatedBy: adminUser.id,
      investigatedAt: new Date(),
      findings: investigation,
      status: 'completed'
    };
  }

  /**
   * Execute threat response action
   * @param {Object} action - Action to execute
   * @param {string} threatId - Threat ID
   * @param {Object} adminUser - Admin user
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Action result
   * @private
   */
  static async executeThreatResponseAction(action, threatId, adminUser, session) {
    const { type, parameters } = action;

    switch (type) {
      case 'block_ip':
        return this.executeIPBlock(parameters.ip, parameters.duration, adminUser.id, session);
      
      case 'disable_account':
        return this.executeAccountDisable(parameters.userId, adminUser.id, session);
      
      case 'quarantine':
        return this.executeQuarantine(parameters.resource, adminUser.id, session);
      
      case 'alert':
        return this.executeAlert(parameters, adminUser.id);
      
      case 'custom':
        return this.executeCustomAction(parameters, adminUser.id, session);
      
      default:
        throw new Error(`Unknown action type: ${type}`);
    }
  }

  /**
   * Execute IP block
   * @param {string} ip - IP to block
   * @param {number} duration - Block duration
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Block result
   * @private
   */
  static async executeIPBlock(ip, duration, userId, session) {
    const block = await BlockedIP.create([{
      ip,
      reason: 'Automated threat response',
      duration,
      expiresAt: duration ? new Date(Date.now() + duration) : null,
      permanent: !duration,
      blockedBy: userId,
      active: true
    }], { session });

    await this.applyIPBlock(ip, block[0], session);

    return {
      success: true,
      blockId: block[0]._id
    };
  }

  /**
   * Execute account disable
   * @param {string} userId - User ID to disable
   * @param {string} adminId - Admin user ID
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Disable result
   * @private
   */
  static async executeAccountDisable(userId, adminId, session) {
    await User.findByIdAndUpdate(
      userId,
      {
        $set: {
          status: 'suspended',
          suspendedAt: new Date(),
          suspendedBy: adminId,
          suspensionReason: 'Automated threat response'
        }
      },
      { session }
    );

    return {
      success: true,
      userId
    };
  }

  /**
   * Execute quarantine
   * @param {string} resource - Resource to quarantine
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Quarantine result
   * @private
   */
  static async executeQuarantine(resource, userId, session) {
    // Implementation depends on resource type
    return {
      success: true,
      resource,
      quarantined: true
    };
  }

  /**
   * Execute alert
   * @param {Object} parameters - Alert parameters
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Alert result
   * @private
   */
  static async executeAlert(parameters, userId) {
    await NotificationService.sendAlert({
      type: 'threat_response',
      priority: parameters.priority || 'high',
      recipients: parameters.recipients,
      data: parameters.data
    });

    return {
      success: true,
      alerted: parameters.recipients.length
    };
  }

  /**
   * Execute custom action
   * @param {Object} parameters - Custom action parameters
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Action result
   * @private
   */
  static async executeCustomAction(parameters, userId, session) {
    // Implementation for custom actions
    return {
      success: true,
      action: 'custom',
      parameters
    };
  }

  /**
   * Escalate threat
   * @param {string} threatId - Threat ID
   * @param {string} userId - User ID
   * @param {string} notes - Escalation notes
   * @param {Object} session - Database session
   * @private
   */
  static async escalateThreat(threatId, userId, notes, session) {
    // Create security incident
    await SecurityIncident.create([{
      type: 'escalated_threat',
      severity: 'high',
      description: `Escalated threat: ${threatId}`,
      affectedResources: [threatId],
      status: 'open',
      reportedBy: userId,
      metadata: {
        threatId,
        escalationNotes: notes
      }
    }], { session });

    // Notify security team
    await NotificationService.notifySecurityTeam({
      type: 'threat_escalation',
      threatId,
      escalatedBy: userId,
      notes
    });
  }

  /**
   * Notify affected parties
   * @param {string} threatId - Threat ID
   * @param {Object} response - Response record
   * @param {Object} session - Database session
   * @private
   */
  static async notifyAffectedParties(threatId, response, session) {
    const threat = await ThreatEvent.findById(threatId).session(session);
    
    if (threat.affectedUser) {
      await NotificationService.sendNotification({
        userId: threat.affectedUser,
        type: 'security_threat_detected',
        priority: 'high',
        data: {
          threatType: threat.type,
          severity: threat.severity,
          responseActions: response.actions.map(a => a.type)
        }
      });
    }

    if (threat.organizationId) {
      const orgAdmins = await User.find({
        organizationId: threat.organizationId,
        role: { $in: ['admin', 'owner'] }
      }).session(session);

      for (const admin of orgAdmins) {
        await NotificationService.sendNotification({
          userId: admin._id,
          type: 'organization_threat_detected',
          priority: 'high',
          data: {
            threatType: threat.type,
            severity: threat.severity,
            affectedResources: threat.affectedResources
          }
        });
      }
    }
  }

  /**
   * Update threat status
   * @param {string} threatId - Threat ID
   * @param {string} status - New status
   * @param {Object} session - Database session
   * @private
   */
  static async updateThreatStatus(threatId, status, session) {
    await ThreatEvent.findByIdAndUpdate(
      threatId,
      {
        $set: {
          status,
          lastUpdated: new Date()
        }
      },
      { session }
    );
  }

  /**
   * Add indicator to monitoring
   * @param {Object} indicator - Threat indicator
   * @param {Object} session - Database session
   * @private
   */
  static async addIndicatorToMonitoring(indicator, session) {
    // Add to real-time monitoring
    logger.info('Adding indicator to monitoring', {
      indicatorId: indicator._id,
      type: indicator.type,
      value: indicator.value
    });
  }

  /**
   * Update indicator monitoring
   * @param {Object} indicator - Threat indicator
   * @param {Object} session - Database session
   * @private
   */
  static async updateIndicatorMonitoring(indicator, session) {
    // Update monitoring rules
    logger.info('Updating indicator monitoring', {
      indicatorId: indicator._id
    });
  }

  /**
   * Remove indicator from monitoring
   * @param {Object} indicator - Threat indicator
   * @param {Object} session - Database session
   * @private
   */
  static async removeIndicatorFromMonitoring(indicator, session) {
    // Remove from monitoring
    logger.info('Removing indicator from monitoring', {
      indicatorId: indicator._id
    });
  }

  /**
   * Apply IP block
   * @param {string} ip - IP address
   * @param {Object} block - Block record
   * @param {Object} session - Database session
   * @private
   */
  static async applyIPBlock(ip, block, session) {
    // Apply block to firewall/security infrastructure
    logger.info('Applying IP block', {
      ip,
      blockId: block._id,
      permanent: block.permanent
    });
  }

  /**
   * Remove IP block
   * @param {string} ip - IP address
   * @param {Object} session - Database session
   * @private
   */
  static async removeIPBlock(ip, session) {
    // Remove block from firewall/security infrastructure
    logger.info('Removing IP block', { ip });
  }

  /**
   * Identify patterns
   * @param {Array} events - Threat events
   * @param {number} minOccurrences - Minimum occurrences
   * @returns {Promise<Array>} Identified patterns
   * @private
   */
  static async identifyPatterns(events, minOccurrences) {
    const patterns = [];
    const patternMap = {};

    // Group by common attributes
    events.forEach(event => {
      const key = `${event.type}-${event.source}`;
      if (!patternMap[key]) {
        patternMap[key] = {
          type: event.type,
          source: event.source,
          events: []
        };
      }
      patternMap[key].events.push(event);
    });

    // Analyze patterns
    for (const [key, pattern] of Object.entries(patternMap)) {
      if (pattern.events.length >= minOccurrences) {
        const analysis = this.analyzePattern(pattern.events);
        patterns.push({
          ...pattern,
          ...analysis,
          confidence: Math.min(pattern.events.length * 10, 100)
        });
      }
    }

    return patterns;
  }

  /**
   * Analyze pattern
   * @param {Array} events - Pattern events
   * @returns {Object} Pattern analysis
   * @private
   */
  static analyzePattern(events) {
    const timestamps = events.map(e => e.timestamp.getTime());
    const intervals = [];
    
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }

    const avgInterval = intervals.length > 0
      ? intervals.reduce((a, b) => a + b, 0) / intervals.length
      : 0;

    return {
      occurrences: events.length,
      firstSeen: events[0].timestamp,
      lastSeen: events[events.length - 1].timestamp,
      avgInterval,
      persistence: this.calculatePersistence(events)
    };
  }

  /**
   * Calculate persistence
   * @param {Array} events - Pattern events
   * @returns {number} Persistence score
   * @private
   */
  static calculatePersistence(events) {
    const timespan = events[events.length - 1].timestamp - events[0].timestamp;
    const days = timespan / (24 * 60 * 60 * 1000);
    
    if (days === 0) return 0;
    
    const eventsPerDay = events.length / days;
    return Math.min(eventsPerDay / 10, 1); // Normalize to 0-1
  }

  /**
   * Apply ML pattern analysis
   * @param {Array} events - Threat events
   * @returns {Promise<Object>} ML analysis
   * @private
   */
  static async applyMLPatternAnalysis(events) {
    // Placeholder for ML analysis
    return {
      anomalies: [],
      predictions: [],
      clusters: []
    };
  }

  /**
   * Store detected pattern
   * @param {Object} pattern - Pattern to store
   * @param {string} userId - User ID
   * @private
   */
  static async storeDetectedPattern(pattern, userId) {
    await ThreatPattern.create({
      ...pattern,
      detectedBy: userId,
      detectedAt: new Date(),
      active: true
    });
  }

  /**
   * Generate pattern insights
   * @param {Array} patterns - Detected patterns
   * @param {Object} mlPatterns - ML patterns
   * @returns {Promise<Array>} Pattern insights
   * @private
   */
  static async generatePatternInsights(patterns, mlPatterns) {
    const insights = [];

    // Persistence insights
    const persistentPatterns = patterns.filter(p => p.persistence > 0.7);
    if (persistentPatterns.length > 0) {
      insights.push({
        type: 'persistence',
        severity: 'high',
        description: `${persistentPatterns.length} persistent attack patterns detected`,
        patterns: persistentPatterns.map(p => p.type)
      });
    }

    // Frequency insights
    const highFreqPatterns = patterns.filter(p => p.avgInterval < 60000); // Less than 1 minute
    if (highFreqPatterns.length > 0) {
      insights.push({
        type: 'frequency',
        severity: 'medium',
        description: 'High-frequency attack patterns detected',
        count: highFreqPatterns.length
      });
    }

    return insights;
  }

  /**
   * Generate pattern recommendations
   * @param {Array} patterns - Detected patterns
   * @returns {Promise<Array>} Recommendations
   * @private
   */
  static async generatePatternRecommendations(patterns) {
    const recommendations = [];

    // Check for brute force patterns
    const bruteForcePatterns = patterns.filter(p => 
      p.type === 'failed_login' && p.occurrences > 10
    );
    if (bruteForcePatterns.length > 0) {
      recommendations.push({
        type: 'brute_force_mitigation',
        priority: 'high',
        description: 'Implement rate limiting and account lockout policies',
        patterns: bruteForcePatterns
      });
    }

    // Check for scanning patterns
    const scanPatterns = patterns.filter(p => 
      p.type === 'port_scan' || p.type === 'vulnerability_scan'
    );
    if (scanPatterns.length > 0) {
      recommendations.push({
        type: 'scan_detection',
        priority: 'medium',
        description: 'Enable advanced scan detection and blocking',
        patterns: scanPatterns
      });
    }

    return recommendations;
  }

  /**
   * Extract IOCs from intelligence
   * @param {Array} intelligence - Threat intelligence
   * @returns {Promise<Array>} Extracted IOCs
   * @private
   */
  static async extractIOCsFromIntelligence(intelligence) {
    const iocs = [];

    for (const intel of intelligence) {
      if (intel.indicators && intel.indicators.length > 0) {
        iocs.push(...intel.indicators.map(indicator => ({
          ...indicator,
          source: intel.source,
          confidence: intel.confidence
        })));
      }
    }

    return iocs;
  }

  /**
   * Correlate with internal data
   * @param {Array} intelligence - Threat intelligence
   * @returns {Promise<Object>} Correlations
   * @private
   */
  static async correlateWithInternalData(intelligence) {
    const correlations = {};

    for (const intel of intelligence) {
      correlations[intel._id] = {
        matches: 0,
        events: []
      };

      // Check against recent threat events
      if (intel.indicators) {
        for (const indicator of intel.indicators) {
          const matches = await ThreatEvent.find({
            $or: [
              { source: indicator.value },
              { 'metadata.indicators': indicator.value }
            ],
            timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
          }).limit(5).lean();

          correlations[intel._id].matches += matches.length;
          correlations[intel._id].events.push(...matches);
        }
      }
    }

    return correlations;
  }

  /**
   * Calculate intelligence relevance
   * @param {Object} intel - Intelligence record
   * @param {Object} correlation - Correlation data
   * @returns {number} Relevance score
   * @private
   */
  static calculateIntelRelevance(intel, correlation) {
    let score = 50; // Base score

    // Adjust based on correlation
    if (correlation && correlation.matches > 0) {
      score += Math.min(correlation.matches * 10, 30);
    }

    // Adjust based on severity
    const severityBonus = {
      critical: 20,
      high: 15,
      medium: 10,
      low: 5
    };
    score += severityBonus[intel.severity] || 0;

    // Adjust based on age
    const age = Date.now() - new Date(intel.publishedAt).getTime();
    const daysSincePublished = age / (24 * 60 * 60 * 1000);
    if (daysSincePublished < 1) score += 10;
    else if (daysSincePublished < 7) score += 5;

    return Math.min(score, 100);
  }

  /**
   * Get available intelligence sources
   * @returns {Promise<Array>} Available sources
   * @private
   */
  static async getAvailableIntelSources() {
    return ThreatIntelligence.distinct('source');
  }

  /**
   * Gather comprehensive threat data
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Comprehensive data
   * @private
   */
  static async gatherComprehensiveThreatData(startDate, endDate, organizationId) {
    const query = {
      timestamp: { $gte: startDate, $lte: endDate }
    };
    if (organizationId) {
      query.organizationId = organizationId;
    }

    const [
      events,
      incidents,
      patterns,
      indicators,
      responses
    ] = await Promise.all([
      ThreatEvent.find(query).lean(),
      SecurityIncident.find({
        createdAt: { $gte: startDate, $lte: endDate },
        organizationId
      }).lean(),
      ThreatPattern.find({
        detectedAt: { $gte: startDate, $lte: endDate },
        organizationId
      }).lean(),
      ThreatIndicator.find({
        createdAt: { $gte: startDate, $lte: endDate }
      }).lean(),
      ThreatResponse.find({
        startTime: { $gte: startDate, $lte: endDate }
      }).lean()
    ]);

    return {
      summary: {
        totalEvents: events.length,
        totalIncidents: incidents.length,
        uniqueThreats: new Set(events.map(e => e.type)).size,
        activeIndicators: indicators.filter(i => i.active).length
      },
      events: this.summarizeEvents(events),
      incidents: this.summarizeIncidents(incidents),
      patterns,
      indicators,
      responses: this.summarizeResponses(responses),
      timeline: this.buildThreatTimeline(events)
    };
  }

  /**
   * Gather executive threat data
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Executive data
   * @private
   */
  static async gatherExecutiveThreatData(startDate, endDate, organizationId) {
    const comprehensive = await this.gatherComprehensiveThreatData(
      startDate,
      endDate,
      organizationId
    );

    return {
      executiveSummary: {
        threatLevel: await this.calculateCurrentThreatLevel(organizationId),
        keyMetrics: {
          incidents: comprehensive.summary.totalIncidents,
          criticalThreats: comprehensive.events.critical || 0,
          successfulMitigations: comprehensive.responses.successful || 0
        },
        trends: await this.calculateThreatTrends(startDate, endDate, organizationId),
        recommendations: await this.generateExecutiveRecommendations(comprehensive)
      },
      riskAssessment: await this.performRiskAssessment(comprehensive),
      costImpact: await this.estimateCostImpact(comprehensive)
    };
  }

  /**
   * Gather technical threat data
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Technical data
   * @private
   */
  static async gatherTechnicalThreatData(startDate, endDate, organizationId) {
    const comprehensive = await this.gatherComprehensiveThreatData(
      startDate,
      endDate,
      organizationId
    );

    return {
      technicalAnalysis: {
        attackVectors: await this.analyzeAttackVectors(comprehensive.events),
        ttps: await this.analyzeTTPs(comprehensive.events),
        vulnerabilities: await this.identifyVulnerabilities(comprehensive),
        indicators: this.categorizeIndicators(comprehensive.indicators)
      },
      detectionCoverage: await this.assessDetectionCoverage(comprehensive),
      mitigationEffectiveness: await this.assessMitigationEffectiveness(comprehensive),
      technicalRecommendations: await this.generateTechnicalRecommendations(comprehensive)
    };
  }

  /**
   * Gather incident report data
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Incident data
   * @private
   */
  static async gatherIncidentReportData(startDate, endDate, organizationId) {
    const incidents = await SecurityIncident.find({
      createdAt: { $gte: startDate, $lte: endDate },
      organizationId
    })
      .populate('reportedBy', 'email profile.firstName profile.lastName')
      .populate('assignedTo', 'email profile.firstName profile.lastName')
      .lean();

    return {
      incidents: incidents.map(incident => ({
        ...incident,
        duration: incident.resolvedAt 
          ? incident.resolvedAt - incident.createdAt 
          : Date.now() - incident.createdAt,
        timeline: this.buildIncidentTimeline(incident)
      })),
      statistics: {
        total: incidents.length,
        byStatus: this.groupByField(incidents, 'status'),
        bySeverity: this.groupByField(incidents, 'severity'),
        avgResolutionTime: this.calculateAvgResolutionTime(incidents),
        impactAnalysis: await this.analyzeIncidentImpact(incidents)
      },
      lessonsLearned: await this.extractLessonsLearned(incidents)
    };
  }

  /**
   * Generate threat predictions
   * @param {Object} data - Historical data
   * @returns {Promise<Object>} Predictions
   * @private
   */
  static async generateThreatPredictions(data) {
    return {
      nextWeek: {
        expectedThreats: Math.round(data.summary.totalEvents * 1.1),
        riskLevel: 'medium',
        confidence: 75
      },
      trends: {
        increasing: ['phishing', 'ransomware'],
        decreasing: ['ddos'],
        emerging: ['supply_chain_attacks']
      }
    };
  }

  /**
   * Format threat report
   * @param {Object} report - Report data
   * @param {string} format - Output format
   * @returns {Promise<Object>} Formatted report
   * @private
   */
  static async formatThreatReport(report, format) {
    switch (format) {
      case 'summary':
        return {
          id: report.id,
          generatedAt: report.generatedAt,
          summary: report.data.summary || report.data.executiveSummary,
          keyFindings: this.extractKeyFindings(report.data)
        };

      case 'detailed':
        return report;

      case 'executive':
        return {
          ...report.data.executiveSummary,
          visualizations: await this.generateVisualizations(report.data)
        };

      default:
        return report;
    }
  }

  /**
   * Store threat report
   * @param {Object} report - Report to store
   * @private
   */
  static async storeThreatReport(report) {
    // Store report for future reference
    logger.info('Storing threat report', {
      reportId: report.id,
      type: report.type
    });
  }

  /**
   * Validate automation rules
   * @param {Object} rules - Automation rules
   * @returns {Promise<Object>} Validation result
   * @private
   */
  static async validateAutomationRules(rules) {
    const errors = [];

    // Validate conditions
    if (!rules.conditions || Object.keys(rules.conditions).length === 0) {
      errors.push('At least one condition is required');
    }

    // Validate actions
    if (!rules.actions || rules.actions.length === 0) {
      errors.push('At least one action is required');
    }

    // Validate action types
    const validActionTypes = ['block', 'alert', 'quarantine', 'log', 'custom'];
    for (const action of rules.actions || []) {
      if (!validActionTypes.includes(action.type)) {
        errors.push(`Invalid action type: ${action.type}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Deploy automation
   * @param {Object} automation - Automation to deploy
   * @param {Object} session - Database session
   * @private
   */
  static async deployAutomation(automation, session) {
    logger.info('Deploying threat automation', {
      automationId: automation._id,
      threatType: automation.metadata.threatType
    });
  }

  /**
   * Clear threat-related caches
   * @private
   */
  static async clearThreatCache() {
    const patterns = [
      `${this.cachePrefix}:*`,
      'threat:*',
      'indicator:*',
      'pattern:*'
    ];

    await Promise.all(patterns.map(pattern => CacheService.deletePattern(pattern)));
  }

  /**
   * Identify attack vector
   * @param {Object} threatEvent - Threat event
   * @returns {string} Attack vector
   * @private
   */
  static identifyAttackVector(threatEvent) {
    // Simple classification based on threat type
    const vectorMap = {
      'brute_force': 'authentication',
      'sql_injection': 'web_application',
      'malware': 'endpoint',
      'phishing': 'email',
      'ddos': 'network'
    };

    return vectorMap[threatEvent.type] || 'unknown';
  }

  /**
   * Map to MITRE ATT&CK
   * @param {Object} threatEvent - Threat event
   * @returns {Promise<Array>} MITRE TTPs
   * @private
   */
  static async mapToMITRE(threatEvent) {
    // Simplified MITRE mapping
    const ttps = [];
    
    switch (threatEvent.type) {
      case 'brute_force':
        ttps.push({
          tactic: 'Credential Access',
          technique: 'T1110 - Brute Force',
          subtechnique: 'T1110.001 - Password Guessing'
        });
        break;
      case 'sql_injection':
        ttps.push({
          tactic: 'Initial Access',
          technique: 'T1190 - Exploit Public-Facing Application',
          subtechnique: null
        });
        break;
      case 'phishing':
        ttps.push({
          tactic: 'Initial Access',
          technique: 'T1566 - Phishing',
          subtechnique: 'T1566.001 - Spearphishing Attachment'
        });
        break;
    }

    return ttps;
  }

  /**
   * Build threat timeline
   * @param {Object|Array} data - Threat data
   * @returns {Promise<Array>} Timeline
   * @private
   */
  static async buildThreatTimeline(data) {
    const events = Array.isArray(data) ? data : [data];
    const timeline = [];

    for (const event of events) {
      timeline.push({
        timestamp: event.timestamp || event.createdAt,
        type: 'threat_detected',
        description: `${event.type} threat detected from ${event.source}`,
        severity: event.severity
      });

      // Add related events
      const responses = await ThreatResponse.find({
        threatId: event._id
      }).lean();

      responses.forEach(response => {
        timeline.push({
          timestamp: response.startTime,
          type: 'response_initiated',
          description: `${response.responseType} response initiated`,
          responseId: response._id
        });
      });
    }

    return timeline.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Calculate pattern risk
   * @param {Object} pattern - Pattern data
   * @returns {number} Risk score
   * @private
   */
  static calculatePatternRisk(pattern) {
    let risk = 0;

    // Base risk on occurrences
    risk += Math.min(pattern.occurrences * 5, 30);

    // Add persistence factor
    risk += pattern.persistence * 30;

    // Add frequency factor
    if (pattern.avgInterval < 60000) { // Less than 1 minute
      risk += 20;
    } else if (pattern.avgInterval < 300000) { // Less than 5 minutes
      risk += 10;
    }

    // Add confidence factor
    risk += (pattern.confidence / 100) * 20;

    return Math.min(Math.round(risk), 100);
  }

  /**
   * Summarize events
   * @param {Array} events - Threat events
   * @returns {Object} Events summary
   * @private
   */
  static summarizeEvents(events) {
    return {
      total: events.length,
      critical: events.filter(e => e.severity === 'critical').length,
      high: events.filter(e => e.severity === 'high').length,
      medium: events.filter(e => e.severity === 'medium').length,
      low: events.filter(e => e.severity === 'low').length,
      byType: this.groupByField(events, 'type'),
      bySource: this.groupTopSources(events)
    };
  }

  /**
   * Summarize incidents
   * @param {Array} incidents - Security incidents
   * @returns {Object} Incidents summary
   * @private
   */
  static summarizeIncidents(incidents) {
    return {
      total: incidents.length,
      open: incidents.filter(i => i.status === 'open').length,
      resolved: incidents.filter(i => i.status === 'resolved').length,
      avgResolutionTime: this.calculateAvgResolutionTime(incidents),
      bySeverity: this.groupByField(incidents, 'severity'),
      byType: this.groupByField(incidents, 'type')
    };
  }

  /**
   * Summarize responses
   * @param {Array} responses - Threat responses
   * @returns {Object} Responses summary
   * @private
   */
  static summarizeResponses(responses) {
    const successful = responses.filter(r => r.status === 'completed');
    const failed = responses.filter(r => r.status === 'failed');

    return {
      total: responses.length,
      successful: successful.length,
      failed: failed.length,
      partial: responses.filter(r => r.status === 'partial').length,
      avgResponseTime: this.calculateAvgResponseTime(responses),
      byType: this.groupByField(responses, 'responseType'),
      automated: responses.filter(r => r.automated).length
    };
  }

  /**
   * Calculate threat trends
   * @param {Date} startDate - Start date
   * @param {Date} endDate - End date
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Trends
   * @private
   */
  static async calculateThreatTrends(startDate, endDate, organizationId) {
    const query = organizationId ? { organizationId } : {};
    
    // Get data for comparison periods
    const currentPeriod = await ThreatEvent.find({
      ...query,
      timestamp: { $gte: startDate, $lte: endDate }
    }).lean();

    const previousPeriodStart = new Date(startDate.getTime() - (endDate - startDate));
    const previousPeriod = await ThreatEvent.find({
      ...query,
      timestamp: { $gte: previousPeriodStart, $lt: startDate }
    }).lean();

    return {
      current: {
        events: currentPeriod.length,
        critical: currentPeriod.filter(e => e.severity === 'critical').length
      },
      previous: {
        events: previousPeriod.length,
        critical: previousPeriod.filter(e => e.severity === 'critical').length
      },
      change: {
        events: ((currentPeriod.length - previousPeriod.length) / previousPeriod.length) * 100,
        critical: ((currentPeriod.filter(e => e.severity === 'critical').length - 
                   previousPeriod.filter(e => e.severity === 'critical').length) / 
                   previousPeriod.filter(e => e.severity === 'critical').length) * 100
      }
    };
  }

  /**
   * Generate executive recommendations
   * @param {Object} data - Threat data
   * @returns {Promise<Array>} Recommendations
   * @private
   */
  static async generateExecutiveRecommendations(data) {
    const recommendations = [];

    if (data.summary.totalIncidents > 10) {
      recommendations.push({
        priority: 'high',
        category: 'resource_allocation',
        title: 'Increase Security Resources',
        description: 'High incident volume suggests need for additional security resources',
        impact: 'Reduced incident response time and improved threat mitigation'
      });
    }

    if (data.events.critical > 0) {
      recommendations.push({
        priority: 'critical',
        category: 'immediate_action',
        title: 'Address Critical Threats',
        description: 'Critical threats require immediate executive attention',
        impact: 'Prevent potential major security breaches'
      });
    }

    return recommendations;
  }

  /**
   * Perform risk assessment
   * @param {Object} data - Threat data
   * @returns {Promise<Object>} Risk assessment
   * @private
   */
  static async performRiskAssessment(data) {
    return {
      overallRisk: 'medium',
      riskFactors: [
        {
          factor: 'threat_volume',
          level: data.summary.totalEvents > 100 ? 'high' : 'medium',
          score: Math.min(data.summary.totalEvents / 2, 50)
        },
        {
          factor: 'critical_incidents',
          level: data.incidents.open > 5 ? 'high' : 'low',
          score: data.incidents.open * 10
        }
      ],
      recommendations: [
        'Implement additional monitoring',
        'Review security policies',
        'Conduct security training'
      ]
    };
  }

  /**
   * Estimate cost impact
   * @param {Object} data - Threat data
   * @returns {Promise<Object>} Cost impact
   * @private
   */
  static async estimateCostImpact(data) {
    const avgIncidentCost = 50000; // Example average
    const avgDowntimeCost = 10000; // Per hour

    return {
      estimatedLoss: data.summary.totalIncidents * avgIncidentCost,
      downtimeCost: data.incidents.open * 2 * avgDowntimeCost, // Assume 2 hours per incident
      mitigationCost: data.responses.total * 5000, // Assume $5k per response
      totalImpact: null // Calculate based on above
    };
  }

  /**
   * Analyze attack vectors
   * @param {Array} events - Threat events
   * @returns {Promise<Object>} Attack vector analysis
   * @private
   */
  static async analyzeAttackVectors(events) {
    const vectors = {};

    events.forEach(event => {
      const vector = this.identifyAttackVector(event);
      if (!vectors[vector]) {
        vectors[vector] = {
          count: 0,
          events: []
        };
      }
      vectors[vector].count++;
      vectors[vector].events.push(event._id);
    });

    return vectors;
  }

  /**
   * Analyze TTPs
   * @param {Array} events - Threat events
   * @returns {Promise<Object>} TTP analysis
   * @private
   */
  static async analyzeTTPs(events) {
    const ttps = {
      tactics: {},
      techniques: {},
      procedures: {}
    };

    for (const event of events) {
      const mitreTTPs = await this.mapToMITRE(event);
      mitreTTPs.forEach(ttp => {
        if (!ttps.tactics[ttp.tactic]) {
          ttps.tactics[ttp.tactic] = 0;
        }
        ttps.tactics[ttp.tactic]++;

        if (!ttps.techniques[ttp.technique]) {
          ttps.techniques[ttp.technique] = 0;
        }
        ttps.techniques[ttp.technique]++;
      });
    }

    return ttps;
  }

  /**
   * Identify vulnerabilities
   * @param {Object} data - Threat data
   * @returns {Promise<Array>} Identified vulnerabilities
   * @private
   */
  static async identifyVulnerabilities(data) {
    const vulnerabilities = [];

    // Analyze patterns for vulnerability indicators
    data.patterns.forEach(pattern => {
      if (pattern.type === 'exploit_attempt') {
        vulnerabilities.push({
          type: 'unpatched_system',
          severity: 'high',
          evidence: pattern
        });
      }
    });

    return vulnerabilities;
  }

  /**
   * Categorize indicators
   * @param {Array} indicators - Threat indicators
   * @returns {Object} Categorized indicators
   * @private
   */
  static categorizeIndicators(indicators) {
    return {
      ip: indicators.filter(i => i.type === 'ip'),
      domain: indicators.filter(i => i.type === 'domain'),
      hash: indicators.filter(i => i.type === 'hash'),
      email: indicators.filter(i => i.type === 'email'),
      url: indicators.filter(i => i.type === 'url')
    };
  }

  /**
   * Assess detection coverage
   * @param {Object} data - Threat data
   * @returns {Promise<Object>} Detection coverage
   * @private
   */
  static async assessDetectionCoverage(data) {
    const totalThreats = data.events.length;
    const detectedThreats = data.events.filter(e => e.detectedBy).length;

    return {
      coveragePercentage: totalThreats > 0 ? (detectedThreats / totalThreats) * 100 : 0,
      gaps: await this.identifyDetectionGaps(data),
      recommendations: [
        'Enhance endpoint detection',
        'Implement behavioral analytics',
        'Add threat intelligence feeds'
      ]
    };
  }

  /**
   * Assess mitigation effectiveness
   * @param {Object} data - Threat data
   * @returns {Promise<Object>} Mitigation effectiveness
   * @private
   */
  static async assessMitigationEffectiveness(data) {
    const successRate = data.responses.total > 0
      ? (data.responses.successful / data.responses.total) * 100
      : 0;

    return {
      successRate,
      avgResponseTime: data.responses.avgResponseTime,
      automationRate: data.responses.total > 0
        ? (data.responses.automated / data.responses.total) * 100
        : 0,
      improvementAreas: [
        'Increase automation',
        'Reduce response time',
        'Improve success rate'
      ]
    };
  }

  /**
   * Generate technical recommendations
   * @param {Object} data - Threat data
   * @returns {Promise<Array>} Technical recommendations
   * @private
   */
  static async generateTechnicalRecommendations(data) {
    const recommendations = [];

    // Based on attack vectors
    const topVectors = Object.entries(data.technicalAnalysis?.attackVectors || {})
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 3);

    topVectors.forEach(([vector, info]) => {
      recommendations.push({
        category: 'defense',
        vector,
        recommendation: `Strengthen ${vector} defenses`,
        priority: info.count > 10 ? 'high' : 'medium'
      });
    });

    return recommendations;
  }

  /**
   * Build incident timeline
   * @param {Object} incident - Security incident
   * @returns {Array} Timeline
   * @private
   */
  static buildIncidentTimeline(incident) {
    const timeline = [
      {
        timestamp: incident.createdAt,
        event: 'incident_created',
        description: 'Incident reported'
      }
    ];

    if (incident.timeline) {
      timeline.push(...incident.timeline);
    }

    if (incident.resolvedAt) {
      timeline.push({
        timestamp: incident.resolvedAt,
        event: 'incident_resolved',
        description: 'Incident resolved'
      });
    }

    return timeline.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Group by field
   * @param {Array} items - Items to group
   * @param {string} field - Field to group by
   * @returns {Object} Grouped items
   * @private
   */
  static groupByField(items, field) {
    const groups = {};
    items.forEach(item => {
      const key = item[field] || 'unknown';
      groups[key] = (groups[key] || 0) + 1;
    });
    return groups;
  }

  /**
   * Group top sources
   * @param {Array} events - Threat events
   * @returns {Array} Top sources
   * @private
   */
  static groupTopSources(events) {
    const sources = {};
    events.forEach(event => {
      sources[event.source] = (sources[event.source] || 0) + 1;
    });

    return Object.entries(sources)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([source, count]) => ({ source, count }));
  }

  /**
   * Calculate average resolution time
   * @param {Array} items - Items with resolution times
   * @returns {number} Average resolution time
   * @private
   */
  static calculateAvgResolutionTime(items) {
    const resolved = items.filter(i => i.resolvedAt);
    if (resolved.length === 0) return 0;

    const totalTime = resolved.reduce((sum, item) => {
      return sum + (item.resolvedAt - item.createdAt);
    }, 0);

    return Math.round(totalTime / resolved.length / 1000 / 60); // Minutes
  }

  /**
   * Calculate average response time
   * @param {Array} responses - Threat responses
   * @returns {number} Average response time
   * @private
   */
  static calculateAvgResponseTime(responses) {
    if (responses.length === 0) return 0;

    const totalTime = responses.reduce((sum, response) => {
      if (response.endTime) {
        return sum + (response.endTime - response.startTime);
      }
      return sum;
    }, 0);

    const completedResponses = responses.filter(r => r.endTime).length;
    return completedResponses > 0 
      ? Math.round(totalTime / completedResponses / 1000 / 60) // Minutes
      : 0;
  }

  /**
   * Analyze incident impact
   * @param {Array} incidents - Security incidents
   * @returns {Promise<Object>} Impact analysis
   * @private
   */
  static async analyzeIncidentImpact(incidents) {
    return {
      affectedUsers: new Set(incidents.flatMap(i => i.affectedUsers || [])).size,
      affectedSystems: new Set(incidents.flatMap(i => i.affectedResources || [])).size,
      dataBreaches: incidents.filter(i => i.type === 'data_breach').length,
      serviceDisruptions: incidents.filter(i => i.type === 'service_disruption').length
    };
  }

  /**
   * Extract lessons learned
   * @param {Array} incidents - Security incidents
   * @returns {Promise<Array>} Lessons learned
   * @private
   */
  static async extractLessonsLearned(incidents) {
    const lessons = [];

    // Analyze resolved incidents
    const resolved = incidents.filter(i => i.status === 'resolved' && i.resolution);

    // Group by type and extract common patterns
    const typeGroups = this.groupByField(resolved, 'type');
    Object.entries(typeGroups).forEach(([type, count]) => {
      if (count > 3) {
        lessons.push({
          type,
          observation: `Recurring ${type} incidents detected`,
          recommendation: `Implement preventive measures for ${type} threats`
        });
      }
    });

    return lessons;
  }

  /**
   * Extract key findings
   * @param {Object} data - Report data
   * @returns {Array} Key findings
   * @private
   */
  static extractKeyFindings(data) {
    const findings = [];

    if (data.summary) {
      if (data.summary.criticalEvents > 0) {
        findings.push({
          severity: 'critical',
          finding: `${data.summary.criticalEvents} critical security events detected`
        });
      }

      if (data.summary.totalIncidents > 20) {
        findings.push({
          severity: 'high',
          finding: 'High volume of security incidents requires attention'
        });
      }
    }

    return findings;
  }

  /**
   * Generate visualizations
   * @param {Object} data - Report data
   * @returns {Promise<Object>} Visualization data
   * @private
   */
  static async generateVisualizations(data) {
    return {
      threatTrend: {
        type: 'line',
        data: data.timeline || []
      },
      severityDistribution: {
        type: 'pie',
        data: data.summary?.bySeverity || {}
      },
      topThreats: {
        type: 'bar',
        data: data.topThreats || []
      }
    };
  }

  /**
   * Identify detection gaps
   * @param {Object} data - Threat data
   * @returns {Promise<Array>} Detection gaps
   * @private
   */
  static async identifyDetectionGaps(data) {
    const gaps = [];

    // Check for undetected threats
    const undetected = data.events.filter(e => !e.detectedBy);
    if (undetected.length > 0) {
      const types = new Set(undetected.map(e => e.type));
      types.forEach(type => {
        gaps.push({
          type,
          gap: 'No detection rule',
          severity: 'high'
        });
      });
    }

    return gaps;
  }

  /**
   * Parse time range string
   * @param {string} timeRange - Time range string
   * @returns {number} Time in milliseconds
   * @private
   */
  static parseTimeRange(timeRange) {
    const unit = timeRange.slice(-1);
    const value = parseInt(timeRange.slice(0, -1));

    const multipliers = {
      'h': 60 * 60 * 1000,
      'd': 24 * 60 * 60 * 1000,
      'w': 7 * 24 * 60 * 60 * 1000,
      'm': 30 * 24 * 60 * 60 * 1000,
      'y': 365 * 24 * 60 * 60 * 1000
    };

    return value * (multipliers[unit] || multipliers['d']);
  }
}

// Inherit from AdminBaseService
Object.setPrototypeOf(ThreatManagementService, AdminBaseService);
Object.setPrototypeOf(ThreatManagementService.prototype, AdminBaseService.prototype);

module.exports = ThreatManagementService;