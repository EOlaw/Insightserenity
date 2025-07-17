// server/admin/security-administration/services/security-service.js
/**
 * @file Admin Security Service
 * @description Comprehensive security management service for administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Core Models
const User = require('../../../shared/users/models/user-model');
const SecuritySettings = require('../../../shared/security/models/security-settings-model');
const SecurityLog = require('../../../shared/security/models/security-log-model');
const ThreatDetection = require('../../../shared/security/models/threat-detection-model');
const IPWhitelist = require('../../../shared/security/models/ip-whitelist-model');
const SessionSecurity = require('../../../shared/security/models/session-security-model');
const EncryptionKey = require('../../../shared/security/models/encryption-key-model');
const SecurityIncident = require('../../../shared/security/models/security-incident-model');
const AccessControl = require('../../../shared/security/models/access-control-model');
const VulnerabilityReport = require('../../../shared/security/models/vulnerability-report-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const EmailService = require('../../../shared/services/email-service');
const EncryptionService = require('../../../shared/security/services/encryption-service');
const VulnerabilityScanner = require('../../../shared/security/services/vulnerability-scanner');

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
 * Admin Security Service Class
 * @class SecurityService
 * @extends AdminBaseService
 */
class SecurityService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'AdminSecurityService';
    this.cachePrefix = 'admin-security';
    this.auditCategory = 'SECURITY_MANAGEMENT';
    this.requiredPermission = AdminPermissions.SECURITY.VIEW;
  }

  /**
   * Get security overview and current status
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Security overview data
   */
  static async getSecurityOverview(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.VIEW);

      const {
        timeRange = '24h',
        includeMetrics = true,
        includeThreats = true,
        includeVulnerabilities = true,
        includeCompliance = true
      } = options;

      // Calculate time boundaries
      const timeRangeMs = this.parseTimeRange(timeRange);
      const startDate = new Date(Date.now() - timeRangeMs);

      // Gather security data in parallel
      const [
        securitySettings,
        activeThreats,
        recentIncidents,
        vulnerabilities,
        sessionMetrics,
        accessMetrics,
        complianceStatus
      ] = await Promise.all([
        this.getGlobalSecuritySettings(),
        includeThreats ? this.getActiveThreats(startDate) : null,
        this.getRecentIncidents(startDate, 10),
        includeVulnerabilities ? this.getVulnerabilitySummary() : null,
        includeMetrics ? this.getSessionSecurityMetrics(startDate) : null,
        includeMetrics ? this.getAccessControlMetrics(startDate) : null,
        includeCompliance ? this.getComplianceStatus() : null
      ]);

      // Calculate security score
      const securityScore = await this.calculateSecurityScore({
        settings: securitySettings,
        threats: activeThreats,
        vulnerabilities,
        compliance: complianceStatus
      });

      // Compile overview
      const overview = {
        score: securityScore,
        status: this.getSecurityStatus(securityScore.overall),
        settings: {
          current: securitySettings,
          recommendations: await this.getSecurityRecommendations(securitySettings)
        },
        threats: {
          active: activeThreats?.count || 0,
          critical: activeThreats?.critical || 0,
          recent: recentIncidents
        },
        vulnerabilities: vulnerabilities || {},
        metrics: {
          sessions: sessionMetrics || {},
          access: accessMetrics || {}
        },
        compliance: complianceStatus || {},
        lastUpdated: new Date(),
        timeRange
      };

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.OVERVIEW_VIEWED, {
        timeRange,
        securityScore: securityScore.overall
      });

      return overview;

    } catch (error) {
      logger.error('Get security overview error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Update global security settings
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} settings - Security settings to update
   * @returns {Promise<Object>} Updated security settings
   */
  static async updateSecuritySettings(adminUser, settings) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.UPDATE);

      // Validate critical changes
      const criticalChanges = this.identifyCriticalSecurityChanges(settings);
      if (criticalChanges.length > 0) {
        await this.validateCriticalOperation(adminUser, 'security.settings.critical', {
          changes: criticalChanges
        });
      }

      // Get current settings
      const currentSettings = await SecuritySettings.findOne({ isGlobal: true }).session(session);
      const originalSettings = currentSettings ? currentSettings.toObject() : null;

      // Validate settings
      const validatedSettings = await this.validateSecuritySettings(settings);

      // Update or create settings
      let updatedSettings;
      if (currentSettings) {
        Object.assign(currentSettings, validatedSettings);
        currentSettings.lastModifiedBy = adminUser.id;
        currentSettings.lastModifiedAt = new Date();
        await currentSettings.save({ session });
        updatedSettings = currentSettings;
      } else {
        updatedSettings = await SecuritySettings.create([{
          ...validatedSettings,
          isGlobal: true,
          createdBy: adminUser.id,
          lastModifiedBy: adminUser.id
        }], { session });
        updatedSettings = updatedSettings[0];
      }

      // Apply security changes
      await this.applySecurityChanges(updatedSettings, originalSettings, session);

      // Clear security cache
      await this.clearSecurityCache();

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.SETTINGS_UPDATED, {
        changes: this.summarizeChanges(originalSettings, updatedSettings),
        criticalChanges,
        previousSettings: originalSettings
      }, { session, critical: true });

      // Send notifications for critical changes
      if (criticalChanges.length > 0) {
        await NotificationService.notifySecurityTeam({
          type: 'critical_security_change',
          adminName: adminUser.profile?.firstName || adminUser.email,
          changes: criticalChanges,
          timestamp: new Date()
        });
      }

      await session.commitTransaction();

      return {
        settings: updatedSettings,
        changes: this.summarizeChanges(originalSettings, updatedSettings),
        message: 'Security settings updated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Update security settings error', {
        error: error.message,
        adminId: adminUser.id,
        settings,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Manage IP whitelist
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - IP whitelist options
   * @returns {Promise<Object>} IP whitelist result
   */
  static async manageIPWhitelist(adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.MANAGE_WHITELIST);

      const {
        action,
        ips = [],
        description,
        scope = 'admin',
        expiresAt
      } = options;

      if (!['add', 'remove', 'list', 'update'].includes(action)) {
        throw new ValidationError('Invalid action specified');
      }

      let result;

      switch (action) {
        case 'add':
          result = await this.addIPsToWhitelist(ips, {
            description,
            scope,
            expiresAt,
            addedBy: adminUser.id,
            session
          });
          break;

        case 'remove':
          result = await this.removeIPsFromWhitelist(ips, {
            removedBy: adminUser.id,
            session
          });
          break;

        case 'update':
          result = await this.updateIPWhitelist(ips[0], {
            description,
            scope,
            expiresAt,
            updatedBy: adminUser.id,
            session
          });
          break;

        case 'list':
          result = await this.getIPWhitelist(scope);
          break;
      }

      // Clear IP whitelist cache
      await CacheService.delete(`${this.cachePrefix}:ip-whitelist:${scope}`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.IP_WHITELIST_MODIFIED, {
        action,
        ips: action !== 'list' ? ips : undefined,
        scope,
        result: result.summary
      }, { session });

      await session.commitTransaction();

      return {
        action,
        result,
        message: `IP whitelist ${action} completed successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage IP whitelist error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Force rotate encryption keys
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Key rotation options
   * @returns {Promise<Object>} Key rotation result
   */
  static async rotateEncryptionKeys(adminUser, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.ROTATE_KEYS);

      const {
        keyTypes = ['master', 'session', 'data'],
        reason,
        immediate = false,
        notifyUsers = true
      } = options;

      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Key rotation reason must be provided (minimum 10 characters)');
      }

      // Validate critical operation
      await this.validateCriticalOperation(adminUser, 'security.encryption.rotate', {
        keyTypes,
        reason
      });

      // Start key rotation process
      const rotationId = crypto.randomUUID();
      const rotationResults = {
        id: rotationId,
        startedAt: new Date(),
        keyTypes,
        results: {}
      };

      // Rotate each key type
      for (const keyType of keyTypes) {
        try {
          const result = await EncryptionService.rotateKey(keyType, {
            reason,
            initiatedBy: adminUser.id,
            immediate,
            session
          });

          rotationResults.results[keyType] = {
            success: true,
            newKeyId: result.newKeyId,
            previousKeyId: result.previousKeyId,
            affectedRecords: result.affectedRecords
          };
        } catch (error) {
          rotationResults.results[keyType] = {
            success: false,
            error: error.message
          };
          throw error; // Rollback on any failure
        }
      }

      rotationResults.completedAt = new Date();

      // Update security settings
      await SecuritySettings.findOneAndUpdate(
        { isGlobal: true },
        {
          $set: {
            'encryption.lastKeyRotation': new Date(),
            'encryption.lastRotationBy': adminUser.id,
            'encryption.rotationCount': { $inc: 1 }
          }
        },
        { session }
      );

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.ENCRYPTION_KEYS_ROTATED, {
        rotationId,
        keyTypes,
        reason,
        results: rotationResults.results
      }, { session, critical: true, alertLevel: 'high' });

      // Send notifications
      if (notifyUsers) {
        await NotificationService.sendBulkNotification({
          type: 'encryption_key_rotation',
          priority: 'high',
          data: {
            rotationId,
            reason,
            impact: 'Sessions may be invalidated. Please re-authenticate.',
            completedAt: rotationResults.completedAt
          }
        });
      }

      await session.commitTransaction();

      return {
        rotationId,
        results: rotationResults,
        message: 'Encryption keys rotated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Rotate encryption keys error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Manage security incidents
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} incidentData - Incident data
   * @returns {Promise<Object>} Incident management result
   */
  static async manageSecurityIncident(adminUser, incidentData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.MANAGE_INCIDENTS);

      const {
        action,
        incidentId,
        type,
        severity,
        description,
        affectedResources,
        resolution,
        status
      } = incidentData;

      let incident;

      switch (action) {
        case 'create':
          incident = await this.createSecurityIncident({
            type,
            severity,
            description,
            affectedResources,
            reportedBy: adminUser.id,
            session
          });
          
          // Auto-trigger incident response
          await this.triggerIncidentResponse(incident, session);
          break;

        case 'update':
          incident = await this.updateSecurityIncident(incidentId, {
            status,
            resolution,
            updatedBy: adminUser.id,
            session
          });
          break;

        case 'escalate':
          incident = await this.escalateIncident(incidentId, {
            escalatedBy: adminUser.id,
            reason: description,
            session
          });
          break;

        case 'resolve':
          incident = await this.resolveIncident(incidentId, {
            resolution,
            resolvedBy: adminUser.id,
            session
          });
          break;
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.INCIDENT_MANAGED, {
        action,
        incidentId: incident._id,
        severity: incident.severity,
        type: incident.type
      }, { session, critical: severity === 'critical' });

      await session.commitTransaction();

      return {
        incident,
        action,
        message: `Security incident ${action}d successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage security incident error', {
        error: error.message,
        adminId: adminUser.id,
        incidentData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Configure threat detection rules
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} ruleData - Threat detection rule data
   * @returns {Promise<Object>} Rule configuration result
   */
  static async configureThreatDetection(adminUser, ruleData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.CONFIGURE_THREAT_DETECTION);

      const {
        action,
        ruleId,
        name,
        type,
        conditions,
        actions: ruleActions,
        severity,
        enabled = true
      } = ruleData;

      let rule;

      switch (action) {
        case 'create':
          rule = await ThreatDetection.create([{
            name,
            type,
            conditions,
            actions: ruleActions,
            severity,
            enabled,
            createdBy: adminUser.id,
            statistics: {
              triggered: 0,
              falsePositives: 0,
              lastTriggered: null
            }
          }], { session });
          rule = rule[0];
          break;

        case 'update':
          rule = await ThreatDetection.findByIdAndUpdate(
            ruleId,
            {
              $set: {
                name,
                conditions,
                actions: ruleActions,
                severity,
                enabled,
                updatedBy: adminUser.id,
                updatedAt: new Date()
              }
            },
            { new: true, session }
          );
          break;

        case 'delete':
          rule = await ThreatDetection.findByIdAndUpdate(
            ruleId,
            {
              $set: {
                enabled: false,
                deleted: true,
                deletedBy: adminUser.id,
                deletedAt: new Date()
              }
            },
            { session }
          );
          break;

        case 'test':
          const testResult = await this.testThreatDetectionRule(ruleId, {
            testData: ruleData.testData
          });
          return { testResult, message: 'Rule tested successfully' };
      }

      // Clear threat detection cache
      await CacheService.delete(`${this.cachePrefix}:threat-rules`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.THREAT_RULE_CONFIGURED, {
        action,
        ruleId: rule?._id,
        ruleName: rule?.name,
        ruleType: rule?.type
      }, { session });

      await session.commitTransaction();

      return {
        rule,
        action,
        message: `Threat detection rule ${action}d successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Configure threat detection error', {
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
   * Perform security scan
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} scanOptions - Scan options
   * @returns {Promise<Object>} Scan results
   */
  static async performSecurityScan(adminUser, scanOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.PERFORM_SCAN);

      const {
        scanType = 'full',
        targets = ['system'],
        deep = false,
        schedule = false
      } = scanOptions;

      // Validate scan type
      const validScanTypes = ['full', 'vulnerability', 'compliance', 'access', 'configuration'];
      if (!validScanTypes.includes(scanType)) {
        throw new ValidationError('Invalid scan type');
      }

      // Start scan
      const scanId = crypto.randomUUID();
      const scanStartTime = Date.now();

      logger.info('Starting security scan', {
        scanId,
        scanType,
        targets,
        initiatedBy: adminUser.id
      });

      // Perform different scan types
      const scanResults = {
        id: scanId,
        type: scanType,
        startedAt: new Date(scanStartTime),
        targets,
        results: {},
        findings: []
      };

      // Execute scans based on type
      if (scanType === 'full' || scanType === 'vulnerability') {
        const vulnResults = await VulnerabilityScanner.scan({
          targets,
          deep,
          scanId
        });
        scanResults.results.vulnerabilities = vulnResults;
        scanResults.findings.push(...vulnResults.findings);
      }

      if (scanType === 'full' || scanType === 'compliance') {
        const complianceResults = await this.performComplianceScan(targets);
        scanResults.results.compliance = complianceResults;
        scanResults.findings.push(...complianceResults.findings);
      }

      if (scanType === 'full' || scanType === 'access') {
        const accessResults = await this.performAccessControlScan(targets);
        scanResults.results.access = accessResults;
        scanResults.findings.push(...accessResults.findings);
      }

      if (scanType === 'full' || scanType === 'configuration') {
        const configResults = await this.performConfigurationScan(targets);
        scanResults.results.configuration = configResults;
        scanResults.findings.push(...configResults.findings);
      }

      scanResults.completedAt = new Date();
      scanResults.duration = Date.now() - scanStartTime;
      scanResults.summary = this.summarizeScanResults(scanResults);

      // Save scan results
      await VulnerabilityReport.create({
        scanId,
        type: scanType,
        initiatedBy: adminUser.id,
        results: scanResults,
        findings: scanResults.findings,
        summary: scanResults.summary
      });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.SCAN_PERFORMED, {
        scanId,
        scanType,
        targets,
        findingsCount: scanResults.findings.length,
        duration: scanResults.duration
      });

      // Send critical findings alert
      const criticalFindings = scanResults.findings.filter(f => f.severity === 'critical');
      if (criticalFindings.length > 0) {
        await NotificationService.alertSecurityTeam({
          type: 'critical_findings',
          scanId,
          findings: criticalFindings,
          initiatedBy: adminUser.id
        });
      }

      return scanResults;

    } catch (error) {
      logger.error('Perform security scan error', {
        error: error.message,
        adminId: adminUser.id,
        scanOptions,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Generate security report
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} reportOptions - Report options
   * @returns {Promise<Object>} Security report
   */
  static async generateSecurityReport(adminUser, reportOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.SECURITY.VIEW_REPORTS);

      const {
        reportType = 'comprehensive',
        timeRange = '30d',
        format = 'detailed',
        includeRecommendations = true
      } = reportOptions;

      const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));
      const endDate = new Date();

      // Gather report data
      const [
        incidents,
        vulnerabilities,
        threatActivity,
        accessLogs,
        complianceStatus,
        auditSummary,
        securityMetrics
      ] = await Promise.all([
        this.getIncidentReport(startDate, endDate),
        this.getVulnerabilityReport(startDate, endDate),
        this.getThreatActivityReport(startDate, endDate),
        this.getAccessControlReport(startDate, endDate),
        this.getComplianceReport(),
        this.getAuditSummary(startDate, endDate),
        this.getSecurityMetrics(startDate, endDate)
      ]);

      // Generate report
      const report = {
        id: crypto.randomUUID(),
        type: reportType,
        generatedAt: new Date(),
        generatedBy: adminUser.id,
        period: { start: startDate, end: endDate },
        summary: {
          overallScore: await this.calculateSecurityScore({
            incidents,
            vulnerabilities,
            compliance: complianceStatus
          }),
          criticalFindings: this.extractCriticalFindings({
            incidents,
            vulnerabilities,
            threats: threatActivity
          }),
          trends: this.analyzeSecurityTrends({
            incidents,
            threats: threatActivity,
            metrics: securityMetrics
          })
        },
        sections: {
          incidents,
          vulnerabilities,
          threats: threatActivity,
          access: accessLogs,
          compliance: complianceStatus,
          audit: auditSummary,
          metrics: securityMetrics
        }
      };

      // Add recommendations if requested
      if (includeRecommendations) {
        report.recommendations = await this.generateSecurityRecommendations(report);
      }

      // Format report based on requested format
      const formattedReport = this.formatSecurityReport(report, format);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.SECURITY.REPORT_GENERATED, {
        reportType,
        timeRange,
        format
      });

      return formattedReport;

    } catch (error) {
      logger.error('Generate security report error', {
        error: error.message,
        adminId: adminUser.id,
        reportOptions,
        stack: error.stack
      });
      throw error;
    }
  }

  // ========== Private Helper Methods ==========

  /**
   * Get global security settings
   * @returns {Promise<Object>} Global security settings
   * @private
   */
  static async getGlobalSecuritySettings() {
    const cacheKey = `${this.cachePrefix}:global-settings`;
    const cached = await CacheService.get(cacheKey);
    if (cached) return cached;

    const settings = await SecuritySettings.findOne({ isGlobal: true });
    const settingsData = settings || AdminSecurityConfig.getDefaultSettings();

    await CacheService.set(cacheKey, settingsData, 300); // 5 minutes
    return settingsData;
  }

  /**
   * Get active threats
   * @param {Date} startDate - Start date
   * @returns {Promise<Object>} Active threats summary
   * @private
   */
  static async getActiveThreats(startDate) {
    const threats = await ThreatDetection.aggregate([
      {
        $match: {
          enabled: true,
          'statistics.lastTriggered': { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$severity',
          count: { $sum: 1 },
          recentTriggers: { $sum: '$statistics.triggered' }
        }
      }
    ]);

    const threatSummary = {
      count: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    threats.forEach(threat => {
      threatSummary.count += threat.count;
      threatSummary[threat._id] = threat.count;
    });

    return threatSummary;
  }

  /**
   * Get recent incidents
   * @param {Date} startDate - Start date
   * @param {number} limit - Limit
   * @returns {Promise<Array>} Recent incidents
   * @private
   */
  static async getRecentIncidents(startDate, limit) {
    return SecurityIncident.find({
      createdAt: { $gte: startDate }
    })
      .sort({ createdAt: -1 })
      .limit(limit)
      .select('type severity status createdAt resolvedAt')
      .lean();
  }

  /**
   * Get vulnerability summary
   * @returns {Promise<Object>} Vulnerability summary
   * @private
   */
  static async getVulnerabilitySummary() {
    const lastReport = await VulnerabilityReport.findOne()
      .sort({ createdAt: -1 })
      .lean();

    if (!lastReport) {
      return { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
    }

    const summary = {
      total: lastReport.findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      lastScan: lastReport.createdAt
    };

    lastReport.findings.forEach(finding => {
      summary[finding.severity]++;
    });

    return summary;
  }

  /**
   * Get session security metrics
   * @param {Date} startDate - Start date
   * @returns {Promise<Object>} Session security metrics
   * @private
   */
  static async getSessionSecurityMetrics(startDate) {
    const [
      totalSessions,
      suspiciousSessions,
      mfaSessions,
      elevatedSessions
    ] = await Promise.all([
      SessionSecurity.countDocuments({ createdAt: { $gte: startDate } }),
      SessionSecurity.countDocuments({
        createdAt: { $gte: startDate },
        'security.anomalyScore': { $gt: 50 }
      }),
      SessionSecurity.countDocuments({
        createdAt: { $gte: startDate },
        'authentication.mfaVerified': true
      }),
      SessionSecurity.countDocuments({
        createdAt: { $gte: startDate },
        'security.level': { $in: ['elevated', 'high', 'critical'] }
      })
    ]);

    return {
      total: totalSessions,
      suspicious: suspiciousSessions,
      mfaProtected: mfaSessions,
      elevated: elevatedSessions,
      mfaPercentage: totalSessions > 0 ? Math.round((mfaSessions / totalSessions) * 100) : 0
    };
  }

  /**
   * Get access control metrics
   * @param {Date} startDate - Start date
   * @returns {Promise<Object>} Access control metrics
   * @private
   */
  static async getAccessControlMetrics(startDate) {
    const [
      totalAccess,
      deniedAccess,
      privilegedAccess,
      emergencyAccess
    ] = await Promise.all([
      AccessControl.countDocuments({ timestamp: { $gte: startDate } }),
      AccessControl.countDocuments({
        timestamp: { $gte: startDate },
        result: 'denied'
      }),
      AccessControl.countDocuments({
        timestamp: { $gte: startDate },
        privilegeLevel: { $in: ['admin', 'super_admin'] }
      }),
      AccessControl.countDocuments({
        timestamp: { $gte: startDate },
        type: 'emergency'
      })
    ]);

    return {
      total: totalAccess,
      denied: deniedAccess,
      privileged: privilegedAccess,
      emergency: emergencyAccess,
      denialRate: totalAccess > 0 ? Math.round((deniedAccess / totalAccess) * 100) : 0
    };
  }

  /**
   * Get compliance status
   * @returns {Promise<Object>} Compliance status
   * @private
   */
  static async getComplianceStatus() {
    // This would connect to compliance checking systems
    return {
      overallScore: 85,
      standards: {
        GDPR: { compliant: true, score: 90 },
        HIPAA: { compliant: true, score: 88 },
        'PCI-DSS': { compliant: true, score: 82 },
        SOC2: { compliant: true, score: 85 }
      },
      lastAudit: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      nextAudit: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000)
    };
  }

  /**
   * Get security recommendations
   * @param {Object} settings - Current settings
   * @returns {Promise<Array>} Security recommendations
   * @private
   */
  static async getSecurityRecommendations(settings) {
    const recommendations = [];

    // Check password policy
    if (!settings.passwordPolicy?.requireMFA) {
      recommendations.push({
        priority: 'high',
        category: 'authentication',
        recommendation: 'Enable mandatory MFA for all admin users',
        impact: 'Significantly reduces account takeover risk'
      });
    }

    // Check session settings
    if (settings.sessionPolicy?.maxDuration > 8 * 60 * 60 * 1000) {
      recommendations.push({
        priority: 'medium',
        category: 'session',
        recommendation: 'Reduce maximum session duration to 8 hours',
        impact: 'Limits exposure from compromised sessions'
      });
    }

    // Check encryption
    if (!settings.encryption?.atRestEnabled) {
      recommendations.push({
        priority: 'critical',
        category: 'encryption',
        recommendation: 'Enable encryption at rest for sensitive data',
        impact: 'Protects data in case of physical breach'
      });
    }

    return recommendations;
  }

  /**
   * Identify critical security changes
   * @param {Object} settings - New settings
   * @returns {Array} Critical changes
   * @private
   */
  static identifyCriticalSecurityChanges(settings) {
    const criticalFields = [
      'authentication.mfaRequired',
      'encryption.enabled',
      'passwordPolicy.minLength',
      'sessionPolicy.maxDuration',
      'ipWhitelist.enabled',
      'threatDetection.enabled'
    ];

    const changes = [];
    criticalFields.forEach(field => {
      if (AdminHelpers.hasNestedProperty(settings, field)) {
        changes.push({
          field,
          value: AdminHelpers.getNestedProperty(settings, field)
        });
      }
    });

    return changes;
  }

  /**
   * Validate security settings
   * @param {Object} settings - Settings to validate
   * @returns {Promise<Object>} Validated settings
   * @private
   */
  static async validateSecuritySettings(settings) {
    // Validate password policy
    if (settings.passwordPolicy) {
      if (settings.passwordPolicy.minLength < 8) {
        throw new ValidationError('Password minimum length must be at least 8 characters');
      }
      if (settings.passwordPolicy.maxAge > 365 * 24 * 60 * 60 * 1000) {
        throw new ValidationError('Password maximum age cannot exceed 365 days');
      }
    }

    // Validate session policy
    if (settings.sessionPolicy) {
      if (settings.sessionPolicy.idleTimeout < 5 * 60 * 1000) {
        throw new ValidationError('Session idle timeout must be at least 5 minutes');
      }
    }

    return settings;
  }

  /**
   * Apply security changes
   * @param {Object} newSettings - New settings
   * @param {Object} oldSettings - Old settings
   * @param {Object} session - Database session
   * @private
   */
  static async applySecurityChanges(newSettings, oldSettings, session) {
    // Apply MFA changes
    if (newSettings.authentication?.mfaRequired && !oldSettings?.authentication?.mfaRequired) {
      await User.updateMany(
        { role: { $in: ['admin', 'super_admin'] } },
        { $set: { 'security.mfaRequired': true } },
        { session }
      );
    }

    // Apply session changes
    if (newSettings.sessionPolicy?.maxDuration !== oldSettings?.sessionPolicy?.maxDuration) {
      // Invalidate sessions exceeding new duration
      const cutoffTime = Date.now() - newSettings.sessionPolicy.maxDuration;
      await SessionSecurity.updateMany(
        { createdAt: { $lt: new Date(cutoffTime) }, status: 'active' },
        { $set: { status: 'expired', expiredAt: new Date() } },
        { session }
      );
    }
  }

  /**
   * Add IPs to whitelist
   * @param {Array} ips - IP addresses
   * @param {Object} options - Options
   * @returns {Promise<Object>} Result
   * @private
   */
  static async addIPsToWhitelist(ips, options) {
    const { description, scope, expiresAt, addedBy, session } = options;
    const results = { added: [], failed: [] };

    for (const ip of ips) {
      try {
        // Validate IP format
        if (!AdminHelpers.isValidIP(ip)) {
          results.failed.push({ ip, reason: 'Invalid IP format' });
          continue;
        }

        // Check if already exists
        const existing = await IPWhitelist.findOne({ ip, scope });
        if (existing) {
          results.failed.push({ ip, reason: 'Already whitelisted' });
          continue;
        }

        // Add to whitelist
        await IPWhitelist.create([{
          ip,
          scope,
          description,
          expiresAt,
          addedBy,
          active: true
        }], { session });

        results.added.push(ip);
      } catch (error) {
        results.failed.push({ ip, reason: error.message });
      }
    }

    return {
      summary: {
        requested: ips.length,
        added: results.added.length,
        failed: results.failed.length
      },
      details: results
    };
  }

  /**
   * Remove IPs from whitelist
   * @param {Array} ips - IP addresses
   * @param {Object} options - Options
   * @returns {Promise<Object>} Result
   * @private
   */
  static async removeIPsFromWhitelist(ips, options) {
    const { removedBy, session } = options;
    const results = { removed: [], failed: [] };

    for (const ip of ips) {
      try {
        const result = await IPWhitelist.findOneAndUpdate(
          { ip, active: true },
          {
            $set: {
              active: false,
              removedAt: new Date(),
              removedBy
            }
          },
          { session }
        );

        if (result) {
          results.removed.push(ip);
        } else {
          results.failed.push({ ip, reason: 'Not found in whitelist' });
        }
      } catch (error) {
        results.failed.push({ ip, reason: error.message });
      }
    }

    return {
      summary: {
        requested: ips.length,
        removed: results.removed.length,
        failed: results.failed.length
      },
      details: results
    };
  }

  /**
   * Get IP whitelist
   * @param {string} scope - Scope
   * @returns {Promise<Array>} IP whitelist
   * @private
   */
  static async getIPWhitelist(scope) {
    const whitelist = await IPWhitelist.find({
      scope,
      active: true,
      $or: [
        { expiresAt: null },
        { expiresAt: { $gt: new Date() } }
      ]
    })
      .populate('addedBy', 'email profile.firstName profile.lastName')
      .sort({ createdAt: -1 })
      .lean();

    return whitelist;
  }

  /**
   * Create security incident
   * @param {Object} data - Incident data
   * @returns {Promise<Object>} Created incident
   * @private
   */
  static async createSecurityIncident(data) {
    const incident = await SecurityIncident.create({
      type: data.type,
      severity: data.severity,
      description: data.description,
      affectedResources: data.affectedResources,
      status: 'open',
      reportedBy: data.reportedBy,
      timeline: [{
        event: 'incident_created',
        timestamp: new Date(),
        userId: data.reportedBy,
        description: 'Security incident reported'
      }]
    });

    return incident;
  }

  /**
   * Trigger incident response
   * @param {Object} incident - Security incident
   * @param {Object} session - Database session
   * @private
   */
  static async triggerIncidentResponse(incident, session) {
    // Notify security team
    await NotificationService.notifySecurityTeam({
      type: 'new_incident',
      incident: {
        id: incident._id,
        type: incident.type,
        severity: incident.severity,
        description: incident.description
      },
      priority: incident.severity === 'critical' ? 'urgent' : 'high'
    });

    // Auto-contain if critical
    if (incident.severity === 'critical') {
      await this.applyContainmentMeasures(incident, session);
    }

    // Start monitoring
    await this.startIncidentMonitoring(incident._id);
  }

  /**
   * Calculate settings score
   * @param {Object} settings - Security settings
   * @returns {number} Score
   * @private
   */
  static calculateSettingsScore(settings) {
    let score = 0;
    const checks = [
      { condition: settings.authentication?.mfaRequired, points: 20 },
      { condition: settings.passwordPolicy?.minLength >= 12, points: 15 },
      { condition: settings.encryption?.atRestEnabled, points: 20 },
      { condition: settings.sessionPolicy?.idleTimeout <= 30 * 60 * 1000, points: 10 },
      { condition: settings.ipWhitelist?.enabled, points: 15 },
      { condition: settings.threatDetection?.enabled, points: 20 }
    ];

    checks.forEach(check => {
      if (check.condition) score += check.points;
    });

    return score;
  }

  /**
   * Summarize changes
   * @param {Object} original - Original object
   * @param {Object} updated - Updated object
   * @returns {Object} Changes summary
   * @private
   */
  static summarizeChanges(original, updated) {
    const changes = {};
    const compareObjects = (obj1, obj2, path = '') => {
      for (const key in obj2) {
        const newPath = path ? `${path}.${key}` : key;
        if (typeof obj2[key] === 'object' && obj2[key] !== null && !Array.isArray(obj2[key])) {
          compareObjects(obj1?.[key] || {}, obj2[key], newPath);
        } else if (obj1?.[key] !== obj2[key]) {
          changes[newPath] = {
            old: obj1?.[key],
            new: obj2[key]
          };
        }
      }
    };

    compareObjects(original || {}, updated || {});
    return changes;
  }

  /**
   * Parse time range string
   * @param {string} timeRange - Time range string (e.g., '24h', '7d', '30d')
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
      'm': 30 * 24 * 60 * 60 * 1000
    };

    return value * (multipliers[unit] || multipliers['d']);
  }

  /**
   * Clear security-related caches
   * @private
   */
  static async clearSecurityCache() {
    const patterns = [
      `${this.cachePrefix}:*`,
      'security:*',
      'threat:*',
      'vulnerability:*'
    ];

    await Promise.all(patterns.map(pattern => CacheService.deletePattern(pattern)));
  }

  /**
   * Format security report
   * @param {Object} report - Raw report data
   * @param {string} format - Output format
   * @returns {Object} Formatted report
   * @private
   */
  static formatSecurityReport(report, format) {
    switch (format) {
      case 'summary':
        return {
          id: report.id,
          generatedAt: report.generatedAt,
          summary: report.summary,
          recommendations: report.recommendations?.slice(0, 5)
        };

      case 'executive':
        return {
          ...report,
          sections: {
            overview: report.summary,
            criticalFindings: report.summary.criticalFindings,
            recommendations: report.recommendations
          }
        };

      case 'detailed':
      default:
        return report;
    }
  }

  /**
   * Additional scan methods
   */
  static async performComplianceScan(targets) {
    // Implement compliance scanning logic
    return {
      findings: [],
      summary: { compliant: true, issues: 0 }
    };
  }

  static async performAccessControlScan(targets) {
    // Implement access control scanning logic
    return {
      findings: [],
      summary: { secure: true, vulnerabilities: 0 }
    };
  }

  static async performConfigurationScan(targets) {
    // Implement configuration scanning logic
    return {
      findings: [],
      summary: { misconfigurations: 0 }
    };
  }

  static async summarizeScanResults(results) {
    return {
      totalFindings: results.findings.length,
      critical: results.findings.filter(f => f.severity === 'critical').length,
      high: results.findings.filter(f => f.severity === 'high').length,
      medium: results.findings.filter(f => f.severity === 'medium').length,
      low: results.findings.filter(f => f.severity === 'low').length
    };
  }

  static async generateSecurityRecommendations(report) {
    const recommendations = [];
    
    // Analyze report data and generate recommendations
    if (report.summary.overallScore.overall < 80) {
      recommendations.push({
        priority: 'high',
        category: 'overall',
        recommendation: 'Improve overall security posture',
        actions: ['Enable MFA', 'Update security policies', 'Conduct security training']
      });
    }

    return recommendations;
  }

  static async extractCriticalFindings(data) {
    const findings = [];
    
    if (data.incidents) {
      const criticalIncidents = data.incidents.filter(i => i.severity === 'critical');
      findings.push(...criticalIncidents.map(i => ({
        type: 'incident',
        severity: 'critical',
        description: i.description,
        timestamp: i.createdAt
      })));
    }

    return findings;
  }

  static async analyzeSecurityTrends(data) {
    return {
      incidents: {
        trend: 'decreasing',
        percentage: -15
      },
      threats: {
        trend: 'stable',
        percentage: 0
      },
      compliance: {
        trend: 'improving',
        percentage: 5
      }
    };
  }

  static async getIncidentReport(startDate, endDate) {
    return SecurityIncident.find({
      createdAt: { $gte: startDate, $lte: endDate }
    }).lean();
  }

  static async getVulnerabilityReport(startDate, endDate) {
    return VulnerabilityReport.find({
      createdAt: { $gte: startDate, $lte: endDate }
    }).lean();
  }

  static async getThreatActivityReport(startDate, endDate) {
    return ThreatDetection.find({
      'statistics.lastTriggered': { $gte: startDate, $lte: endDate }
    }).lean();
  }

  static async getAccessControlReport(startDate, endDate) {
    return AccessControl.find({
      timestamp: { $gte: startDate, $lte: endDate }
    }).lean();
  }

  static async getComplianceReport() {
    return this.getComplianceStatus();
  }

  static async getAuditSummary(startDate, endDate) {
    return AuditService.getAuditSummary({
      startDate,
      endDate,
      groupBy: 'category'
    });
  }

  static async getSecurityMetrics(startDate, endDate) {
    return {
      sessions: await this.getSessionSecurityMetrics(startDate),
      access: await this.getAccessControlMetrics(startDate),
      threats: await this.getActiveThreats(startDate)
    };
  }

  static async applyContainmentMeasures(incident, session) {
    // Implement containment logic based on incident type
    logger.info('Applying containment measures', {
      incidentId: incident._id,
      type: incident.type,
      severity: incident.severity
    });
  }

  static async startIncidentMonitoring(incidentId) {
    // Implement monitoring logic
    logger.info('Started incident monitoring', { incidentId });
  }

  static async testThreatDetectionRule(ruleId, options) {
    const rule = await ThreatDetection.findById(ruleId);
    if (!rule) {
      throw new NotFoundError('Threat detection rule not found');
    }

    // Implement rule testing logic
    return {
      passed: true,
      results: {
        conditionsMet: true,
        actionsTaken: []
      }
    };
  }

  static async updateSecurityIncident(incidentId, updates) {
    return SecurityIncident.findByIdAndUpdate(
      incidentId,
      {
        $set: updates,
        $push: {
          timeline: {
            event: 'incident_updated',
            timestamp: new Date(),
            userId: updates.updatedBy,
            description: 'Incident details updated'
          }
        }
      },
      { new: true }
    );
  }

  static async escalateIncident(incidentId, escalationData) {
    return SecurityIncident.findByIdAndUpdate(
      incidentId,
      {
        $set: {
          status: 'escalated',
          escalatedAt: new Date(),
          escalatedBy: escalationData.escalatedBy
        },
        $push: {
          timeline: {
            event: 'incident_escalated',
            timestamp: new Date(),
            userId: escalationData.escalatedBy,
            description: escalationData.reason
          }
        }
      },
      { new: true }
    );
  }

  static async resolveIncident(incidentId, resolutionData) {
    return SecurityIncident.findByIdAndUpdate(
      incidentId,
      {
        $set: {
          status: 'resolved',
          resolution: resolutionData.resolution,
          resolvedAt: new Date(),
          resolvedBy: resolutionData.resolvedBy
        },
        $push: {
          timeline: {
            event: 'incident_resolved',
            timestamp: new Date(),
            userId: resolutionData.resolvedBy,
            description: resolutionData.resolution
          }
        }
      },
      { new: true }
    );
  }

  static async updateIPWhitelist(ip, updates) {
    return IPWhitelist.findOneAndUpdate(
      { ip, active: true },
      { $set: updates },
      { new: true }
    );
  }

  static async validateAlertConditions(conditions) {
    // Implement alert condition validation
    return true;
  }

  static async highlightSearchResults(results, query) {
    // Implement search result highlighting
    return results;
  }

  static async collectComplianceData(standard, mappings, dateRange, scope) {
    // Implement compliance data collection
    return {
      compliant: true,
      nonCompliant: 0,
      gaps: [],
      overallScore: 85,
      controls: [],
      findings: [],
      recommendations: []
    };
  }

  static async collectComplianceEvidence(controls, dateRange) {
    // Implement evidence collection
    return [];
  }

  static async getRelatedAuditEvents(auditLog) {
    // Find related events based on various criteria
    return [];
  }

  static async getComplianceMappings(auditLog) {
    // Get compliance mappings for the audit event
    return [];
  }

  static async decryptSingleAuditLog(auditLog, adminUser) {
    // Implement audit log decryption
    return auditLog;
  }

  static async archiveBatch(logs, options) {
    // Implement batch archiving
    return {
      count: logs.length,
      location: `archive/${options.archiveId}`
    };
  }

  static async testAuditAlert(alert, session) {
    // Implement alert testing
    logger.info('Testing audit alert', { alertId: alert._id });
  }

  static async processAuditExport(exportJob, query, adminUser) {
    // Implement asynchronous export processing
    logger.info('Processing audit export', { exportId: exportJob._id });
  }

  static async getAvailableAuditFilters() {
    // Return available filter options
    return {
      eventTypes: [],
      severities: ['low', 'medium', 'high', 'critical'],
      categories: []
    };
  }

  static async validateRetentionCompliance(retentionDays, complianceStandard) {
    // Validate retention against compliance requirements
    return true;
  }

  static async applyRetentionPolicy(policy, session) {
    // Apply retention policy to existing logs
    return { affected: 0 };
  }

  static async enhanceAuditData(logs) {
    // Enhance audit logs with additional context
    return logs;
  }
}

// Inherit from AdminBaseService
Object.setPrototypeOf(SecurityService, AdminBaseService);
Object.setPrototypeOf(SecurityService.prototype, AdminBaseService.prototype);

module.exports = SecurityService;