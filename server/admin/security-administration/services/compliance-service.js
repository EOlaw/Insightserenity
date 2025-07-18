// server/admin/security-administration/services/compliance-service.js
/**
 * @file Admin Compliance Service
 * @description Comprehensive compliance management service for administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const moment = require('moment');

// Core Models
const ComplianceStandard = require('../../../shared/security/models/compliance-standard-model');
const ComplianceAssessment = require('../../../shared/security/models/compliance-assessment-model');
const ComplianceControl = require('../../../shared/security/models/compliance-control-model');
const ComplianceEvidence = require('../../../shared/security/models/compliance-evidence-model');
const ComplianceGap = require('../../../shared/security/models/compliance-gap-model');
const ComplianceRemediation = require('../../../shared/security/models/compliance-remediation-model');
const ComplianceReport = require('../../../shared/security/models/compliance-report-model');
const ComplianceSchedule = require('../../../shared/security/models/compliance-schedule-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');
const Organization = require('../../../shared/organizations/models/organization-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('./audit-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const ExportService = require('../../../shared/admin/services/admin-export-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const StorageService = require('../../../shared/services/storage-service');

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
 * Admin Compliance Service Class
 * @class ComplianceService
 * @extends AdminBaseService
 */
class ComplianceService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'AdminComplianceService';
    this.cachePrefix = 'admin-compliance';
    this.auditCategory = 'COMPLIANCE_MANAGEMENT';
    this.requiredPermission = AdminPermissions.COMPLIANCE.VIEW;
  }

  /**
   * Get compliance overview across all standards
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Compliance overview
   */
  static async getComplianceOverview(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.VIEW);

      const {
        includeAssessments = true,
        includeGaps = true,
        includeSchedule = true,
        organizationId,
        timeRange = '90d'
      } = options;

      // Get cached overview if available
      const cacheKey = `${this.cachePrefix}:overview:${organizationId || 'global'}:${timeRange}`;
      const cached = await CacheService.get(cacheKey);
      if (cached) return cached;

      // Get active compliance standards
      const standards = await ComplianceStandard.find({ active: true }).lean();

      // Gather compliance data in parallel
      const [
        assessmentData,
        gapAnalysis,
        upcomingSchedule,
        complianceScores,
        remediationStatus
      ] = await Promise.all([
        includeAssessments ? this.getRecentAssessments(standards, organizationId, timeRange) : null,
        includeGaps ? this.getComplianceGaps(standards, organizationId) : null,
        includeSchedule ? this.getUpcomingComplianceEvents(organizationId) : null,
        this.calculateComplianceScores(standards, organizationId),
        this.getRemediationStatus(organizationId)
      ]);

      // Build overview
      const overview = {
        summary: {
          overallScore: this.calculateOverallScore(complianceScores),
          activeStandards: standards.length,
          openGaps: gapAnalysis?.totalGaps || 0,
          criticalGaps: gapAnalysis?.criticalGaps || 0,
          pendingRemediations: remediationStatus.pending,
          nextAssessment: upcomingSchedule?.[0]?.dueDate || null
        },
        standards: standards.map(standard => ({
          id: standard._id,
          name: standard.name,
          acronym: standard.acronym,
          score: complianceScores[standard._id] || 0,
          status: this.getComplianceStatus(complianceScores[standard._id]),
          lastAssessment: assessmentData?.byStandard[standard._id]?.lastAssessment,
          gaps: gapAnalysis?.byStandard[standard._id]?.count || 0
        })),
        assessments: assessmentData,
        gaps: gapAnalysis,
        schedule: upcomingSchedule,
        remediation: remediationStatus,
        lastUpdated: new Date()
      };

      // Cache overview
      await CacheService.set(cacheKey, overview, 300); // 5 minutes

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.OVERVIEW_VIEWED, {
        organizationId,
        overallScore: overview.summary.overallScore
      });

      return overview;

    } catch (error) {
      logger.error('Get compliance overview error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Manage compliance standards
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} standardData - Standard data
   * @returns {Promise<Object>} Management result
   */
  static async manageComplianceStandard(adminUser, standardData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.MANAGE);

      const {
        action,
        standardId,
        name,
        acronym,
        version,
        description,
        requirements,
        controls,
        categories,
        assessmentFrequency,
        enabled = true
      } = standardData;

      let standard;

      switch (action) {
        case 'create':
          // Check if standard already exists
          const existing = await ComplianceStandard.findOne({
            $or: [{ acronym }, { name }]
          }).session(session);

          if (existing) {
            throw new ValidationError('Compliance standard already exists');
          }

          standard = await ComplianceStandard.create([{
            name,
            acronym,
            version,
            description,
            requirements: requirements || [],
            categories: categories || [],
            assessmentFrequency,
            enabled,
            createdBy: adminUser.id,
            controlCount: 0,
            lastUpdated: new Date()
          }], { session });
          standard = standard[0];

          // Create associated controls if provided
          if (controls && controls.length > 0) {
            await this.createComplianceControls(standard._id, controls, adminUser.id, session);
            standard.controlCount = controls.length;
            await standard.save({ session });
          }
          break;

        case 'update':
          standard = await ComplianceStandard.findByIdAndUpdate(
            standardId,
            {
              $set: {
                name,
                version,
                description,
                requirements,
                categories,
                assessmentFrequency,
                enabled,
                lastUpdated: new Date(),
                updatedBy: adminUser.id
              }
            },
            { new: true, session }
          );

          if (!standard) {
            throw new NotFoundError('Compliance standard not found');
          }

          // Update controls if provided
          if (controls) {
            await this.updateComplianceControls(standardId, controls, adminUser.id, session);
          }
          break;

        case 'disable':
          standard = await ComplianceStandard.findByIdAndUpdate(
            standardId,
            {
              $set: {
                enabled: false,
                disabledAt: new Date(),
                disabledBy: adminUser.id
              }
            },
            { new: true, session }
          );
          break;

        case 'enable':
          standard = await ComplianceStandard.findByIdAndUpdate(
            standardId,
            {
              $set: {
                enabled: true,
                enabledAt: new Date(),
                enabledBy: adminUser.id
              },
              $unset: { disabledAt: 1 }
            },
            { new: true, session }
          );
          break;
      }

      // Clear compliance cache
      await this.clearComplianceCache();

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.STANDARD_MANAGED, {
        action,
        standardId: standard._id,
        standardName: standard.name,
        standardAcronym: standard.acronym
      }, { session });

      await session.commitTransaction();

      return {
        standard,
        action,
        message: `Compliance standard ${action}d successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage compliance standard error', {
        error: error.message,
        adminId: adminUser.id,
        standardData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Perform compliance assessment
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} assessmentData - Assessment data
   * @returns {Promise<Object>} Assessment result
   */
  static async performComplianceAssessment(adminUser, assessmentData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.ASSESS);

      const {
        standardId,
        organizationId,
        scope = 'full',
        controlResponses,
        evidence = [],
        notes
      } = assessmentData;

      // Validate standard
      const standard = await ComplianceStandard.findById(standardId).session(session);
      if (!standard || !standard.enabled) {
        throw new NotFoundError('Compliance standard not found or disabled');
      }

      // Get controls for the standard
      const controls = await ComplianceControl.find({
        standardId,
        active: true
      }).session(session);

      if (controls.length === 0) {
        throw new ValidationError('No controls found for this standard');
      }

      // Create assessment
      const assessment = await ComplianceAssessment.create([{
        standardId,
        organizationId,
        assessorId: adminUser.id,
        scope,
        status: 'in_progress',
        startDate: new Date(),
        controls: controls.map(control => ({
          controlId: control._id,
          status: 'pending',
          score: 0
        })),
        overallScore: 0,
        findings: [],
        gaps: []
      }], { session });
      const createdAssessment = assessment[0];

      // Process control responses
      const assessmentResults = await this.processControlResponses(
        createdAssessment,
        controlResponses,
        controls,
        session
      );

      // Store evidence
      if (evidence.length > 0) {
        await this.storeAssessmentEvidence(
          createdAssessment._id,
          evidence,
          adminUser.id,
          session
        );
      }

      // Identify gaps
      const gaps = await this.identifyComplianceGaps(
        createdAssessment,
        assessmentResults,
        standard,
        session
      );

      // Update assessment with results
      createdAssessment.controls = assessmentResults.controls;
      createdAssessment.overallScore = assessmentResults.overallScore;
      createdAssessment.findings = assessmentResults.findings;
      createdAssessment.gaps = gaps;
      createdAssessment.status = 'completed';
      createdAssessment.completionDate = new Date();
      createdAssessment.notes = notes;
      await createdAssessment.save({ session });

      // Create remediation plans for gaps
      if (gaps.length > 0) {
        await this.createRemediationPlans(gaps, createdAssessment._id, adminUser.id, session);
      }

      // Update organization compliance status
      await this.updateOrganizationCompliance(
        organizationId,
        standardId,
        assessmentResults.overallScore,
        session
      );

      // Clear relevant caches
      await this.clearComplianceCache(organizationId);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.ASSESSMENT_COMPLETED, {
        assessmentId: createdAssessment._id,
        standardId,
        standardName: standard.name,
        organizationId,
        overallScore: assessmentResults.overallScore,
        gapsIdentified: gaps.length
      }, { session });

      // Send notifications for critical gaps
      const criticalGaps = gaps.filter(gap => gap.severity === 'critical');
      if (criticalGaps.length > 0) {
        await NotificationService.notifyComplianceTeam({
          type: 'critical_gaps_identified',
          assessmentId: createdAssessment._id,
          standard: standard.name,
          criticalGaps: criticalGaps.length,
          organization: organizationId
        });
      }

      await session.commitTransaction();

      return {
        assessment: createdAssessment,
        summary: {
          overallScore: assessmentResults.overallScore,
          controlsPassed: assessmentResults.passed,
          controlsFailed: assessmentResults.failed,
          gapsIdentified: gaps.length,
          criticalGaps: criticalGaps.length
        },
        message: 'Compliance assessment completed successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Perform compliance assessment error', {
        error: error.message,
        adminId: adminUser.id,
        assessmentData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Manage compliance gaps
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} gapData - Gap management data
   * @returns {Promise<Object>} Gap management result
   */
  static async manageComplianceGap(adminUser, gapData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.MANAGE_GAPS);

      const {
        action,
        gapId,
        status,
        remediationPlan,
        targetDate,
        assignedTo,
        notes,
        evidence
      } = gapData;

      let gap;
      let result = {};

      switch (action) {
        case 'update':
          gap = await ComplianceGap.findById(gapId).session(session);
          if (!gap) {
            throw new NotFoundError('Compliance gap not found');
          }

          // Update gap status
          gap.status = status || gap.status;
          gap.targetDate = targetDate || gap.targetDate;
          gap.assignedTo = assignedTo || gap.assignedTo;
          gap.notes = notes ? [...gap.notes, { text: notes, createdBy: adminUser.id, createdAt: new Date() }] : gap.notes;
          gap.updatedAt = new Date();
          gap.updatedBy = adminUser.id;

          // Update remediation plan if provided
          if (remediationPlan) {
            const remediation = await ComplianceRemediation.findOne({
              gapId: gap._id
            }).session(session);

            if (remediation) {
              remediation.plan = remediationPlan.plan || remediation.plan;
              remediation.steps = remediationPlan.steps || remediation.steps;
              remediation.resources = remediationPlan.resources || remediation.resources;
              remediation.estimatedCost = remediationPlan.estimatedCost || remediation.estimatedCost;
              remediation.updatedAt = new Date();
              remediation.updatedBy = adminUser.id;
              await remediation.save({ session });
              result.remediation = remediation;
            }
          }

          await gap.save({ session });
          break;

        case 'close':
          gap = await ComplianceGap.findById(gapId).session(session);
          if (!gap) {
            throw new NotFoundError('Compliance gap not found');
          }

          if (!evidence || evidence.length === 0) {
            throw new ValidationError('Evidence required to close compliance gap');
          }

          // Store closing evidence
          await this.storeGapEvidence(gapId, evidence, adminUser.id, session);

          // Close the gap
          gap.status = 'closed';
          gap.closedDate = new Date();
          gap.closedBy = adminUser.id;
          gap.closureNotes = notes;
          await gap.save({ session });

          // Update remediation status
          await ComplianceRemediation.findOneAndUpdate(
            { gapId: gap._id },
            {
              $set: {
                status: 'completed',
                completionDate: new Date(),
                completedBy: adminUser.id
              }
            },
            { session }
          );
          break;

        case 'reopen':
          gap = await ComplianceGap.findById(gapId).session(session);
          if (!gap) {
            throw new NotFoundError('Compliance gap not found');
          }

          gap.status = 'open';
          gap.reopenedDate = new Date();
          gap.reopenedBy = adminUser.id;
          gap.reopenReason = notes;
          gap.closedDate = null;
          gap.closedBy = null;
          await gap.save({ session });
          break;

        case 'escalate':
          gap = await ComplianceGap.findById(gapId).session(session);
          if (!gap) {
            throw new NotFoundError('Compliance gap not found');
          }

          gap.severity = this.escalateSeverity(gap.severity);
          gap.escalated = true;
          gap.escalatedDate = new Date();
          gap.escalatedBy = adminUser.id;
          gap.escalationReason = notes;
          await gap.save({ session });

          // Notify compliance team
          await NotificationService.notifyComplianceTeam({
            type: 'gap_escalated',
            gapId: gap._id,
            severity: gap.severity,
            reason: notes
          });
          break;
      }

      // Clear gap cache
      await CacheService.delete(`${this.cachePrefix}:gaps:${gap.organizationId}`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.GAP_MANAGED, {
        action,
        gapId: gap._id,
        status: gap.status,
        severity: gap.severity
      }, { session });

      await session.commitTransaction();

      return {
        gap,
        remediation: result.remediation,
        action,
        message: `Compliance gap ${action}d successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage compliance gap error', {
        error: error.message,
        adminId: adminUser.id,
        gapData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Generate compliance report
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} reportOptions - Report options
   * @returns {Promise<Object>} Compliance report
   */
  static async generateComplianceReport(adminUser, reportOptions = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.GENERATE_REPORTS);

      const {
        reportType = 'comprehensive',
        standardId,
        organizationId,
        dateFrom,
        dateTo,
        includeEvidence = false,
        format = 'detailed'
      } = reportOptions;

      // Validate inputs
      if (reportType === 'standard' && !standardId) {
        throw new ValidationError('Standard ID required for standard-specific report');
      }

      const dateRange = {
        start: dateFrom ? new Date(dateFrom) : new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
        end: dateTo ? new Date(dateTo) : new Date()
      };

      // Gather report data based on type
      let reportData;
      switch (reportType) {
        case 'comprehensive':
          reportData = await this.gatherComprehensiveReportData(organizationId, dateRange);
          break;
        case 'standard':
          reportData = await this.gatherStandardReportData(standardId, organizationId, dateRange);
          break;
        case 'gap':
          reportData = await this.gatherGapReportData(organizationId, dateRange);
          break;
        case 'remediation':
          reportData = await this.gatherRemediationReportData(organizationId, dateRange);
          break;
        case 'executive':
          reportData = await this.gatherExecutiveReportData(organizationId, dateRange);
          break;
        default:
          throw new ValidationError('Invalid report type');
      }

      // Include evidence if requested
      if (includeEvidence) {
        reportData.evidence = await this.gatherReportEvidence(reportData, dateRange);
      }

      // Create report record
      const report = await ComplianceReport.create({
        type: reportType,
        standardId,
        organizationId,
        generatedBy: adminUser.id,
        dateRange,
        data: reportData,
        format,
        status: 'completed'
      });

      // Format report based on requested format
      const formattedReport = await this.formatComplianceReport(report, format);

      // Generate export file if needed
      if (reportOptions.export) {
        const exportResult = await ExportService.exportData({
          data: formattedReport,
          format: reportOptions.exportFormat || 'pdf',
          filename: `compliance-report-${report._id}`,
          template: 'compliance-report'
        });
        formattedReport.exportUrl = exportResult.url;
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.REPORT_GENERATED, {
        reportId: report._id,
        reportType,
        standardId,
        organizationId,
        dateRange
      });

      return {
        report: formattedReport,
        metadata: {
          id: report._id,
          generatedAt: report.createdAt,
          type: reportType,
          dateRange
        }
      };

    } catch (error) {
      logger.error('Generate compliance report error', {
        error: error.message,
        adminId: adminUser.id,
        reportOptions,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Schedule compliance activities
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} scheduleData - Schedule data
   * @returns {Promise<Object>} Schedule result
   */
  static async scheduleComplianceActivity(adminUser, scheduleData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.SCHEDULE);

      const {
        activityType,
        standardId,
        organizationId,
        scheduledDate,
        recurrence,
        assignedTo,
        description,
        reminders = true
      } = scheduleData;

      // Validate activity type
      const validActivityTypes = ['assessment', 'audit', 'review', 'training', 'certification'];
      if (!validActivityTypes.includes(activityType)) {
        throw new ValidationError('Invalid activity type');
      }

      // Create schedule entry
      const schedule = await ComplianceSchedule.create([{
        activityType,
        standardId,
        organizationId,
        scheduledDate: new Date(scheduledDate),
        recurrence,
        assignedTo,
        description,
        reminders,
        status: 'scheduled',
        createdBy: adminUser.id
      }], { session });

      const createdSchedule = schedule[0];

      // Set up recurrence if specified
      if (recurrence && recurrence.enabled) {
        await this.setupRecurrence(createdSchedule, recurrence, session);
      }

      // Set up reminders if enabled
      if (reminders) {
        await this.setupComplianceReminders(createdSchedule, session);
      }

      // Clear schedule cache
      await CacheService.delete(`${this.cachePrefix}:schedule:${organizationId}`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.ACTIVITY_SCHEDULED, {
        scheduleId: createdSchedule._id,
        activityType,
        standardId,
        organizationId,
        scheduledDate
      }, { session });

      // Send notification to assigned user
      if (assignedTo) {
        await NotificationService.sendNotification({
          userId: assignedTo,
          type: 'compliance_activity_assigned',
          data: {
            activityType,
            scheduledDate,
            description
          }
        });
      }

      await session.commitTransaction();

      return {
        schedule: createdSchedule,
        message: 'Compliance activity scheduled successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Schedule compliance activity error', {
        error: error.message,
        adminId: adminUser.id,
        scheduleData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Manage compliance evidence
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} evidenceData - Evidence data
   * @returns {Promise<Object>} Evidence management result
   */
  static async manageComplianceEvidence(adminUser, evidenceData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.MANAGE_EVIDENCE);

      const {
        action,
        evidenceId,
        type,
        relatedTo,
        relatedId,
        title,
        description,
        files = [],
        metadata = {},
        tags = []
      } = evidenceData;

      let evidence;

      switch (action) {
        case 'upload':
          // Process and store files
          const storedFiles = await this.processEvidenceFiles(files, adminUser.id);

          evidence = await ComplianceEvidence.create([{
            type,
            relatedTo,
            relatedId,
            title,
            description,
            files: storedFiles,
            metadata,
            tags,
            uploadedBy: adminUser.id,
            status: 'active'
          }], { session });
          evidence = evidence[0];
          break;

        case 'update':
          evidence = await ComplianceEvidence.findById(evidenceId).session(session);
          if (!evidence) {
            throw new NotFoundError('Evidence not found');
          }

          evidence.title = title || evidence.title;
          evidence.description = description || evidence.description;
          evidence.metadata = { ...evidence.metadata, ...metadata };
          evidence.tags = tags || evidence.tags;
          evidence.updatedAt = new Date();
          evidence.updatedBy = adminUser.id;
          await evidence.save({ session });
          break;

        case 'verify':
          evidence = await ComplianceEvidence.findById(evidenceId).session(session);
          if (!evidence) {
            throw new NotFoundError('Evidence not found');
          }

          evidence.verified = true;
          evidence.verifiedBy = adminUser.id;
          evidence.verifiedAt = new Date();
          evidence.verificationNotes = evidenceData.notes;
          await evidence.save({ session });
          break;

        case 'archive':
          evidence = await ComplianceEvidence.findById(evidenceId).session(session);
          if (!evidence) {
            throw new NotFoundError('Evidence not found');
          }

          evidence.status = 'archived';
          evidence.archivedBy = adminUser.id;
          evidence.archivedAt = new Date();
          await evidence.save({ session });
          break;
      }

      // Clear evidence cache
      await CacheService.delete(`${this.cachePrefix}:evidence:${evidence.relatedId}`);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.EVIDENCE_MANAGED, {
        action,
        evidenceId: evidence._id,
        type: evidence.type,
        relatedTo: evidence.relatedTo,
        relatedId: evidence.relatedId
      }, { session });

      await session.commitTransaction();

      return {
        evidence,
        action,
        message: `Evidence ${action}ed successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Manage compliance evidence error', {
        error: error.message,
        adminId: adminUser.id,
        evidenceData,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get compliance dashboard data
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Dashboard options
   * @returns {Promise<Object>} Dashboard data
   */
  static async getComplianceDashboard(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.COMPLIANCE.VIEW);

      const {
        organizationId,
        timeRange = '30d',
        standardId
      } = options;

      // Get dashboard data
      const [
        scoresTrend,
        assessmentMetrics,
        gapMetrics,
        remediationMetrics,
        upcomingActivities,
        recentChanges
      ] = await Promise.all([
        this.getComplianceScoresTrend(organizationId, timeRange, standardId),
        this.getAssessmentMetrics(organizationId, timeRange),
        this.getGapMetrics(organizationId, standardId),
        this.getRemediationMetrics(organizationId),
        this.getUpcomingActivities(organizationId, 10),
        this.getRecentComplianceChanges(organizationId, 10)
      ]);

      const dashboard = {
        scores: scoresTrend,
        assessments: assessmentMetrics,
        gaps: gapMetrics,
        remediation: remediationMetrics,
        activities: upcomingActivities,
        recentChanges,
        generated: new Date()
      };

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.COMPLIANCE.DASHBOARD_VIEWED, {
        organizationId,
        timeRange,
        standardId
      });

      return dashboard;

    } catch (error) {
      logger.error('Get compliance dashboard error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  // ========== Private Helper Methods ==========

  /**
   * Get recent assessments
   * @param {Array} standards - Compliance standards
   * @param {string} organizationId - Organization ID
   * @param {string} timeRange - Time range
   * @returns {Promise<Object>} Assessment data
   * @private
   */
  static async getRecentAssessments(standards, organizationId, timeRange) {
    const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));
    const query = {
      status: 'completed',
      completionDate: { $gte: startDate }
    };

    if (organizationId) {
      query.organizationId = organizationId;
    }

    const assessments = await ComplianceAssessment.find(query)
      .populate('standardId', 'name acronym')
      .sort({ completionDate: -1 })
      .lean();

    const byStandard = {};
    standards.forEach(standard => {
      const standardAssessments = assessments.filter(
        a => a.standardId?._id.toString() === standard._id.toString()
      );
      
      byStandard[standard._id] = {
        count: standardAssessments.length,
        lastAssessment: standardAssessments[0]?.completionDate || null,
        avgScore: standardAssessments.length > 0
          ? Math.round(standardAssessments.reduce((sum, a) => sum + a.overallScore, 0) / standardAssessments.length)
          : 0
      };
    });

    return {
      total: assessments.length,
      byStandard
    };
  }

  /**
   * Get compliance gaps
   * @param {Array} standards - Compliance standards
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Gap analysis
   * @private
   */
  static async getComplianceGaps(standards, organizationId) {
    const query = {
      status: { $in: ['open', 'in_progress'] }
    };

    if (organizationId) {
      query.organizationId = organizationId;
    }

    const gaps = await ComplianceGap.find(query)
      .populate('standardId', 'name acronym')
      .lean();

    const byStandard = {};
    let totalGaps = 0;
    let criticalGaps = 0;

    standards.forEach(standard => {
      const standardGaps = gaps.filter(
        g => g.standardId?._id.toString() === standard._id.toString()
      );
      
      byStandard[standard._id] = {
        count: standardGaps.length,
        critical: standardGaps.filter(g => g.severity === 'critical').length,
        high: standardGaps.filter(g => g.severity === 'high').length,
        medium: standardGaps.filter(g => g.severity === 'medium').length,
        low: standardGaps.filter(g => g.severity === 'low').length
      };

      totalGaps += standardGaps.length;
      criticalGaps += byStandard[standard._id].critical;
    });

    return {
      totalGaps,
      criticalGaps,
      byStandard
    };
  }

  /**
   * Get upcoming compliance events
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Array>} Upcoming events
   * @private
   */
  static async getUpcomingComplianceEvents(organizationId) {
    const query = {
      scheduledDate: { $gte: new Date() },
      status: { $in: ['scheduled', 'pending'] }
    };

    if (organizationId) {
      query.organizationId = organizationId;
    }

    return ComplianceSchedule.find(query)
      .populate('standardId', 'name acronym')
      .populate('assignedTo', 'email profile.firstName profile.lastName')
      .sort({ scheduledDate: 1 })
      .limit(10)
      .lean();
  }

  /**
   * Calculate compliance scores
   * @param {Array} standards - Compliance standards
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Compliance scores
   * @private
   */
  static async calculateComplianceScores(standards, organizationId) {
    const scores = {};

    for (const standard of standards) {
      const latestAssessment = await ComplianceAssessment.findOne({
        standardId: standard._id,
        organizationId,
        status: 'completed'
      })
        .sort({ completionDate: -1 })
        .select('overallScore')
        .lean();

      scores[standard._id] = latestAssessment?.overallScore || 0;
    }

    return scores;
  }

  /**
   * Get remediation status
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Remediation status
   * @private
   */
  static async getRemediationStatus(organizationId) {
    const query = {};
    if (organizationId) {
      query.organizationId = organizationId;
    }

    const [
      total,
      pending,
      inProgress,
      completed,
      overdue
    ] = await Promise.all([
      ComplianceRemediation.countDocuments(query),
      ComplianceRemediation.countDocuments({ ...query, status: 'pending' }),
      ComplianceRemediation.countDocuments({ ...query, status: 'in_progress' }),
      ComplianceRemediation.countDocuments({ ...query, status: 'completed' }),
      ComplianceRemediation.countDocuments({
        ...query,
        status: { $nin: ['completed', 'cancelled'] },
        targetDate: { $lt: new Date() }
      })
    ]);

    return {
      total,
      pending,
      inProgress,
      completed,
      overdue,
      completionRate: total > 0 ? Math.round((completed / total) * 100) : 0
    };
  }

  /**
   * Calculate overall compliance score
   * @param {Object} scores - Individual standard scores
   * @returns {number} Overall score
   * @private
   */
  static calculateOverallScore(scores) {
    const scoreValues = Object.values(scores);
    if (scoreValues.length === 0) return 0;
    
    const sum = scoreValues.reduce((acc, score) => acc + score, 0);
    return Math.round(sum / scoreValues.length);
  }

  /**
   * Get compliance status from score
   * @param {number} score - Compliance score
   * @returns {string} Status
   * @private
   */
  static getComplianceStatus(score) {
    if (score >= 90) return 'excellent';
    if (score >= 80) return 'good';
    if (score >= 70) return 'satisfactory';
    if (score >= 60) return 'needs_improvement';
    return 'non_compliant';
  }

  /**
   * Create compliance controls
   * @param {string} standardId - Standard ID
   * @param {Array} controls - Control data
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @returns {Promise<Array>} Created controls
   * @private
   */
  static async createComplianceControls(standardId, controls, userId, session) {
    const controlDocs = controls.map(control => ({
      standardId,
      controlId: control.controlId,
      title: control.title,
      description: control.description,
      category: control.category,
      requirements: control.requirements || [],
      testingProcedures: control.testingProcedures || [],
      implementationGuidance: control.implementationGuidance,
      severity: control.severity || 'medium',
      active: true,
      createdBy: userId
    }));

    return ComplianceControl.create(controlDocs, { session });
  }

  /**
   * Update compliance controls
   * @param {string} standardId - Standard ID
   * @param {Array} controls - Control updates
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @private
   */
  static async updateComplianceControls(standardId, controls, userId, session) {
    for (const control of controls) {
      if (control._id) {
        // Update existing control
        await ComplianceControl.findByIdAndUpdate(
          control._id,
          {
            $set: {
              title: control.title,
              description: control.description,
              category: control.category,
              requirements: control.requirements,
              testingProcedures: control.testingProcedures,
              implementationGuidance: control.implementationGuidance,
              severity: control.severity,
              updatedBy: userId,
              updatedAt: new Date()
            }
          },
          { session }
        );
      } else {
        // Create new control
        await ComplianceControl.create([{
          standardId,
          ...control,
          active: true,
          createdBy: userId
        }], { session });
      }
    }
  }

  /**
   * Process control responses
   * @param {Object} assessment - Assessment document
   * @param {Array} responses - Control responses
   * @param {Array} controls - Control definitions
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Assessment results
   * @private
   */
  static async processControlResponses(assessment, responses, controls, session) {
    const results = {
      controls: [],
      findings: [],
      passed: 0,
      failed: 0,
      overallScore: 0
    };

    for (const control of controls) {
      const response = responses.find(r => r.controlId === control._id.toString());
      
      if (!response) {
        results.controls.push({
          controlId: control._id,
          status: 'not_assessed',
          score: 0
        });
        continue;
      }

      const controlResult = {
        controlId: control._id,
        status: response.status,
        score: response.score || 0,
        evidence: response.evidence || [],
        notes: response.notes,
        assessedAt: new Date()
      };

      // Determine pass/fail
      if (response.status === 'passed' || response.score >= 80) {
        controlResult.status = 'passed';
        results.passed++;
      } else {
        controlResult.status = 'failed';
        results.failed++;
        
        // Create finding for failed control
        results.findings.push({
          controlId: control._id,
          title: `Failed: ${control.title}`,
          description: response.notes || 'Control assessment failed',
          severity: control.severity,
          recommendation: control.implementationGuidance
        });
      }

      results.controls.push(controlResult);
    }

    // Calculate overall score
    const totalControls = results.passed + results.failed;
    results.overallScore = totalControls > 0 
      ? Math.round((results.passed / totalControls) * 100)
      : 0;

    return results;
  }

  /**
   * Store assessment evidence
   * @param {string} assessmentId - Assessment ID
   * @param {Array} evidence - Evidence data
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @private
   */
  static async storeAssessmentEvidence(assessmentId, evidence, userId, session) {
    const evidenceDocs = evidence.map(item => ({
      type: 'assessment',
      relatedTo: 'assessment',
      relatedId: assessmentId,
      title: item.title,
      description: item.description,
      files: item.files || [],
      metadata: item.metadata || {},
      uploadedBy: userId,
      status: 'active'
    }));

    return ComplianceEvidence.create(evidenceDocs, { session });
  }

  /**
   * Identify compliance gaps
   * @param {Object} assessment - Assessment document
   * @param {Object} results - Assessment results
   * @param {Object} standard - Compliance standard
   * @param {Object} session - Database session
   * @returns {Promise<Array>} Identified gaps
   * @private
   */
  static async identifyComplianceGaps(assessment, results, standard, session) {
    const gaps = [];

    for (const finding of results.findings) {
      const control = await ComplianceControl.findById(finding.controlId).session(session);
      
      const gap = await ComplianceGap.create([{
        assessmentId: assessment._id,
        standardId: standard._id,
        organizationId: assessment.organizationId,
        controlId: finding.controlId,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        category: control?.category,
        requirements: control?.requirements || [],
        currentState: 'non_compliant',
        targetState: 'compliant',
        status: 'open',
        identifiedBy: assessment.assessorId,
        identifiedDate: new Date()
      }], { session });

      gaps.push(gap[0]);
    }

    return gaps;
  }

  /**
   * Create remediation plans
   * @param {Array} gaps - Compliance gaps
   * @param {string} assessmentId - Assessment ID
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @private
   */
  static async createRemediationPlans(gaps, assessmentId, userId, session) {
    const remediationPlans = gaps.map(gap => ({
      gapId: gap._id,
      assessmentId,
      organizationId: gap.organizationId,
      title: `Remediation for: ${gap.title}`,
      description: `Remediation plan to address ${gap.description}`,
      priority: this.getPriorityFromSeverity(gap.severity),
      status: 'pending',
      targetDate: new Date(Date.now() + this.getRemediationTimeframe(gap.severity)),
      createdBy: userId
    }));

    return ComplianceRemediation.create(remediationPlans, { session });
  }

  /**
   * Update organization compliance
   * @param {string} organizationId - Organization ID
   * @param {string} standardId - Standard ID
   * @param {number} score - Compliance score
   * @param {Object} session - Database session
   * @private
   */
  static async updateOrganizationCompliance(organizationId, standardId, score, session) {
    const standard = await ComplianceStandard.findById(standardId).session(session);
    
    await Organization.findByIdAndUpdate(
      organizationId,
      {
        $set: {
          [`compliance.${standard.acronym}`]: {
            score,
            lastAssessment: new Date(),
            status: this.getComplianceStatus(score)
          }
        }
      },
      { session }
    );
  }

  /**
   * Clear compliance cache
   * @param {string} organizationId - Organization ID
   * @private
   */
  static async clearComplianceCache(organizationId = null) {
    const patterns = [
      `${this.cachePrefix}:overview:*`,
      `${this.cachePrefix}:scores:*`,
      `${this.cachePrefix}:gaps:*`,
      `${this.cachePrefix}:schedule:*`
    ];

    if (organizationId) {
      patterns.push(`${this.cachePrefix}:*:${organizationId}:*`);
    }

    await Promise.all(patterns.map(pattern => CacheService.deletePattern(pattern)));
  }

  /**
   * Setup recurrence for scheduled activity
   * @param {Object} schedule - Schedule document
   * @param {Object} recurrence - Recurrence settings
   * @param {Object} session - Database session
   * @private
   */
  static async setupRecurrence(schedule, recurrence, session) {
    const { frequency, interval, endDate } = recurrence;
    
    // Calculate next occurrence dates
    const occurrences = [];
    let currentDate = moment(schedule.scheduledDate);
    const end = endDate ? moment(endDate) : moment().add(1, 'year');

    while (currentDate.isBefore(end) && occurrences.length < 50) {
      currentDate.add(interval || 1, frequency);
      if (currentDate.isBefore(end)) {
        occurrences.push(currentDate.toDate());
      }
    }

    // Create future schedule entries
    const futureSchedules = occurrences.map(date => ({
      ...schedule.toObject(),
      _id: undefined,
      scheduledDate: date,
      parentScheduleId: schedule._id,
      status: 'scheduled'
    }));

    if (futureSchedules.length > 0) {
      await ComplianceSchedule.create(futureSchedules, { session });
    }
  }

  /**
   * Setup compliance reminders
   * @param {Object} schedule - Schedule document
   * @param {Object} session - Database session
   * @private
   */
  static async setupComplianceReminders(schedule, session) {
    const reminderDates = [
      { days: 30, type: 'month_before' },
      { days: 7, type: 'week_before' },
      { days: 1, type: 'day_before' }
    ];

    for (const reminder of reminderDates) {
      const reminderDate = moment(schedule.scheduledDate).subtract(reminder.days, 'days');
      
      if (reminderDate.isAfter(moment())) {
        // Schedule reminder notification
        await NotificationService.scheduleNotification({
          type: 'compliance_reminder',
          scheduledFor: reminderDate.toDate(),
          recipients: schedule.assignedTo ? [schedule.assignedTo] : [],
          data: {
            scheduleId: schedule._id,
            activityType: schedule.activityType,
            scheduledDate: schedule.scheduledDate,
            reminderType: reminder.type
          }
        });
      }
    }
  }

  /**
   * Escalate severity level
   * @param {string} currentSeverity - Current severity
   * @returns {string} Escalated severity
   * @private
   */
  static escalateSeverity(currentSeverity) {
    const severityLevels = ['low', 'medium', 'high', 'critical'];
    const currentIndex = severityLevels.indexOf(currentSeverity);
    
    if (currentIndex < severityLevels.length - 1) {
      return severityLevels[currentIndex + 1];
    }
    return currentSeverity;
  }

  /**
   * Get priority from severity
   * @param {string} severity - Severity level
   * @returns {string} Priority level
   * @private
   */
  static getPriorityFromSeverity(severity) {
    const mapping = {
      critical: 'urgent',
      high: 'high',
      medium: 'medium',
      low: 'low'
    };
    return mapping[severity] || 'medium';
  }

  /**
   * Get remediation timeframe
   * @param {string} severity - Severity level
   * @returns {number} Timeframe in milliseconds
   * @private
   */
  static getRemediationTimeframe(severity) {
    const timeframes = {
      critical: 7 * 24 * 60 * 60 * 1000,    // 7 days
      high: 30 * 24 * 60 * 60 * 1000,       // 30 days
      medium: 60 * 24 * 60 * 60 * 1000,     // 60 days
      low: 90 * 24 * 60 * 60 * 1000         // 90 days
    };
    return timeframes[severity] || timeframes.medium;
  }

  /**
   * Store gap evidence
   * @param {string} gapId - Gap ID
   * @param {Array} evidence - Evidence data
   * @param {string} userId - User ID
   * @param {Object} session - Database session
   * @private
   */
  static async storeGapEvidence(gapId, evidence, userId, session) {
    const evidenceDocs = evidence.map(item => ({
      type: 'gap_closure',
      relatedTo: 'gap',
      relatedId: gapId,
      title: item.title,
      description: item.description,
      files: item.files || [],
      metadata: item.metadata || {},
      uploadedBy: userId,
      status: 'active'
    }));

    return ComplianceEvidence.create(evidenceDocs, { session });
  }

  /**
   * Process evidence files
   * @param {Array} files - File data
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Stored file references
   * @private
   */
  static async processEvidenceFiles(files, userId) {
    const storedFiles = [];

    for (const file of files) {
      const stored = await StorageService.uploadFile({
        file: file.buffer,
        filename: file.originalname,
        mimetype: file.mimetype,
        path: `compliance/evidence/${userId}`,
        metadata: {
          uploadedBy: userId,
          uploadedAt: new Date()
        }
      });

      storedFiles.push({
        filename: file.originalname,
        url: stored.url,
        size: file.size,
        mimetype: file.mimetype,
        uploadedAt: new Date()
      });
    }

    return storedFiles;
  }

  /**
   * Gather comprehensive report data
   * @param {string} organizationId - Organization ID
   * @param {Object} dateRange - Date range
   * @returns {Promise<Object>} Report data
   * @private
   */
  static async gatherComprehensiveReportData(organizationId, dateRange) {
    const standards = await ComplianceStandard.find({ active: true }).lean();
    const reportData = {
      standards: [],
      overallCompliance: 0,
      trends: [],
      gaps: [],
      remediations: []
    };

    for (const standard of standards) {
      const standardData = await this.gatherStandardReportData(
        standard._id,
        organizationId,
        dateRange
      );
      reportData.standards.push({
        ...standard,
        ...standardData
      });
    }

    // Calculate overall compliance
    const scores = reportData.standards.map(s => s.currentScore || 0);
    reportData.overallCompliance = scores.length > 0
      ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
      : 0;

    // Get trends
    reportData.trends = await this.getComplianceScoresTrend(
      organizationId,
      '365d',
      null
    );

    // Get all gaps
    reportData.gaps = await ComplianceGap.find({
      organizationId,
      status: { $in: ['open', 'in_progress'] }
    })
      .populate('standardId', 'name acronym')
      .sort({ severity: 1, identifiedDate: -1 })
      .lean();

    // Get remediation summary
    reportData.remediations = await this.getRemediationStatus(organizationId);

    return reportData;
  }

  /**
   * Gather standard-specific report data
   * @param {string} standardId - Standard ID
   * @param {string} organizationId - Organization ID
   * @param {Object} dateRange - Date range
   * @returns {Promise<Object>} Standard report data
   * @private
   */
  static async gatherStandardReportData(standardId, organizationId, dateRange) {
    const [
      assessments,
      gaps,
      controls,
      evidence,
      remediations
    ] = await Promise.all([
      ComplianceAssessment.find({
        standardId,
        organizationId,
        completionDate: { $gte: dateRange.start, $lte: dateRange.end }
      }).sort({ completionDate: -1 }).lean(),
      
      ComplianceGap.find({
        standardId,
        organizationId
      }).lean(),
      
      ComplianceControl.find({
        standardId,
        active: true
      }).lean(),
      
      ComplianceEvidence.find({
        relatedTo: 'assessment',
        relatedId: { $in: assessments.map(a => a._id) }
      }).lean(),
      
      ComplianceRemediation.find({
        organizationId,
        gapId: { $in: gaps.map(g => g._id) }
      }).lean()
    ]);

    const latestAssessment = assessments[0];

    return {
      currentScore: latestAssessment?.overallScore || 0,
      lastAssessmentDate: latestAssessment?.completionDate,
      assessmentCount: assessments.length,
      controlsTotal: controls.length,
      controlsPassed: latestAssessment?.controls.filter(c => c.status === 'passed').length || 0,
      gapsOpen: gaps.filter(g => g.status === 'open').length,
      gapsClosed: gaps.filter(g => g.status === 'closed').length,
      evidenceCount: evidence.length,
      remediationProgress: this.calculateRemediationProgress(remediations)
    };
  }

  /**
   * Gather gap report data
   * @param {string} organizationId - Organization ID
   * @param {Object} dateRange - Date range
   * @returns {Promise<Object>} Gap report data
   * @private
   */
  static async gatherGapReportData(organizationId, dateRange) {
    const gaps = await ComplianceGap.find({
      organizationId,
      identifiedDate: { $gte: dateRange.start, $lte: dateRange.end }
    })
      .populate('standardId', 'name acronym')
      .populate('controlId', 'title category')
      .populate('identifiedBy', 'email profile.firstName profile.lastName')
      .sort({ severity: 1, identifiedDate: -1 })
      .lean();

    const remediations = await ComplianceRemediation.find({
      gapId: { $in: gaps.map(g => g._id) }
    }).lean();

    return {
      gaps: gaps.map(gap => ({
        ...gap,
        remediation: remediations.find(r => r.gapId.toString() === gap._id.toString()),
        age: Math.floor((Date.now() - gap.identifiedDate) / (24 * 60 * 60 * 1000))
      })),
      summary: {
        total: gaps.length,
        bySeverity: this.groupBySeverity(gaps),
        byStatus: this.groupByStatus(gaps),
        avgAge: this.calculateAverageAge(gaps)
      }
    };
  }

  /**
   * Gather remediation report data
   * @param {string} organizationId - Organization ID
   * @param {Object} dateRange - Date range
   * @returns {Promise<Object>} Remediation report data
   * @private
   */
  static async gatherRemediationReportData(organizationId, dateRange) {
    const remediations = await ComplianceRemediation.find({
      organizationId,
      createdAt: { $gte: dateRange.start, $lte: dateRange.end }
    })
      .populate('gapId')
      .populate('assignedTo', 'email profile.firstName profile.lastName')
      .sort({ priority: 1, targetDate: 1 })
      .lean();

    return {
      remediations: remediations.map(rem => ({
        ...rem,
        daysUntilDue: Math.floor((rem.targetDate - Date.now()) / (24 * 60 * 60 * 1000)),
        isOverdue: rem.targetDate < new Date() && rem.status !== 'completed'
      })),
      summary: {
        total: remediations.length,
        completed: remediations.filter(r => r.status === 'completed').length,
        inProgress: remediations.filter(r => r.status === 'in_progress').length,
        overdue: remediations.filter(r => r.targetDate < new Date() && r.status !== 'completed').length,
        completionRate: this.calculateCompletionRate(remediations)
      }
    };
  }

  /**
   * Gather executive report data
   * @param {string} organizationId - Organization ID
   * @param {Object} dateRange - Date range
   * @returns {Promise<Object>} Executive report data
   * @private
   */
  static async gatherExecutiveReportData(organizationId, dateRange) {
    const overview = await this.getComplianceOverview(
      { role: 'system' }, // System context
      { organizationId, includeAssessments: true, includeGaps: true }
    );

    const trends = await this.getComplianceScoresTrend(organizationId, '365d');
    const risks = await this.assessComplianceRisks(organizationId);
    const recommendations = await this.generateComplianceRecommendations(organizationId);

    return {
      executiveSummary: {
        overallCompliance: overview.summary.overallScore,
        complianceStatus: this.getComplianceStatus(overview.summary.overallScore),
        activeStandards: overview.summary.activeStandards,
        criticalGaps: overview.summary.criticalGaps,
        keyRisks: risks.slice(0, 5),
        topRecommendations: recommendations.slice(0, 5)
      },
      trends,
      standards: overview.standards,
      riskMatrix: this.generateRiskMatrix(risks),
      recommendations
    };
  }

  /**
   * Gather report evidence
   * @param {Object} reportData - Report data
   * @param {Object} dateRange - Date range
   * @returns {Promise<Array>} Evidence data
   * @private
   */
  static async gatherReportEvidence(reportData, dateRange) {
    // Implementation depends on report type
    return [];
  }

  /**
   * Format compliance report
   * @param {Object} report - Report document
   * @param {string} format - Output format
   * @returns {Promise<Object>} Formatted report
   * @private
   */
  static async formatComplianceReport(report, format) {
    switch (format) {
      case 'summary':
        return {
          id: report._id,
          type: report.type,
          generatedAt: report.createdAt,
          summary: report.data.summary || report.data.executiveSummary
        };

      case 'detailed':
        return report.data;

      case 'executive':
        return {
          ...report.data.executiveSummary,
          trends: report.data.trends,
          recommendations: report.data.recommendations
        };

      default:
        return report.data;
    }
  }

  /**
   * Get compliance scores trend
   * @param {string} organizationId - Organization ID
   * @param {string} timeRange - Time range
   * @param {string} standardId - Standard ID
   * @returns {Promise<Array>} Scores trend
   * @private
   */
  static async getComplianceScoresTrend(organizationId, timeRange, standardId = null) {
    const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));
    const query = {
      organizationId,
      status: 'completed',
      completionDate: { $gte: startDate }
    };

    if (standardId) {
      query.standardId = standardId;
    }

    const assessments = await ComplianceAssessment.find(query)
      .select('standardId overallScore completionDate')
      .populate('standardId', 'acronym')
      .sort({ completionDate: 1 })
      .lean();

    // Group by month
    const trendData = {};
    assessments.forEach(assessment => {
      const month = moment(assessment.completionDate).format('YYYY-MM');
      if (!trendData[month]) {
        trendData[month] = {};
      }
      
      const standard = assessment.standardId?.acronym || 'Unknown';
      if (!trendData[month][standard]) {
        trendData[month][standard] = [];
      }
      
      trendData[month][standard].push(assessment.overallScore);
    });

    // Calculate averages
    return Object.entries(trendData).map(([month, standards]) => {
      const standardScores = {};
      Object.entries(standards).forEach(([standard, scores]) => {
        standardScores[standard] = Math.round(
          scores.reduce((a, b) => a + b, 0) / scores.length
        );
      });

      return {
        month,
        scores: standardScores,
        average: Math.round(
          Object.values(standardScores).reduce((a, b) => a + b, 0) / 
          Object.values(standardScores).length
        )
      };
    });
  }

  /**
   * Get assessment metrics
   * @param {string} organizationId - Organization ID
   * @param {string} timeRange - Time range
   * @returns {Promise<Object>} Assessment metrics
   * @private
   */
  static async getAssessmentMetrics(organizationId, timeRange) {
    const startDate = new Date(Date.now() - this.parseTimeRange(timeRange));
    const assessments = await ComplianceAssessment.find({
      organizationId,
      completionDate: { $gte: startDate }
    }).lean();

    return {
      total: assessments.length,
      completed: assessments.filter(a => a.status === 'completed').length,
      avgScore: assessments.length > 0
        ? Math.round(assessments.reduce((sum, a) => sum + a.overallScore, 0) / assessments.length)
        : 0,
      byStandard: this.groupAssessmentsByStandard(assessments)
    };
  }

  /**
   * Get gap metrics
   * @param {string} organizationId - Organization ID
   * @param {string} standardId - Standard ID
   * @returns {Promise<Object>} Gap metrics
   * @private
   */
  static async getGapMetrics(organizationId, standardId = null) {
    const query = { organizationId };
    if (standardId) {
      query.standardId = standardId;
    }

    const gaps = await ComplianceGap.find(query).lean();

    return {
      total: gaps.length,
      open: gaps.filter(g => g.status === 'open').length,
      inProgress: gaps.filter(g => g.status === 'in_progress').length,
      closed: gaps.filter(g => g.status === 'closed').length,
      bySeverity: this.groupBySeverity(gaps),
      avgAge: this.calculateAverageAge(gaps)
    };
  }

  /**
   * Get remediation metrics
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Remediation metrics
   * @private
   */
  static async getRemediationMetrics(organizationId) {
    const remediations = await ComplianceRemediation.find({ organizationId }).lean();

    return {
      total: remediations.length,
      pending: remediations.filter(r => r.status === 'pending').length,
      inProgress: remediations.filter(r => r.status === 'in_progress').length,
      completed: remediations.filter(r => r.status === 'completed').length,
      overdue: remediations.filter(r => 
        r.targetDate < new Date() && r.status !== 'completed'
      ).length,
      completionRate: this.calculateCompletionRate(remediations),
      avgCompletionTime: this.calculateAvgCompletionTime(remediations)
    };
  }

  /**
   * Get upcoming activities
   * @param {string} organizationId - Organization ID
   * @param {number} limit - Result limit
   * @returns {Promise<Array>} Upcoming activities
   * @private
   */
  static async getUpcomingActivities(organizationId, limit = 10) {
    return ComplianceSchedule.find({
      organizationId,
      scheduledDate: { $gte: new Date() },
      status: { $in: ['scheduled', 'pending'] }
    })
      .populate('standardId', 'name acronym')
      .populate('assignedTo', 'email profile.firstName profile.lastName')
      .sort({ scheduledDate: 1 })
      .limit(limit)
      .lean();
  }

  /**
   * Get recent compliance changes
   * @param {string} organizationId - Organization ID
   * @param {number} limit - Result limit
   * @returns {Promise<Array>} Recent changes
   * @private
   */
  static async getRecentComplianceChanges(organizationId, limit = 10) {
    const recentDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // Last 7 days

    const [
      assessments,
      gaps,
      remediations
    ] = await Promise.all([
      ComplianceAssessment.find({
        organizationId,
        completionDate: { $gte: recentDate }
      }).select('standardId overallScore completionDate').limit(limit).lean(),
      
      ComplianceGap.find({
        organizationId,
        $or: [
          { identifiedDate: { $gte: recentDate } },
          { closedDate: { $gte: recentDate } }
        ]
      }).select('title status severity identifiedDate closedDate').limit(limit).lean(),
      
      ComplianceRemediation.find({
        organizationId,
        $or: [
          { createdAt: { $gte: recentDate } },
          { completionDate: { $gte: recentDate } }
        ]
      }).select('title status completionDate').limit(limit).lean()
    ]);

    // Combine and sort by date
    const changes = [
      ...assessments.map(a => ({ type: 'assessment', ...a, date: a.completionDate })),
      ...gaps.map(g => ({ type: 'gap', ...g, date: g.closedDate || g.identifiedDate })),
      ...remediations.map(r => ({ type: 'remediation', ...r, date: r.completionDate || r.createdAt }))
    ].sort((a, b) => b.date - a.date).slice(0, limit);

    return changes;
  }

  /**
   * Calculate remediation progress
   * @param {Array} remediations - Remediation documents
   * @returns {Object} Progress metrics
   * @private
   */
  static async calculateRemediationProgress(remediations) {
    const total = remediations.length;
    if (total === 0) return { percentage: 0, completed: 0, total: 0 };

    const completed = remediations.filter(r => r.status === 'completed').length;
    const percentage = Math.round((completed / total) * 100);

    return { percentage, completed, total };
  }

  /**
   * Group by severity
   * @param {Array} items - Items with severity
   * @returns {Object} Grouped counts
   * @private
   */
  static groupBySeverity(items) {
    return {
      critical: items.filter(i => i.severity === 'critical').length,
      high: items.filter(i => i.severity === 'high').length,
      medium: items.filter(i => i.severity === 'medium').length,
      low: items.filter(i => i.severity === 'low').length
    };
  }

  /**
   * Group by status
   * @param {Array} items - Items with status
   * @returns {Object} Grouped counts
   * @private
   */
  static groupByStatus(items) {
    const statusCounts = {};
    items.forEach(item => {
      statusCounts[item.status] = (statusCounts[item.status] || 0) + 1;
    });
    return statusCounts;
  }

  /**
   * Calculate average age
   * @param {Array} items - Items with date
   * @returns {number} Average age in days
   * @private
   */
  static calculateAverageAge(items) {
    if (items.length === 0) return 0;

    const totalAge = items.reduce((sum, item) => {
      const date = item.identifiedDate || item.createdAt;
      const age = Math.floor((Date.now() - date) / (24 * 60 * 60 * 1000));
      return sum + age;
    }, 0);

    return Math.round(totalAge / items.length);
  }

  /**
   * Calculate completion rate
   * @param {Array} items - Items with status
   * @returns {number} Completion rate percentage
   * @private
   */
  static calculateCompletionRate(items) {
    if (items.length === 0) return 0;
    const completed = items.filter(i => i.status === 'completed').length;
    return Math.round((completed / items.length) * 100);
  }

  /**
   * Calculate average completion time
   * @param {Array} remediations - Remediation documents
   * @returns {number} Average completion time in days
   * @private
   */
  static calculateAvgCompletionTime(remediations) {
    const completed = remediations.filter(r => r.status === 'completed' && r.completionDate);
    if (completed.length === 0) return 0;

    const totalTime = completed.reduce((sum, r) => {
      const time = r.completionDate - r.createdAt;
      return sum + time;
    }, 0);

    return Math.round(totalTime / completed.length / (24 * 60 * 60 * 1000));
  }

  /**
   * Group assessments by standard
   * @param {Array} assessments - Assessment documents
   * @returns {Object} Grouped assessments
   * @private
   */
  static groupAssessmentsByStandard(assessments) {
    const grouped = {};
    assessments.forEach(assessment => {
      const standardId = assessment.standardId?.toString() || 'unknown';
      if (!grouped[standardId]) {
        grouped[standardId] = {
          count: 0,
          totalScore: 0
        };
      }
      grouped[standardId].count++;
      grouped[standardId].totalScore += assessment.overallScore;
    });

    // Calculate averages
    Object.keys(grouped).forEach(standardId => {
      grouped[standardId].avgScore = Math.round(
        grouped[standardId].totalScore / grouped[standardId].count
      );
    });

    return grouped;
  }

  /**
   * Assess compliance risks
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Array>} Compliance risks
   * @private
   */
  static async assessComplianceRisks(organizationId) {
    // Implementation for risk assessment
    return [];
  }

  /**
   * Generate compliance recommendations
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Array>} Recommendations
   * @private
   */
  static async generateComplianceRecommendations(organizationId) {
    // Implementation for generating recommendations
    return [];
  }

  /**
   * Generate risk matrix
   * @param {Array} risks - Risk data
   * @returns {Object} Risk matrix
   * @private
   */
  static generateRiskMatrix(risks) {
    // Implementation for risk matrix generation
    return {
      high: { high: [], medium: [], low: [] },
      medium: { high: [], medium: [], low: [] },
      low: { high: [], medium: [], low: [] }
    };
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
Object.setPrototypeOf(ComplianceService, AdminBaseService);
Object.setPrototypeOf(ComplianceService.prototype, AdminBaseService.prototype);

module.exports = ComplianceService;