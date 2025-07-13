/**
 * @file Emergency Access Controller
 * @description Handles emergency access procedures and break-glass functionality
 * @module admin/super-admin/controllers
 * @version 1.0.0
 */

const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../../../shared/admin/utils/admin-helpers');
const { AdminMetrics } = require('../../../shared/admin/utils/admin-metrics');
const { ADMIN_ACTIONS } = require('../../../shared/admin/constants/admin-actions');
const { ADMIN_EVENTS } = require('../../../shared/admin/constants/admin-events');
const EmergencyAccessService = require('../services/emergency-access-service');
const { AuditService } = require('../../../shared/services/audit-service');
const config = require('../../../config/configuration');

class EmergencyAccessController {
    constructor() {
        this.logger = new AdminLogger('EmergencyAccessController');
        this.service = new EmergencyAccessService();
        this.metrics = AdminMetrics.getInstance();
        this.auditService = new AuditService();
    }

    /**
     * Request emergency access
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async requestEmergencyAccess(req, res, next) {
        try {
            const {
                reason,
                resourceType,
                resourceId,
                duration,
                justification,
                ticketId
            } = req.body;

            this.logger.warn('Emergency access requested', {
                adminId: req.user.id,
                resourceType,
                resourceId,
                duration
            });

            const request = await this.service.createEmergencyAccessRequest({
                requestedBy: req.user.id,
                reason,
                resourceType,
                resourceId,
                duration,
                justification,
                ticketId,
                requestIp: req.ip,
                userAgent: req.get('user-agent')
            });

            // Record metrics
            this.metrics.incrementCounter('emergency_access.requests.created');

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.EMERGENCY_ACCESS.REQUEST,
                userId: req.user.id,
                resourceType: 'emergency_access',
                resourceId: request.id,
                details: {
                    requestType: resourceType,
                    targetResource: resourceId,
                    reason,
                    duration,
                    ticketId
                },
                severity: 'critical',
                ip: req.ip
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.EMERGENCY_ACCESS_REQUESTED, {
                requestId: request.id,
                requestedBy: req.user.id,
                resourceType,
                resourceId
            });

            // Send notifications to approvers
            await req.adminContext.notifications.sendCriticalAlert({
                type: 'emergency_access_request',
                recipients: await this.service.getEmergencyApprovers(),
                data: {
                    requestId: request.id,
                    requestedBy: req.user.email,
                    resourceType,
                    reason,
                    urgency: 'high'
                }
            });

            res.status(201).json({
                success: true,
                message: 'Emergency access request submitted',
                data: {
                    requestId: request.id,
                    status: request.status,
                    approversNotified: request.approversNotified,
                    estimatedResponseTime: '15 minutes'
                }
            });
        } catch (error) {
            this.logger.error('Error requesting emergency access', error);
            next(error);
        }
    }

    /**
     * Approve emergency access request
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async approveEmergencyAccess(req, res, next) {
        try {
            const { id } = req.params;
            const { comments, conditions, expiresAt } = req.body;

            this.logger.warn('Approving emergency access', {
                adminId: req.user.id,
                requestId: id
            });

            const approval = await this.service.approveEmergencyAccess({
                requestId: id,
                approvedBy: req.user.id,
                comments,
                conditions,
                expiresAt,
                approvalIp: req.ip
            });

            // Record metrics
            this.metrics.incrementCounter('emergency_access.requests.approved');

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.EMERGENCY_ACCESS.APPROVE,
                userId: req.user.id,
                resourceType: 'emergency_access',
                resourceId: id,
                details: {
                    requesterId: approval.requestedBy,
                    accessGranted: approval.accessDetails,
                    conditions,
                    expiresAt
                },
                severity: 'critical',
                ip: req.ip
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.EMERGENCY_ACCESS_APPROVED, {
                requestId: id,
                approvedBy: req.user.id,
                requesterId: approval.requestedBy
            });

            // Send notification to requester
            await req.adminContext.notifications.sendNotification({
                userId: approval.requestedBy,
                type: 'emergency_access_approved',
                priority: 'high',
                data: {
                    requestId: id,
                    approvedBy: req.user.email,
                    accessDetails: approval.accessDetails,
                    expiresAt
                }
            });

            res.json({
                success: true,
                message: 'Emergency access approved',
                data: approval
            });
        } catch (error) {
            this.logger.error('Error approving emergency access', error);
            next(error);
        }
    }

    /**
     * Deny emergency access request
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async denyEmergencyAccess(req, res, next) {
        try {
            const { id } = req.params;
            const { reason, recommendations } = req.body;

            this.logger.warn('Denying emergency access', {
                adminId: req.user.id,
                requestId: id,
                reason
            });

            const denial = await this.service.denyEmergencyAccess({
                requestId: id,
                deniedBy: req.user.id,
                reason,
                recommendations,
                denialIp: req.ip
            });

            // Record metrics
            this.metrics.incrementCounter('emergency_access.requests.denied');

            // Audit action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.EMERGENCY_ACCESS.DENY,
                userId: req.user.id,
                resourceType: 'emergency_access',
                resourceId: id,
                details: {
                    requesterId: denial.requestedBy,
                    reason,
                    recommendations
                },
                severity: 'high',
                ip: req.ip
            });

            // Send notification to requester
            await req.adminContext.notifications.sendNotification({
                userId: denial.requestedBy,
                type: 'emergency_access_denied',
                data: {
                    requestId: id,
                    deniedBy: req.user.email,
                    reason,
                    recommendations
                }
            });

            res.json({
                success: true,
                message: 'Emergency access denied',
                data: denial
            });
        } catch (error) {
            this.logger.error('Error denying emergency access', error);
            next(error);
        }
    }

    /**
     * Revoke active emergency access
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async revokeEmergencyAccess(req, res, next) {
        try {
            const { id } = req.params;
            const { reason, immediate = true } = req.body;

            this.logger.error('Revoking emergency access', {
                adminId: req.user.id,
                accessId: id,
                immediate,
                reason
            });

            const revocation = await this.service.revokeEmergencyAccess({
                accessId: id,
                revokedBy: req.user.id,
                reason,
                immediate,
                revocationIp: req.ip
            });

            // Record metrics
            this.metrics.incrementCounter('emergency_access.revoked');

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.EMERGENCY_ACCESS.REVOKE,
                userId: req.user.id,
                resourceType: 'emergency_access',
                resourceId: id,
                details: {
                    affectedUser: revocation.userId,
                    reason,
                    immediate,
                    accessDuration: revocation.accessDuration
                },
                severity: 'critical',
                ip: req.ip
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.EMERGENCY_ACCESS_REVOKED, {
                accessId: id,
                revokedBy: req.user.id,
                affectedUser: revocation.userId,
                immediate
            });

            res.json({
                success: true,
                message: 'Emergency access revoked',
                data: revocation
            });
        } catch (error) {
            this.logger.error('Error revoking emergency access', error);
            next(error);
        }
    }

    /**
     * Get emergency access requests
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getEmergencyAccessRequests(req, res, next) {
        try {
            const {
                status,
                requesterId,
                resourceType,
                startDate,
                endDate,
                page = 1,
                limit = 20
            } = req.query;

            this.logger.info('Fetching emergency access requests', {
                adminId: req.user.id,
                filters: { status, requesterId, resourceType }
            });

            const requests = await this.service.getEmergencyAccessRequests({
                status,
                requesterId,
                resourceType,
                startDate,
                endDate,
                page: parseInt(page),
                limit: parseInt(limit)
            });

            res.json({
                success: true,
                data: requests.items,
                pagination: requests.pagination
            });
        } catch (error) {
            this.logger.error('Error fetching emergency access requests', error);
            next(error);
        }
    }

    /**
     * Get active emergency accesses
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getActiveEmergencyAccesses(req, res, next) {
        try {
            this.logger.info('Fetching active emergency accesses', {
                adminId: req.user.id
            });

            const activeAccesses = await this.service.getActiveEmergencyAccesses();

            res.json({
                success: true,
                data: activeAccesses,
                summary: {
                    total: activeAccesses.length,
                    byResourceType: this.groupByResourceType(activeAccesses),
                    expiringIn24Hours: activeAccesses.filter(a => 
                        this.isExpiringWithin(a.expiresAt, 24)
                    ).length
                }
            });
        } catch (error) {
            this.logger.error('Error fetching active emergency accesses', error);
            next(error);
        }
    }

    /**
     * Get emergency access audit trail
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getEmergencyAccessAuditTrail(req, res, next) {
        try {
            const { id } = req.params;

            this.logger.info('Fetching emergency access audit trail', {
                adminId: req.user.id,
                accessId: id
            });

            const auditTrail = await this.service.getEmergencyAccessAuditTrail(id);

            res.json({
                success: true,
                data: auditTrail
            });
        } catch (error) {
            this.logger.error('Error fetching audit trail', error);
            next(error);
        }
    }

    /**
     * Execute break-glass procedure
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async executeBreakGlass(req, res, next) {
        try {
            const {
                reason,
                targetSystem,
                urgencyLevel,
                incidentId,
                verificationCode
            } = req.body;

            this.logger.error('BREAK-GLASS PROCEDURE INITIATED', {
                adminId: req.user.id,
                targetSystem,
                urgencyLevel,
                incidentId
            });

            // Verify break-glass code
            const isValidCode = await this.service.verifyBreakGlassCode(
                req.user.id,
                verificationCode
            );

            if (!isValidCode) {
                return res.status(403).json({
                    success: false,
                    error: {
                        message: 'Invalid break-glass verification code',
                        code: 'INVALID_BREAK_GLASS_CODE'
                    }
                });
            }

            const breakGlassAccess = await this.service.executeBreakGlass({
                executedBy: req.user.id,
                reason,
                targetSystem,
                urgencyLevel,
                incidentId,
                executionIp: req.ip,
                userAgent: req.get('user-agent')
            });

            // Record critical metrics
            this.metrics.incrementCounter('emergency_access.break_glass.executed');
            this.metrics.recordGauge('emergency_access.break_glass.active', 1);

            // Audit critical action with highest severity
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.EMERGENCY_ACCESS.BREAK_GLASS,
                userId: req.user.id,
                resourceType: 'break_glass',
                resourceId: breakGlassAccess.id,
                details: {
                    targetSystem,
                    urgencyLevel,
                    incidentId,
                    reason,
                    accessGranted: breakGlassAccess.permissions
                },
                severity: 'critical',
                ip: req.ip,
                tags: ['break-glass', 'emergency', urgencyLevel]
            });

            // Emit critical event
            req.adminContext.events.emit(ADMIN_EVENTS.BREAK_GLASS_EXECUTED, {
                accessId: breakGlassAccess.id,
                executedBy: req.user.id,
                targetSystem,
                urgencyLevel,
                incidentId
            });

            // Send immediate notifications to all super admins and security team
            await req.adminContext.notifications.broadcastCriticalAlert({
                type: 'break_glass_executed',
                priority: 'critical',
                data: {
                    executedBy: req.user.email,
                    targetSystem,
                    urgencyLevel,
                    incidentId,
                    reason,
                    timestamp: new Date()
                }
            });

            res.json({
                success: true,
                message: 'Break-glass access granted',
                data: {
                    accessId: breakGlassAccess.id,
                    permissions: breakGlassAccess.permissions,
                    expiresAt: breakGlassAccess.expiresAt,
                    monitoringEnabled: true,
                    warningMessage: 'All actions are being monitored and logged'
                }
            });
        } catch (error) {
            this.logger.error('Error executing break-glass procedure', error);
            next(error);
        }
    }

    /**
     * Generate emergency access report
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async generateEmergencyAccessReport(req, res, next) {
        try {
            const { startDate, endDate, includeBreakGlass = true } = req.query;

            this.logger.info('Generating emergency access report', {
                adminId: req.user.id,
                dateRange: { startDate, endDate }
            });

            const report = await this.service.generateEmergencyAccessReport({
                startDate,
                endDate,
                includeBreakGlass: includeBreakGlass === 'true',
                generatedBy: req.user.id
            });

            // Audit report generation
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.EMERGENCY_ACCESS.GENERATE_REPORT,
                userId: req.user.id,
                resourceType: 'emergency_access_report',
                details: {
                    dateRange: { startDate, endDate },
                    recordCount: report.summary.totalRequests
                },
                severity: 'medium'
            });

            res.json({
                success: true,
                data: report
            });
        } catch (error) {
            this.logger.error('Error generating emergency access report', error);
            next(error);
        }
    }

    /**
     * Helper: Group accesses by resource type
     * @private
     */
    groupByResourceType(accesses) {
        return accesses.reduce((grouped, access) => {
            const type = access.resourceType;
            grouped[type] = (grouped[type] || 0) + 1;
            return grouped;
        }, {});
    }

    /**
     * Helper: Check if access is expiring within hours
     * @private
     */
    isExpiringWithin(expiresAt, hours) {
        const expiryTime = new Date(expiresAt).getTime();
        const hoursInMs = hours * 60 * 60 * 1000;
        return expiryTime - Date.now() <= hoursInMs;
    }
}

module.exports = new EmergencyAccessController();