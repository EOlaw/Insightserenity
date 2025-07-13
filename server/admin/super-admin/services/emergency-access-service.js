/**
 * @file Emergency Access Service
 * @description Service for handling emergency access procedures and break-glass functionality
 * @module admin/super-admin/services
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminCacheService } = require('../../../shared/admin/services/admin-cache-service');
const { AdminBaseService } = require('../../../shared/admin/services/admin-base-service');
const { AdminNotificationService } = require('../../../shared/admin/services/admin-notification-service');
const { AdminEventEmitter } = require('../../../shared/admin/services/admin-event-emitter');
const EmergencyAccessRequest = require('../../../models/emergency-access-request-model');
const EmergencyAccess = require('../../../models/emergency-access-model');
const BreakGlassAccess = require('../../../models/break-glass-access-model');
const User = require('../../../models/user-model');
const config = require('../../../config/configuration');

class EmergencyAccessService extends AdminBaseService {
    constructor() {
        super('EmergencyAccessService');
        this.cache = AdminCacheService.getInstance();
        this.notifications = AdminNotificationService.getInstance();
        this.eventEmitter = AdminEventEmitter.getInstance();
    }

    /**
     * Create emergency access request
     * @param {Object} requestData - Request data
     * @returns {Promise<Object>}
     */
    async createEmergencyAccessRequest(requestData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const {
                requestedBy,
                reason,
                resourceType,
                resourceId,
                duration,
                justification,
                ticketId,
                requestIp,
                userAgent
            } = requestData;

            // Validate requester
            const requester = await User.findById(requestedBy).session(session);
            if (!requester) {
                throw new Error('Requester not found');
            }

            // Check for existing pending requests
            const existingRequest = await EmergencyAccessRequest.findOne({
                requestedBy,
                resourceType,
                resourceId,
                status: 'pending'
            }).session(session);

            if (existingRequest) {
                throw new Error('A pending request already exists for this resource');
            }

            // Create request
            const request = new EmergencyAccessRequest({
                requestedBy,
                reason,
                resourceType,
                resourceId,
                duration,
                justification,
                ticketId,
                urgencyLevel: this.calculateUrgencyLevel(reason, duration),
                metadata: {
                    requestIp,
                    userAgent,
                    requesterEmail: requester.email,
                    requesterRole: requester.role
                }
            });

            await request.save({ session });

            // Get approvers
            const approvers = await this.getEmergencyApprovers();
            request.approversNotified = approvers.length;

            await session.commitTransaction();

            // Send notifications asynchronously
            this.notifyApprovers(request, approvers).catch(err => 
                this.logger.error('Error notifying approvers', err)
            );

            return request;
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error creating emergency access request', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Approve emergency access request
     * @param {Object} approvalData - Approval data
     * @returns {Promise<Object>}
     */
    async approveEmergencyAccess(approvalData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const {
                requestId,
                approvedBy,
                comments,
                conditions,
                expiresAt,
                approvalIp
            } = approvalData;

            const request = await EmergencyAccessRequest.findById(requestId).session(session);
            if (!request) {
                throw new Error('Request not found');
            }

            if (request.status !== 'pending') {
                throw new Error('Request is not pending approval');
            }

            // Validate approver
            const approver = await User.findById(approvedBy).session(session);
            if (!approver || !this.canApproveEmergencyAccess(approver)) {
                throw new Error('Insufficient permissions to approve emergency access');
            }

            // Update request
            request.status = 'approved';
            request.approvedBy = approvedBy;
            request.approvalComments = comments;
            request.conditions = conditions;
            request.processedAt = new Date();
            await request.save({ session });

            // Create emergency access
            const emergencyAccess = new EmergencyAccess({
                requestId,
                userId: request.requestedBy,
                resourceType: request.resourceType,
                resourceId: request.resourceId,
                grantedBy: approvedBy,
                expiresAt: expiresAt || new Date(Date.now() + request.duration),
                conditions,
                accessToken: this.generateAccessToken(),
                metadata: {
                    approvalIp,
                    approverEmail: approver.email,
                    originalReason: request.reason
                }
            });

            await emergencyAccess.save({ session });

            // Grant actual permissions
            const accessDetails = await this.grantEmergencyPermissions(
                request.requestedBy,
                request.resourceType,
                request.resourceId,
                session
            );

            await session.commitTransaction();

            // Send notifications
            await this.notifyAccessGranted(request, emergencyAccess, approver);

            return {
                requestId,
                requestedBy: request.requestedBy,
                accessDetails,
                accessToken: emergencyAccess.accessToken,
                expiresAt: emergencyAccess.expiresAt
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error approving emergency access', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Deny emergency access request
     * @param {Object} denialData - Denial data
     * @returns {Promise<Object>}
     */
    async denyEmergencyAccess(denialData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const {
                requestId,
                deniedBy,
                reason,
                recommendations,
                denialIp
            } = denialData;

            const request = await EmergencyAccessRequest.findById(requestId).session(session);
            if (!request) {
                throw new Error('Request not found');
            }

            if (request.status !== 'pending') {
                throw new Error('Request is not pending');
            }

            // Update request
            request.status = 'denied';
            request.deniedBy = deniedBy;
            request.denialReason = reason;
            request.recommendations = recommendations;
            request.processedAt = new Date();
            request.metadata.denialIp = denialIp;

            await request.save({ session });
            await session.commitTransaction();

            // Send notification
            await this.notifyAccessDenied(request, deniedBy);

            return {
                requestId,
                requestedBy: request.requestedBy,
                status: 'denied',
                reason,
                recommendations
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error denying emergency access', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Revoke active emergency access
     * @param {Object} revocationData - Revocation data
     * @returns {Promise<Object>}
     */
    async revokeEmergencyAccess(revocationData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const {
                accessId,
                revokedBy,
                reason,
                immediate,
                revocationIp
            } = revocationData;

            const access = await EmergencyAccess.findById(accessId).session(session);
            if (!access || access.status !== 'active') {
                throw new Error('Active emergency access not found');
            }

            // Calculate access duration
            const accessDuration = Date.now() - access.createdAt.getTime();

            // Update access record
            access.status = 'revoked';
            access.revokedBy = revokedBy;
            access.revokedAt = new Date();
            access.revocationReason = reason;
            access.metadata.revocationIp = revocationIp;

            await access.save({ session });

            // Revoke actual permissions
            await this.revokeEmergencyPermissions(
                access.userId,
                access.resourceType,
                access.resourceId,
                session
            );

            await session.commitTransaction();

            // Clear access token from cache
            await this.cache.invalidate(`emergency:access:${access.accessToken}`);

            // Send notifications
            await this.notifyAccessRevoked(access, revokedBy, immediate);

            return {
                accessId,
                userId: access.userId,
                status: 'revoked',
                accessDuration,
                immediate
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error revoking emergency access', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get emergency access requests
     * @param {Object} filters - Query filters
     * @returns {Promise<Object>}
     */
    async getEmergencyAccessRequests(filters = {}) {
        try {
            const {
                status,
                requesterId,
                resourceType,
                startDate,
                endDate,
                page = 1,
                limit = 20
            } = filters;

            const query = {};

            if (status) query.status = status;
            if (requesterId) query.requestedBy = requesterId;
            if (resourceType) query.resourceType = resourceType;

            if (startDate || endDate) {
                query.createdAt = {};
                if (startDate) query.createdAt.$gte = new Date(startDate);
                if (endDate) query.createdAt.$lte = new Date(endDate);
            }

            const totalCount = await EmergencyAccessRequest.countDocuments(query);
            
            const requests = await EmergencyAccessRequest.find(query)
                .populate('requestedBy', 'email fullName role')
                .populate('approvedBy', 'email fullName')
                .populate('deniedBy', 'email fullName')
                .sort({ createdAt: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();

            return {
                items: requests,
                pagination: {
                    total: totalCount,
                    page,
                    limit,
                    pages: Math.ceil(totalCount / limit)
                }
            };
        } catch (error) {
            this.logger.error('Error fetching emergency access requests', error);
            throw error;
        }
    }

    /**
     * Get active emergency accesses
     * @returns {Promise<Array>}
     */
    async getActiveEmergencyAccesses() {
        try {
            const activeAccesses = await EmergencyAccess.find({
                status: 'active',
                expiresAt: { $gt: new Date() }
            })
            .populate('userId', 'email fullName role')
            .populate('grantedBy', 'email fullName')
            .lean();

            // Check and expire any that should be expired
            const now = new Date();
            const toExpire = activeAccesses.filter(access => 
                new Date(access.expiresAt) <= now
            );

            if (toExpire.length > 0) {
                await this.expireEmergencyAccesses(toExpire.map(a => a._id));
                return activeAccesses.filter(a => !toExpire.includes(a));
            }

            return activeAccesses;
        } catch (error) {
            this.logger.error('Error fetching active emergency accesses', error);
            throw error;
        }
    }

    /**
     * Get emergency access audit trail
     * @param {String} accessId - Access ID
     * @returns {Promise<Array>}
     */
    async getEmergencyAccessAuditTrail(accessId) {
        try {
            const access = await EmergencyAccess.findById(accessId)
                .populate('userId', 'email fullName')
                .populate('grantedBy', 'email fullName')
                .populate('revokedBy', 'email fullName')
                .lean();

            if (!access) {
                throw new Error('Emergency access not found');
            }

            const request = await EmergencyAccessRequest.findById(access.requestId)
                .populate('requestedBy', 'email fullName')
                .populate('approvedBy', 'email fullName')
                .lean();

            // Get all related actions
            const auditTrail = [
                {
                    action: 'requested',
                    timestamp: request.createdAt,
                    user: request.requestedBy,
                    details: {
                        reason: request.reason,
                        resourceType: request.resourceType,
                        duration: request.duration
                    }
                },
                {
                    action: 'approved',
                    timestamp: request.processedAt,
                    user: request.approvedBy,
                    details: {
                        comments: request.approvalComments,
                        conditions: request.conditions
                    }
                },
                {
                    action: 'access_granted',
                    timestamp: access.createdAt,
                    user: access.grantedBy,
                    details: {
                        expiresAt: access.expiresAt,
                        accessToken: access.accessToken.substring(0, 8) + '...'
                    }
                }
            ];

            if (access.status === 'revoked') {
                auditTrail.push({
                    action: 'revoked',
                    timestamp: access.revokedAt,
                    user: access.revokedBy,
                    details: {
                        reason: access.revocationReason
                    }
                });
            }

            // Add any access usage logs
            const usageLogs = await this.getAccessUsageLogs(accessId);
            auditTrail.push(...usageLogs);

            return auditTrail.sort((a, b) => a.timestamp - b.timestamp);
        } catch (error) {
            this.logger.error('Error fetching audit trail', error);
            throw error;
        }
    }

    /**
     * Execute break-glass procedure
     * @param {Object} breakGlassData - Break-glass data
     * @returns {Promise<Object>}
     */
    async executeBreakGlass(breakGlassData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const {
                executedBy,
                reason,
                targetSystem,
                urgencyLevel,
                incidentId,
                executionIp,
                userAgent
            } = breakGlassData;

            // Create break-glass access record
            const breakGlassAccess = new BreakGlassAccess({
                executedBy,
                reason,
                targetSystem,
                urgencyLevel,
                incidentId,
                executionIp,
                userAgent,
                accessToken: this.generateBreakGlassToken(),
                permissions: this.getBreakGlassPermissions(targetSystem),
                expiresAt: new Date(Date.now() + 4 * 60 * 60 * 1000), // 4 hours
                metadata: {
                    executionTime: new Date(),
                    systemState: await this.captureSystemState()
                }
            });

            await breakGlassAccess.save({ session });

            // Grant break-glass permissions
            await this.grantBreakGlassPermissions(
                executedBy,
                breakGlassAccess.permissions,
                session
            );

            await session.commitTransaction();

            // Start monitoring session
            this.startBreakGlassMonitoring(breakGlassAccess._id);

            // Send critical alerts
            await this.sendBreakGlassAlerts(breakGlassAccess);

            return {
                id: breakGlassAccess._id,
                accessToken: breakGlassAccess.accessToken,
                permissions: breakGlassAccess.permissions,
                expiresAt: breakGlassAccess.expiresAt,
                monitoringId: `monitor-${breakGlassAccess._id}`
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error executing break-glass procedure', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Verify break-glass code
     * @param {String} userId - User ID
     * @param {String} code - Verification code
     * @returns {Promise<Boolean>}
     */
    async verifyBreakGlassCode(userId, code) {
        try {
            // In production, this would verify against a secure code delivery system
            // For now, simulate verification
            const user = await User.findById(userId);
            if (!user || user.role !== 'super_admin') {
                return false;
            }

            // Check if code matches recent emergency code
            const cacheKey = `break_glass:code:${userId}`;
            const storedCode = await this.cache.get(cacheKey);

            if (!storedCode) {
                // Generate and send new code
                const newCode = this.generateEmergencyCode();
                await this.cache.set(cacheKey, newCode, 300); // 5 minutes
                
                // In production, send code via secure channel (SMS, authenticator app, etc.)
                this.logger.info('Break-glass code generated', { userId, code: newCode });
                
                return false;
            }

            return storedCode === code;
        } catch (error) {
            this.logger.error('Error verifying break-glass code', error);
            return false;
        }
    }

    /**
     * Generate emergency access report
     * @param {Object} reportOptions - Report options
     * @returns {Promise<Object>}
     */
    async generateEmergencyAccessReport(reportOptions) {
        try {
            const {
                startDate,
                endDate,
                includeBreakGlass = true,
                generatedBy
            } = reportOptions;

            const dateQuery = {};
            if (startDate) dateQuery.$gte = new Date(startDate);
            if (endDate) dateQuery.$lte = new Date(endDate);

            // Get emergency access requests
            const requests = await EmergencyAccessRequest.find({
                createdAt: dateQuery
            })
            .populate('requestedBy', 'email fullName role')
            .lean();

            // Get emergency accesses
            const accesses = await EmergencyAccess.find({
                createdAt: dateQuery
            })
            .populate('userId', 'email fullName')
            .lean();

            // Get break-glass accesses if included
            let breakGlassAccesses = [];
            if (includeBreakGlass) {
                breakGlassAccesses = await BreakGlassAccess.find({
                    createdAt: dateQuery
                })
                .populate('executedBy', 'email fullName')
                .lean();
            }

            // Generate statistics
            const summary = {
                totalRequests: requests.length,
                approvedRequests: requests.filter(r => r.status === 'approved').length,
                deniedRequests: requests.filter(r => r.status === 'denied').length,
                pendingRequests: requests.filter(r => r.status === 'pending').length,
                activeAccesses: accesses.filter(a => a.status === 'active').length,
                breakGlassUsage: breakGlassAccesses.length,
                averageApprovalTime: this.calculateAverageApprovalTime(requests),
                byResourceType: this.groupByResourceType(requests),
                byUrgencyLevel: this.groupByUrgencyLevel(requests)
            };

            return {
                summary,
                requests: requests.slice(0, 100), // Limit for performance
                accesses: accesses.slice(0, 100),
                breakGlassAccesses: breakGlassAccesses.slice(0, 50),
                generatedAt: new Date(),
                generatedBy
            };
        } catch (error) {
            this.logger.error('Error generating emergency access report', error);
            throw error;
        }
    }

    // Private helper methods

    async getEmergencyApprovers() {
        // Get users with emergency approval permissions
        const approvers = await User.find({
            $or: [
                { role: 'super_admin' },
                { permissions: 'emergency:approve' }
            ],
            status: 'active'
        }).select('_id email fullName').lean();

        return approvers;
    }

    calculateUrgencyLevel(reason, duration) {
        // Simple urgency calculation based on reason keywords and duration
        const urgentKeywords = ['critical', 'emergency', 'urgent', 'immediate', 'security'];
        const hasUrgentKeyword = urgentKeywords.some(keyword => 
            reason.toLowerCase().includes(keyword)
        );

        if (hasUrgentKeyword && duration <= 3600000) { // 1 hour
            return 'critical';
        } else if (hasUrgentKeyword || duration <= 14400000) { // 4 hours
            return 'high';
        } else if (duration <= 86400000) { // 24 hours
            return 'medium';
        }
        
        return 'low';
    }

    canApproveEmergencyAccess(user) {
        return user.role === 'super_admin' || 
               user.permissions?.includes('emergency:approve');
    }

    generateAccessToken() {
        return `EA-${crypto.randomBytes(32).toString('hex')}`;
    }

    generateBreakGlassToken() {
        return `BG-${crypto.randomBytes(32).toString('hex')}`;
    }

    generateEmergencyCode() {
        return crypto.randomInt(100000, 999999).toString();
    }

    async grantEmergencyPermissions(userId, resourceType, resourceId, session) {
        // Implementation would depend on resource type
        // This is a placeholder showing the pattern
        const permissions = {
            grantedPermissions: [],
            elevatedRoles: [],
            accessScope: {}
        };

        switch (resourceType) {
            case 'user':
                permissions.grantedPermissions = ['users:read', 'users:write'];
                permissions.accessScope = { userId: resourceId };
                break;
            case 'organization':
                permissions.grantedPermissions = ['organizations:read', 'organizations:write'];
                permissions.accessScope = { organizationId: resourceId };
                break;
            case 'system':
                permissions.grantedPermissions = ['system:admin'];
                permissions.elevatedRoles = ['emergency_admin'];
                break;
        }

        // Store temporary permissions
        await this.cache.set(
            `emergency:permissions:${userId}`,
            permissions,
            86400 // 24 hours
        );

        return permissions;
    }

    async revokeEmergencyPermissions(userId, resourceType, resourceId, session) {
        await this.cache.invalidate(`emergency:permissions:${userId}`);
        // Additional cleanup based on resource type
    }

    getBreakGlassPermissions(targetSystem) {
        // Define break-glass permissions based on target system
        const systemPermissions = {
            all: ['*'],
            database: ['db:read', 'db:write', 'db:admin'],
            infrastructure: ['infra:read', 'infra:write', 'infra:admin'],
            security: ['security:read', 'security:write', 'security:admin'],
            billing: ['billing:read', 'billing:write', 'billing:admin']
        };

        return systemPermissions[targetSystem] || systemPermissions.all;
    }

    async grantBreakGlassPermissions(userId, permissions, session) {
        // Store break-glass permissions with monitoring
        await this.cache.set(
            `break_glass:permissions:${userId}`,
            {
                permissions,
                grantedAt: new Date(),
                monitoring: true
            },
            14400 // 4 hours
        );
    }

    async captureSystemState() {
        return {
            timestamp: new Date(),
            activeUsers: await User.countDocuments({ status: 'active' }),
            systemLoad: process.cpuUsage(),
            memoryUsage: process.memoryUsage()
        };
    }

    startBreakGlassMonitoring(accessId) {
        // Start monitoring all actions during break-glass session
        this.eventEmitter.emit('break_glass:monitoring:start', { accessId });
    }

    async expireEmergencyAccesses(accessIds) {
        await EmergencyAccess.updateMany(
            { _id: { $in: accessIds } },
            { 
                $set: { 
                    status: 'expired',
                    expiredAt: new Date()
                }
            }
        );
    }

    async getAccessUsageLogs(accessId) {
        // Placeholder - would fetch actual usage logs
        return [];
    }

    calculateAverageApprovalTime(requests) {
        const approved = requests.filter(r => r.status === 'approved' && r.processedAt);
        if (approved.length === 0) return 0;

        const totalTime = approved.reduce((sum, req) => {
            return sum + (req.processedAt - req.createdAt);
        }, 0);

        return Math.round(totalTime / approved.length / 60000); // in minutes
    }

    groupByResourceType(items) {
        return items.reduce((grouped, item) => {
            const type = item.resourceType;
            grouped[type] = (grouped[type] || 0) + 1;
            return grouped;
        }, {});
    }

    groupByUrgencyLevel(items) {
        return items.reduce((grouped, item) => {
            const level = item.urgencyLevel;
            grouped[level] = (grouped[level] || 0) + 1;
            return grouped;
        }, {});
    }

    // Notification methods

    async notifyApprovers(request, approvers) {
        const notification = {
            type: 'emergency_access_request',
            priority: 'high',
            data: {
                requestId: request._id,
                requestedBy: request.metadata.requesterEmail,
                resourceType: request.resourceType,
                reason: request.reason,
                urgencyLevel: request.urgencyLevel
            }
        };

        await Promise.all(
            approvers.map(approver => 
                this.notifications.sendNotification({
                    userId: approver._id,
                    ...notification
                })
            )
        );
    }

    async notifyAccessGranted(request, access, approver) {
        await this.notifications.sendNotification({
            userId: request.requestedBy,
            type: 'emergency_access_approved',
            data: {
                approvedBy: approver.email,
                expiresAt: access.expiresAt,
                conditions: access.conditions
            }
        });
    }

    async notifyAccessDenied(request, deniedBy) {
        const denier = await User.findById(deniedBy).select('email');
        
        await this.notifications.sendNotification({
            userId: request.requestedBy,
            type: 'emergency_access_denied',
            data: {
                deniedBy: denier.email,
                reason: request.denialReason,
                recommendations: request.recommendations
            }
        });
    }

    async notifyAccessRevoked(access, revokedBy, immediate) {
        const revoker = await User.findById(revokedBy).select('email');
        
        await this.notifications.sendNotification({
            userId: access.userId,
            type: 'emergency_access_revoked',
            priority: immediate ? 'critical' : 'high',
            data: {
                revokedBy: revoker.email,
                reason: access.revocationReason,
                immediate
            }
        });
    }

    async sendBreakGlassAlerts(breakGlassAccess) {
        const criticalAlert = {
            type: 'break_glass_executed',
            priority: 'critical',
            data: {
                executedBy: breakGlassAccess.executedBy,
                targetSystem: breakGlassAccess.targetSystem,
                urgencyLevel: breakGlassAccess.urgencyLevel,
                incidentId: breakGlassAccess.incidentId,
                reason: breakGlassAccess.reason
            }
        };

        // Send to all super admins
        const superAdmins = await User.find({ 
            role: 'super_admin',
            _id: { $ne: breakGlassAccess.executedBy }
        }).select('_id');

        await Promise.all(
            superAdmins.map(admin => 
                this.notifications.sendCriticalAlert({
                    recipients: [admin._id],
                    ...criticalAlert
                })
            )
        );

        // Also send to security team email
        await this.notifications.sendEmailAlert({
            to: config.audit.alerting.criticalEventsEmail,
            subject: 'CRITICAL: Break-Glass Access Executed',
            template: 'break-glass-alert',
            data: criticalAlert.data
        });
    }
}

module.exports = EmergencyAccessService;