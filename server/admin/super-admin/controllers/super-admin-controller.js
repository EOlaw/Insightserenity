/**
 * @file Super Admin Controller
 * @description Handles super admin level operations and system management
 * @module admin/super-admin/controllers
 * @version 1.0.0
 */

const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../../../shared/admin/utils/admin-helpers');
const { AdminMetrics } = require('../../../shared/admin/utils/admin-metrics');
const { ADMIN_ACTIONS } = require('../../../shared/admin/constants/admin-actions');
const { ADMIN_EVENTS } = require('../../../shared/admin/constants/admin-events');
const SuperAdminService = require('../services/super-admin-service');
const { AuditService } = require('../../../shared/services/audit-service');
const config = require('../../../config/configuration');

class SuperAdminController {
    constructor() {
        this.logger = new AdminLogger('SuperAdminController');
        this.service = new SuperAdminService();
        this.metrics = AdminMetrics.getInstance();
        this.auditService = new AuditService();
    }

    /**
     * Get super admin dashboard data
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getDashboard(req, res, next) {
        try {
            this.logger.info('Fetching super admin dashboard', {
                adminId: req.user.id
            });

            const dashboardData = await this.service.getSuperAdminDashboard();

            // Record metrics
            this.metrics.incrementCounter('super_admin.dashboard.views');

            // Audit the access
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SUPER_ADMIN.VIEW_DASHBOARD,
                userId: req.user.id,
                resourceType: 'super_admin_dashboard',
                details: {
                    ip: req.ip,
                    userAgent: req.get('user-agent')
                },
                severity: 'low'
            });

            res.json({
                success: true,
                data: dashboardData
            });
        } catch (error) {
            this.logger.error('Error fetching super admin dashboard', error);
            next(error);
        }
    }

    /**
     * Get system overview and statistics
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getSystemOverview(req, res, next) {
        try {
            this.logger.info('Fetching system overview', {
                adminId: req.user.id
            });

            const overview = await this.service.getSystemOverview();

            res.json({
                success: true,
                data: overview
            });
        } catch (error) {
            this.logger.error('Error fetching system overview', error);
            next(error);
        }
    }

    /**
     * Get all admin users
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getAdminUsers(req, res, next) {
        try {
            const { page = 1, limit = 20, role, status, search } = req.query;

            this.logger.info('Fetching admin users', {
                adminId: req.user.id,
                filters: { role, status, search }
            });

            const result = await this.service.getAdminUsers({
                page: parseInt(page),
                limit: parseInt(limit),
                role,
                status,
                search
            });

            // Audit data access
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SUPER_ADMIN.LIST_ADMINS,
                userId: req.user.id,
                resourceType: 'admin_users',
                details: {
                    filters: { role, status, search },
                    resultCount: result.users.length
                },
                severity: 'medium'
            });

            res.json({
                success: true,
                data: result.users,
                pagination: result.pagination
            });
        } catch (error) {
            this.logger.error('Error fetching admin users', error);
            next(error);
        }
    }

    /**
     * Create new admin user
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async createAdminUser(req, res, next) {
        try {
            const adminData = req.body;

            this.logger.info('Creating new admin user', {
                adminId: req.user.id,
                newAdminEmail: adminData.email,
                role: adminData.role
            });

            const newAdmin = await this.service.createAdminUser(adminData, req.user);

            // Record metrics
            this.metrics.incrementCounter('super_admin.admin_users.created');

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SUPER_ADMIN.CREATE_ADMIN,
                userId: req.user.id,
                resourceType: 'admin_user',
                resourceId: newAdmin.id,
                details: {
                    email: adminData.email,
                    role: adminData.role,
                    permissions: adminData.permissions
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.ADMIN_USER_CREATED, {
                adminId: newAdmin.id,
                createdBy: req.user.id,
                role: adminData.role
            });

            res.status(201).json({
                success: true,
                message: 'Admin user created successfully',
                data: {
                    id: newAdmin.id,
                    email: newAdmin.email,
                    role: newAdmin.role,
                    status: newAdmin.status
                }
            });
        } catch (error) {
            this.logger.error('Error creating admin user', error);
            next(error);
        }
    }

    /**
     * Update admin user
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async updateAdminUser(req, res, next) {
        try {
            const { id } = req.params;
            const updates = req.body;

            this.logger.info('Updating admin user', {
                adminId: req.user.id,
                targetAdminId: id,
                updates: Object.keys(updates)
            });

            // Prevent self-demotion for super admins
            if (id === req.user.id && updates.role && updates.role !== 'super_admin') {
                return res.status(400).json({
                    success: false,
                    error: {
                        message: 'Cannot change your own super admin role',
                        code: 'SELF_DEMOTION_PREVENTED'
                    }
                });
            }

            const updatedAdmin = await this.service.updateAdminUser(id, updates, req.user);

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SUPER_ADMIN.UPDATE_ADMIN,
                userId: req.user.id,
                resourceType: 'admin_user',
                resourceId: id,
                details: {
                    updates,
                    previousRole: updatedAdmin.previousRole
                },
                severity: 'critical'
            });

            // Emit event if role changed
            if (updates.role && updates.role !== updatedAdmin.previousRole) {
                req.adminContext.events.emit(ADMIN_EVENTS.ADMIN_ROLE_CHANGED, {
                    adminId: id,
                    previousRole: updatedAdmin.previousRole,
                    newRole: updates.role,
                    changedBy: req.user.id
                });
            }

            res.json({
                success: true,
                message: 'Admin user updated successfully',
                data: updatedAdmin
            });
        } catch (error) {
            this.logger.error('Error updating admin user', error);
            next(error);
        }
    }

    /**
     * Revoke admin access
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async revokeAdminAccess(req, res, next) {
        try {
            const { id } = req.params;
            const { reason, immediate = false } = req.body;

            this.logger.warn('Revoking admin access', {
                adminId: req.user.id,
                targetAdminId: id,
                immediate,
                reason
            });

            // Prevent self-revocation
            if (id === req.user.id) {
                return res.status(400).json({
                    success: false,
                    error: {
                        message: 'Cannot revoke your own admin access',
                        code: 'SELF_REVOCATION_PREVENTED'
                    }
                });
            }

            const result = await this.service.revokeAdminAccess(id, {
                reason,
                immediate,
                revokedBy: req.user.id
            });

            // Record metrics
            this.metrics.incrementCounter('super_admin.admin_access.revoked');

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SUPER_ADMIN.REVOKE_ACCESS,
                userId: req.user.id,
                resourceType: 'admin_user',
                resourceId: id,
                details: {
                    reason,
                    immediate,
                    sessionsTerminated: result.sessionsTerminated
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.ADMIN_ACCESS_REVOKED, {
                adminId: id,
                revokedBy: req.user.id,
                reason,
                immediate
            });

            // Send notification
            await req.adminContext.notifications.sendCriticalAlert({
                type: 'admin_access_revoked',
                recipients: [id],
                data: {
                    revokedBy: req.user.email,
                    reason,
                    timestamp: new Date()
                }
            });

            res.json({
                success: true,
                message: immediate ? 'Admin access revoked immediately' : 'Admin access revocation scheduled',
                data: result
            });
        } catch (error) {
            this.logger.error('Error revoking admin access', error);
            next(error);
        }
    }

    /**
     * Get system activity logs
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getSystemActivityLogs(req, res, next) {
        try {
            const {
                startDate,
                endDate,
                userId,
                action,
                severity,
                page = 1,
                limit = 50
            } = req.query;

            this.logger.info('Fetching system activity logs', {
                adminId: req.user.id,
                filters: { startDate, endDate, userId, action, severity }
            });

            const logs = await this.service.getSystemActivityLogs({
                startDate,
                endDate,
                userId,
                action,
                severity,
                page: parseInt(page),
                limit: parseInt(limit)
            });

            res.json({
                success: true,
                data: logs.activities,
                pagination: logs.pagination
            });
        } catch (error) {
            this.logger.error('Error fetching system activity logs', error);
            next(error);
        }
    }

    /**
     * Execute system maintenance task
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async executeMaintenanceTask(req, res, next) {
        try {
            const { task, parameters = {} } = req.body;

            this.logger.warn('Executing maintenance task', {
                adminId: req.user.id,
                task,
                parameters: Object.keys(parameters)
            });

            const result = await this.service.executeMaintenanceTask(task, parameters, req.user);

            // Record metrics
            this.metrics.incrementCounter(`super_admin.maintenance.${task}`);

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SUPER_ADMIN.EXECUTE_MAINTENANCE,
                userId: req.user.id,
                resourceType: 'system',
                details: {
                    task,
                    parameters,
                    result: result.summary
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.MAINTENANCE_EXECUTED, {
                task,
                executedBy: req.user.id,
                result: result.summary
            });

            res.json({
                success: true,
                message: `Maintenance task '${task}' executed successfully`,
                data: result
            });
        } catch (error) {
            this.logger.error('Error executing maintenance task', error);
            next(error);
        }
    }

    /**
     * Get super admin permissions
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getPermissions(req, res, next) {
        try {
            const permissions = await this.service.getSuperAdminPermissions();

            res.json({
                success: true,
                data: permissions
            });
        } catch (error) {
            this.logger.error('Error fetching super admin permissions', error);
            next(error);
        }
    }

    /**
     * Export system data
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async exportSystemData(req, res, next) {
        try {
            const { dataType, format = 'json', filters = {} } = req.body;

            this.logger.info('Exporting system data', {
                adminId: req.user.id,
                dataType,
                format
            });

            const exportResult = await this.service.exportSystemData({
                dataType,
                format,
                filters,
                requestedBy: req.user
            });

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.SUPER_ADMIN.EXPORT_DATA,
                userId: req.user.id,
                resourceType: 'system_data',
                details: {
                    dataType,
                    format,
                    recordCount: exportResult.recordCount,
                    fileSize: exportResult.fileSize
                },
                severity: 'high'
            });

            res.json({
                success: true,
                message: 'System data export initiated',
                data: {
                    exportId: exportResult.exportId,
                    status: exportResult.status,
                    downloadUrl: exportResult.downloadUrl,
                    expiresAt: exportResult.expiresAt
                }
            });
        } catch (error) {
            this.logger.error('Error exporting system data', error);
            next(error);
        }
    }
}

module.exports = new SuperAdminController();