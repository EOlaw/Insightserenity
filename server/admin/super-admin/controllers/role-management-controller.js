/**
 * @file Role Management Controller
 * @description Handles admin role and permission management
 * @module admin/super-admin/controllers
 * @version 1.0.0
 */

const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../../../shared/admin/utils/admin-helpers');
const { ADMIN_ACTIONS } = require('../../../shared/admin/constants/admin-actions');
const { ADMIN_EVENTS } = require('../../../shared/admin/constants/admin-events');
const { ADMIN_ROLES } = require('../../../shared/admin/constants/admin-roles');
const { ADMIN_PERMISSIONS } = require('../../../shared/admin/constants/admin-permissions');
const RoleManagementService = require('../services/role-management-service');
const { AuditService } = require('../../../shared/services/audit-service');

class RoleManagementController {
    constructor() {
        this.logger = new AdminLogger('RoleManagementController');
        this.service = new RoleManagementService();
        this.auditService = new AuditService();
    }

    /**
     * Get all admin roles
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getRoles(req, res, next) {
        try {
            const { includePermissions = true, includeUsers = false } = req.query;

            this.logger.info('Fetching admin roles', {
                adminId: req.user.id,
                includePermissions,
                includeUsers
            });

            const roles = await this.service.getAllRoles({
                includePermissions: includePermissions === 'true',
                includeUsers: includeUsers === 'true'
            });

            res.json({
                success: true,
                data: roles
            });
        } catch (error) {
            this.logger.error('Error fetching roles', error);
            next(error);
        }
    }

    /**
     * Get role by ID
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getRoleById(req, res, next) {
        try {
            const { id } = req.params;

            this.logger.info('Fetching role details', {
                adminId: req.user.id,
                roleId: id
            });

            const role = await this.service.getRoleById(id);

            if (!role) {
                return res.status(404).json({
                    success: false,
                    error: {
                        message: 'Role not found',
                        code: 'ROLE_NOT_FOUND'
                    }
                });
            }

            res.json({
                success: true,
                data: role
            });
        } catch (error) {
            this.logger.error('Error fetching role', error);
            next(error);
        }
    }

    /**
     * Create custom admin role
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async createRole(req, res, next) {
        try {
            const { name, description, permissions, isActive = true } = req.body;

            this.logger.info('Creating new admin role', {
                adminId: req.user.id,
                roleName: name,
                permissionCount: permissions?.length
            });

            // Validate permissions
            const invalidPermissions = await this.service.validatePermissions(permissions);
            if (invalidPermissions.length > 0) {
                return res.status(400).json({
                    success: false,
                    error: {
                        message: 'Invalid permissions provided',
                        code: 'INVALID_PERMISSIONS',
                        details: { invalidPermissions }
                    }
                });
            }

            const newRole = await this.service.createRole({
                name,
                description,
                permissions,
                isActive,
                createdBy: req.user.id
            });

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.ROLE_MANAGEMENT.CREATE_ROLE,
                userId: req.user.id,
                resourceType: 'admin_role',
                resourceId: newRole.id,
                details: {
                    name,
                    permissions,
                    isActive
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.ROLE_CREATED, {
                roleId: newRole.id,
                roleName: name,
                createdBy: req.user.id
            });

            res.status(201).json({
                success: true,
                message: 'Role created successfully',
                data: newRole
            });
        } catch (error) {
            this.logger.error('Error creating role', error);
            next(error);
        }
    }

    /**
     * Update admin role
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async updateRole(req, res, next) {
        try {
            const { id } = req.params;
            const updates = req.body;

            this.logger.info('Updating admin role', {
                adminId: req.user.id,
                roleId: id,
                updates: Object.keys(updates)
            });

            // Prevent modification of system roles
            const systemRoles = Object.values(ADMIN_ROLES).map(r => r.id);
            if (systemRoles.includes(id)) {
                return res.status(400).json({
                    success: false,
                    error: {
                        message: 'System roles cannot be modified',
                        code: 'SYSTEM_ROLE_IMMUTABLE'
                    }
                });
            }

            // Validate permissions if updating
            if (updates.permissions) {
                const invalidPermissions = await this.service.validatePermissions(updates.permissions);
                if (invalidPermissions.length > 0) {
                    return res.status(400).json({
                        success: false,
                        error: {
                            message: 'Invalid permissions provided',
                            code: 'INVALID_PERMISSIONS',
                            details: { invalidPermissions }
                        }
                    });
                }
            }

            const updatedRole = await this.service.updateRole(id, updates, req.user);

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.ROLE_MANAGEMENT.UPDATE_ROLE,
                userId: req.user.id,
                resourceType: 'admin_role',
                resourceId: id,
                details: {
                    updates,
                    previousPermissions: updatedRole.previousPermissions
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.ROLE_UPDATED, {
                roleId: id,
                updates,
                updatedBy: req.user.id
            });

            res.json({
                success: true,
                message: 'Role updated successfully',
                data: updatedRole
            });
        } catch (error) {
            this.logger.error('Error updating role', error);
            next(error);
        }
    }

    /**
     * Delete custom admin role
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async deleteRole(req, res, next) {
        try {
            const { id } = req.params;
            const { reassignTo } = req.body;

            this.logger.warn('Deleting admin role', {
                adminId: req.user.id,
                roleId: id,
                reassignTo
            });

            // Prevent deletion of system roles
            const systemRoles = Object.values(ADMIN_ROLES).map(r => r.id);
            if (systemRoles.includes(id)) {
                return res.status(400).json({
                    success: false,
                    error: {
                        message: 'System roles cannot be deleted',
                        code: 'SYSTEM_ROLE_PROTECTED'
                    }
                });
            }

            const result = await this.service.deleteRole(id, {
                reassignTo,
                deletedBy: req.user.id
            });

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.ROLE_MANAGEMENT.DELETE_ROLE,
                userId: req.user.id,
                resourceType: 'admin_role',
                resourceId: id,
                details: {
                    reassignedTo: reassignTo,
                    affectedUsers: result.affectedUsers
                },
                severity: 'critical'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.ROLE_DELETED, {
                roleId: id,
                deletedBy: req.user.id,
                affectedUsers: result.affectedUsers
            });

            res.json({
                success: true,
                message: 'Role deleted successfully',
                data: result
            });
        } catch (error) {
            this.logger.error('Error deleting role', error);
            next(error);
        }
    }

    /**
     * Get all available permissions
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getPermissions(req, res, next) {
        try {
            const { category, includeDescription = true } = req.query;

            this.logger.info('Fetching available permissions', {
                adminId: req.user.id,
                category
            });

            const permissions = await this.service.getAllPermissions({
                category,
                includeDescription: includeDescription === 'true'
            });

            res.json({
                success: true,
                data: permissions
            });
        } catch (error) {
            this.logger.error('Error fetching permissions', error);
            next(error);
        }
    }

    /**
     * Assign role to admin user
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async assignRole(req, res, next) {
        try {
            const { userId, roleId, expiresAt } = req.body;

            this.logger.info('Assigning role to admin user', {
                adminId: req.user.id,
                targetUserId: userId,
                roleId,
                expiresAt
            });

            const result = await this.service.assignRoleToUser({
                userId,
                roleId,
                expiresAt,
                assignedBy: req.user.id
            });

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.ROLE_MANAGEMENT.ASSIGN_ROLE,
                userId: req.user.id,
                resourceType: 'admin_user',
                resourceId: userId,
                details: {
                    roleId,
                    previousRole: result.previousRole,
                    expiresAt
                },
                severity: 'high'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.ROLE_ASSIGNED, {
                userId,
                roleId,
                previousRole: result.previousRole,
                assignedBy: req.user.id
            });

            // Send notification
            await req.adminContext.notifications.sendNotification({
                userId,
                type: 'role_assigned',
                data: {
                    newRole: result.roleName,
                    assignedBy: req.user.email,
                    expiresAt
                }
            });

            res.json({
                success: true,
                message: 'Role assigned successfully',
                data: result
            });
        } catch (error) {
            this.logger.error('Error assigning role', error);
            next(error);
        }
    }

    /**
     * Revoke role from admin user
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async revokeRole(req, res, next) {
        try {
            const { userId } = req.params;
            const { reason } = req.body;

            this.logger.warn('Revoking role from admin user', {
                adminId: req.user.id,
                targetUserId: userId,
                reason
            });

            const result = await this.service.revokeUserRole({
                userId,
                reason,
                revokedBy: req.user.id
            });

            // Audit critical action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.ROLE_MANAGEMENT.REVOKE_ROLE,
                userId: req.user.id,
                resourceType: 'admin_user',
                resourceId: userId,
                details: {
                    revokedRole: result.revokedRole,
                    reason
                },
                severity: 'high'
            });

            // Emit event
            req.adminContext.events.emit(ADMIN_EVENTS.ROLE_REVOKED, {
                userId,
                revokedRole: result.revokedRole,
                revokedBy: req.user.id,
                reason
            });

            res.json({
                success: true,
                message: 'Role revoked successfully',
                data: result
            });
        } catch (error) {
            this.logger.error('Error revoking role', error);
            next(error);
        }
    }

    /**
     * Get role assignment history
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async getRoleHistory(req, res, next) {
        try {
            const { userId } = req.params;
            const { startDate, endDate, limit = 50 } = req.query;

            this.logger.info('Fetching role assignment history', {
                adminId: req.user.id,
                userId,
                dateRange: { startDate, endDate }
            });

            const history = await this.service.getUserRoleHistory({
                userId,
                startDate,
                endDate,
                limit: parseInt(limit)
            });

            res.json({
                success: true,
                data: history
            });
        } catch (error) {
            this.logger.error('Error fetching role history', error);
            next(error);
        }
    }

    /**
     * Clone existing role
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next middleware function
     */
    async cloneRole(req, res, next) {
        try {
            const { id } = req.params;
            const { name, description, modifications = {} } = req.body;

            this.logger.info('Cloning admin role', {
                adminId: req.user.id,
                sourceRoleId: id,
                newName: name
            });

            const clonedRole = await this.service.cloneRole({
                sourceRoleId: id,
                name,
                description,
                modifications,
                clonedBy: req.user.id
            });

            // Audit action
            await this.auditService.logAction({
                action: ADMIN_ACTIONS.ROLE_MANAGEMENT.CLONE_ROLE,
                userId: req.user.id,
                resourceType: 'admin_role',
                resourceId: clonedRole.id,
                details: {
                    sourceRoleId: id,
                    modifications
                },
                severity: 'medium'
            });

            res.status(201).json({
                success: true,
                message: 'Role cloned successfully',
                data: clonedRole
            });
        } catch (error) {
            this.logger.error('Error cloning role', error);
            next(error);
        }
    }
}

module.exports = new RoleManagementController();