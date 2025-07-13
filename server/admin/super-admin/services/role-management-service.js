/**
 * @file Role Management Service
 * @description Service for managing admin roles and permissions
 * @module admin/super-admin/services
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminCacheService } = require('../../../shared/admin/services/admin-cache-service');
const { AdminBaseService } = require('../../../shared/admin/services/admin-base-service');
const { ADMIN_ROLES } = require('../../../shared/admin/constants/admin-roles');
const { ADMIN_PERMISSIONS } = require('../../../shared/admin/constants/admin-permissions');
const User = require('../../../models/user-model');
const AdminRole = require('../../../models/admin-role-model');
const AdminRoleAssignment = require('../../../models/admin-role-assignment-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

class RoleManagementService extends AdminBaseService {
    constructor() {
        super('RoleManagementService');
        this.cache = AdminCacheService.getInstance();
    }

    /**
     * Get all admin roles
     * @param {Object} options - Query options
     * @returns {Promise<Array>}
     */
    async getAllRoles(options = {}) {
        try {
            const { includePermissions = true, includeUsers = false } = options;
            const cacheKey = `admin:roles:all:${includePermissions}:${includeUsers}`;
            
            const cached = await this.cache.get(cacheKey);
            if (cached) {
                return cached;
            }

            // Get system-defined roles
            const systemRoles = await Promise.all(
                Object.entries(ADMIN_ROLES).map(async ([key, role]) => ({
                    id: key,
                    name: role.name,
                    description: role.description,
                    type: 'system',
                    isActive: true,
                    permissions: includePermissions ? role.permissions : undefined,
                    userCount: includeUsers ? await this.getRoleUserCount(key) : undefined,
                    users: includeUsers ? await this.getRoleUsers(key) : undefined
                }))
            );

            // Get custom roles
            const customRoles = await AdminRole.find({ isDeleted: false })
                .lean()
                .then(roles => Promise.all(
                    roles.map(async (role) => ({
                        id: role._id.toString(),
                        name: role.name,
                        description: role.description,
                        type: 'custom',
                        isActive: role.isActive,
                        permissions: includePermissions ? role.permissions : undefined,
                        userCount: includeUsers ? await this.getRoleUserCount(role._id) : undefined,
                        users: includeUsers ? await this.getRoleUsers(role._id) : undefined,
                        createdAt: role.createdAt,
                        createdBy: role.createdBy
                    }))
                ));

            const allRoles = [...systemRoles, ...customRoles];
            
            // Cache for 10 minutes
            await this.cache.set(cacheKey, allRoles, 600);
            
            return allRoles;
        } catch (error) {
            this.logger.error('Error fetching all roles', error);
            throw error;
        }
    }

    /**
     * Get role by ID
     * @param {String} roleId - Role ID
     * @returns {Promise<Object>}
     */
    async getRoleById(roleId) {
        try {
            // Check if it's a system role
            if (ADMIN_ROLES[roleId]) {
                const systemRole = ADMIN_ROLES[roleId];
                return {
                    id: roleId,
                    name: systemRole.name,
                    description: systemRole.description,
                    type: 'system',
                    isActive: true,
                    permissions: systemRole.permissions,
                    userCount: await this.getRoleUserCount(roleId)
                };
            }

            // Check custom roles
            const customRole = await AdminRole.findById(roleId).lean();
            if (!customRole) {
                return null;
            }

            return {
                id: customRole._id.toString(),
                name: customRole.name,
                description: customRole.description,
                type: 'custom',
                isActive: customRole.isActive,
                permissions: customRole.permissions,
                userCount: await this.getRoleUserCount(customRole._id),
                createdAt: customRole.createdAt,
                createdBy: customRole.createdBy
            };
        } catch (error) {
            this.logger.error('Error fetching role by ID', error);
            throw error;
        }
    }

    /**
     * Create custom admin role
     * @param {Object} roleData - Role data
     * @returns {Promise<Object>}
     */
    async createRole(roleData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { name, description, permissions, isActive, createdBy } = roleData;

            // Check if role name already exists
            const existingRole = await AdminRole.findOne({ 
                name: new RegExp(`^${name}$`, 'i'),
                isDeleted: false 
            });

            if (existingRole) {
                throw new Error('Role name already exists');
            }

            // Create new role
            const newRole = new AdminRole({
                name,
                description,
                permissions,
                isActive,
                createdBy,
                metadata: {
                    version: 1,
                    lastModified: new Date()
                }
            });

            await newRole.save({ session });
            await session.commitTransaction();

            // Clear roles cache
            await this.cache.invalidate('admin:roles:*');

            return {
                id: newRole._id.toString(),
                name: newRole.name,
                description: newRole.description,
                permissions: newRole.permissions,
                isActive: newRole.isActive,
                type: 'custom',
                createdAt: newRole.createdAt
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error creating role', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Update admin role
     * @param {String} roleId - Role ID
     * @param {Object} updates - Updates to apply
     * @param {Object} updatedBy - User making the update
     * @returns {Promise<Object>}
     */
    async updateRole(roleId, updates, updatedBy) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const role = await AdminRole.findById(roleId).session(session);
            if (!role || role.isDeleted) {
                throw new Error('Role not found');
            }

            const previousPermissions = [...role.permissions];
            const allowedUpdates = ['name', 'description', 'permissions', 'isActive'];
            
            // Apply updates
            allowedUpdates.forEach(field => {
                if (updates[field] !== undefined) {
                    role[field] = updates[field];
                }
            });

            role.metadata.lastModified = new Date();
            role.metadata.lastModifiedBy = updatedBy.id;
            role.metadata.version += 1;

            await role.save({ session });

            // If permissions changed, update all users with this role
            if (updates.permissions) {
                await this.updateRoleUsersPermissions(roleId, updates.permissions, session);
            }

            await session.commitTransaction();

            // Clear caches
            await this.cache.invalidate('admin:roles:*');
            await this.cache.invalidate(`admin:role:${roleId}`);

            return {
                ...role.toObject(),
                previousPermissions
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error updating role', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Delete custom admin role
     * @param {String} roleId - Role ID
     * @param {Object} options - Deletion options
     * @returns {Promise<Object>}
     */
    async deleteRole(roleId, options = {}) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { reassignTo, deletedBy } = options;

            const role = await AdminRole.findById(roleId).session(session);
            if (!role || role.isDeleted) {
                throw new Error('Role not found');
            }

            // Get users with this role
            const affectedUsers = await User.find({ role: roleId }).session(session);

            // Reassign users if specified
            if (reassignTo) {
                await User.updateMany(
                    { role: roleId },
                    { 
                        $set: { 
                            role: reassignTo,
                            'adminMetadata.roleChangedAt': new Date(),
                            'adminMetadata.roleChangedBy': deletedBy
                        }
                    },
                    { session }
                );
            } else {
                // Remove role from users
                await User.updateMany(
                    { role: roleId },
                    { 
                        $unset: { role: 1 },
                        $set: {
                            'adminMetadata.roleRemovedAt': new Date(),
                            'adminMetadata.roleRemovedBy': deletedBy
                        }
                    },
                    { session }
                );
            }

            // Soft delete the role
            role.isDeleted = true;
            role.deletedAt = new Date();
            role.deletedBy = deletedBy;
            await role.save({ session });

            await session.commitTransaction();

            // Clear caches
            await this.cache.invalidate('admin:roles:*');
            await this.cache.invalidate(`admin:role:${roleId}`);

            return {
                roleId,
                roleName: role.name,
                affectedUsers: affectedUsers.length,
                reassignedTo: reassignTo
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error deleting role', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get all available permissions
     * @param {Object} options - Query options
     * @returns {Promise<Object>}
     */
    async getAllPermissions(options = {}) {
        try {
            const { category, includeDescription = true } = options;
            
            const permissions = {};
            
            Object.entries(ADMIN_PERMISSIONS).forEach(([cat, perms]) => {
                if (!category || cat === category) {
                    permissions[cat] = Object.entries(perms).map(([key, perm]) => ({
                        id: perm,
                        name: this.formatPermissionName(perm),
                        description: includeDescription ? this.getPermissionDescription(perm) : undefined,
                        category: cat
                    }));
                }
            });

            return permissions;
        } catch (error) {
            this.logger.error('Error fetching permissions', error);
            throw error;
        }
    }

    /**
     * Validate permissions
     * @param {Array} permissions - Permissions to validate
     * @returns {Promise<Array>} Invalid permissions
     */
    async validatePermissions(permissions) {
        try {
            const allPermissions = Object.values(ADMIN_PERMISSIONS).flat();
            const invalidPermissions = permissions.filter(perm => !allPermissions.includes(perm));
            
            return invalidPermissions;
        } catch (error) {
            this.logger.error('Error validating permissions', error);
            throw error;
        }
    }

    /**
     * Assign role to user
     * @param {Object} assignmentData - Assignment data
     * @returns {Promise<Object>}
     */
    async assignRoleToUser(assignmentData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { userId, roleId, expiresAt, assignedBy } = assignmentData;

            const user = await User.findById(userId).session(session);
            if (!user) {
                throw new Error('User not found');
            }

            const role = await this.getRoleById(roleId);
            if (!role) {
                throw new Error('Role not found');
            }

            const previousRole = user.role;

            // Update user role
            user.role = roleId;
            user.adminMetadata = user.adminMetadata || {};
            user.adminMetadata.roleAssignedAt = new Date();
            user.adminMetadata.roleAssignedBy = assignedBy;

            await user.save({ session });

            // Create role assignment record
            const assignment = new AdminRoleAssignment({
                userId,
                roleId,
                assignedBy,
                expiresAt,
                previousRole,
                metadata: {
                    userEmail: user.email,
                    roleName: role.name
                }
            });

            await assignment.save({ session });
            await session.commitTransaction();

            // Clear user cache
            await this.cache.invalidate(`user:${userId}`);

            return {
                userId,
                roleId,
                roleName: role.name,
                previousRole,
                expiresAt
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error assigning role', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Revoke user role
     * @param {Object} revocationData - Revocation data
     * @returns {Promise<Object>}
     */
    async revokeUserRole(revocationData) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { userId, reason, revokedBy } = revocationData;

            const user = await User.findById(userId).session(session);
            if (!user || !user.role) {
                throw new Error('User or role not found');
            }

            const revokedRole = user.role;

            // Remove role from user
            user.role = undefined;
            user.adminMetadata = user.adminMetadata || {};
            user.adminMetadata.roleRevokedAt = new Date();
            user.adminMetadata.roleRevokedBy = revokedBy;
            user.adminMetadata.revocationReason = reason;

            await user.save({ session });

            // Update role assignment record
            await AdminRoleAssignment.updateOne(
                { userId, roleId: revokedRole, status: 'active' },
                {
                    $set: {
                        status: 'revoked',
                        revokedAt: new Date(),
                        revokedBy,
                        revocationReason: reason
                    }
                },
                { session }
            );

            await session.commitTransaction();

            // Clear user cache
            await this.cache.invalidate(`user:${userId}`);

            return {
                userId,
                revokedRole,
                reason
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error revoking user role', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get user role history
     * @param {Object} options - Query options
     * @returns {Promise<Array>}
     */
    async getUserRoleHistory(options = {}) {
        try {
            const { userId, startDate, endDate, limit = 50 } = options;

            const query = { userId };
            
            if (startDate || endDate) {
                query.createdAt = {};
                if (startDate) query.createdAt.$gte = new Date(startDate);
                if (endDate) query.createdAt.$lte = new Date(endDate);
            }

            const history = await AdminRoleAssignment.find(query)
                .populate('assignedBy', 'email fullName')
                .populate('revokedBy', 'email fullName')
                .sort({ createdAt: -1 })
                .limit(limit)
                .lean();

            return history.map(record => ({
                ...record,
                roleName: this.getRoleNameById(record.roleId),
                previousRoleName: record.previousRole ? this.getRoleNameById(record.previousRole) : null
            }));
        } catch (error) {
            this.logger.error('Error fetching role history', error);
            throw error;
        }
    }

    /**
     * Clone existing role
     * @param {Object} cloneData - Clone data
     * @returns {Promise<Object>}
     */
    async cloneRole(cloneData) {
        try {
            const { sourceRoleId, name, description, modifications = {}, clonedBy } = cloneData;

            const sourceRole = await this.getRoleById(sourceRoleId);
            if (!sourceRole) {
                throw new Error('Source role not found');
            }

            // Get source permissions and apply modifications
            let permissions = [...sourceRole.permissions];
            
            if (modifications.addPermissions) {
                permissions = [...new Set([...permissions, ...modifications.addPermissions])];
            }
            
            if (modifications.removePermissions) {
                permissions = permissions.filter(p => !modifications.removePermissions.includes(p));
            }

            // Create cloned role
            return this.createRole({
                name,
                description: description || `Cloned from ${sourceRole.name}`,
                permissions,
                isActive: true,
                createdBy: clonedBy
            });
        } catch (error) {
            this.logger.error('Error cloning role', error);
            throw error;
        }
    }

    // Private helper methods

    async getRoleUserCount(roleId) {
        return User.countDocuments({ role: roleId, status: 'active' });
    }

    async getRoleUsers(roleId) {
        return User.find({ role: roleId, status: 'active' })
            .select('email fullName status')
            .limit(10)
            .lean();
    }

    async updateRoleUsersPermissions(roleId, newPermissions, session) {
        await User.updateMany(
            { role: roleId },
            {
                $set: {
                    permissions: newPermissions,
                    'adminMetadata.permissionsUpdatedAt': new Date()
                }
            },
            { session }
        );
    }

    formatPermissionName(permission) {
        return permission
            .split(':')
            .map(part => part.charAt(0).toUpperCase() + part.slice(1))
            .join(' - ')
            .replace(/_/g, ' ');
    }

    getPermissionDescription(permission) {
        const descriptions = {
            'users:read': 'View user information and lists',
            'users:write': 'Create and update user accounts',
            'users:delete': 'Delete user accounts',
            'organizations:read': 'View organization information',
            'organizations:write': 'Create and update organizations',
            'organizations:delete': 'Delete organizations',
            'billing:access': 'Access billing and payment information',
            'security:access': 'Access security settings and logs',
            'monitoring:access': 'Access system monitoring data',
            'platform:read': 'View platform settings',
            'platform:write': 'Modify platform settings',
            'system:config:write': 'Modify system configuration',
            'reports:access': 'Generate and view reports',
            'support:read': 'View support tickets',
            'support:write': 'Manage support tickets'
        };

        return descriptions[permission] || 'No description available';
    }

    getRoleNameById(roleId) {
        if (ADMIN_ROLES[roleId]) {
            return ADMIN_ROLES[roleId].name;
        }
        
        // For custom roles, would need to fetch from DB
        return roleId;
    }
}

module.exports = RoleManagementService;