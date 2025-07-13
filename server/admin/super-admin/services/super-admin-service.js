/**
 * @file Super Admin Service
 * @description Core service for super admin operations and system management
 * @module admin/super-admin/services
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { AdminLogger } = require('../../../shared/admin/utils/admin-logger');
const { AdminHelpers } = require('../../../shared/admin/utils/admin-helpers');
const { AdminCacheService } = require('../../../shared/admin/services/admin-cache-service');
const { AdminBaseService } = require('../../../shared/admin/services/admin-base-service');
const { AdminMetrics } = require('../../../shared/admin/utils/admin-metrics');
const { ADMIN_ROLES } = require('../../../shared/admin/constants/admin-roles');
const { ADMIN_PERMISSIONS } = require('../../../shared/admin/constants/admin-permissions');
const User = require('../../../models/user-model');
const Organization = require('../../../models/organization-model');
const AdminSession = require('../../../shared/admin/models/admin-session-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');
const config = require('../../../config/configuration');

class SuperAdminService extends AdminBaseService {
    constructor() {
        super('SuperAdminService');
        this.cache = AdminCacheService.getInstance();
        this.metrics = AdminMetrics.getInstance();
    }

    /**
     * Get super admin dashboard data
     * @returns {Promise<Object>}
     */
    async getSuperAdminDashboard() {
        try {
            const cacheKey = 'super_admin:dashboard';
            const cached = await this.cache.get(cacheKey);
            
            if (cached) {
                return cached;
            }

            // Gather dashboard data
            const [
                systemStats,
                adminActivity,
                criticalAlerts,
                performanceMetrics,
                securitySummary
            ] = await Promise.all([
                this.getSystemStatistics(),
                this.getRecentAdminActivity(),
                this.getCriticalAlerts(),
                this.getPerformanceMetrics(),
                this.getSecuritySummary()
            ]);

            const dashboardData = {
                systemStats,
                adminActivity,
                criticalAlerts,
                performanceMetrics,
                securitySummary,
                lastUpdated: new Date()
            };

            // Cache for 5 minutes
            await this.cache.set(cacheKey, dashboardData, 300);

            return dashboardData;
        } catch (error) {
            this.logger.error('Error getting super admin dashboard', error);
            throw error;
        }
    }

    /**
     * Get system overview and statistics
     * @returns {Promise<Object>}
     */
    async getSystemOverview() {
        try {
            const overview = {
                environment: {
                    nodeEnv: config.app.env,
                    appVersion: config.app.version,
                    nodeVersion: process.version,
                    uptime: process.uptime(),
                    memory: process.memoryUsage()
                },
                database: await this.getDatabaseStats(),
                resources: await this.getResourceUsage(),
                features: this.getEnabledFeatures(),
                health: await this.getSystemHealth()
            };

            return overview;
        } catch (error) {
            this.logger.error('Error getting system overview', error);
            throw error;
        }
    }

    /**
     * Get all admin users with filtering
     * @param {Object} options - Query options
     * @returns {Promise<Object>}
     */
    async getAdminUsers(options = {}) {
        try {
            const {
                page = 1,
                limit = 20,
                role,
                status,
                search,
                sortBy = 'createdAt',
                sortOrder = 'desc'
            } = options;

            const query = {
                $or: [
                    { role: { $in: Object.keys(ADMIN_ROLES) } },
                    { 'permissions.0': { $exists: true } }
                ]
            };

            // Apply filters
            if (role) {
                query.role = role;
            }

            if (status) {
                query.status = status;
            }

            if (search) {
                query.$and = [
                    query.$or || { $or: [] },
                    {
                        $or: [
                            { email: new RegExp(search, 'i') },
                            { fullName: new RegExp(search, 'i') }
                        ]
                    }
                ];
            }

            const totalCount = await User.countDocuments(query);
            const users = await User.find(query)
                .select('-password -refreshTokens -twoFactorSecret')
                .sort({ [sortBy]: sortOrder === 'desc' ? -1 : 1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();

            // Enhance with additional data
            const enhancedUsers = await Promise.all(
                users.map(async (user) => {
                    const lastActivity = await this.getLastAdminActivity(user._id);
                    const activeSession = await this.getActiveAdminSession(user._id);

                    return {
                        ...user,
                        lastActivity,
                        hasActiveSession: !!activeSession,
                        permissions: await this.getUserEffectivePermissions(user)
                    };
                })
            );

            return {
                users: enhancedUsers,
                pagination: {
                    total: totalCount,
                    page,
                    limit,
                    pages: Math.ceil(totalCount / limit)
                }
            };
        } catch (error) {
            this.logger.error('Error fetching admin users', error);
            throw error;
        }
    }

    /**
     * Create new admin user
     * @param {Object} adminData - Admin user data
     * @param {Object} createdBy - User creating the admin
     * @returns {Promise<Object>}
     */
    async createAdminUser(adminData, createdBy) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { email, password, fullName, role, permissions = [] } = adminData;

            // Check if user already exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                throw new Error('User with this email already exists');
            }

            // Validate role
            if (!ADMIN_ROLES[role]) {
                throw new Error('Invalid admin role');
            }

            // Hash password
            const hashedPassword = await bcrypt.hash(password, config.auth.saltRounds);

            // Create admin user
            const newAdmin = new User({
                email,
                password: hashedPassword,
                fullName,
                role,
                permissions,
                status: 'active',
                emailVerified: true, // Skip email verification for admin-created users
                createdBy: createdBy.id,
                adminMetadata: {
                    createdAt: new Date(),
                    createdBy: createdBy.id,
                    createdByEmail: createdBy.email
                }
            });

            await newAdmin.save({ session });

            // Create initial admin session
            await AdminSession.create([{
                userId: newAdmin._id,
                role: newAdmin.role,
                permissions: newAdmin.permissions,
                createdBy: createdBy.id,
                metadata: {
                    initialCreation: true
                }
            }], { session });

            await session.commitTransaction();

            // Send welcome email
            await this.sendAdminWelcomeEmail(newAdmin, createdBy);

            return {
                id: newAdmin._id,
                email: newAdmin.email,
                fullName: newAdmin.fullName,
                role: newAdmin.role,
                status: newAdmin.status
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error creating admin user', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Update admin user
     * @param {String} adminId - Admin user ID
     * @param {Object} updates - Updates to apply
     * @param {Object} updatedBy - User making the update
     * @returns {Promise<Object>}
     */
    async updateAdminUser(adminId, updates, updatedBy) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const admin = await User.findById(adminId).session(session);
            if (!admin) {
                throw new Error('Admin user not found');
            }

            const previousRole = admin.role;
            const allowedUpdates = ['fullName', 'role', 'permissions', 'status'];
            const updateData = {};

            // Filter allowed updates
            Object.keys(updates).forEach(key => {
                if (allowedUpdates.includes(key)) {
                    updateData[key] = updates[key];
                }
            });

            // Validate role change
            if (updateData.role && !ADMIN_ROLES[updateData.role]) {
                throw new Error('Invalid admin role');
            }

            // Apply updates
            Object.assign(admin, updateData);
            admin.adminMetadata = admin.adminMetadata || {};
            admin.adminMetadata.lastModifiedAt = new Date();
            admin.adminMetadata.lastModifiedBy = updatedBy.id;

            await admin.save({ session });

            // If role changed, invalidate sessions
            if (updateData.role && updateData.role !== previousRole) {
                await this.invalidateUserSessions(adminId, session);
            }

            await session.commitTransaction();

            // Clear cache
            await this.cache.invalidate(`user:${adminId}`);

            return {
                ...admin.toObject(),
                previousRole
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error updating admin user', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Revoke admin access
     * @param {String} adminId - Admin user ID
     * @param {Object} options - Revocation options
     * @returns {Promise<Object>}
     */
    async revokeAdminAccess(adminId, options = {}) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const { reason, immediate, revokedBy } = options;

            const admin = await User.findById(adminId).session(session);
            if (!admin) {
                throw new Error('Admin user not found');
            }

            // Update user status
            admin.status = 'suspended';
            admin.suspensionReason = reason;
            admin.suspendedAt = new Date();
            admin.suspendedBy = revokedBy;

            await admin.save({ session });

            // Terminate all sessions
            const sessionsTerminated = await AdminSession.updateMany(
                { userId: adminId, status: 'active' },
                {
                    $set: {
                        status: 'terminated',
                        terminatedAt: new Date(),
                        terminationReason: `Admin access revoked: ${reason}`
                    }
                },
                { session }
            );

            // Clear all user tokens
            admin.refreshTokens = [];
            await admin.save({ session });

            await session.commitTransaction();

            // Clear cache
            await this.cache.invalidate(`user:${adminId}`);
            await this.cache.invalidate(`admin:sessions:${adminId}`);

            return {
                adminId,
                status: 'revoked',
                sessionsTerminated: sessionsTerminated.modifiedCount,
                revokedAt: new Date()
            };
        } catch (error) {
            await session.abortTransaction();
            this.logger.error('Error revoking admin access', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get system activity logs
     * @param {Object} filters - Filter options
     * @returns {Promise<Object>}
     */
    async getSystemActivityLogs(filters = {}) {
        try {
            const {
                startDate,
                endDate,
                userId,
                action,
                severity,
                page = 1,
                limit = 50
            } = filters;

            const query = {};

            if (startDate || endDate) {
                query.timestamp = {};
                if (startDate) query.timestamp.$gte = new Date(startDate);
                if (endDate) query.timestamp.$lte = new Date(endDate);
            }

            if (userId) query.userId = userId;
            if (action) query.action = new RegExp(action, 'i');
            if (severity) query.severity = severity;

            const totalCount = await AdminActionLog.countDocuments(query);
            const activities = await AdminActionLog.find(query)
                .populate('userId', 'email fullName role')
                .sort({ timestamp: -1 })
                .skip((page - 1) * limit)
                .limit(limit)
                .lean();

            return {
                activities,
                pagination: {
                    total: totalCount,
                    page,
                    limit,
                    pages: Math.ceil(totalCount / limit)
                }
            };
        } catch (error) {
            this.logger.error('Error fetching system activity logs', error);
            throw error;
        }
    }

    /**
     * Execute maintenance task
     * @param {String} task - Task name
     * @param {Object} parameters - Task parameters
     * @param {Object} executedBy - User executing the task
     * @returns {Promise<Object>}
     */
    async executeMaintenanceTask(task, parameters, executedBy) {
        try {
            this.logger.warn(`Executing maintenance task: ${task}`, {
                executedBy: executedBy.id,
                parameters
            });

            let result;

            switch (task) {
                case 'clear_cache':
                    result = await this.clearSystemCache(parameters);
                    break;
                case 'cleanup_sessions':
                    result = await this.cleanupExpiredSessions(parameters);
                    break;
                case 'optimize_database':
                    result = await this.optimizeDatabase(parameters);
                    break;
                case 'rotate_logs':
                    result = await this.rotateLogs(parameters);
                    break;
                case 'backup_database':
                    result = await this.backupDatabase(parameters);
                    break;
                default:
                    throw new Error(`Unknown maintenance task: ${task}`);
            }

            return {
                task,
                status: 'completed',
                summary: result,
                executedAt: new Date(),
                executedBy: executedBy.id
            };
        } catch (error) {
            this.logger.error('Error executing maintenance task', error);
            throw error;
        }
    }

    /**
     * Get super admin permissions
     * @returns {Promise<Object>}
     */
    async getSuperAdminPermissions() {
        return {
            role: ADMIN_ROLES.SUPER_ADMIN,
            permissions: Object.values(ADMIN_PERMISSIONS).flat(),
            description: 'Super Admin has full system access',
            restrictions: []
        };
    }

    /**
     * Export system data
     * @param {Object} options - Export options
     * @returns {Promise<Object>}
     */
    async exportSystemData(options = {}) {
        try {
            const { dataType, format, filters, requestedBy } = options;
            
            this.logger.info('Exporting system data', {
                dataType,
                format,
                requestedBy: requestedBy.id
            });

            let data;
            let recordCount = 0;

            switch (dataType) {
                case 'users':
                    data = await this.exportUsers(filters);
                    recordCount = data.length;
                    break;
                case 'organizations':
                    data = await this.exportOrganizations(filters);
                    recordCount = data.length;
                    break;
                case 'audit_logs':
                    data = await this.exportAuditLogs(filters);
                    recordCount = data.length;
                    break;
                case 'system_config':
                    data = await this.exportSystemConfig(filters);
                    recordCount = Object.keys(data).length;
                    break;
                default:
                    throw new Error(`Unsupported data type: ${dataType}`);
            }

            // Format data
            const formatted = await this.formatExportData(data, format);
            
            // Store export temporarily
            const exportId = await this.storeExport(formatted, {
                dataType,
                format,
                recordCount,
                requestedBy: requestedBy.id
            });

            return {
                exportId,
                status: 'ready',
                recordCount,
                fileSize: formatted.length,
                downloadUrl: `/api/admin/exports/${exportId}`,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
            };
        } catch (error) {
            this.logger.error('Error exporting system data', error);
            throw error;
        }
    }

    // Private helper methods

    async getSystemStatistics() {
        const [userCount, orgCount, activeAdmins] = await Promise.all([
            User.countDocuments(),
            Organization.countDocuments(),
            User.countDocuments({ 
                role: { $in: Object.keys(ADMIN_ROLES) },
                status: 'active'
            })
        ]);

        return {
            totalUsers: userCount,
            totalOrganizations: orgCount,
            activeAdmins,
            systemUptime: process.uptime()
        };
    }

    async getRecentAdminActivity() {
        return AdminActionLog.find({ severity: { $in: ['high', 'critical'] } })
            .populate('userId', 'email fullName')
            .sort({ timestamp: -1 })
            .limit(10)
            .lean();
    }

    async getCriticalAlerts() {
        // Placeholder - would integrate with monitoring system
        return [];
    }

    async getPerformanceMetrics() {
        return {
            cpuUsage: process.cpuUsage(),
            memoryUsage: process.memoryUsage(),
            uptime: process.uptime()
        };
    }

    async getSecuritySummary() {
        const recentBreaches = await AdminActionLog.countDocuments({
            action: { $regex: /security\.breach/i },
            timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });

        return {
            recentSecurityEvents: recentBreaches,
            mfaEnabled: config.auth.twoFactor.enabled,
            lastSecurityAudit: new Date() // Placeholder
        };
    }

    async getDatabaseStats() {
        const stats = await mongoose.connection.db.stats();
        return {
            collections: stats.collections,
            dataSize: stats.dataSize,
            indexSize: stats.indexSize,
            totalSize: stats.totalSize
        };
    }

    async getResourceUsage() {
        return {
            cpu: process.cpuUsage(),
            memory: process.memoryUsage(),
            uptime: process.uptime()
        };
    }

    getEnabledFeatures() {
        return config.features;
    }

    async getSystemHealth() {
        // Placeholder - would check various system components
        return {
            status: 'healthy',
            components: {
                database: 'healthy',
                cache: 'healthy',
                storage: 'healthy'
            }
        };
    }

    async getLastAdminActivity(userId) {
        const lastAction = await AdminActionLog.findOne({ userId })
            .sort({ timestamp: -1 })
            .lean();
        
        return lastAction?.timestamp || null;
    }

    async getActiveAdminSession(userId) {
        return AdminSession.findOne({
            userId,
            status: 'active',
            expiresAt: { $gt: new Date() }
        }).lean();
    }

    async getUserEffectivePermissions(user) {
        if (user.role === 'super_admin') {
            return Object.values(ADMIN_PERMISSIONS).flat();
        }
        
        const rolePermissions = ADMIN_ROLES[user.role]?.permissions || [];
        return [...new Set([...rolePermissions, ...(user.permissions || [])])];
    }

    async invalidateUserSessions(userId, session) {
        await AdminSession.updateMany(
            { userId, status: 'active' },
            { 
                $set: { 
                    status: 'invalidated',
                    invalidatedAt: new Date()
                }
            },
            { session }
        );
    }

    async sendAdminWelcomeEmail(admin, createdBy) {
        // Placeholder - would integrate with email service
        this.logger.info('Sending admin welcome email', {
            to: admin.email,
            createdBy: createdBy.email
        });
    }

    // Maintenance task implementations

    async clearSystemCache(parameters) {
        const { pattern = '*' } = parameters;
        const cleared = await this.cache.invalidate(pattern);
        return { cleared, pattern };
    }

    async cleanupExpiredSessions(parameters) {
        const { olderThan = 30 } = parameters;
        const cutoffDate = new Date(Date.now() - olderThan * 24 * 60 * 60 * 1000);
        
        const result = await AdminSession.deleteMany({
            $or: [
                { expiresAt: { $lt: new Date() } },
                { createdAt: { $lt: cutoffDate }, status: 'inactive' }
            ]
        });

        return { deleted: result.deletedCount };
    }

    async optimizeDatabase(parameters) {
        // Placeholder - would run database optimization
        return { status: 'optimized', collections: [] };
    }

    async rotateLogs(parameters) {
        // Placeholder - would rotate application logs
        return { rotated: true, files: [] };
    }

    async backupDatabase(parameters) {
        // Placeholder - would trigger database backup
        return { backupId: `backup-${Date.now()}`, status: 'initiated' };
    }

    // Export helper methods

    async exportUsers(filters) {
        const query = filters || {};
        return User.find(query)
            .select('-password -twoFactorSecret -refreshTokens')
            .lean();
    }

    async exportOrganizations(filters) {
        const query = filters || {};
        return Organization.find(query).lean();
    }

    async exportAuditLogs(filters) {
        const query = filters || {};
        return AdminActionLog.find(query).lean();
    }

    async exportSystemConfig(filters) {
        // Return sanitized config
        return {
            app: config.app,
            features: config.features,
            limits: config.organization.defaultLimits
        };
    }

    async formatExportData(data, format) {
        switch (format) {
            case 'json':
                return JSON.stringify(data, null, 2);
            case 'csv':
                // Placeholder - would convert to CSV
                return JSON.stringify(data);
            default:
                return JSON.stringify(data);
        }
    }

    async storeExport(data, metadata) {
        // Placeholder - would store in temporary storage
        const exportId = `export-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        await this.cache.set(`export:${exportId}`, {
            data,
            metadata
        }, 86400); // 24 hours
        
        return exportId;
    }
}

module.exports = SuperAdminService;