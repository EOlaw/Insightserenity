// server/admin/super-admin/services/role-management-service.js
/**
 * @file Role Management Service
 * @description Service for managing system-wide roles and permissions for super administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

// Core Models
const Role = require('../../../shared/users/models/role-model');
const Permission = require('../../../shared/users/models/permission-model');
const User = require('../../../shared/users/models/user-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError, ConflictError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

// Configuration
const config = require('../../../config');

/**
 * Role Management Service Class
 * @class RoleManagementService
 * @extends AdminBaseService
 */
class RoleManagementService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'RoleManagementService';
    this.cachePrefix = 'role-management';
    this.auditCategory = 'ROLE_MANAGEMENT';
    this.requiredPermission = AdminPermissions.SUPER_ADMIN.ROLE_MANAGEMENT;

    // Predefined system roles that cannot be deleted
    this.systemRoles = [
      'super_admin',
      'platform_admin',
      'support_admin',
      'org_owner',
      'org_admin',
      'org_member',
      'guest'
    ];

    // Permission categories
    this.permissionCategories = {
      SYSTEM: 'system',
      ORGANIZATION: 'organization',
      USER: 'user',
      BILLING: 'billing',
      CONTENT: 'content',
      API: 'api',
      REPORTING: 'reporting'
    };
  }

  /**
   * Get all roles with detailed information
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Paginated roles list
   */
  async getAllRoles(adminUser, options = {}) {
    try {
      await this.validateAccess(adminUser, 'read');

      const {
        page = 1,
        limit = 20,
        search = '',
        category = null,
        includeSystem = true,
        includeCustom = true,
        sortBy = 'priority',
        sortOrder = 'asc'
      } = options;

      // Build query
      const query = {};

      if (search) {
        query.$or = [
          { name: new RegExp(search, 'i') },
          { displayName: new RegExp(search, 'i') },
          { description: new RegExp(search, 'i') }
        ];
      }

      if (category) {
        query.category = category;
      }

      if (!includeSystem) {
        query.isSystem = false;
      }

      if (!includeCustom) {
        query.isSystem = true;
      }

      // Execute query with pagination
      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };

      const [roles, totalCount] = await Promise.all([
        Role.find(query)
          .populate('permissions')
          .populate('createdBy', 'email profile.firstName profile.lastName')
          .populate('updatedBy', 'email profile.firstName profile.lastName')
          .sort(sort)
          .limit(limit)
          .skip(skip),
        Role.countDocuments(query)
      ]);

      // Enhance role data with usage statistics
      const enhancedRoles = await Promise.all(
        roles.map(async (role) => {
          const [userCount, orgCount] = await Promise.all([
            User.countDocuments({ 'role.primary': role.name }),
            HostedOrganization.countDocuments({ 
              'settings.defaultRoles': role.name 
            })
          ]);

          return {
            ...role.toObject(),
            usage: {
              users: userCount,
              organizations: orgCount,
              lastAssigned: await this.getLastAssignedDate(role.name)
            },
            canDelete: !this.systemRoles.includes(role.name) && userCount === 0,
            canModify: !role.isSystem || adminUser.permissions?.system?.includes('override')
          };
        })
      );

      await this.auditLog(adminUser, AdminEvents.ROLE_MANAGEMENT.ROLES_VIEWED, {
        count: enhancedRoles.length,
        filters: { search, category, includeSystem, includeCustom }
      });

      return {
        roles: enhancedRoles,
        pagination: {
          page,
          limit,
          total: totalCount,
          pages: Math.ceil(totalCount / limit)
        },
        metadata: {
          systemRolesCount: await Role.countDocuments({ isSystem: true }),
          customRolesCount: await Role.countDocuments({ isSystem: false }),
          categories: await this.getRoleCategories()
        }
      };

    } catch (error) {
      logger.error('Get all roles error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get detailed role information
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} roleId - Role ID or name
   * @returns {Promise<Object>} Detailed role information
   */
  async getRoleDetails(adminUser, roleId) {
    try {
      await this.validateAccess(adminUser, 'read');

      // Find role by ID or name
      const role = await Role.findOne({
        $or: [
          { _id: mongoose.Types.ObjectId.isValid(roleId) ? roleId : null },
          { name: roleId }
        ]
      })
      .populate('permissions')
      .populate('inheritedFrom')
      .populate('createdBy', 'email profile')
      .populate('updatedBy', 'email profile');

      if (!role) {
        throw new NotFoundError('Role not found');
      }

      // Get comprehensive role data
      const [
        userCount,
        recentAssignments,
        permissionMatrix,
        auditHistory
      ] = await Promise.all([
        User.countDocuments({ 'role.primary': role.name }),
        this.getRecentRoleAssignments(role.name, 10),
        this.buildPermissionMatrix(role),
        this.getRoleAuditHistory(role._id, 20)
      ]);

      const roleDetails = {
        ...role.toObject(),
        statistics: {
          totalUsers: userCount,
          activeUsers: await User.countDocuments({ 
            'role.primary': role.name,
            status: 'active'
          }),
          organizations: await HostedOrganization.countDocuments({
            'settings.defaultRoles': role.name
          })
        },
        recentAssignments,
        permissionMatrix,
        auditHistory,
        metadata: {
          isSystemRole: this.systemRoles.includes(role.name),
          canDelete: !this.systemRoles.includes(role.name) && userCount === 0,
          canModify: !role.isSystem || adminUser.permissions?.system?.includes('override'),
          dependencies: await this.getRoleDependencies(role.name)
        }
      };

      await this.auditLog(adminUser, AdminEvents.ROLE_MANAGEMENT.ROLE_VIEWED, {
        roleId: role._id,
        roleName: role.name
      });

      return roleDetails;

    } catch (error) {
      logger.error('Get role details error', {
        error: error.message,
        adminId: adminUser.id,
        roleId,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Create a new custom role
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} roleData - Role creation data
   * @returns {Promise<Object>} Created role
   */
  async createRole(adminUser, roleData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'create');

      const {
        name,
        displayName,
        description,
        category = 'custom',
        permissions = [],
        inheritFrom = null,
        priority = 100,
        constraints = {},
        metadata = {}
      } = roleData;

      // Validate role name
      if (!name || !/^[a-z0-9_]+$/.test(name)) {
        throw new ValidationError('Role name must contain only lowercase letters, numbers, and underscores');
      }

      // Check if role already exists
      const existingRole = await Role.findOne({ name }).session(session);
      if (existingRole) {
        throw new ConflictError(`Role with name '${name}' already exists`);
      }

      // Validate and process permissions
      const processedPermissions = await this.validateAndProcessPermissions(
        permissions,
        inheritFrom,
        session
      );

      // Create role object
      const newRole = new Role({
        name,
        displayName: displayName || name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        description,
        category,
        permissions: processedPermissions.permissionIds,
        inheritedFrom: inheritFrom ? await this.resolveRoleId(inheritFrom, session) : null,
        priority,
        constraints: {
          maxUsers: constraints.maxUsers || null,
          requireMFA: constraints.requireMFA || false,
          requireEmailVerification: constraints.requireEmailVerification || true,
          ipWhitelist: constraints.ipWhitelist || [],
          timeRestrictions: constraints.timeRestrictions || null,
          geographicRestrictions: constraints.geographicRestrictions || null
        },
        metadata: {
          ...metadata,
          source: 'admin_created',
          createdVia: 'super_admin_panel'
        },
        isSystem: false,
        isActive: true,
        createdBy: adminUser.id,
        updatedBy: adminUser.id
      });

      await newRole.save({ session });

      // Clear role-related caches
      await this.clearRoleCaches();

      // Create admin action log
      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'ROLE_CREATED',
        category: 'ROLE_MANAGEMENT',
        severity: 'MEDIUM',
        targetResource: {
          type: 'role',
          id: newRole._id,
          name: newRole.name
        },
        data: {
          role: newRole.toObject(),
          permissionCount: processedPermissions.permissionIds.length
        }
      }], { session });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.ROLE_MANAGEMENT.ROLE_CREATED, {
        roleId: newRole._id,
        roleName: newRole.name,
        category,
        permissionCount: processedPermissions.permissionIds.length
      }, { session, critical: false });

      // Send notification to other admins
      await NotificationService.notifyAdmins({
        type: 'role_created',
        priority: 'medium',
        data: {
          roleName: newRole.displayName,
          createdBy: `${adminUser.profile?.firstName || ''} ${adminUser.profile?.lastName || ''}`.trim() || adminUser.email,
          category
        }
      });

      await session.commitTransaction();

      // Return populated role
      const populatedRole = await Role.findById(newRole._id)
        .populate('permissions')
        .populate('inheritedFrom');

      return {
        role: populatedRole,
        message: 'Role created successfully',
        warnings: processedPermissions.warnings
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Create role error', {
        error: error.message,
        adminId: adminUser.id,
        roleName: roleData.name,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Update an existing role
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} roleId - Role ID or name
   * @param {Object} updateData - Role update data
   * @returns {Promise<Object>} Updated role
   */
  async updateRole(adminUser, roleId, updateData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'update');

      // Find role
      const role = await Role.findOne({
        $or: [
          { _id: mongoose.Types.ObjectId.isValid(roleId) ? roleId : null },
          { name: roleId }
        ]
      }).session(session);

      if (!role) {
        throw new NotFoundError('Role not found');
      }

      // Check if role can be modified
      if (role.isSystem && !adminUser.permissions?.system?.includes('override')) {
        throw new ForbiddenError('System roles cannot be modified without override permission');
      }

      // Store original state for comparison
      const originalRole = role.toObject();

      // Update allowed fields
      const allowedUpdates = [
        'displayName',
        'description',
        'permissions',
        'priority',
        'constraints',
        'metadata',
        'isActive'
      ];

      const updates = {};
      let permissionsUpdated = false;

      for (const field of allowedUpdates) {
        if (updateData[field] !== undefined) {
          if (field === 'permissions') {
            // Special handling for permissions
            const processedPermissions = await this.validateAndProcessPermissions(
              updateData.permissions,
              role.inheritedFrom,
              session
            );
            updates.permissions = processedPermissions.permissionIds;
            permissionsUpdated = true;
          } else if (field === 'constraints') {
            // Merge constraints
            updates.constraints = {
              ...role.constraints,
              ...updateData.constraints
            };
          } else {
            updates[field] = updateData[field];
          }
        }
      }

      // Apply updates
      Object.assign(role, updates);
      role.updatedBy = adminUser.id;
      role.updatedAt = new Date();

      await role.save({ session });

      // If permissions were updated, check affected users
      let affectedUsers = [];
      if (permissionsUpdated) {
        affectedUsers = await this.handlePermissionChanges(
          role,
          originalRole.permissions,
          updates.permissions,
          session
        );
      }

      // Clear caches
      await this.clearRoleCaches();
      if (affectedUsers.length > 0) {
        await this.clearUserPermissionCaches(affectedUsers);
      }

      // Create detailed change log
      const changes = this.compareRoleChanges(originalRole, role.toObject());

      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'ROLE_UPDATED',
        category: 'ROLE_MANAGEMENT',
        severity: permissionsUpdated ? 'HIGH' : 'MEDIUM',
        targetResource: {
          type: 'role',
          id: role._id,
          name: role.name
        },
        data: {
          changes,
          affectedUsers: affectedUsers.length,
          originalRole: this.sanitizeRoleForLog(originalRole),
          updatedRole: this.sanitizeRoleForLog(role.toObject())
        }
      }], { session });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.ROLE_MANAGEMENT.ROLE_UPDATED, {
        roleId: role._id,
        roleName: role.name,
        changes: Object.keys(changes),
        affectedUsers: affectedUsers.length
      }, { 
        session, 
        critical: permissionsUpdated && affectedUsers.length > 10 
      });

      // Notify affected users if significant changes
      if (permissionsUpdated && affectedUsers.length > 0) {
        await this.notifyAffectedUsers(role, changes, affectedUsers);
      }

      await session.commitTransaction();

      // Return updated role
      const updatedRole = await Role.findById(role._id)
        .populate('permissions')
        .populate('inheritedFrom');

      return {
        role: updatedRole,
        changes,
        affectedUsers: affectedUsers.length,
        message: 'Role updated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Update role error', {
        error: error.message,
        adminId: adminUser.id,
        roleId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Delete a custom role
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} roleId - Role ID or name
   * @param {Object} options - Deletion options
   * @returns {Promise<Object>} Deletion result
   */
  async deleteRole(adminUser, roleId, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'delete');

      const { 
        reassignTo = null,
        force = false,
        reason = 'Administrative action'
      } = options;

      // Find role
      const role = await Role.findOne({
        $or: [
          { _id: mongoose.Types.ObjectId.isValid(roleId) ? roleId : null },
          { name: roleId }
        ]
      }).session(session);

      if (!role) {
        throw new NotFoundError('Role not found');
      }

      // Check if role can be deleted
      if (this.systemRoles.includes(role.name)) {
        throw new ForbiddenError('System roles cannot be deleted');
      }

      if (role.isSystem && !force) {
        throw new ForbiddenError('System-marked roles require force flag to delete');
      }

      // Check for existing users
      const userCount = await User.countDocuments({ 
        'role.primary': role.name 
      }).session(session);

      if (userCount > 0 && !reassignTo) {
        throw new ValidationError(
          `Cannot delete role with ${userCount} assigned users. Provide reassignTo option.`
        );
      }

      // Handle user reassignment if needed
      let reassignedUsers = [];
      if (userCount > 0 && reassignTo) {
        // Validate target role
        const targetRole = await Role.findOne({
          $or: [
            { _id: mongoose.Types.ObjectId.isValid(reassignTo) ? reassignTo : null },
            { name: reassignTo }
          ]
        }).session(session);

        if (!targetRole) {
          throw new NotFoundError('Target role for reassignment not found');
        }

        // Reassign users
        const updateResult = await User.updateMany(
          { 'role.primary': role.name },
          {
            $set: {
              'role.primary': targetRole.name,
              'role.updatedAt': new Date(),
              'role.updatedBy': adminUser.id,
              'role.reassignedFrom': role.name
            }
          },
          { session }
        );

        reassignedUsers = await User.find({ 
          'role.primary': targetRole.name,
          'role.reassignedFrom': role.name
        })
        .select('_id email')
        .session(session);
      }

      // Remove role from organization defaults
      await HostedOrganization.updateMany(
        { 'settings.defaultRoles': role.name },
        { $pull: { 'settings.defaultRoles': role.name } },
        { session }
      );

      // Soft delete or hard delete based on configuration
      if (config.platform.softDelete) {
        role.deleted = true;
        role.deletedAt = new Date();
        role.deletedBy = adminUser.id;
        role.deletionReason = reason;
        await role.save({ session });
      } else {
        await role.deleteOne({ session });
      }

      // Clear caches
      await this.clearRoleCaches();
      if (reassignedUsers.length > 0) {
        await this.clearUserPermissionCaches(reassignedUsers.map(u => u._id));
      }

      // Create deletion record
      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'ROLE_DELETED',
        category: 'ROLE_MANAGEMENT',
        severity: 'HIGH',
        targetResource: {
          type: 'role',
          id: role._id,
          name: role.name
        },
        data: {
          roleData: this.sanitizeRoleForLog(role.toObject()),
          reassignedTo: reassignTo,
          reassignedCount: reassignedUsers.length,
          reason,
          force
        }
      }], { session });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.ROLE_MANAGEMENT.ROLE_DELETED, {
        roleId: role._id,
        roleName: role.name,
        reassignedUsers: reassignedUsers.length,
        reason
      }, { session, critical: true });

      // Notify reassigned users
      if (reassignedUsers.length > 0) {
        await this.notifyReassignedUsers(
          reassignedUsers,
          role.displayName,
          reassignTo
        );
      }

      await session.commitTransaction();

      return {
        success: true,
        deletedRole: {
          id: role._id,
          name: role.name,
          displayName: role.displayName
        },
        reassignedUsers: reassignedUsers.length,
        message: `Role deleted successfully. ${reassignedUsers.length} users reassigned.`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Delete role error', {
        error: error.message,
        adminId: adminUser.id,
        roleId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Clone an existing role
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} sourceRoleId - Source role ID or name
   * @param {Object} cloneData - Clone configuration
   * @returns {Promise<Object>} Cloned role
   */
  async cloneRole(adminUser, sourceRoleId, cloneData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'create');

      const {
        name,
        displayName,
        description,
        modifyPermissions = {}
      } = cloneData;

      // Find source role
      const sourceRole = await Role.findOne({
        $or: [
          { _id: mongoose.Types.ObjectId.isValid(sourceRoleId) ? sourceRoleId : null },
          { name: sourceRoleId }
        ]
      })
      .populate('permissions')
      .session(session);

      if (!sourceRole) {
        throw new NotFoundError('Source role not found');
      }

      // Validate new role name
      if (!name || !/^[a-z0-9_]+$/.test(name)) {
        throw new ValidationError('Role name must contain only lowercase letters, numbers, and underscores');
      }

      // Check if role name already exists
      const existingRole = await Role.findOne({ name }).session(session);
      if (existingRole) {
        throw new ConflictError(`Role with name '${name}' already exists`);
      }

      // Clone permissions with modifications
      let clonedPermissions = [...sourceRole.permissions];
      
      if (modifyPermissions.add && modifyPermissions.add.length > 0) {
        const addPermissions = await Permission.find({
          _id: { $in: modifyPermissions.add }
        }).session(session);
        clonedPermissions.push(...addPermissions);
      }

      if (modifyPermissions.remove && modifyPermissions.remove.length > 0) {
        clonedPermissions = clonedPermissions.filter(
          p => !modifyPermissions.remove.includes(p._id.toString())
        );
      }

      // Create cloned role
      const clonedRole = new Role({
        name,
        displayName: displayName || `${sourceRole.displayName} (Clone)`,
        description: description || `Cloned from ${sourceRole.displayName}`,
        category: sourceRole.category,
        permissions: clonedPermissions.map(p => p._id),
        inheritedFrom: sourceRole.inheritedFrom,
        priority: sourceRole.priority + 1,
        constraints: { ...sourceRole.constraints },
        metadata: {
          ...sourceRole.metadata,
          clonedFrom: sourceRole._id,
          clonedAt: new Date()
        },
        isSystem: false,
        isActive: true,
        createdBy: adminUser.id,
        updatedBy: adminUser.id
      });

      await clonedRole.save({ session });

      // Clear caches
      await this.clearRoleCaches();

      // Log action
      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'ROLE_CLONED',
        category: 'ROLE_MANAGEMENT',
        severity: 'MEDIUM',
        targetResource: {
          type: 'role',
          id: clonedRole._id,
          name: clonedRole.name
        },
        data: {
          sourceRole: {
            id: sourceRole._id,
            name: sourceRole.name
          },
          modifications: modifyPermissions
        }
      }], { session });

      await this.auditLog(adminUser, AdminEvents.ROLE_MANAGEMENT.ROLE_CLONED, {
        sourceRoleId: sourceRole._id,
        sourceRoleName: sourceRole.name,
        clonedRoleId: clonedRole._id,
        clonedRoleName: clonedRole.name
      }, { session });

      await session.commitTransaction();

      // Return populated cloned role
      const populatedRole = await Role.findById(clonedRole._id)
        .populate('permissions')
        .populate('inheritedFrom');

      return {
        role: populatedRole,
        message: 'Role cloned successfully',
        source: {
          id: sourceRole._id,
          name: sourceRole.name,
          displayName: sourceRole.displayName
        }
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Clone role error', {
        error: error.message,
        adminId: adminUser.id,
        sourceRoleId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Bulk assign role to multiple users
   * @param {Object} adminUser - Authenticated super admin user
   * @param {string} roleId - Role ID or name
   * @param {Array} userIds - Array of user IDs
   * @param {Object} options - Assignment options
   * @returns {Promise<Object>} Assignment result
   */
  async bulkAssignRole(adminUser, roleId, userIds, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validateAccess(adminUser, 'assign');

      const {
        notifyUsers = true,
        reason = 'Administrative role assignment',
        effectiveDate = new Date(),
        expiryDate = null
      } = options;

      // Validate inputs
      if (!Array.isArray(userIds) || userIds.length === 0) {
        throw new ValidationError('User IDs must be a non-empty array');
      }

      if (userIds.length > AdminLimits.BULK_OPERATIONS.MAX_USERS) {
        throw new ValidationError(`Cannot assign role to more than ${AdminLimits.BULK_OPERATIONS.MAX_USERS} users at once`);
      }

      // Find role
      const role = await Role.findOne({
        $or: [
          { _id: mongoose.Types.ObjectId.isValid(roleId) ? roleId : null },
          { name: roleId }
        ]
      }).session(session);

      if (!role) {
        throw new NotFoundError('Role not found');
      }

      // Find all users
      const users = await User.find({
        _id: { $in: userIds },
        status: { $ne: 'deleted' }
      }).session(session);

      if (users.length !== userIds.length) {
        throw new ValidationError(`Found only ${users.length} valid users out of ${userIds.length} provided`);
      }

      // Process assignments
      const results = {
        successful: [],
        failed: [],
        skipped: []
      };

      for (const user of users) {
        try {
          // Check if user already has this role
          if (user.role.primary === role.name) {
            results.skipped.push({
              userId: user._id,
              email: user.email,
              reason: 'Already has this role'
            });
            continue;
          }

          // Store previous role
          const previousRole = user.role.primary;

          // Update user role
          user.role = {
            primary: role.name,
            secondary: user.role.secondary || [],
            assignedBy: adminUser.id,
            assignedAt: effectiveDate,
            expiresAt: expiryDate,
            previousRole: previousRole,
            assignmentReason: reason
          };

          user.updatedBy = adminUser.id;
          await user.save({ session });

          results.successful.push({
            userId: user._id,
            email: user.email,
            previousRole,
            newRole: role.name
          });

        } catch (error) {
          results.failed.push({
            userId: user._id,
            email: user.email,
            error: error.message
          });
        }
      }

      // Clear user permission caches
      if (results.successful.length > 0) {
        await this.clearUserPermissionCaches(
          results.successful.map(r => r.userId)
        );
      }

      // Create bulk assignment record
      await AdminActionLog.create([{
        actionId: crypto.randomUUID(),
        adminUserId: adminUser.id,
        action: 'ROLE_BULK_ASSIGNED',
        category: 'ROLE_MANAGEMENT',
        severity: 'HIGH',
        targetResource: {
          type: 'role',
          id: role._id,
          name: role.name
        },
        data: {
          totalUsers: userIds.length,
          successful: results.successful.length,
          failed: results.failed.length,
          skipped: results.skipped.length,
          reason,
          effectiveDate,
          expiryDate
        }
      }], { session });

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.ROLE_MANAGEMENT.ROLE_BULK_ASSIGNED, {
        roleId: role._id,
        roleName: role.name,
        totalUsers: userIds.length,
        successful: results.successful.length,
        failed: results.failed.length
      }, { session, critical: true });

      // Send notifications if enabled
      if (notifyUsers && results.successful.length > 0) {
        await this.notifyRoleAssignment(
          results.successful,
          role,
          reason
        );
      }

      await session.commitTransaction();

      return {
        role: {
          id: role._id,
          name: role.name,
          displayName: role.displayName
        },
        results,
        summary: {
          total: userIds.length,
          successful: results.successful.length,
          failed: results.failed.length,
          skipped: results.skipped.length
        },
        message: `Role assigned to ${results.successful.length} users successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Bulk assign role error', {
        error: error.message,
        adminId: adminUser.id,
        roleId,
        userCount: userIds.length,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Get role assignment history
   * @param {Object} adminUser - Authenticated super admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Assignment history
   */
  async getRoleAssignmentHistory(adminUser, options = {}) {
    try {
      await this.validateAccess(adminUser, 'read');

      const {
        roleId = null,
        userId = null,
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
        endDate = new Date(),
        page = 1,
        limit = 50
      } = options;

      // Build query
      const query = {
        action: { $in: ['ROLE_ASSIGNED', 'ROLE_BULK_ASSIGNED', 'ROLE_REMOVED'] },
        timestamp: { $gte: startDate, $lte: endDate }
      };

      if (roleId) {
        query['targetResource.id'] = roleId;
      }

      if (userId) {
        query['data.userId'] = userId;
      }

      // Execute query
      const skip = (page - 1) * limit;

      const [history, totalCount] = await Promise.all([
        AdminActionLog.find(query)
          .populate('adminUserId', 'email profile')
          .sort({ timestamp: -1 })
          .limit(limit)
          .skip(skip),
        AdminActionLog.countDocuments(query)
      ]);

      return {
        history: history.map(entry => ({
          id: entry._id,
          action: entry.action,
          admin: {
            id: entry.adminUserId._id,
            email: entry.adminUserId.email,
            name: `${entry.adminUserId.profile?.firstName || ''} ${entry.adminUserId.profile?.lastName || ''}`.trim()
          },
          role: entry.targetResource,
          data: entry.data,
          timestamp: entry.timestamp
        })),
        pagination: {
          page,
          limit,
          total: totalCount,
          pages: Math.ceil(totalCount / limit)
        }
      };

    } catch (error) {
      logger.error('Get role assignment history error', {
        error: error.message,
        adminId: adminUser.id,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Validate access for role management operations
   * @param {Object} user - User to validate
   * @param {string} action - Action to perform
   * @private
   */
  async validateAccess(user, action) {
    const hasPermission = await this.checkPermission(
      user,
      this.requiredPermission,
      action
    );

    if (!hasPermission) {
      await this.auditLog(user, AdminEvents.ROLE_MANAGEMENT.UNAUTHORIZED_ACCESS, {
        attemptedAction: action,
        permission: this.requiredPermission
      });
      throw new ForbiddenError(`Insufficient permissions for role management: ${action}`);
    }

    // Additional MFA check for critical operations
    const criticalActions = ['create', 'update', 'delete', 'assign'];
    if (criticalActions.includes(action) && user.security?.requireMFA && !user.auth?.mfaVerified) {
      throw new ForbiddenError('MFA verification required for this operation');
    }
  }

  /**
   * Validate and process permissions
   * @param {Array} permissions - Permission IDs or objects
   * @param {string} inheritFrom - Role to inherit from
   * @param {Object} session - Database session
   * @returns {Promise<Object>} Processed permissions
   * @private
   */
  async validateAndProcessPermissions(permissions, inheritFrom, session) {
    const processedPermissions = {
      permissionIds: [],
      warnings: []
    };

    // Get inherited permissions if applicable
    if (inheritFrom) {
      const parentRole = await Role.findById(inheritFrom)
        .populate('permissions')
        .session(session);

      if (parentRole) {
        processedPermissions.permissionIds.push(
          ...parentRole.permissions.map(p => p._id)
        );
      }
    }

    // Process provided permissions
    for (const permission of permissions) {
      const permissionId = typeof permission === 'string' ? permission : permission._id;

      // Validate permission exists
      const permissionDoc = await Permission.findById(permissionId).session(session);
      if (!permissionDoc) {
        processedPermissions.warnings.push(`Permission ${permissionId} not found`);
        continue;
      }

      // Check for dangerous permissions
      if (permissionDoc.resource.includes('super_admin') || permissionDoc.actions.includes('*')) {
        processedPermissions.warnings.push(
          `Permission ${permissionDoc.resource} grants elevated access`
        );
      }

      processedPermissions.permissionIds.push(permissionDoc._id);
    }

    // Remove duplicates
    processedPermissions.permissionIds = [
      ...new Set(processedPermissions.permissionIds.map(id => id.toString()))
    ].map(id => mongoose.Types.ObjectId(id));

    return processedPermissions;
  }

  /**
   * Additional helper methods for role management
   * These would include various utility functions for:
   * - Permission matrix building
   * - Role comparison
   * - Cache management
   * - Notification handling
   * - Audit history retrieval
   * - etc.
   */
}

module.exports = new RoleManagementService();