// server/admin/user-management/services/admin-user-service.js
/**
 * @file Admin User Service
 * @description Comprehensive user management service for administrators
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Core Models
const User = require('../../../shared/users/models/user-model');
const UserProfile = require('../../../shared/users/models/user-profile-model');
const HostedOrganization = require('../../../hosted-organizations/organizations/models/organization-model');
const Role = require('../../../shared/users/models/role-model');
const UserActivity = require('../../../shared/users/models/user-activity-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');
const AdminActionLog = require('../../../shared/admin/models/admin-action-log-model');
const UserSession = require('../../../shared/users/models/user-session-model');
const LoginHistory = require('../../../shared/users/models/login-history-model');

// Shared Services
const AdminBaseService = require('../../../shared/admin/services/admin-base-service');
const AuditService = require('../../../shared/security/services/audit-service');
const CacheService = require('../../../shared/utils/cache-service');
const EmailService = require('../../../shared/services/email-service');
const NotificationService = require('../../../shared/admin/services/admin-notification-service');
const UserService = require('../../../shared/users/services/user-service');
const PermissionService = require('../../../shared/users/services/permission-service');

// Utilities
const { AppError, ValidationError, NotFoundError, ForbiddenError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminEvents = require('../../../shared/admin/constants/admin-events');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');
const { encrypt, decrypt } = require('../../../shared/utils/encryption');
const { generateSecureToken, hashPassword } = require('../../../shared/utils/auth-helpers');

// Configuration
const config = require('../../../config');

/**
 * Admin User Service Class
 * @class AdminUserService
 * @extends AdminBaseService
 */
class AdminUserService extends AdminBaseService {
  constructor() {
    super();
    this.serviceName = 'AdminUserService';
    this.cachePrefix = 'admin-user';
    this.auditCategory = 'USER_MANAGEMENT';
    this.requiredPermission = AdminPermissions.USER_MANAGEMENT.VIEW;
  }

  /**
   * Get paginated users with advanced filtering
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Paginated user list
   */
  async getUsers(adminUser, options = {}) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW);

      const {
        page = 1,
        limit = 20,
        search = '',
        status,
        role,
        organization,
        verified,
        hasSubscription,
        createdFrom,
        createdTo,
        lastActiveFrom,
        lastActiveTo,
        sortBy = 'createdAt',
        sortOrder = 'desc',
        includeDeleted = false,
        exportFormat
      } = options;

      // Build query
      const query = this.buildUserQuery({
        search,
        status,
        role,
        organization,
        verified,
        hasSubscription,
        createdFrom,
        createdTo,
        lastActiveFrom,
        lastActiveTo,
        includeDeleted
      });

      // Calculate pagination
      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

      // Execute query with population
      const [users, totalCount] = await Promise.all([
        User.find(query)
          .populate('role.primary', 'name displayName permissions')
          .populate('organization.current', 'name subdomain plan')
          .populate('profile', 'firstName lastName avatar')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        User.countDocuments(query)
      ]);

      // Enhance user data
      const enhancedUsers = await this.enhanceUserData(users);

      // Handle export if requested
      if (exportFormat) {
        return await this.exportUsers(adminUser, enhancedUsers, exportFormat);
      }

      // Prepare response
      const response = {
        users: enhancedUsers,
        pagination: {
          total: totalCount,
          page,
          limit,
          pages: Math.ceil(totalCount / limit),
          hasMore: skip + users.length < totalCount
        },
        filters: {
          applied: Object.keys(options).filter(key => 
            options[key] !== undefined && 
            !['page', 'limit', 'sortBy', 'sortOrder'].includes(key)
          ),
          available: await this.getAvailableFilters()
        }
      };

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.USERS_VIEWED, {
        count: users.length,
        filters: response.filters.applied,
        page,
        limit
      });

      return response;

    } catch (error) {
      logger.error('Get users error', {
        error: error.message,
        adminId: adminUser.id,
        options,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Get detailed user information
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - Target user ID
   * @returns {Promise<Object>} Detailed user data
   */
  async getUserDetails(adminUser, userId) {
    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW);

      // Find user with all related data
      const user = await User.findById(userId)
        .populate('role.primary role.secondary')
        .populate('organization.current organization.owned')
        .populate('profile')
        .populate('permissions.custom')
        .lean();

      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Gather additional user data in parallel
      const [
        activityStats,
        loginHistory,
        activeSessions,
        subscriptionDetails,
        securityInfo,
        resourceUsage,
        auditSummary
      ] = await Promise.all([
        this.getUserActivityStats(userId),
        this.getUserLoginHistory(userId, { limit: 10 }),
        this.getUserActiveSessions(userId),
        this.getUserSubscriptionDetails(userId),
        this.getUserSecurityInfo(userId),
        this.getUserResourceUsage(userId),
        this.getUserAuditSummary(userId)
      ]);

      // Compile comprehensive user details
      const userDetails = {
        ...user,
        activity: activityStats,
        loginHistory: loginHistory.recent,
        activeSessions,
        subscription: subscriptionDetails,
        security: securityInfo,
        resourceUsage,
        auditSummary,
        metadata: {
          accountAge: this.calculateAccountAge(user.createdAt),
          riskScore: await this.calculateUserRiskScore(user),
          complianceStatus: await this.checkUserCompliance(user)
        }
      };

      // Remove sensitive data based on admin permissions
      if (!await this.hasPermission(adminUser, AdminPermissions.USER_MANAGEMENT.VIEW_SENSITIVE)) {
        delete userDetails.auth.password;
        delete userDetails.auth.twoFactor.secret;
        delete userDetails.security.encryptionKeys;
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.USER_DETAILS_VIEWED, {
        targetUserId: userId,
        targetUserEmail: user.email,
        dataAccessed: Object.keys(userDetails)
      });

      return userDetails;

    } catch (error) {
      logger.error('Get user details error', {
        error: error.message,
        adminId: adminUser.id,
        userId,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Create new user with admin privileges
   * @param {Object} adminUser - Authenticated admin user
   * @param {Object} userData - User data to create
   * @returns {Promise<Object>} Created user
   */
  async createUser(adminUser, userData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.CREATE);

      const {
        email,
        password,
        profile,
        role,
        organization,
        permissions,
        sendWelcomeEmail = true,
        requirePasswordChange = false,
        skipEmailVerification = false
      } = userData;

      // Validate email uniqueness
      const existingUser = await User.findOne({ email }).session(session);
      if (existingUser) {
        throw new ValidationError('User with this email already exists');
      }

      // Validate role
      const roleDoc = await Role.findById(role).session(session);
      if (!roleDoc) {
        throw new ValidationError('Invalid role specified');
      }

      // Validate organization if provided
      let orgDoc = null;
      if (organization) {
        orgDoc = await HostedOrganization.findById(organization).session(session);
        if (!orgDoc) {
          throw new ValidationError('Invalid organization specified');
        }
      }

      // Hash password
      const hashedPassword = await hashPassword(password);

      // Create user document
      const newUser = new User({
        email,
        auth: {
          password: hashedPassword,
          requirePasswordChange,
          email: {
            verified: skipEmailVerification,
            verificationToken: skipEmailVerification ? null : generateSecureToken()
          }
        },
        role: {
          primary: roleDoc._id,
          secondary: []
        },
        organization: orgDoc ? {
          current: orgDoc._id,
          owned: [],
          member: [orgDoc._id]
        } : undefined,
        permissions: {
          custom: permissions || []
        },
        status: 'active',
        createdBy: adminUser.id,
        metadata: {
          createdByAdmin: true,
          adminId: adminUser.id,
          creationMethod: 'admin_panel'
        }
      });

      await newUser.save({ session });

      // Create user profile
      const userProfile = new UserProfile({
        userId: newUser._id,
        ...profile,
        completeness: this.calculateProfileCompleteness(profile)
      });

      await userProfile.save({ session });

      // Update organization member count if applicable
      if (orgDoc) {
        await HostedOrganization.findByIdAndUpdate(
          orgDoc._id,
          {
            $inc: { 'statistics.totalMembers': 1 },
            $push: { members: newUser._id }
          },
          { session }
        );
      }

      // Send welcome email if requested
      if (sendWelcomeEmail) {
        await EmailService.sendAdminCreatedAccountEmail({
          email: newUser.email,
          name: `${profile.firstName} ${profile.lastName}`.trim(),
          temporaryPassword: password,
          requirePasswordChange,
          loginUrl: config.frontend.loginUrl
        });
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.USER_CREATED, {
        userId: newUser._id,
        email: newUser.email,
        role: roleDoc.name,
        organization: orgDoc?.name,
        sendWelcomeEmail,
        requirePasswordChange
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        user: {
          id: newUser._id,
          email: newUser.email,
          profile,
          role: roleDoc.name,
          organization: orgDoc?.name,
          status: newUser.status
        },
        message: 'User created successfully',
        emailSent: sendWelcomeEmail
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Create user error', {
        error: error.message,
        adminId: adminUser.id,
        userData: { email: userData.email },
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Update user information
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - User ID to update
   * @param {Object} updates - Update data
   * @returns {Promise<Object>} Updated user
   */
  async updateUser(adminUser, userId, updates) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.UPDATE);

      // Find existing user
      const user = await User.findById(userId).session(session);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Check if admin can modify this user
      await this.validateUserModificationPermission(adminUser, user);

      // Store original values for audit
      const originalValues = {
        email: user.email,
        status: user.status,
        role: user.role.primary,
        organization: user.organization.current
      };

      // Validate and apply updates
      const allowedUpdates = [
        'email',
        'status',
        'role',
        'organization',
        'permissions',
        'profile',
        'settings',
        'security'
      ];

      const updateOperations = {};
      const auditChanges = [];

      for (const [field, value] of Object.entries(updates)) {
        if (!allowedUpdates.includes(field)) {
          throw new ValidationError(`Field '${field}' cannot be updated`);
        }

        switch (field) {
          case 'email':
            if (value !== user.email) {
              const emailExists = await User.findOne({ 
                email: value, 
                _id: { $ne: userId } 
              }).session(session);
              
              if (emailExists) {
                throw new ValidationError('Email already in use');
              }
              
              updateOperations.email = value;
              updateOperations['auth.email.verified'] = false;
              auditChanges.push({ field: 'email', old: user.email, new: value });
            }
            break;

          case 'status':
            if (value !== user.status) {
              if (!['active', 'suspended', 'locked'].includes(value)) {
                throw new ValidationError('Invalid status value');
              }
              
              updateOperations.status = value;
              auditChanges.push({ field: 'status', old: user.status, new: value });
              
              // Force logout if suspending/locking
              if (['suspended', 'locked'].includes(value)) {
                await this.forceUserLogout(userId, session);
              }
            }
            break;

          case 'role':
            const newRole = await Role.findById(value.primary).session(session);
            if (!newRole) {
              throw new ValidationError('Invalid role specified');
            }
            
            if (value.primary !== user.role.primary?.toString()) {
              updateOperations['role.primary'] = newRole._id;
              auditChanges.push({ 
                field: 'role', 
                old: originalValues.role, 
                new: newRole._id 
              });
            }
            break;

          case 'organization':
            if (value !== user.organization.current?.toString()) {
              const org = await HostedOrganization.findById(value).session(session);
              if (!org) {
                throw new ValidationError('Invalid organization specified');
              }
              
              updateOperations['organization.current'] = org._id;
              auditChanges.push({ 
                field: 'organization', 
                old: originalValues.organization, 
                new: org._id 
              });
            }
            break;

          case 'permissions':
            updateOperations['permissions.custom'] = value;
            auditChanges.push({ field: 'permissions', updated: true });
            break;

          case 'profile':
            // Update profile separately
            await UserProfile.findOneAndUpdate(
              { userId },
              { 
                ...value,
                updatedAt: new Date()
              },
              { session }
            );
            auditChanges.push({ field: 'profile', updated: true });
            break;

          case 'security':
            // Handle security updates carefully
            if (value.requireMFA !== undefined) {
              updateOperations['security.requireMFA'] = value.requireMFA;
            }
            if (value.requirePasswordChange !== undefined) {
              updateOperations['auth.requirePasswordChange'] = value.requirePasswordChange;
            }
            auditChanges.push({ field: 'security', updated: true });
            break;
        }
      }

      // Apply updates
      if (Object.keys(updateOperations).length > 0) {
        await User.findByIdAndUpdate(
          userId,
          {
            $set: {
              ...updateOperations,
              'metadata.lastModifiedBy': adminUser.id,
              'metadata.lastModifiedAt': new Date()
            }
          },
          { session }
        );
      }

      // Clear user cache
      await this.clearUserCache(userId);

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.USER_UPDATED, {
        userId,
        email: user.email,
        changes: auditChanges
      }, { session, critical: true });

      // Send notification if significant changes
      if (auditChanges.some(change => ['email', 'status', 'role'].includes(change.field))) {
        await NotificationService.sendAdminNotification({
          type: 'account_updated_by_admin',
          userId,
          data: {
            adminName: adminUser.profile?.firstName || adminUser.email,
            changes: auditChanges.map(c => c.field)
          }
        });
      }

      await session.commitTransaction();

      // Return updated user
      const updatedUser = await User.findById(userId)
        .populate('role.primary')
        .populate('organization.current')
        .populate('profile')
        .lean();

      return {
        user: updatedUser,
        changes: auditChanges,
        message: 'User updated successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Update user error', {
        error: error.message,
        adminId: adminUser.id,
        userId,
        updates,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Delete or soft delete user
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - User ID to delete
   * @param {Object} options - Deletion options
   * @returns {Promise<Object>} Deletion result
   */
  async deleteUser(adminUser, userId, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.DELETE);

      const {
        hardDelete = false,
        reason,
        anonymizeData = true,
        transferOwnership = null
      } = options;

      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Deletion reason must be provided (minimum 10 characters)');
      }

      // Find user
      const user = await User.findById(userId)
        .populate('organization.owned')
        .session(session);

      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Check if admin can delete this user
      await this.validateUserDeletionPermission(adminUser, user);

      // Check for owned resources
      if (user.organization.owned.length > 0 && !transferOwnership) {
        throw new ValidationError('User owns organizations. Transfer ownership before deletion.');
      }

      // Handle ownership transfer if needed
      if (transferOwnership && user.organization.owned.length > 0) {
        await this.transferUserOwnerships(user, transferOwnership, session);
      }

      // Force logout user
      await this.forceUserLogout(userId, session);

      if (hardDelete && await this.hasPermission(adminUser, AdminPermissions.USER_MANAGEMENT.HARD_DELETE)) {
        // Hard delete - permanent removal
        await this.performHardDelete(user, adminUser, reason, session);
      } else {
        // Soft delete
        await this.performSoftDelete(user, adminUser, reason, anonymizeData, session);
      }

      // Log critical audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.USER_DELETED, {
        userId,
        email: user.email,
        deletionType: hardDelete ? 'hard' : 'soft',
        reason,
        anonymized: anonymizeData,
        transferredOwnership: transferOwnership
      }, { session, critical: true, alertLevel: 'high' });

      await session.commitTransaction();

      return {
        success: true,
        userId,
        deletionType: hardDelete ? 'hard' : 'soft',
        message: `User ${hardDelete ? 'permanently deleted' : 'deactivated'} successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Delete user error', {
        error: error.message,
        adminId: adminUser.id,
        userId,
        options,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Reset user password
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - User ID
   * @param {Object} options - Reset options
   * @returns {Promise<Object>} Password reset result
   */
  async resetUserPassword(adminUser, userId, options = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.RESET_PASSWORD);

      const {
        newPassword,
        generateRandom = !newPassword,
        requireChange = true,
        notifyUser = true,
        reason
      } = options;

      if (!reason || reason.trim().length < 5) {
        throw new ValidationError('Password reset reason must be provided');
      }

      // Find user
      const user = await User.findById(userId).session(session);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Generate password if needed
      const password = generateRandom ? 
        AdminHelpers.generateSecurePassword() : 
        newPassword;

      // Validate password
      if (!this.validatePasswordStrength(password)) {
        throw new ValidationError('Password does not meet security requirements');
      }

      // Hash password
      const hashedPassword = await hashPassword(password);

      // Update user password
      user.auth.password = hashedPassword;
      user.auth.requirePasswordChange = requireChange;
      user.auth.passwordChangedAt = new Date();
      user.auth.passwordResetToken = null;
      user.auth.passwordResetExpires = null;

      // Invalidate all sessions
      await UserSession.updateMany(
        { userId, isActive: true },
        { 
          $set: { 
            isActive: false, 
            endedAt: new Date(),
            endReason: 'password_reset_by_admin'
          }
        },
        { session }
      );

      await user.save({ session });

      // Send notification if requested
      if (notifyUser) {
        await EmailService.sendPasswordResetByAdminEmail({
          email: user.email,
          name: user.profile?.firstName || 'User',
          temporaryPassword: generateRandom ? password : null,
          requireChange,
          adminName: adminUser.profile?.firstName || adminUser.email,
          reason
        });
      }

      // Log audit event
      await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.PASSWORD_RESET, {
        userId,
        email: user.email,
        requireChange,
        notifyUser,
        reason
      }, { session, critical: true });

      await session.commitTransaction();

      return {
        success: true,
        userId,
        temporaryPassword: generateRandom ? password : undefined,
        requireChange,
        notificationSent: notifyUser,
        message: 'Password reset successfully'
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Reset user password error', {
        error: error.message,
        adminId: adminUser.id,
        userId,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Suspend or unsuspend user account
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - User ID
   * @param {Object} suspensionData - Suspension details
   * @returns {Promise<Object>} Suspension result
   */
  async toggleUserSuspension(adminUser, userId, suspensionData) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.SUSPEND);

      const {
        action, // 'suspend' or 'unsuspend'
        reason,
        duration, // in days, optional
        notifyUser = true
      } = suspensionData;

      if (!['suspend', 'unsuspend'].includes(action)) {
        throw new ValidationError('Invalid suspension action');
      }

      if (!reason || reason.trim().length < 10) {
        throw new ValidationError('Suspension reason must be provided (minimum 10 characters)');
      }

      // Find user
      const user = await User.findById(userId).session(session);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Check current status
      if (action === 'suspend' && user.status === 'suspended') {
        throw new ValidationError('User is already suspended');
      }

      if (action === 'unsuspend' && user.status !== 'suspended') {
        throw new ValidationError('User is not suspended');
      }

      // Update user status
      if (action === 'suspend') {
        user.status = 'suspended';
        user.suspension = {
          reason: encrypt(reason),
          suspendedAt: new Date(),
          suspendedBy: adminUser.id,
          expiresAt: duration ? new Date(Date.now() + duration * 24 * 60 * 60 * 1000) : null
        };

        // Force logout
        await this.forceUserLogout(userId, session);
      } else {
        user.status = 'active';
        user.suspension = {
          ...user.suspension,
          unsuspendedAt: new Date(),
          unsuspendedBy: adminUser.id,
          unsuspendReason: reason
        };
      }

      await user.save({ session });

      // Send notification if requested
      if (notifyUser) {
        await EmailService.sendAccountSuspensionEmail({
          email: user.email,
          name: user.profile?.firstName || 'User',
          action,
          reason,
          duration,
          supportEmail: config.email.supportEmail
        });
      }

      // Log audit event
      await this.auditLog(adminUser, 
        action === 'suspend' ? 
          AdminEvents.USER_MANAGEMENT.USER_SUSPENDED : 
          AdminEvents.USER_MANAGEMENT.USER_UNSUSPENDED,
        {
          userId,
          email: user.email,
          reason,
          duration,
          notifyUser
        }, 
        { session, critical: true }
      );

      await session.commitTransaction();

      return {
        success: true,
        userId,
        action,
        status: user.status,
        expiresAt: user.suspension?.expiresAt,
        message: `User ${action}ed successfully`
      };

    } catch (error) {
      await session.abortTransaction();
      logger.error('Toggle user suspension error', {
        error: error.message,
        adminId: adminUser.id,
        userId,
        action: suspensionData.action,
        stack: error.stack
      });
      throw error;
    } finally {
      await session.endSession();
    }
  }

  /**
   * Force user logout across all sessions
   * @param {Object} adminUser - Authenticated admin user
   * @param {string} userId - User ID
   * @param {Object} options - Logout options
   * @returns {Promise<Object>} Logout result
   */
  async forceUserLogout(userId, sessionOrAdminUser, options = {}) {
    try {
      let adminUser = null;
      let dbSession = null;

      // Handle both direct calls and calls from within transactions
      if (sessionOrAdminUser?.constructor?.name === 'ClientSession') {
        dbSession = sessionOrAdminUser;
      } else {
        adminUser = sessionOrAdminUser;
        await this.validatePermission(adminUser, AdminPermissions.USER_MANAGEMENT.FORCE_LOGOUT);
      }

      const { reason = 'Forced logout by administrator' } = options;

      // Find all active sessions
      const activeSessions = await UserSession.find({
        userId,
        isActive: true
      }).session(dbSession);

      if (activeSessions.length === 0) {
        return {
          success: true,
          message: 'No active sessions found',
          sessionsTerminated: 0
        };
      }

      // Terminate all sessions
      await UserSession.updateMany(
        { userId, isActive: true },
        {
          $set: {
            isActive: false,
            endedAt: new Date(),
            endReason: reason,
            endedBy: adminUser?.id || 'system'
          }
        },
        { session: dbSession }
      );

      // Clear session cache
      for (const session of activeSessions) {
        await CacheService.delete(`session:${session.sessionId}`);
      }

      // Clear user tokens cache
      await CacheService.delete(`user:tokens:${userId}`);

      // Log audit event if admin user provided
      if (adminUser) {
        await this.auditLog(adminUser, AdminEvents.USER_MANAGEMENT.USER_FORCE_LOGOUT, {
          userId,
          sessionsTerminated: activeSessions.length,
          reason
        });
      }

      return {
        success: true,
        sessionsTerminated: activeSessions.length,
        message: `Terminated ${activeSessions.length} active session(s)`
      };

    } catch (error) {
      logger.error('Force user logout error', {
        error: error.message,
        userId,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Build user query from filters
   * @param {Object} filters - Filter parameters
   * @returns {Object} MongoDB query
   * @private
   */
  buildUserQuery(filters) {
    const query = {};

    if (!filters.includeDeleted) {
      query.status = { $ne: 'deleted' };
    }

    if (filters.search) {
      query.$or = [
        { email: { $regex: filters.search, $options: 'i' } },
        { 'profile.firstName': { $regex: filters.search, $options: 'i' } },
        { 'profile.lastName': { $regex: filters.search, $options: 'i' } }
      ];
    }

    if (filters.status) {
      query.status = filters.status;
    }

    if (filters.role) {
      query['role.primary'] = filters.role;
    }

    if (filters.organization) {
      query['organization.current'] = filters.organization;
    }

    if (filters.verified !== undefined) {
      query['auth.email.verified'] = filters.verified;
    }

    if (filters.hasSubscription !== undefined) {
      query['subscription.status'] = filters.hasSubscription ? 
        { $in: ['active', 'trial'] } : 
        { $in: ['inactive', 'cancelled', null] };
    }

    if (filters.createdFrom || filters.createdTo) {
      query.createdAt = {};
      if (filters.createdFrom) {
        query.createdAt.$gte = new Date(filters.createdFrom);
      }
      if (filters.createdTo) {
        query.createdAt.$lte = new Date(filters.createdTo);
      }
    }

    if (filters.lastActiveFrom || filters.lastActiveTo) {
      query.lastActiveAt = {};
      if (filters.lastActiveFrom) {
        query.lastActiveAt.$gte = new Date(filters.lastActiveFrom);
      }
      if (filters.lastActiveTo) {
        query.lastActiveAt.$lte = new Date(filters.lastActiveTo);
      }
    }

    return query;
  }

  /**
   * Enhance user data with additional information
   * @param {Array} users - Raw user data
   * @returns {Promise<Array>} Enhanced user data
   * @private
   */
  async enhanceUserData(users) {
    return Promise.all(users.map(async (user) => {
      const enhanced = { ...user };

      // Add computed fields
      enhanced.displayName = user.profile ? 
        `${user.profile.firstName || ''} ${user.profile.lastName || ''}`.trim() || user.email :
        user.email;

      enhanced.accountAge = this.calculateAccountAge(user.createdAt);
      
      // Add activity status
      const lastActive = user.lastActiveAt || user.lastLoginAt;
      enhanced.activityStatus = this.calculateActivityStatus(lastActive);

      // Add risk indicators
      enhanced.riskIndicators = await this.identifyRiskIndicators(user);

      return enhanced;
    }));
  }

  /**
   * Get user activity statistics
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Activity statistics
   * @private
   */
  async getUserActivityStats(userId) {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const [totalLogins, recentLogins, totalActions, recentActions] = await Promise.all([
      LoginHistory.countDocuments({ userId }),
      LoginHistory.countDocuments({ 
        userId, 
        timestamp: { $gte: thirtyDaysAgo } 
      }),
      UserActivity.countDocuments({ userId }),
      UserActivity.countDocuments({ 
        userId, 
        timestamp: { $gte: sevenDaysAgo } 
      })
    ]);

    // Get activity breakdown
    const activityBreakdown = await UserActivity.aggregate([
      {
        $match: {
          userId: mongoose.Types.ObjectId(userId),
          timestamp: { $gte: thirtyDaysAgo }
        }
      },
      {
        $group: {
          _id: '$action',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 10
      }
    ]);

    return {
      totalLogins,
      loginsLast30Days: recentLogins,
      totalActions,
      actionsLast7Days: recentActions,
      topActivities: activityBreakdown,
      averageDailyActions: (recentActions / 7).toFixed(2)
    };
  }

  /**
   * Get user login history
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Login history
   * @private
   */
  async getUserLoginHistory(userId, options = {}) {
    const { limit = 20, page = 1 } = options;

    const history = await LoginHistory.find({ userId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .skip((page - 1) * limit)
      .lean();

    const total = await LoginHistory.countDocuments({ userId });

    return {
      recent: history,
      total,
      pagination: {
        page,
        limit,
        pages: Math.ceil(total / limit)
      }
    };
  }

  /**
   * Get user active sessions
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Active sessions
   * @private
   */
  async getUserActiveSessions(userId) {
    const sessions = await UserSession.find({
      userId,
      isActive: true,
      expiresAt: { $gt: new Date() }
    })
    .select('sessionId device location createdAt lastActivityAt')
    .lean();

    return sessions.map(session => ({
      ...session,
      duration: Date.now() - new Date(session.createdAt).getTime()
    }));
  }

  /**
   * Calculate user risk score
   * @param {Object} user - User object
   * @returns {Promise<number>} Risk score (0-100)
   * @private
   */
  async calculateUserRiskScore(user) {
    let riskScore = 0;

    // Account age factor
    const accountAgeDays = (Date.now() - new Date(user.createdAt).getTime()) / (24 * 60 * 60 * 1000);
    if (accountAgeDays < 7) riskScore += 20;
    else if (accountAgeDays < 30) riskScore += 10;

    // Email verification
    if (!user.auth?.email?.verified) riskScore += 15;

    // Suspension history
    if (user.suspension?.suspendedAt) riskScore += 25;

    // Failed login attempts
    const recentFailedLogins = await LoginHistory.countDocuments({
      userId: user._id,
      success: false,
      timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });
    if (recentFailedLogins > 5) riskScore += 20;
    else if (recentFailedLogins > 2) riskScore += 10;

    // Multiple device usage
    const uniqueDevices = await UserSession.distinct('device.fingerprint', { userId: user._id });
    if (uniqueDevices.length > 5) riskScore += 10;

    // Ensure score is within bounds
    return Math.min(Math.max(riskScore, 0), 100);
  }

  /**
   * Additional helper methods would continue here...
   */
}

module.exports = new AdminUserService();