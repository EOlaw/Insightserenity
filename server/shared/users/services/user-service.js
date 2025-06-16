// server/shared/users/services/user-service.js
/**
 * @file User Service
 * @description Comprehensive user service handling all user-related business logic
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const User = require('../models/user-model');
const Auth = require('../../auth/models/auth-model');
const Organization = require('../../../hosted-organizations/organizations/models/organization-model');
const logger = require('../../utils/logger');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  ForbiddenError 
} = require('../../utils/app-error');
const EmailService = require('../../../shared/services/email-service');
const FileService = require('../../../shared/utils/helpers/file-helper');
const CacheService = require('../../../shared/services/cache-service');
const AuditService = require('../../../shared/security/services/audit-service');
const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');

/**
 * User Service Class
 * @class UserService
 */
class UserService {
  /**
   * Create new user
   * @param {Object} userData - User data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created user
   */
  static async createUser(userData, context) {
    try {
      // Validate required fields
      const requiredFields = ['email', 'firstName', 'lastName', 'userType', 'role'];
      const missingFields = requiredFields.filter(field => {
        if (field === 'role') return !userData.role?.primary;
        return !userData[field];
      });
      
      if (missingFields.length > 0) {
        throw new ValidationError(`Missing required fields: ${missingFields.join(', ')}`);
      }
      
      // Check if user already exists
      const existingUser = await User.findOne({ 
        email: userData.email.toLowerCase() 
      });
      
      if (existingUser) {
        throw new ConflictError('User with this email already exists');
      }
      
      // Validate username if provided
      if (userData.username) {
        const usernameExists = await User.findOne({ 
          username: userData.username.toLowerCase() 
        });
        
        if (usernameExists) {
          throw new ConflictError('Username is already taken');
        }
      }
      
      // Create user
      const user = new User({
        ...userData,
        email: userData.email.toLowerCase(),
        username: userData.username?.toLowerCase(),
        status: userData.status || 'active',
        metadata: {
          ...userData.metadata,
          source: context.source || 'api',
          createdBy: context.userId
        }
      });
      
      await user.save();
      
      // Send welcome email
      if (config.features.sendWelcomeEmail && user.isEmailVerified) {
        await this.sendWelcomeEmail(user);
      }
      
      // Audit log
      await AuditService.log({
        type: 'user_created',
        action: 'create',
        category: 'users',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'user',
          id: user._id.toString()
        },
        metadata: {
          email: user.email,
          userType: user.userType,
          role: user.role.primary
        }
      });
      
      return user;
      
    } catch (error) {
      logger.error('Create user error', { error, userData });
      throw error;
    }
  }
  
  /**
   * Create user with OAuth
   * @param {Object} userData - User data
   * @param {Object} oauthData - OAuth data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created user and auth
   */
  static async createUserWithOAuth(userData, oauthData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Create user
      const user = await this.createUser(userData, context);
      
      // Create auth record
      const auth = new Auth({
        userId: user._id,
        authMethods: {
          oauth: {
            [oauthData.provider]: oauthData.profile
          }
        },
        metadata: {
          createdBy: {
            userId: user._id,
            method: `oauth_${oauthData.provider}`
          },
          source: context.source || 'web'
        }
      });
      
      await auth.save({ session });
      
      await session.commitTransaction();
      
      return {
        success: true,
        user,
        auth
      };
      
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Create user with passkey
   * @param {Object} userData - User data
   * @param {Object} passkeyData - Passkey credential data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created user and auth
   */
  static async createUserWithPasskey(userData, passkeyData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Create user
      const user = await this.createUser({
        ...userData,
        isEmailVerified: true // Passkey registration verifies user presence
      }, context);
      
      // Create auth record
      const auth = new Auth({
        userId: user._id,
        authMethods: {
          passkey: {
            credentials: [passkeyData]
          }
        },
        metadata: {
          createdBy: {
            userId: user._id,
            method: 'passkey'
          },
          source: context.source || 'web'
        }
      });
      
      await auth.save({ session });
      
      await session.commitTransaction();
      
      return {
        success: true,
        user,
        auth
      };
      
    } catch (error) {
      await session.abortTransaction();
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Get user by ID
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} User
   */
  static async getUserById(userId, options = {}) {
    const { 
      select, 
      populate, 
      lean = false,
      includeDeleted = false 
    } = options;
    
    try {
      // Check cache first
      const cacheKey = `user:${userId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached && !populate && !select) {
        return cached;
      }
      
      let query = User.findById(userId);
      
      if (!includeDeleted) {
        query = query.where('status').ne('deleted');
      }
      
      if (select) {
        query = query.select(select);
      }
      
      if (populate) {
        if (Array.isArray(populate)) {
          populate.forEach(p => query = query.populate(p));
        } else {
          query = query.populate(populate);
        }
      }
      
      if (lean) {
        query = query.lean();
      }
      
      const user = await query;
      
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      // Cache the result if it's a simple query
      if (!populate && !select && !lean) {
        await CacheService.set(cacheKey, user, 300); // 5 minutes
      }
      
      return user;
      
    } catch (error) {
      logger.error('Get user by ID error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Get user by email
   * @param {string} email - User email
   * @param {Object} options - Query options
   * @returns {Promise<Object>} User
   */
  static async getUserByEmail(email, options = {}) {
    try {
      const query = User.findOne({ 
        email: email.toLowerCase(),
        status: { $ne: 'deleted' }
      });
      
      if (options.select) {
        query.select(options.select);
      }
      
      if (options.populate) {
        query.populate(options.populate);
      }
      
      return await query;
      
    } catch (error) {
      logger.error('Get user by email error', { error, email });
      throw error;
    }
  }
  
  /**
   * Get user with auth record
   * @param {string} email - User email
   * @returns {Promise<Object>} User and auth
   */
  static async getUserWithAuth(email) {
    try {
      const user = await this.getUserByEmail(email);
      
      if (!user) {
        return null;
      }
      
      const auth = await Auth.findOne({ userId: user._id });
      
      if (!auth) {
        logger.warn('User found but no auth record', { userId: user._id });
        return null;
      }
      
      return { user, auth };
      
    } catch (error) {
      logger.error('Get user with auth error', { error, email });
      throw error;
    }
  }
  
  /**
   * Get user with auth by ID
   * @param {string} userId - User ID
   * @returns {Promise<Object>} User and auth
   */
  static async getUserWithAuthById(userId) {
    try {
      const user = await this.getUserById(userId);
      const auth = await Auth.findOne({ userId });
      
      if (!auth) {
        logger.warn('User found but no auth record', { userId });
        return null;
      }
      
      return { user, auth };
      
    } catch (error) {
      logger.error('Get user with auth by ID error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Get user by OAuth provider
   * @param {string} provider - OAuth provider
   * @param {string} providerId - Provider user ID
   * @returns {Promise<Object>} User and auth
   */
  static async getUserByOAuthProvider(provider, providerId) {
    try {
      const auth = await Auth.findByOAuthProvider(provider, providerId);
      
      if (!auth) {
        return null;
      }
      
      const user = await User.findById(auth.userId);
      
      if (!user || user.status === 'deleted') {
        return null;
      }
      
      return { user, auth };
      
    } catch (error) {
      logger.error('Get user by OAuth provider error', { error, provider, providerId });
      throw error;
    }
  }
  
  /**
   * Update user
   * @param {string} userId - User ID
   * @param {Object} updateData - Update data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated user
   */
  static async updateUser(userId, updateData, context) {
    try {
      const user = await this.getUserById(userId);
      
      // Check permissions
      if (context.userId !== userId && !context.isAdmin) {
        throw new ForbiddenError('Insufficient permissions to update user');
      }
      
      // Prevent updating sensitive fields
      const restrictedFields = ['email', 'role', 'permissions', 'status'];
      restrictedFields.forEach(field => {
        if (updateData[field] && !context.isAdmin) {
          delete updateData[field];
        }
      });
      
      // Validate username if being updated
      if (updateData.username && updateData.username !== user.username) {
        const usernameExists = await User.findOne({ 
          username: updateData.username.toLowerCase(),
          _id: { $ne: userId }
        });
        
        if (usernameExists) {
          throw new ConflictError('Username is already taken');
        }
      }
      
      // Update user
      Object.assign(user, updateData);
      user.activity.lastProfileUpdate = new Date();
      
      await user.save();
      
      // Clear cache
      await CacheService.delete(`user:${userId}`);
      
      // Audit log
      await AuditService.log({
        type: 'user_updated',
        action: 'update',
        category: 'users',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'user',
          id: userId
        },
        metadata: {
          fields: Object.keys(updateData)
        }
      });
      
      return user;
      
    } catch (error) {
      logger.error('Update user error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Update user profile
   * @param {string} userId - User ID
   * @param {Object} profileData - Profile data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated user
   */
  static async updateUserProfile(userId, profileData, context) {
    try {
      const user = await this.getUserById(userId);
      
      // Check permissions
      if (context.userId !== userId && !context.hasPermission('users.update')) {
        throw new ForbiddenError('Insufficient permissions to update profile');
      }
      
      // Update profile fields
      if (profileData.bio) {
        user.profile.bio = { ...user.profile.bio, ...profileData.bio };
      }
      
      if (profileData.socialLinks) {
        user.profile.socialLinks = { ...user.profile.socialLinks, ...profileData.socialLinks };
      }
      
      if (profileData.professionalInfo) {
        user.profile.professionalInfo = { 
          ...user.profile.professionalInfo, 
          ...profileData.professionalInfo 
        };
      }
      
      // Update other profile fields
      const allowedFields = [
        'displayName', 'title', 'department', 'location', 'timezone',
        'dateOfBirth', 'gender', 'languages'
      ];
      
      allowedFields.forEach(field => {
        if (profileData[field] !== undefined) {
          user.profile[field] = profileData[field];
        }
      });
      
      // Recalculate profile completeness
      user.calculateProfileCompleteness();
      
      await user.save();
      
      // Clear cache
      await CacheService.delete(`user:${userId}`);
      
      return user;
      
    } catch (error) {
      logger.error('Update user profile error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Update user avatar
   * @param {string} userId - User ID
   * @param {Object} file - Uploaded file
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated user
   */
  static async updateUserAvatar(userId, file, context) {
    try {
      const user = await this.getUserById(userId);
      
      // Check permissions
      if (context.userId !== userId && !context.hasPermission('users.update')) {
        throw new ForbiddenError('Insufficient permissions to update avatar');
      }
      
      // Upload new avatar
      const uploadResult = await FileService.uploadImage(file, {
        folder: `avatars/${userId}`,
        transformation: {
          width: 400,
          height: 400,
          crop: 'fill',
          gravity: 'face'
        }
      });
      
      // Delete old avatar if exists
      if (user.profile.avatar?.publicId && user.profile.avatar.source === 'upload') {
        await FileService.deleteFile(user.profile.avatar.publicId);
      }
      
      // Update user avatar
      user.profile.avatar = {
        url: uploadResult.url,
        publicId: uploadResult.publicId,
        source: 'upload'
      };
      
      await user.save();
      
      // Clear cache
      await CacheService.delete(`user:${userId}`);
      
      return user;
      
    } catch (error) {
      logger.error('Update user avatar error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Update user preferences
   * @param {string} userId - User ID
   * @param {Object} preferences - Preferences data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated user
   */
  static async updateUserPreferences(userId, preferences, context) {
    try {
      const user = await this.getUserById(userId);
      
      // Check permissions
      if (context.userId !== userId) {
        throw new ForbiddenError('Can only update own preferences');
      }
      
      // Deep merge preferences
      user.preferences = this.deepMerge(user.preferences.toObject(), preferences);
      
      await user.save();
      
      // Clear cache
      await CacheService.delete(`user:${userId}`);
      
      return user;
      
    } catch (error) {
      logger.error('Update user preferences error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Search users
   * @param {Object} searchParams - Search parameters
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Search results
   */
  static async searchUsers(searchParams, context) {
    try {
      const {
        query,
        userType,
        role,
        organizationId,
        status = 'active',
        skills,
        location,
        activelyLooking,
        page = 1,
        limit = 20,
        sort = '-activity.lastActive'
      } = searchParams;
      
      const filter = {
        status,
        active: true
      };
      
      // Text search
      if (query) {
        filter.$or = [
          { firstName: new RegExp(query, 'i') },
          { lastName: new RegExp(query, 'i') },
          { 'profile.displayName': new RegExp(query, 'i') },
          { email: new RegExp(query, 'i') },
          { username: new RegExp(query, 'i') },
          { 'profile.bio.short': new RegExp(query, 'i') }
        ];
      }
      
      // Apply filters
      if (userType) filter.userType = userType;
      if (role) filter['role.primary'] = role;
      if (organizationId) filter['organization.current'] = organizationId;
      if (location) filter['profile.location'] = new RegExp(location, 'i');
      
      // Skills filter
      if (skills && skills.length > 0) {
        filter['profile.professionalInfo.skills.name'] = { $in: skills };
      }
      
      // Job seeker specific filters
      if (activelyLooking !== undefined) {
        filter['profile.candidateProfile.activelyLooking'] = activelyLooking;
      }
      
      // Execute search
      const skip = (page - 1) * limit;
      
      const [users, total] = await Promise.all([
        User.find(filter)
          .select('firstName lastName email profile.displayName profile.avatar profile.title profile.location userType role')
          .sort(sort)
          .limit(limit)
          .skip(skip)
          .lean(),
        User.countDocuments(filter)
      ]);
      
      return {
        users,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      };
      
    } catch (error) {
      logger.error('Search users error', { error, searchParams });
      throw error;
    }
  }
  
  /**
   * Get user's organizations
   * @param {string} userId - User ID
   * @returns {Promise<Array>} User's organizations
   */
  static async getUserOrganizations(userId) {
    try {
      const user = await this.getUserById(userId, {
        populate: {
          path: 'organization.organizations.organizationId',
          select: 'name slug logo type status'
        }
      });
      
      return user.organization.organizations
        .filter(org => org.active && org.organizationId)
        .map(org => ({
          ...org.organizationId.toObject(),
          role: org.role,
          department: org.department,
          joinedAt: org.joinedAt
        }));
      
    } catch (error) {
      logger.error('Get user organizations error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Add user to organization
   * @param {string} userId - User ID
   * @param {string} organizationId - Organization ID
   * @param {Object} memberData - Member data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated user
   */
  static async addUserToOrganization(userId, organizationId, memberData, context) {
    try {
      const user = await this.getUserById(userId);
      const organization = await Organization.findById(organizationId);
      
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Check if already member
      const existingMembership = user.organization.organizations.find(
        org => org.organizationId.toString() === organizationId
      );
      
      if (existingMembership && existingMembership.active) {
        throw new ConflictError('User is already a member of this organization');
      }
      
      // Add or update membership
      if (existingMembership) {
        existingMembership.active = true;
        existingMembership.role = memberData.role;
        existingMembership.department = memberData.department;
        existingMembership.joinedAt = new Date();
      } else {
        user.organization.organizations.push({
          organizationId,
          role: memberData.role,
          department: memberData.department,
          joinedAt: new Date(),
          active: true
        });
      }
      
      // Set as current organization if it's the only one
      if (user.organization.organizations.filter(org => org.active).length === 1) {
        user.organization.current = organizationId;
      }
      
      await user.save();
      
      // Clear cache
      await CacheService.delete(`user:${userId}`);
      
      // Send notification
      await this.sendOrganizationWelcomeEmail(user, organization);
      
      // Audit log
      await AuditService.log({
        type: 'user_added_to_organization',
        action: 'add_member',
        category: 'users',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'user',
          id: userId
        },
        metadata: {
          organizationId,
          role: memberData.role
        }
      });
      
      return user;
      
    } catch (error) {
      logger.error('Add user to organization error', { error, userId, organizationId });
      throw error;
    }
  }
  
  /**
   * Remove user from organization
   * @param {string} userId - User ID
   * @param {string} organizationId - Organization ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated user
   */
  static async removeUserFromOrganization(userId, organizationId, context) {
    try {
      const user = await this.getUserById(userId);
      
      const membership = user.organization.organizations.find(
        org => org.organizationId.toString() === organizationId
      );
      
      if (!membership || !membership.active) {
        throw new NotFoundError('User is not a member of this organization');
      }
      
      // Mark as inactive instead of removing
      membership.active = false;
      membership.leftAt = new Date();
      
      // Update current organization if needed
      if (user.organization.current?.toString() === organizationId) {
        const activeOrgs = user.organization.organizations.filter(
          org => org.active && org.organizationId.toString() !== organizationId
        );
        
        user.organization.current = activeOrgs.length > 0 ? 
          activeOrgs[0].organizationId : null;
      }
      
      await user.save();
      
      // Clear cache
      await CacheService.delete(`user:${userId}`);
      
      // Audit log
      await AuditService.log({
        type: 'user_removed_from_organization',
        action: 'remove_member',
        category: 'users',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'user',
          id: userId
        },
        metadata: {
          organizationId
        }
      });
      
      return user;
      
    } catch (error) {
      logger.error('Remove user from organization error', { error, userId, organizationId });
      throw error;
    }
  }
  
  /**
   * Get user statistics
   * @param {string} userId - User ID
   * @returns {Promise<Object>} User statistics
   */
  static async getUserStatistics(userId) {
    try {
      const user = await this.getUserById(userId);
      
      const stats = {
        profile: {
          completeness: user.profileCompleteness.percentage,
          views: user.statistics.profile.views,
          lastUpdated: user.activity.lastProfileUpdate
        },
        activity: {
          lastLogin: user.activity.lastLogin,
          totalLogins: user.activity.totalLogins,
          currentStreak: user.activity.currentStreak,
          longestStreak: user.activity.longestStreak
        },
        engagement: user.statistics.engagement,
        network: user.statistics.network,
        gamification: {
          level: user.gamification.level.current,
          points: user.gamification.points,
          badges: user.gamification.badges.length,
          nextLevelProgress: user.gamification.level.progress
        }
      };
      
      // Add role-specific stats
      if (user.userType === 'job_seeker') {
        stats.recruitment = user.statistics.recruitment;
      }
      
      if (['core_consultant', 'hosted_org_user'].includes(user.userType)) {
        stats.projects = user.statistics.projects;
      }
      
      return stats;
      
    } catch (error) {
      logger.error('Get user statistics error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Delete user (soft delete)
   * @param {string} userId - User ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Deleted user
   */
  static async deleteUser(userId, context) {
    try {
      const user = await this.getUserById(userId);
      
      // Check permissions
      if (context.userId !== userId && !context.isAdmin) {
        throw new ForbiddenError('Insufficient permissions to delete user');
      }
      
      // Soft delete
      user.status = 'deleted';
      user.active = false;
      user.metadata.deletion = {
        requested: true,
        requestedAt: new Date(),
        requestedBy: context.userId
      };
      
      // Anonymize personal data
      user.email = `deleted_${user._id}@deleted.com`;
      user.firstName = 'Deleted';
      user.lastName = 'User';
      user.profile = {
        displayName: 'Deleted User'
      };
      
      await user.save();
      
      // Clear cache
      await CacheService.delete(`user:${userId}`);
      
      // Also mark auth record as deleted
      await Auth.updateOne(
        { userId },
        { $set: { 'metadata.deleted': true } }
      );
      
      // Audit log
      await AuditService.log({
        type: 'user_deleted',
        action: 'delete',
        category: 'users',
        result: 'success',
        userId: context.userId,
        severity: 'high',
        target: {
          type: 'user',
          id: userId
        }
      });
      
      return { success: true, message: 'User deleted successfully' };
      
    } catch (error) {
      logger.error('Delete user error', { error, userId });
      throw error;
    }
  }
  
  /**
   * Bulk update users
   * @param {Array} userIds - User IDs
   * @param {Object} updateData - Update data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Update result
   */
  static async bulkUpdateUsers(userIds, updateData, context) {
    try {
      // Check admin permissions
      if (!context.isAdmin) {
        throw new ForbiddenError('Admin permissions required for bulk updates');
      }
      
      // Restrict certain fields from bulk update
      const restrictedFields = ['email', 'password', 'permissions'];
      restrictedFields.forEach(field => delete updateData[field]);
      
      const result = await User.updateMany(
        { 
          _id: { $in: userIds },
          status: { $ne: 'deleted' }
        },
        { 
          $set: updateData,
          $currentDate: { 'activity.lastActive': true }
        }
      );
      
      // Clear cache for all updated users
      await Promise.all(
        userIds.map(userId => CacheService.delete(`user:${userId}`))
      );
      
      // Audit log
      await AuditService.log({
        type: 'users_bulk_updated',
        action: 'bulk_update',
        category: 'users',
        result: 'success',
        userId: context.userId,
        metadata: {
          userCount: result.modifiedCount,
          fields: Object.keys(updateData)
        }
      });
      
      return {
        success: true,
        updated: result.modifiedCount,
        message: `${result.modifiedCount} users updated successfully`
      };
      
    } catch (error) {
      logger.error('Bulk update users error', { error });
      throw error;
    }
  }
  
  /**
   * Send welcome email
   * @param {Object} user - User object
   */
  static async sendWelcomeEmail(user) {
    try {
      await EmailService.sendEmail({
        to: user.email,
        subject: 'Welcome to InsightSerenity',
        template: 'welcome',
        data: {
          firstName: user.firstName,
          loginUrl: `${config.client.url}/auth/login`
        }
      });
    } catch (error) {
      logger.error('Send welcome email error', { error, userId: user._id });
    }
  }
  
  /**
   * Send organization welcome email
   * @param {Object} user - User object
   * @param {Object} organization - Organization object
   */
  static async sendOrganizationWelcomeEmail(user, organization) {
    try {
      await EmailService.sendEmail({
        to: user.email,
        subject: `Welcome to ${organization.name}`,
        template: 'organization-welcome',
        data: {
          firstName: user.firstName,
          organizationName: organization.name,
          dashboardUrl: `${config.client.url}/organizations/${organization.slug}`
        }
      });
    } catch (error) {
      logger.error('Send organization welcome email error', { error });
    }
  }
  
  /**
   * Deep merge objects
   * @param {Object} target - Target object
   * @param {Object} source - Source object
   * @returns {Object} Merged object
   */
  static deepMerge(target, source) {
    const output = { ...target };
    
    Object.keys(source).forEach(key => {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        if (target[key] && typeof target[key] === 'object' && !Array.isArray(target[key])) {
          output[key] = this.deepMerge(target[key], source[key]);
        } else {
          output[key] = source[key];
        }
      } else {
        output[key] = source[key];
      }
    });
    
    return output;
  }
}

module.exports = UserService;