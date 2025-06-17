// server/shared/users/controllers/user-controller.js
/**
 * @file User Controller
 * @description Handles HTTP requests for user-related operations
 * @version 3.0.0
 */

const config = require('../../config/config');
const { 
  ValidationError, 
  NotFoundError,
  ForbiddenError 
} = require('../../utils/app-error');
const { asyncHandler } = require('../../utils/async-handler');
const FileUploadService = require('../../utils/helpers/file-helper');
const logger = require('../../utils/logger');
const responseHandler = require('../../utils/response-handler');
const UserService = require('../services/user-service');

/**
 * User Controller Class
 * @class UserController
 */
class UserController {
  /**
   * Get current user profile
   * @route   GET /api/users/me
   * @access  Private
   */
  static getMe = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const user = await UserService.getUserById(userId, {
      populate: [
        {
          path: 'organization.current',
          select: 'name slug logo type'
        }
      ]
    });
    
    responseHandler.success(res, { user }, 'User profile retrieved successfully');
  });
  
  /**
   * Update current user profile
   * @route   PUT /api/users/me
   * @access  Private
   */
  static updateMe = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const updateData = req.body;
    
    // Remove fields that shouldn't be updated through this endpoint
    const restrictedFields = ['email', 'role', 'permissions', 'status', 'userType'];
    restrictedFields.forEach(field => delete updateData[field]);
    
    const context = {
      userId: req.user._id,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const updatedUser = await UserService.updateUser(userId, updateData, context);
    
    responseHandler.success(res, { user: updatedUser }, 'Profile updated successfully');
  });
  
  /**
   * Update current user profile details
   * @route   PUT /api/users/me/profile
   * @access  Private
   */
  static updateMyProfile = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const profileData = req.body;
    
    const context = {
      userId: req.user._id,
      hasPermission: (permission) => req.user.permissions?.includes(permission)
    };
    
    const updatedUser = await UserService.updateUserProfile(userId, profileData, context);
    
    responseHandler.success(res, { user: updatedUser }, 'Profile details updated successfully');
  });
  
  /**
   * Update current user avatar
   * @route   POST /api/users/me/avatar
   * @access  Private
   */
  static updateMyAvatar = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    if (!req.file) {
      throw new ValidationError('No file uploaded');
    }
    
    // Validate file
    const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowedTypes.includes(req.file.mimetype)) {
      throw new ValidationError('Invalid file type. Only JPEG, PNG, and WebP images are allowed');
    }
    
    const maxSize = 5 * 1024 * 1024; // 5MB
    if (req.file.size > maxSize) {
      throw new ValidationError('File size exceeds 5MB limit');
    }
    
    const context = {
      userId: req.user._id,
      hasPermission: (permission) => req.user.permissions?.includes(permission)
    };
    
    const updatedUser = await UserService.updateUserAvatar(userId, req.file, context);
    
    responseHandler.success(res, { 
      user: updatedUser,
      avatar: updatedUser.profile.avatar
    }, 'Avatar updated successfully');
  });
  
  /**
   * Remove current user avatar
   * @route   DELETE /api/users/me/avatar
   * @access  Private
   */
  static removeMyAvatar = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const context = {
      userId: req.user._id
    };
    
    const user = await UserService.getUserById(userId);
    
    if (user.profile.avatar?.publicId) {
      await FileUploadService.deleteFile(user.profile.avatar.publicId);
    }
    
    user.profile.avatar = null;
    await user.save();
    
    responseHandler.success(res, { user }, 'Avatar removed successfully');
  });
  
  /**
   * Update current user preferences
   * @route   PUT /api/users/me/preferences
   * @access  Private
   */
  static updateMyPreferences = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const preferences = req.body;
    
    const context = {
      userId: req.user._id
    };
    
    const updatedUser = await UserService.updateUserPreferences(userId, preferences, context);
    
    responseHandler.success(res, { 
      user: updatedUser,
      preferences: updatedUser.preferences
    }, 'Preferences updated successfully');
  });
  
  /**
   * Get user by ID
   * @route   GET /api/users/:userId
   * @access  Private
   */
  static getUserById = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { fields } = req.query;
    
    const options = {
      lean: true
    };
    
    // Restrict fields based on permissions
    if (!req.user.permissions?.includes('users.view.full')) {
      options.select = fields || 'firstName lastName email profile.displayName profile.avatar profile.title profile.location userType role status';
    } else if (fields) {
      options.select = fields;
    }
    
    const user = await UserService.getUserById(userId, options);
    
    responseHandler.success(res, { user }, 'User retrieved successfully');
  });
  
  /**
   * Search users
   * @route   GET /api/users/search
   * @access  Private
   */
  static searchUsers = asyncHandler(async (req, res) => {
    const searchParams = {
      query: req.query.q,
      userType: req.query.userType,
      role: req.query.role,
      organizationId: req.query.organizationId,
      status: req.query.status,
      skills: req.query.skills ? req.query.skills.split(',') : undefined,
      location: req.query.location,
      activelyLooking: req.query.activelyLooking === 'true' ? true : 
                       req.query.activelyLooking === 'false' ? false : undefined,
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 20,
      sort: req.query.sort
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current
    };
    
    const results = await UserService.searchUsers(searchParams, context);
    
    responseHandler.success(res, results, 'Users found');
  });
  
  /**
   * Get all users (admin)
   * @route   GET /api/users
   * @access  Private (Admin)
   */
  static getAllUsers = asyncHandler(async (req, res) => {
    // Check admin permissions
    if (!req.user.permissions?.includes('users.view.all')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const {
      page = 1,
      limit = 20,
      sort = '-createdAt',
      status,
      userType,
      role,
      organizationId
    } = req.query;
    
    const filter = {};
    if (status) filter.status = status;
    if (userType) filter.userType = userType;
    if (role) filter['role.primary'] = role;
    if (organizationId) filter['organization.current'] = organizationId;
    
    const skip = (page - 1) * limit;
    
    const [users, total] = await Promise.all([
      UserService.User.find(filter)
        .select('-preferences -permissions -metadata')
        .populate('organization.current', 'name slug')
        .sort(sort)
        .limit(limit)
        .skip(skip)
        .lean(),
      UserService.User.countDocuments(filter)
    ]);
    
    responseHandler.success(res, {
      users,
      pagination: {
        total,
        page,
        limit,
        pages: Math.ceil(total / limit)
      }
    }, 'Users retrieved successfully');
  });
  
  /**
   * Create user (admin)
   * @route   POST /api/users
   * @access  Private (Admin)
   */
  static createUser = asyncHandler(async (req, res) => {
    // Check admin permissions
    if (!req.user.permissions?.includes('users.create')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const userData = req.body;
    
    const context = {
      userId: req.user._id,
      source: 'admin',
      isAdmin: true
    };
    
    const user = await UserService.createUser(userData, context);
    
    responseHandler.success(res, { user }, 'User created successfully', 201);
  });
  
  /**
   * Update user (admin)
   * @route   PUT /api/users/:userId
   * @access  Private (Admin)
   */
  static updateUser = asyncHandler(async (req, res) => {
    // Check admin permissions
    if (!req.user.permissions?.includes('users.update')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const { userId } = req.params;
    const updateData = req.body;
    
    const context = {
      userId: req.user._id,
      isAdmin: true
    };
    
    const updatedUser = await UserService.updateUser(userId, updateData, context);
    
    responseHandler.success(res, { user: updatedUser }, 'User updated successfully');
  });
  
  /**
   * Delete user (admin)
   * @route   DELETE /api/users/:userId
   * @access  Private (Admin)
   */
  static deleteUser = asyncHandler(async (req, res) => {
    // Check admin permissions
    if (!req.user.permissions?.includes('users.delete')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const { userId } = req.params;
    
    const context = {
      userId: req.user._id,
      isAdmin: true
    };
    
    const result = await UserService.deleteUser(userId, context);
    
    responseHandler.success(res, result, 'User deleted successfully');
  });
  
  /**
   * Bulk update users (admin)
   * @route   PUT /api/users/bulk
   * @access  Private (Admin)
   */
  static bulkUpdateUsers = asyncHandler(async (req, res) => {
    // Check admin permissions
    if (!req.user.permissions?.includes('users.bulk.update')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const { userIds, updateData } = req.body;
    
    if (!Array.isArray(userIds) || userIds.length === 0) {
      throw new ValidationError('User IDs array is required');
    }
    
    const context = {
      userId: req.user._id,
      isAdmin: true
    };
    
    const result = await UserService.bulkUpdateUsers(userIds, updateData, context);
    
    responseHandler.success(res, result, 'Users updated successfully');
  });
  
  /**
   * Get user organizations
   * @route   GET /api/users/:userId/organizations
   * @access  Private
   */
  static getUserOrganizations = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    
    // Check if user can view this information
    if (userId !== req.user._id.toString() && 
        !req.user.permissions?.includes('organizations.view')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const organizations = await UserService.getUserOrganizations(userId);
    
    responseHandler.success(res, { organizations }, 'Organizations retrieved successfully');
  });
  
  /**
   * Add user to organization
   * @route   POST /api/users/:userId/organizations
   * @access  Private (Organization Admin)
   */
  static addUserToOrganization = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { organizationId, role, department } = req.body;
    
    // Check permissions
    if (!req.user.permissions?.includes('organizations.members.add')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const context = {
      userId: req.user._id,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const updatedUser = await UserService.addUserToOrganization(
      userId,
      organizationId,
      { role, department },
      context
    );
    
    responseHandler.success(res, { user: updatedUser }, 'User added to organization successfully');
  });
  
  /**
   * Remove user from organization
   * @route   DELETE /api/users/:userId/organizations/:organizationId
   * @access  Private (Organization Admin)
   */
  static removeUserFromOrganization = asyncHandler(async (req, res) => {
    const { userId, organizationId } = req.params;
    
    // Check permissions
    if (!req.user.permissions?.includes('organizations.members.remove')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const context = {
      userId: req.user._id,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const updatedUser = await UserService.removeUserFromOrganization(
      userId,
      organizationId,
      context
    );
    
    responseHandler.success(res, { user: updatedUser }, 'User removed from organization successfully');
  });
  
  /**
   * Get user statistics
   * @route   GET /api/users/:userId/statistics
   * @access  Private
   */
  static getUserStatistics = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    
    // Check if user can view statistics
    if (userId !== req.user._id.toString() && 
        !req.user.permissions?.includes('users.view.statistics')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const statistics = await UserService.getUserStatistics(userId);
    
    responseHandler.success(res, { statistics }, 'User statistics retrieved successfully');
  });
  
  /**
   * Get my statistics
   * @route   GET /api/users/me/statistics
   * @access  Private
   */
  static getMyStatistics = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const statistics = await UserService.getUserStatistics(userId);
    
    responseHandler.success(res, { statistics }, 'Statistics retrieved successfully');
  });
  
  /**
   * Update user skills
   * @route   PUT /api/users/me/skills
   * @access  Private
   */
  static updateMySkills = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { skills } = req.body;
    
    if (!Array.isArray(skills)) {
      throw new ValidationError('Skills must be an array');
    }
    
    const context = {
      userId: req.user._id
    };
    
    const user = await UserService.getUserById(userId);
    user.profile.professionalInfo.skills = skills;
    await user.save();
    
    responseHandler.success(res, { 
      user,
      skills: user.profile.professionalInfo.skills
    }, 'Skills updated successfully');
  });
  
  /**
   * Update user experience
   * @route   PUT /api/users/me/experience
   * @access  Private
   */
  static updateMyExperience = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { experience } = req.body;
    
    if (!Array.isArray(experience)) {
      throw new ValidationError('Experience must be an array');
    }
    
    const context = {
      userId: req.user._id
    };
    
    const user = await UserService.getUserById(userId);
    user.profile.professionalInfo.experience = experience;
    await user.save();
    
    responseHandler.success(res, { 
      user,
      experience: user.profile.professionalInfo.experience
    }, 'Experience updated successfully');
  });
  
  /**
   * Update user education
   * @route   PUT /api/users/me/education
   * @access  Private
   */
  static updateMyEducation = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { education } = req.body;
    
    if (!Array.isArray(education)) {
      throw new ValidationError('Education must be an array');
    }
    
    const context = {
      userId: req.user._id
    };
    
    const user = await UserService.getUserById(userId);
    user.profile.professionalInfo.education = education;
    await user.save();
    
    responseHandler.success(res, { 
      user,
      education: user.profile.professionalInfo.education
    }, 'Education updated successfully');
  });
  
  /**
   * Switch organization
   * @route   POST /api/users/me/switch-organization
   * @access  Private
   */
  static switchOrganization = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { organizationId } = req.body;
    
    const user = await UserService.getUserById(userId);
    
    // Check if user is member of the organization
    const membership = user.organization.organizations.find(
      org => org.organizationId.toString() === organizationId && org.active
    );
    
    if (!membership) {
      throw new ForbiddenError('You are not a member of this organization');
    }
    
    user.organization.current = organizationId;
    await user.save();
    
    responseHandler.success(res, { 
      user,
      organization: organizationId
    }, 'Organization switched successfully');
  });
  
  /**
   * Get user activity log
   * @route   GET /api/users/:userId/activity
   * @access  Private (Admin)
   */
  static getUserActivity = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { limit = 50, offset = 0 } = req.query;
    
    // Check permissions
    if (userId !== req.user._id.toString() && 
        !req.user.permissions?.includes('users.view.activity')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const user = await UserService.getUserById(userId, {
      select: 'activity'
    });
    
    responseHandler.success(res, { 
      activity: user.activity,
      loginHistory: user.activity.loginHistory?.slice(offset, offset + limit)
    }, 'Activity retrieved successfully');
  });
  
  /**
   * Export user data (GDPR)
   * @route   GET /api/users/me/export
   * @access  Private
   */
  static exportMyData = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const user = await UserService.getUserById(userId, {
      populate: [
        { path: 'organization.current' },
        { path: 'organization.organizations.organizationId' }
      ]
    });
    
    // Remove sensitive data
    const exportData = user.toObject();
    delete exportData.permissions;
    delete exportData.metadata;
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="user-data-${userId}.json"`);
    
    res.json(exportData);
  });
  
  /**
   * Verify user email (for admin-created users)
   * @route   POST /api/users/:userId/verify-email
   * @access  Private (Admin)
   */
  static verifyUserEmail = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    
    // Check admin permissions
    if (!req.user.permissions?.includes('users.verify')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const user = await UserService.getUserById(userId);
    user.isEmailVerified = true;
    user.status = 'active';
    await user.save();
    
    responseHandler.success(res, { user }, 'Email verified successfully');
  });
  
  /**
   * Suspend user
   * @route   POST /api/users/:userId/suspend
   * @access  Private (Admin)
   */
  static suspendUser = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { reason, duration } = req.body;
    
    // Check admin permissions
    if (!req.user.permissions?.includes('users.suspend')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const user = await UserService.getUserById(userId);
    user.status = 'suspended';
    user.metadata.suspension = {
      reason,
      suspendedAt: new Date(),
      suspendedBy: req.user._id,
      duration
    };
    
    await user.save();
    
    // TODO: Revoke all active sessions
    
    responseHandler.success(res, { user }, 'User suspended successfully');
  });
  
  /**
   * Reactivate user
   * @route   POST /api/users/:userId/reactivate
   * @access  Private (Admin)
   */
  static reactivateUser = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    
    // Check admin permissions
    if (!req.user.permissions?.includes('users.reactivate')) {
      throw new ForbiddenError('Insufficient permissions');
    }
    
    const user = await UserService.getUserById(userId);
    
    if (user.status !== 'suspended' && user.status !== 'inactive') {
      throw new ValidationError('User is not suspended or inactive');
    }
    
    user.status = 'active';
    user.metadata.reactivation = {
      reactivatedAt: new Date(),
      reactivatedBy: req.user._id
    };
    
    await user.save();
    
    responseHandler.success(res, { user }, 'User reactivated successfully');
  });
}

module.exports = UserController;