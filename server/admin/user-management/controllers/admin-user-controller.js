// server/admin/user-management/controllers/admin-user-controller.js
/**
 * @file Admin User Controller
 * @description Controller for handling admin user management operations
 * @version 1.0.0
 */

// Services
const AdminUserService = require('../services/admin-user-service');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');

// Utilities
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizers');
const ResponseFormatter = require('../../../shared/utils/response-formatter');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Admin User Controller Class
 */
class AdminUserController {
  /**
   * Get users with filtering and pagination
   * @route GET /api/admin/users
   */
  getUsers = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    
    // Sanitize and validate query parameters
    const queryParams = sanitizeQuery(req.query);
    
    const options = {
      page: parseInt(queryParams.page) || 1,
      limit: Math.min(parseInt(queryParams.limit) || 20, AdminLimits.PAGINATION.MAX_LIMIT),
      search: queryParams.search,
      status: queryParams.status,
      role: queryParams.role,
      organization: queryParams.organization,
      verified: queryParams.verified ? queryParams.verified === 'true' : undefined,
      hasSubscription: queryParams.hasSubscription ? queryParams.hasSubscription === 'true' : undefined,
      createdFrom: queryParams.createdFrom,
      createdTo: queryParams.createdTo,
      lastActiveFrom: queryParams.lastActiveFrom,
      lastActiveTo: queryParams.lastActiveTo,
      sortBy: queryParams.sortBy || 'createdAt',
      sortOrder: queryParams.sortOrder || 'desc',
      includeDeleted: queryParams.includeDeleted === 'true',
      exportFormat: queryParams.exportFormat
    };

    // Validate date ranges
    if (options.createdFrom && options.createdTo) {
      if (new Date(options.createdFrom) > new Date(options.createdTo)) {
        throw new ValidationError('Invalid date range: createdFrom must be before createdTo');
      }
    }

    // Execute service method
    const result = await AdminUserService.getUsers(adminUser, options);

    // Handle export response
    if (options.exportFormat) {
      res.setHeader('Content-Type', result.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${result.fileName}"`);
      return res.send(result.data);
    }

    // Return standard response
    res.status(200).json(
      ResponseFormatter.success(result, 'Users retrieved successfully')
    );
  });

  /**
   * Get detailed user information
   * @route GET /api/admin/users/:userId
   */
  getUserDetails = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;

    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const userDetails = await AdminUserService.getUserDetails(adminUser, userId);

    res.status(200).json(
      ResponseFormatter.success(userDetails, 'User details retrieved successfully')
    );
  });

  /**
   * Create new user
   * @route POST /api/admin/users
   */
  createUser = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    
    // Sanitize and validate request body
    const userData = sanitizeBody(req.body);

    // Validate required fields
    const requiredFields = ['email', 'password', 'role'];
    const missingFields = requiredFields.filter(field => !userData[field]);
    
    if (missingFields.length > 0) {
      throw new ValidationError(`Missing required fields: ${missingFields.join(', ')}`);
    }

    // Validate email format
    if (!AdminHelpers.isValidEmail(userData.email)) {
      throw new ValidationError('Invalid email format');
    }

    // Validate password strength
    if (!AdminHelpers.isStrongPassword(userData.password)) {
      throw new ValidationError('Password does not meet security requirements');
    }

    // Validate role
    if (!AdminHelpers.isValidObjectId(userData.role)) {
      throw new ValidationError('Invalid role ID');
    }

    // Validate organization if provided
    if (userData.organization && !AdminHelpers.isValidObjectId(userData.organization)) {
      throw new ValidationError('Invalid organization ID');
    }

    // Create user
    const result = await AdminUserService.createUser(adminUser, userData);

    res.status(201).json(
      ResponseFormatter.success(result, 'User created successfully')
    );
  });

  /**
   * Update user information
   * @route PUT /api/admin/users/:userId
   */
  updateUser = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    // Sanitize and validate update data
    const updates = sanitizeBody(req.body);

    // Validate specific update fields
    if (updates.email && !AdminHelpers.isValidEmail(updates.email)) {
      throw new ValidationError('Invalid email format');
    }

    if (updates.role && !AdminHelpers.isValidObjectId(updates.role.primary)) {
      throw new ValidationError('Invalid role ID');
    }

    if (updates.organization && !AdminHelpers.isValidObjectId(updates.organization)) {
      throw new ValidationError('Invalid organization ID');
    }

    if (updates.status && !['active', 'suspended', 'locked'].includes(updates.status)) {
      throw new ValidationError('Invalid status value');
    }

    // Prevent self-modification of critical fields
    if (userId === adminUser.id) {
      const restrictedFields = ['status', 'role', 'permissions'];
      const attemptedRestricted = Object.keys(updates).filter(field => 
        restrictedFields.includes(field)
      );
      
      if (attemptedRestricted.length > 0) {
        throw new ValidationError('Cannot modify own account critical fields');
      }
    }

    // Update user
    const result = await AdminUserService.updateUser(adminUser, userId, updates);

    res.status(200).json(
      ResponseFormatter.success(result, 'User updated successfully')
    );
  });

  /**
   * Delete user account
   * @route DELETE /api/admin/users/:userId
   */
  deleteUser = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    // Prevent self-deletion
    if (userId === adminUser.id) {
      throw new ValidationError('Cannot delete your own account');
    }

    // Get deletion options from body
    const options = sanitizeBody(req.body);

    // Validate deletion reason
    if (!options.reason || options.reason.trim().length < 10) {
      throw new ValidationError('Deletion reason required (minimum 10 characters)');
    }

    // Validate transfer ownership if provided
    if (options.transferOwnership && !AdminHelpers.isValidObjectId(options.transferOwnership)) {
      throw new ValidationError('Invalid transfer ownership user ID');
    }

    // Delete user
    const result = await AdminUserService.deleteUser(adminUser, userId, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'User deleted successfully')
    );
  });

  /**
   * Reset user password
   * @route POST /api/admin/users/:userId/reset-password
   */
  resetUserPassword = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const options = sanitizeBody(req.body);

    // Validate password if provided
    if (options.newPassword && !AdminHelpers.isStrongPassword(options.newPassword)) {
      throw new ValidationError('Password does not meet security requirements');
    }

    // Validate reason
    if (!options.reason || options.reason.trim().length < 5) {
      throw new ValidationError('Password reset reason required (minimum 5 characters)');
    }

    // Reset password
    const result = await AdminUserService.resetUserPassword(adminUser, userId, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'Password reset successfully')
    );
  });

  /**
   * Toggle user suspension
   * @route POST /api/admin/users/:userId/suspension
   */
  toggleUserSuspension = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    // Prevent self-suspension
    if (userId === adminUser.id) {
      throw new ValidationError('Cannot suspend your own account');
    }

    const suspensionData = sanitizeBody(req.body);

    // Validate required fields
    if (!suspensionData.action || !['suspend', 'unsuspend'].includes(suspensionData.action)) {
      throw new ValidationError('Invalid suspension action');
    }

    if (!suspensionData.reason || suspensionData.reason.trim().length < 10) {
      throw new ValidationError('Suspension reason required (minimum 10 characters)');
    }

    // Validate duration if provided
    if (suspensionData.duration && (suspensionData.duration < 1 || suspensionData.duration > 365)) {
      throw new ValidationError('Suspension duration must be between 1 and 365 days');
    }

    // Toggle suspension
    const result = await AdminUserService.toggleUserSuspension(adminUser, userId, suspensionData);

    res.status(200).json(
      ResponseFormatter.success(result, `User ${suspensionData.action}ed successfully`)
    );
  });

  /**
   * Force user logout
   * @route POST /api/admin/users/:userId/force-logout
   */
  forceUserLogout = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const options = sanitizeBody(req.body);

    // Force logout
    const result = await AdminUserService.forceUserLogout(userId, adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'User logged out successfully')
    );
  });

  /**
   * Get user activity logs
   * @route GET /api/admin/users/:userId/activity
   */
  getUserActivity = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const queryParams = sanitizeQuery(req.query);
    
    const options = {
      page: parseInt(queryParams.page) || 1,
      limit: Math.min(parseInt(queryParams.limit) || 20, AdminLimits.PAGINATION.MAX_LIMIT),
      startDate: queryParams.startDate,
      endDate: queryParams.endDate,
      activityType: queryParams.activityType
    };

    // Get user activity
    const result = await AdminUserService.getUserActivity(adminUser, userId, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'User activity retrieved successfully')
    );
  });

  /**
   * Get user sessions
   * @route GET /api/admin/users/:userId/sessions
   */
  getUserSessions = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const queryParams = sanitizeQuery(req.query);
    
    const options = {
      includeInactive: queryParams.includeInactive === 'true',
      limit: Math.min(parseInt(queryParams.limit) || 10, 50)
    };

    // Get user sessions
    const result = await AdminUserService.getUserSessions(adminUser, userId, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'User sessions retrieved successfully')
    );
  });

  /**
   * Update user permissions
   * @route PUT /api/admin/users/:userId/permissions
   */
  updateUserPermissions = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    // Prevent self-modification of permissions
    if (userId === adminUser.id) {
      throw new ValidationError('Cannot modify your own permissions');
    }

    const { permissions } = sanitizeBody(req.body);

    if (!Array.isArray(permissions)) {
      throw new ValidationError('Permissions must be an array');
    }

    // Validate permission structure
    permissions.forEach((permission, index) => {
      if (!permission.resource || !permission.actions) {
        throw new ValidationError(`Invalid permission structure at index ${index}`);
      }
      
      if (!Array.isArray(permission.actions)) {
        throw new ValidationError(`Permission actions must be an array at index ${index}`);
      }
    });

    // Update permissions
    const result = await AdminUserService.updateUserPermissions(adminUser, userId, permissions);

    res.status(200).json(
      ResponseFormatter.success(result, 'User permissions updated successfully')
    );
  });

  /**
   * Send password reset email
   * @route POST /api/admin/users/:userId/send-password-reset
   */
  sendPasswordResetEmail = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const options = sanitizeBody(req.body);

    // Send password reset email
    const result = await AdminUserService.sendPasswordResetEmail(adminUser, userId, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'Password reset email sent successfully')
    );
  });

  /**
   * Verify user email manually
   * @route POST /api/admin/users/:userId/verify-email
   */
  verifyUserEmail = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const options = sanitizeBody(req.body);

    // Verify email
    const result = await AdminUserService.verifyUserEmail(adminUser, userId, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'User email verified successfully')
    );
  });

  /**
   * Get user audit logs
   * @route GET /api/admin/users/:userId/audit-logs
   */
  getUserAuditLogs = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    
    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const queryParams = sanitizeQuery(req.query);
    
    const options = {
      page: parseInt(queryParams.page) || 1,
      limit: Math.min(parseInt(queryParams.limit) || 20, AdminLimits.PAGINATION.MAX_LIMIT),
      startDate: queryParams.startDate,
      endDate: queryParams.endDate,
      action: queryParams.action,
      severity: queryParams.severity
    };

    // Get audit logs
    const result = await AdminUserService.getUserAuditLogs(adminUser, userId, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'User audit logs retrieved successfully')
    );
  });
}

module.exports = new AdminUserController();