/**
 * Role Conversion Controller
 * @description Clean controller for handling role upgrades and conversions
 */

const AuthService = require('../services/auth-service');
const { AppError } = require('../../utils/app-error');
const logger = require('../../utils/logger');
const responseHandler = require('../../utils/response-handler');
const { asyncHandler } = require('../../utils/async-handler');

class RoleConversionController {
  /**
   * Upgrade prospect to client
   * @route POST /api/auth/upgrade-to-client
   * @access Private - Prospects only
   */
  static upgradeToClient = asyncHandler(async (req, res, next) => {
    const { paymentVerification, salesApproval } = req.body;
    
    // Basic validation
    if (!paymentVerification && !salesApproval) {
      throw new AppError('Payment verification or sales approval required', 400);
    }

    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: req.user._id,
      source: 'role_upgrade_request'
    };

    const verificationData = {
      paymentVerified: !!paymentVerification,
      salesApproved: !!salesApproval
    };

    // Delegate to service
    const result = await AuthService.upgradeUserRole(
      req.user._id,
      'client',
      verificationData,
      context
    );

    responseHandler.success(res, result, result.message);
  });

  /**
   * Admin role management
   * @route POST /api/auth/admin/change-user-role
   * @access Private - Admins only
   */
  static adminChangeUserRole = asyncHandler(async (req, res, next) => {
    const { userId, newRole, action, reason } = req.body;

    // Validate admin permissions
    if (!req.user.permissions?.includes('users.manage') && req.user.role.primary !== 'super_admin') {
      throw new AppError('Insufficient permissions for role management', 403);
    }

    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      adminUserId: req.user._id,
      isAdmin: true,
      reason
    };

    let result;

    if (action === 'upgrade') {
      const verificationData = {
        adminApproved: true,
        salesApproved: true // Admin approval counts as sales approval
      };
      
      result = await AuthService.upgradeUserRole(userId, newRole, verificationData, context);
    } else if (action === 'downgrade') {
      result = await AuthService.downgradeUserRole(userId, newRole, context);
    } else {
      throw new AppError('Invalid action. Must be "upgrade" or "downgrade"', 400);
    }

    responseHandler.success(res, result, `User role ${action}d successfully`);
  });

  /**
   * Get available role upgrade options for current user
   * @route GET /api/auth/upgrade-options
   * @access Private
   */
  static getUpgradeOptions = asyncHandler(async (req, res, next) => {
    const currentRole = req.user.role.primary;
    
    // Define upgrade paths
    const upgradeOptions = {
      prospect: [
        {
          role: 'client',
          name: 'Client',
          description: 'Access to create organizations and start paid subscriptions',
          requirements: ['Payment verification OR Sales approval'],
          benefits: ['Create organizations', 'Invite team members', 'Access paid features']
        }
      ],
      client: [
        {
          role: 'org_owner',
          name: 'Organization Owner',
          description: 'Full control over organization settings and billing',
          requirements: ['Active organization'],
          benefits: ['Full organization control', 'Billing management', 'Advanced settings']
        }
      ]
    };

    const availableUpgrades = upgradeOptions[currentRole] || [];

    responseHandler.success(res, {
      currentRole,
      availableUpgrades,
      canUpgrade: availableUpgrades.length > 0
    }, 'Upgrade options retrieved successfully');
  });
}

module.exports = RoleConversionController;