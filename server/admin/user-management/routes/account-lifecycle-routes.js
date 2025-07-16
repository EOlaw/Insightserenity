// server/admin/user-management/routes/account-lifecycle-routes.js
/**
 * @file Account Lifecycle Routes
 * @description Routes for account lifecycle management operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const AccountLifecycleController = require('../controllers/account-lifecycle-controller');

// Middleware
const { requireUserManagementPermission, verifyTargetUserAccess, verifyOrganizationScope, requireElevatedPrivileges, trackUserManagementAction } = require('../middleware/user-management-auth');
const { adminRateLimiter } = require('../../../shared/admin/middleware/admin-rate-limiting');
const { cacheMiddleware } = require('../../../shared/admin/middleware/admin-cache-middleware');

// Validation
const { middleware: lifecycleValidationMiddleware } = require('../validation/lifecycle-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * @route   GET /api/admin/users/lifecycle/overview
 * @desc    Get account lifecycle overview
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_LIFECYCLE permission
 */
router.get(
  '/overview',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_LIFECYCLE),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateLifecycleOverview,
  cacheMiddleware('lifecycle_overview', 3600), // 1 hour cache
  trackUserManagementAction('view_lifecycle_overview'),
  adminRateLimiter('lifecycleView'),
  AccountLifecycleController.getLifecycleOverview
);

/**
 * @route   POST /api/admin/users/lifecycle/policies
 * @desc    Configure lifecycle policies
 * @access  Admin - Requires USER_MANAGEMENT.CONFIGURE_POLICIES permission
 */
router.post(
  '/policies',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.CONFIGURE_POLICIES),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requireRecentAuth: true
  }),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateLifecyclePolicies,
  trackUserManagementAction('configure_lifecycle_policies'),
  adminRateLimiter('policyConfiguration'),
  AccountLifecycleController.configureLifecyclePolicies
);

/**
 * @route   POST /api/admin/users/:userId/lifecycle/transition
 * @desc    Transition account lifecycle stage
 * @access  Admin - Requires USER_MANAGEMENT.MANAGE_LIFECYCLE permission
 */
router.post(
  '/:userId/lifecycle/transition',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.MANAGE_LIFECYCLE),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyTargetUserAccess,
  lifecycleValidationMiddleware.validateLifecycleTransition,
  trackUserManagementAction('lifecycle_transition'),
  adminRateLimiter('lifecycleTransition'),
  AccountLifecycleController.transitionAccountLifecycle
);

/**
 * @route   POST /api/admin/users/:userId/lifecycle/reactivate
 * @desc    Reactivate user account
 * @access  Admin - Requires USER_MANAGEMENT.REACTIVATE permission
 */
router.post(
  '/:userId/lifecycle/reactivate',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.REACTIVATE),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyTargetUserAccess,
  lifecycleValidationMiddleware.validateAccountReactivation,
  trackUserManagementAction('account_reactivation'),
  adminRateLimiter('accountReactivation'),
  AccountLifecycleController.reactivateAccount
);

/**
 * @route   POST /api/admin/users/lifecycle/schedule-deletion
 * @desc    Schedule account deletion
 * @access  Admin - Requires USER_MANAGEMENT.SCHEDULE_DELETION permission
 */
router.post(
  '/lifecycle/schedule-deletion',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.SCHEDULE_DELETION),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateScheduledDeletion,
  trackUserManagementAction('schedule_deletion'),
  adminRateLimiter('scheduleDeletion'),
  AccountLifecycleController.scheduleAccountDeletion
);

/**
 * @route   GET /api/admin/users/lifecycle/automation-rules
 * @desc    Get lifecycle automation rules
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_LIFECYCLE permission
 */
router.get(
  '/lifecycle/automation-rules',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_LIFECYCLE),
  verifyOrganizationScope,
  cacheMiddleware('lifecycle_automation_rules', 1800), // 30 minutes cache
  trackUserManagementAction('view_automation_rules'),
  adminRateLimiter('automationRuleView'),
  AccountLifecycleController.getLifecycleAutomationRules
);

/**
 * @route   POST /api/admin/users/lifecycle/automation-rules
 * @desc    Create lifecycle automation rule
 * @access  Admin - Requires USER_MANAGEMENT.CREATE_AUTOMATION permission
 */
router.post(
  '/lifecycle/automation-rules',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.CREATE_AUTOMATION),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateAutomationRule,
  trackUserManagementAction('create_automation_rule'),
  adminRateLimiter('automationRuleCreate'),
  AccountLifecycleController.createLifecycleAutomationRule
);

/**
 * @route   PUT /api/admin/users/lifecycle/automation-rules/:ruleId
 * @desc    Update lifecycle automation rule
 * @access  Admin - Requires USER_MANAGEMENT.CREATE_AUTOMATION permission
 */
router.put(
  '/lifecycle/automation-rules/:ruleId',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.CREATE_AUTOMATION),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateAutomationRule,
  trackUserManagementAction('update_automation_rule'),
  adminRateLimiter('automationRuleUpdate'),
  AccountLifecycleController.updateLifecycleAutomationRule
);

/**
 * @route   DELETE /api/admin/users/lifecycle/automation-rules/:ruleId
 * @desc    Delete lifecycle automation rule
 * @access  Admin - Requires USER_MANAGEMENT.CREATE_AUTOMATION permission
 */
router.delete(
  '/lifecycle/automation-rules/:ruleId',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.CREATE_AUTOMATION),
  requireElevatedPrivileges({ requireMFA: true }),
  trackUserManagementAction('delete_automation_rule'),
  adminRateLimiter('automationRuleDelete'),
  AccountLifecycleController.deleteLifecycleAutomationRule
);

/**
 * @route   GET /api/admin/users/lifecycle/retention-analysis
 * @desc    Get account retention analysis
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_ANALYTICS permission
 */
router.get(
  '/lifecycle/retention-analysis',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_ANALYTICS),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateRetentionAnalysis,
  cacheMiddleware('lifecycle_retention', 3600), // 1 hour cache
  trackUserManagementAction('view_retention_analysis'),
  adminRateLimiter('analyticsView'),
  AccountLifecycleController.getAccountRetentionAnalysis
);

/**
 * @route   GET /api/admin/users/lifecycle/at-risk
 * @desc    Get at-risk accounts
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_LIFECYCLE permission
 */
router.get(
  '/lifecycle/at-risk',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_LIFECYCLE),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateAtRiskAccounts,
  cacheMiddleware('lifecycle_at_risk', 1800), // 30 minutes cache
  trackUserManagementAction('view_at_risk_accounts'),
  adminRateLimiter('lifecycleView'),
  AccountLifecycleController.getAtRiskAccounts
);

/**
 * @route   GET /api/admin/users/lifecycle/events
 * @desc    Get lifecycle events history
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_LIFECYCLE permission
 */
router.get(
  '/lifecycle/events',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_LIFECYCLE),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateLifecycleEvents,
  trackUserManagementAction('view_lifecycle_events'),
  adminRateLimiter('lifecycleView'),
  AccountLifecycleController.getLifecycleEvents
);

/**
 * @route   POST /api/admin/users/lifecycle/execute-action
 * @desc    Execute lifecycle action manually
 * @access  Admin - Requires USER_MANAGEMENT.MANAGE_LIFECYCLE permission
 */
router.post(
  '/lifecycle/execute-action',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.MANAGE_LIFECYCLE),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requireRecentAuth: true
  }),
  verifyOrganizationScope,
  lifecycleValidationMiddleware.validateLifecycleAction,
  trackUserManagementAction('execute_lifecycle_action'),
  adminRateLimiter('lifecycleAction'),
  AccountLifecycleController.executeLifecycleAction
);

/**
 * @route   GET /api/admin/users/lifecycle/recommendations
 * @desc    Get lifecycle recommendations
 * @access  Admin - Requires USER_MANAGEMENT.VIEW_LIFECYCLE permission
 */
router.get(
  '/lifecycle/recommendations',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW_LIFECYCLE),
  verifyOrganizationScope,
  cacheMiddleware('lifecycle_recommendations', 3600), // 1 hour cache
  trackUserManagementAction('view_lifecycle_recommendations'),
  adminRateLimiter('lifecycleView'),
  AccountLifecycleController.getLifecycleRecommendations
);

module.exports = router;