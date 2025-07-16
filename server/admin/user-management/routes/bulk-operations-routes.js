// server/admin/user-management/routes/bulk-operations-routes.js
/**
 * @file Bulk Operations Routes
 * @description Routes for bulk user operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();
const multer = require('multer');

// Controllers
const BulkOperationsController = require('../controllers/bulk-operations-controller');

// Middleware
const { requireUserManagementPermission, verifyOrganizationScope, requireElevatedPrivileges, trackUserManagementAction, validateCrossOrganizationOperation } = require('../middleware/user-management-auth');
const { checkConcurrentOperations, checkDailyOperationLimit, checkOperationSizeLimit, createBulkOperationRateLimiter, checkResourceAvailability, validateBulkPermissions, trackBulkOperationMetrics } = require('../middleware/bulk-operation-limits');

// Validation
const { middleware: bulkValidationMiddleware } = require('../validation/bulk-operations-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: AdminLimits.FILE_UPLOAD.MAX_IMPORT_SIZE
  },
  fileFilter: (req, file, cb) => {
    const allowedMimeTypes = [
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ];
    
    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only CSV and Excel files are allowed.'));
    }
  }
});

// Apply common middleware to all bulk routes
router.use(validateBulkPermissions);
router.use(checkResourceAvailability);
router.use(trackBulkOperationMetrics);

/**
 * @route   POST /api/admin/users/bulk/import
 * @desc    Import users from file
 * @access  Admin - Requires USER_MANAGEMENT.BULK_IMPORT permission
 */
router.post(
  '/import',
  upload.single('file'),
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_IMPORT),
  requireElevatedPrivileges({ requireMFA: true }),
  checkConcurrentOperations,
  checkDailyOperationLimit,
  createBulkOperationRateLimiter('import'),
  bulkValidationMiddleware.validateBulkImport,
  trackUserManagementAction('bulk_import'),
  BulkOperationsController.initiateUserImport
);

/**
 * @route   POST /api/admin/users/bulk/update
 * @desc    Update multiple users
 * @access  Admin - Requires USER_MANAGEMENT.BULK_UPDATE permission
 */
router.post(
  '/update',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_UPDATE),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  checkConcurrentOperations,
  checkOperationSizeLimit,
  createBulkOperationRateLimiter('update'),
  bulkValidationMiddleware.validateBulkUpdate,
  trackUserManagementAction('bulk_update'),
  BulkOperationsController.executeBulkUpdate
);

/**
 * @route   POST /api/admin/users/bulk/delete
 * @desc    Delete multiple users
 * @access  Admin - Requires USER_MANAGEMENT.BULK_DELETE permission
 */
router.post(
  '/delete',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_DELETE),
  requireElevatedPrivileges({ 
    requireMFA: true, 
    requirePasswordConfirmation: true 
  }),
  verifyOrganizationScope,
  checkConcurrentOperations,
  checkOperationSizeLimit,
  createBulkOperationRateLimiter('delete'),
  bulkValidationMiddleware.validateBulkDelete,
  trackUserManagementAction('bulk_delete'),
  BulkOperationsController.executeBulkDelete
);

/**
 * @route   POST /api/admin/users/bulk/export
 * @desc    Export users to file
 * @access  Admin - Requires USER_MANAGEMENT.EXPORT permission
 */
router.post(
  '/export',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.EXPORT),
  verifyOrganizationScope,
  checkConcurrentOperations,
  createBulkOperationRateLimiter('export'),
  bulkValidationMiddleware.validateBulkExport,
  trackUserManagementAction('bulk_export'),
  BulkOperationsController.exportUsers
);

/**
 * @route   POST /api/admin/users/bulk/email
 * @desc    Send bulk emails to users
 * @access  Admin - Requires USER_MANAGEMENT.BULK_EMAIL permission
 */
router.post(
  '/email',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_EMAIL),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  checkConcurrentOperations,
  checkOperationSizeLimit,
  createBulkOperationRateLimiter('email'),
  bulkValidationMiddleware.validateBulkEmail,
  trackUserManagementAction('bulk_email'),
  BulkOperationsController.sendBulkEmails
);

/**
 * @route   POST /api/admin/users/bulk/assign-role
 * @desc    Bulk assign role to users
 * @access  Admin - Requires USER_MANAGEMENT.BULK_UPDATE permission
 */
router.post(
  '/assign-role',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_UPDATE),
  requireElevatedPrivileges({ requireMFA: true }),
  verifyOrganizationScope,
  checkConcurrentOperations,
  checkOperationSizeLimit,
  createBulkOperationRateLimiter('update'),
  bulkValidationMiddleware.validateBulkRoleAssignment,
  trackUserManagementAction('bulk_assign_role'),
  BulkOperationsController.bulkAssignRole
);

/**
 * @route   POST /api/admin/users/bulk/assign-organization
 * @desc    Bulk assign organization to users
 * @access  Admin - Requires USER_MANAGEMENT.BULK_UPDATE permission
 */
router.post(
  '/assign-organization',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_UPDATE),
  requireElevatedPrivileges({ requireMFA: true }),
  validateCrossOrganizationOperation,
  checkConcurrentOperations,
  checkOperationSizeLimit,
  createBulkOperationRateLimiter('update'),
  bulkValidationMiddleware.validateBulkOrganizationAssignment,
  trackUserManagementAction('bulk_assign_organization'),
  BulkOperationsController.bulkAssignOrganization
);

/**
 * @route   POST /api/admin/users/bulk/reset-passwords
 * @desc    Bulk reset user passwords
 * @access  Admin - Requires USER_MANAGEMENT.BULK_UPDATE permission
 */
router.post(
  '/reset-passwords',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_UPDATE),
  requireElevatedPrivileges({ 
    requireMFA: true,
    requirePasswordConfirmation: true
  }),
  verifyOrganizationScope,
  checkConcurrentOperations,
  checkOperationSizeLimit,
  createBulkOperationRateLimiter('update'),
  bulkValidationMiddleware.validateBulkPasswordReset,
  trackUserManagementAction('bulk_reset_passwords'),
  BulkOperationsController.bulkResetPasswords
);

/**
 * @route   GET /api/admin/users/bulk/operations/:operationId
 * @desc    Get bulk operation status
 * @access  Admin - Requires USER_MANAGEMENT.VIEW permission
 */
router.get(
  '/operations/:operationId',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW),
  trackUserManagementAction('view_operation_status'),
  BulkOperationsController.getOperationStatus
);

/**
 * @route   GET /api/admin/users/bulk/operations
 * @desc    Get bulk operations history
 * @access  Admin - Requires USER_MANAGEMENT.VIEW permission
 */
router.get(
  '/operations',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW),
  trackUserManagementAction('view_operations_history'),
  BulkOperationsController.getOperationsHistory
);

/**
 * @route   POST /api/admin/users/bulk/operations/:operationId/cancel
 * @desc    Cancel bulk operation
 * @access  Admin - Requires USER_MANAGEMENT.BULK_OPERATIONS permission
 */
router.post(
  '/operations/:operationId/cancel',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_OPERATIONS),
  trackUserManagementAction('cancel_operation'),
  BulkOperationsController.cancelOperation
);

/**
 * @route   POST /api/admin/users/bulk/operations/:operationId/retry
 * @desc    Retry failed bulk operation
 * @access  Admin - Requires USER_MANAGEMENT.BULK_OPERATIONS permission
 */
router.post(
  '/operations/:operationId/retry',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_OPERATIONS),
  checkConcurrentOperations,
  trackUserManagementAction('retry_operation'),
  BulkOperationsController.retryOperation
);

/**
 * @route   GET /api/admin/users/bulk/operations/:operationId/download
 * @desc    Download bulk operation results
 * @access  Admin - Requires USER_MANAGEMENT.VIEW permission
 */
router.get(
  '/operations/:operationId/download',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.VIEW),
  trackUserManagementAction('download_operation_results'),
  BulkOperationsController.downloadOperationResults
);

/**
 * @route   GET /api/admin/users/bulk/import-template
 * @desc    Get import template file
 * @access  Admin - Requires USER_MANAGEMENT.BULK_IMPORT permission
 */
router.get(
  '/import-template',
  requireUserManagementPermission(AdminPermissions.USER_MANAGEMENT.BULK_IMPORT),
  trackUserManagementAction('download_import_template'),
  BulkOperationsController.getImportTemplate
);

module.exports = router;