/**
 * @file Bulk Operation Validation
 * @description Validation schemas for bulk administrative operations
 * @version 1.0.0
 */

const { body, param, query } = require('express-validator');
const AdminPermissions = require('../utils/admin-permissions');
const AdminValidators = require('../utils/admin-validators');

/**
 * Common bulk operation patterns
 */
const patterns = {
  operationId: /^BULK-[A-Z0-9]{8}-[A-Z0-9]{4}$/,
  batchId: /^BATCH-[0-9]{13}-[A-Z0-9]{6}$/
};

/**
 * Validate bulk user operation
 */
const bulkUserOperationSchema = [
  body('operation')
    .notEmpty().withMessage('Operation is required')
    .isIn([
      'activate', 'deactivate', 'suspend', 'unsuspend',
      'delete', 'restore', 'resetPassword', 'updateRole',
      'removeRole', 'updatePermissions', 'sendNotification',
      'exportData', 'archiveData'
    ])
    .withMessage('Invalid bulk operation type'),

  body('userIds')
    .isArray({ min: 1, max: 1000 }).withMessage('User IDs must be an array with 1-1000 items')
    .custom((value) => {
      return value.every(id => /^[0-9a-fA-F]{24}$/.test(id));
    }).withMessage('All user IDs must be valid MongoDB ObjectIDs'),

  body('options')
    .optional()
    .isObject().withMessage('Options must be an object'),

  body('options.force')
    .optional()
    .isBoolean().withMessage('Force option must be boolean'),

  body('options.skipValidation')
    .optional()
    .isBoolean().withMessage('Skip validation must be boolean'),

  body('options.notifyUsers')
    .optional()
    .isBoolean().withMessage('Notify users must be boolean'),

  body('options.reason')
    .optional()
    .trim()
    .isLength({ min: 10, max: 500 }).withMessage('Reason must be between 10 and 500 characters')
    .custom((value) => {
      return !/<[^>]*>/g.test(value);
    }).withMessage('Reason cannot contain HTML tags'),

  body('schedule')
    .optional()
    .isObject().withMessage('Schedule must be an object'),

  body('schedule.executeAt')
    .optional()
    .isISO8601().withMessage('Execute at must be valid ISO date')
    .custom((value) => new Date(value) > new Date())
    .withMessage('Scheduled time must be in the future'),

  body('schedule.timezone')
    .optional()
    .isIn(['UTC', 'America/New_York', 'America/Chicago', 'America/Los_Angeles', 'Europe/London', 'Asia/Tokyo'])
    .withMessage('Invalid timezone')
];

/**
 * Validate bulk organization operation
 */
const bulkOrganizationOperationSchema = [
  body('operation')
    .notEmpty().withMessage('Operation is required')
    .isIn([
      'suspend', 'unsuspend', 'archive', 'unarchive',
      'delete', 'updatePlan', 'updateBilling', 'updateLimits',
      'enableFeature', 'disableFeature', 'sendAnnouncement',
      'exportData', 'generateReport'
    ])
    .withMessage('Invalid organization bulk operation'),

  body('organizationIds')
    .isArray({ min: 1, max: 500 }).withMessage('Organization IDs must be an array with 1-500 items')
    .custom((value) => {
      return value.every(id => /^[0-9a-fA-F]{24}$/.test(id));
    }).withMessage('All organization IDs must be valid MongoDB ObjectIDs'),

  body('filters')
    .optional()
    .isObject().withMessage('Filters must be an object'),

  body('filters.status')
    .optional()
    .isIn(['active', 'suspended', 'trial', 'expired', 'archived'])
    .withMessage('Invalid status filter'),

  body('filters.plan')
    .optional()
    .isIn(['starter', 'professional', 'business', 'enterprise'])
    .withMessage('Invalid plan filter'),

  body('confirmation')
    .isObject().withMessage('Confirmation is required for bulk operations'),

  body('confirmation.acknowledged')
    .isBoolean().withMessage('Acknowledgment is required')
    .equals('true').withMessage('You must acknowledge the bulk operation'),

  body('confirmation.affectedCount')
    .isInt({ min: 1 }).withMessage('Affected count must be provided')
    .custom((value, { req }) => {
      const ids = req.body.organizationIds || [];
      return value === ids.length;
    }).withMessage('Affected count must match the number of selected items')
];

/**
 * Validate bulk billing operation
 */
const bulkBillingOperationSchema = [
  body('operation')
    .notEmpty().withMessage('Operation is required')
    .isIn([
      'generateInvoices', 'sendReminders', 'applyCredits',
      'applyDiscounts', 'suspendForNonPayment', 'reactivate',
      'updatePaymentMethod', 'exportBillingData'
    ])
    .withMessage('Invalid billing operation'),

  body('targetType')
    .notEmpty().withMessage('Target type is required')
    .isIn(['users', 'organizations', 'subscriptions'])
    .withMessage('Invalid target type'),

  body('targetIds')
    .isArray({ min: 1, max: 200 }).withMessage('Target IDs must be an array with 1-200 items'),

  body('billingDetails')
    .optional()
    .isObject().withMessage('Billing details must be an object'),

  body('billingDetails.amount')
    .optional()
    .isFloat({ min: 0, max: 999999.99 }).withMessage('Amount must be between 0 and 999,999.99')
    .toFloat(),

  body('billingDetails.currency')
    .optional()
    .isIn(['USD', 'EUR', 'GBP', 'CAD', 'AUD'])
    .withMessage('Invalid currency'),

  body('billingDetails.description')
    .optional()
    .trim()
    .isLength({ max: 200 }).withMessage('Description cannot exceed 200 characters'),

  body('auditTrail')
    .isObject().withMessage('Audit trail information is required'),

  body('auditTrail.reason')
    .notEmpty().withMessage('Reason is required for billing operations')
    .isLength({ min: 20, max: 1000 }).withMessage('Reason must be between 20 and 1000 characters')
];

/**
 * Validate bulk system operation
 */
const bulkSystemOperationSchema = [
  body('operation')
    .notEmpty().withMessage('Operation is required')
    .isIn([
      'clearCache', 'reindexSearch', 'optimizeDatabase',
      'cleanupLogs', 'archiveOldData', 'runMaintenance',
      'updateConfiguration', 'restartServices'
    ])
    .withMessage('Invalid system operation')
    .custom((value, { req }) => {
      // Check if user has permission for system operations
      const criticalOps = ['updateConfiguration', 'restartServices'];
      if (criticalOps.includes(value)) {
        return req.user?.permissions?.includes('system.critical.execute');
      }
      return true;
    }).withMessage('Insufficient permissions for critical system operation'),

  body('targets')
    .isArray().withMessage('Targets must be an array')
    .custom((value) => {
      const validTargets = ['cache', 'search', 'database', 'logs', 'files', 'config', 'services'];
      return value.every(target => validTargets.includes(target));
    }).withMessage('Invalid system targets'),

  body('parameters')
    .optional()
    .isObject().withMessage('Parameters must be an object'),

  body('maintenanceWindow')
    .optional()
    .isObject().withMessage('Maintenance window must be an object'),

  body('maintenanceWindow.start')
    .optional()
    .isISO8601().withMessage('Start time must be valid ISO date'),

  body('maintenanceWindow.duration')
    .optional()
    .isInt({ min: 1, max: 480 }).withMessage('Duration must be between 1 and 480 minutes')
];

/**
 * Validate bulk operation status check
 */
const bulkOperationStatusSchema = [
  param('operationId')
    .notEmpty().withMessage('Operation ID is required')
    .matches(patterns.operationId).withMessage('Invalid operation ID format'),

  query('includeDetails')
    .optional()
    .isBoolean().withMessage('Include details must be boolean')
    .toBoolean()
];

/**
 * Validate bulk operation cancellation
 */
const bulkOperationCancelSchema = [
  param('operationId')
    .notEmpty().withMessage('Operation ID is required')
    .matches(patterns.operationId).withMessage('Invalid operation ID format'),

  body('reason')
    .notEmpty().withMessage('Cancellation reason is required')
    .isLength({ min: 10, max: 500 }).withMessage('Reason must be between 10 and 500 characters')
];

/**
 * Validate bulk data export
 */
const bulkExportSchema = [
  body('exportType')
    .notEmpty().withMessage('Export type is required')
    .isIn(['users', 'organizations', 'billing', 'audit', 'analytics', 'full'])
    .withMessage('Invalid export type'),

  body('format')
    .notEmpty().withMessage('Export format is required')
    .isIn(['csv', 'xlsx', 'json', 'xml'])
    .withMessage('Invalid export format'),

  body('filters')
    .optional()
    .isObject().withMessage('Filters must be an object'),

  body('filters.dateRange')
    .optional()
    .isObject().withMessage('Date range must be an object'),

  body('filters.dateRange.start')
    .optional()
    .isISO8601().withMessage('Start date must be valid ISO date'),

  body('filters.dateRange.end')
    .optional()
    .isISO8601().withMessage('End date must be valid ISO date')
    .custom((value, { req }) => {
      if (req.body.filters?.dateRange?.start) {
        return new Date(value) > new Date(req.body.filters.dateRange.start);
      }
      return true;
    }).withMessage('End date must be after start date'),

  body('options')
    .optional()
    .isObject().withMessage('Options must be an object'),

  body('options.includeDeleted')
    .optional()
    .isBoolean().withMessage('Include deleted must be boolean'),

  body('options.compress')
    .optional()
    .isBoolean().withMessage('Compress option must be boolean'),

  body('options.encrypt')
    .optional()
    .isBoolean().withMessage('Encrypt option must be boolean'),

  body('options.splitFiles')
    .optional()
    .isBoolean().withMessage('Split files must be boolean'),

  body('options.maxRecordsPerFile')
    .optional()
    .isInt({ min: 100, max: 100000 }).withMessage('Max records must be between 100 and 100,000')
];

/**
 * Validate bulk import operation
 */
const bulkImportSchema = [
  body('importType')
    .notEmpty().withMessage('Import type is required')
    .isIn(['users', 'organizations', 'products', 'services'])
    .withMessage('Invalid import type'),

  body('source')
    .notEmpty().withMessage('Import source is required')
    .isIn(['file', 'api', 'database'])
    .withMessage('Invalid import source'),

  body('mappings')
    .isObject().withMessage('Field mappings are required')
    .custom((value) => {
      return Object.keys(value).length > 0;
    }).withMessage('At least one field mapping is required'),

  body('options')
    .optional()
    .isObject().withMessage('Options must be an object'),

  body('options.validateOnly')
    .optional()
    .isBoolean().withMessage('Validate only must be boolean'),

  body('options.updateExisting')
    .optional()
    .isBoolean().withMessage('Update existing must be boolean'),

  body('options.skipErrors')
    .optional()
    .isBoolean().withMessage('Skip errors must be boolean'),

  body('options.batchSize')
    .optional()
    .isInt({ min: 10, max: 1000 }).withMessage('Batch size must be between 10 and 1000')
];

module.exports = {
  bulkUserOperationSchema,
  bulkOrganizationOperationSchema,
  bulkBillingOperationSchema,
  bulkSystemOperationSchema,
  bulkOperationStatusSchema,
  bulkOperationCancelSchema,
  bulkExportSchema,
  bulkImportSchema,
  patterns
};