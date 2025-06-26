// server/core-business/reports/validation/reports-validation.js
/**
 * @file Reports Validation Schemas
 * @description Validation schemas for reports API endpoints
 * @version 3.0.0
 */

const { body, param, query } = require('express-validator');

/**
 * Common validation rules
 */
const reportIdValidation = param('reportId')
  .isMongoId()
  .withMessage('Invalid report ID format');

const executionIdValidation = param('executionId')
  .notEmpty()
  .withMessage('Execution ID is required')
  .matches(/^EXE-[\d\w-]+$/)
  .withMessage('Invalid execution ID format');

/**
 * Create report validation
 */
const createReportSchema = [
  body('name')
    .trim()
    .notEmpty().withMessage('Report name is required')
    .isLength({ min: 3, max: 100 }).withMessage('Name must be between 3 and 100 characters'),
  
  body('type')
    .isIn(['dashboard', 'detailed', 'summary', 'analytical', 'operational', 'strategic', 'compliance', 'custom'])
    .withMessage('Invalid report type'),
  
  body('category')
    .isIn(['financial', 'project', 'client', 'service', 'team', 'performance', 'compliance', 'executive', 'operational', 'custom'])
    .withMessage('Invalid report category'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters'),
  
  body('dataSources')
    .optional()
    .isArray().withMessage('Data sources must be an array'),
  
  body('dataSources.*.type')
    .isIn(['mongodb', 'api', 'file', 'external_db', 'computed', 'joined'])
    .withMessage('Invalid data source type'),
  
  body('parameters')
    .optional()
    .isArray().withMessage('Parameters must be an array'),
  
  body('visualizations')
    .optional()
    .isArray().withMessage('Visualizations must be an array'),
  
  body('query.type')
    .optional()
    .isIn(['aggregation', 'raw', 'custom', 'stored'])
    .withMessage('Invalid query type'),
  
  body('access.level')
    .optional()
    .isIn(['public', 'organization', 'department', 'team', 'role', 'user', 'custom'])
    .withMessage('Invalid access level')
];

/**
 * Update report validation
 */
const updateReportSchema = [
  reportIdValidation,
  
  body('name')
    .optional()
    .trim()
    .isLength({ min: 3, max: 100 }).withMessage('Name must be between 3 and 100 characters'),
  
  body('type')
    .optional()
    .isIn(['dashboard', 'detailed', 'summary', 'analytical', 'operational', 'strategic', 'compliance', 'custom'])
    .withMessage('Invalid report type'),
  
  body('category')
    .optional()
    .isIn(['financial', 'project', 'client', 'service', 'team', 'performance', 'compliance', 'executive', 'operational', 'custom'])
    .withMessage('Invalid report category'),
  
  body('status')
    .optional()
    .isIn(['draft', 'active', 'inactive', 'archived', 'deprecated'])
    .withMessage('Invalid status'),
  
  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Description cannot exceed 500 characters')
];

/**
 * List reports validation
 */
const listReportsSchema = [
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer')
    .toInt(),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
    .toInt(),
  
  query('sort')
    .optional()
    .matches(/^-?(name|createdAt|updatedAt|type|category|status)$/)
    .withMessage('Invalid sort field'),
  
  query('type')
    .optional()
    .isIn(['dashboard', 'detailed', 'summary', 'analytical', 'operational', 'strategic', 'compliance', 'custom']),
  
  query('category')
    .optional()
    .isIn(['financial', 'project', 'client', 'service', 'team', 'performance', 'compliance', 'executive', 'operational', 'custom']),
  
  query('status')
    .optional()
    .isIn(['draft', 'active', 'inactive', 'archived', 'deprecated']),
  
  query('createdBy')
    .optional()
    .isMongoId().withMessage('Invalid user ID'),
  
  query('tags')
    .optional()
    .isString().withMessage('Tags must be a comma-separated string'),
  
  query('createdAfter')
    .optional()
    .isISO8601().withMessage('Invalid date format'),
  
  query('createdBefore')
    .optional()
    .isISO8601().withMessage('Invalid date format'),
  
  query('search')
    .optional()
    .trim()
    .isLength({ max: 100 }).withMessage('Search query too long')
];

/**
 * Execute report validation
 */
const executeReportSchema = [
  reportIdValidation,
  
  body('parameters')
    .optional()
    .isObject().withMessage('Parameters must be an object'),
  
  body('format')
    .optional()
    .isIn(['pdf', 'excel', 'csv', 'json', 'xml', 'html'])
    .withMessage('Invalid export format'),
  
  body('synchronous')
    .optional()
    .isBoolean().withMessage('Synchronous must be a boolean')
];

/**
 * Export report validation
 */
const exportReportSchema = [
  reportIdValidation,
  
  body('format')
    .notEmpty().withMessage('Export format is required')
    .isIn(['pdf', 'excel', 'csv', 'json', 'xml', 'html', 'powerpoint', 'word'])
    .withMessage('Invalid export format'),
  
  body('executeFirst')
    .optional()
    .isBoolean().withMessage('ExecuteFirst must be a boolean'),
  
  body('parameters')
    .optional()
    .isObject().withMessage('Parameters must be an object'),
  
  body('options')
    .optional()
    .isObject().withMessage('Options must be an object'),
  
  body('options.includeVisualizations')
    .optional()
    .isBoolean(),
  
  body('options.includeRawData')
    .optional()
    .isBoolean(),
  
  body('options.maxRows')
    .optional()
    .isInt({ min: 1, max: 1000000 }).withMessage('MaxRows must be between 1 and 1,000,000')
];

/**
 * Share report validation
 */
const shareReportSchema = [
  reportIdValidation,
  
  body('recipients')
    .isArray({ min: 1 }).withMessage('At least one recipient is required'),
  
  body('recipients.*.userId')
    .optional()
    .isMongoId().withMessage('Invalid user ID'),
  
  body('recipients.*.email')
    .optional()
    .isEmail().withMessage('Invalid email address'),
  
  body('permissions')
    .optional()
    .isIn(['view', 'run', 'edit', 'admin'])
    .withMessage('Invalid permission level'),
  
  body('message')
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage('Message cannot exceed 500 characters'),
  
  body('expiresAt')
    .optional()
    .isISO8601().withMessage('Invalid expiration date')
    .custom((value) => new Date(value) > new Date())
    .withMessage('Expiration date must be in the future'),
  
  body('makePublic')
    .optional()
    .isBoolean().withMessage('MakePublic must be a boolean')
];

/**
 * Clone report validation
 */
const cloneReportSchema = [
  reportIdValidation,
  
  body('name')
    .optional()
    .trim()
    .isLength({ min: 3, max: 100 }).withMessage('Name must be between 3 and 100 characters'),
  
  body('includeSchedule')
    .optional()
    .isBoolean().withMessage('IncludeSchedule must be a boolean'),
  
  body('includeSharing')
    .optional()
    .isBoolean().withMessage('IncludeSharing must be a boolean'),
  
  body('targetOrganization')
    .optional()
    .isMongoId().withMessage('Invalid organization ID')
];

/**
 * Schedule report validation
 */
const scheduleReportSchema = [
  reportIdValidation,
  
  body('isActive')
    .isBoolean().withMessage('IsActive must be a boolean'),
  
  body('frequency')
    .if(body('isActive').equals(true))
    .notEmpty().withMessage('Frequency is required when schedule is active')
    .isIn(['once', 'hourly', 'daily', 'weekly', 'monthly', 'quarterly', 'yearly', 'custom'])
    .withMessage('Invalid frequency'),
  
  body('startDate')
    .if(body('isActive').equals(true))
    .notEmpty().withMessage('Start date is required when schedule is active')
    .isISO8601().withMessage('Invalid start date'),
  
  body('endDate')
    .optional()
    .isISO8601().withMessage('Invalid end date')
    .custom((value, { req }) => !value || new Date(value) > new Date(req.body.startDate))
    .withMessage('End date must be after start date'),
  
  body('timezone')
    .optional()
    .isString().withMessage('Timezone must be a string'),
  
  body('recipients.emails')
    .optional()
    .isArray().withMessage('Emails must be an array'),
  
  body('recipients.emails.*.email')
    .optional()
    .isEmail().withMessage('Invalid email address'),
  
  body('delivery.method')
    .optional()
    .isIn(['email', 'webhook', 'storage', 'multiple'])
    .withMessage('Invalid delivery method')
];

/**
 * Test query validation
 */
const testQuerySchema = [
  body('dataSource')
    .notEmpty().withMessage('Data source is required')
    .isObject().withMessage('Data source must be an object'),
  
  body('dataSource.type')
    .notEmpty().withMessage('Data source type is required')
    .isIn(['mongodb', 'api', 'file', 'external_db', 'computed', 'joined'])
    .withMessage('Invalid data source type'),
  
  body('query')
    .notEmpty().withMessage('Query is required'),
  
  body('parameters')
    .optional()
    .isObject().withMessage('Parameters must be an object'),
  
  body('limit')
    .optional()
    .isInt({ min: 1, max: 1000 }).withMessage('Limit must be between 1 and 1000')
    .toInt()
];

/**
 * Bulk operation validation
 */
const bulkOperationSchema = [
  body('operation')
    .notEmpty().withMessage('Operation is required')
    .isIn(['activate', 'deactivate', 'archive', 'delete', 'tag', 'untag', 'share', 'updateAccess'])
    .withMessage('Invalid bulk operation'),
  
  body('reportIds')
    .isArray({ min: 1, max: 100 }).withMessage('Report IDs must be an array with 1-100 items'),
  
  body('reportIds.*')
    .isMongoId().withMessage('Invalid report ID'),
  
  body('data')
    .optional()
    .isObject().withMessage('Operation data must be an object')
];

/**
 * Statistics query validation
 */
const statisticsQuerySchema = [
  query('startDate')
    .optional()
    .isISO8601().withMessage('Invalid start date'),
  
  query('endDate')
    .optional()
    .isISO8601().withMessage('Invalid end date'),
  
  query('groupBy')
    .optional()
    .isIn(['category', 'type', 'user', 'department', 'daily', 'weekly', 'monthly'])
    .withMessage('Invalid groupBy option')
];

/**
 * Activity log validation
 */
const activityLogSchema = [
  reportIdValidation,
  
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer')
    .toInt(),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
    .toInt(),
  
  query('startDate')
    .optional()
    .isISO8601().withMessage('Invalid start date'),
  
  query('endDate')
    .optional()
    .isISO8601().withMessage('Invalid end date'),
  
  query('action')
    .optional()
    .isString().withMessage('Action must be a string')
];

/**
 * Access log validation
 */
const accessLogSchema = [
  reportIdValidation,
  
  query('page')
    .optional()
    .isInt({ min: 1 }).withMessage('Page must be a positive integer')
    .toInt(),
  
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
    .toInt(),
  
  query('userId')
    .optional()
    .isMongoId().withMessage('Invalid user ID'),
  
  query('action')
    .optional()
    .isIn(['view', 'run', 'export', 'share', 'edit'])
    .withMessage('Invalid action'),
  
  query('startDate')
    .optional()
    .isISO8601().withMessage('Invalid start date'),
  
  query('endDate')
    .optional()
    .isISO8601().withMessage('Invalid end date')
];

/**
 * Update access validation
 */
const updateAccessSchema = [
  reportIdValidation,
  
  body('level')
    .optional()
    .isIn(['public', 'organization', 'department', 'team', 'role', 'user', 'custom'])
    .withMessage('Invalid access level'),
  
  body('roles')
    .optional()
    .isArray().withMessage('Roles must be an array'),
  
  body('roles.*.role')
    .optional()
    .isString().withMessage('Role must be a string'),
  
  body('roles.*.permissions')
    .optional()
    .isObject().withMessage('Permissions must be an object'),
  
  body('users')
    .optional()
    .isArray().withMessage('Users must be an array'),
  
  body('users.*.user')
    .optional()
    .isMongoId().withMessage('Invalid user ID'),
  
  body('users.*.permissions')
    .optional()
    .isObject().withMessage('Permissions must be an object'),
  
  body('publicAccess.enabled')
    .optional()
    .isBoolean().withMessage('Public access enabled must be a boolean')
];

/**
 * Template validation
 */
const templateSchema = [
  body('templateId')
    .notEmpty().withMessage('Template ID is required')
    .isMongoId().withMessage('Invalid template ID'),
  
  body('name')
    .trim()
    .notEmpty().withMessage('Report name is required')
    .isLength({ min: 3, max: 100 }).withMessage('Name must be between 3 and 100 characters'),
  
  body('customizations')
    .optional()
    .isObject().withMessage('Customizations must be an object')
];

/**
 * Simple validations
 */
const reportIdSchema = [reportIdValidation];
const executionIdSchema = [reportIdValidation, executionIdValidation];

module.exports = {
  createReportSchema,
  updateReportSchema,
  listReportsSchema,
  executeReportSchema,
  exportReportSchema,
  shareReportSchema,
  cloneReportSchema,
  scheduleReportSchema,
  testQuerySchema,
  bulkOperationSchema,
  reportIdSchema,
  executionIdSchema,
  templateSchema,
  statisticsQuerySchema,
  activityLogSchema,
  accessLogSchema,
  updateAccessSchema
};