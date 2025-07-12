/**
 * @file Export Validation
 * @description Validation schemas for data export operations in admin panel
 * @version 1.0.0
 */

const { body, param, query } = require('express-validator');
const AdminValidators = require('../utils/admin-validators');
const config = require('../../../config/config');

/**
 * Export format configurations
 */
const exportFormats = {
  csv: {
    maxRows: 100000,
    maxColumns: 100,
    supportedDelimiters: [',', ';', '\t', '|'],
    encoding: ['utf-8', 'utf-16', 'ascii']
  },
  xlsx: {
    maxRows: 1048576, // Excel max
    maxColumns: 16384,
    maxSheets: 10,
    maxFileSize: 100 * 1024 * 1024 // 100MB
  },
  json: {
    maxRecords: 50000,
    maxDepth: 10,
    prettyPrint: true,
    maxFileSize: 50 * 1024 * 1024 // 50MB
  },
  xml: {
    maxRecords: 25000,
    maxDepth: 8,
    prettyPrint: true,
    maxFileSize: 50 * 1024 * 1024 // 50MB
  },
  pdf: {
    maxPages: 1000,
    maxRecords: 10000,
    supportedOrientations: ['portrait', 'landscape'],
    supportedPageSizes: ['A4', 'Letter', 'Legal']
  }
};

/**
 * Validate export request
 */
const exportRequestSchema = [
  body('exportType')
    .notEmpty().withMessage('Export type is required')
    .isIn([
      'users', 'organizations', 'billing', 'audit_logs',
      'analytics', 'reports', 'system_logs', 'configurations',
      'permissions', 'sessions', 'api_usage', 'custom'
    ])
    .withMessage('Invalid export type'),

  body('format')
    .notEmpty().withMessage('Export format is required')
    .isIn(['csv', 'xlsx', 'json', 'xml', 'pdf'])
    .withMessage('Invalid export format')
    .custom((format, { req }) => {
      // Check if format is supported for the export type
      const unsupportedCombos = {
        system_logs: ['pdf'],
        configurations: ['pdf'],
        api_usage: ['xml', 'pdf']
      };
      
      const exportType = req.body.exportType;
      if (unsupportedCombos[exportType]?.includes(format)) {
        return false;
      }
      return true;
    })
    .withMessage('This format is not supported for the selected export type'),

  body('fields')
    .optional()
    .isArray().withMessage('Fields must be an array')
    .custom((fields, { req }) => {
      const format = req.body.format;
      const formatConfig = exportFormats[format];
      
      if (format === 'csv' || format === 'xlsx') {
        return fields.length <= formatConfig.maxColumns;
      }
      return true;
    })
    .withMessage('Too many fields selected for export format'),

  body('fields.*')
    .matches(/^[a-zA-Z0-9_\.]+$/)
    .withMessage('Field names can only contain letters, numbers, underscores, and dots'),

  body('filters')
    .optional()
    .isObject().withMessage('Filters must be an object'),

  body('filters.dateRange')
    .optional()
    .isObject().withMessage('Date range must be an object'),

  body('filters.dateRange.start')
    .optional()
    .isISO8601().withMessage('Start date must be valid ISO date')
    .custom((value) => {
      const date = new Date(value);
      const oneYearAgo = new Date();
      oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 5);
      return date >= oneYearAgo;
    })
    .withMessage('Start date cannot be more than 5 years ago'),

  body('filters.dateRange.end')
    .optional()
    .isISO8601().withMessage('End date must be valid ISO date')
    .custom((value, { req }) => {
      if (req.body.filters?.dateRange?.start) {
        return new Date(value) >= new Date(req.body.filters.dateRange.start);
      }
      return true;
    })
    .withMessage('End date must be after start date'),

  body('filters.status')
    .optional()
    .custom((value) => {
      if (Array.isArray(value)) {
        return value.every(s => typeof s === 'string');
      }
      return typeof value === 'string';
    })
    .withMessage('Status filter must be string or array of strings'),

  body('options')
    .optional()
    .isObject().withMessage('Options must be an object')
];

/**
 * Validate CSV export options
 */
const csvExportOptionsSchema = [
  body('options.delimiter')
    .optional()
    .isIn(exportFormats.csv.supportedDelimiters)
    .withMessage('Invalid CSV delimiter'),

  body('options.includeHeaders')
    .optional()
    .isBoolean().withMessage('Include headers must be boolean')
    .toBoolean(),

  body('options.encoding')
    .optional()
    .isIn(exportFormats.csv.encoding)
    .withMessage('Invalid encoding'),

  body('options.escapeFormulas')
    .optional()
    .isBoolean().withMessage('Escape formulas must be boolean')
    .toBoolean(),

  body('options.dateFormat')
    .optional()
    .isIn(['ISO', 'US', 'EU', 'timestamp'])
    .withMessage('Invalid date format'),

  body('options.nullValue')
    .optional()
    .isString()
    .isLength({ max: 10 })
    .withMessage('Null value representation too long')
];

/**
 * Validate Excel export options
 */
const xlsxExportOptionsSchema = [
  body('options.sheetName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 31 })
    .withMessage('Sheet name must be between 1 and 31 characters')
    .matches(/^[^\\\/\?\*\[\]]+$/)
    .withMessage('Sheet name contains invalid characters'),

  body('options.includeFormulas')
    .optional()
    .isBoolean().withMessage('Include formulas must be boolean')
    .toBoolean(),

  body('options.autoFilter')
    .optional()
    .isBoolean().withMessage('Auto filter must be boolean')
    .toBoolean(),

  body('options.freezeHeaders')
    .optional()
    .isBoolean().withMessage('Freeze headers must be boolean')
    .toBoolean(),

  body('options.styling')
    .optional()
    .isObject().withMessage('Styling must be an object'),

  body('options.multipleSheets')
    .optional()
    .isBoolean().withMessage('Multiple sheets must be boolean')
    .toBoolean(),

  body('options.recordsPerSheet')
    .optional()
    .isInt({ min: 100, max: 1000000 })
    .withMessage('Records per sheet must be between 100 and 1,000,000')
];

/**
 * Validate JSON export options
 */
const jsonExportOptionsSchema = [
  body('options.prettyPrint')
    .optional()
    .isBoolean().withMessage('Pretty print must be boolean')
    .toBoolean(),

  body('options.includeMetadata')
    .optional()
    .isBoolean().withMessage('Include metadata must be boolean')
    .toBoolean(),

  body('options.flattenNested')
    .optional()
    .isBoolean().withMessage('Flatten nested must be boolean')
    .toBoolean(),

  body('options.excludeNull')
    .optional()
    .isBoolean().withMessage('Exclude null must be boolean')
    .toBoolean(),

  body('options.maxDepth')
    .optional()
    .isInt({ min: 1, max: exportFormats.json.maxDepth })
    .withMessage(`Max depth must be between 1 and ${exportFormats.json.maxDepth}`)
];

/**
 * Validate PDF export options
 */
const pdfExportOptionsSchema = [
  body('options.orientation')
    .optional()
    .isIn(exportFormats.pdf.supportedOrientations)
    .withMessage('Invalid PDF orientation'),

  body('options.pageSize')
    .optional()
    .isIn(exportFormats.pdf.supportedPageSizes)
    .withMessage('Invalid page size'),

  body('options.includeHeader')
    .optional()
    .isBoolean().withMessage('Include header must be boolean')
    .toBoolean(),

  body('options.includeFooter')
    .optional()
    .isBoolean().withMessage('Include footer must be boolean')
    .toBoolean(),

  body('options.includePageNumbers')
    .optional()
    .isBoolean().withMessage('Include page numbers must be boolean')
    .toBoolean(),

  body('options.includeTimestamp')
    .optional()
    .isBoolean().withMessage('Include timestamp must be boolean')
    .toBoolean(),

  body('options.watermark')
    .optional()
    .isString()
    .isLength({ max: 50 })
    .withMessage('Watermark text too long')
];

/**
 * Validate scheduled export
 */
const scheduledExportSchema = [
  ...exportRequestSchema,

  body('schedule')
    .notEmpty().withMessage('Schedule is required')
    .isObject().withMessage('Schedule must be an object'),

  body('schedule.frequency')
    .notEmpty().withMessage('Schedule frequency is required')
    .isIn(['daily', 'weekly', 'monthly', 'quarterly', 'yearly'])
    .withMessage('Invalid schedule frequency'),

  body('schedule.time')
    .notEmpty().withMessage('Schedule time is required')
    .matches(/^([01]\d|2[0-3]):([0-5]\d)$/)
    .withMessage('Time must be in HH:MM format'),

  body('schedule.timezone')
    .notEmpty().withMessage('Timezone is required')
    .isIn([
      'UTC', 'America/New_York', 'America/Chicago',
      'America/Denver', 'America/Los_Angeles',
      'Europe/London', 'Europe/Paris', 'Asia/Tokyo',
      'Asia/Shanghai', 'Australia/Sydney'
    ])
    .withMessage('Invalid timezone'),

  body('schedule.dayOfWeek')
    .optional()
    .isInt({ min: 0, max: 6 })
    .withMessage('Day of week must be 0-6 (Sunday-Saturday)')
    .custom((value, { req }) => {
      return req.body.schedule?.frequency === 'weekly' ? value !== undefined : true;
    })
    .withMessage('Day of week is required for weekly exports'),

  body('schedule.dayOfMonth')
    .optional()
    .isInt({ min: 1, max: 31 })
    .withMessage('Day of month must be 1-31')
    .custom((value, { req }) => {
      const frequency = req.body.schedule?.frequency;
      return ['monthly', 'quarterly', 'yearly'].includes(frequency) ? value !== undefined : true;
    })
    .withMessage('Day of month is required for monthly/quarterly/yearly exports'),

  body('delivery')
    .notEmpty().withMessage('Delivery settings required')
    .isObject().withMessage('Delivery must be an object'),

  body('delivery.method')
    .notEmpty().withMessage('Delivery method is required')
    .isIn(['email', 'sftp', 's3', 'webhook', 'download'])
    .withMessage('Invalid delivery method'),

  body('delivery.recipients')
    .optional()
    .isArray().withMessage('Recipients must be an array')
    .custom((recipients, { req }) => {
      if (req.body.delivery?.method === 'email') {
        return recipients.length > 0 && recipients.every(r => 
          AdminValidators.validateEmail(r).valid
        );
      }
      return true;
    })
    .withMessage('Valid email recipients required for email delivery'),

  body('delivery.destination')
    .optional()
    .custom((value, { req }) => {
      const method = req.body.delivery?.method;
      if (method === 's3') {
        return /^s3:\/\/[a-z0-9.-]+\/.*/.test(value);
      }
      if (method === 'sftp') {
        return /^sftp:\/\/.+/.test(value);
      }
      if (method === 'webhook') {
        return AdminValidators.validateURL(value).valid;
      }
      return true;
    })
    .withMessage('Invalid destination for delivery method')
];

/**
 * Validate export status check
 */
const exportStatusSchema = [
  param('exportId')
    .notEmpty().withMessage('Export ID is required')
    .matches(/^EXP-[0-9]{13}-[A-Z0-9]{8}$/)
    .withMessage('Invalid export ID format')
];

/**
 * Validate export download
 */
const exportDownloadSchema = [
  param('exportId')
    .notEmpty().withMessage('Export ID is required')
    .matches(/^EXP-[0-9]{13}-[A-Z0-9]{8}$/)
    .withMessage('Invalid export ID format'),

  query('token')
    .optional()
    .isJWT()
    .withMessage('Invalid download token')
];

/**
 * Validate export template
 */
const exportTemplateSchema = [
  body('name')
    .trim()
    .notEmpty().withMessage('Template name is required')
    .isLength({ min: 3, max: 100 })
    .withMessage('Template name must be between 3 and 100 characters')
    .matches(/^[a-zA-Z0-9\s_-]+$/)
    .withMessage('Template name contains invalid characters'),

  body('description')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Description cannot exceed 500 characters'),

  body('configuration')
    .notEmpty().withMessage('Template configuration is required')
    .isObject().withMessage('Configuration must be an object'),

  body('isPublic')
    .optional()
    .isBoolean().withMessage('Is public must be boolean')
    .toBoolean(),

  body('tags')
    .optional()
    .isArray({ max: 10 })
    .withMessage('Maximum 10 tags allowed'),

  body('tags.*')
    .trim()
    .isLength({ min: 2, max: 30 })
    .withMessage('Tags must be between 2 and 30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Tags can only contain letters, numbers, underscores, and hyphens')
];

/**
 * Combine export validation based on format
 */
const getExportValidation = (format) => {
  const baseValidation = [...exportRequestSchema];
  
  switch (format) {
    case 'csv':
      return [...baseValidation, ...csvExportOptionsSchema];
    case 'xlsx':
      return [...baseValidation, ...xlsxExportOptionsSchema];
    case 'json':
      return [...baseValidation, ...jsonExportOptionsSchema];
    case 'pdf':
      return [...baseValidation, ...pdfExportOptionsSchema];
    default:
      return baseValidation;
  }
};

module.exports = {
  exportRequestSchema,
  csvExportOptionsSchema,
  xlsxExportOptionsSchema,
  jsonExportOptionsSchema,
  pdfExportOptionsSchema,
  scheduledExportSchema,
  exportStatusSchema,
  exportDownloadSchema,
  exportTemplateSchema,
  getExportValidation,
  exportFormats
};