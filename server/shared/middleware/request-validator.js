// /server/shared/middleware/request-validator.js

/**
 * @file Request Validator Middleware
 * @description Request validation middleware using express-validator
 * @version 1.0.0
 */

const { body, param, query, header, cookie, validationResult } = require('express-validator');
const logger = require('../utils/logger');
const ResponseHelper = require('../utils/helpers/response-helper');
const joiSchemas = require('../utils/validation/joi-schemas');
const customValidators = require('../utils/validation/custom-validators');
const constants = require('../config/constants');

/**
 * Request Validator Class
 */
class RequestValidator {
  constructor() {
    this.schemas = joiSchemas;
    this.customValidators = customValidators;
  }
  
  /**
   * Validate request using Joi schema
   */
  validateSchema(schema, source = 'body') {
    return async (req, res, next) => {
      try {
        const data = req[source];
        const { error, value } = schema.validate(data, {
          abortEarly: false,
          stripUnknown: true,
          convert: true
        });
        
        if (error) {
          const errors = error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            type: detail.type,
            value: detail.context.value
          }));
          
          return ResponseHelper.validationError(res, errors);
        }
        
        // Replace request data with validated and sanitized data
        req[source] = value;
        next();
      } catch (err) {
        logger.error('Schema validation error:', err);
        return ResponseHelper.error(res, 'Validation failed', 400);
      }
    };
  }
  
  /**
   * Handle validation results
   */
  handleValidationResult() {
    return (req, res, next) => {
      const errors = validationResult(req);
      
      if (!errors.isEmpty()) {
        const formattedErrors = errors.array().map(error => ({
          field: error.param,
          message: error.msg,
          value: error.value,
          location: error.location
        }));
        
        return ResponseHelper.validationError(res, formattedErrors);
      }
      
      next();
    };
  }
  
  /**
   * Common validators
   */
  common = {
    // ID validators
    mongoId: (field = 'id', location = 'param') => {
      const validator = location === 'param' ? param : 
                       location === 'query' ? query : body;
      
      return validator(field)
        .isMongoId()
        .withMessage('Invalid ID format');
    },
    
    uuid: (field = 'id', location = 'param') => {
      const validator = location === 'param' ? param : 
                       location === 'query' ? query : body;
      
      return validator(field)
        .isUUID()
        .withMessage('Invalid UUID format');
    },
    
    // Pagination validators
    pagination: () => [
      query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer')
        .toInt(),
      
      query('limit')
        .optional()
        .isInt({ min: 1, max: constants.API.PAGINATION.MAX_LIMIT })
        .withMessage(`Limit must be between 1 and ${constants.API.PAGINATION.MAX_LIMIT}`)
        .toInt(),
      
      query('sortBy')
        .optional()
        .isIn(['createdAt', 'updatedAt', 'name', 'email', 'status'])
        .withMessage('Invalid sort field'),
      
      query('sortOrder')
        .optional()
        .isIn(['asc', 'desc', '1', '-1'])
        .withMessage('Sort order must be asc or desc')
    ],
    
    // Date range validators
    dateRange: () => [
      query('startDate')
        .optional()
        .isISO8601()
        .withMessage('Invalid start date format')
        .toDate(),
      
      query('endDate')
        .optional()
        .isISO8601()
        .withMessage('Invalid end date format')
        .toDate()
        .custom((value, { req }) => {
          if (req.query.startDate && value < req.query.startDate) {
            throw new Error('End date must be after start date');
          }
          return true;
        })
    ],
    
    // Search validators
    search: () => [
      query('q')
        .optional()
        .trim()
        .isLength({ min: 1, max: 100 })
        .withMessage('Search query must be between 1 and 100 characters')
        .escape()
    ]
  };
  
  /**
   * User validation rules
   */
  user = {
    register: () => [
      body('email')
        .trim()
        .isEmail()
        .withMessage('Invalid email address')
        .normalizeEmail()
        .custom(async (email) => {
          const result = customValidators.validateEmail(email);
          if (!result.valid) {
            throw new Error(result.message);
          }
          return true;
        }),
      
      body('password')
        .isLength({ min: constants.AUTH.PASSWORD.MIN_LENGTH })
        .withMessage(`Password must be at least ${constants.AUTH.PASSWORD.MIN_LENGTH} characters`)
        .custom((password) => {
          const result = customValidators.validatePasswordStrength(password);
          if (!result.valid) {
            throw new Error(result.suggestions.join('. '));
          }
          return true;
        }),
      
      body('confirmPassword')
        .custom((value, { req }) => value === req.body.password)
        .withMessage('Passwords do not match'),
      
      body('firstName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('First name must be between 2 and 50 characters')
        .matches(/^[a-zA-Z\s'-]+$/)
        .withMessage('First name contains invalid characters'),
      
      body('lastName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Last name must be between 2 and 50 characters')
        .matches(/^[a-zA-Z\s'-]+$/)
        .withMessage('Last name contains invalid characters'),
      
      body('acceptTerms')
        .isBoolean()
        .equals('true')
        .withMessage('You must accept the terms and conditions')
    ],
    
    login: () => [
      body('email')
        .trim()
        .isEmail()
        .withMessage('Invalid email address')
        .normalizeEmail(),
      
      body('password')
        .notEmpty()
        .withMessage('Password is required'),
      
      body('rememberMe')
        .optional()
        .isBoolean()
        .toBoolean(),
      
      body('twoFactorCode')
        .optional()
        .isLength({ min: 6, max: 6 })
        .withMessage('Two-factor code must be 6 digits')
        .isNumeric()
        .withMessage('Two-factor code must contain only numbers')
    ],
    
    updateProfile: () => [
      body('firstName')
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('First name must be between 2 and 50 characters'),
      
      body('lastName')
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Last name must be between 2 and 50 characters'),
      
      body('phone')
        .optional()
        .custom((phone) => {
          const result = customValidators.validatePhoneNumber(phone);
          if (!result.valid) {
            throw new Error(result.message);
          }
          return true;
        }),
      
      body('bio')
        .optional()
        .trim()
        .isLength({ max: 500 })
        .withMessage('Bio must not exceed 500 characters'),
      
      body('timezone')
        .optional()
        .isIn(Intl.supportedValuesOf('timeZone'))
        .withMessage('Invalid timezone')
    ]
  };
  
  /**
   * Organization validation rules
   */
  organization = {
    create: () => [
      body('name')
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Organization name must be between 2 and 100 characters'),
      
      body('slug')
        .trim()
        .custom((slug) => {
          const result = customValidators.validateSlug(slug);
          if (!result.valid) {
            throw new Error(result.message);
          }
          return true;
        }),
      
      body('type')
        .isIn(Object.values(constants.ORGANIZATION.TYPES))
        .withMessage('Invalid organization type'),
      
      body('email')
        .optional()
        .trim()
        .isEmail()
        .withMessage('Invalid email address')
        .normalizeEmail(),
      
      body('website')
        .optional()
        .trim()
        .custom((url) => {
          const result = customValidators.validateUrl(url);
          if (!result.valid) {
            throw new Error(result.message);
          }
          return true;
        }),
      
      body('size')
        .optional()
        .isIn(Object.values(constants.ORGANIZATION.SIZE_RANGES))
        .withMessage('Invalid organization size')
    ],
    
    inviteMember: () => [
      body('email')
        .trim()
        .isEmail()
        .withMessage('Invalid email address')
        .normalizeEmail(),
      
      body('role')
        .isIn(Object.values(constants.ROLES.ORGANIZATION).map(r => r.name))
        .withMessage('Invalid role'),
      
      body('message')
        .optional()
        .trim()
        .isLength({ max: 500 })
        .withMessage('Message must not exceed 500 characters'),
      
      body('expiresIn')
        .optional()
        .isInt({ min: 1, max: 30 })
        .withMessage('Expiration must be between 1 and 30 days')
        .toInt()
    ]
  };
  
  /**
   * File upload validation rules
   */
  file = {
    upload: (options = {}) => {
      return (req, res, next) => {
        const {
          maxSize = constants.FILE_UPLOAD.MAX_SIZE.DEFAULT,
          allowedTypes = [],
          required = true
        } = options;
        
        // Check if file exists
        if (required && !req.file && !req.files) {
          return ResponseHelper.validationError(res, [{
            field: 'file',
            message: 'File is required'
          }]);
        }
        
        // Validate file(s)
        const files = req.files || (req.file ? [req.file] : []);
        const errors = [];
        
        files.forEach((file, index) => {
          // Validate file size
          if (file.size > maxSize) {
            errors.push({
              field: `file${files.length > 1 ? `[${index}]` : ''}`,
              message: `File size exceeds maximum allowed size of ${maxSize / 1048576}MB`
            });
          }
          
          // Validate file type
          if (allowedTypes.length > 0 && !allowedTypes.includes(file.mimetype)) {
            errors.push({
              field: `file${files.length > 1 ? `[${index}]` : ''}`,
              message: `File type ${file.mimetype} is not allowed`
            });
          }
        });
        
        if (errors.length > 0) {
          return ResponseHelper.validationError(res, errors);
        }
        
        next();
      };
    }
  };
  
  /**
   * API validation rules
   */
  api = {
    apiKey: () => [
      header('x-api-key')
        .exists()
        .withMessage('API key is required')
        .isLength({ min: 32 })
        .withMessage('Invalid API key format')
    ],
    
    version: () => [
      header('x-api-version')
        .optional()
        .isIn(['v1', 'v2', 'v3'])
        .withMessage('Invalid API version')
    ],
    
    webhook: () => [
      header('x-webhook-signature')
        .exists()
        .withMessage('Webhook signature is required'),
      
      header('x-webhook-timestamp')
        .exists()
        .withMessage('Webhook timestamp is required')
        .isInt()
        .withMessage('Invalid webhook timestamp')
        .toInt()
        .custom((timestamp) => {
          const now = Date.now();
          const diff = Math.abs(now - timestamp);
          if (diff > 300000) { // 5 minutes
            throw new Error('Webhook timestamp is too old');
          }
          return true;
        })
    ]
  };
  
  /**
   * Create custom validator
   */
  custom(validationFn, errorMessage) {
    return body().custom(async (value, { req }) => {
      const result = await validationFn(value, req);
      if (!result) {
        throw new Error(errorMessage);
      }
      return true;
    });
  }
  
  /**
   * Combine multiple validation chains
   */
  combine(...validationChains) {
    return [
      ...validationChains.flat(),
      this.handleValidationResult()
    ];
  }
  
  /**
   * Create validation middleware from Joi schema
   */
  fromJoiSchema(schemaName, source = 'body') {
    const schemaPath = schemaName.split('.');
    let schema = this.schemas;
    
    for (const path of schemaPath) {
      schema = schema[path];
      if (!schema) {
        throw new Error(`Schema ${schemaName} not found`);
      }
    }
    
    return this.validateSchema(schema, source);
  }
  
  /**
   * Sanitization middleware
   */
  sanitize = {
    body: () => [
      body('*').trim().escape()
    ],
    
    html: (fields = []) => {
      return fields.map(field => 
        body(field)
          .customSanitizer((value) => {
            // Allow certain HTML tags
            return value; // Implement HTML sanitization
          })
      );
    },
    
    query: () => [
      query('*').trim().escape()
    ]
  };
}

// Create singleton instance
const validator = new RequestValidator();

module.exports = {
  // Validation functions
  validate: validator.validateSchema.bind(validator),
  handleResult: validator.handleValidationResult.bind(validator),
  
  // Common validators
  common: validator.common,
  
  // Domain validators
  user: validator.user,
  organization: validator.organization,
  file: validator.file,
  api: validator.api,
  
  // Utilities
  custom: validator.custom,
  combine: validator.combine.bind(validator),
  fromJoi: validator.fromJoiSchema.bind(validator),
  sanitize: validator.sanitize,
  
  // Express validator exports
  body,
  param,
  query,
  header,
  cookie,
  validationResult,
  
  // Class export
  RequestValidator
};