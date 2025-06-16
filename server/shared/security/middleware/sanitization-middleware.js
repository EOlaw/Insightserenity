// /server/shared/security/middleware/sanitization-middleware.js

/**
 * @file Input Sanitization Middleware
 * @description Comprehensive input sanitization for security
 * @version 1.0.0
 */

const validator = require('validator');
const xss = require('xss');
const DOMPurify = require('isomorphic-dompurify');
const logger = require('../../utils/logger');
const { ValidationError } = require('../../utils/app-error');

/**
 * Sanitization configuration
 */
const sanitizationConfig = {
  // XSS protection options
  xss: {
    whiteList: {
      a: ['href', 'title', 'target', 'rel'],
      img: ['src', 'alt', 'title', 'width', 'height'],
      b: [],
      i: [],
      u: [],
      strong: [],
      em: [],
      p: [],
      br: [],
      ul: [],
      ol: [],
      li: [],
      blockquote: [],
      code: ['class'],
      pre: ['class'],
      h1: [], h2: [], h3: [], h4: [], h5: [], h6: []
    },
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style']
  },
  
  // SQL injection patterns
  sqlPatterns: [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)/gi,
    /(--|\/\*|\*\/|;|'|"|`|\\)/g,
    /(\bOR\b\s*\d*\s*=\s*\d*|\bAND\b\s*\d*\s*=\s*\d*)/gi
  ],
  
  // NoSQL injection patterns
  noSqlPatterns: [
    /(\$where|\$regex|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin)/g,
    /({|}|\[|\])/g
  ],
  
  // Path traversal patterns
  pathTraversalPatterns: [
    /\.\.\//g,
    /\.\.%2[fF]/g,
    /%2[eE]\./g,
    /\.\./g
  ],
  
  // Command injection patterns
  commandPatterns: [
    /([;&|`$])/g,
    /(\b(cat|ls|rm|mv|cp|chmod|chown|echo|eval)\b)/gi
  ]
};

/**
 * Sanitize string input
 */
const sanitizeString = (input, options = {}) => {
  if (typeof input !== 'string') return input;
  
  let sanitized = input;
  
  // Trim whitespace
  if (options.trim !== false) {
    sanitized = sanitized.trim();
  }
  
  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, '');
  
  // Escape HTML if not explicitly allowed
  if (options.allowHtml !== true) {
    sanitized = validator.escape(sanitized);
  } else {
    // Use DOMPurify for HTML content
    sanitized = DOMPurify.sanitize(sanitized, {
      ALLOWED_TAGS: options.allowedTags || Object.keys(sanitizationConfig.xss.whiteList),
      ALLOWED_ATTR: options.allowedAttributes || []
    });
  }
  
  // Additional XSS protection
  if (options.xss !== false) {
    sanitized = xss(sanitized, sanitizationConfig.xss);
  }
  
  // SQL injection protection
  if (options.sql !== false) {
    sanitizationConfig.sqlPatterns.forEach(pattern => {
      if (pattern.test(sanitized)) {
        logger.warn('SQL injection pattern detected', { 
          input: sanitized.substring(0, 100),
          pattern: pattern.toString()
        });
        sanitized = sanitized.replace(pattern, '');
      }
    });
  }
  
  // NoSQL injection protection
  if (options.noSql !== false) {
    sanitizationConfig.noSqlPatterns.forEach(pattern => {
      if (pattern.test(sanitized)) {
        logger.warn('NoSQL injection pattern detected', { 
          input: sanitized.substring(0, 100),
          pattern: pattern.toString()
        });
        sanitized = sanitized.replace(pattern, '');
      }
    });
  }
  
  // Path traversal protection
  if (options.path !== false) {
    sanitizationConfig.pathTraversalPatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });
  }
  
  // Command injection protection
  if (options.command !== false) {
    sanitizationConfig.commandPatterns.forEach(pattern => {
      sanitized = sanitized.replace(pattern, '');
    });
  }
  
  // Length validation
  if (options.maxLength && sanitized.length > options.maxLength) {
    sanitized = sanitized.substring(0, options.maxLength);
  }
  
  return sanitized;
};

/**
 * Sanitize object recursively
 */
const sanitizeObject = (obj, options = {}, depth = 0) => {
  if (depth > 10) {
    logger.warn('Maximum sanitization depth reached');
    return obj;
  }
  
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, options, depth + 1));
  }
  
  if (obj && typeof obj === 'object') {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(obj)) {
      // Sanitize key
      const sanitizedKey = sanitizeString(key, { ...options, allowHtml: false });
      
      // Skip if key contains suspicious patterns
      if (key !== sanitizedKey) {
        logger.warn('Suspicious object key detected', { 
          original: key,
          sanitized: sanitizedKey 
        });
        continue;
      }
      
      // Sanitize value
      if (typeof value === 'string') {
        sanitized[sanitizedKey] = sanitizeString(value, options);
      } else if (typeof value === 'object' && value !== null) {
        sanitized[sanitizedKey] = sanitizeObject(value, options, depth + 1);
      } else {
        sanitized[sanitizedKey] = value;
      }
    }
    
    return sanitized;
  }
  
  return obj;
};

/**
 * Main sanitization middleware
 */
const sanitize = (options = {}) => {
  return (req, res, next) => {
    try {
      // Sanitize body
      if (req.body && Object.keys(req.body).length > 0) {
        req.body = sanitizeObject(req.body, options);
      }
      
      // Sanitize query parameters
      if (req.query && Object.keys(req.query).length > 0) {
        req.query = sanitizeObject(req.query, { ...options, allowHtml: false });
      }
      
      // Sanitize URL parameters
      if (req.params && Object.keys(req.params).length > 0) {
        req.params = sanitizeObject(req.params, { ...options, allowHtml: false });
      }
      
      // Sanitize headers (selective)
      const headersToSanitize = ['referer', 'user-agent', 'x-forwarded-for'];
      headersToSanitize.forEach(header => {
        if (req.headers[header]) {
          req.headers[header] = sanitizeString(req.headers[header], { 
            ...options, 
            allowHtml: false,
            sql: false,
            noSql: false
          });
        }
      });
      
      next();
    } catch (error) {
      logger.error('Sanitization error', { error: error.message });
      next(new ValidationError('Invalid input data'));
    }
  };
};

/**
 * Strict sanitization for sensitive endpoints
 */
const strictSanitize = sanitize({
  allowHtml: false,
  xss: true,
  sql: true,
  noSql: true,
  path: true,
  command: true,
  trim: true
});

/**
 * Relaxed sanitization for content endpoints
 */
const contentSanitize = sanitize({
  allowHtml: true,
  allowedTags: ['p', 'b', 'i', 'u', 'strong', 'em', 'a', 'ul', 'ol', 'li', 'br'],
  allowedAttributes: ['href', 'target', 'rel'],
  xss: true,
  sql: true,
  noSql: true,
  trim: true
});

/**
 * File upload sanitization
 */
const fileSanitize = (options = {}) => {
  const allowedExtensions = options.allowedExtensions || [
    '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', 
    '.txt', '.csv', '.xls', '.xlsx'
  ];
  
  const maxFileSize = options.maxFileSize || 10 * 1024 * 1024; // 10MB default
  
  return (req, res, next) => {
    if (!req.files && !req.file) {
      return next();
    }
    
    const files = req.files || [req.file];
    const fileArray = Array.isArray(files) ? files : [files];
    
    for (const file of fileArray) {
      if (!file) continue;
      
      // Sanitize filename
      let filename = file.originalname || file.name || '';
      filename = sanitizeString(filename, { 
        allowHtml: false, 
        path: true,
        command: true 
      });
      
      // Remove special characters from filename
      filename = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
      
      // Validate extension
      const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase();
      if (!allowedExtensions.includes(ext)) {
        return next(new ValidationError(`File type ${ext} not allowed`));
      }
      
      // Validate file size
      if (file.size > maxFileSize) {
        return next(new ValidationError(`File size exceeds maximum allowed size`));
      }
      
      // Update filename
      file.sanitizedName = filename;
      
      // Validate MIME type
      if (options.validateMimeType && file.mimetype) {
        const allowedMimeTypes = {
          '.jpg': ['image/jpeg'],
          '.jpeg': ['image/jpeg'],
          '.png': ['image/png'],
          '.gif': ['image/gif'],
          '.pdf': ['application/pdf'],
          '.doc': ['application/msword'],
          '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
          '.txt': ['text/plain'],
          '.csv': ['text/csv', 'application/csv'],
          '.xls': ['application/vnd.ms-excel'],
          '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']
        };
        
        const expectedMimeTypes = allowedMimeTypes[ext] || [];
        if (!expectedMimeTypes.includes(file.mimetype)) {
          logger.warn('MIME type mismatch', {
            filename,
            extension: ext,
            mimetype: file.mimetype,
            expected: expectedMimeTypes
          });
        }
      }
    }
    
    next();
  };
};

/**
 * MongoDB query sanitization
 */
const mongoSanitize = (options = {}) => {
  return (req, res, next) => {
    const sanitizeMongoQuery = (obj) => {
      if (!obj || typeof obj !== 'object') return obj;
      
      for (const key in obj) {
        if (key.startsWith('$')) {
          delete obj[key];
          logger.warn('MongoDB operator in user input', { key });
        } else if (typeof obj[key] === 'object') {
          obj[key] = sanitizeMongoQuery(obj[key]);
        }
      }
      
      return obj;
    };
    
    if (req.body) req.body = sanitizeMongoQuery(req.body);
    if (req.query) req.query = sanitizeMongoQuery(req.query);
    if (req.params) req.params = sanitizeMongoQuery(req.params);
    
    next();
  };
};

module.exports = {
  // Main middleware
  sanitize,
  strictSanitize,
  contentSanitize,
  fileSanitize,
  mongoSanitize,
  
  // Utility functions
  sanitizeString,
  sanitizeObject,
  
  // Specialized sanitizers
  emailSanitize: (email) => sanitizeString(email, { 
    allowHtml: false,
    trim: true,
    maxLength: 254 
  }),
  
  urlSanitize: (url) => sanitizeString(url, {
    allowHtml: false,
    trim: true,
    xss: false,
    sql: false
  }),
  
  usernameSanitize: (username) => sanitizeString(username, {
    allowHtml: false,
    trim: true,
    maxLength: 30
  }).replace(/[^a-zA-Z0-9._-]/g, '')
};