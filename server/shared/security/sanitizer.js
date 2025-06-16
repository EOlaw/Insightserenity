/**
 * @file Input Sanitizer
 * @description Security utility for sanitizing user input
 * @version 1.0.0
 */

const validator = require('validator');
const xss = require('xss');

/**
 * Sanitize input data based on allowed fields
 * @param {Object} data - Input data to sanitize
 * @param {Array} allowedFields - Array of allowed field names
 * @returns {Object} - Sanitized data
 */
const sanitizeInput = (data, allowedFields = []) => {
  const sanitized = {};
  
  for (const field of allowedFields) {
    if (field.includes('.')) {
      // Handle nested fields
      const parts = field.split('.');
      const value = getNestedValue(data, field);
      
      if (value !== undefined) {
        setNestedValue(sanitized, field, sanitizeValue(value));
      }
    } else if (data[field] !== undefined) {
      sanitized[field] = sanitizeValue(data[field]);
    }
  }
  
  return sanitized;
};

/**
 * Sanitize a single value based on its type
 * @param {any} value - Value to sanitize
 * @returns {any} - Sanitized value
 */
const sanitizeValue = (value) => {
  if (value === null || value === undefined) {
    return value;
  }
  
  if (typeof value === 'string') {
    return sanitizeString(value);
  }
  
  if (typeof value === 'number') {
    return sanitizeNumber(value);
  }
  
  if (typeof value === 'boolean') {
    return value;
  }
  
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  
  if (typeof value === 'object') {
    const sanitized = {};
    for (const [key, val] of Object.entries(value)) {
      sanitized[sanitizeKey(key)] = sanitizeValue(val);
    }
    return sanitized;
  }
  
  return value;
};

/**
 * Sanitize string value
 * @param {string} str - String to sanitize
 * @returns {string} - Sanitized string
 */
const sanitizeString = (str) => {
  // Trim whitespace
  let sanitized = str.trim();
  
  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, '');
  
  // Escape HTML
  sanitized = validator.escape(sanitized);
  
  // Remove any potential XSS
  sanitized = xss(sanitized, {
    whiteList: {}, // No HTML tags allowed by default
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script']
  });
  
  return sanitized;
};

/**
 * Sanitize HTML content (allows safe HTML)
 * @param {string} html - HTML content to sanitize
 * @returns {string} - Sanitized HTML
 */
const sanitizeHTML = (html) => {
  return xss(html, {
    whiteList: {
      a: ['href', 'title', 'target'],
      b: [],
      i: [],
      em: [],
      strong: [],
      p: [],
      br: [],
      ul: [],
      ol: [],
      li: [],
      blockquote: [],
      code: [],
      pre: [],
      h1: [],
      h2: [],
      h3: [],
      h4: [],
      h5: [],
      h6: []
    },
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script', 'style']
  });
};

/**
 * Sanitize number value
 * @param {number} num - Number to sanitize
 * @returns {number} - Sanitized number
 */
const sanitizeNumber = (num) => {
  // Ensure it's a valid number
  if (isNaN(num) || !isFinite(num)) {
    return 0;
  }
  return num;
};

/**
 * Sanitize object key
 * @param {string} key - Object key to sanitize
 * @returns {string} - Sanitized key
 */
const sanitizeKey = (key) => {
  // Remove any characters that could be problematic in object keys
  return key.replace(/[.$\[\]#\/]/g, '_');
};

/**
 * Sanitize filename
 * @param {string} filename - Filename to sanitize
 * @returns {string} - Sanitized filename
 */
const sanitizeFilename = (filename) => {
  // Remove path separators
  let sanitized = filename.replace(/[\/\\]/g, '');
  
  // Remove special characters
  sanitized = sanitized.replace(/[^a-zA-Z0-9.-_]/g, '_');
  
  // Limit length
  if (sanitized.length > 255) {
    const ext = sanitized.split('.').pop();
    const name = sanitized.substring(0, 250 - ext.length - 1);
    sanitized = `${name}.${ext}`;
  }
  
  return sanitized;
};

/**
 * Sanitize URL
 * @param {string} url - URL to sanitize
 * @returns {string|null} - Sanitized URL or null if invalid
 */
const sanitizeURL = (url) => {
  try {
    const parsed = new URL(url);
    
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    
    return parsed.toString();
  } catch (error) {
    return null;
  }
};

/**
 * Sanitize email
 * @param {string} email - Email to sanitize
 * @returns {string} - Sanitized email
 */
const sanitizeEmail = (email) => {
  const normalized = validator.normalizeEmail(email, {
    gmail_remove_dots: false,
    gmail_remove_subaddress: false,
    outlookdotcom_remove_subaddress: false,
    yahoo_remove_subaddress: false,
    icloud_remove_subaddress: false
  });
  
  return normalized ? normalized.toLowerCase() : '';
};

/**
 * Sanitize phone number
 * @param {string} phone - Phone number to sanitize
 * @returns {string} - Sanitized phone number
 */
const sanitizePhone = (phone) => {
  // Remove all non-numeric characters except + for international
  return phone.replace(/[^\d+]/g, '');
};

/**
 * Get nested value from object
 * @param {Object} obj - Object to search
 * @param {string} path - Dot notation path
 * @returns {any} - Value at path
 */
const getNestedValue = (obj, path) => {
  return path.split('.').reduce((current, key) => current?.[key], obj);
};

/**
 * Set nested value in object
 * @param {Object} obj - Object to modify
 * @param {string} path - Dot notation path
 * @param {any} value - Value to set
 */
const setNestedValue = (obj, path, value) => {
  const keys = path.split('.');
  const lastKey = keys.pop();
  
  const target = keys.reduce((current, key) => {
    if (!current[key]) current[key] = {};
    return current[key];
  }, obj);
  
  target[lastKey] = value;
};

/**
 * Create sanitization middleware
 * @param {Array} allowedFields - Array of allowed fields
 * @returns {Function} - Express middleware
 */
const createSanitizer = (allowedFields) => {
  return (req, res, next) => {
    if (req.body) {
      req.body = sanitizeInput(req.body, allowedFields);
    }
    
    if (req.query) {
      req.query = sanitizeInput(req.query, Object.keys(req.query));
    }
    
    next();
  };
};

/**
 * Sanitize MongoDB query to prevent injection
 * @param {Object} query - MongoDB query object
 * @returns {Object} - Sanitized query
 */
const sanitizeMongoQuery = (query) => {
  const sanitized = {};
  
  for (const [key, value] of Object.entries(query)) {
    // Remove keys starting with $
    if (key.startsWith('$')) {
      continue;
    }
    
    if (typeof value === 'object' && value !== null) {
      // Recursively sanitize nested objects
      sanitized[key] = sanitizeMongoQuery(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
};

module.exports = {
  sanitizeInput,
  sanitizeValue,
  sanitizeString,
  sanitizeHTML,
  sanitizeNumber,
  sanitizeFilename,
  sanitizeURL,
  sanitizeEmail,
  sanitizePhone,
  createSanitizer,
  sanitizeMongoQuery
};