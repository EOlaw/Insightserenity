/**
 * @file ID Generator Helper
 * @description Utility for generating unique identifiers across the platform
 * @version 1.0.0
 */

const crypto = require('crypto');

/**
 * Generate a unique identifier with optional prefix
 * @param {string} prefix - Optional prefix for the ID (e.g., 'ORG', 'USR', 'PRJ')
 * @param {number} length - Length of random part (default: 12)
 * @returns {string} - Unique identifier
 */
const generateUniqueId = (prefix = '', length = 12) => {
  const timestamp = Date.now().toString(36);
  const randomPart = crypto.randomBytes(Math.ceil(length / 2))
    .toString('hex')
    .slice(0, length);
  
  if (prefix) {
    return `${prefix}_${timestamp}${randomPart}`.toUpperCase();
  }
  
  return `${timestamp}${randomPart}`;
};

/**
 * Generate a short unique code (for verification, referral codes, etc.)
 * @param {number} length - Length of the code (default: 6)
 * @returns {string} - Short unique code
 */
const generateShortCode = (length = 6) => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  
  for (let i = 0; i < length; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return code;
};

/**
 * Generate a UUID v4
 * @returns {string} - UUID v4
 */
const generateUUID = () => {
  return crypto.randomUUID();
};

/**
 * Generate a secure token for authentication/verification
 * @param {number} length - Length in bytes (default: 32)
 * @returns {string} - Secure token
 */
const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Generate a slug-friendly ID
 * @param {string} text - Text to base the slug on
 * @returns {string} - Slug-friendly ID
 */
const generateSlugId = (text) => {
  const baseSlug = text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  
  const randomSuffix = crypto.randomBytes(3).toString('hex');
  return `${baseSlug}-${randomSuffix}`;
};

/**
 * Generate an invoice or document number
 * @param {string} prefix - Prefix for the number (e.g., 'INV', 'DOC')
 * @param {number} sequence - Current sequence number
 * @returns {string} - Formatted document number
 */
const generateDocumentNumber = (prefix, sequence) => {
  const year = new Date().getFullYear();
  const paddedSequence = sequence.toString().padStart(6, '0');
  return `${prefix}-${year}-${paddedSequence}`;
};

/**
 * Generate a reference code for transactions
 * @returns {string} - Transaction reference code
 */
const generateTransactionRef = () => {
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `TXN-${timestamp}-${random}`;
};

module.exports = {
  generateUniqueId,
  generateShortCode,
  generateUUID,
  generateSecureToken,
  generateSlugId,
  generateDocumentNumber,
  generateTransactionRef
};