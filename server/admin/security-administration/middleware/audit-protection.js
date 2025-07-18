// server/admin/security-administration/middleware/audit-protection.js
/**
 * @file Audit Protection Middleware
 * @description Middleware for protecting audit data integrity and access
 * @version 1.0.0
 */

const crypto = require('crypto');
const { ForbiddenError, UnauthorizedError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');
const CacheService = require('../../../shared/utils/cache-service');
const AuditLog = require('../../../shared/security/models/audit-log-model');

/**
 * Audit Protection Middleware Class
 * @class AuditProtectionMiddleware
 */
class AuditProtectionMiddleware {
  /**
   * Protect audit log integrity
   */
  static protectAuditIntegrity = async (req, res, next) => {
    try {
      // Prevent modification of audit logs
      if (req.path.includes('/audit/logs') && ['PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        // Only allow specific operations
        const allowedOperations = ['/archive', '/export', '/decrypt'];
        const isAllowed = allowedOperations.some(op => req.path.includes(op));
        
        if (!isAllowed) {
          await AdminActivityTracker.track(req.adminUser, 'audit.integrity.violation_attempt', {
            path: req.path,
            method: req.method
          });
          
          throw new ForbiddenError('Audit logs cannot be modified or deleted');
        }
      }

      // Add integrity headers to responses
      if (req.path.includes('/audit') && req.method === 'GET') {
        res.on('finish', () => {
          if (res.statusCode === 200 && res.locals.auditData) {
            res.setHeader('X-Audit-Integrity', this.generateIntegrityHash(res.locals.auditData));
          }
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Validate audit access permissions
   */
  static validateAuditAccess = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Authentication required');
      }

      // Check basic audit view permission
      if (!adminUser.permissions?.includes(AdminPermissions.AUDIT.VIEW)) {
        throw new ForbiddenError('Insufficient permissions to access audit logs');
      }

      // Additional checks for sensitive operations
      if (req.query.decrypt === 'true' || req.path.includes('/decrypt')) {
        if (!adminUser.permissions?.includes(AdminPermissions.AUDIT.DECRYPT)) {
          await AdminActivityTracker.track(adminUser, 'audit.decrypt.denied', {
            path: req.path
          });
          
          throw new ForbiddenError('Decryption permission required');
        }

        // Require MFA for decryption
        if (!req.session?.mfaVerified) {
          throw new UnauthorizedError('MFA verification required for audit decryption');
        }
      }

      // Check export permissions
      if (req.path.includes('/export')) {
        if (!adminUser.permissions?.includes(AdminPermissions.AUDIT.EXPORT)) {
          throw new ForbiddenError('Export permission required');
        }
      }

      // Validate scope access
      await this.validateScopeAccess(req, adminUser);

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Enforce audit retention policies
   */
  static enforceRetentionPolicies = async (req, res, next) => {
    try {
      // Check if operation affects retention
      if (req.path.includes('/retention') || req.path.includes('/purge')) {
        const adminUser = req.adminUser;
        
        // Only super admins can modify retention
        if (adminUser.role !== 'super_admin') {
          throw new ForbiddenError('Only super administrators can modify retention policies');
        }

        // Validate retention period against compliance
        if (req.body.retentionDays) {
          const minRetention = await this.getMinimumRetention(req.body.standard);
          
          if (req.body.retentionDays < minRetention) {
            throw new ValidationError(
              `Retention period must be at least ${minRetention} days for ${req.body.standard} compliance`
            );
          }
        }

        // Prevent deletion of logs under legal hold
        if (req.method === 'DELETE' || req.path.includes('/purge')) {
          const hasLegalHold = await this.checkLegalHoldStatus(req);
          
          if (hasLegalHold) {
            throw new ForbiddenError('Cannot delete audit logs under legal hold');
          }
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Track audit access patterns
   */
  static trackAuditAccess = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser || !req.path.includes('/audit')) {
        return next();
      }

      // Track access pattern
      const accessPattern = {
        userId: adminUser.id,
        path: req.path,
        method: req.method,
        timestamp: Date.now(),
        ip: req.ip,
        query: req.query
      };

      // Detect suspicious patterns
      const suspicious = await this.detectSuspiciousAccess(adminUser.id, accessPattern);
      
      if (suspicious) {
        await AdminActivityTracker.track(adminUser, 'audit.suspicious_access', {
          pattern: suspicious,
          ...accessPattern
        });

        // Rate limit suspicious users
        const key = `audit:suspicious:${adminUser.id}`;
        const count = await CacheService.increment(key);
        
        if (count === 1) {
          await CacheService.expire(key, 3600); // 1 hour
        }

        if (count > 10) {
          throw new ForbiddenError('Suspicious audit access pattern detected');
        }
      }

      // Log high-volume access
      await this.trackVolumeAccess(adminUser.id, req.path);

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Protect sensitive audit fields
   */
  static protectSensitiveFields = async (req, res, next) => {
    try {
      // Intercept response to filter sensitive data
      const originalJson = res.json;
      
      res.json = function(data) {
        if (req.path.includes('/audit') && data.success && data.data) {
          // Filter sensitive fields unless explicitly requested and authorized
          const filtered = AuditProtectionMiddleware.filterSensitiveData(
            data.data,
            req.adminUser,
            req.query
          );
          
          arguments[0] = {
            ...data,
            data: filtered
          };
        }
        
        return originalJson.apply(res, arguments);
      };

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Validate audit export requests
   */
  static validateExportRequest = async (req, res, next) => {
    try {
      if (!req.path.includes('/export')) {
        return next();
      }

      const adminUser = req.adminUser;
      
      // Check export limits
      const exportCount = await this.getExportCount(adminUser.id);
      const maxExports = adminUser.role === 'super_admin' ? 10 : 5;
      
      if (exportCount >= maxExports) {
        throw new ForbiddenError(`Export limit reached (${maxExports} per day)`);
      }

      // Validate export size
      if (req.body.dateFrom && req.body.dateTo) {
        const estimatedSize = await this.estimateExportSize(req.body);
        
        if (estimatedSize > 1000000) { // 1M records
          throw new ValidationError('Export size too large. Please narrow your date range.');
        }
      }

      // Require reason for large exports
      if (!req.body.reason && req.body.includeDecrypted) {
        throw new ValidationError('Reason required for exporting decrypted audit logs');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Ensure audit trail for audit operations
   */
  static ensureAuditTrail = async (req, res, next) => {
    try {
      // Create pre-operation audit entry
      if (req.path.includes('/audit') && req.method !== 'GET') {
        req.auditTrailId = crypto.randomUUID();
        
        await AuditLog.create({
          userId: req.adminUser.id,
          organizationId: req.adminUser.organizationId,
          eventType: `audit.operation.${req.method.toLowerCase()}`,
          severity: 'medium',
          category: 'AUDIT_MANAGEMENT',
          details: {
            operationId: req.auditTrailId,
            path: req.path,
            method: req.method,
            body: this.sanitizeBody(req.body),
            status: 'initiated'
          },
          metadata: {
            ipAddress: req.ip,
            userAgent: req.headers['user-agent'],
            sessionId: req.sessionID
          },
          timestamp: new Date()
        });
      }

      // Track operation completion
      res.on('finish', async () => {
        if (req.auditTrailId) {
          await AuditLog.create({
            userId: req.adminUser.id,
            organizationId: req.adminUser.organizationId,
            eventType: `audit.operation.completed`,
            severity: 'low',
            category: 'AUDIT_MANAGEMENT',
            details: {
              operationId: req.auditTrailId,
              statusCode: res.statusCode,
              success: res.statusCode < 400
            },
            metadata: {
              ipAddress: req.ip,
              userAgent: req.headers['user-agent'],
              sessionId: req.sessionID
            },
            timestamp: new Date()
          });
        }
      });

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Prevent audit tampering
   */
  static preventTampering = async (req, res, next) => {
    try {
      // Check for tampering indicators
      if (req.path.includes('/audit')) {
        // Validate timestamp manipulation attempts
        if (req.body.timestamp || req.query.timestamp) {
          const providedTime = new Date(req.body.timestamp || req.query.timestamp);
          const now = new Date();
          
          // Allow only minor time differences (5 minutes)
          if (Math.abs(providedTime - now) > 5 * 60 * 1000) {
            await AdminActivityTracker.track(req.adminUser, 'audit.tampering.attempt', {
              providedTimestamp: providedTime,
              actualTimestamp: now
            });
            
            throw new ForbiddenError('Invalid timestamp detected');
          }
        }

        // Prevent ID manipulation
        if (req.body._id || req.body.id) {
          delete req.body._id;
          delete req.body.id;
        }

        // Validate checksum if provided
        if (req.headers['x-audit-checksum']) {
          const valid = await this.validateChecksum(req);
          
          if (!valid) {
            throw new ValidationError('Invalid audit checksum');
          }
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Rate limit audit operations
   */
  static rateLimitAuditOps = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser || !req.path.includes('/audit')) {
        return next();
      }

      // Different limits for different operations
      const limits = {
        'GET': { window: 60000, max: 100 }, // 100 per minute
        'POST': { window: 3600000, max: 50 }, // 50 per hour
        'DELETE': { window: 86400000, max: 5 } // 5 per day
      };

      const limit = limits[req.method] || { window: 60000, max: 50 };
      const key = `audit:rate:${adminUser.id}:${req.method}:${Math.floor(Date.now() / limit.window)}`;
      
      const count = await CacheService.increment(key);
      
      if (count === 1) {
        await CacheService.expire(key, Math.ceil(limit.window / 1000));
      }

      if (count > limit.max) {
        throw new ForbiddenError('Audit operation rate limit exceeded');
      }

      // Add rate limit headers
      res.setHeader('X-RateLimit-Limit', limit.max);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, limit.max - count));
      res.setHeader('X-RateLimit-Reset', new Date(Math.ceil(Date.now() / limit.window) * limit.window).toISOString());

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Validate critical audit operations
   */
  static validateCriticalOps = async (req, res, next) => {
    try {
      const criticalOps = [
        { path: '/purge', method: 'DELETE' },
        { path: '/decrypt', method: 'POST' },
        { path: '/export', method: 'POST' }
      ];

      const isCritical = criticalOps.some(op => 
        req.path.includes(op.path) && req.method === op.method
      );

      if (!isCritical) {
        return next();
      }

      const adminUser = req.adminUser;

      // Require elevated session
      if (!req.session?.elevated) {
        throw new UnauthorizedError('Elevated privileges required for critical audit operations');
      }

      // Check session age
      const sessionAge = Date.now() - new Date(req.session.elevatedAt).getTime();
      if (sessionAge > 15 * 60 * 1000) { // 15 minutes
        throw new UnauthorizedError('Elevated session expired. Please re-authenticate.');
      }

      // Require approval token for purge operations
      if (req.path.includes('/purge')) {
        const approvalToken = req.headers['x-approval-token'] || req.body.approvalToken;
        
        if (!approvalToken) {
          throw new ValidationError('Approval token required for purge operations');
        }

        const approved = await this.validateApprovalToken(approvalToken, adminUser.id);
        
        if (!approved) {
          throw new ForbiddenError('Invalid or expired approval token');
        }
      }

      // Log critical operation
      await AdminActivityTracker.track(adminUser, 'audit.critical_operation.authorized', {
        operation: req.path,
        method: req.method
      });

      next();
    } catch (error) {
      next(error);
    }
  };

  // Helper methods

  /**
   * Generate integrity hash
   * @private
   */
  static generateIntegrityHash(data) {
    const hash = crypto.createHash('sha256');
    hash.update(JSON.stringify(data));
    return hash.digest('hex');
  }

  /**
   * Validate scope access
   * @private
   */
  static async validateScopeAccess(req, adminUser) {
    // Organization admins can only access their org's audit logs
    if (adminUser.organizationId) {
      if (req.query.organizationId && req.query.organizationId !== adminUser.organizationId.toString()) {
        throw new ForbiddenError('Cannot access audit logs from other organizations');
      }
      
      // Force organization filter
      req.query.organizationId = adminUser.organizationId.toString();
    }

    // Check user-specific access
    if (req.query.userId && adminUser.role !== 'super_admin') {
      // Can only access own logs unless admin
      if (req.query.userId !== adminUser.id.toString() && !adminUser.permissions?.includes(AdminPermissions.AUDIT.VIEW_ALL)) {
        throw new ForbiddenError('Cannot access audit logs for other users');
      }
    }
  }

  /**
   * Get minimum retention period
   * @private
   */
  static async getMinimumRetention(standard) {
    const retentionMap = {
      'GDPR': 1095, // 3 years
      'HIPAA': 2190, // 6 years
      'PCI-DSS': 365, // 1 year
      'SOC2': 1095, // 3 years
      'ISO27001': 1095 // 3 years
    };

    return retentionMap[standard] || 365; // Default 1 year
  }

  /**
   * Check legal hold status
   * @private
   */
  static async checkLegalHoldStatus(req) {
    try {
      // Check if any logs in the range are under legal hold
      const query = {};
      
      if (req.body.dateFrom) {
        query.timestamp = { $gte: new Date(req.body.dateFrom) };
      }
      
      if (req.body.dateTo) {
        query.timestamp = { ...query.timestamp, $lte: new Date(req.body.dateTo) };
      }

      query.legalHold = true;

      const count = await AuditLog.countDocuments(query);
      return count > 0;
    } catch (error) {
      logger.error('Error checking legal hold status', { error: error.message });
      return false;
    }
  }

  /**
   * Detect suspicious access patterns
   * @private
   */
  static async detectSuspiciousAccess(userId, pattern) {
    try {
      const key = `audit:access:${userId}`;
      const recentAccess = await CacheService.lrange(key, 0, -1);
      
      // Add current access
      await CacheService.rpush(key, JSON.stringify(pattern));
      await CacheService.expire(key, 3600); // 1 hour
      
      // Keep only last 100 accesses
      if (recentAccess.length > 100) {
        await CacheService.ltrim(key, -100, -1);
      }

      // Analyze patterns
      const patterns = recentAccess.map(a => JSON.parse(a));
      
      // Check for rapid sequential access
      const recentPatterns = patterns.filter(p => Date.now() - p.timestamp < 60000); // Last minute
      if (recentPatterns.length > 20) {
        return 'rapid_access';
      }

      // Check for bulk export attempts
      const exportAttempts = patterns.filter(p => p.path.includes('/export'));
      if (exportAttempts.length > 5) {
        return 'excessive_exports';
      }

      // Check for decryption attempts
      const decryptAttempts = patterns.filter(p => p.query.decrypt === 'true');
      if (decryptAttempts.length > 3) {
        return 'excessive_decryption';
      }

      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Track volume access
   * @private
   */
  static async trackVolumeAccess(userId, path) {
    try {
      const key = `audit:volume:${userId}:${new Date().toISOString().split('T')[0]}`;
      const field = path.includes('/logs') ? 'logs' : 'other';
      
      await CacheService.hincrby(key, field, 1);
      await CacheService.expire(key, 86400); // 24 hours
    } catch (error) {
      // Silent fail
    }
  }

  /**
   * Filter sensitive data
   * @private
   */
  static filterSensitiveData(data, adminUser, query) {
    // Don't filter for super admins with decrypt permission
    if (adminUser.role === 'super_admin' && query.decrypt === 'true') {
      return data;
    }

    const filterFields = (obj) => {
      if (!obj) return obj;

      const filtered = { ...obj };
      
      // Remove sensitive fields
      const sensitiveFields = [
        'ipAddress',
        'sessionId',
        'authToken',
        'password',
        'ssn',
        'creditCard'
      ];

      sensitiveFields.forEach(field => {
        if (filtered[field]) {
          filtered[field] = '[REDACTED]';
        }
      });

      // Recursively filter nested objects
      Object.keys(filtered).forEach(key => {
        if (typeof filtered[key] === 'object' && filtered[key] !== null) {
          if (Array.isArray(filtered[key])) {
            filtered[key] = filtered[key].map(item => 
              typeof item === 'object' ? filterFields(item) : item
            );
          } else {
            filtered[key] = filterFields(filtered[key]);
          }
        }
      });

      return filtered;
    };

    if (Array.isArray(data)) {
      return data.map(item => filterFields(item));
    }

    return filterFields(data);
  }

  /**
   * Get export count
   * @private
   */
  static async getExportCount(userId) {
    try {
      const key = `audit:export:${userId}:${new Date().toISOString().split('T')[0]}`;
      const count = await CacheService.get(key) || 0;
      return parseInt(count);
    } catch (error) {
      return 0;
    }
  }

  /**
   * Estimate export size
   * @private
   */
  static async estimateExportSize(params) {
    try {
      const query = {};
      
      if (params.dateFrom) {
        query.timestamp = { $gte: new Date(params.dateFrom) };
      }
      
      if (params.dateTo) {
        query.timestamp = { ...query.timestamp, $lte: new Date(params.dateTo) };
      }

      const count = await AuditLog.countDocuments(query);
      return count;
    } catch (error) {
      return 0;
    }
  }

  /**
   * Sanitize request body
   * @private
   */
  static sanitizeBody(body) {
    if (!body) return {};

    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'secret', 'key'];
    
    sensitiveFields.forEach(field => {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    });

    return sanitized;
  }

  /**
   * Validate checksum
   * @private
   */
  static async validateChecksum(req) {
    try {
      const providedChecksum = req.headers['x-audit-checksum'];
      const calculatedChecksum = this.generateIntegrityHash(req.body);
      
      return providedChecksum === calculatedChecksum;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate approval token
   * @private
   */
  static async validateApprovalToken(token, userId) {
    try {
      const key = `approval:${token}`;
      const approval = await CacheService.get(key);
      
      if (!approval) {
        return false;
      }

      // Ensure approver is different from requester
      if (approval.approvedBy === userId) {
        return false;
      }

      // Check expiration
      if (new Date(approval.expiresAt) < new Date()) {
        return false;
      }

      // Mark as used
      await CacheService.delete(key);
      
      return true;
    } catch (error) {
      return false;
    }
  }
}

module.exports = AuditProtectionMiddleware;