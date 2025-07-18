// server/admin/security-administration/middleware/security-access.js
/**
 * @file Security Access Middleware
 * @description Middleware for controlling access to security administration features
 * @version 1.0.0
 */

const { ForbiddenError, UnauthorizedError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');
const CacheService = require('../../../shared/utils/cache-service');

/**
 * Security Access Middleware Class
 * @class SecurityAccessMiddleware
 */
class SecurityAccessMiddleware {
  /**
   * Check security view permission
   */
  static canViewSecurity = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.VIEW)) {
        await AdminActivityTracker.track(adminUser, 'security.access.denied', {
          permission: AdminPermissions.SECURITY.VIEW,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to view security settings');
      }

      // Check if security module is enabled for the organization
      if (adminUser.organizationId) {
        const orgSettings = await CacheService.get(`org:${adminUser.organizationId}:settings`);
        if (orgSettings?.modules?.security === false) {
          throw new ForbiddenError('Security module is not enabled for your organization');
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check security update permission
   */
  static canUpdateSecurity = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.UPDATE)) {
        await AdminActivityTracker.track(adminUser, 'security.update.denied', {
          permission: AdminPermissions.SECURITY.UPDATE,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to update security settings');
      }

      // Require MFA for security updates
      if (!req.session?.mfaVerified) {
        throw new UnauthorizedError('MFA verification required for security updates');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check key rotation permission
   */
  static canRotateKeys = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Only super admins can rotate keys
      if (adminUser.role !== 'super_admin' || !adminUser.permissions?.includes(AdminPermissions.SECURITY.ROTATE_KEYS)) {
        await AdminActivityTracker.track(adminUser, 'security.key_rotation.denied', {
          permission: AdminPermissions.SECURITY.ROTATE_KEYS,
          path: req.path
        });
        
        throw new ForbiddenError('Only super administrators can rotate encryption keys');
      }

      // Require MFA and recent authentication
      if (!req.session?.mfaVerified) {
        throw new UnauthorizedError('MFA verification required for key rotation');
      }

      // Check if session is recent (within last 15 minutes)
      const sessionAge = Date.now() - new Date(req.session.lastActivity).getTime();
      if (sessionAge > 15 * 60 * 1000) {
        throw new UnauthorizedError('Recent authentication required for key rotation');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check IP whitelist management permission
   */
  static canManageIPWhitelist = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.MANAGE_WHITELIST)) {
        await AdminActivityTracker.track(adminUser, 'security.ip_whitelist.denied', {
          permission: AdminPermissions.SECURITY.MANAGE_WHITELIST,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to manage IP whitelist');
      }

      // Additional check for critical IPs
      if (req.body.action === 'remove') {
        const criticalIPs = ['127.0.0.1', '::1']; // Add more critical IPs
        const ipsToRemove = req.body.ips || [req.body.ip];
        
        const hasCriticalIP = ipsToRemove.some(ip => criticalIPs.includes(ip));
        if (hasCriticalIP) {
          throw new ForbiddenError('Cannot remove critical IP addresses from whitelist');
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check incident management permission
   */
  static canManageIncidents = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.MANAGE_INCIDENTS)) {
        await AdminActivityTracker.track(adminUser, 'security.incidents.denied', {
          permission: AdminPermissions.SECURITY.MANAGE_INCIDENTS,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to manage security incidents');
      }

      // Check incident severity restrictions
      if (req.body.severity === 'critical' && adminUser.role !== 'super_admin') {
        throw new ForbiddenError('Only super administrators can manage critical incidents');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check threat detection configuration permission
   */
  static canConfigureThreatDetection = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.CONFIGURE_THREAT_DETECTION)) {
        await AdminActivityTracker.track(adminUser, 'security.threat_detection.denied', {
          permission: AdminPermissions.SECURITY.CONFIGURE_THREAT_DETECTION,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to configure threat detection');
      }

      // Validate rule limits
      if (req.body.action === 'create') {
        const ruleCount = await this.getActiveRuleCount(adminUser.organizationId);
        const maxRules = adminUser.organizationId ? 100 : 500; // Org vs platform limit
        
        if (ruleCount >= maxRules) {
          throw new ForbiddenError(`Maximum number of threat detection rules (${maxRules}) reached`);
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check security scan permission
   */
  static canPerformScan = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.PERFORM_SCAN)) {
        await AdminActivityTracker.track(adminUser, 'security.scan.denied', {
          permission: AdminPermissions.SECURITY.PERFORM_SCAN,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to perform security scans');
      }

      // Check scan rate limits
      const scanKey = `scan:${adminUser.id}:count`;
      const scanCount = await CacheService.get(scanKey) || 0;
      
      if (scanCount >= 10) { // Max 10 scans per hour
        throw new ForbiddenError('Security scan rate limit exceeded. Please try again later.');
      }

      // Increment scan count
      await CacheService.set(scanKey, scanCount + 1, 3600); // 1 hour TTL

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check security report viewing permission
   */
  static canViewReports = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.VIEW_REPORTS)) {
        await AdminActivityTracker.track(adminUser, 'security.reports.denied', {
          permission: AdminPermissions.SECURITY.VIEW_REPORTS,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to view security reports');
      }

      // Check report access based on organization
      if (req.params.organizationId && adminUser.organizationId) {
        if (req.params.organizationId !== adminUser.organizationId.toString()) {
          throw new ForbiddenError('Cannot access reports from other organizations');
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Check security data export permission
   */
  static canExportSecurityData = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check permission
      if (!adminUser.permissions?.includes(AdminPermissions.SECURITY.EXPORT)) {
        await AdminActivityTracker.track(adminUser, 'security.export.denied', {
          permission: AdminPermissions.SECURITY.EXPORT,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient permissions to export security data');
      }

      // Require MFA for exports
      if (!req.session?.mfaVerified) {
        throw new UnauthorizedError('MFA verification required for security data export');
      }

      // Check export limits
      const exportKey = `export:security:${adminUser.id}:count`;
      const exportCount = await CacheService.get(exportKey) || 0;
      
      if (exportCount >= 5) { // Max 5 exports per day
        throw new ForbiddenError('Security export limit exceeded. Please try again tomorrow.');
      }

      // Increment export count
      await CacheService.set(exportKey, exportCount + 1, 86400); // 24 hour TTL

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Validate security operation context
   */
  static validateSecurityContext = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Check IP whitelist for security operations
      if (process.env.ENFORCE_IP_WHITELIST === 'true') {
        const clientIP = req.ip || req.connection.remoteAddress;
        const isWhitelisted = await this.checkIPWhitelist(clientIP, 'security_admin');
        
        if (!isWhitelisted) {
          await AdminActivityTracker.track(adminUser, 'security.ip_restricted', {
            ip: clientIP,
            path: req.path
          });
          
          throw new ForbiddenError('Security operations restricted to whitelisted IPs');
        }
      }

      // Check time-based restrictions
      const currentHour = new Date().getHours();
      const isMaintenanceWindow = currentHour >= 2 && currentHour <= 4; // 2-4 AM
      
      if (req.method !== 'GET' && !isMaintenanceWindow && process.env.RESTRICT_SECURITY_CHANGES === 'true') {
        throw new ForbiddenError('Security changes restricted to maintenance window (2-4 AM)');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Require elevated privileges for critical operations
   */
  static requireElevatedPrivileges = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Admin authentication required');
      }

      // Check if session has elevated privileges
      if (!req.session?.elevated) {
        throw new UnauthorizedError('Elevated privileges required. Please re-authenticate.');
      }

      // Check elevation expiry (30 minutes)
      const elevationAge = Date.now() - new Date(req.session.elevatedAt).getTime();
      if (elevationAge > 30 * 60 * 1000) {
        delete req.session.elevated;
        delete req.session.elevatedAt;
        throw new UnauthorizedError('Elevated privileges expired. Please re-authenticate.');
      }

      // Log elevated access
      await AdminActivityTracker.track(adminUser, 'security.elevated_access', {
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
   * Get active rule count for organization
   * @private
   */
  static async getActiveRuleCount(organizationId) {
    try {
      const cacheKey = `rules:count:${organizationId || 'platform'}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached !== null) {
        return cached;
      }

      // This would query the database for actual count
      // For now, returning a mock value
      const count = 25;
      
      await CacheService.set(cacheKey, count, 300); // 5 minutes cache
      return count;
    } catch (error) {
      logger.error('Error getting rule count', { error: error.message, organizationId });
      return 0;
    }
  }

  /**
   * Check if IP is whitelisted
   * @private
   */
  static async checkIPWhitelist(ip, scope) {
    try {
      const cacheKey = `ip:whitelist:${scope}:${ip}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached !== null) {
        return cached;
      }

      // This would check actual whitelist in database
      // For now, returning true for localhost
      const isWhitelisted = ['127.0.0.1', '::1'].includes(ip);
      
      await CacheService.set(cacheKey, isWhitelisted, 3600); // 1 hour cache
      return isWhitelisted;
    } catch (error) {
      logger.error('Error checking IP whitelist', { error: error.message, ip, scope });
      return false;
    }
  }
}

module.exports = SecurityAccessMiddleware;