/**
 * @file Admin IP Validation Middleware
 * @description IP-based access control and validation for administrative operations
 * @version 1.0.0
 */

const ipRangeCheck = require('ip-range-check');
const geoip = require('geoip-lite');
const { AuthorizationError, AppError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../../audit/services/audit-service');
const AdminAuditLogger = require('./admin-audit-logging');
const config = require('../../../config/config');

/**
 * Admin IP Validation Middleware Class
 * @class AdminIPValidator
 */
class AdminIPValidator {
  /**
   * Initialize IP validation configurations
   */
  static initialize() {
    // Default IP whitelist configuration
    this.defaultWhitelist = {
      development: [
        '127.0.0.1',
        '::1',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        'localhost'
      ],
      production: [] // Must be configured via environment
    };

    // Trusted proxy configuration
    this.trustedProxies = config.security.trustedProxies || [];

    // Geo-restriction settings
    this.geoRestrictions = {
      enabled: config.security.adminGeoRestriction?.enabled || false,
      allowedCountries: config.security.adminGeoRestriction?.countries || [],
      blockedCountries: config.security.adminGeoRestriction?.blockedCountries || [],
      allowVPN: config.security.adminGeoRestriction?.allowVPN || false
    };

    // Dynamic IP management
    this.dynamicWhitelist = new Map();
    this.temporaryAccess = new Map();
    this.blockedIPs = new Map();
    
    // Suspicious activity tracking
    this.suspiciousActivity = new Map();
    this.suspiciousThreshold = 5;
    this.blockDuration = 3600000; // 1 hour
  }

  /**
   * Main IP validation middleware
   * @param {Object} options - Validation options
   * @returns {Function} Express middleware
   */
  static validateIP(options = {}) {
    const {
      enforceWhitelist = true,
      allowTemporaryAccess = true,
      checkGeoLocation = true,
      detectProxies = true,
      strictMode = false
    } = options;

    return async (req, res, next) => {
      try {
        const clientIP = this.getClientIP(req);
        const validationContext = {
          ip: clientIP,
          userId: req.user?._id,
          endpoint: req.originalUrl,
          method: req.method,
          timestamp: new Date()
        };

        // Check if IP is blocked
        if (this.isIPBlocked(clientIP)) {
          throw new AuthorizationError('IP address is blocked from admin access');
        }

        // Check if IP requires validation
        if (enforceWhitelist && !this.isIPWhitelisted(clientIP, req.user)) {
          if (allowTemporaryAccess && this.hasTemporaryAccess(clientIP, req.user?._id)) {
            logger.info('Admin access via temporary IP grant', validationContext);
          } else {
            await this.handleUnauthorizedIP(validationContext);
            throw new AuthorizationError('IP address not authorized for admin access');
          }
        }

        // Perform geo-location validation
        if (checkGeoLocation && this.geoRestrictions.enabled) {
          const geoValidation = await this.validateGeoLocation(clientIP);
          if (!geoValidation.allowed) {
            await this.handleGeoRestriction(validationContext, geoValidation);
            throw new AuthorizationError(`Admin access not allowed from ${geoValidation.country || 'unknown location'}`);
          }
        }

        // Detect and validate proxy usage
        if (detectProxies) {
          const proxyDetection = await this.detectProxy(clientIP, req);
          if (proxyDetection.isProxy && strictMode) {
            await this.handleProxyDetection(validationContext, proxyDetection);
            throw new AuthorizationError('Admin access through proxy servers is not allowed');
          }
        }

        // Track IP usage patterns
        await this.trackIPUsage(clientIP, req.user?._id);

        // Set IP context in request
        req.adminIP = {
          address: clientIP,
          whitelisted: this.isIPWhitelisted(clientIP, req.user),
          temporary: this.hasTemporaryAccess(clientIP, req.user?._id),
          geo: await this.getGeoInfo(clientIP),
          trusted: this.isTrustedIP(clientIP)
        };

        // Log successful validation
        await AdminAuditLogger.logAdminEvent({
          eventType: 'admin_ip_validated',
          userId: req.user?._id,
          targetType: 'ip_validation',
          operation: 'validate',
          metadata: {
            ...validationContext,
            validation: req.adminIP
          }
        });

        next();
      } catch (error) {
        await AdminAuditLogger.logAdminEvent({
          eventType: 'admin_ip_validation_failed',
          userId: req.user?._id,
          targetType: 'ip_validation',
          operation: 'validate',
          metadata: {
            error: error.message,
            ip: this.getClientIP(req),
            endpoint: req.originalUrl
          }
        });

        next(error);
      }
    };
  }

  /**
   * Get client IP address considering proxies
   * @param {Object} req - Express request
   * @returns {string} Client IP
   */
  static getClientIP(req) {
    // Check various headers for IP address
    const headers = [
      'x-real-ip',
      'x-forwarded-for',
      'cf-connecting-ip', // Cloudflare
      'x-cluster-client-ip',
      'x-forwarded',
      'forwarded-for'
    ];

    for (const header of headers) {
      const value = req.headers[header];
      if (value) {
        // Handle comma-separated list (x-forwarded-for)
        const ips = value.split(',').map(ip => ip.trim());
        
        // If using trusted proxies, return the first non-proxy IP
        if (this.trustedProxies.length > 0) {
          for (const ip of ips) {
            if (!this.trustedProxies.some(proxy => ipRangeCheck(ip, proxy))) {
              return ip;
            }
          }
        }
        
        return ips[0];
      }
    }

    // Fallback to direct connection
    return req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           req.ip;
  }

  /**
   * Check if IP is whitelisted
   * @param {string} ip - IP address
   * @param {Object} user - User object
   * @returns {boolean} Is whitelisted
   */
  static isIPWhitelisted(ip, user) {
    // Check environment-specific default whitelist
    const envWhitelist = this.defaultWhitelist[config.app.env] || [];
    if (envWhitelist.some(range => ipRangeCheck(ip, range))) {
      return true;
    }

    // Check configured admin whitelist
    const adminWhitelist = config.security.adminIPWhitelist || [];
    if (adminWhitelist.some(range => ipRangeCheck(ip, range))) {
      return true;
    }

    // Check user-specific whitelist
    if (user?.adminSettings?.allowedIPs) {
      return user.adminSettings.allowedIPs.some(range => ipRangeCheck(ip, range));
    }

    // Check organization-specific whitelist
    if (user?.organizations) {
      for (const org of user.organizations) {
        if (org.adminIPWhitelist?.includes(ip)) {
          return true;
        }
      }
    }

    // Check dynamic whitelist
    return this.dynamicWhitelist.has(ip);
  }

  /**
   * Check if IP has temporary access
   * @param {string} ip - IP address
   * @param {string} userId - User ID
   * @returns {boolean} Has temporary access
   */
  static hasTemporaryAccess(ip, userId) {
    const key = `${ip}:${userId}`;
    const access = this.temporaryAccess.get(key);
    
    if (!access) return false;
    
    // Check if access has expired
    if (access.expiresAt < new Date()) {
      this.temporaryAccess.delete(key);
      return false;
    }
    
    return true;
  }

  /**
   * Grant temporary IP access
   * @param {string} ip - IP address
   * @param {string} userId - User ID
   * @param {number} duration - Duration in milliseconds
   * @param {string} reason - Reason for grant
   */
  static async grantTemporaryAccess(ip, userId, duration, reason) {
    const key = `${ip}:${userId}`;
    const access = {
      ip,
      userId,
      grantedAt: new Date(),
      expiresAt: new Date(Date.now() + duration),
      reason,
      grantId: crypto.randomUUID()
    };
    
    this.temporaryAccess.set(key, access);
    
    // Audit the grant
    await AdminAuditLogger.logAdminEvent({
      eventType: 'admin_ip_temporary_access_granted',
      userId,
      targetType: 'ip_access',
      operation: 'grant',
      metadata: {
        ip,
        duration,
        expiresAt: access.expiresAt,
        reason
      }
    });
    
    // Schedule cleanup
    setTimeout(() => {
      this.temporaryAccess.delete(key);
    }, duration);
    
    return access;
  }

  /**
   * Check if IP is blocked
   * @param {string} ip - IP address
   * @returns {boolean} Is blocked
   */
  static isIPBlocked(ip) {
    const blockEntry = this.blockedIPs.get(ip);
    
    if (!blockEntry) return false;
    
    // Check if block has expired
    if (blockEntry.expiresAt && blockEntry.expiresAt < new Date()) {
      this.blockedIPs.delete(ip);
      return false;
    }
    
    return true;
  }

  /**
   * Block IP address
   * @param {string} ip - IP address
   * @param {string} reason - Block reason
   * @param {number} duration - Block duration (null for permanent)
   */
  static async blockIP(ip, reason, duration = null) {
    const blockEntry = {
      ip,
      blockedAt: new Date(),
      expiresAt: duration ? new Date(Date.now() + duration) : null,
      reason,
      permanent: !duration
    };
    
    this.blockedIPs.set(ip, blockEntry);
    
    // Audit the block
    await AdminAuditLogger.logAdminEvent({
      eventType: 'admin_ip_blocked',
      targetType: 'ip_block',
      operation: 'block',
      metadata: {
        ip,
        reason,
        permanent: blockEntry.permanent,
        expiresAt: blockEntry.expiresAt
      }
    });
    
    // Schedule cleanup for temporary blocks
    if (duration) {
      setTimeout(() => {
        this.blockedIPs.delete(ip);
      }, duration);
    }
  }

  /**
   * Validate geo-location
   * @param {string} ip - IP address
   * @returns {Object} Validation result
   */
  static async validateGeoLocation(ip) {
    const geo = geoip.lookup(ip);
    
    if (!geo) {
      return {
        allowed: false,
        reason: 'Unable to determine location',
        country: null
      };
    }
    
    // Check blocked countries first
    if (this.geoRestrictions.blockedCountries.includes(geo.country)) {
      return {
        allowed: false,
        reason: 'Country is blocked',
        country: geo.country
      };
    }
    
    // Check allowed countries if configured
    if (this.geoRestrictions.allowedCountries.length > 0) {
      const allowed = this.geoRestrictions.allowedCountries.includes(geo.country);
      return {
        allowed,
        reason: allowed ? 'Country is allowed' : 'Country not in allowed list',
        country: geo.country,
        city: geo.city,
        region: geo.region
      };
    }
    
    return {
      allowed: true,
      reason: 'No geo-restrictions apply',
      country: geo.country,
      city: geo.city,
      region: geo.region
    };
  }

  /**
   * Get geo information for IP
   * @param {string} ip - IP address
   * @returns {Object} Geo information
   */
  static async getGeoInfo(ip) {
    const geo = geoip.lookup(ip);
    
    if (!geo) {
      return {
        available: false,
        country: 'Unknown',
        city: 'Unknown',
        timezone: 'Unknown'
      };
    }
    
    return {
      available: true,
      country: geo.country,
      region: geo.region,
      city: geo.city,
      timezone: geo.timezone,
      coordinates: geo.ll
    };
  }

  /**
   * Detect proxy usage
   * @param {string} ip - IP address
   * @param {Object} req - Express request
   * @returns {Object} Proxy detection result
   */
  static async detectProxy(ip, req) {
    const indicators = {
      headers: 0,
      patterns: 0,
      reputation: 0
    };
    
    // Check for proxy headers
    const proxyHeaders = [
      'x-forwarded-for',
      'x-real-ip',
      'x-originating-ip',
      'x-forwarded',
      'forwarded-for',
      'client-ip',
      'via',
      'x-proxy-id',
      'x-forwarded-server',
      'x-forwarded-host'
    ];
    
    proxyHeaders.forEach(header => {
      if (req.headers[header]) {
        indicators.headers++;
      }
    });
    
    // Check for multiple IPs in forwarded headers
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor && forwardedFor.split(',').length > 1) {
      indicators.patterns++;
    }
    
    // Check for known proxy/VPN ranges (simplified)
    const knownProxyRanges = [
      '10.0.0.0/8',     // Private range often used by VPNs
      '172.16.0.0/12',  // Private range
      '192.168.0.0/16'  // Private range
    ];
    
    if (knownProxyRanges.some(range => ipRangeCheck(ip, range))) {
      indicators.patterns++;
    }
    
    // Calculate proxy probability
    const totalIndicators = indicators.headers + indicators.patterns + indicators.reputation;
    const isProxy = totalIndicators >= 2;
    
    return {
      isProxy,
      confidence: Math.min(totalIndicators * 25, 100),
      indicators,
      type: isProxy ? 'suspected_proxy' : 'direct'
    };
  }

  /**
   * Check if IP is trusted
   * @param {string} ip - IP address
   * @returns {boolean} Is trusted
   */
  static isTrustedIP(ip) {
    // Internal/private IPs in production are not trusted
    if (config.app.env === 'production') {
      const privateRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8'
      ];
      
      return !privateRanges.some(range => ipRangeCheck(ip, range));
    }
    
    return true;
  }

  /**
   * Track IP usage patterns
   * @param {string} ip - IP address
   * @param {string} userId - User ID
   */
  static async trackIPUsage(ip, userId) {
    const key = `usage:${ip}`;
    const usage = this.suspiciousActivity.get(key) || {
      count: 0,
      users: new Set(),
      firstSeen: new Date(),
      lastSeen: new Date()
    };
    
    usage.count++;
    usage.lastSeen = new Date();
    if (userId) {
      usage.users.add(userId);
    }
    
    // Check for suspicious patterns
    if (usage.users.size > 3) {
      // Multiple users from same IP
      await this.handleSuspiciousActivity(ip, 'multiple_users', usage);
    }
    
    if (usage.count > 100 && (usage.lastSeen - usage.firstSeen) < 3600000) {
      // High frequency access
      await this.handleSuspiciousActivity(ip, 'high_frequency', usage);
    }
    
    this.suspiciousActivity.set(key, usage);
    
    // Clean old entries periodically
    if (Math.random() < 0.01) {
      this.cleanupOldEntries();
    }
  }

  /**
   * Handle unauthorized IP access attempt
   * @param {Object} context - Validation context
   */
  static async handleUnauthorizedIP(context) {
    const key = `unauthorized:${context.ip}`;
    const attempts = (this.suspiciousActivity.get(key) || 0) + 1;
    
    this.suspiciousActivity.set(key, attempts);
    
    // Auto-block after threshold
    if (attempts >= this.suspiciousThreshold) {
      await this.blockIP(context.ip, 'Exceeded unauthorized access attempts', this.blockDuration);
    }
    
    // Log security event
    await AuditService.log({
      type: 'admin_unauthorized_ip_access',
      action: 'block',
      category: 'security',
      result: 'blocked',
      severity: 'high',
      userId: context.userId,
      metadata: {
        ...context,
        attemptCount: attempts,
        autoBlocked: attempts >= this.suspiciousThreshold
      }
    });
  }

  /**
   * Handle geo-restriction violation
   * @param {Object} context - Validation context
   * @param {Object} geoValidation - Geo validation result
   */
  static async handleGeoRestriction(context, geoValidation) {
    await AuditService.log({
      type: 'admin_geo_restriction_violation',
      action: 'block',
      category: 'security',
      result: 'blocked',
      severity: 'medium',
      userId: context.userId,
      metadata: {
        ...context,
        ...geoValidation,
        restriction: this.geoRestrictions
      }
    });
  }

  /**
   * Handle proxy detection
   * @param {Object} context - Validation context
   * @param {Object} proxyDetection - Proxy detection result
   */
  static async handleProxyDetection(context, proxyDetection) {
    await AuditService.log({
      type: 'admin_proxy_access_detected',
      action: 'detect',
      category: 'security',
      result: 'detected',
      severity: 'medium',
      userId: context.userId,
      metadata: {
        ...context,
        ...proxyDetection
      }
    });
  }

  /**
   * Handle suspicious activity
   * @param {string} ip - IP address
   * @param {string} type - Activity type
   * @param {Object} details - Activity details
   */
  static async handleSuspiciousActivity(ip, type, details) {
    await AuditService.log({
      type: 'admin_suspicious_ip_activity',
      action: 'detect',
      category: 'security',
      result: 'detected',
      severity: 'high',
      metadata: {
        ip,
        activityType: type,
        details: {
          count: details.count,
          userCount: details.users?.size || 0,
          duration: details.lastSeen - details.firstSeen
        }
      }
    });
    
    // Auto-block for severe violations
    if (type === 'multiple_users' && details.users.size > 5) {
      await this.blockIP(ip, `Suspicious activity: ${type}`, this.blockDuration * 2);
    }
  }

  /**
   * Clean up old tracking entries
   */
  static cleanupOldEntries() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    // Clean suspicious activity
    for (const [key, value] of this.suspiciousActivity.entries()) {
      if (value.lastSeen && (now - value.lastSeen.getTime()) > maxAge) {
        this.suspiciousActivity.delete(key);
      }
    }
    
    // Clean temporary access
    for (const [key, value] of this.temporaryAccess.entries()) {
      if (value.expiresAt < new Date()) {
        this.temporaryAccess.delete(key);
      }
    }
  }

  /**
   * Get IP validation statistics
   * @returns {Object} Statistics
   */
  static getStatistics() {
    return {
      whitelistedIPs: this.dynamicWhitelist.size,
      temporaryAccess: this.temporaryAccess.size,
      blockedIPs: this.blockedIPs.size,
      suspiciousIPs: Array.from(this.suspiciousActivity.entries())
        .filter(([key]) => key.startsWith('unauthorized:')).length
    };
  }
}

// Initialize on module load
AdminIPValidator.initialize();

module.exports = AdminIPValidator;