// server/admin/security-administration/middleware/threat-monitoring.js
/**
 * @file Threat Monitoring Middleware
 * @description Middleware for real-time threat monitoring and detection
 * @version 1.0.0
 */

const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');
const CacheService = require('../../../shared/utils/cache-service');
const ThreatDetection = require('../../../shared/security/models/threat-detection-model');
const ThreatEvent = require('../../../shared/security/models/threat-event-model');
const BlockedIP = require('../../../shared/security/models/blocked-ip-model');

/**
 * Threat Monitoring Middleware Class
 * @class ThreatMonitoringMiddleware
 */
class ThreatMonitoringMiddleware {
  /**
   * Monitor request patterns for threats
   */
  static monitorRequestPatterns = async (req, res, next) => {
    try {
      const clientIP = req.ip || req.connection.remoteAddress;
      const userAgent = req.headers['user-agent'];
      const path = req.path;
      const method = req.method;

      // Check if IP is already blocked
      const isBlocked = await this.checkBlockedIP(clientIP);
      if (isBlocked) {
        logger.warn('Blocked IP attempted access', {
          ip: clientIP,
          path,
          method,
          userAgent
        });
        
        // Record blocked attempt
        await this.recordBlockedAttempt(clientIP, req);
        
        return res.status(403).json({
          success: false,
          message: 'Access denied'
        });
      }

      // Monitor request rate
      const requestRate = await this.checkRequestRate(clientIP);
      if (requestRate.exceeded) {
        await this.handleRateLimitExceeded(clientIP, requestRate, req);
        
        return res.status(429).json({
          success: false,
          message: 'Too many requests'
        });
      }

      // Check for suspicious patterns
      const threatIndicators = await this.detectThreatPatterns(req);
      if (threatIndicators.length > 0) {
        await this.handleThreatDetection(threatIndicators, req);
      }

      // Log request for pattern analysis
      await this.logRequestPattern(req);

      next();
    } catch (error) {
      logger.error('Threat monitoring error', {
        error: error.message,
        ip: req.ip,
        path: req.path
      });
      next(); // Don't block on monitoring errors
    }
  };

  /**
   * Validate request integrity
   */
  static validateRequestIntegrity = async (req, res, next) => {
    try {
      // Check for SQL injection patterns
      if (this.detectSQLInjection(req)) {
        await this.recordThreatEvent('sql_injection', req);
        
        return res.status(400).json({
          success: false,
          message: 'Invalid request'
        });
      }

      // Check for XSS patterns
      if (this.detectXSS(req)) {
        await this.recordThreatEvent('xss_attempt', req);
        
        return res.status(400).json({
          success: false,
          message: 'Invalid request'
        });
      }

      // Check for path traversal
      if (this.detectPathTraversal(req)) {
        await this.recordThreatEvent('path_traversal', req);
        
        return res.status(400).json({
          success: false,
          message: 'Invalid request'
        });
      }

      // Validate request headers
      const headerValidation = this.validateHeaders(req);
      if (!headerValidation.valid) {
        await this.recordThreatEvent('suspicious_headers', req, {
          reason: headerValidation.reason
        });
        
        return res.status(400).json({
          success: false,
          message: 'Invalid request headers'
        });
      }

      next();
    } catch (error) {
      logger.error('Request integrity validation error', {
        error: error.message,
        path: req.path
      });
      next();
    }
  };

  /**
   * Monitor authentication attempts
   */
  static monitorAuthAttempts = async (req, res, next) => {
    try {
      const clientIP = req.ip || req.connection.remoteAddress;
      const isAuthEndpoint = req.path.includes('/auth') || req.path.includes('/login');

      if (!isAuthEndpoint) {
        return next();
      }

      // Track failed auth attempts
      res.on('finish', async () => {
        if (res.statusCode === 401 || res.statusCode === 403) {
          await this.recordFailedAuth(clientIP, req);

          // Check if threshold exceeded
          const failedAttempts = await this.getFailedAuthCount(clientIP);
          if (failedAttempts >= 5) {
            await this.handleBruteForceDetection(clientIP, req);
          }
        } else if (res.statusCode === 200) {
          // Clear failed attempts on successful auth
          await this.clearFailedAuthAttempts(clientIP);
        }
      });

      next();
    } catch (error) {
      logger.error('Auth monitoring error', {
        error: error.message,
        path: req.path
      });
      next();
    }
  };

  /**
   * Monitor API abuse patterns
   */
  static monitorAPIAbuse = async (req, res, next) => {
    try {
      const clientIP = req.ip || req.connection.remoteAddress;
      const adminUser = req.adminUser;

      // Check for data scraping patterns
      const scrapingDetected = await this.detectDataScraping(clientIP, req);
      if (scrapingDetected) {
        await this.recordThreatEvent('data_scraping', req);
        
        return res.status(429).json({
          success: false,
          message: 'Unusual activity detected'
        });
      }

      // Monitor bulk operations
      if (req.path.includes('/bulk') || req.body?.ids?.length > 100) {
        await this.monitorBulkOperation(adminUser, req);
      }

      // Check for automated behavior
      const automationScore = await this.calculateAutomationScore(clientIP, req);
      if (automationScore > 0.8) {
        await this.recordThreatEvent('automated_behavior', req, {
          score: automationScore
        });
      }

      next();
    } catch (error) {
      logger.error('API abuse monitoring error', {
        error: error.message,
        path: req.path
      });
      next();
    }
  };

  /**
   * Real-time threat analysis
   */
  static analyzeThreatInRealTime = async (req, res, next) => {
    try {
      const clientIP = req.ip || req.connection.remoteAddress;

      // Get active threat rules
      const activeRules = await this.getActiveThreatRules();

      // Evaluate request against rules
      for (const rule of activeRules) {
        const matches = await this.evaluateRule(rule, req);
        
        if (matches) {
          const response = await this.executeRuleActions(rule, req);
          
          if (response.block) {
            return res.status(response.statusCode || 403).json({
              success: false,
              message: response.message || 'Access denied'
            });
          }
        }
      }

      // Update threat intelligence
      await this.updateThreatIntelligence(req);

      next();
    } catch (error) {
      logger.error('Real-time threat analysis error', {
        error: error.message,
        path: req.path
      });
      next();
    }
  };

  // Helper methods

  /**
   * Check if IP is blocked
   * @private
   */
  static async checkBlockedIP(ip) {
    try {
      const cacheKey = `blocked:ip:${ip}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached !== null) {
        return cached;
      }

      const blocked = await BlockedIP.findOne({
        ip,
        active: true,
        $or: [
          { permanent: true },
          { expiresAt: { $gt: new Date() } }
        ]
      });

      const isBlocked = !!blocked;
      await CacheService.set(cacheKey, isBlocked, 300); // 5 minutes cache
      
      return isBlocked;
    } catch (error) {
      logger.error('Error checking blocked IP', { error: error.message, ip });
      return false;
    }
  }

  /**
   * Check request rate
   * @private
   */
  static async checkRequestRate(ip) {
    try {
      const windowMs = 60000; // 1 minute
      const maxRequests = 100;
      
      const key = `rate:${ip}:${Math.floor(Date.now() / windowMs)}`;
      const count = await CacheService.increment(key);
      
      if (count === 1) {
        await CacheService.expire(key, 60); // Expire after 1 minute
      }

      return {
        count,
        exceeded: count > maxRequests,
        limit: maxRequests,
        window: windowMs
      };
    } catch (error) {
      logger.error('Error checking request rate', { error: error.message, ip });
      return { count: 0, exceeded: false };
    }
  }

  /**
   * Detect threat patterns
   * @private
   */
  static async detectThreatPatterns(req) {
    const indicators = [];

    // Check for suspicious user agents
    const userAgent = req.headers['user-agent'] || '';
    if (this.isSuspiciousUserAgent(userAgent)) {
      indicators.push({
        type: 'suspicious_user_agent',
        value: userAgent,
        confidence: 0.7
      });
    }

    // Check for directory traversal attempts
    if (req.url.includes('../') || req.url.includes('..\\')) {
      indicators.push({
        type: 'directory_traversal',
        value: req.url,
        confidence: 0.9
      });
    }

    // Check for command injection patterns
    const params = { ...req.query, ...req.body };
    if (this.detectCommandInjection(params)) {
      indicators.push({
        type: 'command_injection',
        value: JSON.stringify(params),
        confidence: 0.8
      });
    }

    return indicators;
  }

  /**
   * Detect SQL injection patterns
   * @private
   */
  static detectSQLInjection(req) {
    const sqlPatterns = [
      /(\b(union|select|insert|update|delete|drop|create)\b.*\b(from|where|table)\b)/i,
      /(\b(or|and)\b\s*[\'"\d]+\s*=\s*[\'"\d]+)/i,
      /(\'|\")\s*;\s*(drop|delete|update|insert)/i,
      /\b(exec|execute)\s*\(/i
    ];

    const params = { ...req.query, ...req.body };
    const paramString = JSON.stringify(params);

    return sqlPatterns.some(pattern => pattern.test(paramString));
  }

  /**
   * Detect XSS patterns
   * @private
   */
  static detectXSS(req) {
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /<iframe[^>]*>.*?<\/iframe>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<img[^>]*onerror\s*=/gi
    ];

    const params = { ...req.query, ...req.body };
    const paramString = JSON.stringify(params);

    return xssPatterns.some(pattern => pattern.test(paramString));
  }

  /**
   * Detect path traversal
   * @private
   */
  static detectPathTraversal(req) {
    const pathPatterns = [
      /\.\.[\/\\]/,
      /%2e%2e[\/\\]/i,
      /\.\.%2f/i,
      /\.\.%5c/i
    ];

    return pathPatterns.some(pattern => pattern.test(req.url));
  }

  /**
   * Validate request headers
   * @private
   */
  static validateHeaders(req) {
    // Check for missing required headers
    if (!req.headers['user-agent']) {
      return { valid: false, reason: 'Missing user agent' };
    }

    // Check for suspicious header values
    const suspiciousHeaders = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip'];
    for (const header of suspiciousHeaders) {
      if (req.headers[header] && req.headers[header].split(',').length > 5) {
        return { valid: false, reason: 'Suspicious proxy chain' };
      }
    }

    return { valid: true };
  }

  /**
   * Record threat event
   * @private
   */
  static async recordThreatEvent(type, req, metadata = {}) {
    try {
      const clientIP = req.ip || req.connection.remoteAddress;
      
      await ThreatEvent.create({
        type,
        source: clientIP,
        target: req.path,
        severity: this.getThreatSeverity(type),
        metadata: {
          ...metadata,
          userAgent: req.headers['user-agent'],
          method: req.method,
          referer: req.headers.referer
        },
        timestamp: new Date()
      });

      // Track in admin activity
      if (req.adminUser) {
        await AdminActivityTracker.track(req.adminUser, 'threat.detected', {
          type,
          severity: this.getThreatSeverity(type)
        });
      }
    } catch (error) {
      logger.error('Error recording threat event', {
        error: error.message,
        type,
        ip: req.ip
      });
    }
  }

  /**
   * Get threat severity
   * @private
   */
  static getThreatSeverity(type) {
    const severityMap = {
      sql_injection: 'high',
      xss_attempt: 'high',
      path_traversal: 'high',
      command_injection: 'critical',
      brute_force: 'high',
      data_scraping: 'medium',
      automated_behavior: 'low',
      suspicious_headers: 'low',
      suspicious_user_agent: 'low'
    };

    return severityMap[type] || 'medium';
  }

  /**
   * Handle rate limit exceeded
   * @private
   */
  static async handleRateLimitExceeded(ip, rateInfo, req) {
    await this.recordThreatEvent('rate_limit_exceeded', req, {
      count: rateInfo.count,
      limit: rateInfo.limit
    });

    // Consider temporary blocking for severe violations
    if (rateInfo.count > rateInfo.limit * 2) {
      await this.temporaryBlockIP(ip, 3600000); // 1 hour
    }
  }

  /**
   * Temporary block IP
   * @private
   */
  static async temporaryBlockIP(ip, duration) {
    try {
      await BlockedIP.create({
        ip,
        reason: 'Automated rate limit violation',
        duration,
        expiresAt: new Date(Date.now() + duration),
        permanent: false,
        active: true,
        blockedBy: 'system'
      });

      // Clear cache
      await CacheService.delete(`blocked:ip:${ip}`);
    } catch (error) {
      logger.error('Error temporarily blocking IP', {
        error: error.message,
        ip
      });
    }
  }

  /**
   * Handle threat detection
   * @private
   */
  static async handleThreatDetection(indicators, req) {
    for (const indicator of indicators) {
      await this.recordThreatEvent(indicator.type, req, {
        indicator: indicator.value,
        confidence: indicator.confidence
      });
    }

    // Aggregate threat score
    const threatScore = indicators.reduce((sum, ind) => sum + ind.confidence, 0) / indicators.length;
    
    if (threatScore > 0.8) {
      const clientIP = req.ip || req.connection.remoteAddress;
      await this.temporaryBlockIP(clientIP, 7200000); // 2 hours
    }
  }

  /**
   * Log request pattern
   * @private
   */
  static async logRequestPattern(req) {
    try {
      const pattern = {
        ip: req.ip || req.connection.remoteAddress,
        path: req.path,
        method: req.method,
        timestamp: Date.now()
      };

      const key = `pattern:${pattern.ip}:${Math.floor(Date.now() / 60000)}`;
      await CacheService.rpush(key, JSON.stringify(pattern));
      await CacheService.expire(key, 3600); // 1 hour
    } catch (error) {
      // Silent fail for pattern logging
    }
  }

  /**
   * Check if user agent is suspicious
   * @private
   */
  static isSuspiciousUserAgent(userAgent) {
    const suspiciousPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /java/i
    ];

    // Allow legitimate bots
    const allowedBots = [
      /googlebot/i,
      /bingbot/i,
      /slackbot/i
    ];

    if (allowedBots.some(pattern => pattern.test(userAgent))) {
      return false;
    }

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  /**
   * Detect command injection
   * @private
   */
  static detectCommandInjection(params) {
    const commandPatterns = [
      /;\s*(ls|cat|rm|mv|cp|wget|curl|bash|sh)\s/i,
      /\|\s*(ls|cat|rm|mv|cp|wget|curl|bash|sh)\s/i,
      /`[^`]*`/,
      /\$\([^)]+\)/
    ];

    const paramString = JSON.stringify(params);
    return commandPatterns.some(pattern => pattern.test(paramString));
  }

  /**
   * Get failed auth count
   * @private
   */
  static async getFailedAuthCount(ip) {
    try {
      const key = `auth:failed:${ip}`;
      const count = await CacheService.get(key) || 0;
      return parseInt(count);
    } catch (error) {
      return 0;
    }
  }

  /**
   * Record failed authentication
   * @private
   */
  static async recordFailedAuth(ip, req) {
    try {
      const key = `auth:failed:${ip}`;
      const count = await CacheService.increment(key);
      
      if (count === 1) {
        await CacheService.expire(key, 900); // 15 minutes
      }

      await this.recordThreatEvent('failed_auth', req, {
        attempt: count
      });
    } catch (error) {
      logger.error('Error recording failed auth', {
        error: error.message,
        ip
      });
    }
  }

  /**
   * Clear failed auth attempts
   * @private
   */
  static async clearFailedAuthAttempts(ip) {
    try {
      await CacheService.delete(`auth:failed:${ip}`);
    } catch (error) {
      // Silent fail
    }
  }

  /**
   * Handle brute force detection
   * @private
   */
  static async handleBruteForceDetection(ip, req) {
    await this.recordThreatEvent('brute_force', req);
    await this.temporaryBlockIP(ip, 3600000); // 1 hour block
  }

  /**
   * Detect data scraping
   * @private
   */
  static async detectDataScraping(ip, req) {
    try {
      // Check request frequency for data endpoints
      if (!req.path.includes('/api/admin/')) {
        return false;
      }

      const key = `scraping:${ip}:${Math.floor(Date.now() / 60000)}`;
      const requests = await CacheService.llen(key);

      return requests > 50; // More than 50 API requests per minute
    } catch (error) {
      return false;
    }
  }

  /**
   * Monitor bulk operation
   * @private
   */
  static async monitorBulkOperation(adminUser, req) {
    const operationSize = req.body?.ids?.length || 0;
    
    if (operationSize > 1000) {
      await this.recordThreatEvent('excessive_bulk_operation', req, {
        size: operationSize,
        adminId: adminUser?.id
      });
    }
  }

  /**
   * Calculate automation score
   * @private
   */
  static async calculateAutomationScore(ip, req) {
    try {
      const key = `behavior:${ip}`;
      const behaviorData = await CacheService.get(key) || {
        requests: [],
        patterns: {}
      };

      // Add current request
      behaviorData.requests.push({
        time: Date.now(),
        path: req.path,
        method: req.method
      });

      // Keep only last 100 requests
      if (behaviorData.requests.length > 100) {
        behaviorData.requests = behaviorData.requests.slice(-100);
      }

      // Calculate intervals between requests
      const intervals = [];
      for (let i = 1; i < behaviorData.requests.length; i++) {
        intervals.push(behaviorData.requests[i].time - behaviorData.requests[i-1].time);
      }

      // Calculate automation indicators
      let score = 0;

      // Check for consistent intervals (bot-like behavior)
      if (intervals.length > 10) {
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, int) => sum + Math.pow(int - avgInterval, 2), 0) / intervals.length;
        
        if (variance < 1000) { // Very consistent timing
          score += 0.4;
        }
      }

      // Check for repetitive patterns
      const pathCounts = {};
      behaviorData.requests.forEach(req => {
        pathCounts[req.path] = (pathCounts[req.path] || 0) + 1;
      });

      const repetitionRatio = Math.max(...Object.values(pathCounts)) / behaviorData.requests.length;
      if (repetitionRatio > 0.7) {
        score += 0.3;
      }

      // Check request rate
      const recentRequests = behaviorData.requests.filter(r => Date.now() - r.time < 60000);
      if (recentRequests.length > 30) {
        score += 0.3;
      }

      await CacheService.set(key, behaviorData, 1800); // 30 minutes

      return Math.min(score, 1);
    } catch (error) {
      return 0;
    }
  }

  /**
   * Get active threat rules
   * @private
   */
  static async getActiveThreatRules() {
    try {
      const cacheKey = 'threat:rules:active';
      const cached = await CacheService.get(cacheKey);
      
      if (cached) {
        return cached;
      }

      const rules = await ThreatDetection.find({
        enabled: true,
        type: { $ne: 'automated_response' }
      })
        .sort({ priority: -1 })
        .lean();

      await CacheService.set(cacheKey, rules, 300); // 5 minutes
      return rules;
    } catch (error) {
      logger.error('Error getting active threat rules', {
        error: error.message
      });
      return [];
    }
  }

  /**
   * Evaluate rule against request
   * @private
   */
  static async evaluateRule(rule, req) {
    try {
      // Simple condition matching
      // In production, this would be more sophisticated
      for (const [key, condition] of Object.entries(rule.conditions)) {
        switch (condition.type) {
          case 'match':
            if (!this.evaluateMatchCondition(condition, req)) {
              return false;
            }
            break;
          case 'threshold':
            if (!await this.evaluateThresholdCondition(condition, req)) {
              return false;
            }
            break;
          // Add more condition types as needed
        }
      }

      return true;
    } catch (error) {
      logger.error('Error evaluating rule', {
        error: error.message,
        ruleId: rule._id
      });
      return false;
    }
  }

  /**
   * Evaluate match condition
   * @private
   */
  static evaluateMatchCondition(condition, req) {
    const value = this.getRequestValue(condition.field, req);
    
    switch (condition.operator) {
      case 'equals':
        return value === condition.value;
      case 'contains':
        return value && value.includes(condition.value);
      case 'regex':
        return new RegExp(condition.value).test(value);
      default:
        return false;
    }
  }

  /**
   * Get request value by field
   * @private
   */
  static getRequestValue(field, req) {
    switch (field) {
      case 'ip':
        return req.ip || req.connection.remoteAddress;
      case 'path':
        return req.path;
      case 'method':
        return req.method;
      case 'user_agent':
        return req.headers['user-agent'];
      default:
        return null;
    }
  }

  /**
   * Execute rule actions
   * @private
   */
  static async executeRuleActions(rule, req) {
    const response = {
      block: false,
      statusCode: null,
      message: null
    };

    for (const action of rule.actions) {
      switch (action.type) {
        case 'block':
          response.block = true;
          response.statusCode = action.statusCode || 403;
          response.message = action.message || 'Access denied';
          break;
        
        case 'alert':
          await this.sendThreatAlert(rule, req, action);
          break;
        
        case 'log':
          await this.recordThreatEvent(rule.name, req, {
            ruleId: rule._id,
            severity: rule.severity
          });
          break;
      }
    }

    return response;
  }

  /**
   * Send threat alert
   * @private
   */
  static async sendThreatAlert(rule, req, action) {
    try {
      // In production, this would send actual alerts
      logger.warn('Threat alert triggered', {
        rule: rule.name,
        ip: req.ip,
        path: req.path,
        severity: rule.severity
      });
    } catch (error) {
      logger.error('Error sending threat alert', {
        error: error.message,
        ruleId: rule._id
      });
    }
  }

  /**
   * Update threat intelligence
   * @private
   */
  static async updateThreatIntelligence(req) {
    try {
      // In production, this would update threat intelligence data
      const ip = req.ip || req.connection.remoteAddress;
      const key = `intel:${ip}`;
      
      await CacheService.hincrby(key, 'requests', 1);
      await CacheService.hset(key, 'lastSeen', Date.now());
      await CacheService.expire(key, 86400); // 24 hours
    } catch (error) {
      // Silent fail for intelligence updates
    }
  }

  /**
   * Evaluate threshold condition
   * @private
   */
  static async evaluateThresholdCondition(condition, req) {
    try {
      const ip = req.ip || req.connection.remoteAddress;
      const key = `threshold:${condition.metric}:${ip}`;
      const count = await CacheService.get(key) || 0;
      
      return count >= condition.threshold;
    } catch (error) {
      return false;
    }
  }

  /**
   * Record blocked attempt
   * @private
   */
  static async recordBlockedAttempt(ip, req) {
    try {
      await this.recordThreatEvent('blocked_access_attempt', req, {
        blockedIP: ip
      });
    } catch (error) {
      logger.error('Error recording blocked attempt', {
        error: error.message,
        ip
      });
    }
  }
}

module.exports = ThreatMonitoringMiddleware;