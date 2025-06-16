// server/shared/security/passport/strategies/local-strategy.js
/**
 * @file Local Authentication Strategy
 * @description Email and password authentication using Passport Local Strategy
 * @version 3.0.0
 */

const LocalStrategy = require('passport-local').Strategy;

const AuthService = require('../../../auth/services/auth-service');
const config = require('../../../config/config');
const UserService = require('../../../users/services/user-service');
const { AuthenticationError, ValidationError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../services/audit-service');

/**
 * Local Authentication Strategy Class
 * @class LocalAuthStrategy
 */
class LocalAuthStrategy {
  constructor() {
    this.strategyOptions = {
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true
    };
  }
  
  /**
   * Create and configure the local strategy
   * @returns {LocalStrategy} Configured passport strategy
   */
  async createStrategy() {
    return new LocalStrategy(this.strategyOptions, async (req, email, password, done) => {
      try {
        // Extract additional context from request
        const context = {
          ip: req.ip,
          userAgent: req.get('user-agent'),
          origin: req.get('origin'),
          deviceId: req.body.deviceId || req.get('x-device-id'),
          sessionData: req.session
        };
        
        // Validate input
        const validation = await this.validateInput(email, password);
        if (!validation.valid) {
          return done(null, false, { 
            message: validation.message,
            code: 'VALIDATION_ERROR'
          });
        }
        
        // Attempt authentication
        const result = await this.authenticateUser(email, password, context);
        
        if (!result.success) {
          return done(null, false, {
            message: result.message,
            code: result.code,
            remainingAttempts: result.remainingAttempts
          });
        }
        
        // Handle MFA if required
        if (result.requiresMFA) {
          return done(null, false, {
            message: 'Multi-factor authentication required',
            code: 'MFA_REQUIRED',
            userId: result.userId,
            mfaMethods: result.mfaMethods
          });
        }
        
        // Successful authentication
        done(null, result.user, {
          method: 'local',
          sessionId: result.sessionId
        });
        
      } catch (error) {
        logger.error('Local authentication error', { error, email });
        done(error);
      }
    });
  }
  
  /**
   * Validate authentication input
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Object} Validation result
   */
  async validateInput(email, password) {
    if (!email || !password) {
      return {
        valid: false,
        message: 'Email and password are required'
      };
    }
    
    // Email format validation
    if (!config.constants.REGEX.EMAIL.test(email)) {
      return {
        valid: false,
        message: 'Invalid email format'
      };
    }
    
    // Password basic validation
    if (password.length < 6) {
      return {
        valid: false,
        message: 'Invalid credentials'
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Authenticate user with email and password
   * @param {string} email - User email
   * @param {string} password - User password
   * @param {Object} context - Authentication context
   * @returns {Promise<Object>} Authentication result
   */
  async authenticateUser(email, password, context) {
    try {
      // Get user with auth record
      const userWithAuth = await UserService.getUserWithAuth(email);
      
      if (!userWithAuth) {
        // Log failed attempt
        await this.logFailedAttempt(null, email, context, 'User not found');
        
        return {
          success: false,
          message: 'Invalid email or password',
          code: 'INVALID_CREDENTIALS'
        };
      }
      
      const { user, auth } = userWithAuth;
      
      // Check if local auth is enabled
      if (!auth.authMethods.local.password) {
        return {
          success: false,
          message: 'Password authentication not enabled for this account',
          code: 'AUTH_METHOD_NOT_ENABLED'
        };
      }
      
      // Check account status
      const accountCheck = await this.checkAccountStatus(user, auth);
      if (!accountCheck.valid) {
        return accountCheck;
      }
      
      // Verify password
      const isPasswordValid = await auth.verifyPassword(password);
      
      if (!isPasswordValid) {
        // Record failed attempt
        await this.handleFailedLogin(user, auth, context);
        
        const remainingAttempts = config.security.maxLoginAttempts - auth.security.loginAttempts.count;
        
        return {
          success: false,
          message: 'Invalid email or password',
          code: 'INVALID_CREDENTIALS',
          remainingAttempts: remainingAttempts > 0 ? remainingAttempts : undefined
        };
      }
      
      // Check if password change is required
      if (this.isPasswordChangeRequired(auth)) {
        return {
          success: false,
          message: 'Password change required',
          code: 'PASSWORD_CHANGE_REQUIRED',
          userId: user._id
        };
      }
      
      // Check if email verification is required
      if (config.features.emailVerification && !auth.authMethods.local.isVerified) {
        return {
          success: false,
          message: 'Email verification required',
          code: 'EMAIL_NOT_VERIFIED',
          userId: user._id
        };
      }
      
      // Check if MFA is required
      if (auth.isMfaEnabled) {
        return {
          success: false,
          requiresMFA: true,
          userId: user._id,
          mfaMethods: auth.mfa.methods
            .filter(m => m.enabled)
            .map(m => ({ type: m.type, isPrimary: m.isPrimary }))
        };
      }
      
      // Successful authentication - create session
      const sessionResult = await this.createUserSession(user, auth, context);
      
      return {
        success: true,
        user: sessionResult.user,
        sessionId: sessionResult.sessionId
      };
      
    } catch (error) {
      logger.error('Authentication service error', { error, email });
      throw error;
    }
  }
  
  /**
   * Check account status
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @returns {Object} Account status check result
   */
  async checkAccountStatus(user, auth) {
    // Check if account is active
    if (!user.active) {
      return {
        valid: false,
        success: false,
        message: 'Account is inactive',
        code: 'ACCOUNT_INACTIVE'
      };
    }
    
    // Check if account is suspended
    if (user.status === 'suspended') {
      return {
        valid: false,
        success: false,
        message: 'Account has been suspended',
        code: 'ACCOUNT_SUSPENDED'
      };
    }
    
    // Check if account is locked
    if (auth.isLocked()) {
      const lockExpiry = auth.security.loginAttempts.lockedUntil;
      const minutesRemaining = Math.ceil((lockExpiry - new Date()) / 60000);
      
      return {
        valid: false,
        success: false,
        message: `Account is locked. Try again in ${minutesRemaining} minutes`,
        code: 'ACCOUNT_LOCKED',
        lockedUntil: lockExpiry
      };
    }
    
    // Check organization status if applicable
    if (user.organization?.current) {
      const orgCheck = await this.checkOrganizationStatus(user.organization.current);
      if (!orgCheck.valid) {
        return orgCheck;
      }
    }
    
    return { valid: true };
  }
  
  /**
   * Check organization status
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Organization status check result
   */
  async checkOrganizationStatus(organizationId) {
    // This would check organization subscription, status, etc.
    // Placeholder implementation
    return { valid: true };
  }
  
  /**
   * Check if password change is required
   * @param {Object} auth - Auth object
   * @returns {boolean} Password change required
   */
  isPasswordChangeRequired(auth) {
    // Check if password has expired
    if (auth.security.passwordPolicy.expiryDays) {
      const lastChange = auth.activity.lastPasswordChange || auth.createdAt;
      const daysSinceChange = Math.floor((new Date() - lastChange) / (1000 * 60 * 60 * 24));
      
      if (daysSinceChange > auth.security.passwordPolicy.expiryDays) {
        return true;
      }
    }
    
    // Check if admin forced password change
    if (auth.security.requirePasswordChange) {
      return true;
    }
    
    return false;
  }
  
  /**
   * Handle failed login attempt
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @param {Object} context - Request context
   */
  async handleFailedLogin(user, auth, context) {
    try {
      // Add login attempt
      auth.addLoginAttempt(false);
      
      // Add to login history
      auth.activity.loginHistory.push({
        timestamp: new Date(),
        ip: context.ip,
        userAgent: context.userAgent,
        method: 'local',
        success: false
      });
      
      // Check for suspicious activity
      await this.checkSuspiciousActivity(auth, context);
      
      await auth.save();
      
      // Audit log
      await AuditService.log({
        type: 'login_failed',
        action: 'authenticate',
        category: 'authentication',
        result: 'failure',
        userId: user._id,
        target: {
          type: 'user',
          id: user._id.toString()
        },
        metadata: {
          ...context,
          method: 'local',
          reason: 'Invalid password'
        }
      });
      
    } catch (error) {
      logger.error('Failed to record failed login', { error, userId: user._id });
    }
  }
  
  /**
   * Check for suspicious activity
   * @param {Object} auth - Auth object
   * @param {Object} context - Request context
   */
  async checkSuspiciousActivity(auth, context) {
    // Check for multiple failed attempts in short time
    const recentFailures = auth.activity.loginHistory
      .filter(h => !h.success && h.timestamp > new Date(Date.now() - 3600000))
      .length;
    
    if (recentFailures >= 5) {
      auth.recordSuspiciousActivity('multiple_failed_attempts', {
        count: recentFailures,
        ip: context.ip,
        userAgent: context.userAgent
      });
    }
    
    // Check for unusual location
    const lastSuccessfulLogin = auth.activity.loginHistory
      .filter(h => h.success)
      .sort((a, b) => b.timestamp - a.timestamp)[0];
    
    if (lastSuccessfulLogin && lastSuccessfulLogin.location) {
      // Location checking logic would go here
    }
  }
  
  /**
   * Create user session
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Session creation result
   */
  async createUserSession(user, auth, context) {
    try {
      // Clear failed login attempts
      auth.addLoginAttempt(true);
      
      // Create session
      const session = auth.addSession({
        deviceInfo: {
          userAgent: context.userAgent,
          platform: this.extractPlatform(context.userAgent),
          browser: this.extractBrowser(context.userAgent)
        },
        location: {
          ip: context.ip
        },
        expiresAt: new Date(Date.now() + config.auth.sessionDuration)
      });
      
      // Add to login history
      auth.activity.loginHistory.push({
        timestamp: new Date(),
        ip: context.ip,
        userAgent: context.userAgent,
        method: 'local',
        success: true,
        mfaUsed: false
      });
      
      // Check for trusted device
      const isTrustedDevice = await this.checkTrustedDevice(auth, context);
      
      await auth.save();
      
      // Update user last login
      user.activity.lastLogin = new Date();
      await user.save();
      
      // Audit log
      await AuditService.log({
        type: 'user_login',
        action: 'authenticate',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        target: {
          type: 'user',
          id: user._id.toString()
        },
        metadata: {
          ...context,
          method: 'local',
          sessionId: session.sessionId,
          trustedDevice: isTrustedDevice
        }
      });
      
      // Prepare user object for session
      const sessionUser = {
        _id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        organization: user.organization,
        userType: user.userType,
        status: user.status,
        sessionId: session.sessionId
      };
      
      return {
        user: sessionUser,
        sessionId: session.sessionId
      };
      
    } catch (error) {
      logger.error('Failed to create user session', { error, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Log failed authentication attempt
   * @param {string} userId - User ID (if known)
   * @param {string} email - Email attempted
   * @param {Object} context - Request context
   * @param {string} reason - Failure reason
   */
  async logFailedAttempt(userId, email, context, reason) {
    try {
      await AuditService.log({
        type: 'login_attempt_failed',
        action: 'authenticate',
        category: 'authentication',
        result: 'failure',
        severity: 'medium',
        userId: userId || null,
        target: {
          type: 'authentication',
          id: email
        },
        metadata: {
          ...context,
          method: 'local',
          reason
        }
      });
    } catch (error) {
      logger.error('Failed to log authentication attempt', { error });
    }
  }
  
  /**
   * Check if device is trusted
   * @param {Object} auth - Auth object
   * @param {Object} context - Request context
   * @returns {Promise<boolean>} Is trusted device
   */
  async checkTrustedDevice(auth, context) {
    // Generate device fingerprint
    const fingerprint = this.generateDeviceFingerprint(context);
    
    // Check against trusted devices
    const trustedDevice = auth.security.trustedDevices.find(device => 
      device.deviceFingerprint === fingerprint
    );
    
    if (trustedDevice) {
      trustedDevice.lastSeenAt = new Date();
      return true;
    }
    
    return false;
  }
  
  /**
   * Generate device fingerprint
   * @param {Object} context - Request context
   * @returns {string} Device fingerprint
   */
  generateDeviceFingerprint(context) {
    const crypto = require('crypto');
    const components = [
      context.userAgent,
      context.ip.split('.').slice(0, 3).join('.'), // Use /24 subnet
      context.deviceId || ''
    ];
    
    return crypto
      .createHash('sha256')
      .update(components.join('|'))
      .digest('hex');
  }
  
  /**
   * Extract platform from user agent
   * @param {string} userAgent - User agent string
   * @returns {string} Platform
   */
  extractPlatform(userAgent) {
    if (/Windows/.test(userAgent)) return 'Windows';
    if (/Mac/.test(userAgent)) return 'macOS';
    if (/Linux/.test(userAgent)) return 'Linux';
    if (/Android/.test(userAgent)) return 'Android';
    if (/iOS|iPhone|iPad/.test(userAgent)) return 'iOS';
    return 'Unknown';
  }
  
  /**
   * Extract browser from user agent
   * @param {string} userAgent - User agent string
   * @returns {string} Browser
   */
  extractBrowser(userAgent) {
    if (/Chrome/.test(userAgent) && !/Edge/.test(userAgent)) return 'Chrome';
    if (/Firefox/.test(userAgent)) return 'Firefox';
    if (/Safari/.test(userAgent) && !/Chrome/.test(userAgent)) return 'Safari';
    if (/Edge/.test(userAgent)) return 'Edge';
    if (/MSIE|Trident/.test(userAgent)) return 'Internet Explorer';
    return 'Unknown';
  }
}

module.exports = LocalAuthStrategy;