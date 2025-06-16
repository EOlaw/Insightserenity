// server/shared/security/passport/strategies/google-strategy.js
/**
 * @file Google OAuth Strategy
 * @description Google authentication using OAuth 2.0
 * @version 3.0.0
 */

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const AuthService = require('../../../auth/services/auth-service');
const config = require('../../../config/config');
const UserService = require('../../../users/services/user-service');
const { AuthenticationError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../services/audit-service');

/**
 * Google OAuth Strategy Class
 * @class GoogleAuthStrategy
 */
class GoogleAuthStrategy {
  constructor() {
    this.strategyOptions = {
      clientID: config.oauth.google.clientId,
      clientSecret: config.oauth.google.clientSecret,
      callbackURL: config.oauth.google.callbackUrl,
      scope: ['profile', 'email', 'openid'],
      passReqToCallback: true,
      state: true
    };
    
    this.profileFields = {
      id: 'id',
      displayName: 'displayName',
      firstName: 'name.givenName',
      lastName: 'name.familyName',
      email: 'emails[0].value',
      emailVerified: 'emails[0].verified',
      picture: 'photos[0].value',
      locale: 'locale',
      provider: 'provider'
    };
  }
  
  /**
   * Create and configure the Google strategy
   * @returns {GoogleStrategy} Configured passport strategy
   */
  async createStrategy() {
    return new GoogleStrategy(this.strategyOptions, async (req, accessToken, refreshToken, profile, done) => {
      try {
        // Extract authentication context
        const context = {
          ip: req.ip,
          userAgent: req.get('user-agent'),
          origin: req.get('origin'),
          organizationId: req.query.organizationId || req.session?.organizationContext
        };
        
        // Process Google profile
        const googleProfile = this.extractProfileData(profile);
        
        // Validate profile data
        const validation = await this.validateProfile(googleProfile);
        if (!validation.valid) {
          return done(null, false, {
            message: validation.message,
            code: 'INVALID_PROFILE'
          });
        }
        
        // Handle authentication
        const result = await this.handleGoogleAuth(googleProfile, {
          accessToken,
          refreshToken,
          context
        });
        
        if (!result.success) {
          return done(null, false, {
            message: result.message,
            code: result.code
          });
        }
        
        // Handle additional requirements
        if (result.requiresAdditionalInfo) {
          req.session.pendingAuth = {
            provider: 'google',
            profileId: googleProfile.id,
            profile: googleProfile,
            tokens: { accessToken, refreshToken }
          };
          
          return done(null, false, {
            message: 'Additional information required',
            code: 'ADDITIONAL_INFO_REQUIRED',
            redirect: '/auth/complete-profile'
          });
        }
        
        // Successful authentication
        done(null, result.user, {
          method: 'google',
          sessionId: result.sessionId,
          isNewUser: result.isNewUser
        });
        
      } catch (error) {
        logger.error('Google authentication error', { error, profileId: profile?.id });
        done(error);
      }
    });
  }
  
  /**
   * Extract profile data from Google profile
   * @param {Object} profile - Google profile object
   * @returns {Object} Extracted profile data
   */
  extractProfileData(profile) {
    const emails = profile.emails || [];
    const primaryEmail = emails.find(e => e.type === 'account') || emails[0];
    
    return {
      id: profile.id,
      email: primaryEmail?.value,
      emailVerified: primaryEmail?.verified || false,
      displayName: profile.displayName,
      firstName: profile.name?.givenName,
      lastName: profile.name?.familyName,
      picture: profile.photos?.[0]?.value,
      locale: profile._json?.locale,
      provider: 'google',
      raw: profile._json
    };
  }
  
  /**
   * Validate Google profile
   * @param {Object} profile - Extracted profile data
   * @returns {Object} Validation result
   */
  async validateProfile(profile) {
    if (!profile.id) {
      return {
        valid: false,
        message: 'Google ID is required'
      };
    }
    
    if (!profile.email) {
      return {
        valid: false,
        message: 'Email is required for authentication'
      };
    }
    
    // Validate email format
    if (!config.constants.REGEX.EMAIL.test(profile.email)) {
      return {
        valid: false,
        message: 'Invalid email format from Google'
      };
    }
    
    // Check if email domain is allowed
    if (config.oauth.google.allowedDomains?.length > 0) {
      const domain = profile.email.split('@')[1];
      if (!config.oauth.google.allowedDomains.includes(domain)) {
        return {
          valid: false,
          message: 'Email domain not allowed'
        };
      }
    }
    
    return { valid: true };
  }
  
  /**
   * Handle Google authentication
   * @param {Object} profile - Google profile data
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Authentication result
   */
  async handleGoogleAuth(profile, authData) {
    try {
      // Check for existing user
      let userWithAuth = await UserService.getUserByOAuthProvider('google', profile.id);
      
      if (!userWithAuth) {
        // Check if user exists with same email
        userWithAuth = await UserService.getUserWithAuth(profile.email);
        
        if (userWithAuth) {
          // Link Google account to existing user
          return await this.linkGoogleAccount(userWithAuth, profile, authData);
        } else {
          // Create new user
          return await this.createGoogleUser(profile, authData);
        }
      } else {
        // Existing Google user - update and login
        return await this.loginGoogleUser(userWithAuth, profile, authData);
      }
      
    } catch (error) {
      logger.error('Google auth handling error', { error, profileId: profile.id });
      throw error;
    }
  }
  
  /**
   * Link Google account to existing user
   * @param {Object} userWithAuth - Existing user with auth
   * @param {Object} profile - Google profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Link result
   */
  async linkGoogleAccount(userWithAuth, profile, authData) {
    const { user, auth } = userWithAuth;
    
    // Check if account linking is allowed
    if (!config.oauth.allowAccountLinking) {
      return {
        success: false,
        message: 'An account with this email already exists. Please login with your password.',
        code: 'ACCOUNT_EXISTS'
      };
    }
    
    // Check account status
    const accountCheck = await this.checkAccountStatus(user, auth);
    if (!accountCheck.valid) {
      return accountCheck;
    }
    
    // Update auth record with Google info
    auth.authMethods.oauth.google = {
      id: profile.id,
      email: profile.email,
      displayName: profile.displayName,
      picture: profile.picture,
      accessToken: authData.accessToken,
      refreshToken: authData.refreshToken,
      tokenExpiry: new Date(Date.now() + 3600000) // 1 hour
    };
    
    // If email wasn't verified, mark it as verified via Google
    if (!auth.authMethods.local.isVerified && profile.emailVerified) {
      auth.authMethods.local.isVerified = true;
      auth.authMethods.local.verificationToken = undefined;
      auth.authMethods.local.verificationExpiry = undefined;
    }
    
    // Create session
    const session = auth.addSession({
      deviceInfo: {
        userAgent: authData.context.userAgent,
        platform: this.extractPlatform(authData.context.userAgent),
        browser: this.extractBrowser(authData.context.userAgent)
      },
      location: {
        ip: authData.context.ip
      },
      expiresAt: new Date(Date.now() + config.auth.sessionDuration)
    });
    
    // Add login history
    auth.activity.loginHistory.push({
      timestamp: new Date(),
      ip: authData.context.ip,
      userAgent: authData.context.userAgent,
      method: 'google',
      success: true
    });
    
    await auth.save();
    
    // Update user profile if needed
    if (!user.profile.avatar && profile.picture) {
      user.profile.avatar = profile.picture;
    }
    
    user.activity.lastLogin = new Date();
    await user.save();
    
    // Audit log
    await AuditService.log({
      type: 'oauth_account_linked',
      action: 'link_account',
      category: 'authentication',
      result: 'success',
      userId: user._id,
      target: {
        type: 'oauth_provider',
        id: 'google'
      },
      metadata: {
        ...authData.context,
        provider: 'google',
        googleId: profile.id
      }
    });
    
    return {
      success: true,
      user: this.prepareUserObject(user, session.sessionId),
      sessionId: session.sessionId,
      isNewUser: false
    };
  }
  
  /**
   * Create new user with Google account
   * @param {Object} profile - Google profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Creation result
   */
  async createGoogleUser(profile, authData) {
    // Check if registration is allowed
    if (!config.oauth.google.allowRegistration) {
      return {
        success: false,
        message: 'Registration with Google is not allowed',
        code: 'REGISTRATION_DISABLED'
      };
    }
    
    // Check if additional info is required
    const requiredFields = this.getRequiredFieldsForRegistration();
    const missingFields = requiredFields.filter(field => !profile[field]);
    
    if (missingFields.length > 0) {
      return {
        success: false,
        requiresAdditionalInfo: true,
        missingFields,
        profile
      };
    }
    
    // Create user data
    const userData = {
      email: profile.email,
      firstName: profile.firstName || profile.displayName?.split(' ')[0],
      lastName: profile.lastName || profile.displayName?.split(' ').slice(1).join(' '),
      profile: {
        displayName: profile.displayName,
        avatar: profile.picture,
        bio: {
          short: `Joined via Google`
        }
      },
      preferences: {
        language: profile.locale?.split('-')[0] || 'en',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      userType: 'hosted_org_user', // Default type
      role: {
        primary: 'prospect' // Default role
      },
      status: 'active',
      isEmailVerified: profile.emailVerified
    };
    
    // Handle organization context
    if (authData.context.organizationId) {
      userData.organization = {
        current: authData.context.organizationId,
        organizations: [authData.context.organizationId]
      };
    }
    
    // Create user and auth records
    const result = await UserService.createUserWithOAuth(userData, {
      provider: 'google',
      profileId: profile.id,
      profile: {
        id: profile.id,
        email: profile.email,
        displayName: profile.displayName,
        picture: profile.picture,
        accessToken: authData.accessToken,
        refreshToken: authData.refreshToken
      }
    }, authData.context);
    
    if (!result.success) {
      return result;
    }
    
    // Create session
    const { user, auth } = result;
    const session = auth.addSession({
      deviceInfo: {
        userAgent: authData.context.userAgent,
        platform: this.extractPlatform(authData.context.userAgent),
        browser: this.extractBrowser(authData.context.userAgent)
      },
      location: {
        ip: authData.context.ip
      },
      expiresAt: new Date(Date.now() + config.auth.sessionDuration)
    });
    
    await auth.save();
    
    // Send welcome email
    await this.sendWelcomeEmail(user, 'google');
    
    // Audit log
    await AuditService.log({
      type: 'user_registration',
      action: 'register',
      category: 'authentication',
      result: 'success',
      userId: user._id,
      target: {
        type: 'user',
        id: user._id.toString()
      },
      metadata: {
        ...authData.context,
        method: 'google',
        provider: 'google',
        autoCreated: true
      }
    });
    
    return {
      success: true,
      user: this.prepareUserObject(user, session.sessionId),
      sessionId: session.sessionId,
      isNewUser: true
    };
  }
  
  /**
   * Login existing Google user
   * @param {Object} userWithAuth - User with auth record
   * @param {Object} profile - Google profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Login result
   */
  async loginGoogleUser(userWithAuth, profile, authData) {
    const { user, auth } = userWithAuth;
    
    // Check account status
    const accountCheck = await this.checkAccountStatus(user, auth);
    if (!accountCheck.valid) {
      return accountCheck;
    }
    
    // Update Google auth data
    const googleAuth = auth.authMethods.oauth.google;
    googleAuth.lastLogin = new Date();
    googleAuth.accessToken = authData.accessToken;
    if (authData.refreshToken) {
      googleAuth.refreshToken = authData.refreshToken;
    }
    googleAuth.tokenExpiry = new Date(Date.now() + 3600000);
    
    // Update profile data if changed
    if (profile.displayName !== googleAuth.displayName) {
      googleAuth.displayName = profile.displayName;
    }
    if (profile.picture !== googleAuth.picture) {
      googleAuth.picture = profile.picture;
      // Update user avatar if it's still the Google one
      if (user.profile.avatar === googleAuth.picture || !user.profile.avatar) {
        user.profile.avatar = profile.picture;
      }
    }
    
    // Create session
    const session = auth.addSession({
      deviceInfo: {
        userAgent: authData.context.userAgent,
        platform: this.extractPlatform(authData.context.userAgent),
        browser: this.extractBrowser(authData.context.userAgent)
      },
      location: {
        ip: authData.context.ip
      },
      expiresAt: new Date(Date.now() + config.auth.sessionDuration)
    });
    
    // Add login history
    auth.activity.loginHistory.push({
      timestamp: new Date(),
      ip: authData.context.ip,
      userAgent: authData.context.userAgent,
      method: 'google',
      success: true
    });
    
    // Clear any failed login attempts
    auth.security.loginAttempts.count = 0;
    auth.security.loginAttempts.lockedUntil = null;
    
    await auth.save();
    
    // Update user activity
    user.activity.lastLogin = new Date();
    await user.save();
    
    // Check for suspicious activity
    await this.checkLoginSecurity(auth, authData.context);
    
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
        ...authData.context,
        method: 'google',
        provider: 'google',
        sessionId: session.sessionId
      }
    });
    
    return {
      success: true,
      user: this.prepareUserObject(user, session.sessionId),
      sessionId: session.sessionId,
      isNewUser: false
    };
  }
  
  /**
   * Check account status
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @returns {Object} Status check result
   */
  async checkAccountStatus(user, auth) {
    if (!user.active) {
      return {
        valid: false,
        success: false,
        message: 'Account is inactive',
        code: 'ACCOUNT_INACTIVE'
      };
    }
    
    if (user.status === 'suspended') {
      return {
        valid: false,
        success: false,
        message: 'Account has been suspended',
        code: 'ACCOUNT_SUSPENDED'
      };
    }
    
    if (user.status === 'deleted') {
      return {
        valid: false,
        success: false,
        message: 'Account has been deleted',
        code: 'ACCOUNT_DELETED'
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Check login security
   * @param {Object} auth - Auth object
   * @param {Object} context - Login context
   */
  async checkLoginSecurity(auth, context) {
    // Check for unusual location
    const lastLogin = auth.activity.loginHistory
      .filter(h => h.success && h.method === 'google')
      .sort((a, b) => b.timestamp - a.timestamp)[1]; // Get second to last
    
    if (lastLogin && lastLogin.ip !== context.ip) {
      // Different IP - could be suspicious
      const ipDistance = this.calculateIPDistance(lastLogin.ip, context.ip);
      if (ipDistance > 100) { // Significant geographic distance
        auth.recordSuspiciousActivity('unusual_location', {
          previousIP: lastLogin.ip,
          currentIP: context.ip,
          method: 'google'
        });
      }
    }
  }
  
  /**
   * Get required fields for registration
   * @returns {Array} Required fields
   */
  getRequiredFieldsForRegistration() {
    // Can be configured based on business requirements
    return ['email', 'firstName', 'lastName'];
  }
  
  /**
   * Prepare user object for session
   * @param {Object} user - User document
   * @param {string} sessionId - Session ID
   * @returns {Object} Prepared user object
   */
  prepareUserObject(user, sessionId) {
    return {
      _id: user._id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      displayName: user.profile.displayName,
      avatar: user.profile.avatar,
      role: user.role,
      organization: user.organization,
      userType: user.userType,
      status: user.status,
      sessionId
    };
  }
  
  /**
   * Send welcome email
   * @param {Object} user - User object
   * @param {string} provider - OAuth provider
   */
  async sendWelcomeEmail(user, provider) {
    // This would integrate with your email service
    logger.info('Sending welcome email', {
      userId: user._id,
      email: user.email,
      provider
    });
  }
  
  /**
   * Calculate IP distance (simplified)
   * @param {string} ip1 - First IP
   * @param {string} ip2 - Second IP
   * @returns {number} Distance estimate
   */
  calculateIPDistance(ip1, ip2) {
    // Simplified implementation - in production would use GeoIP
    const parts1 = ip1.split('.');
    const parts2 = ip2.split('.');
    
    if (parts1[0] !== parts2[0]) return 1000; // Different country/region
    if (parts1[1] !== parts2[1]) return 500;  // Different state/area
    if (parts1[2] !== parts2[2]) return 100;  // Different city/locality
    return 10; // Same general area
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
    return 'Unknown';
  }
}

module.exports = GoogleAuthStrategy;