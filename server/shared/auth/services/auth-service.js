// server/shared/auth/services/auth-service.js
/**
 * @file Authentication Service
 * @description Comprehensive authentication service handling all auth operations
 * @version 3.0.0
 */

const crypto = require('crypto');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');

const config = require('../../config/config');
const constants = require('../../config/constants');
const AuditService = require('../../security/services/audit-service');
const EncryptionService = require('../../security/services/encryption-service');
const TokenBlacklistService = require('../../security/services/token-blacklist-service');
const EmailService = require('../../services/email-service');
const User = require('../../users/models/user-model');
const { 
  AuthenticationError, 
  ValidationError, 
  NotFoundError,
  ConflictError 
} = require('../../utils/app-error');
const logger = require('../../utils/logger');
const Auth = require('../models/auth-model');

/**
 * Authentication Service Class
 * @class AuthService
 */
class AuthService {
  /**
   * Register new user with email/password - CORRECTED ROLE HANDLING
   * @param {Object} userData - User registration data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Registration result
   */
  static async register(userData, context) {
    try {
      const { email, password, firstName, lastName, organizationId, role } = userData;
      
      // Validate email format
      if (!constants.REGEX.EMAIL.test(email)) {
        throw new ValidationError('Invalid email format');
      }
      
      // Validate password strength
      const passwordValidation = this.validatePasswordStrength(password);
      if (!passwordValidation.valid) {
        throw new ValidationError(passwordValidation.message);
      }
      
      // Check if user already exists
      const existingUser = await User.findOne({ email: email.toLowerCase() });
      if (existingUser) {
        throw new ConflictError('User with this email already exists');
      }
      
      // Extract role value correctly - FIXED
      let primaryRole = 'prospect'; // Default role
      if (role) {
        if (typeof role === 'string') {
          primaryRole = role;
        } else if (role.primary) {
          primaryRole = role.primary;
        }
      }
      
      // Validate role against allowed values
      if (!constants.USER.ROLES_ENUM.includes(primaryRole)) {
        throw new ValidationError(`Invalid role: ${primaryRole}. Must be one of: ${constants.USER.ROLES_ENUM.join(', ')}`);
      }
      
      // Create user data with corrected role assignment
      const newUserData = {
        email: email.toLowerCase(),
        firstName,
        lastName,
        profile: {
          displayName: `${firstName} ${lastName}`.trim()
        },
        userType: organizationId ? 'hosted_org_user' : 'core_consultant',
        role: {
          primary: primaryRole  // Correctly assign string value to primary field
        },
        organization: organizationId ? {
          current: organizationId,
          organizations: [organizationId]
        } : undefined,
        status: 'pending', // Pending email verification
        preferences: {
          language: context.language || 'en',
          timezone: context.timezone || 'UTC'
        }
      };
      
      // Create user
      const user = await User.create(newUserData);
      
      // Create auth record
      const auth = new Auth({
        userId: user._id,
        authMethods: {
          local: {
            email: email.toLowerCase(),
            isVerified: false
          }
        },
        metadata: {
          createdBy: {
            userId: user._id,
            method: 'registration'
          },
          source: context.source || 'web'
        }
      });
      
      // Set password
      await auth.setPassword(password);
      
      // Generate verification token
      const verificationToken = auth.generateVerificationToken();
      
      await auth.save();
      
      // Send verification email
      await this.sendVerificationEmail(user, verificationToken, context);
      
      // Create initial session if auto-login is enabled
      let sessionData = null;
      if (config.features.autoLoginAfterRegistration) {
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
        
        await auth.save();
        
        const tokens = await this.generateTokens(user, session.sessionId);
        sessionData = {
          ...tokens,
          sessionId: session.sessionId
        };
      }
      
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
          ...context,
          email: user.email,
          role: user.role.primary,
          organizationId
        }
      });
      
      return {
        success: true,
        message: 'Registration successful. Please check your email to verify your account.',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role
        },
        session: sessionData
      };
      
    } catch (error) {
      logger.error('Registration error', { error, email: userData.email });
      
      // Audit failed registration
      await AuditService.log({
        type: 'registration_failed',
        action: 'register',
        category: 'authentication',
        result: 'failure',
        severity: 'medium',
        target: {
          type: 'registration',
          id: userData.email
        },
        metadata: {
          ...context,
          error: error.message
        }
      });
      
      throw error;
    }
  }
  
  /**
   * Login user with email/password
   * @param {Object} credentials - Login credentials
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Login result
   */
  static async login(credentials, context) {
    try {
      const { email, password, rememberMe, deviceId } = credentials;
      
      // Get user with auth
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        throw new AuthenticationError('Invalid email or password');
      }
      
      const auth = await Auth.findOne({ userId: user._id });
      if (!auth) {
        throw new AuthenticationError('Authentication record not found');
      }
      
      // Check if local auth is enabled
      if (!auth.authMethods.local.password) {
        throw new AuthenticationError('Password authentication not enabled for this account');
      }
      
      // Check account status
      if (!user.active) {
        throw new AuthenticationError('Account is inactive');
      }
      
      if (user.status === 'suspended') {
        throw new AuthenticationError('Account has been suspended');
      }
      
      // Check if account is locked
      if (auth.isLocked()) {
        const lockExpiry = auth.security.loginAttempts.lockedUntil;
        const minutesRemaining = Math.ceil((lockExpiry - new Date()) / 60000);
        throw new AuthenticationError(`Account is locked. Try again in ${minutesRemaining} minutes`);
      }
      
      // Verify password
      const isPasswordValid = await auth.verifyPassword(password);
      
      if (!isPasswordValid) {
        // Record failed attempt
        auth.addLoginAttempt(false);
        await auth.save();
        
        const remainingAttempts = config.security.maxLoginAttempts - auth.security.loginAttempts.count;
        
        throw new AuthenticationError(
          `Invalid email or password${remainingAttempts > 0 ? `. ${remainingAttempts} attempts remaining` : ''}`
        );
      }
      
      // Check if email verification is required
      // if (config.features.emailVerification && !auth.authMethods.local.isVerified) {
      //   throw new AuthenticationError('Please verify your email before logging in');
      // }

      // Check if email is verified
      if (!auth.authMethods.local.isVerified && !user.isEmailVerified) {
        // Log the failed login attempt due to unverified email
        auth.addLoginAttempt(false, 'email_not_verified');
        await auth.save();
        
        // Audit log
        await AuditService.log({
          type: 'login_blocked_unverified_email',
          action: 'login_attempt',
          category: 'authentication',
          result: 'blocked',
          userId: user._id,
          metadata: {
            ...context,
            reason: 'email_not_verified'
          }
        });
        
        // Return specific error with verification token option
        throw new AuthenticationError('Please verify your email address before logging in. Check your inbox or request a new verification email.', 403, {
          code: 'EMAIL_NOT_VERIFIED',
          needsEmailVerification: true,
          canResendVerification: true,
          email: user.email
        });
      }

      // Reset login attempts on successful password verification
      auth.resetLoginAttempts();
      
      // Check if password change is required
      if (this.isPasswordChangeRequired(auth)) {
        return {
          success: false,
          requiresPasswordChange: true,
          userId: user._id,
          message: 'Password change required'
        };
      }
      
      // Check if MFA is enabled
      if (auth.isMfaEnabled) {
        // Generate MFA challenge
        const mfaChallenge = await this.generateMfaChallenge(user._id, auth);
        
        return {
          success: false,
          requiresMfa: true,
          userId: user._id,
          challengeId: mfaChallenge.id,
          mfaMethods: auth.mfa.methods
            .filter(m => m.enabled)
            .map(m => ({ type: m.type, isPrimary: m.isPrimary }))
        };
      }
      
      // Successful login - create session
      const sessionDuration = rememberMe ? 
        config.auth.rememberMeDuration : 
        config.auth.sessionDuration;
      
      const session = auth.addSession({
        deviceInfo: {
          userAgent: context.userAgent,
          platform: this.extractPlatform(context.userAgent),
          browser: this.extractBrowser(context.userAgent),
          deviceId
        },
        location: {
          ip: context.ip
        },
        expiresAt: new Date(Date.now() + sessionDuration)
      });
      
      // Clear failed login attempts
      auth.addLoginAttempt(true);
      
      // Add to login history
      auth.activity.loginHistory.push({
        timestamp: new Date(),
        ip: context.ip,
        userAgent: context.userAgent,
        method: 'local',
        success: true,
        mfaUsed: false
      });
      
      await auth.save();
      
      // Update user last login
      user.activity.lastLogin = new Date();
      await user.save();
      
      // Generate tokens
      const tokens = await this.generateTokens(user, session.sessionId, rememberMe);
      
      // Check for trusted device
      if (deviceId) {
        const isTrusted = auth.security.trustedDevices.some(d => d.deviceId === deviceId);
        if (!isTrusted && rememberMe) {
          // Add as trusted device
          const trustedDevice = auth.addTrustedDevice({
            deviceFingerprint: this.generateDeviceFingerprint(context),
            name: `${this.extractBrowser(context.userAgent)} on ${this.extractPlatform(context.userAgent)}`
          });
          await auth.save();
          
          tokens.trustToken = trustedDevice.trustToken;
        }
      }
      
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
          rememberMe
        }
      });
      
      return {
        success: true,
        message: 'Login successful',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          displayName: user.profile.displayName,
          avatar: user.profile.avatar,
          role: user.role,
          organization: user.organization
        },
        ...tokens,
        sessionId: session.sessionId
      };
      
    } catch (error) {
      logger.error('Login error', { error, email: credentials.email });
      throw error;
    }
  }
  
  // /**
  //  * Logout user
  //  * @param {Object} sessionData - Session data
  //  * @param {Object} context - Request context
  //  * @returns {Promise<Object>} Logout result
  //  */
  // static async logout(sessionData, context) {
  //   try {
  //     const { accessToken, refreshToken, sessionId, userId, logoutAll } = sessionData;
      
  //     // Verify and decode token
  //     let tokenData;
  //     if (accessToken) {
  //       try {
  //         tokenData = jwt.verify(accessToken, config.auth.jwtSecret);
  //       } catch (error) {
  //         // Token might be expired, but we still want to logout
  //         tokenData = jwt.decode(accessToken);
  //       }
  //     }
      
  //     const effectiveUserId = userId || tokenData?.userId;
  //     const effectiveSessionId = sessionId || tokenData?.sessionId;
      
  //     if (!effectiveUserId) {
  //       throw new ValidationError('User ID required for logout');
  //     }
      
  //     // Get auth record
  //     const auth = await Auth.findOne({ userId: effectiveUserId });
  //     if (!auth) {
  //       throw new NotFoundError('Authentication record not found');
  //     }
      
  //     // Revoke session(s)
  //     if (logoutAll) {
  //       // Revoke all sessions
  //       auth.sessions.forEach(session => {
  //         if (session.isActive) {
  //           session.isActive = false;
  //           session.revokedAt = new Date();
  //           session.revokedReason = 'User logged out from all devices';
  //         }
  //       });
  //     } else if (effectiveSessionId) {
  //       // Revoke specific session
  //       auth.revokeSession(effectiveSessionId, 'User logged out');
  //     }
      
  //     // Update activity
  //     auth.activity.lastLogout = new Date();
  //     await auth.save();
      
  //     // Blacklist tokens
  //     if (accessToken) {
  //       await TokenBlacklistService.blacklistToken(accessToken, 'access', 'logout');
  //     }
  //     if (refreshToken) {
  //       await TokenBlacklistService.blacklistToken(refreshToken, 'refresh', 'logout');
  //     }
      
  //     // Update user activity
  //     const user = await User.findById(effectiveUserId);
  //     if (user) {
  //       user.activity.lastLogout = new Date();
  //       await user.save();
  //     }
      
  //     // Audit log
  //     await AuditService.log({
  //       type: 'user_logout',
  //       action: 'logout',
  //       category: 'authentication',
  //       result: 'success',
  //       userId: effectiveUserId,
  //       target: {
  //         type: 'user',
  //         id: effectiveUserId.toString()
  //       },
  //       metadata: {
  //         ...context,
  //         sessionId: effectiveSessionId,
  //         logoutAll
  //       }
  //     });
      
  //     return {
  //       success: true,
  //       message: logoutAll ? 'Logged out from all devices' : 'Logout successful'
  //     };
      
  //   } catch (error) {
  //     logger.error('Logout error', { error });
  //     throw error;
  //   }
  // }

    /**
     * Logout user with fallback for circular dependency issue
     * @param {Object} sessionData - Session data
     * @param {Object} context - Request context
     * @returns {Promise<Object>} Logout result
     */
    static async logout(sessionData, context) {
      try {
        const { accessToken, refreshToken, sessionId, userId, logoutAll } = sessionData;
        
        // Verify and decode token
        let tokenData;
        if (accessToken) {
          try {
            tokenData = jwt.verify(accessToken, config.auth.jwtSecret);
          } catch (error) {
            // Token might be expired, but we still want to logout
            tokenData = jwt.decode(accessToken);
          }
        }
        
        const effectiveUserId = userId || tokenData?.userId;
        const effectiveSessionId = sessionId || tokenData?.sessionId;
        
        if (!effectiveUserId) {
          throw new ValidationError('User ID required for logout');
        }
        
        // Get auth record
        const auth = await Auth.findOne({ userId: effectiveUserId });
        if (!auth) {
          throw new NotFoundError('Authentication record not found');
        }
        
        // Revoke session(s)
        if (logoutAll) {
          // Revoke all sessions
          auth.sessions.forEach(session => {
            if (session.isActive) {
              session.isActive = false;
              session.revokedAt = new Date();
              session.revokedReason = 'User logged out from all devices';
            }
          });
        } else if (effectiveSessionId) {
          // Revoke specific session
          auth.revokeSession(effectiveSessionId, 'User logged out');
        }
        
        // Update activity
        auth.activity.lastLogout = new Date();
        await auth.save();
        
        // Blacklist tokens with error handling for circular dependency
        try {
          if (accessToken && TokenBlacklistService && typeof TokenBlacklistService.blacklistToken === 'function') {
            await TokenBlacklistService.blacklistToken(accessToken, 'access', 'logout');
          } else {
            logger.warn('TokenBlacklistService.blacklistToken not available - token not blacklisted', {
              hasService: !!TokenBlacklistService,
              hasMethod: !!(TokenBlacklistService && typeof TokenBlacklistService.blacklistToken === 'function'),
              userId: effectiveUserId
            });
          }
          
          if (refreshToken && TokenBlacklistService && typeof TokenBlacklistService.blacklistToken === 'function') {
            await TokenBlacklistService.blacklistToken(refreshToken, 'refresh', 'logout');
          } else {
            logger.warn('TokenBlacklistService.blacklistToken not available - refresh token not blacklisted', {
              hasService: !!TokenBlacklistService,
              hasMethod: !!(TokenBlacklistService && typeof TokenBlacklistService.blacklistToken === 'function'),
              userId: effectiveUserId
            });
          }
        } catch (blacklistError) {
          // Log the error but don't fail the logout
          logger.error('Token blacklisting failed during logout', {
            error: blacklistError.message,
            userId: effectiveUserId,
            sessionId: effectiveSessionId
          });
        }
        
        // Update user activity
        const user = await User.findById(effectiveUserId);
        if (user) {
          user.activity.lastLogout = new Date();
          await user.save();
        }
        
        // Audit log
        await AuditService.log({
          type: 'user_logout',
          action: 'logout',
          category: 'authentication',
          result: 'success',
          userId: effectiveUserId,
          target: {
            type: 'user',
            id: effectiveUserId.toString()
          },
          metadata: {
            ...context,
            sessionId: effectiveSessionId,
            logoutAll,
            tokenBlacklistingSkipped: !TokenBlacklistService || typeof TokenBlacklistService.blacklistToken !== 'function'
          }
        });
        
        return {
          success: true,
          message: logoutAll ? 'Logged out from all devices' : 'Logout successful'
        };
        
      } catch (error) {
        logger.error('Logout error', { error });
        throw error;
      }
    }
  
  /**
   * Refresh access token
   * @param {string} refreshToken - Refresh token
   * @param {Object} context - Request context
   * @returns {Promise<Object>} New tokens
   */
  static async refreshToken(refreshToken, context) {
    try {
      // Check if token is blacklisted
      const isBlacklisted = await TokenBlacklistService.isTokenBlacklisted(refreshToken);
      if (isBlacklisted) {
        throw new AuthenticationError('Invalid refresh token');
      }
      
      // Verify refresh token
      let decoded;
      try {
        decoded = jwt.verify(refreshToken, config.auth.refreshTokenSecret);
      } catch (error) {
        throw new AuthenticationError('Invalid or expired refresh token');
      }
      
      // Get user and auth
      const user = await User.findById(decoded.userId);
      if (!user || !user.active) {
        throw new AuthenticationError('User not found or inactive');
      }
      
      const auth = await Auth.findOne({ userId: user._id });
      if (!auth) {
        throw new AuthenticationError('Authentication record not found');
      }
      
      // Verify session
      const session = auth.sessions.find(s => 
        s.sessionId === decoded.sessionId && 
        s.isActive &&
        (!s.expiresAt || s.expiresAt > new Date())
      );
      
      if (!session) {
        throw new AuthenticationError('Session not found or expired');
      }
      
      // Update session activity
      auth.updateSessionActivity(session.sessionId);
      await auth.save();
      
      // Generate new access token
      const accessToken = jwt.sign(
        {
          userId: user._id,
          email: user.email,
          role: user.role.primary,
          sessionId: session.sessionId,
          type: 'access'
        },
        config.auth.jwtSecret,
        { expiresIn: config.auth.accessTokenExpiry }
      );
      
      // Optionally rotate refresh token
      let newRefreshToken = refreshToken;
      if (config.auth.rotateRefreshTokens) {
        // Blacklist old refresh token
        await TokenBlacklistService.blacklistToken(refreshToken, 'refresh', 'rotation');
        
        // Generate new refresh token
        newRefreshToken = jwt.sign(
          {
            userId: user._id,
            sessionId: session.sessionId,
            type: 'refresh'
          },
          config.auth.refreshTokenSecret,
          { expiresIn: config.auth.refreshTokenExpiry }
        );
      }
      
      // Audit log
      await AuditService.log({
        type: 'token_refreshed',
        action: 'refresh_token',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        metadata: {
          ...context,
          sessionId: session.sessionId,
          tokenRotated: config.auth.rotateRefreshTokens
        }
      });
      
      return {
        success: true,
        accessToken,
        refreshToken: newRefreshToken,
        expiresIn: config.auth.accessTokenExpiry
      };
      
    } catch (error) {
      logger.error('Token refresh error', { error });
      throw error;
    }
  }
  
  /**
   * Verify email with token
   * @param {string} token - Verification token
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Verification result
   */
  static async verifyEmail(token, context) {
    try {
      // Hash the token to compare with stored version
      const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
      
      // Find auth with this verification token
      const auth = await Auth.findOne({
        'authMethods.local.verificationToken': hashedToken,
        'authMethods.local.verificationExpiry': { $gt: new Date() }
      });
      
      if (!auth) {
        throw new ValidationError('Invalid or expired verification token');
      }
      
      // Verify the token
      const verified = auth.verifyEmailToken(token);
      if (!verified) {
        throw new ValidationError('Invalid verification token');
      }
      
      await auth.save();
      
      // Update user status
      const user = await User.findById(auth.userId);
      if (user && user.status === 'pending') {
        user.status = 'active';
        user.isEmailVerified = true;
        await user.save();
      }
      
      // Audit log
      await AuditService.log({
        type: 'email_verified',
        action: 'verify_email',
        category: 'authentication',
        result: 'success',
        userId: auth.userId,
        metadata: context
      });
      
      return {
        success: true,
        message: 'Email verified successfully. You can now login.',
        userId: auth.userId
      };
      
    } catch (error) {
      logger.error('Email verification error', { error });
      throw error;
    }
  }
  
  /**
   * Resend verification email
   * @param {string} email - User email
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Resend result
   */
  static async resendVerificationEmail(email, context) {
    try {
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        // Don't reveal if user exists
        return {
          success: true,
          message: 'If an account exists with this email, a verification email will be sent.'
        };
      }
      
      const auth = await Auth.findOne({ userId: user._id });
      if (!auth || auth.authMethods.local.isVerified) {
        return {
          success: true,
          message: 'If an account exists with this email, a verification email will be sent.'
        };
      }
      
      // Check rate limiting
      const lastSent = auth.authMethods.local.verificationExpiry;
      if (lastSent) {
        const timeSinceLastSent = Date.now() - (lastSent.getTime() - 24 * 60 * 60 * 1000);
        if (timeSinceLastSent < 60000) { // 1 minute
          throw new ValidationError('Please wait before requesting another verification email');
        }
      }
      
      // Generate new verification token
      const verificationToken = auth.generateVerificationToken();
      await auth.save();
      
      // Send verification email
      await this.sendVerificationEmail(user, verificationToken, context);
      
      // Audit log
      await AuditService.log({
        type: 'verification_email_resent',
        action: 'resend_verification',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        metadata: context
      });
      
      return {
        success: true,
        message: 'Verification email sent successfully'
      };
      
    } catch (error) {
      logger.error('Resend verification error', { error });
      throw error;
    }
  }
  
  /**
   * Request password reset
   * @param {string} email - User email
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Reset request result
   */
  static async requestPasswordReset(email, context) {
    try {
      const user = await User.findOne({ email: email.toLowerCase() });
      
      if (!user) {
        // Don't reveal if user exists
        return {
          success: true,
          message: 'If an account exists with this email, a password reset link will be sent.'
        };
      }
      
      const auth = await Auth.findOne({ userId: user._id });
      if (!auth || !auth.authMethods.local.password) {
        return {
          success: true,
          message: 'If an account exists with this email, a password reset link will be sent.'
        };
      }
      
      // Check rate limiting
      if (auth.security.passwordReset.requestedAt) {
        const timeSinceLastRequest = Date.now() - auth.security.passwordReset.requestedAt.getTime();
        if (timeSinceLastRequest < 300000) { // 5 minutes
          throw new ValidationError('Please wait before requesting another password reset');
        }
      }
      
      // Generate reset token
      const resetToken = auth.generatePasswordResetToken();
      auth.security.passwordReset.requestedFrom = {
        ip: context.ip,
        userAgent: context.userAgent
      };
      await auth.save();
      
      // Send password reset email
      await this.sendPasswordResetEmail(user, resetToken, context);
      
      // Audit log
      await AuditService.log({
        type: 'password_reset_requested',
        action: 'request_password_reset',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        metadata: context
      });
      
      return {
        success: true,
        message: 'Password reset email sent successfully'
      };
      
    } catch (error) {
      logger.error('Password reset request error', { error });
      throw error;
    }
  }
  
  /**
   * Reset password with token
   * @param {Object} resetData - Password reset data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Reset result
   */
  static async resetPassword(resetData, context) {
    try {
      const { token, newPassword } = resetData;
      
      // Find auth by reset token
      const auth = await Auth.findByPasswordResetToken(token);
      if (!auth) {
        throw new ValidationError('Invalid or expired reset token');
      }
      
      // Validate new password
      const passwordValidation = this.validatePasswordStrength(newPassword);
      if (!passwordValidation.valid) {
        throw new ValidationError(passwordValidation.message);
      }
      
      // Set new password
      await auth.setPassword(newPassword);
      
      // Clear reset token
      auth.security.passwordReset = {};
      
      // Clear any login attempts
      auth.security.loginAttempts = {
        count: 0,
        lastAttempt: null,
        lockedUntil: null
      };
      
      // Revoke all sessions for security
      auth.sessions.forEach(session => {
        if (session.isActive) {
          session.isActive = false;
          session.revokedAt = new Date();
          session.revokedReason = 'Password reset';
        }
      });
      
      await auth.save();
      
      // Get user for email notification
      const user = await User.findById(auth.userId);
      
      // Send password changed notification
      await this.sendPasswordChangedEmail(user, context);
      
      // Audit log
      await AuditService.log({
        type: 'password_reset_completed',
        action: 'reset_password',
        category: 'authentication',
        result: 'success',
        userId: auth.userId,
        severity: 'high',
        metadata: context
      });
      
      return {
        success: true,
        message: 'Password reset successful. Please login with your new password.'
      };
      
    } catch (error) {
      logger.error('Password reset error', { error });
      throw error;
    }
  }
  
  /**
   * Change password for authenticated user
   * @param {Object} passwordData - Password change data
   * @param {string} userId - User ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Change result
   */
  static async changePassword(passwordData, userId, context) {
    try {
      const { currentPassword, newPassword } = passwordData;
      
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      // Verify current password
      const isValid = await auth.verifyPassword(currentPassword);
      if (!isValid) {
        throw new AuthenticationError('Current password is incorrect');
      }
      
      // Validate new password
      const passwordValidation = this.validatePasswordStrength(newPassword);
      if (!passwordValidation.valid) {
        throw new ValidationError(passwordValidation.message);
      }
      
      // Check if new password is same as current
      const isSamePassword = await auth.verifyPassword(newPassword);
      if (isSamePassword) {
        throw new ValidationError('New password must be different from current password');
      }
      
      // Set new password
      await auth.setPassword(newPassword);
      await auth.save();
      
      // Get user for notification
      const user = await User.findById(userId);
      
      // Send notification
      await this.sendPasswordChangedEmail(user, context);
      
      // Audit log
      await AuditService.log({
        type: 'password_changed',
        action: 'change_password',
        category: 'authentication',
        result: 'success',
        userId,
        severity: 'high',
        metadata: context
      });
      
      return {
        success: true,
        message: 'Password changed successfully'
      };
      
    } catch (error) {
      logger.error('Password change error', { error });
      throw error;
    }
  }
  
  /**
   * Setup MFA for user
   * @param {string} userId - User ID
   * @param {string} method - MFA method
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Setup result
   */
  static async setupMfa(userId, method, context) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      const user = await User.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      let setupData;
      
      switch (method) {
        case 'totp':
          setupData = await this.setupTotpMfa(user, auth);
          break;
          
        case 'sms':
          setupData = await this.setupSmsMfa(user, auth);
          break;
          
        case 'email':
          setupData = await this.setupEmailMfa(user, auth);
          break;
          
        case 'backup_codes':
          setupData = await this.setupBackupCodes(user, auth);
          break;
          
        default:
          throw new ValidationError(`Unsupported MFA method: ${method}`);
      }
      
      // Audit log
      await AuditService.log({
        type: 'mfa_setup_initiated',
        action: 'setup_mfa',
        category: 'authentication',
        result: 'success',
        userId,
        metadata: {
          ...context,
          method
        }
      });
      
      return {
        success: true,
        method,
        ...setupData
      };
      
    } catch (error) {
      logger.error('MFA setup error', { error });
      throw error;
    }
  }
  
  /**
   * Setup TOTP MFA
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @returns {Promise<Object>} TOTP setup data
   */
  static async setupTotpMfa(user, auth) {
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${config.server.appName} (${user.email})`,
      issuer: config.server.appName,
      length: 32
    });
    
    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    // Store encrypted secret temporarily
    const encryptedSecret = await EncryptionService.encrypt(secret.base32);
    
    // Create temporary setup session
    const setupToken = crypto.randomBytes(32).toString('hex');
    auth.mfa.pendingSetup = {
      method: 'totp',
      secret: encryptedSecret,
      setupToken,
      expiresAt: new Date(Date.now() + 3600000) // 1 hour
    };
    
    await auth.save();
    
    return {
      qrCode: qrCodeUrl,
      secret: secret.base32,
      setupToken,
      message: 'Scan the QR code with your authenticator app and verify with a code'
    };
  }
  
  /**
   * Verify MFA setup
   * @param {string} userId - User ID
   * @param {Object} verificationData - Verification data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Verification result
   */
  static async verifyMfaSetup(userId, verificationData, context) {
    try {
      const { method, code, setupToken } = verificationData;
      
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      // Verify setup token
      if (!auth.mfa.pendingSetup || 
          auth.mfa.pendingSetup.setupToken !== setupToken ||
          auth.mfa.pendingSetup.expiresAt < new Date()) {
        throw new ValidationError('Invalid or expired setup session');
      }
      
      let verified = false;
      
      switch (method) {
        case 'totp':
          // Decrypt secret
          const secret = await EncryptionService.decrypt(auth.mfa.pendingSetup.secret);
          
          // Verify code
          verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: code,
            window: 2
          });
          
          if (verified) {
            // Add MFA method
            auth.addMfaMethod('totp', {
              totpSecret: auth.mfa.pendingSetup.secret
            });
          }
          break;
          
        default:
          throw new ValidationError(`Unsupported MFA method: ${method}`);
      }
      
      if (!verified) {
        throw new ValidationError('Invalid verification code');
      }
      
      // Generate backup codes
      const backupCodes = auth.generateBackupCodes();
      
      // Clear pending setup
      auth.mfa.pendingSetup = undefined;
      await auth.save();
      
      // Audit log
      await AuditService.log({
        type: 'mfa_enabled',
        action: 'enable_mfa',
        category: 'authentication',
        result: 'success',
        userId,
        severity: 'high',
        metadata: {
          ...context,
          method
        }
      });
      
      return {
        success: true,
        message: 'MFA enabled successfully',
        backupCodes,
        warning: 'Save these backup codes in a secure place. They can be used to access your account if you lose your MFA device.'
      };
      
    } catch (error) {
      logger.error('MFA verification error', { error });
      throw error;
    }
  }
  
  /**
   * Verify MFA code
   * @param {string} userId - User ID
   * @param {Object} mfaData - MFA verification data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} MFA verification result
   */
  static async verifyMfa(userId, mfaData, context) {
    try {
      const { method, code, challengeId, trustDevice } = mfaData;
      
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      const user = await User.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      // Find MFA method
      const mfaMethod = auth.mfa.methods.find(m => m.type === method && m.enabled);
      if (!mfaMethod) {
        throw new ValidationError('MFA method not found or disabled');
      }
      
      let verified = false;
      
      switch (method) {
        case 'totp':
          // Decrypt secret
          const secret = await EncryptionService.decrypt(mfaMethod.config.totpSecret);
          
          // Verify TOTP code
          verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: code,
            window: 2
          });
          break;
          
        case 'backup_codes':
          // Find and use backup code
          const backupCode = mfaMethod.config.codes.find(c => 
            !c.used && crypto.createHash('sha256').update(code).digest('hex') === c.code
          );
          
          if (backupCode) {
            backupCode.used = true;
            backupCode.usedAt = new Date();
            verified = true;
          }
          break;
          
        default:
          throw new ValidationError(`Unsupported MFA method: ${method}`);
      }
      
      if (!verified) {
        // Record failed attempt
        mfaMethod.verificationAttempts = (mfaMethod.verificationAttempts || 0) + 1;
        await auth.save();
        
        throw new AuthenticationError('Invalid verification code');
      }
      
      // Update MFA method usage
      mfaMethod.lastUsedAt = new Date();
      mfaMethod.verificationAttempts = 0;
      
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
        mfaUsed: true
      });
      
      await auth.save();
      
      // Update user last login
      user.activity.lastLogin = new Date();
      await user.save();
      
      // Generate tokens
      const tokens = await this.generateTokens(user, session.sessionId);
      
      // Handle trusted device
      if (trustDevice) {
        const trustedDevice = auth.addTrustedDevice({
          deviceFingerprint: this.generateDeviceFingerprint(context),
          name: `${this.extractBrowser(context.userAgent)} on ${this.extractPlatform(context.userAgent)}`
        });
        await auth.save();
        
        tokens.trustToken = trustedDevice.trustToken;
      }
      
      // Audit log
      await AuditService.log({
        type: 'mfa_verification_success',
        action: 'verify_mfa',
        category: 'authentication',
        result: 'success',
        userId,
        metadata: {
          ...context,
          method,
          sessionId: session.sessionId
        }
      });
      
      return {
        success: true,
        message: 'MFA verification successful',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          displayName: user.profile.displayName,
          avatar: user.profile.avatar,
          role: user.role,
          organization: user.organization
        },
        ...tokens,
        sessionId: session.sessionId
      };
      
    } catch (error) {
      logger.error('MFA verification error', { error });
      throw error;
    }
  }
  
  /**
   * Disable MFA method
   * @param {string} userId - User ID
   * @param {string} method - MFA method to disable
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Disable result
   */
  static async disableMfa(userId, method, context) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      const mfaMethod = auth.mfa.methods.find(m => m.type === method);
      if (!mfaMethod) {
        throw new NotFoundError('MFA method not found');
      }
      
      // Ensure at least one MFA method remains if MFA is required
      const enabledMethods = auth.mfa.methods.filter(m => m.enabled && m.type !== method);
      if (config.security.requireMfa && enabledMethods.length === 0) {
        throw new ValidationError('Cannot disable the last MFA method when MFA is required');
      }
      
      // Disable the method
      mfaMethod.enabled = false;
      
      // If no methods remain enabled, disable MFA entirely
      if (enabledMethods.length === 0) {
        auth.mfa.enabled = false;
      }
      
      await auth.save();
      
      // Audit log
      await AuditService.log({
        type: 'mfa_disabled',
        action: 'disable_mfa',
        category: 'authentication',
        result: 'success',
        userId,
        severity: 'high',
        metadata: {
          ...context,
          method,
          remainingMethods: enabledMethods.map(m => m.type)
        }
      });
      
      return {
        success: true,
        message: `${method} MFA method disabled successfully`,
        mfaEnabled: auth.mfa.enabled,
        remainingMethods: enabledMethods.map(m => ({ type: m.type, isPrimary: m.isPrimary }))
      };
      
    } catch (error) {
      logger.error('MFA disable error', { error });
      throw error;
    }
  }
  
  /**
   * Get user sessions
   * @param {string} userId - User ID
   * @returns {Promise<Object>} User sessions
   */
  static async getUserSessions(userId) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      const activeSessions = auth.sessions
        .filter(s => s.isActive && (!s.expiresAt || s.expiresAt > new Date()))
        .map(s => ({
          sessionId: s.sessionId,
          deviceInfo: s.deviceInfo,
          location: s.location,
          createdAt: s.createdAt,
          lastActivityAt: s.lastActivityAt,
          expiresAt: s.expiresAt,
          isCurrent: false // Will be set by controller based on request
        }))
        .sort((a, b) => b.lastActivityAt - a.lastActivityAt);
      
      return {
        success: true,
        sessions: activeSessions,
        totalActive: activeSessions.length
      };
      
    } catch (error) {
      logger.error('Get sessions error', { error });
      throw error;
    }
  }
  
  /**
   * Revoke specific session
   * @param {string} userId - User ID
   * @param {string} sessionId - Session ID to revoke
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Revoke result
   */
  static async revokeSession(userId, sessionId, context) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      const session = auth.sessions.find(s => s.sessionId === sessionId);
      if (!session) {
        throw new NotFoundError('Session not found');
      }
      
      if (!session.isActive) {
        throw new ValidationError('Session is already revoked');
      }
      
      // Revoke session
      auth.revokeSession(sessionId, 'User revoked session');
      await auth.save();
      
      // Audit log
      await AuditService.log({
        type: 'session_revoked',
        action: 'revoke_session',
        category: 'authentication',
        result: 'success',
        userId,
        metadata: {
          ...context,
          revokedSessionId: sessionId,
          deviceInfo: session.deviceInfo
        }
      });
      
      return {
        success: true,
        message: 'Session revoked successfully'
      };
      
    } catch (error) {
      logger.error('Revoke session error', { error });
      throw error;
    }
  }

  /**
   * Revoke all other sessions (excluding current session)
   * @param {string} userId - User ID
   * @param {string} currentSessionId - Current session ID to exclude
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Revoke result
   */
  static async revokeAllOtherSessions(userId, currentSessionId, context) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      let revokedCount = 0;
      const revokedSessions = [];
      
      // Revoke all sessions except the current one
      auth.sessions.forEach(session => {
        if (session.sessionId !== currentSessionId && session.isActive) {
          session.isActive = false;
          session.revokedAt = new Date();
          session.revokedReason = 'User revoked all other sessions';
          revokedCount++;
          revokedSessions.push({
            sessionId: session.sessionId,
            deviceInfo: session.deviceInfo
          });
        }
      });
      
      if (revokedCount === 0) {
        return {
          success: true,
          message: 'No other active sessions to revoke',
          revokedCount: 0
        };
      }
      
      // Save changes
      await auth.save();
      
      // Audit log
      await AuditService.log({
        type: 'sessions_revoked_bulk',
        action: 'revoke_all_other_sessions',
        category: 'authentication',
        result: 'success',
        userId,
        metadata: {
          ...context,
          currentSessionId,
          revokedCount,
          revokedSessions: revokedSessions.map(s => ({
            sessionId: s.sessionId,
            deviceInfo: s.deviceInfo
          }))
        }
      });
      
      return {
        success: true,
        message: `Successfully revoked ${revokedCount} other session${revokedCount !== 1 ? 's' : ''}`,
        revokedCount
      };
      
    } catch (error) {
      logger.error('Revoke all other sessions error', { error, userId, currentSessionId });
      throw error;
    }
  }
  
  /**
   * Get auth statistics for user
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Auth statistics
   */
  static async getAuthStats(userId) {
    try {
      return await Auth.getAuthStats(userId);
    } catch (error) {
      logger.error('Get auth stats error', { error });
      throw error;
    }
  }
  
  /**
   * Generate MFA challenge
   * @param {string} userId - User ID
   * @param {Object} auth - Auth record
   * @returns {Promise<Object>} MFA challenge
   */
  static async generateMfaChallenge(userId, auth) {
    const challengeId = crypto.randomBytes(16).toString('hex');
    const challenge = {
      id: challengeId,
      userId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 300000), // 5 minutes
      attempts: 0
    };
    
    // Store challenge (in production, use Redis or similar)
    // For now, storing in auth record
    auth.mfa.activeChallenge = challenge;
    await auth.save();
    
    return challenge;
  }
  
  /**
   * Validate password strength - CORRECTED VERSION
   * @param {string} password - Password to validate
   * @returns {Object} Validation result
   */
  static validatePasswordStrength(password) {
    // Access the correct configuration paths based on your config structure
    const minLength = config.auth.passwordMinLength || 8;
    const requireUppercase = config.auth.requireUppercase !== false;
    const requireLowercase = config.auth.requireLowercase !== false;
    const requireNumbers = config.auth.requireNumbers !== false;
    const requireSpecialChars = config.auth.requireSpecialChars !== false;
    
    if (!password) {
      return {
        valid: false,
        message: 'Password is required'
      };
    }
    
    if (password.length < minLength) {
      return {
        valid: false,
        message: `Password must be at least ${minLength} characters long`
      };
    }
    
    if (requireUppercase && !/[A-Z]/.test(password)) {
      return {
        valid: false,
        message: 'Password must contain at least one uppercase letter'
      };
    }
    
    if (requireLowercase && !/[a-z]/.test(password)) {
      return {
        valid: false,
        message: 'Password must contain at least one lowercase letter'
      };
    }
    
    if (requireNumbers && !/\d/.test(password)) {
      return {
        valid: false,
        message: 'Password must contain at least one number'
      };
    }
    
    if (requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      return {
        valid: false,
        message: 'Password must contain at least one special character'
      };
    }
    
    // Check for common passwords
    const commonPasswords = ['password', '12345678', 'qwerty', 'abc123', 'password123'];
    if (commonPasswords.includes(password.toLowerCase())) {
      return {
        valid: false,
        message: 'Password is too common. Please choose a more secure password.'
      };
    }
    
    return {
      valid: true,
      message: 'Password meets security requirements'
    };
  }
  
  /**
   * Check if password change is required
   * @param {Object} auth - Auth record
   * @returns {boolean} Password change required
   */
  static isPasswordChangeRequired(auth) {
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

  // /**
  //  * Generate JWT tokens with rememberMe support
  //  * @param {Object} user - User object
  //  * @param {string} sessionId - Session ID
  //  * @param {boolean} rememberMe - Whether to extend refresh token duration
  //  * @returns {Promise<Object>} Generated tokens
  //  */
  // static async generateTokens(user, sessionId, rememberMe = false) {
  //   const jwt = require('jsonwebtoken');
    
  //   // ROBUST CONFIG ACCESS - Get secrets directly from environment with fallbacks
  //   const jwtSecret = process.env.ACCESS_TOKEN_SECRET || 
  //                   process.env.JWT_SECRET || 
  //                   'fallback-secret-development-only';
                    
  //   const jwtRefreshSecret = process.env.REFRESH_TOKEN_SECRET || 
  //                           process.env.JWT_REFRESH_SECRET || 
  //                           'fallback-refresh-secret-development-only';
                            
  //   const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
    
  //   // 🔧 REMEMBER ME LOGIC: Use extended duration if rememberMe is true
  //   const refreshTokenExpiry = rememberMe 
  //     ? '14d'  // 14 days for remember me
  //     : (process.env.REFRESH_TOKEN_EXPIRES_IN || '7d'); // 7 days normal
    
  //   // Add debug logging to verify rememberMe logic
  //   console.log(`🔧 AuthService.generateTokens - RememberMe: ${rememberMe}`);
  //   console.log(`🔧 Refresh token expiry: ${refreshTokenExpiry}`);
  //   console.log('jwtSecret:', jwtSecret?.substring(0, 20) + '...');
  //   console.log('jwtRefreshSecret:', jwtRefreshSecret?.substring(0, 20) + '...');
    
  //   const tokenPayload = {
  //     userId: user._id,
  //     email: user.email,
  //     role: user.role.primary,
  //     organizationId: user.organization?.current,
  //     sessionId
  //   };
    
  //   const accessToken = jwt.sign(
  //     { ...tokenPayload, type: 'access' },
  //     jwtSecret,
  //     { expiresIn: accessTokenExpiry }
  //   );
    
  //   const refreshToken = jwt.sign(
  //     { 
  //       userId: user._id, 
  //       sessionId,
  //       type: 'refresh' 
  //     },
  //     jwtRefreshSecret,
  //     { expiresIn: refreshTokenExpiry }  // 🔥 This now uses conditional expiry!
  //   );
    
  //   return {
  //     accessToken,
  //     refreshToken,
  //     tokenType: 'Bearer',
  //     expiresIn: accessTokenExpiry,
  //     rememberMe, // Include in response for debugging
  //     refreshTokenExpiry // Include actual expiry used
  //   };
  // }

  /**
   * Generate JWT tokens with rememberMe support
   * @param {Object} user - User object
   * @param {string} sessionId - Session ID
   * @param {boolean} rememberMe - Whether to extend refresh token duration
   * @returns {Promise<Object>} Generated tokens
   */
  static async generateTokens(user, sessionId, rememberMe = false) {
    const jwt = require('jsonwebtoken');
    
    // ROBUST CONFIG ACCESS - Get secrets directly from environment with fallbacks
    const jwtSecret = process.env.ACCESS_TOKEN_SECRET || 
                    process.env.JWT_SECRET || 
                    'fallback-secret-development-only';
                    
    const jwtRefreshSecret = process.env.REFRESH_TOKEN_SECRET || 
                            process.env.JWT_REFRESH_SECRET || 
                            'fallback-refresh-secret-development-only';
                            
    const accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
    
    // 🔧 REMEMBER ME LOGIC: Use extended duration if rememberMe is true
    const refreshTokenExpiry = rememberMe 
      ? '14d'  // 14 days for remember me
      : (process.env.REFRESH_TOKEN_EXPIRES_IN || '7d'); // 7 days normal
    
    // Get issuer and audience from config
    const issuer = config.auth.jwt.issuer;
    const audience = config.auth.jwt.audience;
    
    console.log(`🔧 AuthService.generateTokens - RememberMe: ${rememberMe}`);
    console.log(`🔧 Refresh token expiry: ${refreshTokenExpiry}`);
    console.log(`🔧 Issuer: ${issuer}, Audience: ${audience}`);
    
    const tokenPayload = {
      userId: user._id,
      email: user.email,
      role: user.role.primary,
      organizationId: user.organization?.current,
      sessionId
    };
    
    const accessToken = jwt.sign(
      { ...tokenPayload, type: 'access' },
      jwtSecret,
      { 
        expiresIn: accessTokenExpiry,
        issuer: issuer,
        audience: audience
      }
    );
    
    const refreshToken = jwt.sign(
      { 
        userId: user._id, 
        sessionId,
        type: 'refresh' 
      },
      jwtRefreshSecret,
      { 
        expiresIn: refreshTokenExpiry,
        issuer: issuer,
        audience: audience
      }
    );
    
    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: accessTokenExpiry,
      rememberMe,
      refreshTokenExpiry
    };
  }

  // /**
  //  * Send verification email with fallback logging
  //  * @param {Object} user - User object
  //  * @param {string} token - Verification token
  //  * @param {Object} context - Request context
  //  */
  // static async sendVerificationEmail(user, token, context) {
  //   try {
  //     // Construct verification URL using correct config path
  //     const verificationUrl = `${config.frontend.verifyEmailUrl}?token=${token}`;
      
  //     const emailData = {
  //       to: user.email,
  //       subject: 'Verify your email address',
  //       template: 'email-verification',
  //       data: {
  //         firstName: user.firstName,
  //         verificationUrl,
  //         expiresIn: '24 hours'
  //       }
  //     };

  //     // Check if EmailService exists and has sendEmail method
  //     if (EmailService && typeof EmailService.sendEmail === 'function') {
  //       await EmailService.sendEmail(emailData);
  //       logger.info('Verification email sent successfully', {
  //         to: user.email,
  //         userId: user._id,
  //         verificationUrl
  //       });
  //     } else {
  //       // Fallback: Log email details instead of sending
  //       logger.info('Email service not available - logging verification email details', {
  //         emailType: 'verification',
  //         to: user.email,
  //         subject: emailData.subject,
  //         firstName: user.firstName,
  //         verificationUrl,
  //         token: token.substring(0, 8) + '...', // Log partial token for security
  //         userId: user._id,
  //         note: 'This email would have been sent if email service was configured'
  //       });
        
  //       // Also log to console for development visibility
  //       console.log('📧 VERIFICATION EMAIL (would be sent):');
  //       console.log(`   To: ${user.email}`);
  //       console.log(`   Subject: ${emailData.subject}`);
  //       console.log(`   Verification URL: ${verificationUrl}`);
  //       console.log(`   Token: ${token}`);
  //     }
      
  //   } catch (error) {
  //     // Log error but don't fail registration
  //     logger.error('Failed to send verification email', {
  //       error: error.message,
  //       userId: user._id,
  //       email: user.email
  //     });
      
  //     // Log fallback information
  //     logger.info('Verification email fallback - registration completed without email', {
  //       userId: user._id,
  //       email: user.email,
  //       token: token.substring(0, 8) + '...',
  //       note: 'User can verify manually using token if needed'
  //     });
      
  //     console.log('📧 VERIFICATION EMAIL FAILED - Token for manual verification:');
  //     console.log(`   User: ${user.email}`);
  //     console.log(`   Token: ${token}`);
  //   }
  // }

  /**
   * Send verification email with fallback logging
   * @param {Object} user - User object
   * @param {string} token - Verification token
   * @param {Object} context - Request context
   */
  static async sendVerificationEmail(user, token, context) {
    try {
      // Construct verification URL using correct config path
      const verificationUrl = `${config.frontend.verifyEmailUrl}?token=${token}`;
      
      const emailData = {
        to: user.email,
        subject: 'Verify your email address',
        template: 'email-verification',
        data: {
          firstName: user.firstName,
          verificationUrl,
          expiresIn: '24 hours'
        }
      };

      // ✅ ENHANCED DEVELOPMENT LOGGING
      if (config.app.env === 'development') {
        console.log('\n🔓 =================== EMAIL VERIFICATION TOKEN (DEVELOPMENT) ===================');
        console.log(`📧 To: ${user.email}`);
        console.log(`👤 User: ${user.firstName} ${user.lastName}`);
        console.log(`🆔 User ID: ${user._id}`);
        console.log(`🔑 Verification Token: ${token}`);
        console.log(`🔗 Verification URL: ${verificationUrl}`);
        console.log(`⏰ Expires: 24 hours from now`);
        console.log(`📅 Created: ${new Date().toISOString()}`);
        console.log('================================================================================\n');
        
        // Additional logger for development
        logger.info('🔓 EMAIL VERIFICATION TOKEN (DEVELOPMENT)', {
          userId: user._id,
          email: user.email,
          firstName: user.firstName,
          fullToken: token, // Full token for development
          verificationUrl,
          environment: 'development',
          note: 'Full token logged for development purposes only'
        });
      }

      // Check if EmailService exists and has sendEmail method
      if (EmailService && typeof EmailService.sendEmail === 'function') {
        await EmailService.sendEmail(emailData);
        logger.info('Verification email sent successfully', {
          to: user.email,
          userId: user._id,
          verificationUrl
        });
      } else {
        // Fallback: Log email details instead of sending
        logger.info('Email service not available - logging verification email details', {
          emailType: 'verification',
          to: user.email,
          subject: emailData.subject,
          firstName: user.firstName,
          verificationUrl,
          token: config.app.env === 'development' ? token : token.substring(0, 8) + '...', // Full token in dev
          userId: user._id,
          note: 'This email would have been sent if email service was configured'
        });
        
        // Also log to console for development visibility
        console.log('📧 VERIFICATION EMAIL (would be sent):');
        console.log(`   To: ${user.email}`);
        console.log(`   Subject: ${emailData.subject}`);
        console.log(`   Verification URL: ${verificationUrl}`);
        if (config.app.env === 'development') {
          console.log(`   Full Token: ${token}`);
        }
      }
      
    } catch (error) {
      // Log error but don't fail registration
      logger.error('Failed to send verification email', {
        error: error.message,
        userId: user._id,
        email: user.email
      });
      
      // Log fallback information
      logger.info('Verification email fallback - registration completed without email', {
        userId: user._id,
        email: user.email,
        verificationUrl: `${config.frontend.verifyEmailUrl}?token=${token}`,
        token: config.app.env === 'development' ? token : 'hidden_for_security'
      });
    }
  }

  /**
   * Send password reset email with fallback logging
   * @param {Object} user - User object
   * @param {string} token - Reset token
   * @param {Object} context - Request context
   */
  static async sendPasswordResetEmail(user, token, context) {
    try {
      const resetUrl = `${config.frontend.resetPasswordUrl}?token=${token}`;
      
      const emailData = {
        to: user.email,
        subject: 'Reset your password',
        template: 'password-reset',
        data: {
          firstName: user.firstName,
          resetUrl,
          expiresIn: '1 hour',
          ip: context.ip
        }
      };

      if (EmailService && typeof EmailService.sendEmail === 'function') {
        await EmailService.sendEmail(emailData);
        logger.info('Password reset email sent successfully', {
          to: user.email,
          userId: user._id,
          resetUrl
        });
      } else {
        logger.info('Email service not available - logging password reset email details', {
          emailType: 'password_reset',
          to: user.email,
          subject: emailData.subject,
          firstName: user.firstName,
          resetUrl,
          token: token.substring(0, 8) + '...',
          userId: user._id,
          ip: context.ip
        });
        
        console.log('📧 PASSWORD RESET EMAIL (would be sent):');
        console.log(`   To: ${user.email}`);
        console.log(`   Subject: ${emailData.subject}`);
        console.log(`   Reset URL: ${resetUrl}`);
        console.log(`   Token: ${token}`);
      }
      
    } catch (error) {
      logger.error('Failed to send password reset email', {
        error: error.message,
        userId: user._id,
        email: user.email
      });
      
      console.log('📧 PASSWORD RESET EMAIL FAILED - Token for manual reset:');
      console.log(`   User: ${user.email}`);
      console.log(`   Token: ${token}`);
    }
  }

  /**
   * Send password changed email with fallback logging
   * @param {Object} user - User object
   * @param {Object} context - Request context
   */
  static async sendPasswordChangedEmail(user, context) {
    try {
      const emailData = {
        to: user.email,
        subject: 'Your password has been changed',
        template: 'password-changed',
        data: {
          firstName: user.firstName,
          loginUrl: config.frontend.loginUrl,
          supportEmail: config.email.supportEmail,
          ip: context.ip,
          timestamp: new Date().toLocaleString()
        }
      };

      if (EmailService && typeof EmailService.sendEmail === 'function') {
        await EmailService.sendEmail(emailData);
        logger.info('Password changed email sent successfully', {
          to: user.email,
          userId: user._id
        });
      } else {
        logger.info('Email service not available - logging password changed email details', {
          emailType: 'password_changed',
          to: user.email,
          subject: emailData.subject,
          firstName: user.firstName,
          userId: user._id,
          ip: context.ip,
          timestamp: emailData.data.timestamp
        });
        
        console.log('📧 PASSWORD CHANGED EMAIL (would be sent):');
        console.log(`   To: ${user.email}`);
        console.log(`   Subject: ${emailData.subject}`);
        console.log(`   Login URL: ${config.frontend.loginUrl}`);
      }
      
    } catch (error) {
      logger.error('Failed to send password changed email', {
        error: error.message,
        userId: user._id,
        email: user.email
      });
    }
  }
  
  /**
   * Get auth by passkey credential
   * @param {string} credentialId - Credential ID
   * @returns {Promise<Object>} Auth record
   */
  static async getAuthByPasskeyCredential(credentialId) {
    return await Auth.findByPasskeyCredential(credentialId);
  }
  
  /**
   * Extract platform from user agent
   * @param {string} userAgent - User agent string
   * @returns {string} Platform
   */
  static extractPlatform(userAgent) {
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
  static extractBrowser(userAgent) {
    if (/Chrome/.test(userAgent) && !/Edge/.test(userAgent)) return 'Chrome';
    if (/Firefox/.test(userAgent)) return 'Firefox';
    if (/Safari/.test(userAgent) && !/Chrome/.test(userAgent)) return 'Safari';
    if (/Edge/.test(userAgent)) return 'Edge';
    if (/MSIE|Trident/.test(userAgent)) return 'Internet Explorer';
    return 'Unknown';
  }
  
  /**
   * Generate device fingerprint
   * @param {Object} context - Request context
   * @returns {string} Device fingerprint
   */
  static generateDeviceFingerprint(context) {
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
}

module.exports = AuthService;