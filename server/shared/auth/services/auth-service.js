/**
 * @file Authentication Service (Complete Refactored Version)
 * @description Comprehensive authentication service with extracted email functionality
 * @version 3.1.0
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
const AuthEmailService = require('./auth-email-service'); // 🆕 NEW: Import the email service
const User = require('../../users/models/user-model');
const { 
  AuthenticationError, 
  ValidationError, 
  NotFoundError,
  ConflictError 
} = require('../../utils/app-error');
const logger = require('../../utils/logger');
const Auth = require('../models/auth-model');
const PermissionMiddleware = require('../../middleware/auth/permission-middleware');

/**
 * Authentication Service Class
 * @class AuthService
 */
class AuthService {
  /**
   * Register new user with email/password - WITH BUSINESS LOGIC ENFORCEMENT
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
      
      // Extract role value correctly
      let requestedRole = 'prospect'; // Default role
      if (role) {
        if (typeof role === 'string') {
          requestedRole = role;
        } else if (role.primary) {
          requestedRole = role.primary;
        }
      }
      
      // Validate role against allowed values
      if (!constants.USER.ROLES_ENUM.includes(requestedRole)) {
        throw new ValidationError(`Invalid role: ${requestedRole}. Must be one of: ${constants.USER.ROLES_ENUM.join(', ')}`);
      }
      
      // BUSINESS LOGIC: Role assignment restrictions using permission middleware
      let finalRole = 'prospect'; // Default to prospect for security
      
      // Check context flags for authorization
      const isPublicRegistration = !context.isAdmin && !context.salesApproved && !context.paymentVerified && !context.internalOnboarding;
      const hasVerification = context.salesApproved || context.paymentVerified;
      const isInternalProcess = context.internalOnboarding || context.isAdmin;
      
      // Get role categories from permission middleware
      const { roleCategories } = PermissionMiddleware;
      
      // Apply business logic for role assignment
      if (isPublicRegistration) {
        // Public registration: Only allow publicly assignable roles
        if (!PermissionMiddleware.isPubliclyAssignableRole(requestedRole)) {
          logger.warn('Attempt to assign elevated role through public registration', {
            requestedRole,
            email: email.toLowerCase(),
            ip: context.ip,
            userAgent: context.userAgent
          });
          
          // Force to prospect and log the attempt
          finalRole = 'prospect';
          
          // Audit the elevation attempt
          await AuditService.log({
            type: 'role_elevation_blocked',
            action: 'register',
            category: 'security',
            result: 'blocked',
            severity: 'medium',
            target: {
              type: 'registration',
              id: email.toLowerCase()
            },
            metadata: {
              ...context,
              requestedRole,
              assignedRole: finalRole,
              reason: 'public_registration_restriction'
            }
          });
        } else {
          finalRole = requestedRole;
        }
      } else if (hasVerification && roleCategories.external.includes(requestedRole) && requestedRole === 'client') {
        // Verified client registration: Allow client role
        finalRole = requestedRole;
        
        logger.info('Verified client registration', {
          email: email.toLowerCase(),
          role: finalRole,
          salesApproved: context.salesApproved,
          paymentVerified: context.paymentVerified
        });
      } else if (isInternalProcess && roleCategories.internal.includes(requestedRole)) {
        // Internal process: Allow internal roles
        finalRole = requestedRole;
        
        logger.info('Internal role assignment', {
          email: email.toLowerCase(),
          role: finalRole,
          isAdmin: context.isAdmin,
          internalOnboarding: context.internalOnboarding
        });
      } else if (context.isAdmin && (roleCategories.platform.includes(requestedRole) || 
                                  roleCategories.organization.includes(requestedRole) || 
                                  roleCategories.recruitment.includes(requestedRole))) {
        // Admin process: Allow platform/organization/recruitment roles
        finalRole = requestedRole;
        
        logger.info('Admin role assignment', {
          email: email.toLowerCase(),
          role: finalRole,
          adminUserId: context.userId
        });
      } else {
        // Unauthorized role assignment attempt
        throw new ValidationError(`Role '${requestedRole}' requires special authorization. Contact your administrator.`);
      }
      
      // Additional validation using permission middleware methods
      if (requestedRole === 'client' && !hasVerification && !context.isAdmin) {
        throw new ValidationError('Client role requires business verification. Please contact sales to upgrade your account.');
      }
      
      if (roleCategories.internal.includes(requestedRole) && !isInternalProcess) {
        throw new ValidationError('Internal roles require administrator approval through HR onboarding process.');
      }
      
      // Determine user type based on final role using permission middleware
      const roleCategory = PermissionMiddleware.getUserRoleCategory({ role: { primary: finalRole } });
      let userType = 'hosted_org_user'; // Default
      
      if (roleCategory === 'internal' || roleCategory === 'platform') {
        userType = 'core_consultant';
      } else if (roleCategory === 'recruitment') {
        userType = 'recruitment_partner';
      } else if (organizationId) {
        userType = 'hosted_org_user';
      }
      
      // Create user data with enforced role assignment
      const newUserData = {
        email: email.toLowerCase(),
        firstName,
        lastName,
        profile: {
          displayName: `${firstName} ${lastName}`.trim()
        },
        userType,
        role: {
          primary: finalRole  // Use enforced role, not requested role
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
          source: context.source || 'web',
          registrationContext: {
            isPublicRegistration,
            hasVerification,
            isInternalProcess,
            requestedRole,
            assignedRole: finalRole
          }
        }
      });
      
      // Set password
      await auth.setPassword(password);
      
      // Generate verification token
      const verificationToken = auth.generateVerificationToken();
      
      await auth.save();
      
      // 🆕 UPDATED: Send verification email using AuthEmailService
      const emailResult = await AuthEmailService.sendVerificationEmail(user, verificationToken, context);
      
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
      
      // Audit log with role enforcement details
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
          requestedRole,
          assignedRole: finalRole,
          roleEnforced: requestedRole !== finalRole,
          userType,
          organizationId,
          registrationMethod: isPublicRegistration ? 'public' : 'verified'
        }
      });
      
      // Include role enforcement information in response
      const responseMessage = emailResult.success 
        ? (finalRole !== requestedRole 
          ? `Registration successful with ${finalRole} role. Please check your email to verify your account.`
          : 'Registration successful. Please check your email to verify your account.')
        : 'Registration successful. Verification email could not be sent - please contact support for assistance.';
      
      return {
        success: true,
        message: responseMessage,
        data: {
          user: {
            id: user._id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role
          },
          tokens: sessionData,
          message: responseMessage,
          emailStatus: emailResult.success ? 'sent' : 'failed',
          roleAssignment: {
            requested: requestedRole,
            assigned: finalRole,
            enforced: requestedRole !== finalRole,
            reason: finalRole !== requestedRole ? 'Business policy enforcement' : 'Role assignment approved'
          },
          ...(config.app.env === 'development' && !emailResult.success && {
            verificationUrl: emailResult.fallbackUrl
          })
        }
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
          error: error.message,
          requestedRole: userData.role
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
        // Get enabled MFA methods
        const enabledMethods = auth.mfa.methods.filter(m => m.enabled);
        
        // For SMS and email methods, create active challenge
        const smsOrEmailMethod = enabledMethods.find(m => m.type === 'sms' || m.type === 'email');
        if (smsOrEmailMethod) {
          await this.createMfaChallenge(user._id, smsOrEmailMethod.type);
        }
        
        return {
          success: false,
          requiresMfa: true,
          userId: user._id,
          mfaMethods: enabledMethods.map(m => ({ type: m.type, isPrimary: m.isPrimary }))
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
        
        // 🆕 NEW: Send verification success email
        try {
          await AuthEmailService.sendVerificationSuccessEmail(user, context);
        } catch (emailError) {
          logger.warn('Failed to send verification success email', {
            error: emailError.message,
            userId: user._id
          });
          // Don't fail the verification if email sending fails
        }
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
      
      // 🆕 UPDATED: Send verification email using AuthEmailService
      await AuthEmailService.sendVerificationEmail(user, verificationToken, context);
      
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
      
      // 🆕 UPDATED: Send password reset email using AuthEmailService
      await AuthEmailService.sendPasswordResetEmail(user, resetToken, context);
      
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
   * @param {string} resetData.token - Reset token
   * @param {string} resetData.newPassword - New password
   * @param {string} resetData.confirmPassword - Password confirmation
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Reset result
   */
  static async resetPassword(resetData, context) {
    try {
      const { token, newPassword, confirmPassword } = resetData;
      
      // Validate required fields
      if (!token) {
        throw new ValidationError('Reset token is required');
      }
      
      if (!newPassword) {
        throw new ValidationError('New password is required');
      }
      
      if (!confirmPassword) {
        throw new ValidationError('Password confirmation is required');
      }
      
      // Validate password confirmation
      if (newPassword !== confirmPassword) {
        throw new ValidationError('Passwords do not match');
      }
      
      // Find auth by reset token
      const auth = await Auth.findByPasswordResetToken(token);
      if (!auth) {
        throw new ValidationError('Invalid or expired reset token');
      }
      
      // Check if token is expired (additional safety check)
      if (auth.security.passwordReset.expiresAt && 
          new Date() > new Date(auth.security.passwordReset.expiresAt)) {
        throw new ValidationError('Reset token has expired');
      }
      
      // Validate new password strength
      const passwordValidation = this.validatePasswordStrength(newPassword);
      if (!passwordValidation.valid) {
        throw new ValidationError(passwordValidation.message);
      }
      
      // Check if new password is same as current password
      const isSamePassword = await auth.verifyPassword(newPassword);
      if (isSamePassword) {
        throw new ValidationError('New password must be different from your current password');
      }
      
      // Set new password
      await auth.setPassword(newPassword);
      
      // Clear reset token and related data
      auth.security.passwordReset = {
        token: null,
        expiresAt: null,
        requestedAt: null,
        requestedFrom: null
      };
      
      // Clear any login attempts
      auth.security.loginAttempts = {
        count: 0,
        lastAttempt: null,
        lockedUntil: null
      };
      
      // Update security tracking
      auth.security.passwordChangedAt = new Date();
      auth.security.requirePasswordChange = false;
      
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
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      // 🆕 UPDATED: Send password changed notification using AuthEmailService
      try {
        await AuthEmailService.sendPasswordChangedEmail(user, context);
      } catch (emailError) {
        logger.warn('Failed to send password changed email', {
          error: emailError.message,
          userId: user._id
        });
        // Don't fail the password reset if email sending fails
      }
      
      // Audit log
      await AuditService.log({
        type: 'password_reset_completed',
        action: 'reset_password',
        category: 'authentication',
        result: 'success',
        userId: auth.userId,
        severity: 'high',
        metadata: {
          ...context,
          resetTokenUsed: true,
          sessionsRevoked: auth.sessions.filter(s => !s.isActive).length
        }
      });
      
      return {
        success: true,
        message: 'Password reset successful. Please login with your new password.',
        data: {
          passwordChanged: true,
          sessionsRevoked: true,
          loginRequired: true
        }
      };
      
    } catch (error) {
      // Log the error with context
      logger.error('Password reset error', {
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack
        },
        context,
        resetData: {
          token: resetData.token ? '[REDACTED]' : null,
          hasNewPassword: !!resetData.newPassword,
          hasConfirmPassword: !!resetData.confirmPassword
        }
      });
      
      // Re-throw the error to be handled by the controller
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
      
      // 🆕 UPDATED: Send notification using AuthEmailService
      try {
        await AuthEmailService.sendPasswordChangedEmail(user, context);
      } catch (emailError) {
        logger.warn('Failed to send password changed email', {
          error: emailError.message,
          userId
        });
        // Don't fail the password change if email sending fails
      }
      
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
   * @param {Object} setupData - Setup data (contains phoneNumber for SMS)
   * @returns {Promise<Object>} Setup result
   */
  static async setupMfa(userId, method, context, setupData) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      const user = await User.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      let result;
      
      switch (method) {
        case 'totp':
          result = await this.setupTotpMfa(user, auth);
          break;
          
        case 'sms':
          result = await this.setupSmsMfa(user, auth, setupData);
          break;
          
        case 'email':
          result = await this.setupEmailMfa(user, auth);
          break;
          
        case 'backup_codes':
          result = await this.setupBackupCodes(user, auth);
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
        ...result
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
    // Use config.app.name||config.server.name for TOTP issuer
    const appName = config.app.name || config.server.name || 'Insightserenity';
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `${appName} (${user.email})`,
      issuer: appName,
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
   * Setup SMS MFA
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @param {Object} setupData - Contains phoneNumber
   * @returns {Promise<Object>} SMS setup data
   */
  static async setupSmsMfa(user, auth, setupData) {
    if (!setupData || !setupData.phoneNumber) {
      throw new ValidationError('Phone number is required for SMS MFA setup');
    }
    
    const { phoneNumber } = setupData;
    
    // Validate phone number format
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    if (!phoneRegex.test(phoneNumber.replace(/[\s\-\(\)]/g, ''))) {
      throw new ValidationError('Please provide a valid phone number in international format');
    }
    
    // Generate verification code
    const verificationCode = crypto.randomInt(100000, 999999).toString();
    const setupToken = crypto.randomBytes(32).toString('hex');
    
    // Hash the verification code for storage
    const hashedCode = crypto.createHash('sha256').update(verificationCode).digest('hex');
    
    // Store pending setup
    auth.mfa.pendingSetup = {
      method: 'sms',
      phoneNumber,
      setupToken,
      verificationCode: hashedCode,
      expiresAt: new Date(Date.now() + 600000), // 10 minutes
      attemptsRemaining: 3
    };
    
    await auth.save();
    
    // For development, log the code
    if (config.app.env === 'development') {
      logger.info('SMS Verification Code (Development)', {
        phoneNumber: phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2'),
        code: verificationCode,
        setupToken
      });
    }
    
    return {
      setupToken,
      phoneNumber: phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2'),
      expiresIn: 600,
      message: 'Verification code sent to your phone. Enter the 6-digit code to complete setup.'
    };
  }

  /**
   * Setup Email MFA
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @returns {Promise<Object>} Email setup data
   */
  static async setupEmailMfa(user, auth) {
    // Generate verification code
    const verificationCode = crypto.randomInt(100000, 999999).toString();
    const setupToken = crypto.randomBytes(32).toString('hex');
    
    // Hash the verification code for storage
    const hashedCode = crypto.createHash('sha256').update(verificationCode).digest('hex');
    
    // Store pending setup
    auth.mfa.pendingSetup = {
      method: 'email',
      email: user.email,
      setupToken,
      verificationCode: hashedCode,
      expiresAt: new Date(Date.now() + 600000), // 10 minutes
      attemptsRemaining: 3
    };
    
    await auth.save();
    
    // For development, log the code
    if (config.app.env === 'development') {
      logger.info('Email Verification Code (Development)', {
        email: user.email,
        code: verificationCode,
        setupToken
      });
    }
    
    return {
      setupToken,
      email: user.email,
      expiresIn: 600,
      message: 'Verification code sent to your email address. Enter the 6-digit code to complete setup.'
    };
  }

  /**
   * Setup Backup Codes MFA
   * @param {Object} user - User object
   * @param {Object} auth - Auth object
   * @returns {Promise<Object>} Backup codes setup data
   */
  static async setupBackupCodes(user, auth) {
    const setupToken = crypto.randomBytes(32).toString('hex');
    
    // Generate backup codes
    const codes = [];
    const plainCodes = [];
    
    for (let i = 0; i < 10; i++) {
      const plainCode = crypto.randomBytes(4).toString('hex').toUpperCase();
      const hashedCode = crypto.createHash('sha256').update(plainCode).digest('hex');
      
      codes.push({
        code: hashedCode,
        used: false,
        generatedAt: new Date()
      });
      plainCodes.push(plainCode);
    }
    
    // Store pending setup with generated codes
    auth.mfa.pendingSetup = {
      method: 'backup_codes',
      codes,
      setupToken,
      expiresAt: new Date(Date.now() + 3600000) // 1 hour
    };
    
    await auth.save();
    
    return {
      setupToken,
      codes: plainCodes,
      message: 'Save these backup codes in a secure place. You will need to confirm setup by providing one of these codes.',
      warning: 'These codes will only be shown once. Store them securely as they can be used to access your account if you lose your primary MFA device.'
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
          const secret = await EncryptionService.decrypt(auth.mfa.pendingSetup.secret.encrypted);
          
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

        case 'sms':
          // Check remaining attempts
          if (auth.mfa.pendingSetup.attemptsRemaining <= 0) {
            throw new ValidationError('Maximum verification attempts exceeded. Please restart SMS setup.');
          }
          
          // Hash the provided code and compare
          const hashedSmsCode = crypto.createHash('sha256').update(code).digest('hex');
          
          if (hashedSmsCode === auth.mfa.pendingSetup.verificationCode) {
            // Add SMS MFA method
            auth.addMfaMethod('sms', {
              phoneNumber: auth.mfa.pendingSetup.phoneNumber,
              verifiedAt: new Date()
            });
            verified = true;
          } else {
            // Decrement attempts
            auth.mfa.pendingSetup.attemptsRemaining -= 1;
            await auth.save();
            throw new ValidationError(`Invalid verification code. ${auth.mfa.pendingSetup.attemptsRemaining} attempts remaining.`);
          }
          break;

        case 'email':
          // Check remaining attempts
          if (auth.mfa.pendingSetup.attemptsRemaining <= 0) {
            throw new ValidationError('Maximum verification attempts exceeded. Please restart email setup.');
          }
          
          // Hash the provided code and compare
          const hashedEmailCode = crypto.createHash('sha256').update(code).digest('hex');
          
          if (hashedEmailCode === auth.mfa.pendingSetup.verificationCode) {
            // Add Email MFA method
            auth.addMfaMethod('email', {
              email: auth.mfa.pendingSetup.email,
              verifiedAt: new Date()
            });
            verified = true;
          } else {
            // Decrement attempts
            auth.mfa.pendingSetup.attemptsRemaining -= 1;
            await auth.save();
            throw new ValidationError(`Invalid verification code. ${auth.mfa.pendingSetup.attemptsRemaining} attempts remaining.`);
          }
          break;

        case 'backup_codes':
          // For backup codes, verify that the user provides one of the generated codes
          const providedCodeHash = crypto.createHash('sha256').update(code.toUpperCase()).digest('hex');
          const codeExists = auth.mfa.pendingSetup.codes.some(c => c.code === providedCodeHash);
          
          if (codeExists) {
            // Add backup codes MFA method
            auth.addMfaMethod('backup_codes', {
              codes: auth.mfa.pendingSetup.codes,
              generatedAt: new Date()
            });
            verified = true;
          } else {
            throw new ValidationError('Invalid backup code. Please provide one of the generated backup codes.');
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

      try {
        // Clear pending setup
        auth.mfa.pendingSetup = undefined;
        auth.markModified('mfa.pendingSetup');
        await auth.save();

        // Verify cleanup
        const verifyAuth = await Auth.findById(auth._id);
        if (verifyAuth.mfa.pendingSetup) {
          logger.warn('Failed to clear pendingSetup field after verification', { userId, method });
        }
      } catch (error) {
        logger.error('Error clearing pending setup after MFA verification', { error, userId, method });
        throw error;
      }
      
      // Get user for notification
      const user = await User.findById(userId);
      
      // 🆕 NEW: Send MFA enabled notification
      try {
        await AuthEmailService.sendMfaEnabledEmail(user, method, context);
      } catch (emailError) {
        logger.warn('Failed to send MFA enabled email', {
          error: emailError.message,
          userId,
          method
        });
        // Don't fail MFA setup if email sending fails
      }
      
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
          const secret = await EncryptionService.decrypt(mfaMethod.config.totpSecret.encrypted);
          
          // Verify TOTP code
          verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token: code,
            window: 2
          });
          break;

        case 'sms':
          // Find temporary SMS challenge
          const smsChallenge = auth.mfa.activeChallenge;
          if (!smsChallenge || smsChallenge.method !== 'sms' || smsChallenge.expiresAt < new Date()) {
            throw new ValidationError('SMS verification session expired. Please restart login process.');
          }
          
          // Verify SMS code
          const hashedSmsLoginCode = crypto.createHash('sha256').update(code).digest('hex');
          if (hashedSmsLoginCode === smsChallenge.code) {
            verified = true;
            // Clear active challenge
            auth.mfa.activeChallenge = undefined;
          }
          break;

        case 'email':
          // Find temporary email challenge
          const emailChallenge = auth.mfa.activeChallenge;
          if (!emailChallenge || emailChallenge.method !== 'email' || emailChallenge.expiresAt < new Date()) {
            throw new ValidationError('Email verification session expired. Please restart login process.');
          }
          
          // Verify email code
          const hashedEmailLoginCode = crypto.createHash('sha256').update(code).digest('hex');
          if (hashedEmailLoginCode === emailChallenge.code) {
            verified = true;
            // Clear active challenge
            auth.mfa.activeChallenge = undefined;
          }
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
   * Create MFA challenge for SMS/Email methods
   * @param {string} userId - User ID
   * @param {string} method - MFA method
   * @returns {Promise<Object>} Challenge result
   */
  static async createMfaChallenge(userId, method) {
    const auth = await Auth.findOne({ userId });
    if (!auth) {
      throw new NotFoundError('Authentication record not found');
    }
    
    const user = await User.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found');
    }
    
    const mfaMethod = auth.mfa.methods.find(m => m.type === method && m.enabled);
    if (!mfaMethod) {
      throw new ValidationError('MFA method not available');
    }
    
    let challengeResult = {};
    
    switch (method) {
      case 'sms':
        const verificationCode = crypto.randomInt(100000, 999999).toString();
        const hashedCode = crypto.createHash('sha256').update(verificationCode).digest('hex');
        
        auth.mfa.activeChallenge = {
          method: 'sms',
          code: hashedCode,
          expiresAt: new Date(Date.now() + 300000), // 5 minutes
          attemptsRemaining: 3
        };
        
        await auth.save();
        
        // Log for development
        if (config.app.env === 'development') {
          logger.info('SMS Login Code (Development)', {
            phoneNumber: mfaMethod.config.phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2'),
            code: verificationCode
          });
        }
        
        challengeResult = {
          method: 'sms',
          maskedPhone: mfaMethod.config.phoneNumber.replace(/(\+\d{1,3})\d{6,10}(\d{3})/, '$1******$2'),
          expiresIn: 300
        };
        break;
        
      case 'email':
        const emailCode = crypto.randomInt(100000, 999999).toString();
        const hashedEmailCode = crypto.createHash('sha256').update(emailCode).digest('hex');
        
        auth.mfa.activeChallenge = {
          method: 'email',
          code: hashedEmailCode,
          expiresAt: new Date(Date.now() + 300000), // 5 minutes
          attemptsRemaining: 3
        };
        
        await auth.save();
        
        // Log for development
        if (config.app.env === 'development') {
          logger.info('Email Login Code (Development)', {
            email: user.email,
            code: emailCode
          });
        }
        
        challengeResult = {
          method: 'email',
          email: user.email,
          expiresIn: 300
        };
        break;
        
      default:
        throw new ValidationError(`Challenge creation not supported for method: ${method}`);
    }
    
    return challengeResult;
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
   * Get user sessions with enhanced current session detection
   * @param {string} userId - User ID
   * @param {string} currentSessionId - Current session ID for marking
   * @returns {Promise<Object>} User sessions with proper current session marking
   */
  static async getUserSessions(userId, currentSessionId = null) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      const now = new Date();
      const activeSessions = auth.sessions
        .filter(s => {
          // Session must be active and not expired
          const isActive = s.isActive && (!s.expiresAt || s.expiresAt > now);
          return isActive;
        })
        .map(s => ({
          sessionId: s.sessionId,
          deviceInfo: s.deviceInfo || {
            userAgent: 'Unknown',
            platform: 'Unknown',
            browser: 'Unknown'
          },
          location: s.location || {
            ip: 'Unknown',
            coordinates: {}
          },
          createdAt: s.createdAt,
          lastActivityAt: s.lastActivityAt,
          expiresAt: s.expiresAt,
          isCurrent: currentSessionId ? s.sessionId === currentSessionId : false
        }))
        .sort((a, b) => b.lastActivityAt - a.lastActivityAt);
      
      // Enhanced session analysis
      const currentSessionIndex = activeSessions.findIndex(s => s.isCurrent);
      const otherSessionsCount = activeSessions.length - (currentSessionIndex >= 0 ? 1 : 0);
      
      return {
        success: true,
        sessions: activeSessions,
        totalActive: activeSessions.length,
        currentSessionExists: currentSessionIndex >= 0,
        otherSessionsCount,
        metadata: {
          hasMultipleSessions: activeSessions.length > 1,
          oldestSession: activeSessions.length > 0 ? activeSessions[activeSessions.length - 1].createdAt : null,
          newestSession: activeSessions.length > 0 ? activeSessions[0].createdAt : null
        }
      };
      
    } catch (error) {
      logger.error('Get sessions error', { error, userId });
      throw error;
    }
  }

  /**
   * Revoke specific session with enterprise behavior
   * @param {string} userId - User ID
   * @param {string} sessionId - Session ID to revoke
   * @param {string} currentSessionId - Current user's session ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Revoke result
   */
  static async revokeSession(userId, sessionId, currentSessionId, context) {
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
      
      const isCurrentSession = sessionId === currentSessionId;
      
      // Revoke session
      auth.revokeSession(sessionId, isCurrentSession ? 'User revoked current session' : 'User revoked session');
      await auth.save();
      
      // If revoking current session, blacklist associated tokens
      let tokensBlacklisted = false;
      if (isCurrentSession) {
        try {
          // Find and blacklist all tokens for this session
          const accessTokens = await Token.find({ 
            userId, 
            sessionId,
            type: 'access',
            isActive: true 
          });
          
          const refreshTokens = await Token.find({ 
            userId, 
            sessionId,
            type: 'refresh',
            isActive: true 
          });
          
          // Blacklist all associated tokens
          for (const token of [...accessTokens, ...refreshTokens]) {
            if (TokenBlacklistService && typeof TokenBlacklistService.blacklistToken === 'function') {
              await TokenBlacklistService.blacklistToken(token.value, token.type, 'session_revoked');
            }
            token.isActive = false;
            token.revokedAt = new Date();
            token.revokedReason = 'session_revoked';
            await token.save();
          }
          tokensBlacklisted = true;
        } catch (tokenError) {
          logger.error('Failed to blacklist tokens during session revocation', {
            error: tokenError.message,
            userId,
            sessionId
          });
        }
      }
      
      // Audit log
      await AuditService.log({
        type: isCurrentSession ? 'current_session_revoked' : 'session_revoked',
        action: 'revoke_session',
        category: 'authentication',
        result: 'success',
        userId,
        metadata: {
          ...context,
          revokedSessionId: sessionId,
          isCurrentSession,
          tokensBlacklisted,
          deviceInfo: session.deviceInfo,
          immediateLogout: isCurrentSession
        }
      });
      
      return {
        success: true,
        message: isCurrentSession 
          ? 'Current session revoked successfully. You will be logged out immediately.' 
          : 'Session revoked successfully',
        isCurrentSession,
        requiresLogout: isCurrentSession,
        tokensInvalidated: isCurrentSession && tokensBlacklisted
      };
      
    } catch (error) {
      logger.error('Revoke session error', { error, userId, sessionId });
      throw error;
    }
  }

  /**
   * Revoke all other sessions with enhanced validation
   * @param {string} userId - User ID
   * @param {string} currentSessionId - Current session ID to preserve
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Revoke result with detailed information
   */
  static async revokeAllOtherSessions(userId, currentSessionId, context) {
    try {
      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }
      
      if (!currentSessionId) {
        throw new ValidationError('Current session ID is required to preserve active session');
      }
      
      let revokedCount = 0;
      const revokedSessions = [];
      const preservedSessions = [];
      
      // Process all sessions
      auth.sessions.forEach(session => {
        if (session.sessionId === currentSessionId) {
          // Preserve current session
          if (session.isActive) {
            preservedSessions.push({
              sessionId: session.sessionId,
              deviceInfo: session.deviceInfo
            });
          }
        } else if (session.isActive) {
          // Revoke other active sessions
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
      
      // Validate that current session exists and is preserved
      const currentSessionPreserved = preservedSessions.length > 0;
      if (!currentSessionPreserved) {
        logger.warn('Current session not found during bulk revocation', {
          userId,
          currentSessionId,
          totalSessions: auth.sessions.length
        });
      }
      
      if (revokedCount === 0) {
        return {
          success: true,
          message: 'No other active sessions to revoke',
          revokedCount: 0,
          currentSessionPreserved,
          details: {
            totalActiveSessions: preservedSessions.length,
            message: currentSessionPreserved 
              ? 'You have only one active session (current session)' 
              : 'No sessions found to revoke'
          }
        };
      }
      
      // Save changes
      await auth.save();
      
      // Audit log with enhanced metadata
      await AuditService.log({
        type: 'sessions_revoked_bulk',
        action: 'revoke_all_other_sessions',
        category: 'authentication',
        result: 'success',
        userId,
        metadata: {
          ...context,
          currentSessionId,
          currentSessionPreserved,
          revokedCount,
          preservedCount: preservedSessions.length,
          revokedSessions: revokedSessions.map(s => ({
            sessionId: s.sessionId,
            deviceInfo: s.deviceInfo
          })),
          preservedSessions: preservedSessions.map(s => ({
            sessionId: s.sessionId,
            deviceInfo: s.deviceInfo
          }))
        }
      });
      
      return {
        success: true,
        message: `Successfully revoked ${revokedCount} other session${revokedCount !== 1 ? 's' : ''}`,
        revokedCount,
        currentSessionPreserved,
        details: {
          revokedSessions: revokedSessions.length,
          preservedSessions: preservedSessions.length,
          totalProcessed: revokedCount + preservedSessions.length
        }
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
   * Validate password strength using configuration-based requirements
   * @param {string} password - Password to validate
   * @param {Object} userContext - User context for validation (optional)
   * @returns {Object} Validation result
   */
  static validatePasswordStrength(password, userContext = {}) {
    // Access configuration values with appropriate fallbacks
    const minLength = config.auth.passwordMinLength || 8;
    const maxLength = config.auth.passwordMaxLength || 128;
    const requireUppercase = config.auth.requireUppercase !== false;
    const requireLowercase = config.auth.requireLowercase !== false;
    const requireNumbers = config.auth.requireNumbers !== false;
    const requireSpecialChars = config.auth.requireSpecialChars !== false;
    const allowCommonPasswords = config.auth.allowCommonPasswords === true;
    const allowSequentialChars = config.auth.allowSequentialChars === true;
    const allowRepeatedChars = config.auth.allowRepeatedChars === true;
    
    if (!password) {
      return {
        valid: false,
        message: 'Password is required'
      };
    }
    
    // Length validation
    if (password.length < minLength) {
      return {
        valid: false,
        message: `Password must be at least ${minLength} characters long`
      };
    }
    
    if (password.length > maxLength) {
      return {
        valid: false,
        message: `Password must not exceed ${maxLength} characters`
      };
    }
    
    // Character requirement validation
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
    
    // Common password validation
    if (!allowCommonPasswords) {
      const commonPasswords = [
        'password', '12345678', 'qwerty', 'abc123', 'password123',
        'admin123', 'welcome123', 'changeme123', 'newpassword123',
        'letmein', 'welcome', 'monkey', 'dragon', 'master'
      ];
      
      if (commonPasswords.includes(password.toLowerCase())) {
        return {
          valid: false,
          message: 'Password is too common. Please choose a more secure password.'
        };
      }
    }
    
    // Sequential character validation
    if (!allowSequentialChars) {
      const sequentialPatterns = [
        /(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i,
        /(?:123|234|345|456|567|678|789|890)/,
        /(?:qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)/i
      ];
      
      for (const pattern of sequentialPatterns) {
        if (pattern.test(password)) {
          return {
            valid: false,
            message: 'Password should not contain sequential characters'
          };
        }
      }
    }
    
    // Repeated character validation
    if (!allowRepeatedChars) {
      if (/(.)\1{2,}/.test(password)) {
        return {
          valid: false,
          message: 'Password should not contain three or more repeated characters'
        };
      }
    }
    
    // Context-based validation when user information is available
    if (userContext && typeof userContext === 'object') {
      if (userContext.email && typeof userContext.email === 'string') {
        const emailPart = userContext.email.split('@')[0].toLowerCase();
        if (emailPart.length > 3 && password.toLowerCase().includes(emailPart)) {
          return {
            valid: false,
            message: 'Password should not contain parts of your email address'
          };
        }
      }
      
      if (userContext.firstName && typeof userContext.firstName === 'string' && userContext.firstName.length > 2) {
        if (password.toLowerCase().includes(userContext.firstName.toLowerCase())) {
          return {
            valid: false,
            message: 'Password should not contain your first name'
          };
        }
      }
      
      if (userContext.lastName && typeof userContext.lastName === 'string' && userContext.lastName.length > 2) {
        if (password.toLowerCase().includes(userContext.lastName.toLowerCase())) {
          return {
            valid: false,
            message: 'Password should not contain your last name'
          };
        }
      }
      
      if (userContext.username && typeof userContext.username === 'string' && userContext.username.length > 2) {
        if (password.toLowerCase().includes(userContext.username.toLowerCase())) {
          return {
            valid: false,
            message: 'Password should not contain your username'
          };
        }
      }
    }
    
    // Calculate strength score for additional feedback
    const strengthResult = this.calculatePasswordStrength(password);
    
    return {
      valid: true,
      message: 'Password meets security requirements',
      strength: strengthResult
    };
  }

  /**
   * Calculate password strength score based on various factors
   * @param {string} password - Password to analyze
   * @returns {Object} Strength analysis with score and feedback
   */
  static calculatePasswordStrength(password) {
    if (!password || typeof password !== 'string') {
      return {
        score: 0,
        level: 'invalid',
        color: 'red',
        description: 'Invalid password',
        feedback: ['Password is required']
      };
    }
    
    let score = 0;
    const feedback = [];
    const criteria = {
      length: false,
      lowercase: false,
      uppercase: false,
      numbers: false,
      specialChars: false,
      variety: false,
      uniqueness: false
    };
    
    // Length scoring with configuration awareness
    const minLength = config.auth.passwordMinLength || 8;
    if (password.length >= minLength) {
      criteria.length = true;
      score += 2;
    }
    if (password.length >= minLength + 4) score += 1;
    if (password.length >= minLength + 8) score += 1;
    if (password.length >= minLength + 12) score += 1;
    
    // Character variety scoring
    if (/[a-z]/.test(password)) {
      criteria.lowercase = true;
      score += 1;
    }
    if (/[A-Z]/.test(password)) {
      criteria.uppercase = true;
      score += 1;
    }
    if (/[0-9]/.test(password)) {
      criteria.numbers = true;
      score += 1;
    }
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      criteria.specialChars = true;
      score += 2;
    }
    
    // Character set variety bonus
    const charTypes = [
      criteria.lowercase,
      criteria.uppercase,
      criteria.numbers,
      criteria.specialChars
    ].filter(Boolean).length;
    
    if (charTypes >= 3) {
      criteria.variety = true;
      score += 1;
    }
    if (charTypes === 4) {
      score += 1;
    }
    
    // Uniqueness and complexity scoring
    const uniqueChars = new Set(password.toLowerCase()).size;
    const uniquenessRatio = uniqueChars / password.length;
    
    if (uniquenessRatio > 0.7) {
      criteria.uniqueness = true;
      score += 1;
    }
    
    // Deduct points for weaknesses
    if (/(.)\1{2,}/.test(password)) {
      score -= 1;
      feedback.push('Avoid repeating characters');
    }
    
    if (/(?:123|abc|qwe)/i.test(password)) {
      score -= 1;
      feedback.push('Avoid sequential patterns');
    }
    
    // Generate feedback based on missing criteria
    if (!criteria.length) {
      feedback.push(`Use at least ${minLength} characters`);
    }
    if (!criteria.lowercase && config.auth.requireLowercase !== false) {
      feedback.push('Add lowercase letters');
    }
    if (!criteria.uppercase && config.auth.requireUppercase !== false) {
      feedback.push('Add uppercase letters');
    }
    if (!criteria.numbers && config.auth.requireNumbers !== false) {
      feedback.push('Add numbers');
    }
    if (!criteria.specialChars && config.auth.requireSpecialChars !== false) {
      feedback.push('Add special characters');
    }
    if (!criteria.variety) {
      feedback.push('Use a mix of different character types');
    }
    if (!criteria.uniqueness) {
      feedback.push('Use more varied characters');
    }
    
    // Determine strength level and appearance
    let level, color, description;
    if (score < 3) {
      level = 'very-weak';
      color = '#dc3545';
      description = 'Very weak password';
    } else if (score < 5) {
      level = 'weak';
      color = '#fd7e14';
      description = 'Weak password';
    } else if (score < 7) {
      level = 'fair';
      color = '#ffc107';
      description = 'Fair password strength';
    } else if (score < 9) {
      level = 'good';
      color = '#20c997';
      description = 'Good password strength';
    } else if (score < 11) {
      level = 'strong';
      color = '#28a745';
      description = 'Strong password';
    } else {
      level = 'excellent';
      color = '#007bff';
      description = 'Excellent password strength';
    }
    
    // Add positive feedback for strong passwords
    if (score >= 7 && feedback.length === 0) {
      feedback.push('Password strength is good');
    }
    
    return {
      score: Math.max(0, score),
      maxScore: 12,
      level,
      color,
      description,
      feedback,
      criteria,
      percentage: Math.min(100, Math.round((Math.max(0, score) / 12) * 100))
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

  /**
   * Upgrade user role with proper validation and business logic
   * @param {string} userId - User ID to upgrade
   * @param {string} newRole - Target role
   * @param {Object} verificationData - Verification context
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Upgrade result
   */
  static async upgradeUserRole(userId, newRole, verificationData, context) {
    try {
      // Get user and auth records
      const user = await User.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      const auth = await Auth.findOne({ userId });
      if (!auth) {
        throw new NotFoundError('Authentication record not found');
      }

      const currentRole = user.role.primary;

      // Validate upgrade path using permission middleware
      const canUpgrade = this.validateRoleUpgrade(currentRole, newRole, verificationData);
      if (!canUpgrade.valid) {
        throw new ValidationError(canUpgrade.message);
      }

      // Determine required user type for new role
      const roleCategory = PermissionMiddleware.getUserRoleCategory({ role: { primary: newRole } });
      let newUserType = user.userType;

      if (roleCategory === 'external' && newRole === 'client') {
        newUserType = 'hosted_org_user';
      } else if (roleCategory === 'internal') {
        newUserType = 'core_consultant';
      } else if (roleCategory === 'recruitment') {
        newUserType = 'recruitment_partner';
      }

      // Update user role and type
      user.role.primary = newRole;
      user.userType = newUserType;
      user.status = 'active'; // Ensure user is active after upgrade
      
      // Add upgrade tracking
      if (!user.roleHistory) {
        user.roleHistory = [];
      }
      
      user.roleHistory.push({
        fromRole: currentRole,
        toRole: newRole,
        upgradedAt: new Date(),
        upgradeReason: verificationData.salesApproved ? 'sales_approval' : 'payment_verification',
        upgradedBy: context.userId || userId,
        verificationData: {
          salesApproved: !!verificationData.salesApproved,
          paymentVerified: !!verificationData.paymentVerified
        }
      });

      await user.save();

      // Update auth metadata to track the upgrade
      auth.metadata.roleUpgrades = auth.metadata.roleUpgrades || [];
      auth.metadata.roleUpgrades.push({
        fromRole: currentRole,
        toRole: newRole,
        upgradedAt: new Date(),
        verificationMethod: verificationData.salesApproved ? 'sales_approval' : 'payment_verification'
      });

      await auth.save();

      // Audit log the role upgrade
      await AuditService.log({
        type: 'user_role_upgraded',
        action: 'upgrade_role',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        severity: 'high',
        target: {
          type: 'user',
          id: user._id.toString()
        },
        metadata: {
          ...context,
          fromRole: currentRole,
          toRole: newRole,
          userType: newUserType,
          verificationData: {
            salesApproved: !!verificationData.salesApproved,
            paymentVerified: !!verificationData.paymentVerified
          },
          upgradeReason: verificationData.salesApproved ? 'sales_approval' : 'payment_verification'
        }
      });

      logger.info('User role upgraded successfully', {
        userId: user._id,
        email: user.email,
        fromRole: currentRole,
        toRole: newRole,
        userType: newUserType,
        verificationMethod: verificationData.salesApproved ? 'sales_approval' : 'payment_verification'
      });

      return {
        success: true,
        message: `Role successfully upgraded from ${currentRole} to ${newRole}`,
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          role: user.role,
          userType: user.userType,
          status: user.status
        },
        upgrade: {
          fromRole: currentRole,
          toRole: newRole,
          upgradedAt: new Date(),
          verificationMethod: verificationData.salesApproved ? 'sales_approval' : 'payment_verification'
        }
      };

    } catch (error) {
      logger.error('Role upgrade error', {
        error: error.message,
        userId,
        newRole,
        verificationData
      });

      // Audit failed upgrade attempt
      await AuditService.log({
        type: 'role_upgrade_failed',
        action: 'upgrade_role',
        category: 'authentication',
        result: 'failure',
        userId,
        severity: 'medium',
        metadata: {
          ...context,
          targetRole: newRole,
          error: error.message,
          verificationData
        }
      });

      throw error;
    }
  }

  /**
   * Validate role upgrade path and requirements
   * @param {string} currentRole - Current user role
   * @param {string} newRole - Target role
   * @param {Object} verificationData - Verification context
   * @returns {Object} Validation result
   */
  static validateRoleUpgrade(currentRole, newRole, verificationData) {
    // Define valid upgrade paths
    const validUpgradePaths = {
      prospect: ['client'],
      client: ['org_owner'], // Clients can become organization owners
      // Add other valid upgrade paths as needed
    };

    // Check if upgrade path is valid
    const allowedTargets = validUpgradePaths[currentRole] || [];
    if (!allowedTargets.includes(newRole)) {
      return {
        valid: false,
        message: `Invalid upgrade path from ${currentRole} to ${newRole}. Allowed upgrades: ${allowedTargets.join(', ')}`
      };
    }

    // Validate requirements for specific role upgrades
    if (newRole === 'client') {
      if (!verificationData.salesApproved && !verificationData.paymentVerified) {
        return {
          valid: false,
          message: 'Client role requires either sales approval or payment verification'
        };
      }
    }

    // Add more role-specific validation as needed
    if (newRole === 'org_owner') {
      if (!verificationData.organizationCreated) {
        return {
          valid: false,
          message: 'Organization owner role requires an active organization'
        };
      }
    }

    return {
      valid: true,
      message: 'Role upgrade validation passed'
    };
  }

  /**
   * Downgrade user role (administrative function)
   * @param {string} userId - User ID to downgrade
   * @param {string} newRole - Target role
   * @param {Object} adminContext - Admin context
   * @returns {Promise<Object>} Downgrade result
   */
  static async downgradeUserRole(userId, newRole, adminContext) {
    try {
      if (!adminContext.isAdmin) {
        throw new ValidationError('Role downgrades require administrative privileges');
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new NotFoundError('User not found');
      }

      const currentRole = user.role.primary;

      // Validate downgrade is necessary
      if (currentRole === newRole) {
        throw new ValidationError('User already has the specified role');
      }

      // Update user role
      user.role.primary = newRole;
      
      // Add downgrade tracking
      if (!user.roleHistory) {
        user.roleHistory = [];
      }
      
      user.roleHistory.push({
        fromRole: currentRole,
        toRole: newRole,
        downgradedAt: new Date(),
        downgradeReason: adminContext.reason || 'administrative_action',
        downgradedBy: adminContext.adminUserId
      });

      await user.save();

      // Audit log
      await AuditService.log({
        type: 'user_role_downgraded',
        action: 'downgrade_role',
        category: 'administration',
        result: 'success',
        userId: user._id,
        severity: 'high',
        target: {
          type: 'user',
          id: user._id.toString()
        },
        metadata: {
          fromRole: currentRole,
          toRole: newRole,
          adminUserId: adminContext.adminUserId,
          reason: adminContext.reason
        }
      });

      return {
        success: true,
        message: `Role downgraded from ${currentRole} to ${newRole}`,
        user: {
          id: user._id,
          email: user.email,
          role: user.role,
          userType: user.userType
        }
      };

    } catch (error) {
      logger.error('Role downgrade error', { error, userId, newRole });
      throw error;
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