// server/shared/auth/controllers/auth-controller.js
/**
 * @file Authentication Controller
 * @description Handles authentication-related HTTP requests
 * @version 3.0.0
 */

const config = require('../../config/config');
const { 
  AuthenticationError, 
  ValidationError,
  NotFoundError 
} = require('../../utils/app-error');
const { asyncHandler } = require('../../utils/async-handler');
const logger = require('../../utils/logger');
const responseHandler = require('../../utils/response-handler');
const AuthService = require('../services/auth-service');

/**
 * Authentication Controller Class
 * @class AuthController
 */
class AuthController {
  /**
   * Register new user
   * @route   POST /api/auth/register
   * @access  Public
   */
  static register = asyncHandler(async (req, res) => {
    const userData = {
      email: req.body.email,
      password: req.body.password,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      organizationId: req.body.organizationId,
      role: req.body.role,
      acceptTerms: req.body.acceptTerms
    };
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      origin: req.get('origin'),
      language: req.get('accept-language'),
      source: 'web'
    };
    
    const result = await AuthService.register(userData, context);
    
    // Set cookies if session was created
    if (result.session) {
      res.cookie('accessToken', result.session.accessToken, {
        httpOnly: true,
        secure: config.server.isProduction,
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });
      
      res.cookie('refreshToken', result.session.refreshToken, {
        httpOnly: true,
        secure: config.server.isProduction,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });
    }
    
    responseHandler.success(res, result, 'Registration successful', 201);
  });
  
  // /**
  //  * Login user
  //  * @route   POST /api/auth/login
  //  * @access  Public
  //  */
  // static login = asyncHandler(async (req, res) => {
  //   const credentials = {
  //     email: req.body.email,
  //     password: req.body.password,
  //     rememberMe: req.body.rememberMe || false,
  //     deviceId: req.body.deviceId
  //   };
    
  //   const context = {
  //     ip: req.ip,
  //     userAgent: req.get('user-agent'),
  //     origin: req.get('origin')
  //   };
    
  //   const result = await AuthService.login(credentials, context);
    
  //   // Handle MFA requirement
  //   if (result.requiresMfa) {
  //     return responseHandler.success(res, {
  //       requiresMfa: true,
  //       userId: result.userId,
  //       challengeId: result.challengeId,
  //       mfaMethods: result.mfaMethods
  //     }, 'Multi-factor authentication required');
  //   }
    
  //   // Handle password change requirement
  //   if (result.requiresPasswordChange) {
  //     return responseHandler.success(res, {
  //       requiresPasswordChange: true,
  //       userId: result.userId
  //     }, 'Password change required');
  //   }
    
  //   // Set cookies
  //   const cookieOptions = {
  //     httpOnly: true,
  //     secure: config.server.isProduction,
  //     sameSite: 'strict'
  //   };
    
  //   res.cookie('accessToken', result.accessToken, {
  //     ...cookieOptions,
  //     maxAge: 15 * 60 * 1000 // 15 minutes
  //   });
    
  //   res.cookie('refreshToken', result.refreshToken, {
  //     ...cookieOptions,
  //     maxAge: credentials.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000
  //   });
    
  //   if (result.trustToken) {
  //     res.cookie('trustToken', result.trustToken, {
  //       ...cookieOptions,
  //       maxAge: 90 * 24 * 60 * 60 * 1000 // 90 days
  //     });
  //   }
    
  //   responseHandler.success(res, result, 'Login successful');
  // });

  /**
   * Login user
   * @route   POST /api/auth/login
   * @access  Public
   */
  static login = asyncHandler(async (req, res) => {
    // Extract and validate credentials (moved outside try block for error handling access)
    const credentials = {
      email: req.body.email,
      password: req.body.password,
      rememberMe: req.body.rememberMe || false,
      deviceId: req.body.deviceId
    };

    // Build request context for audit and security tracking (moved outside try block)
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      origin: req.get('origin'),
      language: req.get('accept-language'),
      source: 'web',
      timestamp: new Date()
    };

    try {

      // Log login attempt for security monitoring
      logger.info('Login attempt initiated', {
        email: credentials.email,
        ip: context.ip,
        userAgent: context.userAgent,
        rememberMe: credentials.rememberMe
      });

      // Attempt authentication through AuthService
      const result = await AuthService.login(credentials, context);

      // Handle multi-factor authentication requirement
      if (result.requiresMfa) {
        logger.info('MFA required for login', {
          userId: result.userId,
          mfaMethods: result.mfaMethods
        });

        return responseHandler.success(res, {
          requiresMfa: true,
          userId: result.userId,
          challengeId: result.challengeId,
          mfaMethods: result.mfaMethods,
          message: 'Multi-factor authentication required'
        }, 'Multi-factor authentication required', 202);
      }

      // Handle mandatory password change requirement
      if (result.requiresPasswordChange) {
        logger.info('Password change required for login', {
          userId: result.userId,
          reason: result.passwordChangeReason
        });

        return responseHandler.success(res, {
          requiresPasswordChange: true,
          userId: result.userId,
          reason: result.passwordChangeReason,
          message: 'Password change required before login'
        }, 'Password change required', 202);
      }

      // Configure secure cookie options based on environment
      const cookieOptions = {
        httpOnly: true,
        secure: config.server.isProduction,
        sameSite: config.server.isProduction ? 'strict' : 'lax',
        path: '/'
      };

      // Set access token cookie with appropriate expiration
      res.cookie('accessToken', result.accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      // Set refresh token cookie with extended expiration for remember me
      const refreshTokenMaxAge = credentials.rememberMe 
        ? 30 * 24 * 60 * 60 * 1000  // 30 days for remember me
        : 7 * 24 * 60 * 60 * 1000;  // 7 days standard

      res.cookie('refreshToken', result.refreshToken, {
        ...cookieOptions,
        maxAge: refreshTokenMaxAge
      });

      // Set trust token if device is trusted
      if (result.trustToken) {
        res.cookie('trustToken', result.trustToken, {
          ...cookieOptions,
          maxAge: 90 * 24 * 60 * 60 * 1000 // 90 days for trusted devices
        });
      }

      // Log successful login for audit trail
      logger.info('Login successful', {
        userId: result.user.id,
        email: result.user.email,
        sessionId: result.sessionId,
        rememberMe: credentials.rememberMe,
        hasTrustToken: !!result.trustToken
      });

      // Return successful login response
      return responseHandler.success(res, {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        tokenType: 'Bearer',
        expiresIn: result.expiresIn,
        sessionId: result.sessionId,
        rememberMe: credentials.rememberMe
      }, 'Login successful');

    } catch (error) {
      // Handle email verification specific error
      if (error.message && error.message.includes('verify your email')) {
        logger.warn('Login blocked - email not verified', {
          email: credentials.email,
          ip: context.ip,
          userAgent: context.userAgent
        });

        return responseHandler.error(res, error.message, 403, {
          code: 'EMAIL_NOT_VERIFIED',
          needsEmailVerification: true,
          canResendVerification: true,
          email: credentials.email,
          actions: {
            resendVerification: {
              url: '/api/v1/auth/resend-verification',
              method: 'POST',
              description: 'Resend email verification'
            }
          }
        });
      }

      // Handle authentication errors (invalid credentials, locked accounts)
      if (error instanceof AuthenticationError) {
        logger.warn('Authentication failed', {
          email: credentials.email,
          error: error.message,
          ip: context.ip,
          userAgent: context.userAgent,
          code: error.code
        });

        // Check if account is locked
        if (error.message.includes('locked')) {
          return responseHandler.error(res, error.message, 423, {
            code: 'ACCOUNT_LOCKED',
            lockedUntil: error.details?.lockedUntil,
            message: 'Account temporarily locked due to multiple failed login attempts'
          });
        }

        // Handle invalid credentials with remaining attempts info
        if (error.details && error.details.remainingAttempts !== undefined) {
          return responseHandler.error(res, error.message, 401, {
            code: 'INVALID_CREDENTIALS',
            remainingAttempts: error.details.remainingAttempts,
            warningThreshold: error.details.remainingAttempts <= 2
          });
        }

        // Generic authentication error response
        return responseHandler.error(res, 'Invalid email or password', 401, {
          code: 'AUTHENTICATION_FAILED'
        });
      }

      // Handle validation errors (malformed input)
      if (error instanceof ValidationError) {
        logger.warn('Login validation error', {
          email: credentials.email,
          error: error.message,
          ip: context.ip
        });

        return responseHandler.error(res, error.message, 400, {
          code: 'VALIDATION_ERROR',
          details: error.details
        });
      }

      // Handle rate limiting errors
      if (error.statusCode === 429) {
        logger.warn('Login rate limit exceeded', {
          email: credentials.email,
          ip: context.ip,
          userAgent: context.userAgent
        });

        return responseHandler.error(res, 'Too many login attempts. Please try again later.', 429, {
          code: 'RATE_LIMIT_EXCEEDED',
          retryAfter: error.retryAfter
        });
      }

      // Handle unexpected server errors
      logger.error('Unexpected login error', {
        email: credentials.email,
        error: error.message,
        stack: error.stack,
        ip: context.ip,
        userAgent: context.userAgent
      });

      return responseHandler.error(res, 'An unexpected error occurred during login', 500, {
        code: 'INTERNAL_SERVER_ERROR',
        timestamp: new Date().toISOString()
      });
    }
  });
  
  /**
   * Logout user
   * @route   POST /api/auth/logout
   * @access  Private
   */
  static logout = asyncHandler(async (req, res) => {
    const sessionData = {
      accessToken: req.token || req.cookies.accessToken,
      refreshToken: req.body.refreshToken || req.cookies.refreshToken,
      sessionId: req.user?.sessionId,
      userId: req.user?._id,
      logoutAll: req.body.logoutAll || false
    };
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.logout(sessionData, context);
    
    // Clear cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.clearCookie('trustToken');
    
    responseHandler.success(res, result, 'Logout successful');
  });
  
  /**
   * Refresh access token
   * @route   POST /api/auth/refresh
   * @access  Public (with refresh token)
   */
  static refreshToken = asyncHandler(async (req, res) => {
    const refreshToken = req.body.refreshToken || req.cookies.refreshToken;
    
    if (!refreshToken) {
      throw new ValidationError('Refresh token is required');
    }
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.refreshToken(refreshToken, context);
    
    // Update cookies
    res.cookie('accessToken', result.accessToken, {
      httpOnly: true,
      secure: config.server.isProduction,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    
    if (result.refreshToken !== refreshToken) {
      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: config.server.isProduction,
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });
    }
    
    responseHandler.success(res, result, 'Token refreshed successfully');
  });
  
  /**
   * Verify email
   * @route   POST /api/auth/verify-email
   * @access  Public
   */
  static verifyEmail = asyncHandler(async (req, res) => {
    const { token } = req.body;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.verifyEmail(token, context);
    
    responseHandler.success(res, result, 'Email verified successfully');
  });
  
  /**
   * Resend verification email
   * @route   POST /api/auth/resend-verification
   * @access  Public
   */
  static resendVerification = asyncHandler(async (req, res) => {
    const { email } = req.body;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.resendVerificationEmail(email, context);
    
    responseHandler.success(res, result, 'Verification email sent');
  });
  
  /**
   * Request password reset
   * @route   POST /api/auth/forgot-password
   * @access  Public
   */
  static forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.requestPasswordReset(email, context);
    
    responseHandler.success(res, result, 'Password reset email sent');
  });
  
  /**
   * Reset password
   * @route   POST /api/auth/reset-password
   * @access  Public
   */
  static resetPassword = asyncHandler(async (req, res) => {
    const { token, password } = req.body;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.resetPassword({ token, newPassword: password }, context);
    
    responseHandler.success(res, result, 'Password reset successful');
  });
  
  /**
   * Change password
   * @route   POST /api/auth/change-password
   * @access  Private
   */
  static changePassword = asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.changePassword(
      { currentPassword, newPassword },
      userId,
      context
    );
    
    responseHandler.success(res, result, 'Password changed successfully');
  });
  
  /**
   * OAuth callback handler
   * @route   Various OAuth callback routes
   * @access  Public
   */
  static oauthCallback = asyncHandler(async (req, res) => {
    // This is called after successful OAuth authentication
    const user = req.user;
    const info = req.authInfo;
    
    if (!user) {
      return res.redirect(`${config.client.url}/auth/login?error=oauth_failed`);
    }
    
    // Generate tokens if not already present
    let tokens = {};
    if (info.sessionId) {
      tokens = await AuthService.generateTokens(user, info.sessionId, false);
    }
    
    // Set cookies
    res.cookie('accessToken', tokens.accessToken, {
      httpOnly: true,
      secure: config.server.isProduction,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: config.server.isProduction,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    // Redirect to client
    const redirectUrl = info.isNewUser ? 
      `${config.client.url}/onboarding?provider=${info.method}` :
      `${config.client.url}/dashboard`;
    
    res.redirect(redirectUrl);
  });
  
  /**
   * Link OAuth account
   * @route   POST /api/auth/oauth/link
   * @access  Private
   */
  static linkOAuthAccount = asyncHandler(async (req, res) => {
    const { provider } = req.body;
    const userId = req.user._id;
    
    // Store user ID in session for OAuth callback
    req.session.linkAccountUserId = userId;
    req.session.linkAccountProvider = provider;
    
    // Return OAuth URL for client to redirect
    const authUrl = `/api/auth/${provider}?link=true`;
    
    responseHandler.success(res, { authUrl }, 'Redirect to OAuth provider');
  });
  
  /**
   * Unlink OAuth account
   * @route   DELETE /api/auth/oauth/unlink/:provider
   * @access  Private
   */
  static unlinkOAuthAccount = asyncHandler(async (req, res) => {
    const { provider } = req.params;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.unlinkOAuthAccount(userId, provider, context);
    
    responseHandler.success(res, result, 'OAuth account unlinked');
  });
  
  /**
   * Begin passkey registration
   * @route   POST /api/auth/passkey/register/begin
   * @access  Private (or public for new users)
   */
  static beginPasskeyRegistration = asyncHandler(async (req, res) => {
    const data = {
      email: req.body.email,
      userId: req.user?._id,
      displayName: req.body.displayName,
      authenticatorType: req.body.authenticatorType || 'platform'
    };
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      origin: req.get('origin'),
      session: req.session
    };
    
    // Use passport passkey strategy
    req.body.action = 'register-begin';
    req.body = { ...req.body, ...data };
    
    // Call passport authenticate
    req.app.get('passport').authenticate('passkey')(req, res);
  });
  
  /**
   * Complete passkey registration
   * @route   POST /api/auth/passkey/register/complete
   * @access  Private (or public for new users)
   */
  static completePasskeyRegistration = asyncHandler(async (req, res) => {
    req.body.action = 'register-complete';
    req.body.userId = req.user?._id;
    
    // Call passport authenticate
    req.app.get('passport').authenticate('passkey')(req, res);
  });
  
  /**
   * Begin passkey authentication
   * @route   POST /api/auth/passkey/authenticate/begin
   * @access  Public
   */
  static beginPasskeyAuthentication = asyncHandler(async (req, res) => {
    req.body.action = 'authenticate-begin';
    
    // Call passport authenticate
    req.app.get('passport').authenticate('passkey')(req, res);
  });
  
  /**
   * Complete passkey authentication
   * @route   POST /api/auth/passkey/authenticate/complete
   * @access  Public
   */
  static completePasskeyAuthentication = asyncHandler(async (req, res) => {
    req.body.action = 'authenticate-complete';
    
    // Call passport authenticate with custom callback
    req.app.get('passport').authenticate('passkey', (err, user, info) => {
      if (err) {
        return responseHandler.error(res, err);
      }
      
      if (!user) {
        return responseHandler.error(res, new AuthenticationError(info?.message || 'Authentication failed'));
      }
      
      // Set cookies
      const cookieOptions = {
        httpOnly: true,
        secure: config.server.isProduction,
        sameSite: 'strict'
      };
      
      res.cookie('accessToken', info.accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000
      });
      
      res.cookie('refreshToken', info.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000
      });
      
      responseHandler.success(res, {
        user,
        ...info
      }, 'Authentication successful');
    })(req, res);
  });
  
  /**
   * Remove passkey
   * @route   DELETE /api/auth/passkey/:credentialId
   * @access  Private
   */
  static removePasskey = asyncHandler(async (req, res) => {
    const { credentialId } = req.params;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.removePasskey(userId, credentialId, context);
    
    responseHandler.success(res, result, 'Passkey removed');
  });
  
  /**
   * Get MFA methods
   * @route   GET /api/auth/mfa/methods
   * @access  Private
   */
  static getMfaMethods = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const result = await AuthService.getMfaMethods(userId);
    
    responseHandler.success(res, result, 'MFA methods retrieved');
  });
  
  /**
   * Setup MFA
   * @route   POST /api/auth/mfa/setup/:method
   * @access  Private
   */
  static setupMfa = asyncHandler(async (req, res) => {
    const { method } = req.params;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const setupData = {
      phoneNumber: req.body.phoneNumber // For SMS method
    };
    
    const result = await AuthService.setupMfa(userId, method, context, setupData);
    
    responseHandler.success(res, result, 'MFA setup initiated');
  });
  
  /**
   * Verify MFA setup
   * @route   POST /api/auth/mfa/verify-setup
   * @access  Private
   */
  static verifyMfaSetup = asyncHandler(async (req, res) => {
    const { method, code, setupToken } = req.body;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.verifyMfaSetup(
      userId,
      { method, code, setupToken },
      context
    );
    
    responseHandler.success(res, result, 'MFA enabled successfully');
  });
  
  /**
   * Verify MFA
   * @route   POST /api/auth/mfa/verify
   * @access  Public (with pending auth)
   */
  static verifyMfa = asyncHandler(async (req, res) => {
    const { userId, method, code, challengeId, trustDevice } = req.body;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.verifyMfa(
      userId,
      { method, code, challengeId, trustDevice },
      context
    );
    
    // Set cookies
    const cookieOptions = {
      httpOnly: true,
      secure: config.server.isProduction,
      sameSite: 'strict'
    };
    
    res.cookie('accessToken', result.accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000
    });
    
    res.cookie('refreshToken', result.refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    if (result.trustToken) {
      res.cookie('trustToken', result.trustToken, {
        ...cookieOptions,
        maxAge: 90 * 24 * 60 * 60 * 1000
      });
    }
    
    responseHandler.success(res, result, 'MFA verification successful');
  });
  
  /**
   * Disable MFA
   * @route   DELETE /api/auth/mfa/:method
   * @access  Private
   */
  static disableMfa = asyncHandler(async (req, res) => {
    const { method } = req.params;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.disableMfa(userId, method, context);
    
    responseHandler.success(res, result, 'MFA method disabled');
  });
  
  /**
   * Regenerate backup codes
   * @route   POST /api/auth/mfa/backup-codes/regenerate
   * @access  Private
   */
  static regenerateBackupCodes = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.regenerateBackupCodes(userId, context);
    
    responseHandler.success(res, result, 'Backup codes regenerated');
  });
  
  /**
   * Get sessions
   * @route   GET /api/auth/sessions
   * @access  Private
   */
  static getSessions = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const currentSessionId = req.user.sessionId;
    
    const result = await AuthService.getUserSessions(userId);
    
    // Mark current session
    if (result.sessions) {
      result.sessions = result.sessions.map(session => ({
        ...session,
        isCurrent: session.sessionId === currentSessionId
      }));
    }
    
    responseHandler.success(res, result, 'Sessions retrieved');
  });
  
  /**
   * Revoke session
   * @route   DELETE /api/auth/sessions/:sessionId
   * @access  Private
   */
  static revokeSession = asyncHandler(async (req, res) => {
    const { sessionId } = req.params;
    const userId = req.user._id;
    const currentSessionId = req.user.sessionId;
    
    if (sessionId === currentSessionId) {
      throw new ValidationError('Cannot revoke current session. Use logout instead.');
    }
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.revokeSession(userId, sessionId, context);
    
    responseHandler.success(res, result, 'Session revoked');
  });
  
  /**
   * Revoke all sessions
   * @route   DELETE /api/auth/sessions
   * @access  Private
   */
  static revokeAllSessions = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const currentSessionId = req.user.sessionId;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.revokeAllOtherSessions(userId, currentSessionId, context);
    
    responseHandler.success(res, result, 'All other sessions revoked');
  });
  
  /**
   * SSO callback
   * @route   POST /api/auth/sso/:organizationSlug/callback
   * @access  Public
   */
  static ssoCallback = asyncHandler(async (req, res) => {
    // This is called after successful SSO authentication
    const user = req.user;
    const info = req.authInfo;
    
    if (!user) {
      return res.redirect(`${config.client.url}/auth/login?error=sso_failed`);
    }
    
    // Set cookies
    res.cookie('accessToken', info.accessToken, {
      httpOnly: true,
      secure: config.server.isProduction,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    
    res.cookie('refreshToken', info.refreshToken, {
      httpOnly: true,
      secure: config.server.isProduction,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    
    // Redirect to client
    res.redirect(`${config.client.url}/dashboard`);
  });
  
  /**
   * Get security status
   * @route   GET /api/auth/security/status
   * @access  Private
   */
  static getSecurityStatus = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const result = await AuthService.getSecurityStatus(userId);
    
    responseHandler.success(res, result, 'Security status retrieved');
  });
  
  /**
   * Get security activity
   * @route   GET /api/auth/security/activity
   * @access  Private
   */
  static getSecurityActivity = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const { limit = 20, offset = 0 } = req.query;
    
    const result = await AuthService.getSecurityActivity(userId, { limit, offset });
    
    responseHandler.success(res, result, 'Security activity retrieved');
  });
  
  /**
   * Add trusted device
   * @route   POST /api/auth/security/trusted-devices
   * @access  Private
   */
  static addTrustedDevice = asyncHandler(async (req, res) => {
    const { deviceName, trustToken } = req.body;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      deviceId: req.get('x-device-id')
    };
    
    const result = await AuthService.addTrustedDevice(
      userId,
      { deviceName, trustToken },
      context
    );
    
    // Set trust token cookie
    if (result.trustToken) {
      res.cookie('trustToken', result.trustToken, {
        httpOnly: true,
        secure: config.server.isProduction,
        sameSite: 'strict',
        maxAge: 90 * 24 * 60 * 60 * 1000 // 90 days
      });
    }
    
    responseHandler.success(res, result, 'Trusted device added');
  });
  
  /**
   * Remove trusted device
   * @route   DELETE /api/auth/security/trusted-devices/:deviceId
   * @access  Private
   */
  static removeTrustedDevice = asyncHandler(async (req, res) => {
    const { deviceId } = req.params;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.removeTrustedDevice(userId, deviceId, context);
    
    responseHandler.success(res, result, 'Trusted device removed');
  });
  
  /**
   * Set security questions
   * @route   POST /api/auth/recovery/questions
   * @access  Private
   */
  static setSecurityQuestions = asyncHandler(async (req, res) => {
    const { questions } = req.body;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.setSecurityQuestions(userId, questions, context);
    
    responseHandler.success(res, result, 'Security questions set');
  });
  
  /**
   * Verify security questions
   * @route   POST /api/auth/recovery/verify
   * @access  Public
   */
  static verifySecurityQuestions = asyncHandler(async (req, res) => {
    const { email, answers } = req.body;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.verifySecurityQuestions(email, answers, context);
    
    responseHandler.success(res, result, 'Security questions verified');
  });
  
  /**
   * Send phone verification
   * @route   POST /api/auth/verify/phone
   * @access  Private
   */
  static sendPhoneVerification = asyncHandler(async (req, res) => {
    const { phoneNumber } = req.body;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.sendPhoneVerification(userId, phoneNumber, context);
    
    responseHandler.success(res, result, 'Verification code sent');
  });
  
  /**
   * Confirm phone verification
   * @route   POST /api/auth/verify/phone/confirm
   * @access  Private
   */
  static confirmPhoneVerification = asyncHandler(async (req, res) => {
    const { code } = req.body;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.confirmPhoneVerification(userId, code, context);
    
    responseHandler.success(res, result, 'Phone number verified');
  });
  
  /**
   * Request account deletion
   * @route   POST /api/auth/account/delete
   * @access  Private
   */
  static requestAccountDeletion = asyncHandler(async (req, res) => {
    const { password, reason } = req.body;
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.requestAccountDeletion(
      userId,
      { password, reason },
      context
    );
    
    responseHandler.success(res, result, 'Account deletion requested');
  });
  
  /**
   * Confirm account deletion
   * @route   POST /api/auth/account/delete/confirm
   * @access  Public (with deletion token)
   */
  static confirmAccountDeletion = asyncHandler(async (req, res) => {
    const { token } = req.body;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.confirmAccountDeletion(token, context);
    
    // Clear all cookies
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.clearCookie('trustToken');
    
    responseHandler.success(res, result, 'Account deleted successfully');
  });
  
  /**
   * Cancel account deletion
   * @route   POST /api/auth/account/delete/cancel
   * @access  Private
   */
  static cancelAccountDeletion = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await AuthService.cancelAccountDeletion(userId, context);
    
    responseHandler.success(res, result, 'Account deletion cancelled');
  });
}

module.exports = AuthController;