// // server/shared/auth/controllers/auth-controller.js
// // Description: Handles authentication-related HTTP requests such as registration, login, logout, and token refresh
// /**
//  * @file Authentication Controller
//  * @description HTTP request handlers for authentication endpoints
//  * @version 3.0.0
//  */

// const AuthService = require('../services/auth-service');
// const TwoFactorService = require('../services/two-factor-service');
// const TokenService = require('../services/token-service');
// const { validationResult } = require('express-validator');
// const { asyncHandler } = require('../../utils/async-handler');
// const ResponseHandler = require('../../utils/response-handler');
// const logger = require('../../utils/logger');
// const config = require('../../config');

// /**
//  * Authentication Controller Class
//  * @class AuthController
//  */
// class AuthController {
//   /**
//    * Register new user
//    * POST /api/auth/register
//    */
//   static register = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Extract registration data
//     const registrationData = {
//       firstName: req.body.firstName,
//       lastName: req.body.lastName,
//       email: req.body.email,
//       password: req.body.password,
//       userType: req.body.userType,
//       role: req.body.role,
//       organizationId: req.body.organizationId,
//       title: req.body.title,
//       bio: req.body.bio,
//       language: req.body.language,
//       timezone: req.body.timezone,
//       acceptTerms: req.body.acceptTerms,
//       autoLogin: req.body.autoLogin !== false
//     };
    
//     // Add request context
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent'),
//       origin: req.get('origin')
//     };
    
//     // Register user
//     const result = await AuthService.register(registrationData, context);
    
//     // Set cookies if tokens are provided
//     if (result.tokens) {
//       AuthController.setAuthCookies(res, result.tokens);
//     }
    
//     // Send response
//     ResponseHandler.created(res, {
//       user: result.user,
//       tokens: result.tokens,
//       requiresVerification: result.requiresVerification
//     }, 'Registration successful');
//   });
  
//   /**
//    * Login user
//    * POST /api/auth/login
//    */
//   static login = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Extract credentials
//     const credentials = {
//       email: req.body.email,
//       password: req.body.password,
//       twoFactorCode: req.body.twoFactorCode,
//       rememberMe: req.body.rememberMe || false
//     };
    
//     // Add request context
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent'),
//       origin: req.get('origin'),
//       deviceId: req.body.deviceId || req.get('x-device-id')
//     };
    
//     // Attempt login
//     const result = await AuthService.login(credentials, context);
    
//     // Handle 2FA required response
//     if (result.requiresTwoFactor) {
//       return ResponseHandler.success(res, {
//         requiresTwoFactor: true,
//         userId: result.userId
//       }, 'Two-factor authentication required');
//     }
    
//     // Set auth cookies
//     AuthController.setAuthCookies(res, result.tokens, credentials.rememberMe);
    
//     // Send response
//     ResponseHandler.success(res, {
//       user: result.user,
//       tokens: result.tokens
//     }, 'Login successful');
//   });
  
//   /**
//    * Logout user
//    * POST /api/auth/logout
//    */
//   static logout = asyncHandler(async (req, res) => {
//     // Extract tokens
//     const tokenData = {
//       accessToken: req.tokenRaw || req.cookies?.access_token,
//       refreshToken: req.body.refreshToken || req.cookies?.refresh_token,
//       userId: req.userId
//     };
    
//     // Add request context
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent')
//     };
    
//     // Perform logout
//     await AuthService.logout(tokenData, context);
    
//     // Clear cookies
//     AuthController.clearAuthCookies(res);
    
//     // Send response
//     ResponseHandler.success(res, null, 'Logout successful');
//   });
  
//   /**
//    * Refresh authentication tokens
//    * POST /api/auth/refresh
//    */
//   static refreshToken = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Extract refresh token
//     const refreshToken = req.body.refreshToken || req.cookies?.refresh_token;
    
//     if (!refreshToken) {
//       return ResponseHandler.unauthorized(res, 'Refresh token required', 'REFRESH_TOKEN_REQUIRED');
//     }
    
//     // Add request context
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent'),
//       deviceId: req.body.deviceId || req.get('x-device-id')
//     };
    
//     // Refresh tokens
//     const result = await AuthService.refreshTokens(refreshToken, context);
    
//     // Set new auth cookies
//     AuthController.setAuthCookies(res, result);
    
//     // Send response
//     ResponseHandler.success(res, {
//       ...result,
//       user: result.organizationChanged ? result.user : undefined
//     }, 'Tokens refreshed successfully');
//   });
  
//   /**
//    * Request password reset
//    * POST /api/auth/forgot-password
//    */
//   static forgotPassword = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Add request context
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent')
//     };
    
//     // Request password reset
//     const result = await AuthService.forgotPassword(req.body.email, context);
    
//     // Send response (always success to prevent email enumeration)
//     ResponseHandler.success(res, result, result.message);
//   });
  
//   /**
//    * Reset password
//    * POST /api/auth/reset-password
//    */
//   static resetPassword = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Add request context
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent')
//     };
    
//     // Reset password
//     const result = await AuthService.resetPassword(
//       req.body.token,
//       req.body.password,
//       context
//     );
    
//     // Send response
//     ResponseHandler.success(res, result, result.message);
//   });
  
//   /**
//    * Change password (authenticated)
//    * POST /api/auth/change-password
//    */
//   static changePassword = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Add request context
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent'),
//       tokenId: req.token?.jti
//     };
    
//     // Change password
//     const result = await AuthService.changePassword(
//       req.userId,
//       req.body.currentPassword,
//       req.body.newPassword,
//       context
//     );
    
//     // Send response
//     ResponseHandler.success(res, result, result.message);
//   });
  
//   /**
//    * Verify email address
//    * POST /api/auth/verify-email
//    */
//   static verifyEmail = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Verify email
//     const result = await AuthService.verifyEmail(req.body.token);
    
//     // Send response
//     ResponseHandler.success(res, {
//       user: result.user,
//       alreadyVerified: result.alreadyVerified
//     }, result.alreadyVerified ? 'Email already verified' : 'Email verified successfully');
//   });
  
//   /**
//    * Resend verification email
//    * POST /api/auth/resend-verification
//    */
//   static resendVerification = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Get user
//     const User = require('../../users/models/user-model');
//     const user = await User.findOne({ email: req.body.email.toLowerCase() });
    
//     if (!user) {
//       // Don't reveal if user exists
//       return ResponseHandler.success(res, null, 'If the email exists and is unverified, a verification email has been sent');
//     }
    
//     if (user.isEmailVerified) {
//       return ResponseHandler.success(res, null, 'Email is already verified');
//     }
    
//     // Generate new verification token
//     const verificationToken = await TokenService.generateVerificationToken(user._id);
    
//     // Send verification email
//     await AuthService.sendVerificationEmail(user, verificationToken);
    
//     // Send response
//     ResponseHandler.success(res, null, 'Verification email sent');
//   });
  
//   /**
//    * Get current session info
//    * GET /api/auth/session
//    */
//   static getSession = asyncHandler(async (req, res) => {
//     if (!req.userId) {
//       return ResponseHandler.unauthorized(res, 'Not authenticated');
//     }
    
//     // Get user
//     const User = require('../../users/models/user-model');
//     const user = await User.findById(req.userId)
//       .select('-password -security')
//       .populate('organization.current', 'name slug type');
    
//     if (!user) {
//       return ResponseHandler.unauthorized(res, 'User not found');
//     }
    
//     // Get session info
//     const sessionInfo = {
//       user,
//       permissions: req.token?.permissions || [],
//       organizationContext: req.token?.organizationId ? {
//         organizationId: req.token.organizationId,
//         organizationType: req.token.organizationType
//       } : null,
//       tokenExpiry: req.token?.exp ? new Date(req.token.exp * 1000) : null
//     };
    
//     // Send response
//     ResponseHandler.success(res, sessionInfo, 'Session retrieved');
//   });
  
//   /**
//    * Validate current session
//    * POST /api/auth/validate
//    */
//   static validateSession = asyncHandler(async (req, res) => {
//     // Session is valid if we reach here (auth middleware passed)
//     ResponseHandler.success(res, {
//       valid: true,
//       userId: req.userId,
//       userRole: req.userRole,
//       organizationId: req.organizationId
//     }, 'Session is valid');
//   });
  
//   /**
//    * Setup two-factor authentication
//    * GET /api/auth/2fa/setup
//    */
//   static setupTwoFactor = asyncHandler(async (req, res) => {
//     // Get user
//     const User = require('../../users/models/user-model');
//     const user = await User.findById(req.userId).select('+security');
    
//     if (!user) {
//       return ResponseHandler.notFound(res, 'User');
//     }
    
//     if (user.security?.twoFactorEnabled) {
//       return ResponseHandler.conflict(res, 'Two-factor authentication is already enabled');
//     }
    
//     // Setup TOTP
//     const setupData = await TwoFactorService.setupTOTP(user);
    
//     // Send response
//     ResponseHandler.success(res, {
//       tempId: setupData.tempId,
//       qrCode: setupData.qrCode,
//       manualEntryKey: setupData.manualEntryKey,
//       backupCodes: setupData.backupCodes
//     }, 'Two-factor authentication setup initiated');
//   });
  
//   /**
//    * Enable two-factor authentication
//    * POST /api/auth/2fa/enable
//    */
//   static enableTwoFactor = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Get user
//     const User = require('../../users/models/user-model');
//     const user = await User.findById(req.userId).select('+security');
    
//     if (!user) {
//       return ResponseHandler.notFound(res, 'User');
//     }
    
//     if (user.security?.twoFactorEnabled) {
//       return ResponseHandler.conflict(res, 'Two-factor authentication is already enabled');
//     }
    
//     // Enable 2FA
//     const result = await TwoFactorService.enableTOTP(
//       user,
//       req.body.tempId,
//       req.body.token
//     );
    
//     // Send response
//     ResponseHandler.success(res, {
//       backupCodes: result.backupCodes
//     }, result.message);
//   });
  
//   /**
//    * Disable two-factor authentication
//    * POST /api/auth/2fa/disable
//    */
//   static disableTwoFactor = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Get user
//     const User = require('../../users/models/user-model');
//     const user = await User.findById(req.userId).select('+security +password');
    
//     if (!user) {
//       return ResponseHandler.notFound(res, 'User');
//     }
    
//     if (!user.security?.twoFactorEnabled) {
//       return ResponseHandler.conflict(res, 'Two-factor authentication is not enabled');
//     }
    
//     // Disable 2FA
//     const result = await TwoFactorService.disable2FA(user, req.body.password);
    
//     // Send response
//     ResponseHandler.success(res, null, result.message);
//   });
  
//   /**
//    * Get two-factor authentication status
//    * GET /api/auth/2fa/status
//    */
//   static getTwoFactorStatus = asyncHandler(async (req, res) => {
//     // Get user
//     const User = require('../../users/models/user-model');
//     const user = await User.findById(req.userId).select('+security');
    
//     if (!user) {
//       return ResponseHandler.notFound(res, 'User');
//     }
    
//     // Get 2FA status
//     const status = TwoFactorService.get2FAStatus(user);
    
//     // Send response
//     ResponseHandler.success(res, status, 'Two-factor authentication status retrieved');
//   });
  
//   /**
//    * Regenerate backup codes
//    * POST /api/auth/2fa/backup-codes
//    */
//   static regenerateBackupCodes = asyncHandler(async (req, res) => {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return ResponseHandler.validationError(res, errors.array());
//     }
    
//     // Get user
//     const User = require('../../users/models/user-model');
//     const user = await User.findById(req.userId).select('+security +password');
    
//     if (!user) {
//       return ResponseHandler.notFound(res, 'User');
//     }
    
//     if (!user.security?.twoFactorEnabled) {
//       return ResponseHandler.conflict(res, 'Two-factor authentication is not enabled');
//     }
    
//     // Regenerate backup codes
//     const result = await TwoFactorService.regenerateBackupCodes(user, req.body.password);
    
//     // Send response
//     ResponseHandler.success(res, {
//       backupCodes: result.backupCodes
//     }, result.message);
//   });
  
//   /**
//    * OAuth callback handler
//    * GET /api/auth/:provider/callback
//    */
//   static oauthCallback = asyncHandler(async (req, res) => {
//     const { provider } = req.params;
//     const user = req.user;
    
//     if (!user) {
//       // Authentication failed
//       const error = req.query.error || 'Authentication failed';
//       return res.redirect(`${config.client.url}/auth/error?error=${encodeURIComponent(error)}`);
//     }
    
//     // Generate tokens
//     const context = {
//       ipAddress: req.ip,
//       userAgent: req.get('user-agent'),
//       provider
//     };
    
//     const tokens = await TokenService.generateAuthTokens(user, context);
    
//     // Set cookies
//     AuthController.setAuthCookies(res, tokens);
    
//     // Redirect to client with success
//     const redirectUrl = req.session?.returnTo || `${config.client.url}/dashboard`;
//     delete req.session?.returnTo;
    
//     res.redirect(redirectUrl);
//   });
  
//   /**
//    * Set authentication cookies
//    * @param {Object} res - Express response
//    * @param {Object} tokens - Authentication tokens
//    * @param {boolean} rememberMe - Remember me flag
//    */
//   static setAuthCookies(res, tokens, rememberMe = false) {
//     const cookieOptions = {
//       httpOnly: true,
//       secure: config.isProduction,
//       sameSite: 'lax',
//       path: '/'
//     };
    
//     // Access token cookie (short-lived)
//     res.cookie('access_token', tokens.accessToken, {
//       ...cookieOptions,
//       maxAge: 15 * 60 * 1000 // 15 minutes
//     });
    
//     // Refresh token cookie (long-lived)
//     const refreshMaxAge = rememberMe ? 
//       30 * 24 * 60 * 60 * 1000 : // 30 days
//       7 * 24 * 60 * 60 * 1000;    // 7 days
    
//     res.cookie('refresh_token', tokens.refreshToken, {
//       ...cookieOptions,
//       maxAge: refreshMaxAge
//     });
    
//     // Organization context cookie (if applicable)
//     if (tokens.organizationContext) {
//       res.cookie('org_context', JSON.stringify(tokens.organizationContext), {
//         ...cookieOptions,
//         httpOnly: false, // Accessible to client
//         maxAge: refreshMaxAge
//       });
//     }
//   }
  
//   /**
//    * Clear authentication cookies
//    * @param {Object} res - Express response
//    */
//   static clearAuthCookies(res) {
//     const cookieOptions = {
//       httpOnly: true,
//       secure: config.isProduction,
//       sameSite: 'lax',
//       path: '/'
//     };
    
//     res.clearCookie('access_token', cookieOptions);
//     res.clearCookie('refresh_token', cookieOptions);
//     res.clearCookie('org_context', { ...cookieOptions, httpOnly: false });
//   }
// }

// module.exports = AuthController;

// server/shared/auth/controllers/auth-controller.js
/**
 * @file Authentication Controller
 * @description Handles authentication-related HTTP requests
 * @version 3.0.0
 */

const AuthService = require('../services/auth-service');
const asyncHandler = require('../../utils/async-handler');
const responseHandler = require('../../utils/response-handler');
const logger = require('../../utils/logger');
const { 
  AuthenticationError, 
  ValidationError,
  NotFoundError 
} = require('../../utils/app-error');
const config = require('../../config');

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
  
  /**
   * Login user
   * @route   POST /api/auth/login
   * @access  Public
   */
  static login = asyncHandler(async (req, res) => {
    const credentials = {
      email: req.body.email,
      password: req.body.password,
      rememberMe: req.body.rememberMe || false,
      deviceId: req.body.deviceId
    };
    
    const context = {
      ip: req.ip,
      userAgent: req.get('user-agent'),
      origin: req.get('origin')
    };
    
    const result = await AuthService.login(credentials, context);
    
    // Handle MFA requirement
    if (result.requiresMfa) {
      return responseHandler.success(res, {
        requiresMfa: true,
        userId: result.userId,
        challengeId: result.challengeId,
        mfaMethods: result.mfaMethods
      }, 'Multi-factor authentication required');
    }
    
    // Handle password change requirement
    if (result.requiresPasswordChange) {
      return responseHandler.success(res, {
        requiresPasswordChange: true,
        userId: result.userId
      }, 'Password change required');
    }
    
    // Set cookies
    const cookieOptions = {
      httpOnly: true,
      secure: config.server.isProduction,
      sameSite: 'strict'
    };
    
    res.cookie('accessToken', result.accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000 // 15 minutes
    });
    
    res.cookie('refreshToken', result.refreshToken, {
      ...cookieOptions,
      maxAge: credentials.rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000
    });
    
    if (result.trustToken) {
      res.cookie('trustToken', result.trustToken, {
        ...cookieOptions,
        maxAge: 90 * 24 * 60 * 60 * 1000 // 90 days
      });
    }
    
    responseHandler.success(res, result, 'Login successful');
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
      tokens = await AuthService.generateTokens(user, info.sessionId);
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