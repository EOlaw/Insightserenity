// server/shared/auth/routes/auth-routes.js
/**
 * @file Authentication Routes
 * @description API routes for authentication operations
 * @version 3.0.0
 */

const express = require('express');

const router = express.Router();
const { body, query, param } = require('express-validator');
const passport = require('passport');

const { rateLimiter } = require('../../utils/rate-limiter-auth-routes');
const passportConfig = require('../../security/passport/passport-config');
// const { validateRequest } = require('../../utils/validation-middleware');
const AuthController = require('../controllers/auth-controller');
const { authenticate, authorize } = require('../../middleware/auth/auth-middleware');


/**
 * Authentication Routes Configuration
 */

// ===========================
// Public Authentication Routes
// ===========================

/**
 * @route   POST /api/auth/register
 * @desc    Register new user
 * @access  Public
 */
router.post('/register',
  // rateLimiter('register', { max: 5, windowMs: 15 * 60 * 1000 }), // 5 attempts per 15 minutes
  // [
  //   body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  //   body('password').isLength({ min: 12 }).withMessage('Password must be at least 12 characters'),
  //   body('firstName').trim().notEmpty().withMessage('First name is required'),
  //   body('lastName').trim().notEmpty().withMessage('Last name is required'),
  //   body('organizationId').optional().isMongoId().withMessage('Invalid organization ID'),
  //   body('acceptTerms').isBoolean().equals('true').withMessage('You must accept the terms of service')
  // ],
  // validateRequest,
  AuthController.register
);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login',
  rateLimiter('login', { max: 10, windowMs: 15 * 60 * 1000 }), // 10 attempts per 15 minutes
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
    body('rememberMe').optional().isBoolean(),
    body('deviceId').optional().isString()
  ],
  // validateRequest,
  AuthController.login
);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout',
  authenticate(),
  [
    body('logoutAll').optional().isBoolean()
  ],
  // validateRequest,
  AuthController.logout
);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public (with refresh token)
 */
router.post('/refresh',
  rateLimiter('refresh', { max: 30, windowMs: 15 * 60 * 1000 }),
  [
    body('refreshToken').notEmpty().withMessage('Refresh token is required')
  ],
  // validateRequest,
  AuthController.refreshToken
);

// ===========================
// Email Verification Routes
// ===========================

/**
 * @route   POST /api/auth/verify-email
 * @desc    Verify email with token
 * @access  Public
 */
router.post('/verify-email',
  rateLimiter('verify', { max: 10, windowMs: 60 * 60 * 1000 }),
  [
    body('token').notEmpty().withMessage('Verification token is required')
  ],
  // validateRequest,
  AuthController.verifyEmail
);

/**
 * @route   POST /api/auth/resend-verification
 * @desc    Resend verification email
 * @access  Public
 */
router.post('/resend-verification',
  rateLimiter('resend', { max: 3, windowMs: 60 * 60 * 1000 }),
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
  ],
  // validateRequest,
  AuthController.resendVerification
);

// ===========================
// Password Management Routes
// ===========================

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post('/forgot-password',
  rateLimiter('password-reset', { max: 3, windowMs: 60 * 60 * 1000 }),
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
  ],
  // validateRequest,
  AuthController.forgotPassword
);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password',
  rateLimiter('password-reset', { max: 5, windowMs: 60 * 60 * 1000 }),
  [
    body('token').notEmpty().withMessage('Reset token is required'),
    body('password').isLength({ min: 12 }).withMessage('Password must be at least 12 characters')
  ],
  // validateRequest,
  AuthController.resetPassword
);

/**
 * @route   POST /api/auth/change-password
 * @desc    Change password for authenticated user
 * @access  Private
 */
router.post('/change-password',
  authenticate({ required: true }),
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 12 }).withMessage('New password must be at least 12 characters')
  ],
  // validateRequest,
  AuthController.changePassword
);

// ===========================
// OAuth Routes
// ===========================

/**
 * @route   GET /api/auth/google
 * @desc    Initiate Google OAuth
 * @access  Public
 */
router.get('/google',
  passportConfig.authenticate('google', {
    scope: ['profile', 'email'],
    state: true,
    session: false
  })
);

/**
 * @route   GET /api/auth/google/callback
 * @desc    Google OAuth callback
 * @access  Public
 */
router.get('/google/callback',
  passportConfig.authenticate('google', {
    session: false,
    failureRedirect: '/auth/login?error=oauth_failed'
  }),
  AuthController.oauthCallback
);

/**
 * @route   GET /api/auth/github
 * @desc    Initiate GitHub OAuth
 * @access  Public
 */
router.get('/github',
  passportConfig.authenticate('github', {
    scope: ['user:email', 'read:user'],
    state: true,
    session: false
  })
);

/**
 * @route   GET /api/auth/github/callback
 * @desc    GitHub OAuth callback
 * @access  Public
 */
router.get('/github/callback',
  passportConfig.authenticate('github', {
    session: false,
    failureRedirect: '/auth/login?error=oauth_failed'
  }),
  AuthController.oauthCallback
);

/**
 * @route   GET /api/auth/linkedin
 * @desc    Initiate LinkedIn OAuth
 * @access  Public
 */
router.get('/linkedin',
  passportConfig.authenticate('linkedin', {
    scope: ['r_emailaddress', 'r_liteprofile'],
    state: true,
    session: false
  })
);

/**
 * @route   GET /api/auth/linkedin/callback
 * @desc    LinkedIn OAuth callback
 * @access  Public
 */
router.get('/linkedin/callback',
  passportConfig.authenticate('linkedin', {
    session: false,
    failureRedirect: '/auth/login?error=oauth_failed'
  }),
  AuthController.oauthCallback
);

/**
 * @route   POST /api/auth/oauth/link
 * @desc    Link OAuth account to existing user
 * @access  Private
 */
router.post('/oauth/link',
  authenticate({ required: true }),
  [
    body('provider').isIn(['google', 'github', 'linkedin']).withMessage('Invalid OAuth provider')
  ],
  // validateRequest,
  AuthController.linkOAuthAccount
);

/**
 * @route   DELETE /api/auth/oauth/unlink/:provider
 * @desc    Unlink OAuth account
 * @access  Private
 */
router.delete('/oauth/unlink/:provider',
  authenticate({ required: true }),
  [
    param('provider').isIn(['google', 'github', 'linkedin']).withMessage('Invalid OAuth provider')
  ],
  // validateRequest,
  AuthController.unlinkOAuthAccount
);

// ===========================
// Passkey/WebAuthn Routes
// ===========================

/**
 * @route   POST /api/auth/passkey/register/begin
 * @desc    Begin passkey registration
 * @access  Private (or public for new users)
 */
router.post('/passkey/register/begin',
  authenticate({ required: false }),
  [
    body('email').optional().isEmail().normalizeEmail(),
    body('displayName').optional().trim().notEmpty(),
    body('authenticatorType').optional().isIn(['platform', 'cross-platform'])
  ],
  // validateRequest,
  AuthController.beginPasskeyRegistration
);

/**
 * @route   POST /api/auth/passkey/register/complete
 * @desc    Complete passkey registration
 * @access  Private (or public for new users)
 */
router.post('/passkey/register/complete',
  authenticate({ required: false }),
  [
    body('credential').notEmpty().withMessage('Credential data is required'),
    body('deviceName').optional().trim()
  ],
  // validateRequest,
  AuthController.completePasskeyRegistration
);

/**
 * @route   POST /api/auth/passkey/authenticate/begin
 * @desc    Begin passkey authentication
 * @access  Public
 */
router.post('/passkey/authenticate/begin',
  rateLimiter('passkey', { max: 10, windowMs: 15 * 60 * 1000 }),
  [
    body('email').optional().isEmail().normalizeEmail(),
    body('credentialId').optional().isString()
  ],
  // validateRequest,
  AuthController.beginPasskeyAuthentication
);

/**
 * @route   POST /api/auth/passkey/authenticate/complete
 * @desc    Complete passkey authentication
 * @access  Public
 */
router.post('/passkey/authenticate/complete',
  rateLimiter('passkey', { max: 10, windowMs: 15 * 60 * 1000 }),
  [
    body('credential').notEmpty().withMessage('Credential data is required')
  ],
  // validateRequest,
  AuthController.completePasskeyAuthentication
);

/**
 * @route   DELETE /api/auth/passkey/:credentialId
 * @desc    Remove passkey credential
 * @access  Private
 */
router.delete('/passkey/:credentialId',
  authenticate({ required: true }),
  [
    param('credentialId').notEmpty().withMessage('Credential ID is required')
  ],
  // validateRequest,
  AuthController.removePasskey
);

// ===========================
// MFA Routes
// ===========================

/**
 * @route   GET /api/auth/mfa/methods
 * @desc    Get available MFA methods
 * @access  Private
 */
router.get('/mfa/methods',
  authenticate({ required: true }),
  AuthController.getMfaMethods
);

/**
 * @route   POST /api/auth/mfa/setup/:method
 * @desc    Setup MFA method
 * @access  Private
 */
router.post('/mfa/setup/:method',
  authenticate({ required: true }),
  [
    param('method').isIn(['totp', 'sms', 'email', 'backup_codes']).withMessage('Invalid MFA method'),
    body('phoneNumber').if(param('method').equals('sms')).isMobilePhone().withMessage('Valid phone number required')
  ],
  // validateRequest,
  AuthController.setupMfa
);

/**
 * @route   POST /api/auth/mfa/verify-setup
 * @desc    Verify MFA setup
 * @access  Private
 */
router.post('/mfa/verify-setup',
  authenticate({ required: true }),
  [
    body('method').isIn(['totp', 'sms', 'email']).withMessage('Invalid MFA method'),
    body('code').notEmpty().withMessage('Verification code is required'),
    body('setupToken').notEmpty().withMessage('Setup token is required')
  ],
  // validateRequest,
  AuthController.verifyMfaSetup
);

/**
 * @route   POST /api/auth/mfa/verify
 * @desc    Verify MFA code during login
 * @access  Public (with pending auth)
 */
router.post('/mfa/verify',
  rateLimiter('mfa', { max: 5, windowMs: 15 * 60 * 1000 }),
  [
    body('userId').isMongoId().withMessage('Valid user ID is required'),
    body('method').isIn(['totp', 'sms', 'email', 'backup_codes']).withMessage('Invalid MFA method'),
    body('code').notEmpty().withMessage('Verification code is required'),
    body('challengeId').optional().isString(),
    body('trustDevice').optional().isBoolean()
  ],
  // validateRequest,
  AuthController.verifyMfa
);

/**
 * @route   DELETE /api/auth/mfa/:method
 * @desc    Disable MFA method
 * @access  Private
 */
router.delete('/mfa/:method',
  authenticate({ required: true }),
  [
    param('method').isIn(['totp', 'sms', 'email', 'backup_codes']).withMessage('Invalid MFA method')
  ],
  // validateRequest,
  AuthController.disableMfa
);

/**
 * @route   POST /api/auth/mfa/backup-codes/regenerate
 * @desc    Regenerate backup codes
 * @access  Private
 */
router.post('/mfa/backup-codes/regenerate',
  authenticate({ required: true }),
  AuthController.regenerateBackupCodes
);

// ===========================
// Session Management Routes
// ===========================

/**
 * @route   GET /api/auth/sessions
 * @desc    Get user's active sessions
 * @access  Private
 */
router.get('/sessions',
  authenticate(),
  AuthController.getSessions
);

/**
 * @route   DELETE /api/auth/sessions/:sessionId
 * @desc    Revoke specific session
 * @access  Private
 */
router.delete('/sessions/:sessionId',
  authenticate(),
  [
    param('sessionId').notEmpty().withMessage('Session ID is required')
  ],
  // validateRequest,
  AuthController.revokeSession
);

/**
 * @route   DELETE /api/auth/sessions
 * @desc    Revoke all other sessions
 * @access  Private
 */
router.delete('/sessions',
  authenticate(),
  AuthController.revokeAllSessions
);

// ===========================
// Organization SSO Routes
// ===========================

/**
 * @route   GET /api/auth/sso/:organizationSlug
 * @desc    Initiate organization SSO
 * @access  Public
 */
router.get('/sso/:organizationSlug',
  [
    param('organizationSlug').notEmpty().withMessage('Organization slug is required')
  ],
  // validateRequest,
  (req, res, next) => {
    req.params.action = 'login';
    next();
  },
  passportConfig.authenticate('organization', { session: false })
);

/**
 * @route   POST /api/auth/sso/:organizationSlug/callback
 * @desc    Organization SSO callback
 * @access  Public
 */
router.post('/sso/:organizationSlug/callback',
  [
    param('organizationSlug').notEmpty().withMessage('Organization slug is required')
  ],
  // validateRequest,
  (req, res, next) => {
    req.params.action = 'callback';
    next();
  },
  passportConfig.authenticate('organization', { session: false }),
  AuthController.ssoCallback
);

/**
 * @route   GET /api/auth/sso/:organizationSlug/metadata
 * @desc    Get SSO metadata
 * @access  Public
 */
router.get('/sso/:organizationSlug/metadata',
  [
    param('organizationSlug').notEmpty().withMessage('Organization slug is required')
  ],
  // validateRequest,
  (req, res, next) => {
    req.params.action = 'metadata';
    next();
  },
  passportConfig.authenticate('organization', { session: false })
);

// ===========================
// Account Security Routes
// ===========================

/**
 * @route   GET /api/auth/security/status
 * @desc    Get account security status
 * @access  Private
 */
router.get('/security/status',
  authenticate({ required: true }),
  AuthController.getSecurityStatus
);

/**
 * @route   GET /api/auth/security/activity
 * @desc    Get recent security activity
 * @access  Private
 */
router.get('/security/activity',
  authenticate({ required: true }),
  [
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('offset').optional().isInt({ min: 0 }).toInt()
  ],
  // validateRequest,
  AuthController.getSecurityActivity
);

/**
 * @route   POST /api/auth/security/trusted-devices
 * @desc    Add trusted device
 * @access  Private
 */
router.post('/security/trusted-devices',
  authenticate({ required: true }),
  [
    body('deviceName').trim().notEmpty().withMessage('Device name is required'),
    body('trustToken').optional().isString()
  ],
  // validateRequest,
  AuthController.addTrustedDevice
);

/**
 * @route   DELETE /api/auth/security/trusted-devices/:deviceId
 * @desc    Remove trusted device
 * @access  Private
 */
router.delete('/security/trusted-devices/:deviceId',
  authenticate({ required: true }),
  [
    param('deviceId').notEmpty().withMessage('Device ID is required')
  ],
  // validateRequest,
  AuthController.removeTrustedDevice
);

// ===========================
// Account Recovery Routes
// ===========================

/**
 * @route   POST /api/auth/recovery/questions
 * @desc    Set security questions
 * @access  Private
 */
router.post('/recovery/questions',
  authenticate({ required: true }),
  [
    body('questions').isArray({ min: 3, max: 5 }).withMessage('3-5 security questions required'),
    body('questions.*.question').notEmpty().withMessage('Question is required'),
    body('questions.*.answer').notEmpty().withMessage('Answer is required')
  ],
  // validateRequest,
  AuthController.setSecurityQuestions
);

/**
 * @route   POST /api/auth/recovery/verify
 * @desc    Verify security questions for account recovery
 * @access  Public
 */
router.post('/recovery/verify',
  rateLimiter('recovery', { max: 3, windowMs: 60 * 60 * 1000 }),
  [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('answers').isArray().withMessage('Answers are required')
  ],
  // validateRequest,
  AuthController.verifySecurityQuestions
);

// ===========================
// User Verification Routes
// ===========================

/**
 * @route   POST /api/auth/verify/phone
 * @desc    Send phone verification code
 * @access  Private
 */
router.post('/verify/phone',
  authenticate({ required: true }),
  [
    body('phoneNumber').isMobilePhone().withMessage('Valid phone number is required')
  ],
  // validateRequest,
  AuthController.sendPhoneVerification
);

/**
 * @route   POST /api/auth/verify/phone/confirm
 * @desc    Confirm phone verification
 * @access  Private
 */
router.post('/verify/phone/confirm',
  authenticate({ required: true }),
  [
    body('code').notEmpty().withMessage('Verification code is required')
  ],
  // validateRequest,
  AuthController.confirmPhoneVerification
);

// ===========================
// Account Deletion Routes
// ===========================

/**
 * @route   POST /api/auth/account/delete
 * @desc    Request account deletion
 * @access  Private
 */
router.post('/account/delete',
  authenticate({ required: true }),
  [
    body('password').notEmpty().withMessage('Password is required for confirmation'),
    body('reason').optional().trim()
  ],
  // validateRequest,
  AuthController.requestAccountDeletion
);

/**
 * @route   POST /api/auth/account/delete/confirm
 * @desc    Confirm account deletion
 * @access  Public (with deletion token)
 */
router.post('/account/delete/confirm',
  [
    body('token').notEmpty().withMessage('Deletion token is required')
  ],
  // validateRequest,
  AuthController.confirmAccountDeletion
);

/**
 * @route   POST /api/auth/account/delete/cancel
 * @desc    Cancel account deletion
 * @access  Private
 */
router.post('/account/delete/cancel',
  authenticate({ required: true }),
  AuthController.cancelAccountDeletion
);

// ===========================
// Export Router
// ===========================

module.exports = router;