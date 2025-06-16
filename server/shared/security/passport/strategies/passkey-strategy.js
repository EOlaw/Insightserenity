// server/shared/security/passport/strategies/passkey-strategy.js
/**
 * @file Passkey Authentication Strategy
 * @description WebAuthn/FIDO2 passwordless authentication strategy
 * @version 3.0.0
 */

const Strategy = require('passport-strategy').Strategy;
const { Fido2Lib } = require('fido2-lib');
const crypto = require('crypto');
const logger = require('../../../utils/logger');
const { AuthenticationError, ValidationError } = require('../../../utils/app-error');
const UserService = require('../../../users/services/user-service');
const AuthService = require('../../../auth/services/auth-service');
const AuditService = require('../../services/audit-service');
const config = require('../../../config');

/**
 * Passkey Authentication Strategy Class
 * @class PasskeyStrategy
 */
class PasskeyStrategy extends Strategy {
  constructor() {
    super();
    this.name = 'passkey';
    
    // Initialize FIDO2 library
    this.f2l = new Fido2Lib({
      timeout: 60000,
      rpId: config.server.host || 'localhost',
      rpName: config.server.appName || 'InsightSerenity',
      rpIcon: config.server.appIcon,
      challengeSize: 128,
      attestation: 'none',
      cryptoParams: [-7, -257], // ES256, RS256
      authenticatorAttachment: 'platform',
      authenticatorRequireResidentKey: false,
      authenticatorUserVerification: 'preferred'
    });
    
    // Supported authenticator types
    this.authenticatorTypes = {
      'platform': 'Platform Authenticator',
      'cross-platform': 'Security Key',
      'usb': 'USB Security Key',
      'nfc': 'NFC Security Key',
      'ble': 'Bluetooth Security Key',
      'internal': 'Built-in Authenticator'
    };
  }
  
  /**
   * Create and configure the passkey strategy
   * @returns {PasskeyStrategy} Configured passport strategy
   */
  async createStrategy() {
    return this;
  }
  
  /**
   * Authenticate request
   * @param {Object} req - Express request object
   * @param {Object} options - Authentication options
   */
  async authenticate(req, options) {
    try {
      const action = req.body.action || req.query.action;
      const context = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        origin: req.get('origin'),
        deviceId: req.body.deviceId || req.get('x-device-id')
      };
      
      let result;
      
      switch (action) {
        case 'register-begin':
          result = await this.beginRegistration(req.body, context);
          break;
          
        case 'register-complete':
          result = await this.completeRegistration(req.body, context);
          break;
          
        case 'authenticate-begin':
          result = await this.beginAuthentication(req.body, context);
          break;
          
        case 'authenticate-complete':
          result = await this.completeAuthentication(req.body, context);
          break;
          
        default:
          return this.fail({ message: 'Invalid passkey action' }, 400);
      }
      
      if (result.success && result.user) {
        this.success(result.user, {
          method: 'passkey',
          sessionId: result.sessionId,
          action: action
        });
      } else if (result.challenge) {
        // Return challenge for client
        req.res.json({
          success: true,
          challenge: result.challenge,
          options: result.options
        });
      } else {
        this.fail(result, result.statusCode || 401);
      }
      
    } catch (error) {
      logger.error('Passkey authentication error', { error });
      this.error(error);
    }
  }
  
  /**
   * Begin passkey registration
   * @param {Object} data - Registration data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Registration challenge
   */
  async beginRegistration(data, context) {
    const { email, userId, displayName, authenticatorType } = data;
    
    try {
      // Get user
      let user, auth;
      
      if (userId) {
        // Adding passkey to existing account
        const userWithAuth = await UserService.getUserWithAuthById(userId);
        if (!userWithAuth) {
          return {
            success: false,
            message: 'User not found',
            statusCode: 404
          };
        }
        ({ user, auth } = userWithAuth);
      } else if (email) {
        // Check if user exists
        const userWithAuth = await UserService.getUserWithAuth(email);
        if (userWithAuth) {
          // User exists - they should login first
          return {
            success: false,
            message: 'Account already exists. Please login to add a passkey.',
            statusCode: 409
          };
        }
        
        // New user registration
        user = {
          _id: crypto.randomBytes(16).toString('hex'),
          email,
          displayName: displayName || email.split('@')[0]
        };
      } else {
        return {
          success: false,
          message: 'Email or userId required',
          statusCode: 400
        };
      }
      
      // Generate registration options
      const registrationOptions = await this.f2l.attestationOptions();
      
      // Generate and store challenge
      const challenge = registrationOptions.challenge;
      const challengeData = {
        challenge: Buffer.from(challenge).toString('base64'),
        userId: user._id,
        email: user.email || email,
        displayName: user.displayName || displayName,
        authenticatorType,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000) // 5 minutes
      };
      
      // Store challenge in auth record or session
      if (auth) {
        auth.authMethods.passkey.challenges.push(challengeData);
        // Keep only last 5 challenges
        if (auth.authMethods.passkey.challenges.length > 5) {
          auth.authMethods.passkey.challenges = auth.authMethods.passkey.challenges.slice(-5);
        }
        await auth.save();
      } else {
        // Store in session for new users
        context.session = context.session || {};
        context.session.passkeyChallenge = challengeData;
      }
      
      // Prepare client options
      const publicKeyCredentialCreationOptions = {
        challenge: challenge,
        rp: {
          name: this.f2l.config.rpName,
          id: this.f2l.config.rpId
        },
        user: {
          id: Buffer.from(user._id.toString()),
          name: user.email || email,
          displayName: user.displayName || displayName || email
        },
        pubKeyCredParams: registrationOptions.pubKeyCredParams,
        authenticatorSelection: {
          authenticatorAttachment: authenticatorType === 'platform' ? 'platform' : 'cross-platform',
          userVerification: 'preferred',
          residentKey: 'preferred'
        },
        timeout: registrationOptions.timeout,
        attestation: 'none'
      };
      
      // Audit log
      await AuditService.log({
        type: 'passkey_registration_started',
        action: 'begin_passkey_registration',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        metadata: {
          ...context,
          authenticatorType,
          email: user.email || email
        }
      });
      
      return {
        success: true,
        challenge: publicKeyCredentialCreationOptions
      };
      
    } catch (error) {
      logger.error('Passkey registration begin error', { error });
      return {
        success: false,
        message: 'Failed to begin passkey registration',
        statusCode: 500
      };
    }
  }
  
  /**
   * Complete passkey registration
   * @param {Object} data - Registration completion data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Registration result
   */
  async completeRegistration(data, context) {
    const { credential, userId, email, deviceName } = data;
    
    try {
      // Validate credential format
      if (!credential || !credential.id || !credential.response) {
        return {
          success: false,
          message: 'Invalid credential data',
          statusCode: 400
        };
      }
      
      // Get stored challenge
      let challengeData;
      let user, auth;
      
      if (userId) {
        // Existing user
        const userWithAuth = await UserService.getUserWithAuthById(userId);
        if (!userWithAuth) {
          return {
            success: false,
            message: 'User not found',
            statusCode: 404
          };
        }
        
        ({ user, auth } = userWithAuth);
        
        // Find valid challenge
        challengeData = auth.authMethods.passkey.challenges.find(c => 
          !c.used && c.expiresAt > new Date()
        );
        
        if (!challengeData) {
          return {
            success: false,
            message: 'No valid challenge found',
            statusCode: 400
          };
        }
      } else {
        // New user - get from session
        challengeData = context.session?.passkeyChallenge;
        
        if (!challengeData || challengeData.expiresAt < new Date()) {
          return {
            success: false,
            message: 'Challenge expired or not found',
            statusCode: 400
          };
        }
      }
      
      // Prepare attestation expectations
      const attestationExpectations = {
        challenge: Buffer.from(challengeData.challenge, 'base64'),
        origin: context.origin || `https://${this.f2l.config.rpId}`,
        factor: 'either'
      };
      
      // Verify attestation
      const regResult = await this.f2l.attestationResult(credential, attestationExpectations);
      
      if (!regResult || !regResult.authnrData) {
        return {
          success: false,
          message: 'Invalid attestation',
          statusCode: 400
        };
      }
      
      // Extract credential data
      const credentialData = {
        credentialId: credential.id,
        publicKey: regResult.authnrData.get('credentialPublicKeyPem'),
        counter: regResult.authnrData.get('counter'),
        deviceType: credential.authenticatorAttachment || challengeData.authenticatorType,
        transports: credential.response.transports || [],
        createdAt: new Date(),
        name: deviceName || this.generateDeviceName(context.userAgent, credential.authenticatorAttachment)
      };
      
      // Create or update user
      if (!user) {
        // Create new user with passkey
        const userData = {
          email: challengeData.email,
          firstName: challengeData.displayName?.split(' ')[0] || challengeData.email.split('@')[0],
          lastName: challengeData.displayName?.split(' ').slice(1).join(' ') || '',
          profile: {
            displayName: challengeData.displayName || challengeData.email
          },
          userType: 'hosted_org_user',
          role: {
            primary: 'prospect'
          },
          status: 'active',
          isEmailVerified: true // Passkey registration verifies user presence
        };
        
        const result = await UserService.createUserWithPasskey(userData, credentialData, context);
        
        if (!result.success) {
          return result;
        }
        
        ({ user, auth } = result);
      } else {
        // Add passkey to existing user
        auth.authMethods.passkey.credentials.push(credentialData);
        
        // Mark challenge as used
        challengeData.used = true;
        
        // Enable passkey auth if this is the first credential
        if (auth.authMethods.passkey.credentials.length === 1) {
          if (!auth.mfa.methods.find(m => m.type === 'passkey')) {
            auth.addMfaMethod('passkey', {
              enabled: true
            });
          }
        }
        
        await auth.save();
      }
      
      // Create session
      const session = auth.addSession({
        deviceInfo: {
          userAgent: context.userAgent,
          platform: this.extractPlatform(context.userAgent),
          browser: this.extractBrowser(context.userAgent),
          authenticatorType: credentialData.deviceType
        },
        location: {
          ip: context.ip
        },
        expiresAt: new Date(Date.now() + config.auth.sessionDuration)
      });
      
      // Add login history
      auth.activity.loginHistory.push({
        timestamp: new Date(),
        ip: context.ip,
        userAgent: context.userAgent,
        method: 'passkey',
        success: true,
        mfaUsed: true
      });
      
      await auth.save();
      
      // Update user activity
      user.activity.lastLogin = new Date();
      await user.save();
      
      // Audit log
      await AuditService.log({
        type: 'passkey_registered',
        action: 'register_passkey',
        category: 'authentication',
        result: 'success',
        userId: user._id,
        target: {
          type: 'passkey',
          id: credential.id
        },
        metadata: {
          ...context,
          deviceType: credentialData.deviceType,
          deviceName: credentialData.name,
          isFirstPasskey: auth.authMethods.passkey.credentials.length === 1
        }
      });
      
      return {
        success: true,
        user: this.prepareUserObject(user, session.sessionId),
        sessionId: session.sessionId,
        message: 'Passkey registered successfully'
      };
      
    } catch (error) {
      logger.error('Passkey registration complete error', { error });
      return {
        success: false,
        message: 'Failed to complete passkey registration',
        statusCode: 500
      };
    }
  }
  
  /**
   * Begin passkey authentication
   * @param {Object} data - Authentication data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Authentication challenge
   */
  async beginAuthentication(data, context) {
    const { email, credentialId } = data;
    
    try {
      let auth;
      let allowCredentials = [];
      
      if (credentialId) {
        // Specific credential requested
        auth = await AuthService.getAuthByPasskeyCredential(credentialId);
        
        if (!auth) {
          return {
            success: false,
            message: 'Credential not found',
            statusCode: 404
          };
        }
        
        const credential = auth.authMethods.passkey.credentials.find(c => 
          c.credentialId === credentialId
        );
        
        if (credential) {
          allowCredentials = [{
            type: 'public-key',
            id: Buffer.from(credential.credentialId, 'base64'),
            transports: credential.transports
          }];
        }
      } else if (email) {
        // Find user by email
        const userWithAuth = await UserService.getUserWithAuth(email);
        
        if (!userWithAuth) {
          // Don't reveal if user exists
          return {
            success: false,
            message: 'Invalid credentials',
            statusCode: 401
          };
        }
        
        auth = userWithAuth.auth;
        
        // Get all user's passkey credentials
        allowCredentials = auth.authMethods.passkey.credentials.map(cred => ({
          type: 'public-key',
          id: Buffer.from(cred.credentialId, 'base64'),
          transports: cred.transports
        }));
        
        if (allowCredentials.length === 0) {
          return {
            success: false,
            message: 'No passkeys found for this account',
            statusCode: 404
          };
        }
      } else {
        // Resident key authentication (no email/credentialId provided)
        // Allow any credential
        allowCredentials = [];
      }
      
      // Generate authentication options
      const authnOptions = await this.f2l.assertionOptions();
      
      // Store challenge
      const challengeData = {
        challenge: Buffer.from(authnOptions.challenge).toString('base64'),
        authId: auth?._id,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 300000) // 5 minutes
      };
      
      if (auth) {
        auth.authMethods.passkey.challenges.push(challengeData);
        await auth.save();
      } else {
        // Store in session for resident key auth
        context.session = context.session || {};
        context.session.passkeyChallenge = challengeData;
      }
      
      // Prepare client options
      const publicKeyCredentialRequestOptions = {
        challenge: authnOptions.challenge,
        allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
        userVerification: 'preferred',
        timeout: 60000,
        rpId: this.f2l.config.rpId
      };
      
      // Audit log
      await AuditService.log({
        type: 'passkey_authentication_started',
        action: 'begin_passkey_authentication',
        category: 'authentication',
        result: 'success',
        userId: auth?.userId,
        metadata: {
          ...context,
          email: email || 'resident_key',
          credentialCount: allowCredentials.length
        }
      });
      
      return {
        success: true,
        challenge: publicKeyCredentialRequestOptions
      };
      
    } catch (error) {
      logger.error('Passkey authentication begin error', { error });
      return {
        success: false,
        message: 'Failed to begin passkey authentication',
        statusCode: 500
      };
    }
  }
  
  /**
   * Complete passkey authentication
   * @param {Object} data - Authentication completion data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Authentication result
   */
  async completeAuthentication(data, context) {
    const { credential } = data;
    
    try {
      // Validate credential format
      if (!credential || !credential.id || !credential.response) {
        return {
          success: false,
          message: 'Invalid credential data',
          statusCode: 400
        };
      }
      
      // Find auth record by credential ID
      const auth = await AuthService.getAuthByPasskeyCredential(credential.id);
      
      if (!auth) {
        return {
          success: false,
          message: 'Invalid credentials',
          statusCode: 401
        };
      }
      
      // Get stored credential
      const storedCredential = auth.authMethods.passkey.credentials.find(c => 
        c.credentialId === credential.id
      );
      
      if (!storedCredential) {
        return {
          success: false,
          message: 'Credential not found',
          statusCode: 401
        };
      }
      
      // Find valid challenge
      const challengeData = auth.authMethods.passkey.challenges.find(c => 
        !c.used && c.expiresAt > new Date()
      );
      
      if (!challengeData) {
        // Check session for resident key auth
        const sessionChallenge = context.session?.passkeyChallenge;
        if (!sessionChallenge || sessionChallenge.expiresAt < new Date()) {
          return {
            success: false,
            message: 'Challenge expired or not found',
            statusCode: 400
          };
        }
        challengeData = sessionChallenge;
      }
      
      // Prepare assertion expectations
      const assertionExpectations = {
        challenge: Buffer.from(challengeData.challenge, 'base64'),
        origin: context.origin || `https://${this.f2l.config.rpId}`,
        factor: 'either',
        publicKey: storedCredential.publicKey,
        prevCounter: storedCredential.counter,
        userHandle: auth.userId.toString()
      };
      
      // Verify assertion
      const authnResult = await this.f2l.assertionResult(credential, assertionExpectations);
      
      if (!authnResult) {
        // Record failed attempt
        await this.recordFailedAuthentication(auth, context);
        
        return {
          success: false,
          message: 'Invalid credentials',
          statusCode: 401
        };
      }
      
      // Update credential counter
      storedCredential.counter = authnResult.authnrData.get('counter');
      storedCredential.lastUsedAt = new Date();
      
      // Mark challenge as used
      challengeData.used = true;
      
      // Get user
      const user = await UserService.getUserById(auth.userId);
      
      if (!user) {
        return {
          success: false,
          message: 'User not found',
          statusCode: 404
        };
      }
      
      // Check account status
      const accountCheck = await this.checkAccountStatus(user, auth);
      if (!accountCheck.valid) {
        return accountCheck;
      }
      
      // Create session
      const session = auth.addSession({
        deviceInfo: {
          userAgent: context.userAgent,
          platform: this.extractPlatform(context.userAgent),
          browser: this.extractBrowser(context.userAgent),
          authenticatorType: storedCredential.deviceType
        },
        location: {
          ip: context.ip
        },
        expiresAt: new Date(Date.now() + config.auth.sessionDuration)
      });
      
      // Add login history
      auth.activity.loginHistory.push({
        timestamp: new Date(),
        ip: context.ip,
        userAgent: context.userAgent,
        method: 'passkey',
        success: true,
        mfaUsed: true
      });
      
      // Clear failed attempts
      auth.security.loginAttempts.count = 0;
      auth.security.loginAttempts.lockedUntil = null;
      
      await auth.save();
      
      // Update user activity
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
          method: 'passkey',
          credentialId: credential.id,
          deviceType: storedCredential.deviceType,
          deviceName: storedCredential.name,
          sessionId: session.sessionId
        }
      });
      
      return {
        success: true,
        user: this.prepareUserObject(user, session.sessionId),
        sessionId: session.sessionId
      };
      
    } catch (error) {
      logger.error('Passkey authentication complete error', { error });
      return {
        success: false,
        message: 'Failed to complete passkey authentication',
        statusCode: 500
      };
    }
  }
  
  /**
   * Record failed authentication attempt
   * @param {Object} auth - Auth record
   * @param {Object} context - Request context
   */
  async recordFailedAuthentication(auth, context) {
    try {
      auth.addLoginAttempt(false);
      
      auth.activity.loginHistory.push({
        timestamp: new Date(),
        ip: context.ip,
        userAgent: context.userAgent,
        method: 'passkey',
        success: false
      });
      
      await auth.save();
      
      await AuditService.log({
        type: 'passkey_authentication_failed',
        action: 'authenticate',
        category: 'authentication',
        result: 'failure',
        userId: auth.userId,
        metadata: context
      });
    } catch (error) {
      logger.error('Failed to record authentication attempt', { error });
    }
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
        statusCode: 403
      };
    }
    
    if (user.status === 'suspended') {
      return {
        valid: false,
        success: false,
        message: 'Account has been suspended',
        statusCode: 403
      };
    }
    
    if (auth.isLocked()) {
      return {
        valid: false,
        success: false,
        message: 'Account is temporarily locked',
        statusCode: 423
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Generate device name from user agent
   * @param {string} userAgent - User agent string
   * @param {string} attachmentType - Authenticator attachment type
   * @returns {string} Device name
   */
  generateDeviceName(userAgent, attachmentType) {
    const platform = this.extractPlatform(userAgent);
    const browser = this.extractBrowser(userAgent);
    const type = attachmentType === 'platform' ? 'Built-in' : 'Security Key';
    
    return `${type} on ${platform} ${browser}`;
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
      displayName: user.profile?.displayName,
      avatar: user.profile?.avatar,
      role: user.role,
      organization: user.organization,
      userType: user.userType,
      status: user.status,
      hasPasskey: true,
      sessionId
    };
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

module.exports = PasskeyStrategy;