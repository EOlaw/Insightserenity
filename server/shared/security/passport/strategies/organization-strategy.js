// server/shared/security/passport/strategies/organization-strategy.js
/**
 * @file Organization SSO Strategy
 * @description Enterprise single sign-on authentication strategy
 * @version 3.0.0
 */

const Strategy = require('passport-strategy').Strategy;
const saml = require('@node-saml/passport-saml');
const jwt = require('jsonwebtoken');

const OrganizationService = require('../../../../hosted-organizations/organizations/services/organization-service');
const AuthService = require('../../../auth/services/auth-service');
const config = require('../../../config/config');
const UserService = require('../../../users/services/user-service');
const { AuthenticationError, ValidationError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../services/audit-service');

/**
 * Organization SSO Strategy Class
 * @class OrganizationSSOStrategy
 */
class OrganizationSSOStrategy extends Strategy {
  constructor() {
    super();
    this.name = 'organization';
    
    // SSO provider configurations
    this.providers = new Map();
    
    // Supported SSO protocols
    this.supportedProtocols = ['saml', 'oidc', 'oauth2', 'ldap', 'custom'];
    
    // Default attribute mappings
    this.defaultAttributeMappings = {
      email: ['email', 'mail', 'emailAddress', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
      firstName: ['firstName', 'givenName', 'given_name', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'],
      lastName: ['lastName', 'surname', 'family_name', 'sn', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'],
      displayName: ['displayName', 'name', 'cn', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'],
      employeeId: ['employeeId', 'employeeNumber', 'employee_id'],
      department: ['department', 'dept', 'ou'],
      jobTitle: ['title', 'jobTitle', 'position'],
      manager: ['manager', 'managerEmail', 'reports_to'],
      groups: ['groups', 'memberOf', 'roles']
    };
  }
  
  /**
   * Create and configure the organization strategy
   * @returns {OrganizationSSOStrategy} Configured passport strategy
   */
  async createStrategy() {
    // Load organization SSO configurations
    await this.loadOrganizationConfigs();
    return this;
  }
  
  /**
   * Authenticate request
   * @param {Object} req - Express request object
   * @param {Object} options - Authentication options
   */
  async authenticate(req, options) {
    try {
      const { organizationId, slug, action } = req.params;
      const identifier = organizationId || slug;
      
      if (!identifier) {
        return this.fail({ message: 'Organization identifier required' }, 400);
      }
      
      const context = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        origin: req.get('origin'),
        organizationIdentifier: identifier
      };
      
      // Get organization SSO configuration
      const ssoConfig = await this.getOrganizationSSOConfig(identifier);
      
      if (!ssoConfig) {
        return this.fail({ message: 'SSO not configured for this organization' }, 404);
      }
      
      // Handle different SSO actions
      let result;
      
      switch (action || req.body.action) {
        case 'login':
          result = await this.initiateSSO(ssoConfig, req, context);
          break;
          
        case 'callback':
          result = await this.handleSSOCallback(ssoConfig, req, context);
          break;
          
        case 'metadata':
          result = await this.getMetadata(ssoConfig);
          break;
          
        case 'logout':
          result = await this.handleSSOLogout(ssoConfig, req, context);
          break;
          
        default:
          return this.fail({ message: 'Invalid SSO action' }, 400);
      }
      
      if (result.redirect) {
        return this.redirect(result.redirect);
      }
      
      if (result.success && result.user) {
        this.success(result.user, {
          method: 'organization-sso',
          provider: ssoConfig.provider,
          sessionId: result.sessionId,
          organizationId: ssoConfig.organizationId
        });
      } else if (result.metadata) {
        req.res.type('application/xml').send(result.metadata);
      } else {
        this.fail(result, result.statusCode || 401);
      }
      
    } catch (error) {
      logger.error('Organization SSO error', { error });
      this.error(error);
    }
  }
  
  /**
   * Load organization SSO configurations
   */
  async loadOrganizationConfigs() {
    try {
      // This would load from database
      // For now, using placeholder
      logger.info('Loading organization SSO configurations');
    } catch (error) {
      logger.error('Failed to load SSO configurations', { error });
    }
  }
  
  /**
   * Get organization SSO configuration
   * @param {string} identifier - Organization ID or slug
   * @returns {Promise<Object>} SSO configuration
   */
  async getOrganizationSSOConfig(identifier) {
    try {
      // Get organization
      const organization = await OrganizationService.getOrganizationByIdentifier(identifier);
      
      if (!organization || !organization.ssoConfig?.enabled) {
        return null;
      }
      
      // Build configuration based on provider type
      const config = {
        organizationId: organization._id,
        organizationName: organization.name,
        slug: organization.slug,
        provider: organization.ssoConfig.provider,
        protocol: organization.ssoConfig.protocol,
        ...organization.ssoConfig.settings
      };
      
      // Add attribute mappings
      config.attributeMappings = {
        ...this.defaultAttributeMappings,
        ...organization.ssoConfig.attributeMappings
      };
      
      return config;
      
    } catch (error) {
      logger.error('Failed to get SSO configuration', { error, identifier });
      return null;
    }
  }
  
  /**
   * Initiate SSO login
   * @param {Object} ssoConfig - SSO configuration
   * @param {Object} req - Express request
   * @param {Object} context - Request context
   * @returns {Promise<Object>} SSO initiation result
   */
  async initiateSSO(ssoConfig, req, context) {
    try {
      switch (ssoConfig.protocol) {
        case 'saml':
          return await this.initiateSAML(ssoConfig, req, context);
          
        case 'oidc':
          return await this.initiateOIDC(ssoConfig, req, context);
          
        case 'oauth2':
          return await this.initiateOAuth2(ssoConfig, req, context);
          
        case 'ldap':
          return await this.handleLDAP(ssoConfig, req, context);
          
        case 'custom':
          return await this.handleCustomSSO(ssoConfig, req, context);
          
        default:
          return {
            success: false,
            message: `Unsupported SSO protocol: ${ssoConfig.protocol}`,
            statusCode: 400
          };
      }
    } catch (error) {
      logger.error('SSO initiation error', { error, organizationId: ssoConfig.organizationId });
      return {
        success: false,
        message: 'Failed to initiate SSO',
        statusCode: 500
      };
    }
  }
  
  /**
   * Initiate SAML authentication
   * @param {Object} ssoConfig - SAML configuration
   * @param {Object} req - Express request
   * @param {Object} context - Request context
   * @returns {Promise<Object>} SAML initiation result
   */
  async initiateSAML(ssoConfig, req, context) {
    const samlStrategy = new saml.Strategy({
      callbackUrl: `${config.server.url}/auth/sso/${ssoConfig.slug}/callback`,
      entryPoint: ssoConfig.saml.entryPoint,
      issuer: ssoConfig.saml.issuer || config.server.url,
      cert: ssoConfig.saml.cert,
      identifierFormat: ssoConfig.saml.identifierFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      acceptedClockSkewMs: 5000,
      attributeConsumingServiceIndex: false,
      disableRequestedAuthnContext: true,
      forceAuthn: false,
      skipRequestCompression: false,
      authnRequestBinding: 'HTTP-Redirect'
    }, () => {});
    
    return new Promise((resolve, reject) => {
      samlStrategy.getAuthorizeUrl(req, {}, (err, url) => {
        if (err) {
          reject(err);
        } else {
          // Store state in session
          req.session.ssoState = {
            organizationId: ssoConfig.organizationId,
            protocol: 'saml',
            timestamp: Date.now(),
            context
          };
          
          // Audit log
          AuditService.log({
            type: 'sso_login_initiated',
            action: 'initiate_sso',
            category: 'authentication',
            result: 'success',
            target: {
              type: 'organization',
              id: ssoConfig.organizationId
            },
            metadata: {
              ...context,
              provider: 'saml',
              organizationSlug: ssoConfig.slug
            }
          });
          
          resolve({ redirect: url });
        }
      });
    });
  }
  
  /**
   * Initiate OIDC authentication
   * @param {Object} ssoConfig - OIDC configuration
   * @param {Object} req - Express request
   * @param {Object} context - Request context
   * @returns {Promise<Object>} OIDC initiation result
   */
  async initiateOIDC(ssoConfig, req, context) {
    const { Issuer, generators } = require('openid-client');
    
    try {
      // Discover OIDC configuration
      const issuer = await Issuer.discover(ssoConfig.oidc.discoveryUrl);
      
      const client = new issuer.Client({
        client_id: ssoConfig.oidc.clientId,
        client_secret: ssoConfig.oidc.clientSecret,
        redirect_uris: [`${config.server.url}/auth/sso/${ssoConfig.slug}/callback`],
        response_types: ['code']
      });
      
      // Generate state and nonce
      const state = generators.state();
      const nonce = generators.nonce();
      
      // Store in session
      req.session.ssoState = {
        organizationId: ssoConfig.organizationId,
        protocol: 'oidc',
        state,
        nonce,
        timestamp: Date.now(),
        context
      };
      
      // Generate authorization URL
      const authorizationUrl = client.authorizationUrl({
        scope: ssoConfig.oidc.scope || 'openid email profile',
        state,
        nonce,
        prompt: 'select_account'
      });
      
      // Audit log
      await AuditService.log({
        type: 'sso_login_initiated',
        action: 'initiate_sso',
        category: 'authentication',
        result: 'success',
        target: {
          type: 'organization',
          id: ssoConfig.organizationId
        },
        metadata: {
          ...context,
          provider: 'oidc',
          organizationSlug: ssoConfig.slug
        }
      });
      
      return { redirect: authorizationUrl };
      
    } catch (error) {
      logger.error('OIDC initiation error', { error });
      return {
        success: false,
        message: 'Failed to initiate OIDC authentication',
        statusCode: 500
      };
    }
  }
  
  /**
   * Handle SSO callback
   * @param {Object} ssoConfig - SSO configuration
   * @param {Object} req - Express request
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Callback handling result
   */
  async handleSSOCallback(ssoConfig, req, context) {
    try {
      // Verify session state
      const sessionState = req.session.ssoState;
      
      if (!sessionState || sessionState.organizationId !== ssoConfig.organizationId) {
        return {
          success: false,
          message: 'Invalid SSO session',
          statusCode: 400
        };
      }
      
      // Check session timeout (5 minutes)
      if (Date.now() - sessionState.timestamp > 300000) {
        delete req.session.ssoState;
        return {
          success: false,
          message: 'SSO session expired',
          statusCode: 400
        };
      }
      
      let profile;
      
      switch (ssoConfig.protocol) {
        case 'saml':
          profile = await this.handleSAMLCallback(ssoConfig, req);
          break;
          
        case 'oidc':
          profile = await this.handleOIDCCallback(ssoConfig, req, sessionState);
          break;
          
        case 'oauth2':
          profile = await this.handleOAuth2Callback(ssoConfig, req, sessionState);
          break;
          
        default:
          return {
            success: false,
            message: 'Invalid SSO protocol',
            statusCode: 400
          };
      }
      
      if (!profile) {
        return {
          success: false,
          message: 'Failed to process SSO response',
          statusCode: 401
        };
      }
      
      // Process user profile
      const result = await this.processUserProfile(profile, ssoConfig, sessionState.context);
      
      // Clean up session
      delete req.session.ssoState;
      
      return result;
      
    } catch (error) {
      logger.error('SSO callback error', { error });
      return {
        success: false,
        message: 'SSO authentication failed',
        statusCode: 500
      };
    }
  }
  
  /**
   * Handle SAML callback
   * @param {Object} ssoConfig - SAML configuration
   * @param {Object} req - Express request
   * @returns {Promise<Object>} User profile
   */
  async handleSAMLCallback(ssoConfig, req) {
    const samlStrategy = new saml.Strategy({
      callbackUrl: `${config.server.url}/auth/sso/${ssoConfig.slug}/callback`,
      entryPoint: ssoConfig.saml.entryPoint,
      issuer: ssoConfig.saml.issuer || config.server.url,
      cert: ssoConfig.saml.cert,
      identifierFormat: ssoConfig.saml.identifierFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      acceptedClockSkewMs: 5000
    }, () => {});
    
    return new Promise((resolve, reject) => {
      samlStrategy._saml.validatePostResponse(req.body, (err, profile) => {
        if (err) {
          logger.error('SAML validation error', { err });
          resolve(null);
        } else {
          resolve(this.mapSAMLProfile(profile, ssoConfig.attributeMappings));
        }
      });
    });
  }
  
  /**
   * Map SAML profile to standard format
   * @param {Object} samlProfile - SAML profile
   * @param {Object} mappings - Attribute mappings
   * @returns {Object} Mapped profile
   */
  mapSAMLProfile(samlProfile, mappings) {
    const profile = {
      id: samlProfile.nameID,
      provider: 'saml',
      raw: samlProfile
    };
    
    // Map attributes
    for (const [key, possibleNames] of Object.entries(mappings)) {
      for (const name of possibleNames) {
        if (samlProfile[name]) {
          profile[key] = Array.isArray(samlProfile[name]) ? 
            samlProfile[name][0] : samlProfile[name];
          break;
        }
      }
    }
    
    return profile;
  }
  
  /**
   * Process user profile from SSO
   * @param {Object} profile - User profile from SSO
   * @param {Object} ssoConfig - SSO configuration
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Processing result
   */
  async processUserProfile(profile, ssoConfig, context) {
    try {
      // Validate required attributes
      if (!profile.email) {
        return {
          success: false,
          message: 'Email not provided by SSO provider',
          statusCode: 400
        };
      }
      
      // Check if user exists
      let userWithAuth = await UserService.getUserWithAuth(profile.email);
      
      if (!userWithAuth) {
        // Check if auto-provisioning is enabled
        if (!ssoConfig.autoProvision) {
          return {
            success: false,
            message: 'Account not found. Please contact your administrator.',
            statusCode: 403
          };
        }
        
        // Create new user
        const userData = {
          email: profile.email,
          firstName: profile.firstName || profile.displayName?.split(' ')[0] || '',
          lastName: profile.lastName || profile.displayName?.split(' ').slice(1).join(' ') || '',
          profile: {
            displayName: profile.displayName || profile.email,
            employeeId: profile.employeeId,
            department: profile.department,
            jobTitle: profile.jobTitle
          },
          organization: {
            current: ssoConfig.organizationId,
            organizations: [ssoConfig.organizationId]
          },
          userType: 'hosted_org_user',
          role: {
            primary: this.mapRoleFromGroups(profile.groups, ssoConfig) || 'org_member'
          },
          status: 'active',
          isEmailVerified: true // SSO validates email
        };
        
        const result = await UserService.createUserWithSSO(userData, {
          provider: ssoConfig.provider,
          protocol: ssoConfig.protocol,
          identifier: profile.id,
          attributes: profile
        }, context);
        
        if (!result.success) {
          return result;
        }
        
        userWithAuth = result;
      } else {
        // Update existing user
        const { user, auth } = userWithAuth;
        
        // Check organization membership
        if (!user.organization.organizations.includes(ssoConfig.organizationId)) {
          return {
            success: false,
            message: 'You are not authorized to access this organization',
            statusCode: 403
          };
        }
        
        // Update SSO information
        auth.authMethods.organizationSSO = {
          provider: ssoConfig.provider,
          identifier: profile.id,
          attributes: profile,
          lastSyncedAt: new Date()
        };
        
        // Update user profile if sync is enabled
        if (ssoConfig.syncProfile) {
          if (profile.firstName) user.firstName = profile.firstName;
          if (profile.lastName) user.lastName = profile.lastName;
          if (profile.displayName) user.profile.displayName = profile.displayName;
          if (profile.department) user.profile.department = profile.department;
          if (profile.jobTitle) user.profile.jobTitle = profile.jobTitle;
          
          // Update role if group mapping is enabled
          if (ssoConfig.syncRoles && profile.groups) {
            const newRole = this.mapRoleFromGroups(profile.groups, ssoConfig);
            if (newRole && newRole !== user.role.primary) {
              user.role.primary = newRole;
            }
          }
        }
        
        await auth.save();
        await user.save();
      }
      
      const { user, auth } = userWithAuth;
      
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
          browser: this.extractBrowser(context.userAgent)
        },
        location: {
          ip: context.ip
        },
        expiresAt: new Date(Date.now() + config.auth.sessionDuration),
        ssoProvider: ssoConfig.provider
      });
      
      // Add login history
      auth.activity.loginHistory.push({
        timestamp: new Date(),
        ip: context.ip,
        userAgent: context.userAgent,
        method: 'organization-sso',
        success: true
      });
      
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
          method: 'organization-sso',
          provider: ssoConfig.provider,
          protocol: ssoConfig.protocol,
          organizationId: ssoConfig.organizationId,
          sessionId: session.sessionId
        }
      });
      
      return {
        success: true,
        user: this.prepareUserObject(user, session.sessionId),
        sessionId: session.sessionId
      };
      
    } catch (error) {
      logger.error('User profile processing error', { error });
      return {
        success: false,
        message: 'Failed to process user profile',
        statusCode: 500
      };
    }
  }
  
  /**
   * Map role from SSO groups
   * @param {Array} groups - User groups from SSO
   * @param {Object} ssoConfig - SSO configuration
   * @returns {string} Mapped role
   */
  mapRoleFromGroups(groups, ssoConfig) {
    if (!groups || !ssoConfig.roleMapping) {
      return null;
    }
    
    // Check each group against role mappings
    for (const group of groups) {
      const normalizedGroup = group.toLowerCase().trim();
      
      for (const [role, patterns] of Object.entries(ssoConfig.roleMapping)) {
        if (patterns.some(pattern => {
          if (pattern.startsWith('/') && pattern.endsWith('/')) {
            // Regex pattern
            const regex = new RegExp(pattern.slice(1, -1), 'i');
            return regex.test(normalizedGroup);
          }
          // Exact match
          return pattern.toLowerCase() === normalizedGroup;
        })) {
          return role;
        }
      }
    }
    
    return ssoConfig.defaultRole || 'org_member';
  }
  
  /**
   * Get SSO metadata
   * @param {Object} ssoConfig - SSO configuration
   * @returns {Promise<Object>} Metadata result
   */
  async getMetadata(ssoConfig) {
    if (ssoConfig.protocol !== 'saml') {
      return {
        success: false,
        message: 'Metadata only available for SAML',
        statusCode: 400
      };
    }
    
    const samlStrategy = new saml.Strategy({
      callbackUrl: `${config.server.url}/auth/sso/${ssoConfig.slug}/callback`,
      issuer: ssoConfig.saml.issuer || config.server.url,
      cert: null, // SP cert if available
      privateCert: null // SP private key if available
    }, () => {});
    
    const metadata = samlStrategy.generateServiceProviderMetadata();
    
    return {
      metadata,
      contentType: 'application/xml'
    };
  }
  
  /**
   * Handle SSO logout
   * @param {Object} ssoConfig - SSO configuration
   * @param {Object} req - Express request
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Logout result
   */
  async handleSSOLogout(ssoConfig, req, context) {
    try {
      // Perform local logout first
      if (req.user) {
        await AuthService.logout({
          accessToken: req.token,
          userId: req.user._id
        }, context);
      }
      
      // Handle protocol-specific logout
      switch (ssoConfig.protocol) {
        case 'saml':
          if (ssoConfig.saml.sloUrl) {
            const samlStrategy = new saml.Strategy({
              logoutUrl: ssoConfig.saml.sloUrl,
              issuer: ssoConfig.saml.issuer || config.server.url,
              cert: ssoConfig.saml.cert
            }, () => {});
            
            return new Promise((resolve) => {
              samlStrategy.logout(req, (err, url) => {
                if (err) {
                  logger.error('SAML logout error', { err });
                  resolve({ redirect: config.client.url });
                } else {
                  resolve({ redirect: url });
                }
              });
            });
          }
          break;
          
        case 'oidc':
          if (ssoConfig.oidc.endSessionEndpoint) {
            const logoutUrl = new URL(ssoConfig.oidc.endSessionEndpoint);
            logoutUrl.searchParams.set('post_logout_redirect_uri', config.client.url);
            if (req.user?.idToken) {
              logoutUrl.searchParams.set('id_token_hint', req.user.idToken);
            }
            return { redirect: logoutUrl.toString() };
          }
          break;
      }
      
      // Default redirect
      return { redirect: config.client.url };
      
    } catch (error) {
      logger.error('SSO logout error', { error });
      return { redirect: config.client.url };
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
    
    return { valid: true };
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
      employeeId: user.profile?.employeeId,
      department: user.profile?.department,
      jobTitle: user.profile?.jobTitle,
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

module.exports = OrganizationSSOStrategy;