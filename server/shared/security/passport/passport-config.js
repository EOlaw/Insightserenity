// server/shared/security/passport/passport-config.js
/**
 * @file Passport Configuration
 * @description Main Passport.js configuration and initialization
 * @version 3.0.0
 */

const passport = require('passport');
const mongoose = require('mongoose');
const logger = require('../../utils/logger');
const { AuthenticationError } = require('../../utils/app-error');

// Import strategies
const LocalStrategy = require('./strategies/local-strategy');
const GoogleStrategy = require('./strategies/google-strategy');
const GitHubStrategy = require('./strategies/github-strategy');
const LinkedInStrategy = require('./strategies/linkedin-strategy');
const PasskeyStrategy = require('./strategies/passkey-strategy');
const OrganizationStrategy = require('./strategies/organization-strategy');

/**
 * Passport Configuration Class
 * @class PassportConfig
 */
class PassportConfig {
  constructor() {
    this.initialized = false;
    this.strategies = new Map();
  }
  
  /**
   * Initialize Passport configuration
   * @param {Object} app - Express application instance
   */
  async initialize(app) {
    if (this.initialized) {
      logger.warn('Passport already initialized');
      return;
    }
    
    try {
      // Initialize Passport
      app.use(passport.initialize());
      app.use(passport.session());
      
      // Configure serialization
      this.configureSerializationStrategies();
      
      // Register all strategies
      await this.registerStrategies();
      
      // Set up strategy event handlers
      this.setupStrategyHandlers();
      
      this.initialized = true;
      logger.info('Passport initialization completed');
    } catch (error) {
      logger.error('Passport initialization failed', { error });
      throw error;
    }
  }
  
  /**
   * Configure user serialization and deserialization
   */
  configureSerializationStrategies() {
    // Serialize user for session storage
    passport.serializeUser((user, done) => {
      try {
        // Store minimal user data in session
        const sessionData = {
          id: user._id || user.id,
          type: user.userType,
          role: user.role?.primary,
          organizationId: user.organization?.current,
          sessionId: user.sessionId
        };
        
        done(null, sessionData);
      } catch (error) {
        logger.error('User serialization error', { error });
        done(error);
      }
    });
    
    // Deserialize user from session
    passport.deserializeUser(async (sessionData, done) => {
      try {
        // Get models
        const User = require('../../users/models/user-model');
        const Auth = require('../../auth/models/auth-model');
        
        // Find user
        const user = await User.findById(sessionData.id)
          .select('-password')
          .populate('organization.current', 'name slug type')
          .lean();
        
        if (!user) {
          return done(null, false);
        }
        
        // Check if user is active
        if (!user.active || user.status === 'suspended') {
          return done(new AuthenticationError('Account is not active'));
        }
        
        // Get auth record for session validation
        const auth = await Auth.findOne({ userId: user._id });
        
        if (auth && sessionData.sessionId) {
          const session = auth.sessions.find(s => 
            s.sessionId === sessionData.sessionId && 
            s.isActive &&
            (!s.expiresAt || s.expiresAt > new Date())
          );
          
          if (!session) {
            return done(new AuthenticationError('Session expired or invalid'));
          }
          
          // Update session activity
          auth.updateSessionActivity(sessionData.sessionId);
          await auth.save();
        }
        
        // Attach additional properties
        user.sessionId = sessionData.sessionId;
        user.permissions = await this.getUserPermissions(user);
        
        done(null, user);
      } catch (error) {
        logger.error('User deserialization error', { error, sessionData });
        done(error);
      }
    });
  }
  
  /**
   * Register all authentication strategies
   */
  async registerStrategies() {
    // Local Strategy (Email/Password)
    const localStrategy = new LocalStrategy();
    passport.use('local', await localStrategy.createStrategy());
    this.strategies.set('local', localStrategy);
    
    // Google OAuth Strategy
    const googleStrategy = new GoogleStrategy();
    passport.use('google', await googleStrategy.createStrategy());
    this.strategies.set('google', googleStrategy);
    
    // GitHub OAuth Strategy
    const githubStrategy = new GitHubStrategy();
    passport.use('github', await githubStrategy.createStrategy());
    this.strategies.set('github', githubStrategy);
    
    // LinkedIn OAuth Strategy
    const linkedinStrategy = new LinkedInStrategy();
    passport.use('linkedin', await linkedinStrategy.createStrategy());
    this.strategies.set('linkedin', linkedinStrategy);
    
    // Passkey Strategy (WebAuthn)
    const passkeyStrategy = new PasskeyStrategy();
    passport.use('passkey', await passkeyStrategy.createStrategy());
    this.strategies.set('passkey', passkeyStrategy);
    
    // Organization SSO Strategy
    const organizationStrategy = new OrganizationStrategy();
    passport.use('organization', await organizationStrategy.createStrategy());
    this.strategies.set('organization', organizationStrategy);
    
    logger.info('All authentication strategies registered', {
      strategies: Array.from(this.strategies.keys())
    });
  }
  
  /**
   * Set up strategy event handlers
   */
  setupStrategyHandlers() {
    // Listen for strategy-specific events
    this.strategies.forEach((strategy, name) => {
      if (strategy.on) {
        strategy.on('authenticated', (user, info) => {
          logger.info('User authenticated', {
            strategy: name,
            userId: user._id,
            method: info?.method
          });
        });
        
        strategy.on('failed', (reason, info) => {
          logger.warn('Authentication failed', {
            strategy: name,
            reason,
            ...info
          });
        });
      }
    });
  }
  
  /**
   * Get user permissions
   * @param {Object} user - User object
   * @returns {Promise<Array>} User permissions
   */
  async getUserPermissions(user) {
    try {
      const permissions = new Set();
      
      // Add role-based permissions
      const rolePermissions = this.getRolePermissions(user.role?.primary);
      rolePermissions.forEach(perm => permissions.add(perm));
      
      // Add secondary role permissions
      if (user.role?.secondary?.length > 0) {
        user.role.secondary.forEach(role => {
          const secondaryPerms = this.getRolePermissions(role);
          secondaryPerms.forEach(perm => permissions.add(perm));
        });
      }
      
      // Add custom permissions
      if (user.permissions?.custom?.length > 0) {
        user.permissions.custom.forEach(perm => permissions.add(perm));
      }
      
      // Add organization-specific permissions
      if (user.organization?.current) {
        const orgPerms = await this.getOrganizationPermissions(user._id, user.organization.current);
        orgPerms.forEach(perm => permissions.add(perm));
      }
      
      return Array.from(permissions);
    } catch (error) {
      logger.error('Failed to get user permissions', { error, userId: user._id });
      return [];
    }
  }
  
  /**
   * Get role-based permissions
   * @param {string} role - User role
   * @returns {Array} Role permissions
   */
  getRolePermissions(role) {
    const rolePermissionMap = {
      // Platform roles
      super_admin: ['*'],
      platform_admin: [
        'platform.manage',
        'users.manage',
        'organizations.manage',
        'billing.manage',
        'recruitment.manage'
      ],
      support_agent: [
        'users.view',
        'organizations.view',
        'tickets.manage',
        'reports.view'
      ],
      
      // Core business roles
      partner: [
        'organization.admin',
        'projects.manage',
        'team.manage',
        'billing.manage',
        'reports.full'
      ],
      director: [
        'organization.write',
        'projects.manage',
        'team.manage',
        'reports.view'
      ],
      manager: [
        'projects.manage',
        'team.view',
        'reports.view'
      ],
      consultant: [
        'projects.write',
        'projects.read',
        'team.read'
      ],
      
      // Client roles
      client: [
        'projects.view.own',
        'invoices.view.own',
        'reports.view.own'
      ],
      
      // Recruitment roles
      recruitment_partner: [
        'jobs.manage',
        'candidates.view',
        'applications.manage',
        'commission.view'
      ],
      recruiter: [
        'jobs.write',
        'candidates.view',
        'applications.write'
      ],
      candidate: [
        'profile.manage.own',
        'applications.manage.own',
        'jobs.view'
      ]
    };
    
    return rolePermissionMap[role] || [];
  }
  
  /**
   * Get organization-specific permissions
   * @param {string} userId - User ID
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Array>} Organization permissions
   */
  async getOrganizationPermissions(userId, organizationId) {
    try {
      // This would fetch from organization member model
      // Placeholder implementation
      return [];
    } catch (error) {
      logger.error('Failed to get organization permissions', { error, userId, organizationId });
      return [];
    }
  }
  
  /**
   * Create authentication middleware
   * @param {string} strategy - Strategy name
   * @param {Object} options - Authentication options
   * @returns {Function} Express middleware
   */
  authenticate(strategy, options = {}) {
    const defaultOptions = {
      session: true,
      failureFlash: false,
      failureMessage: true,
      ...options
    };
    
    return (req, res, next) => {
      // Add request context to passport
      req.authContext = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        organizationId: req.headers['x-organization-id'] || req.query.organizationId
      };
      
      passport.authenticate(strategy, defaultOptions, (err, user, info) => {
        if (err) {
          logger.error('Authentication error', { error: err, strategy });
          return next(err);
        }
        
        if (!user) {
          const message = info?.message || 'Authentication failed';
          return res.status(401).json({
            success: false,
            error: {
              message,
              code: info?.code || 'AUTH_FAILED'
            }
          });
        }
        
        // Log in user
        req.logIn(user, defaultOptions, (loginErr) => {
          if (loginErr) {
            logger.error('Login error', { error: loginErr, userId: user._id });
            return next(loginErr);
          }
          
          // Call success handler
          if (options.successRedirect) {
            return res.redirect(options.successRedirect);
          }
          
          if (options.successCallback) {
            return options.successCallback(req, res, next, user);
          }
          
          next();
        });
      })(req, res, next);
    };
  }
  
  /**
   * Ensure user is authenticated
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  ensureAuthenticated(options = {}) {
    return (req, res, next) => {
      if (req.isAuthenticated()) {
        // Check session validity
        if (req.user?.sessionId) {
          // Additional session validation can be added here
        }
        
        return next();
      }
      
      if (options.redirectTo) {
        return res.redirect(options.redirectTo);
      }
      
      res.status(401).json({
        success: false,
        error: {
          message: 'Authentication required',
          code: 'AUTH_REQUIRED'
        }
      });
    };
  }
  
  /**
   * Ensure user has specific role
   * @param {string|Array} roles - Required roles
   * @param {Object} options - Middleware options
   * @returns {Function} Express middleware
   */
  ensureRole(roles, options = {}) {
    const roleArray = Array.isArray(roles) ? roles : [roles];
    
    return [
      this.ensureAuthenticated(options),
      (req, res, next) => {
        const userRole = req.user?.role?.primary;
        
        if (roleArray.includes(userRole) || userRole === 'super_admin') {
          return next();
        }
        
        res.status(403).json({
          success: false,
          error: {
            message: 'Insufficient role privileges',
            code: 'ROLE_REQUIRED',
            details: { required: roleArray }
          }
        });
      }
    ];
  }
  
  /**
   * Get strategy instance
   * @param {string} name - Strategy name
   * @returns {Object} Strategy instance
   */
  getStrategy(name) {
    return this.strategies.get(name);
  }
  
  /**
   * Refresh strategy configuration
   * @param {string} name - Strategy name
   */
  async refreshStrategy(name) {
    const strategy = this.strategies.get(name);
    if (strategy && strategy.refresh) {
      await strategy.refresh();
      logger.info('Strategy refreshed', { strategy: name });
    }
  }
}

// Create and export singleton instance
module.exports = new PassportConfig();