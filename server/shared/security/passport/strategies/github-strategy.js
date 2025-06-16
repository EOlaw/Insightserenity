// server/shared/security/passport/strategies/github-strategy.js
/**
 * @file GitHub OAuth Strategy
 * @description GitHub authentication using OAuth 2.0
 * @version 3.0.0
 */

const GitHubStrategy = require('passport-github2').Strategy;

const AuthService = require('../../../auth/services/auth-service');
const config = require('../../../config/config');
const UserService = require('../../../users/services/user-service');
const { AuthenticationError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../services/audit-service');

/**
 * GitHub OAuth Strategy Class
 * @class GitHubAuthStrategy
 */
class GitHubAuthStrategy {
  constructor() {
    this.strategyOptions = {
      clientID: config.oauth.github.clientId,
      clientSecret: config.oauth.github.clientSecret,
      callbackURL: config.oauth.github.callbackUrl,
      scope: ['user:email', 'read:user'],
      passReqToCallback: true
    };
    
    this.developerRoles = ['developer', 'consultant', 'technical_lead', 'architect'];
  }
  
  /**
   * Create and configure the GitHub strategy
   * @returns {GitHubStrategy} Configured passport strategy
   */
  async createStrategy() {
    return new GitHubStrategy(this.strategyOptions, async (req, accessToken, refreshToken, profile, done) => {
      try {
        // Extract authentication context
        const context = {
          ip: req.ip,
          userAgent: req.get('user-agent'),
          origin: req.get('origin'),
          organizationId: req.query.organizationId || req.session?.organizationContext,
          intendedRole: req.query.role || 'developer'
        };
        
        // Process GitHub profile
        const githubProfile = await this.extractProfileData(profile, accessToken);
        
        // Validate profile data
        const validation = await this.validateProfile(githubProfile);
        if (!validation.valid) {
          return done(null, false, {
            message: validation.message,
            code: 'INVALID_PROFILE'
          });
        }
        
        // Check GitHub account requirements
        const requirements = await this.checkGitHubRequirements(githubProfile, accessToken);
        if (!requirements.passed) {
          return done(null, false, {
            message: requirements.message,
            code: 'REQUIREMENTS_NOT_MET',
            details: requirements.details
          });
        }
        
        // Handle authentication
        const result = await this.handleGitHubAuth(githubProfile, {
          accessToken,
          refreshToken,
          context,
          developerInfo: requirements.developerInfo
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
            provider: 'github',
            profileId: githubProfile.id,
            profile: githubProfile,
            tokens: { accessToken, refreshToken },
            developerInfo: requirements.developerInfo
          };
          
          return done(null, false, {
            message: 'Additional information required',
            code: 'ADDITIONAL_INFO_REQUIRED',
            redirect: '/auth/complete-profile'
          });
        }
        
        // Successful authentication
        done(null, result.user, {
          method: 'github',
          sessionId: result.sessionId,
          isNewUser: result.isNewUser,
          developerProfile: requirements.developerInfo
        });
        
      } catch (error) {
        logger.error('GitHub authentication error', { error, profileId: profile?.id });
        done(error);
      }
    });
  }
  
  /**
   * Extract profile data from GitHub profile
   * @param {Object} profile - GitHub profile object
   * @param {string} accessToken - GitHub access token
   * @returns {Object} Extracted profile data
   */
  async extractProfileData(profile, accessToken) {
    // GitHub doesn't always provide email in profile
    let email = profile.emails?.[0]?.value;
    
    if (!email && accessToken) {
      // Fetch primary email from GitHub API
      try {
        const axios = require('axios');
        const response = await axios.get('https://api.github.com/user/emails', {
          headers: {
            'Authorization': `token ${accessToken}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        });
        
        const primaryEmail = response.data.find(e => e.primary);
        email = primaryEmail?.email;
      } catch (error) {
        logger.error('Failed to fetch GitHub email', { error });
      }
    }
    
    return {
      id: profile.id,
      username: profile.username,
      email: email,
      displayName: profile.displayName || profile.username,
      firstName: profile.displayName?.split(' ')[0] || profile.username,
      lastName: profile.displayName?.split(' ').slice(1).join(' ') || '',
      avatar: profile.photos?.[0]?.value,
      profileUrl: profile.profileUrl,
      company: profile._json?.company,
      location: profile._json?.location,
      bio: profile._json?.bio,
      blog: profile._json?.blog,
      hireable: profile._json?.hireable,
      publicRepos: profile._json?.public_repos,
      followers: profile._json?.followers,
      following: profile._json?.following,
      createdAt: profile._json?.created_at,
      provider: 'github',
      raw: profile._json
    };
  }
  
  /**
   * Validate GitHub profile
   * @param {Object} profile - Extracted profile data
   * @returns {Object} Validation result
   */
  async validateProfile(profile) {
    if (!profile.id) {
      return {
        valid: false,
        message: 'GitHub ID is required'
      };
    }
    
    if (!profile.username) {
      return {
        valid: false,
        message: 'GitHub username is required'
      };
    }
    
    if (!profile.email) {
      return {
        valid: false,
        message: 'Email is required. Please make your email public on GitHub or grant email permissions.'
      };
    }
    
    // Validate email format
    if (!config.constants.REGEX.EMAIL.test(profile.email)) {
      return {
        valid: false,
        message: 'Invalid email format from GitHub'
      };
    }
    
    // Check if GitHub account is too new (anti-spam)
    const accountAge = Date.now() - new Date(profile.createdAt).getTime();
    const minimumAge = 30 * 24 * 60 * 60 * 1000; // 30 days
    
    if (accountAge < minimumAge) {
      return {
        valid: false,
        message: 'GitHub account must be at least 30 days old'
      };
    }
    
    return { valid: true };
  }
  
  /**
   * Check GitHub account requirements
   * @param {Object} profile - GitHub profile
   * @param {string} accessToken - Access token
   * @returns {Promise<Object>} Requirements check result
   */
  async checkGitHubRequirements(profile, accessToken) {
    const requirements = {
      minimumRepos: 5,
      minimumFollowers: 0,
      minimumContributions: 10,
      requiredLanguages: ['JavaScript', 'TypeScript', 'Python', 'Java', 'C#', 'Go', 'Ruby', 'PHP']
    };
    
    const developerInfo = {
      githubUsername: profile.username,
      publicRepos: profile.publicRepos || 0,
      followers: profile.followers || 0,
      accountAge: Math.floor((Date.now() - new Date(profile.createdAt).getTime()) / (1000 * 60 * 60 * 24)),
      languages: [],
      topRepositories: [],
      contributions: 0,
      verified: false
    };
    
    try {
      if (accessToken) {
        const axios = require('axios');
        
        // Fetch user's repositories
        const reposResponse = await axios.get(`https://api.github.com/users/${profile.username}/repos`, {
          headers: {
            'Authorization': `token ${accessToken}`,
            'Accept': 'application/vnd.github.v3+json'
          },
          params: {
            sort: 'updated',
            per_page: 100
          }
        });
        
        const repos = reposResponse.data;
        
        // Extract languages
        const languageSet = new Set();
        repos.forEach(repo => {
          if (repo.language) {
            languageSet.add(repo.language);
          }
        });
        developerInfo.languages = Array.from(languageSet);
        
        // Get top repositories
        developerInfo.topRepositories = repos
          .filter(repo => !repo.fork)
          .sort((a, b) => b.stargazers_count - a.stargazers_count)
          .slice(0, 5)
          .map(repo => ({
            name: repo.name,
            stars: repo.stargazers_count,
            language: repo.language,
            description: repo.description
          }));
        
        // Estimate contributions (simplified)
        developerInfo.contributions = repos.reduce((total, repo) => {
          return total + (repo.fork ? 0 : 1) + repo.stargazers_count;
        }, 0);
      }
      
      // Check requirements
      const checks = {
        hasMinimumRepos: developerInfo.publicRepos >= requirements.minimumRepos,
        hasRelevantLanguages: developerInfo.languages.some(lang => 
          requirements.requiredLanguages.includes(lang)
        ),
        hasActivity: developerInfo.contributions >= requirements.minimumContributions,
        isEstablished: developerInfo.accountAge >= 30
      };
      
      developerInfo.verified = Object.values(checks).every(check => check);
      
      // Determine if requirements are met
      const passed = developerInfo.verified || config.oauth.github.allowUnverifiedDevelopers;
      
      return {
        passed,
        message: passed ? 'Requirements met' : 'GitHub account does not meet developer requirements',
        details: checks,
        developerInfo
      };
      
    } catch (error) {
      logger.error('Failed to check GitHub requirements', { error });
      // Allow authentication to continue even if checks fail
      return {
        passed: true,
        message: 'Requirements check skipped',
        developerInfo
      };
    }
  }
  
  /**
   * Handle GitHub authentication
   * @param {Object} profile - GitHub profile data
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Authentication result
   */
  async handleGitHubAuth(profile, authData) {
    try {
      // Check for existing user
      let userWithAuth = await UserService.getUserByOAuthProvider('github', profile.id);
      
      if (!userWithAuth) {
        // Check if user exists with same email
        userWithAuth = await UserService.getUserWithAuth(profile.email);
        
        if (userWithAuth) {
          // Link GitHub account to existing user
          return await this.linkGitHubAccount(userWithAuth, profile, authData);
        } else {
          // Create new user
          return await this.createGitHubUser(profile, authData);
        }
      } else {
        // Existing GitHub user - update and login
        return await this.loginGitHubUser(userWithAuth, profile, authData);
      }
      
    } catch (error) {
      logger.error('GitHub auth handling error', { error, profileId: profile.id });
      throw error;
    }
  }
  
  /**
   * Link GitHub account to existing user
   * @param {Object} userWithAuth - Existing user with auth
   * @param {Object} profile - GitHub profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Link result
   */
  async linkGitHubAccount(userWithAuth, profile, authData) {
    const { user, auth } = userWithAuth;
    
    // Check if account linking is allowed
    if (!config.oauth.allowAccountLinking) {
      return {
        success: false,
        message: 'An account with this email already exists. Please login with your existing method.',
        code: 'ACCOUNT_EXISTS'
      };
    }
    
    // Check account status
    const accountCheck = await this.checkAccountStatus(user, auth);
    if (!accountCheck.valid) {
      return accountCheck;
    }
    
    // Update auth record with GitHub info
    auth.authMethods.oauth.github = {
      id: profile.id,
      username: profile.username,
      email: profile.email,
      avatar: profile.avatar,
      accessToken: authData.accessToken
    };
    
    // If this is a developer profile, update user info
    if (authData.developerInfo.verified) {
      if (!user.profile.developerProfile) {
        user.profile.developerProfile = {};
      }
      
      user.profile.developerProfile.github = {
        username: profile.username,
        profileUrl: profile.profileUrl,
        languages: authData.developerInfo.languages,
        repositories: authData.developerInfo.topRepositories,
        contributions: authData.developerInfo.contributions,
        verified: true
      };
      
      // Update user role if they're currently a basic user
      if (['prospect', 'client'].includes(user.role.primary)) {
        user.role.primary = 'developer';
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
      method: 'github',
      success: true
    });
    
    await auth.save();
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
        id: 'github'
      },
      metadata: {
        ...authData.context,
        provider: 'github',
        githubUsername: profile.username,
        developerVerified: authData.developerInfo.verified
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
   * Create new user with GitHub account
   * @param {Object} profile - GitHub profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Creation result
   */
  async createGitHubUser(profile, authData) {
    // Check if registration is allowed
    if (!config.oauth.github.allowRegistration) {
      return {
        success: false,
        message: 'Registration with GitHub is not allowed',
        code: 'REGISTRATION_DISABLED'
      };
    }
    
    // Determine user type and role based on context
    let userType = 'core_consultant';
    let primaryRole = 'developer';
    
    if (authData.context.intendedRole === 'candidate') {
      userType = 'job_seeker';
      primaryRole = 'candidate';
    } else if (authData.developerInfo.verified) {
      primaryRole = 'consultant';
    }
    
    // Check if additional info is required
    const requiredFields = this.getRequiredFieldsForRegistration(primaryRole);
    const providedData = {
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName
    };
    
    const missingFields = requiredFields.filter(field => !providedData[field]);
    
    if (missingFields.length > 0) {
      return {
        success: false,
        requiresAdditionalInfo: true,
        missingFields,
        profile,
        suggestedRole: primaryRole
      };
    }
    
    // Create user data
    const userData = {
      email: profile.email,
      firstName: profile.firstName || profile.username,
      lastName: profile.lastName || '',
      username: profile.username,
      profile: {
        displayName: profile.displayName || profile.username,
        avatar: profile.avatar,
        bio: {
          short: profile.bio || `Developer from GitHub`,
          full: profile.bio
        },
        location: profile.location,
        website: profile.blog,
        developerProfile: authData.developerInfo.verified ? {
          github: {
            username: profile.username,
            profileUrl: profile.profileUrl,
            languages: authData.developerInfo.languages,
            repositories: authData.developerInfo.topRepositories,
            contributions: authData.developerInfo.contributions,
            verified: true
          }
        } : null
      },
      preferences: {
        language: 'en',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      userType,
      role: {
        primary: primaryRole
      },
      status: 'active',
      isEmailVerified: true // GitHub emails are verified
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
      provider: 'github',
      profileId: profile.id,
      profile: {
        id: profile.id,
        username: profile.username,
        email: profile.email,
        avatar: profile.avatar,
        accessToken: authData.accessToken
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
    await this.sendWelcomeEmail(user, 'github', authData.developerInfo);
    
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
        method: 'github',
        provider: 'github',
        githubUsername: profile.username,
        developerVerified: authData.developerInfo.verified,
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
   * Login existing GitHub user
   * @param {Object} userWithAuth - User with auth record
   * @param {Object} profile - GitHub profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Login result
   */
  async loginGitHubUser(userWithAuth, profile, authData) {
    const { user, auth } = userWithAuth;
    
    // Check account status
    const accountCheck = await this.checkAccountStatus(user, auth);
    if (!accountCheck.valid) {
      return accountCheck;
    }
    
    // Update GitHub auth data
    const githubAuth = auth.authMethods.oauth.github;
    githubAuth.lastLogin = new Date();
    githubAuth.accessToken = authData.accessToken;
    
    // Update profile data if changed
    if (profile.username !== githubAuth.username) {
      githubAuth.username = profile.username;
    }
    if (profile.avatar !== githubAuth.avatar) {
      githubAuth.avatar = profile.avatar;
      // Update user avatar if it matches the old GitHub avatar
      if (user.profile.avatar === githubAuth.avatar || !user.profile.avatar) {
        user.profile.avatar = profile.avatar;
      }
    }
    
    // Update developer profile if verified
    if (authData.developerInfo.verified) {
      if (!user.profile.developerProfile) {
        user.profile.developerProfile = {};
      }
      
      user.profile.developerProfile.github = {
        username: profile.username,
        profileUrl: profile.profileUrl,
        languages: authData.developerInfo.languages,
        repositories: authData.developerInfo.topRepositories,
        contributions: authData.developerInfo.contributions,
        verified: true,
        lastUpdated: new Date()
      };
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
      method: 'github',
      success: true
    });
    
    // Clear any failed login attempts
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
        ...authData.context,
        method: 'github',
        provider: 'github',
        githubUsername: profile.username,
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
    
    return { valid: true };
  }
  
  /**
   * Get required fields for registration
   * @param {string} role - User role
   * @returns {Array} Required fields
   */
  getRequiredFieldsForRegistration(role) {
    const baseFields = ['email'];
    
    if (role === 'consultant' || role === 'developer') {
      return [...baseFields, 'firstName', 'lastName'];
    }
    
    return baseFields;
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
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      displayName: user.profile.displayName,
      avatar: user.profile.avatar,
      role: user.role,
      organization: user.organization,
      userType: user.userType,
      status: user.status,
      isDeveloper: !!user.profile.developerProfile?.github?.verified,
      sessionId
    };
  }
  
  /**
   * Send welcome email
   * @param {Object} user - User object
   * @param {string} provider - OAuth provider
   * @param {Object} developerInfo - Developer information
   */
  async sendWelcomeEmail(user, provider, developerInfo) {
    // This would integrate with your email service
    logger.info('Sending welcome email', {
      userId: user._id,
      email: user.email,
      provider,
      isDeveloper: developerInfo?.verified
    });
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

module.exports = GitHubAuthStrategy;