// server/shared/security/passport/strategies/linkedin-strategy.js
/**
 * @file LinkedIn OAuth Strategy
 * @description LinkedIn authentication using OAuth 2.0
 * @version 3.0.0
 */

const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;

const AuthService = require('../../../auth/services/auth-service');
const config = require('../../../config/config');
const UserService = require('../../../users/services/user-service');
const { AuthenticationError } = require('../../../utils/app-error');
const logger = require('../../../utils/logger');
const AuditService = require('../../services/audit-service');

/**
 * LinkedIn OAuth Strategy Class
 * @class LinkedInAuthStrategy
 */
class LinkedInAuthStrategy {
  constructor() {
    this.strategyOptions = {
      clientID: config.oauth.linkedin.clientId,
      clientSecret: config.oauth.linkedin.clientSecret,
      callbackURL: config.oauth.linkedin.callbackUrl,
      scope: ['r_emailaddress', 'r_liteprofile', 'w_member_social'],
      passReqToCallback: true,
      state: true
    };
    
    this.professionalRoles = [
      'consultant', 'manager', 'director', 'partner',
      'client', 'recruitment_partner', 'hiring_manager'
    ];
  }
  
  /**
   * Create and configure the LinkedIn strategy
   * @returns {LinkedInStrategy} Configured passport strategy
   */
  async createStrategy() {
    return new LinkedInStrategy(this.strategyOptions, async (req, accessToken, refreshToken, profile, done) => {
      try {
        // Extract authentication context
        const context = {
          ip: req.ip,
          userAgent: req.get('user-agent'),
          origin: req.get('origin'),
          organizationId: req.query.organizationId || req.session?.organizationContext,
          intendedRole: req.query.role || 'consultant',
          businessContext: req.query.context || 'professional'
        };
        
        // Process LinkedIn profile
        const linkedinProfile = await this.extractProfileData(profile, accessToken);
        
        // Validate profile data
        const validation = await this.validateProfile(linkedinProfile);
        if (!validation.valid) {
          return done(null, false, {
            message: validation.message,
            code: 'INVALID_PROFILE'
          });
        }
        
        // Analyze professional profile
        const professionalAnalysis = await this.analyzeProfessionalProfile(linkedinProfile, accessToken);
        
        // Handle authentication
        const result = await this.handleLinkedInAuth(linkedinProfile, {
          accessToken,
          refreshToken,
          context,
          professionalInfo: professionalAnalysis
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
            provider: 'linkedin',
            profileId: linkedinProfile.id,
            profile: linkedinProfile,
            tokens: { accessToken, refreshToken },
            professionalInfo: professionalAnalysis
          };
          
          return done(null, false, {
            message: 'Additional information required',
            code: 'ADDITIONAL_INFO_REQUIRED',
            redirect: '/auth/complete-profile'
          });
        }
        
        // Successful authentication
        done(null, result.user, {
          method: 'linkedin',
          sessionId: result.sessionId,
          isNewUser: result.isNewUser,
          professionalProfile: professionalAnalysis
        });
        
      } catch (error) {
        logger.error('LinkedIn authentication error', { error, profileId: profile?.id });
        done(error);
      }
    });
  }
  
  /**
   * Extract profile data from LinkedIn profile
   * @param {Object} profile - LinkedIn profile object
   * @param {string} accessToken - LinkedIn access token
   * @returns {Object} Extracted profile data
   */
  async extractProfileData(profile, accessToken) {
    // LinkedIn API v2 provides structured data
    const profileData = profile._json;
    
    // Extract name components
    const firstName = profileData.firstName?.localized?.en_US || 
                     profile.name?.givenName || '';
    const lastName = profileData.lastName?.localized?.en_US || 
                    profile.name?.familyName || '';
    
    // Extract primary email
    const email = profile.emails?.[0]?.value || profileData.emailAddress;
    
    // Extract profile picture
    let profilePicture = null;
    if (profileData.profilePicture?.displayImage) {
      const elements = profileData.profilePicture['displayImage~']?.elements;
      if (elements && elements.length > 0) {
        // Get the highest quality image
        const bestImage = elements.reduce((prev, current) => 
          (current.data['com.linkedin.digitalmedia.mediaartifact.StillImage']?.displaySize?.width || 0) >
          (prev.data['com.linkedin.digitalmedia.mediaartifact.StillImage']?.displaySize?.width || 0) 
          ? current : prev
        );
        profilePicture = bestImage.identifiers?.[0]?.identifier;
      }
    }
    
    return {
      id: profile.id,
      email: email,
      firstName: firstName,
      lastName: lastName,
      displayName: profile.displayName || `${firstName} ${lastName}`.trim(),
      headline: profileData.headline?.localized?.en_US,
      summary: profileData.summary?.localized?.en_US,
      profilePicture: profilePicture || profile.photos?.[0]?.value,
      profileUrl: profile._raw?.publicProfileUrl,
      location: {
        country: profileData.location?.country,
        countryCode: profileData.location?.countryCode,
        city: profileData.location?.city
      },
      industry: profileData.industry,
      positions: profileData.positions,
      educations: profileData.educations,
      skills: profileData.skills,
      languages: profileData.languages,
      provider: 'linkedin',
      raw: profileData
    };
  }
  
  /**
   * Validate LinkedIn profile
   * @param {Object} profile - Extracted profile data
   * @returns {Object} Validation result
   */
  async validateProfile(profile) {
    if (!profile.id) {
      return {
        valid: false,
        message: 'LinkedIn ID is required'
      };
    }
    
    if (!profile.email) {
      return {
        valid: false,
        message: 'Email is required for authentication. Please grant email permissions.'
      };
    }
    
    // Validate email format
    if (!config.constants.REGEX.EMAIL.test(profile.email)) {
      return {
        valid: false,
        message: 'Invalid email format from LinkedIn'
      };
    }
    
    // Check if we have minimum required profile information
    if (!profile.firstName && !profile.lastName && !profile.displayName) {
      return {
        valid: false,
        message: 'Profile name information is required'
      };
    }
    
    // Check for business email if required
    if (config.oauth.linkedin.requireBusinessEmail) {
      const personalDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
      const emailDomain = profile.email.split('@')[1].toLowerCase();
      
      if (personalDomains.includes(emailDomain)) {
        return {
          valid: false,
          message: 'Please use your business email address'
        };
      }
    }
    
    return { valid: true };
  }
  
  /**
   * Analyze professional profile
   * @param {Object} profile - LinkedIn profile
   * @param {string} accessToken - Access token
   * @returns {Promise<Object>} Professional analysis
   */
  async analyzeProfessionalProfile(profile, accessToken) {
    const analysis = {
      verifiedProfessional: false,
      seniorityLevel: 'unknown',
      yearsOfExperience: 0,
      currentPosition: null,
      currentCompany: null,
      industries: [],
      skills: [],
      recommendations: 0,
      connections: 0,
      profileCompleteness: 0,
      suggestedRole: 'consultant'
    };
    
    try {
      // Analyze positions to determine seniority
      if (profile.positions && profile.positions.length > 0) {
        const currentPosition = profile.positions.find(p => p.current) || profile.positions[0];
        analysis.currentPosition = currentPosition?.title;
        analysis.currentCompany = currentPosition?.company?.name;
        
        // Calculate years of experience
        const firstPosition = profile.positions[profile.positions.length - 1];
        if (firstPosition?.startDate) {
          const startYear = firstPosition.startDate.year;
          analysis.yearsOfExperience = new Date().getFullYear() - startYear;
        }
        
        // Determine seniority level
        const title = (currentPosition?.title || '').toLowerCase();
        if (title.includes('ceo') || title.includes('founder') || title.includes('owner')) {
          analysis.seniorityLevel = 'owner';
          analysis.suggestedRole = 'partner';
        } else if (title.includes('vp') || title.includes('vice president') || title.includes('director')) {
          analysis.seniorityLevel = 'executive';
          analysis.suggestedRole = 'director';
        } else if (title.includes('manager') || title.includes('lead')) {
          analysis.seniorityLevel = 'manager';
          analysis.suggestedRole = 'manager';
        } else if (title.includes('senior')) {
          analysis.seniorityLevel = 'senior';
          analysis.suggestedRole = 'senior_consultant';
        } else if (title.includes('junior') || title.includes('associate')) {
          analysis.seniorityLevel = 'junior';
          analysis.suggestedRole = 'junior_consultant';
        } else if (analysis.yearsOfExperience > 5) {
          analysis.seniorityLevel = 'mid';
          analysis.suggestedRole = 'consultant';
        }
        
        // Check for recruitment roles
        if (title.includes('recruiter') || title.includes('talent')) {
          analysis.suggestedRole = 'recruiter';
        } else if (title.includes('hr') || title.includes('human resources')) {
          analysis.suggestedRole = 'hiring_manager';
        }
      }
      
      // Extract industries
      if (profile.industry) {
        analysis.industries.push(profile.industry);
      }
      
      // Extract skills
      if (profile.skills && Array.isArray(profile.skills)) {
        analysis.skills = profile.skills.slice(0, 10);
      }
      
      // Calculate profile completeness
      const fields = [
        profile.firstName,
        profile.lastName,
        profile.email,
        profile.headline,
        profile.summary,
        profile.profilePicture,
        profile.positions?.length > 0,
        profile.educations?.length > 0,
        profile.skills?.length > 0
      ];
      
      analysis.profileCompleteness = Math.round(
        (fields.filter(Boolean).length / fields.length) * 100
      );
      
      // Mark as verified professional if profile is substantial
      analysis.verifiedProfessional = 
        analysis.profileCompleteness >= 70 &&
        analysis.yearsOfExperience >= 2 &&
        analysis.currentPosition !== null;
      
    } catch (error) {
      logger.error('Failed to analyze LinkedIn profile', { error });
    }
    
    return analysis;
  }
  
  /**
   * Handle LinkedIn authentication
   * @param {Object} profile - LinkedIn profile data
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Authentication result
   */
  async handleLinkedInAuth(profile, authData) {
    try {
      // Check for existing user
      let userWithAuth = await UserService.getUserByOAuthProvider('linkedin', profile.id);
      
      if (!userWithAuth) {
        // Check if user exists with same email
        userWithAuth = await UserService.getUserWithAuth(profile.email);
        
        if (userWithAuth) {
          // Link LinkedIn account to existing user
          return await this.linkLinkedInAccount(userWithAuth, profile, authData);
        } else {
          // Create new user
          return await this.createLinkedInUser(profile, authData);
        }
      } else {
        // Existing LinkedIn user - update and login
        return await this.loginLinkedInUser(userWithAuth, profile, authData);
      }
      
    } catch (error) {
      logger.error('LinkedIn auth handling error', { error, profileId: profile.id });
      throw error;
    }
  }
  
  /**
   * Link LinkedIn account to existing user
   * @param {Object} userWithAuth - Existing user with auth
   * @param {Object} profile - LinkedIn profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Link result
   */
  async linkLinkedInAccount(userWithAuth, profile, authData) {
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
    
    // Update auth record with LinkedIn info
    auth.authMethods.oauth.linkedin = {
      id: profile.id,
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName,
      picture: profile.profilePicture,
      accessToken: authData.accessToken,
      tokenExpiry: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000) // 60 days
    };
    
    // Update professional profile
    if (!user.profile.professionalInfo) {
      user.profile.professionalInfo = {};
    }
    
    user.profile.professionalInfo = {
      ...user.profile.professionalInfo,
      headline: profile.headline,
      summary: profile.summary,
      linkedinUrl: profile.profileUrl,
      industry: profile.industry,
      currentPosition: authData.professionalInfo.currentPosition,
      currentCompany: authData.professionalInfo.currentCompany,
      yearsOfExperience: authData.professionalInfo.yearsOfExperience,
      verified: authData.professionalInfo.verifiedProfessional,
      lastUpdated: new Date()
    };
    
    // Update user role if suggested role is higher
    if (authData.professionalInfo.suggestedRole && 
        this.isHigherRole(authData.professionalInfo.suggestedRole, user.role.primary)) {
      user.role.previousRoles = user.role.previousRoles || [];
      user.role.previousRoles.push({
        role: user.role.primary,
        changedAt: new Date(),
        changedFrom: 'linkedin_verification'
      });
      user.role.primary = authData.professionalInfo.suggestedRole;
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
      method: 'linkedin',
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
        id: 'linkedin'
      },
      metadata: {
        ...authData.context,
        provider: 'linkedin',
        linkedinId: profile.id,
        professionalVerified: authData.professionalInfo.verifiedProfessional,
        roleUpgraded: authData.professionalInfo.suggestedRole !== user.role.primary
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
   * Create new user with LinkedIn account
   * @param {Object} profile - LinkedIn profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Creation result
   */
  async createLinkedInUser(profile, authData) {
    // Check if registration is allowed
    if (!config.oauth.linkedin.allowRegistration) {
      return {
        success: false,
        message: 'Registration with LinkedIn is not allowed',
        code: 'REGISTRATION_DISABLED'
      };
    }
    
    // Determine user type based on context and professional info
    let userType = 'hosted_org_user';
    let primaryRole = authData.professionalInfo.suggestedRole || 'consultant';
    
    if (authData.context.businessContext === 'recruitment') {
      if (authData.professionalInfo.currentPosition?.toLowerCase().includes('recruiter')) {
        userType = 'recruitment_partner';
        primaryRole = 'recruiter';
      } else {
        primaryRole = 'hiring_manager';
      }
    } else if (authData.context.businessContext === 'client') {
      primaryRole = 'client';
    }
    
    // Check if additional info is required
    const requiredFields = this.getRequiredFieldsForRegistration(primaryRole);
    const providedData = {
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName,
      phone: null, // LinkedIn doesn't provide phone
      company: authData.professionalInfo.currentCompany
    };
    
    const missingFields = requiredFields.filter(field => !providedData[field]);
    
    if (missingFields.length > 0) {
      return {
        success: false,
        requiresAdditionalInfo: true,
        missingFields,
        profile,
        suggestedRole: primaryRole,
        professionalInfo: authData.professionalInfo
      };
    }
    
    // Create user data
    const userData = {
      email: profile.email,
      firstName: profile.firstName,
      lastName: profile.lastName,
      profile: {
        displayName: profile.displayName,
        avatar: profile.profilePicture,
        bio: {
          short: profile.headline || `${authData.professionalInfo.currentPosition} at ${authData.professionalInfo.currentCompany}`,
          full: profile.summary
        },
        location: profile.location?.city,
        professionalInfo: {
          headline: profile.headline,
          summary: profile.summary,
          linkedinUrl: profile.profileUrl,
          industry: profile.industry,
          currentPosition: authData.professionalInfo.currentPosition,
          currentCompany: authData.professionalInfo.currentCompany,
          yearsOfExperience: authData.professionalInfo.yearsOfExperience,
          skills: authData.professionalInfo.skills,
          verified: authData.professionalInfo.verifiedProfessional
        }
      },
      preferences: {
        language: 'en',
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        communicationPreferences: {
          professionalUpdates: true,
          industryNews: true
        }
      },
      userType,
      role: {
        primary: primaryRole
      },
      status: 'active',
      isEmailVerified: true // LinkedIn emails are verified
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
      provider: 'linkedin',
      profileId: profile.id,
      profile: {
        id: profile.id,
        email: profile.email,
        firstName: profile.firstName,
        lastName: profile.lastName,
        picture: profile.profilePicture,
        accessToken: authData.accessToken,
        tokenExpiry: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000)
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
    await this.sendWelcomeEmail(user, 'linkedin', authData.professionalInfo);
    
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
        method: 'linkedin',
        provider: 'linkedin',
        linkedinId: profile.id,
        professionalVerified: authData.professionalInfo.verifiedProfessional,
        autoCreated: true,
        suggestedRole: primaryRole
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
   * Login existing LinkedIn user
   * @param {Object} userWithAuth - User with auth record
   * @param {Object} profile - LinkedIn profile
   * @param {Object} authData - Authentication data
   * @returns {Promise<Object>} Login result
   */
  async loginLinkedInUser(userWithAuth, profile, authData) {
    const { user, auth } = userWithAuth;
    
    // Check account status
    const accountCheck = await this.checkAccountStatus(user, auth);
    if (!accountCheck.valid) {
      return accountCheck;
    }
    
    // Update LinkedIn auth data
    const linkedinAuth = auth.authMethods.oauth.linkedin;
    linkedinAuth.lastLogin = new Date();
    linkedinAuth.accessToken = authData.accessToken;
    linkedinAuth.tokenExpiry = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000);
    
    // Update profile data if changed
    let profileUpdated = false;
    
    if (profile.firstName !== linkedinAuth.firstName || profile.lastName !== linkedinAuth.lastName) {
      linkedinAuth.firstName = profile.firstName;
      linkedinAuth.lastName = profile.lastName;
      profileUpdated = true;
    }
    
    if (profile.profilePicture !== linkedinAuth.picture) {
      linkedinAuth.picture = profile.profilePicture;
      if (user.profile.avatar === linkedinAuth.picture || !user.profile.avatar) {
        user.profile.avatar = profile.profilePicture;
      }
      profileUpdated = true;
    }
    
    // Update professional info
    if (authData.professionalInfo.currentPosition || authData.professionalInfo.currentCompany) {
      user.profile.professionalInfo = {
        ...user.profile.professionalInfo,
        headline: profile.headline,
        currentPosition: authData.professionalInfo.currentPosition,
        currentCompany: authData.professionalInfo.currentCompany,
        yearsOfExperience: authData.professionalInfo.yearsOfExperience,
        lastUpdated: new Date()
      };
      profileUpdated = true;
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
      method: 'linkedin',
      success: true
    });
    
    // Clear any failed login attempts
    auth.security.loginAttempts.count = 0;
    auth.security.loginAttempts.lockedUntil = null;
    
    await auth.save();
    
    if (profileUpdated) {
      await user.save();
    }
    
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
        method: 'linkedin',
        provider: 'linkedin',
        linkedinId: profile.id,
        sessionId: session.sessionId,
        profileUpdated
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
   * Check if one role is higher than another
   * @param {string} newRole - New role
   * @param {string} currentRole - Current role
   * @returns {boolean} Is higher role
   */
  isHigherRole(newRole, currentRole) {
    const roleHierarchy = {
      prospect: 1,
      junior_consultant: 2,
      consultant: 3,
      senior_consultant: 4,
      manager: 5,
      senior_manager: 6,
      director: 7,
      partner: 8
    };
    
    return (roleHierarchy[newRole] || 0) > (roleHierarchy[currentRole] || 0);
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
    const baseFields = ['email', 'firstName', 'lastName'];
    
    if (role === 'recruitment_partner' || role === 'recruiter') {
      return [...baseFields, 'company', 'phone'];
    }
    
    if (role === 'client' || role === 'hiring_manager') {
      return [...baseFields, 'company'];
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
      firstName: user.firstName,
      lastName: user.lastName,
      displayName: user.profile.displayName,
      avatar: user.profile.avatar,
      role: user.role,
      organization: user.organization,
      userType: user.userType,
      status: user.status,
      isProfessional: !!user.profile.professionalInfo?.verified,
      currentPosition: user.profile.professionalInfo?.currentPosition,
      currentCompany: user.profile.professionalInfo?.currentCompany,
      sessionId
    };
  }
  
  /**
   * Send welcome email
   * @param {Object} user - User object
   * @param {string} provider - OAuth provider
   * @param {Object} professionalInfo - Professional information
   */
  async sendWelcomeEmail(user, provider, professionalInfo) {
    // This would integrate with your email service
    logger.info('Sending welcome email', {
      userId: user._id,
      email: user.email,
      provider,
      isProfessional: professionalInfo?.verifiedProfessional,
      role: user.role.primary
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

module.exports = LinkedInAuthStrategy;