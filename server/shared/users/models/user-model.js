// server/shared/users/models/user-model.js
/**
 * @file User Model
 * @description Comprehensive user model for all user types in the platform
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');
const config = require('../../config');
const constants = require('../../config/constants');

/**
 * User Schema Definition
 */
const userSchema = new mongoose.Schema({
  // Basic Information
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true,
    validate: {
      validator: (email) => constants.REGEX.EMAIL.test(email),
      message: 'Invalid email format'
    }
  },
  
  username: {
    type: String,
    unique: true,
    sparse: true,
    trim: true,
    lowercase: true,
    minlength: 3,
    maxlength: 30,
    validate: {
      validator: (username) => constants.REGEX.USERNAME.test(username),
      message: 'Username can only contain lowercase letters, numbers, hyphens, and underscores'
    }
  },
  
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 50
  },
  
  middleName: {
    type: String,
    trim: true,
    maxlength: 50
  },
  
  // User Type and Role
  userType: {
    type: String,
    required: true,
    enum: constants.USER.TYPES_ENUM,
    index: true
  },
  
  role: {
    primary: {
      type: String,
      required: true,
      enum: constants.USER.ROLES_ENUM,
      index: true
    },
    secondary: [{
      type: String,
      enum: constants.USER.ROLES_ENUM
    }],
    previousRoles: [{
      role: String,
      changedAt: Date,
      changedBy: mongoose.Schema.Types.ObjectId,
      reason: String
    }]
  },
  
  // Profile Information
  profile: {
    displayName: {
      type: String,
      trim: true,
      maxlength: 100
    },
    
    avatar: {
      url: String,
      publicId: String,
      source: {
        type: String,
        enum: ['upload', 'gravatar', 'oauth', 'generated']
      }
    },
    
    coverImage: {
      url: String,
      publicId: String
    },
    
    bio: {
      short: {
        type: String,
        maxlength: 160
      },
      full: {
        type: String,
        maxlength: 2000
      }
    },
    
    title: String,
    department: String,
    location: String,
    timezone: String,
    
    dateOfBirth: {
      type: Date,
      validate: {
        validator: function(date) {
          const age = Math.floor((new Date() - date) / (365.25 * 24 * 60 * 60 * 1000));
          return age >= 16 && age <= 120;
        },
        message: 'User must be between 16 and 120 years old'
      }
    },
    
    gender: {
      type: String,
      enum: ['male', 'female', 'other', 'prefer_not_to_say']
    },
    
    languages: [{
      code: String,
      name: String,
      proficiency: {
        type: String,
        enum: ['native', 'fluent', 'professional', 'conversational', 'basic']
      }
    }],
    
    // Professional Information
    professionalInfo: {
      headline: String,
      summary: String,
      yearsOfExperience: Number,
      currentPosition: String,
      currentCompany: String,
      linkedinUrl: String,
      portfolioUrl: String,
      resumeUrl: String,
      industry: String,
      specializations: [String],
      certifications: [{
        name: String,
        issuer: String,
        issueDate: Date,
        expiryDate: Date,
        credentialId: String,
        credentialUrl: String
      }],
      education: [{
        institution: String,
        degree: String,
        fieldOfStudy: String,
        startDate: Date,
        endDate: Date,
        grade: String,
        activities: String,
        description: String
      }],
      experience: [{
        company: String,
        title: String,
        location: String,
        startDate: Date,
        endDate: Date,
        current: Boolean,
        description: String,
        achievements: [String]
      }],
      skills: [{
        name: String,
        category: String,
        level: {
          type: String,
          enum: ['beginner', 'intermediate', 'advanced', 'expert']
        },
        yearsOfExperience: Number,
        endorsements: Number
      }],
      achievements: [{
        title: String,
        description: String,
        date: Date,
        url: String
      }],
      publications: [{
        title: String,
        publisher: String,
        date: Date,
        url: String,
        authors: [String]
      }]
    },
    
    // Developer Profile (for technical users)
    developerProfile: {
      github: {
        username: String,
        profileUrl: String,
        verified: Boolean,
        languages: [String],
        repositories: [{
          name: String,
          stars: Number,
          language: String,
          description: String
        }],
        contributions: Number,
        followers: Number,
        following: Number
      },
      stackoverflow: {
        userId: String,
        profileUrl: String,
        reputation: Number,
        badges: {
          gold: Number,
          silver: Number,
          bronze: Number
        }
      },
      personalWebsite: String,
      techStack: [String],
      openSourceContributions: [{
        project: String,
        url: String,
        role: String,
        description: String
      }]
    },
    
    // Social Links
    socialLinks: {
      twitter: String,
      facebook: String,
      instagram: String,
      youtube: String,
      medium: String,
      devto: String,
      behance: String,
      dribbble: String
    },
    
    // Employee Information (for organization users)
    employeeInfo: {
      employeeId: String,
      department: String,
      division: String,
      jobTitle: String,
      reportingTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      directReports: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      }],
      startDate: Date,
      workLocation: String,
      workPhone: String,
      workEmail: String,
      costCenter: String,
      employmentType: {
        type: String,
        enum: constants.RECRUITMENT.EMPLOYMENT_TYPES_ENUM
      }
    },
    
    // Recruitment Information (for job seekers/candidates)
    candidateProfile: {
      resumeVisibility: {
        type: String,
        enum: ['public', 'recruiters_only', 'private'],
        default: 'recruiters_only'
      },
      activelyLooking: {
        type: Boolean,
        default: false
      },
      availableFrom: Date,
      expectedSalary: {
        min: Number,
        max: Number,
        currency: String,
        period: {
          type: String,
          enum: ['hourly', 'monthly', 'yearly']
        }
      },
      preferredLocations: [String],
      preferredJobTypes: [{
        type: String,
        enum: constants.RECRUITMENT.EMPLOYMENT_TYPES_ENUM
      }],
      remotePreference: {
        type: String,
        enum: constants.RECRUITMENT.WORK_LOCATIONS_ENUM
      },
      noticePeriod: {
        value: Number,
        unit: {
          type: String,
          enum: ['days', 'weeks', 'months']
        }
      }
    }
  },
  
  // Contact Information
  contact: {
    phone: {
      countryCode: String,
      number: String,
      verified: {
        type: Boolean,
        default: false
      },
      verifiedAt: Date
    },
    
    alternateEmail: {
      email: String,
      verified: {
        type: Boolean,
        default: false
      },
      verifiedAt: Date
    },
    
    address: {
      street1: String,
      street2: String,
      city: String,
      state: String,
      country: String,
      postalCode: String,
      coordinates: {
        latitude: Number,
        longitude: Number
      }
    },
    
    emergencyContact: {
      name: String,
      relationship: String,
      phone: String,
      email: String
    }
  },
  
  // Organization Associations
  organization: {
    current: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      index: true
    },
    
    organizations: [{
      organizationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization'
      },
      role: String,
      department: String,
      joinedAt: Date,
      leftAt: Date,
      active: Boolean
    }],
    
    invitations: [{
      organizationId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Organization'
      },
      invitedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
      },
      role: String,
      invitedAt: Date,
      expiresAt: Date,
      status: {
        type: String,
        enum: ['pending', 'accepted', 'declined', 'expired']
      }
    }]
  },
  
  // Permissions and Access Control
  permissions: {
    system: [{
      resource: String,
      actions: [String],
      conditions: mongoose.Schema.Types.Mixed
    }],
    
    organization: [{
      organizationId: mongoose.Schema.Types.ObjectId,
      permissions: [{
        resource: String,
        actions: [String],
        conditions: mongoose.Schema.Types.Mixed
      }]
    }],
    
    custom: [String],
    
    restrictions: [{
      type: String,
      reason: String,
      imposedAt: Date,
      imposedBy: mongoose.Schema.Types.ObjectId,
      expiresAt: Date
    }]
  },
  
  // Preferences
  preferences: {
    language: {
      type: String,
      default: 'en'
    },
    
    timezone: {
      type: String,
      default: 'UTC'
    },
    
    dateFormat: {
      type: String,
      default: 'MM/DD/YYYY'
    },
    
    timeFormat: {
      type: String,
      enum: ['12h', '24h'],
      default: '12h'
    },
    
    currency: {
      type: String,
      enum: constants.BILLING.CURRENCIES_ENUM,
      default: 'USD'
    },
    
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'light'
    },
    
    emailNotifications: {
      marketing: { type: Boolean, default: false },
      updates: { type: Boolean, default: true },
      security: { type: Boolean, default: true },
      activity: { type: Boolean, default: true },
      jobAlerts: { type: Boolean, default: true },
      messages: { type: Boolean, default: true },
      reminders: { type: Boolean, default: true },
      digest: {
        enabled: { type: Boolean, default: false },
        frequency: {
          type: String,
          enum: ['daily', 'weekly', 'monthly']
        }
      }
    },
    
    pushNotifications: {
      enabled: { type: Boolean, default: false },
      sound: { type: Boolean, default: true },
      vibrate: { type: Boolean, default: true }
    },
    
    privacy: {
      profileVisibility: {
        type: String,
        enum: ['public', 'members_only', 'connections_only', 'private'],
        default: 'members_only'
      },
      showEmail: { type: Boolean, default: false },
      showPhone: { type: Boolean, default: false },
      showLocation: { type: Boolean, default: true },
      allowMessaging: {
        type: String,
        enum: ['everyone', 'connections_only', 'nobody'],
        default: 'connections_only'
      },
      allowConnectionRequests: { type: Boolean, default: true }
    },
    
    accessibility: {
      screenReader: { type: Boolean, default: false },
      highContrast: { type: Boolean, default: false },
      largeText: { type: Boolean, default: false },
      reduceMotion: { type: Boolean, default: false },
      keyboardNavigation: { type: Boolean, default: false }
    }
  },
  
  // Status and Activity
  status: {
    type: String,
    enum: constants.USER.STATUS_ENUM,
    default: 'pending',
    index: true
  },
  
  active: {
    type: Boolean,
    default: true,
    index: true
  },
  
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  
  isPhoneVerified: {
    type: Boolean,
    default: false
  },
  
  isProfileComplete: {
    type: Boolean,
    default: false
  },
  
  profileCompleteness: {
    percentage: {
      type: Number,
      default: 0,
      min: 0,
      max: 100
    },
    missingFields: [String],
    lastCalculated: Date
  },
  
  activity: {
    lastLogin: Date,
    lastLogout: Date,
    lastActive: Date,
    lastPasswordChange: Date,
    lastProfileUpdate: Date,
    
    totalLogins: {
      type: Number,
      default: 0
    },
    
    currentStreak: {
      days: { type: Number, default: 0 },
      startDate: Date
    },
    
    longestStreak: {
      days: { type: Number, default: 0 },
      startDate: Date,
      endDate: Date
    },
    
    onlineStatus: {
      type: String,
      enum: ['online', 'away', 'busy', 'offline'],
      default: 'offline'
    },
    
    lastSeenAt: Date
  },
  
  // Gamification and Achievements
  gamification: {
    points: {
      total: { type: Number, default: 0 },
      current: { type: Number, default: 0 },
      spent: { type: Number, default: 0 }
    },
    
    level: {
      current: { type: Number, default: 1 },
      progress: { type: Number, default: 0 },
      nextLevelPoints: { type: Number, default: 100 }
    },
    
    badges: [{
      badgeId: String,
      name: String,
      description: String,
      icon: String,
      earnedAt: Date,
      category: String,
      rarity: {
        type: String,
        enum: ['common', 'uncommon', 'rare', 'epic', 'legendary']
      }
    }],
    
    achievements: [{
      achievementId: String,
      name: String,
      description: String,
      unlockedAt: Date,
      progress: Number,
      maxProgress: Number
    }],
    
    leaderboard: {
      globalRank: Number,
      organizationRank: Number,
      departmentRank: Number
    }
  },
  
  // Statistics and Metrics
  statistics: {
    profile: {
      views: { type: Number, default: 0 },
      uniqueViewers: { type: Number, default: 0 },
      searchAppearances: { type: Number, default: 0 },
      lastViewedAt: Date
    },
    
    engagement: {
      postsCreated: { type: Number, default: 0 },
      commentsCreated: { type: Number, default: 0 },
      likesGiven: { type: Number, default: 0 },
      likesReceived: { type: Number, default: 0 },
      sharesCount: { type: Number, default: 0 }
    },
    
    network: {
      connectionsCount: { type: Number, default: 0 },
      followersCount: { type: Number, default: 0 },
      followingCount: { type: Number, default: 0 },
      endorsementsReceived: { type: Number, default: 0 },
      endorsementsGiven: { type: Number, default: 0 },
      recommendationsReceived: { type: Number, default: 0 },
      recommendationsGiven: { type: Number, default: 0 }
    },
    
    recruitment: {
      applicationsSubmitted: { type: Number, default: 0 },
      applicationViews: { type: Number, default: 0 },
      interviewsScheduled: { type: Number, default: 0 },
      offersReceived: { type: Number, default: 0 },
      jobsReferred: { type: Number, default: 0 }
    },
    
    projects: {
      created: { type: Number, default: 0 },
      participated: { type: Number, default: 0 },
      completed: { type: Number, default: 0 },
      hoursLogged: { type: Number, default: 0 }
    }
  },
  
  // Subscription and Billing
  subscription: {
    plan: {
      type: String,
      enum: constants.BILLING.PLAN_TYPES_ENUM,
      default: 'free'
    },
    
    status: {
      type: String,
      enum: constants.BILLING.SUBSCRIPTION_STATUS_ENUM,
      default: 'active'
    },
    
    startDate: Date,
    endDate: Date,
    renewalDate: Date,
    
    trial: {
      isActive: { type: Boolean, default: false },
      startDate: Date,
      endDate: Date,
      extended: { type: Boolean, default: false }
    },
    
    billing: {
      customerId: String,
      paymentMethod: String,
      lastPaymentDate: Date,
      nextPaymentDate: Date,
      amount: Number,
      currency: {
        type: String,
        enum: constants.BILLING.CURRENCIES_ENUM
      },
      interval: {
        type: String,
        enum: constants.BILLING.SUBSCRIPTION_BILLING_CYCLES_ENUM
      }
    },
    
    features: [{
      name: String,
      enabled: Boolean,
      limit: Number,
      used: Number
    }],
    
    addons: [{
      name: String,
      price: Number,
      startDate: Date,
      endDate: Date
    }]
  },
  
  // Authentication
  auth: {
    provider: {
      type: String,
      enum: constants.AUTH.PROVIDERS_ENUM,
      default: 'local'
    },
    
    providers: [{
      name: {
        type: String,
        enum: constants.AUTH.PROVIDERS_ENUM
      },
      providerId: String,
      email: String,
      profileData: mongoose.Schema.Types.Mixed,
      connectedAt: Date,
      lastUsed: Date
    }],
    
    twoFactor: {
      enabled: { type: Boolean, default: false },
      secret: String,
      backupCodes: [String],
      methods: [{
        type: String,
        enum: constants.AUTH.TWO_FACTOR_METHODS_ENUM
      }],
      lastUsed: Date
    },
    
    sessions: [{
      sessionId: String,
      type: {
        type: String,
        enum: constants.AUTH.SESSION_TYPES_ENUM
      },
      device: String,
      browser: String,
      ipAddress: String,
      location: String,
      createdAt: Date,
      lastActive: Date,
      expiresAt: Date
    }],
    
    passwordHistory: [{
      hash: String,
      createdAt: Date
    }],
    
    failedAttempts: {
      count: { type: Number, default: 0 },
      lastAttempt: Date,
      lockedUntil: Date
    },
    
    tokens: [{
      type: {
        type: String,
        enum: constants.AUTH.TOKEN_TYPES_ENUM
      },
      token: String,
      expiresAt: Date,
      usedAt: Date,
      createdAt: Date
    }]
  },
  
  // Metadata
  metadata: {
    source: {
      type: String,
      enum: constants.AUTH.SOURCE_TYPES_ENUM,
      default: 'web'
    },
    
    referrer: {
      type: String,
      userId: mongoose.Schema.Types.ObjectId,
      campaign: String,
      medium: String
    },
    
    tags: [String],
    
    customFields: mongoose.Schema.Types.Mixed,
    
    importData: {
      source: String,
      importedAt: Date,
      importedBy: mongoose.Schema.Types.ObjectId,
      originalId: String
    },
    
    deletion: {
      requested: { type: Boolean, default: false },
      requestedAt: Date,
      requestedBy: mongoose.Schema.Types.ObjectId,
      scheduledFor: Date,
      reason: String,
      token: String
    },
    
    statusHistory: [{
      status: {
        type: String,
        enum: constants.USER.STATUS_ENUM
      },
      changedAt: Date,
      changedBy: mongoose.Schema.Types.ObjectId,
      reason: String
    }]
  }
}, {
  timestamps: true,
  collection: 'users'
});

// Indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ username: 1 });
userSchema.index({ 'profile.displayName': 'text', firstName: 'text', lastName: 'text' });
userSchema.index({ userType: 1, 'role.primary': 1 });
userSchema.index({ 'organization.current': 1 });
userSchema.index({ status: 1, active: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ 'activity.lastLogin': -1 });
userSchema.index({ 'profile.professionalInfo.skills.name': 1 });
userSchema.index({ 'profile.location': 1 });
userSchema.index({ 'profile.candidateProfile.activelyLooking': 1 });
userSchema.index({ 'subscription.plan': 1, 'subscription.status': 1 });
userSchema.index({ 'auth.provider': 1 });
userSchema.index({ 'metadata.source': 1 });

// Compound indexes
userSchema.index({ userType: 1, status: 1, active: 1 });
userSchema.index({ 'organization.current': 1, 'role.primary': 1 });
userSchema.index({ 'subscription.status': 1, 'subscription.endDate': 1 });

// Virtual fields
userSchema.virtual('fullName').get(function() {
  const parts = [this.firstName, this.middleName, this.lastName].filter(Boolean);
  return parts.join(' ');
});

userSchema.virtual('initials').get(function() {
  const firstInitial = this.firstName ? this.firstName[0].toUpperCase() : '';
  const lastInitial = this.lastName ? this.lastName[0].toUpperCase() : '';
  return firstInitial + lastInitial;
});

userSchema.virtual('age').get(function() {
  if (!this.profile.dateOfBirth) return null;
  const today = new Date();
  const birthDate = new Date(this.profile.dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age;
});

userSchema.virtual('isTrialActive').get(function() {
  if (!this.subscription.trial.isActive) return false;
  return new Date() < this.subscription.trial.endDate;
});

userSchema.virtual('subscriptionDaysRemaining').get(function() {
  if (!this.subscription.endDate) return null;
  const now = new Date();
  const endDate = new Date(this.subscription.endDate);
  const diffTime = endDate - now;
  return Math.ceil(diffTime / constants.TIME.DAY);
});

/**
 * Instance Methods
 */

// Update last active timestamp
userSchema.methods.updateLastActive = function() {
  this.activity.lastActive = new Date();
  return this.save();
};

// Calculate profile completeness
userSchema.methods.calculateProfileCompleteness = function() {
  const requiredFields = [
    'email', 'firstName', 'lastName', 'profile.displayName',
    'profile.bio.short', 'profile.location', 'profile.avatar.url'
  ];
  
  const optionalFields = [
    'username', 'profile.bio.full', 'profile.title',
    'contact.phone.number', 'profile.socialLinks.linkedin',
    'profile.professionalInfo.headline', 'profile.professionalInfo.summary'
  ];
  
  let completed = 0;
  let total = requiredFields.length + optionalFields.length;
  const missing = [];
  
  // Check required fields
  requiredFields.forEach(field => {
    const value = field.split('.').reduce((obj, key) => obj?.[key], this);
    if (value) {
      completed++;
    } else {
      missing.push(field);
    }
  });
  
  // Check optional fields
  optionalFields.forEach(field => {
    const value = field.split('.').reduce((obj, key) => obj?.[key], this);
    if (value) {
      completed++;
    }
  });
  
  // Additional checks based on user type
  if (this.userType === constants.USER.TYPES.JOB_SEEKER) {
    const candidateFields = [
      'profile.candidateProfile.resume',
      'profile.professionalInfo.experience',
      'profile.professionalInfo.skills'
    ];
    total += candidateFields.length;
    
    candidateFields.forEach(field => {
      const value = field.split('.').reduce((obj, key) => obj?.[key], this);
      if (value && (Array.isArray(value) ? value.length > 0 : true)) {
        completed++;
      } else {
        missing.push(field);
      }
    });
  }
  
  const percentage = Math.round((completed / total) * 100);
  
  this.profileCompleteness = {
    percentage,
    missingFields: missing,
    lastCalculated: new Date()
  };
  
  this.isProfileComplete = percentage >= 80;
  
  return this.profileCompleteness;
};

// Add points for gamification
userSchema.methods.addPoints = async function(points, reason) {
  this.gamification.points.total += points;
  this.gamification.points.current += points;
  
  // Check for level up
  while (this.gamification.points.total >= this.gamification.level.nextLevelPoints) {
    this.gamification.level.current++;
    this.gamification.level.progress = 0;
    this.gamification.level.nextLevelPoints = this.gamification.level.current * 100;
  }
  
  // Update progress
  this.gamification.level.progress = 
    ((this.gamification.points.total % 100) / 100) * 100;
  
  return this.save();
};

// Award badge
userSchema.methods.awardBadge = async function(badge) {
  const existingBadge = this.gamification.badges.find(b => b.badgeId === badge.badgeId);
  
  if (!existingBadge) {
    this.gamification.badges.push({
      ...badge,
      earnedAt: new Date()
    });
    
    // Award points for badge
    const pointsMap = {
      common: 10,
      uncommon: 25,
      rare: 50,
      epic: 100,
      legendary: 250
    };
    
    await this.addPoints(pointsMap[badge.rarity] || 10, `Earned ${badge.name} badge`);
  }
  
  return this.save();
};

// Update online status
userSchema.methods.updateOnlineStatus = function(status) {
  this.activity.onlineStatus = status;
  this.activity.lastSeenAt = new Date();
  
  if (status === 'offline') {
    this.activity.lastLogout = new Date();
  }
  
  return this.save();
};

// Check if user can perform action
userSchema.methods.canPerform = function(resource, action, organizationId) {
  // Check system permissions
  const systemPerm = this.permissions.system.find(p => 
    p.resource === resource && p.actions.includes(action)
  );
  
  if (systemPerm) return true;
  
  // Check organization permissions
  if (organizationId) {
    const orgPerms = this.permissions.organization.find(o => 
      o.organizationId.equals(organizationId)
    );
    
    if (orgPerms) {
      const perm = orgPerms.permissions.find(p => 
        p.resource === resource && p.actions.includes(action)
      );
      if (perm) return true;
    }
  }
  
  // Check custom permissions
  const customPermString = `${resource}:${action}`;
  return this.permissions.custom.includes(customPermString);
};

// Get avatar URL with fallback
userSchema.methods.getAvatarUrl = function() {
  if (this.profile.avatar?.url) {
    return this.profile.avatar.url;
  }
  
  // Generate Gravatar URL as fallback
  const hash = crypto
    .createHash('md5')
    .update(this.email.toLowerCase())
    .digest('hex');
  
  return `https://www.gravatar.com/avatar/${hash}?d=identicon&s=200`;
};

// Check if subscription is active
userSchema.methods.hasActiveSubscription = function() {
  if (!this.subscription.endDate) return false;
  return new Date() < new Date(this.subscription.endDate) && 
         this.subscription.status === constants.BILLING.SUBSCRIPTION_STATUS.ACTIVE;
};

// Check if user has feature access
userSchema.methods.hasFeatureAccess = function(featureName) {
  const feature = this.subscription.features.find(f => f.name === featureName);
  return feature ? feature.enabled : false;
};

// Add session
userSchema.methods.addSession = function(sessionData) {
  this.auth.sessions.push({
    ...sessionData,
    createdAt: new Date(),
    lastActive: new Date()
  });
  
  // Keep only last 10 sessions
  if (this.auth.sessions.length > 10) {
    this.auth.sessions = this.auth.sessions.slice(-10);
  }
  
  return this.save();
};

// Remove session
userSchema.methods.removeSession = function(sessionId) {
  this.auth.sessions = this.auth.sessions.filter(s => s.sessionId !== sessionId);
  return this.save();
};

// Update status with history
userSchema.methods.updateStatus = function(newStatus, reason, changedBy) {
  const oldStatus = this.status;
  this.status = newStatus;
  
  this.metadata.statusHistory.push({
    status: newStatus,
    changedAt: new Date(),
    changedBy,
    reason: `Changed from ${oldStatus} to ${newStatus}. ${reason || ''}`
  });
  
  return this.save();
};

/**
 * Static Methods
 */

// Find by email or username
userSchema.statics.findByEmailOrUsername = async function(identifier) {
  const query = identifier.includes('@') 
    ? { email: identifier.toLowerCase() }
    : { username: identifier.toLowerCase() };
  
  return this.findOne(query);
};

// Search users
userSchema.statics.searchUsers = async function(searchTerm, options = {}) {
  const {
    userType,
    role,
    organizationId,
    status = constants.USER.STATUS.ACTIVE,
    limit = 20,
    skip = 0,
    fields
  } = options;
  
  const query = {
    status,
    active: true,
    $or: [
      { firstName: new RegExp(searchTerm, 'i') },
      { lastName: new RegExp(searchTerm, 'i') },
      { 'profile.displayName': new RegExp(searchTerm, 'i') },
      { email: new RegExp(searchTerm, 'i') },
      { username: new RegExp(searchTerm, 'i') }
    ]
  };
  
  if (userType) query.userType = userType;
  if (role) query['role.primary'] = role;
  if (organizationId) query['organization.current'] = organizationId;
  
  return this.find(query)
    .select(fields || 'firstName lastName email profile.displayName profile.avatar')
    .limit(limit)
    .skip(skip)
    .sort({ 'activity.lastActive': -1 });
};

// Get active users count
userSchema.statics.getActiveUsersCount = async function(period = 'day') {
  const dateMap = {
    day: constants.TIME.DAY,
    week: constants.TIME.WEEK,
    month: constants.TIME.MONTH
  };
  
  const since = new Date(Date.now() - dateMap[period]);
  
  return this.countDocuments({
    status: constants.USER.STATUS.ACTIVE,
    active: true,
    'activity.lastActive': { $gte: since }
  });
};

// Get user statistics
userSchema.statics.getUserStats = async function(userId) {
  const user = await this.findById(userId);
  if (!user) return null;
  
  return {
    profileCompleteness: user.profileCompleteness.percentage,
    totalLogins: user.activity.totalLogins,
    currentStreak: user.activity.currentStreak,
    level: user.gamification.level.current,
    points: user.gamification.points.total,
    badges: user.gamification.badges.length,
    connections: user.statistics.network.connectionsCount,
    profileViews: user.statistics.profile.views
  };
};

// Bulk update user status
userSchema.statics.bulkUpdateStatus = async function(userIds, status, reason) {
  return this.updateMany(
    { _id: { $in: userIds } },
    { 
      $set: { 
        status,
        'activity.lastActive': new Date()
      },
      $push: {
        'metadata.statusHistory': {
          status,
          changedAt: new Date(),
          reason
        }
      }
    }
  );
};

// Get users by subscription status
userSchema.statics.getUsersBySubscriptionStatus = async function(status) {
  return this.find({
    'subscription.status': status,
    status: constants.USER.STATUS.ACTIVE,
    active: true
  });
};

// Get trial users expiring soon
userSchema.statics.getTrialUsersExpiringSoon = async function(days = 3) {
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + days);
  
  return this.find({
    'subscription.trial.isActive': true,
    'subscription.trial.endDate': { $lte: expiryDate },
    status: constants.USER.STATUS.ACTIVE,
    active: true
  });
};

// Pre-save middleware
userSchema.pre('save', async function(next) {
  // Generate display name if not provided
  if (!this.profile.displayName) {
    this.profile.displayName = `${this.firstName} ${this.lastName}`.trim();
  }
  
  // Calculate profile completeness on save
  if (this.isModified()) {
    this.calculateProfileCompleteness();
  }
  
  // Update last active
  this.activity.lastActive = new Date();
  
  // Clean up expired sessions
  const now = new Date();
  this.auth.sessions = this.auth.sessions.filter(session => 
    !session.expiresAt || session.expiresAt > now
  );
  
  // Clean up expired tokens
  this.auth.tokens = this.auth.tokens.filter(token => 
    !token.expiresAt || token.expiresAt > now
  );
  
  next();
});

// Post-save middleware
userSchema.post('save', function(doc) {
  // Emit user updated event
  if (this.wasNew) {
    // Handle new user created
    console.log('New user created', { userId: doc._id, email: doc.email });
  } else {
    // Handle user updated
    console.log('User updated', { userId: doc._id });
  }
});

// Pre-remove middleware
userSchema.pre('deleteOne', { document: true, query: false }, function(next) {
  // Log user deletion
  console.log('User being deleted', { userId: this._id, email: this.email });
  next();
});

// Create and export model
const User = mongoose.model('User', userSchema);

module.exports = User;