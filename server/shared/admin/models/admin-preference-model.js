/**
 * @file Admin Preference Model
 * @description Comprehensive preference management for administrative users including UI, notifications, and operational settings
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { ValidationError, AppError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

// Import admin constants
const { AdminRoles } = require('../constants/admin-roles');

/**
 * Notification Preferences Schema
 * Controls how and when the admin user receives notifications
 */
const notificationPreferencesSchema = new Schema({
  // Global notification settings
  enabled: {
    type: Boolean,
    default: true
  },
  
  // Channel preferences
  channels: {
    inApp: {
      enabled: { type: Boolean, default: true },
      sound: { type: Boolean, default: true },
      desktop: { type: Boolean, default: true },
      badge: { type: Boolean, default: true }
    },
    
    email: {
      enabled: { type: Boolean, default: true },
      frequency: {
        type: String,
        enum: ['immediate', 'hourly', 'daily', 'weekly', 'never'],
        default: 'immediate'
      },
      digest: { type: Boolean, default: false },
      digestTime: { type: String, default: '09:00' }, // HH:MM format
      digestDays: [{ type: Number, min: 0, max: 6 }], // 0=Sunday, 6=Saturday
      format: {
        type: String,
        enum: ['plain', 'html', 'markdown'],
        default: 'html'
      }
    },
    
    sms: {
      enabled: { type: Boolean, default: false },
      criticalOnly: { type: Boolean, default: true },
      phoneNumber: String,
      verified: { type: Boolean, default: false }
    },
    
    push: {
      enabled: { type: Boolean, default: true },
      devices: [{
        deviceId: String,
        deviceName: String,
        platform: String,
        registeredAt: Date,
        lastUsed: Date
      }]
    },
    
    webhook: {
      enabled: { type: Boolean, default: false },
      url: String,
      secret: String,
      events: [String],
      retryAttempts: { type: Number, default: 3 }
    }
  },
  
  // Category-specific preferences
  categories: {
    security: {
      priority: {
        type: String,
        enum: ['all', 'high_critical', 'critical_only', 'none'],
        default: 'high_critical'
      },
      channels: [String],
      immediate: { type: Boolean, default: true }
    },
    
    system: {
      priority: {
        type: String,
        enum: ['all', 'high_critical', 'critical_only', 'none'],
        default: 'high_critical'
      },
      channels: [String],
      immediate: { type: Boolean, default: false }
    },
    
    operations: {
      priority: {
        type: String,
        enum: ['all', 'high_critical', 'critical_only', 'none'],
        default: 'all'
      },
      channels: [String],
      immediate: { type: Boolean, default: false }
    },
    
    compliance: {
      priority: {
        type: String,
        enum: ['all', 'high_critical', 'critical_only', 'none'],
        default: 'all'
      },
      channels: [String],
      immediate: { type: Boolean, default: true }
    },
    
    business: {
      priority: {
        type: String,
        enum: ['all', 'high_critical', 'critical_only', 'none'],
        default: 'high_critical'
      },
      channels: [String],
      immediate: { type: Boolean, default: false }
    }
  },
  
  // Quiet hours
  quietHours: {
    enabled: { type: Boolean, default: false },
    startTime: { type: String, default: '22:00' }, // HH:MM
    endTime: { type: String, default: '08:00' }, // HH:MM
    timezone: { type: String, default: 'UTC' },
    allowCritical: { type: Boolean, default: true },
    weekendsOnly: { type: Boolean, default: false }
  },
  
  // Do not disturb settings
  doNotDisturb: {
    enabled: { type: Boolean, default: false },
    startDate: Date,
    endDate: Date,
    reason: String,
    allowEmergency: { type: Boolean, default: true }
  }
}, {
  _id: false
});

/**
 * Dashboard Preferences Schema
 * Controls dashboard layout and widget configurations
 */
const dashboardPreferencesSchema = new Schema({
  // Layout preferences
  layout: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'light'
    },
    
    density: {
      type: String,
      enum: ['compact', 'comfortable', 'spacious'],
      default: 'comfortable'
    },
    
    sidebar: {
      collapsed: { type: Boolean, default: false },
      pinned: { type: Boolean, default: true },
      width: { type: Number, default: 280 }
    },
    
    navigation: {
      style: {
        type: String,
        enum: ['sidebar', 'topbar', 'mixed'],
        default: 'sidebar'
      },
      breadcrumbs: { type: Boolean, default: true },
      quickActions: { type: Boolean, default: true }
    }
  },
  
  // Widget configurations
  widgets: [{
    id: String,
    type: String,
    title: String,
    position: {
      row: Number,
      col: Number,
      width: Number,
      height: Number
    },
    configuration: Schema.Types.Mixed,
    visible: { type: Boolean, default: true },
    refreshInterval: Number, // in seconds
    lastRefresh: Date
  }],
  
  // Default dashboard view
  defaultView: {
    type: String,
    enum: ['overview', 'security', 'operations', 'analytics', 'users', 'organizations'],
    default: 'overview'
  },
  
  // Quick filters
  quickFilters: [{
    name: String,
    filters: Schema.Types.Mixed,
    isDefault: { type: Boolean, default: false }
  }],
  
  // Auto-refresh settings
  autoRefresh: {
    enabled: { type: Boolean, default: true },
    interval: { type: Number, default: 30 }, // in seconds
    pauseOnInactive: { type: Boolean, default: true }
  },
  
  // Chart and visualization preferences
  visualizations: {
    colorScheme: {
      type: String,
      enum: ['default', 'colorblind', 'high_contrast', 'custom'],
      default: 'default'
    },
    customColors: [String],
    animations: { type: Boolean, default: true },
    defaultChartType: {
      type: String,
      enum: ['line', 'bar', 'pie', 'area', 'scatter'],
      default: 'line'
    }
  }
}, {
  _id: false
});

/**
 * Interface Preferences Schema
 * Controls general UI behavior and appearance
 */
const interfacePreferencesSchema = new Schema({
  // Language and localization
  language: {
    type: String,
    default: 'en',
    validate: {
      validator: function(v) {
        return /^[a-z]{2}(-[A-Z]{2})?$/.test(v);
      },
      message: 'Invalid language code format'
    }
  },
  
  timezone: {
    type: String,
    default: 'UTC'
  },
  
  dateFormat: {
    type: String,
    enum: ['MM/DD/YYYY', 'DD/MM/YYYY', 'YYYY-MM-DD', 'DD MMM YYYY'],
    default: 'MM/DD/YYYY'
  },
  
  timeFormat: {
    type: String,
    enum: ['12h', '24h'],
    default: '12h'
  },
  
  // Display preferences
  display: {
    pageSize: {
      type: Number,
      min: 10,
      max: 200,
      default: 25
    },
    
    tableViews: {
      dense: { type: Boolean, default: false },
      showRowNumbers: { type: Boolean, default: false },
      stickyHeaders: { type: Boolean, default: true },
      horizontalScroll: { type: Boolean, default: true }
    },
    
    formViews: {
      showHelp: { type: Boolean, default: true },
      validateOnBlur: { type: Boolean, default: true },
      confirmDangerous: { type: Boolean, default: true }
    }
  },
  
  // Accessibility preferences
  accessibility: {
    highContrast: { type: Boolean, default: false },
    reducedMotion: { type: Boolean, default: false },
    screenReader: { type: Boolean, default: false },
    fontSize: {
      type: String,
      enum: ['small', 'medium', 'large', 'extra_large'],
      default: 'medium'
    },
    keyboardNavigation: { type: Boolean, default: true }
  },
  
  // Keyboard shortcuts
  shortcuts: {
    enabled: { type: Boolean, default: true },
    customShortcuts: [{
      action: String,
      key: String,
      modifiers: [String] // 'ctrl', 'alt', 'shift', 'meta'
    }]
  },
  
  // Session preferences
  session: {
    rememberTableFilters: { type: Boolean, default: true },
    rememberSearchHistory: { type: Boolean, default: true },
    autoSaveFormData: { type: Boolean, default: true },
    sessionTimeout: { type: Number, default: 3600 }, // in seconds
    multipleTabWarning: { type: Boolean, default: true }
  }
}, {
  _id: false
});

/**
 * Security Preferences Schema
 * Controls security-related preferences and behaviors
 */
const securityPreferencesSchema = new Schema({
  // Authentication preferences
  authentication: {
    mfaPreference: {
      type: String,
      enum: ['totp', 'sms', 'email', 'webauthn'],
      default: 'totp'
    },
    
    sessionSecurity: {
      logoutOnClose: { type: Boolean, default: false },
      requireReauth: { type: Number, default: 3600 }, // seconds
      ipWhitelist: [String],
      deviceTrust: { type: Boolean, default: true }
    },
    
    passwordPolicy: {
      changeFrequency: { type: Number, default: 90 }, // days
      requireComplexity: { type: Boolean, default: true },
      preventReuse: { type: Number, default: 12 }
    }
  },
  
  // Privacy preferences
  privacy: {
    profileVisibility: {
      type: String,
      enum: ['public', 'organization', 'team', 'private'],
      default: 'organization'
    },
    
    activityTracking: {
      allowTracking: { type: Boolean, default: true },
      shareAnonymous: { type: Boolean, default: false }
    },
    
    dataRetention: {
      personalData: { type: Number, default: 365 }, // days
      sessionData: { type: Number, default: 90 }, // days
      logData: { type: Number, default: 730 } // days
    }
  },
  
  // Audit preferences
  audit: {
    detailedLogging: { type: Boolean, default: true },
    realTimeAlerts: { type: Boolean, default: true },
    sensitiveDataMasking: { type: Boolean, default: true }
  }
}, {
  _id: false
});

/**
 * Operational Preferences Schema
 * Controls operational behavior and automation
 */
const operationalPreferencesSchema = new Schema({
  // Automation preferences
  automation: {
    autoApproval: {
      enabled: { type: Boolean, default: false },
      thresholds: {
        lowRisk: { type: Boolean, default: false },
        mediumRisk: { type: Boolean, default: false },
        maxAmount: Number,
        categories: [String]
      }
    },
    
    bulkOperations: {
      batchSize: { type: Number, default: 100, min: 1, max: 1000 },
      autoConfirm: { type: Boolean, default: false },
      parallelProcessing: { type: Boolean, default: true }
    },
    
    notifications: {
      summaryReports: { type: Boolean, default: true },
      performanceAlerts: { type: Boolean, default: true },
      quotaWarnings: { type: Boolean, default: true }
    }
  },
  
  // Workflow preferences
  workflow: {
    defaultAssignee: {
      type: Schema.Types.ObjectId,
      ref: 'User'
    },
    
    escalationRules: [{
      condition: String,
      delay: Number, // minutes
      assignTo: {
        type: Schema.Types.ObjectId,
        ref: 'User'
      }
    }],
    
    approvalFlow: {
      requireComments: { type: Boolean, default: true },
      allowDelegation: { type: Boolean, default: true },
      timeoutAction: {
        type: String,
        enum: ['auto_approve', 'auto_reject', 'escalate'],
        default: 'escalate'
      }
    }
  },
  
  // Reporting preferences
  reporting: {
    defaultFormat: {
      type: String,
      enum: ['pdf', 'excel', 'csv', 'json'],
      default: 'pdf'
    },
    
    scheduledReports: [{
      reportType: String,
      frequency: String,
      recipients: [String],
      format: String,
      filters: Schema.Types.Mixed
    }],
    
    dataRetention: {
      reports: { type: Number, default: 365 }, // days
      exports: { type: Number, default: 90 } // days
    }
  }
}, {
  _id: false
});

/**
 * Admin Preference Schema
 * Main schema for administrative user preferences
 */
const adminPreferenceSchema = new Schema({
  // User association
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true,
    index: true
  },
  
  // User information for quick reference
  userInfo: {
    username: String,
    email: String,
    role: String,
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization' }
  },
  
  // Preference categories
  notifications: {
    type: notificationPreferencesSchema,
    default: () => ({})
  },
  
  dashboard: {
    type: dashboardPreferencesSchema,
    default: () => ({})
  },
  
  interface: {
    type: interfacePreferencesSchema,
    default: () => ({})
  },
  
  security: {
    type: securityPreferencesSchema,
    default: () => ({})
  },
  
  operational: {
    type: operationalPreferencesSchema,
    default: () => ({})
  },
  
  // Custom preferences for extensibility
  custom: {
    type: Schema.Types.Mixed,
    default: {}
  },
  
  // Preference profiles
  profiles: [{
    name: String,
    description: String,
    isDefault: { type: Boolean, default: false },
    preferences: Schema.Types.Mixed,
    createdAt: { type: Date, default: Date.now },
    lastUsed: Date
  }],
  
  // Synchronization settings
  synchronization: {
    enabled: { type: Boolean, default: true },
    lastSync: Date,
    syncAcrossDevices: { type: Boolean, default: true },
    conflictResolution: {
      type: String,
      enum: ['server_wins', 'client_wins', 'merge', 'manual'],
      default: 'server_wins'
    }
  },
  
  // Backup and restore
  backup: {
    autoBackup: { type: Boolean, default: true },
    backupFrequency: {
      type: String,
      enum: ['daily', 'weekly', 'monthly'],
      default: 'weekly'
    },
    retentionPeriod: { type: Number, default: 90 }, // days
    lastBackup: Date
  },
  
  // Version tracking
  version: {
    type: Number,
    default: 1
  },
  
  // Migration tracking
  migrationVersion: {
    type: String,
    default: '1.0.0'
  }
}, {
  timestamps: true,
  collection: 'admin_preferences'
});

// Indexes for performance
adminPreferenceSchema.index({ userId: 1 }, { unique: true });
adminPreferenceSchema.index({ 'userInfo.organizationId': 1 });
adminPreferenceSchema.index({ 'userInfo.role': 1 });
adminPreferenceSchema.index({ updatedAt: -1 });

// Pre-save middleware
adminPreferenceSchema.pre('save', function(next) {
  try {
    // Increment version on updates
    if (!this.isNew) {
      this.version += 1;
    }
    
    // Update sync timestamp
    if (this.synchronization.enabled) {
      this.synchronization.lastSync = new Date();
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Instance Methods
adminPreferenceSchema.methods = {
  /**
   * Apply preference profile
   * @param {string} profileName - Profile name to apply
   * @returns {Promise<boolean>} Success status
   */
  async applyProfile(profileName) {
    const profile = this.profiles.find(p => p.name === profileName);
    if (!profile) {
      throw new ValidationError(`Profile ${profileName} not found`);
    }
    
    // Merge profile preferences
    Object.assign(this, profile.preferences);
    
    // Update profile usage
    profile.lastUsed = new Date();
    
    await this.save();
    
    logger.info('Preference profile applied', {
      userId: this.userId,
      profile: profileName
    });
    
    return true;
  },
  
  /**
   * Create preference profile from current settings
   * @param {string} name - Profile name
   * @param {string} description - Profile description
   * @returns {Promise<Object>} Created profile
   */
  async createProfile(name, description) {
    // Check if profile already exists
    if (this.profiles.some(p => p.name === name)) {
      throw new ValidationError(`Profile ${name} already exists`);
    }
    
    const currentPreferences = {
      notifications: this.notifications.toObject(),
      dashboard: this.dashboard.toObject(),
      interface: this.interface.toObject(),
      security: this.security.toObject(),
      operational: this.operational.toObject()
    };
    
    const profile = {
      name,
      description,
      preferences: currentPreferences,
      createdAt: new Date()
    };
    
    this.profiles.push(profile);
    await this.save();
    
    logger.info('Preference profile created', {
      userId: this.userId,
      profile: name
    });
    
    return profile;
  },
  
  /**
   * Reset preferences to defaults
   * @param {Array} categories - Categories to reset (optional)
   * @returns {Promise<boolean>} Success status
   */
  async resetToDefaults(categories = null) {
    const categoriesToReset = categories || ['notifications', 'dashboard', 'interface', 'security', 'operational'];
    
    for (const category of categoriesToReset) {
      if (this[category]) {
        // Reset to schema defaults
        this[category] = new adminPreferenceSchema.paths[category].schema();
      }
    }
    
    await this.save();
    
    logger.info('Preferences reset to defaults', {
      userId: this.userId,
      categories: categoriesToReset
    });
    
    return true;
  },
  
  /**
   * Export preferences for backup or migration
   * @param {Object} options - Export options
   * @returns {Object} Exported preferences
   */
  exportPreferences(options = {}) {
    const { includeProfiles = true, includeCustom = true } = options;
    
    const exported = {
      version: this.version,
      migrationVersion: this.migrationVersion,
      exportedAt: new Date(),
      preferences: {
        notifications: this.notifications.toObject(),
        dashboard: this.dashboard.toObject(),
        interface: this.interface.toObject(),
        security: this.security.toObject(),
        operational: this.operational.toObject()
      }
    };
    
    if (includeProfiles) {
      exported.profiles = this.profiles.map(p => p.toObject());
    }
    
    if (includeCustom) {
      exported.custom = this.custom;
    }
    
    return exported;
  },
  
  /**
   * Import preferences from backup or migration
   * @param {Object} importData - Imported preference data
   * @param {Object} options - Import options
   * @returns {Promise<boolean>} Success status
   */
  async importPreferences(importData, options = {}) {
    const { 
      overwriteExisting = false, 
      mergeProfiles = true,
      validateVersion = true 
    } = options;
    
    if (validateVersion && importData.migrationVersion !== this.migrationVersion) {
      logger.warn('Migration version mismatch during import', {
        current: this.migrationVersion,
        imported: importData.migrationVersion
      });
    }
    
    // Import core preferences
    if (importData.preferences) {
      for (const [category, prefs] of Object.entries(importData.preferences)) {
        if (this[category] && (overwriteExisting || !this[category])) {
          Object.assign(this[category], prefs);
        }
      }
    }
    
    // Import profiles
    if (importData.profiles && mergeProfiles) {
      for (const importedProfile of importData.profiles) {
        const existingIndex = this.profiles.findIndex(p => p.name === importedProfile.name);
        if (existingIndex >= 0) {
          if (overwriteExisting) {
            this.profiles[existingIndex] = importedProfile;
          }
        } else {
          this.profiles.push(importedProfile);
        }
      }
    }
    
    // Import custom preferences
    if (importData.custom) {
      if (overwriteExisting) {
        this.custom = importData.custom;
      } else {
        Object.assign(this.custom, importData.custom);
      }
    }
    
    await this.save();
    
    logger.info('Preferences imported successfully', {
      userId: this.userId,
      importedAt: new Date()
    });
    
    return true;
  },
  
  /**
   * Get notification settings for specific category
   * @param {string} category - Notification category
   * @returns {Object} Category notification settings
   */
  getNotificationSettings(category) {
    const categorySettings = this.notifications.categories[category];
    const globalSettings = this.notifications;
    
    if (!categorySettings) {
      return null;
    }
    
    return {
      enabled: globalSettings.enabled,
      priority: categorySettings.priority,
      channels: categorySettings.channels.length ? 
        categorySettings.channels : 
        Object.keys(globalSettings.channels).filter(c => globalSettings.channels[c].enabled),
      immediate: categorySettings.immediate,
      quietHours: globalSettings.quietHours,
      doNotDisturb: globalSettings.doNotDisturb
    };
  }
};

// Static Methods
adminPreferenceSchema.statics = {
  /**
   * Get or create preferences for user
   * @param {string} userId - User ID
   * @param {Object} userInfo - User information
   * @returns {Promise<Object>} User preferences
   */
  async getOrCreateForUser(userId, userInfo = {}) {
    let preferences = await this.findOne({ userId });
    
    if (!preferences) {
      preferences = new this({
        userId,
        userInfo: {
          username: userInfo.username,
          email: userInfo.email,
          role: userInfo.role,
          organizationId: userInfo.organizationId
        }
      });
      
      await preferences.save();
      
      logger.info('Admin preferences created for user', {
        userId,
        username: userInfo.username
      });
    }
    
    return preferences;
  },
  
  /**
   * Bulk update preferences for organization
   * @param {string} organizationId - Organization ID
   * @param {Object} updates - Preference updates
   * @returns {Promise<Object>} Update results
   */
  async bulkUpdateForOrganization(organizationId, updates) {
    const result = await this.updateMany(
      { 'userInfo.organizationId': organizationId },
      { $set: updates },
      { new: true }
    );
    
    logger.info('Bulk preference update completed', {
      organizationId,
      modifiedCount: result.modifiedCount
    });
    
    return result;
  },
  
  /**
   * Get default preferences for role
   * @param {string} role - Admin role
   * @returns {Object} Default preferences
   */
  getDefaultsForRole(role) {
    const roleDefaults = {
      super_admin: {
        'notifications.categories.security.priority': 'all',
        'notifications.categories.security.immediate': true,
        'security.audit.detailedLogging': true,
        'operational.automation.autoApproval.enabled': false
      },
      
      platform_admin: {
        'notifications.categories.operations.priority': 'high_critical',
        'dashboard.defaultView': 'overview',
        'operational.bulkOperations.batchSize': 200
      },
      
      organization_admin: {
        'notifications.categories.business.priority': 'all',
        'dashboard.defaultView': 'organizations',
        'interface.display.pageSize': 50
      },
      
      security_admin: {
        'notifications.categories.security.priority': 'all',
        'notifications.categories.security.immediate': true,
        'security.audit.realTimeAlerts': true,
        'dashboard.defaultView': 'security'
      }
    };
    
    return roleDefaults[role] || {};
  },
  
  /**
   * Migrate preferences to new version
   * @param {string} fromVersion - Source version
   * @param {string} toVersion - Target version
   * @returns {Promise<Object>} Migration results
   */
  async migratePreferences(fromVersion, toVersion) {
    const migrationCount = await this.countDocuments({
      migrationVersion: fromVersion
    });
    
    if (migrationCount === 0) {
      return { migrated: 0, message: 'No preferences require migration' };
    }
    
    // Apply version-specific migrations
    const migrationRules = this.getMigrationRules(fromVersion, toVersion);
    
    let migratedCount = 0;
    const cursor = this.find({ migrationVersion: fromVersion }).cursor();
    
    for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
      try {
        this.applyMigrationRules(doc, migrationRules);
        doc.migrationVersion = toVersion;
        await doc.save();
        migratedCount++;
      } catch (error) {
        logger.error('Failed to migrate preferences', {
          userId: doc.userId,
          error: error.message
        });
      }
    }
    
    logger.info('Preference migration completed', {
      fromVersion,
      toVersion,
      migratedCount
    });
    
    return { migrated: migratedCount, total: migrationCount };
  },
  
  /**
   * Get migration rules for version transition
   * @param {string} fromVersion - Source version
   * @param {string} toVersion - Target version
   * @returns {Array} Migration rules
   */
  getMigrationRules(fromVersion, toVersion) {
    // Define migration rules between versions
    const migrations = {
      '1.0.0_to_1.1.0': [
        {
          type: 'rename_field',
          from: 'notifications.digest',
          to: 'notifications.channels.email.digest'
        },
        {
          type: 'add_default',
          field: 'security.privacy.dataRetention',
          value: { personalData: 365, sessionData: 90, logData: 730 }
        }
      ]
    };
    
    const migrationKey = `${fromVersion}_to_${toVersion}`;
    return migrations[migrationKey] || [];
  },
  
  /**
   * Apply migration rules to document
   * @param {Object} doc - Document to migrate
   * @param {Array} rules - Migration rules
   */
  applyMigrationRules(doc, rules) {
    for (const rule of rules) {
      switch (rule.type) {
        case 'rename_field':
          const value = this.getNestedValue(doc, rule.from);
          if (value !== undefined) {
            this.setNestedValue(doc, rule.to, value);
            this.deleteNestedValue(doc, rule.from);
          }
          break;
          
        case 'add_default':
          if (this.getNestedValue(doc, rule.field) === undefined) {
            this.setNestedValue(doc, rule.field, rule.value);
          }
          break;
          
        case 'transform_value':
          const currentValue = this.getNestedValue(doc, rule.field);
          if (currentValue !== undefined) {
            const transformed = rule.transform(currentValue);
            this.setNestedValue(doc, rule.field, transformed);
          }
          break;
      }
    }
  },
  
  /**
   * Helper to get nested object value
   * @param {Object} obj - Object to search
   * @param {string} path - Dot notation path
   * @returns {*} Value at path
   */
  getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => 
      current && current[key] !== undefined ? current[key] : undefined, obj
    );
  },
  
  /**
   * Helper to set nested object value
   * @param {Object} obj - Object to modify
   * @param {string} path - Dot notation path
   * @param {*} value - Value to set
   */
  setNestedValue(obj, path, value) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((current, key) => {
      if (!current[key]) current[key] = {};
      return current[key];
    }, obj);
    target[lastKey] = value;
  },
  
  /**
   * Helper to delete nested object value
   * @param {Object} obj - Object to modify
   * @param {string} path - Dot notation path
   */
  deleteNestedValue(obj, path) {
    const keys = path.split('.');
    const lastKey = keys.pop();
    const target = keys.reduce((current, key) => 
      current && current[key] ? current[key] : {}, obj
    );
    if (target && target[lastKey] !== undefined) {
      delete target[lastKey];
    }
  }
};

// Create the model
const AdminPreference = mongoose.model('AdminPreference', adminPreferenceSchema);

module.exports = AdminPreference;