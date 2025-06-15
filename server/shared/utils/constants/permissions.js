// /server/shared/utils/constants/permissions.js

/**
 * @file Permission Mappings
 * @description Comprehensive permission definitions and mappings
 * @version 1.0.0
 */

/**
 * Permission structure:
 * - Follows pattern: resource.action.scope
 * - Resources: platform, org, core, recruitment, etc.
 * - Actions: create, read, update, delete, manage, etc.
 * - Scope: own, team, all, etc.
 */

module.exports = {
  /**
   * Platform permissions
   */
  PLATFORM: {
    // System management
    MANAGE: 'platform.manage',
    SETTINGS: 'platform.settings',
    MAINTENANCE: 'platform.maintenance.manage',
    
    // User management
    USERS_VIEW: 'platform.users.view',
    USERS_CREATE: 'platform.users.create',
    USERS_UPDATE: 'platform.users.update',
    USERS_DELETE: 'platform.users.delete',
    USERS_MANAGE: 'platform.users.manage',
    USERS_IMPERSONATE: 'platform.impersonate.users',
    USERS_ASSIST: 'platform.users.assist',
    
    // Organization management
    ORGS_VIEW: 'platform.organizations.view',
    ORGS_CREATE: 'platform.organizations.create',
    ORGS_UPDATE: 'platform.organizations.update',
    ORGS_DELETE: 'platform.organizations.delete',
    ORGS_MANAGE: 'platform.organizations.manage',
    ORGS_MODERATE: 'platform.organizations.moderate',
    
    // Billing management
    BILLING_VIEW: 'platform.billing.view',
    BILLING_MANAGE: 'platform.billing.manage',
    BILLING_REFUND: 'platform.billing.refund',
    
    // Security management
    SECURITY_VIEW: 'platform.security.view',
    SECURITY_MANAGE: 'platform.security.manage',
    SECURITY_AUDIT: 'platform.security.audit',
    
    // Integration management
    INTEGRATIONS_VIEW: 'platform.integrations.view',
    INTEGRATIONS_MANAGE: 'platform.integrations.manage',
    
    // Analytics
    ANALYTICS_VIEW: 'platform.analytics.view',
    ANALYTICS_FULL: 'platform.analytics.full',
    REPORTS_GENERATE: 'platform.reports.generate',
    
    // Content management
    CONTENT_CREATE: 'platform.content.create',
    CONTENT_EDIT: 'platform.content.edit',
    CONTENT_DELETE: 'platform.content.delete',
    CONTENT_PUBLISH: 'platform.content.publish',
    CONTENT_MANAGE: 'platform.content.manage',
    
    // Support
    SUPPORT_VIEW: 'platform.support.tickets.view',
    SUPPORT_MANAGE: 'platform.support.tickets.manage',
    SUPPORT_ADMIN: 'platform.support.manage',
    
    // API access
    API_ACCESS: 'platform.api.access',
    API_KEYS_MANAGE: 'platform.api.keys.manage',
    WEBHOOKS_MANAGE: 'platform.webhooks.manage',
    
    // Developer tools
    LOGS_VIEW: 'platform.logs.view',
    LOGS_TECHNICAL: 'platform.logs.technical',
    SANDBOX_ACCESS: 'platform.sandbox.access',
    
    // Communication
    ANNOUNCEMENTS_CREATE: 'platform.announcements.create',
    NOTIFICATIONS_SEND: 'platform.notifications.send',
    
    // Media
    MEDIA_UPLOAD: 'platform.media.upload',
    MEDIA_MANAGE: 'platform.media.manage',
    
    // Blog
    BLOG_CREATE: 'platform.blog.create',
    BLOG_EDIT: 'platform.blog.edit',
    BLOG_PUBLISH: 'platform.blog.publish',
    BLOG_MANAGE: 'platform.blog.manage',
    
    // Pages
    PAGES_CREATE: 'platform.pages.create',
    PAGES_EDIT: 'platform.pages.edit',
    PAGES_PUBLISH: 'platform.pages.publish',
    PAGES_MANAGE: 'platform.pages.manage'
  },
  
  /**
   * Core business permissions
   */
  CORE: {
    // Executive
    EXECUTIVE_FULL: 'core.executive.full',
    STRATEGY_VIEW: 'core.strategy.view',
    STRATEGY_MANAGE: 'core.strategy.manage',
    
    // Financial
    FINANCES_VIEW: 'core.finances.view',
    FINANCES_MANAGE: 'core.finances.manage',
    FINANCES_FULL: 'core.finances.full',
    BUDGETS_VIEW: 'core.budgets.view',
    BUDGETS_TEAM: 'core.budgets.team',
    BUDGETS_DEPARTMENT: 'core.budgets.department',
    BUDGETS_APPROVE: 'core.budgets.approve',
    INVESTMENTS_MANAGE: 'core.investments.manage',
    
    // HR
    HR_VIEW: 'core.hr.view',
    HR_MANAGE: 'core.hr.manage',
    HR_FULL: 'core.hr.full',
    HIRING_REQUEST: 'core.hiring.request',
    HIRING_APPROVE: 'core.hiring.approve',
    PERFORMANCE_REVIEW: 'core.performance.review',
    
    // Technology
    TECHNOLOGY_VIEW: 'core.technology.view',
    TECHNOLOGY_MANAGE: 'core.technology.manage',
    INFRASTRUCTURE_VIEW: 'core.infrastructure.view',
    INFRASTRUCTURE_MANAGE: 'core.infrastructure.manage',
    
    // Departments
    DEPARTMENTS_VIEW: 'core.departments.view',
    DEPARTMENTS_MANAGE: 'core.departments.manage',
    
    // Teams
    TEAMS_VIEW: 'core.teams.view',
    TEAMS_MANAGE: 'core.teams.manage',
    TEAMS_LEAD: 'core.teams.lead',
    TEAMS_TECHNICAL: 'core.teams.technical',
    
    // Projects
    PROJECTS_VIEW: 'core.projects.view',
    PROJECTS_CREATE: 'core.projects.create',
    PROJECTS_CONTRIBUTE: 'core.projects.contribute',
    PROJECTS_COORDINATE: 'core.projects.coordinate',
    PROJECTS_MANAGE: 'core.projects.manage',
    PROJECTS_LEAD: 'core.projects.lead',
    PROJECTS_TECHNICAL: 'core.projects.technical',
    
    // Clients
    CLIENTS_VIEW: 'core.clients.view',
    CLIENTS_SERVE: 'core.clients.serve',
    CLIENTS_MANAGE: 'core.clients.manage',
    CLIENTS_PRIMARY: 'core.clients.primary',
    CLIENTS_SENIOR: 'core.clients.senior',
    CLIENTS_VIP: 'core.clients.vip',
    
    // Contracts
    CONTRACTS_VIEW: 'core.contracts.view',
    CONTRACTS_CREATE: 'core.contracts.create',
    CONTRACTS_NEGOTIATE: 'core.contracts.negotiate',
    CONTRACTS_APPROVE: 'core.contracts.approve',
    
    // Business development
    BUSINESS_DEVELOP: 'core.business.develop',
    PROPOSALS_CREATE: 'core.proposals.create',
    PROPOSALS_LEAD: 'core.proposals.lead',
    
    // Consulting
    CONSULTING_ASSIST: 'core.consulting.assist',
    CONSULTING_DELIVER: 'core.consulting.deliver',
    CONSULTING_SENIOR: 'core.consulting.senior',
    CONSULTING_LEAD: 'core.consulting.lead',
    
    // Delivery
    DELIVERY_ASSIST: 'core.delivery.assist',
    DELIVERY_MANAGE: 'core.delivery.manage',
    DELIVERY_OVERSEE: 'core.delivery.oversee',
    
    // Quality
    QUALITY_CHECK: 'core.quality.check',
    QUALITY_ASSURE: 'core.quality.assure',
    
    // Mentoring
    MENTORING_RECEIVE: 'core.mentoring.receive',
    MENTORING_PROVIDE: 'core.mentoring.provide',
    
    // Analysis
    ANALYSIS_VIEW: 'core.analysis.view',
    ANALYSIS_PERFORM: 'core.analysis.perform',
    DATA_COLLECT: 'core.data.collect',
    
    // Research
    RESEARCH_SUPPORT: 'core.research.support',
    RESEARCH_CONDUCT: 'core.research.conduct',
    
    // Reports
    REPORTS_VIEW: 'core.reports.view',
    REPORTS_ASSIST: 'core.reports.assist',
    REPORTS_CREATE: 'core.reports.create',
    REPORTS_STRATEGIC: 'core.reports.strategic',
    
    // Documentation
    DOCUMENTATION_VIEW: 'core.documentation.view',
    DOCUMENTATION_CREATE: 'core.documentation.create',
    
    // Tasks
    TASKS_VIEW: 'core.tasks.view',
    TASKS_EXECUTE: 'core.tasks.execute',
    TASKS_ASSIGN: 'core.tasks.assign'
  },
  
  /**
   * Organization permissions
   */
  ORGANIZATION: {
    // Basic access
    VIEW: 'org.view',
    LIMITED_VIEW: 'org.limited.view',
    PUBLIC_CONTENT: 'org.public.content',
    
    // Settings
    SETTINGS_VIEW: 'org.settings.view',
    SETTINGS_EDIT: 'org.settings.edit',
    SETTINGS_MANAGE: 'org.settings.manage',
    
    // Billing
    BILLING_VIEW: 'org.billing.view',
    BILLING_MANAGE: 'org.billing.manage',
    
    // Subscription
    SUBSCRIPTION_VIEW: 'org.subscription.view',
    SUBSCRIPTION_MANAGE: 'org.subscription.manage',
    
    // Users
    USERS_VIEW: 'org.users.view',
    USERS_INVITE: 'org.users.invite',
    USERS_MANAGE: 'org.users.manage',
    
    // Roles
    ROLES_VIEW: 'org.roles.view',
    ROLES_ASSIGN: 'org.roles.assign',
    
    // Projects
    PROJECTS_VIEW: 'org.projects.view',
    PROJECTS_CREATE: 'org.projects.create',
    PROJECTS_CONTRIBUTE: 'org.projects.contribute',
    PROJECTS_MANAGE: 'org.projects.manage',
    
    // Teams
    TEAMS_VIEW: 'org.teams.view',
    TEAMS_CREATE: 'org.teams.create',
    TEAMS_MANAGE: 'org.teams.manage',
    
    // Tasks
    TASKS_VIEW: 'org.tasks.view',
    TASKS_CREATE: 'org.tasks.create',
    TASKS_MANAGE: 'org.tasks.manage',
    
    // Comments
    COMMENTS_VIEW: 'org.comments.view',
    COMMENTS_CREATE: 'org.comments.create',
    
    // Files
    FILES_VIEW: 'org.files.view',
    FILES_DOWNLOAD: 'org.files.download',
    FILES_UPLOAD: 'org.files.upload',
    FILES_DELETE: 'org.files.delete',
    
    // Reports
    REPORTS_VIEW: 'org.reports.view',
    REPORTS_GENERATE: 'org.reports.generate',
    
    // Resources
    RESOURCES_VIEW: 'org.resources.view',
    RESOURCES_ALLOCATE: 'org.resources.allocate',
    
    // Integrations
    INTEGRATIONS_VIEW: 'org.integrations.view',
    INTEGRATIONS_MANAGE: 'org.integrations.manage',
    
    // Security
    SECURITY_VIEW: 'org.security.view',
    SECURITY_MANAGE: 'org.security.manage',
    
    // Organization lifecycle
    DELETE: 'org.delete',
    TRANSFER_OWNERSHIP: 'org.transfer.ownership'
  },
  
  /**
   * Recruitment permissions
   */
  RECRUITMENT: {
    // Platform management
    PLATFORM_VIEW: 'recruitment.platform.view',
    PLATFORM_MANAGE: 'recruitment.platform.manage',
    
    // Partners
    PARTNERS_VIEW: 'recruitment.partners.view',
    PARTNERS_MANAGE: 'recruitment.partners.manage',
    
    // Settings
    SETTINGS_VIEW: 'recruitment.settings.view',
    SETTINGS_CONFIGURE: 'recruitment.settings.configure',
    
    // Agency
    AGENCY_VIEW: 'recruitment.agency.view',
    AGENCY_MANAGE: 'recruitment.agency.manage',
    
    // Clients
    CLIENTS_VIEW: 'recruitment.clients.view',
    CLIENTS_MANAGE: 'recruitment.clients.manage',
    
    // Team
    TEAM_VIEW: 'recruitment.team.view',
    TEAM_MANAGE: 'recruitment.team.manage',
    
    // Jobs
    JOBS_VIEW: 'recruitment.jobs.view',
    JOBS_SEARCH: 'recruitment.jobs.search',
    JOBS_CREATE: 'recruitment.jobs.create',
    JOBS_POST: 'recruitment.jobs.post',
    JOBS_EDIT: 'recruitment.jobs.edit',
    JOBS_DELETE: 'recruitment.jobs.delete',
    JOBS_APPLY: 'recruitment.jobs.apply',
    
    // Candidates
    CANDIDATES_VIEW: 'recruitment.candidates.view',
    CANDIDATES_SOURCE: 'recruitment.candidates.source',
    CANDIDATES_EVALUATE: 'recruitment.candidates.evaluate',
    
    // Applications
    APPLICATIONS_VIEW: 'recruitment.applications.view',
    APPLICATIONS_TRACK: 'recruitment.applications.track',
    APPLICATIONS_SCREEN: 'recruitment.applications.screen',
    APPLICATIONS_REVIEW: 'recruitment.applications.review',
    
    // Interviews
    INTERVIEWS_VIEW: 'recruitment.interviews.view',
    INTERVIEWS_SCHEDULE: 'recruitment.interviews.schedule',
    INTERVIEWS_CONDUCT: 'recruitment.interviews.conduct',
    INTERVIEWS_ATTEND: 'recruitment.interviews.attend',
    
    // Feedback
    FEEDBACK_VIEW: 'recruitment.feedback.view',
    FEEDBACK_PROVIDE: 'recruitment.feedback.provide',
    
    // Decisions
    DECISIONS_VIEW: 'recruitment.decisions.view',
    DECISIONS_MAKE: 'recruitment.decisions.make',
    
    // Offers
    OFFERS_VIEW: 'recruitment.offers.view',
    OFFERS_COORDINATE: 'recruitment.offers.coordinate',
    OFFERS_APPROVE: 'recruitment.offers.approve',
    
    // Commissions
    COMMISSIONS_VIEW: 'recruitment.commissions.view',
    COMMISSIONS_MANAGE: 'recruitment.commissions.manage',
    
    // Analytics
    ANALYTICS_VIEW: 'recruitment.analytics.view',
    ANALYTICS_FULL: 'recruitment.analytics.full',
    
    // Profile (candidate)
    PROFILE_VIEW: 'recruitment.profile.view',
    PROFILE_MANAGE: 'recruitment.profile.manage'
  },
  
  /**
   * Helper functions
   */
  
  /**
   * Check if a permission exists
   * @param {string} permission - Permission string
   * @returns {boolean} Permission exists
   */
  exists(permission) {
    for (const category of Object.values(this)) {
      if (typeof category === 'object' && !Array.isArray(category)) {
        if (Object.values(category).includes(permission)) {
          return true;
        }
      }
    }
    return false;
  },
  
  /**
   * Get permission category
   * @param {string} permission - Permission string
   * @returns {string|null} Category name
   */
  getCategory(permission) {
    for (const [categoryName, category] of Object.entries(this)) {
      if (typeof category === 'object' && !Array.isArray(category)) {
        if (Object.values(category).includes(permission)) {
          return categoryName;
        }
      }
    }
    return null;
  },
  
  /**
   * Get all permissions in a category
   * @param {string} categoryName - Category name
   * @returns {Array} Array of permissions
   */
  getByCategory(categoryName) {
    const category = this[categoryName.toUpperCase()];
    if (!category || typeof category !== 'object') return [];
    
    return Object.values(category).filter(value => 
      typeof value === 'string' && value.includes('.')
    );
  },
  
  /**
   * Parse permission string
   * @param {string} permission - Permission string
   * @returns {Object} Parsed permission
   */
  parse(permission) {
    const parts = permission.split('.');
    return {
      resource: parts[0] || null,
      action: parts[1] || null,
      scope: parts[2] || null,
      full: permission
    };
  },
  
  /**
   * Check if permission allows action
   * @param {string} permission - Permission to check
   * @param {string} action - Action to verify
   * @returns {boolean} Permission allows action
   */
  allowsAction(permission, action) {
    const parsed = this.parse(permission);
    return parsed.action === action || parsed.action === 'manage';
  },
  
  /**
   * Check if permission is a wildcard
   * @param {string} permission - Permission to check
   * @returns {boolean} Is wildcard permission
   */
  isWildcard(permission) {
    return permission.includes('*') || permission.endsWith('.manage');
  },
  
  /**
   * Get all permissions matching pattern
   * @param {string} pattern - Permission pattern
   * @returns {Array} Matching permissions
   */
  getMatching(pattern) {
    const results = [];
    const regex = new RegExp(pattern.replace('*', '.*'));
    
    for (const category of Object.values(this)) {
      if (typeof category === 'object' && !Array.isArray(category)) {
        for (const permission of Object.values(category)) {
          if (typeof permission === 'string' && regex.test(permission)) {
            results.push(permission);
          }
        }
      }
    }
    
    return results;
  }
};