// /server/shared/utils/constants/roles.js

/**
 * @file Role Definitions
 * @description Comprehensive role definitions for the platform
 * @version 1.0.0
 */

/**
 * Role hierarchy and definitions
 */
module.exports = {
  /**
   * Platform-level roles (highest level)
   */
  PLATFORM: {
    SUPER_ADMIN: {
      name: 'super_admin',
      displayName: 'Super Administrator',
      description: 'Full platform access and control',
      level: 1000,
      category: 'platform',
      inherits: ['platform_admin'],
      capabilities: [
        'platform.manage',
        'platform.settings',
        'platform.users.manage',
        'platform.organizations.manage',
        'platform.billing.manage',
        'platform.security.manage',
        'platform.integrations.manage',
        'platform.analytics.full',
        'platform.support.manage',
        'platform.maintenance.manage'
      ]
    },
    
    PLATFORM_ADMIN: {
      name: 'platform_admin',
      displayName: 'Platform Administrator',
      description: 'Platform administration without critical settings',
      level: 900,
      category: 'platform',
      inherits: ['support_agent'],
      capabilities: [
        'platform.users.manage',
        'platform.organizations.view',
        'platform.organizations.moderate',
        'platform.analytics.view',
        'platform.reports.generate',
        'platform.content.manage',
        'platform.announcements.create'
      ]
    },
    
    SUPPORT_AGENT: {
      name: 'support_agent',
      displayName: 'Support Agent',
      description: 'Customer support and assistance',
      level: 800,
      category: 'platform',
      inherits: ['content_manager'],
      capabilities: [
        'platform.support.tickets.manage',
        'platform.users.view',
        'platform.users.assist',
        'platform.organizations.view',
        'platform.logs.view',
        'platform.impersonate.users'
      ]
    },
    
    CONTENT_MANAGER: {
      name: 'content_manager',
      displayName: 'Content Manager',
      description: 'Platform content and marketing management',
      level: 700,
      category: 'platform',
      inherits: [],
      capabilities: [
        'platform.content.create',
        'platform.content.edit',
        'platform.content.publish',
        'platform.blog.manage',
        'platform.pages.manage',
        'platform.media.manage'
      ]
    },
    
    DEVELOPER: {
      name: 'developer',
      displayName: 'Developer',
      description: 'API access and development tools',
      level: 600,
      category: 'platform',
      inherits: [],
      capabilities: [
        'platform.api.access',
        'platform.api.keys.manage',
        'platform.webhooks.manage',
        'platform.logs.technical',
        'platform.sandbox.access'
      ]
    }
  },
  
  /**
   * Core business roles (Insightserenity consultancy)
   */
  CORE_BUSINESS: {
    CEO: {
      name: 'ceo',
      displayName: 'Chief Executive Officer',
      description: 'Executive leadership',
      level: 500,
      category: 'core_business',
      inherits: ['cto', 'cfo'],
      capabilities: [
        'core.executive.full',
        'core.strategy.manage',
        'core.finances.full',
        'core.hr.full',
        'core.clients.vip'
      ]
    },
    
    CTO: {
      name: 'cto',
      displayName: 'Chief Technology Officer',
      description: 'Technology leadership',
      level: 490,
      category: 'core_business',
      inherits: ['director'],
      capabilities: [
        'core.technology.manage',
        'core.projects.technical',
        'core.teams.technical',
        'core.infrastructure.manage'
      ]
    },
    
    CFO: {
      name: 'cfo',
      displayName: 'Chief Financial Officer',
      description: 'Financial leadership',
      level: 490,
      category: 'core_business',
      inherits: ['director'],
      capabilities: [
        'core.finances.manage',
        'core.budgets.approve',
        'core.contracts.approve',
        'core.investments.manage'
      ]
    },
    
    DIRECTOR: {
      name: 'director',
      displayName: 'Director',
      description: 'Department leadership',
      level: 480,
      category: 'core_business',
      inherits: ['partner'],
      capabilities: [
        'core.departments.manage',
        'core.strategy.contribute',
        'core.budgets.department',
        'core.hiring.approve'
      ]
    },
    
    PARTNER: {
      name: 'partner',
      displayName: 'Partner',
      description: 'Senior business partner',
      level: 470,
      category: 'core_business',
      inherits: ['senior_manager'],
      capabilities: [
        'core.clients.manage',
        'core.projects.lead',
        'core.contracts.negotiate',
        'core.business.develop'
      ]
    },
    
    SENIOR_MANAGER: {
      name: 'senior_manager',
      displayName: 'Senior Manager',
      description: 'Senior management',
      level: 460,
      category: 'core_business',
      inherits: ['manager'],
      capabilities: [
        'core.teams.lead',
        'core.projects.manage',
        'core.clients.senior',
        'core.reports.strategic'
      ]
    },
    
    MANAGER: {
      name: 'manager',
      displayName: 'Manager',
      description: 'Team management',
      level: 450,
      category: 'core_business',
      inherits: ['principal_consultant'],
      capabilities: [
        'core.teams.manage',
        'core.projects.coordinate',
        'core.performance.review',
        'core.budgets.team'
      ]
    },
    
    PRINCIPAL_CONSULTANT: {
      name: 'principal_consultant',
      displayName: 'Principal Consultant',
      description: 'Lead consulting role',
      level: 440,
      category: 'core_business',
      inherits: ['senior_consultant'],
      capabilities: [
        'core.consulting.lead',
        'core.clients.primary',
        'core.proposals.lead',
        'core.delivery.oversee'
      ]
    },
    
    SENIOR_CONSULTANT: {
      name: 'senior_consultant',
      displayName: 'Senior Consultant',
      description: 'Senior consulting role',
      level: 430,
      category: 'core_business',
      inherits: ['consultant'],
      capabilities: [
        'core.consulting.senior',
        'core.clients.manage',
        'core.mentoring.provide',
        'core.quality.assure'
      ]
    },
    
    CONSULTANT: {
      name: 'consultant',
      displayName: 'Consultant',
      description: 'Standard consulting role',
      level: 420,
      category: 'core_business',
      inherits: ['junior_consultant'],
      capabilities: [
        'core.consulting.deliver',
        'core.clients.serve',
        'core.projects.contribute',
        'core.reports.create'
      ]
    },
    
    JUNIOR_CONSULTANT: {
      name: 'junior_consultant',
      displayName: 'Junior Consultant',
      description: 'Entry-level consulting role',
      level: 410,
      category: 'core_business',
      inherits: ['analyst'],
      capabilities: [
        'core.consulting.assist',
        'core.research.conduct',
        'core.documentation.create',
        'core.tasks.execute'
      ]
    },
    
    ANALYST: {
      name: 'analyst',
      displayName: 'Analyst',
      description: 'Analysis and research role',
      level: 400,
      category: 'core_business',
      inherits: [],
      capabilities: [
        'core.analysis.perform',
        'core.data.collect',
        'core.reports.assist',
        'core.research.support'
      ]
    }
  },
  
  /**
   * Organization roles (hosted businesses)
   */
  ORGANIZATION: {
    OWNER: {
      name: 'org_owner',
      displayName: 'Organization Owner',
      description: 'Full organization control',
      level: 300,
      category: 'organization',
      inherits: ['org_admin'],
      capabilities: [
        'org.settings.manage',
        'org.billing.manage',
        'org.subscription.manage',
        'org.delete',
        'org.transfer.ownership'
      ]
    },
    
    ADMIN: {
      name: 'org_admin',
      displayName: 'Organization Admin',
      description: 'Organization administration',
      level: 290,
      category: 'organization',
      inherits: ['org_manager'],
      capabilities: [
        'org.users.manage',
        'org.roles.assign',
        'org.settings.edit',
        'org.integrations.manage',
        'org.security.manage'
      ]
    },
    
    MANAGER: {
      name: 'org_manager',
      displayName: 'Organization Manager',
      description: 'Operational management',
      level: 280,
      category: 'organization',
      inherits: ['org_member'],
      capabilities: [
        'org.projects.manage',
        'org.teams.manage',
        'org.reports.generate',
        'org.resources.allocate'
      ]
    },
    
    MEMBER: {
      name: 'org_member',
      displayName: 'Organization Member',
      description: 'Standard member access',
      level: 270,
      category: 'organization',
      inherits: ['org_viewer'],
      capabilities: [
        'org.projects.contribute',
        'org.tasks.manage',
        'org.comments.create',
        'org.files.upload'
      ]
    },
    
    VIEWER: {
      name: 'org_viewer',
      displayName: 'Organization Viewer',
      description: 'Read-only access',
      level: 260,
      category: 'organization',
      inherits: [],
      capabilities: [
        'org.view',
        'org.projects.view',
        'org.reports.view',
        'org.files.download'
      ]
    },
    
    GUEST: {
      name: 'org_guest',
      displayName: 'Organization Guest',
      description: 'Limited guest access',
      level: 250,
      category: 'organization',
      inherits: [],
      capabilities: [
        'org.limited.view',
        'org.public.content'
      ]
    }
  },
  
  /**
   * Recruitment platform roles
   */
  RECRUITMENT: {
    ADMIN: {
      name: 'recruitment_admin',
      displayName: 'Recruitment Admin',
      description: 'Recruitment platform administration',
      level: 200,
      category: 'recruitment',
      inherits: ['recruitment_partner'],
      capabilities: [
        'recruitment.platform.manage',
        'recruitment.partners.manage',
        'recruitment.settings.configure',
        'recruitment.analytics.full'
      ]
    },
    
    PARTNER: {
      name: 'recruitment_partner',
      displayName: 'Recruitment Partner',
      description: 'Recruitment agency partner',
      level: 190,
      category: 'recruitment',
      inherits: ['recruiter'],
      capabilities: [
        'recruitment.agency.manage',
        'recruitment.clients.manage',
        'recruitment.commissions.view',
        'recruitment.team.manage'
      ]
    },
    
    RECRUITER: {
      name: 'recruiter',
      displayName: 'Recruiter',
      description: 'Professional recruiter',
      level: 180,
      category: 'recruitment',
      inherits: ['hiring_manager'],
      capabilities: [
        'recruitment.candidates.source',
        'recruitment.jobs.post',
        'recruitment.applications.screen',
        'recruitment.interviews.schedule',
        'recruitment.offers.coordinate'
      ]
    },
    
    HIRING_MANAGER: {
      name: 'hiring_manager',
      displayName: 'Hiring Manager',
      description: 'Company hiring manager',
      level: 170,
      category: 'recruitment',
      inherits: ['interviewer'],
      capabilities: [
        'recruitment.jobs.create',
        'recruitment.applications.review',
        'recruitment.decisions.make',
        'recruitment.offers.approve'
      ]
    },
    
    INTERVIEWER: {
      name: 'interviewer',
      displayName: 'Interviewer',
      description: 'Interview panel member',
      level: 160,
      category: 'recruitment',
      inherits: [],
      capabilities: [
        'recruitment.interviews.conduct',
        'recruitment.feedback.provide',
        'recruitment.candidates.evaluate'
      ]
    },
    
    CANDIDATE: {
      name: 'candidate',
      displayName: 'Candidate',
      description: 'Job candidate',
      level: 100,
      category: 'recruitment',
      inherits: [],
      capabilities: [
        'recruitment.profile.manage',
        'recruitment.jobs.search',
        'recruitment.jobs.apply',
        'recruitment.applications.track',
        'recruitment.interviews.attend'
      ]
    }
  },
  
  /**
   * Helper functions
   */
  
  /**
   * Get role by name
   * @param {string} roleName - Role name
   * @returns {Object|null} Role object
   */
  getRole(roleName) {
    for (const category of Object.values(this)) {
      if (typeof category === 'object' && !Array.isArray(category)) {
        for (const role of Object.values(category)) {
          if (role.name === roleName) {
            return role;
          }
        }
      }
    }
    return null;
  },
  
  /**
   * Get all capabilities for a role (including inherited)
   * @param {string} roleName - Role name
   * @returns {Array} Array of capabilities
   */
  getRoleCapabilities(roleName) {
    const role = this.getRole(roleName);
    if (!role) return [];
    
    const capabilities = new Set(role.capabilities);
    
    // Add inherited capabilities
    if (role.inherits && role.inherits.length > 0) {
      for (const inheritedRoleName of role.inherits) {
        const inheritedCapabilities = this.getRoleCapabilities(inheritedRoleName);
        inheritedCapabilities.forEach(cap => capabilities.add(cap));
      }
    }
    
    return Array.from(capabilities);
  },
  
  /**
   * Check if role has capability
   * @param {string} roleName - Role name
   * @param {string} capability - Capability to check
   * @returns {boolean} Has capability
   */
  hasCapability(roleName, capability) {
    const capabilities = this.getRoleCapabilities(roleName);
    return capabilities.includes(capability);
  },
  
  /**
   * Get role hierarchy level
   * @param {string} roleName - Role name
   * @returns {number} Role level
   */
  getRoleLevel(roleName) {
    const role = this.getRole(roleName);
    return role ? role.level : 0;
  },
  
  /**
   * Compare role levels
   * @param {string} roleA - First role
   * @param {string} roleB - Second role
   * @returns {number} Comparison result
   */
  compareRoles(roleA, roleB) {
    const levelA = this.getRoleLevel(roleA);
    const levelB = this.getRoleLevel(roleB);
    return levelA - levelB;
  },
  
  /**
   * Get all roles in a category
   * @param {string} categoryName - Category name
   * @returns {Array} Array of roles
   */
  getRolesByCategory(categoryName) {
    const category = this[categoryName.toUpperCase()];
    if (!category || typeof category !== 'object') return [];
    
    return Object.values(category).filter(item => 
      item && typeof item === 'object' && item.name
    );
  },
  
  /**
   * Get role display name
   * @param {string} roleName - Role name
   * @returns {string} Display name
   */
  getRoleDisplayName(roleName) {
    const role = this.getRole(roleName);
    return role ? role.displayName : roleName;
  }
};