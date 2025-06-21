// /server/shared/database/seeders/002-seed-auth-users.js

/**
 * @file Authentication Users Seeder
 * @description Seeds comprehensive user data for all roles with verified accounts
 * @version 3.0.0
 */

const bcrypt = require('bcryptjs');
const { ObjectId } = require('mongodb');

const constants = require('../../config/constants');
const logger = require('../../utils/logger');

module.exports = {
  version: 2,
  name: 'seed-auth-users',
  environment: ['development', 'staging', 'testing'], // Run in these environments
  
  /**
   * Run the seeder
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<void>}
   */
  async up(db) {
    logger.info('Running seeder: seed-auth-users');
    
    try {
      // Create organizations first (needed for user assignments)
      const organizations = await this.createOrganizations(db);
      
      // Create users for all roles
      const userData = await this.createUsers(db, organizations);
      
      // Safely extract users and authRecords with fallback to empty arrays
      const users = userData?.users || [];
      const authRecords = userData?.authRecords || [];
      
      // Insert organizations
      if (organizations && organizations.length > 0) {
        await db.collection('organizations').insertMany(organizations);
        logger.info(`Seeded ${organizations.length} organizations`);
      }
      
      // Insert users
      if (users && users.length > 0) {
        await db.collection('users').insertMany(users);
        logger.info(`Seeded ${users.length} users`);
      }
      
      // Insert authentication records
      if (authRecords && authRecords.length > 0) {
        await db.collection('authentications').insertMany(authRecords);
        logger.info(`Seeded ${authRecords.length} authentication records`);
      }
      
      // Add seeder record
      await db.collection('seeders').insertOne({
        version: this.version,
        name: this.name,
        executedAt: new Date(),
        success: true
      });
      
      logger.info('Seeder completed: seed-auth-users');
      
      // Log all test credentials
      this.logCredentials();
      
    } catch (error) {
      logger.error('Seeder failed: seed-auth-users', error);
      throw error;
    }
  },
  
  /**
   * Create organizations needed for user assignments
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<Array>} Array of organization objects
   */
  async createOrganizations(db) {
    const organizations = [];
    
    // Core Business Organization
    const coreBusinessId = new ObjectId();
    organizations.push({
      _id: coreBusinessId,
      name: 'Insight Serenity Consulting',
      slug: 'insight-serenity',
      type: constants.ORGANIZATION.TYPES.CORE_BUSINESS,
      status: constants.ORGANIZATION.STATUS.ACTIVE,
      description: 'Premier consulting services provider',
      website: 'https://insightserenity.com',
      email: 'contact@insightserenity.com',
      phone: '+1-555-0100',
      industry: 'Management Consulting',
      size: constants.ORGANIZATION.SIZE_RANGES.MEDIUM,
      location: {
        address: '100 Main Street, Suite 500',
        city: 'Houston',
        state: 'Texas',
        country: 'US',
        postalCode: '77002',
        coordinates: { lat: 29.7604, lng: -95.3698 }
      },
      subscription: {
        tier: constants.ORGANIZATION.SUBSCRIPTION_TIERS.ENTERPRISE,
        status: 'active',
        startDate: new Date(),
        endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) // 1 year
      },
      settings: {
        features: {
          recruitment: true,
          projects: true,
          billing: true,
          analytics: true,
          whiteLabel: true
        }
      },
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Hosted Business Organization
    const hostedBusinessId = new ObjectId();
    organizations.push({
      _id: hostedBusinessId,
      name: 'TechVision Inc',
      slug: 'techvision',
      type: constants.ORGANIZATION.TYPES.HOSTED_BUSINESS,
      status: constants.ORGANIZATION.STATUS.ACTIVE,
      description: 'Innovative technology solutions for modern businesses',
      website: 'https://techvision.example.com',
      email: 'info@techvision.example.com',
      phone: '+1-555-0200',
      industry: 'Software Development',
      size: constants.ORGANIZATION.SIZE_RANGES.SMALL,
      location: {
        address: '200 Tech Boulevard',
        city: 'Austin',
        state: 'Texas',
        country: 'US',
        postalCode: '78701',
        coordinates: { lat: 30.2672, lng: -97.7431 }
      },
      subscription: {
        tier: constants.ORGANIZATION.SUBSCRIPTION_TIERS.PROFESSIONAL,
        status: 'active',
        startDate: new Date(),
        endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
      },
      settings: {
        features: {
          recruitment: false,
          projects: true,
          billing: true,
          analytics: true,
          whiteLabel: false
        }
      },
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Recruitment Partner Organization
    const recruitmentPartnerId = new ObjectId();
    organizations.push({
      _id: recruitmentPartnerId,
      name: 'Elite Talent Solutions',
      slug: 'elite-talent',
      type: constants.ORGANIZATION.TYPES.RECRUITMENT_PARTNER,
      status: constants.ORGANIZATION.STATUS.ACTIVE,
      description: 'Premier executive search and recruitment services',
      website: 'https://elitetalent.example.com',
      email: 'partnerships@elitetalent.example.com',
      phone: '+1-555-0300',
      industry: 'Human Resources',
      size: constants.ORGANIZATION.SIZE_RANGES.MICRO,
      location: {
        address: '300 Recruitment Plaza',
        city: 'Dallas',
        state: 'Texas',
        country: 'US',
        postalCode: '75201',
        coordinates: { lat: 32.7767, lng: -96.7970 }
      },
      subscription: {
        tier: constants.ORGANIZATION.SUBSCRIPTION_TIERS.STARTER,
        status: 'active',
        startDate: new Date(),
        endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
      },
      settings: {
        features: {
          recruitment: true,
          projects: false,
          billing: true,
          analytics: false,
          whiteLabel: false
        }
      },
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    return organizations.map(org => ({ ...org, organizationId: org._id }));
  },
  
  /**
   * Create users for all roles
   * @param {Object} db - MongoDB database instance
   * @param {Array} organizations - Array of organization objects
   * @returns {Promise<Array>} Array of user objects
   */
  async createUsers(db, organizations) {
    const users = [];
    const authRecords = [];
    const [coreOrg, hostedOrg, recruitmentOrg] = organizations;
    
    // User templates with realistic data
    const userTemplates = [
      
      // =========================
      // CORE BUSINESS ROLES
      // =========================
      
      {
        firstName: 'Emma',
        lastName: 'Thompson',
        email: 'emma.thompson@insightserenity.com',
        username: 'ethompson',
        role: { primary: 'partner' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Senior Partner with 15+ years in strategic consulting',
        title: 'Senior Partner',
        department: 'Executive Leadership',
        skills: ['Strategic Planning', 'Executive Leadership', 'M&A Advisory', 'Board Relations']
      },
      
      {
        firstName: 'James',
        lastName: 'Rodriguez',
        email: 'james.rodriguez@insightserenity.com',
        username: 'jrodriguez',
        role: { primary: 'director' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Director of Operations with expertise in process optimization',
        title: 'Director of Operations',
        department: 'Operations',
        skills: ['Operations Management', 'Process Optimization', 'Change Management', 'Team Leadership']
      },
      
      {
        firstName: 'Sarah',
        lastName: 'Chen',
        email: 'sarah.chen@insightserenity.com',
        username: 'schen',
        role: { primary: 'senior_manager' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Senior Manager specializing in digital transformation',
        title: 'Senior Manager - Digital Practice',
        department: 'Digital Transformation',
        skills: ['Digital Strategy', 'Technology Implementation', 'Data Analytics', 'Project Management']
      },
      
      {
        firstName: 'Michael',
        lastName: 'Johnson',
        email: 'michael.johnson@insightserenity.com',
        username: 'mjohnson',
        role: { primary: 'manager' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Manager focused on organizational development and HR consulting',
        title: 'Manager - HR Practice',
        department: 'Human Resources',
        skills: ['HR Strategy', 'Organizational Development', 'Talent Management', 'Employee Engagement']
      },
      
      {
        firstName: 'David',
        lastName: 'Park',
        email: 'david.park@insightserenity.com',
        username: 'dpark',
        role: { primary: 'principal_consultant' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Principal Consultant with deep expertise in financial services',
        title: 'Principal Consultant',
        department: 'Financial Services',
        skills: ['Financial Analysis', 'Risk Management', 'Regulatory Compliance', 'Strategic Planning']
      },
      
      {
        firstName: 'Lisa',
        lastName: 'Williams',
        email: 'lisa.williams@insightserenity.com',
        username: 'lwilliams',
        role: { primary: 'senior_consultant' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Senior Consultant specializing in supply chain optimization',
        title: 'Senior Consultant',
        department: 'Supply Chain',
        skills: ['Supply Chain Management', 'Logistics', 'Vendor Management', 'Cost Optimization']
      },
      
      {
        firstName: 'Alex',
        lastName: 'Davis',
        email: 'alex.davis@insightserenity.com',
        username: 'adavis',
        role: { primary: 'consultant' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Consultant focused on marketing strategy and customer experience',
        title: 'Consultant',
        department: 'Marketing',
        skills: ['Marketing Strategy', 'Customer Experience', 'Brand Management', 'Digital Marketing']
      },
      
      {
        firstName: 'Rachel',
        lastName: 'Kim',
        email: 'rachel.kim@insightserenity.com',
        username: 'rkim',
        role: { primary: 'junior_consultant' },
        userType: constants.USER.TYPES.CORE_CONSULTANT,
        organizationId: coreOrg._id,
        bio: 'Junior Consultant with background in data analysis and business intelligence',
        title: 'Junior Consultant',
        department: 'Analytics',
        skills: ['Data Analysis', 'Business Intelligence', 'SQL', 'Excel']
      },
      
      {
        firstName: 'Jennifer',
        lastName: 'Brown',
        email: 'jennifer.brown@corporateclient.com',
        username: 'jbrown_client',
        role: { primary: 'client' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: hostedOrg._id,
        bio: 'VP of Strategy at Fortune 500 company',
        title: 'VP Strategy',
        department: 'Corporate Strategy',
        skills: ['Strategic Planning', 'Business Development', 'Stakeholder Management', 'Financial Planning']
      },
      
      {
        firstName: 'Robert',
        lastName: 'Miller',
        email: 'robert.miller@prospect-company.com',
        username: 'rmiller_prospect',
        role: { primary: 'prospect' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: null, // Prospects don't have organization assignment yet
        bio: 'CEO of growing tech startup exploring consulting services',
        title: 'CEO',
        department: 'Executive',
        skills: ['Entrepreneurship', 'Product Management', 'Fundraising', 'Team Building']
      },
      
      // =========================
      // HOSTED ORGANIZATION ROLES
      // =========================
      
      {
        firstName: 'Thomas',
        lastName: 'Anderson',
        email: 'thomas.anderson@techvision.com',
        username: 'tanderson',
        role: { primary: 'org_owner' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: hostedOrg._id,
        bio: 'Founder and CEO of TechVision Inc',
        title: 'CEO & Founder',
        department: 'Executive',
        skills: ['Leadership', 'Vision Setting', 'Strategic Planning', 'Technology Innovation']
      },
      
      {
        firstName: 'Maria',
        lastName: 'Garcia',
        email: 'maria.garcia@techvision.com',
        username: 'mgarcia',
        role: { primary: 'org_admin' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: hostedOrg._id,
        bio: 'Chief Technology Officer managing platform operations',
        title: 'Chief Technology Officer',
        department: 'Technology',
        skills: ['System Administration', 'Cloud Architecture', 'DevOps', 'Security']
      },
      
      {
        firstName: 'Kevin',
        lastName: 'Lee',
        email: 'kevin.lee@techvision.com',
        username: 'klee',
        role: { primary: 'org_manager' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: hostedOrg._id,
        bio: 'Engineering Manager leading development teams',
        title: 'Engineering Manager',
        department: 'Engineering',
        skills: ['Team Management', 'Software Development', 'Agile Methodologies', 'Technical Leadership']
      },
      
      {
        firstName: 'Amy',
        lastName: 'Taylor',
        email: 'amy.taylor@techvision.com',
        username: 'ataylor',
        role: { primary: 'org_member' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: hostedOrg._id,
        bio: 'Senior Software Developer specializing in full-stack development',
        title: 'Senior Software Developer',
        department: 'Engineering',
        skills: ['JavaScript', 'React', 'Node.js', 'Database Design']
      },
      
      {
        firstName: 'Daniel',
        lastName: 'Wilson',
        email: 'daniel.wilson@techvision.com',
        username: 'dwilson',
        role: { primary: 'org_viewer' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: hostedOrg._id,
        bio: 'Business Analyst with read-only access to platform insights',
        title: 'Business Analyst',
        department: 'Business Intelligence',
        skills: ['Data Analysis', 'Reporting', 'Market Research', 'Requirements Gathering']
      },
      
      // =========================
      // RECRUITMENT ROLES
      // =========================
      
      {
        firstName: 'Victoria',
        lastName: 'Martinez',
        email: 'victoria.martinez@elitetalent.com',
        username: 'vmartinez',
        role: { primary: 'recruitment_admin' },
        userType: constants.USER.TYPES.RECRUITMENT_PARTNER,
        organizationId: recruitmentOrg._id,
        bio: 'Recruitment Operations Administrator managing partner relationships',
        title: 'Recruitment Operations Admin',
        department: 'Operations',
        skills: ['Recruitment Operations', 'Partner Management', 'Process Optimization', 'Data Management']
      },
      
      {
        firstName: 'Steven',
        lastName: 'Clark',
        email: 'steven.clark@elitetalent.com',
        username: 'sclark',
        role: { primary: 'recruitment_partner' },
        userType: constants.USER.TYPES.RECRUITMENT_PARTNER,
        organizationId: recruitmentOrg._id,
        bio: 'Senior Recruitment Partner specializing in executive search',
        title: 'Senior Recruitment Partner',
        department: 'Executive Search',
        skills: ['Executive Search', 'Talent Acquisition', 'Client Relations', 'Interview Techniques']
      },
      
      {
        firstName: 'Laura',
        lastName: 'Thompson',
        email: 'laura.thompson@elitetalent.com',
        username: 'lthompson',
        role: { primary: 'recruiter' },
        userType: constants.USER.TYPES.RECRUITMENT_PARTNER,
        organizationId: recruitmentOrg._id,
        bio: 'Senior Recruiter focusing on technology and consulting roles',
        title: 'Senior Recruiter',
        department: 'Technology Recruiting',
        skills: ['Technical Recruiting', 'Candidate Sourcing', 'Interview Coordination', 'Market Knowledge']
      },
      
      {
        firstName: 'Mark',
        lastName: 'Johnson',
        email: 'mark.johnson@clientcompany.com',
        username: 'mjohnson_hm',
        role: { primary: 'hiring_manager' },
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        organizationId: hostedOrg._id,
        bio: 'Hiring Manager responsible for building high-performing teams',
        title: 'VP Engineering',
        department: 'Engineering',
        skills: ['Team Building', 'Technical Assessment', 'Leadership Development', 'Strategic Hiring']
      },
      
      {
        firstName: 'Jessica',
        lastName: 'Adams',
        email: 'jessica.adams@jobseeker.com',
        username: 'jadams_candidate',
        role: { primary: 'candidate' },
        userType: constants.USER.TYPES.JOB_SEEKER,
        organizationId: null, // Job seekers don't belong to organizations initially
        bio: 'Experienced consultant seeking new opportunities in strategic consulting',
        title: 'Senior Business Consultant',
        department: 'Consulting',
        skills: ['Strategy Consulting', 'Business Analysis', 'Client Management', 'Process Improvement']
      },
      
      // =========================
      // PLATFORM ROLES
      // =========================
      
      {
        firstName: 'Administrator',
        lastName: 'Super',
        email: 'admin@insightserenity.com',
        username: 'superadmin',
        role: { primary: 'super_admin' },
        userType: constants.USER.TYPES.PLATFORM_ADMIN,
        organizationId: coreOrg._id,
        bio: 'Platform Super Administrator with full system access',
        title: 'Super Administrator',
        department: 'Platform Operations',
        skills: ['System Administration', 'Security Management', 'Platform Operations', 'Database Management']
      },
      
      {
        firstName: 'Patricia',
        lastName: 'White',
        email: 'patricia.white@insightserenity.com',
        username: 'pwhite',
        role: { primary: 'platform_admin' },
        userType: constants.USER.TYPES.PLATFORM_ADMIN,
        organizationId: coreOrg._id,
        bio: 'Platform Administrator managing user accounts and system configuration',
        title: 'Platform Administrator',
        department: 'Platform Operations',
        skills: ['User Management', 'System Configuration', 'Access Control', 'Platform Monitoring']
      },
      
      {
        firstName: 'Christopher',
        lastName: 'Moore',
        email: 'christopher.moore@insightserenity.com',
        username: 'cmoore',
        role: { primary: 'support_agent' },
        userType: constants.USER.TYPES.PLATFORM_ADMIN,
        organizationId: coreOrg._id,
        bio: 'Customer Support Agent helping users navigate the platform',
        title: 'Senior Support Agent',
        department: 'Customer Support',
        skills: ['Customer Support', 'Problem Solving', 'Platform Knowledge', 'Communication']
      },
      
      {
        firstName: 'Michelle',
        lastName: 'Davis',
        email: 'michelle.davis@insightserenity.com',
        username: 'mdavis',
        role: { primary: 'content_manager' },
        userType: constants.USER.TYPES.PLATFORM_ADMIN,
        organizationId: coreOrg._id,
        bio: 'Content Manager responsible for platform documentation and resources',
        title: 'Content Manager',
        department: 'Content & Documentation',
        skills: ['Content Management', 'Technical Writing', 'Documentation', 'Knowledge Management']
      }
    ];
    
    // Generate user records
    for (const template of userTemplates) {
      const userId = new ObjectId();
      const hashedPassword = await bcrypt.hash('Test@123!', 12);
      
      const user = {
        _id: userId,
        email: template.email.toLowerCase(),
        username: template.username,
        firstName: template.firstName,
        lastName: template.lastName,
        
        // User type and role assignment
        userType: template.userType,
        role: {
          primary: template.role.primary,
          secondary: [],
          previousRoles: []
        },
        
        // Profile information
        profile: {
          displayName: `${template.firstName} ${template.lastName}`,
          bio: {
            short: template.bio,
            full: template.bio
          },
          title: template.title,
          department: template.department,
          location: 'Houston, TX',
          timezone: 'America/Chicago',
          avatar: {
            url: null,
            publicId: null,
            source: 'generated'
          },
          professionalInfo: {
            skills: template.skills.map(skill => ({
              name: skill,
              level: 'advanced',
              yearsOfExperience: Math.floor(Math.random() * 10) + 2,
              endorsed: true
            })),
            industries: ['Consulting', 'Technology'],
            certifications: [],
            languages: [
              { language: 'English', proficiency: 'native' }
            ]
          }
        },
        
        // Organization assignment
        organization: template.organizationId ? {
          current: template.organizationId,
          history: [{
            organizationId: template.organizationId,
            role: template.role.primary,
            joinedAt: new Date(),
            leftAt: null,
            active: true
          }]
        } : null,
        
        // Account status
        status: constants.USER.STATUS.ACTIVE,
        active: true,
        verified: true, // All users are verified for testing
        
        // Authentication
        auth: {
          provider: constants.AUTH.PROVIDERS.LOCAL,
          lastPasswordChange: new Date(),
          passwordHistory: [],
          loginAttempts: 0,
          lockUntil: null,
          twoFactorEnabled: false
        },
        
        // Activity tracking
        activity: {
          lastLogin: null,
          lastActive: new Date(),
          loginCount: 0,
          sessionCount: 0
        },
        
        // Preferences
        preferences: {
          theme: 'light',
          language: 'en',
          timezone: 'America/Chicago',
          notifications: {
            email: {
              marketing: true,
              updates: true,
              security: true
            },
            push: {
              enabled: true,
              marketing: false,
              updates: true
            },
            sms: {
              enabled: false
            }
          }
        },
        
        // Security
        security: {
          sessions: [],
          trustedDevices: [],
          ipWhitelist: [],
          securityQuestions: []
        },
        
        // Metadata
        metadata: {
          source: constants.AUTH.SOURCE_TYPES_ENUM[0], // 'web'
          tags: ['test-user', 'seeded'],
          customFields: {},
          statusHistory: [{
            status: constants.USER.STATUS.ACTIVE,
            changedAt: new Date(),
            reason: 'Account created via seeder'
          }]
        },
        
        // Timestamps
        createdAt: new Date(),
        updatedAt: new Date()
      };
      
      // Set password hash (this should be done separately from the user object for security)
      user.password = hashedPassword;
      
      users.push(user);
    }
    
    return users;
  },
  
  /**
   * Log all test credentials
   */
  logCredentials() {
    logger.info('\n=== TEST USER CREDENTIALS ===');
    logger.info('Password for ALL users: Test@123!');
    logger.info('\n--- CORE BUSINESS ROLES ---');
    logger.info('Partner: emma.thompson@insightserenity.com');
    logger.info('Director: james.rodriguez@insightserenity.com');
    logger.info('Senior Manager: sarah.chen@insightserenity.com');
    logger.info('Manager: michael.johnson@insightserenity.com');
    logger.info('Principal Consultant: david.park@insightserenity.com');
    logger.info('Senior Consultant: lisa.williams@insightserenity.com');
    logger.info('Consultant: alex.davis@insightserenity.com');
    logger.info('Junior Consultant: rachel.kim@insightserenity.com');
    logger.info('Client: jennifer.brown@corporateclient.com');
    logger.info('Prospect: robert.miller@prospect-company.com');
    
    logger.info('\n--- HOSTED ORGANIZATION ROLES ---');
    logger.info('Org Owner: thomas.anderson@techvision.com');
    logger.info('Org Admin: maria.garcia@techvision.com');
    logger.info('Org Manager: kevin.lee@techvision.com');
    logger.info('Org Member: amy.taylor@techvision.com');
    logger.info('Org Viewer: daniel.wilson@techvision.com');
    
    logger.info('\n--- RECRUITMENT ROLES ---');
    logger.info('Recruitment Admin: victoria.martinez@elitetalent.com');
    logger.info('Recruitment Partner: steven.clark@elitetalent.com');
    logger.info('Recruiter: laura.thompson@elitetalent.com');
    logger.info('Hiring Manager: mark.johnson@clientcompany.com');
    logger.info('Candidate: jessica.adams@jobseeker.com');
    
    logger.info('\n--- PLATFORM ROLES ---');
    logger.info('Super Admin: admin@insightserenity.com');
    logger.info('Platform Admin: patricia.white@insightserenity.com');
    logger.info('Support Agent: christopher.moore@insightserenity.com');
    logger.info('Content Manager: michelle.davis@insightserenity.com');
    
    logger.info('\n=== END CREDENTIALS ===\n');
  },
  
  /**
   * Rollback the seeder
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<void>}
   */
  async down(db) {
    logger.info('Rolling back seeder: seed-auth-users');
    
    try {
      // Delete seeded authentication records
      await db.collection('authentications').deleteMany({
        'metadata.source': 'web'
      });
      
      // Delete seeded users (by checking for our seeded tag)
      await db.collection('users').deleteMany({
        'metadata.tags': 'seeded'
      });
      
      // Delete seeded organizations (by checking for our specific ones)
      await db.collection('organizations').deleteMany({
        slug: { $in: ['insight-serenity', 'techvision', 'elite-talent'] }
      });
      
      // Remove seeder record
      await db.collection('seeders').deleteOne({
        version: this.version,
        name: this.name
      });
      
      logger.info('Rollback completed: seed-auth-users');
    } catch (error) {
      logger.error('Rollback failed: seed-auth-users', error);
      throw error;
    }
  }
};