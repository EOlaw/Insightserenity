// /server/shared/database/seeders/001-seed-initial-data.js

/**
 * @file Initial Data Seeder
 * @description Seeds initial data for development and testing
 * @version 1.0.0
 */

const bcrypt = require('bcryptjs');
const { ObjectId } = require('mongodb');
const logger = require('../../utils/logger');
const constants = require('../../config/constants');

module.exports = {
  version: 1,
  name: 'seed-initial-data',
  environment: ['development', 'staging'], // Only run in these environments
  
  /**
   * Run the seeder
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<void>}
   */
  async up(db) {
    logger.info('Running seeder: seed-initial-data');
    
    try {
      // Seed data objects
      const seedData = {
        users: [],
        organizations: [],
        projects: [],
        apiKeys: []
      };
      
      // 1. Create Super Admin user
      const superAdminId = new ObjectId();
      const superAdminPassword = await bcrypt.hash('Admin@123', 10);
      
      seedData.users.push({
        _id: superAdminId,
        email: 'admin@insightserenity.com',
        username: 'superadmin',
        firstName: 'Super',
        lastName: 'Admin',
        password: superAdminPassword,
        status: 'active',
        verified: true,
        verificationToken: null,
        verificationExpires: null,
        roles: [constants.ROLES.PLATFORM.SUPER_ADMIN.name],
        organizations: [],
        profile: {
          bio: 'Platform Super Administrator',
          avatar: null,
          phone: '+1234567890',
          location: {
            city: 'Houston',
            state: 'Texas',
            country: 'US'
          },
          skills: ['Platform Management', 'System Administration']
        },
        preferences: {
          theme: 'dark',
          language: 'en',
          notifications: {
            email: true,
            sms: false,
            push: true
          }
        },
        security: {
          twoFactorEnabled: false,
          twoFactorSecret: null,
          passwordChangedAt: new Date(),
          passwordHistory: [],
          loginAttempts: 0,
          lockUntil: null
        },
        lastLoginAt: null,
        lastLoginIp: null,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // 2. Create Core Business (Insightserenity)
      const coreBusinessId = new ObjectId();
      
      seedData.organizations.push({
        _id: coreBusinessId,
        name: 'Insightserenity Consulting',
        slug: 'insightserenity',
        type: 'core_business',
        status: 'active',
        description: 'Leading technology and business consulting firm',
        website: 'https://insightserenity.com',
        email: 'info@insightserenity.com',
        phone: '+1234567890',
        industry: 'Technology Consulting',
        size: '51-200',
        location: {
          address: '123 Main Street',
          city: 'Houston',
          state: 'Texas',
          country: 'US',
          postalCode: '77001',
          coordinates: {
            lat: 29.7604,
            lng: -95.3698
          }
        },
        subscription: {
          tier: 'enterprise',
          status: 'active',
          startDate: new Date(),
          endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
          trialEndsAt: null
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
        customDomain: null,
        branding: {
          logo: '/assets/logos/insightserenity.png',
          favicon: '/assets/favicons/insightserenity.ico',
          primaryColor: '#1a73e8',
          secondaryColor: '#34a853'
        },
        features: {
          maxUsers: -1,
          maxProjects: -1,
          maxStorage: 1099511627776, // 1TB
          apiAccess: true,
          customBranding: true,
          advancedAnalytics: true
        },
        limits: {
          users: -1,
          projects: -1,
          storage: 1099511627776,
          apiCalls: -1
        },
        metrics: {
          totalUsers: 1,
          activeUsers: 1,
          totalProjects: 0,
          storageUsed: 0
        },
        ownerId: superAdminId,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // Update super admin with organization
      seedData.users[0].organizations.push({
        organizationId: coreBusinessId,
        role: constants.ROLES.CORE_BUSINESS.CEO.name,
        joinedAt: new Date(),
        active: true
      });
      
      // 3. Create test users for different roles
      const testUsers = [
        {
          email: 'ceo@insightserenity.com',
          username: 'ceo',
          firstName: 'John',
          lastName: 'Doe',
          role: constants.ROLES.CORE_BUSINESS.CEO.name,
          orgRole: constants.ROLES.CORE_BUSINESS.CEO.name
        },
        {
          email: 'consultant@insightserenity.com',
          username: 'consultant1',
          firstName: 'Jane',
          lastName: 'Smith',
          role: constants.ROLES.CORE_BUSINESS.CONSULTANT.name,
          orgRole: constants.ROLES.CORE_BUSINESS.CONSULTANT.name
        },
        {
          email: 'developer@insightserenity.com',
          username: 'dev1',
          firstName: 'Mike',
          lastName: 'Johnson',
          role: constants.ROLES.PLATFORM.DEVELOPER.name,
          orgRole: constants.ROLES.CORE_BUSINESS.CONSULTANT.name
        }
      ];
      
      for (const userData of testUsers) {
        const userId = new ObjectId();
        const password = await bcrypt.hash('Test@123', 10);
        
        seedData.users.push({
          _id: userId,
          email: userData.email,
          username: userData.username,
          firstName: userData.firstName,
          lastName: userData.lastName,
          password,
          status: 'active',
          verified: true,
          verificationToken: null,
          verificationExpires: null,
          roles: [userData.role],
          organizations: [{
            organizationId: coreBusinessId,
            role: userData.orgRole,
            joinedAt: new Date(),
            active: true
          }],
          profile: {
            bio: `${userData.role} at Insightserenity`,
            avatar: null,
            phone: null,
            location: {
              city: 'Houston',
              state: 'Texas',
              country: 'US'
            },
            skills: []
          },
          preferences: {
            theme: 'light',
            language: 'en',
            notifications: {
              email: true,
              sms: false,
              push: true
            }
          },
          security: {
            twoFactorEnabled: false,
            twoFactorSecret: null,
            passwordChangedAt: new Date(),
            passwordHistory: [],
            loginAttempts: 0,
            lockUntil: null
          },
          lastLoginAt: null,
          lastLoginIp: null,
          createdAt: new Date(),
          updatedAt: new Date()
        });
      }
      
      // 4. Create sample hosted organization
      const hostedOrgId = new ObjectId();
      const hostedOrgOwnerId = new ObjectId();
      
      seedData.organizations.push({
        _id: hostedOrgId,
        name: 'TechCorp Solutions',
        slug: 'techcorp',
        type: 'hosted_business',
        status: 'active',
        description: 'Innovative technology solutions provider',
        website: 'https://techcorp.example.com',
        email: 'info@techcorp.example.com',
        phone: '+1987654321',
        industry: 'Software Development',
        size: '11-50',
        location: {
          address: '456 Tech Avenue',
          city: 'Austin',
          state: 'Texas',
          country: 'US',
          postalCode: '78701',
          coordinates: {
            lat: 30.2672,
            lng: -97.7431
          }
        },
        subscription: {
          tier: 'professional',
          status: 'active',
          startDate: new Date(),
          endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days trial
          trialEndsAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
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
        customDomain: null,
        branding: {
          logo: null,
          favicon: null,
          primaryColor: '#2196f3',
          secondaryColor: '#ff9800'
        },
        features: {
          maxUsers: 100,
          maxProjects: 50,
          maxStorage: 107374182400, // 100GB
          apiAccess: true,
          customBranding: true,
          advancedAnalytics: false
        },
        limits: {
          users: 100,
          projects: 50,
          storage: 107374182400,
          apiCalls: 100000
        },
        metrics: {
          totalUsers: 1,
          activeUsers: 1,
          totalProjects: 0,
          storageUsed: 0
        },
        ownerId: hostedOrgOwnerId,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // Create owner for hosted organization
      const hostedOrgPassword = await bcrypt.hash('Test@123', 10);
      
      seedData.users.push({
        _id: hostedOrgOwnerId,
        email: 'owner@techcorp.example.com',
        username: 'techcorp_owner',
        firstName: 'Tech',
        lastName: 'Owner',
        password: hostedOrgPassword,
        status: 'active',
        verified: true,
        verificationToken: null,
        verificationExpires: null,
        roles: [],
        organizations: [{
          organizationId: hostedOrgId,
          role: constants.ROLES.ORGANIZATION.OWNER.name,
          joinedAt: new Date(),
          active: true
        }],
        profile: {
          bio: 'Founder and CEO of TechCorp Solutions',
          avatar: null,
          phone: null,
          location: {
            city: 'Austin',
            state: 'Texas',
            country: 'US'
          },
          skills: ['Leadership', 'Technology', 'Business Development']
        },
        preferences: {
          theme: 'light',
          language: 'en',
          notifications: {
            email: true,
            sms: false,
            push: true
          }
        },
        security: {
          twoFactorEnabled: false,
          twoFactorSecret: null,
          passwordChangedAt: new Date(),
          passwordHistory: [],
          loginAttempts: 0,
          lockUntil: null
        },
        lastLoginAt: null,
        lastLoginIp: null,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // 5. Create sample projects
      const projectIds = [new ObjectId(), new ObjectId()];
      
      seedData.projects.push({
        _id: projectIds[0],
        name: 'Platform Development Phase 2',
        description: 'Enhance platform features and scalability',
        organizationId: coreBusinessId,
        clientId: null,
        status: 'active',
        type: 'internal',
        priority: 'high',
        startDate: new Date(),
        endDate: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
        budget: {
          amount: 250000,
          currency: 'USD',
          spent: 45000
        },
        team: seedData.users.slice(0, 3).map(user => ({
          userId: user._id,
          role: 'member',
          joinedAt: new Date()
        })),
        deliverables: [
          {
            name: 'Authentication System Upgrade',
            description: 'Implement OAuth2 and SSO',
            status: 'completed',
            dueDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
          },
          {
            name: 'Analytics Dashboard',
            description: 'Create comprehensive analytics dashboard',
            status: 'in_progress',
            dueDate: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000)
          }
        ],
        tags: ['platform', 'development', 'priority'],
        attachments: [],
        progress: 35,
        createdBy: superAdminId,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      seedData.projects.push({
        _id: projectIds[1],
        name: 'Website Redesign',
        description: 'Modern redesign of company website',
        organizationId: hostedOrgId,
        clientId: null,
        status: 'planning',
        type: 'internal',
        priority: 'medium',
        startDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        endDate: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000),
        budget: {
          amount: 50000,
          currency: 'USD',
          spent: 0
        },
        team: [{
          userId: hostedOrgOwnerId,
          role: 'lead',
          joinedAt: new Date()
        }],
        deliverables: [
          {
            name: 'Design Mockups',
            description: 'Create design mockups for all pages',
            status: 'pending',
            dueDate: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000)
          }
        ],
        tags: ['website', 'design', 'marketing'],
        attachments: [],
        progress: 0,
        createdBy: hostedOrgOwnerId,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // 6. Create API keys
      const crypto = require('crypto');
      
      seedData.apiKeys.push({
        _id: new ObjectId(),
        key: `isk_live_${crypto.randomBytes(32).toString('hex')}`,
        name: 'Development API Key',
        description: 'API key for development testing',
        userId: superAdminId,
        organizationId: coreBusinessId,
        permissions: ['read', 'write'],
        rateLimit: {
          requests: 1000,
          window: 3600 // 1 hour
        },
        active: true,
        lastUsedAt: null,
        expiresAt: null,
        createdAt: new Date()
      });
      
      seedData.apiKeys.push({
        _id: new ObjectId(),
        key: `isk_test_${crypto.randomBytes(32).toString('hex')}`,
        name: 'Test Integration Key',
        description: 'API key for integration testing',
        userId: null,
        organizationId: hostedOrgId,
        permissions: ['read'],
        rateLimit: {
          requests: 100,
          window: 3600
        },
        active: true,
        lastUsedAt: null,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        createdAt: new Date()
      });
      
      // Insert all seed data
      if (seedData.users.length > 0) {
        await db.collection('users').insertMany(seedData.users);
        logger.info(`Seeded ${seedData.users.length} users`);
      }
      
      if (seedData.organizations.length > 0) {
        await db.collection('organizations').insertMany(seedData.organizations);
        logger.info(`Seeded ${seedData.organizations.length} organizations`);
      }
      
      if (seedData.projects.length > 0) {
        await db.collection('projects').insertMany(seedData.projects);
        logger.info(`Seeded ${seedData.projects.length} projects`);
      }
      
      if (seedData.apiKeys.length > 0) {
        await db.collection('apiKeys').insertMany(seedData.apiKeys);
        logger.info(`Seeded ${seedData.apiKeys.length} API keys`);
      }
      
      // Create sample notifications
      const notifications = [];
      
      for (const user of seedData.users.slice(0, 3)) {
        notifications.push({
          _id: new ObjectId(),
          userId: user._id,
          organizationId: user.organizations[0]?.organizationId || null,
          type: 'info',
          category: 'system',
          title: 'Welcome to Insightserenity Platform',
          message: 'Your account has been successfully created. Explore the platform features!',
          data: {
            link: '/dashboard/getting-started'
          },
          read: false,
          readAt: null,
          actionUrl: '/dashboard/getting-started',
          expiresAt: null,
          createdAt: new Date()
        });
      }
      
      if (notifications.length > 0) {
        await db.collection('notifications').insertMany(notifications);
        logger.info(`Seeded ${notifications.length} notifications`);
      }
      
      // Add seeder record
      await db.collection('seeders').insertOne({
        version: this.version,
        name: this.name,
        executedAt: new Date(),
        success: true
      });
      
      logger.info('Seeder completed: seed-initial-data');
      
      // Log test credentials
      logger.info('Test Credentials:');
      logger.info('Super Admin - Email: admin@insightserenity.com, Password: Admin@123');
      logger.info('CEO - Email: ceo@insightserenity.com, Password: Test@123');
      logger.info('Consultant - Email: consultant@insightserenity.com, Password: Test@123');
      logger.info('Developer - Email: developer@insightserenity.com, Password: Test@123');
      logger.info('Hosted Org Owner - Email: owner@techcorp.example.com, Password: Test@123');
      
    } catch (error) {
      logger.error('Seeder failed: seed-initial-data', error);
      throw error;
    }
  },
  
  /**
   * Rollback the seeder
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<void>}
   */
  async down(db) {
    logger.info('Rolling back seeder: seed-initial-data');
    
    try {
      // Delete seeded data in reverse order
      await db.collection('notifications').deleteMany({});
      await db.collection('apiKeys').deleteMany({});
      await db.collection('projects').deleteMany({});
      await db.collection('organizations').deleteMany({});
      await db.collection('users').deleteMany({});
      
      // Remove seeder record
      await db.collection('seeders').deleteOne({
        version: this.version,
        name: this.name
      });
      
      logger.info('Rollback completed: seed-initial-data');
    } catch (error) {
      logger.error('Rollback failed: seed-initial-data', error);
      throw error;
    }
  }
};