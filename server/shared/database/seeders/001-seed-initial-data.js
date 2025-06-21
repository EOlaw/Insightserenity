// /server/shared/database/seeders/001-seed-initial-data.js

/**
 * @file Initial Data Seeder - FIXED VERSION
 * @description Seeds initial data for development and testing
 * @version 1.1.0
 */

const bcrypt = require('bcryptjs');
const { ObjectId } = require('mongodb');

const constants = require('../../config/constants');
const logger = require('../../utils/logger');

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
      
      // 1. Create Core Business Organization
      const coreBusinessId = new ObjectId();
      seedData.organizations.push({
        _id: coreBusinessId,
        name: 'Insightserenity Core Business',
        slug: 'insightserenity-core',
        type: constants.ORGANIZATION.TYPES.CORE_BUSINESS,
        status: constants.ORGANIZATION.STATUS.ACTIVE,
        description: 'Core consulting business operations',
        website: 'https://insightserenity.com',
        email: 'contact@insightserenity.com',
        phone: '+1555123456',
        industry: 'Management Consulting',
        size: constants.ORGANIZATION.SIZE_RANGES.MEDIUM,
        location: {
          address: '100 Main Street',
          city: 'Houston',
          state: 'Texas',
          country: 'US',
          postalCode: '77002'
        },
        subscription: {
          tier: constants.ORGANIZATION.SUBSCRIPTION_TIERS.ENTERPRISE,
          status: 'active',
          startDate: new Date(),
          endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
        },
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // 2. Create Hosted Organization
      const hostedOrgId = new ObjectId();
      const hostedOrgOwnerId = new ObjectId();
      
      seedData.organizations.push({
        _id: hostedOrgId,
        name: 'TechCorp Solutions',
        slug: 'techcorp-solutions',
        type: constants.ORGANIZATION.TYPES.HOSTED_BUSINESS,
        status: constants.ORGANIZATION.STATUS.ACTIVE,
        description: 'Technology solutions provider',
        website: 'https://techcorp.example.com',
        email: 'info@techcorp.example.com',
        phone: '+1555987654',
        industry: 'Software Development',
        size: constants.ORGANIZATION.SIZE_RANGES.SMALL,
        location: {
          address: '456 Tech Avenue',
          city: 'Austin',
          state: 'Texas',
          country: 'US',
          postalCode: '78701'
        },
        subscription: {
          tier: constants.ORGANIZATION.SUBSCRIPTION_TIERS.PROFESSIONAL,
          status: 'active',
          startDate: new Date(),
          endDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
        },
        ownerId: hostedOrgOwnerId,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // 3. Create Super Admin user
      const superAdminId = new ObjectId();
      const superAdminPassword = await bcrypt.hash('Admin@123', 10);
      
      seedData.users.push({
        _id: superAdminId,
        email: 'admin@insightserenity.com',
        username: 'superadmin',
        firstName: 'Super',
        lastName: 'Admin',
        password: superAdminPassword,
        userType: constants.USER.TYPES.PLATFORM_ADMIN,
        role: {
          primary: 'super_admin',
          secondary: [],
          previousRoles: []
        },
        status: constants.USER.STATUS.ACTIVE,
        active: true,
        verified: true,
        organization: {
          current: coreBusinessId,
          history: [{
            organizationId: coreBusinessId,
            role: 'super_admin',
            joinedAt: new Date(),
            active: true
          }]
        },
        profile: {
          displayName: 'Super Admin',
          bio: {
            short: 'Platform Super Administrator',
            full: 'Platform Super Administrator with full system access'
          },
          avatar: {
            url: null,
            publicId: null,
            source: 'generated'
          },
          location: 'Houston, TX',
          timezone: 'America/Chicago',
          professionalInfo: {
            skills: [
              { name: 'Platform Management', level: 'expert', yearsOfExperience: 10 },
              { name: 'System Administration', level: 'expert', yearsOfExperience: 10 }
            ],
            industries: ['Technology', 'Consulting'],
            certifications: [],
            languages: [{ language: 'English', proficiency: 'native' }]
          }
        },
        preferences: {
          theme: 'dark',
          language: 'en',
          timezone: 'America/Chicago',
          notifications: {
            email: { marketing: false, updates: true, security: true },
            push: { enabled: true, marketing: false, updates: true },
            sms: { enabled: false }
          }
        },
        auth: {
          provider: constants.AUTH.PROVIDERS.LOCAL,
          lastPasswordChange: new Date(),
          passwordHistory: [],
          loginAttempts: 0,
          lockUntil: null,
          twoFactorEnabled: false
        },
        activity: {
          lastLogin: null,
          lastActive: new Date(),
          loginCount: 0,
          sessionCount: 0
        },
        security: {
          sessions: [],
          trustedDevices: [],
          ipWhitelist: [],
          securityQuestions: []
        },
        metadata: {
          source: 'web',
          tags: ['admin', 'seeded'],
          customFields: {},
          statusHistory: [{
            status: constants.USER.STATUS.ACTIVE,
            changedAt: new Date(),
            reason: 'Account created via initial seeder'
          }]
        },
        createdAt: new Date(),
        updatedAt: new Date()
      });
      
      // 4. Create test users for different roles
      const testUsers = [
        {
          email: 'consultant@insightserenity.com',
          username: 'consultant1',
          firstName: 'Jane',
          lastName: 'Smith',
          role: 'consultant',
          userType: constants.USER.TYPES.CORE_CONSULTANT,
          organizationId: coreBusinessId
        },
        {
          email: 'manager@insightserenity.com',
          username: 'manager1',
          firstName: 'John',
          lastName: 'Manager',
          role: 'manager',
          userType: constants.USER.TYPES.CORE_CONSULTANT,
          organizationId: coreBusinessId
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
          userType: userData.userType,
          role: {
            primary: userData.role,
            secondary: [],
            previousRoles: []
          },
          status: constants.USER.STATUS.ACTIVE,
          active: true,
          verified: true,
          organization: {
            current: userData.organizationId,
            history: [{
              organizationId: userData.organizationId,
              role: userData.role,
              joinedAt: new Date(),
              active: true
            }]
          },
          profile: {
            displayName: `${userData.firstName} ${userData.lastName}`,
            bio: {
              short: `${userData.role} at Insightserenity`,
              full: `${userData.role} at Insightserenity`
            },
            avatar: {
              url: null,
              publicId: null,
              source: 'generated'
            },
            location: 'Houston, TX',
            timezone: 'America/Chicago',
            professionalInfo: {
              skills: [],
              industries: ['Consulting'],
              certifications: [],
              languages: [{ language: 'English', proficiency: 'native' }]
            }
          },
          preferences: {
            theme: 'light',
            language: 'en',
            timezone: 'America/Chicago',
            notifications: {
              email: { marketing: true, updates: true, security: true },
              push: { enabled: true, marketing: false, updates: true },
              sms: { enabled: false }
            }
          },
          auth: {
            provider: constants.AUTH.PROVIDERS.LOCAL,
            lastPasswordChange: new Date(),
            passwordHistory: [],
            loginAttempts: 0,
            lockUntil: null,
            twoFactorEnabled: false
          },
          activity: {
            lastLogin: null,
            lastActive: new Date(),
            loginCount: 0,
            sessionCount: 0
          },
          security: {
            sessions: [],
            trustedDevices: [],
            ipWhitelist: [],
            securityQuestions: []
          },
          metadata: {
            source: 'web',
            tags: ['test-user', 'seeded'],
            customFields: {},
            statusHistory: [{
              status: constants.USER.STATUS.ACTIVE,
              changedAt: new Date(),
              reason: 'Account created via initial seeder'
            }]
          },
          createdAt: new Date(),
          updatedAt: new Date()
        });
      }
      
      // 5. Create hosted organization owner
      const hostedOrgPassword = await bcrypt.hash('Test@123', 10);
      
      seedData.users.push({
        _id: hostedOrgOwnerId,
        email: 'owner@techcorp.example.com',
        username: 'techcorp_owner',
        firstName: 'Tech',
        lastName: 'Owner',
        password: hostedOrgPassword,
        userType: constants.USER.TYPES.HOSTED_ORG_USER,
        role: {
          primary: 'org_owner',
          secondary: [],
          previousRoles: []
        },
        status: constants.USER.STATUS.ACTIVE,
        active: true,
        verified: true,
        organization: {
          current: hostedOrgId,
          history: [{
            organizationId: hostedOrgId,
            role: 'org_owner',
            joinedAt: new Date(),
            active: true
          }]
        },
        profile: {
          displayName: 'Tech Owner',
          bio: {
            short: 'Founder and CEO of TechCorp Solutions',
            full: 'Founder and CEO of TechCorp Solutions'
          },
          avatar: {
            url: null,
            publicId: null,
            source: 'generated'
          },
          location: 'Austin, TX',
          timezone: 'America/Chicago',
          professionalInfo: {
            skills: [
              { name: 'Leadership', level: 'expert', yearsOfExperience: 15 },
              { name: 'Technology', level: 'advanced', yearsOfExperience: 20 },
              { name: 'Business Development', level: 'expert', yearsOfExperience: 12 }
            ],
            industries: ['Technology', 'Software'],
            certifications: [],
            languages: [{ language: 'English', proficiency: 'native' }]
          }
        },
        preferences: {
          theme: 'light',
          language: 'en',
          timezone: 'America/Chicago',
          notifications: {
            email: { marketing: true, updates: true, security: true },
            push: { enabled: true, marketing: false, updates: true },
            sms: { enabled: false }
          }
        },
        auth: {
          provider: constants.AUTH.PROVIDERS.LOCAL,
          lastPasswordChange: new Date(),
          passwordHistory: [],
          loginAttempts: 0,
          lockUntil: null,
          twoFactorEnabled: false
        },
        activity: {
          lastLogin: null,
          lastActive: new Date(),
          loginCount: 0,
          sessionCount: 0
        },
        security: {
          sessions: [],
          trustedDevices: [],
          ipWhitelist: [],
          securityQuestions: []
        },
        metadata: {
          source: 'web',
          tags: ['org-owner', 'seeded'],
          customFields: {},
          statusHistory: [{
            status: constants.USER.STATUS.ACTIVE,
            changedAt: new Date(),
            reason: 'Account created via initial seeder'
          }]
        },
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
          window: 3600
        },
        active: true,
        lastUsedAt: null,
        expiresAt: null,
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
          organizationId: user.organization?.current || null,
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
      logger.info('Consultant - Email: consultant@insightserenity.com, Password: Test@123');
      logger.info('Manager - Email: manager@insightserenity.com, Password: Test@123');
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
      await db.collection('organizations').deleteMany({
        slug: { $in: ['insightserenity-core', 'techcorp-solutions'] }
      });
      await db.collection('users').deleteMany({
        'metadata.tags': { $in: ['admin', 'test-user', 'org-owner', 'seeded'] }
      });
      
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