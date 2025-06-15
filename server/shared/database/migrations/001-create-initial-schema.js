// /server/shared/database/migrations/001-create-initial-schema.js

/**
 * @file Initial Schema Migration
 * @description Creates the initial database schema for the platform
 * @version 1.0.0
 */

const logger = require('../../utils/logger');

module.exports = {
  version: 1,
  name: 'create-initial-schema',
  
  /**
   * Run the migration
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<void>}
   */
  async up(db) {
    logger.info('Running migration: create-initial-schema');
    
    try {
      // Create collections with validation schemas
      
      // Users collection
      await db.createCollection('users', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['email', 'firstName', 'lastName', 'status'],
            properties: {
              email: {
                bsonType: 'string',
                pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
              },
              username: {
                bsonType: 'string',
                minLength: 3,
                maxLength: 30
              },
              firstName: {
                bsonType: 'string',
                minLength: 1,
                maxLength: 50
              },
              lastName: {
                bsonType: 'string',
                minLength: 1,
                maxLength: 50
              },
              password: {
                bsonType: 'string'
              },
              status: {
                enum: ['pending', 'active', 'inactive', 'suspended', 'deleted']
              },
              verified: {
                bsonType: 'bool'
              },
              verificationToken: {
                bsonType: ['string', 'null']
              },
              verificationExpires: {
                bsonType: ['date', 'null']
              },
              roles: {
                bsonType: 'array',
                items: {
                  bsonType: 'string'
                }
              },
              organizations: {
                bsonType: 'array',
                items: {
                  bsonType: 'object',
                  required: ['organizationId', 'role'],
                  properties: {
                    organizationId: {
                      bsonType: 'objectId'
                    },
                    role: {
                      bsonType: 'string'
                    },
                    joinedAt: {
                      bsonType: 'date'
                    },
                    active: {
                      bsonType: 'bool'
                    }
                  }
                }
              },
              profile: {
                bsonType: 'object',
                properties: {
                  bio: {
                    bsonType: 'string',
                    maxLength: 500
                  },
                  avatar: {
                    bsonType: 'string'
                  },
                  phone: {
                    bsonType: 'string'
                  },
                  location: {
                    bsonType: 'object'
                  },
                  skills: {
                    bsonType: 'array',
                    items: {
                      bsonType: 'string'
                    }
                  }
                }
              },
              preferences: {
                bsonType: 'object'
              },
              security: {
                bsonType: 'object',
                properties: {
                  twoFactorEnabled: {
                    bsonType: 'bool'
                  },
                  twoFactorSecret: {
                    bsonType: ['string', 'null']
                  },
                  passwordChangedAt: {
                    bsonType: ['date', 'null']
                  },
                  passwordHistory: {
                    bsonType: 'array'
                  },
                  loginAttempts: {
                    bsonType: 'int'
                  },
                  lockUntil: {
                    bsonType: ['date', 'null']
                  }
                }
              },
              lastLoginAt: {
                bsonType: ['date', 'null']
              },
              lastLoginIp: {
                bsonType: ['string', 'null']
              },
              createdAt: {
                bsonType: 'date'
              },
              updatedAt: {
                bsonType: 'date'
              }
            }
          }
        }
      });
      
      // Organizations collection
      await db.createCollection('organizations', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['name', 'slug', 'type', 'status'],
            properties: {
              name: {
                bsonType: 'string',
                minLength: 2,
                maxLength: 100
              },
              slug: {
                bsonType: 'string',
                pattern: '^[a-z0-9]+(?:-[a-z0-9]+)*$'
              },
              type: {
                enum: ['core_business', 'hosted_business', 'recruitment_partner', 'white_label']
              },
              status: {
                enum: ['pending_setup', 'active', 'suspended', 'expired', 'terminated', 'trial']
              },
              description: {
                bsonType: 'string',
                maxLength: 500
              },
              website: {
                bsonType: 'string'
              },
              email: {
                bsonType: 'string'
              },
              phone: {
                bsonType: 'string'
              },
              industry: {
                bsonType: 'string'
              },
              size: {
                enum: ['1-10', '11-50', '51-200', '201-500', '501-1000', '1000+']
              },
              location: {
                bsonType: 'object',
                properties: {
                  address: { bsonType: 'string' },
                  city: { bsonType: 'string' },
                  state: { bsonType: 'string' },
                  country: { bsonType: 'string' },
                  postalCode: { bsonType: 'string' },
                  coordinates: {
                    bsonType: 'object',
                    properties: {
                      lat: { bsonType: 'double' },
                      lng: { bsonType: 'double' }
                    }
                  }
                }
              },
              subscription: {
                bsonType: 'object',
                properties: {
                  tier: {
                    enum: ['trial', 'starter', 'professional', 'enterprise', 'custom']
                  },
                  status: {
                    enum: ['active', 'canceled', 'past_due', 'unpaid', 'trialing']
                  },
                  startDate: { bsonType: 'date' },
                  endDate: { bsonType: 'date' },
                  trialEndsAt: { bsonType: ['date', 'null'] }
                }
              },
              settings: {
                bsonType: 'object'
              },
              customDomain: {
                bsonType: 'object',
                properties: {
                  domain: { bsonType: 'string' },
                  verified: { bsonType: 'bool' },
                  verificationToken: { bsonType: 'string' },
                  sslEnabled: { bsonType: 'bool' }
                }
              },
              branding: {
                bsonType: 'object',
                properties: {
                  logo: { bsonType: 'string' },
                  favicon: { bsonType: 'string' },
                  primaryColor: { bsonType: 'string' },
                  secondaryColor: { bsonType: 'string' }
                }
              },
              features: {
                bsonType: 'object'
              },
              limits: {
                bsonType: 'object',
                properties: {
                  users: { bsonType: 'int' },
                  projects: { bsonType: 'int' },
                  storage: { bsonType: 'long' },
                  apiCalls: { bsonType: 'int' }
                }
              },
              metrics: {
                bsonType: 'object',
                properties: {
                  totalUsers: { bsonType: 'int' },
                  activeUsers: { bsonType: 'int' },
                  totalProjects: { bsonType: 'int' },
                  storageUsed: { bsonType: 'long' }
                }
              },
              ownerId: {
                bsonType: 'objectId'
              },
              createdAt: {
                bsonType: 'date'
              },
              updatedAt: {
                bsonType: 'date'
              }
            }
          }
        }
      });
      
      // Sessions collection
      await db.createCollection('sessions', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['userId', 'token'],
            properties: {
              userId: { bsonType: 'objectId' },
              token: { bsonType: 'string' },
              refreshToken: { bsonType: 'string' },
              userAgent: { bsonType: 'string' },
              ip: { bsonType: 'string' },
              active: { bsonType: 'bool' },
              lastActivity: { bsonType: 'date' },
              expiresAt: { bsonType: 'date' },
              createdAt: { bsonType: 'date' }
            }
          }
        }
      });
      
      // API Keys collection
      await db.createCollection('apiKeys', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['key', 'name'],
            properties: {
              key: { bsonType: 'string' },
              name: { bsonType: 'string' },
              description: { bsonType: 'string' },
              userId: { bsonType: 'objectId' },
              organizationId: { bsonType: 'objectId' },
              permissions: {
                bsonType: 'array',
                items: { bsonType: 'string' }
              },
              rateLimit: {
                bsonType: 'object',
                properties: {
                  requests: { bsonType: 'int' },
                  window: { bsonType: 'int' }
                }
              },
              active: { bsonType: 'bool' },
              lastUsedAt: { bsonType: ['date', 'null'] },
              expiresAt: { bsonType: ['date', 'null'] },
              createdAt: { bsonType: 'date' }
            }
          }
        }
      });
      
      // Projects collection
      await db.createCollection('projects', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['name', 'organizationId', 'status'],
            properties: {
              name: { bsonType: 'string' },
              description: { bsonType: 'string' },
              organizationId: { bsonType: 'objectId' },
              clientId: { bsonType: ['objectId', 'null'] },
              status: {
                enum: ['planning', 'active', 'on_hold', 'completed', 'cancelled', 'archived']
              },
              type: { bsonType: 'string' },
              priority: {
                enum: ['low', 'medium', 'high', 'critical']
              },
              startDate: { bsonType: 'date' },
              endDate: { bsonType: 'date' },
              budget: {
                bsonType: 'object',
                properties: {
                  amount: { bsonType: 'double' },
                  currency: { bsonType: 'string' },
                  spent: { bsonType: 'double' }
                }
              },
              team: {
                bsonType: 'array',
                items: {
                  bsonType: 'object',
                  properties: {
                    userId: { bsonType: 'objectId' },
                    role: { bsonType: 'string' },
                    joinedAt: { bsonType: 'date' }
                  }
                }
              },
              deliverables: {
                bsonType: 'array',
                items: {
                  bsonType: 'object',
                  properties: {
                    name: { bsonType: 'string' },
                    description: { bsonType: 'string' },
                    status: { bsonType: 'string' },
                    dueDate: { bsonType: 'date' }
                  }
                }
              },
              tags: {
                bsonType: 'array',
                items: { bsonType: 'string' }
              },
              attachments: {
                bsonType: 'array',
                items: { bsonType: 'objectId' }
              },
              progress: {
                bsonType: 'int',
                minimum: 0,
                maximum: 100
              },
              createdBy: { bsonType: 'objectId' },
              createdAt: { bsonType: 'date' },
              updatedAt: { bsonType: 'date' }
            }
          }
        }
      });
      
      // Audit Logs collection
      await db.createCollection('auditLogs', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['action', 'timestamp'],
            properties: {
              userId: { bsonType: ['objectId', 'null'] },
              organizationId: { bsonType: ['objectId', 'null'] },
              action: { bsonType: 'string' },
              entityType: { bsonType: 'string' },
              entityId: { bsonType: 'string' },
              changes: { bsonType: 'object' },
              ip: { bsonType: 'string' },
              userAgent: { bsonType: 'string' },
              timestamp: { bsonType: 'date' },
              metadata: { bsonType: 'object' }
            }
          }
        }
      });
      
      // Notifications collection
      await db.createCollection('notifications', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['userId', 'type', 'title'],
            properties: {
              userId: { bsonType: 'objectId' },
              organizationId: { bsonType: ['objectId', 'null'] },
              type: {
                enum: ['info', 'success', 'warning', 'error', 'system']
              },
              category: { bsonType: 'string' },
              title: { bsonType: 'string' },
              message: { bsonType: 'string' },
              data: { bsonType: 'object' },
              read: { bsonType: 'bool' },
              readAt: { bsonType: ['date', 'null'] },
              actionUrl: { bsonType: 'string' },
              expiresAt: { bsonType: ['date', 'null'] },
              createdAt: { bsonType: 'date' }
            }
          }
        }
      });
      
      // Add migration record
      await db.collection('migrations').insertOne({
        version: this.version,
        name: this.name,
        executedAt: new Date(),
        success: true
      });
      
      logger.info('Migration completed: create-initial-schema');
    } catch (error) {
      logger.error('Migration failed: create-initial-schema', error);
      throw error;
    }
  },
  
  /**
   * Rollback the migration
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<void>}
   */
  async down(db) {
    logger.info('Rolling back migration: create-initial-schema');
    
    try {
      // Drop collections in reverse order
      const collections = [
        'notifications',
        'auditLogs',
        'projects',
        'apiKeys',
        'sessions',
        'organizations',
        'users'
      ];
      
      for (const collection of collections) {
        try {
          await db.dropCollection(collection);
          logger.info(`Dropped collection: ${collection}`);
        } catch (error) {
          // Collection might not exist
          logger.debug(`Collection ${collection} does not exist`);
        }
      }
      
      // Remove migration record
      await db.collection('migrations').deleteOne({
        version: this.version,
        name: this.name
      });
      
      logger.info('Rollback completed: create-initial-schema');
    } catch (error) {
      logger.error('Rollback failed: create-initial-schema', error);
      throw error;
    }
  }
};