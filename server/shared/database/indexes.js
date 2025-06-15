// /server/shared/database/indexes.js

/**
 * @file Database Indexes
 * @description MongoDB index definitions for optimal query performance
 * @version 1.0.0
 */

const logger = require('../utils/logger');

/**
 * Database Index Manager
 */
class DatabaseIndexManager {
  constructor() {
    this.indexes = this.defineIndexes();
  }
  
  /**
   * Define all database indexes
   */
  defineIndexes() {
    return {
      // User indexes
      users: [
        // Unique indexes
        { fields: { email: 1 }, options: { unique: true, sparse: true } },
        { fields: { username: 1 }, options: { unique: true, sparse: true } },
        
        // Search indexes
        { fields: { email: 'text', firstName: 'text', lastName: 'text' }, options: { name: 'user_search' } },
        
        // Query optimization indexes
        { fields: { status: 1, createdAt: -1 }, options: { name: 'user_status_date' } },
        { fields: { 'organizations.organizationId': 1, 'organizations.active': 1 }, options: { name: 'user_orgs' } },
        { fields: { roles: 1 }, options: { name: 'user_roles' } },
        { fields: { lastLoginAt: -1 }, options: { name: 'user_last_login' } },
        
        // Compound indexes
        { fields: { active: 1, verified: 1, createdAt: -1 }, options: { name: 'user_active_verified' } },
        
        // TTL index for password reset tokens
        { fields: { 'passwordReset.expiresAt': 1 }, options: { expireAfterSeconds: 0 } }
      ],
      
      // Organization indexes
      organizations: [
        // Unique indexes
        { fields: { slug: 1 }, options: { unique: true } },
        { fields: { 'customDomain.domain': 1 }, options: { unique: true, sparse: true } },
        
        // Search indexes
        { fields: { name: 'text', description: 'text' }, options: { name: 'org_search' } },
        
        // Query optimization indexes
        { fields: { type: 1, status: 1 }, options: { name: 'org_type_status' } },
        { fields: { status: 1, createdAt: -1 }, options: { name: 'org_status_date' } },
        { fields: { 'subscription.tier': 1, 'subscription.status': 1 }, options: { name: 'org_subscription' } },
        { fields: { industry: 1 }, options: { name: 'org_industry' } },
        { fields: { size: 1 }, options: { name: 'org_size' } },
        
        // Geospatial index
        { fields: { 'location.coordinates': '2dsphere' }, options: { sparse: true } },
        
        // Compound indexes
        { fields: { active: 1, verified: 1, type: 1 }, options: { name: 'org_active_type' } }
      ],
      
      // Session indexes
      sessions: [
        // TTL index for session expiry
        { fields: { expiresAt: 1 }, options: { expireAfterSeconds: 0 } },
        
        // Query indexes
        { fields: { userId: 1, active: 1 }, options: { name: 'session_user_active' } },
        { fields: { token: 1 }, options: { unique: true } }
      ],
      
      // API Key indexes
      apiKeys: [
        // Unique index
        { fields: { key: 1 }, options: { unique: true } },
        
        // Query indexes
        { fields: { userId: 1, active: 1 }, options: { name: 'apikey_user_active' } },
        { fields: { organizationId: 1, active: 1 }, options: { name: 'apikey_org_active' } },
        { fields: { expiresAt: 1 }, options: { expireAfterSeconds: 0, sparse: true } }
      ],
      
      // Project indexes
      projects: [
        // Query optimization indexes
        { fields: { organizationId: 1, status: 1 }, options: { name: 'project_org_status' } },
        { fields: { status: 1, createdAt: -1 }, options: { name: 'project_status_date' } },
        { fields: { 'team.userId': 1 }, options: { name: 'project_team_members' } },
        { fields: { tags: 1 }, options: { name: 'project_tags' } },
        { fields: { clientId: 1 }, options: { name: 'project_client' } },
        
        // Search index
        { fields: { name: 'text', description: 'text' }, options: { name: 'project_search' } },
        
        // Compound indexes
        { fields: { organizationId: 1, clientId: 1, status: 1 }, options: { name: 'project_org_client_status' } }
      ],
      
      // Job indexes (Recruitment)
      jobs: [
        // Query optimization indexes
        { fields: { organizationId: 1, status: 1 }, options: { name: 'job_org_status' } },
        { fields: { status: 1, postedDate: -1 }, options: { name: 'job_status_date' } },
        { fields: { category: 1, status: 1 }, options: { name: 'job_category_status' } },
        { fields: { 'location.city': 1, 'location.country': 1 }, options: { name: 'job_location' } },
        { fields: { 'salary.min': 1, 'salary.max': 1 }, options: { name: 'job_salary_range' } },
        { fields: { skills: 1 }, options: { name: 'job_skills' } },
        { fields: { type: 1 }, options: { name: 'job_type' } },
        
        // Search index
        { fields: { title: 'text', description: 'text', requirements: 'text' }, options: { name: 'job_search' } },
        
        // Geospatial index
        { fields: { 'location.coordinates': '2dsphere' }, options: { sparse: true } },
        
        // TTL index for auto-closing jobs
        { fields: { applicationDeadline: 1 }, options: { expireAfterSeconds: 86400, partialFilterExpression: { status: 'published' } } }
      ],
      
      // Application indexes (Recruitment)
      applications: [
        // Unique compound index
        { fields: { jobId: 1, candidateId: 1 }, options: { unique: true } },
        
        // Query optimization indexes
        { fields: { jobId: 1, status: 1 }, options: { name: 'application_job_status' } },
        { fields: { candidateId: 1, status: 1 }, options: { name: 'application_candidate_status' } },
        { fields: { status: 1, createdAt: -1 }, options: { name: 'application_status_date' } },
        { fields: { 'screening.score': -1 }, options: { name: 'application_score', sparse: true } }
      ],
      
      // Billing indexes
      subscriptions: [
        // Query optimization indexes
        { fields: { organizationId: 1, status: 1 }, options: { name: 'subscription_org_status' } },
        { fields: { status: 1, nextBillingDate: 1 }, options: { name: 'subscription_billing' } },
        { fields: { stripeSubscriptionId: 1 }, options: { unique: true, sparse: true } }
      ],
      
      invoices: [
        // Query optimization indexes
        { fields: { organizationId: 1, status: 1 }, options: { name: 'invoice_org_status' } },
        { fields: { status: 1, dueDate: 1 }, options: { name: 'invoice_due' } },
        { fields: { stripeInvoiceId: 1 }, options: { unique: true, sparse: true } }
      ],
      
      // Notification indexes
      notifications: [
        // Query optimization indexes
        { fields: { userId: 1, read: 1, createdAt: -1 }, options: { name: 'notification_user_unread' } },
        { fields: { organizationId: 1, type: 1 }, options: { name: 'notification_org_type' } },
        
        // TTL index for auto-deletion
        { fields: { expiresAt: 1 }, options: { expireAfterSeconds: 0, sparse: true } }
      ],
      
      // Audit log indexes
      auditLogs: [
        // Query optimization indexes
        { fields: { userId: 1, action: 1, timestamp: -1 }, options: { name: 'audit_user_action' } },
        { fields: { organizationId: 1, timestamp: -1 }, options: { name: 'audit_org_time' } },
        { fields: { entityType: 1, entityId: 1, timestamp: -1 }, options: { name: 'audit_entity' } },
        { fields: { ip: 1, timestamp: -1 }, options: { name: 'audit_ip_time' } },
        
        // TTL index for log retention
        { fields: { timestamp: 1 }, options: { expireAfterSeconds: 31536000 } } // 1 year
      ],
      
      // Webhook indexes
      webhooks: [
        // Query optimization indexes
        { fields: { organizationId: 1, active: 1 }, options: { name: 'webhook_org_active' } },
        { fields: { events: 1, active: 1 }, options: { name: 'webhook_events_active' } }
      ],
      
      // File/Media indexes
      files: [
        // Query optimization indexes
        { fields: { userId: 1, type: 1 }, options: { name: 'file_user_type' } },
        { fields: { organizationId: 1, type: 1 }, options: { name: 'file_org_type' } },
        { fields: { hash: 1 }, options: { name: 'file_hash' } },
        
        // TTL index for temporary files
        { fields: { expiresAt: 1 }, options: { expireAfterSeconds: 0, sparse: true } }
      ]
    };
  }
  
  /**
   * Create indexes for a collection
   * @param {Object} db - MongoDB database instance
   * @param {string} collectionName - Collection name
   * @returns {Promise<void>}
   */
  async createCollectionIndexes(db, collectionName) {
    const indexes = this.indexes[collectionName];
    if (!indexes) {
      logger.warn(`No indexes defined for collection: ${collectionName}`);
      return;
    }
    
    const collection = db.collection(collectionName);
    
    for (const index of indexes) {
      try {
        await collection.createIndex(index.fields, index.options);
        logger.info(`Created index on ${collectionName}`, {
          fields: index.fields,
          name: index.options.name
        });
      } catch (error) {
        // Index might already exist
        if (error.code === 85) {
          logger.debug(`Index already exists on ${collectionName}`, {
            name: index.options.name
          });
        } else {
          logger.error(`Failed to create index on ${collectionName}`, {
            fields: index.fields,
            error: error.message
          });
        }
      }
    }
  }
  
  /**
   * Create all indexes
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<void>}
   */
  async createAllIndexes(db) {
    logger.info('Starting database index creation');
    
    const collections = Object.keys(this.indexes);
    
    for (const collection of collections) {
      await this.createCollectionIndexes(db, collection);
    }
    
    logger.info('Database index creation completed');
  }
  
  /**
   * Drop all indexes (except _id)
   * @param {Object} db - MongoDB database instance
   * @param {string} collectionName - Collection name
   * @returns {Promise<void>}
   */
  async dropCollectionIndexes(db, collectionName) {
    try {
      const collection = db.collection(collectionName);
      await collection.dropIndexes();
      logger.info(`Dropped all indexes on ${collectionName}`);
    } catch (error) {
      logger.error(`Failed to drop indexes on ${collectionName}`, {
        error: error.message
      });
    }
  }
  
  /**
   * Reindex a collection
   * @param {Object} db - MongoDB database instance
   * @param {string} collectionName - Collection name
   * @returns {Promise<void>}
   */
  async reindexCollection(db, collectionName) {
    logger.info(`Reindexing collection: ${collectionName}`);
    
    // Drop existing indexes
    await this.dropCollectionIndexes(db, collectionName);
    
    // Recreate indexes
    await this.createCollectionIndexes(db, collectionName);
    
    logger.info(`Reindexing completed for: ${collectionName}`);
  }
  
  /**
   * Get index statistics
   * @param {Object} db - MongoDB database instance
   * @param {string} collectionName - Collection name
   * @returns {Promise<Array>} Index statistics
   */
  async getIndexStats(db, collectionName) {
    try {
      const collection = db.collection(collectionName);
      const stats = await collection.aggregate([
        { $indexStats: {} }
      ]).toArray();
      
      return stats.map(stat => ({
        name: stat.name,
        accesses: stat.accesses.ops,
        since: stat.accesses.since,
        size: stat.host ? stat.host.size : null
      }));
    } catch (error) {
      logger.error(`Failed to get index stats for ${collectionName}`, {
        error: error.message
      });
      return [];
    }
  }
  
  /**
   * Analyze index usage
   * @param {Object} db - MongoDB database instance
   * @returns {Promise<Object>} Index usage analysis
   */
  async analyzeIndexUsage(db) {
    const analysis = {};
    const collections = Object.keys(this.indexes);
    
    for (const collection of collections) {
      const stats = await this.getIndexStats(db, collection);
      
      analysis[collection] = {
        totalIndexes: stats.length,
        indexes: stats,
        unusedIndexes: stats.filter(s => s.accesses === 0).map(s => s.name),
        mostUsed: stats.sort((a, b) => b.accesses - a.accesses)[0]
      };
    }
    
    return analysis;
  }
  
  /**
   * Optimize indexes based on usage
   * @param {Object} db - MongoDB database instance
   * @param {Object} options - Optimization options
   * @returns {Promise<Object>} Optimization results
   */
  async optimizeIndexes(db, options = {}) {
    const {
      dropUnused = false,
      minAccesses = 100,
      analyzePeriodDays = 30
    } = options;
    
    const results = {
      analyzed: 0,
      optimized: 0,
      dropped: []
    };
    
    const analysis = await this.analyzeIndexUsage(db);
    
    for (const [collection, data] of Object.entries(analysis)) {
      results.analyzed++;
      
      if (dropUnused && data.unusedIndexes.length > 0) {
        for (const indexName of data.unusedIndexes) {
          // Don't drop critical indexes
          if (indexName === '_id_' || indexName.includes('unique')) {
            continue;
          }
          
          try {
            const coll = db.collection(collection);
            await coll.dropIndex(indexName);
            results.dropped.push(`${collection}.${indexName}`);
            results.optimized++;
            
            logger.info(`Dropped unused index`, {
              collection,
              index: indexName
            });
          } catch (error) {
            logger.error(`Failed to drop index`, {
              collection,
              index: indexName,
              error: error.message
            });
          }
        }
      }
    }
    
    return results;
  }
}

// Create singleton instance
const indexManager = new DatabaseIndexManager();

// Export manager and utility functions
module.exports = {
  indexManager,
  
  /**
   * Create all indexes
   * @param {Object} db - MongoDB database instance
   */
  createIndexes: async (db) => {
    await indexManager.createAllIndexes(db);
  },
  
  /**
   * Create indexes for specific collection
   * @param {Object} db - MongoDB database instance
   * @param {string} collection - Collection name
   */
  createCollectionIndexes: async (db, collection) => {
    await indexManager.createCollectionIndexes(db, collection);
  },
  
  /**
   * Analyze index usage
   * @param {Object} db - MongoDB database instance
   */
  analyzeUsage: async (db) => {
    return await indexManager.analyzeIndexUsage(db);
  },
  
  /**
   * Optimize indexes
   * @param {Object} db - MongoDB database instance
   * @param {Object} options - Optimization options
   */
  optimize: async (db, options) => {
    return await indexManager.optimizeIndexes(db, options);
  }
};