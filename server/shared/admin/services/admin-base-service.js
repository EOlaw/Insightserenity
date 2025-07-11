/**
 * @file Admin Base Service
 * @description Base service class for all administrative services with standardized patterns
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const AuditService = require('../../../audit/services/audit-service');
const { CacheService } = require('../../../services/cache-service');
const AdminAuditLogger = require('../middleware/admin-audit-logging');
const EncryptionService = require('../../../security/services/encryption-service');
const logger = require('../../../utils/logger');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  BusinessRuleError 
} = require('../../../utils/app-error');

/**
 * Admin Base Service Class
 * @class AdminBaseService
 */
class AdminBaseService {
  /**
   * Constructor
   * @param {string} serviceName - Name of the service
   * @param {Object} model - Mongoose model
   * @param {Object} options - Service options
   */
  constructor(serviceName, model, options = {}) {
    this.serviceName = serviceName;
    this.model = model;
    this.modelName = model.modelName;
    this.options = {
      enableCache: true,
      cachePrefix: `admin:${serviceName}`,
      cacheTTL: 300, // 5 minutes
      enableAuditTrail: true,
      enableEncryption: true,
      sensitiveFields: [],
      requiredPermissions: {},
      bulkOperationLimit: 100,
      ...options
    };

    this.encryptionService = new EncryptionService();
    this.cache = this.options.enableCache ? new CacheService(this.options.cachePrefix) : null;
    
    // Initialize hooks
    this.initializeHooks();
  }

  /**
   * Initialize service hooks
   */
  initializeHooks() {
    this.hooks = {
      beforeCreate: [],
      afterCreate: [],
      beforeUpdate: [],
      afterUpdate: [],
      beforeDelete: [],
      afterDelete: [],
      beforeBulkOperation: [],
      afterBulkOperation: []
    };
  }

  /**
   * Register hook
   * @param {string} hookName - Hook name
   * @param {Function} handler - Hook handler
   */
  registerHook(hookName, handler) {
    if (this.hooks[hookName]) {
      this.hooks[hookName].push(handler);
    }
  }

  /**
   * Execute hooks
   * @param {string} hookName - Hook name
   * @param {Object} context - Hook context
   */
  async executeHooks(hookName, context) {
    if (!this.hooks[hookName]) return;

    for (const hook of this.hooks[hookName]) {
      await hook.call(this, context);
    }
  }

  /**
   * Find one document by ID with admin context
   * @param {string} id - Document ID
   * @param {Object} options - Query options
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Document
   */
  async findById(id, options = {}, context = {}) {
    try {
      logger.debug(`Admin ${this.serviceName}: Finding by ID`, { id, userId: context.userId });

      // Check cache first
      if (this.cache && !options.skipCache) {
        const cached = await this.cache.get(`${id}`);
        if (cached) {
          logger.debug(`Admin ${this.serviceName}: Cache hit`, { id });
          return cached;
        }
      }

      // Build query
      let query = this.model.findById(id);

      // Apply population
      if (options.populate) {
        const populations = Array.isArray(options.populate) ? options.populate : [options.populate];
        populations.forEach(pop => query = query.populate(pop));
      }

      // Apply field selection
      if (options.select) {
        query = query.select(options.select);
      }

      // Execute query
      const document = await query.lean();

      if (!document) {
        throw new NotFoundError(`${this.modelName} not found`);
      }

      // Decrypt sensitive fields if needed
      if (this.options.enableEncryption && this.options.sensitiveFields.length > 0) {
        this.decryptSensitiveFields(document);
      }

      // Cache result
      if (this.cache && !options.skipCache) {
        await this.cache.set(`${id}`, document, this.options.cacheTTL);
      }

      // Audit log
      if (this.options.enableAuditTrail) {
        await AdminAuditLogger.logAdminEvent({
          eventType: `admin_${this.serviceName}_viewed`,
          userId: context.userId,
          targetId: id,
          targetType: this.modelName,
          operation: 'read',
          metadata: {
            fields: options.select,
            populated: options.populate
          }
        });
      }

      return document;
    } catch (error) {
      logger.error(`Admin ${this.serviceName}: Error finding by ID`, {
        error: error.message,
        id,
        userId: context.userId
      });
      throw error;
    }
  }

  /**
   * Find documents with admin filters and pagination
   * @param {Object} filters - Query filters
   * @param {Object} options - Query options
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Paginated results
   */
  async find(filters = {}, options = {}, context = {}) {
    try {
      logger.debug(`Admin ${this.serviceName}: Finding documents`, {
        filters,
        options,
        userId: context.userId
      });

      // Apply default pagination
      const page = parseInt(options.page) || 1;
      const limit = Math.min(parseInt(options.limit) || 20, 100);
      const skip = (page - 1) * limit;

      // Build query
      let query = this.model.find(filters);

      // Apply sorting
      if (options.sort) {
        query = query.sort(options.sort);
      } else {
        query = query.sort('-createdAt');
      }

      // Apply population
      if (options.populate) {
        const populations = Array.isArray(options.populate) ? options.populate : [options.populate];
        populations.forEach(pop => query = query.populate(pop));
      }

      // Apply field selection
      if (options.select) {
        query = query.select(options.select);
      }

      // Execute count and paginated query
      const [total, documents] = await Promise.all([
        this.model.countDocuments(filters),
        query.skip(skip).limit(limit).lean()
      ]);

      // Decrypt sensitive fields
      if (this.options.enableEncryption && this.options.sensitiveFields.length > 0) {
        documents.forEach(doc => this.decryptSensitiveFields(doc));
      }

      // Build response
      const result = {
        data: documents,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit),
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1
        },
        filters: filters
      };

      // Audit log
      if (this.options.enableAuditTrail) {
        await AdminAuditLogger.logAdminEvent({
          eventType: `admin_${this.serviceName}_listed`,
          userId: context.userId,
          targetType: this.modelName,
          operation: 'list',
          metadata: {
            filters,
            resultCount: documents.length,
            totalCount: total,
            page,
            limit
          }
        });
      }

      return result;
    } catch (error) {
      logger.error(`Admin ${this.serviceName}: Error finding documents`, {
        error: error.message,
        filters,
        userId: context.userId
      });
      throw error;
    }
  }

  /**
   * Create document with admin context
   * @param {Object} data - Document data
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Created document
   */
  async create(data, context = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info(`Admin ${this.serviceName}: Creating document`, {
        userId: context.userId,
        dataKeys: Object.keys(data)
      });

      // Execute before create hooks
      await this.executeHooks('beforeCreate', { data, context });

      // Validate required fields
      await this.validateRequiredFields(data, 'create');

      // Add admin metadata
      const documentData = {
        ...data,
        createdBy: {
          userId: context.userId,
          adminRole: context.adminRole,
          reason: context.reason,
          method: 'admin_panel'
        },
        metadata: {
          ...data.metadata,
          createdViaAdmin: true,
          adminSessionId: context.sessionId
        }
      };

      // Encrypt sensitive fields
      if (this.options.enableEncryption && this.options.sensitiveFields.length > 0) {
        this.encryptSensitiveFields(documentData);
      }

      // Create document
      const document = await this.model.create([documentData], { session });
      const created = document[0].toObject();

      // Clear cache
      if (this.cache) {
        await this.cache.clearPattern('*');
      }

      // Execute after create hooks
      await this.executeHooks('afterCreate', { document: created, context });

      // Audit log with trail
      const auditTrail = AdminAuditLogger.createAuditTrail({
        name: `create_${this.modelName}`,
        userId: context.userId
      });

      await auditTrail.addStep({
        action: 'validate',
        result: 'success',
        details: { fieldsValidated: Object.keys(data) }
      });

      await auditTrail.addStep({
        action: 'create',
        result: 'success',
        details: { 
          documentId: created._id,
          fields: Object.keys(data)
        }
      });

      await auditTrail.complete('success');

      // Commit transaction
      await session.commitTransaction();

      // Decrypt for response
      if (this.options.enableEncryption && this.options.sensitiveFields.length > 0) {
        this.decryptSensitiveFields(created);
      }

      return created;
    } catch (error) {
      await session.abortTransaction();
      logger.error(`Admin ${this.serviceName}: Error creating document`, {
        error: error.message,
        userId: context.userId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Update document with admin context
   * @param {string} id - Document ID
   * @param {Object} updates - Update data
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Updated document
   */
  async update(id, updates, context = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info(`Admin ${this.serviceName}: Updating document`, {
        id,
        userId: context.userId,
        updateKeys: Object.keys(updates)
      });

      // Find existing document
      const existing = await this.model.findById(id).session(session);
      if (!existing) {
        throw new NotFoundError(`${this.modelName} not found`);
      }

      // Execute before update hooks
      await this.executeHooks('beforeUpdate', { 
        existing: existing.toObject(), 
        updates, 
        context 
      });

      // Track changes for audit
      const changes = this.trackChanges(existing.toObject(), updates);

      // Add admin metadata
      updates.lastModifiedBy = {
        userId: context.userId,
        adminRole: context.adminRole,
        reason: context.reason,
        timestamp: new Date()
      };

      // Update metadata
      updates.metadata = {
        ...existing.metadata,
        ...updates.metadata,
        lastAdminUpdate: new Date(),
        adminUpdateCount: (existing.metadata?.adminUpdateCount || 0) + 1
      };

      // Encrypt sensitive fields
      if (this.options.enableEncryption && this.options.sensitiveFields.length > 0) {
        this.encryptSensitiveFields(updates);
      }

      // Update document
      Object.assign(existing, updates);
      const updated = await existing.save({ session });

      // Clear cache
      if (this.cache) {
        await this.cache.delete(`${id}`);
        await this.cache.clearPattern('*');
      }

      // Execute after update hooks
      await this.executeHooks('afterUpdate', { 
        document: updated.toObject(), 
        changes, 
        context 
      });

      // Detailed audit log
      await AdminAuditLogger.logAdminEvent({
        eventType: `admin_${this.serviceName}_updated`,
        userId: context.userId,
        targetId: id,
        targetType: this.modelName,
        operation: 'update',
        changes,
        reason: context.reason,
        metadata: {
          fieldsUpdated: Object.keys(updates),
          previousValues: changes.map(c => ({ field: c.field, oldValue: c.oldValue })),
          sessionId: context.sessionId
        }
      });

      // Commit transaction
      await session.commitTransaction();

      const result = updated.toObject();
      
      // Decrypt for response
      if (this.options.enableEncryption && this.options.sensitiveFields.length > 0) {
        this.decryptSensitiveFields(result);
      }

      return result;
    } catch (error) {
      await session.abortTransaction();
      logger.error(`Admin ${this.serviceName}: Error updating document`, {
        error: error.message,
        id,
        userId: context.userId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Delete document with admin context
   * @param {string} id - Document ID
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Deleted document
   */
  async delete(id, context = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.warn(`Admin ${this.serviceName}: Deleting document`, {
        id,
        userId: context.userId,
        reason: context.reason
      });

      // Require reason for deletion
      if (!context.reason) {
        throw new ValidationError('Deletion reason is required for admin operations');
      }

      // Find document
      const document = await this.model.findById(id).session(session);
      if (!document) {
        throw new NotFoundError(`${this.modelName} not found`);
      }

      // Execute before delete hooks
      await this.executeHooks('beforeDelete', { 
        document: document.toObject(), 
        context 
      });

      // Create deletion record
      const deletionRecord = {
        documentId: id,
        documentType: this.modelName,
        documentData: document.toObject(),
        deletedBy: {
          userId: context.userId,
          adminRole: context.adminRole,
          reason: context.reason,
          timestamp: new Date()
        },
        metadata: context.metadata || {}
      };

      // Store deletion record (you would have a DeletionLog model)
      await AuditService.log({
        type: 'admin_deletion_record',
        action: 'delete',
        category: 'data_management',
        result: 'success',
        severity: 'high',
        userId: context.userId,
        target: {
          type: this.modelName,
          id: id
        },
        metadata: deletionRecord,
        retention: 'legal_hold' // Keep deletion records indefinitely
      });

      // Perform deletion
      await document.deleteOne({ session });

      // Clear cache
      if (this.cache) {
        await this.cache.delete(`${id}`);
        await this.cache.clearPattern('*');
      }

      // Execute after delete hooks
      await this.executeHooks('afterDelete', { 
        deletedDocument: document.toObject(), 
        context 
      });

      // Commit transaction
      await session.commitTransaction();

      return {
        success: true,
        message: `${this.modelName} deleted successfully`,
        deletedDocument: {
          _id: id,
          deletedAt: new Date(),
          deletedBy: context.userId,
          reason: context.reason
        }
      };
    } catch (error) {
      await session.abortTransaction();
      logger.error(`Admin ${this.serviceName}: Error deleting document`, {
        error: error.message,
        id,
        userId: context.userId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Bulk update documents
   * @param {Object} filter - Filter criteria
   * @param {Object} updates - Update data
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Bulk update result
   */
  async bulkUpdate(filter, updates, context = {}) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.warn(`Admin ${this.serviceName}: Bulk update operation`, {
        filter,
        updateKeys: Object.keys(updates),
        userId: context.userId
      });

      // Require reason for bulk operations
      if (!context.reason) {
        throw new ValidationError('Reason is required for bulk admin operations');
      }

      // Execute before bulk operation hooks
      await this.executeHooks('beforeBulkOperation', { 
        operation: 'update',
        filter, 
        updates, 
        context 
      });

      // Find affected documents
      const documents = await this.model.find(filter).session(session).lean();
      
      if (documents.length === 0) {
        throw new NotFoundError('No documents found matching criteria');
      }

      if (documents.length > this.options.bulkOperationLimit) {
        throw new BusinessRuleError(
          `Bulk operation limit exceeded. Maximum: ${this.options.bulkOperationLimit}, Found: ${documents.length}`
        );
      }

      // Create audit trail
      const auditTrail = AdminAuditLogger.createAuditTrail({
        name: `bulk_update_${this.modelName}`,
        userId: context.userId
      });

      await auditTrail.addStep({
        action: 'identify_targets',
        result: 'success',
        details: {
          filter,
          documentCount: documents.length,
          documentIds: documents.map(d => d._id)
        }
      });

      // Perform bulk update
      const updateData = {
        ...updates,
        lastModifiedBy: {
          userId: context.userId,
          adminRole: context.adminRole,
          reason: context.reason,
          timestamp: new Date(),
          bulkOperation: true
        }
      };

      const result = await this.model.updateMany(
        filter,
        { $set: updateData },
        { session }
      );

      await auditTrail.addStep({
        action: 'execute_update',
        result: 'success',
        details: {
          modifiedCount: result.modifiedCount,
          matchedCount: result.matchedCount
        }
      });

      // Clear cache
      if (this.cache) {
        await this.cache.clearPattern('*');
      }

      // Execute after bulk operation hooks
      await this.executeHooks('afterBulkOperation', { 
        operation: 'update',
        result, 
        context 
      });

      await auditTrail.complete('success');

      // Commit transaction
      await session.commitTransaction();

      return {
        success: true,
        matchedCount: result.matchedCount,
        modifiedCount: result.modifiedCount,
        documentIds: documents.map(d => d._id),
        updates: Object.keys(updates),
        performedBy: context.userId,
        reason: context.reason
      };
    } catch (error) {
      await session.abortTransaction();
      logger.error(`Admin ${this.serviceName}: Bulk update error`, {
        error: error.message,
        filter,
        userId: context.userId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Export data with admin privileges
   * @param {Object} filter - Filter criteria
   * @param {Object} options - Export options
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Export result
   */
  async export(filter = {}, options = {}, context = {}) {
    try {
      logger.info(`Admin ${this.serviceName}: Exporting data`, {
        filter,
        format: options.format || 'json',
        userId: context.userId
      });

      // Build query
      let query = this.model.find(filter);

      // Apply field selection
      if (options.fields) {
        query = query.select(options.fields.join(' '));
      }

      // Execute query
      const documents = await query.lean();

      // Decrypt sensitive fields if included
      if (this.options.enableEncryption && this.options.sensitiveFields.length > 0) {
        documents.forEach(doc => {
          // Only decrypt if explicitly requested
          if (options.includeSensitive && context.canViewSensitive) {
            this.decryptSensitiveFields(doc);
          } else {
            // Remove sensitive fields
            this.options.sensitiveFields.forEach(field => {
              delete doc[field];
            });
          }
        });
      }

      // Audit the export
      await AdminAuditLogger.logAdminEvent({
        eventType: 'admin_data_export',
        userId: context.userId,
        targetType: this.modelName,
        operation: 'export',
        metadata: {
          format: options.format || 'json',
          recordCount: documents.length,
          filter,
          fields: options.fields,
          includedSensitive: options.includeSensitive || false
        }
      });

      return {
        data: documents,
        metadata: {
          exportedAt: new Date(),
          exportedBy: context.userId,
          recordCount: documents.length,
          format: options.format || 'json'
        }
      };
    } catch (error) {
      logger.error(`Admin ${this.serviceName}: Export error`, {
        error: error.message,
        userId: context.userId
      });
      throw error;
    }
  }

  /**
   * Get service statistics
   * @param {Object} context - Admin context
   * @returns {Promise<Object>} Service statistics
   */
  async getStatistics(context = {}) {
    try {
      const stats = await this.model.aggregate([
        {
          $facet: {
            total: [{ $count: 'count' }],
            byStatus: [
              { $group: { _id: '$status', count: { $sum: 1 } } }
            ],
            recentActivity: [
              { $match: { createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
              { $count: 'count' }
            ],
            byMonth: [
              {
                $group: {
                  _id: {
                    year: { $year: '$createdAt' },
                    month: { $month: '$createdAt' }
                  },
                  count: { $sum: 1 }
                }
              },
              { $sort: { '_id.year': -1, '_id.month': -1 } },
              { $limit: 12 }
            ]
          }
        }
      ]);

      const result = {
        total: stats[0].total[0]?.count || 0,
        byStatus: stats[0].byStatus.reduce((acc, item) => {
          acc[item._id] = item.count;
          return acc;
        }, {}),
        last24Hours: stats[0].recentActivity[0]?.count || 0,
        monthlyTrend: stats[0].byMonth.map(item => ({
          month: `${item._id.year}-${String(item._id.month).padStart(2, '0')}`,
          count: item.count
        }))
      };

      // Cache statistics
      if (this.cache) {
        await this.cache.set('statistics', result, 3600); // 1 hour
      }

      return result;
    } catch (error) {
      logger.error(`Admin ${this.serviceName}: Error getting statistics`, {
        error: error.message,
        userId: context.userId
      });
      throw error;
    }
  }

  /**
   * Validate required fields
   * @param {Object} data - Data to validate
   * @param {string} operation - Operation type
   */
  async validateRequiredFields(data, operation) {
    const requiredFields = this.options.requiredFields[operation] || [];
    const missingFields = requiredFields.filter(field => !data[field]);

    if (missingFields.length > 0) {
      throw new ValidationError(`Missing required fields: ${missingFields.join(', ')}`);
    }
  }

  /**
   * Track changes between documents
   * @param {Object} original - Original document
   * @param {Object} updates - Updates
   * @returns {Array} Changes
   */
  trackChanges(original, updates) {
    const changes = [];

    for (const [key, value] of Object.entries(updates)) {
      if (key.startsWith('_') || key === 'metadata') continue;

      const originalValue = original[key];
      if (JSON.stringify(originalValue) !== JSON.stringify(value)) {
        changes.push({
          field: key,
          oldValue: originalValue,
          newValue: value,
          changedAt: new Date()
        });
      }
    }

    return changes;
  }

  /**
   * Encrypt sensitive fields
   * @param {Object} data - Data object
   */
  encryptSensitiveFields(data) {
    for (const field of this.options.sensitiveFields) {
      if (data[field] !== undefined && data[field] !== null) {
        data[field] = this.encryptionService.encryptField(data[field], field);
      }
    }
  }

  /**
   * Decrypt sensitive fields
   * @param {Object} data - Data object
   */
  decryptSensitiveFields(data) {
    for (const field of this.options.sensitiveFields) {
      if (data[field]) {
        try {
          data[field] = this.encryptionService.decryptField(data[field]);
        } catch (error) {
          logger.error(`Failed to decrypt field ${field}`, { error: error.message });
          data[field] = '[DECRYPTION_ERROR]';
        }
      }
    }
  }

  /**
   * Clear all caches for this service
   */
  async clearCache() {
    if (this.cache) {
      await this.cache.clearPattern('*');
      logger.info(`Admin ${this.serviceName}: Cache cleared`);
    }
  }
}

module.exports = AdminBaseService;