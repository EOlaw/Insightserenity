/**
 * @file Audit Repository
 * @description Data access layer for audit logs
 * @version 1.0.0
 */

const AuditLog = require('../models/audit-model');
const logger = require('../../utils/logger');

/**
 * Audit Repository Class
 * @class AuditRepository
 */
class AuditRepository {
  /**
   * Create a single audit log
   * @param {Object} auditData - Audit log data
   * @returns {Promise<Object>} Created audit log
   */
  async create(auditData) {
    try {
      const auditLog = new AuditLog(auditData);
      await auditLog.save();
      return auditLog.toObject();
    } catch (error) {
      logger.error('Failed to create audit log', {
        error: error.message,
        auditData
      });
      throw error;
    }
  }
  
  /**
   * Bulk insert audit logs
   * @param {Array<Object>} auditLogs - Array of audit logs
   * @returns {Promise<Object>} Bulk insert result
   */
  async bulkInsert(auditLogs) {
    try {
      return await AuditLog.bulkInsertWithValidation(auditLogs);
    } catch (error) {
      logger.error('Failed to bulk insert audit logs', {
        error: error.message,
        count: auditLogs.length
      });
      throw error;
    }
  }
  
  /**
   * Find audit log by ID
   * @param {string} id - Audit log ID
   * @returns {Promise<Object>} Audit log
   */
  async findById(id) {
    try {
      const auditLog = await AuditLog.findById(id)
        .populate('actor.userId', 'email firstName lastName')
        .populate('actor.organizationId', 'name')
        .lean();
      
      if (!auditLog) {
        return null;
      }
      
      // Decrypt changes if encrypted
      if (auditLog.security?.encryption?.enabled) {
        const model = new AuditLog(auditLog);
        auditLog.changes = await model.decryptChanges();
      }
      
      return auditLog;
    } catch (error) {
      logger.error('Failed to find audit log by ID', {
        error: error.message,
        id
      });
      throw error;
    }
  }
  
  /**
   * Query audit logs with filters and pagination
   * @param {Object} filters - Query filters
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Query results
   */
  async query(filters = {}, options = {}) {
    try {
      const {
        page = 1,
        limit = 50,
        sort = { timestamp: -1 },
        populate = true,
        decrypt = false
      } = options;
      
      const query = this.buildQuery(filters);
      const skip = (page - 1) * limit;
      
      // Build base query
      let mongoQuery = AuditLog.find(query)
        .sort(sort)
        .limit(limit)
        .skip(skip);
      
      // Add population if requested
      if (populate) {
        mongoQuery = mongoQuery
          .populate('actor.userId', 'email firstName lastName')
          .populate('actor.organizationId', 'name');
      }
      
      // Execute query and count
      const [results, total] = await Promise.all([
        mongoQuery.lean(),
        AuditLog.countDocuments(query)
      ]);
      
      // Decrypt sensitive fields if requested
      let processedResults = results;
      if (decrypt) {
        processedResults = await this.decryptResults(results);
      }
      
      return {
        results: processedResults,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
          hasNext: page < Math.ceil(total / limit),
          hasPrev: page > 1
        }
      };
    } catch (error) {
      logger.error('Failed to query audit logs', {
        error: error.message,
        filters,
        options
      });
      throw error;
    }
  }
  
  /**
   * Build MongoDB query from filters
   * @private
   * @param {Object} filters - Query filters
   * @returns {Object} MongoDB query
   */
  buildQuery(filters) {
    const query = {};
    
    // Event filters
    if (filters.eventType) {
      query['event.type'] = Array.isArray(filters.eventType) 
        ? { $in: filters.eventType }
        : filters.eventType;
    }
    
    if (filters.category) {
      query['event.category'] = Array.isArray(filters.category)
        ? { $in: filters.category }
        : filters.category;
    }
    
    if (filters.action) {
      query['event.action'] = new RegExp(filters.action, 'i');
    }
    
    if (filters.result) {
      query['event.result'] = filters.result;
    }
    
    if (filters.severity) {
      query['event.severity'] = Array.isArray(filters.severity)
        ? { $in: filters.severity }
        : filters.severity;
    }
    
    // Actor filters
    if (filters.userId) {
      query['actor.userId'] = filters.userId;
    }
    
    if (filters.userEmail) {
      query['actor.email'] = new RegExp(filters.userEmail, 'i');
    }
    
    if (filters.organizationId) {
      query.$or = [
        { 'actor.organizationId': filters.organizationId },
        { 'target.organizationId': filters.organizationId }
      ];
    }
    
    if (filters.ipAddress) {
      query['actor.ipAddress'] = filters.ipAddress;
    }
    
    // Target filters
    if (filters.targetType) {
      query['target.type'] = filters.targetType;
    }
    
    if (filters.targetId) {
      query['target.id'] = filters.targetId;
    }
    
    // Time range filters
    if (filters.startDate || filters.endDate) {
      query.timestamp = {};
      if (filters.startDate) {
        query.timestamp.$gte = new Date(filters.startDate);
      }
      if (filters.endDate) {
        query.timestamp.$lte = new Date(filters.endDate);
      }
    }
    
    // Security filters
    if (filters.minRiskScore !== undefined) {
      query['security.risk.score'] = { $gte: filters.minRiskScore };
    }
    
    if (filters.riskFactors) {
      query['security.risk.factors'] = { $in: filters.riskFactors };
    }
    
    if (filters.regulations) {
      query['security.compliance.regulations'] = { $in: filters.regulations };
    }
    
    // Context filters
    if (filters.requestId) {
      query['context.requestId'] = filters.requestId;
    }
    
    if (filters.correlationId) {
      query['context.correlationId'] = filters.correlationId;
    }
    
    if (filters.source) {
      query['context.source'] = filters.source;
    }
    
    // Retention filters
    if (filters.archived !== undefined) {
      query['retention.archived'] = filters.archived;
    }
    
    if (filters.retentionPolicy) {
      query['retention.policy'] = filters.retentionPolicy;
    }
    
    // Text search
    if (filters.search) {
      query.$text = { $search: filters.search };
    }
    
    return query;
  }
  
  /**
   * Decrypt results
   * @private
   * @param {Array<Object>} results - Query results
   * @returns {Promise<Array<Object>>} Decrypted results
   */
  async decryptResults(results) {
    const decryptedResults = [];
    
    for (const result of results) {
      if (result.security?.encryption?.enabled && result.changes) {
        const model = new AuditLog(result);
        const decryptedChanges = await model.decryptChanges();
        decryptedResults.push({
          ...result,
          changes: decryptedChanges
        });
      } else {
        decryptedResults.push(result);
      }
    }
    
    return decryptedResults;
  }
  
  /**
   * Get audit statistics
   * @param {Object} filters - Statistics filters
   * @returns {Promise<Object>} Audit statistics
   */
  async getStatistics(filters = {}) {
    try {
      const query = this.buildQuery(filters);
      
      const [
        totalCount,
        categoryCounts,
        severityCounts,
        resultCounts,
        topActors,
        topTargets,
        riskDistribution
      ] = await Promise.all([
        // Total count
        AuditLog.countDocuments(query),
        
        // Category distribution
        AuditLog.aggregate([
          { $match: query },
          { $group: { _id: '$event.category', count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ]),
        
        // Severity distribution
        AuditLog.aggregate([
          { $match: query },
          { $group: { _id: '$event.severity', count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ]),
        
        // Result distribution
        AuditLog.aggregate([
          { $match: query },
          { $group: { _id: '$event.result', count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ]),
        
        // Top actors
        AuditLog.aggregate([
          { $match: query },
          { $group: { 
            _id: '$actor.email',
            userId: { $first: '$actor.userId' },
            count: { $sum: 1 } 
          }},
          { $sort: { count: -1 } },
          { $limit: 10 }
        ]),
        
        // Top targets
        AuditLog.aggregate([
          { $match: query },
          { $group: { 
            _id: '$target.type',
            count: { $sum: 1 } 
          }},
          { $sort: { count: -1 } },
          { $limit: 10 }
        ]),
        
        // Risk distribution
        AuditLog.aggregate([
          { $match: query },
          { $group: {
            _id: {
              $cond: [
                { $lt: ['$security.risk.score', 25] }, 'low',
                { $cond: [
                  { $lt: ['$security.risk.score', 50] }, 'medium',
                  { $cond: [
                    { $lt: ['$security.risk.score', 75] }, 'high',
                    'critical'
                  ]}
                ]}
              ]
            },
            count: { $sum: 1 }
          }}
        ])
      ]);
      
      return {
        total: totalCount,
        byCategory: this.formatAggregationResult(categoryCounts),
        bySeverity: this.formatAggregationResult(severityCounts),
        byResult: this.formatAggregationResult(resultCounts),
        topActors: topActors.map(a => ({
          email: a._id,
          userId: a.userId,
          count: a.count
        })),
        topTargets: topTargets.map(t => ({
          type: t._id,
          count: t.count
        })),
        riskDistribution: this.formatAggregationResult(riskDistribution)
      };
    } catch (error) {
      logger.error('Failed to get audit statistics', {
        error: error.message,
        filters
      });
      throw error;
    }
  }
  
  /**
   * Format aggregation result
   * @private
   * @param {Array} result - Aggregation result
   * @returns {Object} Formatted result
   */
  formatAggregationResult(result) {
    return result.reduce((acc, item) => {
      acc[item._id] = item.count;
      return acc;
    }, {});
  }
  
  /**
   * Archive old audit logs
   * @param {number} daysOld - Days threshold
   * @returns {Promise<number>} Number of archived logs
   */
  async archiveOldLogs(daysOld = 365) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysOld);
      
      const result = await AuditLog.updateMany(
        {
          timestamp: { $lt: cutoffDate },
          'retention.archived': false,
          'retention.policy': { $ne: 'permanent' }
        },
        {
          $set: {
            'retention.archived': true,
            'retention.archivedAt': new Date()
          }
        }
      );
      
      logger.info('Archived old audit logs', {
        count: result.modifiedCount,
        cutoffDate
      });
      
      return result.modifiedCount;
    } catch (error) {
      logger.error('Failed to archive old logs', {
        error: error.message,
        daysOld
      });
      throw error;
    }
  }
  
  /**
   * Delete expired logs
   * @returns {Promise<number>} Number of deleted logs
   */
  async deleteExpiredLogs() {
    try {
      const result = await AuditLog.deleteMany({
        'retention.expiresAt': { $lt: new Date() },
        'retention.policy': { $ne: 'legal_hold' }
      });
      
      logger.info('Deleted expired audit logs', {
        count: result.deletedCount
      });
      
      return result.deletedCount;
    } catch (error) {
      logger.error('Failed to delete expired logs', {
        error: error.message
      });
      throw error;
    }
  }
  
  /**
   * Find logs by risk score
   * @param {number} minScore - Minimum risk score
   * @param {Object} options - Query options
   * @returns {Promise<Object>} High risk logs
   */
  async findHighRiskLogs(minScore = 70, options = {}) {
    return this.query(
      { minRiskScore: minScore },
      { ...options, sort: { 'security.risk.score': -1 } }
    );
  }
  
  /**
   * Find anomalous patterns
   * @param {string} userId - User ID
   * @param {number} hours - Time window in hours
   * @returns {Promise<Object>} Anomaly analysis
   */
  async findAnomalies(userId, hours = 24) {
    try {
      const since = new Date();
      since.setHours(since.getHours() - hours);
      
      const [
        userActivity,
        failureRate,
        unusualTargets
      ] = await Promise.all([
        // User activity pattern
        AuditLog.aggregate([
          {
            $match: {
              'actor.userId': userId,
              timestamp: { $gte: since }
            }
          },
          {
            $group: {
              _id: {
                hour: { $hour: '$timestamp' },
                action: '$event.action'
              },
              count: { $sum: 1 }
            }
          }
        ]),
        
        // Failure rate
        AuditLog.aggregate([
          {
            $match: {
              'actor.userId': userId,
              timestamp: { $gte: since }
            }
          },
          {
            $group: {
              _id: '$event.result',
              count: { $sum: 1 }
            }
          }
        ]),
        
        // Unusual targets
        AuditLog.aggregate([
          {
            $match: {
              'actor.userId': userId,
              timestamp: { $gte: since }
            }
          },
          {
            $group: {
              _id: '$target.type',
              count: { $sum: 1 },
              targets: { $addToSet: '$target.id' }
            }
          }
        ])
      ]);
      
      return {
        userId,
        timeWindow: { hours, since },
        activityPattern: userActivity,
        failureRate: this.formatAggregationResult(failureRate),
        targetAccess: unusualTargets
      };
    } catch (error) {
      logger.error('Failed to find anomalies', {
        error: error.message,
        userId,
        hours
      });
      throw error;
    }
  }
}

module.exports = AuditRepository;