// // server/shared/security/services/audit-service.js
// /**
//  * @file Audit Service
//  * @description Comprehensive audit logging and compliance tracking
//  * @version 3.0.0
//  */

// const mongoose = require('mongoose');

// const config = require('../../config/config');
// const logger = require('../../utils/logger');

// const EncryptionService = require('./encryption-service');

// /**
//  * Audit Log Schema
//  */
// const auditLogSchema = new mongoose.Schema({
//   // Event identification
//   eventId: {
//     type: String,
//     required: true,
//     unique: true,
//     default: () => EncryptionService.generateToken(16)
//   },
  
//   // Event details
//   event: {
//     type: {
//       type: String,
//       required: true,
//       index: true
//     },
//     category: {
//       type: String,
//       required: true,
//       enum: ['authentication', 'authorization', 'data_access', 'data_modification', 
//               'configuration', 'security', 'compliance', 'system'],
//       index: true
//     },
//     action: {
//       type: String,
//       required: true,
//       index: true
//     },
//     result: {
//       type: String,
//       required: true,
//       enum: ['success', 'failure', 'error', 'blocked'],
//       index: true
//     },
//     severity: {
//       type: String,
//       enum: ['low', 'medium', 'high', 'critical'],
//       default: 'medium'
//     }
//   },
  
//   // Actor information
//   actor: {
//     userId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'User',
//       index: true
//     },
//     email: String,
//     role: String,
//     organizationId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'Organization',
//       index: true
//     },
//     ipAddress: {
//       type: String,
//       index: true
//     },
//     userAgent: String,
//     sessionId: String
//   },
  
//   // Target information
//   target: {
//     type: {
//       type: String,
//       index: true
//     },
//     id: {
//       type: String,
//       index: true
//     },
//     name: String,
//     organizationId: {
//       type: mongoose.Schema.Types.ObjectId,
//       ref: 'Organization'
//     }
//   },
  
//   // Change details
//   changes: {
//     before: mongoose.Schema.Types.Mixed,
//     after: mongoose.Schema.Types.Mixed,
//     fields: [String]
//   },
  
//   // Metadata
//   metadata: {
//     requestId: String,
//     correlationId: String,
//     source: String,
//     version: String,
//     environment: String
//   },
  
//   // Security context
//   security: {
//     risk: {
//       score: Number,
//       factors: [String]
//     },
//     compliance: {
//       regulations: [String],
//       controls: [String]
//     },
//     encryption: {
//       enabled: { type: Boolean, default: false },
//       algorithm: String
//     }
//   },
  
//   // Timestamps
//   timestamp: {
//     type: Date,
//     required: true,
//     default: Date.now,
//     index: true
//   },
  
//   // Retention
//   retention: {
//     expiresAt: Date,
//     archived: { type: Boolean, default: false },
//     archivedAt: Date
//   }
// }, {
//   collection: 'audit_logs',
//   timestamps: false
// });

// // Indexes
// auditLogSchema.index({ 'event.type': 1, timestamp: -1 });
// auditLogSchema.index({ 'actor.userId': 1, timestamp: -1 });
// auditLogSchema.index({ 'target.type': 1, 'target.id': 1, timestamp: -1 });
// auditLogSchema.index({ 'retention.expiresAt': 1 }, { expireAfterSeconds: 0 });

// // Encrypt sensitive fields before saving
// auditLogSchema.pre('save', function(next) {
//   if (this.security.encryption.enabled && this.changes) {
//     if (this.changes.before) {
//       this.changes.before = EncryptionService.encryptField(
//         this.changes.before,
//         'audit_changes_before'
//       );
//     }
//     if (this.changes.after) {
//       this.changes.after = EncryptionService.encryptField(
//         this.changes.after,
//         'audit_changes_after'
//       );
//     }
//   }
//   next();
// });

// const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// /**
//  * Audit Service Class
//  * @class AuditService
//  */
// class AuditService {
//   constructor() {
//     this.queue = [];
//     this.batchSize = 100;
//     this.flushInterval = 5000; // 5 seconds
    
//     // Start batch processor
//     this.startBatchProcessor();
    
//     // Compliance mappings
//     this.complianceMap = {
//       GDPR: ['data_access', 'data_modification', 'data_deletion', 'consent'],
//       HIPAA: ['health_data_access', 'health_data_modification', 'authentication'],
//       PCI: ['payment_data_access', 'payment_method_modification', 'authentication'],
//       SOC2: ['access_control', 'data_security', 'availability', 'confidentiality']
//     };
//   }
  
//   /**
//    * Log audit event
//    * @param {Object} eventData - Event data
//    * @returns {Promise<AuditLog>} Created audit log
//    */
//   async log(eventData) {
//     try {
//       const auditEntry = {
//         event: {
//           type: eventData.type || eventData.action,
//           category: eventData.category || this.categorizeEvent(eventData.type),
//           action: eventData.action,
//           result: eventData.result || 'success',
//           severity: eventData.severity || this.calculateSeverity(eventData)
//         },
        
//         actor: {
//           userId: eventData.userId,
//           email: eventData.userEmail,
//           role: eventData.userRole,
//           organizationId: eventData.organizationId,
//           ipAddress: eventData.ipAddress,
//           userAgent: eventData.userAgent,
//           sessionId: eventData.sessionId
//         },
        
//         target: eventData.target || {},
        
//         changes: eventData.changes || {},
        
//         metadata: {
//           requestId: eventData.requestId,
//           correlationId: eventData.correlationId,
//           source: eventData.source || 'api',
//           version: config.deployment.version,
//           environment: config.env
//         },
        
//         security: {
//           risk: this.assessRisk(eventData),
//           compliance: this.mapCompliance(eventData),
//           encryption: {
//             enabled: this.shouldEncrypt(eventData),
//             algorithm: config.security.encryption.algorithm
//           }
//         },
        
//         retention: this.calculateRetention(eventData)
//       };
      
//       // Add to queue for batch processing
//       this.queue.push(auditEntry);
      
//       // Flush immediately for critical events
//       if (auditEntry.event.severity === 'critical') {
//         await this.flush();
//       }
      
//       // Also log to application logger for real-time monitoring
//       logger.audit(auditEntry.event.action, {
//         ...auditEntry,
//         audit: true
//       });
      
//       return auditEntry;
//     } catch (error) {
//       logger.error('Audit logging failed', {
//         error: error.message,
//         eventData
//       });
//       // Don't throw - audit failures shouldn't break the application
//     }
//   }
  
//   /**
//    * Categorize event type
//    * @param {string} eventType - Event type
//    * @returns {string} Event category
//    */
//   categorizeEvent(eventType) {
//     const categories = {
//       authentication: ['login', 'logout', 'password_reset', 'mfa_', '2fa_'],
//       authorization: ['permission_', 'role_', 'access_denied'],
//       data_access: ['view_', 'read_', 'list_', 'search_', 'export_'],
//       data_modification: ['create_', 'update_', 'delete_', 'import_'],
//       configuration: ['config_', 'settings_', 'preference_'],
//       security: ['security_', 'threat_', 'vulnerability_', 'encryption_'],
//       compliance: ['compliance_', 'audit_', 'regulation_'],
//       system: ['system_', 'startup', 'shutdown', 'error_', 'performance_']
//     };
    
//     for (const [category, patterns] of Object.entries(categories)) {
//       if (patterns.some(pattern => eventType.toLowerCase().includes(pattern))) {
//         return category;
//       }
//     }
    
//     return 'system';
//   }
  
//   /**
//    * Calculate event severity
//    * @param {Object} eventData - Event data
//    * @returns {string} Severity level
//    */
//   calculateSeverity(eventData) {
//     // Critical events
//     if (eventData.type.includes('security_breach') ||
//         eventData.type.includes('data_leak') ||
//         eventData.result === 'blocked') {
//       return 'critical';
//     }
    
//     // High severity events
//     if (eventData.type.includes('unauthorized_access') ||
//         eventData.type.includes('permission_escalation') ||
//         eventData.type.includes('delete_') ||
//         eventData.result === 'failure' && eventData.category === 'security') {
//       return 'high';
//     }
    
//     // Low severity events
//     if (eventData.type.includes('view_') ||
//         eventData.type.includes('list_') ||
//         eventData.category === 'data_access') {
//       return 'low';
//     }
    
//     return 'medium';
//   }
  
//   /**
//    * Assess security risk
//    * @param {Object} eventData - Event data
//    * @returns {Object} Risk assessment
//    */
//   assessRisk(eventData) {
//     let score = 0;
//     const factors = [];
    
//     // Failed authentication attempts
//     if (eventData.type === 'login_failed') {
//       score += 20;
//       factors.push('failed_authentication');
//     }
    
//     // Unusual location
//     if (eventData.unusualLocation) {
//       score += 30;
//       factors.push('unusual_location');
//     }
    
//     // After hours access
//     const hour = new Date().getHours();
//     if (hour < 6 || hour > 22) {
//       score += 10;
//       factors.push('after_hours');
//     }
    
//     // Sensitive data access
//     if (eventData.target?.type === 'payment_method' ||
//         eventData.target?.type === 'personal_data') {
//       score += 25;
//       factors.push('sensitive_data');
//     }
    
//     // Bulk operations
//     if (eventData.bulk || eventData.count > 100) {
//       score += 15;
//       factors.push('bulk_operation');
//     }
    
//     return { score: Math.min(score, 100), factors };
//   }
  
//   /**
//    * Map compliance requirements
//    * @param {Object} eventData - Event data
//    * @returns {Object} Compliance mapping
//    */
//   mapCompliance(eventData) {
//     const regulations = [];
//     const controls = [];
    
//     // GDPR compliance
//     if (eventData.target?.type === 'personal_data' ||
//         eventData.type.includes('consent') ||
//         eventData.type.includes('data_deletion')) {
//       regulations.push('GDPR');
//       controls.push('data_protection', 'user_rights');
//     }
    
//     // PCI compliance
//     if (eventData.target?.type === 'payment_method' ||
//         eventData.type.includes('payment')) {
//       regulations.push('PCI-DSS');
//       controls.push('payment_security', 'encryption');
//     }
    
//     // SOC2 compliance
//     if (eventData.category === 'security' ||
//         eventData.category === 'authentication') {
//       regulations.push('SOC2');
//       controls.push('access_control', 'security_monitoring');
//     }
    
//     return { regulations, controls };
//   }
  
//   /**
//    * Determine if event should be encrypted
//    * @param {Object} eventData - Event data
//    * @returns {boolean} Should encrypt
//    */
//   shouldEncrypt(eventData) {
//     return eventData.category === 'data_modification' ||
//            eventData.target?.type === 'payment_method' ||
//            eventData.target?.type === 'personal_data' ||
//            eventData.containsSensitiveData;
//   }
  
//   /**
//    * Calculate retention period
//    * @param {Object} eventData - Event data
//    * @returns {Object} Retention settings
//    */
//   calculateRetention(eventData) {
//     let retentionDays = 90; // Default 90 days
    
//     // Compliance requirements
//     if (eventData.security?.compliance?.regulations?.includes('GDPR')) {
//       retentionDays = 365 * 3; // 3 years for GDPR
//     }
    
//     if (eventData.security?.compliance?.regulations?.includes('PCI-DSS')) {
//       retentionDays = 365 * 2; // 2 years for PCI
//     }
    
//     // Security events - longer retention
//     if (eventData.category === 'security' || 
//         eventData.event?.severity === 'critical') {
//       retentionDays = 365 * 5; // 5 years
//     }
    
//     // Calculate expiry date
//     const expiresAt = new Date();
//     expiresAt.setDate(expiresAt.getDate() + retentionDays);
    
//     return { expiresAt };
//   }
  
//   /**
//    * Start batch processor
//    */
//   startBatchProcessor() {
//     setInterval(async () => {
//       if (this.queue.length > 0) {
//         await this.flush();
//       }
//     }, this.flushInterval);
    
//     // Handle process shutdown
//     process.on('SIGINT', async () => {
//       await this.flush();
//     });
//   }
  
//   /**
//    * Flush audit queue
//    */
//   async flush() {
//     if (this.queue.length === 0) return;
    
//     const batch = this.queue.splice(0, this.batchSize);
    
//     try {
//       await AuditLog.insertMany(batch, { ordered: false });
//       logger.debug(`Flushed ${batch.length} audit logs`);
//     } catch (error) {
//       logger.error('Failed to flush audit logs', {
//         error: error.message,
//         count: batch.length
//       });
      
//       // Re-queue failed items
//       this.queue.unshift(...batch);
//     }
//   }
  
//   /**
//    * Query audit logs
//    * @param {Object} filters - Query filters
//    * @param {Object} options - Query options
//    * @returns {Promise<Object>} Query results
//    */
//   async query(filters = {}, options = {}) {
//     const {
//       page = 1,
//       limit = 50,
//       sort = { timestamp: -1 }
//     } = options;
    
//     const query = this.buildQuery(filters);
    
//     const [results, total] = await Promise.all([
//       AuditLog.find(query)
//         .sort(sort)
//         .limit(limit)
//         .skip((page - 1) * limit)
//         .populate('actor.userId', 'email firstName lastName')
//         .populate('actor.organizationId', 'name')
//         .lean(),
//       AuditLog.countDocuments(query)
//     ]);
    
//     // Decrypt sensitive fields if needed
//     const decryptedResults = results.map(log => {
//       if (log.security?.encryption?.enabled && log.changes) {
//         return {
//           ...log,
//           changes: {
//             before: EncryptionService.decryptField(log.changes.before),
//             after: EncryptionService.decryptField(log.changes.after),
//             fields: log.changes.fields
//           }
//         };
//       }
//       return log;
//     });
    
//     return {
//       results: decryptedResults,
//       pagination: {
//         page,
//         limit,
//         total,
//         pages: Math.ceil(total / limit)
//       }
//     };
//   }
  
//   /**
//    * Build query from filters
//    * @param {Object} filters - Query filters
//    * @returns {Object} MongoDB query
//    */
//   buildQuery(filters) {
//     const query = {};
    
//     if (filters.eventType) {
//       query['event.type'] = filters.eventType;
//     }
    
//     if (filters.category) {
//       query['event.category'] = filters.category;
//     }
    
//     if (filters.userId) {
//       query['actor.userId'] = filters.userId;
//     }
    
//     if (filters.organizationId) {
//       query.$or = [
//         { 'actor.organizationId': filters.organizationId },
//         { 'target.organizationId': filters.organizationId }
//       ];
//     }
    
//     if (filters.startDate || filters.endDate) {
//       query.timestamp = {};
//       if (filters.startDate) {
//         query.timestamp.$gte = new Date(filters.startDate);
//       }
//       if (filters.endDate) {
//         query.timestamp.$lte = new Date(filters.endDate);
//       }
//     }
    
//     if (filters.severity) {
//       query['event.severity'] = filters.severity;
//     }
    
//     if (filters.result) {
//       query['event.result'] = filters.result;
//     }
    
//     return query;
//   }
  
//   /**
//    * Generate compliance report
//    * @param {string} regulation - Regulation type
//    * @param {Date} startDate - Report start date
//    * @param {Date} endDate - Report end date
//    * @returns {Promise<Object>} Compliance report
//    */
//   async generateComplianceReport(regulation, startDate, endDate) {
//     const events = await AuditLog.find({
//       'security.compliance.regulations': regulation,
//       timestamp: {
//         $gte: startDate,
//         $lte: endDate
//       }
//     }).lean();
    
//     const report = {
//       regulation,
//       period: { startDate, endDate },
//       summary: {
//         totalEvents: events.length,
//         byCategory: {},
//         bySeverity: {},
//         byResult: {}
//       },
//       events: []
//     };
    
//     // Analyze events
//     events.forEach(event => {
//       // Category breakdown
//       report.summary.byCategory[event.event.category] = 
//         (report.summary.byCategory[event.event.category] || 0) + 1;
      
//       // Severity breakdown
//       report.summary.bySeverity[event.event.severity] = 
//         (report.summary.bySeverity[event.event.severity] || 0) + 1;
      
//       // Result breakdown
//       report.summary.byResult[event.event.result] = 
//         (report.summary.byResult[event.event.result] || 0) + 1;
      
//       // Add sanitized event
//       report.events.push({
//         timestamp: event.timestamp,
//         type: event.event.type,
//         category: event.event.category,
//         result: event.event.result,
//         actor: event.actor.email || event.actor.userId,
//         target: `${event.target.type}:${event.target.id}`
//       });
//     });
    
//     return report;
//   }
  
//   /**
//    * Archive old audit logs
//    * @param {number} daysOld - Days threshold
//    * @returns {Promise<number>} Number of archived logs
//    */
//   async archiveOldLogs(daysOld = 365) {
//     const cutoffDate = new Date();
//     cutoffDate.setDate(cutoffDate.getDate() - daysOld);
    
//     const result = await AuditLog.updateMany(
//       {
//         timestamp: { $lt: cutoffDate },
//         'retention.archived': false
//       },
//       {
//         $set: {
//           'retention.archived': true,
//           'retention.archivedAt': new Date()
//         }
//       }
//     );
    
//     logger.info('Archived old audit logs', {
//       count: result.modifiedCount,
//       cutoffDate
//     });
    
//     return result.modifiedCount;
//   }
// }

// // Create and export singleton instance
// module.exports = new AuditService();