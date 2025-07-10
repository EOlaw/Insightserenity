/**
 * @file Audit Log Model
 * @description Mongoose schema and model for audit logs
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const EncryptionService = require('../../security/services/encryption-service');

/**
 * Audit Log Schema
 */
const auditLogSchema = new mongoose.Schema({
  // Event identification
  eventId: {
    type: String,
    required: true,
    unique: true,
    index: true,
    default: () => EncryptionService.generateToken(16)
  },
  
  // Event details
  event: {
    type: {
      type: String,
      required: true,
      index: true
    },
    category: {
      type: String,
      required: true,
      enum: ['authentication', 'authorization', 'data_access', 'data_modification', 
              'configuration', 'security', 'compliance', 'system'],
      index: true
    },
    action: {
      type: String,
      required: true,
      index: true
    },
    result: {
      type: String,
      required: true,
      enum: ['success', 'failure', 'error', 'blocked'],
      index: true
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium'
    },
    description: {
      type: String,
      maxLength: 500
    }
  },
  
  // Actor information
  actor: {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      index: true
    },
    email: {
      type: String,
      index: true
    },
    role: String,
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization',
      index: true
    },
    ipAddress: {
      type: String,
      index: true
    },
    userAgent: String,
    sessionId: String,
    location: {
      country: String,
      city: String,
      region: String
    }
  },
  
  // Target information
  target: {
    type: {
      type: String,
      index: true
    },
    id: {
      type: String,
      index: true
    },
    name: String,
    organizationId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Organization'
    },
    metadata: mongoose.Schema.Types.Mixed
  },
  
  // Change details
  changes: {
    before: mongoose.Schema.Types.Mixed,
    after: mongoose.Schema.Types.Mixed,
    fields: [String],
    summary: String
  },
  
  // Request context
  context: {
    requestId: {
      type: String,
      index: true
    },
    correlationId: String,
    source: {
      type: String,
      enum: ['api', 'web', 'mobile', 'system', 'integration'],
      default: 'api'
    },
    endpoint: String,
    method: String,
    duration: Number,
    version: String,
    environment: String
  },
  
  // Security and compliance
  security: {
    risk: {
      score: {
        type: Number,
        min: 0,
        max: 100
      },
      factors: [String],
      anomalies: [String]
    },
    compliance: {
      regulations: [String],
      controls: [String],
      violations: [String]
    },
    encryption: {
      enabled: { type: Boolean, default: false },
      algorithm: String,
      keyVersion: String
    },
    integrity: {
      hash: String,
      signature: String
    }
  },
  
  // Timestamps
  timestamp: {
    type: Date,
    required: true,
    default: Date.now,
    index: true
  },
  
  // Retention and archival
  retention: {
    policy: {
      type: String,
      enum: ['standard', 'extended', 'permanent', 'legal_hold'],
      default: 'standard'
    },
    expiresAt: {
      type: Date,
      index: true
    },
    archived: { 
      type: Boolean, 
      default: false,
      index: true
    },
    archivedAt: Date,
    archiveLocation: String
  },
  
  // Additional metadata
  metadata: {
    tags: [String],
    customFields: mongoose.Schema.Types.Mixed,
    processed: { type: Boolean, default: false },
    processedAt: Date
  }
}, {
  collection: 'audit_logs',
  timestamps: true,
  strict: true
});

// Compound indexes for common queries
auditLogSchema.index({ 'event.type': 1, timestamp: -1 });
auditLogSchema.index({ 'actor.userId': 1, timestamp: -1 });
auditLogSchema.index({ 'actor.organizationId': 1, timestamp: -1 });
auditLogSchema.index({ 'target.type': 1, 'target.id': 1, timestamp: -1 });
auditLogSchema.index({ 'context.requestId': 1 });
auditLogSchema.index({ 'security.compliance.regulations': 1, timestamp: -1 });
auditLogSchema.index({ 'retention.expiresAt': 1 }, { expireAfterSeconds: 0 });
auditLogSchema.index({ 'retention.archived': 1, 'retention.policy': 1 });

// Text index for searching
auditLogSchema.index({ 
  'event.action': 'text', 
  'event.description': 'text',
  'changes.summary': 'text' 
});

// Pre-save middleware for encryption
auditLogSchema.pre('save', async function(next) {
  try {
    // Encrypt sensitive fields if encryption is enabled
    if (this.security.encryption.enabled) {
      if (this.changes?.before) {
        this.changes.before = await EncryptionService.encryptField(
          this.changes.before,
          'audit_changes'
        );
      }
      if (this.changes?.after) {
        this.changes.after = await EncryptionService.encryptField(
          this.changes.after,
          'audit_changes'
        );
      }
    }
    
    // Generate integrity hash
    if (!this.security.integrity.hash) {
      const dataToHash = JSON.stringify({
        event: this.event,
        actor: this.actor,
        target: this.target,
        timestamp: this.timestamp
      });
      this.security.integrity.hash = EncryptionService.hash(dataToHash);
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

// Virtual for age calculation
auditLogSchema.virtual('age').get(function() {
  return Date.now() - this.timestamp.getTime();
});

// Instance method to decrypt changes
auditLogSchema.methods.decryptChanges = async function() {
  if (!this.security.encryption.enabled) {
    return this.changes;
  }
  
  return {
    before: this.changes.before ? 
      await EncryptionService.decryptField(this.changes.before) : null,
    after: this.changes.after ? 
      await EncryptionService.decryptField(this.changes.after) : null,
    fields: this.changes.fields,
    summary: this.changes.summary
  };
};

// Instance method to check compliance
auditLogSchema.methods.isCompliantWith = function(regulation) {
  return this.security.compliance.regulations.includes(regulation);
};

// Static method for bulk insert with validation
auditLogSchema.statics.bulkInsertWithValidation = async function(logs) {
  const validLogs = [];
  const errors = [];
  
  for (const log of logs) {
    try {
      const validLog = new this(log);
      await validLog.validate();
      validLogs.push(validLog.toObject());
    } catch (error) {
      errors.push({ log, error: error.message });
    }
  }
  
  if (validLogs.length > 0) {
    await this.insertMany(validLogs, { ordered: false });
  }
  
  return { inserted: validLogs.length, errors };
};

// Export model
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

module.exports = AuditLog;