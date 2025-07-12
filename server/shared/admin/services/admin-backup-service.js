/**
 * @file Admin Backup Service
 * @description Comprehensive backup and restore service for administrative data and system configurations
 * @version 1.0.0
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const archiver = require('archiver');
const extract = require('extract-zip');
const mongoose = require('mongoose');

const AdminBaseService = require('./admin-base-service');
const config = require('../../../shared/config/config');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { FileService } = require('../../../shared/services/file-service');

// Import admin models
const AdminActionLog = require('../models/admin-action-log-model');
const AdminSession = require('../models/admin-session-model');
const AdminPreference = require('../models/admin-preference-model');
const AdminNotification = require('../models/admin-notification-model');

// Import shared models that admins might need to backup
const User = require('../../../shared/users/models/user-model');
const Organization = require('../../../hosted-organizations/organizations/models/organization-model');

/**
 * Admin Backup Service Class
 * Handles backup and restore operations for administrative data
 */
class AdminBackupService extends AdminBaseService {
  constructor() {
    super('AdminBackupService');
    
    this.backupConfig = {
      baseDirectory: config.backup?.directory || './backups',
      compression: config.backup?.compression || 'zip',
      encryption: config.backup?.encryption || true,
      retention: {
        daily: config.backup?.retention?.daily || 7,
        weekly: config.backup?.retention?.weekly || 4,
        monthly: config.backup?.retention?.monthly || 12
      },
      chunkSize: config.backup?.chunkSize || 50 * 1024 * 1024, // 50MB chunks
      maxBackupSize: config.backup?.maxSize || 10 * 1024 * 1024 * 1024 // 10GB max
    };
    
    this.backupTypes = {
      FULL: 'full',
      INCREMENTAL: 'incremental',
      DIFFERENTIAL: 'differential',
      ADMIN_ONLY: 'admin_only',
      CONFIGURATION: 'configuration'
    };
    
    this.initializeBackupService();
  }
  
  /**
   * Initialize backup service
   * @private
   */
  async initializeBackupService() {
    try {
      // Ensure backup directory exists
      await this.ensureBackupDirectory();
      
      // Initialize backup metadata tracking
      this.backupMetadata = new Map();
      
      logger.info('Admin backup service initialized', {
        baseDirectory: this.backupConfig.baseDirectory,
        encryption: this.backupConfig.encryption
      });
      
    } catch (error) {
      logger.error('Failed to initialize backup service', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Create a full backup of administrative data
   * @param {Object} context - Operation context
   * @param {Object} options - Backup options
   * @returns {Promise<Object>} Backup information
   */
  async createFullBackup(context, options = {}) {
    return this.executeOperation('backup.create.full', async () => {
      const {
        includeUserData = false,
        includeOrganizations = false,
        includeConfigurations = true,
        compression = true,
        encryption = true,
        description = 'Full administrative backup'
      } = options;
      
      const backupId = this.generateBackupId('full');
      const backupPath = await this.createBackupDirectory(backupId);
      
      logger.info('Starting full backup creation', {
        backupId,
        options: { includeUserData, includeOrganizations, includeConfigurations }
      });
      
      const session = await this.startTransaction();
      
      try {
        const backupManifest = {
          id: backupId,
          type: this.backupTypes.FULL,
          createdBy: context.userId,
          createdAt: new Date(),
          description,
          options,
          collections: [],
          files: [],
          integrity: {},
          metadata: {
            version: '1.0.0',
            environment: config.nodeEnv,
            nodeVersion: process.version,
            mongoVersion: await this.getMongoVersion()
          }
        };
        
        // Backup administrative collections
        await this.backupAdminCollections(backupPath, backupManifest);
        
        // Backup configurations
        if (includeConfigurations) {
          await this.backupConfigurations(backupPath, backupManifest);
        }
        
        // Backup user data if requested
        if (includeUserData) {
          await this.backupUserData(backupPath, backupManifest, context);
        }
        
        // Backup organization data if requested
        if (includeOrganizations) {
          await this.backupOrganizationData(backupPath, backupManifest, context);
        }
        
        // Generate integrity checksums
        await this.generateIntegrityChecksums(backupPath, backupManifest);
        
        // Save backup manifest
        await this.saveBackupManifest(backupPath, backupManifest);
        
        // Compress backup if requested
        let finalBackupPath = backupPath;
        if (compression) {
          finalBackupPath = await this.compressBackup(backupPath, backupId);
        }
        
        // Encrypt backup if requested
        if (encryption) {
          finalBackupPath = await this.encryptBackup(finalBackupPath, backupId);
        }
        
        // Update backup metadata
        this.backupMetadata.set(backupId, {
          ...backupManifest,
          path: finalBackupPath,
          compressed: compression,
          encrypted: encryption,
          size: await this.getBackupSize(finalBackupPath)
        });
        
        await this.commitTransaction(session);
        
        // Clean up temporary directory if compressed
        if (compression && finalBackupPath !== backupPath) {
          await this.cleanupDirectory(backupPath);
        }
        
        logger.info('Full backup created successfully', {
          backupId,
          path: finalBackupPath,
          collections: backupManifest.collections.length
        });
        
        return {
          backupId,
          type: this.backupTypes.FULL,
          path: finalBackupPath,
          size: await this.getBackupSize(finalBackupPath),
          collections: backupManifest.collections.length,
          createdAt: backupManifest.createdAt,
          integrity: backupManifest.integrity
        };
        
      } catch (error) {
        await this.abortTransaction(session);
        await this.cleanupDirectory(backupPath);
        throw error;
      }
    }, context);
  }
  
  /**
   * Create an incremental backup
   * @param {Object} context - Operation context
   * @param {Object} options - Backup options
   * @returns {Promise<Object>} Backup information
   */
  async createIncrementalBackup(context, options = {}) {
    return this.executeOperation('backup.create.incremental', async () => {
      const { baseBackupId, since } = options;
      
      if (!baseBackupId && !since) {
        throw new ValidationError('Base backup ID or since timestamp required for incremental backup');
      }
      
      const sinceDate = since ? new Date(since) : await this.getBaseBackupDate(baseBackupId);
      const backupId = this.generateBackupId('incremental');
      const backupPath = await this.createBackupDirectory(backupId);
      
      logger.info('Starting incremental backup creation', {
        backupId,
        baseBackupId,
        since: sinceDate
      });
      
      const backupManifest = {
        id: backupId,
        type: this.backupTypes.INCREMENTAL,
        baseBackupId,
        since: sinceDate,
        createdBy: context.userId,
        createdAt: new Date(),
        collections: [],
        files: [],
        integrity: {}
      };
      
      // Backup only changed documents
      await this.backupChangedDocuments(backupPath, backupManifest, sinceDate);
      
      // Generate integrity checksums
      await this.generateIntegrityChecksums(backupPath, backupManifest);
      
      // Save backup manifest
      await this.saveBackupManifest(backupPath, backupManifest);
      
      logger.info('Incremental backup created successfully', {
        backupId,
        changedDocuments: backupManifest.collections.reduce((sum, col) => sum + col.documentCount, 0)
      });
      
      return {
        backupId,
        type: this.backupTypes.INCREMENTAL,
        baseBackupId,
        path: backupPath,
        changedDocuments: backupManifest.collections.reduce((sum, col) => sum + col.documentCount, 0),
        createdAt: backupManifest.createdAt
      };
      
    }, context);
  }
  
  /**
   * Restore backup
   * @param {Object} context - Operation context
   * @param {string} backupId - Backup ID to restore
   * @param {Object} options - Restore options
   * @returns {Promise<Object>} Restore information
   */
  async restoreBackup(context, backupId, options = {}) {
    return this.executeOperation('backup.restore', async () => {
      const {
        collections = [],
        dryRun = false,
        overwriteExisting = false,
        restoreToTimestamp = null
      } = options;
      
      logger.info('Starting backup restore', {
        backupId,
        collections: collections.length ? collections : 'all',
        dryRun,
        overwriteExisting
      });
      
      // Validate backup exists and is accessible
      const backupInfo = await this.validateBackupForRestore(backupId);
      
      // Decrypt backup if encrypted
      let backupPath = backupInfo.path;
      if (backupInfo.encrypted) {
        backupPath = await this.decryptBackup(backupPath, backupId);
      }
      
      // Extract backup if compressed
      if (backupInfo.compressed) {
        backupPath = await this.extractBackup(backupPath, backupId);
      }
      
      // Load backup manifest
      const manifest = await this.loadBackupManifest(backupPath);
      
      // Verify backup integrity
      await this.verifyBackupIntegrity(backupPath, manifest);
      
      if (dryRun) {
        return {
          backupId,
          dryRun: true,
          collectionsToRestore: collections.length ? collections : manifest.collections.map(c => c.name),
          estimatedDocuments: manifest.collections.reduce((sum, col) => sum + col.documentCount, 0),
          warnings: await this.analyzeRestoreWarnings(manifest, options)
        };
      }
      
      const session = await this.startTransaction();
      
      try {
        const restoreResults = {
          backupId,
          restoredCollections: [],
          restoredDocuments: 0,
          skippedDocuments: 0,
          errors: [],
          startedAt: new Date()
        };
        
        // Restore collections
        for (const collectionInfo of manifest.collections) {
          if (collections.length && !collections.includes(collectionInfo.name)) {
            continue;
          }
          
          const result = await this.restoreCollection(
            backupPath,
            collectionInfo,
            overwriteExisting,
            restoreToTimestamp,
            session
          );
          
          restoreResults.restoredCollections.push(collectionInfo.name);
          restoreResults.restoredDocuments += result.restored;
          restoreResults.skippedDocuments += result.skipped;
          
          if (result.errors.length) {
            restoreResults.errors.push(...result.errors);
          }
        }
        
        await this.commitTransaction(session);
        
        restoreResults.completedAt = new Date();
        restoreResults.duration = restoreResults.completedAt - restoreResults.startedAt;
        
        logger.info('Backup restore completed successfully', {
          backupId,
          restoredDocuments: restoreResults.restoredDocuments,
          duration: restoreResults.duration
        });
        
        return restoreResults;
        
      } catch (error) {
        await this.abortTransaction(session);
        throw error;
      }
      
    }, context);
  }
  
  /**
   * List available backups
   * @param {Object} context - Operation context
   * @param {Object} filters - Filter options
   * @returns {Promise<Array>} List of backups
   */
  async listBackups(context, filters = {}) {
    return this.executeOperation('backup.list', async () => {
      const {
        type = null,
        createdBy = null,
        startDate = null,
        endDate = null,
        limit = 50,
        offset = 0
      } = filters;
      
      const backups = [];
      
      try {
        const backupDirectory = this.backupConfig.baseDirectory;
        const entries = await fs.readdir(backupDirectory, { withFileTypes: true });
        
        for (const entry of entries) {
          if (entry.isDirectory() || entry.name.endsWith('.zip') || entry.name.endsWith('.enc')) {
            try {
              const backupInfo = await this.getBackupInfo(entry.name);
              
              // Apply filters
              if (type && backupInfo.type !== type) continue;
              if (createdBy && backupInfo.createdBy !== createdBy) continue;
              if (startDate && backupInfo.createdAt < new Date(startDate)) continue;
              if (endDate && backupInfo.createdAt > new Date(endDate)) continue;
              
              backups.push(backupInfo);
              
            } catch (error) {
              logger.warn('Failed to read backup info', { 
                backup: entry.name, 
                error: error.message 
              });
            }
          }
        }
        
        // Sort by creation date (newest first)
        backups.sort((a, b) => b.createdAt - a.createdAt);
        
        // Apply pagination
        const paginatedBackups = backups.slice(offset, offset + limit);
        
        return {
          backups: paginatedBackups,
          total: backups.length,
          offset,
          limit
        };
        
      } catch (error) {
        logger.error('Failed to list backups', { error: error.message });
        throw new AppError('Failed to list backups', 500);
      }
      
    }, context);
  }
  
  /**
   * Delete backup
   * @param {Object} context - Operation context
   * @param {string} backupId - Backup ID to delete
   * @param {Object} options - Delete options
   * @returns {Promise<Object>} Delete result
   */
  async deleteBackup(context, backupId, options = {}) {
    return this.executeOperation('backup.delete', async () => {
      const { force = false } = options;
      
      logger.info('Deleting backup', { backupId, force });
      
      const backupInfo = await this.getBackupInfo(backupId);
      
      if (!backupInfo) {
        throw new NotFoundError('Backup', backupId);
      }
      
      // Check if backup is referenced by other backups
      if (!force) {
        const dependentBackups = await this.findDependentBackups(backupId);
        if (dependentBackups.length > 0) {
          throw new ValidationError(
            `Backup ${backupId} is referenced by other backups: ${dependentBackups.join(', ')}`
          );
        }
      }
      
      try {
        // Delete backup files
        if (await this.fileExists(backupInfo.path)) {
          await this.deleteBackupFiles(backupInfo.path);
        }
        
        // Remove from metadata
        this.backupMetadata.delete(backupId);
        
        logger.info('Backup deleted successfully', { backupId });
        
        return {
          backupId,
          deleted: true,
          deletedAt: new Date()
        };
        
      } catch (error) {
        logger.error('Failed to delete backup', {
          backupId,
          error: error.message
        });
        throw new AppError(`Failed to delete backup: ${error.message}`, 500);
      }
      
    }, context);
  }
  
  /**
   * Backup administrative collections
   * @param {string} backupPath - Backup directory path
   * @param {Object} manifest - Backup manifest
   * @private
   */
  async backupAdminCollections(backupPath, manifest) {
    const adminCollections = [
      { model: AdminActionLog, name: 'admin_action_logs' },
      { model: AdminSession, name: 'admin_sessions' },
      { model: AdminPreference, name: 'admin_preferences' },
      { model: AdminNotification, name: 'admin_notifications' }
    ];
    
    for (const { model, name } of adminCollections) {
      const collectionPath = path.join(backupPath, `${name}.json`);
      const documents = await model.find({}).lean();
      
      await fs.writeFile(collectionPath, JSON.stringify(documents, null, 2));
      
      manifest.collections.push({
        name,
        path: collectionPath,
        documentCount: documents.length,
        backupSize: (await fs.stat(collectionPath)).size
      });
      
      logger.debug(`Backed up collection: ${name}`, {
        documents: documents.length
      });
    }
  }
  
  /**
   * Backup system configurations
   * @param {string} backupPath - Backup directory path
   * @param {Object} manifest - Backup manifest
   * @private
   */
  async backupConfigurations(backupPath, manifest) {
    const configPath = path.join(backupPath, 'configurations');
    await fs.mkdir(configPath, { recursive: true });
    
    // Backup application configuration
    const appConfigPath = path.join(configPath, 'app-config.json');
    await fs.writeFile(appConfigPath, JSON.stringify(config, null, 2));
    
    manifest.files.push({
      type: 'configuration',
      name: 'app-config.json',
      path: appConfigPath,
      description: 'Application configuration'
    });
    
    // Backup environment variables (sanitized)
    const envConfig = this.sanitizeEnvironmentVariables(process.env);
    const envConfigPath = path.join(configPath, 'environment.json');
    await fs.writeFile(envConfigPath, JSON.stringify(envConfig, null, 2));
    
    manifest.files.push({
      type: 'configuration',
      name: 'environment.json',
      path: envConfigPath,
      description: 'Environment configuration (sanitized)'
    });
  }
  
  /**
   * Generate backup ID
   * @param {string} type - Backup type
   * @returns {string} Backup ID
   * @private
   */
  generateBackupId(type) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const randomId = crypto.randomBytes(8).toString('hex');
    return `${type}-${timestamp}-${randomId}`;
  }
  
  /**
   * Create backup directory
   * @param {string} backupId - Backup ID
   * @returns {Promise<string>} Backup directory path
   * @private
   */
  async createBackupDirectory(backupId) {
    const backupPath = path.join(this.backupConfig.baseDirectory, backupId);
    await fs.mkdir(backupPath, { recursive: true });
    return backupPath;
  }
  
  /**
   * Ensure backup directory exists
   * @private
   */
  async ensureBackupDirectory() {
    await fs.mkdir(this.backupConfig.baseDirectory, { recursive: true });
  }
  
  /**
   * Get MongoDB version
   * @returns {Promise<string>} MongoDB version
   * @private
   */
  async getMongoVersion() {
    try {
      const result = await mongoose.connection.db.admin().buildInfo();
      return result.version;
    } catch (error) {
      return 'unknown';
    }
  }
  
  /**
   * Generate integrity checksums
   * @param {string} backupPath - Backup directory path
   * @param {Object} manifest - Backup manifest
   * @private
   */
  async generateIntegrityChecksums(backupPath, manifest) {
    const checksums = {};
    
    // Generate checksums for collection files
    for (const collection of manifest.collections) {
      const content = await fs.readFile(collection.path);
      checksums[collection.name] = crypto.createHash('sha256').update(content).digest('hex');
    }
    
    // Generate checksums for configuration files
    for (const file of manifest.files) {
      const content = await fs.readFile(file.path);
      checksums[file.name] = crypto.createHash('sha256').update(content).digest('hex');
    }
    
    manifest.integrity = {
      algorithm: 'sha256',
      checksums,
      generatedAt: new Date()
    };
  }
  
  /**
   * Save backup manifest
   * @param {string} backupPath - Backup directory path
   * @param {Object} manifest - Backup manifest
   * @private
   */
  async saveBackupManifest(backupPath, manifest) {
    const manifestPath = path.join(backupPath, 'manifest.json');
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
  }
  
  /**
   * Compress backup
   * @param {string} backupPath - Backup directory path
   * @param {string} backupId - Backup ID
   * @returns {Promise<string>} Compressed backup path
   * @private
   */
  async compressBackup(backupPath, backupId) {
    const compressedPath = `${backupPath}.zip`;
    
    return new Promise((resolve, reject) => {
      const output = require('fs').createWriteStream(compressedPath);
      const archive = archiver('zip', { zlib: { level: 9 } });
      
      output.on('close', () => {
        logger.debug('Backup compressed', {
          backupId,
          originalSize: archive.pointer(),
          compressedPath
        });
        resolve(compressedPath);
      });
      
      archive.on('error', reject);
      archive.pipe(output);
      archive.directory(backupPath, false);
      archive.finalize();
    });
  }
  
  /**
   * Encrypt backup
   * @param {string} backupPath - Backup file path
   * @param {string} backupId - Backup ID
   * @returns {Promise<string>} Encrypted backup path
   * @private
   */
  async encryptBackup(backupPath, backupId) {
    const encryptedPath = `${backupPath}.enc`;
    const key = this.getEncryptionKey();
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipher('aes-256-cbc', key);
    const input = require('fs').createReadStream(backupPath);
    const output = require('fs').createWriteStream(encryptedPath);
    
    // Write IV to the beginning of the encrypted file
    output.write(iv);
    
    return new Promise((resolve, reject) => {
      input.pipe(cipher).pipe(output);
      
      output.on('finish', () => {
        logger.debug('Backup encrypted', { backupId, encryptedPath });
        resolve(encryptedPath);
      });
      
      output.on('error', reject);
      input.on('error', reject);
      cipher.on('error', reject);
    });
  }
  
  /**
   * Get encryption key
   * @returns {string} Encryption key
   * @private
   */
  getEncryptionKey() {
    return config.backup?.encryptionKey || config.app?.secretKey || 'default-backup-key';
  }
  
  /**
   * Sanitize environment variables
   * @param {Object} env - Environment variables
   * @returns {Object} Sanitized environment variables
   * @private
   */
  sanitizeEnvironmentVariables(env) {
    const sensitiveKeys = [
      'password', 'secret', 'key', 'token', 'auth', 'credential',
      'private', 'api_key', 'database_url', 'connection_string'
    ];
    
    const sanitized = {};
    
    for (const [key, value] of Object.entries(env)) {
      const lowerKey = key.toLowerCase();
      const isSensitive = sensitiveKeys.some(sensitive => lowerKey.includes(sensitive));
      
      sanitized[key] = isSensitive ? '[REDACTED]' : value;
    }
    
    return sanitized;
  }
  
  /**
   * Get backup size
   * @param {string} backupPath - Backup path
   * @returns {Promise<number>} Backup size in bytes
   * @private
   */
  async getBackupSize(backupPath) {
    try {
      const stats = await fs.stat(backupPath);
      return stats.size;
    } catch (error) {
      return 0;
    }
  }
  
  /**
   * Check if file exists
   * @param {string} filePath - File path
   * @returns {Promise<boolean>} File exists
   * @private
   */
  async fileExists(filePath) {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }
  
  /**
   * Cleanup directory
   * @param {string} dirPath - Directory path
   * @private
   */
  async cleanupDirectory(dirPath) {
    try {
      await fs.rm(dirPath, { recursive: true, force: true });
    } catch (error) {
      logger.warn('Failed to cleanup directory', {
        path: dirPath,
        error: error.message
      });
    }
  }
}

module.exports = AdminBackupService;