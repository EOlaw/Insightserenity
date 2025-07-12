/**
 * @file Admin Maintenance Service
 * @description Comprehensive system maintenance service for administrative operations including scheduled maintenance, health checks, and system optimization
 * @version 1.0.0
 */

const cron = require('node-cron');
const mongoose = require('mongoose');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');

const AdminBaseService = require('./admin-base-service');
const config = require('../../../shared/config/config');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { EmailService } = require('../../../shared/services/email-service');

// Import admin models
const AdminActionLog = require('../models/admin-action-log-model');
const AdminSession = require('../models/admin-session-model');
const AdminPreference = require('../models/admin-preference-model');
const AdminNotification = require('../models/admin-notification-model');

// Import other services
const AdminCacheService = require('./admin-cache-service');
const AdminBackupService = require('./admin-backup-service');

/**
 * Admin Maintenance Service Class
 * Handles system maintenance operations and health monitoring
 */
class AdminMaintenanceService extends AdminBaseService {
  constructor() {
    super('AdminMaintenanceService');
    
    this.maintenanceConfig = {
      maintenanceWindow: {
        start: config.maintenance?.window?.start || '02:00',
        end: config.maintenance?.window?.end || '06:00',
        timezone: config.maintenance?.window?.timezone || 'UTC',
        excludeDays: config.maintenance?.window?.excludeDays || [0, 6] // Exclude weekends
      },
      healthChecks: {
        interval: config.maintenance?.healthChecks?.interval || 300000, // 5 minutes
        timeout: config.maintenance?.healthChecks?.timeout || 30000, // 30 seconds
        retryAttempts: config.maintenance?.healthChecks?.retryAttempts || 3
      },
      cleanup: {
        expiredSessions: config.maintenance?.cleanup?.expiredSessions || true,
        oldAuditLogs: config.maintenance?.cleanup?.oldAuditLogs || true,
        tempFiles: config.maintenance?.cleanup?.tempFiles || true,
        cacheOptimization: config.maintenance?.cleanup?.cacheOptimization || true
      },
      notifications: {
        enabled: config.maintenance?.notifications?.enabled || true,
        recipients: config.maintenance?.notifications?.recipients || [],
        channels: config.maintenance?.notifications?.channels || ['email']
      }
    };
    
    this.maintenanceStatus = {
      isMaintenanceMode: false,
      currentTasks: new Map(),
      lastMaintenance: null,
      nextScheduled: null,
      healthStatus: 'healthy'
    };
    
    this.scheduledTasks = new Map();
    this.healthChecks = new Map();
    
    this.initializeMaintenanceService();
  }
  
  /**
   * Initialize maintenance service
   * @private
   */
  async initializeMaintenanceService() {
    try {
      // Set up scheduled maintenance tasks
      this.setupScheduledTasks();
      
      // Initialize health checks
      this.initializeHealthChecks();
      
      // Set up monitoring
      this.setupSystemMonitoring();
      
      // Register cleanup operations
      this.registerCleanupOperations();
      
      logger.info('Admin maintenance service initialized', {
        maintenanceWindow: this.maintenanceConfig.maintenanceWindow,
        healthCheckInterval: this.maintenanceConfig.healthChecks.interval
      });
      
    } catch (error) {
      logger.error('Failed to initialize maintenance service', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Enter maintenance mode
   * @param {Object} context - Operation context
   * @param {Object} options - Maintenance options
   * @returns {Promise<Object>} Maintenance status
   */
  async enterMaintenanceMode(context, options = {}) {
    return this.executeOperation('maintenance.enter', async () => {
      const {
        reason = 'Scheduled maintenance',
        estimatedDuration = 3600000, // 1 hour
        allowAdminAccess = true,
        notifyUsers = true,
        gracefulShutdown = true
      } = options;
      
      if (this.maintenanceStatus.isMaintenanceMode) {
        throw new ValidationError('System is already in maintenance mode');
      }
      
      logger.info('Entering maintenance mode', {
        reason,
        estimatedDuration,
        initiatedBy: context.userId
      });
      
      // Set maintenance status
      this.maintenanceStatus.isMaintenanceMode = true;
      this.maintenanceStatus.maintenanceStarted = new Date();
      this.maintenanceStatus.estimatedEnd = new Date(Date.now() + estimatedDuration);
      this.maintenanceStatus.reason = reason;
      this.maintenanceStatus.initiatedBy = context.userId;
      this.maintenanceStatus.allowAdminAccess = allowAdminAccess;
      
      // Notify active users if requested
      if (notifyUsers) {
        await this.notifyMaintenanceStart(context, options);
      }
      
      // Gracefully handle active sessions
      if (gracefulShutdown) {
        await this.handleActiveSessionsGracefully(allowAdminAccess);
      }
      
      // Create maintenance notification
      await this.createMaintenanceNotification('maintenance_started', {
        reason,
        estimatedDuration,
        allowAdminAccess
      });
      
      // Schedule automatic exit if duration specified
      if (estimatedDuration > 0) {
        this.scheduleMaintenanceExit(estimatedDuration);
      }
      
      return {
        maintenanceMode: true,
        startedAt: this.maintenanceStatus.maintenanceStarted,
        estimatedEnd: this.maintenanceStatus.estimatedEnd,
        reason,
        allowAdminAccess
      };
      
    }, context);
  }
  
  /**
   * Exit maintenance mode
   * @param {Object} context - Operation context
   * @param {Object} options - Exit options
   * @returns {Promise<Object>} Exit status
   */
  async exitMaintenanceMode(context, options = {}) {
    return this.executeOperation('maintenance.exit', async () => {
      if (!this.maintenanceStatus.isMaintenanceMode) {
        throw new ValidationError('System is not in maintenance mode');
      }
      
      const { notifyUsers = true, runHealthChecks = true } = options;
      
      logger.info('Exiting maintenance mode', {
        duration: new Date() - this.maintenanceStatus.maintenanceStarted,
        initiatedBy: context.userId
      });
      
      // Run health checks before exiting
      if (runHealthChecks) {
        const healthResults = await this.runComprehensiveHealthCheck();
        if (!healthResults.overall.healthy) {
          throw new AppError(
            'System health checks failed. Cannot exit maintenance mode safely.',
            503,
            'HEALTH_CHECK_FAILED'
          );
        }
      }
      
      // Clear maintenance status
      const maintenanceDuration = new Date() - this.maintenanceStatus.maintenanceStarted;
      this.maintenanceStatus.isMaintenanceMode = false;
      this.maintenanceStatus.lastMaintenance = {
        startedAt: this.maintenanceStatus.maintenanceStarted,
        endedAt: new Date(),
        duration: maintenanceDuration,
        reason: this.maintenanceStatus.reason,
        initiatedBy: this.maintenanceStatus.initiatedBy
      };
      
      // Clear current maintenance fields
      delete this.maintenanceStatus.maintenanceStarted;
      delete this.maintenanceStatus.estimatedEnd;
      delete this.maintenanceStatus.reason;
      delete this.maintenanceStatus.initiatedBy;
      delete this.maintenanceStatus.allowAdminAccess;
      
      // Notify users if requested
      if (notifyUsers) {
        await this.notifyMaintenanceEnd(context);
      }
      
      // Create maintenance notification
      await this.createMaintenanceNotification('maintenance_ended', {
        duration: maintenanceDuration
      });
      
      return {
        maintenanceMode: false,
        endedAt: this.maintenanceStatus.lastMaintenance.endedAt,
        duration: maintenanceDuration,
        healthStatus: this.maintenanceStatus.healthStatus
      };
      
    }, context);
  }
  
  /**
   * Run comprehensive health check
   * @param {Object} context - Operation context
   * @returns {Promise<Object>} Health check results
   */
  async runComprehensiveHealthCheck(context = {}) {
    return this.executeOperation('maintenance.health_check', async () => {
      logger.info('Running comprehensive health check');
      
      const healthResults = {
        timestamp: new Date(),
        overall: { healthy: true, score: 0 },
        checks: {},
        recommendations: [],
        warnings: [],
        errors: []
      };
      
      // Database health check
      healthResults.checks.database = await this.checkDatabaseHealth();
      
      // Cache health check
      healthResults.checks.cache = await this.checkCacheHealth();
      
      // Memory usage check
      healthResults.checks.memory = await this.checkMemoryUsage();
      
      // Disk space check
      healthResults.checks.diskSpace = await this.checkDiskSpace();
      
      // Session health check
      healthResults.checks.sessions = await this.checkSessionHealth();
      
      // Audit log health check
      healthResults.checks.auditLogs = await this.checkAuditLogHealth();
      
      // Network connectivity check
      healthResults.checks.network = await this.checkNetworkHealth();
      
      // Calculate overall health score
      const checks = Object.values(healthResults.checks);
      const totalScore = checks.reduce((sum, check) => sum + (check.score || 0), 0);
      healthResults.overall.score = totalScore / checks.length;
      healthResults.overall.healthy = healthResults.overall.score >= 70;
      
      // Collect warnings and errors
      for (const check of checks) {
        if (check.warnings) healthResults.warnings.push(...check.warnings);
        if (check.errors) healthResults.errors.push(...check.errors);
        if (check.recommendations) healthResults.recommendations.push(...check.recommendations);
      }
      
      // Update system health status
      this.maintenanceStatus.healthStatus = healthResults.overall.healthy ? 'healthy' : 'unhealthy';
      
      logger.info('Health check completed', {
        overallScore: healthResults.overall.score,
        healthy: healthResults.overall.healthy,
        warnings: healthResults.warnings.length,
        errors: healthResults.errors.length
      });
      
      return healthResults;
      
    }, context);
  }
  
  /**
   * Run system cleanup
   * @param {Object} context - Operation context
   * @param {Object} options - Cleanup options
   * @returns {Promise<Object>} Cleanup results
   */
  async runSystemCleanup(context, options = {}) {
    return this.executeOperation('maintenance.cleanup', async () => {
      const {
        cleanupExpiredSessions = true,
        cleanupOldAuditLogs = true,
        cleanupTempFiles = true,
        optimizeCache = true,
        optimizeDatabase = false
      } = options;
      
      logger.info('Starting system cleanup', { options });
      
      const cleanupResults = {
        timestamp: new Date(),
        operations: [],
        totalItemsRemoved: 0,
        totalSpaceFreed: 0,
        errors: []
      };
      
      // Cleanup expired sessions
      if (cleanupExpiredSessions) {
        try {
          const sessionCleanup = await this.cleanupExpiredSessions();
          cleanupResults.operations.push({
            operation: 'expired_sessions',
            status: 'success',
            itemsRemoved: sessionCleanup.deletedCount,
            details: sessionCleanup
          });
          cleanupResults.totalItemsRemoved += sessionCleanup.deletedCount;
        } catch (error) {
          cleanupResults.errors.push({
            operation: 'expired_sessions',
            error: error.message
          });
        }
      }
      
      // Cleanup old audit logs
      if (cleanupOldAuditLogs) {
        try {
          const auditCleanup = await this.cleanupOldAuditLogs();
          cleanupResults.operations.push({
            operation: 'old_audit_logs',
            status: 'success',
            itemsRemoved: auditCleanup.archivedCount,
            details: auditCleanup
          });
          cleanupResults.totalItemsRemoved += auditCleanup.archivedCount;
        } catch (error) {
          cleanupResults.errors.push({
            operation: 'old_audit_logs',
            error: error.message
          });
        }
      }
      
      // Cleanup temporary files
      if (cleanupTempFiles) {
        try {
          const fileCleanup = await this.cleanupTemporaryFiles();
          cleanupResults.operations.push({
            operation: 'temp_files',
            status: 'success',
            itemsRemoved: fileCleanup.filesDeleted,
            spaceFreed: fileCleanup.spaceFreed,
            details: fileCleanup
          });
          cleanupResults.totalSpaceFreed += fileCleanup.spaceFreed;
        } catch (error) {
          cleanupResults.errors.push({
            operation: 'temp_files',
            error: error.message
          });
        }
      }
      
      // Optimize cache
      if (optimizeCache) {
        try {
          const cacheOptimization = await this.optimizeCache();
          cleanupResults.operations.push({
            operation: 'cache_optimization',
            status: 'success',
            details: cacheOptimization
          });
        } catch (error) {
          cleanupResults.errors.push({
            operation: 'cache_optimization',
            error: error.message
          });
        }
      }
      
      // Optimize database
      if (optimizeDatabase) {
        try {
          const dbOptimization = await this.optimizeDatabase();
          cleanupResults.operations.push({
            operation: 'database_optimization',
            status: 'success',
            details: dbOptimization
          });
        } catch (error) {
          cleanupResults.errors.push({
            operation: 'database_optimization',
            error: error.message
          });
        }
      }
      
      logger.info('System cleanup completed', {
        totalOperations: cleanupResults.operations.length,
        totalItemsRemoved: cleanupResults.totalItemsRemoved,
        totalSpaceFreed: cleanupResults.totalSpaceFreed,
        errors: cleanupResults.errors.length
      });
      
      return cleanupResults;
      
    }, context);
  }
  
  /**
   * Get system status
   * @param {Object} context - Operation context
   * @returns {Promise<Object>} System status
   */
  async getSystemStatus(context) {
    return this.executeOperation('maintenance.status', async () => {
      const status = {
        timestamp: new Date(),
        maintenanceMode: this.maintenanceStatus.isMaintenanceMode,
        healthStatus: this.maintenanceStatus.healthStatus,
        uptime: process.uptime(),
        lastMaintenance: this.maintenanceStatus.lastMaintenance,
        nextScheduled: this.maintenanceStatus.nextScheduled,
        activeTasks: Array.from(this.maintenanceStatus.currentTasks.entries()).map(([id, task]) => ({
          id,
          name: task.name,
          startedAt: task.startedAt,
          progress: task.progress || 0
        })),
        systemInfo: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch,
          memory: process.memoryUsage(),
          loadAverage: os.loadavg(),
          cpuCount: os.cpus().length
        }
      };
      
      // Add maintenance-specific info if in maintenance mode
      if (this.maintenanceStatus.isMaintenanceMode) {
        status.maintenanceInfo = {
          startedAt: this.maintenanceStatus.maintenanceStarted,
          estimatedEnd: this.maintenanceStatus.estimatedEnd,
          reason: this.maintenanceStatus.reason,
          allowAdminAccess: this.maintenanceStatus.allowAdminAccess,
          duration: new Date() - this.maintenanceStatus.maintenanceStarted
        };
      }
      
      return status;
      
    }, context);
  }
  
  /**
   * Schedule maintenance task
   * @param {Object} context - Operation context
   * @param {Object} taskConfig - Task configuration
   * @returns {Promise<Object>} Scheduled task info
   */
  async scheduleMaintenanceTask(context, taskConfig) {
    return this.executeOperation('maintenance.schedule_task', async () => {
      const {
        name,
        schedule, // Cron expression
        operation,
        options = {},
        enabled = true,
        description
      } = taskConfig;
      
      if (!name || !schedule || !operation) {
        throw new ValidationError('Task name, schedule, and operation are required');
      }
      
      // Validate cron expression
      if (!cron.validate(schedule)) {
        throw new ValidationError('Invalid cron schedule expression');
      }
      
      const taskId = this.generateTaskId(name);
      
      const task = {
        id: taskId,
        name,
        schedule,
        operation,
        options,
        enabled,
        description,
        createdBy: context.userId,
        createdAt: new Date(),
        lastRun: null,
        nextRun: null,
        runCount: 0,
        successCount: 0,
        errorCount: 0
      };
      
      // Schedule the task
      if (enabled) {
        const cronTask = cron.schedule(schedule, async () => {
          await this.executeScheduledTask(task);
        }, {
          scheduled: false,
          timezone: this.maintenanceConfig.maintenanceWindow.timezone
        });
        
        task.cronTask = cronTask;
        task.nextRun = cronTask.nextDates(1)[0];
        cronTask.start();
      }
      
      this.scheduledTasks.set(taskId, task);
      
      logger.info('Maintenance task scheduled', {
        taskId,
        name,
        schedule,
        operation
      });
      
      return {
        taskId,
        name,
        schedule,
        operation,
        enabled,
        nextRun: task.nextRun,
        createdAt: task.createdAt
      };
      
    }, context);
  }
  
  /**
   * Setup scheduled maintenance tasks
   * @private
   */
  setupScheduledTasks() {
    // Daily cleanup at 3 AM
    this.scheduleTask('daily_cleanup', '0 3 * * *', async () => {
      const context = { userId: 'system', systemAction: true };
      await this.runSystemCleanup(context, {
        cleanupExpiredSessions: true,
        cleanupOldAuditLogs: true,
        cleanupTempFiles: true,
        optimizeCache: true
      });
    });
    
    // Weekly database optimization on Sundays at 2 AM
    this.scheduleTask('weekly_optimization', '0 2 * * 0', async () => {
      const context = { userId: 'system', systemAction: true };
      await this.runSystemCleanup(context, {
        optimizeDatabase: true
      });
    });
    
    // Hourly health checks
    this.scheduleTask('health_check', '0 * * * *', async () => {
      const context = { userId: 'system', systemAction: true };
      await this.runComprehensiveHealthCheck(context);
    });
  }
  
  /**
   * Initialize health checks
   * @private
   */
  initializeHealthChecks() {
    // Set up periodic health checks
    setInterval(async () => {
      try {
        await this.runBasicHealthCheck();
      } catch (error) {
        logger.error('Health check failed', { error: error.message });
      }
    }, this.maintenanceConfig.healthChecks.interval);
  }
  
  /**
   * Check database health
   * @returns {Promise<Object>} Database health status
   * @private
   */
  async checkDatabaseHealth() {
    const health = {
      name: 'Database',
      healthy: true,
      score: 100,
      metrics: {},
      warnings: [],
      errors: []
    };
    
    try {
      // Check database connection
      const state = mongoose.connection.readyState;
      health.metrics.connectionState = state;
      
      if (state !== 1) {
        health.healthy = false;
        health.score = 0;
        health.errors.push('Database connection is not active');
        return health;
      }
      
      // Check database response time
      const start = Date.now();
      await mongoose.connection.db.admin().ping();
      health.metrics.responseTime = Date.now() - start;
      
      if (health.metrics.responseTime > 1000) {
        health.score -= 30;
        health.warnings.push('Database response time is high');
      }
      
      // Check active connections
      const stats = await mongoose.connection.db.admin().serverStatus();
      health.metrics.activeConnections = stats.connections?.current || 0;
      health.metrics.availableConnections = stats.connections?.available || 0;
      
      // Check collection sizes
      const collections = await mongoose.connection.db.listCollections().toArray();
      health.metrics.collectionCount = collections.length;
      
    } catch (error) {
      health.healthy = false;
      health.score = 0;
      health.errors.push(`Database health check failed: ${error.message}`);
    }
    
    return health;
  }
  
  /**
   * Check cache health
   * @returns {Promise<Object>} Cache health status
   * @private
   */
  async checkCacheHealth() {
    const health = {
      name: 'Cache',
      healthy: true,
      score: 100,
      metrics: {},
      warnings: [],
      errors: []
    };
    
    try {
      // This would integrate with your cache service
      // For now, we'll simulate cache health check
      health.metrics.connected = true;
      health.metrics.hitRate = 85; // Simulated
      health.metrics.memoryUsage = 60; // Simulated percentage
      
      if (health.metrics.hitRate < 70) {
        health.score -= 20;
        health.warnings.push('Cache hit rate is below optimal threshold');
      }
      
      if (health.metrics.memoryUsage > 80) {
        health.score -= 15;
        health.warnings.push('Cache memory usage is high');
      }
      
    } catch (error) {
      health.healthy = false;
      health.score = 0;
      health.errors.push(`Cache health check failed: ${error.message}`);
    }
    
    return health;
  }
  
  /**
   * Check memory usage
   * @returns {Promise<Object>} Memory health status
   * @private
   */
  async checkMemoryUsage() {
    const health = {
      name: 'Memory',
      healthy: true,
      score: 100,
      metrics: {},
      warnings: [],
      errors: []
    };
    
    try {
      const memUsage = process.memoryUsage();
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();
      
      health.metrics.heapUsed = memUsage.heapUsed;
      health.metrics.heapTotal = memUsage.heapTotal;
      health.metrics.external = memUsage.external;
      health.metrics.rss = memUsage.rss;
      health.metrics.systemTotal = totalMemory;
      health.metrics.systemFree = freeMemory;
      health.metrics.systemUsedPercent = ((totalMemory - freeMemory) / totalMemory) * 100;
      
      // Check heap usage
      const heapUsagePercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;
      if (heapUsagePercent > 80) {
        health.score -= 25;
        health.warnings.push('Heap memory usage is high');
      }
      
      // Check system memory
      if (health.metrics.systemUsedPercent > 90) {
        health.score -= 30;
        health.warnings.push('System memory usage is critical');
      } else if (health.metrics.systemUsedPercent > 80) {
        health.score -= 15;
        health.warnings.push('System memory usage is high');
      }
      
    } catch (error) {
      health.healthy = false;
      health.score = 0;
      health.errors.push(`Memory health check failed: ${error.message}`);
    }
    
    return health;
  }
  
  /**
   * Check disk space
   * @returns {Promise<Object>} Disk space health status
   * @private
   */
  async checkDiskSpace() {
    const health = {
      name: 'Disk Space',
      healthy: true,
      score: 100,
      metrics: {},
      warnings: [],
      errors: []
    };
    
    try {
      // Check multiple important directories
      const pathsToCheck = [
        process.cwd(), // Application directory
        os.tmpdir(), // Temp directory
        this.exportConfig?.baseDirectory || './exports',
        './logs'
      ];
      
      for (const checkPath of pathsToCheck) {
        try {
          const stats = await fs.stat(checkPath);
          // Note: Getting actual disk space requires platform-specific commands
          // This is a simplified check
          health.metrics[checkPath] = {
            exists: true,
            accessible: true
          };
        } catch (error) {
          health.metrics[checkPath] = {
            exists: false,
            accessible: false,
            error: error.message
          };
          
          if (checkPath === process.cwd()) {
            health.score -= 50;
            health.errors.push(`Critical directory not accessible: ${checkPath}`);
          } else {
            health.score -= 10;
            health.warnings.push(`Directory not accessible: ${checkPath}`);
          }
        }
      }
      
    } catch (error) {
      health.healthy = false;
      health.score = 0;
      health.errors.push(`Disk space health check failed: ${error.message}`);
    }
    
    return health;
  }
  
  /**
   * Cleanup expired sessions
   * @returns {Promise<Object>} Cleanup results
   * @private
   */
  async cleanupExpiredSessions() {
    return AdminSession.cleanupExpiredSessions({
      batchSize: 1000,
      olderThan: 24 * 60 * 60 * 1000 // 24 hours
    });
  }
  
  /**
   * Cleanup old audit logs
   * @returns {Promise<Object>} Cleanup results
   * @private
   */
  async cleanupOldAuditLogs() {
    // Archive old logs instead of deleting
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 90); // 90 days
    
    const result = await AdminActionLog.updateMany(
      {
        timestamp: { $lt: cutoffDate },
        archived: { $ne: true }
      },
      {
        $set: {
          archived: true,
          archivedAt: new Date()
        }
      }
    );
    
    return {
      archivedCount: result.modifiedCount
    };
  }
  
  /**
   * Generate task ID
   * @param {string} name - Task name
   * @returns {string} Task ID
   * @private
   */
  generateTaskId(name) {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 9);
    return `${name.replace(/\s+/g, '_').toLowerCase()}_${timestamp}_${random}`;
  }
  
  /**
   * Schedule a task with cron
   * @param {string} name - Task name
   * @param {string} schedule - Cron schedule
   * @param {Function} task - Task function
   * @private
   */
  scheduleTask(name, schedule, task) {
    try {
      const cronTask = cron.schedule(schedule, task, {
        scheduled: true,
        timezone: this.maintenanceConfig.maintenanceWindow.timezone
      });
      
      logger.info(`Scheduled maintenance task: ${name}`, { schedule });
      
    } catch (error) {
      logger.error(`Failed to schedule task: ${name}`, {
        schedule,
        error: error.message
      });
    }
  }
}

module.exports = AdminMaintenanceService;