// /server/shared/utils/helpers/queue-helper.js

/**
 * @file Queue Helper
 * @description Job queue utilities using Bull with Redis availability checks
 * @version 1.1.0
 */

const Bull = require('bull');

const config = require('../../config');
const constants = require('../../config/constants');
const logger = require('../logger');

/**
 * Queue Helper Class
 */
class QueueHelper {
  constructor() {
    this.queues = new Map();
    this.processors = new Map();
    this.fallbackJobs = new Map(); // Store jobs when Redis is disabled
    this.redisEnabled = config.redis?.enabled !== false; // Check Redis availability
    
    // Only configure Redis options if Redis is enabled
    this.defaultOptions = this.redisEnabled ? {
      redis: {
        host: config.redis.host,
        port: config.redis.port,
        password: config.redis.password,
        db: config.redis.queueDb || 1
      },
      defaultJobOptions: {
        removeOnComplete: true,
        removeOnFail: false,
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        }
      }
    } : {
      defaultJobOptions: {
        removeOnComplete: true,
        removeOnFail: false,
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        }
      }
    };
    
    this.initializeQueues();
  }
  
  /**
   * Initialize default queues only if Redis is enabled
   */
  initializeQueues() {
    if (!this.redisEnabled) {
      logger.info('Redis disabled - Queue operations will use fallback processing');
      return;
    }

    try {
      // Email queue
      this.createQueue('email', {
        defaultJobOptions: {
          attempts: 5,
          backoff: {
            type: 'exponential',
            delay: 5000
          }
        }
      });
      
      // File processing queue
      this.createQueue('file-processing', {
        defaultJobOptions: {
          timeout: 300000, // 5 minutes
          attempts: 2
        }
      });
      
      // Notification queue
      this.createQueue('notifications', {
        defaultJobOptions: {
          priority: constants.QUEUE_PRIORITY.HIGH,
          attempts: 3
        }
      });
      
      // Analytics queue
      this.createQueue('analytics', {
        defaultJobOptions: {
          priority: constants.QUEUE_PRIORITY.LOW,
          removeOnComplete: 100,
          removeOnFail: 1000
        }
      });
      
      // Webhook queue
      this.createQueue('webhooks', {
        defaultJobOptions: {
          attempts: 5,
          backoff: {
            type: 'fixed',
            delay: 10000
          }
        }
      });
      
      // Report generation queue
      this.createQueue('reports', {
        defaultJobOptions: {
          timeout: 600000, // 10 minutes
          attempts: 2,
          priority: constants.QUEUE_PRIORITY.NORMAL
        }
      });
      
      // Cleanup queue
      this.createQueue('cleanup', {
        defaultJobOptions: {
          priority: constants.QUEUE_PRIORITY.BACKGROUND,
          removeOnComplete: true
        }
      });

      logger.info('Queue system initialized with Redis support');
    } catch (error) {
      logger.error('Failed to initialize queue system', { error: error.message });
      this.redisEnabled = false; // Fallback to disabled mode
    }
  }
  
  /**
   * Create or get a queue
   * @param {string} name - Queue name
   * @param {Object} options - Queue options
   * @returns {Object} Bull queue instance or null if Redis disabled
   */
  createQueue(name, options = {}) {
    if (!this.redisEnabled) {
      logger.warn(`Queue ${name} requested but Redis is disabled - using fallback`);
      return null;
    }

    if (this.queues.has(name)) {
      return this.queues.get(name);
    }
    
    try {
      const queueOptions = {
        ...this.defaultOptions,
        ...options
      };
      
      const queue = new Bull(name, queueOptions);
      
      // Set up event handlers
      this.setupQueueEvents(queue, name);
      
      // Store queue
      this.queues.set(name, queue);
      
      return queue;
    } catch (error) {
      logger.error(`Failed to create queue ${name}`, { error: error.message });
      return null;
    }
  }
  
  /**
   * Get queue by name
   * @param {string} name - Queue name
   * @returns {Object} Bull queue instance or null if Redis disabled
   */
  getQueue(name) {
    if (!this.redisEnabled) {
      return null;
    }

    if (!this.queues.has(name)) {
      return this.createQueue(name);
    }
    return this.queues.get(name);
  }
  
  /**
   * Set up queue event handlers
   * @param {Object} queue - Bull queue instance
   * @param {string} name - Queue name
   */
  setupQueueEvents(queue, name) {
    queue.on('completed', (job, result) => {
      logger.debug(`Job ${job.id} completed in queue ${name}`, {
        jobName: job.name,
        duration: Date.now() - job.timestamp
      });
    });
    
    queue.on('failed', (job, err) => {
      logger.error(`Job ${job.id} failed in queue ${name}`, {
        jobName: job.name,
        error: err.message,
        stack: err.stack,
        attemptsMade: job.attemptsMade
      });
    });
    
    queue.on('stalled', (job) => {
      logger.warn(`Job ${job.id} stalled in queue ${name}`, {
        jobName: job.name
      });
    });
    
    queue.on('error', (error) => {
      logger.error(`Queue ${name} error:`, error);
    });
    
    queue.on('waiting', (jobId) => {
      logger.debug(`Job ${jobId} waiting in queue ${name}`);
    });
    
    queue.on('active', (job) => {
      logger.debug(`Job ${job.id} active in queue ${name}`, {
        jobName: job.name
      });
    });
    
    queue.on('progress', (job, progress) => {
      logger.debug(`Job ${job.id} progress in queue ${name}: ${progress}%`);
    });
  }
  
  /**
   * Add job to queue with fallback support
   * @param {string} queueName - Queue name
   * @param {string} jobName - Job name
   * @param {Object} data - Job data
   * @param {Object} options - Job options
   * @returns {Promise<Object>} Job instance or fallback result
   */
  async addJob(queueName, jobName, data, options = {}) {
    if (!this.redisEnabled) {
      logger.info(`Processing job ${jobName} immediately (Redis disabled)`);
      return this.processFallbackJob(queueName, jobName, data, options);
    }

    const queue = this.getQueue(queueName);
    if (!queue) {
      throw new Error(`Queue ${queueName} not available`);
    }

    const jobOptions = {
      ...queue.defaultJobOptions,
      ...options
    };
    
    const job = await queue.add(jobName, data, jobOptions);
    
    logger.info(`Job ${job.id} added to queue ${queueName}`, {
      jobName,
      priority: jobOptions.priority,
      delay: jobOptions.delay
    });
    
    return job;
  }

  /**
   * Process job immediately when Redis is disabled
   * @param {string} queueName - Queue name
   * @param {string} jobName - Job name
   * @param {Object} data - Job data
   * @param {Object} options - Job options
   * @returns {Promise} Processing result
   */
  async processFallbackJob(queueName, jobName, data, options) {
    const processorKey = `${queueName}:${jobName}`;
    const processor = this.processors.get(processorKey) || this.processors.get(`${queueName}:*`);
    
    if (processor) {
      try {
        const mockJob = { data, name: jobName, id: `fallback-${Date.now()}` };
        const result = await processor(mockJob);
        logger.info(`Fallback job processed successfully`, { 
          queue: queueName, 
          job: jobName 
        });
        return result;
      } catch (error) {
        logger.error(`Fallback job processing failed`, { 
          queue: queueName, 
          job: jobName, 
          error: error.message 
        });
        throw error;
      }
    } else {
      logger.warn(`No processor found for fallback job`, { 
        queue: queueName, 
        job: jobName 
      });
      const jobId = `${queueName}:${jobName}:${Date.now()}`;
      this.fallbackJobs.set(jobId, { queueName, jobName, data, options, timestamp: Date.now() });
      return { id: jobId, status: 'stored' };
    }
  }
  
  /**
   * Add bulk jobs to queue with fallback support
   * @param {string} queueName - Queue name
   * @param {Array} jobs - Array of job objects
   * @returns {Promise<Array>} Array of job instances or fallback results
   */
  async addBulkJobs(queueName, jobs) {
    if (!this.redisEnabled) {
      logger.info(`Processing ${jobs.length} jobs immediately (Redis disabled)`);
      const results = [];
      for (const job of jobs) {
        const result = await this.processFallbackJob(queueName, job.name, job.data, job.options);
        results.push(result);
      }
      return results;
    }

    const queue = this.getQueue(queueName);
    if (!queue) {
      throw new Error(`Queue ${queueName} not available`);
    }

    const bulkJobs = jobs.map(job => ({
      name: job.name,
      data: job.data,
      opts: {
        ...queue.defaultJobOptions,
        ...job.options
      }
    }));
    
    const result = await queue.addBulk(bulkJobs);
    
    logger.info(`${result.length} jobs added to queue ${queueName}`);
    
    return result;
  }
  
  /**
   * Process jobs in queue
   * @param {string} queueName - Queue name
   * @param {string} jobName - Job name (optional)
   * @param {Function} processor - Job processor function
   * @param {Object} options - Processing options
   */
  process(queueName, jobName, processor, options = {}) {
    const concurrency = options.concurrency || 1;
    
    // Store processor for later reference (works with or without Redis)
    const processorKey = `${queueName}:${jobName || '*'}`;
    this.processors.set(processorKey, processor);

    if (!this.redisEnabled) {
      logger.info(`Processor registered for fallback processing: ${processorKey}`);
      return;
    }

    const queue = this.getQueue(queueName);
    if (!queue) {
      logger.warn(`Cannot register processor for queue ${queueName} - queue not available`);
      return;
    }
    
    // Wrap processor with error handling
    const wrappedProcessor = async (job) => {
      const startTime = Date.now();
      
      try {
        logger.info(`Processing job ${job.id} in queue ${queueName}`, {
          jobName: job.name,
          attemptsMade: job.attemptsMade
        });
        
        const result = await processor(job);
        
        logger.info(`Job ${job.id} processed successfully`, {
          duration: Date.now() - startTime
        });
        
        return result;
      } catch (error) {
        logger.error(`Job ${job.id} processing error:`, {
          error: error.message,
          stack: error.stack,
          duration: Date.now() - startTime
        });
        
        throw error;
      }
    };
    
    if (jobName) {
      queue.process(jobName, concurrency, wrappedProcessor);
    } else {
      queue.process(concurrency, wrappedProcessor);
    }
  }
  
  /**
   * Pause queue
   * @param {string} queueName - Queue name
   * @returns {Promise<void>}
   */
  async pauseQueue(queueName) {
    if (!this.redisEnabled) {
      logger.warn(`Cannot pause queue ${queueName} - Redis disabled`);
      return;
    }

    const queue = this.getQueue(queueName);
    if (!queue) return;

    await queue.pause();
    logger.info(`Queue ${queueName} paused`);
  }
  
  /**
   * Resume queue
   * @param {string} queueName - Queue name
   * @returns {Promise<void>}
   */
  async resumeQueue(queueName) {
    if (!this.redisEnabled) {
      logger.warn(`Cannot resume queue ${queueName} - Redis disabled`);
      return;
    }

    const queue = this.getQueue(queueName);
    if (!queue) return;

    await queue.resume();
    logger.info(`Queue ${queueName} resumed`);
  }
  
  /**
   * Get queue status
   * @param {string} queueName - Queue name
   * @returns {Promise<Object>} Queue status
   */
  async getQueueStatus(queueName) {
    if (!this.redisEnabled) {
      return {
        name: queueName,
        counts: {
          waiting: 0,
          active: 0,
          completed: 0,
          failed: 0,
          delayed: 0,
          total: 0
        },
        status: 'disabled',
        fallbackJobs: Array.from(this.fallbackJobs.values()).filter(job => job.queueName === queueName).length
      };
    }

    const queue = this.getQueue(queueName);
    if (!queue) return null;
    
    const [
      waiting,
      active,
      completed,
      failed,
      delayed,
      paused
    ] = await Promise.all([
      queue.getWaitingCount(),
      queue.getActiveCount(),
      queue.getCompletedCount(),
      queue.getFailedCount(),
      queue.getDelayedCount(),
      queue.isPaused()
    ]);
    
    return {
      name: queueName,
      counts: {
        waiting,
        active,
        completed,
        failed,
        delayed,
        total: waiting + active + delayed
      },
      status: paused ? 'paused' : 'active'
    };
  }
  
  /**
   * Get all queues status
   * @returns {Promise<Array>} Array of queue statuses
   */
  async getAllQueuesStatus() {
    const statuses = [];
    
    if (!this.redisEnabled) {
      const fallbackStats = {
        name: 'fallback',
        counts: {
          waiting: 0,
          active: 0,
          completed: 0,
          failed: 0,
          delayed: 0,
          total: this.fallbackJobs.size
        },
        status: 'fallback',
        fallbackJobs: this.fallbackJobs.size
      };
      statuses.push(fallbackStats);
      return statuses;
    }
    
    for (const [name] of this.queues) {
      const status = await this.getQueueStatus(name);
      statuses.push(status);
    }
    
    return statuses;
  }
  
  /**
   * Clean queue
   * @param {string} queueName - Queue name
   * @param {Object} options - Clean options
   * @returns {Promise<Object>} Clean result
   */
  async cleanQueue(queueName, options = {}) {
    if (!this.redisEnabled) {
      logger.warn(`Cannot clean queue ${queueName} - Redis disabled`);
      return { cleaned: 0, status: 'disabled', queue: queueName };
    }

    const queue = this.getQueue(queueName);
    if (!queue) return { cleaned: 0, status: 'not_found', queue: queueName };

    const {
      grace = 3600000, // 1 hour
      status = 'completed',
      limit = 1000
    } = options;
    
    const jobs = await queue.clean(grace, status, limit);
    
    logger.info(`Cleaned ${jobs.length} jobs from queue ${queueName}`, {
      status,
      grace
    });
    
    return {
      cleaned: jobs.length,
      status,
      queue: queueName
    };
  }
  
  /**
   * Empty queue
   * @param {string} queueName - Queue name
   * @returns {Promise<void>}
   */
  async emptyQueue(queueName) {
    if (!this.redisEnabled) {
      logger.warn(`Cannot empty queue ${queueName} - Redis disabled`);
      return;
    }

    const queue = this.getQueue(queueName);
    if (!queue) return;

    await queue.empty();
    logger.warn(`Queue ${queueName} emptied`);
  }
  
  /**
   * Close queue
   * @param {string} queueName - Queue name
   * @returns {Promise<void>}
   */
  async closeQueue(queueName) {
    if (!this.redisEnabled) {
      logger.warn(`Cannot close queue ${queueName} - Redis disabled`);
      return;
    }

    const queue = this.queues.get(queueName);
    if (queue) {
      await queue.close();
      this.queues.delete(queueName);
      logger.info(`Queue ${queueName} closed`);
    }
  }
  
  /**
   * Close all queues
   * @returns {Promise<void>}
   */
  async closeAll() {
    if (!this.redisEnabled) {
      this.fallbackJobs.clear();
      logger.info('Cleared fallback jobs storage');
      return;
    }

    for (const [name, queue] of this.queues) {
      await queue.close();
      logger.info(`Queue ${name} closed`);
    }
    this.queues.clear();
  }
  
  /**
   * Schedule recurring job
   * @param {string} queueName - Queue name
   * @param {string} jobName - Job name
   * @param {string} cronExpression - Cron expression
   * @param {Object} data - Job data
   * @param {Object} options - Job options
   * @returns {Promise<void>}
   */
  async scheduleRecurring(queueName, jobName, cronExpression, data, options = {}) {
    if (!this.redisEnabled) {
      logger.warn(`Cannot schedule recurring job ${jobName} - Redis disabled`);
      return;
    }

    const queue = this.getQueue(queueName);
    if (!queue) {
      throw new Error(`Queue ${queueName} not available`);
    }
    
    await queue.add(
      jobName,
      data,
      {
        ...options,
        repeat: {
          cron: cronExpression,
          tz: options.timezone || 'UTC'
        }
      }
    );
    
    logger.info(`Scheduled recurring job ${jobName} in queue ${queueName}`, {
      cron: cronExpression
    });
  }
  
  /**
   * Get job by ID
   * @param {string} queueName - Queue name
   * @param {string} jobId - Job ID
   * @returns {Promise<Object>} Job instance
   */
  async getJob(queueName, jobId) {
    if (!this.redisEnabled) {
      return this.fallbackJobs.get(jobId) || null;
    }

    const queue = this.getQueue(queueName);
    if (!queue) return null;

    return queue.getJob(jobId);
  }
  
  /**
   * Retry failed job
   * @param {string} queueName - Queue name
   * @param {string} jobId - Job ID
   * @returns {Promise<void>}
   */
  async retryJob(queueName, jobId) {
    if (!this.redisEnabled) {
      const fallbackJob = this.fallbackJobs.get(jobId);
      if (fallbackJob) {
        logger.info(`Retrying fallback job ${jobId}`);
        return this.processFallbackJob(fallbackJob.queueName, fallbackJob.jobName, fallbackJob.data, fallbackJob.options);
      }
      return;
    }

    const job = await this.getJob(queueName, jobId);
    if (job && job.failedReason) {
      await job.retry();
      logger.info(`Retrying job ${jobId} in queue ${queueName}`);
    }
  }
  
  /**
   * Create queue dashboard data
   * @returns {Promise<Object>} Dashboard data
   */
  async getDashboardData() {
    const queues = await this.getAllQueuesStatus();
    const stats = {
      totalQueues: queues.length,
      totalJobs: 0,
      activeJobs: 0,
      failedJobs: 0,
      completedJobs: 0,
      waitingJobs: 0,
      redisEnabled: this.redisEnabled,
      fallbackJobs: this.redisEnabled ? 0 : this.fallbackJobs.size
    };
    
    queues.forEach(queue => {
      stats.totalJobs += queue.counts.total;
      stats.activeJobs += queue.counts.active;
      stats.failedJobs += queue.counts.failed;
      stats.completedJobs += queue.counts.completed;
      stats.waitingJobs += queue.counts.waiting;
    });
    
    return {
      stats,
      queues,
      timestamp: new Date().toISOString()
    };
  }
  
  /**
   * Common job processors
   */
  processors = {
    // Email processor
    email: async (job) => {
      const EmailHelper = require('./email-helper');
      const { template, to, subject, data } = job.data;
      
      if (template) {
        return EmailHelper.sendTemplate(template, { to, subject, data });
      }
      return EmailHelper.send(job.data);
    },
    
    // File processing
    fileProcessing: async (job) => {
      const FileHelper = require('./file-helper');
      const { filePath, operation, options } = job.data;
      
      switch (operation) {
        case 'image':
          return FileHelper.processImage(filePath, options);
        case 'video':
          return FileHelper.processVideo(filePath, options);
        case 'upload':
          return FileHelper.uploadToS3(filePath, options.s3Key, options);
        default:
          throw new Error(`Unknown file operation: ${operation}`);
      }
    },
    
    // Webhook delivery
    webhook: async (job) => {
      const axios = require('axios');
      const { url, method, headers, data, timeout = 30000 } = job.data;
      
      const response = await axios({
        url,
        method,
        headers,
        data,
        timeout
      });
      
      return {
        status: response.status,
        data: response.data
      };
    },
    
    // Cleanup processor
    cleanup: async (job) => {
      const { type, options } = job.data;
      
      switch (type) {
        case 'temp-files':
          const FileHelper = require('./file-helper');
          return FileHelper.cleanupTempFiles(options.maxAge);
        case 'expired-sessions':
          // Implement session cleanup
          break;
        case 'old-logs':
          // Implement log cleanup
          break;
        default:
          throw new Error(`Unknown cleanup type: ${type}`);
      }
    }
  };
}

// Create singleton instance
const queueHelper = new QueueHelper();

// Export both the instance and the class
module.exports = queueHelper;
module.exports.QueueHelper = QueueHelper;