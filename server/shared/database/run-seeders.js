// /server/shared/database/run-seeders.js

/**
 * @file Database Seeding Runner
 * @description Script to execute database seeders with proper environment checking
 * @version 1.0.0
 */

const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');

const config = require('../config/config');
const logger = require('../utils/logger');

/**
 * Seeder Runner Class
 * @class SeederRunner
 */
class SeederRunner {
  constructor() {
    this.client = null;
    this.db = null;
    this.seedersPath = path.join(__dirname, 'seeders');
    this.currentEnvironment = process.env.NODE_ENV || 'development';
  }
  
  /**
   * Connect to MongoDB
   * @returns {Promise<void>}
   */
  async connect() {
    try {
      logger.info('Connecting to MongoDB for seeding...', {
        environment: this.currentEnvironment,
        uri: config.database.uri.replace(/\/\/[^:]+:[^@]+@/, '//***:***@') // Hide credentials in logs
      });
      
      this.client = new MongoClient(config.database.uri, {
        maxPoolSize: 10,
        serverSelectionTimeoutMS: 30000,
        socketTimeoutMS: 45000,
        family: 4
      });
      
      await this.client.connect();
      
      // Extract database name from URI
      const dbName = this.extractDatabaseName(config.database.uri);
      this.db = this.client.db(dbName);
      
      logger.info('Connected to MongoDB successfully', { database: dbName });
    } catch (error) {
      logger.error('Failed to connect to MongoDB', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Extract database name from MongoDB URI
   * @param {string} uri - MongoDB connection URI
   * @returns {string} Database name
   */
  extractDatabaseName(uri) {
    try {
      const url = new URL(uri);
      return url.pathname.substring(1) || 'insightserenity';
    } catch (error) {
      logger.warn('Could not extract database name from URI, using default');
      return 'insightserenity';
    }
  }
  
  /**
   * Disconnect from MongoDB
   * @returns {Promise<void>}
   */
  async disconnect() {
    if (this.client) {
      await this.client.close();
      logger.info('Disconnected from MongoDB');
    }
  }
  
  /**
   * Load all seeder files
   * @returns {Array<Object>} Array of seeder modules
   */
  loadSeeders() {
    try {
      const seederFiles = fs.readdirSync(this.seedersPath)
        .filter(file => file.endsWith('.js'))
        .sort(); // Ensure consistent execution order
      
      const seeders = [];
      
      for (const file of seederFiles) {
        const seederPath = path.join(this.seedersPath, file);
        
        try {
          // Clear require cache to ensure fresh load
          delete require.cache[require.resolve(seederPath)];
          const seeder = require(seederPath);
          
          // Validate seeder structure
          if (!this.validateSeeder(seeder, file)) {
            continue;
          }
          
          // Check environment compatibility
          if (!this.isSeederCompatible(seeder)) {
            logger.info(`Skipping seeder ${file} - not compatible with environment ${this.currentEnvironment}`);
            continue;
          }
          
          seeders.push({
            ...seeder,
            filename: file
          });
          
          logger.debug(`Loaded seeder: ${file}`, {
            name: seeder.name,
            version: seeder.version,
            environment: seeder.environment
          });
        } catch (error) {
          logger.error(`Failed to load seeder ${file}`, { error: error.message });
        }
      }
      
      logger.info(`Loaded ${seeders.length} seeders`, {
        environment: this.currentEnvironment,
        seeders: seeders.map(s => s.name)
      });
      
      return seeders;
    } catch (error) {
      logger.error('Failed to load seeders', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Validate seeder structure
   * @param {Object} seeder - Seeder module
   * @param {string} filename - Seeder filename
   * @returns {boolean} Is valid seeder
   */
  validateSeeder(seeder, filename) {
    const requiredProperties = ['name', 'version', 'up'];
    
    for (const prop of requiredProperties) {
      if (!seeder[prop]) {
        logger.error(`Seeder ${filename} is missing required property: ${prop}`);
        return false;
      }
    }
    
    if (typeof seeder.up !== 'function') {
      logger.error(`Seeder ${filename} 'up' method must be a function`);
      return false;
    }
    
    if (seeder.down && typeof seeder.down !== 'function') {
      logger.error(`Seeder ${filename} 'down' method must be a function`);
      return false;
    }
    
    return true;
  }
  
  /**
   * Check if seeder is compatible with current environment
   * @param {Object} seeder - Seeder module
   * @returns {boolean} Is compatible
   */
  isSeederCompatible(seeder) {
    if (!seeder.environment) {
      return true; // No environment restriction
    }
    
    return seeder.environment.includes(this.currentEnvironment);
  }
  
  /**
   * Check if seeder has already been executed
   * @param {Object} seeder - Seeder module
   * @returns {Promise<boolean>} Has been executed
   */
  async hasBeenExecuted(seeder) {
    try {
      const seederRecord = await this.db.collection('seeders').findOne({
        name: seeder.name,
        version: seeder.version
      });
      
      return !!seederRecord;
    } catch (error) {
      logger.error('Failed to check seeder execution status', {
        seeder: seeder.name,
        error: error.message
      });
      return false;
    }
  }
  
  /**
   * Execute a single seeder
   * @param {Object} seeder - Seeder module
   * @param {boolean} force - Force execution even if already run
   * @returns {Promise<boolean>} Execution success
   */
  async executeSeeder(seeder, force = false) {
    const startTime = Date.now();
    
    try {
      // Check if already executed
      if (!force && await this.hasBeenExecuted(seeder)) {
        logger.info(`Seeder ${seeder.name} has already been executed, skipping`);
        return true;
      }
      
      logger.info(`Executing seeder: ${seeder.name}`, {
        version: seeder.version,
        filename: seeder.filename,
        force
      });
      
      // Execute the seeder
      await seeder.up(this.db);
      
      const duration = Date.now() - startTime;
      logger.info(`Seeder ${seeder.name} executed successfully`, {
        duration: `${duration}ms`
      });
      
      return true;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`Seeder ${seeder.name} failed`, {
        error: error.message,
        duration: `${duration}ms`,
        stack: error.stack
      });
      
      return false;
    }
  }
  
  /**
   * Rollback a single seeder
   * @param {Object} seeder - Seeder module
   * @returns {Promise<boolean>} Rollback success
   */
  async rollbackSeeder(seeder) {
    if (!seeder.down) {
      logger.warn(`Seeder ${seeder.name} does not support rollback (no 'down' method)`);
      return false;
    }
    
    const startTime = Date.now();
    
    try {
      logger.info(`Rolling back seeder: ${seeder.name}`, {
        version: seeder.version,
        filename: seeder.filename
      });
      
      await seeder.down(this.db);
      
      const duration = Date.now() - startTime;
      logger.info(`Seeder ${seeder.name} rolled back successfully`, {
        duration: `${duration}ms`
      });
      
      return true;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.error(`Seeder ${seeder.name} rollback failed`, {
        error: error.message,
        duration: `${duration}ms`,
        stack: error.stack
      });
      
      return false;
    }
  }
  
  /**
   * Run all seeders
   * @param {Object} options - Execution options
   * @returns {Promise<void>}
   */
  async runSeeders(options = {}) {
    const { force = false, specific = null, rollback = false } = options;
    
    try {
      await this.connect();
      
      const seeders = this.loadSeeders();
      
      if (seeders.length === 0) {
        logger.warn('No seeders found to execute');
        return;
      }
      
      // Filter to specific seeder if requested
      const seedersToRun = specific 
        ? seeders.filter(s => s.name === specific || s.filename === specific)
        : seeders;
      
      if (specific && seedersToRun.length === 0) {
        throw new Error(`Seeder '${specific}' not found`);
      }
      
      logger.info(`Starting ${rollback ? 'rollback' : 'execution'} of ${seedersToRun.length} seeders`, {
        environment: this.currentEnvironment,
        force,
        rollback,
        specific
      });
      
      let successCount = 0;
      let failureCount = 0;
      
      // Execute seeders in order (or reverse order for rollback)
      const orderedSeeders = rollback ? seedersToRun.reverse() : seedersToRun;
      
      for (const seeder of orderedSeeders) {
        const success = rollback 
          ? await this.rollbackSeeder(seeder)
          : await this.executeSeeder(seeder, force);
        
        if (success) {
          successCount++;
        } else {
          failureCount++;
          
          // Stop on first failure unless force mode
          if (!force) {
            logger.error('Stopping seeder execution due to failure');
            break;
          }
        }
      }
      
      logger.info(`Seeder ${rollback ? 'rollback' : 'execution'} completed`, {
        total: seedersToRun.length,
        successful: successCount,
        failed: failureCount
      });
      
      if (failureCount > 0 && !force) {
        throw new Error(`${failureCount} seeders failed`);
      }
      
    } finally {
      await this.disconnect();
    }
  }
}

/**
 * Parse command line arguments
 * @returns {Object} Parsed options
 */
function parseArguments() {
  const args = process.argv.slice(2);
  const options = {
    force: false,
    rollback: false,
    specific: null,
    help: false
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    switch (arg) {
      case '--force':
      case '-f':
        options.force = true;
        break;
      case '--rollback':
      case '-r':
        options.rollback = true;
        break;
      case '--seeder':
      case '-s':
        options.specific = args[i + 1];
        i++; // Skip next argument
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        // Assume it's a seeder name if no flag specified
        if (!arg.startsWith('-') && !options.specific) {
          options.specific = arg;
        }
    }
  }
  
  return options;
}

/**
 * Display help information
 */
function showHelp() {
  console.log(`
Database Seeder Runner

Usage:
  node run-seeders.js [options] [seeder-name]

Options:
  --force,     -f    Force execution even if seeder already ran
  --rollback,  -r    Rollback seeders instead of running them
  --seeder,    -s    Run specific seeder by name or filename
  --help,      -h    Show this help message

Examples:
  node run-seeders.js                           # Run all seeders
  node run-seeders.js --force                   # Force run all seeders
  node run-seeders.js --seeder seed-auth-users  # Run specific seeder
  node run-seeders.js -s 002-seed-auth-users.js # Run specific seeder by filename
  node run-seeders.js --rollback                # Rollback all seeders
  node run-seeders.js --rollback -s seed-auth-users # Rollback specific seeder

Environment:
  Current environment: ${process.env.NODE_ENV || 'development'}
  
  Set NODE_ENV to change environment:
  NODE_ENV=staging node run-seeders.js
  `);
}

/**
 * Main execution function
 */
async function main() {
  const options = parseArguments();
  
  if (options.help) {
    showHelp();
    process.exit(0);
  }
  
  const runner = new SeederRunner();
  
  try {
    await runner.runSeeders(options);
    
    logger.info('Seeding operation completed successfully');
    process.exit(0);
  } catch (error) {
    logger.error('Seeding operation failed', {
      error: error.message,
      stack: error.stack
    });
    
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception in seeder', {
    error: error.message,
    stack: error.stack
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection in seeder', {
    reason: reason.message || reason,
    promise
  });
  process.exit(1);
});

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = SeederRunner;