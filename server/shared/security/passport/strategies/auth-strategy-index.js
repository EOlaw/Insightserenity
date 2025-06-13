// server/shared/security/passport/strategies/index.js
/**
 * @file Authentication Strategies Index
 * @description Export all authentication strategies
 * @version 3.0.0
 */

const LocalStrategy = require('./local-strategy');
const GoogleStrategy = require('./google-strategy');
const GitHubStrategy = require('./github-strategy');
const LinkedInStrategy = require('./linkedin-strategy');
const PasskeyStrategy = require('./passkey-strategy');
const OrganizationStrategy = require('./organization-strategy');

/**
 * Authentication Strategies Manager
 * @class StrategiesManager
 */
class StrategiesManager {
  constructor() {
    this.strategies = new Map();
    this.initialized = false;
  }
  
  /**
   * Initialize all strategies
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.initialized) {
      return;
    }
    
    try {
      // Initialize each strategy
      const strategyClasses = {
        local: LocalStrategy,
        google: GoogleStrategy,
        github: GitHubStrategy,
        linkedin: LinkedInStrategy,
        passkey: PasskeyStrategy,
        organization: OrganizationStrategy
      };
      
      for (const [name, StrategyClass] of Object.entries(strategyClasses)) {
        const strategy = new StrategyClass();
        this.strategies.set(name, strategy);
      }
      
      this.initialized = true;
      console.log('✓ Authentication strategies initialized');
    } catch (error) {
      console.error('Failed to initialize authentication strategies', error);
      throw error;
    }
  }
  
  /**
   * Get strategy by name
   * @param {string} name - Strategy name
   * @returns {Object} Strategy instance
   */
  getStrategy(name) {
    if (!this.initialized) {
      throw new Error('Strategies not initialized');
    }
    return this.strategies.get(name);
  }
  
  /**
   * Get all strategies
   * @returns {Map} All strategies
   */
  getAllStrategies() {
    if (!this.initialized) {
      throw new Error('Strategies not initialized');
    }
    return this.strategies;
  }
  
  /**
   * Get available strategy names
   * @returns {Array<string>} Strategy names
   */
  getAvailableStrategies() {
    return Array.from(this.strategies.keys());
  }
  
  /**
   * Check if strategy is available
   * @param {string} name - Strategy name
   * @returns {boolean} Is available
   */
  isStrategyAvailable(name) {
    return this.strategies.has(name);
  }
}

// Create singleton instance
const strategiesManager = new StrategiesManager();

// Export individual strategies and manager
module.exports = {
  // Individual strategy classes
  LocalStrategy,
  GoogleStrategy,
  GitHubStrategy,
  LinkedInStrategy,
  PasskeyStrategy,
  OrganizationStrategy,
  
  // Strategies manager
  strategiesManager,
  
  // Convenience methods
  initialize: () => strategiesManager.initialize(),
  getStrategy: (name) => strategiesManager.getStrategy(name),
  getAllStrategies: () => strategiesManager.getAllStrategies(),
  getAvailableStrategies: () => strategiesManager.getAvailableStrategies(),
  isStrategyAvailable: (name) => strategiesManager.isStrategyAvailable(name)
};