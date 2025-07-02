/**
 * @file Organization Tenant Service
 * @description Business logic for multi-tenant organization management
 * @version 1.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

const OrganizationTenant = require('../models/organization-tenant-model');
const { AppError, ValidationError } = require('../../shared/utils/app-error');
const logger = require('../../shared/utils/logger');
const { CacheService } = require('../../shared/services/cache-service');
const { EventEmitter } = require('../../shared/utils/events/event-emitter');
const EmailService = require('../../shared/services/email-service');
const { TENANT_CONSTANTS } = require('../constants/tenant-constants');

/**
 * Organization Tenant Service Class
 * @class OrganizationTenantService
 */
class OrganizationTenantService {
  constructor() {
    this.cache = CacheService;
    this.eventEmitter = EventEmitter;
  }

  /**
   * Create a new organization tenant
   * @param {Object} tenantData - The tenant data
   * @param {string} userId - The ID of the user creating the tenant
   * @returns {Promise<Object>} - The created tenant
   */
  async createTenant(tenantData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Creating new organization tenant', { userId, tenantName: tenantData.name });

      // Validate required fields
      this._validateTenantData(tenantData);

      // Generate tenant code if not provided
      if (!tenantData.tenantCode) {
        tenantData.tenantCode = await this._generateUniqueTenantCode(tenantData.name);
      }

      // Set defaults
      const tenant = new OrganizationTenant({
        ...tenantData,
        owner: userId,
        createdBy: userId,
        updatedBy: userId,
        status: TENANT_CONSTANTS.TENANT_STATUS.PENDING,
        'flags.isActive': false,
        'subscription.status': TENANT_CONSTANTS.SUBSCRIPTION_STATUS.TRIAL,
        'subscription.trialEndsAt': new Date(Date.now() + TENANT_CONSTANTS.TRIAL_DURATION_DAYS * 24 * 60 * 60 * 1000),
        // Initialize resourceLimits with proper structure
        resourceLimits: {
          users: { max: -1, current: 0 },
          storage: { maxGB: -1, currentBytes: 0 },
          apiCalls: { maxPerMonth: -1, currentMonth: 0 },
          projects: { max: -1, current: 0 },
          customDomains: { max: 1, current: 0 }
        }
      });

      // Set resource limits based on plan
      this._setResourceLimits(tenant);

      // Save tenant
      await tenant.save({ session });

      // Create tenant database if using dedicated strategy
      if (tenant.database.strategy === TENANT_CONSTANTS.DATABASE_STRATEGIES.DEDICATED) {
        await this._createTenantDatabase(tenant, session);
      }

      // Initialize tenant settings
      await this._initializeTenantSettings(tenant, session);

      // Send welcome email
      await this._sendWelcomeEmail(tenant);

      // Emit event
      this.eventEmitter.emit(TENANT_CONSTANTS.EVENT_TYPES.TENANT_CREATED, {
        tenantId: tenant._id,
        tenantCode: tenant.tenantCode,
        ownerId: userId
      });

      await session.commitTransaction();

      logger.info('Organization tenant created successfully', { 
        tenantId: tenant._id, 
        tenantCode: tenant.tenantCode 
      });

      return tenant;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to create organization tenant', { error, userId });
      
      if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        throw new ValidationError(`A tenant with this ${field} already exists`);
      }
      
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Get tenant by ID
   * @param {string} tenantId - The tenant ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - The tenant
   */
  async getTenantById(tenantId, options = {}) {
    try {
      // Validate ObjectId format
      if (!mongoose.Types.ObjectId.isValid(tenantId)) {
        logger.debug('Invalid tenant ID format', { tenantId });
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }
      
      // Check cache first
      const cacheKey = `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_BY_ID}${tenantId}`;
      const cached = await this.cache.get(cacheKey);
      if (cached && !options.bypassCache) {
        return cached;
      }

      // Build query
      let query = OrganizationTenant.findById(tenantId);

      if (options.populate) {
        const populateFields = Array.isArray(options.populate) ? options.populate : [options.populate];
        populateFields.forEach(field => {
          query = query.populate(field);
        });
      }

      if (options.select) {
        query = query.select(options.select);
      }

      const tenant = await query.lean({ virtuals: true });

      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      // Cache the result
      await this.cache.set(cacheKey, tenant, TENANT_CONSTANTS.CACHE_TTL.TENANT_DATA);

      return tenant;

    } catch (error) {
      logger.error('Failed to get tenant by ID', { error, tenantId });
      throw error;
    }
  }

  /**
   * Get tenant by code
   * @param {string} tenantCode - The tenant code
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - The tenant
   */
  async getTenantByCode(tenantCode, options = {}) {
    try {
      // Validate tenant code format
      const codeRegex = /^[A-Z0-9]{3,10}$/;
      if (!codeRegex.test(tenantCode)) {
        throw new ValidationError(TENANT_CONSTANTS.ERROR_MESSAGES.INVALID_TENANT_CODE);
      }

      // Check cache
      const cacheKey = `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_BY_CODE}${tenantCode}`;
      const cached = await this.cache.get(cacheKey);
      if (cached && !options.bypassCache) {
        return cached;
      }

      const tenant = await OrganizationTenant.findOne({ tenantCode })
        .populate(options.populate || [])
        .select(options.select || '')
        .lean({ virtuals: true });

      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      // Cache the result
      await this.cache.set(cacheKey, tenant, TENANT_CONSTANTS.CACHE_TTL.TENANT_DATA);

      return tenant;

    } catch (error) {
      logger.error('Failed to get tenant by code', { error, tenantCode });
      throw error;
    }
  }

  /**
   * Get tenant by domain
   * @param {string} domain - The domain
   * @returns {Promise<Object>} - The tenant
   */
  async getTenantByDomain(domain) {
    try {
      // Check cache
      const cacheKey = `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_BY_DOMAIN}${domain}`;
      const cached = await this.cache.get(cacheKey);
      if (cached) {
        return cached;
      }

      const tenant = await OrganizationTenant.findByDomain(domain);

      if (!tenant) {
        return null; // Domain not found is not an error
      }

      // Cache the result
      await this.cache.set(cacheKey, tenant, TENANT_CONSTANTS.CACHE_TTL.TENANT_DATA);

      return tenant;

    } catch (error) {
      logger.error('Failed to get tenant by domain', { error, domain });
      throw error;
    }
  }

  /**
   * Update tenant
   * @param {string} tenantId - The tenant ID
   * @param {Object} updateData - The update data
   * @param {string} userId - The ID of the user updating
   * @returns {Promise<Object>} - The updated tenant
   */
  async updateTenant(tenantId, updateData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Updating organization tenant', { tenantId, userId });

      // Get current tenant
      const tenant = await OrganizationTenant.findById(tenantId).session(session);
      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      // Check if tenant is active
      if (tenant.status === TENANT_CONSTANTS.TENANT_STATUS.TERMINATED) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_TERMINATED, 403);
      }

      // Validate update data
      this._validateUpdateData(updateData, tenant);

      // Track changes for audit
      const changes = this._trackChanges(tenant, updateData);

      // Apply updates
      Object.assign(tenant, updateData);
      tenant.updatedBy = userId;

      // Handle special updates
      if (updateData.subscription?.plan) {
        await this._handlePlanChange(tenant, updateData.subscription.plan, session);
      }

      // Save changes
      await tenant.save({ session });

      // Clear cache
      await this._clearTenantCache(tenant);

      // Emit update event
      this.eventEmitter.emit(TENANT_CONSTANTS.EVENT_TYPES.TENANT_UPDATED, {
        tenantId: tenant._id,
        changes,
        userId
      });

      await session.commitTransaction();

      logger.info('Organization tenant updated successfully', { tenantId });

      return tenant;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to update organization tenant', { error, tenantId });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Activate tenant
   * @param {string} tenantId - The tenant ID
   * @param {string} userId - The ID of the user activating
   * @returns {Promise<Object>} - The activated tenant
   */
  async activateTenant(tenantId, userId) {
    try {
      logger.info('Activating organization tenant', { tenantId, userId });

      const tenant = await OrganizationTenant.findById(tenantId);
      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      if (tenant.status === TENANT_CONSTANTS.TENANT_STATUS.ACTIVE) {
        return tenant; // Already active
      }

      if (tenant.status === TENANT_CONSTANTS.TENANT_STATUS.TERMINATED) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_TERMINATED, 403);
      }

      // Verify requirements for activation
      await this._verifyActivationRequirements(tenant);

      // Activate tenant
      tenant.status = TENANT_CONSTANTS.TENANT_STATUS.ACTIVE;
      tenant.flags.isActive = true;
      tenant.activatedAt = new Date();
      tenant.updatedBy = userId;

      // If coming from trial, convert subscription
      if (tenant.subscription.status === TENANT_CONSTANTS.SUBSCRIPTION_STATUS.TRIAL) {
        tenant.subscription.status = TENANT_CONSTANTS.SUBSCRIPTION_STATUS.ACTIVE;
      }

      await tenant.save();

      // Clear cache
      await this._clearTenantCache(tenant);

      // Send activation email
      await this._sendActivationEmail(tenant);

      // Emit activation event
      this.eventEmitter.emit(TENANT_CONSTANTS.EVENT_TYPES.TENANT_ACTIVATED, {
        tenantId: tenant._id,
        userId
      });

      logger.info('Organization tenant activated successfully', { tenantId });

      return tenant;

    } catch (error) {
      logger.error('Failed to activate organization tenant', { error, tenantId });
      throw error;
    }
  }

  /**
   * Suspend tenant
   * @param {string} tenantId - The tenant ID
   * @param {string} reason - Suspension reason
   * @param {string} userId - The ID of the user suspending
   * @returns {Promise<Object>} - The suspended tenant
   */
  async suspendTenant(tenantId, reason, userId) {
    try {
      logger.info('Suspending organization tenant', { tenantId, reason, userId });

      const tenant = await OrganizationTenant.findById(tenantId);
      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      await tenant.suspend(reason);
      tenant.updatedBy = userId;
      await tenant.save();

      // Clear cache
      await this._clearTenantCache(tenant);

      // Send suspension email
      await this._sendSuspensionEmail(tenant, reason);

      // Emit suspension event
      this.eventEmitter.emit(TENANT_CONSTANTS.EVENT_TYPES.TENANT_SUSPENDED, {
        tenantId: tenant._id,
        reason,
        userId
      });

      logger.info('Organization tenant suspended successfully', { tenantId });

      return tenant;

    } catch (error) {
      logger.error('Failed to suspend organization tenant', { error, tenantId });
      throw error;
    }
  }

  /**
   * Search tenants
   * @param {Object} filters - Search filters
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - Search results
   */
  async searchTenants(filters = {}, options = {}) {
    try {
      logger.debug('Searching organization tenants', { filters, options });

      const {
        page = 1,
        limit = 20,
        sort = '-createdAt',
        populate = [],
        select = ''
      } = options;

      // Build query
      const query = this._buildSearchQuery(filters);

      // Execute count query
      const total = await OrganizationTenant.countDocuments(query);

      // Execute main query
      let mainQuery = OrganizationTenant.find(query)
        .sort(sort)
        .limit(limit)
        .skip((page - 1) * limit)
        .select(select)
        .lean({ virtuals: true });

      // Apply population
      populate.forEach(field => {
        mainQuery = mainQuery.populate(field);
      });

      const tenants = await mainQuery;

      return {
        tenants,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      };

    } catch (error) {
      logger.error('Failed to search organization tenants', { error, filters });
      throw error;
    }
  }

  /**
   * Get tenant statistics
   * @param {Object} filters - Optional filters
   * @returns {Promise<Object>} - Statistics
   */
  async getTenantStatistics(filters = {}) {
    try {
      // Check cache
      const cacheKey = TENANT_CONSTANTS.CACHE_KEYS.TENANT_STATS;
      const cached = await this.cache.get(cacheKey);
      if (cached && !filters.bypassCache) {
        return cached;
      }

      const stats = await OrganizationTenant.getStatistics();

      // Add additional statistics
      const enrichedStats = {
        ...stats,
        summary: {
          totalTenants: stats.totals[0]?.total || 0,
          activeTenants: stats.totals[0]?.active || 0,
          trialTenants: stats.totals[0]?.trial || 0,
          suspendedTenants: stats.totals[0]?.suspended || 0
        },
        byStatus: this._formatGroupedStats(stats.byStatus),
        byPlan: this._formatGroupedStats(stats.byPlan),
        bySize: this._formatGroupedStats(stats.bySize)
      };

      // Cache the results
      await this.cache.set(cacheKey, enrichedStats, TENANT_CONSTANTS.CACHE_TTL.TENANT_STATS);

      return enrichedStats;

    } catch (error) {
      logger.error('Failed to get tenant statistics', { error });
      throw error;
    }
  }

  /**
   * Update subscription
   * @param {string} tenantId - The tenant ID
   * @param {Object} subscriptionData - Subscription update data
   * @param {string} userId - The ID of the user updating
   * @returns {Promise<Object>} - The updated tenant
   */
  async updateSubscription(tenantId, subscriptionData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Updating tenant subscription', { tenantId, subscriptionData, userId });

      const tenant = await OrganizationTenant.findById(tenantId).session(session);
      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      // Validate plan change
      const oldPlan = tenant.subscription.plan;
      const newPlan = subscriptionData.plan;

      if (newPlan && !Object.values(TENANT_CONSTANTS.SUBSCRIPTION_PLANS).includes(newPlan)) {
        throw new ValidationError(TENANT_CONSTANTS.ERROR_MESSAGES.INVALID_PLAN);
      }

      // Update subscription
      Object.assign(tenant.subscription, subscriptionData);
      tenant.updatedBy = userId;

      // Handle plan change
      if (newPlan && newPlan !== oldPlan) {
        await this._handlePlanChange(tenant, newPlan, session);
        
        // Emit appropriate event
        const eventType = this._isPlanUpgrade(oldPlan, newPlan) 
          ? TENANT_CONSTANTS.EVENT_TYPES.TENANT_UPGRADED
          : TENANT_CONSTANTS.EVENT_TYPES.TENANT_DOWNGRADED;
          
        this.eventEmitter.emit(eventType, {
          tenantId: tenant._id,
          oldPlan,
          newPlan,
          userId
        });
      }

      await tenant.save({ session });
      await session.commitTransaction();

      // Clear cache
      await this._clearTenantCache(tenant);

      logger.info('Tenant subscription updated successfully', { tenantId });

      return tenant;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to update tenant subscription', { error, tenantId });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Add custom domain
   * @param {string} tenantId - The tenant ID
   * @param {string} domain - The domain to add
   * @param {string} userId - The ID of the user adding
   * @returns {Promise<Object>} - The domain object
   */
  async addCustomDomain(tenantId, domain, userId) {
    try {
      logger.info('Adding custom domain to tenant', { tenantId, domain, userId });

      const tenant = await OrganizationTenant.findById(tenantId);
      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      // Check if feature is available
      if (!tenant.hasFeature(TENANT_CONSTANTS.FEATURES.WHITE_LABEL)) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.FEATURE_NOT_AVAILABLE, 403);
      }

      // Add domain
      const domainObj = await tenant.addDomain(domain);
      tenant.updatedBy = userId;
      await tenant.save();

      // Clear cache
      await this._clearTenantCache(tenant);

      // Emit event
      this.eventEmitter.emit(TENANT_CONSTANTS.EVENT_TYPES.DOMAIN_ADDED, {
        tenantId: tenant._id,
        domain,
        userId
      });

      logger.info('Custom domain added successfully', { tenantId, domain });

      return domainObj;

    } catch (error) {
      logger.error('Failed to add custom domain', { error, tenantId, domain });
      throw error;
    }
  }

  /**
   * Verify custom domain
   * @param {string} tenantId - The tenant ID
   * @param {string} domain - The domain to verify
   * @returns {Promise<boolean>} - Verification status
   */
  async verifyCustomDomain(tenantId, domain) {
    try {
      logger.info('Verifying custom domain', { tenantId, domain });

      const tenant = await OrganizationTenant.findById(tenantId);
      if (!tenant) {
        throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.TENANT_NOT_FOUND, 404);
      }

      const isVerified = await tenant.verifyDomain(domain);

      if (isVerified) {
        // Clear cache
        await this._clearTenantCache(tenant);

        // Emit event
        this.eventEmitter.emit(TENANT_CONSTANTS.EVENT_TYPES.DOMAIN_VERIFIED, {
          tenantId: tenant._id,
          domain
        });
      }

      logger.info('Custom domain verification completed', { tenantId, domain, isVerified });

      return isVerified;

    } catch (error) {
      logger.error('Failed to verify custom domain', { error, tenantId, domain });
      throw error;
    }
  }

  /**
   * Get tenant usage
   * @param {string} tenantId - The tenant ID
   * @returns {Promise<Object>} - Usage data
   */
  async getTenantUsage(tenantId) {
    try {
      // Check cache
      const cacheKey = `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_USAGE}${tenantId}`;
      const cached = await this.cache.get(cacheKey);
      if (cached) {
        return cached;
      }

      const tenant = await this.getTenantById(tenantId);

      const usage = {
        users: {
          current: tenant.resourceLimits.users.current,
          max: tenant.resourceLimits.users.max,
          percentage: tenant.resourceLimits.users.max === -1 ? 0 : 
            Math.round((tenant.resourceLimits.users.current / tenant.resourceLimits.users.max) * 100)
        },
        storage: {
          currentGB: parseFloat(tenant.storageUsedGB),
          maxGB: tenant.resourceLimits.storage.maxGB,
          percentage: tenant.storageUsagePercent
        },
        apiCalls: {
          currentMonth: tenant.resourceLimits.apiCalls.currentMonth,
          maxPerMonth: tenant.resourceLimits.apiCalls.maxPerMonth,
          percentage: tenant.resourceLimits.apiCalls.maxPerMonth === -1 ? 0 :
            Math.round((tenant.resourceLimits.apiCalls.currentMonth / tenant.resourceLimits.apiCalls.maxPerMonth) * 100)
        },
        projects: {
          current: tenant.resourceLimits.projects.current,
          max: tenant.resourceLimits.projects.max,
          percentage: tenant.resourceLimits.projects.max === -1 ? 0 :
            Math.round((tenant.resourceLimits.projects.current / tenant.resourceLimits.projects.max) * 100)
        }
      };

      // Cache the results
      await this.cache.set(cacheKey, usage, TENANT_CONSTANTS.CACHE_TTL.TENANT_USAGE);

      return usage;

    } catch (error) {
      logger.error('Failed to get tenant usage', { error, tenantId });
      throw error;
    }
  }

  /**
   * Private helper methods
   */

  /**
   * Validate tenant data
   * @private
   */
  _validateTenantData(data) {
    const required = ['name', 'contactEmail'];
    const missing = required.filter(field => !data[field]);
    
    if (missing.length > 0) {
      throw new ValidationError(`Missing required fields: ${missing.join(', ')}`);
    }

    // Validate email format
    const emailRegex = /^\S+@\S+\.\S+$/;
    if (!emailRegex.test(data.contactEmail)) {
      throw new ValidationError('Invalid email format');
    }

    // Validate tenant code if provided
    if (data.tenantCode) {
      const codeRegex = /^[A-Z0-9]{3,10}$/;
      if (!codeRegex.test(data.tenantCode)) {
        throw new ValidationError(TENANT_CONSTANTS.ERROR_MESSAGES.INVALID_TENANT_CODE);
      }
    }
  }

  /**
   * Generate unique tenant code
   * @private
   */
  async _generateUniqueTenantCode(name) {
    const baseCode = name
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '')
      .substring(0, 6) || 'ORG';

    let code = baseCode;
    let suffix = 0;

    while (await OrganizationTenant.findOne({ tenantCode: code })) {
      suffix++;
      code = `${baseCode}${suffix}`;
    }

    return code;
  }

  /**
   * Set resource limits based on plan
   * @private
   */
  _setResourceLimits(tenant) {
    const planLimits = TENANT_CONSTANTS.PLAN_LIMITS[tenant.subscription.plan];
    
    if (!planLimits) {
      logger.warn('No plan limits found for plan', { plan: tenant.subscription.plan });
      return;
    }

    // Initialize resourceLimits structure if it doesn't exist
    if (!tenant.resourceLimits) {
      tenant.resourceLimits = {};
    }

    // Initialize each resource type with default structure
    if (!tenant.resourceLimits.users) {
      tenant.resourceLimits.users = { max: -1, current: 0 };
    }

    if (!tenant.resourceLimits.storage) {
      tenant.resourceLimits.storage = { maxGB: -1, currentBytes: 0 };
    }

    if (!tenant.resourceLimits.apiCalls) {
      tenant.resourceLimits.apiCalls = { maxPerMonth: -1, currentMonth: 0 };
    }

    if (!tenant.resourceLimits.projects) {
      tenant.resourceLimits.projects = { max: -1, current: 0 };
    }

    if (!tenant.resourceLimits.customDomains) {
      tenant.resourceLimits.customDomains = { max: 1, current: 0 };
    }

    // Now safely set the limits
    tenant.resourceLimits.users.max = planLimits.users;
    tenant.resourceLimits.storage.maxGB = planLimits.storageGB;
    tenant.resourceLimits.apiCalls.maxPerMonth = planLimits.apiCallsPerMonth;
    tenant.resourceLimits.projects.max = planLimits.projects;
    tenant.resourceLimits.customDomains.max = planLimits.customDomains;

    logger.debug('Resource limits set successfully', { 
      tenantId: tenant._id || tenant.tenantId,
      plan: tenant.subscription.plan,
      limits: tenant.resourceLimits
    });
  }

  /**
   * Initialize tenant settings
   * @private
   */
  async _initializeTenantSettings(tenant, session) {
    // Create default roles and permissions
    // Initialize audit log
    // Set up default integrations
    // etc.
  }

  /**
   * Create tenant database
   * @private
   */
  async _createTenantDatabase(tenant, session) {
    // Implementation for creating dedicated tenant database
    // This would vary based on your database strategy
  }

  /**
   * Handle plan change
   * @private
   */
  async _handlePlanChange(tenant, newPlan, session) {
    // Update resource limits
    const planLimits = TENANT_CONSTANTS.PLAN_LIMITS[newPlan];
    
    if (planLimits) {
      // Check if downgr ading and current usage exceeds new limits
      if (tenant.resourceLimits.users.current > planLimits.users && planLimits.users !== -1) {
        throw new AppError('Current user count exceeds new plan limit', 400);
      }

      // Update limits
      tenant.resourceLimits.users.max = planLimits.users;
      tenant.resourceLimits.storage.maxGB = planLimits.storageGB;
      tenant.resourceLimits.apiCalls.maxPerMonth = planLimits.apiCallsPerMonth;
      tenant.resourceLimits.projects.max = planLimits.projects;
      tenant.resourceLimits.customDomains.max = planLimits.customDomains;
    }

    // Update features based on plan
    // This would be more sophisticated in production
    if (newPlan === TENANT_CONSTANTS.SUBSCRIPTION_PLANS.ENTERPRISE) {
      Object.keys(tenant.settings.features).forEach(feature => {
        tenant.settings.features[feature] = true;
      });
    }
  }

  /**
   * Determine if plan change is an upgrade
   * @private
   */
  _isPlanUpgrade(oldPlan, newPlan) {
    const planOrder = [
      TENANT_CONSTANTS.SUBSCRIPTION_PLANS.TRIAL,
      TENANT_CONSTANTS.SUBSCRIPTION_PLANS.STARTER,
      TENANT_CONSTANTS.SUBSCRIPTION_PLANS.GROWTH,
      TENANT_CONSTANTS.SUBSCRIPTION_PLANS.PROFESSIONAL,
      TENANT_CONSTANTS.SUBSCRIPTION_PLANS.ENTERPRISE
    ];

    return planOrder.indexOf(newPlan) > planOrder.indexOf(oldPlan);
  }

  /**
   * Verify activation requirements
   * @private
   */
  async _verifyActivationRequirements(tenant) {
    // Check if payment information is set up
    if (!tenant.billing.customerId && tenant.subscription.plan !== TENANT_CONSTANTS.SUBSCRIPTION_PLANS.TRIAL) {
      throw new AppError(TENANT_CONSTANTS.ERROR_MESSAGES.PAYMENT_REQUIRED, 400);
    }

    // Check if tenant is verified
    if (!tenant.flags.isVerified && tenant.subscription.plan !== TENANT_CONSTANTS.SUBSCRIPTION_PLANS.TRIAL) {
      throw new AppError('Tenant verification required', 400);
    }
  }

  /**
   * Clear tenant cache
   * @private
   */
  async _clearTenantCache(tenant) {
    const cacheKeys = [
      `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_BY_ID}${tenant._id}`,
      `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_BY_CODE}${tenant.tenantCode}`,
      `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_LIMITS}${tenant._id}`,
      `${TENANT_CONSTANTS.CACHE_KEYS.TENANT_USAGE}${tenant._id}`,
      TENANT_CONSTANTS.CACHE_KEYS.TENANT_STATS
    ];

    // Add domain cache keys
    tenant.domains.forEach(domain => {
      cacheKeys.push(`${TENANT_CONSTANTS.CACHE_KEYS.TENANT_BY_DOMAIN}${domain.domain}`);
    });

    await Promise.all(cacheKeys.map(key => this.cache.del(key)));
  }

  /**
   * Track changes for audit
   * @private
   */
  _trackChanges(original, updates) {
    const changes = {};
    
    Object.keys(updates).forEach(key => {
      if (JSON.stringify(original[key]) !== JSON.stringify(updates[key])) {
        changes[key] = {
          from: original[key],
          to: updates[key]
        };
      }
    });

    return changes;
  }

  /**
   * Validate update data
   * @private
   */
  _validateUpdateData(data, tenant) {
    // Prevent updating immutable fields
    const immutableFields = ['tenantId', 'tenantCode', 'createdAt', 'owner'];
    immutableFields.forEach(field => {
      if (data[field]) {
        delete data[field];
      }
    });

    // Validate email if provided
    if (data.contactEmail) {
      const emailRegex = /^\S+@\S+\.\S+$/;
      if (!emailRegex.test(data.contactEmail)) {
        throw new ValidationError('Invalid email format');
      }
    }

    // Validate status transitions
    if (data.status) {
      const validTransitions = {
        [TENANT_CONSTANTS.TENANT_STATUS.PENDING]: ['active', 'terminated'],
        [TENANT_CONSTANTS.TENANT_STATUS.ACTIVE]: ['suspended', 'terminated'],
        [TENANT_CONSTANTS.TENANT_STATUS.SUSPENDED]: ['active', 'terminated'],
        [TENANT_CONSTANTS.TENANT_STATUS.TERMINATED]: [] // No transitions from terminated
      };

      const currentStatus = tenant.status;
      const allowedTransitions = validTransitions[currentStatus] || [];

      if (!allowedTransitions.includes(data.status)) {
        throw new ValidationError(`Invalid status transition from ${currentStatus} to ${data.status}`);
      }
    }
  }

  /**
   * Build search query
   * @private
   */
  _buildSearchQuery(filters) {
    const query = {};

    // Status filter
    if (filters.status) {
      query.status = Array.isArray(filters.status) ? { $in: filters.status } : filters.status;
    }

    // Plan filter
    if (filters.plan) {
      query['subscription.plan'] = Array.isArray(filters.plan) ? { $in: filters.plan } : filters.plan;
    }

    // Size filter
    if (filters.size) {
      query.size = Array.isArray(filters.size) ? { $in: filters.size } : filters.size;
    }

    // Industry filter
    if (filters.industry) {
      query.industry = Array.isArray(filters.industry) ? { $in: filters.industry } : filters.industry;
    }

    // Search term
    if (filters.search) {
      query.$or = [
        { name: { $regex: filters.search, $options: 'i' } },
        { tenantCode: { $regex: filters.search, $options: 'i' } },
        { contactEmail: { $regex: filters.search, $options: 'i' } }
      ];
    }

    // Date filters
    if (filters.createdAfter) {
      query.createdAt = { $gte: new Date(filters.createdAfter) };
    }

    if (filters.createdBefore) {
      query.createdAt = { ...query.createdAt, $lte: new Date(filters.createdBefore) };
    }

    // Feature filters
    if (filters.features) {
      Object.entries(filters.features).forEach(([feature, enabled]) => {
        query[`settings.features.${feature}`] = enabled;
      });
    }

    // Flag filters
    if (filters.flags) {
      Object.entries(filters.flags).forEach(([flag, value]) => {
        query[`flags.${flag}`] = value;
      });
    }

    return query;
  }

  /**
   * Format grouped statistics
   * @private
   */
  _formatGroupedStats(groupedData) {
    const formatted = {};
    groupedData.forEach(item => {
      if (item._id) {
        formatted[item._id] = item.count;
      }
    });
    return formatted;
  }

  /**
   * Email notification methods
   * @private
   */
  async _sendWelcomeEmail(tenant) {
    try {
      await EmailService.send({
        to: tenant.contactEmail,
        subject: 'Welcome to Our Platform!',
        template: 'tenant-welcome',
        data: {
          tenantName: tenant.name,
          tenantCode: tenant.tenantCode,
          trialDays: TENANT_CONSTANTS.TRIAL_DURATION_DAYS
        }
      });
    } catch (error) {
      logger.error('Failed to send welcome email', { error, tenantId: tenant._id });
    }
  }

  async _sendActivationEmail(tenant) {
    try {
      await EmailService.send({
        to: tenant.contactEmail,
        subject: 'Your Organization is Now Active!',
        template: 'tenant-activation',
        data: {
          tenantName: tenant.name,
          activationDate: tenant.activatedAt
        }
      });
    } catch (error) {
      logger.error('Failed to send activation email', { error, tenantId: tenant._id });
    }
  }

  async _sendSuspensionEmail(tenant, reason) {
    try {
      await EmailService.send({
        to: tenant.contactEmail,
        subject: 'Important: Your Organization Has Been Suspended',
        template: 'tenant-suspension',
        data: {
          tenantName: tenant.name,
          reason,
          supportEmail: process.env.SUPPORT_EMAIL || 'support@platform.com'
        }
      });
    } catch (error) {
      logger.error('Failed to send suspension email', { error, tenantId: tenant._id });
    }
  }
}

module.exports = new OrganizationTenantService();