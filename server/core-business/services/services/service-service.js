// server/core-business/services/services/services-service.js
/**
 * @file Services Service
 * @description Business logic for service management
 * @version 3.0.0
 */

const mongoose = require('mongoose');

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  ForbiddenError,
  AppError 
} = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { CacheService } = require('../../../shared/services/cache-service');
const EmailService = require('../../../shared/services/email-service');
const FileService = require('../../../shared/services/file-service');
const AuditService = require('../../../shared/security/services/audit-service');
const Service = require('../models/services-model');
const ServicePackage = require('../models/schemas/service-package-model');
const ServiceTemplate = require('../models/schemas/service-template-model');

/**
 * Services Service Class
 * @class ServicesService
 */
class ServicesService {
  /**
   * Create new service
   * @param {Object} serviceData - Service data
   * @param {Object} user - Current user
   * @returns {Promise<Object>} Created service
   */
  static async createService(serviceData, user) {
    try {
      // Validate required fields
      const requiredFields = ['name', 'category', 'description', 'type', 'deliveryMethod', 'pricing'];
      const missingFields = requiredFields.filter(field => {
        if (field === 'category') return !serviceData.category?.primary;
        if (field === 'description') return !serviceData.description?.short || !serviceData.description?.full;
        if (field === 'pricing') return !serviceData.pricing?.basePrice || !serviceData.pricing?.billingCycle;
        return !serviceData[field];
      });
      
      if (missingFields.length > 0) {
        throw new ValidationError(`Missing required fields: ${missingFields.join(', ')}`);
      }
      
      // Check for duplicate service name within organization
      const existingService = await Service.findOne({
        name: serviceData.name,
        organization: serviceData.organization || user.organization.current,
        status: { $ne: 'archived' }
      });
      
      if (existingService) {
        throw new ConflictError('Service with this name already exists in the organization');
      }
      
      // Create service instance
      const service = new Service({
        ...serviceData,
        organization: serviceData.organization || user.organization.current,
        owner: user._id,
        metadata: {
          createdBy: user._id
        }
      });
      
      // Save service
      await service.save();
      
      // Populate references
      await service.populate([
        { path: 'owner', select: 'firstName lastName email' },
        { path: 'organization', select: 'name slug' }
      ]);
      
      // Log activity
      await AuditService.log({
        userId: user._id,
        action: 'service.created',
        resource: 'service',
        resourceId: service._id,
        details: {
          serviceId: service.serviceId,
          name: service.name,
          category: service.category.primary
        },
        ip: user.lastIp
      });
      
      // Clear cache
      await CacheService.clearPattern(`services:org:${service.organization}:*`);
      
      logger.info('Service created successfully', {
        serviceId: service.serviceId,
        name: service.name,
        userId: user._id
      });
      
      return service;
      
    } catch (error) {
      logger.error('Create service error', { error, serviceData, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Update service
   * @param {string} serviceId - Service ID
   * @param {Object} updates - Update data
   * @param {Object} user - Current user
   * @returns {Promise<Object>} Updated service
   */
  static async updateService(serviceId, updates, user) {
    try {
      // Find service
      const service = await Service.findById(serviceId);
      
      if (!service) {
        throw new NotFoundError('Service not found');
      }
      
      // Check permissions
      if (!service.canBeManaged(user._id) && user.role.primary !== 'admin') {
        throw new ForbiddenError('You do not have permission to update this service');
      }
      
      // Prevent updating certain fields
      const restrictedFields = ['serviceId', 'organization', 'owner', 'metrics', 'reviews'];
      restrictedFields.forEach(field => delete updates[field]);
      
      // Handle status changes
      if (updates.status && updates.status !== service.status) {
        await this.validateStatusChange(service, updates.status);
      }
      
      // Update change log
      const changeLog = {
        version: service.metadata.version + 1,
        changes: JSON.stringify(updates),
        changedBy: user._id,
        changedAt: new Date()
      };
      
      // Apply updates
      Object.assign(service, updates);
      service.metadata.lastModifiedBy = user._id;
      service.metadata.changeLog.push(changeLog);
      
      // Save service
      await service.save();
      
      // Log activity
      await AuditService.log({
        userId: user._id,
        action: 'service.updated',
        resource: 'service',
        resourceId: service._id,
        details: {
          serviceId: service.serviceId,
          updates: Object.keys(updates)
        },
        ip: user.lastIp
      });
      
      // Clear cache
      await CacheService.clearPattern(`services:*:${service._id}`);
      await CacheService.clearPattern(`services:org:${service.organization}:*`);
      
      return service;
      
    } catch (error) {
      logger.error('Update service error', { error, serviceId, updates, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Get service by ID
   * @param {string} serviceId - Service ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Service
   */
  static async getServiceById(serviceId, options = {}) {
    try {
      const { populate = true, includeArchived = false } = options;
      
      const query = Service.findById(serviceId);
      
      if (!includeArchived) {
        query.where('status').ne('archived');
      }
      
      if (populate) {
        query.populate([
          { path: 'owner', select: 'firstName lastName email profile.avatar' },
          { path: 'organization', select: 'name slug logo' },
          { path: 'managers', select: 'firstName lastName email' },
          { path: 'relatedServices.service', select: 'name slug pricing.basePrice' },
          { path: 'packages', select: 'name description pricing' }
        ]);
      }
      
      const service = await query;
      
      if (!service) {
        throw new NotFoundError('Service not found');
      }
      
      // Try to get from cache first
      const cacheKey = `services:detail:${serviceId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached && !options.skipCache) {
        return cached;
      }
      
      // Store in cache
      await CacheService.set(cacheKey, service, 300); // 5 minutes
      
      return service;
      
    } catch (error) {
      logger.error('Get service by ID error', { error, serviceId });
      throw error;
    }
  }
  
  /**
   * List services with filtering and pagination
   * @param {Object} filters - Filter options
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Services list with pagination
   */
  static async listServices(filters = {}, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        sort = '-createdAt',
        populate = true
      } = options;
      
      // Build query
      const query = {};
      
      // Apply filters
      if (filters.organization) {
        query.organization = filters.organization;
      }
      
      if (filters.category) {
        query.$or = [
          { 'category.primary': filters.category },
          { 'category.secondary': filters.category }
        ];
      }
      
      if (filters.type) {
        query.type = filters.type;
      }
      
      if (filters.deliveryMethod) {
        query.deliveryMethod = filters.deliveryMethod;
      }
      
      if (filters.status) {
        query.status = filters.status;
      } else {
        query.status = { $ne: 'archived' };
      }
      
      if (filters.availability) {
        query['availability.status'] = filters.availability;
      }
      
      if (filters.priceRange) {
        query['pricing.basePrice'] = {
          $gte: filters.priceRange.min || 0,
          $lte: filters.priceRange.max || Number.MAX_SAFE_INTEGER
        };
      }
      
      if (filters.search) {
        const searchRegex = new RegExp(filters.search, 'i');
        query.$or = [
          { name: searchRegex },
          { 'description.short': searchRegex },
          { 'category.tags': searchRegex }
        ];
      }
      
      // Execute query with pagination
      const skip = (page - 1) * limit;
      
      let servicesQuery = Service.find(query)
        .sort(sort)
        .skip(skip)
        .limit(limit);
      
      if (populate) {
        servicesQuery = servicesQuery.populate([
          { path: 'owner', select: 'firstName lastName email' },
          { path: 'organization', select: 'name slug' }
        ]);
      }
      
      const [services, total] = await Promise.all([
        servicesQuery,
        Service.countDocuments(query)
      ]);
      
      return {
        services,
        pagination: {
          total,
          pages: Math.ceil(total / limit),
          page,
          limit
        }
      };
      
    } catch (error) {
      logger.error('List services error', { error, filters });
      throw error;
    }
  }
  
  /**
   * Search services
   * @param {string} searchTerm - Search term
   * @param {Object} options - Search options
   * @returns {Promise<Array>} Search results
   */
  static async searchServices(searchTerm, options = {}) {
    try {
      const {
        limit = 20,
        organization,
        includeArchived = false
      } = options;
      
      const results = await Service.searchServices(searchTerm, {
        limit,
        organization,
        status: includeArchived ? null : { $ne: 'archived' }
      });
      
      return results;
      
    } catch (error) {
      logger.error('Search services error', { error, searchTerm });
      throw error;
    }
  }
  
  /**
   * Calculate service pricing
   * @param {string} serviceId - Service ID
   * @param {Object} options - Pricing options
   * @returns {Promise<Object>} Calculated pricing
   */
  static async calculatePricing(serviceId, options = {}) {
    try {
      const service = await this.getServiceById(serviceId, { populate: false });
      
      if (!service.isActive) {
        throw new ValidationError('Service is not active');
      }
      
      const pricing = service.calculatePrice(options);
      
      // Add additional fees if any
      if (options.additionalFees) {
        pricing.additionalFees = options.additionalFees;
        pricing.total += options.additionalFees.reduce((sum, fee) => sum + fee.amount, 0);
      }
      
      return {
        service: {
          id: service._id,
          name: service.name,
          type: service.type,
          billingCycle: service.pricing.billingCycle
        },
        pricing,
        options
      };
      
    } catch (error) {
      logger.error('Calculate pricing error', { error, serviceId, options });
      throw error;
    }
  }
  
  /**
   * Add service review
   * @param {string} serviceId - Service ID
   * @param {Object} reviewData - Review data
   * @param {Object} user - Current user
   * @returns {Promise<Object>} Updated service
   */
  static async addReview(serviceId, reviewData, user) {
    try {
      const service = await this.getServiceById(serviceId, { populate: false });
      
      // Check if user has already reviewed
      const existingReview = service.reviews.find(
        r => r.client.toString() === user._id.toString()
      );
      
      if (existingReview) {
        throw new ConflictError('You have already reviewed this service');
      }
      
      // Validate review data
      if (!reviewData.rating || reviewData.rating < 1 || reviewData.rating > 5) {
        throw new ValidationError('Rating must be between 1 and 5');
      }
      
      // Add review
      const review = {
        client: user._id,
        project: reviewData.projectId,
        rating: reviewData.rating,
        feedback: {
          positive: reviewData.positive,
          improvement: reviewData.improvement,
          recommendation: reviewData.recommendation || false
        },
        verified: false // Will be verified by admin
      };
      
      await service.addReview(review);
      
      // Send notification to service owner
      await EmailService.sendServiceReviewNotification(service, review);
      
      // Log activity
      await AuditService.log({
        userId: user._id,
        action: 'service.reviewed',
        resource: 'service',
        resourceId: service._id,
        details: {
          rating: review.rating,
          recommendation: review.feedback.recommendation
        },
        ip: user.lastIp
      });
      
      return service;
      
    } catch (error) {
      logger.error('Add review error', { error, serviceId, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Update service availability
   * @param {string} serviceId - Service ID
   * @param {string} status - New availability status
   * @param {Object} options - Additional options
   * @param {Object} user - Current user
   * @returns {Promise<Object>} Updated service
   */
  static async updateAvailability(serviceId, status, options = {}, user) {
    try {
      const service = await this.getServiceById(serviceId, { populate: false });
      
      // Check permissions
      if (!service.canBeManaged(user._id) && user.role.primary !== 'admin') {
        throw new ForbiddenError('You do not have permission to update service availability');
      }
      
      // Validate status
      const validStatuses = ['available', 'limited', 'booked', 'discontinued', 'coming_soon'];
      if (!validStatuses.includes(status)) {
        throw new ValidationError(`Invalid availability status. Must be one of: ${validStatuses.join(', ')}`);
      }
      
      // Update availability
      await service.updateAvailability(status, options.capacity);
      
      // Add blackout dates if provided
      if (options.blackoutDates) {
        service.availability.blackoutDates.push(...options.blackoutDates);
        await service.save();
      }
      
      // Log activity
      await AuditService.log({
        userId: user._id,
        action: 'service.availability.updated',
        resource: 'service',
        resourceId: service._id,
        details: {
          previousStatus: service.availability.status,
          newStatus: status,
          capacity: options.capacity
        },
        ip: user.lastIp
      });
      
      // Clear cache
      await CacheService.clearPattern(`services:*:${service._id}`);
      
      return service;
      
    } catch (error) {
      logger.error('Update availability error', { error, serviceId, status });
      throw error;
    }
  }
  
  /**
   * Clone service
   * @param {string} serviceId - Service ID to clone
   * @param {Object} options - Clone options
   * @param {Object} user - Current user
   * @returns {Promise<Object>} Cloned service
   */
  static async cloneService(serviceId, options = {}, user) {
    try {
      const originalService = await this.getServiceById(serviceId, { populate: false });
      
      // Check permissions
      if (!originalService.canBeManaged(user._id) && user.role.primary !== 'admin') {
        throw new ForbiddenError('You do not have permission to clone this service');
      }
      
      // Prepare cloned data
      const clonedData = originalService.toObject();
      
      // Remove unique fields and metadata
      delete clonedData._id;
      delete clonedData.serviceId;
      delete clonedData.slug;
      delete clonedData.metrics;
      delete clonedData.reviews;
      delete clonedData.createdAt;
      delete clonedData.updatedAt;
      delete clonedData.metadata;
      
      // Apply overrides
      Object.assign(clonedData, {
        name: options.name || `${originalService.name} (Copy)`,
        status: 'draft',
        owner: user._id,
        managers: [],
        metadata: {
          createdBy: user._id,
          clonedFrom: originalService._id
        }
      });
      
      // Create cloned service
      const clonedService = await this.createService(clonedData, user);
      
      logger.info('Service cloned successfully', {
        originalId: originalService._id,
        clonedId: clonedService._id,
        userId: user._id
      });
      
      return clonedService;
      
    } catch (error) {
      logger.error('Clone service error', { error, serviceId, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Archive service
   * @param {string} serviceId - Service ID
   * @param {string} reason - Archive reason
   * @param {Object} user - Current user
   * @returns {Promise<Object>} Archived service
   */
  static async archiveService(serviceId, reason, user) {
    try {
      const service = await this.getServiceById(serviceId, { populate: false });
      
      // Check permissions
      if (!service.canBeManaged(user._id) && user.role.primary !== 'admin') {
        throw new ForbiddenError('You do not have permission to archive this service');
      }
      
      // Check if service can be archived
      if (service.metrics.activeProjects > 0) {
        throw new ValidationError('Cannot archive service with active projects');
      }
      
      // Update status
      service.status = 'archived';
      service.lifecycle.deprecatedAt = new Date();
      service.metadata.lastModifiedBy = user._id;
      
      // Add archive note
      service.metadata.internalNotes.push({
        note: `Service archived: ${reason}`,
        addedBy: user._id,
        type: 'general'
      });
      
      await service.save();
      
      // Log activity
      await AuditService.log({
        userId: user._id,
        action: 'service.archived',
        resource: 'service',
        resourceId: service._id,
        details: {
          reason,
          activeProjects: service.metrics.activeProjects
        },
        ip: user.lastIp
      });
      
      // Clear cache
      await CacheService.clearPattern(`services:*:${service._id}`);
      await CacheService.clearPattern(`services:org:${service.organization}:*`);
      
      return service;
      
    } catch (error) {
      logger.error('Archive service error', { error, serviceId, userId: user._id });
      throw error;
    }
  }
  
  /**
   * Get service statistics
   * @param {string} organizationId - Organization ID
   * @returns {Promise<Object>} Service statistics
   */
  static async getStatistics(organizationId) {
    try {
      const cacheKey = `services:stats:${organizationId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached) {
        return cached;
      }
      
      const stats = await Service.getStatistics(organizationId);
      
      // Add additional statistics
      const categoryStats = await Service.aggregate([
        { $match: { organization: mongoose.Types.ObjectId(organizationId) } },
        { $group: {
          _id: '$category.primary',
          count: { $sum: 1 },
          avgRating: { $avg: '$metrics.averageRating' },
          totalRevenue: { $sum: '$metrics.totalRevenue' }
        }},
        { $sort: { totalRevenue: -1 } }
      ]);
      
      stats.byCategory = categoryStats;
      
      // Cache for 30 minutes
      await CacheService.set(cacheKey, stats, 1800);
      
      return stats;
      
    } catch (error) {
      logger.error('Get statistics error', { error, organizationId });
      throw error;
    }
  }
  
  /**
   * Validate status change
   * @private
   */
  static async validateStatusChange(service, newStatus) {
    const currentStatus = service.status;
    
    // Define valid status transitions
    const validTransitions = {
      draft: ['pending_approval', 'active'],
      pending_approval: ['active', 'draft'],
      active: ['inactive', 'deprecated'],
      inactive: ['active', 'deprecated', 'archived'],
      deprecated: ['archived'],
      archived: [] // Cannot transition from archived
    };
    
    if (!validTransitions[currentStatus]?.includes(newStatus)) {
      throw new ValidationError(
        `Cannot change status from ${currentStatus} to ${newStatus}`
      );
    }
    
    // Additional validations
    if (newStatus === 'active' && !service.isAvailable()) {
      throw new ValidationError('Service must be available to be activated');
    }
    
    if (newStatus === 'archived' && service.metrics.activeProjects > 0) {
      throw new ValidationError('Cannot archive service with active projects');
    }
  }
}

module.exports = ServicesService;