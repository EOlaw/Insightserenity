// server/core-business/services/controllers/services-controller.js
/**
 * @file Services Controller
 * @description Handles HTTP requests for service management
 * @version 3.0.0
 */

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { 
  ValidationError, 
  NotFoundError,
  ForbiddenError 
} = require('../../../shared/utils/app-error');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const logger = require('../../../shared/utils/logger');
const responseHandler = require('../../../shared/utils/response-handler');
const ServicesService = require('../services/services-service');
const FileService = require('../../../shared/services/file-service');

/**
 * Services Controller Class
 * @class ServicesController
 */
class ServicesController {
  /**
   * Create new service
   * @route   POST /api/services
   * @access  Private - Admin, Manager
   */
  static createService = asyncHandler(async (req, res) => {
    const serviceData = {
      name: req.body.name,
      slug: req.body.slug,
      category: req.body.category,
      description: req.body.description,
      type: req.body.type,
      deliveryMethod: req.body.deliveryMethod,
      duration: req.body.duration,
      pricing: req.body.pricing,
      deliverables: req.body.deliverables,
      requirements: req.body.requirements,
      sla: req.body.sla,
      team: req.body.team,
      process: req.body.process,
      availability: req.body.availability,
      relatedServices: req.body.relatedServices,
      documents: req.body.documents,
      compliance: req.body.compliance,
      metadata: req.body.metadata
    };
    
    // Add organization from user context if not provided
    if (!serviceData.organization && req.user.organization?.current) {
      serviceData.organization = req.user.organization.current;
    }
    
    const service = await ServicesService.createService(serviceData, req.user);
    
    responseHandler.success(res, service, 'Service created successfully', 201);
  });
  
  /**
   * Update service
   * @route   PUT /api/services/:id
   * @access  Private - Service Owner, Admin
   */
  static updateService = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    const service = await ServicesService.updateService(id, updates, req.user);
    
    responseHandler.success(res, service, 'Service updated successfully');
  });
  
  /**
   * Get service by ID
   * @route   GET /api/services/:id
   * @access  Private
   */
  static getService = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const options = {
      populate: req.query.populate !== 'false',
      includeArchived: req.query.includeArchived === 'true'
    };
    
    const service = await ServicesService.getServiceById(id, options);
    
    // Check if user has access to view this service
    if (service.status === 'draft' || service.status === 'pending_approval') {
      if (!service.canBeManaged(req.user._id) && req.user.role.primary !== 'admin') {
        throw new ForbiddenError('You do not have permission to view this service');
      }
    }
    
    responseHandler.success(res, service);
  });
  
  /**
   * List services
   * @route   GET /api/services
   * @access  Private
   */
  static listServices = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization || req.user.organization?.current,
      category: req.query.category,
      type: req.query.type,
      deliveryMethod: req.query.deliveryMethod,
      status: req.query.status,
      availability: req.query.availability,
      search: req.query.search
    };
    
    // Parse price range
    if (req.query.minPrice || req.query.maxPrice) {
      filters.priceRange = {
        min: parseFloat(req.query.minPrice) || 0,
        max: parseFloat(req.query.maxPrice) || Number.MAX_SAFE_INTEGER
      };
    }
    
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 20,
      sort: req.query.sort || '-createdAt',
      populate: req.query.populate !== 'false'
    };
    
    // Validate pagination limits
    if (options.limit > constants.API.PAGINATION.MAX_LIMIT) {
      options.limit = constants.API.PAGINATION.MAX_LIMIT;
    }
    
    const result = await ServicesService.listServices(filters, options);
    
    responseHandler.successWithPagination(res, result.services, result.pagination);
  });
  
  /**
   * Search services
   * @route   GET /api/services/search
   * @access  Private
   */
  static searchServices = asyncHandler(async (req, res) => {
    const { q: searchTerm } = req.query;
    
    if (!searchTerm || searchTerm.length < 2) {
      throw new ValidationError('Search term must be at least 2 characters');
    }
    
    const options = {
      limit: parseInt(req.query.limit) || 20,
      organization: req.query.organization || req.user.organization?.current,
      includeArchived: req.query.includeArchived === 'true'
    };
    
    const results = await ServicesService.searchServices(searchTerm, options);
    
    responseHandler.success(res, results);
  });
  
  /**
   * Calculate service pricing
   * @route   POST /api/services/:id/calculate-price
   * @access  Private
   */
  static calculatePricing = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const pricingOptions = {
      quantity: req.body.quantity || 1,
      duration: req.body.duration || 1,
      customerType: req.body.customerType || req.user.userType,
      date: req.body.date ? new Date(req.body.date) : new Date(),
      additionalFees: req.body.additionalFees
    };
    
    const pricing = await ServicesService.calculatePricing(id, pricingOptions);
    
    responseHandler.success(res, pricing);
  });
  
  /**
   * Add service review
   * @route   POST /api/services/:id/reviews
   * @access  Private - Verified Clients
   */
  static addReview = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const reviewData = {
      projectId: req.body.projectId,
      rating: req.body.rating,
      positive: req.body.positive,
      improvement: req.body.improvement,
      recommendation: req.body.recommendation
    };
    
    const service = await ServicesService.addReview(id, reviewData, req.user);
    
    responseHandler.success(res, service, 'Review added successfully');
  });
  
  /**
   * Update service availability
   * @route   PATCH /api/services/:id/availability
   * @access  Private - Service Owner, Admin
   */
  static updateAvailability = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { status, capacity, blackoutDates } = req.body;
    
    if (!status) {
      throw new ValidationError('Availability status is required');
    }
    
    const options = {
      capacity,
      blackoutDates
    };
    
    const service = await ServicesService.updateAvailability(id, status, options, req.user);
    
    responseHandler.success(res, service, 'Availability updated successfully');
  });
  
  /**
   * Clone service
   * @route   POST /api/services/:id/clone
   * @access  Private - Service Owner, Admin
   */
  static cloneService = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const options = {
      name: req.body.name,
      organization: req.body.organization
    };
    
    const clonedService = await ServicesService.cloneService(id, options, req.user);
    
    responseHandler.success(res, clonedService, 'Service cloned successfully', 201);
  });
  
  /**
   * Archive service
   * @route   DELETE /api/services/:id
   * @access  Private - Service Owner, Admin
   */
  static archiveService = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    
    if (!reason) {
      throw new ValidationError('Archive reason is required');
    }
    
    const service = await ServicesService.archiveService(id, reason, req.user);
    
    responseHandler.success(res, service, 'Service archived successfully');
  });
  
  /**
   * Get service statistics
   * @route   GET /api/services/statistics
   * @access  Private - Admin, Manager
   */
  static getStatistics = asyncHandler(async (req, res) => {
    const organizationId = req.query.organization || req.user.organization?.current;
    
    if (!organizationId) {
      throw new ValidationError('Organization ID is required');
    }
    
    const statistics = await ServicesService.getStatistics(organizationId);
    
    responseHandler.success(res, statistics);
  });
  
  /**
   * Upload service document
   * @route   POST /api/services/:id/documents
   * @access  Private - Service Owner, Admin
   */
  static uploadDocument = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    if (!req.file) {
      throw new ValidationError('No file uploaded');
    }
    
    // Get service to check permissions
    const service = await ServicesService.getServiceById(id, { populate: false });
    
    if (!service.canBeManaged(req.user._id) && req.user.role.primary !== 'admin') {
      throw new ForbiddenError('You do not have permission to upload documents for this service');
    }
    
    // Upload file
    const uploadResult = await FileService.uploadDocument(req.file, {
      folder: `services/${id}/documents`,
      allowedTypes: constants.FILE.ALLOWED_TYPES.DOCUMENT
    });
    
    // Add document to service
    const documentData = {
      type: req.body.type || 'other',
      name: req.body.name || req.file.originalname,
      description: req.body.description,
      url: uploadResult.url,
      uploadedBy: req.user._id,
      version: req.body.version,
      isPublic: req.body.isPublic === 'true'
    };
    
    service.documents.push(documentData);
    await service.save();
    
    responseHandler.success(res, {
      document: documentData,
      service: service._id
    }, 'Document uploaded successfully');
  });
  
  /**
   * Get service deliverables
   * @route   GET /api/services/:id/deliverables
   * @access  Private
   */
  static getDeliverables = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const service = await ServicesService.getServiceById(id, { populate: false });
    
    const deliverables = service.deliverables.sort((a, b) => a.order - b.order);
    
    responseHandler.success(res, deliverables);
  });
  
  /**
   * Get service requirements
   * @route   GET /api/services/:id/requirements
   * @access  Private
   */
  static getRequirements = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const service = await ServicesService.getServiceById(id, { populate: false });
    
    responseHandler.success(res, service.requirements);
  });
  
  /**
   * Check service requirements
   * @route   POST /api/services/:id/check-requirements
   * @access  Private
   */
  static checkRequirements = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { provider, client } = req.body;
    
    const service = await ServicesService.getServiceById(id, { populate: false });
    
    const result = service.checkRequirements({ provider, client });
    
    responseHandler.success(res, result);
  });
  
  /**
   * Get related services
   * @route   GET /api/services/:id/related
   * @access  Private
   */
  static getRelatedServices = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const service = await ServicesService.getServiceById(id, {
      populate: true
    });
    
    const related = {
      prerequisites: [],
      complements: [],
      upgrades: [],
      alternatives: []
    };
    
    service.relatedServices.forEach(rel => {
      if (rel.service) {
        related[`${rel.type}s`]?.push({
          service: rel.service,
          description: rel.description
        });
      }
    });
    
    responseHandler.success(res, related);
  });
  
  /**
   * Get service reviews
   * @route   GET /api/services/:id/reviews
   * @access  Private
   */
  static getReviews = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { page = 1, limit = 10, verified } = req.query;
    
    const service = await ServicesService.getServiceById(id, { populate: false });
    
    let reviews = [...service.reviews];
    
    // Filter by verification status if requested
    if (verified !== undefined) {
      reviews = reviews.filter(r => r.verified === (verified === 'true'));
    }
    
    // Sort by date (newest first)
    reviews.sort((a, b) => b.reviewedAt - a.reviewedAt);
    
    // Paginate
    const startIndex = (page - 1) * limit;
    const paginatedReviews = reviews.slice(startIndex, startIndex + limit);
    
    // Populate client information
    await service.populate({
      path: 'reviews.client',
      select: 'firstName lastName profile.avatar'
    });
    
    responseHandler.successWithPagination(res, paginatedReviews, {
      total: reviews.length,
      pages: Math.ceil(reviews.length / limit),
      page: parseInt(page),
      limit: parseInt(limit)
    });
  });
  
  /**
   * Export services
   * @route   GET /api/services/export
   * @access  Private - Admin, Manager
   */
  static exportServices = asyncHandler(async (req, res) => {
    const filters = {
      organization: req.query.organization || req.user.organization?.current,
      status: req.query.status,
      category: req.query.category,
      dateFrom: req.query.dateFrom,
      dateTo: req.query.dateTo
    };
    
    const format = req.query.format || 'csv';
    
    // Get all services matching filters
    const { services } = await ServicesService.listServices(filters, {
      page: 1,
      limit: 10000, // Get all
      populate: true
    });
    
    let exportData;
    
    if (format === 'csv') {
      // Convert to CSV format
      const headers = [
        'Service ID', 'Name', 'Category', 'Type', 'Status',
        'Base Price', 'Currency', 'Average Rating', 'Total Projects',
        'Created Date', 'Owner'
      ];
      
      const rows = services.map(service => [
        service.serviceId,
        service.name,
        service.category.primary,
        service.type,
        service.status,
        service.pricing.basePrice,
        service.pricing.currency,
        service.metrics.averageRating,
        service.metrics.deliveredCount,
        service.createdAt.toISOString().split('T')[0],
        `${service.owner.firstName} ${service.owner.lastName}`
      ]);
      
      exportData = [headers, ...rows]
        .map(row => row.map(cell => `"${cell}"`).join(','))
        .join('\n');
      
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=services-export.csv');
    } else {
      // JSON format
      exportData = JSON.stringify(services, null, 2);
      
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename=services-export.json');
    }
    
    res.send(exportData);
  });
}

module.exports = ServicesController;