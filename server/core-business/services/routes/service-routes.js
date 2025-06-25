// server/core-business/services/routes/services-routes.js
/**
 * @file Services Routes
 * @description API routes for service management
 * @version 3.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const ServicesController = require('../controllers/services-controller');

// Middleware
const { authenticate } = require('../../../shared/middleware/auth/auth-middleware');
const { authorize } = require('../../../shared/middleware/auth/permission-middleware');
const { validateRequest } = require('../../../shared/middleware/request-validator');
const { rateLimiter } = require('../../../shared/utils/rate-limiter');
const fileHelper = require('../../../shared/utils/helpers/file-helper');

// Validation schemas
const {
  createServiceSchema,
  updateServiceSchema,
  listServicesSchema,
  calculatePriceSchema,
  reviewSchema,
  availabilitySchema,
  cloneServiceSchema,
  archiveServiceSchema,
  checkRequirementsSchema,
  exportServicesSchema
} = require('../validation/services-validation');

/**
 * Apply authentication to all routes
 */
router.use(authenticate());

/**
 * Service CRUD Operations
 */

// List services
router.get('/',
  authorize(['service.read', 'service.admin']),
  validateRequest(listServicesSchema),
  rateLimiter('services-list', { max: 100, windowMs: 60 * 1000 }), // 100 requests per minute
  ServicesController.listServices
);

// Export services
router.get('/export',
  authorize(['service.admin', 'manager', 'admin']),
  validateRequest(exportServicesSchema),
  rateLimiter('services-export', { max: 10, windowMs: 60 * 60 * 1000 }), // 10 per hour
  ServicesController.exportServices
);

// Get service statistics
router.get('/statistics',
  authorize(['service.admin', 'manager', 'admin']),
  rateLimiter('services-stats', { max: 30, windowMs: 60 * 1000 }),
  ServicesController.getStatistics
);

// Search services
router.get('/search',
  authorize(['service.read']),
  rateLimiter('services-search', { max: 60, windowMs: 60 * 1000 }),
  ServicesController.searchServices
);

// Create new service
router.post('/',
  authorize(['service.create', 'service.admin']),
  validateRequest(createServiceSchema),
  rateLimiter('services-create', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  ServicesController.createService
);

// Get service by ID
router.get('/:id',
  authorize(['service.read']),
  ServicesController.getService
);

// Update service
router.put('/:id',
  authorize(['service.write', 'service.admin']),
  validateRequest(updateServiceSchema),
  ServicesController.updateService
);

// Archive service (soft delete)
router.delete('/:id',
  authorize(['service.delete', 'service.admin']),
  validateRequest(archiveServiceSchema),
  ServicesController.archiveService
);

/**
 * Service Features
 */

// Calculate service pricing
router.post('/:id/calculate-price',
  authorize(['service.read']),
  validateRequest(calculatePriceSchema),
  ServicesController.calculatePricing
);

// Update service availability
router.patch('/:id/availability',
  authorize(['service.write', 'service.admin']),
  validateRequest(availabilitySchema),
  ServicesController.updateAvailability
);

// Clone service
router.post('/:id/clone',
  authorize(['service.create', 'service.admin']),
  validateRequest(cloneServiceSchema),
  ServicesController.cloneService
);

/**
 * Service Components
 */

// Get service deliverables
router.get('/:id/deliverables',
  authorize(['service.read']),
  ServicesController.getDeliverables
);

// Get service requirements
router.get('/:id/requirements',
  authorize(['service.read']),
  ServicesController.getRequirements
);

// Check service requirements
router.post('/:id/check-requirements',
  authorize(['service.read']),
  validateRequest(checkRequirementsSchema),
  ServicesController.checkRequirements
);

// Get related services
router.get('/:id/related',
  authorize(['service.read']),
  ServicesController.getRelatedServices
);

/**
 * Service Reviews
 */

// Get service reviews
router.get('/:id/reviews',
  authorize(['service.read']),
  ServicesController.getReviews
);

// Add service review
router.post('/:id/reviews',
  authorize(['service.review', 'client']),
  validateRequest(reviewSchema),
  rateLimiter('services-review', { max: 5, windowMs: 24 * 60 * 60 * 1000 }), // 5 per day
  ServicesController.addReview
);

/**
 * Service Documents
 */

// Upload service document
router.post('/:id/documents',
  authorize(['service.write', 'service.admin']),
  rateLimiter('services-upload', { max: 20, windowMs: 60 * 60 * 1000 }),
  fileHelper.upload.document('document', {
    maxSize: constants.FILE.MAX_SIZES.DOCUMENT,
    folder: 'services'
  }),
  ServicesController.uploadDocument
);

/**
 * Error handling middleware
 */
router.use((error, req, res, next) => {
  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Invalid JSON payload',
        code: 'INVALID_JSON'
      }
    });
  }
  
  if (error.name === 'MulterError') {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: {
          message: 'File size exceeds limit',
          code: 'FILE_TOO_LARGE'
        }
      });
    }
  }
  
  next(error);
});

module.exports = router;