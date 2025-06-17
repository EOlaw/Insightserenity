/**
 * @file Consultant Routes
 * @description API routes for consultant management
 * @version 2.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const ConsultantController = require('../controllers/consultant-controller');

// Middleware
const { authenticate } = require('../../../shared/middleware/auth');
const { authorize } = require('../../../shared/middleware/authorization');
const { validateRequest } = require('../../../shared/middleware/validator');
const { cache } = require('../../../shared/middleware/cache');
const { rateLimiter } = require('../../../shared/middleware/rate-limiter');
const fileUpload = require('../../../shared/middleware/file-upload');

// Validators
const {
  createConsultantSchema,
  updateConsultantSchema,
  consultantIdSchema,
  queryConsultantSchema,
  skillSchema,
  certificationSchema,
  availabilitySchema,
  performanceReviewSchema,
  searchConsultantSchema
} = require('../../../shared/utils/validation/consultant-validators');

// Apply authentication to all routes
router.use(authenticate);

/**
 * Search and filtering routes
 */

// Search consultants with advanced filters
router.post(
  '/search',
  authorize(['admin', 'manager', 'hr', 'project_manager']),
  searchConsultantSchema,
  validateRequest,
  cache('5m', { varyBy: ['body', 'user'] }),
  ConsultantController.searchConsultants
);

// Get available consultants for project staffing
router.get(
  '/available',
  authorize(['admin', 'manager', 'project_manager']),
  queryConsultantSchema,
  validateRequest,
  cache('2m', { varyBy: ['query', 'user'] }),
  ConsultantController.getAvailableConsultants
);

// Get consultants by skill
router.get(
  '/by-skill/:skillName',
  authorize(['admin', 'manager', 'project_manager']),
  cache('5m', { varyBy: ['params', 'query'] }),
  ConsultantController.getConsultantsBySkill
);

// Get consultants by department
router.get(
  '/by-department/:department',
  authorize(['admin', 'manager', 'hr']),
  cache('5m', { varyBy: ['params', 'query'] }),
  ConsultantController.getConsultantsByDepartment
);

/**
 * Main consultant CRUD operations
 */

// Get all consultants
router.get(
  '/',
  authorize(['admin', 'manager', 'hr']),
  queryConsultantSchema,
  validateRequest,
  cache('5m', { varyBy: ['query', 'user'] }),
  ConsultantController.getAllConsultants
);

// Create new consultant profile
router.post(
  '/',
  authorize(['admin', 'hr']),
  fileUpload.single('resume'),
  createConsultantSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 50 }), // 50 per hour
  ConsultantController.createConsultant
);

// Get consultant by ID
router.get(
  '/:id',
  authorize(['admin', 'manager', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('10m', { varyBy: ['params', 'user'] }),
  ConsultantController.getConsultantById
);

// Update consultant profile
router.patch(
  '/:id',
  authorize(['admin', 'hr', 'consultant']),
  fileUpload.fields([
    { name: 'resume', maxCount: 1 },
    { name: 'certifications', maxCount: 10 }
  ]),
  consultantIdSchema,
  validateRequest,
  updateConsultantSchema,
  validateRequest,
  ConsultantController.updateConsultant
);

// Deactivate consultant
router.delete(
  '/:id',
  authorize(['admin', 'hr']),
  consultantIdSchema,
  validateRequest,
  ConsultantController.deactivateConsultant
);

/**
 * Skills management
 */

// Get consultant skills
router.get(
  '/:id/skills',
  authorize(['admin', 'manager', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('10m', { varyBy: ['params'] }),
  ConsultantController.getConsultantSkills
);

// Add skill to consultant
router.post(
  '/:id/skills',
  authorize(['admin', 'hr', 'consultant', 'manager']),
  consultantIdSchema,
  validateRequest,
  skillSchema,
  validateRequest,
  ConsultantController.addSkill
);

// Update skill
router.patch(
  '/:id/skills/:skillId',
  authorize(['admin', 'hr', 'consultant', 'manager']),
  consultantIdSchema,
  validateRequest,
  skillSchema,
  validateRequest,
  ConsultantController.updateSkill
);

// Verify skill
router.post(
  '/:id/skills/:skillId/verify',
  authorize(['admin', 'manager', 'senior_consultant']),
  consultantIdSchema,
  validateRequest,
  ConsultantController.verifySkill
);

/**
 * Certification management
 */

// Get consultant certifications
router.get(
  '/:id/certifications',
  authorize(['admin', 'manager', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('10m', { varyBy: ['params'] }),
  ConsultantController.getConsultantCertifications
);

// Add certification
router.post(
  '/:id/certifications',
  authorize(['admin', 'hr', 'consultant']),
  fileUpload.single('certificate'),
  consultantIdSchema,
  validateRequest,
  certificationSchema,
  validateRequest,
  ConsultantController.addCertification
);

// Update certification
router.patch(
  '/:id/certifications/:certificationId',
  authorize(['admin', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  certificationSchema,
  validateRequest,
  ConsultantController.updateCertification
);

/**
 * Availability and scheduling
 */

// Get consultant availability
router.get(
  '/:id/availability',
  authorize(['admin', 'manager', 'project_manager', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('2m', { varyBy: ['params', 'query'] }),
  ConsultantController.getAvailability
);

// Update availability
router.patch(
  '/:id/availability',
  authorize(['admin', 'manager', 'consultant']),
  consultantIdSchema,
  validateRequest,
  availabilitySchema,
  validateRequest,
  ConsultantController.updateAvailability
);

// Get consultant schedule
router.get(
  '/:id/schedule',
  authorize(['admin', 'manager', 'project_manager', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('5m', { varyBy: ['params', 'query'] }),
  ConsultantController.getSchedule
);

// Book consultant time
router.post(
  '/:id/bookings',
  authorize(['admin', 'manager', 'project_manager']),
  consultantIdSchema,
  validateRequest,
  ConsultantController.bookConsultant
);

/**
 * Performance management
 */

// Get performance reviews
router.get(
  '/:id/performance',
  authorize(['admin', 'hr', 'manager', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('10m', { varyBy: ['params', 'user'] }),
  ConsultantController.getPerformanceReviews
);

// Create performance review
router.post(
  '/:id/performance',
  authorize(['admin', 'hr', 'manager']),
  consultantIdSchema,
  validateRequest,
  performanceReviewSchema,
  validateRequest,
  ConsultantController.createPerformanceReview
);

// Update performance review
router.patch(
  '/:id/performance/:reviewId',
  authorize(['admin', 'hr', 'manager']),
  consultantIdSchema,
  validateRequest,
  performanceReviewSchema,
  validateRequest,
  ConsultantController.updatePerformanceReview
);

// Submit self assessment
router.post(
  '/:id/performance/:reviewId/self-assessment',
  authorize(['consultant']),
  consultantIdSchema,
  validateRequest,
  ConsultantController.submitSelfAssessment
);

/**
 * Experience and employment
 */

// Get consultant experience
router.get(
  '/:id/experience',
  authorize(['admin', 'hr', 'manager', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('1h', { varyBy: ['params'] }),
  ConsultantController.getExperience
);

// Add experience
router.post(
  '/:id/experience',
  authorize(['admin', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  ConsultantController.addExperience
);

/**
 * Reporting and analytics
 */

// Get utilization report
router.get(
  '/reports/utilization',
  authorize(['admin', 'manager', 'hr']),
  cache('15m', { varyBy: ['query'] }),
  ConsultantController.getUtilizationReport
);

// Get skills inventory
router.get(
  '/reports/skills-inventory',
  authorize(['admin', 'manager', 'hr']),
  cache('30m'),
  ConsultantController.getSkillsInventory
);

// Get consultant metrics
router.get(
  '/:id/metrics',
  authorize(['admin', 'manager', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('15m', { varyBy: ['params', 'query'] }),
  ConsultantController.getConsultantMetrics
);

/**
 * Team and reporting structure
 */

// Get consultant's team
router.get(
  '/:id/team',
  authorize(['admin', 'manager', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('30m', { varyBy: ['params'] }),
  ConsultantController.getConsultantTeam
);

// Get direct reports
router.get(
  '/:id/direct-reports',
  authorize(['admin', 'manager', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  cache('30m', { varyBy: ['params'] }),
  ConsultantController.getDirectReports
);

/**
 * Documents and compliance
 */

// Upload document
router.post(
  '/:id/documents',
  authorize(['admin', 'hr', 'consultant']),
  fileUpload.single('document'),
  consultantIdSchema,
  validateRequest,
  ConsultantController.uploadDocument
);

// Get consultant documents
router.get(
  '/:id/documents',
  authorize(['admin', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  ConsultantController.getDocuments
);

// Update compliance status
router.patch(
  '/:id/compliance',
  authorize(['admin', 'hr']),
  consultantIdSchema,
  validateRequest,
  ConsultantController.updateCompliance
);

/**
 * Export functionality
 */

// Export consultant data
router.get(
  '/export',
  authorize(['admin', 'hr']),
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 10 }), // 10 exports per hour
  ConsultantController.exportConsultants
);

// Export individual consultant profile
router.get(
  '/:id/export',
  authorize(['admin', 'hr', 'consultant']),
  consultantIdSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 20 }), // 20 exports per hour
  ConsultantController.exportConsultantProfile
);

module.exports = router;