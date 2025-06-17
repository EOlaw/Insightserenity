/**
 * @file Project Routes
 * @description API routes for project management
 * @version 2.0.0
 */

const express = require('express');
const router = express.Router();
const ProjectController = require('../controllers/project-controller');
const { authenticate } = require('../../../shared/middleware/auth/auth-middleware');
const { authorize } = require('../../shared/middleware/authorize');
const validateRequest = require('../../shared/middleware/validate-request');
const fileUpload = require('../../shared/middleware/file-upload');
const rateLimiter = require('../../shared/security/rate-limiter');
const { cache } = require('../../shared/middleware/cache');

// Import validation schemas
const {
  createProjectSchema,
  updateProjectSchema,
  updateProjectStatusSchema,
  queryProjectSchema,
  projectIdSchema,
  teamMemberSchema,
  milestoneUpdateSchema,
  riskSchema,
  issueSchema,
  changeRequestSchema,
  changeRequestReviewSchema,
  deliverableSchema,
  communicationLogSchema,
  lessonLearnedSchema,
  exportProjectSchema,
  projectStatsQuerySchema
} = require('../../../shared/utils/validation/project-validation');

/**
 * Middleware to check project access
 */
const checkProjectAccess = async (req, res, next) => {
  try {
    const project = await ProjectService.getProjectById(req.params.id);
    if (!project.canBeAccessedBy(req.user._id, req.user.role)) {
      return res.status(403).json({
        status: 'error',
        message: 'You do not have permission to access this project'
      });
    }
    req.project = project;
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Public routes (requires authentication)
 */
router.use(authenticate);

/**
 * Project statistics and analytics
 */

// Get project statistics
router.get(
  '/stats',
  authorize(['admin', 'manager', 'consultant']),
  projectStatsQuerySchema,
  validateRequest,
  cache('5m', { varyBy: ['query', 'user'] }),
  ProjectController.getProjectStats
);

// Get active projects
router.get(
  '/active',
  authorize(['admin', 'manager', 'consultant']),
  cache('2m', { varyBy: ['query', 'user'] }),
  ProjectController.getActiveProjects
);

// Get projects by client
router.get(
  '/by-client/:clientId',
  authorize(['admin', 'manager', 'consultant']),
  cache('5m', { varyBy: ['params', 'query', 'user'] }),
  ProjectController.getProjectsByClient
);

/**
 * Main project CRUD operations
 */

// Get all projects
router.get(
  '/',
  authorize(['admin', 'manager', 'consultant']),
  queryProjectSchema,
  validateRequest,
  cache('2m', { varyBy: ['query', 'user'] }),
  ProjectController.getAllProjects
);

// Create new project
router.post(
  '/',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.array('documents', 10),
  createProjectSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 30 }), // 30 projects per hour
  ProjectController.createProject
);

// Get project by ID
router.get(
  '/:id',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  cache('5m', { varyBy: ['params', 'query', 'user'] }),
  ProjectController.getProjectById
);

// Update project
router.patch(
  '/:id',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.array('documents', 10),
  projectIdSchema,
  validateRequest,
  updateProjectSchema,
  validateRequest,
  ProjectController.updateProject
);

// Delete project (soft delete via status change)
router.delete(
  '/:id',
  authorize(['admin']),
  projectIdSchema,
  validateRequest,
  ProjectController.updateProjectStatus
);

/**
 * Project status and lifecycle management
 */

// Update project status
router.patch(
  '/:id/status',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  updateProjectStatusSchema,
  validateRequest,
  ProjectController.updateProjectStatus
);

// Archive project
router.post(
  '/:id/archive',
  authorize(['admin', 'manager']),
  projectIdSchema,
  validateRequest,
  ProjectController.archiveProject
);

/**
 * Team management
 */

// Get project team
router.get(
  '/:id/team',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  ProjectController.getProjectById // Returns full project with team
);

// Add team member
router.post(
  '/:id/team',
  authorize(['admin', 'manager']),
  projectIdSchema,
  validateRequest,
  teamMemberSchema,
  validateRequest,
  ProjectController.addTeamMember
);

// Update team member
router.patch(
  '/:id/team/:memberId',
  authorize(['admin', 'manager']),
  projectIdSchema,
  validateRequest,
  teamMemberSchema,
  validateRequest,
  ProjectController.updateTeamMember
);

// Remove team member
router.delete(
  '/:id/team/:memberId',
  authorize(['admin', 'manager']),
  projectIdSchema,
  validateRequest,
  ProjectController.removeTeamMember
);

/**
 * Milestone management
 */

// Get project milestones
router.get(
  '/:id/milestones',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  cache('5m', { varyBy: ['params', 'user'] }),
  ProjectController.getProjectById // Returns full project with milestones
);

// Add milestone
router.post(
  '/:id/milestones',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  milestoneUpdateSchema,
  validateRequest,
  ProjectController.addMilestone
);

// Update milestone
router.patch(
  '/:id/milestones/:milestoneId',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  milestoneUpdateSchema,
  validateRequest,
  ProjectController.updateMilestone
);

/**
 * Risk management
 */

// Get project risks
router.get(
  '/:id/risks',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  cache('5m', { varyBy: ['params', 'user'] }),
  ProjectController.getProjectById // Returns full project with risks
);

// Add risk
router.post(
  '/:id/risks',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  riskSchema,
  validateRequest,
  ProjectController.addRisk
);

// Update risk
router.patch(
  '/:id/risks/:riskId',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  riskSchema,
  validateRequest,
  ProjectController.updateRisk
);

/**
 * Issue management
 */

// Get project issues
router.get(
  '/:id/issues',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  cache('2m', { varyBy: ['params', 'user'] }),
  ProjectController.getProjectById // Returns full project with issues
);

// Add issue
router.post(
  '/:id/issues',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  issueSchema,
  validateRequest,
  ProjectController.addIssue
);

// Update issue
router.patch(
  '/:id/issues/:issueId',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  issueSchema,
  validateRequest,
  ProjectController.updateIssue
);

/**
 * Change request management
 */

// Get change requests
router.get(
  '/:id/change-requests',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  cache('5m', { varyBy: ['params', 'user'] }),
  ProjectController.getProjectById // Returns full project with change requests
);

// Create change request
router.post(
  '/:id/change-requests',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.array('documents', 5),
  projectIdSchema,
  validateRequest,
  changeRequestSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 20 }), // 20 change requests per hour
  ProjectController.createChangeRequest
);

// Review change request
router.patch(
  '/:id/change-requests/:changeRequestId/review',
  authorize(['admin', 'manager']),
  projectIdSchema,
  validateRequest,
  changeRequestReviewSchema,
  validateRequest,
  ProjectController.reviewChangeRequest
);

/**
 * Deliverables management
 */

// Get project deliverables
router.get(
  '/:id/deliverables',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  cache('5m', { varyBy: ['params', 'user'] }),
  ProjectController.getProjectById // Returns full project with deliverables
);

// Add deliverable
router.post(
  '/:id/deliverables',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.array('attachments', 10),
  projectIdSchema,
  validateRequest,
  deliverableSchema,
  validateRequest,
  ProjectController.addDeliverable
);

// Update deliverable
router.patch(
  '/:id/deliverables/:deliverableId',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.array('attachments', 10),
  projectIdSchema,
  validateRequest,
  deliverableSchema,
  validateRequest,
  ProjectController.updateDeliverable
);

/**
 * Communication and collaboration
 */

// Get communication logs
router.get(
  '/:id/communications',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  ProjectController.getProjectById // Returns full project with communication logs
);

// Add communication log
router.post(
  '/:id/communications',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.array('attachments', 5),
  projectIdSchema,
  validateRequest,
  communicationLogSchema,
  validateRequest,
  ProjectController.addCommunicationLog
);

/**
 * Knowledge management
 */

// Get lessons learned
router.get(
  '/:id/lessons-learned',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  checkProjectAccess,
  ProjectController.getProjectById // Returns full project with lessons learned
);

// Add lesson learned
router.post(
  '/:id/lessons-learned',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  lessonLearnedSchema,
  validateRequest,
  ProjectController.addLessonLearned
);

/**
 * Reports and analytics
 */

// Get project dashboard
router.get(
  '/:id/dashboard',
  authorize(['admin', 'manager', 'consultant', 'analyst']),
  projectIdSchema,
  validateRequest,
  cache('2m', { varyBy: ['params', 'user'] }),
  ProjectController.getProjectDashboard
);

// Generate status report
router.get(
  '/:id/reports/status',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  rateLimiter({ windowMs: 15 * 60 * 1000, max: 10 }), // 10 reports per 15 minutes
  ProjectController.generateStatusReport
);

// Export project data
router.get(
  '/:id/export',
  authorize(['admin', 'manager', 'consultant']),
  projectIdSchema,
  validateRequest,
  exportProjectSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 20 }), // 20 exports per hour
  ProjectController.exportProject
);

/**
 * Bulk operations (Admin only)
 */

// Bulk update projects
router.patch(
  '/bulk',
  authorize(['admin']),
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 5 }), // 5 bulk operations per hour
  ProjectController.bulkUpdateProjects
);

// Import projects
router.post(
  '/import',
  authorize(['admin']),
  fileUpload.single('file'),
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 5 }), // 5 imports per hour
  ProjectController.importProjects
);

/**
 * Middleware to handle project-specific errors
 */
router.use((err, req, res, next) => {
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => ({
      field: e.path,
      message: e.message
    }));
    
    return res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors
    });
  }
  
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return res.status(400).json({
      status: 'error',
      message: `Duplicate value for ${field}`,
      field
    });
  }
  
  next(err);
});

module.exports = router;