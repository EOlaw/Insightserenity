// server/core-business/team/routes/team-routes.js
/**
 * @file Team Routes
 * @description API routes for team management
 * @version 3.0.0
 */

const express = require('express');
const router = express.Router();

const config = require('../../../shared/config/config');
const TeamController = require('../controllers/team-controller');

// Authentication middleware
const { authenticate, requireAuth } = require('../../../shared/middleware/auth/auth-middleware');
const PermissionMiddleware = require('../../../shared/middleware/auth/permission-middleware');

// Validation middleware
const { validate, handleResult } = require('../../../shared/middleware/request-validator');
const { body, param, query } = require('../../../shared/middleware/request-validator');

// Other middleware
const { asyncHandler } = require('../../../shared/utils/async-handler');
const rateLimiter = require('../../../shared/security/rate-limiter');
const { CacheMiddleware } = require('../../../shared/middleware/cache-middleware');
const AuditMiddleware = require('../../../shared/middleware/audit-middleware');

/**
 * Validation schemas
 */
const teamValidation = {
  createTeam: [
    body('name')
      .trim()
      .isLength({ min: 3, max: 100 })
      .withMessage('Team name must be between 3 and 100 characters'),
    body('type')
      .isIn(['project', 'department', 'functional', 'cross_functional', 'temporary', 'permanent'])
      .withMessage('Invalid team type'),
    body('organization')
      .optional()
      .isMongoId()
      .withMessage('Invalid organization ID'),
    body('description')
      .optional()
      .isLength({ max: 1000 })
      .withMessage('Description cannot exceed 1000 characters'),
    body('members')
      .optional()
      .isArray()
      .withMessage('Members must be an array'),
    body('members.*.user')
      .if(body('members').exists())
      .isMongoId()
      .withMessage('Invalid user ID in members'),
    body('members.*.role')
      .if(body('members').exists())
      .isIn(['lead', 'co-lead', 'member', 'advisor', 'observer'])
      .withMessage('Invalid member role'),
    handleResult
  ],
  
  updateTeam: [
    param('id').isMongoId().withMessage('Invalid team ID'),
    body('name')
      .optional()
      .trim()
      .isLength({ min: 3, max: 100 })
      .withMessage('Team name must be between 3 and 100 characters'),
    body('type')
      .optional()
      .isIn(['project', 'department', 'functional', 'cross_functional', 'temporary', 'permanent'])
      .withMessage('Invalid team type'),
    body('status')
      .optional()
      .isIn(['active', 'inactive', 'archived', 'suspended'])
      .withMessage('Invalid team status'),
    body('description')
      .optional()
      .isLength({ max: 1000 })
      .withMessage('Description cannot exceed 1000 characters'),
    handleResult
  ],
  
  teamId: [
    param('id').isMongoId().withMessage('Invalid team ID'),
    handleResult
  ],
  
  addMember: [
    param('id').isMongoId().withMessage('Invalid team ID'),
    body('userId').isMongoId().withMessage('Invalid user ID'),
    body('role')
      .optional()
      .isIn(['lead', 'co-lead', 'member', 'advisor', 'observer'])
      .withMessage('Invalid member role'),
    body('allocation.percentage')
      .optional()
      .isInt({ min: 0, max: 100 })
      .withMessage('Allocation percentage must be between 0 and 100'),
    handleResult
  ],
  
  updateMemberRole: [
    param('id').isMongoId().withMessage('Invalid team ID'),
    param('memberId').isMongoId().withMessage('Invalid member ID'),
    body('role')
      .isIn(['lead', 'co-lead', 'member', 'advisor', 'observer'])
      .withMessage('Invalid member role'),
    handleResult
  ],
  
  queryTeams: [
    query('page')
      .optional()
      .isInt({ min: 1 })
      .withMessage('Page must be a positive integer'),
    query('limit')
      .optional()
      .isInt({ min: 1, max: 100 })
      .withMessage('Limit must be between 1 and 100'),
    query('status')
      .optional()
      .isIn(['active', 'inactive', 'archived', 'suspended'])
      .withMessage('Invalid status filter'),
    query('type')
      .optional()
      .isIn(['project', 'department', 'functional', 'cross_functional', 'temporary', 'permanent'])
      .withMessage('Invalid type filter'),
    handleResult
  ],
  
  searchTeams: [
    query('q')
      .trim()
      .isLength({ min: 2 })
      .withMessage('Search query must be at least 2 characters'),
    handleResult
  ]
};

/**
 * Public routes (no authentication required)
 */
router.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    service: 'teams',
    version: '3.0.0'
  });
});

/**
 * All routes below require authentication
 */
router.use(authenticate);

/**
 * Team CRUD operations
 */

// Search teams (before /:id to avoid route conflicts)
router.get(
  '/search',
  teamValidation.searchTeams,
  CacheMiddleware.cache({ ttl: 120, varyBy: ['query', 'user'] }),
  TeamController.searchTeams
);

// Get team statistics
router.get(
  '/statistics',
  PermissionMiddleware.require(['team.read', 'organization.admin']),
  CacheMiddleware.cache({ ttl: 300, varyBy: ['query', 'user'] }),
  TeamController.getTeamStatistics
);

// Get user's teams
router.get(
  '/my-teams',
  CacheMiddleware.cache({ ttl: 300, varyBy: ['user', 'query'] }),
  TeamController.getMyTeams
);

// Get all teams
router.get(
  '/',
  teamValidation.queryTeams,
  PermissionMiddleware.require('team.read'),
  CacheMiddleware.cache({ ttl: 180, varyBy: ['query', 'user'] }),
  TeamController.getAllTeams
);

// Create new team
router.post(
  '/',
  teamValidation.createTeam,
  PermissionMiddleware.require(['team.write', 'organization.admin']),
  rateLimiter.createLimiter({ windowMs: 15 * 60 * 1000, max: 10 }), // 10 teams per 15 minutes
  AuditMiddleware.track('team_creation'),
  TeamController.createTeam
);

// Get team by ID
router.get(
  '/:id',
  teamValidation.teamId,
  CacheMiddleware.cache({ ttl: 300, varyBy: ['params', 'query'] }),
  TeamController.getTeamById
);

// Update team
router.put(
  '/:id',
  teamValidation.updateTeam,
  TeamController.updateTeam
);

// Delete team (archive)
router.delete(
  '/:id',
  teamValidation.teamId,
  PermissionMiddleware.require(['team.delete', 'organization.admin']),
  AuditMiddleware.track('team_deletion'),
  TeamController.deleteTeam
);

/**
 * Team member management
 */

// Add team member
router.post(
  '/:id/members',
  teamValidation.addMember,
  rateLimiter.createLimiter({ windowMs: 15 * 60 * 1000, max: 50 }), // 50 additions per 15 minutes
  AuditMiddleware.track('team_member_addition'),
  TeamController.addTeamMember
);

// Remove team member
router.delete(
  '/:id/members/:memberId',
  [
    param('id').isMongoId().withMessage('Invalid team ID'),
    param('memberId').isMongoId().withMessage('Invalid member ID'),
    body('reason').optional().isString().withMessage('Reason must be a string'),
    handleResult
  ],
  AuditMiddleware.track('team_member_removal'),
  TeamController.removeTeamMember
);

// Update member role
router.put(
  '/:id/members/:memberId/role',
  teamValidation.updateMemberRole,
  AuditMiddleware.track('team_member_role_update'),
  TeamController.updateMemberRole
);

// Leave team
router.post(
  '/:id/leave',
  teamValidation.teamId,
  AuditMiddleware.track('team_member_leave'),
  TeamController.leaveTeam
);

/**
 * Team invitations
 */

// Accept team invitation
router.post(
  '/:id/accept-invitation',
  teamValidation.teamId,
  rateLimiter.createLimiter({ windowMs: 15 * 60 * 1000, max: 10 }), // 10 acceptances per 15 minutes
  AuditMiddleware.track('team_invitation_acceptance'),
  TeamController.acceptInvitation
);

/**
 * Team objectives and resources
 */

// Update team objectives
router.put(
  '/:id/objectives',
  [
    param('id').isMongoId().withMessage('Invalid team ID'),
    body('objectives').isArray().withMessage('Objectives must be an array'),
    body('objectives.*.title').notEmpty().withMessage('Objective title is required'),
    body('objectives.*.status')
      .optional()
      .isIn(['not_started', 'in_progress', 'at_risk', 'completed', 'cancelled'])
      .withMessage('Invalid objective status'),
    body('objectives.*.progress')
      .optional()
      .isInt({ min: 0, max: 100 })
      .withMessage('Progress must be between 0 and 100'),
    handleResult
  ],
  TeamController.updateObjectives
);

// Update team resources
router.put(
  '/:id/resources',
  [
    param('id').isMongoId().withMessage('Invalid team ID'),
    body('resources').isObject().withMessage('Resources must be an object'),
    handleResult
  ],
  TeamController.updateResources
);

/**
 * Team analytics and health
 */

// Get team health report
router.get(
  '/:id/health',
  teamValidation.teamId,
  CacheMiddleware.cache({ ttl: 600, varyBy: ['params'] }),
  TeamController.getTeamHealth
);

/**
 * Error handling middleware
 */
router.use((error, req, res, next) => {
  logger.error('Team route error', {
    error: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
    userId: req.user?._id
  });
  
  res.status(error.statusCode || 500).json({
    status: 'error',
    message: error.message || 'An error occurred processing your request'
  });
});

module.exports = router;