// server/core-business/proposals/routes/proposals-routes.js
/**
 * @file Proposal Routes
 * @description API routes for proposal management
 * @version 3.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const ProposalController = require('../controllers/proposals-controller');

// Middleware
const { authenticate } = require('../../../shared/middleware/auth/auth-middleware');
const { authorize } = require('../../../shared/middleware/auth/permission-middleware');
const { validateRequest } = require('../../../shared/middleware/request-validator');
const { rateLimiter } = require('../../../shared/utils/rate-limiter');
const fileHelper = require('../../../shared/utils/helpers/file-helper');

// Validation schemas
const { body, param, query } = require('express-validator');

/**
 * Apply authentication to all routes
 */
router.use(authenticate());

// ===========================
// Proposal CRUD Operations
// ===========================

/**
 * @route   POST /api/proposals
 * @desc    Create new proposal
 * @access  Private - Manager, Admin
 */
router.post('/',
  authorize(['proposal.create', 'proposal.admin']),
  rateLimiter('proposal-create', { max: 50, windowMs: 60 * 60 * 1000 }), // 50 per hour
  [
    body('title').trim().notEmpty().withMessage('Title is required')
      .isLength({ min: 5, max: 200 }).withMessage('Title must be between 5 and 200 characters'),
    body('type').isIn(['service', 'project', 'retainer', 'partnership', 'custom'])
      .withMessage('Invalid proposal type'),
    body('category').isIn([
      'consulting', 'implementation', 'assessment', 'audit',
      'training', 'support', 'development', 'design',
      'strategy', 'transformation', 'other'
    ]).withMessage('Invalid category'),
    body('client.organization').isMongoId().withMessage('Valid client organization ID required'),
    body('executiveSummary').trim().notEmpty().withMessage('Executive summary is required')
      .isLength({ min: 100, max: 5000 }).withMessage('Executive summary must be between 100 and 5000 characters'),
    body('validity.endDate').isISO8601().withMessage('Valid end date required'),
    body('pricing.currency').optional().isIn(['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'INR', 'JPY', 'CNY']),
    body('pricing.model').optional().isIn(['fixed', 'hourly', 'retainer', 'milestone', 'subscription', 'hybrid'])
  ],
  validateRequest,
  ProposalController.createProposal
);

/**
 * @route   GET /api/proposals
 * @desc    List proposals with filtering and pagination
 * @access  Private
 */
router.get('/',
  authorize(['proposal.read', 'proposal.admin']),
  rateLimiter('proposal-list', { max: 100, windowMs: 60 * 1000 }), // 100 per minute
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('status').optional().isIn([
      'draft', 'internal_review', 'pending_approval', 'approved',
      'sent', 'viewed', 'under_negotiation', 'accepted',
      'rejected', 'expired', 'withdrawn', 'converted'
    ]),
    query('type').optional().isIn(['service', 'project', 'retainer', 'partnership', 'custom']),
    query('category').optional().isString(),
    query('client').optional().isMongoId(),
    query('organization').optional().isMongoId(),
    query('tags').optional().isString(),
    query('search').optional().isString().trim(),
    query('validityStatus').optional().isIn(['active', 'expired']),
    query('startDate').optional().isISO8601(),
    query('endDate').optional().isISO8601(),
    query('minValue').optional().isFloat({ min: 0 }),
    query('maxValue').optional().isFloat({ min: 0 }),
    query('sort').optional().isString(),
    query('includeStats').optional().isBoolean().toBoolean()
  ],
  validateRequest,
  ProposalController.listProposals
);

/**
 * @route   GET /api/proposals/templates
 * @desc    Get available proposal templates
 * @access  Private
 */
router.get('/templates',
  authorize(['proposal.read', 'proposal.admin']),
  [
    query('type').optional().isString(),
    query('category').optional().isString(),
    query('search').optional().isString().trim()
  ],
  validateRequest,
  ProposalController.getProposalTemplates
);

/**
 * @route   GET /api/proposals/statistics
 * @desc    Get proposal statistics
 * @access  Private - Manager, Admin
 */
router.get('/statistics',
  authorize(['proposal.admin', 'manager', 'admin']),
  rateLimiter('proposal-stats', { max: 30, windowMs: 60 * 1000 }), // 30 per minute
  [
    query('startDate').optional().isISO8601(),
    query('endDate').optional().isISO8601()
  ],
  validateRequest,
  ProposalController.getProposalStatistics
);

/**
 * @route   GET /api/proposals/export
 * @desc    Export proposals
 * @access  Private - Manager, Admin
 */
router.get('/export',
  authorize(['proposal.export', 'proposal.admin']),
  rateLimiter('proposal-export', { max: 10, windowMs: 60 * 60 * 1000 }), // 10 per hour
  [
    query('status').optional().isString(),
    query('type').optional().isString(),
    query('category').optional().isString(),
    query('client').optional().isMongoId(),
    query('startDate').optional().isISO8601(),
    query('endDate').optional().isISO8601(),
    query('format').optional().isIn(['summary', 'detailed']),
    query('limit').optional().isInt({ min: 1, max: 5000 }).toInt()
  ],
  validateRequest,
  ProposalController.exportProposals
);

/**
 * @route   GET /api/proposals/:proposalId
 * @desc    Get proposal by ID
 * @access  Private
 */
router.get('/:proposalId',
  authorize(['proposal.read', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty(),
    query('includeServices').optional().isBoolean().toBoolean(),
    query('includeDocuments').optional().isBoolean().toBoolean(),
    query('includeRevisions').optional().isBoolean().toBoolean(),
    query('includeApprovals').optional().isBoolean().toBoolean(),
    query('includeAll').optional().isBoolean().toBoolean(),
    query('recordView').optional().isBoolean().toBoolean()
  ],
  validateRequest,
  ProposalController.getProposal
);

/**
 * @route   GET /api/proposals/:proposalId/preview
 * @desc    Preview proposal
 * @access  Private
 */
router.get('/:proposalId/preview',
  authorize(['proposal.read', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty(),
    query('format').optional().isIn(['html', 'json'])
  ],
  validateRequest,
  ProposalController.previewProposal
);

/**
 * @route   PUT /api/proposals/:proposalId
 * @desc    Update proposal
 * @access  Private
 */
router.put('/:proposalId',
  authorize(['proposal.write', 'proposal.admin']),
  rateLimiter('proposal-update', { max: 100, windowMs: 60 * 60 * 1000 }), // 100 per hour
  [
    param('proposalId').trim().notEmpty(),
    body('title').optional().trim().isLength({ min: 5, max: 200 }),
    body('type').optional().isIn(['service', 'project', 'retainer', 'partnership', 'custom']),
    body('category').optional().isString(),
    body('executiveSummary').optional().trim().isLength({ min: 100, max: 5000 }),
    body('status').optional().isIn([
      'draft', 'internal_review', 'pending_approval', 'approved',
      'sent', 'viewed', 'under_negotiation', 'accepted',
      'rejected', 'expired', 'withdrawn', 'converted'
    ]),
    body('validity.endDate').optional().isISO8601(),
    body('_createRevision').optional().isBoolean(),
    body('_revisionReason').optional().isString(),
    body('_isMajorRevision').optional().isBoolean()
  ],
  validateRequest,
  ProposalController.updateProposal
);

/**
 * @route   DELETE /api/proposals/:proposalId
 * @desc    Delete proposal
 * @access  Private - Admin, Creator
 */
router.delete('/:proposalId',
  authorize(['proposal.delete', 'proposal.admin']),
  rateLimiter('proposal-delete', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  [
    param('proposalId').trim().notEmpty()
  ],
  validateRequest,
  ProposalController.deleteProposal
);

// ===========================
// Proposal Actions
// ===========================

/**
 * @route   POST /api/proposals/:proposalId/clone
 * @desc    Clone existing proposal
 * @access  Private
 */
router.post('/:proposalId/clone',
  authorize(['proposal.create', 'proposal.admin']),
  rateLimiter('proposal-clone', { max: 30, windowMs: 60 * 60 * 1000 }), // 30 per hour
  [
    param('proposalId').trim().notEmpty(),
    body('title').optional().trim().isLength({ min: 5, max: 200 }),
    body('client').optional().isObject(),
    body('client.organization').optional().isMongoId(),
    body('updatePricing').optional().isBoolean(),
    body('updateTimeline').optional().isBoolean(),
    body('updateTeam').optional().isBoolean()
  ],
  validateRequest,
  ProposalController.cloneProposal
);

/**
 * @route   POST /api/proposals/:proposalId/send
 * @desc    Send proposal to client
 * @access  Private
 */
router.post('/:proposalId/send',
  authorize(['proposal.send', 'proposal.admin']),
  rateLimiter('proposal-send', { max: 50, windowMs: 60 * 60 * 1000 }), // 50 per hour
  [
    param('proposalId').trim().notEmpty(),
    body('recipients').isArray({ min: 1 }).withMessage('At least one recipient required'),
    body('recipients.*').isEmail().withMessage('Invalid recipient email'),
    body('subject').optional().trim().isLength({ max: 200 }),
    body('message').optional().trim().isLength({ max: 2000 }),
    body('method').optional().isIn(['email', 'portal', 'print', 'other']),
    body('regenerateDocument').optional().isBoolean()
  ],
  validateRequest,
  ProposalController.sendProposal
);

/**
 * @route   PATCH /api/proposals/:proposalId/status
 * @desc    Update proposal status
 * @access  Private
 */
router.patch('/:proposalId/status',
  authorize(['proposal.write', 'proposal.admin']),
  rateLimiter('proposal-status', { max: 100, windowMs: 60 * 60 * 1000 }), // 100 per hour
  [
    param('proposalId').trim().notEmpty(),
    body('status').isIn([
      'draft', 'internal_review', 'pending_approval', 'approved',
      'sent', 'viewed', 'under_negotiation', 'accepted',
      'rejected', 'expired', 'withdrawn', 'converted'
    ]).withMessage('Invalid status'),
    body('comment').optional().trim().isLength({ max: 500 })
  ],
  validateRequest,
  ProposalController.updateProposalStatus
);

// ===========================
// Proposal Sections
// ===========================

/**
 * @route   POST /api/proposals/:proposalId/sections
 * @desc    Add new section to proposal
 * @access  Private
 */
router.post('/:proposalId/sections',
  authorize(['proposal.write', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty(),
    body('title').trim().notEmpty().isLength({ max: 200 }),
    body('type').isIn([
      'overview', 'approach', 'methodology', 'deliverables',
      'timeline', 'team', 'case_study', 'testimonial',
      'terms', 'appendix', 'custom'
    ]),
    body('content').trim().notEmpty(),
    body('order').optional().isInt({ min: 0 }),
    body('isVisible').optional().isBoolean()
  ],
  validateRequest,
  ProposalController.addProposalSection
);

/**
 * @route   PUT /api/proposals/:proposalId/sections/:sectionId
 * @desc    Update proposal section
 * @access  Private
 */
router.put('/:proposalId/sections/:sectionId',
  authorize(['proposal.write', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty(),
    param('sectionId').isMongoId(),
    body('title').optional().trim().isLength({ max: 200 }),
    body('content').optional().trim(),
    body('order').optional().isInt({ min: 0 }),
    body('isVisible').optional().isBoolean()
  ],
  validateRequest,
  ProposalController.updateProposalSection
);

/**
 * @route   DELETE /api/proposals/:proposalId/sections/:sectionId
 * @desc    Delete proposal section
 * @access  Private
 */
router.delete('/:proposalId/sections/:sectionId',
  authorize(['proposal.write', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty(),
    param('sectionId').isMongoId()
  ],
  validateRequest,
  ProposalController.deleteProposalSection
);

// ===========================
// Proposal Documents
// ===========================

/**
 * @route   POST /api/proposals/:proposalId/documents
 * @desc    Upload document to proposal
 * @access  Private
 */
router.post('/:proposalId/documents',
  authorize(['proposal.write', 'proposal.admin']),
  rateLimiter('proposal-upload', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  fileHelper.upload.document('document'),
  [
    param('proposalId').trim().notEmpty(),
    body('type').optional().isIn(['proposal_doc', 'presentation', 'contract', 'sow', 'reference', 'other']),
    body('name').optional().trim().isLength({ max: 200 }),
    body('description').optional().trim().isLength({ max: 500 }),
    body('isPublic').optional().isBoolean()
  ],
  validateRequest,
  ProposalController.uploadProposalDocument
);

/**
 * @route   DELETE /api/proposals/:proposalId/documents/:documentId
 * @desc    Delete proposal document
 * @access  Private
 */
router.delete('/:proposalId/documents/:documentId',
  authorize(['proposal.write', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty(),
    param('documentId').isMongoId()
  ],
  validateRequest,
  ProposalController.deleteProposalDocument
);

// ===========================
// Proposal Analytics & Feedback
// ===========================

/**
 * @route   GET /api/proposals/:proposalId/analytics
 * @desc    Get proposal analytics
 * @access  Private
 */
router.get('/:proposalId/analytics',
  authorize(['proposal.read', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty()
  ],
  validateRequest,
  ProposalController.getProposalAnalytics
);

/**
 * @route   POST /api/proposals/:proposalId/feedback
 * @desc    Add feedback to proposal
 * @access  Private
 */
router.post('/:proposalId/feedback',
  authorize(['proposal.feedback', 'proposal.admin', 'client']),
  rateLimiter('proposal-feedback', { max: 50, windowMs: 60 * 60 * 1000 }), // 50 per hour
  [
    param('proposalId').trim().notEmpty(),
    body('type').optional().isIn(['comment', 'question', 'concern', 'approval']),
    body('section').optional().trim(),
    body('content').trim().notEmpty().isLength({ max: 2000 })
  ],
  validateRequest,
  ProposalController.addProposalFeedback
);

/**
 * @route   PATCH /api/proposals/:proposalId/feedback/:feedbackId/resolve
 * @desc    Resolve proposal feedback
 * @access  Private
 */
router.patch('/:proposalId/feedback/:feedbackId/resolve',
  authorize(['proposal.write', 'proposal.admin']),
  [
    param('proposalId').trim().notEmpty(),
    param('feedbackId').isMongoId()
  ],
  validateRequest,
  ProposalController.resolveProposalFeedback
);

// ===========================
// Error Handling
// ===========================

/**
 * Handle 404 for proposal routes
 */
router.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Proposal endpoint not found',
    path: req.originalUrl
  });
});

module.exports = router;