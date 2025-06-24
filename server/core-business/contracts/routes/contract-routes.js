// server/core-business/contract/routes/contract-routes.js
/**
 * @file Contract Routes
 * @description API routes for contract management operations
 * @version 3.0.0
 */

const express = require('express');
const router = express.Router();

const ContractController = require('../controllers/contract-controller');
const { authenticate } = require('../../../shared/middleware/auth/auth-middleware');
const { authorize } = require('../../../shared/middleware/auth/permission-middleware');
const { validateRequest } = require('../../../shared/middleware/validation-middleware');
const { rateLimiter } = require('../../../shared/utils/rate-limiter');
const fileUpload = require('../../../shared/utils/helpers/file-helper');
const { cache } = require('../../../shared/middleware/cache-middleware');

// Import validation schemas
const {
  createContractSchema,
  updateContractSchema,
  updateContractStatusSchema,
  listContractsSchema,
  contractIdSchema,
  addAmendmentSchema,
  updateAmendmentStatusSchema,
  generateDocumentSchema,
  uploadDocumentSchema,
  signContractSchema,
  renewContractSchema,
  exportContractsSchema,
  analyticsQuerySchema
} = require('../../../shared/utils/validation/contract-validation');

/**
 * All routes require authentication
 */
router.use(authenticate());

// ===========================
// Contract CRUD Operations
// ===========================

/**
 * @route   POST /api/contracts
 * @desc    Create new contract
 * @access  Private (Contract Admin, Manager)
 */
router.post('/',
  authorize(['contract.create', 'contract.admin']),
  validateRequest(createContractSchema),
  rateLimiter('contract-create', { max: 50, windowMs: 60 * 60 * 1000 }), // 50 per hour
  ContractController.createContract
);

/**
 * @route   GET /api/contracts
 * @desc    List contracts with filtering and pagination
 * @access  Private
 */
router.get('/',
  authorize(['contract.read', 'contract.admin']),
  validateRequest(listContractsSchema),
  cache('contracts-list', { ttl: 120, varyBy: ['query', 'user'] }),
  ContractController.listContracts
);

/**
 * @route   GET /api/contracts/analytics
 * @desc    Get contract analytics
 * @access  Private (Admin, Manager)
 */
router.get('/analytics',
  authorize(['contract.analytics', 'contract.admin']),
  validateRequest(analyticsQuerySchema),
  cache('contracts-analytics', { ttl: 300, varyBy: ['query', 'organization'] }),
  ContractController.getContractAnalytics
);

/**
 * @route   GET /api/contracts/export
 * @desc    Export contracts data
 * @access  Private (Admin, Manager)
 */
router.get('/export',
  authorize(['contract.export', 'contract.admin']),
  validateRequest(exportContractsSchema),
  rateLimiter('contract-export', { max: 10, windowMs: 60 * 60 * 1000 }), // 10 per hour
  ContractController.exportContracts
);

/**
 * @route   GET /api/contracts/:id
 * @desc    Get contract by ID
 * @access  Private
 */
router.get('/:id',
  validateRequest(contractIdSchema),
  authorize(['contract.read']),
  cache('contract-detail', { ttl: 300, varyBy: ['params', 'query'] }),
  ContractController.getContract
);

/**
 * @route   PUT /api/contracts/:id
 * @desc    Update contract
 * @access  Private (Contract Admin, Manager)
 */
router.put('/:id',
  validateRequest(contractIdSchema),
  authorize(['contract.update', 'contract.admin']),
  validateRequest(updateContractSchema),
  ContractController.updateContract
);

/**
 * @route   DELETE /api/contracts/:id
 * @desc    Delete contract (draft only)
 * @access  Private (Contract Admin)
 */
router.delete('/:id',
  validateRequest(contractIdSchema),
  authorize(['contract.delete', 'contract.admin']),
  rateLimiter('contract-delete', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  ContractController.deleteContract
);

// ===========================
// Contract Status Management
// ===========================

/**
 * @route   PATCH /api/contracts/:id/status
 * @desc    Update contract status
 * @access  Private (Contract Admin, Manager, Approver)
 */
router.patch('/:id/status',
  validateRequest(contractIdSchema),
  authorize(['contract.approve', 'contract.admin']),
  validateRequest(updateContractStatusSchema),
  ContractController.updateContractStatus
);

// ===========================
// Contract Amendments
// ===========================

/**
 * @route   POST /api/contracts/:id/amendments
 * @desc    Add contract amendment
 * @access  Private (Contract Admin, Manager)
 */
router.post('/:id/amendments',
  validateRequest(contractIdSchema),
  authorize(['contract.amend', 'contract.admin']),
  validateRequest(addAmendmentSchema),
  ContractController.addAmendment
);

/**
 * @route   PATCH /api/contracts/:id/amendments/:amendmentId/status
 * @desc    Update amendment status
 * @access  Private (Contract Admin, Manager, Approver)
 */
router.patch('/:id/amendments/:amendmentId/status',
  authorize(['contract.approve', 'contract.admin']),
  validateRequest(updateAmendmentStatusSchema),
  ContractController.updateAmendmentStatus
);

// ===========================
// Contract Documents
// ===========================

/**
 * @route   POST /api/contracts/:id/generate-document
 * @desc    Generate contract document PDF
 * @access  Private
 */
router.post('/:id/generate-document',
  validateRequest(contractIdSchema),
  authorize(['contract.read']),
  validateRequest(generateDocumentSchema),
  rateLimiter('document-generate', { max: 30, windowMs: 60 * 60 * 1000 }), // 30 per hour
  ContractController.generateContractDocument
);

/**
 * @route   POST /api/contracts/:id/documents
 * @desc    Upload contract document
 * @access  Private (Contract Admin, Manager)
 */
router.post('/:id/documents',
  validateRequest(contractIdSchema),
  authorize(['contract.update', 'contract.admin']),
  fileUpload.upload.document('document', {
    maxSize: 10 * 1024 * 1024, // 10MB
    folder: 'contracts'
  }),
  validateRequest(uploadDocumentSchema),
  ContractController.uploadDocument
);

/**
 * @route   DELETE /api/contracts/:id/documents/:documentId
 * @desc    Delete contract document
 * @access  Private (Contract Admin, Manager)
 */
router.delete('/:id/documents/:documentId',
  authorize(['contract.update', 'contract.admin']),
  ContractController.deleteDocument
);

// ===========================
// Contract Signatures
// ===========================

/**
 * @route   POST /api/contracts/:id/sign
 * @desc    Sign contract
 * @access  Private (Authorized Signatories)
 */
router.post('/:id/sign',
  validateRequest(contractIdSchema),
  validateRequest(signContractSchema),
  rateLimiter('contract-sign', { max: 5, windowMs: 15 * 60 * 1000 }), // 5 per 15 minutes
  ContractController.signContract
);

// ===========================
// Contract Lifecycle
// ===========================

/**
 * @route   POST /api/contracts/:id/renew
 * @desc    Renew contract
 * @access  Private (Contract Admin, Manager)
 */
router.post('/:id/renew',
  validateRequest(contractIdSchema),
  authorize(['contract.create', 'contract.admin']),
  validateRequest(renewContractSchema),
  ContractController.renewContract
);

/**
 * @route   GET /api/contracts/:id/timeline
 * @desc    Get contract timeline/history
 * @access  Private
 */
router.get('/:id/timeline',
  validateRequest(contractIdSchema),
  authorize(['contract.read']),
  cache('contract-timeline', { ttl: 180, varyBy: ['params'] }),
  ContractController.getContractTimeline
);

// ===========================
// Bulk Operations
// ===========================

/**
 * @route   POST /api/contracts/bulk/status
 * @desc    Bulk update contract status
 * @access  Private (Admin)
 */
router.post('/bulk/status',
  authorize(['contract.admin', 'system.admin']),
  rateLimiter('bulk-operations', { max: 10, windowMs: 60 * 60 * 1000 }), // 10 per hour
  ContractController.bulkUpdateStatus
);

/**
 * @route   POST /api/contracts/bulk/export
 * @desc    Bulk export contracts
 * @access  Private (Admin, Manager)
 */
router.post('/bulk/export',
  authorize(['contract.export', 'contract.admin']),
  rateLimiter('bulk-export', { max: 5, windowMs: 60 * 60 * 1000 }), // 5 per hour
  ContractController.bulkExport
);

// ===========================
// Contract Templates
// ===========================

/**
 * @route   GET /api/contracts/templates
 * @desc    List available contract templates
 * @access  Private
 */
router.get('/templates',
  authorize(['contract.read']),
  cache('contract-templates', { ttl: 3600 }), // 1 hour
  ContractController.listTemplates
);

/**
 * @route   POST /api/contracts/templates/:templateId/preview
 * @desc    Preview contract from template
 * @access  Private
 */
router.post('/templates/:templateId/preview',
  authorize(['contract.read']),
  ContractController.previewFromTemplate
);

// ===========================
// Contract Notifications & Reminders
// ===========================

/**
 * @route   GET /api/contracts/:id/reminders
 * @desc    Get contract reminders
 * @access  Private
 */
router.get('/:id/reminders',
  validateRequest(contractIdSchema),
  authorize(['contract.read']),
  ContractController.getContractReminders
);

/**
 * @route   POST /api/contracts/:id/reminders
 * @desc    Set contract reminder
 * @access  Private (Contract Admin, Manager)
 */
router.post('/:id/reminders',
  validateRequest(contractIdSchema),
  authorize(['contract.update', 'contract.admin']),
  ContractController.setContractReminder
);

// ===========================
// Contract Compliance & Audit
// ===========================

/**
 * @route   GET /api/contracts/:id/compliance
 * @desc    Get contract compliance status
 * @access  Private (Admin, Manager)
 */
router.get('/:id/compliance',
  validateRequest(contractIdSchema),
  authorize(['contract.compliance', 'contract.admin']),
  ContractController.getComplianceStatus
);

/**
 * @route   GET /api/contracts/:id/audit-trail
 * @desc    Get contract audit trail
 * @access  Private (Admin)
 */
router.get('/:id/audit-trail',
  validateRequest(contractIdSchema),
  authorize(['contract.audit', 'system.admin']),
  cache('contract-audit', { ttl: 300, varyBy: ['params', 'query'] }),
  ContractController.getAuditTrail
);

// ===========================
// Contract Search & Filtering
// ===========================

/**
 * @route   POST /api/contracts/search
 * @desc    Advanced contract search
 * @access  Private
 */
router.post('/search',
  authorize(['contract.read']),
  validateRequest(searchContractsSchema),
  ContractController.searchContracts
);

/**
 * @route   GET /api/contracts/upcoming-renewals
 * @desc    Get contracts with upcoming renewals
 * @access  Private (Manager, Admin)
 */
router.get('/upcoming-renewals',
  authorize(['contract.read', 'contract.admin']),
  cache('upcoming-renewals', { ttl: 600, varyBy: ['query', 'organization'] }),
  ContractController.getUpcomingRenewals
);

/**
 * @route   GET /api/contracts/expiring
 * @desc    Get expiring contracts
 * @access  Private (Manager, Admin)
 */
router.get('/expiring',
  authorize(['contract.read', 'contract.admin']),
  cache('expiring-contracts', { ttl: 600, varyBy: ['query', 'organization'] }),
  ContractController.getExpiringContracts
);

// ===========================
// Contract Integration
// ===========================

/**
 * @route   POST /api/contracts/:id/link-project
 * @desc    Link contract to project
 * @access  Private (Contract Admin, Project Manager)
 */
router.post('/:id/link-project',
  validateRequest(contractIdSchema),
  authorize(['contract.update', 'project.update']),
  ContractController.linkToProject
);

/**
 * @route   POST /api/contracts/:id/generate-invoice
 * @desc    Generate invoice from contract
 * @access  Private (Contract Admin, Finance)
 */
router.post('/:id/generate-invoice',
  validateRequest(contractIdSchema),
  authorize(['contract.invoice', 'billing.create']),
  ContractController.generateInvoice
);

// ===========================
// Contract Workflow
// ===========================

/**
 * @route   POST /api/contracts/:id/workflow/advance
 * @desc    Advance contract to next workflow stage
 * @access  Private (Contract Admin, Manager)
 */
router.post('/:id/workflow/advance',
  validateRequest(contractIdSchema),
  authorize(['contract.workflow', 'contract.admin']),
  ContractController.advanceWorkflow
);

/**
 * @route   POST /api/contracts/:id/workflow/reject
 * @desc    Reject contract at current workflow stage
 * @access  Private (Contract Admin, Manager, Approver)
 */
router.post('/:id/workflow/reject',
  validateRequest(contractIdSchema),
  authorize(['contract.workflow', 'contract.admin']),
  ContractController.rejectWorkflow
);

module.exports = router;