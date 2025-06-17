/**
 * @file Client Routes
 * @description API routes for client management
 * @version 2.0.0
 */

const express = require('express');
const router = express.Router();
const ClientController = require('../controllers/client-controller');
const { authenticate } = require('../../../shared/middleware/auth/auth-middleware');
const { authorize } = require('../../shared/middleware/authorize');
const validateRequest = require('../../shared/middleware/validate-request');
const fileUpload = require('../../shared/middleware/file-upload');
const rateLimiter = require('../../shared/security/rate-limiter');
const { cache } = require('../../shared/middleware/cache');
const {
  createClientSchema,
  updateClientSchema,
  updateClientStatusSchema,
  queryClientSchema,
  clientIdSchema,
  clientCodeSchema,
  contactPersonSchema,
  updateContactPersonSchema,
  suspendClientSchema,
  mergeClientsSchema,
  importClientsSchema,
  searchQuerySchema,
  documentSchema,
  noteSchema,
  updateTagsSchema,
  exportQuerySchema,
  timelineQuerySchema
} = require('../../shared/validations/client-validation');

/**
 * Public routes (no authentication required)
 * Note: In practice, most client routes should be protected
 */

// Health check endpoint
router.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'clients' });
});

/**
 * All routes below require authentication
 */
router.use(authenticate);

/**
 * Client CRUD operations
 */

// Search clients (should be before /:id to avoid route conflicts)
router.get(
  '/search',
  authorize(['admin', 'manager', 'consultant']),
  searchQuerySchema,
  validateRequest,
  cache('2m', { varyBy: ['query', 'user'] }),
  ClientController.searchClients
);

// Get client statistics
router.get(
  '/stats',
  authorize(['admin', 'manager', 'consultant']),
  cache('5m', { varyBy: ['user'] }),
  ClientController.getClientStats
);

// Get high-risk clients
router.get(
  '/high-risk',
  authorize(['admin', 'manager', 'consultant']),
  cache('5m', { varyBy: ['query', 'user'] }),
  ClientController.getHighRiskClients
);

// Export clients
router.get(
  '/export',
  authorize(['admin', 'manager']),
  exportQuerySchema,
  validateRequest,
  rateLimiter({ windowMs: 15 * 60 * 1000, max: 10 }), // 10 exports per 15 minutes
  ClientController.exportClients
);

// Get clients by account manager
router.get(
  '/by-manager/:managerId',
  authorize(['admin', 'manager', 'consultant']),
  cache('5m', { varyBy: ['params', 'user'] }),
  ClientController.getClientsByManager
);

// Get client by code
router.get(
  '/code/:code',
  authorize(['admin', 'manager', 'consultant']),
  clientCodeSchema,
  validateRequest,
  cache('5m', { varyBy: ['params', 'user'] }),
  ClientController.getClientByCode
);

// Get all clients
router.get(
  '/',
  authorize(['admin', 'manager', 'consultant']),
  queryClientSchema,
  validateRequest,
  cache('2m', { varyBy: ['query', 'user'] }),
  ClientController.getAllClients
);

// Create new client
router.post(
  '/',
  authorize(['admin', 'manager']),
  fileUpload.single('companyLogo'),
  createClientSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 50 }), // 50 creates per hour
  ClientController.createClient
);

// Import clients (bulk operation)
router.post(
  '/import',
  authorize(['admin']),
  fileUpload.single('file'),
  importClientsSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 5 }), // 5 imports per hour
  ClientController.importClients
);

// Merge clients
router.post(
  '/merge',
  authorize(['admin']),
  mergeClientsSchema,
  validateRequest,
  ClientController.mergeClients
);

// Bulk update health scores
router.post(
  '/health-scores/bulk-update',
  authorize(['admin']),
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 2 }), // 2 bulk updates per hour
  ClientController.bulkUpdateHealthScores
);

// Get client by ID
router.get(
  '/:id',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  cache('5m', { varyBy: ['params', 'query', 'user'] }),
  ClientController.getClientById
);

// Update client
router.patch(
  '/:id',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.single('companyLogo'),
  clientIdSchema,
  validateRequest,
  updateClientSchema,
  validateRequest,
  ClientController.updateClient
);

// Delete client (soft delete - changes status)
router.delete(
  '/:id',
  authorize(['admin']),
  clientIdSchema,
  validateRequest,
  ClientController.updateClientStatus
);

/**
 * Client status management
 */

// Update client status
router.patch(
  '/:id/status',
  authorize(['admin', 'manager']),
  clientIdSchema,
  validateRequest,
  updateClientStatusSchema,
  validateRequest,
  ClientController.updateClientStatus
);

// Suspend client
router.post(
  '/:id/suspend',
  authorize(['admin', 'manager']),
  clientIdSchema,
  validateRequest,
  suspendClientSchema,
  validateRequest,
  ClientController.suspendClient
);

// Reactivate client
router.post(
  '/:id/reactivate',
  authorize(['admin', 'manager']),
  clientIdSchema,
  validateRequest,
  ClientController.reactivateClient
);

/**
 * Contact person management
 */

// Get all contacts for a client
router.get(
  '/:id/contacts',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  cache('5m', { varyBy: ['params', 'user'] }),
  ClientController.getClientById // Returns full client with contacts
);

// Add contact person
router.post(
  '/:id/contacts',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  contactPersonSchema,
  validateRequest,
  ClientController.addContactPerson
);

// Update contact person
router.patch(
  '/:id/contacts/:contactId',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  updateContactPersonSchema,
  validateRequest,
  ClientController.updateContactPerson
);

// Remove contact person
router.delete(
  '/:id/contacts/:contactId',
  authorize(['admin', 'manager']),
  clientIdSchema,
  validateRequest,
  ClientController.removeContactPerson
);

/**
 * Client analytics and insights
 */

// Update health score
router.post(
  '/:id/health-score',
  authorize(['admin', 'manager']),
  clientIdSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 20 }), // 20 updates per hour
  ClientController.updateHealthScore
);

// Get engagement timeline
router.get(
  '/:id/timeline',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  timelineQuerySchema,
  validateRequest,
  cache('10m', { varyBy: ['params', 'query', 'user'] }),
  ClientController.getEngagementTimeline
);

/**
 * Document management
 */

// Get client documents
router.get(
  '/:id/documents',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  cache('5m', { varyBy: ['params', 'user'] }),
  ClientController.getClientById // Returns client with documents if includeDocuments=true
);

// Add document
router.post(
  '/:id/documents',
  authorize(['admin', 'manager', 'consultant']),
  fileUpload.single('document'),
  clientIdSchema,
  validateRequest,
  documentSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 100 }), // 100 uploads per hour
  ClientController.addDocument
);

// Remove document
router.delete(
  '/:id/documents/:documentId',
  authorize(['admin', 'manager']),
  clientIdSchema,
  validateRequest,
  ClientController.removeDocument
);

/**
 * Notes and internal information
 */

// Add note
router.post(
  '/:id/notes',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  noteSchema,
  validateRequest,
  rateLimiter({ windowMs: 60 * 60 * 1000, max: 200 }), // 200 notes per hour
  ClientController.addNote
);

// Update tags
router.patch(
  '/:id/tags',
  authorize(['admin', 'manager', 'consultant']),
  clientIdSchema,
  validateRequest,
  updateTagsSchema,
  validateRequest,
  ClientController.updateTags
);

/**
 * Middleware to handle client-specific errors
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