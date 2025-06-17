/**
 * @file Client Controller
 * @description HTTP request handlers for client management
 * @version 2.0.0
 */

const ClientService = require('../services/client-service');
const { AppError } = require('../../shared/utils/app-error');
const { catchAsync } = require('../../shared/utils/catch-async');
const { sanitizeQuery } = require('../../shared/utils/sanitizers');
const logger = require('../../shared/utils/logger');
const { uploadToS3 } = require('../../shared/utils/file-upload');

class ClientController {
  /**
   * Create a new client
   * POST /api/v1/clients
   */
  static createClient = catchAsync(async (req, res, next) => {
    const { body, user, files } = req;

    logger.debug('Creating new client', {
      userId: user._id,
      clientName: body.name,
      hasFiles: !!files
    });

    // Handle file uploads if any
    if (files?.companyLogo) {
      const logoUrl = await uploadToS3(files.companyLogo, 'client-logos');
      body.companyLogo = logoUrl;
    }

    // Ensure account manager is set
    if (!body.accountManagement) {
      body.accountManagement = {};
    }
    if (!body.accountManagement.accountManager) {
      body.accountManagement.accountManager = user._id;
    }

    const client = await ClientService.createClient(body, user._id);

    logger.info('Client created successfully via API', {
      clientId: client._id,
      clientName: client.name,
      code: client.code,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        client
      }
    });
  });

  /**
   * Get all clients with filtering
   * GET /api/v1/clients
   */
  static getAllClients = catchAsync(async (req, res, next) => {
    const { query, user } = req;
    
    logger.debug('Fetching clients with filters', {
      filters: query,
      userId: user._id,
      userRole: user.role
    });
    
    // Extract and sanitize query parameters
    const options = {
      page: parseInt(query.page) || 1,
      limit: parseInt(query.limit) || 20,
      sortBy: sanitizeQuery(query.sortBy) || 'createdAt',
      sortOrder: query.sortOrder === 'asc' ? 'asc' : 'desc',
      search: sanitizeQuery(query.search),
      status: sanitizeQuery(query.status),
      tier: sanitizeQuery(query.tier),
      industry: sanitizeQuery(query.industry),
      country: sanitizeQuery(query.country),
      city: sanitizeQuery(query.city),
      accountManager: sanitizeQuery(query.accountManager),
      tags: query.tags ? query.tags.split(',').map(tag => sanitizeQuery(tag)) : undefined,
      revenueRange: sanitizeQuery(query.revenueRange),
      employeeRange: sanitizeQuery(query.employeeRange),
      healthScoreMin: query.healthScoreMin ? parseInt(query.healthScoreMin) : undefined,
      healthScoreMax: query.healthScoreMax ? parseInt(query.healthScoreMax) : undefined,
      churnRisk: sanitizeQuery(query.churnRisk),
      lastActivityDays: query.lastActivityDays ? parseInt(query.lastActivityDays) : undefined,
      includeInactive: query.includeInactive === 'true',
      includeBlacklisted: query.includeBlacklisted === 'true' && user.role === 'admin'
    };

    // Apply role-based filtering
    const filter = {};
    
    // Non-admins can only see clients they have access to
    if (user.role !== 'admin') {
      filter.$or = [
        { 'accountManagement.accountManager': user._id },
        { 'accountManagement.secondaryManager': user._id },
        { 'accountManagement.team.member': user._id }
      ];
    }

    const result = await ClientService.getAllClients(filter, options);

    logger.debug('Clients fetched successfully', {
      count: result.clients.length,
      total: result.pagination.total,
      page: result.pagination.page,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: result.clients.length,
      ...result
    });
  });

  /**
   * Get client by ID
   * GET /api/v1/clients/:id
   */
  static getClientById = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { includeNotes, includeDocuments } = req.query;

    logger.debug('Fetching client by ID', {
      clientId: id,
      includeNotes: includeNotes === 'true',
      includeDocuments: includeDocuments === 'true',
      userId: req.user._id
    });

    const options = {
      includeNotes: includeNotes === 'true',
      includeDocuments: includeDocuments === 'true'
    };

    const client = await ClientService.getClientById(id, options);

    // Check access permissions
    if (req.user.role !== 'admin' && !client.canBeContactedBy(req.user._id)) {
      logger.warn('Client access denied - insufficient permissions', {
        clientId: id,
        userId: req.user._id,
        userRole: req.user.role
      });
      return next(new AppError('You do not have permission to view this client', 403));
    }

    logger.debug('Client fetched successfully', {
      clientId: client._id,
      clientName: client.name,
      code: client.code
    });

    res.status(200).json({
      status: 'success',
      data: {
        client
      }
    });
  });

  /**
   * Get client by code
   * GET /api/v1/clients/code/:code
   */
  static getClientByCode = catchAsync(async (req, res, next) => {
    const { code } = req.params;

    logger.debug('Fetching client by code', {
      code,
      userId: req.user._id
    });

    const client = await ClientService.getClientByCode(code);

    // Check access permissions
    if (req.user.role !== 'admin' && !client.canBeContactedBy(req.user._id)) {
      logger.warn('Client access denied by code - insufficient permissions', {
        code,
        userId: req.user._id
      });
      return next(new AppError('You do not have permission to view this client', 403));
    }

    logger.debug('Client fetched by code successfully', {
      clientId: client._id,
      clientName: client.name,
      code: client.code
    });

    res.status(200).json({
      status: 'success',
      data: {
        client
      }
    });
  });

  /**
   * Update client
   * PATCH /api/v1/clients/:id
   */
  static updateClient = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user, files } = req;

    logger.debug('Updating client', {
      clientId: id,
      userId: user._id,
      updateFields: Object.keys(body),
      hasFiles: !!files
    });

    // Check permissions
    const client = await ClientService.getClientById(id);
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Client update denied - insufficient permissions', {
        clientId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to update this client', 403));
    }

    // Handle file uploads
    if (files?.companyLogo) {
      const logoUrl = await uploadToS3(files.companyLogo, 'client-logos');
      body.companyLogo = logoUrl;
    }

    const updatedClient = await ClientService.updateClient(id, body, user._id);

    logger.info('Client updated successfully', {
      clientId: updatedClient._id,
      clientName: updatedClient.name,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: updatedClient
      }
    });
  });

  /**
   * Add contact person to client
   * POST /api/v1/clients/:id/contacts
   */
  static addContactPerson = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user } = req;

    logger.debug('Adding contact person to client', {
      clientId: id,
      contactEmail: body.email,
      userId: user._id
    });

    // Check permissions
    const client = await ClientService.getClientById(id);
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Add contact denied - insufficient permissions', {
        clientId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to modify this client', 403));
    }

    const updatedClient = await ClientService.addContactPerson(id, body, user._id);

    logger.info('Contact person added successfully', {
      clientId: id,
      contactEmail: body.email,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        client: updatedClient
      }
    });
  });

  /**
   * Update contact person
   * PATCH /api/v1/clients/:id/contacts/:contactId
   */
  static updateContactPerson = catchAsync(async (req, res, next) => {
    const { id, contactId } = req.params;
    const { body, user } = req;

    logger.debug('Updating contact person', {
      clientId: id,
      contactId,
      userId: user._id
    });

    // Check permissions
    const client = await ClientService.getClientById(id);
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Update contact denied - insufficient permissions', {
        clientId: id,
        contactId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to modify this client', 403));
    }

    const updatedClient = await ClientService.updateContactPerson(id, contactId, body, user._id);

    logger.info('Contact person updated successfully', {
      clientId: id,
      contactId,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: updatedClient
      }
    });
  });

  /**
   * Remove contact person
   * DELETE /api/v1/clients/:id/contacts/:contactId
   */
  static removeContactPerson = catchAsync(async (req, res, next) => {
    const { id, contactId } = req.params;
    const { user } = req;

    logger.debug('Removing contact person', {
      clientId: id,
      contactId,
      userId: user._id
    });

    // Check permissions
    const client = await ClientService.getClientById(id);
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Remove contact denied - insufficient permissions', {
        clientId: id,
        contactId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to modify this client', 403));
    }

    const updatedClient = await ClientService.removeContactPerson(id, contactId, user._id);

    logger.info('Contact person removed successfully', {
      clientId: id,
      contactId,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: updatedClient
      }
    });
  });

  /**
   * Update client status
   * PATCH /api/v1/clients/:id/status
   */
  static updateClientStatus = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { status, reason, renewalDate, lostReason } = req.body;
    const { user } = req;

    logger.debug('Updating client status', {
      clientId: id,
      newStatus: status,
      reason,
      userId: user._id
    });

    // Validate status
    const validStatuses = ['prospect', 'lead', 'opportunity', 'active', 'inactive', 'dormant', 'lost', 'blacklisted'];
    if (!validStatuses.includes(status)) {
      logger.warn('Invalid status provided', { status, clientId: id });
      return next(new AppError('Invalid status', 400));
    }

    // Check permissions - only admins can blacklist
    if (status === 'blacklisted' && user.role !== 'admin') {
      logger.warn('Blacklist attempt by non-admin', {
        clientId: id,
        userId: user._id
      });
      return next(new AppError('Only administrators can blacklist clients', 403));
    }

    const additionalData = {
      reason,
      renewalDate,
      lostReason
    };

    const updatedClient = await ClientService.updateClientStatus(id, status, user._id, additionalData);

    logger.info('Client status updated successfully', {
      clientId: updatedClient._id,
      clientName: updatedClient.name,
      newStatus: status,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: updatedClient
      }
    });
  });

  /**
   * Suspend client
   * POST /api/v1/clients/:id/suspend
   */
  static suspendClient = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { reason } = req.body;
    const { user } = req;

    logger.debug('Suspending client', {
      clientId: id,
      reason,
      userId: user._id
    });

    if (!reason) {
      return next(new AppError('Suspension reason is required', 400));
    }

    // Check permissions
    if (user.role !== 'admin' && user.role !== 'manager') {
      logger.warn('Suspend attempt by unauthorized user', {
        clientId: id,
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('You do not have permission to suspend clients', 403));
    }

    const suspendedClient = await ClientService.suspendClient(id, reason, user._id);

    logger.info('Client suspended successfully', {
      clientId: suspendedClient._id,
      clientName: suspendedClient.name,
      reason,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: suspendedClient
      }
    });
  });

  /**
   * Reactivate client
   * POST /api/v1/clients/:id/reactivate
   */
  static reactivateClient = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { user } = req;

    logger.debug('Reactivating client', {
      clientId: id,
      userId: user._id
    });

    // Check permissions
    if (user.role !== 'admin' && user.role !== 'manager') {
      logger.warn('Reactivate attempt by unauthorized user', {
        clientId: id,
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('You do not have permission to reactivate clients', 403));
    }

    const reactivatedClient = await ClientService.reactivateClient(id, user._id);

    logger.info('Client reactivated successfully', {
      clientId: reactivatedClient._id,
      clientName: reactivatedClient.name,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: reactivatedClient
      }
    });
  });

  /**
   * Get high-risk clients
   * GET /api/v1/clients/high-risk
   */
  static getHighRiskClients = catchAsync(async (req, res, next) => {
    const { limit, assignedTo } = req.query;
    const { user } = req;

    logger.debug('Fetching high-risk clients', {
      limit,
      assignedTo,
      userId: user._id
    });

    const options = {
      limit: parseInt(limit) || 20,
      includeReasons: true
    };

    // Non-admins can only see their own high-risk clients
    if (user.role !== 'admin') {
      options.assignedTo = user._id;
    } else if (assignedTo) {
      options.assignedTo = assignedTo;
    }

    const clients = await ClientService.getHighRiskClients(options);

    logger.debug('High-risk clients fetched successfully', {
      count: clients.length,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: clients.length,
      data: {
        clients
      }
    });
  });

  /**
   * Update client health score
   * POST /api/v1/clients/:id/health-score
   */
  static updateHealthScore = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { user } = req;

    logger.debug('Updating client health score', {
      clientId: id,
      userId: user._id
    });

    const client = await ClientService.updateClientHealthScore(id);

    logger.info('Client health score updated', {
      clientId: client._id,
      clientName: client.name,
      healthScore: client.relationship.healthScore.score,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: {
          id: client._id,
          name: client.name,
          healthScore: client.relationship.healthScore,
          churnRisk: client.relationship.churnRisk
        }
      }
    });
  });

  /**
   * Bulk update health scores
   * POST /api/v1/clients/health-scores/bulk-update
   */
  static bulkUpdateHealthScores = catchAsync(async (req, res, next) => {
    const { user } = req;

    logger.info('Starting bulk health score update', {
      userId: user._id
    });

    // Admin only operation
    if (user.role !== 'admin') {
      logger.warn('Bulk health score update denied - insufficient permissions', {
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('Only administrators can perform bulk updates', 403));
    }

    const result = await ClientService.bulkUpdateHealthScores();

    logger.info('Bulk health score update completed', {
      ...result,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: result
    });
  });

  /**
   * Get client engagement timeline
   * GET /api/v1/clients/:id/timeline
   */
  static getEngagementTimeline = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { startDate, endDate } = req.query;
    const { user } = req;

    logger.debug('Fetching client engagement timeline', {
      clientId: id,
      startDate,
      endDate,
      userId: user._id
    });

    // Check permissions
    const client = await ClientService.getClientById(id);
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Timeline access denied - insufficient permissions', {
        clientId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to view this client', 403));
    }

    const start = startDate ? new Date(startDate) : new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    const end = endDate ? new Date(endDate) : new Date();

    const timeline = await ClientService.getClientEngagementTimeline(id, start, end);

    logger.debug('Client engagement timeline fetched successfully', {
      clientId: id,
      period: `${start.toISOString()} to ${end.toISOString()}`,
      eventsCount: timeline.events.length
    });

    res.status(200).json({
      status: 'success',
      data: timeline
    });
  });

  /**
   * Merge clients
   * POST /api/v1/clients/merge
   */
  static mergeClients = catchAsync(async (req, res, next) => {
    const { primaryClientId, secondaryClientId } = req.body;
    const { user } = req;

    logger.info('Merging clients', {
      primaryClientId,
      secondaryClientId,
      userId: user._id
    });

    // Admin only operation
    if (user.role !== 'admin') {
      logger.warn('Client merge denied - insufficient permissions', {
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('Only administrators can merge clients', 403));
    }

    if (!primaryClientId || !secondaryClientId) {
      return next(new AppError('Both primary and secondary client IDs are required', 400));
    }

    const mergedClient = await ClientService.mergeClients(primaryClientId, secondaryClientId, user._id);

    logger.info('Clients merged successfully', {
      primaryClientId: mergedClient._id,
      secondaryClientId,
      mergedClientName: mergedClient.name,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        client: mergedClient
      }
    });
  });

  /**
   * Export clients
   * GET /api/v1/clients/export
   */
  static exportClients = catchAsync(async (req, res, next) => {
    const { format = 'json', fields, ...filters } = req.query;
    const { user } = req;

    logger.info('Exporting clients', {
      format,
      fields,
      filters,
      userId: user._id
    });

    // Check permissions
    if (user.role !== 'admin' && user.role !== 'manager') {
      logger.warn('Export denied - insufficient permissions', {
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('You do not have permission to export clients', 403));
    }

    const fieldsArray = fields ? fields.split(',').map(f => sanitizeQuery(f)) : [];

    // Apply role-based filtering for non-admins
    if (user.role !== 'admin') {
      filters.$or = [
        { 'accountManagement.accountManager': user._id },
        { 'accountManagement.secondaryManager': user._id }
      ];
    }

    const result = await ClientService.exportClients(filters, fieldsArray, format);

    logger.info('Clients exported successfully', {
      format,
      count: result.count,
      userId: user._id
    });

    if (format === 'csv') {
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename=clients-export.csv');
      return res.send(result.data);
    } else if (format === 'xlsx') {
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', 'attachment; filename=clients-export.xlsx');
      return res.send(result.data);
    }

    res.status(200).json({
      status: 'success',
      ...result
    });
  });

  /**
   * Import clients
   * POST /api/v1/clients/import
   */
  static importClients = catchAsync(async (req, res, next) => {
    const { clients, options = {} } = req.body;
    const { user, file } = req;

    logger.info('Importing clients', {
      source: file ? 'file' : 'data',
      count: clients?.length || 0,
      options,
      userId: user._id
    });

    // Admin only operation
    if (user.role !== 'admin') {
      logger.warn('Import denied - insufficient permissions', {
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('Only administrators can import clients', 403));
    }

    let clientsData = clients;

    // Handle file upload
    if (file) {
      // Parse file based on format (CSV, XLSX, etc.)
      // clientsData = await parseClientFile(file);
    }

    if (!Array.isArray(clientsData) || clientsData.length === 0) {
      return next(new AppError('No valid client data provided', 400));
    }

    const result = await ClientService.importClients(clientsData, options, user._id);

    logger.info('Client import completed', {
      ...result,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: result
    });
  });

  /**
   * Get client statistics
   * GET /api/v1/clients/stats
   */
  static getClientStats = catchAsync(async (req, res, next) => {
    const { user } = req;

    logger.debug('Fetching client statistics', {
      userId: user._id,
      userRole: user.role
    });

    // Build filter based on permissions
    const filter = {};
    
    if (user.role !== 'admin') {
      filter.$or = [
        { 'accountManagement.accountManager': user._id },
        { 'accountManagement.secondaryManager': user._id },
        { 'accountManagement.team.member': user._id }
      ];
    }

    const stats = await ClientService.getClientStatistics(filter);

    logger.debug('Client statistics fetched successfully', {
      stats,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        stats
      }
    });
  });

  /**
   * Search clients
   * GET /api/v1/clients/search
   */
  static searchClients = catchAsync(async (req, res, next) => {
    const { q, ...filters } = req.query;
    const { user } = req;

    logger.debug('Searching clients', {
      searchTerm: q,
      filters,
      userId: user._id
    });

    if (!q || q.length < 2) {
      return next(new AppError('Search query must be at least 2 characters', 400));
    }

    // Apply role-based filtering for non-admins
    if (user.role !== 'admin') {
      filters.$or = [
        { 'accountManagement.accountManager': user._id },
        { 'accountManagement.secondaryManager': user._id },
        { 'accountManagement.team.member': user._id }
      ];
    }

    const clients = await ClientService.searchClients(q, filters);

    logger.debug('Client search completed', {
      searchTerm: q,
      resultsCount: clients.length,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: clients.length,
      data: {
        clients
      }
    });
  });

  /**
   * Get clients by account manager
   * GET /api/v1/clients/by-manager/:managerId
   */
  static getClientsByManager = catchAsync(async (req, res, next) => {
    const { managerId } = req.params;
    const { user } = req;

    logger.debug('Fetching clients by account manager', {
      managerId,
      userId: user._id
    });

    // Check permissions - users can only see their own clients unless admin
    if (user.role !== 'admin' && user._id.toString() !== managerId) {
      logger.warn('Access denied to other manager clients', {
        managerId,
        userId: user._id
      });
      return next(new AppError('You can only view your own clients', 403));
    }

    const clients = await ClientService.findByAccountManager(managerId);

    logger.debug('Clients by manager fetched successfully', {
      managerId,
      count: clients.length
    });

    res.status(200).json({
      status: 'success',
      results: clients.length,
      data: {
        clients
      }
    });
  });

  /**
   * Add document to client
   * POST /api/v1/clients/:id/documents
   */
  static addDocument = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user, file } = req;

    logger.debug('Adding document to client', {
      clientId: id,
      documentType: body.type,
      hasFile: !!file,
      userId: user._id
    });

    if (!file) {
      return next(new AppError('Document file is required', 400));
    }

    // Check permissions
    const client = await ClientService.getClientById(id);
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Add document denied - insufficient permissions', {
        clientId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to modify this client', 403));
    }

    // Upload document
    const documentUrl = await uploadToS3(file, 'client-documents');

    const documentData = {
      name: body.name || file.originalname,
      type: body.type || 'other',
      description: body.description,
      url: documentUrl,
      uploadedBy: user._id,
      size: file.size,
      mimeType: file.mimetype,
      tags: body.tags ? body.tags.split(',') : [],
      confidential: body.confidential === 'true',
      expiryDate: body.expiryDate
    };

    client.documents.push(documentData);
    await client.save();

    logger.info('Document added to client successfully', {
      clientId: id,
      documentName: documentData.name,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        document: client.documents[client.documents.length - 1]
      }
    });
  });

  /**
   * Remove document from client
   * DELETE /api/v1/clients/:id/documents/:documentId
   */
  static removeDocument = catchAsync(async (req, res, next) => {
    const { id, documentId } = req.params;
    const { user } = req;

    logger.debug('Removing document from client', {
      clientId: id,
      documentId,
      userId: user._id
    });

    // Check permissions
    const client = await ClientService.getClientById(id, { includeDocuments: true });
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Remove document denied - insufficient permissions', {
        clientId: id,
        documentId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to modify this client', 403));
    }

    const document = client.documents.id(documentId);
    if (!document) {
      return next(new AppError('Document not found', 404));
    }

    // Delete from S3
    // await deleteFromS3(document.url);

    document.remove();
    await client.save();

    logger.info('Document removed from client successfully', {
      clientId: id,
      documentId,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      message: 'Document removed successfully'
    });
  });

  /**
   * Add note to client
   * POST /api/v1/clients/:id/notes
   */
  static addNote = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { content, type = 'general', visibility = 'team', isPinned = false } = req.body;
    const { user } = req;

    logger.debug('Adding note to client', {
      clientId: id,
      noteType: type,
      visibility,
      userId: user._id
    });

    if (!content || content.trim().length === 0) {
      return next(new AppError('Note content is required', 400));
    }

    // Check permissions
    const client = await ClientService.getClientById(id, { includeNotes: true });
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Add note denied - insufficient permissions', {
        clientId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to add notes to this client', 403));
    }

    const noteData = {
      content: content.trim(),
      type,
      visibility,
      author: user._id,
      isPinned
    };

    client.internal.notes.push(noteData);
    await client.save();

    logger.info('Note added to client successfully', {
      clientId: id,
      noteType: type,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        note: client.internal.notes[client.internal.notes.length - 1]
      }
    });
  });

  /**
   * Update client tags
   * PATCH /api/v1/clients/:id/tags
   */
  static updateTags = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { tags, operation = 'replace' } = req.body;
    const { user } = req;

    logger.debug('Updating client tags', {
      clientId: id,
      operation,
      tagsCount: tags?.length,
      userId: user._id
    });

    if (!Array.isArray(tags)) {
      return next(new AppError('Tags must be an array', 400));
    }

    // Check permissions
    const client = await ClientService.getClientById(id);
    
    if (user.role !== 'admin' && !client.canBeContactedBy(user._id)) {
      logger.warn('Update tags denied - insufficient permissions', {
        clientId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to modify this client', 403));
    }

    // Sanitize tags
    const sanitizedTags = tags.map(tag => sanitizeQuery(tag).toLowerCase());

    switch (operation) {
      case 'add':
        const existingTags = new Set(client.internal.tags);
        sanitizedTags.forEach(tag => existingTags.add(tag));
        client.internal.tags = Array.from(existingTags);
        break;
      case 'remove':
        client.internal.tags = client.internal.tags.filter(tag => 
          !sanitizedTags.includes(tag)
        );
        break;
      case 'replace':
      default:
        client.internal.tags = sanitizedTags;
    }

    client.updatedBy = user._id;
    await client.save();

    logger.info('Client tags updated successfully', {
      clientId: id,
      operation,
      newTagsCount: client.internal.tags.length,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        tags: client.internal.tags
      }
    });
  });
}

module.exports = ClientController;