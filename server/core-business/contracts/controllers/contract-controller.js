// server/core-business/contract/controllers/contract-controller.js
/**
 * @file Contract Controller
 * @description Handles HTTP requests for contract-related operations
 * @version 3.0.0
 */

const config = require('../../../shared/config/config');
const { 
  ValidationError, 
  NotFoundError,
  ForbiddenError,
  BusinessRuleError 
} = require('../../../shared/utils/app-error');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const logger = require('../../../shared/utils/logger');
const responseHandler = require('../../../shared/utils/response-handler');
const ContractService = require('../services/contract-service');
const FileUploadService = require('../../../shared/utils/helpers/file-helper');

/**
 * Contract Controller Class
 * @class ContractController
 */
class ContractController {
  /**
   * Create new contract
   * @route   POST /api/contracts
   * @access  Private (Contract Admin, Manager)
   */
  static createContract = asyncHandler(async (req, res) => {
    const contractData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const contract = await ContractService.createContract(contractData, context);
    
    responseHandler.success(res, { contract }, 'Contract created successfully', 201);
  });
  
  /**
   * Get contract by ID
   * @route   GET /api/contracts/:id
   * @access  Private
   */
  static getContract = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { 
      includeAmendments = true,
      includeDocuments = true,
      includeProjects = false 
    } = req.query;
    
    const populateOptions = [];
    
    // Build populate options based on query params
    populateOptions.push('client');
    populateOptions.push('metadata.createdBy');
    populateOptions.push('metadata.lastModifiedBy');
    
    if (includeAmendments) {
      populateOptions.push('amendments.createdBy');
    }
    
    if (includeDocuments) {
      populateOptions.push('documents.uploadedBy');
    }
    
    if (includeProjects) {
      populateOptions.push({
        path: 'projects',
        select: 'name projectId status timeline.startDate timeline.endDate'
      });
    }
    
    const contract = await ContractService.getContractById(id, { populate: populateOptions });
    
    // Check permissions
    const hasPermission = await ContractService.checkContractPermission(
      contract, 
      req.user._id, 
      'read'
    );
    
    if (!hasPermission) {
      throw new ForbiddenError('You do not have permission to view this contract');
    }
    
    responseHandler.success(res, { contract }, 'Contract retrieved successfully');
  });
  
  /**
   * List contracts with filtering and pagination
   * @route   GET /api/contracts
   * @access  Private
   */
  static listContracts = asyncHandler(async (req, res) => {
    const {
      page = 1,
      limit = 20,
      sort = '-createdAt',
      status,
      type,
      client,
      search,
      startDate,
      endDate,
      minValue,
      maxValue,
      tags
    } = req.query;
    
    // Build filters
    const filters = {};
    
    if (status) filters.status = status.split(',');
    if (type) filters.type = type.split(',');
    if (client) filters.client = client;
    if (search) filters.search = search;
    if (tags) filters.tags = tags.split(',');
    
    if (startDate || endDate) {
      filters.dateRange = {};
      if (startDate) filters.dateRange.startDate = startDate;
      if (endDate) filters.dateRange.endDate = endDate;
    }
    
    if (minValue || maxValue) {
      filters.valueRange = {};
      if (minValue) filters.valueRange.min = parseFloat(minValue);
      if (maxValue) filters.valueRange.max = parseFloat(maxValue);
    }
    
    // Add organization filter for non-admins
    if (req.user.role?.primary !== 'super_admin') {
      filters.organization = req.user.organization?.current;
    }
    
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort,
      populate: ['client', 'metadata.createdBy']
    };
    
    const result = await ContractService.listContracts(filters, options);
    
    responseHandler.success(res, result, 'Contracts retrieved successfully');
  });
  
  /**
   * Update contract
   * @route   PUT /api/contracts/:id
   * @access  Private (Contract Admin, Manager)
   */
  static updateContract = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updateData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const updatedContract = await ContractService.updateContract(id, updateData, context);
    
    responseHandler.success(res, { contract: updatedContract }, 'Contract updated successfully');
  });
  
  /**
   * Update contract status
   * @route   PATCH /api/contracts/:id/status
   * @access  Private (Contract Admin, Manager, Approver)
   */
  static updateContractStatus = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { status, reason, comment } = req.body;
    
    if (!status) {
      throw new ValidationError('Status is required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin',
      reason,
      comment
    };
    
    const updatedContract = await ContractService.updateContractStatus(id, status, context);
    
    responseHandler.success(res, { contract: updatedContract }, 'Contract status updated successfully');
  });
  
  /**
   * Delete contract
   * @route   DELETE /api/contracts/:id
   * @access  Private (Contract Admin)
   */
  static deleteContract = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const contract = await ContractService.getContractById(id);
    
    // Only allow deletion of draft contracts
    if (contract.status !== 'draft') {
      throw new BusinessRuleError('Only draft contracts can be deleted');
    }
    
    // Check permissions
    const hasPermission = await ContractService.checkContractPermission(
      contract, 
      req.user._id, 
      'delete'
    );
    
    if (!hasPermission) {
      throw new ForbiddenError('You do not have permission to delete this contract');
    }
    
    await contract.remove();
    
    responseHandler.success(res, null, 'Contract deleted successfully');
  });
  
  /**
   * Add contract amendment
   * @route   POST /api/contracts/:id/amendments
   * @access  Private (Contract Admin, Manager)
   */
  static addAmendment = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const amendmentData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const updatedContract = await ContractService.addAmendment(id, amendmentData, context);
    
    responseHandler.success(res, { contract: updatedContract }, 'Amendment added successfully');
  });
  
  /**
   * Update amendment status
   * @route   PATCH /api/contracts/:id/amendments/:amendmentId/status
   * @access  Private (Contract Admin, Manager, Approver)
   */
  static updateAmendmentStatus = asyncHandler(async (req, res) => {
    const { id, amendmentId } = req.params;
    const { status, reason } = req.body;
    
    const contract = await ContractService.getContractById(id);
    const amendment = contract.amendments.id(amendmentId);
    
    if (!amendment) {
      throw new NotFoundError('Amendment not found');
    }
    
    // Update amendment status
    amendment.status = status;
    amendment.statusHistory.push({
      status,
      changedBy: req.user._id,
      changedAt: new Date(),
      reason
    });
    
    // If approved, update contract financial summary
    if (status === 'approved' && amendment.changes.financial) {
      contract.financial.summary = ContractService.calculateFinancialSummary(contract);
    }
    
    await contract.save();
    
    responseHandler.success(res, { contract }, 'Amendment status updated successfully');
  });
  
  /**
   * Generate contract document
   * @route   POST /api/contracts/:id/generate-document
   * @access  Private
   */
  static generateContractDocument = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { template, includeAnnexes = true } = req.body;
    
    const options = {
      template,
      includeAnnexes,
      userId: req.user._id
    };
    
    const documentInfo = await ContractService.generateContractDocument(id, options);
    
    responseHandler.success(res, { document: documentInfo }, 'Contract document generated successfully');
  });
  
  /**
   * Upload contract document
   * @route   POST /api/contracts/:id/documents
   * @access  Private (Contract Admin, Manager)
   */
  static uploadDocument = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { title, type, description } = req.body;
    
    if (!req.file) {
      throw new ValidationError('No file uploaded');
    }
    
    const contract = await ContractService.getContractById(id);
    
    // Check permissions
    const hasPermission = await ContractService.checkContractPermission(
      contract, 
      req.user._id, 
      'update'
    );
    
    if (!hasPermission) {
      throw new ForbiddenError('You do not have permission to upload documents to this contract');
    }
    
    // Process file upload
    const uploadResult = await FileUploadService.uploadDocument(req.file, {
      folder: 'contracts',
      metadata: {
        contractId: contract._id,
        uploadedBy: req.user._id
      }
    });
    
    // Add document to contract
    contract.documents.push({
      title: title || req.file.originalname,
      type: type || 'other',
      description,
      fileUrl: uploadResult.url,
      fileSize: req.file.size,
      fileType: req.file.mimetype,
      uploadedBy: req.user._id,
      uploadedAt: new Date()
    });
    
    await contract.save();
    
    responseHandler.success(res, { contract }, 'Document uploaded successfully');
  });
  
  /**
   * Delete contract document
   * @route   DELETE /api/contracts/:id/documents/:documentId
   * @access  Private (Contract Admin, Manager)
   */
  static deleteDocument = asyncHandler(async (req, res) => {
    const { id, documentId } = req.params;
    
    const contract = await ContractService.getContractById(id);
    
    // Check permissions
    const hasPermission = await ContractService.checkContractPermission(
      contract, 
      req.user._id, 
      'update'
    );
    
    if (!hasPermission) {
      throw new ForbiddenError('You do not have permission to delete documents from this contract');
    }
    
    // Find and remove document
    const document = contract.documents.id(documentId);
    if (!document) {
      throw new NotFoundError('Document not found');
    }
    
    // Delete file from storage
    await FileUploadService.deleteFile(document.fileUrl);
    
    // Remove from contract
    document.remove();
    await contract.save();
    
    responseHandler.success(res, { contract }, 'Document deleted successfully');
  });
  
  /**
   * Add contract signature
   * @route   POST /api/contracts/:id/sign
   * @access  Private
   */
  static signContract = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { signatureData, signatureType = 'electronic' } = req.body;
    
    const contract = await ContractService.getContractById(id);
    
    // Find signatory
    const signatory = contract.signatories.internal.find(
      sig => sig.user.toString() === req.user._id.toString()
    );
    
    if (!signatory) {
      throw new ForbiddenError('You are not authorized to sign this contract');
    }
    
    if (signatory.signedAt) {
      throw new BusinessRuleError('You have already signed this contract');
    }
    
    // Update signature
    signatory.signedAt = new Date();
    signatory.signatureType = signatureType;
    signatory.signatureData = signatureData;
    signatory.ipAddress = req.ip;
    signatory.userAgent = req.get('user-agent');
    
    await contract.save();
    
    // Check if all required signatures are collected
    const requiredSignatures = contract.signatories.internal.filter(sig => sig.isRequired);
    const allSigned = requiredSignatures.every(sig => sig.signedAt);
    
    if (allSigned && contract.status === 'approved') {
      // Auto-activate contract if configured
      if (contract.settings.autoActivateOnSignature) {
        const context = {
          userId: req.user._id,
          comment: 'Auto-activated after all signatures collected'
        };
        await ContractService.updateContractStatus(id, 'active', context);
      }
    }
    
    responseHandler.success(res, { contract }, 'Contract signed successfully');
  });
  
  /**
   * Renew contract
   * @route   POST /api/contracts/:id/renew
   * @access  Private (Contract Admin, Manager)
   */
  static renewContract = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const renewalData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      permissions: req.user.permissions,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const newContract = await ContractService.renewContract(id, renewalData, context);
    
    responseHandler.success(res, { contract: newContract }, 'Contract renewed successfully', 201);
  });
  
  /**
   * Get contract timeline
   * @route   GET /api/contracts/:id/timeline
   * @access  Private
   */
  static getContractTimeline = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const contract = await ContractService.getContractById(id, {
      populate: ['statusHistory.changedBy', 'amendments.createdBy', 'revisions.modifiedBy']
    });
    
    // Build timeline events
    const timeline = [];
    
    // Add creation event
    timeline.push({
      type: 'created',
      date: contract.createdAt,
      user: contract.metadata.createdBy,
      description: 'Contract created'
    });
    
    // Add status changes
    contract.statusHistory.forEach(status => {
      timeline.push({
        type: 'status_change',
        date: status.changedAt,
        user: status.changedBy,
        description: `Status changed to ${status.status}`,
        metadata: { 
          status: status.status,
          reason: status.reason 
        }
      });
    });
    
    // Add amendments
    contract.amendments.forEach(amendment => {
      timeline.push({
        type: 'amendment',
        date: amendment.createdAt,
        user: amendment.createdBy,
        description: `Amendment #${amendment.amendmentNumber} added`,
        metadata: { 
          amendmentId: amendment._id,
          title: amendment.title 
        }
      });
    });
    
    // Add signatures
    contract.signatories.internal.forEach(sig => {
      if (sig.signedAt) {
        timeline.push({
          type: 'signature',
          date: sig.signedAt,
          user: sig.user,
          description: `Contract signed by ${sig.name}`,
          metadata: { 
            signatureType: sig.signatureType 
          }
        });
      }
    });
    
    // Sort timeline by date
    timeline.sort((a, b) => new Date(b.date) - new Date(a.date));
    
    responseHandler.success(res, { timeline }, 'Contract timeline retrieved successfully');
  });
  
  /**
   * Get contract analytics
   * @route   GET /api/contracts/analytics
   * @access  Private (Admin, Manager)
   */
  static getContractAnalytics = asyncHandler(async (req, res) => {
    const {
      startDate,
      endDate,
      groupBy = 'month',
      metrics = 'all'
    } = req.query;
    
    // Build date filter
    const dateFilter = {};
    if (startDate) dateFilter.$gte = new Date(startDate);
    if (endDate) dateFilter.$lte = new Date(endDate);
    
    // Add organization filter for non-admins
    const orgFilter = req.user.role?.primary !== 'super_admin' 
      ? { organization: req.user.organization?.current }
      : {};
    
    // Aggregate contract data
    const analytics = await Contract.aggregate([
      {
        $match: {
          ...orgFilter,
          ...(startDate || endDate ? { createdAt: dateFilter } : {})
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            ...(groupBy === 'week' && { week: { $week: '$createdAt' } }),
            ...(groupBy === 'day' && { day: { $dayOfMonth: '$createdAt' } })
          },
          count: { $sum: 1 },
          totalValue: { $sum: '$financial.summary.totalValue' },
          avgValue: { $avg: '$financial.summary.totalValue' },
          byStatus: {
            $push: {
              status: '$status',
              value: '$financial.summary.totalValue'
            }
          },
          byType: {
            $push: {
              type: '$type',
              value: '$financial.summary.totalValue'
            }
          }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1 }
      }
    ]);
    
    // Calculate summary statistics
    const summary = await Contract.aggregate([
      { $match: orgFilter },
      {
        $group: {
          _id: null,
          totalContracts: { $sum: 1 },
          totalValue: { $sum: '$financial.summary.totalValue' },
          avgValue: { $avg: '$financial.summary.totalValue' },
          activeContracts: {
            $sum: {
              $cond: [{ $eq: ['$status', 'active'] }, 1, 0]
            }
          },
          completedContracts: {
            $sum: {
              $cond: [{ $eq: ['$status', 'completed'] }, 1, 0]
            }
          }
        }
      }
    ]);
    
    responseHandler.success(res, {
      analytics,
      summary: summary[0] || {},
      period: { startDate, endDate, groupBy }
    }, 'Contract analytics retrieved successfully');
  });
  
  /**
   * Export contracts
   * @route   GET /api/contracts/export
   * @access  Private (Admin, Manager)
   */
  static exportContracts = asyncHandler(async (req, res) => {
    const {
      format = 'csv',
      status,
      type,
      startDate,
      endDate
    } = req.query;
    
    // Build filters (similar to listContracts)
    const filters = {};
    if (status) filters.status = status.split(',');
    if (type) filters.type = type.split(',');
    if (startDate || endDate) {
      filters.dateRange = {};
      if (startDate) filters.dateRange.startDate = startDate;
      if (endDate) filters.dateRange.endDate = endDate;
    }
    
    // Add organization filter for non-admins
    if (req.user.role?.primary !== 'super_admin') {
      filters.organization = req.user.organization?.current;
    }
    
    // Get all contracts matching filters
    const contracts = await ContractService.listContracts(filters, {
      page: 1,
      limit: 10000, // Get all
      populate: ['client', 'projects']
    });
    
    // Format data for export
    const exportData = contracts.contracts.map(contract => ({
      'Contract Number': contract.contractNumber,
      'Title': contract.title,
      'Type': contract.type,
      'Status': contract.status,
      'Client': contract.client?.name || '',
      'Start Date': contract.timeline.startDate,
      'End Date': contract.timeline.endDate,
      'Total Value': contract.financial.summary.totalValue,
      'Currency': contract.financial.currency,
      'Created Date': contract.createdAt,
      'Created By': contract.metadata.createdBy?.email || ''
    }));
    
    // Generate export file
    let fileBuffer, filename, mimetype;
    
    if (format === 'csv') {
      const csv = require('csv-writer');
      const createCsvWriter = csv.createObjectCsvWriter;
      
      // Create CSV in memory
      const csvStringifier = csv.createObjectCsvStringifier({
        header: Object.keys(exportData[0] || {}).map(key => ({ id: key, title: key }))
      });
      
      const csvString = csvStringifier.getHeaderString() + 
                       csvStringifier.stringifyRecords(exportData);
      fileBuffer = Buffer.from(csvString);
      filename = `contracts-export-${Date.now()}.csv`;
      mimetype = 'text/csv';
    } else if (format === 'excel') {
      const ExcelJS = require('exceljs');
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Contracts');
      
      // Add headers
      worksheet.columns = Object.keys(exportData[0] || {}).map(key => ({
        header: key,
        key: key,
        width: 20
      }));
      
      // Add data
      worksheet.addRows(exportData);
      
      // Style headers
      worksheet.getRow(1).font = { bold: true };
      worksheet.getRow(1).fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE0E0E0' }
      };
      
      fileBuffer = await workbook.xlsx.writeBuffer();
      filename = `contracts-export-${Date.now()}.xlsx`;
      mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    } else {
      throw new ValidationError('Invalid export format');
    }
    
    // Set response headers
    res.setHeader('Content-Type', mimetype);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', fileBuffer.length);
    
    // Send file
    res.send(fileBuffer);
  });
}

module.exports = ContractController;