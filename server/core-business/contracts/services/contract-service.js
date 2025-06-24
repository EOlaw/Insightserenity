// server/core-business/contract/services/contract-service.js
/**
 * @file Contract Service
 * @description Comprehensive contract service handling all contract-related business logic
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const crypto = require('crypto');

const Contract = require('../models/contract-model');
const Client = require('../../clients/models/client-model');
const Project = require('../../projects/models/project-model');
const User = require('../../../shared/users/models/user-model');
const Organization = require('../../../hosted-organizations/organizations/models/organization-model');

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const AuditService = require('../../../shared/security/services/audit-service');
const { CacheService } = require('../../../shared/services/cache-service');
const EmailService = require('../../../shared/services/email-service');
const FileService = require('../../../shared/services/file-service');
const NotificationService = require('../../../shared/services/notification-service');
const { QueueHelper } = require('../../../shared/utils/helpers/queue-helper');
const PDFGenerator = require('../../../shared/utils/helpers/pdf-generator');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  ForbiddenError,
  BusinessRuleError 
} = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');

/**
 * Contract Service Class
 * @class ContractService
 */
class ContractService {
  /**
   * Create new contract
   * @param {Object} contractData - Contract data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created contract
   */
  static async createContract(contractData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.info('Creating new contract', {
        clientId: contractData.client,
        type: contractData.type,
        userId: context.userId
      });

      // Validate client exists and is active
      const client = await Client.findById(contractData.client).session(session);
      if (!client) {
        throw new NotFoundError('Client not found');
      }
      if (client.status !== 'active') {
        throw new BusinessRuleError('Cannot create contract for inactive client');
      }

      // Validate organization if provided
      if (contractData.organization) {
        const organization = await Organization.findById(contractData.organization).session(session);
        if (!organization) {
          throw new NotFoundError('Organization not found');
        }
      }

      // Generate unique contract number
      const contractNumber = await this.generateContractNumber(contractData.type, session);

      // Calculate financial summary
      const financialSummary = this.calculateFinancialSummary(contractData);

      // Prepare contract data
      const newContract = new Contract({
        ...contractData,
        contractNumber,
        financial: {
          ...contractData.financial,
          summary: financialSummary
        },
        workflow: {
          currentStage: 'draft',
          stages: this.initializeWorkflowStages(contractData.type)
        },
        metadata: {
          createdBy: context.userId,
          lastModifiedBy: context.userId,
          version: 1,
          tags: contractData.tags || []
        }
      });

      // Save contract
      const savedContract = await newContract.save({ session });

      // Create audit log
      await AuditService.log({
        type: 'contract_created',
        action: 'create',
        category: 'contract',
        userId: context.userId,
        organizationId: contractData.organization,
        target: {
          type: 'contract',
          id: savedContract._id.toString()
        },
        metadata: {
          contractNumber: savedContract.contractNumber,
          clientId: savedContract.client,
          type: savedContract.type,
          value: savedContract.financial.summary.totalValue
        },
        session
      });

      // Send notifications
      await this.sendContractCreationNotifications(savedContract, context);

      await session.commitTransaction();

      // Clear relevant caches
      await CacheService.clearPattern(`contracts:*`);
      await CacheService.clearPattern(`clients:${contractData.client}:*`);

      // Populate and return
      const populatedContract = await Contract.findById(savedContract._id)
        .populate('client', 'name code')
        .populate('signatories.internal.user', 'firstName lastName email')
        .populate('metadata.createdBy', 'firstName lastName');

      return populatedContract;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Contract creation failed', { 
        error: error.message, 
        contractData,
        userId: context.userId 
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Update contract
   * @param {string} contractId - Contract ID
   * @param {Object} updateData - Update data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated contract
   */
  static async updateContract(contractId, updateData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      // Find and validate contract
      const contract = await Contract.findById(contractId).session(session);
      if (!contract) {
        throw new NotFoundError('Contract not found');
      }

      // Check permissions
      const hasPermission = await this.checkContractPermission(contract, context.userId, 'update');
      if (!hasPermission) {
        throw new ForbiddenError('Insufficient permissions to update contract');
      }

      // Validate update based on contract status
      this.validateContractUpdate(contract, updateData);

      // Track changes for audit
      const changes = this.trackContractChanges(contract, updateData);

      // Update financial summary if financial data changed
      if (updateData.financial) {
        updateData.financial.summary = this.calculateFinancialSummary({
          ...contract.toObject(),
          financial: { ...contract.financial, ...updateData.financial }
        });
      }

      // Apply updates
      Object.assign(contract, updateData);
      contract.metadata.lastModifiedBy = context.userId;
      contract.metadata.lastModifiedAt = new Date();
      contract.metadata.version += 1;

      // Add to revision history
      contract.revisions.push({
        version: contract.metadata.version,
        modifiedBy: context.userId,
        modifiedAt: new Date(),
        changes: changes,
        comment: updateData.revisionComment
      });

      const updatedContract = await contract.save({ session });

      // Create audit log
      await AuditService.log({
        type: 'contract_updated',
        action: 'update',
        category: 'contract',
        userId: context.userId,
        organizationId: contract.organization,
        target: {
          type: 'contract',
          id: contract._id.toString()
        },
        metadata: {
          contractNumber: contract.contractNumber,
          version: contract.metadata.version,
          changes: changes
        },
        session
      });

      await session.commitTransaction();

      // Clear caches
      await CacheService.clearPattern(`contracts:${contractId}:*`);
      await CacheService.clearPattern(`contracts:list:*`);

      // Send update notifications
      await this.sendContractUpdateNotifications(updatedContract, changes, context);

      return updatedContract;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Contract update failed', { 
        error: error.message, 
        contractId,
        userId: context.userId 
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Get contract by ID
   * @param {string} contractId - Contract ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Contract
   */
  static async getContractById(contractId, options = {}) {
    try {
      // Check cache first
      const cacheKey = `contracts:${contractId}:${JSON.stringify(options)}`;
      const cached = await CacheService.get(cacheKey);
      if (cached) {
        return cached;
      }

      const query = Contract.findById(contractId);

      // Apply population
      if (options.populate) {
        const populateOptions = Array.isArray(options.populate) 
          ? options.populate 
          : [options.populate];
        
        populateOptions.forEach(pop => query.populate(pop));
      }

      const contract = await query.exec();

      if (!contract) {
        throw new NotFoundError('Contract not found');
      }

      // Cache the result
      await CacheService.set(cacheKey, contract, 300); // 5 minutes

      return contract;

    } catch (error) {
      logger.error('Failed to get contract', { error: error.message, contractId });
      throw error;
    }
  }

  /**
   * List contracts with filtering and pagination
   * @param {Object} filters - Filter options
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Contracts list with metadata
   */
  static async listContracts(filters = {}, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        sort = '-createdAt',
        populate = ['client', 'metadata.createdBy']
      } = options;

      // Build query
      const query = this.buildContractQuery(filters);

      // Check cache
      const cacheKey = `contracts:list:${JSON.stringify({ query, options })}`;
      const cached = await CacheService.get(cacheKey);
      if (cached) {
        return cached;
      }

      // Execute query with pagination
      const skip = (page - 1) * limit;
      
      const [contracts, total] = await Promise.all([
        Contract.find(query)
          .populate(populate)
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        Contract.countDocuments(query)
      ]);

      const result = {
        contracts,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit)
        }
      };

      // Cache results
      await CacheService.set(cacheKey, result, 120); // 2 minutes

      return result;

    } catch (error) {
      logger.error('Failed to list contracts', { error: error.message, filters });
      throw error;
    }
  }

  /**
   * Update contract status
   * @param {string} contractId - Contract ID
   * @param {string} newStatus - New status
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated contract
   */
  static async updateContractStatus(contractId, newStatus, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const contract = await Contract.findById(contractId).session(session);
      if (!contract) {
        throw new NotFoundError('Contract not found');
      }

      // Validate status transition
      const validTransition = this.validateStatusTransition(contract.status, newStatus);
      if (!validTransition) {
        throw new BusinessRuleError(`Invalid status transition from ${contract.status} to ${newStatus}`);
      }

      // Special handling for different status changes
      switch (newStatus) {
        case 'active':
          await this.activateContract(contract, context, session);
          break;
        case 'terminated':
          await this.terminateContract(contract, context, session);
          break;
        case 'completed':
          await this.completeContract(contract, context, session);
          break;
      }

      // Update status
      contract.status = newStatus;
      contract.statusHistory.push({
        status: newStatus,
        changedBy: context.userId,
        changedAt: new Date(),
        reason: context.reason,
        comment: context.comment
      });

      const updatedContract = await contract.save({ session });

      // Audit log
      await AuditService.log({
        type: 'contract_status_changed',
        action: 'update_status',
        category: 'contract',
        userId: context.userId,
        organizationId: contract.organization,
        target: {
          type: 'contract',
          id: contract._id.toString()
        },
        metadata: {
          contractNumber: contract.contractNumber,
          oldStatus: contract.status,
          newStatus: newStatus,
          reason: context.reason
        },
        session
      });

      await session.commitTransaction();

      // Clear caches
      await CacheService.clearPattern(`contracts:${contractId}:*`);

      // Send notifications
      await this.sendStatusChangeNotifications(updatedContract, newStatus, context);

      return updatedContract;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Contract status update failed', { 
        error: error.message, 
        contractId,
        newStatus 
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Generate contract document
   * @param {string} contractId - Contract ID
   * @param {Object} options - Generation options
   * @returns {Promise<Object>} Generated document info
   */
  static async generateContractDocument(contractId, options = {}) {
    try {
      const contract = await this.getContractById(contractId, {
        populate: [
          'client',
          'projects',
          'signatories.internal.user',
          'signatories.external'
        ]
      });

      // Prepare document data
      const documentData = await this.prepareDocumentData(contract);

      // Generate PDF
      const pdfBuffer = await PDFGenerator.generateContract(documentData, {
        template: options.template || contract.documentTemplates.contract,
        includeAnnexes: options.includeAnnexes !== false,
        watermark: contract.status === 'draft' ? 'DRAFT' : null
      });

      // Store document
      const filename = `contract-${contract.contractNumber}-${Date.now()}.pdf`;
      const uploadResult = await FileService.uploadDocument({
        buffer: pdfBuffer,
        filename,
        mimetype: 'application/pdf'
      }, {
        folder: 'contracts',
        metadata: {
          contractId: contract._id,
          version: contract.metadata.version,
          generatedBy: options.userId
        }
      });

      // Update contract with document reference
      contract.documents.push({
        title: `Contract Document v${contract.metadata.version}`,
        type: 'contract',
        description: 'Generated contract document',
        fileUrl: uploadResult.url,
        fileSize: uploadResult.size,
        uploadedBy: options.userId,
        version: contract.metadata.version,
        metadata: {
          generated: true,
          template: options.template
        }
      });

      await contract.save();

      return {
        url: uploadResult.url,
        filename,
        size: uploadResult.size,
        contractId: contract._id,
        version: contract.metadata.version
      };

    } catch (error) {
      logger.error('Contract document generation failed', { 
        error: error.message, 
        contractId 
      });
      throw error;
    }
  }

  /**
   * Add amendment to contract
   * @param {string} contractId - Contract ID
   * @param {Object} amendmentData - Amendment data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated contract
   */
  static async addAmendment(contractId, amendmentData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const contract = await Contract.findById(contractId).session(session);
      if (!contract) {
        throw new NotFoundError('Contract not found');
      }

      // Validate contract is active
      if (contract.status !== 'active') {
        throw new BusinessRuleError('Amendments can only be added to active contracts');
      }

      // Generate amendment number
      const amendmentNumber = contract.amendments.length + 1;

      // Create amendment
      const amendment = {
        amendmentNumber,
        ...amendmentData,
        status: 'draft',
        createdBy: context.userId,
        workflow: {
          currentStage: 'draft',
          stages: this.initializeAmendmentWorkflowStages()
        }
      };

      contract.amendments.push(amendment);

      // Update contract value if financial amendment
      if (amendmentData.changes.financial) {
        contract.financial.summary = this.calculateFinancialSummary(contract);
      }

      const updatedContract = await contract.save({ session });

      // Audit log
      await AuditService.log({
        type: 'contract_amendment_added',
        action: 'add_amendment',
        category: 'contract',
        userId: context.userId,
        organizationId: contract.organization,
        target: {
          type: 'contract',
          id: contract._id.toString()
        },
        metadata: {
          contractNumber: contract.contractNumber,
          amendmentNumber,
          changes: amendmentData.changes
        },
        session
      });

      await session.commitTransaction();

      // Send notifications
      await this.sendAmendmentNotifications(updatedContract, amendment, context);

      return updatedContract;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Amendment addition failed', { 
        error: error.message, 
        contractId 
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  /**
   * Process contract renewal
   * @param {string} contractId - Contract ID
   * @param {Object} renewalData - Renewal data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} New contract
   */
  static async renewContract(contractId, renewalData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const originalContract = await Contract.findById(contractId).session(session);
      if (!originalContract) {
        throw new NotFoundError('Contract not found');
      }

      // Validate renewal eligibility
      if (!originalContract.renewal.isRenewable) {
        throw new BusinessRuleError('Contract is not eligible for renewal');
      }

      // Check renewal window
      const renewalWindow = this.calculateRenewalWindow(originalContract);
      const now = new Date();
      if (now < renewalWindow.start || now > renewalWindow.end) {
        throw new BusinessRuleError('Contract is not within renewal window');
      }

      // Create new contract based on original
      const newContractData = {
        ...originalContract.toObject(),
        _id: undefined,
        contractNumber: undefined,
        status: 'draft',
        timeline: {
          ...renewalData.timeline,
          executionDate: null,
          effectiveDate: null
        },
        financial: {
          ...originalContract.financial,
          ...renewalData.financial
        },
        previousContract: originalContract._id,
        renewal: {
          isRenewal: true,
          originalContract: originalContract._id,
          renewalNumber: (originalContract.renewal.renewalCount || 0) + 1
        },
        statusHistory: [],
        amendments: [],
        documents: [],
        revisions: [],
        metadata: {
          createdBy: context.userId,
          lastModifiedBy: context.userId,
          version: 1
        }
      };

      // Create new contract
      const newContract = await this.createContract(newContractData, context);

      // Update original contract
      originalContract.renewal.hasRenewed = true;
      originalContract.renewal.renewalContract = newContract._id;
      originalContract.renewal.renewalDate = new Date();
      await originalContract.save({ session });

      await session.commitTransaction();

      return newContract;

    } catch (error) {
      await session.abortTransaction();
      logger.error('Contract renewal failed', { 
        error: error.message, 
        contractId 
      });
      throw error;
    } finally {
      session.endSession();
    }
  }

  // Helper Methods

  /**
   * Generate unique contract number
   * @private
   */
  static async generateContractNumber(type, session) {
    const year = new Date().getFullYear();
    const typePrefix = this.getContractTypePrefix(type);
    
    // Find the latest contract number for this year and type
    const latestContract = await Contract.findOne({
      contractNumber: new RegExp(`^${typePrefix}-${year}-`)
    })
    .sort('-contractNumber')
    .session(session);

    let sequence = 1;
    if (latestContract) {
      const parts = latestContract.contractNumber.split('-');
      sequence = parseInt(parts[2]) + 1;
    }

    return `${typePrefix}-${year}-${String(sequence).padStart(4, '0')}`;
  }

  /**
   * Get contract type prefix
   * @private
   */
  static getContractTypePrefix(type) {
    const prefixes = {
      'service_agreement': 'SA',
      'master_service_agreement': 'MSA',
      'statement_of_work': 'SOW',
      'non_disclosure_agreement': 'NDA',
      'purchase_order': 'PO',
      'license_agreement': 'LA',
      'maintenance_agreement': 'MA',
      'consulting_agreement': 'CA',
      'partnership_agreement': 'PA',
      'subcontractor_agreement': 'SCA'
    };
    return prefixes[type] || 'CTR';
  }

  /**
   * Calculate financial summary
   * @private
   */
  static calculateFinancialSummary(contractData) {
    const { financial, amendments = [] } = contractData;
    
    let totalValue = financial.contractValue || 0;
    let totalPaid = 0;
    let totalInvoiced = 0;

    // Add amendment values
    amendments.forEach(amendment => {
      if (amendment.status === 'approved' && amendment.changes.financial) {
        totalValue += amendment.changes.financial.additionalValue || 0;
      }
    });

    // Calculate from payment schedule
    if (financial.paymentSchedule) {
      financial.paymentSchedule.forEach(payment => {
        if (payment.status === 'paid') {
          totalPaid += payment.amount;
        }
        if (payment.invoiceId) {
          totalInvoiced += payment.amount;
        }
      });
    }

    return {
      totalValue,
      totalInvoiced,
      totalPaid,
      balance: totalValue - totalPaid,
      invoicedBalance: totalInvoiced - totalPaid,
      remainingValue: totalValue - totalInvoiced
    };
  }

  /**
   * Initialize workflow stages
   * @private
   */
  static initializeWorkflowStages(contractType) {
    const baseStages = [
      {
        name: 'draft',
        displayName: 'Draft',
        order: 1,
        status: 'pending',
        isCurrent: true
      },
      {
        name: 'internal_review',
        displayName: 'Internal Review',
        order: 2,
        status: 'pending'
      },
      {
        name: 'client_review',
        displayName: 'Client Review',
        order: 3,
        status: 'pending'
      },
      {
        name: 'negotiation',
        displayName: 'Negotiation',
        order: 4,
        status: 'pending'
      },
      {
        name: 'legal_review',
        displayName: 'Legal Review',
        order: 5,
        status: 'pending'
      },
      {
        name: 'signature',
        displayName: 'Signature',
        order: 6,
        status: 'pending'
      },
      {
        name: 'executed',
        displayName: 'Executed',
        order: 7,
        status: 'pending'
      }
    ];

    // Customize based on contract type
    if (contractType === 'non_disclosure_agreement') {
      return baseStages.filter(stage => 
        !['negotiation', 'legal_review'].includes(stage.name)
      );
    }

    return baseStages;
  }

  /**
   * Validate contract update
   * @private
   */
  static validateContractUpdate(contract, updateData) {
    // Cannot update executed contracts except for specific fields
    if (contract.status === 'executed' || contract.status === 'active') {
      const allowedFields = ['notes', 'tags', 'documents', 'amendments'];
      const updateFields = Object.keys(updateData);
      const disallowedFields = updateFields.filter(field => !allowedFields.includes(field));
      
      if (disallowedFields.length > 0) {
        throw new BusinessRuleError(
          `Cannot update fields ${disallowedFields.join(', ')} for ${contract.status} contract`
        );
      }
    }

    // Validate financial changes
    if (updateData.financial) {
      if (updateData.financial.contractValue < 0) {
        throw new ValidationError('Contract value cannot be negative');
      }
    }

    // Validate dates
    if (updateData.timeline) {
      const { startDate, endDate } = updateData.timeline;
      if (startDate && endDate && new Date(startDate) > new Date(endDate)) {
        throw new ValidationError('Start date cannot be after end date');
      }
    }
  }

  /**
   * Track contract changes
   * @private
   */
  static trackContractChanges(originalContract, updateData) {
    const changes = [];
    const trackFields = [
      'title', 'type', 'status', 'client', 'financial.contractValue',
      'financial.currency', 'timeline.startDate', 'timeline.endDate'
    ];

    trackFields.forEach(field => {
      const fieldPath = field.split('.');
      const oldValue = fieldPath.reduce((obj, key) => obj?.[key], originalContract);
      const newValue = fieldPath.reduce((obj, key) => obj?.[key], updateData);

      if (newValue !== undefined && oldValue !== newValue) {
        changes.push({
          field,
          oldValue,
          newValue
        });
      }
    });

    return changes;
  }

  /**
   * Build contract query from filters
   * @private
   */
  static buildContractQuery(filters) {
    const query = {};

    if (filters.status) {
      query.status = Array.isArray(filters.status) 
        ? { $in: filters.status } 
        : filters.status;
    }

    if (filters.type) {
      query.type = Array.isArray(filters.type) 
        ? { $in: filters.type } 
        : filters.type;
    }

    if (filters.client) {
      query.client = filters.client;
    }

    if (filters.organization) {
      query.organization = filters.organization;
    }

    if (filters.valueRange) {
      query['financial.summary.totalValue'] = {};
      if (filters.valueRange.min) {
        query['financial.summary.totalValue'].$gte = filters.valueRange.min;
      }
      if (filters.valueRange.max) {
        query['financial.summary.totalValue'].$lte = filters.valueRange.max;
      }
    }

    if (filters.dateRange) {
      if (filters.dateRange.startDate || filters.dateRange.endDate) {
        query['timeline.startDate'] = {};
        if (filters.dateRange.startDate) {
          query['timeline.startDate'].$gte = new Date(filters.dateRange.startDate);
        }
        if (filters.dateRange.endDate) {
          query['timeline.startDate'].$lte = new Date(filters.dateRange.endDate);
        }
      }
    }

    if (filters.tags && filters.tags.length > 0) {
      query['metadata.tags'] = { $in: filters.tags };
    }

    if (filters.search) {
      query.$or = [
        { contractNumber: { $regex: filters.search, $options: 'i' } },
        { title: { $regex: filters.search, $options: 'i' } },
        { 'metadata.tags': { $regex: filters.search, $options: 'i' } }
      ];
    }

    return query;
  }

  /**
   * Send contract creation notifications
   * @private
   */
  static async sendContractCreationNotifications(contract, context) {
    try {
      // Queue email notifications
      await QueueHelper.addJob('notifications', {
        type: 'contract_created',
        contractId: contract._id,
        recipients: await this.getContractStakeholders(contract),
        data: {
          contractNumber: contract.contractNumber,
          title: contract.title,
          client: contract.client,
          createdBy: context.userId
        }
      });

      // In-app notifications
      await NotificationService.create({
        type: 'contract_created',
        title: 'New Contract Created',
        message: `Contract ${contract.contractNumber} has been created`,
        recipients: await this.getContractStakeholders(contract),
        data: {
          contractId: contract._id,
          contractNumber: contract.contractNumber
        }
      });

    } catch (error) {
      logger.error('Failed to send contract notifications', { 
        error: error.message,
        contractId: contract._id 
      });
    }
  }

  /**
   * Get contract stakeholders
   * @private
   */
  static async getContractStakeholders(contract) {
    const stakeholders = new Set();

    // Add internal signatories
    contract.signatories.internal.forEach(signatory => {
      if (signatory.user) {
        stakeholders.add(signatory.user.toString());
      }
    });

    // Add project managers if projects are linked
    if (contract.projects && contract.projects.length > 0) {
      const projects = await Project.find({
        _id: { $in: contract.projects }
      }).select('team');

      projects.forEach(project => {
        project.team.forEach(member => {
          if (member.role === 'project_manager') {
            stakeholders.add(member.user.toString());
          }
        });
      });
    }

    // Add contract owner
    if (contract.metadata.createdBy) {
      stakeholders.add(contract.metadata.createdBy.toString());
    }

    return Array.from(stakeholders);
  }

  /**
   * Calculate renewal window
   * @private
   */
  static calculateRenewalWindow(contract) {
    const endDate = new Date(contract.timeline.endDate);
    const noticeInDays = contract.renewal.noticeRequiredDays || 30;
    
    // Window starts X days before end date
    const windowStart = new Date(endDate);
    windowStart.setDate(windowStart.getDate() - noticeInDays);
    
    // Window ends on contract end date
    return {
      start: windowStart,
      end: endDate
    };
  }

  /**
   * Validate status transition
   * @private
   */
  static validateStatusTransition(currentStatus, newStatus) {
    const transitions = {
      'draft': ['pending_approval', 'cancelled'],
      'pending_approval': ['approved', 'draft', 'cancelled'],
      'approved': ['active', 'cancelled'],
      'active': ['completed', 'terminated', 'suspended'],
      'suspended': ['active', 'terminated'],
      'completed': ['closed'],
      'terminated': ['closed'],
      'cancelled': [],
      'closed': []
    };

    return transitions[currentStatus]?.includes(newStatus) || false;
  }

  /**
   * Check contract permission
   * @private
   */
  static async checkContractPermission(contract, userId, action) {
    // Super admins have all permissions
    const user = await User.findById(userId);
    if (user?.role?.primary === 'super_admin') {
      return true;
    }

    // Contract creator has full permissions
    if (contract.metadata.createdBy?.toString() === userId) {
      return true;
    }

    // Check organization membership
    if (contract.organization) {
      const org = await Organization.findById(contract.organization);
      const member = org?.members?.find(m => m.user.toString() === userId);
      
      if (member) {
        const rolePermissions = {
          'owner': ['read', 'update', 'delete', 'approve'],
          'admin': ['read', 'update', 'approve'],
          'manager': ['read', 'update'],
          'member': ['read']
        };
        
        return rolePermissions[member.role]?.includes(action) || false;
      }
    }

    // Check if user is internal signatory
    const isSignatory = contract.signatories.internal.some(
      sig => sig.user?.toString() === userId
    );
    
    if (isSignatory) {
      return ['read', 'approve'].includes(action);
    }

    return false;
  }

  /**
   * Activate contract
   * @private
   */
  static async activateContract(contract, context, session) {
    // Ensure all required signatures are collected
    const requiredSignatures = contract.signatories.internal.filter(sig => sig.isRequired);
    const missingSigs = requiredSignatures.filter(sig => !sig.signedAt);
    
    if (missingSigs.length > 0) {
      throw new BusinessRuleError('Cannot activate contract - missing required signatures');
    }

    // Set execution and effective dates
    contract.timeline.executionDate = new Date();
    contract.timeline.effectiveDate = contract.timeline.effectiveDate || new Date();

    // Create projects if auto-create is enabled
    if (contract.settings.autoCreateProjects && contract.deliverables.length > 0) {
      await this.createProjectsFromContract(contract, context, session);
    }

    // Set up automated reminders
    if (contract.settings.enableAutomatedReminders) {
      await this.setupContractReminders(contract, session);
    }
  }

  /**
   * Terminate contract
   * @private
   */
  static async terminateContract(contract, context, session) {
    // Update associated projects
    if (contract.projects.length > 0) {
      await Project.updateMany(
        { _id: { $in: contract.projects } },
        { 
          $set: { 
            status: 'on_hold',
            'notes': `Contract ${contract.contractNumber} terminated`
          }
        },
        { session }
      );
    }

    // Calculate termination fees if applicable
    if (contract.termination.earlyTerminationFee) {
      // Add termination fee to financial summary
      contract.financial.summary.terminationFee = this.calculateTerminationFee(contract);
    }

    contract.termination.terminatedAt = new Date();
    contract.termination.terminatedBy = context.userId;
    contract.termination.reason = context.reason;
  }

  /**
   * Complete contract
   * @private
   */
  static async completeContract(contract, context, session) {
    // Verify all deliverables are completed
    const incompleteDeliverables = contract.deliverables.filter(
      d => d.status !== 'completed' && d.status !== 'accepted'
    );
    
    if (incompleteDeliverables.length > 0) {
      throw new BusinessRuleError(
        `Cannot complete contract - ${incompleteDeliverables.length} deliverables incomplete`
      );
    }

    // Update completion metrics
    contract.performance.actualEndDate = new Date();
    contract.performance.completionStatus = 'on_time'; // or calculate based on dates
    
    // Calculate final metrics
    const startDate = new Date(contract.timeline.startDate);
    const endDate = new Date(contract.timeline.endDate);
    const actualEnd = new Date();
    
    contract.performance.daysOverdue = Math.max(0, 
      Math.floor((actualEnd - endDate) / (1000 * 60 * 60 * 24))
    );
  }
}

module.exports = ContractService;