// server/core-business/proposals/services/proposals-service.js
/**
 * @file Proposal Service
 * @description Business logic for proposal management operations
 * @version 3.0.0
 */

const mongoose = require('mongoose');

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  BusinessRuleError,
  ForbiddenError 
} = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const Proposal = require('../models/proposals-model');
const Organization = require('../../../hosted-organizations/organizations/models/organization-model');
const User = require('../../../shared/users/models/user-model');
const Service = require('../../services/models/service-model');
const { CacheService } = require('../../../shared/services/cache-service');
const EmailService = require('../../../shared/services/email-service');
const FileService = require('../../../shared/services/file-service');
const AuditService = require('../../../shared/security/services/audit-service');
const NotificationService = require('../../../shared/services/notification-service');

/**
 * Proposal Service Class
 * @class ProposalService
 */
class ProposalService {
  /**
   * Create new proposal
   * @param {Object} proposalData - Proposal data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created proposal
   */
  static async createProposal(proposalData, context) {
    try {
      // Validate required fields
      const requiredFields = ['title', 'client', 'executiveSummary', 'validity'];
      const missingFields = requiredFields.filter(field => {
        if (field === 'client') return !proposalData.client?.organization;
        if (field === 'validity') return !proposalData.validity?.endDate;
        return !proposalData[field];
      });
      
      if (missingFields.length > 0) {
        throw new ValidationError(`Missing required fields: ${missingFields.join(', ')}`);
      }
      
      // Validate client organization exists
      const clientOrg = await Organization.findById(proposalData.client.organization);
      if (!clientOrg) {
        throw new NotFoundError('Client organization not found');
      }
      
      // Check permissions
      if (!context.isAdmin && context.organizationId !== proposalData.metadata?.organization?.toString()) {
        throw new ForbiddenError('Cannot create proposals for other organizations');
      }
      
      // Validate services if provided
      if (proposalData.services && proposalData.services.length > 0) {
        const serviceIds = proposalData.services
          .filter(s => s.service)
          .map(s => s.service);
        
        const services = await Service.find({ _id: { $in: serviceIds } });
        if (services.length !== serviceIds.length) {
          throw new ValidationError('One or more services not found');
        }
      }
      
      // Create proposal document
      const proposal = new Proposal({
        ...proposalData,
        metadata: {
          ...proposalData.metadata,
          createdBy: context.userId,
          organization: proposalData.metadata?.organization || context.organizationId,
          source: proposalData.metadata?.source || 'manual'
        },
        workflow: {
          currentStage: 'creation',
          stages: [{
            name: 'Creation',
            status: 'completed',
            startedAt: new Date(),
            completedAt: new Date(),
            completedBy: context.userId
          }]
        }
      });
      
      // Generate proposal ID and slug
      await proposal.generateProposalId();
      proposal.generateSlug();
      
      // Calculate initial pricing if items provided
      if (proposalData.pricing?.items) {
        proposal.pricing = this._calculatePricing(proposalData.pricing);
      }
      
      // Save proposal
      await proposal.save();
      
      // Create audit log
      await AuditService.log({
        user: context.userId,
        action: 'proposal.created',
        resource: {
          type: 'Proposal',
          id: proposal._id,
          name: proposal.title
        },
        metadata: {
          proposalId: proposal.proposalId,
          clientOrganization: clientOrg.name,
          totalValue: proposal.pricing?.total || 0
        },
        ip: context.ip,
        userAgent: context.userAgent
      });
      
      // Send notifications
      await this._sendProposalNotifications('created', proposal, context);
      
      // Clear relevant caches
      await CacheService.clearPattern(`proposals:${context.organizationId}:*`);
      
      logger.info('Proposal created successfully', {
        proposalId: proposal.proposalId,
        title: proposal.title,
        createdBy: context.userId
      });
      
      return proposal;
      
    } catch (error) {
      logger.error('Error creating proposal', {
        error: error.message,
        proposalData,
        context
      });
      throw error;
    }
  }
  
  /**
   * Get proposal by ID
   * @param {string} proposalId - Proposal ID
   * @param {Object} options - Query options
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Proposal document
   */
  static async getProposalById(proposalId, options = {}, context) {
    try {
      // Try cache first
      const cacheKey = `proposal:${proposalId}:${JSON.stringify(options)}`;
      const cached = await CacheService.get(cacheKey);
      if (cached) return cached;
      
      // Build query
      const query = mongoose.Types.ObjectId.isValid(proposalId) 
        ? { _id: proposalId }
        : { proposalId: proposalId.toUpperCase() };
      
      // Find proposal
      let proposal = await Proposal.findOne(query);
      
      if (!proposal) {
        throw new NotFoundError('Proposal not found');
      }
      
      // Check permissions
      const canView = proposal.canView(context.userId, context.userRole, context.organizationId);
      if (!canView) {
        throw new ForbiddenError('Insufficient permissions to view this proposal');
      }
      
      // Apply population based on options
      if (options.populate || options.includeAll) {
        const populateOptions = [];
        
        populateOptions.push('metadata.createdBy');
        populateOptions.push('client.organization');
        populateOptions.push('client.contact');
        populateOptions.push('team.lead');
        populateOptions.push('team.members.user');
        
        if (options.includeServices) {
          populateOptions.push('services.service');
        }
        
        if (options.includeDocuments) {
          populateOptions.push('documents.uploadedBy');
        }
        
        if (options.includeRevisions) {
          populateOptions.push('revisions.metadata.createdBy');
        }
        
        if (options.includeApprovals) {
          populateOptions.push('approval.levels.approvers.user');
          populateOptions.push('approval.history.approver');
        }
        
        proposal = await Proposal.findOne(query).populate(populateOptions);
      }
      
      // Record view if from external viewer
      if (options.recordView && context.isExternal) {
        await proposal.recordView({
          viewedBy: context.userEmail || 'anonymous',
          device: context.device,
          location: context.location,
          sections: options.viewedSections
        });
      }
      
      // Cache the result
      await CacheService.set(cacheKey, proposal, 300); // 5 minutes
      
      return proposal;
      
    } catch (error) {
      logger.error('Error getting proposal', {
        error: error.message,
        proposalId,
        context
      });
      throw error;
    }
  }
  
  /**
   * Update proposal
   * @param {string} proposalId - Proposal ID
   * @param {Object} updateData - Update data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated proposal
   */
  static async updateProposal(proposalId, updateData, context) {
    try {
      // Get existing proposal
      const proposal = await this.getProposalById(proposalId, {}, context);
      
      // Check edit permissions
      const canEdit = proposal.canEdit(context.userId, context.userRole);
      if (!canEdit) {
        throw new ForbiddenError('Insufficient permissions to edit this proposal');
      }
      
      // Validate status transitions
      if (updateData.status && updateData.status !== proposal.status) {
        this._validateStatusTransition(proposal.status, updateData.status);
      }
      
      // Track changes for revision history
      const changes = this._trackChanges(proposal, updateData);
      
      // Update fields
      const restrictedFields = ['proposalId', 'metadata.createdBy', 'metadata.organization'];
      restrictedFields.forEach(field => delete updateData[field]);
      
      // Handle pricing updates
      if (updateData.pricing) {
        updateData.pricing = this._calculatePricing(updateData.pricing);
      }
      
      // Apply updates
      Object.assign(proposal, updateData);
      proposal.metadata.lastModifiedBy = context.userId;
      
      // Add revision if significant changes
      if (changes.length > 0 && context.createRevision) {
        await proposal.addRevision({
          changes: changes,
          reason: context.revisionReason || 'Updates made',
          sections: context.sectionsModified,
          isMajor: context.isMajorRevision
        }, context.userId);
      }
      
      // Save proposal
      await proposal.save();
      
      // Create audit log
      await AuditService.log({
        user: context.userId,
        action: 'proposal.updated',
        resource: {
          type: 'Proposal',
          id: proposal._id,
          name: proposal.title
        },
        changes: changes,
        metadata: {
          proposalId: proposal.proposalId,
          version: proposal.version
        },
        ip: context.ip,
        userAgent: context.userAgent
      });
      
      // Send notifications
      await this._sendProposalNotifications('updated', proposal, context);
      
      // Clear caches
      await CacheService.clearPattern(`proposal:${proposalId}:*`);
      await CacheService.clearPattern(`proposals:${proposal.metadata.organization}:*`);
      
      logger.info('Proposal updated successfully', {
        proposalId: proposal.proposalId,
        updatedBy: context.userId,
        changes: changes.length
      });
      
      return proposal;
      
    } catch (error) {
      logger.error('Error updating proposal', {
        error: error.message,
        proposalId,
        updateData,
        context
      });
      throw error;
    }
  }
  
  /**
   * List proposals with filtering and pagination
   * @param {Object} filters - Filter options
   * @param {Object} options - Query options
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Proposals list with metadata
   */
  static async listProposals(filters = {}, options = {}, context) {
    try {
      // Build base query
      const query = {};
      
      // Organization filter (required unless admin)
      if (!context.isAdmin) {
        query['metadata.organization'] = context.organizationId;
      } else if (filters.organization) {
        query['metadata.organization'] = filters.organization;
      }
      
      // Status filter
      if (filters.status) {
        if (Array.isArray(filters.status)) {
          query.status = { $in: filters.status };
        } else {
          query.status = filters.status;
        }
      }
      
      // Type filter
      if (filters.type) {
        query.type = filters.type;
      }
      
      // Category filter
      if (filters.category) {
        query.category = filters.category;
      }
      
      // Client filter
      if (filters.client) {
        query['client.organization'] = filters.client;
      }
      
      // Date range filter
      if (filters.dateRange) {
        query.createdAt = {
          $gte: new Date(filters.dateRange.start),
          $lte: new Date(filters.dateRange.end)
        };
      }
      
      // Value range filter
      if (filters.valueRange) {
        query['pricing.total'] = {
          $gte: filters.valueRange.min,
          $lte: filters.valueRange.max
        };
      }
      
      // Tags filter
      if (filters.tags && filters.tags.length > 0) {
        query.tags = { $in: filters.tags };
      }
      
      // Text search
      if (filters.search) {
        query.$text = { $search: filters.search };
      }
      
      // Validity filter
      if (filters.validityStatus === 'active') {
        query['validity.endDate'] = { $gte: new Date() };
      } else if (filters.validityStatus === 'expired') {
        query['validity.endDate'] = { $lt: new Date() };
      }
      
      // Build options
      const page = options.page || 1;
      const limit = Math.min(options.limit || 20, 100);
      const skip = (page - 1) * limit;
      const sort = options.sort || { createdAt: -1 };
      
      // Execute query with pagination
      const [proposals, total] = await Promise.all([
        Proposal.find(query)
          .populate(options.populate || ['client.organization', 'metadata.createdBy'])
          .sort(sort)
          .limit(limit)
          .skip(skip)
          .lean(),
        Proposal.countDocuments(query)
      ]);
      
      // Calculate metadata
      const metadata = {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        hasNextPage: page < Math.ceil(total / limit),
        hasPrevPage: page > 1
      };
      
      // Get aggregated stats if requested
      if (options.includeStats) {
        metadata.stats = await this._getProposalStats(query);
      }
      
      return {
        proposals,
        metadata
      };
      
    } catch (error) {
      logger.error('Error listing proposals', {
        error: error.message,
        filters,
        context
      });
      throw error;
    }
  }
  
  /**
   * Send proposal to client
   * @param {string} proposalId - Proposal ID
   * @param {Object} sendData - Send configuration
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Send result
   */
  static async sendProposal(proposalId, sendData, context) {
    try {
      const proposal = await this.getProposalById(proposalId, {
        includeAll: true
      }, context);
      
      // Validate proposal is ready to send
      if (proposal.status === 'draft') {
        throw new BusinessRuleError('Cannot send proposal in draft status');
      }
      
      if (proposal.isExpired) {
        throw new BusinessRuleError('Cannot send expired proposal');
      }
      
      // Validate recipients
      if (!sendData.recipients || sendData.recipients.length === 0) {
        throw new ValidationError('At least one recipient is required');
      }
      
      // Generate proposal document if needed
      let proposalDocument = proposal.documents.find(d => d.type === 'proposal_doc');
      if (!proposalDocument || sendData.regenerateDocument) {
        proposalDocument = await this._generateProposalDocument(proposal);
      }
      
      // Prepare email data
      const emailData = {
        to: sendData.recipients,
        subject: sendData.subject || `Proposal: ${proposal.title}`,
        template: 'proposal-submission',
        data: {
          proposalTitle: proposal.title,
          proposalId: proposal.proposalId,
          clientName: proposal.client.organization.name,
          executiveSummary: proposal.executiveSummary,
          totalValue: proposal.pricing?.total,
          validity: proposal.validity.endDate,
          viewLink: `${config.app.clientUrl}/proposals/view/${proposal.slug}`,
          message: sendData.message
        },
        attachments: [
          {
            filename: `${proposal.proposalId}-proposal.pdf`,
            path: proposalDocument.url
          }
        ]
      };
      
      // Send email
      const emailResult = await EmailService.send(emailData);
      
      // Update proposal status and tracking
      proposal.status = 'sent';
      proposal.interactions.sent = {
        date: new Date(),
        method: sendData.method || 'email',
        sentBy: context.userId,
        recipients: sendData.recipients.map(email => ({
          email,
          name: sendData.recipientNames?.[email] || email
        }))
      };
      
      await proposal.updateStatus('sent', context.userId, 'Proposal sent to client');
      
      // Create audit log
      await AuditService.log({
        user: context.userId,
        action: 'proposal.sent',
        resource: {
          type: 'Proposal',
          id: proposal._id,
          name: proposal.title
        },
        metadata: {
          proposalId: proposal.proposalId,
          recipients: sendData.recipients,
          method: sendData.method
        },
        ip: context.ip,
        userAgent: context.userAgent
      });
      
      // Send notifications
      await this._sendProposalNotifications('sent', proposal, context);
      
      logger.info('Proposal sent successfully', {
        proposalId: proposal.proposalId,
        recipients: sendData.recipients.length,
        sentBy: context.userId
      });
      
      return {
        success: true,
        proposal,
        emailResult,
        trackingLink: `${config.app.clientUrl}/proposals/track/${proposal.slug}`
      };
      
    } catch (error) {
      logger.error('Error sending proposal', {
        error: error.message,
        proposalId,
        sendData,
        context
      });
      throw error;
    }
  }
  
  /**
   * Clone existing proposal
   * @param {string} proposalId - Source proposal ID
   * @param {Object} cloneData - Clone configuration
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Cloned proposal
   */
  static async cloneProposal(proposalId, cloneData, context) {
    try {
      const sourceProposal = await this.getProposalById(proposalId, {
        includeAll: true
      }, context);
      
      // Prepare clone data
      const proposalData = {
        title: cloneData.title || `${sourceProposal.title} (Copy)`,
        type: sourceProposal.type,
        category: sourceProposal.category,
        client: cloneData.client || sourceProposal.client,
        executiveSummary: sourceProposal.executiveSummary,
        sections: sourceProposal.sections.map(s => ({
          ...s.toObject(),
          metadata: {
            ...s.metadata,
            lastEditedBy: null,
            lastEditedAt: null
          }
        })),
        services: sourceProposal.services,
        deliverables: sourceProposal.deliverables,
        pricing: cloneData.updatePricing ? cloneData.pricing : sourceProposal.pricing,
        timeline: cloneData.updateTimeline ? cloneData.timeline : sourceProposal.timeline,
        team: cloneData.updateTeam ? cloneData.team : sourceProposal.team,
        terms: sourceProposal.terms,
        validity: cloneData.validity || {
          startDate: new Date(),
          endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
        },
        tags: sourceProposal.tags,
        metadata: {
          source: 'cloned',
          template: sourceProposal._id
        }
      };
      
      // Create new proposal
      const clonedProposal = await this.createProposal(proposalData, context);
      
      // Add relationship
      clonedProposal.relatedProposals.push({
        proposal: sourceProposal._id,
        relationship: 'parent'
      });
      await clonedProposal.save();
      
      logger.info('Proposal cloned successfully', {
        sourceProposalId: sourceProposal.proposalId,
        clonedProposalId: clonedProposal.proposalId,
        clonedBy: context.userId
      });
      
      return clonedProposal;
      
    } catch (error) {
      logger.error('Error cloning proposal', {
        error: error.message,
        proposalId,
        cloneData,
        context
      });
      throw error;
    }
  }
  
  /**
   * Delete proposal
   * @param {string} proposalId - Proposal ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Deletion result
   */
  static async deleteProposal(proposalId, context) {
    try {
      const proposal = await this.getProposalById(proposalId, {}, context);
      
      // Check permissions
      if (!context.isAdmin && !proposal.metadata.createdBy.equals(context.userId)) {
        throw new ForbiddenError('Insufficient permissions to delete this proposal');
      }
      
      // Prevent deletion of accepted proposals
      if (proposal.status === 'accepted') {
        throw new BusinessRuleError('Cannot delete accepted proposals');
      }
      
      // Delete associated files
      for (const doc of proposal.documents) {
        if (doc.publicId) {
          await FileService.deleteFile(doc.publicId);
        }
      }
      
      // Delete proposal
      await proposal.deleteOne();
      
      // Create audit log
      await AuditService.log({
        user: context.userId,
        action: 'proposal.deleted',
        resource: {
          type: 'Proposal',
          id: proposal._id,
          name: proposal.title
        },
        metadata: {
          proposalId: proposal.proposalId,
          status: proposal.status
        },
        ip: context.ip,
        userAgent: context.userAgent
      });
      
      // Clear caches
      await CacheService.clearPattern(`proposal:${proposalId}:*`);
      await CacheService.clearPattern(`proposals:${proposal.metadata.organization}:*`);
      
      logger.info('Proposal deleted successfully', {
        proposalId: proposal.proposalId,
        deletedBy: context.userId
      });
      
      return {
        success: true,
        message: 'Proposal deleted successfully'
      };
      
    } catch (error) {
      logger.error('Error deleting proposal', {
        error: error.message,
        proposalId,
        context
      });
      throw error;
    }
  }
  
  /**
   * Get proposal analytics
   * @param {string} proposalId - Proposal ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Analytics data
   */
  static async getProposalAnalytics(proposalId, context) {
    try {
      const proposal = await this.getProposalById(proposalId, {}, context);
      
      // Enhance analytics with calculated metrics
      const analytics = {
        ...proposal.analytics.toObject(),
        engagement: {
          ...proposal.analytics.engagement,
          score: this._calculateEngagementScore(proposal.analytics)
        },
        performance: {
          ...proposal.analytics.performance,
          comparisons: await this._getPerformanceComparisons(proposal)
        },
        insights: this._generateInsights(proposal)
      };
      
      return analytics;
      
    } catch (error) {
      logger.error('Error getting proposal analytics', {
        error: error.message,
        proposalId,
        context
      });
      throw error;
    }
  }
  
  /**
   * Export proposals
   * @param {Object} filters - Export filters
   * @param {Object} options - Export options
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Export data
   */
  static async exportProposals(filters, options, context) {
    try {
      // Get proposals
      const { proposals } = await this.listProposals(filters, {
        limit: options.limit || 1000,
        populate: ['client.organization', 'metadata.createdBy', 'team.lead']
      }, context);
      
      // Format data based on export type
      let exportData;
      if (options.format === 'summary') {
        exportData = proposals.map(p => ({
          proposalId: p.proposalId,
          title: p.title,
          client: p.client.organization.name,
          status: p.status,
          totalValue: p.pricing?.total || 0,
          createdAt: p.createdAt,
          validity: p.validity.endDate,
          createdBy: `${p.metadata.createdBy.firstName} ${p.metadata.createdBy.lastName}`
        }));
      } else {
        exportData = proposals;
      }
      
      // Create audit log
      await AuditService.log({
        user: context.userId,
        action: 'proposal.exported',
        metadata: {
          count: proposals.length,
          format: options.format,
          filters
        },
        ip: context.ip,
        userAgent: context.userAgent
      });
      
      return {
        data: exportData,
        metadata: {
          exportedAt: new Date(),
          exportedBy: context.userId,
          count: proposals.length,
          filters,
          format: options.format
        }
      };
      
    } catch (error) {
      logger.error('Error exporting proposals', {
        error: error.message,
        filters,
        options,
        context
      });
      throw error;
    }
  }
  
  // Private helper methods
  
  /**
   * Calculate pricing totals
   * @private
   */
  static _calculatePricing(pricing) {
    const items = pricing.items || [];
    
    // Calculate line items
    const calculatedItems = items.map(item => {
      const subtotal = item.quantity * item.unitPrice;
      const discountAmount = item.discountType === 'percentage' 
        ? subtotal * (item.discount / 100)
        : item.discount || 0;
      
      return {
        ...item,
        total: subtotal - discountAmount
      };
    });
    
    // Calculate totals
    const subtotal = calculatedItems.reduce((sum, item) => sum + item.total, 0);
    const discountAmount = pricing.discountType === 'percentage'
      ? subtotal * ((pricing.discount || 0) / 100)
      : pricing.discount || 0;
    
    const discountedSubtotal = subtotal - discountAmount;
    const taxAmount = discountedSubtotal * ((pricing.taxRate || 0) / 100);
    const total = discountedSubtotal + taxAmount;
    
    // Calculate breakdown
    const breakdown = {
      services: 0,
      products: 0,
      expenses: 0,
      recurring: 0
    };
    
    calculatedItems.forEach(item => {
      if (item.type === 'service') breakdown.services += item.total;
      else if (item.type === 'product') breakdown.products += item.total;
      else if (item.type === 'expense') breakdown.expenses += item.total;
      
      if (item.unit === 'month' || item.unit === 'subscription') {
        breakdown.recurring += item.total;
      }
    });
    
    return {
      ...pricing,
      items: calculatedItems,
      breakdown,
      subtotal,
      discount: discountAmount,
      taxAmount,
      total
    };
  }
  
  /**
   * Validate status transitions
   * @private
   */
  static _validateStatusTransition(currentStatus, newStatus) {
    const validTransitions = {
      draft: ['internal_review', 'pending_approval', 'withdrawn'],
      internal_review: ['draft', 'pending_approval', 'withdrawn'],
      pending_approval: ['approved', 'internal_review', 'withdrawn'],
      approved: ['sent', 'withdrawn'],
      sent: ['viewed', 'expired', 'withdrawn'],
      viewed: ['under_negotiation', 'accepted', 'rejected', 'expired'],
      under_negotiation: ['accepted', 'rejected', 'withdrawn'],
      accepted: ['converted'],
      rejected: [],
      expired: [],
      withdrawn: [],
      converted: []
    };
    
    const allowed = validTransitions[currentStatus] || [];
    if (!allowed.includes(newStatus)) {
      throw new BusinessRuleError(
        `Invalid status transition from ${currentStatus} to ${newStatus}`
      );
    }
  }
  
  /**
   * Track changes for revision history
   * @private
   */
  static _trackChanges(original, updates) {
    const changes = [];
    const significantFields = [
      'title', 'executiveSummary', 'pricing', 'timeline', 
      'services', 'deliverables', 'team', 'terms'
    ];
    
    for (const field of significantFields) {
      if (updates[field] && JSON.stringify(original[field]) !== JSON.stringify(updates[field])) {
        changes.push({
          field,
          before: original[field],
          after: updates[field]
        });
      }
    }
    
    return changes;
  }
  
  /**
   * Send proposal notifications
   * @private
   */
  static async _sendProposalNotifications(event, proposal, context) {
    try {
      const notifications = [];
      
      switch (event) {
        case 'created':
          // Notify team lead
          if (proposal.team?.lead) {
            notifications.push({
              userId: proposal.team.lead,
              type: 'proposal_created',
              title: 'New Proposal Created',
              message: `A new proposal "${proposal.title}" has been created`,
              data: { proposalId: proposal._id }
            });
          }
          break;
          
        case 'sent':
          // Notify team members
          const teamMembers = proposal.team?.members || [];
          for (const member of teamMembers) {
            notifications.push({
              userId: member.user,
              type: 'proposal_sent',
              title: 'Proposal Sent',
              message: `Proposal "${proposal.title}" has been sent to client`,
              data: { proposalId: proposal._id }
            });
          }
          break;
          
        case 'accepted':
          // Notify organization
          notifications.push({
            organizationId: proposal.metadata.organization,
            type: 'proposal_accepted',
            title: 'Proposal Accepted!',
            message: `Proposal "${proposal.title}" has been accepted by ${proposal.client.organization.name}`,
            priority: 'high',
            data: { proposalId: proposal._id }
          });
          break;
      }
      
      // Send notifications
      for (const notification of notifications) {
        await NotificationService.send(notification);
      }
      
    } catch (error) {
      logger.error('Error sending proposal notifications', {
        error: error.message,
        event,
        proposalId: proposal._id
      });
      // Don't throw - notifications are not critical
    }
  }
  
  /**
   * Calculate engagement score
   * @private
   */
  static _calculateEngagementScore(analytics) {
    const factors = {
      views: Math.min(analytics.views.total / 10, 1) * 30,
      uniqueViews: Math.min(analytics.views.unique / 5, 1) * 20,
      timeSpent: Math.min(analytics.engagement.timeOnProposal.total / 3600, 1) * 25,
      downloads: Math.min(analytics.engagement.downloads.total / 3, 1) * 15,
      interactions: Math.min(analytics.interactions.questions.total / 5, 1) * 10
    };
    
    return Math.round(Object.values(factors).reduce((sum, val) => sum + val, 0));
  }
  
  /**
   * Get proposal statistics
   * @private
   */
  static async _getProposalStats(query) {
    const stats = await Proposal.aggregate([
      { $match: query },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          totalValue: { $sum: '$pricing.total' },
          avgValue: { $avg: '$pricing.total' },
          byStatus: {
            $push: {
              status: '$status',
              value: '$pricing.total'
            }
          }
        }
      },
      {
        $project: {
          _id: 0,
          total: 1,
          totalValue: { $round: ['$totalValue', 2] },
          avgValue: { $round: ['$avgValue', 2] },
          statusBreakdown: {
            $arrayToObject: {
              $map: {
                input: { $setUnion: ['$byStatus.status'] },
                as: 'status',
                in: {
                  k: '$$status',
                  v: {
                    count: {
                      $size: {
                        $filter: {
                          input: '$byStatus',
                          cond: { $eq: ['$$this.status', '$$status'] }
                        }
                      }
                    },
                    value: {
                      $sum: {
                        $map: {
                          input: {
                            $filter: {
                              input: '$byStatus',
                              cond: { $eq: ['$$this.status', '$$status'] }
                            }
                          },
                          in: '$$this.value'
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    ]);
    
    return stats[0] || {
      total: 0,
      totalValue: 0,
      avgValue: 0,
      statusBreakdown: {}
    };
  }
  
  /**
   * Generate proposal document
   * @private
   */
  static async _generateProposalDocument(proposal) {
    // This would integrate with a document generation service
    // For now, return a placeholder
    return {
      type: 'proposal_doc',
      name: `${proposal.proposalId}-proposal.pdf`,
      url: `/api/proposals/${proposal._id}/document`,
      publicId: `proposals/${proposal._id}/document`,
      mimeType: 'application/pdf'
    };
  }
  
  /**
   * Generate insights from proposal data
   * @private
   */
  static _generateInsights(proposal) {
    const insights = [];
    const analytics = proposal.analytics;
    
    // Engagement insights
    if (analytics.views.total > 0 && analytics.engagement.timeOnProposal.total < 300) {
      insights.push({
        type: 'warning',
        category: 'engagement',
        message: 'Low engagement time - consider following up',
        recommendation: 'Schedule a call to walk through the proposal'
      });
    }
    
    // Conversion insights
    if (proposal.status === 'sent' && proposal.daysUntilExpiration < 7) {
      insights.push({
        type: 'urgent',
        category: 'expiration',
        message: 'Proposal expiring soon',
        recommendation: 'Follow up with client or extend validity period'
      });
    }
    
    // Price insights
    if (analytics.views.total > 5 && proposal.status === 'viewed') {
      insights.push({
        type: 'info',
        category: 'interest',
        message: 'High view count indicates strong interest',
        recommendation: 'Reach out to address any concerns'
      });
    }
    
    return insights;
  }
  
  /**
   * Get performance comparisons
   * @private
   */
  static async _getPerformanceComparisons(proposal) {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    
    const comparisons = await Proposal.aggregate([
      {
        $match: {
          'metadata.organization': proposal.metadata.organization,
          createdAt: { $gte: thirtyDaysAgo },
          _id: { $ne: proposal._id }
        }
      },
      {
        $group: {
          _id: null,
          avgViews: { $avg: '$analytics.views.total' },
          avgEngagementTime: { $avg: '$analytics.engagement.timeOnProposal.total' },
          avgDaysToConvert: { $avg: '$analytics.conversion.daysToConvert' },
          conversionRate: {
            $avg: {
              $cond: [
                { $eq: ['$analytics.conversion.isConverted', true] },
                1,
                0
              ]
            }
          }
        }
      }
    ]);
    
    return comparisons[0] || {
      avgViews: 0,
      avgEngagementTime: 0,
      avgDaysToConvert: 0,
      conversionRate: 0
    };
  }
}

module.exports = ProposalService;