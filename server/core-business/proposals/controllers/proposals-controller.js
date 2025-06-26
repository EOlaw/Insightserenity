// server/core-business/proposals/controllers/proposals-controller.js
/**
 * @file Proposal Controller
 * @description Handles HTTP requests for proposal management
 * @version 3.0.0
 */

const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const { 
  ValidationError, 
  NotFoundError,
  ForbiddenError,
  BusinessRuleError 
} = require('../../../shared/utils/app-error');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const logger = require('../../../shared/utils/logger');
const responseHandler = require('../../../shared/utils/response-handler');
const ProposalService = require('../services/proposals-service');
const FileService = require('../../../shared/services/file-service');

/**
 * Proposal Controller Class
 * @class ProposalController
 */
class ProposalController {
  /**
   * Create new proposal
   * @route   POST /api/proposals
   * @access  Private - Manager, Admin
   */
  static createProposal = asyncHandler(async (req, res) => {
    const proposalData = {
      title: req.body.title,
      type: req.body.type,
      category: req.body.category,
      client: req.body.client,
      executiveSummary: req.body.executiveSummary,
      sections: req.body.sections,
      services: req.body.services,
      deliverables: req.body.deliverables,
      pricing: req.body.pricing,
      timeline: req.body.timeline,
      team: req.body.team,
      terms: req.body.terms,
      validity: req.body.validity,
      tags: req.body.tags,
      customFields: req.body.customFields,
      metadata: req.body.metadata
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      isAdmin: req.user.role?.primary === 'super_admin',
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const proposal = await ProposalService.createProposal(proposalData, context);
    
    responseHandler.success(res, { proposal }, 'Proposal created successfully', 201);
  });
  
  /**
   * Get proposal by ID
   * @route   GET /api/proposals/:proposalId
   * @access  Private
   */
  static getProposal = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const options = {
      includeServices: req.query.includeServices === 'true',
      includeDocuments: req.query.includeDocuments === 'true',
      includeRevisions: req.query.includeRevisions === 'true',
      includeApprovals: req.query.includeApprovals === 'true',
      includeAll: req.query.includeAll === 'true',
      recordView: req.query.recordView === 'true'
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      isExternal: req.user.userType === 'client',
      userEmail: req.user.email,
      device: req.get('user-agent'),
      location: {
        ip: req.ip
      }
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, options, context);
    
    responseHandler.success(res, { proposal }, 'Proposal retrieved successfully');
  });
  
  /**
   * Update proposal
   * @route   PUT /api/proposals/:proposalId
   * @access  Private
   */
  static updateProposal = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const updateData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      createRevision: req.body._createRevision !== false,
      revisionReason: req.body._revisionReason,
      sectionsModified: req.body._sectionsModified,
      isMajorRevision: req.body._isMajorRevision === true,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    // Remove meta fields from update data
    delete updateData._createRevision;
    delete updateData._revisionReason;
    delete updateData._sectionsModified;
    delete updateData._isMajorRevision;
    
    const proposal = await ProposalService.updateProposal(proposalId, updateData, context);
    
    responseHandler.success(res, { proposal }, 'Proposal updated successfully');
  });
  
  /**
   * List proposals
   * @route   GET /api/proposals
   * @access  Private
   */
  static listProposals = asyncHandler(async (req, res) => {
    const filters = {
      status: req.query.status,
      type: req.query.type,
      category: req.query.category,
      client: req.query.client,
      organization: req.query.organization,
      tags: req.query.tags ? req.query.tags.split(',') : undefined,
      search: req.query.search,
      validityStatus: req.query.validityStatus,
      dateRange: req.query.startDate && req.query.endDate ? {
        start: req.query.startDate,
        end: req.query.endDate
      } : undefined,
      valueRange: req.query.minValue && req.query.maxValue ? {
        min: parseFloat(req.query.minValue),
        max: parseFloat(req.query.maxValue)
      } : undefined
    };
    
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 20,
      sort: req.query.sort || '-createdAt',
      populate: req.query.populate ? req.query.populate.split(',') : undefined,
      includeStats: req.query.includeStats === 'true'
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    const result = await ProposalService.listProposals(filters, options, context);
    
    responseHandler.success(res, result, 'Proposals retrieved successfully');
  });
  
  /**
   * Delete proposal
   * @route   DELETE /api/proposals/:proposalId
   * @access  Private - Admin, Creator
   */
  static deleteProposal = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      isAdmin: req.user.role?.primary === 'super_admin',
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await ProposalService.deleteProposal(proposalId, context);
    
    responseHandler.success(res, result, 'Proposal deleted successfully');
  });
  
  /**
   * Clone proposal
   * @route   POST /api/proposals/:proposalId/clone
   * @access  Private
   */
  static cloneProposal = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const cloneData = {
      title: req.body.title,
      client: req.body.client,
      updatePricing: req.body.updatePricing,
      pricing: req.body.pricing,
      updateTimeline: req.body.updateTimeline,
      timeline: req.body.timeline,
      updateTeam: req.body.updateTeam,
      team: req.body.team,
      validity: req.body.validity
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const proposal = await ProposalService.cloneProposal(proposalId, cloneData, context);
    
    responseHandler.success(res, { proposal }, 'Proposal cloned successfully', 201);
  });
  
  /**
   * Send proposal to client
   * @route   POST /api/proposals/:proposalId/send
   * @access  Private
   */
  static sendProposal = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const sendData = {
      recipients: req.body.recipients,
      recipientNames: req.body.recipientNames,
      subject: req.body.subject,
      message: req.body.message,
      method: req.body.method || 'email',
      regenerateDocument: req.body.regenerateDocument === true
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const result = await ProposalService.sendProposal(proposalId, sendData, context);
    
    responseHandler.success(res, result, 'Proposal sent successfully');
  });
  
  /**
   * Update proposal status
   * @route   PATCH /api/proposals/:proposalId/status
   * @access  Private
   */
  static updateProposalStatus = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const { status, comment } = req.body;
    
    if (!status) {
      throw new ValidationError('Status is required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    await proposal.updateStatus(status, context.userId, comment);
    
    responseHandler.success(res, { proposal }, 'Proposal status updated successfully');
  });
  
  /**
   * Add proposal section
   * @route   POST /api/proposals/:proposalId/sections
   * @access  Private
   */
  static addProposalSection = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const sectionData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      createRevision: true,
      revisionReason: 'Added new section',
      sectionsModified: [sectionData.title],
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    
    // Add section with proper ordering
    const maxOrder = Math.max(...proposal.sections.map(s => s.order || 0), 0);
    sectionData.order = sectionData.order || maxOrder + 1;
    sectionData.metadata = {
      ...sectionData.metadata,
      lastEditedBy: context.userId,
      lastEditedAt: new Date()
    };
    
    proposal.sections.push(sectionData);
    
    const updatedProposal = await ProposalService.updateProposal(
      proposalId,
      { sections: proposal.sections },
      context
    );
    
    responseHandler.success(res, { proposal: updatedProposal }, 'Section added successfully');
  });
  
  /**
   * Update proposal section
   * @route   PUT /api/proposals/:proposalId/sections/:sectionId
   * @access  Private
   */
  static updateProposalSection = asyncHandler(async (req, res) => {
    const { proposalId, sectionId } = req.params;
    const sectionData = req.body;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      createRevision: true,
      revisionReason: 'Updated section',
      sectionsModified: [sectionData.title],
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    
    // Find and update section
    const sectionIndex = proposal.sections.findIndex(s => s._id.toString() === sectionId);
    if (sectionIndex === -1) {
      throw new NotFoundError('Section not found');
    }
    
    proposal.sections[sectionIndex] = {
      ...proposal.sections[sectionIndex].toObject(),
      ...sectionData,
      metadata: {
        ...proposal.sections[sectionIndex].metadata,
        lastEditedBy: context.userId,
        lastEditedAt: new Date(),
        version: (proposal.sections[sectionIndex].metadata?.version || 0) + 1
      }
    };
    
    const updatedProposal = await ProposalService.updateProposal(
      proposalId,
      { sections: proposal.sections },
      context
    );
    
    responseHandler.success(res, { proposal: updatedProposal }, 'Section updated successfully');
  });
  
  /**
   * Delete proposal section
   * @route   DELETE /api/proposals/:proposalId/sections/:sectionId
   * @access  Private
   */
  static deleteProposalSection = asyncHandler(async (req, res) => {
    const { proposalId, sectionId } = req.params;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      createRevision: true,
      revisionReason: 'Deleted section',
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    
    // Remove section
    const sectionIndex = proposal.sections.findIndex(s => s._id.toString() === sectionId);
    if (sectionIndex === -1) {
      throw new NotFoundError('Section not found');
    }
    
    const deletedSection = proposal.sections[sectionIndex];
    context.sectionsModified = [deletedSection.title];
    
    proposal.sections.splice(sectionIndex, 1);
    
    const updatedProposal = await ProposalService.updateProposal(
      proposalId,
      { sections: proposal.sections },
      context
    );
    
    responseHandler.success(res, { proposal: updatedProposal }, 'Section deleted successfully');
  });
  
  /**
   * Get proposal analytics
   * @route   GET /api/proposals/:proposalId/analytics
   * @access  Private
   */
  static getProposalAnalytics = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary
    };
    
    const analytics = await ProposalService.getProposalAnalytics(proposalId, context);
    
    responseHandler.success(res, { analytics }, 'Analytics retrieved successfully');
  });
  
  /**
   * Upload proposal document
   * @route   POST /api/proposals/:proposalId/documents
   * @access  Private
   */
  static uploadProposalDocument = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const { type, name, description, isPublic } = req.body;
    
    if (!req.file) {
      throw new ValidationError('Document file is required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    // Upload file
    const uploadResult = await FileService.uploadDocument(req.file, {
      folder: 'proposals',
      allowedTypes: constants.FILE.ALLOWED_TYPES.DOCUMENT
    });
    
    // Get proposal and add document
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    
    const document = {
      type: type || 'other',
      name: name || req.file.originalname,
      description,
      url: uploadResult.url,
      publicId: uploadResult.publicId,
      size: uploadResult.size,
      mimeType: uploadResult.mimetype,
      uploadedBy: context.userId,
      isPublic: isPublic === true
    };
    
    proposal.documents.push(document);
    await proposal.save();
    
    responseHandler.success(res, { document }, 'Document uploaded successfully');
  });
  
  /**
   * Delete proposal document
   * @route   DELETE /api/proposals/:proposalId/documents/:documentId
   * @access  Private
   */
  static deleteProposalDocument = asyncHandler(async (req, res) => {
    const { proposalId, documentId } = req.params;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    
    // Find and remove document
    const docIndex = proposal.documents.findIndex(d => d._id.toString() === documentId);
    if (docIndex === -1) {
      throw new NotFoundError('Document not found');
    }
    
    const document = proposal.documents[docIndex];
    
    // Delete file
    if (document.publicId) {
      await FileService.deleteFile(document.publicId);
    }
    
    proposal.documents.splice(docIndex, 1);
    await proposal.save();
    
    responseHandler.success(res, { message: 'Document deleted successfully' });
  });
  
  /**
   * Add proposal feedback
   * @route   POST /api/proposals/:proposalId/feedback
   * @access  Private
   */
  static addProposalFeedback = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const { type, section, content } = req.body;
    
    if (!content) {
      throw new ValidationError('Feedback content is required');
    }
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      userEmail: req.user.email
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    
    const feedback = {
      from: context.userEmail,
      date: new Date(),
      type: type || 'comment',
      section,
      content,
      resolved: false
    };
    
    proposal.interactions.feedback.push(feedback);
    await proposal.save();
    
    responseHandler.success(res, { feedback }, 'Feedback added successfully');
  });
  
  /**
   * Resolve proposal feedback
   * @route   PATCH /api/proposals/:proposalId/feedback/:feedbackId/resolve
   * @access  Private
   */
  static resolveProposalFeedback = asyncHandler(async (req, res) => {
    const { proposalId, feedbackId } = req.params;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {}, context);
    
    // Find and update feedback
    const feedback = proposal.interactions.feedback.id(feedbackId);
    if (!feedback) {
      throw new NotFoundError('Feedback not found');
    }
    
    feedback.resolved = true;
    feedback.resolvedBy = context.userId;
    feedback.resolvedAt = new Date();
    
    await proposal.save();
    
    responseHandler.success(res, { feedback }, 'Feedback resolved successfully');
  });
  
  /**
   * Export proposals
   * @route   GET /api/proposals/export
   * @access  Private
   */
  static exportProposals = asyncHandler(async (req, res) => {
    const filters = {
      status: req.query.status,
      type: req.query.type,
      category: req.query.category,
      client: req.query.client,
      dateRange: req.query.startDate && req.query.endDate ? {
        start: req.query.startDate,
        end: req.query.endDate
      } : undefined
    };
    
    const options = {
      format: req.query.format || 'summary',
      limit: parseInt(req.query.limit) || 1000
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      isAdmin: req.user.role?.primary === 'super_admin',
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const exportData = await ProposalService.exportProposals(filters, options, context);
    
    // Set appropriate headers for download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 
      `attachment; filename="proposals-export-${new Date().toISOString().split('T')[0]}.json"`
    );
    
    res.json(exportData);
  });
  
  /**
   * Get proposal templates
   * @route   GET /api/proposals/templates
   * @access  Private
   */
  static getProposalTemplates = asyncHandler(async (req, res) => {
    const filters = {
      type: req.query.type,
      category: req.query.category,
      search: req.query.search
    };
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary
    };
    
    // This would fetch from a templates collection
    const templates = [
      {
        id: 'standard-consulting',
        name: 'Standard Consulting Proposal',
        description: 'Template for general consulting services',
        type: 'service',
        category: 'consulting'
      },
      {
        id: 'project-implementation',
        name: 'Project Implementation Proposal',
        description: 'Template for implementation projects',
        type: 'project',
        category: 'implementation'
      }
    ];
    
    responseHandler.success(res, { templates }, 'Templates retrieved successfully');
  });
  
  /**
   * Get proposal statistics
   * @route   GET /api/proposals/statistics
   * @access  Private
   */
  static getProposalStatistics = asyncHandler(async (req, res) => {
    const dateRange = req.query.startDate && req.query.endDate ? {
      start: req.query.startDate,
      end: req.query.endDate
    } : undefined;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary,
      isAdmin: req.user.role?.primary === 'super_admin'
    };
    
    // Get various statistics
    const [conversionMetrics, proposalsByStatus, proposalsByType] = await Promise.all([
      ProposalService.Proposal.getConversionMetrics(context.organizationId, dateRange),
      ProposalService.listProposals({ dateRange }, { includeStats: true }, context),
      ProposalService.listProposals({ dateRange }, { includeStats: true }, context)
    ]);
    
    const statistics = {
      conversion: conversionMetrics[0] || {},
      statusBreakdown: proposalsByStatus.metadata.stats?.statusBreakdown || {},
      totalValue: proposalsByStatus.metadata.stats?.totalValue || 0,
      averageValue: proposalsByStatus.metadata.stats?.avgValue || 0,
      totalProposals: proposalsByStatus.metadata.total || 0,
      dateRange
    };
    
    responseHandler.success(res, { statistics }, 'Statistics retrieved successfully');
  });
  
  /**
   * Preview proposal
   * @route   GET /api/proposals/:proposalId/preview
   * @access  Private
   */
  static previewProposal = asyncHandler(async (req, res) => {
    const { proposalId } = req.params;
    const { format = 'html' } = req.query;
    
    const context = {
      userId: req.user._id,
      organizationId: req.user.organization?.current,
      userRole: req.user.role?.primary
    };
    
    const proposal = await ProposalService.getProposalById(proposalId, {
      includeAll: true
    }, context);
    
    // Generate preview based on format
    if (format === 'html') {
      // This would use a template engine to generate HTML
      const html = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>${proposal.title}</title>
            <style>
              body { font-family: Arial, sans-serif; margin: 40px; }
              h1 { color: #333; }
              .section { margin-bottom: 30px; }
            </style>
          </head>
          <body>
            <h1>${proposal.title}</h1>
            <div class="section">
              <h2>Executive Summary</h2>
              <p>${proposal.executiveSummary}</p>
            </div>
            <!-- More sections would be rendered here -->
          </body>
        </html>
      `;
      
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
    } else {
      responseHandler.success(res, { proposal }, 'Preview generated successfully');
    }
  });
}

module.exports = ProposalController;