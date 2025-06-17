/**
 * @file Project Controller
 * @description HTTP request handlers for project management
 * @version 2.0.0
 */

const ProjectService = require('../services/project-service');
const { AppError } = require('../../shared/utils/app-error');
const { catchAsync } = require('../../shared/utils/catch-async');
const { sanitizeQuery } = require('../../shared/utils/sanitizers');
const logger = require('../../shared/utils/logger');
const { uploadToS3 } = require('../../shared/utils/file-upload');

class ProjectController {
  /**
   * Create a new project
   * POST /api/v1/projects
   */
  static createProject = catchAsync(async (req, res, next) => {
    const { body, user, files } = req;

    logger.debug('Creating new project', {
      userId: user._id,
      projectName: body.name,
      clientId: body.client,
      hasFiles: !!files
    });

    // Validate user permissions
    if (!['admin', 'manager', 'consultant'].includes(user.role)) {
      logger.warn('Project creation denied - insufficient permissions', {
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('You do not have permission to create projects', 403));
    }

    // Handle file uploads if any
    if (files?.documents) {
      body.initialDocuments = await Promise.all(
        files.documents.map(file => uploadToS3(file, 'project-documents'))
      );
    }

    const project = await ProjectService.createProject(body, user._id);

    logger.info('Project created successfully via API', {
      projectId: project._id,
      projectCode: project.code,
      projectName: project.name,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        project
      }
    });
  });

  /**
   * Get all projects with filtering
   * GET /api/v1/projects
   */
  static getAllProjects = catchAsync(async (req, res, next) => {
    const { query, user } = req;
    
    logger.debug('Fetching projects with filters', {
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
      status: query.status ? 
        (Array.isArray(query.status) ? query.status : query.status.split(',')) : 
        undefined,
      client: sanitizeQuery(query.client),
      projectManager: sanitizeQuery(query.projectManager),
      type: sanitizeQuery(query.type),
      priority: sanitizeQuery(query.priority),
      tags: query.tags ? query.tags.split(',').map(tag => sanitizeQuery(tag)) : undefined,
      includeArchived: query.includeArchived === 'true',
      healthScoreMin: query.healthScoreMin ? parseInt(query.healthScoreMin) : undefined,
      isDelayed: query.isDelayed === 'true' ? true : query.isDelayed === 'false' ? false : undefined,
      isOverBudget: query.isOverBudget === 'true' ? true : query.isOverBudget === 'false' ? false : undefined
    };

    // Add date range if provided
    if (query.startDateFrom || query.startDateTo) {
      options.dateRange = {
        start: query.startDateFrom ? new Date(query.startDateFrom) : undefined,
        end: query.startDateTo ? new Date(query.startDateTo) : undefined
      };
    }

    // Add budget range if provided
    if (query.budgetMin || query.budgetMax) {
      options.budgetRange = {
        min: query.budgetMin ? parseFloat(query.budgetMin) : undefined,
        max: query.budgetMax ? parseFloat(query.budgetMax) : undefined
      };
    }

    // Apply role-based filtering
    const filter = {};
    
    // Non-admins can only see projects they're involved in
    if (user.role !== 'admin') {
      filter.$or = [
        { 'team.projectManager': user._id },
        { 'team.members.consultant': user._id },
        { createdBy: user._id }
      ];
    }

    const result = await ProjectService.getAllProjects(filter, options);

    logger.debug('Projects fetched successfully', {
      count: result.projects.length,
      total: result.pagination.total,
      page: result.pagination.page,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: result.projects.length,
      ...result
    });
  });

  /**
   * Get project by ID
   * GET /api/v1/projects/:id
   */
  static getProjectById = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { includeLogs, includeFinancialDetails } = req.query;
    const { user } = req;

    logger.debug('Fetching project by ID', {
      projectId: id,
      includeLogs: includeLogs === 'true',
      includeFinancialDetails: includeFinancialDetails !== 'false',
      userId: user._id
    });

    const options = {
      includeLogs: includeLogs === 'true',
      includeFinancialDetails: includeFinancialDetails !== 'false'
    };

    const project = await ProjectService.getProjectById(id, options);

    // Check access permissions
    if (user.role !== 'admin' && !project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Project access denied - insufficient permissions', {
        projectId: id,
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('You do not have permission to view this project', 403));
    }

    logger.debug('Project fetched successfully', {
      projectId: project._id,
      projectCode: project.code,
      projectName: project.name
    });

    res.status(200).json({
      status: 'success',
      data: {
        project
      }
    });
  });

  /**
   * Update project
   * PATCH /api/v1/projects/:id
   */
  static updateProject = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user, files } = req;

    logger.debug('Updating project', {
      projectId: id,
      userId: user._id,
      updateFields: Object.keys(body),
      hasFiles: !!files
    });

    // Check permissions
    const project = await ProjectService.getProjectById(id);
    
    if (user.role !== 'admin' && 
        project.team.projectManager.toString() !== user._id.toString() &&
        project.createdBy.toString() !== user._id.toString()) {
      logger.warn('Project update denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to update this project', 403));
    }

    // Handle file uploads
    if (files?.documents) {
      body.newDocuments = await Promise.all(
        files.documents.map(file => uploadToS3(file, 'project-documents'))
      );
    }

    const updatedProject = await ProjectService.updateProject(id, body, user._id);

    logger.info('Project updated successfully', {
      projectId: updatedProject._id,
      projectCode: updatedProject.code,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        project: updatedProject
      }
    });
  });

  /**
   * Update project status
   * PATCH /api/v1/projects/:id/status
   */
  static updateProjectStatus = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { status, reason, holdReason, cancellationReason } = req.body;
    const { user } = req;

    logger.debug('Updating project status', {
      projectId: id,
      newStatus: status,
      userId: user._id
    });

    // Validate status
    const validStatuses = [
      'draft', 'pending_approval', 'approved', 'active', 
      'on_hold', 'completed', 'cancelled', 'archived'
    ];
    
    if (!validStatuses.includes(status)) {
      logger.warn('Invalid project status provided', { status, projectId: id });
      return next(new AppError('Invalid project status', 400));
    }

    // Check permissions
    const project = await ProjectService.getProjectById(id);
    
    if (user.role !== 'admin' && user.role !== 'manager' &&
        project.team.projectManager.toString() !== user._id.toString()) {
      logger.warn('Status update denied - insufficient permissions', {
        projectId: id,
        userId: user._id,
        userRole: user.role
      });
      return next(new AppError('You do not have permission to change project status', 403));
    }

    const additionalData = {
      reason,
      holdReason,
      cancellationReason
    };

    const updatedProject = await ProjectService.updateProjectStatus(
      id, 
      status, 
      user._id, 
      additionalData
    );

    logger.info('Project status updated successfully', {
      projectId: updatedProject._id,
      projectCode: updatedProject.code,
      newStatus: status,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        project: updatedProject
      }
    });
  });

  /**
   * Add team member to project
   * POST /api/v1/projects/:id/team
   */
  static addTeamMember = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user } = req;

    logger.debug('Adding team member to project', {
      projectId: id,
      consultantId: body.consultant,
      role: body.role,
      userId: user._id
    });

    // Check permissions
    const project = await ProjectService.getProjectById(id);
    
    if (user.role !== 'admin' && user.role !== 'manager' &&
        project.team.projectManager.toString() !== user._id.toString()) {
      logger.warn('Add team member denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to manage project team', 403));
    }

    const updatedProject = await ProjectService.addTeamMember(id, body, user._id);

    logger.info('Team member added successfully', {
      projectId: id,
      consultantId: body.consultant,
      role: body.role,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        project: updatedProject
      }
    });
  });

  /**
   * Remove team member from project
   * DELETE /api/v1/projects/:id/team/:memberId
   */
  static removeTeamMember = catchAsync(async (req, res, next) => {
    const { id, memberId } = req.params;
    const { user } = req;

    logger.debug('Removing team member from project', {
      projectId: id,
      memberId,
      userId: user._id
    });

    // Check permissions
    const project = await ProjectService.getProjectById(id);
    
    if (user.role !== 'admin' && 
        project.team.projectManager.toString() !== user._id.toString()) {
      logger.warn('Remove team member denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to manage project team', 403));
    }

    const member = project.team.members.id(memberId);
    if (!member) {
      return next(new AppError('Team member not found', 404));
    }

    member.remove();
    project.updatedBy = user._id;
    await project.save();

    logger.info('Team member removed successfully', {
      projectId: id,
      memberId,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      message: 'Team member removed successfully'
    });
  });

  /**
   * Update milestone
   * PATCH /api/v1/projects/:id/milestones/:milestoneId
   */
  static updateMilestone = catchAsync(async (req, res, next) => {
    const { id, milestoneId } = req.params;
    const { body, user } = req;

    logger.debug('Updating project milestone', {
      projectId: id,
      milestoneId,
      userId: user._id,
      updateFields: Object.keys(body)
    });

    // Check permissions
    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Milestone update denied - insufficient permissions', {
        projectId: id,
        milestoneId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to update milestones', 403));
    }

    const updatedProject = await ProjectService.updateMilestone(
      id, 
      milestoneId, 
      body, 
      user._id
    );

    logger.info('Milestone updated successfully', {
      projectId: id,
      milestoneId,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        project: updatedProject
      }
    });
  });

  /**
   * Add risk to project
   * POST /api/v1/projects/:id/risks
   */
  static addRisk = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user } = req;

    logger.debug('Adding risk to project', {
      projectId: id,
      riskTitle: body.title,
      category: body.category,
      userId: user._id
    });

    // Check permissions
    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Add risk denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to add risks', 403));
    }

    const updatedProject = await ProjectService.addRisk(id, body, user._id);

    logger.info('Risk added successfully', {
      projectId: id,
      riskTitle: body.title,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        risk: updatedProject.risks[updatedProject.risks.length - 1]
      }
    });
  });

  /**
   * Update risk
   * PATCH /api/v1/projects/:id/risks/:riskId
   */
  static updateRisk = catchAsync(async (req, res, next) => {
    const { id, riskId } = req.params;
    const { body, user } = req;

    logger.debug('Updating project risk', {
      projectId: id,
      riskId,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Update risk denied - insufficient permissions', {
        projectId: id,
        riskId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to update risks', 403));
    }

    const risk = project.risks.id(riskId);
    if (!risk) {
      return next(new AppError('Risk not found', 404));
    }

    Object.assign(risk, body);
    risk.reviewedAt = new Date();
    
    if (body.status === 'closed') {
      risk.closedAt = new Date();
    }

    project.updatedBy = user._id;
    await project.save();

    logger.info('Risk updated successfully', {
      projectId: id,
      riskId,
      status: risk.status,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        risk
      }
    });
  });

  /**
   * Add issue to project
   * POST /api/v1/projects/:id/issues
   */
  static addIssue = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user } = req;

    logger.debug('Adding issue to project', {
      projectId: id,
      issueTitle: body.title,
      severity: body.severity,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Add issue denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to add issues', 403));
    }

    body.reportedBy = user._id;
    body.reportedAt = new Date();

    project.issues.push(body);
    project.updatedBy = user._id;
    await project.save();

    const issue = project.issues[project.issues.length - 1];

    logger.info('Issue added successfully', {
      projectId: id,
      issueId: issue._id,
      issueTitle: issue.title,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        issue
      }
    });
  });

  /**
   * Update issue
   * PATCH /api/v1/projects/:id/issues/:issueId
   */
  static updateIssue = catchAsync(async (req, res, next) => {
    const { id, issueId } = req.params;
    const { body, user } = req;

    logger.debug('Updating project issue', {
      projectId: id,
      issueId,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Update issue denied - insufficient permissions', {
        projectId: id,
        issueId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to update issues', 403));
    }

    const issue = project.issues.id(issueId);
    if (!issue) {
      return next(new AppError('Issue not found', 404));
    }

    // Handle resolution
    if (body.status === 'resolved' && issue.status !== 'resolved') {
      body.resolution = {
        ...body.resolution,
        resolvedBy: user._id,
        resolvedAt: new Date()
      };
    }

    Object.assign(issue, body);
    project.updatedBy = user._id;
    await project.save();

    logger.info('Issue updated successfully', {
      projectId: id,
      issueId,
      status: issue.status,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        issue
      }
    });
  });

  /**
   * Create change request
   * POST /api/v1/projects/:id/change-requests
   */
  static createChangeRequest = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user, files } = req;

    logger.debug('Creating change request', {
      projectId: id,
      changeType: body.type,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Create change request denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to create change requests', 403));
    }

    // Handle document uploads
    if (files?.documents) {
      body.documents = await Promise.all(
        files.documents.map(file => uploadToS3(file, 'project-change-requests'))
      );
    }

    const changeRequest = await ProjectService.createChangeRequest(id, body, user._id);

    logger.info('Change request created successfully', {
      projectId: id,
      changeRequestId: changeRequest._id,
      requestNumber: changeRequest.requestNumber,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        changeRequest
      }
    });
  });

  /**
   * Review change request
   * PATCH /api/v1/projects/:id/change-requests/:changeRequestId/review
   */
  static reviewChangeRequest = catchAsync(async (req, res, next) => {
    const { id, changeRequestId } = req.params;
    const { decision, comments } = req.body;
    const { user } = req;

    logger.debug('Reviewing change request', {
      projectId: id,
      changeRequestId,
      decision,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    const changeRequest = project.changeRequests.id(changeRequestId);
    
    if (!changeRequest) {
      return next(new AppError('Change request not found', 404));
    }

    // Check if user is a reviewer
    const reviewer = changeRequest.reviewers.find(r => 
      r.reviewer.toString() === user._id.toString() && r.decision === 'pending'
    );
    
    if (!reviewer && user.role !== 'admin') {
      logger.warn('Change request review denied - not a reviewer', {
        projectId: id,
        changeRequestId,
        userId: user._id
      });
      return next(new AppError('You are not authorized to review this change request', 403));
    }

    // Update review
    if (reviewer) {
      reviewer.decision = decision;
      reviewer.comments = comments;
      reviewer.reviewedAt = new Date();
    }

    // Check if all reviews are complete
    const pendingReviews = changeRequest.reviewers.filter(r => r.decision === 'pending');
    const approvals = changeRequest.reviewers.filter(r => r.decision === 'approved');
    
    if (pendingReviews.length === 0) {
      if (approvals.length === changeRequest.reviewers.length) {
        changeRequest.status = 'approved';
        changeRequest.approvedBy = user._id;
      } else {
        changeRequest.status = 'rejected';
      }
    }

    project.updatedBy = user._id;
    await project.save();

    logger.info('Change request reviewed', {
      projectId: id,
      changeRequestId,
      decision,
      status: changeRequest.status,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        changeRequest
      }
    });
  });

  /**
   * Get project dashboard
   * GET /api/v1/projects/:id/dashboard
   */
  static getProjectDashboard = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { user } = req;

    logger.debug('Fetching project dashboard', {
      projectId: id,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Project dashboard access denied', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to view this project', 403));
    }

    const dashboard = await ProjectService.getProjectDashboard(id);

    logger.debug('Project dashboard fetched successfully', {
      projectId: id,
      healthScore: dashboard.overview.health,
      progress: dashboard.overview.progress
    });

    res.status(200).json({
      status: 'success',
      data: {
        dashboard
      }
    });
  });

  /**
   * Generate project status report
   * GET /api/v1/projects/:id/reports/status
   */
  static generateStatusReport = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { format = 'json', includeFinancials = 'true' } = req.query;
    const { user } = req;

    logger.debug('Generating project status report', {
      projectId: id,
      format,
      includeFinancials: includeFinancials === 'true',
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Status report generation denied', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to generate reports', 403));
    }

    const options = {
      format,
      includeFinancials: includeFinancials === 'true' && 
                        (user.role === 'admin' || 
                         project.team.projectManager.toString() === user._id.toString())
    };

    const report = await ProjectService.generateStatusReport(id, options);

    logger.info('Status report generated successfully', {
      projectId: id,
      format,
      userId: user._id
    });

    if (format === 'pdf' && report.pdf) {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=project-${project.code}-status-report.pdf`);
      return res.send(report.pdf);
    }

    res.status(200).json({
      status: 'success',
      data: {
        report: format === 'pdf' ? report.report : report
      }
    });
  });

  /**
   * Archive project
   * POST /api/v1/projects/:id/archive
   */
  static archiveProject = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { reason } = req.body;
    const { user } = req;

    logger.debug('Archiving project', {
      projectId: id,
      reason,
      userId: user._id
    });

    if (!reason) {
      return next(new AppError('Archive reason is required', 400));
    }

    // Check permissions - only admins and project managers can archive
    const project = await ProjectService.getProjectById(id);
    
    if (user.role !== 'admin' && 
        project.team.projectManager.toString() !== user._id.toString()) {
      logger.warn('Project archive denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to archive this project', 403));
    }

    const archivedProject = await ProjectService.archiveProject(id, reason, user._id);

    logger.info('Project archived successfully', {
      projectId: archivedProject._id,
      projectCode: archivedProject.code,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        project: archivedProject
      }
    });
  });

  /**
   * Get project statistics
   * GET /api/v1/projects/stats
   */
  static getProjectStats = catchAsync(async (req, res, next) => {
    const { user } = req;
    const { clientId, dateFrom, dateTo } = req.query;

    logger.debug('Fetching project statistics', {
      userId: user._id,
      userRole: user.role,
      filters: { clientId, dateFrom, dateTo }
    });

    // Build filter based on permissions and parameters
    const filter = {};
    
    if (user.role !== 'admin') {
      filter.$or = [
        { 'team.projectManager': user._id },
        { 'team.members.consultant': user._id }
      ];
    }

    if (clientId) {
      filter.client = clientId;
    }

    if (dateFrom || dateTo) {
      filter.createdAt = {};
      if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
      if (dateTo) filter.createdAt.$lte = new Date(dateTo);
    }

    const stats = await ProjectService.getProjectStatistics(filter);

    logger.debug('Project statistics fetched successfully', {
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
   * Get projects by client
   * GET /api/v1/projects/by-client/:clientId
   */
  static getProjectsByClient = catchAsync(async (req, res, next) => {
    const { clientId } = req.params;
    const { status, dateRange } = req.query;
    const { user } = req;

    logger.debug('Fetching projects by client', {
      clientId,
      status,
      userId: user._id
    });

    const options = {
      status: status ? status.split(',') : undefined,
      dateRange: dateRange ? JSON.parse(dateRange) : undefined
    };

    const projects = await ProjectService.getProjectsByClient(clientId, options);

    // Filter based on user permissions
    const accessibleProjects = user.role === 'admin' ? projects :
      projects.filter(p => p.canBeAccessedBy(user._id, user.role));

    logger.debug('Projects by client fetched successfully', {
      clientId,
      totalProjects: projects.length,
      accessibleProjects: accessibleProjects.length,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: accessibleProjects.length,
      data: {
        projects: accessibleProjects
      }
    });
  });

  /**
   * Get active projects
   * GET /api/v1/projects/active
   */
  static getActiveProjects = catchAsync(async (req, res, next) => {
    const { projectManager, client, priority } = req.query;
    const { user } = req;

    logger.debug('Fetching active projects', {
      filters: { projectManager, client, priority },
      userId: user._id
    });

    const filters = {
      projectManager: projectManager || (user.role !== 'admin' ? user._id : undefined),
      client,
      priority
    };

    const projects = await ProjectService.getActiveProjects(filters);

    logger.debug('Active projects fetched successfully', {
      count: projects.length,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: projects.length,
      data: {
        projects
      }
    });
  });

  /**
   * Add deliverable to project
   * POST /api/v1/projects/:id/deliverables
   */
  static addDeliverable = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user, files } = req;

    logger.debug('Adding deliverable to project', {
      projectId: id,
      deliverableName: body.name,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Add deliverable denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to add deliverables', 403));
    }

    // Handle file uploads
    if (files?.attachments) {
      body.attachments = await Promise.all(
        files.attachments.map(async file => ({
          name: file.originalname,
          url: await uploadToS3(file, 'project-deliverables'),
          size: file.size,
          uploadedAt: new Date()
        }))
      );
    }

    project.deliverables.push(body);
    project.updatedBy = user._id;
    await project.save();

    const deliverable = project.deliverables[project.deliverables.length - 1];

    logger.info('Deliverable added successfully', {
      projectId: id,
      deliverableId: deliverable._id,
      deliverableName: deliverable.name,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        deliverable
      }
    });
  });

  /**
   * Update deliverable
   * PATCH /api/v1/projects/:id/deliverables/:deliverableId
   */
  static updateDeliverable = catchAsync(async (req, res, next) => {
    const { id, deliverableId } = req.params;
    const { body, user, files } = req;

    logger.debug('Updating project deliverable', {
      projectId: id,
      deliverableId,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Update deliverable denied - insufficient permissions', {
        projectId: id,
        deliverableId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to update deliverables', 403));
    }

    const deliverable = project.deliverables.id(deliverableId);
    if (!deliverable) {
      return next(new AppError('Deliverable not found', 404));
    }

    // Handle status changes
    if (body.status === 'submitted' && deliverable.status !== 'submitted') {
      body.submittedDate = new Date();
    }

    // Handle new file uploads
    if (files?.attachments) {
      const newAttachments = await Promise.all(
        files.attachments.map(async file => ({
          name: file.originalname,
          url: await uploadToS3(file, 'project-deliverables'),
          size: file.size,
          uploadedAt: new Date()
        }))
      );
      deliverable.attachments.push(...newAttachments);
    }

    Object.assign(deliverable, body);
    project.updatedBy = user._id;
    await project.save();

    logger.info('Deliverable updated successfully', {
      projectId: id,
      deliverableId,
      status: deliverable.status,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        deliverable
      }
    });
  });

  /**
   * Add communication log
   * POST /api/v1/projects/:id/communications
   */
  static addCommunicationLog = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user, files } = req;

    logger.debug('Adding communication log to project', {
      projectId: id,
      type: body.type,
      subject: body.subject,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id, { includeLogs: true });
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Add communication log denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to add communication logs', 403));
    }

    // Handle attachments
    if (files?.attachments) {
      body.attachments = await Promise.all(
        files.attachments.map(async file => ({
          name: file.originalname,
          url: await uploadToS3(file, 'project-communications'),
          type: file.mimetype
        }))
      );
    }

    body.recordedBy = user._id;
    project.communication.logs.push(body);
    project.updatedBy = user._id;
    await project.save();

    const log = project.communication.logs[project.communication.logs.length - 1];

    logger.info('Communication log added successfully', {
      projectId: id,
      logId: log._id,
      type: log.type,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        communicationLog: log
      }
    });
  });

  /**
   * Add lesson learned
   * POST /api/v1/projects/:id/lessons-learned
   */
  static addLessonLearned = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user } = req;

    logger.debug('Adding lesson learned to project', {
      projectId: id,
      category: body.category,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Add lesson learned denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to add lessons learned', 403));
    }

    body.addedBy = user._id;
    body.addedAt = new Date();

    project.knowledge.lessonsLearned.push(body);
    project.updatedBy = user._id;
    await project.save();

    const lesson = project.knowledge.lessonsLearned[project.knowledge.lessonsLearned.length - 1];

    logger.info('Lesson learned added successfully', {
      projectId: id,
      lessonId: lesson._id,
      category: lesson.category,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        lessonLearned: lesson
      }
    });
  });

  /**
   * Export project data
   * GET /api/v1/projects/:id/export
   */
  static exportProject = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { format = 'json', sections } = req.query;
    const { user } = req;

    logger.info('Exporting project data', {
      projectId: id,
      format,
      sections,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id, { 
      includeLogs: true, 
      includeFinancialDetails: true 
    });
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Project export denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to export this project', 403));
    }

    // Filter sections based on permissions
    const allowedSections = sections ? sections.split(',') : ['all'];
    if (user.role !== 'admin' && user._id.toString() !== project.team.projectManager.toString()) {
      // Remove financial sections for non-managers
      const financialSections = ['financial', 'budget', 'costs', 'revenue'];
      allowedSections.filter(section => !financialSections.includes(section));
    }

    const exportData = await ProjectService.exportProject(id, {
      format,
      sections: allowedSections
    });

    logger.info('Project exported successfully', {
      projectId: id,
      format,
      userId: user._id
    });

    if (format === 'pdf') {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=project-${project.code}-export.pdf`);
      return res.send(exportData);
    } else if (format === 'xlsx') {
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.setHeader('Content-Disposition', `attachment; filename=project-${project.code}-export.xlsx`);
      return res.send(exportData);
    }

    res.status(200).json({
      status: 'success',
      data: exportData
    });
  });

  /**
   * Get projects by client
   * GET /api/v1/projects/by-client/:clientId
   */
  static getProjectsByClient = catchAsync(async (req, res, next) => {
    const { clientId } = req.params;
    const { status, dateRange } = req.query;
    const { user } = req;

    logger.debug('Fetching projects by client', {
      clientId,
      status,
      userId: user._id
    });

    const options = {
      status: status ? status.split(',') : undefined,
      dateRange: dateRange ? JSON.parse(dateRange) : undefined
    };

    const Project = require('../models/project-model');
    const projects = await Project.findByClient(clientId, options);

    // Filter based on user permissions
    const accessibleProjects = user.role === 'admin' ? projects :
      projects.filter(p => p.canBeAccessedBy(user._id, user.role));

    logger.debug('Projects by client fetched successfully', {
      clientId,
      totalProjects: projects.length,
      accessibleProjects: accessibleProjects.length,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: accessibleProjects.length,
      data: {
        projects: accessibleProjects
      }
    });
  });

  /**
   * Get active projects
   * GET /api/v1/projects/active
   */
  static getActiveProjects = catchAsync(async (req, res, next) => {
    const { projectManager, client, priority } = req.query;
    const { user } = req;

    logger.debug('Fetching active projects', {
      filters: { projectManager, client, priority },
      userId: user._id
    });

    const filters = {
      projectManager: projectManager || (user.role !== 'admin' ? user._id : undefined),
      client,
      priority
    };

    const Project = require('../models/project-model');
    const projects = await Project.findActiveProjects(filters);

    logger.debug('Active projects fetched successfully', {
      count: projects.length,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      results: projects.length,
      data: {
        projects
      }
    });
  });

  /**
   * Add milestone
   * POST /api/v1/projects/:id/milestones
   */
  static addMilestone = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const { body, user } = req;

    logger.debug('Adding milestone to project', {
      projectId: id,
      milestoneName: body.name,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (!project.canBeAccessedBy(user._id, user.role)) {
      logger.warn('Add milestone denied - insufficient permissions', {
        projectId: id,
        userId: user._id
      });
      return next(new AppError('You do not have permission to add milestones', 403));
    }

    project.milestones.push(body);
    project.updatedBy = user._id;
    await project.save();

    const milestone = project.milestones[project.milestones.length - 1];

    logger.info('Milestone added successfully', {
      projectId: id,
      milestoneId: milestone._id,
      milestoneName: milestone.name,
      userId: user._id
    });

    res.status(201).json({
      status: 'success',
      data: {
        milestone
      }
    });
  });

  /**
   * Update team member
   * PATCH /api/v1/projects/:id/team/:memberId
   */
  static updateTeamMember = catchAsync(async (req, res, next) => {
    const { id, memberId } = req.params;
    const { body, user } = req;

    logger.debug('Updating team member', {
      projectId: id,
      memberId,
      userId: user._id
    });

    const project = await ProjectService.getProjectById(id);
    
    if (user.role !== 'admin' && user.role !== 'manager' &&
        project.team.projectManager.toString() !== user._id.toString()) {
      logger.warn('Update team member denied - insufficient permissions', {
        projectId: id,
        memberId,
        userId: user._id
      });
      return next(new AppError('You do not have permission to update team members', 403));
    }

    const member = project.team.members.id(memberId);
    if (!member) {
      return next(new AppError('Team member not found', 404));
    }

    Object.assign(member, body);
    project.updatedBy = user._id;
    await project.save();

    logger.info('Team member updated successfully', {
      projectId: id,
      memberId,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: {
        member
      }
    });
  });

  /**
   * Bulk update projects
   * PATCH /api/v1/projects/bulk
   */
  static bulkUpdateProjects = catchAsync(async (req, res, next) => {
    const { projectIds, updateData } = req.body;
    const { user } = req;

    logger.info('Bulk updating projects', {
      projectIds,
      count: projectIds?.length,
      updateFields: Object.keys(updateData || {}),
      userId: user._id
    });

    if (!Array.isArray(projectIds) || projectIds.length === 0) {
      return next(new AppError('Project IDs array is required', 400));
    }

    if (!updateData || Object.keys(updateData).length === 0) {
      return next(new AppError('Update data is required', 400));
    }

    const results = {
      successful: 0,
      failed: 0,
      errors: []
    };

    for (const projectId of projectIds) {
      try {
        await ProjectService.updateProject(projectId, updateData, user._id);
        results.successful++;
      } catch (error) {
        results.failed++;
        results.errors.push({
          projectId,
          error: error.message
        });
      }
    }

    logger.info('Bulk update completed', {
      ...results,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: results
    });
  });

  /**
   * Import projects
   * POST /api/v1/projects/import
   */
  static importProjects = catchAsync(async (req, res, next) => {
    const { projects } = req.body;
    const { user, file } = req;

    logger.info('Importing projects', {
      source: file ? 'file' : 'data',
      count: projects?.length || 0,
      userId: user._id
    });

    let projectsData = projects;

    // Handle file upload
    if (file) {
      // Parse file based on format (CSV, XLSX, etc.)
      // projectsData = await parseProjectFile(file);
      return next(new AppError('File import not yet implemented', 501));
    }

    if (!Array.isArray(projectsData) || projectsData.length === 0) {
      return next(new AppError('No valid project data provided', 400));
    }

    const results = {
      total: projectsData.length,
      successful: 0,
      failed: 0,
      created: [],
      errors: []
    };

    for (const [index, projectData] of projectsData.entries()) {
      try {
        const project = await ProjectService.createProject(projectData, user._id);
        results.successful++;
        results.created.push({
          projectId: project._id,
          projectCode: project.code,
          projectName: project.name
        });
      } catch (error) {
        results.failed++;
        results.errors.push({
          row: index + 1,
          project: projectData.name || 'Unknown',
          error: error.message
        });
      }
    }

    logger.info('Project import completed', {
      ...results,
      userId: user._id
    });

    res.status(200).json({
      status: 'success',
      data: results
    });
  });

  /**
   * Export project data (helper method for service)
   * @private
   */
  static async exportProject(projectId, options) {
    // This would be implemented in the service layer
    // For now, returning a placeholder
    return {
      projectId,
      format: options.format,
      sections: options.sections,
      exportedAt: new Date()
    };
  }
}

module.exports = ProjectController;