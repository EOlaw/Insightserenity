/**
 * @file Project Service Layer
 * @description Business logic layer for advanced project management
 * @version 2.0.0
 */

const Project = require('../models/project-model');
const Client = require('../../clients/models/client-model');
const { AppError } = require('../../shared/utils/app-error');
const logger = require('../../shared/utils/logger');
const mongoose = require('mongoose');
const { sendEmail } = require('../../shared/services/email-service');
const { generatePDF } = require('../../shared/utils/pdf-generator');
const { uploadToS3 } = require('../../shared/utils/file-upload');
const NotificationService = require('../../shared/services/notification-service');

class ProjectService {
  /**
   * Create a new project with comprehensive validation
   * @param {Object} projectData - The project data
   * @param {string} userId - The ID of the user creating the project
   * @returns {Promise<Object>} - The created project
   */
  static async createProject(projectData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.debug('Starting project creation process', {
        projectName: projectData.name,
        clientId: projectData.client,
        userId,
        projectType: projectData.type
      });

      // Validate client exists and is active
      const client = await Client.findById(projectData.client).session(session);
      if (!client) {
        throw new AppError('Client not found', 404);
      }
      if (!client.status.isActive) {
        throw new AppError('Cannot create project for inactive client', 400);
      }

      // Validate project manager exists
      if (!projectData.team?.projectManager) {
        projectData.team = { ...projectData.team, projectManager: userId };
      }

      // Set creator
      projectData.createdBy = userId;
      projectData.updatedBy = userId;

      // Calculate budget breakdown if not provided
      if (projectData.financial?.budget?.total?.amount && !projectData.financial.budget.breakdown?.length) {
        projectData.financial.budget.breakdown = this.generateDefaultBudgetBreakdown(
          projectData.financial.budget.total.amount,
          projectData.type
        );
      }

      // Generate initial milestones if not provided
      if (!projectData.milestones || projectData.milestones.length === 0) {
        projectData.milestones = this.generateDefaultMilestones(
          projectData.timeline.estimatedStartDate,
          projectData.timeline.estimatedEndDate,
          projectData.type
        );
      }

      // Create project within transaction
      const [project] = await Project.create([projectData], { session });

      // Update client project stats
      await Client.findByIdAndUpdate(
        projectData.client,
        {
          $inc: { 
            'projectStats.totalProjects': 1,
            'projectStats.activeProjects': projectData.status === 'active' ? 1 : 0
          },
          'relationship.lastActivityDate': new Date()
        },
        { session }
      );

      // Create project folder structure in document management system
      await this.createProjectFolderStructure(project._id, project.projectId);

      // Send notifications
      await this.sendProjectCreationNotifications(project, client);

      // Populate references for response
      await project.populate([
        { path: 'client', select: 'name code industry' },
        { path: 'team.projectManager', select: 'firstName lastName email' },
        { path: 'createdBy', select: 'firstName lastName email' }
      ]);

      await session.commitTransaction();
      
      logger.info('Project created successfully', {
        projectId: project._id,
        projectCode: project.code,
        projectName: project.name,
        clientName: client.name,
        userId
      });

      // Trigger async post-creation tasks
      this.performPostCreationTasks(project._id).catch(err => {
        logger.error('Post-creation tasks failed', { 
          projectId: project._id, 
          error: err.message 
        });
      });

      return project;
    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Project creation failed', {
        projectName: projectData.name,
        clientId: projectData.client,
        userId,
        error: error.message,
        stack: error.stack
      });
      
      if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        throw new AppError(`A project with this ${field} already exists`, 400);
      }
      
      throw error instanceof AppError ? error : 
            new AppError(`Failed to create project: ${error.message}`, 400);
    } finally {
      session.endSession();
    }
  }

  /**
   * Get all projects with advanced filtering
   * @param {Object} filter - Filter criteria
   * @param {Object} options - Query options
   * @returns {Promise<Object>} - Projects with pagination
   */
  static async getAllProjects(filter = {}, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'createdAt',
        sortOrder = 'desc',
        search,
        status,
        client,
        projectManager,
        type,
        priority,
        dateRange,
        budgetRange,
        tags,
        includeArchived = false,
        healthScoreMin,
        isDelayed,
        isOverBudget
      } = options;

      logger.debug('Fetching projects with filters', {
        filter,
        options: {
          page,
          limit,
          sortBy,
          search,
          status
        }
      });

      const skip = (page - 1) * limit;
      const queryFilter = { ...filter };

      // Archive filter
      if (!includeArchived) {
        queryFilter['archived.isArchived'] = { $ne: true };
      }

      // Basic filters
      if (status) {
        queryFilter.status = Array.isArray(status) ? { $in: status } : status;
      }
      if (client) queryFilter.client = client;
      if (projectManager) queryFilter['team.projectManager'] = projectManager;
      if (type) queryFilter.type = type;
      if (priority) queryFilter.priority = priority;

      // Date range filter
      if (dateRange?.start || dateRange?.end) {
        queryFilter['timeline.estimatedStartDate'] = {};
        if (dateRange.start) {
          queryFilter['timeline.estimatedStartDate'].$gte = new Date(dateRange.start);
        }
        if (dateRange.end) {
          queryFilter['timeline.estimatedStartDate'].$lte = new Date(dateRange.end);
        }
      }

      // Budget range filter
      if (budgetRange?.min || budgetRange?.max) {
        queryFilter['financial.budget.total.amount'] = {};
        if (budgetRange.min) {
          queryFilter['financial.budget.total.amount'].$gte = budgetRange.min;
        }
        if (budgetRange.max) {
          queryFilter['financial.budget.total.amount'].$lte = budgetRange.max;
        }
      }

      // Tags filter
      if (tags?.length) {
        queryFilter.tags = { $in: tags };
      }

      // Text search
      if (search) {
        queryFilter.$text = { $search: search };
      }

      // Build sort option
      const sortOption = {};
      if (search) {
        sortOption.score = { $meta: 'textScore' };
      }
      sortOption[sortBy] = sortOrder === 'asc' ? 1 : -1;

      // Execute main query
      let query = Project.find(queryFilter)
        .sort(sortOption)
        .skip(skip)
        .limit(parseInt(limit))
        .populate('client', 'name code industry relationship.tier')
        .populate('team.projectManager', 'firstName lastName email profile.avatar')
        .populate('contract', 'contractNumber value.total')
        .select('-communication.logs -changeLog -knowledge.lessonsLearned');

      // Get total count
      const total = await Project.countDocuments(queryFilter);

      // Execute query
      let projects = await query;

      // Post-query filters (for computed properties)
      if (healthScoreMin) {
        projects = projects.filter(p => p.healthScore >= healthScoreMin);
      }
      if (isDelayed !== undefined) {
        projects = projects.filter(p => p.isDelayed === isDelayed);
      }
      if (isOverBudget !== undefined) {
        projects = projects.filter(p => p.isOverBudget === isOverBudget);
      }

      // Get aggregated statistics
      const stats = await this.getProjectStatistics(queryFilter);

      logger.debug('Projects fetched successfully', {
        totalFound: total,
        pageSize: projects.length,
        page,
        hasFilters: Object.keys(queryFilter).length > 0
      });

      return {
        projects,
        pagination: {
          total,
          page: parseInt(page),
          limit: parseInt(limit),
          pages: Math.ceil(total / limit),
          hasMore: page < Math.ceil(total / limit)
        },
        stats
      };
    } catch (error) {
      logger.error('Failed to fetch projects', {
        filter,
        options,
        error: error.message
      });
      throw new AppError(`Failed to fetch projects: ${error.message}`, 500);
    }
  }

  /**
   * Get project by ID with full details
   * @param {string} projectId - The project ID
   * @param {Object} options - Additional options
   * @returns {Promise<Object>} - The project
   */
  static async getProjectById(projectId, options = {}) {
    try {
      const { 
        includeLogs = false,
        includeFinancialDetails = true 
      } = options;

      logger.debug('Fetching project by ID', {
        projectId,
        includeLogs,
        includeFinancialDetails
      });

      let query = Project.findById(projectId);

      // Conditional field exclusion
      if (!includeLogs) {
        query = query.select('-communication.logs -changeLog');
      }
      if (!includeFinancialDetails) {
        query = query.select('-financial.costs -financial.revenue');
      }

      const project = await query
        .populate('client', 'name code industry addresses.headquarters contacts.main')
        .populate('team.projectManager', 'firstName lastName email profile')
        .populate('team.members.consultant', 'firstName lastName email profile.title profile.skills')
        .populate('contract', 'contractNumber type value terms')
        .populate('proposal', 'proposalNumber status value')
        .populate('createdBy', 'firstName lastName email')
        .populate('updatedBy', 'firstName lastName email');

      if (!project) {
        logger.warn('Project not found', { projectId });
        throw new AppError('Project not found', 404);
      }

      logger.debug('Project fetched successfully', {
        projectId: project._id,
        projectCode: project.code,
        projectName: project.name
      });

      return project;
    } catch (error) {
      if (error instanceof AppError) throw error;
      if (error.name === 'CastError') {
        logger.warn('Invalid project ID format', { projectId });
        throw new AppError('Invalid project ID', 400);
      }
      logger.error('Failed to fetch project by ID', {
        projectId,
        error: error.message
      });
      throw new AppError(`Failed to fetch project: ${error.message}`, 500);
    }
  }

  /**
   * Update project with validation
   * @param {string} projectId - The project ID
   * @param {Object} updateData - The update data
   * @param {string} userId - The ID of the user updating
   * @returns {Promise<Object>} - The updated project
   */
  static async updateProject(projectId, updateData, userId) {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      logger.debug('Updating project', {
        projectId,
        userId,
        updateFields: Object.keys(updateData)
      });

      // Get current project
      const currentProject = await Project.findById(projectId).session(session);
      if (!currentProject) {
        throw new AppError('Project not found', 404);
      }

      // Check if update requires change request
      const requiresChangeRequest = this.requiresChangeRequest(currentProject, updateData);
      if (requiresChangeRequest && !updateData.changeRequestId) {
        throw new AppError('This update requires an approved change request', 400);
      }

      // Set updater
      updateData.updatedBy = userId;

      // Don't allow direct modification of certain fields
      delete updateData.projectId;
      delete updateData.createdBy;
      delete updateData.healthScore;

      // Handle status transitions
      if (updateData.status && updateData.status !== currentProject.status) {
        await this.validateStatusTransition(currentProject.status, updateData.status);
        
        // Add to phase history if moving to new phase
        const phaseMap = {
          'approved': 'planning',
          'active': 'execution',
          'completed': 'closure'
        };
        
        if (phaseMap[updateData.status]) {
          if (!updateData.phase) updateData.phase = {};
          updateData.phase.current = phaseMap[updateData.status];
          
          currentProject.phase.history.push({
            phase: currentProject.phase.current,
            startDate: currentProject.phase.history.length > 0 ? 
              currentProject.phase.history[currentProject.phase.history.length - 1].endDate : 
              currentProject.createdAt,
            endDate: new Date(),
            completedBy: userId
          });
        }
      }

      // Update project
      const project = await Project.findByIdAndUpdate(
        projectId,
        updateData,
        { 
          new: true, 
          runValidators: true,
          session
        }
      );

      // Log significant changes
      const significantChanges = this.detectSignificantChanges(currentProject, project);
      if (significantChanges.length > 0) {
        for (const change of significantChanges) {
          project.changeLog.push({
            type: change.type,
            description: change.description,
            oldValue: change.oldValue,
            newValue: change.newValue,
            changedBy: userId,
            impact: change.impact
          });
        }
        await project.save({ session });
      }

      await project.populate([
        { path: 'client', select: 'name code' },
        { path: 'team.projectManager', select: 'firstName lastName email' },
        { path: 'updatedBy', select: 'firstName lastName email' }
      ]);

      await session.commitTransaction();
      
      logger.info('Project updated successfully', {
        projectId: project._id,
        projectCode: project.code,
        userId,
        changesCount: significantChanges.length
      });

      // Send notifications for significant changes
      if (significantChanges.length > 0) {
        await this.notifyProjectChanges(project, significantChanges);
      }

      return project;
    } catch (error) {
      await session.abortTransaction();
      
      logger.error('Project update failed', {
        projectId,
        userId,
        error: error.message
      });
      
      if (error instanceof AppError) throw error;
      throw new AppError(`Failed to update project: ${error.message}`, 500);
    } finally {
      session.endSession();
    }
  }

  /**
   * Update project status
   * @param {string} projectId - The project ID
   * @param {string} status - New status
   * @param {string} userId - User making the change
   * @param {Object} additionalData - Additional data for status change
   * @returns {Promise<Object>} - Updated project
   */
  static async updateProjectStatus(projectId, status, userId, additionalData = {}) {
    try {
      logger.debug('Updating project status', {
        projectId,
        newStatus: status,
        userId
      });

      const project = await Project.findById(projectId);
      if (!project) {
        throw new AppError('Project not found', 404);
      }

      const oldStatus = project.status;
      
      // Validate status transition
      await this.validateStatusTransition(oldStatus, status);

      // Apply status-specific logic
      const updateData = { 
        status, 
        updatedBy: userId,
        ...this.getStatusUpdateData(status, additionalData)
      };

      // Update project
      await project.updateOne(updateData);
      
      // Reload project
      const updatedProject = await Project.findById(projectId)
        .populate('client', 'name code')
        .populate('team.projectManager', 'firstName lastName email');

      // Update client stats if needed
      if (status === 'active' && oldStatus !== 'active') {
        await Client.findByIdAndUpdate(project.client, {
          $inc: { 'projectStats.activeProjects': 1 }
        });
      } else if (status === 'completed' && oldStatus === 'active') {
        await Client.findByIdAndUpdate(project.client, {
          $inc: { 
            'projectStats.activeProjects': -1,
            'projectStats.completedProjects': 1
          }
        });
      }

      logger.info('Project status updated successfully', {
        projectId: project._id,
        projectCode: project.code,
        oldStatus,
        newStatus: status,
        userId
      });

      // Send notifications
      await this.notifyStatusChange(updatedProject, oldStatus, status);

      return updatedProject;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to update project status', {
        projectId,
        status,
        userId,
        error: error.message
      });
      throw new AppError(`Failed to update project status: ${error.message}`, 500);
    }
  }

  /**
   * Add team member to project
   * @param {string} projectId - The project ID
   * @param {Object} memberData - Team member data
   * @param {string} userId - User adding the member
   * @returns {Promise<Object>} - Updated project
   */
  static async addTeamMember(projectId, memberData, userId) {
    try {
      logger.debug('Adding team member to project', {
        projectId,
        consultantId: memberData.consultant,
        role: memberData.role,
        userId
      });

      const project = await Project.findById(projectId);
      if (!project) {
        throw new AppError('Project not found', 404);
      }

      // Check consultant availability
      const availability = await this.checkConsultantAvailability(
        memberData.consultant,
        memberData.allocation.startDate,
        memberData.allocation.endDate,
        memberData.allocation.percentage
      );

      if (!availability.isAvailable) {
        throw new AppError(`Consultant is not available: ${availability.reason}`, 400);
      }

      // Add team member
      await project.addTeamMember(memberData);

      logger.info('Team member added successfully', {
        projectId,
        consultantId: memberData.consultant,
        role: memberData.role,
        allocation: memberData.allocation.percentage
      });

      // Send notification to consultant
      await NotificationService.sendNotification({
        type: 'project_assignment',
        recipient: memberData.consultant,
        data: {
          projectId: project._id,
          projectName: project.name,
          role: memberData.role,
          startDate: memberData.allocation.startDate
        }
      });

      return project;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to add team member', {
        projectId,
        memberData,
        error: error.message
      });
      throw new AppError(`Failed to add team member: ${error.message}`, 500);
    }
  }

  /**
   * Update milestone
   * @param {string} projectId - The project ID
   * @param {string} milestoneId - The milestone ID
   * @param {Object} updateData - Update data
   * @param {string} userId - User making the update
   * @returns {Promise<Object>} - Updated project
   */
  static async updateMilestone(projectId, milestoneId, updateData, userId) {
    try {
      logger.debug('Updating milestone', {
        projectId,
        milestoneId,
        userId,
        updateFields: Object.keys(updateData)
      });

      const project = await Project.findById(projectId);
      if (!project) {
        throw new AppError('Project not found', 404);
      }

      const milestone = project.milestones.id(milestoneId);
      if (!milestone) {
        throw new AppError('Milestone not found', 404);
      }

      // Update milestone fields
      Object.assign(milestone, updateData);

      // Handle status changes
      if (updateData.status === 'completed' && milestone.status !== 'completed') {
        milestone.actualDate = new Date();
        milestone.completion = 100;

        // Check if this triggers payment milestone
        if (milestone.type === 'payment' && milestone.payment?.amount) {
          await this.createPaymentInvoice(project, milestone);
        }
      }

      // Check dependencies
      if (updateData.status === 'completed') {
        await this.checkAndUpdateDependentMilestones(project, milestoneId);
      }

      project.updatedBy = userId;
      await project.save();

      logger.info('Milestone updated successfully', {
        projectId,
        milestoneId,
        milestoneName: milestone.name,
        status: milestone.status
      });

      // Notify stakeholders if milestone is delayed
      if (milestone.status === 'delayed' || 
          (milestone.plannedDate < new Date() && milestone.status !== 'completed')) {
        await this.notifyMilestoneDelay(project, milestone);
      }

      return project;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to update milestone', {
        projectId,
        milestoneId,
        error: error.message
      });
      throw new AppError(`Failed to update milestone: ${error.message}`, 500);
    }
  }

  /**
   * Add risk to project
   * @param {string} projectId - The project ID
   * @param {Object} riskData - Risk data
   * @param {string} userId - User adding the risk
   * @returns {Promise<Object>} - Updated project
   */
  static async addRisk(projectId, riskData, userId) {
    try {
      logger.debug('Adding risk to project', {
        projectId,
        riskTitle: riskData.title,
        category: riskData.category,
        userId
      });

      const project = await Project.findById(projectId);
      if (!project) {
        throw new AppError('Project not found', 404);
      }

      // Set identifier
      riskData.identifiedBy = userId;
      riskData.identifiedAt = new Date();

      // Calculate risk score
      const probabilityMap = { very_low: 1, low: 2, medium: 3, high: 4, very_high: 5 };
      const impactMap = { negligible: 1, minor: 2, moderate: 3, major: 4, severe: 5 };
      riskData.riskScore = probabilityMap[riskData.probability] * impactMap[riskData.impact];

      project.risks.push(riskData);
      project.updatedBy = userId;
      await project.save();

      logger.info('Risk added successfully', {
        projectId,
        riskTitle: riskData.title,
        riskScore: riskData.riskScore
      });

      // Notify if high risk
      if (riskData.riskScore >= 16) {
        await this.notifyHighRisk(project, riskData);
      }

      return project;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to add risk', {
        projectId,
        riskData,
        error: error.message
      });
      throw new AppError(`Failed to add risk: ${error.message}`, 500);
    }
  }

  /**
   * Create change request
   * @param {string} projectId - The project ID
   * @param {Object} changeRequestData - Change request data
   * @param {string} userId - User creating the request
   * @returns {Promise<Object>} - Updated project
   */
  static async createChangeRequest(projectId, changeRequestData, userId) {
    try {
      logger.debug('Creating change request', {
        projectId,
        changeType: changeRequestData.type,
        userId
      });

      const project = await Project.findById(projectId);
      if (!project) {
        throw new AppError('Project not found', 404);
      }

      // Set requester
      changeRequestData.requestedBy = userId;
      changeRequestData.requestedAt = new Date();

      // Add default reviewers based on impact
      if (!changeRequestData.reviewers || changeRequestData.reviewers.length === 0) {
        changeRequestData.reviewers = await this.getDefaultChangeRequestReviewers(
          project,
          changeRequestData
        );
      }

      project.changeRequests.push(changeRequestData);
      project.updatedBy = userId;
      await project.save();

      const changeRequest = project.changeRequests[project.changeRequests.length - 1];

      logger.info('Change request created successfully', {
        projectId,
        changeRequestId: changeRequest._id,
        requestNumber: changeRequest.requestNumber
      });

      // Notify reviewers
      await this.notifyChangeRequestReviewers(project, changeRequest);

      return changeRequest;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to create change request', {
        projectId,
        changeRequestData,
        error: error.message
      });
      throw new AppError(`Failed to create change request: ${error.message}`, 500);
    }
  }

  /**
   * Generate project status report
   * @param {string} projectId - The project ID
   * @param {Object} options - Report options
   * @returns {Promise<Object>} - Status report
   */
  static async generateStatusReport(projectId, options = {}) {
    try {
      const { format = 'json', includeFinancials = true } = options;

      logger.debug('Generating project status report', {
        projectId,
        format,
        includeFinancials
      });

      const project = await Project.findById(projectId)
        .populate('client', 'name code')
        .populate('team.projectManager', 'firstName lastName email')
        .populate('team.members.consultant', 'firstName lastName');

      if (!project) {
        throw new AppError('Project not found', 404);
      }

      const report = project.generateStatusReport();

      // Add additional details
      report.client = {
        name: project.client.name,
        code: project.client.code
      };

      report.team = {
        projectManager: project.team.projectManager,
        totalMembers: project.team.members.length,
        activeMembers: project.team.members.filter(m => 
          m.approvalStatus === 'approved' &&
          (!m.allocation.endDate || m.allocation.endDate > new Date())
        ).length
      };

      if (includeFinancials) {
        report.financial = {
          revenue: project.financial.revenue,
          profitability: project.financial.profitability,
          invoicing: {
            total: project.financial.revenue.invoiced,
            outstanding: project.financial.revenue.outstanding
          }
        };
      }

      // Recent activities
      report.recentActivities = await this.getRecentProjectActivities(projectId);

      if (format === 'pdf') {
        const pdfBuffer = await generatePDF({
          template: 'project-status-report',
          data: report
        });

        return {
          report,
          pdf: pdfBuffer
        };
      }

      logger.info('Status report generated successfully', {
        projectId,
        projectCode: project.code
      });

      return report;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to generate status report', {
        projectId,
        error: error.message
      });
      throw new AppError(`Failed to generate status report: ${error.message}`, 500);
    }
  }

  /**
   * Get project dashboard data
   * @param {string} projectId - The project ID
   * @returns {Promise<Object>} - Dashboard data
   */
  static async getProjectDashboard(projectId) {
    try {
      logger.debug('Fetching project dashboard data', { projectId });

      const project = await Project.findById(projectId)
        .populate('client', 'name code logo')
        .populate('team.projectManager', 'firstName lastName email profile.avatar')
        .populate('team.members.consultant', 'firstName lastName profile.avatar');

      if (!project) {
        throw new AppError('Project not found', 404);
      }

      const dashboard = {
        overview: {
          projectId: project.projectId,
          name: project.name,
          code: project.code,
          client: project.client,
          status: project.status,
          health: project.healthScore,
          progress: project.progress,
          daysRemaining: Math.ceil(
            (project.timeline.estimatedEndDate - new Date()) / (1000 * 60 * 60 * 24)
          )
        },
        timeline: {
          start: project.timeline.actualStartDate || project.timeline.estimatedStartDate,
          end: project.timeline.estimatedEndDate,
          duration: project.duration,
          isDelayed: project.isDelayed,
          extensions: project.timeline.extensions.length
        },
        budget: {
          total: project.financial.budget.total,
          spent: project.financial.costs.total,
          remaining: project.financial.budget.total.amount - project.financial.costs.total,
          utilization: project.budgetUtilization,
          isOverBudget: project.isOverBudget
        },
        team: {
          projectManager: project.team.projectManager,
          totalMembers: project.team.members.length,
          activeMembers: project.team.members.filter(m => 
            m.approvalStatus === 'approved' &&
            (!m.allocation.endDate || m.allocation.endDate > new Date())
          ),
          utilization: project.calculateResourceUtilization()
        },
        milestones: {
          total: project.milestones.length,
          completed: project.milestones.filter(m => m.status === 'completed').length,
          inProgress: project.milestones.filter(m => m.status === 'in_progress').length,
          upcoming: project.milestones
            .filter(m => m.status === 'pending' && m.plannedDate <= new Date(Date.now() + 30 * 24 * 60 * 60 * 1000))
            .sort((a, b) => a.plannedDate - b.plannedDate)
            .slice(0, 5)
        },
        risks: {
          total: project.risks.filter(r => r.status !== 'closed').length,
          byPriority: {
            critical: project.risks.filter(r => r.status !== 'closed' && r.riskScore >= 20).length,
            high: project.risks.filter(r => r.status !== 'closed' && r.riskScore >= 12 && r.riskScore < 20).length,
            medium: project.risks.filter(r => r.status !== 'closed' && r.riskScore >= 6 && r.riskScore < 12).length,
            low: project.risks.filter(r => r.status !== 'closed' && r.riskScore < 6).length
          },
          topRisks: project.risks
            .filter(r => r.status !== 'closed')
            .sort((a, b) => b.riskScore - a.riskScore)
            .slice(0, 5)
        },
        issues: {
          total: project.issues.filter(i => i.status !== 'closed').length,
          bySeverity: {
            critical: project.issues.filter(i => i.status !== 'closed' && i.severity === 'critical').length,
            high: project.issues.filter(i => i.status !== 'closed' && i.severity === 'high').length,
            medium: project.issues.filter(i => i.status !== 'closed' && i.severity === 'medium').length,
            low: project.issues.filter(i => i.status !== 'closed' && i.severity === 'low').length
          },
          recentIssues: project.issues
            .sort((a, b) => b.reportedAt - a.reportedAt)
            .slice(0, 5)
        },
        deliverables: {
          total: project.deliverables.length,
          completed: project.deliverables.filter(d => d.status === 'approved').length,
          inProgress: project.deliverables.filter(d => d.status === 'in_progress').length,
          pending: project.deliverables.filter(d => d.status === 'pending').length,
          overdue: project.deliverables.filter(d => 
            d.status !== 'approved' && d.dueDate < new Date()
          ).length
        },
        activities: await this.getRecentProjectActivities(projectId, 10),
        quality: project.quality.metrics
      };

      logger.debug('Project dashboard data fetched successfully', {
        projectId,
        healthScore: dashboard.overview.health
      });

      return dashboard;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to fetch project dashboard', {
        projectId,
        error: error.message
      });
      throw new AppError(`Failed to fetch project dashboard: ${error.message}`, 500);
    }
  }

  /**
   * Archive project
   * @param {string} projectId - The project ID
   * @param {string} reason - Archive reason
   * @param {string} userId - User archiving the project
   * @returns {Promise<Object>} - Archived project
   */
  static async archiveProject(projectId, reason, userId) {
    try {
      logger.info('Archiving project', {
        projectId,
        reason,
        userId
      });

      const project = await Project.findById(projectId);
      if (!project) {
        throw new AppError('Project not found', 404);
      }

      if (project.status === 'active') {
        throw new AppError('Cannot archive active project. Please complete or cancel it first.', 400);
      }

      project.archived = {
        isArchived: true,
        archivedAt: new Date(),
        archivedBy: userId,
        archiveReason: reason
      };

      project.updatedBy = userId;
      await project.save();

      logger.info('Project archived successfully', {
        projectId: project._id,
        projectCode: project.code,
        userId
      });

      return project;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to archive project', {
        projectId,
        error: error.message
      });
      throw new AppError(`Failed to archive project: ${error.message}`, 500);
    }
  }

  /**
   * Get project statistics
   * @param {Object} filter - Filter criteria
   * @returns {Promise<Object>} - Statistics
   */
  static async getProjectStatistics(filter = {}) {
    try {
      const stats = await Project.aggregate([
        { $match: filter },
        {
          $group: {
            _id: null,
            totalProjects: { $sum: 1 },
            totalBudget: { $sum: '$financial.budget.total.amount' },
            totalRevenue: { $sum: '$financial.revenue.recognized' },
            totalCosts: { $sum: '$financial.costs.total' },
            avgHealthScore: { $avg: '$healthScore' },
            byStatus: {
              $push: {
                status: '$status',
                priority: '$priority'
              }
            },
            byType: { $push: '$type' }
          }
        },
        {
          $project: {
            totalProjects: 1,
            totalBudget: 1,
            totalRevenue: 1,
            totalCosts: 1,
            avgHealthScore: { $round: ['$avgHealthScore', 2] },
            statusBreakdown: {
              $arrayToObject: {
                $map: {
                  input: { $setUnion: ['$byStatus.status'] },
                  as: 'status',
                  in: {
                    k: '$$status',
                    v: {
                      $size: {
                        $filter: {
                          input: '$byStatus',
                          as: 'item',
                          cond: { $eq: ['$$item.status', '$$status'] }
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
        totalProjects: 0,
        totalBudget: 0,
        totalRevenue: 0,
        totalCosts: 0,
        avgHealthScore: 0,
        statusBreakdown: {}
      };
    } catch (error) {
      logger.error('Failed to get project statistics', {
        filter,
        error: error.message
      });
      throw new AppError(`Failed to get project statistics: ${error.message}`, 500);
    }
  }

  /**
   * Helper methods
   */

  /**
   * Generate default budget breakdown
   * @private
   */
  static generateDefaultBudgetBreakdown(totalAmount, projectType) {
    const breakdownPercentages = {
      strategy: { labor: 85, travel: 10, materials: 3, other: 2 },
      implementation: { labor: 70, travel: 5, materials: 20, other: 5 },
      transformation: { labor: 75, travel: 10, materials: 10, other: 5 },
      assessment: { labor: 90, travel: 5, materials: 3, other: 2 },
      training: { labor: 80, travel: 5, materials: 10, other: 5 },
      default: { labor: 80, travel: 5, materials: 10, other: 5 }
    };

    const percentages = breakdownPercentages[projectType] || breakdownPercentages.default;
    
    return Object.entries(percentages).map(([category, percentage]) => ({
      category,
      name: `${category.charAt(0).toUpperCase() + category.slice(1)} Budget`,
      plannedAmount: Math.round(totalAmount * percentage / 100),
      actualAmount: 0,
      unit: category === 'labor' ? 'hours' : 'fixed'
    }));
  }

  /**
   * Generate default milestones
   * @private
   */
  static generateDefaultMilestones(startDate, endDate, projectType) {
    const duration = Math.ceil((new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24));
    const milestones = [];

    // Kickoff milestone
    milestones.push({
      name: 'Project Kickoff',
      description: 'Initial project kickoff meeting and team onboarding',
      type: 'phase_completion',
      phase: 'initiation',
      plannedDate: startDate,
      status: 'pending'
    });

    // Mid-project milestone
    const midDate = new Date(startDate);
    midDate.setDate(midDate.getDate() + Math.floor(duration / 2));
    
    milestones.push({
      name: 'Mid-Project Review',
      description: 'Mid-project status review and assessment',
      type: 'review',
      phase: 'execution',
      plannedDate: midDate,
      status: 'pending'
    });

    // Final deliverable
    const finalDate = new Date(endDate);
    finalDate.setDate(finalDate.getDate() - 7);
    
    milestones.push({
      name: 'Final Deliverable',
      description: 'Submission of final project deliverables',
      type: 'deliverable',
      phase: 'closure',
      plannedDate: finalDate,
      status: 'pending'
    });

    // Project completion
    milestones.push({
      name: 'Project Completion',
      description: 'Project closure and handover',
      type: 'phase_completion',
      phase: 'closure',
      plannedDate: endDate,
      status: 'pending'
    });

    return milestones;
  }

  /**
   * Check if changes require a change request
   * @private
   */
  static requiresChangeRequest(currentProject, updateData) {
    const significantFields = [
      'financial.budget.total.amount',
      'timeline.estimatedEndDate',
      'description.scope'
    ];

    return significantFields.some(field => {
      const current = field.split('.').reduce((obj, key) => obj?.[key], currentProject);
      const updated = field.split('.').reduce((obj, key) => obj?.[key], updateData);
      
      return updated !== undefined && updated !== current;
    });
  }

  /**
   * Validate status transition
   * @private
   */
  static async validateStatusTransition(currentStatus, newStatus) {
    const validTransitions = {
      draft: ['pending_approval', 'cancelled'],
      pending_approval: ['approved', 'draft', 'cancelled'],
      approved: ['active', 'cancelled'],
      active: ['on_hold', 'completed', 'cancelled'],
      on_hold: ['active', 'cancelled'],
      completed: ['archived'],
      cancelled: ['archived']
    };

    if (!validTransitions[currentStatus]?.includes(newStatus)) {
      throw new AppError(
        `Invalid status transition from ${currentStatus} to ${newStatus}`,
        400
      );
    }
  }

  /**
   * Get status update data
   * @private
   */
  static getStatusUpdateData(status, additionalData) {
    const updateData = {};

    switch (status) {
      case 'active':
        if (!additionalData.actualStartDate) {
          updateData['timeline.actualStartDate'] = new Date();
        }
        updateData['phase.current'] = 'execution';
        break;
        
      case 'completed':
        updateData['timeline.actualEndDate'] = new Date();
        updateData['phase.current'] = 'closure';
        break;
        
      case 'on_hold':
        if (additionalData.holdReason) {
          updateData['changeLog'] = {
            $push: {
              type: 'status',
              description: `Project put on hold: ${additionalData.holdReason}`,
              date: new Date()
            }
          };
        }
        break;
        
      case 'cancelled':
        if (additionalData.cancellationReason) {
          updateData['changeLog'] = {
            $push: {
              type: 'status',
              description: `Project cancelled: ${additionalData.cancellationReason}`,
              date: new Date()
            }
          };
        }
        break;
    }

    return updateData;
  }

  /**
   * Detect significant changes
   * @private
   */
  static detectSignificantChanges(oldProject, newProject) {
    const changes = [];
    const significantFields = [
      { path: 'timeline.estimatedEndDate', type: 'timeline', description: 'Project end date changed' },
      { path: 'financial.budget.total.amount', type: 'budget', description: 'Project budget changed' },
      { path: 'team.projectManager', type: 'team', description: 'Project manager changed' },
      { path: 'priority', type: 'other', description: 'Project priority changed' }
    ];

    significantFields.forEach(field => {
      const oldValue = field.path.split('.').reduce((obj, key) => obj?.[key], oldProject);
      const newValue = field.path.split('.').reduce((obj, key) => obj?.[key], newProject);
      
      if (oldValue?.toString() !== newValue?.toString()) {
        changes.push({
          type: field.type,
          description: field.description,
          oldValue,
          newValue,
          impact: this.assessChangeImpact(field.path, oldValue, newValue)
        });
      }
    });

    return changes;
  }

  /**
   * Assess change impact
   * @private
   */
  static assessChangeImpact(field, oldValue, newValue) {
    if (field === 'financial.budget.total.amount') {
      const change = ((newValue - oldValue) / oldValue) * 100;
      return `Budget ${change > 0 ? 'increased' : 'decreased'} by ${Math.abs(change).toFixed(1)}%`;
    }
    
    if (field === 'timeline.estimatedEndDate') {
      const days = Math.ceil((new Date(newValue) - new Date(oldValue)) / (1000 * 60 * 60 * 24));
      return `Timeline ${days > 0 ? 'extended' : 'shortened'} by ${Math.abs(days)} days`;
    }
    
    return 'Change may impact project execution';
  }

  /**
   * Create project folder structure
   * @private
   */
  static async createProjectFolderStructure(projectId, projectCode) {
    try {
      const folders = [
        `projects/${projectCode}/documents`,
        `projects/${projectCode}/deliverables`,
        `projects/${projectCode}/communications`,
        `projects/${projectCode}/financial`,
        `projects/${projectCode}/reports`
      ];

      // Create folders in document management system
      // This would integrate with your DMS
      
      logger.debug('Project folder structure created', {
        projectId,
        projectCode,
        folders
      });
    } catch (error) {
      logger.error('Failed to create project folders', {
        projectId,
        error: error.message
      });
    }
  }

  /**
   * Check consultant availability
   * @private
   */
  static async checkConsultantAvailability(consultantId, startDate, endDate, allocationPercentage) {
    try {
      // Get all active project allocations for the consultant
      const allocations = await Project.aggregate([
        {
          $match: {
            status: { $in: ['active', 'approved'] },
            'team.members.consultant': consultantId
          }
        },
        { $unwind: '$team.members' },
        {
          $match: {
            'team.members.consultant': consultantId,
            'team.members.allocation.startDate': { $lte: endDate },
            $or: [
              { 'team.members.allocation.endDate': { $gte: startDate } },
              { 'team.members.allocation.endDate': null }
            ]
          }
        },
        {
          $group: {
            _id: null,
            totalAllocation: { $sum: '$team.members.allocation.percentage' }
          }
        }
      ]);

      const currentAllocation = allocations[0]?.totalAllocation || 0;
      const newTotalAllocation = currentAllocation + allocationPercentage;

      if (newTotalAllocation > 100) {
        return {
          isAvailable: false,
          reason: `Consultant would be allocated ${newTotalAllocation}% (current: ${currentAllocation}%)`
        };
      }

      return { isAvailable: true };
    } catch (error) {
      logger.error('Failed to check consultant availability', {
        consultantId,
        error: error.message
      });
      return {
        isAvailable: false,
        reason: 'Failed to verify availability'
      };
    }
  }

  /**
   * Get recent project activities
   * @private
   */
  static async getRecentProjectActivities(projectId, limit = 20) {
    try {
      // In a real implementation, this would aggregate from various sources:
      // - Change logs
      // - Communication logs
      // - Milestone updates
      // - Team changes
      // - Document uploads

      const project = await Project.findById(projectId)
        .select('changeLog milestones.status milestones.actualDate')
        .sort('-changeLog.date')
        .limit(limit);

      return project?.changeLog || [];
    } catch (error) {
      logger.error('Failed to get project activities', {
        projectId,
        error: error.message
      });
      return [];
    }
  }

  /**
   * Send project creation notifications
   * @private
   */
  static async sendProjectCreationNotifications(project, client) {
    try {
      const notifications = [
        // Notify project manager
        {
          type: 'project_assigned',
          recipient: project.team.projectManager,
          data: {
            projectId: project._id,
            projectName: project.name,
            clientName: client.name,
            role: 'Project Manager'
          }
        }
      ];

      // Notify client primary contact
      if (client.primaryContact) {
        await sendEmail({
          to: client.primaryContact.email,
          subject: `Project ${project.name} has been initiated`,
          template: 'project-initiated-client',
          data: {
            projectName: project.name,
            projectCode: project.code,
            contactName: `${client.primaryContact.firstName} ${client.primaryContact.lastName}`
          }
        });
      }

      await Promise.all(
        notifications.map(notification => 
          NotificationService.sendNotification(notification)
        )
      );
    } catch (error) {
      logger.error('Failed to send project creation notifications', {
        projectId: project._id,
        error: error.message
      });
    }
  }

  /**
   * Notify project changes
   * @private
   */
  static async notifyProjectChanges(project, changes) {
    try {
      const stakeholders = [
        project.team.projectManager,
        ...project.team.members.filter(m => m.approvalStatus === 'approved').map(m => m.consultant)
      ];

      await NotificationService.sendBulkNotification({
        type: 'project_updated',
        recipients: stakeholders,
        data: {
          projectId: project._id,
          projectName: project.name,
          changes: changes.map(c => c.description)
        }
      });
    } catch (error) {
      logger.error('Failed to notify project changes', {
        projectId: project._id,
        error: error.message
      });
    }
  }

  /**
   * Perform post-creation tasks
   * @private
   */
  static async performPostCreationTasks(projectId) {
    try {
      // Setup project integrations
      // Create initial project reports
      // Schedule recurring tasks
      // Initialize project metrics collection
      
      logger.debug('Post-creation tasks completed', { projectId });
    } catch (error) {
      logger.error('Post-creation tasks failed', {
        projectId,
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Get projects by client
   * @param {string} clientId - Client ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} - Projects
   */
  static async getProjectsByClient(clientId, options = {}) {
    try {
      logger.debug('Fetching projects by client', {
        clientId,
        options
      });

      const Project = require('../models/project-model');
      const projects = await Project.findByClient(clientId, options);

      logger.debug('Projects by client fetched successfully', {
        clientId,
        count: projects.length
      });

      return projects;
    } catch (error) {
      logger.error('Failed to fetch projects by client', {
        clientId,
        error: error.message
      });
      throw new AppError(`Failed to fetch projects by client: ${error.message}`, 500);
    }
  }

  /**
   * Get active projects
   * @param {Object} filters - Filter criteria
   * @returns {Promise<Array>} - Active projects
   */
  static async getActiveProjects(filters = {}) {
    try {
      logger.debug('Fetching active projects', { filters });

      const Project = require('../models/project-model');
      const projects = await Project.findActiveProjects(filters);

      logger.debug('Active projects fetched successfully', {
        count: projects.length
      });

      return projects;
    } catch (error) {
      logger.error('Failed to fetch active projects', {
        filters,
        error: error.message
      });
      throw new AppError(`Failed to fetch active projects: ${error.message}`, 500);
    }
  }

  /**
   * Export project data
   * @param {string} projectId - Project ID
   * @param {Object} options - Export options
   * @returns {Promise<Object|Buffer>} - Exported data
   */
  static async exportProject(projectId, options = {}) {
    try {
      const { format = 'json', sections = ['all'] } = options;

      logger.debug('Exporting project', {
        projectId,
        format,
        sections
      });

      const project = await this.getProjectById(projectId, {
        includeLogs: true,
        includeFinancialDetails: true
      });

      let exportData = {};

      // Build export data based on sections
      if (sections.includes('all') || sections.includes('general')) {
        exportData.general = {
          projectId: project.projectId,
          name: project.name,
          code: project.code,
          description: project.description,
          type: project.type,
          status: project.status,
          priority: project.priority
        };
      }

      if (sections.includes('all') || sections.includes('timeline')) {
        exportData.timeline = project.timeline;
      }

      if (sections.includes('all') || sections.includes('team')) {
        exportData.team = {
          projectManager: project.team.projectManager,
          members: project.team.members.map(m => ({
            consultant: m.consultant,
            role: m.role,
            allocation: m.allocation
          }))
        };
      }

      if (sections.includes('all') || sections.includes('financial')) {
        exportData.financial = project.financial;
      }

      if (sections.includes('all') || sections.includes('milestones')) {
        exportData.milestones = project.milestones;
      }

      if (sections.includes('all') || sections.includes('deliverables')) {
        exportData.deliverables = project.deliverables;
      }

      if (sections.includes('all') || sections.includes('risks')) {
        exportData.risks = project.risks;
      }

      if (sections.includes('all') || sections.includes('issues')) {
        exportData.issues = project.issues;
      }

      // Handle different export formats
      if (format === 'pdf') {
        const pdfBuffer = await generatePDF({
          template: 'project-export',
          data: exportData
        });
        return pdfBuffer;
      } else if (format === 'xlsx') {
        // Convert to Excel format
        // This would use a library like exceljs
        return exportData; // Placeholder
      }

      logger.info('Project exported successfully', {
        projectId,
        format,
        sectionsExported: Object.keys(exportData)
      });

      return exportData;
    } catch (error) {
      if (error instanceof AppError) throw error;
      logger.error('Failed to export project', {
        projectId,
        error: error.message
      });
      throw new AppError(`Failed to export project: ${error.message}`, 500);
    }
  }

  /**
   * Get default change request reviewers
   * @private
   */
  static async getDefaultChangeRequestReviewers(project, changeRequest) {
    const reviewers = [];

    // Always include project manager
    reviewers.push({
      reviewer: project.team.projectManager,
      role: 'Project Manager'
    });

    // Include sponsor for high-impact changes
    if (changeRequest.priority === 'high' || changeRequest.priority === 'critical') {
      if (project.team.sponsor?.internal) {
        reviewers.push({
          reviewer: project.team.sponsor.internal,
          role: 'Project Sponsor'
        });
      }
    }

    // Include finance for budget changes
    if (changeRequest.type === 'budget' && changeRequest.impact?.budget?.amount > 0) {
      // This would lookup the finance approver
      // For now, returning empty
    }

    return reviewers;
  }

  /**
   * Create payment invoice for milestone
   * @private
   */
  static async createPaymentInvoice(project, milestone) {
    try {
      logger.info('Creating payment invoice for milestone', {
        projectId: project._id,
        milestoneId: milestone._id,
        amount: milestone.payment.amount
      });

      // This would integrate with the invoice service
      // For now, just logging
      
      milestone.payment.invoiced = true;
      await project.save();
    } catch (error) {
      logger.error('Failed to create payment invoice', {
        projectId: project._id,
        milestoneId: milestone._id,
        error: error.message
      });
    }
  }

  /**
   * Check and update dependent milestones
   * @private
   */
  static async checkAndUpdateDependentMilestones(project, completedMilestoneId) {
    const dependentMilestones = project.milestones.filter(m => 
      m.dependencies?.some(d => 
        d.milestone.toString() === completedMilestoneId && 
        d.type === 'finish_to_start'
      )
    );

    for (const milestone of dependentMilestones) {
      if (milestone.status === 'pending') {
        // Check if all dependencies are met
        const allDependenciesMet = milestone.dependencies.every(dep => {
          const depMilestone = project.milestones.id(dep.milestone);
          return !depMilestone || depMilestone.status === 'completed';
        });

        if (allDependenciesMet) {
          milestone.status = 'in_progress';
          logger.debug('Dependent milestone status updated', {
            milestoneId: milestone._id,
            milestoneName: milestone.name
          });
        }
      }
    }
  }

  /**
   * Notify milestone delay
   * @private
   */
  static async notifyMilestoneDelay(project, milestone) {
    try {
      const stakeholders = [
        project.team.projectManager,
        ...milestone.assignedTo
      ];

      await NotificationService.sendBulkNotification({
        type: 'milestone_delayed',
        recipients: stakeholders,
        data: {
          projectId: project._id,
          projectName: project.name,
          milestoneName: milestone.name,
          plannedDate: milestone.plannedDate,
          daysDelayed: Math.ceil((new Date() - milestone.plannedDate) / (1000 * 60 * 60 * 24))
        }
      });
    } catch (error) {
      logger.error('Failed to notify milestone delay', {
        projectId: project._id,
        milestoneId: milestone._id,
        error: error.message
      });
    }
  }

  /**
   * Notify high risk
   * @private
   */
  static async notifyHighRisk(project, risk) {
    try {
      await NotificationService.sendNotification({
        type: 'high_risk_identified',
        recipient: project.team.projectManager,
        priority: 'high',
        data: {
          projectId: project._id,
          projectName: project.name,
          riskTitle: risk.title,
          riskScore: risk.riskScore,
          category: risk.category
        }
      });
    } catch (error) {
      logger.error('Failed to notify high risk', {
        projectId: project._id,
        risk: risk.title,
        error: error.message
      });
    }
  }

  /**
   * Notify change request reviewers
   * @private
   */
  static async notifyChangeRequestReviewers(project, changeRequest) {
    try {
      const reviewerIds = changeRequest.reviewers.map(r => r.reviewer);
      
      await NotificationService.sendBulkNotification({
        type: 'change_request_review',
        recipients: reviewerIds,
        data: {
          projectId: project._id,
          projectName: project.name,
          changeRequestNumber: changeRequest.requestNumber,
          changeType: changeRequest.type,
          priority: changeRequest.priority
        }
      });
    } catch (error) {
      logger.error('Failed to notify change request reviewers', {
        projectId: project._id,
        changeRequestId: changeRequest._id,
        error: error.message
      });
    }
  }

  /**
   * Notify status change
   * @private
   */
  static async notifyStatusChange(project, oldStatus, newStatus) {
    try {
      const stakeholders = [
        project.team.projectManager,
        project.team.sponsor?.internal,
        ...project.team.members
          .filter(m => m.approvalStatus === 'approved' && m.role === 'lead_consultant')
          .map(m => m.consultant)
      ].filter(Boolean);

      await NotificationService.sendBulkNotification({
        type: 'project_status_changed',
        recipients: stakeholders,
        data: {
          projectId: project._id,
          projectName: project.name,
          projectCode: project.code,
          oldStatus,
          newStatus
        }
      });
    } catch (error) {
      logger.error('Failed to notify status change', {
        projectId: project._id,
        error: error.message
      });
    }
  }
}

module.exports = ProjectService;