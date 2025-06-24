// server/core-business/team/controllers/team-controller.js
/**
 * @file Team Controller
 * @description Handles team-related HTTP requests
 * @version 3.0.0
 */

const config = require('../../../shared/config/config');
const { 
  ValidationError,
  NotFoundError,
  ForbiddenError 
} = require('../../../shared/utils/app-error');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const logger = require('../../../shared/utils/logger');
const responseHandler = require('../../../shared/utils/response-handler');
const TeamService = require('../services/team-service');

/**
 * Team Controller Class
 * @class TeamController
 */
class TeamController {
  /**
   * Create new team
   * @route   POST /api/v1/teams
   * @access  Private
   */
  static createTeam = asyncHandler(async (req, res) => {
    const teamData = {
      name: req.body.name,
      description: req.body.description,
      type: req.body.type,
      organization: req.body.organization || req.user.organization?.current,
      department: req.body.department,
      parentTeam: req.body.parentTeam,
      members: req.body.members,
      settings: req.body.settings,
      objectives: req.body.objectives,
      tags: req.body.tags
    };
    
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      ip: req.ip,
      userAgent: req.get('user-agent')
    };
    
    const team = await TeamService.createTeam(teamData, context);
    
    responseHandler.success(res, { team }, 'Team created successfully', 201);
  });
  
  /**
   * Get team by ID
   * @route   GET /api/v1/teams/:id
   * @access  Private
   */
  static getTeamById = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const options = {
      includeMembers: req.query.includeMembers === 'true',
      includeOrganization: req.query.includeOrganization === 'true',
      includeProjects: req.query.includeProjects === 'true',
      includeMetrics: req.query.includeMetrics === 'true',
      includeHealth: req.query.includeHealth === 'true'
    };
    
    const team = await TeamService.getTeamById(teamId, options);
    
    // Check if user has access to view this team
    const hasAccess = team.members.some(m => 
      m.user._id?.toString() === req.user._id.toString() && m.status === 'active'
    ) || 
    req.user.role?.primary === 'super_admin' ||
    team.settings.visibility === 'public' ||
    (team.settings.visibility === 'organization' && 
     req.user.organization?.current?.toString() === team.organization._id?.toString());
    
    if (!hasAccess) {
      throw new ForbiddenError('You do not have permission to view this team');
    }
    
    responseHandler.success(res, { team }, 'Team retrieved successfully');
  });
  
  /**
   * Update team
   * @route   PUT /api/v1/teams/:id
   * @access  Private
   */
  static updateTeam = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const updateData = {
      name: req.body.name,
      description: req.body.description,
      type: req.body.type,
      settings: req.body.settings,
      objectives: req.body.objectives,
      status: req.body.status,
      tags: req.body.tags
    };
    
    // Remove undefined fields
    Object.keys(updateData).forEach(key => 
      updateData[key] === undefined && delete updateData[key]
    );
    
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      ip: req.ip
    };
    
    const team = await TeamService.updateTeam(teamId, updateData, context);
    
    responseHandler.success(res, { team }, 'Team updated successfully');
  });
  
  /**
   * Delete team (archive)
   * @route   DELETE /api/v1/teams/:id
   * @access  Private
   */
  static deleteTeam = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      reason: req.body.reason,
      ip: req.ip
    };
    
    const result = await TeamService.deleteTeam(teamId, context);
    
    responseHandler.success(res, result, 'Team archived successfully');
  });
  
  /**
   * Get all teams
   * @route   GET /api/v1/teams
   * @access  Private
   */
  static getAllTeams = asyncHandler(async (req, res) => {
    const filter = {};
    const options = {
      page: parseInt(req.query.page) || 1,
      limit: parseInt(req.query.limit) || 20,
      sortBy: req.query.sortBy || 'createdAt',
      sortOrder: req.query.sortOrder || 'desc',
      search: req.query.search,
      populate: req.query.populate !== 'false'
    };
    
    // Apply filters based on query params
    if (req.query.status) {
      filter.status = req.query.status;
    }
    
    if (req.query.type) {
      filter.type = req.query.type;
    }
    
    if (req.query.organization) {
      filter.organization = req.query.organization;
    }
    
    // Filter by user's organization if not admin
    if (req.user.role?.primary !== 'super_admin' && !req.query.organization) {
      filter.organization = req.user.organization?.current;
    }
    
    // Filter by user's teams if specified
    if (req.query.myTeams === 'true') {
      filter['members.user'] = req.user._id;
      filter['members.status'] = 'active';
    }
    
    const result = await TeamService.getAllTeams(filter, options);
    
    responseHandler.success(res, result, 'Teams retrieved successfully');
  });
  
  /**
   * Get user's teams
   * @route   GET /api/v1/teams/my-teams
   * @access  Private
   */
  static getMyTeams = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    const options = {
      status: req.query.status,
      type: req.query.type,
      skipCache: req.query.skipCache === 'true'
    };
    
    const teams = await TeamService.getTeamsByUser(userId, options);
    
    responseHandler.success(res, { teams }, 'User teams retrieved successfully');
  });
  
  /**
   * Add team member
   * @route   POST /api/v1/teams/:id/members
   * @access  Private
   */
  static addTeamMember = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const memberData = {
      userId: req.body.userId,
      role: req.body.role || 'member',
      allocation: req.body.allocation,
      autoAccept: req.body.autoAccept || false
    };
    
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      ip: req.ip
    };
    
    const team = await TeamService.addTeamMember(teamId, memberData, context);
    
    responseHandler.success(res, { team }, 'Team member added successfully');
  });
  
  /**
   * Remove team member
   * @route   DELETE /api/v1/teams/:id/members/:memberId
   * @access  Private
   */
  static removeTeamMember = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const memberId = req.params.memberId;
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      reason: req.body.reason,
      ip: req.ip
    };
    
    const team = await TeamService.removeTeamMember(teamId, memberId, context);
    
    responseHandler.success(res, { team }, 'Team member removed successfully');
  });
  
  /**
   * Update team member role
   * @route   PUT /api/v1/teams/:id/members/:memberId/role
   * @access  Private
   */
  static updateMemberRole = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const memberId = req.params.memberId;
    const newRole = req.body.role;
    
    if (!newRole) {
      throw new ValidationError('New role is required');
    }
    
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      ip: req.ip
    };
    
    const team = await TeamService.updateMemberRole(teamId, memberId, newRole, context);
    
    responseHandler.success(res, { team }, 'Member role updated successfully');
  });
  
  /**
   * Accept team invitation
   * @route   POST /api/v1/teams/:id/accept-invitation
   * @access  Private
   */
  static acceptInvitation = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const context = {
      userId: req.user._id,
      ip: req.ip
    };
    
    const team = await TeamService.acceptInvitation(teamId, context);
    
    responseHandler.success(res, { team }, 'Invitation accepted successfully');
  });
  
  /**
   * Search teams
   * @route   GET /api/v1/teams/search
   * @access  Private
   */
  static searchTeams = asyncHandler(async (req, res) => {
    const searchTerm = req.query.q || req.query.search;
    
    if (!searchTerm || searchTerm.length < 2) {
      throw new ValidationError('Search term must be at least 2 characters');
    }
    
    const filters = {
      organization: req.query.organization || req.user.organization?.current,
      type: req.query.type,
      status: req.query.status || 'active',
      userId: req.query.myTeams === 'true' ? req.user._id : undefined,
      limit: parseInt(req.query.limit) || 20
    };
    
    // Remove undefined filters
    Object.keys(filters).forEach(key => 
      filters[key] === undefined && delete filters[key]
    );
    
    const teams = await TeamService.searchTeams(searchTerm, filters);
    
    responseHandler.success(res, { teams }, 'Search completed successfully');
  });
  
  /**
   * Get team statistics
   * @route   GET /api/v1/teams/statistics
   * @access  Private
   */
  static getTeamStatistics = asyncHandler(async (req, res) => {
    const filter = {};
    
    // Apply filters based on query params
    if (req.query.organization) {
      filter.organization = req.query.organization;
    } else if (req.user.role?.primary !== 'super_admin') {
      filter.organization = req.user.organization?.current;
    }
    
    if (req.query.type) {
      filter.type = req.query.type;
    }
    
    if (req.query.status) {
      filter.status = req.query.status;
    }
    
    const statistics = await TeamService.getTeamStatistics(filter);
    
    responseHandler.success(res, { statistics }, 'Statistics retrieved successfully');
  });
  
  /**
   * Update team objectives
   * @route   PUT /api/v1/teams/:id/objectives
   * @access  Private
   */
  static updateObjectives = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const objectives = req.body.objectives;
    
    if (!Array.isArray(objectives)) {
      throw new ValidationError('Objectives must be an array');
    }
    
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      ip: req.ip
    };
    
    const team = await TeamService.updateTeam(teamId, { objectives }, context);
    
    responseHandler.success(res, { team }, 'Objectives updated successfully');
  });
  
  /**
   * Update team resources
   * @route   PUT /api/v1/teams/:id/resources
   * @access  Private
   */
  static updateResources = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const resources = req.body.resources;
    
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      ip: req.ip
    };
    
    const team = await TeamService.updateTeam(teamId, { resources }, context);
    
    responseHandler.success(res, { team }, 'Resources updated successfully');
  });
  
  /**
   * Get team health report
   * @route   GET /api/v1/teams/:id/health
   * @access  Private
   */
  static getTeamHealth = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    
    const team = await TeamService.getTeamById(teamId, { includeHealth: true });
    
    // Check access
    const hasAccess = team.members.some(m => 
      m.user._id?.toString() === req.user._id.toString() && m.status === 'active'
    ) || req.user.role?.primary === 'super_admin';
    
    if (!hasAccess) {
      throw new ForbiddenError('You do not have permission to view team health');
    }
    
    const healthReport = {
      teamId: team._id,
      teamName: team.name,
      healthScore: team.metrics.health.score,
      factors: team.metrics.health.factors,
      lastAssessed: team.metrics.health.lastAssessed,
      recommendations: this.generateHealthRecommendations(team.metrics.health)
    };
    
    responseHandler.success(res, { healthReport }, 'Team health retrieved successfully');
  });
  
  /**
   * Leave team
   * @route   POST /api/v1/teams/:id/leave
   * @access  Private
   */
  static leaveTeam = asyncHandler(async (req, res) => {
    const teamId = req.params.id;
    const context = {
      userId: req.user._id,
      userRole: req.user.role?.primary,
      reason: req.body.reason || 'User left the team',
      ip: req.ip
    };
    
    const team = await TeamService.removeTeamMember(teamId, req.user._id, context);
    
    responseHandler.success(res, { team }, 'Successfully left the team');
  });
  
  /**
   * Generate health recommendations
   * @private
   * @param {Object} health - Health metrics
   * @returns {Array} Recommendations
   */
  static generateHealthRecommendations(health) {
    const recommendations = [];
    
    if (health.factors.workload < 50) {
      recommendations.push({
        area: 'workload',
        priority: 'high',
        suggestion: 'Team appears to be overloaded. Consider redistributing tasks or adding members.'
      });
    }
    
    if (health.factors.morale < 60) {
      recommendations.push({
        area: 'morale',
        priority: 'high',
        suggestion: 'Team morale is low. Schedule a team meeting to address concerns.'
      });
    }
    
    if (health.factors.clarity < 70) {
      recommendations.push({
        area: 'clarity',
        priority: 'medium',
        suggestion: 'Goal clarity can be improved. Review and update team objectives.'
      });
    }
    
    if (health.factors.growth < 50) {
      recommendations.push({
        area: 'growth',
        priority: 'medium',
        suggestion: 'Limited growth opportunities detected. Plan skill development activities.'
      });
    }
    
    if (health.factors.recognition < 60) {
      recommendations.push({
        area: 'recognition',
        priority: 'low',
        suggestion: 'Increase team recognition. Implement regular appreciation practices.'
      });
    }
    
    return recommendations;
  }
}

module.exports = TeamController;