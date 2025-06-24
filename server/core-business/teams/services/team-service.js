// server/core-business/team/services/team-service.js
/**
 * @file Team Service
 * @description Comprehensive team service handling all team-related business logic
 * @version 3.0.0
 */

const mongoose = require('mongoose');

const Organization = require('../../../hosted-organizations/organizations/models/organization-model');
const config = require('../../../shared/config/config');
const constants = require('../../../shared/config/constants');
const AuditService = require('../../../shared/security/services/audit-service');
const { CacheService } = require('../../../shared/services/cache-service');
const EmailService = require('../../../shared/services/email-service');
const FileService = require('../../../shared/services/file-service');
const User = require('../../../shared/users/models/user-model');
const Project = require('../../projects/models/project-model');
const { 
  ValidationError, 
  NotFoundError, 
  ConflictError,
  ForbiddenError 
} = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const Team = require('../models/team-model');

/**
 * Team Service Class
 * @class TeamService
 */
class TeamService {
  /**
   * Create new team
   * @param {Object} teamData - Team data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Created team
   */
  static async createTeam(teamData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      // Validate required fields
      const requiredFields = ['name', 'type', 'organization'];
      const missingFields = requiredFields.filter(field => !teamData[field]);
      
      if (missingFields.length > 0) {
        throw new ValidationError(`Missing required fields: ${missingFields.join(', ')}`);
      }
      
      // Validate organization exists and user has permission
      const organization = await Organization.findById(teamData.organization).session(session);
      if (!organization) {
        throw new NotFoundError('Organization not found');
      }
      
      // Check user permission to create team
      const user = await User.findById(context.userId).session(session);
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      // Verify user belongs to organization or is admin
      const hasPermission = user.role.primary === 'super_admin' || 
                          user.organization?.current?.toString() === organization._id.toString() ||
                          user.organization?.organizations?.some(org => org.toString() === organization._id.toString());
      
      if (!hasPermission) {
        throw new ForbiddenError('You do not have permission to create teams in this organization');
      }
      
      // Check for duplicate team name in organization
      const existingTeam = await Team.findOne({
        name: teamData.name,
        organization: teamData.organization,
        status: { $ne: 'archived' }
      }).session(session);
      
      if (existingTeam) {
        throw new ConflictError('A team with this name already exists in the organization');
      }
      
      // Prepare team data
      const newTeam = new Team({
        ...teamData,
        metadata: {
          createdBy: context.userId,
          tags: teamData.tags || []
        },
        settings: {
          ...constants.TEAM.DEFAULT_SETTINGS,
          ...teamData.settings
        }
      });
      
      // Add creator as team lead if no members specified
      if (!teamData.members || teamData.members.length === 0) {
        await newTeam.addMember(context.userId, 'lead', context.userId, { autoAccept: true });
      } else {
        // Process provided members
        for (const member of teamData.members) {
          const memberUser = await User.findById(member.user).session(session);
          if (!memberUser) {
            throw new NotFoundError(`User ${member.user} not found`);
          }
          
          await newTeam.addMember(
            member.user,
            member.role || 'member',
            context.userId,
            { 
              autoAccept: member.autoAccept || false,
              allocation: member.allocation
            }
          );
        }
      }
      
      // Save team
      await newTeam.save({ session });
      
      // Send notifications to invited members
      const pendingMembers = newTeam.members.filter(m => m.status === 'pending');
      for (const member of pendingMembers) {
        await this.sendTeamInvitation(newTeam, member.user, context.userId);
      }
      
      // Update organization team count
      organization.metrics.totalTeams = (organization.metrics.totalTeams || 0) + 1;
      await organization.save({ session });
      
      // Commit transaction
      await session.commitTransaction();
      
      // Clear cache
      await CacheService.delete(`organization:${organization._id}:teams`);
      await CacheService.delete(`user:${context.userId}:teams`);
      
      // Audit log
      await AuditService.log({
        type: 'team_created',
        action: 'create',
        category: 'team_management',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'team',
          id: newTeam._id.toString()
        },
        metadata: {
          teamName: newTeam.name,
          teamType: newTeam.type,
          organizationId: organization._id,
          memberCount: newTeam.members.length
        }
      });
      
      // Populate and return
      await newTeam.populate([
        { path: 'members.user', select: 'firstName lastName email profile.avatar' },
        { path: 'organization', select: 'name' },
        { path: 'metadata.createdBy', select: 'firstName lastName' }
      ]);
      
      logger.info('Team created successfully', {
        teamId: newTeam._id,
        teamName: newTeam.name,
        organizationId: organization._id,
        createdBy: context.userId
      });
      
      return newTeam;
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Team creation failed', {
        error: error.message,
        teamData,
        userId: context.userId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Get team by ID
   * @param {string} teamId - Team ID
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Team document
   */
  static async getTeamById(teamId, options = {}) {
    try {
      // Check cache first
      const cacheKey = `team:${teamId}`;
      const cached = await CacheService.get(cacheKey);
      if (cached && !options.skipCache) {
        return cached;
      }
      
      const query = Team.findById(teamId);
      
      // Apply population based on options
      if (options.populate || options.includeMembers) {
        query.populate('members.user', 'firstName lastName email profile status role');
      }
      
      if (options.includeOrganization) {
        query.populate('organization', 'name settings');
      }
      
      if (options.includeProjects) {
        query.populate('projects.project', 'name status progress');
      }
      
      if (options.includeMetrics) {
        query.select('+metrics');
      }
      
      const team = await query.exec();
      
      if (!team) {
        throw new NotFoundError('Team not found');
      }
      
      // Calculate health score if requested
      if (options.includeHealth) {
        await team.calculateHealthScore();
        await team.save();
      }
      
      // Cache the result
      await CacheService.set(cacheKey, team, 300); // 5 minutes
      
      return team;
      
    } catch (error) {
      logger.error('Failed to get team by ID', {
        error: error.message,
        teamId
      });
      throw error;
    }
  }
  
  /**
   * Update team
   * @param {string} teamId - Team ID
   * @param {Object} updateData - Update data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated team
   */
  static async updateTeam(teamId, updateData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const team = await Team.findById(teamId).session(session);
      if (!team) {
        throw new NotFoundError('Team not found');
      }
      
      // Check permissions
      const hasPermission = await this.checkTeamPermission(team, context.userId, 'canEditTeam');
      if (!hasPermission && context.userRole !== 'super_admin') {
        throw new ForbiddenError('You do not have permission to update this team');
      }
      
      // Fields that cannot be updated
      const restrictedFields = ['_id', 'organization', 'code', 'createdAt'];
      restrictedFields.forEach(field => delete updateData[field]);
      
      // Handle special updates
      if (updateData.status && updateData.status !== team.status) {
        await this.validateStatusTransition(team.status, updateData.status);
      }
      
      // Update team
      Object.assign(team, updateData);
      team.metadata.updatedBy = context.userId;
      
      await team.save({ session });
      
      // Commit transaction
      await session.commitTransaction();
      
      // Clear cache
      await CacheService.delete(`team:${teamId}`);
      await CacheService.delete(`organization:${team.organization}:teams`);
      
      // Audit log
      await AuditService.log({
        type: 'team_updated',
        action: 'update',
        category: 'team_management',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'team',
          id: teamId
        },
        metadata: {
          changes: Object.keys(updateData)
        }
      });
      
      // Populate and return
      await team.populate([
        { path: 'members.user', select: 'firstName lastName email' },
        { path: 'organization', select: 'name' }
      ]);
      
      logger.info('Team updated successfully', {
        teamId,
        updatedBy: context.userId,
        changes: Object.keys(updateData)
      });
      
      return team;
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Team update failed', {
        error: error.message,
        teamId,
        updateData
      });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Delete team (archive)
   * @param {string} teamId - Team ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Archived team
   */
  static async deleteTeam(teamId, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const team = await Team.findById(teamId).session(session);
      if (!team) {
        throw new NotFoundError('Team not found');
      }
      
      // Check permissions
      const hasPermission = team.metadata.createdBy.toString() === context.userId ||
                          context.userRole === 'super_admin' ||
                          context.userRole === 'org_owner';
      
      if (!hasPermission) {
        throw new ForbiddenError('You do not have permission to delete this team');
      }
      
      // Check if team has active projects
      const activeProjects = team.projects.filter(p => p.status === 'active');
      if (activeProjects.length > 0) {
        throw new ValidationError('Cannot delete team with active projects');
      }
      
      // Archive instead of hard delete
      team.status = 'archived';
      team.lifecycle.archivalDate = new Date();
      team.metadata.updatedBy = context.userId;
      
      await team.save({ session });
      
      // Update organization metrics
      const organization = await Organization.findById(team.organization).session(session);
      if (organization) {
        organization.metrics.totalTeams = Math.max(0, (organization.metrics.totalTeams || 1) - 1);
        await organization.save({ session });
      }
      
      // Commit transaction
      await session.commitTransaction();
      
      // Clear cache
      await CacheService.delete(`team:${teamId}`);
      await CacheService.delete(`organization:${team.organization}:teams`);
      
      // Audit log
      await AuditService.log({
        type: 'team_archived',
        action: 'delete',
        category: 'team_management',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'team',
          id: teamId
        },
        metadata: {
          teamName: team.name,
          reason: context.reason
        }
      });
      
      logger.info('Team archived successfully', {
        teamId,
        archivedBy: context.userId
      });
      
      return { success: true, message: 'Team archived successfully' };
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Team deletion failed', {
        error: error.message,
        teamId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Get all teams with filtering
   * @param {Object} filter - MongoDB filter
   * @param {Object} options - Query options
   * @returns {Promise<Object>} Teams list with pagination
   */
  static async getAllTeams(filter = {}, options = {}) {
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'createdAt',
        sortOrder = 'desc',
        populate = true,
        search
      } = options;
      
      // Build query
      const query = { ...filter };
      
      // Add search if provided
      if (search) {
        query.$or = [
          { name: { $regex: search, $options: 'i' } },
          { code: { $regex: search, $options: 'i' } },
          { description: { $regex: search, $options: 'i' } }
        ];
      }
      
      // Execute query with pagination
      const skip = (page - 1) * limit;
      const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
      
      const [teams, total] = await Promise.all([
        Team.find(query)
          .populate(populate ? 'members.user organization' : '')
          .sort(sort)
          .skip(skip)
          .limit(limit)
          .lean(),
        Team.countDocuments(query)
      ]);
      
      return {
        teams,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit)
        }
      };
      
    } catch (error) {
      logger.error('Failed to get teams', {
        error: error.message,
        filter,
        options
      });
      throw error;
    }
  }
  
  /**
   * Get teams by user
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Promise<Array>} User's teams
   */
  static async getTeamsByUser(userId, options = {}) {
    try {
      const cacheKey = `user:${userId}:teams`;
      const cached = await CacheService.get(cacheKey);
      if (cached && !options.skipCache) {
        return cached;
      }
      
      const teams = await Team.findByUser(userId, options);
      
      // Cache the result
      await CacheService.set(cacheKey, teams, 600); // 10 minutes
      
      return teams;
      
    } catch (error) {
      logger.error('Failed to get teams by user', {
        error: error.message,
        userId
      });
      throw error;
    }
  }
  
  /**
   * Add team member
   * @param {string} teamId - Team ID
   * @param {Object} memberData - Member data
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated team
   */
  static async addTeamMember(teamId, memberData, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const team = await Team.findById(teamId).session(session);
      if (!team) {
        throw new NotFoundError('Team not found');
      }
      
      // Check permissions
      const hasPermission = await this.checkTeamPermission(team, context.userId, 'canInviteMembers');
      if (!hasPermission && context.userRole !== 'super_admin') {
        throw new ForbiddenError('You do not have permission to add members to this team');
      }
      
      // Validate user exists
      const user = await User.findById(memberData.userId).session(session);
      if (!user) {
        throw new NotFoundError('User not found');
      }
      
      // Add member
      await team.addMember(
        memberData.userId,
        memberData.role || 'member',
        context.userId,
        {
          allocation: memberData.allocation,
          autoAccept: memberData.autoAccept || false
        }
      );
      
      await team.save({ session });
      
      // Send invitation if not auto-accepted
      if (!memberData.autoAccept) {
        await this.sendTeamInvitation(team, memberData.userId, context.userId);
      }
      
      // Commit transaction
      await session.commitTransaction();
      
      // Clear cache
      await CacheService.delete(`team:${teamId}`);
      await CacheService.delete(`user:${memberData.userId}:teams`);
      
      // Audit log
      await AuditService.log({
        type: 'team_member_added',
        action: 'add_member',
        category: 'team_management',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'team',
          id: teamId
        },
        metadata: {
          memberId: memberData.userId,
          memberRole: memberData.role
        }
      });
      
      // Populate and return
      await team.populate('members.user', 'firstName lastName email');
      
      logger.info('Team member added successfully', {
        teamId,
        memberId: memberData.userId,
        addedBy: context.userId
      });
      
      return team;
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to add team member', {
        error: error.message,
        teamId,
        memberData
      });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Remove team member
   * @param {string} teamId - Team ID
   * @param {string} memberId - Member user ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated team
   */
  static async removeTeamMember(teamId, memberId, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const team = await Team.findById(teamId).session(session);
      if (!team) {
        throw new NotFoundError('Team not found');
      }
      
      // Check permissions
      const hasPermission = await this.checkTeamPermission(team, context.userId, 'canRemoveMembers');
      const isSelfRemoval = memberId === context.userId;
      
      if (!hasPermission && !isSelfRemoval && context.userRole !== 'super_admin') {
        throw new ForbiddenError('You do not have permission to remove members from this team');
      }
      
      // Remove member
      await team.removeMember(memberId, context.userId, context.reason);
      await team.save({ session });
      
      // Commit transaction
      await session.commitTransaction();
      
      // Clear cache
      await CacheService.delete(`team:${teamId}`);
      await CacheService.delete(`user:${memberId}:teams`);
      
      // Send notification
      await this.sendMemberRemovedNotification(team, memberId, context.userId);
      
      // Audit log
      await AuditService.log({
        type: 'team_member_removed',
        action: 'remove_member',
        category: 'team_management',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'team',
          id: teamId
        },
        metadata: {
          memberId,
          reason: context.reason,
          isSelfRemoval
        }
      });
      
      logger.info('Team member removed successfully', {
        teamId,
        memberId,
        removedBy: context.userId
      });
      
      return team;
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to remove team member', {
        error: error.message,
        teamId,
        memberId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Update team member role
   * @param {string} teamId - Team ID
   * @param {string} memberId - Member user ID
   * @param {string} newRole - New role
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated team
   */
  static async updateMemberRole(teamId, memberId, newRole, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const team = await Team.findById(teamId).session(session);
      if (!team) {
        throw new NotFoundError('Team not found');
      }
      
      // Check permissions
      const hasPermission = await this.checkTeamPermission(team, context.userId, 'canEditTeam');
      if (!hasPermission && context.userRole !== 'super_admin') {
        throw new ForbiddenError('You do not have permission to update member roles');
      }
      
      // Update role
      await team.updateMemberRole(memberId, newRole, context.userId);
      await team.save({ session });
      
      // Commit transaction
      await session.commitTransaction();
      
      // Clear cache
      await CacheService.delete(`team:${teamId}`);
      
      // Audit log
      await AuditService.log({
        type: 'team_member_role_updated',
        action: 'update_role',
        category: 'team_management',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'team',
          id: teamId
        },
        metadata: {
          memberId,
          newRole
        }
      });
      
      logger.info('Team member role updated successfully', {
        teamId,
        memberId,
        newRole,
        updatedBy: context.userId
      });
      
      return team;
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to update member role', {
        error: error.message,
        teamId,
        memberId,
        newRole
      });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Accept team invitation
   * @param {string} teamId - Team ID
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Updated team
   */
  static async acceptInvitation(teamId, context) {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
      const team = await Team.findById(teamId).session(session);
      if (!team) {
        throw new NotFoundError('Team not found');
      }
      
      const member = team.members.find(m => 
        m.user.toString() === context.userId && m.status === 'pending'
      );
      
      if (!member) {
        throw new NotFoundError('No pending invitation found');
      }
      
      // Accept invitation
      member.status = 'active';
      member.metadata.acceptedAt = new Date();
      
      await team.save({ session });
      
      // Commit transaction
      await session.commitTransaction();
      
      // Clear cache
      await CacheService.delete(`team:${teamId}`);
      await CacheService.delete(`user:${context.userId}:teams`);
      
      // Send notifications
      await this.sendInvitationAcceptedNotification(team, context.userId);
      
      // Audit log
      await AuditService.log({
        type: 'team_invitation_accepted',
        action: 'accept_invitation',
        category: 'team_management',
        result: 'success',
        userId: context.userId,
        target: {
          type: 'team',
          id: teamId
        }
      });
      
      logger.info('Team invitation accepted', {
        teamId,
        userId: context.userId
      });
      
      return team;
      
    } catch (error) {
      await session.abortTransaction();
      logger.error('Failed to accept team invitation', {
        error: error.message,
        teamId,
        userId: context.userId
      });
      throw error;
    } finally {
      session.endSession();
    }
  }
  
  /**
   * Get team statistics
   * @param {Object} filter - Filter criteria
   * @returns {Promise<Object>} Team statistics
   */
  static async getTeamStatistics(filter = {}) {
    try {
      const stats = await Team.aggregate([
        { $match: filter },
        {
          $group: {
            _id: null,
            totalTeams: { $sum: 1 },
            activeTeams: {
              $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
            },
            totalMembers: { $sum: { $size: '$members' } },
            avgTeamSize: { $avg: { $size: '$members' } },
            byType: {
              $push: '$type'
            },
            avgHealthScore: { $avg: '$metrics.health.score' }
          }
        },
        {
          $project: {
            _id: 0,
            totalTeams: 1,
            activeTeams: 1,
            totalMembers: 1,
            avgTeamSize: { $round: ['$avgTeamSize', 1] },
            avgHealthScore: { $round: ['$avgHealthScore', 1] },
            typeDistribution: {
              $arrayToObject: {
                $map: {
                  input: { $setUnion: ['$byType', []] },
                  as: 'type',
                  in: {
                    k: '$$type',
                    v: {
                      $size: {
                        $filter: {
                          input: '$byType',
                          cond: { $eq: ['$$this', '$$type'] }
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
        totalTeams: 0,
        activeTeams: 0,
        totalMembers: 0,
        avgTeamSize: 0,
        avgHealthScore: 0,
        typeDistribution: {}
      };
      
    } catch (error) {
      logger.error('Failed to get team statistics', {
        error: error.message,
        filter
      });
      throw error;
    }
  }
  
  /**
   * Search teams
   * @param {string} searchTerm - Search term
   * @param {Object} filters - Additional filters
   * @returns {Promise<Array>} Search results
   */
  static async searchTeams(searchTerm, filters = {}) {
    try {
      const results = await Team.searchTeams(searchTerm, filters);
      return results;
    } catch (error) {
      logger.error('Team search failed', {
        error: error.message,
        searchTerm,
        filters
      });
      throw error;
    }
  }
  
  /**
   * Check team permission
   * @private
   * @param {Object} team - Team document
   * @param {string} userId - User ID
   * @param {string} permission - Permission to check
   * @returns {Promise<boolean>} Has permission
   */
  static async checkTeamPermission(team, userId, permission) {
    return team.canUserPerform(userId, permission);
  }
  
  /**
   * Validate status transition
   * @private
   * @param {string} currentStatus - Current status
   * @param {string} newStatus - New status
   * @throws {ValidationError} If transition is invalid
   */
  static async validateStatusTransition(currentStatus, newStatus) {
    const validTransitions = {
      active: ['inactive', 'suspended', 'archived'],
      inactive: ['active', 'archived'],
      suspended: ['active', 'archived'],
      archived: [] // Cannot transition from archived
    };
    
    if (!validTransitions[currentStatus]?.includes(newStatus)) {
      throw new ValidationError(`Cannot transition from ${currentStatus} to ${newStatus}`);
    }
  }
  
  /**
   * Send team invitation email
   * @private
   * @param {Object} team - Team document
   * @param {string} userId - Invited user ID
   * @param {string} invitedBy - Inviter user ID
   */
  static async sendTeamInvitation(team, userId, invitedBy) {
    try {
      const user = await User.findById(userId);
      const inviter = await User.findById(invitedBy);
      
      if (!user || !inviter) return;
      
      await EmailService.sendEmail({
        to: user.email,
        subject: `You've been invited to join ${team.name}`,
        template: 'team-invitation',
        data: {
          userName: user.firstName,
          teamName: team.name,
          inviterName: `${inviter.firstName} ${inviter.lastName}`,
          acceptUrl: `${config.app.clientUrl}/teams/${team._id}/accept-invitation`
        }
      });
      
    } catch (error) {
      logger.error('Failed to send team invitation email', {
        error: error.message,
        teamId: team._id,
        userId
      });
    }
  }
  
  /**
   * Send member removed notification
   * @private
   * @param {Object} team - Team document
   * @param {string} userId - Removed user ID
   * @param {string} removedBy - Remover user ID
   */
  static async sendMemberRemovedNotification(team, userId, removedBy) {
    try {
      const user = await User.findById(userId);
      if (!user) return;
      
      await EmailService.sendEmail({
        to: user.email,
        subject: `You've been removed from ${team.name}`,
        template: 'team-member-removed',
        data: {
          userName: user.firstName,
          teamName: team.name
        }
      });
      
    } catch (error) {
      logger.error('Failed to send member removed notification', {
        error: error.message,
        teamId: team._id,
        userId
      });
    }
  }
  
  /**
   * Send invitation accepted notification
   * @private
   * @param {Object} team - Team document
   * @param {string} userId - User who accepted
   */
  static async sendInvitationAcceptedNotification(team, userId) {
    try {
      const user = await User.findById(userId);
      const teamLead = team.members.find(m => m.role === 'lead' && m.status === 'active');
      
      if (!user || !teamLead) return;
      
      const lead = await User.findById(teamLead.user);
      
      await EmailService.sendEmail({
        to: lead.email,
        subject: `${user.firstName} ${user.lastName} joined ${team.name}`,
        template: 'team-member-joined',
        data: {
          leadName: lead.firstName,
          memberName: `${user.firstName} ${user.lastName}`,
          teamName: team.name
        }
      });
      
    } catch (error) {
      logger.error('Failed to send invitation accepted notification', {
        error: error.message,
        teamId: team._id,
        userId
      });
    }
  }
  
  /**
   * Auto-archive inactive teams
   * @returns {Promise<number>} Number of teams archived
   */
  static async autoArchiveInactiveTeams() {
    try {
      const teams = await Team.find({
        status: 'active',
        'settings.autoArchive.enabled': true
      });
      
      let archivedCount = 0;
      
      for (const team of teams) {
        if (team.shouldAutoArchive()) {
          team.status = 'archived';
          team.lifecycle.archivalDate = new Date();
          await team.save();
          archivedCount++;
          
          logger.info('Team auto-archived due to inactivity', {
            teamId: team._id,
            teamName: team.name,
            lastActivity: team.metadata.lastActivityAt
          });
        }
      }
      
      return archivedCount;
      
    } catch (error) {
      logger.error('Auto-archive process failed', {
        error: error.message
      });
      throw error;
    }
  }
}

module.exports = TeamService;