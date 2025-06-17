/**
 * @file Consultant Service
 * @description Business logic and database operations for consultant management
 * @version 2.0.0
 */

const Consultant = require('../models/consultant-model');
const User = require('../../../shared/users/models/user-model');
const Project = require('../../projects/models/project-model');
const { AppError } = require('../../../shared/utils/app-error');
const { generatePDF } = require('../../../shared/utils/pdf-generator');
const logger = require('../../../shared/utils/logger');
const EmailService = require('../../../shared/services/email-service');
const CacheService = require('../../../shared/services/cache-service');

/**
 * Consultant Service Class
 */
class ConsultantService {
  /**
   * Search consultants with advanced filtering
   * @param {Object} criteria - Search criteria including skills, availability, department, etc.
   * @param {Object} options - Pagination and sorting options
   * @returns {Promise<Object>} - Paginated list of consultants matching criteria
   */
  static async searchConsultants(criteria, options = {}) {
    const {
      page = 1,
      limit = 20,
      sort = '-availability.summary.utilizationPercentage'
    } = options;
    
    const query = {
      'status.isActive': true,
      'employment.status': 'active'
    };
    
    // Build search query based on criteria
    if (criteria.skills && criteria.skills.length > 0) {
      query['skills.name'] = { $in: criteria.skills };
    }
    
    if (criteria.department) {
      query['professional.department'] = criteria.department;
    }
    
    if (criteria.role) {
      query['professional.role'] = criteria.role;
    }
    
    if (criteria.industries && criteria.industries.length > 0) {
      query['professional.industries.name'] = { $in: criteria.industries };
    }
    
    if (criteria.minRating) {
      query['performance.currentRating.overall'] = { $gte: criteria.minRating };
    }
    
    if (criteria.location) {
      query['contactInfo.address.current.city'] = criteria.location;
    }
    
    if (criteria.clearance) {
      const clearanceLevels = ['none', 'public_trust', 'secret', 'top_secret', 'ts_sci'];
      const requiredIndex = clearanceLevels.indexOf(criteria.clearance);
      const acceptableLevels = clearanceLevels.slice(requiredIndex);
      query['professional.clearanceLevel'] = { $in: acceptableLevels };
    }
    
    if (criteria.availability) {
      const { startDate, endDate, minAllocation } = criteria.availability;
      if (startDate && endDate) {
        query.$or = [
          { 'availability.nextAvailable': { $lte: new Date(startDate) } },
          { 'availability.summary.utilizationPercentage': { $lte: 100 - minAllocation } }
        ];
      }
    }
    
    const skip = (page - 1) * limit;
    
    const [consultants, total] = await Promise.all([
      Consultant.find(query)
        .populate('userId', 'email')
        .populate('employment.reportingTo.primary', 'firstName lastName')
        .populate('availability.currentAssignment.project', 'name code')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean(),
      Consultant.countDocuments(query)
    ]);
    
    return {
      data: consultants,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  }
  
  /**
   * Get all consultants with pagination
   * @param {Object} options - Query options including page, limit, sort, and filter
   * @returns {Promise<Object>} - Paginated list of consultants with metadata
   */
  static async getAllConsultants(options = {}) {
    const {
      page = 1,
      limit = 20,
      sort = '-createdAt',
      filter = {}
    } = options;
    
    const query = { ...filter };
    const skip = (page - 1) * limit;
    
    const [consultants, total] = await Promise.all([
      Consultant.find(query)
        .populate('userId', 'email')
        .populate('employment.reportingTo.primary', 'firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean(),
      Consultant.countDocuments(query)
    ]);
    
    return {
      data: consultants,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    };
  }
  
  /**
   * Create a new consultant profile
   * @param {Object} consultantData - The consultant data including personal, professional, and employment details
   * @param {string} createdBy - The ID of the user creating the consultant profile
   * @returns {Promise<Object>} - The created consultant profile
   */
  static async createConsultant(consultantData, createdBy) {
    try {
      // Check if user already has a consultant profile
      const existingConsultant = await Consultant.findOne({ userId: consultantData.userId });
      if (existingConsultant) {
        throw new AppError('User already has a consultant profile', 400);
      }
      
      // Verify user exists
      const user = await User.findById(consultantData.userId);
      if (!user) {
        throw new AppError('User not found', 404);
      }
      
      // Create consultant profile
      const consultant = new Consultant({
        ...consultantData,
        metadata: {
          ...consultantData.metadata,
          source: 'manual'
        }
      });
      
      await consultant.save();
      
      // Update user with consultant reference
      user.consultantProfile = consultant._id;
      user.userType = 'core_consultant';
      await user.save();
      
      // Send welcome email
      await EmailService.sendConsultantWelcome(user.email, {
        name: consultant.fullName,
        employeeId: consultant.employeeId
      });
      
      logger.info(`Consultant profile created: ${consultant.employeeId}`);
      
      return consultant;
    } catch (error) {
      logger.error('Error creating consultant:', error);
      throw error;
    }
  }
  
  /**
   * Get consultant by ID
   * @param {string} id - The consultant ID
   * @param {Array<string>} includeOptions - Array of related data to include (e.g., 'projects', 'skills', 'performance')
   * @returns {Promise<Object>} - The consultant profile with requested related data
   */
  static async getConsultantById(id, includeOptions = []) {
    const query = Consultant.findById(id)
      .populate('userId', 'email lastLogin')
      .populate('employment.reportingTo.primary', 'firstName lastName email')
      .populate('employment.team.current', 'name description');
    
    // Dynamic population based on include options
    if (includeOptions.includes('projects') || includeOptions.includes('all')) {
      query.populate('availability.projects.project', 'name code client status');
    }
    
    if (includeOptions.includes('skills') || includeOptions.includes('all')) {
      query.populate('skills.endorsements.endorser', 'firstName lastName');
    }
    
    if (includeOptions.includes('performance') || includeOptions.includes('all')) {
      query.populate('performance.reviews.reviewer.primary', 'firstName lastName');
    }
    
    const consultant = await query.lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    return consultant;
  }
  
  /**
   * Update consultant profile
   * @param {string} id - The consultant ID
   * @param {Object} updates - The fields to update
   * @param {string} updatedBy - The ID of the user performing the update
   * @returns {Promise<Object>} - The updated consultant profile
   */
  static async updateConsultant(id, updates, updatedBy) {
    const consultant = await Consultant.findById(id);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Handle sensitive fields that require special permissions
    const restrictedFields = ['compensation', 'employment.status', 'professional.role'];
    const hasRestrictedUpdates = restrictedFields.some(field => 
      updates.hasOwnProperty(field.split('.')[0])
    );
    
    if (hasRestrictedUpdates) {
      const user = await User.findById(updatedBy);
      if (!['admin', 'hr'].includes(user.role)) {
        throw new AppError('Insufficient permissions to update restricted fields', 403);
      }
    }
    
    // Update consultant
    Object.assign(consultant, updates);
    consultant.updatedBy = updatedBy;
    
    await consultant.save();
    
    // Clear cache
    await CacheService.clearPattern(`consultant:${id}:*`);
    
    logger.info(`Consultant ${id} updated by ${updatedBy}`);
    
    return consultant;
  }
  
  /**
   * Deactivate consultant
   */
  static async deactivateConsultant(id, reason, deactivatedBy) {
    const consultant = await Consultant.findById(id);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Check for active projects
    const activeProjects = await Project.find({
      'team.members.consultant': id,
      status: 'active'
    });
    
    if (activeProjects.length > 0) {
      throw new AppError('Cannot deactivate consultant with active projects', 400);
    }
    
    consultant.status.isActive = false;
    consultant.status.deactivatedDate = new Date();
    consultant.status.deactivatedBy = deactivatedBy;
    consultant.status.deactivationReason = reason;
    consultant.employment.status = 'terminated';
    
    await consultant.save();
    
    // Update user status
    await User.findByIdAndUpdate(consultant.userId, { isActive: false });
    
    // Send notification
    await EmailService.sendConsultantDeactivation(consultant.contactInfo.email.work, {
      name: consultant.fullName,
      reason
    });
    
    logger.warn(`Consultant ${id} deactivated`, { reason, deactivatedBy });
    
    return consultant;
  }
  
  /**
   * Find available consultants for project staffing
   */
  static async findAvailableConsultants(criteria) {
    const { dateRange, skills, minAllocation, location } = criteria;
    
    const query = {
      'status.isActive': true,
      'employment.status': 'active',
      'professional.travelPreference.willingToTravel': true
    };
    
    if (skills && skills.length > 0) {
      query['skills.name'] = { $in: skills };
    }
    
    if (location) {
      query.$or = [
        { 'contactInfo.address.current.city': location },
        { 'professional.travelPreference.preferredLocations': location }
      ];
    }
    
    const consultants = await Consultant.find(query)
      .populate('userId', 'email')
      .populate('availability.projects.project', 'name endDate')
      .lean();
    
    // Filter by availability
    const availableConsultants = consultants.filter(consultant => {
      const utilization = consultant.availability?.summary?.utilizationPercentage || 0;
      const hasCapacity = utilization <= (100 - minAllocation);
      
      if (!hasCapacity) return false;
      
      // Check date conflicts
      if (dateRange && consultant.availability?.projects) {
        const hasConflict = consultant.availability.projects.some(project => {
          if (project.status !== 'active' && project.status !== 'confirmed') return false;
          
          const projectEnd = project.endDate || new Date('2099-12-31');
          const projectStart = project.startDate;
          
          return (projectStart <= dateRange.end && projectEnd >= dateRange.start);
        });
        
        if (hasConflict && utilization + minAllocation > 100) return false;
      }
      
      return true;
    });
    
    return availableConsultants;
  }
  
  /**
   * Get consultants by skill
   */
  static async getConsultantsBySkill(skillName, minLevel = 3) {
    const consultants = await Consultant.find({
      'status.isActive': true,
      'skills.name': skillName,
      'skills.level': { $gte: minLevel }
    })
    .populate('userId', 'email')
    .select('personalInfo professional skills availability')
    .lean();
    
    // Sort by skill level
    consultants.sort((a, b) => {
      const skillA = a.skills.find(s => s.name === skillName);
      const skillB = b.skills.find(s => s.name === skillName);
      return (skillB?.level || 0) - (skillA?.level || 0);
    });
    
    return consultants;
  }
  
  /**
   * Get consultants by department
   */
  static async getConsultantsByDepartment(department, includeInactive = false) {
    const query = {
      'professional.department': department
    };
    
    if (!includeInactive) {
      query['status.isActive'] = true;
    }
    
    return await Consultant.find(query)
      .populate('userId', 'email')
      .populate('employment.reportingTo.primary', 'firstName lastName')
      .select('personalInfo professional employment status')
      .sort('professional.role personalInfo.lastName')
      .lean();
  }
  
  /**
   * Skills Management
   */
  static async getConsultantSkills(consultantId, filters = {}) {
    const consultant = await Consultant.findById(consultantId)
      .select('skills')
      .populate('skills.endorsements.endorser', 'firstName lastName')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    let skills = consultant.skills;
    
    if (filters.category) {
      skills = skills.filter(skill => skill.category === filters.category);
    }
    
    if (filters.verified !== undefined) {
      skills = skills.filter(skill => skill.verified === (filters.verified === 'true'));
    }
    
    return skills;
  }
  
  static async addSkill(consultantId, skillData, addedBy) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Check if skill already exists
    const existingSkill = consultant.skills.find(s => 
      s.name === skillData.name && s.category === skillData.category
    );
    
    if (existingSkill) {
      throw new AppError('Skill already exists', 400);
    }
    
    consultant.skills.push({
      ...skillData,
      lastAssessed: new Date()
    });
    
    await consultant.save();
    
    logger.info(`Skill ${skillData.name} added to consultant ${consultantId}`);
    
    return consultant.skills[consultant.skills.length - 1];
  }
  
  static async updateSkill(consultantId, skillId, updates, updatedBy) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    const skill = consultant.skills.id(skillId);
    if (!skill) {
      throw new AppError('Skill not found', 404);
    }
    
    Object.assign(skill, updates);
    skill.lastAssessed = new Date();
    
    await consultant.save();
    
    return skill;
  }
  
  static async verifySkill(consultantId, skillId, verifierId, verificationData) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    const skill = consultant.skills.id(skillId);
    if (!skill) {
      throw new AppError('Skill not found', 404);
    }
    
    skill.verified = true;
    skill.verifiedBy = verifierId;
    skill.verifiedDate = new Date();
    
    if (verificationData.assessmentScore) {
      skill.assessmentScore = verificationData.assessmentScore;
    }
    
    await consultant.save();
    
    // Send notification
    await EmailService.sendSkillVerification(consultant.contactInfo.email.work, {
      consultantName: consultant.fullName,
      skillName: skill.name,
      level: skill.level
    });
    
    return skill;
  }
  
  /**
   * Certification Management
   */
  static async getConsultantCertifications(consultantId, activeOnly = true) {
    const consultant = await Consultant.findById(consultantId)
      .select('certifications')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    let certifications = consultant.certifications;
    
    if (activeOnly) {
      certifications = certifications.filter(cert => cert.isActive);
    }
    
    return certifications;
  }
  
  static async addCertification(consultantId, certificationData) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    consultant.certifications.push(certificationData);
    await consultant.save();
    
    // Update related skills
    if (certificationData.relatedSkills) {
      for (const skillName of certificationData.relatedSkills) {
        const skill = consultant.skills.find(s => s.name === skillName);
        if (skill) {
          skill.lastAssessed = new Date();
          skill.trainingCompleted.push({
            name: certificationData.name,
            provider: certificationData.issuingOrganization,
            date: certificationData.issueDate,
            certificateUrl: certificationData.documentUrl
          });
        }
      }
      await consultant.save();
    }
    
    return consultant.certifications[consultant.certifications.length - 1];
  }
  
  static async updateCertification(consultantId, certificationId, updates) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    const certification = consultant.certifications.id(certificationId);
    if (!certification) {
      throw new AppError('Certification not found', 404);
    }
    
    Object.assign(certification, updates);
    
    // Check expiry
    if (certification.expiryDate && new Date(certification.expiryDate) < new Date()) {
      certification.isActive = false;
    }
    
    await consultant.save();
    
    return certification;
  }
  
  /**
   * Availability Management
   */
  static async getAvailability(consultantId, dateRange) {
    const consultant = await Consultant.findById(consultantId)
      .select('availability')
      .populate('availability.projects.project', 'name code client')
      .populate('availability.currentAssignment.project', 'name code client')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    let availability = consultant.availability;
    
    // Filter calendar by date range if provided
    if (dateRange && availability.calendar) {
      availability.calendar = availability.calendar.filter(day => 
        day.date >= dateRange.startDate && day.date <= dateRange.endDate
      );
    }
    
    return availability;
  }
  
  static async updateAvailability(consultantId, availabilityData, updatedBy) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Update availability
    Object.assign(consultant.availability, availabilityData);
    
    // Recalculate utilization
    consultant.availability.summary.lastUpdated = new Date();
    consultant.availability.summary.utilizationPercentage = this.calculateUtilization(consultant.availability);
    
    await consultant.save();
    
    // Clear cache
    await CacheService.clearPattern(`consultant:${consultantId}:availability:*`);
    
    return consultant.availability;
  }
  
  static async getConsultantSchedule(consultantId, { month, year }) {
    const startDate = new Date(year, month - 1, 1);
    const endDate = new Date(year, month, 0);
    
    const consultant = await Consultant.findById(consultantId)
      .select('availability personalInfo')
      .populate({
        path: 'availability.projects.project',
        select: 'name code client timeline milestones'
      })
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Build calendar view
    const schedule = [];
    for (let day = 1; day <= endDate.getDate(); day++) {
      const date = new Date(year, month - 1, day);
      const daySchedule = {
        date,
        dayOfWeek: date.getDay(),
        isWeekend: date.getDay() === 0 || date.getDay() === 6,
        activities: [],
        totalHours: 0,
        availableHours: 8
      };
      
      // Add project activities
      consultant.availability?.projects?.forEach(project => {
        if (project.startDate <= date && (!project.endDate || project.endDate >= date)) {
          daySchedule.activities.push({
            type: 'project',
            name: project.project?.name,
            hours: 8 * (project.allocation / 100),
            billable: project.billable
          });
          daySchedule.totalHours += 8 * (project.allocation / 100);
        }
      });
      
      // Add time off
      consultant.availability?.upcomingTimeOff?.forEach(timeOff => {
        if (timeOff.startDate <= date && timeOff.endDate >= date && timeOff.approved) {
          daySchedule.activities.push({
            type: 'timeoff',
            name: timeOff.type,
            hours: 8,
            billable: false
          });
          daySchedule.totalHours = 8;
          daySchedule.availableHours = 0;
        }
      });
      
      daySchedule.availableHours = Math.max(0, 8 - daySchedule.totalHours);
      schedule.push(daySchedule);
    }
    
    return {
      consultant: {
        id: consultant._id,
        name: consultant.fullName
      },
      month,
      year,
      schedule,
      summary: {
        totalDays: schedule.length,
        workingDays: schedule.filter(d => !d.isWeekend).length,
        billableHours: schedule.reduce((sum, d) => 
          sum + d.activities.filter(a => a.billable).reduce((h, a) => h + a.hours, 0), 0
        ),
        totalHours: schedule.reduce((sum, d) => sum + d.totalHours, 0),
        utilization: Math.round(
          (schedule.reduce((sum, d) => sum + d.totalHours, 0) / 
          (schedule.filter(d => !d.isWeekend).length * 8)) * 100
        )
      }
    };
  }
  
  static async bookConsultant(consultantId, bookingData, bookedBy) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Validate availability
    const isAvailable = await this.checkAvailability(
      consultant,
      bookingData.startDate,
      bookingData.endDate,
      bookingData.allocation
    );
    
    if (!isAvailable) {
      throw new AppError('Consultant not available for the requested period', 400);
    }
    
    // Add to projects
    consultant.availability.projects.push({
      project: bookingData.projectId,
      client: bookingData.clientId,
      allocation: bookingData.allocation,
      startDate: bookingData.startDate,
      endDate: bookingData.endDate,
      status: bookingData.tentative ? 'tentative' : 'confirmed',
      billable: bookingData.billable !== false,
      role: bookingData.role,
      responsibilities: bookingData.responsibilities
    });
    
    // Update current assignment if needed
    if (!consultant.availability.currentAssignment || bookingData.isPrimary) {
      consultant.availability.currentAssignment = {
        project: bookingData.projectId,
        client: bookingData.clientId,
        role: bookingData.role,
        allocation: bookingData.allocation,
        startDate: bookingData.startDate,
        endDate: bookingData.endDate,
        billable: bookingData.billable !== false
      };
    }
    
    // Update utilization
    consultant.availability.summary.utilizationPercentage = this.calculateUtilization(consultant.availability);
    consultant.availability.summary.lastUpdated = new Date();
    
    await consultant.save();
    
    // Send notification
    await EmailService.sendProjectAssignment(consultant.contactInfo.email.work, {
      consultantName: consultant.fullName,
      projectName: bookingData.projectName,
      startDate: bookingData.startDate,
      role: bookingData.role
    });
    
    logger.info(`Consultant ${consultantId} booked for project ${bookingData.projectId}`);
    
    return consultant.availability;
  }
  
  /**
   * Performance Management
   */
  static async getPerformanceReviews(consultantId, filters = {}) {
    const consultant = await Consultant.findById(consultantId)
      .select('performance')
      .populate('performance.reviews.reviewer.primary', 'firstName lastName')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    let reviews = consultant.performance.reviews;
    
    if (filters.year) {
      reviews = reviews.filter(review => review.year === parseInt(filters.year));
    }
    
    if (filters.period) {
      reviews = reviews.filter(review => review.period === filters.period);
    }
    
    return reviews;
  }
  
  static async createPerformanceReview(consultantId, reviewData, createdBy) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Check for existing review
    const existingReview = consultant.performance.reviews.find(r => 
      r.year === reviewData.year && r.period === reviewData.period
    );
    
    if (existingReview) {
      throw new AppError('Review already exists for this period', 400);
    }
    
    const review = {
      ...reviewData,
      reviewer: {
        primary: createdBy,
        reviewDate: new Date()
      },
      status: 'self_assessment'
    };
    
    consultant.performance.reviews.push(review);
    
    // Update current rating if this is the latest review
    if (reviewData.ratings.overall) {
      consultant.performance.currentRating = {
        overall: reviewData.ratings.overall,
        trend: this.calculateRatingTrend(consultant.performance.reviews),
        lastUpdated: new Date()
      };
    }
    
    await consultant.save();
    
    // Send notification for self assessment
    await EmailService.sendPerformanceReviewNotification(consultant.contactInfo.email.work, {
      consultantName: consultant.fullName,
      reviewPeriod: `${reviewData.period} ${reviewData.year}`,
      dueDate: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000) // 14 days
    });
    
    return consultant.performance.reviews[consultant.performance.reviews.length - 1];
  }
  
  static async updatePerformanceReview(consultantId, reviewId, updates, updatedBy) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    const review = consultant.performance.reviews.id(reviewId);
    if (!review) {
      throw new AppError('Review not found', 404);
    }
    
    Object.assign(review, updates);
    
    // Update status based on completeness
    if (review.selfAssessment.submitted && review.ratings.overall) {
      review.status = 'calibration';
    }
    
    await consultant.save();
    
    return review;
  }
  
  static async submitSelfAssessment(consultantId, reviewId, assessment) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    const review = consultant.performance.reviews.id(reviewId);
    if (!review) {
      throw new AppError('Review not found', 404);
    }
    
    review.selfAssessment = {
      submitted: true,
      submittedDate: new Date(),
      ...assessment
    };
    
    review.status = 'manager_review';
    
    await consultant.save();
    
    // Notify manager
    const manager = await User.findById(consultant.employment.reportingTo.primary);
    if (manager) {
      await EmailService.sendManagerReviewNotification(manager.email, {
        consultantName: consultant.fullName,
        reviewPeriod: `${review.period} ${review.year}`
      });
    }
    
    return review;
  }
  
  /**
   * Experience Management
   */
  static async getConsultantExperience(consultantId) {
    const consultant = await Consultant.findById(consultantId)
      .select('experience education')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    return {
      experience: consultant.experience,
      education: consultant.education
    };
  }
  
  static async addExperience(consultantId, experienceData) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    consultant.experience.previous.push(experienceData);
    
    // Recalculate total years
    let totalMonths = 0;
    consultant.experience.previous.forEach(exp => {
      if (exp.startDate && exp.endDate) {
        const months = (exp.endDate - exp.startDate) / (1000 * 60 * 60 * 24 * 30);
        totalMonths += months;
      }
    });
    consultant.experience.totalYears = Math.round((totalMonths / 12) * 10) / 10;
    
    await consultant.save();
    
    return consultant.experience.previous[consultant.experience.previous.length - 1];
  }
  
  /**
   * Reporting and Analytics
   */
  static async generateUtilizationReport(options) {
    const { startDate, endDate, groupBy = 'department' } = options;
    
    const pipeline = [
      {
        $match: {
          'status.isActive': true,
          'employment.status': 'active'
        }
      },
      {
        $group: {
          _id: `$professional.${groupBy}`,
          avgUtilization: { $avg: '$availability.summary.utilizationPercentage' },
          totalConsultants: { $sum: 1 },
          billableConsultants: {
            $sum: { $cond: ['$availability.currentAssignment.billable', 1, 0] }
          },
          totalCapacity: { $sum: 8 }, // Assuming 8 hours per day
          bookedHours: { $sum: '$availability.summary.billableHours' }
        }
      },
      {
        $project: {
          group: '$_id',
          metrics: {
            averageUtilization: { $round: ['$avgUtilization', 1] },
            totalConsultants: 1,
            billableConsultants: 1,
            billablePercentage: {
              $round: [
                { $multiply: [{ $divide: ['$billableConsultants', '$totalConsultants'] }, 100] },
                1
              ]
            },
            capacityHours: { $multiply: ['$totalCapacity', 20, 8] }, // 20 working days
            bookedHours: 1,
            availableHours: { $subtract: ['$capacityHours', '$bookedHours'] }
          }
        }
      },
      {
        $sort: { 'metrics.averageUtilization': -1 }
      }
    ];
    
    const results = await Consultant.aggregate(pipeline);
    
    return {
      period: { startDate, endDate },
      groupBy,
      data: results,
      summary: {
        totalGroups: results.length,
        overallUtilization: Math.round(
          results.reduce((sum, r) => sum + r.metrics.averageUtilization, 0) / results.length
        ),
        totalConsultants: results.reduce((sum, r) => sum + r.metrics.totalConsultants, 0),
        totalBillable: results.reduce((sum, r) => sum + r.metrics.billableConsultants, 0)
      }
    };
  }
  
  static async getSkillsInventory(filters = {}) {
    const pipeline = [
      {
        $match: {
          'status.isActive': true
        }
      },
      {
        $unwind: '$skills'
      }
    ];
    
    if (filters.category) {
      pipeline.push({
        $match: { 'skills.category': filters.category }
      });
    }
    
    if (filters.minLevel) {
      pipeline.push({
        $match: { 'skills.level': { $gte: filters.minLevel } }
      });
    }
    
    pipeline.push(
      {
        $group: {
          _id: {
            category: '$skills.category',
            name: '$skills.name'
          },
          count: { $sum: 1 },
          avgLevel: { $avg: '$skills.level' },
          avgExperience: { $avg: '$skills.yearsExperience' },
          consultants: {
            $push: {
              id: '$_id',
              name: '$fullName',
              level: '$skills.level',
              verified: '$skills.verified'
            }
          }
        }
      },
      {
        $sort: { count: -1, avgLevel: -1 }
      },
      {
        $group: {
          _id: '$_id.category',
          skills: {
            $push: {
              name: '$_id.name',
              count: '$count',
              avgLevel: { $round: ['$avgLevel', 1] },
              avgExperience: { $round: ['$avgExperience', 1] },
              consultants: '$consultants'
            }
          },
          totalSkills: { $sum: 1 },
          totalConsultants: { $sum: '$count' }
        }
      }
    );
    
    const results = await Consultant.aggregate(pipeline);
    
    return {
      categories: results,
      summary: {
        totalCategories: results.length,
        totalUniqueSkills: results.reduce((sum, cat) => sum + cat.totalSkills, 0),
        totalSkillInstances: results.reduce((sum, cat) => sum + cat.totalConsultants, 0)
      }
    };
  }
  
  static async getConsultantMetrics(consultantId, options) {
    const { period = 'annual', year = new Date().getFullYear() } = options;
    
    const consultant = await Consultant.findById(consultantId)
      .populate('availability.projects.project', 'name financial.revenue.recognized')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Calculate metrics based on period
    const metrics = {
      utilization: consultant.availability?.summary?.utilizationPercentage || 0,
      billableHours: consultant.availability?.summary?.billableHours || 0,
      projectsCompleted: 0,
      clientSatisfaction: 0,
      revenueGenerated: 0,
      certifications: consultant.certifications?.filter(c => c.isActive).length || 0,
      skills: consultant.skills?.length || 0,
      performanceRating: consultant.performance?.currentRating?.overall || 0
    };
    
    // Calculate project metrics
    if (consultant.availability?.projects) {
      const yearProjects = consultant.availability.projects.filter(p => {
        const projectYear = new Date(p.startDate).getFullYear();
        return projectYear === year && p.status === 'completed';
      });
      
      metrics.projectsCompleted = yearProjects.length;
      metrics.revenueGenerated = yearProjects.reduce((sum, p) => {
        const revenue = p.project?.financial?.revenue?.recognized || 0;
        const allocation = p.allocation / 100;
        return sum + (revenue * allocation);
      }, 0);
    }
    
    // Get performance metrics
    const yearReview = consultant.performance?.reviews?.find(r => r.year === year);
    if (yearReview) {
      metrics.clientSatisfaction = yearReview.metrics?.clientSatisfaction || 0;
    }
    
    return {
      consultant: {
        id: consultant._id,
        name: consultant.fullName,
        role: consultant.professional.role,
        department: consultant.professional.department
      },
      period: { type: period, year },
      metrics,
      comparison: {
        utilizationTarget: consultant.billing?.utilization?.target || 80,
        utilizationVariance: metrics.utilization - (consultant.billing?.utilization?.target || 80)
      }
    };
  }
  
  /**
   * Team and Reporting Structure
   */
  static async getConsultantTeam(consultantId) {
    const consultant = await Consultant.findById(consultantId)
      .populate('employment.team.current', 'name description members')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Get team members
    const teamMembers = await Consultant.find({
      'employment.team.current': consultant.employment?.team?.current,
      _id: { $ne: consultantId }
    })
    .select('personalInfo professional employment availability')
    .populate('userId', 'email')
    .lean();
    
    return {
      team: consultant.employment?.team?.current,
      members: teamMembers,
      reporting: {
        reportsTo: consultant.employment?.reportingTo?.primary,
        dottedLineTo: consultant.employment?.reportingTo?.dotted
      }
    };
  }
  
  static async getDirectReports(consultantId) {
    const directReports = await Consultant.find({
      'employment.reportingTo.primary': consultantId,
      'status.isActive': true
    })
    .select('personalInfo professional employment performance availability')
    .populate('userId', 'email lastLogin')
    .lean();
    
    return directReports.map(report => ({
      ...report,
      metrics: {
        utilization: report.availability?.summary?.utilizationPercentage || 0,
        performanceRating: report.performance?.currentRating?.overall || 0,
        yearsInRole: this.calculateYearsInRole(report.employment?.startDate)
      }
    }));
  }
  
  /**
   * Document Management
   */
  static async uploadDocument(consultantId, documentData) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    const document = {
      type: documentData.type,
      documentUrl: documentData.url,
      uploadedAt: new Date(),
      description: documentData.description
    };
    
    if (!consultant.documents.compliance) {
      consultant.documents.compliance = [];
    }
    
    consultant.documents.compliance.push(document);
    await consultant.save();
    
    return document;
  }
  
  static async getConsultantDocuments(consultantId, type) {
    const consultant = await Consultant.findById(consultantId)
      .select('documents')
      .lean();
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    let documents = [];
    
    // Collect all documents
    if (consultant.documents.resume?.current) {
      documents.push({
        type: 'resume',
        ...consultant.documents.resume.current
      });
    }
    
    if (consultant.documents.contracts) {
      documents = documents.concat(consultant.documents.contracts);
    }
    
    if (consultant.documents.compliance) {
      documents = documents.concat(consultant.documents.compliance);
    }
    
    // Filter by type if specified
    if (type) {
      documents = documents.filter(doc => doc.type === type);
    }
    
    return documents;
  }
  
  static async updateCompliance(consultantId, complianceData, updatedBy) {
    const consultant = await Consultant.findById(consultantId);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    if (!consultant.documents.compliance) {
      consultant.documents.compliance = [];
    }
    
    consultant.documents.compliance.push({
      ...complianceData,
      completedDate: new Date()
    });
    
    await consultant.save();
    
    logger.info(`Compliance updated for consultant ${consultantId}`, complianceData);
    
    return consultant.documents.compliance[consultant.documents.compliance.length - 1];
  }
  
  /**
   * Profile Generation
   */
  static async generateConsultantProfilePDF(consultant) {
    const profileData = {
      personalInfo: {
        name: consultant.fullName,
        email: consultant.contactInfo.email.work,
        phone: consultant.contactInfo.phone.mobile,
        location: `${consultant.contactInfo.address.current.city}, ${consultant.contactInfo.address.current.country}`
      },
      professional: consultant.professional,
      skills: consultant.skills.filter(s => s.verified),
      certifications: consultant.certifications.filter(c => c.isActive),
      experience: consultant.experience,
      education: consultant.education,
      performance: consultant.performance.currentRating
    };
    
    return await generatePDF('consultant-profile', profileData);
  }
  
  /**
   * Utility Methods
   */
  static calculateUtilization(availability) {
    if (!availability || !availability.projects) return 0;
    
    const activeProjects = availability.projects.filter(p => 
      p.status === 'active' || p.status === 'confirmed'
    );
    
    const totalAllocation = activeProjects.reduce((sum, p) => sum + p.allocation, 0);
    return Math.min(100, totalAllocation);
  }
  
  static calculateRatingTrend(reviews) {
    if (!reviews || reviews.length < 2) return 'stable';
    
    const sortedReviews = reviews
      .filter(r => r.ratings?.overall)
      .sort((a, b) => new Date(b.endDate) - new Date(a.endDate));
    
    if (sortedReviews.length < 2) return 'stable';
    
    const latestRating = sortedReviews[0].ratings.overall;
    const previousRating = sortedReviews[1].ratings.overall;
    
    if (latestRating > previousRating) return 'improving';
    if (latestRating < previousRating) return 'declining';
    return 'stable';
  }
  
  static calculateYearsInRole(startDate) {
    if (!startDate) return 0;
    const years = (new Date() - new Date(startDate)) / (1000 * 60 * 60 * 24 * 365);
    return Math.round(years * 10) / 10;
  }
  
  static async checkAvailability(consultant, startDate, endDate, requiredAllocation) {
    const conflicts = consultant.availability?.projects?.filter(project => {
      if (project.status !== 'active' && project.status !== 'confirmed') return false;
      
      const projectEnd = project.endDate || new Date('2099-12-31');
      const hasDateOverlap = project.startDate <= endDate && projectEnd >= startDate;
      
      return hasDateOverlap;
    });
    
    if (!conflicts || conflicts.length === 0) return true;
    
    const maxAllocationDuringPeriod = Math.max(
      ...conflicts.map(p => p.allocation)
    );
    
    return (maxAllocationDuringPeriod + requiredAllocation) <= 100;
  }
  
  static getLimitedProfile(consultant) {
    return {
      _id: consultant._id,
      personalInfo: {
        firstName: consultant.personalInfo.firstName,
        lastName: consultant.personalInfo.lastName,
        preferredName: consultant.personalInfo.preferredName
      },
      professional: {
        role: consultant.professional.role,
        department: consultant.professional.department,
        specialization: consultant.professional.specialization
      },
      contactInfo: {
        email: { work: consultant.contactInfo.email.work }
      },
      availability: {
        summary: consultant.availability?.summary
      }
    };
  }
}

module.exports = ConsultantService;