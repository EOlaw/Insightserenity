/**
 * @file Consultant Controller
 * @description Business logic for consultant management operations
 * @version 2.0.0
 */

const ConsultantService = require('../services/consultant-service');
const { AppError } = require('../../../shared/utils/errors');
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { successResponse } = require('../../../shared/utils/helpers/response-helper');
const logger = require('../../../shared/utils/logger');
const { exportToExcel, exportToPDF } = require('../../../shared/utils/export');

/**
 * Consultant Controller Class
 */
class ConsultantController {
  /**
   * Search consultants with advanced filters
   */
  static searchConsultants = asyncHandler(async (req, res) => {
    const { skills, availability, department, role, industries, minRating, location, clearance } = req.body;
    const { page = 1, limit = 20, sort = '-availability.summary.utilizationPercentage' } = req.query;
    
    const searchCriteria = {
      skills,
      availability,
      department,
      role,
      industries,
      minRating,
      location,
      clearance
    };
    
    const results = await ConsultantService.searchConsultants(searchCriteria, {
      page: parseInt(page),
      limit: parseInt(limit),
      sort
    });
    
    logger.info(`Consultant search performed by ${req.user.id}`, { criteria: searchCriteria });
    
    return successResponse(res, 'Consultants retrieved successfully', results);
  });
  
  /**
   * Get all consultants
   */
  static getAllConsultants = asyncHandler(async (req, res) => {
    const { page = 1, limit = 20, sort = '-createdAt', filter = {} } = req.query;
    
    const consultants = await ConsultantService.getAllConsultants({
      page: parseInt(page),
      limit: parseInt(limit),
      sort,
      filter
    });
    
    return successResponse(res, 'Consultants retrieved successfully', consultants);
  });
  
  /**
   * Create new consultant profile
   */
  static createConsultant = asyncHandler(async (req, res) => {
    const consultantData = req.body;
    
    if (req.file) {
      consultantData.documents = {
        resume: {
          current: {
            url: req.file.path,
            uploadedAt: new Date(),
            version: 1
          }
        }
      };
    }
    
    const consultant = await ConsultantService.createConsultant(consultantData, req.user.id);
    
    logger.info(`New consultant created: ${consultant.employeeId} by ${req.user.id}`);
    
    return successResponse(res, 'Consultant created successfully', consultant, 201);
  });
  
  /**
   * Get consultant by ID
   */
  static getConsultantById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const includeOptions = req.query.include ? req.query.include.split(',') : [];
    
    const consultant = await ConsultantService.getConsultantById(id, includeOptions);
    
    if (!consultant) {
      throw new AppError('Consultant not found', 404);
    }
    
    // Check access permissions
    const canViewFullProfile = ['admin', 'hr', 'manager'].includes(req.user.role) || 
                              consultant.userId.toString() === req.user.id;
    
    if (!canViewFullProfile) {
      // Return limited profile for other consultants
      const limitedProfile = ConsultantService.getLimitedProfile(consultant);
      return successResponse(res, 'Consultant profile retrieved successfully', limitedProfile);
    }
    
    return successResponse(res, 'Consultant profile retrieved successfully', consultant);
  });
  
  /**
   * Update consultant profile
   */
  static updateConsultant = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    // Check if user can update this profile
    const consultant = await ConsultantService.getConsultantById(id);
    const canUpdate = ['admin', 'hr'].includes(req.user.role) || 
                     consultant.userId.toString() === req.user.id;
    
    if (!canUpdate) {
      throw new AppError('Unauthorized to update this profile', 403);
    }
    
    // Handle file uploads
    if (req.files) {
      if (req.files.resume) {
        updates.resumeUrl = req.files.resume[0].path;
      }
      if (req.files.certifications) {
        updates.certificationDocs = req.files.certifications.map(file => file.path);
      }
    }
    
    const updatedConsultant = await ConsultantService.updateConsultant(id, updates, req.user.id);
    
    logger.info(`Consultant ${id} updated by ${req.user.id}`);
    
    return successResponse(res, 'Consultant updated successfully', updatedConsultant);
  });
  
  /**
   * Deactivate consultant
   */
  static deactivateConsultant = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    
    const result = await ConsultantService.deactivateConsultant(id, reason, req.user.id);
    
    logger.warn(`Consultant ${id} deactivated by ${req.user.id}`, { reason });
    
    return successResponse(res, 'Consultant deactivated successfully', result);
  });
  
  /**
   * Get available consultants for project staffing
   */
  static getAvailableConsultants = asyncHandler(async (req, res) => {
    const { startDate, endDate, skills, minAllocation = 20, location } = req.query;
    
    const criteria = {
      dateRange: { start: new Date(startDate), end: new Date(endDate) },
      skills: skills ? skills.split(',') : undefined,
      minAllocation: parseInt(minAllocation),
      location
    };
    
    const consultants = await ConsultantService.findAvailableConsultants(criteria);
    
    return successResponse(res, 'Available consultants retrieved successfully', consultants);
  });
  
  /**
   * Get consultants by skill
   */
  static getConsultantsBySkill = asyncHandler(async (req, res) => {
    const { skillName } = req.params;
    const { minLevel = 3 } = req.query;
    
    const consultants = await ConsultantService.getConsultantsBySkill(skillName, parseInt(minLevel));
    
    return successResponse(res, 'Consultants retrieved successfully', consultants);
  });
  
  /**
   * Get consultants by department
   */
  static getConsultantsByDepartment = asyncHandler(async (req, res) => {
    const { department } = req.params;
    const { includeInactive = false } = req.query;
    
    const consultants = await ConsultantService.getConsultantsByDepartment(
      department, 
      includeInactive === 'true'
    );
    
    return successResponse(res, 'Consultants retrieved successfully', consultants);
  });
  
  /**
   * Skills Management
   */
  static getConsultantSkills = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { category, verified } = req.query;
    
    const skills = await ConsultantService.getConsultantSkills(id, { category, verified });
    
    return successResponse(res, 'Skills retrieved successfully', skills);
  });
  
  static addSkill = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const skillData = req.body;
    
    const result = await ConsultantService.addSkill(id, skillData, req.user.id);
    
    logger.info(`Skill added to consultant ${id} by ${req.user.id}`, { skill: skillData.name });
    
    return successResponse(res, 'Skill added successfully', result);
  });
  
  static updateSkill = asyncHandler(async (req, res) => {
    const { id, skillId } = req.params;
    const updates = req.body;
    
    const result = await ConsultantService.updateSkill(id, skillId, updates, req.user.id);
    
    return successResponse(res, 'Skill updated successfully', result);
  });
  
  static verifySkill = asyncHandler(async (req, res) => {
    const { id, skillId } = req.params;
    const { assessmentScore, comments } = req.body;
    
    const result = await ConsultantService.verifySkill(
      id, 
      skillId, 
      req.user.id, 
      { assessmentScore, comments }
    );
    
    logger.info(`Skill ${skillId} verified for consultant ${id} by ${req.user.id}`);
    
    return successResponse(res, 'Skill verified successfully', result);
  });
  
  /**
   * Certification Management
   */
  static getConsultantCertifications = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { active = true } = req.query;
    
    const certifications = await ConsultantService.getConsultantCertifications(
      id, 
      active === 'true'
    );
    
    return successResponse(res, 'Certifications retrieved successfully', certifications);
  });
  
  static addCertification = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const certificationData = req.body;
    
    if (req.file) {
      certificationData.documentUrl = req.file.path;
    }
    
    const result = await ConsultantService.addCertification(id, certificationData);
    
    logger.info(`Certification added to consultant ${id}`, { certification: certificationData.name });
    
    return successResponse(res, 'Certification added successfully', result);
  });
  
  static updateCertification = asyncHandler(async (req, res) => {
    const { id, certificationId } = req.params;
    const updates = req.body;
    
    const result = await ConsultantService.updateCertification(id, certificationId, updates);
    
    return successResponse(res, 'Certification updated successfully', result);
  });
  
  /**
   * Availability and Scheduling
   */
  static getAvailability = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { startDate, endDate } = req.query;
    
    const availability = await ConsultantService.getAvailability(id, {
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined
    });
    
    return successResponse(res, 'Availability retrieved successfully', availability);
  });
  
  static updateAvailability = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const availabilityData = req.body;
    
    const result = await ConsultantService.updateAvailability(id, availabilityData, req.user.id);
    
    return successResponse(res, 'Availability updated successfully', result);
  });
  
  static getSchedule = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { month, year } = req.query;
    
    const schedule = await ConsultantService.getConsultantSchedule(id, {
      month: parseInt(month),
      year: parseInt(year)
    });
    
    return successResponse(res, 'Schedule retrieved successfully', schedule);
  });
  
  static bookConsultant = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const bookingData = req.body;
    
    const result = await ConsultantService.bookConsultant(id, bookingData, req.user.id);
    
    logger.info(`Consultant ${id} booked by ${req.user.id}`, { booking: bookingData });
    
    return successResponse(res, 'Consultant booked successfully', result);
  });
  
  /**
   * Performance Management
   */
  static getPerformanceReviews = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { year, period } = req.query;
    
    const reviews = await ConsultantService.getPerformanceReviews(id, { year, period });
    
    return successResponse(res, 'Performance reviews retrieved successfully', reviews);
  });
  
  static createPerformanceReview = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const reviewData = req.body;
    
    const review = await ConsultantService.createPerformanceReview(
      id, 
      reviewData, 
      req.user.id
    );
    
    logger.info(`Performance review created for consultant ${id} by ${req.user.id}`);
    
    return successResponse(res, 'Performance review created successfully', review);
  });
  
  static updatePerformanceReview = asyncHandler(async (req, res) => {
    const { id, reviewId } = req.params;
    const updates = req.body;
    
    const result = await ConsultantService.updatePerformanceReview(
      id, 
      reviewId, 
      updates, 
      req.user.id
    );
    
    return successResponse(res, 'Performance review updated successfully', result);
  });
  
  static submitSelfAssessment = asyncHandler(async (req, res) => {
    const { id, reviewId } = req.params;
    const assessment = req.body;
    
    // Verify consultant is submitting their own assessment
    const consultant = await ConsultantService.getConsultantById(id);
    if (consultant.userId.toString() !== req.user.id) {
      throw new AppError('Unauthorized to submit assessment for another consultant', 403);
    }
    
    const result = await ConsultantService.submitSelfAssessment(id, reviewId, assessment);
    
    return successResponse(res, 'Self assessment submitted successfully', result);
  });
  
  /**
   * Experience Management
   */
  static getExperience = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const experience = await ConsultantService.getConsultantExperience(id);
    
    return successResponse(res, 'Experience retrieved successfully', experience);
  });
  
  static addExperience = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const experienceData = req.body;
    
    const result = await ConsultantService.addExperience(id, experienceData);
    
    return successResponse(res, 'Experience added successfully', result);
  });
  
  /**
   * Reporting and Analytics
   */
  static getUtilizationReport = asyncHandler(async (req, res) => {
    const { startDate, endDate, groupBy = 'department' } = req.query;
    
    const report = await ConsultantService.generateUtilizationReport({
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      groupBy
    });
    
    return successResponse(res, 'Utilization report generated successfully', report);
  });
  
  static getSkillsInventory = asyncHandler(async (req, res) => {
    const { category, minLevel } = req.query;
    
    const inventory = await ConsultantService.getSkillsInventory({
      category,
      minLevel: minLevel ? parseInt(minLevel) : undefined
    });
    
    return successResponse(res, 'Skills inventory retrieved successfully', inventory);
  });
  
  static getConsultantMetrics = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { period = 'annual', year = new Date().getFullYear() } = req.query;
    
    const metrics = await ConsultantService.getConsultantMetrics(id, {
      period,
      year: parseInt(year)
    });
    
    return successResponse(res, 'Consultant metrics retrieved successfully', metrics);
  });
  
  /**
   * Team and Reporting Structure
   */
  static getConsultantTeam = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const team = await ConsultantService.getConsultantTeam(id);
    
    return successResponse(res, 'Team information retrieved successfully', team);
  });
  
  static getDirectReports = asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const reports = await ConsultantService.getDirectReports(id);
    
    return successResponse(res, 'Direct reports retrieved successfully', reports);
  });
  
  /**
   * Documents and Compliance
   */
  static uploadDocument = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { type, description } = req.body;
    
    if (!req.file) {
      throw new AppError('No file uploaded', 400);
    }
    
    const result = await ConsultantService.uploadDocument(id, {
      type,
      description,
      url: req.file.path,
      uploadedBy: req.user.id
    });
    
    return successResponse(res, 'Document uploaded successfully', result);
  });
  
  static getDocuments = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { type } = req.query;
    
    const documents = await ConsultantService.getConsultantDocuments(id, type);
    
    return successResponse(res, 'Documents retrieved successfully', documents);
  });
  
  static updateCompliance = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const complianceData = req.body;
    
    const result = await ConsultantService.updateCompliance(id, complianceData, req.user.id);
    
    logger.info(`Compliance updated for consultant ${id} by ${req.user.id}`);
    
    return successResponse(res, 'Compliance updated successfully', result);
  });
  
  /**
   * Export Functionality
   */
  static exportConsultants = asyncHandler(async (req, res) => {
    const { format = 'excel', filter = {} } = req.query;
    
    const consultants = await ConsultantService.getAllConsultants({ filter, limit: 10000 });
    
    let exportData;
    if (format === 'excel') {
      exportData = await exportToExcel(consultants.data, 'consultants');
    } else if (format === 'pdf') {
      exportData = await exportToPDF(consultants.data, 'consultants');
    } else {
      throw new AppError('Invalid export format', 400);
    }
    
    res.setHeader('Content-Type', exportData.contentType);
    res.setHeader('Content-Disposition', `attachment; filename=${exportData.filename}`);
    
    return res.send(exportData.buffer);
  });
  
  static exportConsultantProfile = asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { format = 'pdf' } = req.query;
    
    const consultant = await ConsultantService.getConsultantById(id, ['all']);
    
    let exportData;
    if (format === 'pdf') {
      exportData = await ConsultantService.generateConsultantProfilePDF(consultant);
    } else {
      throw new AppError('Invalid export format for profile', 400);
    }
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=consultant-${consultant.employeeId}.pdf`);
    
    return res.send(exportData);
  });
}

module.exports = ConsultantController;