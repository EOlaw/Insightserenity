/**
 * @file Consultant Model
 * @description Comprehensive model for managing consultants and their professional information
 * @version 2.0.0
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

// Import sub-schemas
const skillSchema = require('./schemas/skill-schema');
const certificationSchema = require('./schemas/certification-schema');
const experienceSchema = require('./schemas/experience-schema');
const availabilitySchema = require('./schemas/availability-schema');
const performanceSchema = require('./schemas/performance-schema');

/**
 * Consultant Schema
 * Core schema for managing consultant profiles and capabilities
 */
const consultantSchema = new Schema({
  // User Reference
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  
  // Basic Information
  employeeId: {
    type: String,
    unique: true,
    required: true,
    match: [/^EMP-\d{6}$/, 'Employee ID must follow format EMP-XXXXXX']
  },
  personalInfo: {
    firstName: { 
      type: String, 
      required: true, 
      trim: true,
      maxlength: [50, 'First name cannot exceed 50 characters']
    },
    lastName: { 
      type: String, 
      required: true, 
      trim: true,
      maxlength: [50, 'Last name cannot exceed 50 characters']
    },
    middleName: { 
      type: String, 
      trim: true,
      maxlength: [50, 'Middle name cannot exceed 50 characters']
    },
    preferredName: String,
    dateOfBirth: {
      type: Date,
      set: function(value) {
        // Store only the date part, no time
        if (value) {
          const date = new Date(value);
          date.setHours(0, 0, 0, 0);
          return date;
        }
        return value;
      }
    },
    gender: {
      type: String,
      enum: ['male', 'female', 'other', 'prefer_not_to_say']
    },
    nationality: String,
    languages: [{
      language: String,
      proficiency: {
        type: String,
        enum: ['native', 'fluent', 'advanced', 'intermediate', 'basic']
      }
    }]
  },
  
  // Contact Information
  contactInfo: {
    email: {
      work: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
      },
      personal: {
        type: String,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email']
      }
    },
    phone: {
      work: String,
      mobile: String,
      emergency: {
        number: String,
        relationship: String,
        name: String
      }
    },
    address: {
      current: {
        street: String,
        city: String,
        state: String,
        country: String,
        postalCode: String
      },
      permanent: {
        street: String,
        city: String,
        state: String,
        country: String,
        postalCode: String
      }
    },
    timezone: {
      type: String,
      default: 'America/New_York'
    }
  },
  
  // Professional Information
  professional: {
    role: {
      type: String,
      required: true,
      enum: ['junior_consultant', 'consultant', 'senior_consultant', 'principal_consultant', 
              'manager', 'senior_manager', 'director', 'partner']
    },
    level: {
      type: String,
      required: true,
      enum: ['entry', 'mid', 'senior', 'lead', 'principal', 'executive']
    },
    specialization: [{
      type: String,
      enum: ['strategy', 'operations', 'technology', 'finance', 'hr', 'marketing', 
              'sales', 'supply_chain', 'risk', 'change_management', 'data_analytics']
    }],
    department: {
      type: String,
      required: true,
      enum: ['consulting', 'advisory', 'implementation', 'technology', 'strategy', 'operations']
    },
    practiceArea: [{
      name: String,
      isPrimary: { type: Boolean, default: false }
    }],
    industries: [{
      name: String,
      yearsExperience: Number,
      expertise: {
        type: String,
        enum: ['basic', 'intermediate', 'advanced', 'expert']
      }
    }],
    clearanceLevel: {
      type: String,
      enum: ['none', 'public_trust', 'secret', 'top_secret', 'ts_sci']
    },
    travelPreference: {
      willingToTravel: { type: Boolean, default: true },
      maxPercentage: { type: Number, min: 0, max: 100 },
      restrictions: [String],
      preferredLocations: [String],
      blackoutDates: [{
        startDate: Date,
        endDate: Date,
        reason: String
      }]
    }
  },
  
  // Employment Details
  employment: {
    startDate: {
      type: Date,
      required: true
    },
    probationEndDate: Date,
    confirmationDate: Date,
    type: {
      type: String,
      required: true,
      enum: ['full_time', 'part_time', 'contract', 'intern']
    },
    status: {
      type: String,
      required: true,
      enum: ['active', 'on_leave', 'notice_period', 'terminated', 'retired'],
      default: 'active'
    },
    workLocation: {
      type: String,
      enum: ['office', 'remote', 'hybrid', 'client_site']
    },
    reportingTo: {
      primary: { type: Schema.Types.ObjectId, ref: 'User' },
      secondary: { type: Schema.Types.ObjectId, ref: 'User' },
      dotted: [{ type: Schema.Types.ObjectId, ref: 'User' }]
    },
    team: {
      current: { type: Schema.Types.ObjectId, ref: 'Team' },
      history: [{
        team: { type: Schema.Types.ObjectId, ref: 'Team' },
        startDate: Date,
        endDate: Date,
        role: String
      }]
    }
  },
  
  // Skills and Competencies
  skills: [skillSchema],
  
  // Certifications and Education
  certifications: [certificationSchema],
  education: [{
    degree: {
      type: String,
      required: true,
      enum: ['high_school', 'associate', 'bachelor', 'master', 'doctorate', 'professional', 'other']
    },
    field: String,
    institution: String,
    location: {
      city: String,
      country: String
    },
    startDate: Date,
    endDate: Date,
    isCompleted: { type: Boolean, default: true },
    gpa: Number,
    achievements: [String]
  }],
  
  // Experience
  experience: {
    totalYears: Number,
    consultingYears: Number,
    previous: [experienceSchema],
    internalProjects: [{
      project: { type: Schema.Types.ObjectId, ref: 'Project' },
      role: String,
      startDate: Date,
      endDate: Date,
      allocation: Number, // percentage
      responsibilities: [String],
      achievements: [String],
      clientFeedback: {
        rating: { type: Number, min: 1, max: 5 },
        comments: String
      }
    }]
  },
  
  // Billing and Financial
  billing: {
    standardRate: {
      amount: { type: Number, required: true, min: 0 },
      currency: { type: String, default: 'USD' }
    },
    rates: [{
      type: {
        type: String,
        enum: ['standard', 'overtime', 'weekend', 'holiday', 'international'],
        required: true
      },
      amount: { type: Number, required: true, min: 0 },
      currency: { type: String, default: 'USD' },
      effectiveFrom: Date,
      effectiveTo: Date
    }],
    costToCompany: {
      base: Number,
      benefits: Number,
      overhead: Number,
      total: Number,
      lastUpdated: Date
    },
    utilization: {
      target: { type: Number, min: 0, max: 100, default: 80 },
      billableHoursTarget: { type: Number, default: 1600 }, // Annual
      nonBillableAllowance: { type: Number, default: 20 } // Percentage
    }
  },
  
  // Availability and Scheduling
  availability: availabilitySchema,
  
  // Performance and Reviews
  performance: performanceSchema,
  
  // Training and Development
  development: {
    careerPath: {
      current: String,
      target: String,
      timeline: String,
      nextPromotion: {
        targetRole: String,
        targetDate: Date,
        readiness: { type: Number, min: 0, max: 100 }
      }
    },
    training: [{
      name: String,
      type: {
        type: String,
        enum: ['technical', 'soft_skills', 'leadership', 'industry', 'certification_prep']
      },
      provider: String,
      startDate: Date,
      endDate: Date,
      status: {
        type: String,
        enum: ['planned', 'in_progress', 'completed', 'cancelled']
      },
      cost: Number,
      outcome: String
    }],
    mentoring: {
      mentors: [{
        mentor: { type: Schema.Types.ObjectId, ref: 'User' },
        startDate: Date,
        endDate: Date,
        focus: String
      }],
      mentees: [{
        mentee: { type: Schema.Types.ObjectId, ref: 'User' },
        startDate: Date,
        endDate: Date,
        focus: String
      }]
    },
    goals: [{
      title: String,
      description: String,
      category: {
        type: String,
        enum: ['performance', 'skill', 'career', 'personal']
      },
      targetDate: Date,
      status: {
        type: String,
        enum: ['not_started', 'in_progress', 'completed', 'cancelled']
      },
      progress: { type: Number, min: 0, max: 100 },
      reviewNotes: String
    }]
  },
  
  // Compensation and Benefits
  compensation: {
    salary: {
      base: {
        amount: Number,
        currency: { type: String, default: 'USD' },
        effectiveDate: Date
      },
      history: [{
        amount: Number,
        currency: String,
        effectiveFrom: Date,
        effectiveTo: Date,
        reason: String,
        approvedBy: { type: Schema.Types.ObjectId, ref: 'User' }
      }]
    },
    bonus: {
      eligible: { type: Boolean, default: true },
      targetPercentage: Number,
      history: [{
        year: Number,
        amount: Number,
        percentage: Number,
        type: {
          type: String,
          enum: ['performance', 'signing', 'retention', 'spot', 'referral']
        },
        paidDate: Date
      }]
    },
    equity: {
      grants: [{
        type: {
          type: String,
          enum: ['options', 'rsu', 'shares']
        },
        quantity: Number,
        grantDate: Date,
        vestingSchedule: String,
        vestedQuantity: Number,
        exercisePrice: Number
      }]
    },
    benefits: {
      healthInsurance: {
        enrolled: { type: Boolean, default: false },
        plan: String,
        dependents: Number
      },
      retirement: {
        enrolled: { type: Boolean, default: false },
        plan: String,
        contributionPercentage: Number,
        companyMatch: Number
      },
      other: [{
        benefit: String,
        enrolled: Boolean,
        details: String
      }]
    }
  },
  
  // Leave and Time Off
  timeOff: {
    policies: [{
      type: {
        type: String,
        enum: ['vacation', 'sick', 'personal', 'parental', 'sabbatical'],
        required: true
      },
      entitlement: Number, // Days per year
      accrualRate: Number, // Days per month
      balance: Number,
      used: Number,
      carriedOver: Number,
      maxCarryOver: Number
    }],
    requests: [{
      type: String,
      startDate: Date,
      endDate: Date,
      days: Number,
      reason: String,
      status: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'cancelled']
      },
      approvedBy: { type: Schema.Types.ObjectId, ref: 'User' },
      approvedDate: Date,
      comments: String
    }]
  },
  
  // Documents and Compliance
  documents: {
    resume: {
      current: {
        url: String,
        uploadedAt: Date,
        version: Number
      },
      history: [{
        url: String,
        uploadedAt: Date,
        version: Number
      }]
    },
    contracts: [{
      type: String,
      documentUrl: String,
      signedDate: Date,
      expiryDate: Date
    }],
    compliance: [{
      type: {
        type: String,
        enum: ['background_check', 'reference_check', 'drug_test', 'security_clearance']
      },
      status: {
        type: String,
        enum: ['pending', 'passed', 'failed', 'expired']
      },
      completedDate: Date,
      expiryDate: Date,
      notes: String
    }]
  },
  
  // System Fields
  metadata: {
    source: {
      type: String,
      enum: ['manual', 'import', 'integration'],
      default: 'manual'
    },
    tags: [String],
    customFields: Schema.Types.Mixed,
    notes: [{
      content: String,
      type: {
        type: String,
        enum: ['general', 'hr', 'performance', 'incident']
      },
      visibility: {
        type: String,
        enum: ['private', 'hr_only', 'manager_only', 'public'],
        default: 'private'
      },
      createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
      createdAt: { type: Date, default: Date.now }
    }]
  },
  
  // Status tracking
  status: {
    isActive: { type: Boolean, default: true },
    lastActiveDate: Date,
    deactivatedDate: Date,
    deactivatedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    deactivationReason: String
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

/**
 * Indexes for performance
 */
consultantSchema.index({ userId: 1 });
consultantSchema.index({ employeeId: 1 });
consultantSchema.index({ 'personalInfo.firstName': 1, 'personalInfo.lastName': 1 });
consultantSchema.index({ 'contactInfo.email.work': 1 });
consultantSchema.index({ 'professional.role': 1 });
consultantSchema.index({ 'professional.department': 1 });
consultantSchema.index({ 'employment.status': 1 });
consultantSchema.index({ 'employment.reportingTo.primary': 1 });
consultantSchema.index({ 'billing.standardRate.amount': -1 });
consultantSchema.index({ 'status.isActive': 1 });
consultantSchema.index({ createdAt: -1 });

/**
 * Compound indexes
 */
consultantSchema.index({ 
  'professional.role': 1, 
  'employment.status': 1,
  'status.isActive': 1
});

consultantSchema.index({ 
  'professional.specialization': 1,
  'professional.industries.name': 1
});

consultantSchema.index({
  'skills.category': 1,
  'skills.level': 1
});

/**
 * Text search index
 */
consultantSchema.index({
  'personalInfo.firstName': 'text',
  'personalInfo.lastName': 'text',
  'contactInfo.email.work': 'text',
  'skills.name': 'text',
  'metadata.tags': 'text'
});

/**
 * Virtual properties
 */
consultantSchema.virtual('fullName').get(function() {
  const { firstName, middleName, lastName, preferredName } = this.personalInfo;
  if (preferredName) return preferredName;
  return middleName 
    ? `${firstName} ${middleName} ${lastName}`
    : `${firstName} ${lastName}`;
});

consultantSchema.virtual('yearsWithCompany').get(function() {
  if (!this.employment.startDate) return 0;
  const years = (new Date() - new Date(this.employment.startDate)) / (1000 * 60 * 60 * 24 * 365);
  return Math.round(years * 10) / 10; // Round to 1 decimal
});

consultantSchema.virtual('currentUtilization').get(function() {
  if (!this.availability || !this.availability.summary) return 0;
  return this.availability.summary.utilizationPercentage || 0;
});

consultantSchema.virtual('isBillable').get(function() {
  return this.availability && 
         this.availability.currentAssignment && 
         this.availability.currentAssignment.billable;
});

consultantSchema.virtual('nextAvailableDate').get(function() {
  if (!this.availability || !this.availability.nextAvailable) return null;
  return this.availability.nextAvailable;
});

/**
 * Pre-save middleware
 */
consultantSchema.pre('save', async function(next) {
  try {
    // Generate employee ID if not provided
    if (!this.employeeId && this.isNew) {
      const count = await this.constructor.countDocuments();
      this.employeeId = `EMP-${String(count + 1).padStart(6, '0')}`;
    }
    
    // Calculate total years of experience
    if (this.experience && this.experience.previous) {
      let totalMonths = 0;
      this.experience.previous.forEach(exp => {
        if (exp.startDate && exp.endDate) {
          const months = (exp.endDate - exp.startDate) / (1000 * 60 * 60 * 24 * 30);
          totalMonths += months;
        }
      });
      this.experience.totalYears = Math.round((totalMonths / 12) * 10) / 10;
    }
    
    // Update cost to company total
    if (this.billing && this.billing.costToCompany) {
      const { base, benefits, overhead } = this.billing.costToCompany;
      this.billing.costToCompany.total = (base || 0) + (benefits || 0) + (overhead || 0);
      this.billing.costToCompany.lastUpdated = new Date();
    }
    
    // Update leave balances
    if (this.timeOff && this.timeOff.policies) {
      this.timeOff.policies.forEach(policy => {
        policy.balance = policy.entitlement - policy.used + (policy.carriedOver || 0);
      });
    }
    
    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Instance methods
 */
consultantSchema.methods.isAvailableOn = function(date, hours = 8) {
  if (!this.availability || !this.availability.calendar) return false;
  
  const dateStr = date.toISOString().split('T')[0];
  const daySchedule = this.availability.calendar.find(cal => 
    cal.date.toISOString().split('T')[0] === dateStr
  );
  
  if (!daySchedule) return true; // No specific schedule means available
  
  const availableHours = daySchedule.availableHours || 0;
  return availableHours >= hours;
};

consultantSchema.methods.addSkill = function(skillData) {
  const existingSkill = this.skills.find(s => 
    s.name === skillData.name && s.category === skillData.category
  );
  
  if (existingSkill) {
    // Update existing skill
    existingSkill.level = skillData.level;
    existingSkill.yearsExperience = skillData.yearsExperience;
    existingSkill.lastAssessed = new Date();
  } else {
    // Add new skill
    this.skills.push({
      ...skillData,
      verifiedDate: new Date()
    });
  }
  
  return this.save();
};

consultantSchema.methods.calculateBillableHours = function(startDate, endDate) {
  if (!this.availability || !this.availability.projects) return 0;
  
  let totalHours = 0;
  this.availability.projects.forEach(project => {
    if (project.billable && 
        project.startDate <= endDate && 
        (!project.endDate || project.endDate >= startDate)) {
      
      const projectStart = project.startDate > startDate ? project.startDate : startDate;
      const projectEnd = project.endDate && project.endDate < endDate ? project.endDate : endDate;
      
      const days = (projectEnd - projectStart) / (1000 * 60 * 60 * 24);
      const workDays = days * 5 / 7; // Rough estimate excluding weekends
      totalHours += workDays * 8 * (project.allocation / 100);
    }
  });
  
  return Math.round(totalHours);
};

consultantSchema.methods.canWorkOnProject = function(projectRequirements) {
  // Check skills match
  if (projectRequirements.requiredSkills) {
    const hasRequiredSkills = projectRequirements.requiredSkills.every(reqSkill => {
      return this.skills.some(skill => 
        skill.name === reqSkill.name && 
        skill.level >= reqSkill.minLevel
      );
    });
    if (!hasRequiredSkills) return false;
  }
  
  // Check clearance level
  if (projectRequirements.clearanceRequired) {
    const clearanceLevels = ['none', 'public_trust', 'secret', 'top_secret', 'ts_sci'];
    const consultantLevel = clearanceLevels.indexOf(this.professional.clearanceLevel);
    const requiredLevel = clearanceLevels.indexOf(projectRequirements.clearanceRequired);
    if (consultantLevel < requiredLevel) return false;
  }
  
  // Check availability
  if (projectRequirements.startDate && projectRequirements.allocation) {
    const currentUtilization = this.currentUtilization || 0;
    if (currentUtilization + projectRequirements.allocation > 100) return false;
  }
  
  // Check travel willingness
  if (projectRequirements.travelPercentage > 0) {
    if (!this.professional.travelPreference.willingToTravel) return false;
    if (projectRequirements.travelPercentage > this.professional.travelPreference.maxPercentage) {
      return false;
    }
  }
  
  return true;
};

/**
 * Static methods
 */
consultantSchema.statics.findAvailableConsultants = function(criteria) {
  const query = {
    'status.isActive': true,
    'employment.status': 'active'
  };
  
  if (criteria.skills) {
    query['skills.name'] = { $in: criteria.skills };
  }
  
  if (criteria.role) {
    query['professional.role'] = criteria.role;
  }
  
  if (criteria.minUtilization !== undefined) {
    query['availability.summary.utilizationPercentage'] = { $lte: criteria.minUtilization };
  }
  
  if (criteria.department) {
    query['professional.department'] = criteria.department;
  }
  
  if (criteria.location) {
    query['contactInfo.address.current.city'] = criteria.location;
  }
  
  return this.find(query)
    .populate('userId', 'email')
    .populate('employment.reportingTo.primary', 'firstName lastName')
    .sort({ 'availability.summary.utilizationPercentage': 1 });
};

consultantSchema.statics.getUtilizationReport = async function(dateRange) {
  const pipeline = [
    {
      $match: {
        'status.isActive': true,
        'employment.status': 'active'
      }
    },
    {
      $group: {
        _id: '$professional.department',
        avgUtilization: { $avg: '$availability.summary.utilizationPercentage' },
        totalConsultants: { $sum: 1 },
        billableConsultants: {
          $sum: { $cond: ['$availability.currentAssignment.billable', 1, 0] }
        },
        totalBillableHours: { $sum: '$availability.summary.billableHours' },
        consultantsByRole: { $push: '$professional.role' }
      }
    },
    {
      $project: {
        department: '$_id',
        avgUtilization: { $round: ['$avgUtilization', 1] },
        totalConsultants: 1,
        billableConsultants: 1,
        billablePercentage: {
          $round: [
            { $multiply: [{ $divide: ['$billableConsultants', '$totalConsultants'] }, 100] },
            1
          ]
        },
        totalBillableHours: 1
      }
    }
  ];
  
  return this.aggregate(pipeline);
};

consultantSchema.statics.getSkillsInventory = async function() {
  const pipeline = [
    {
      $match: {
        'status.isActive': true
      }
    },
    {
      $unwind: '$skills'
    },
    {
      $group: {
        _id: {
          category: '$skills.category',
          name: '$skills.name'
        },
        count: { $sum: 1 },
        avgLevel: { $avg: '$skills.level' },
        consultants: {
          $push: {
            id: '$_id',
            name: '$fullName',
            level: '$skills.level'
          }
        }
      }
    },
    {
      $sort: { count: -1 }
    }
  ];
  
  return this.aggregate(pipeline);
};

const Consultant = mongoose.model('Consultant', consultantSchema);

module.exports = Consultant;