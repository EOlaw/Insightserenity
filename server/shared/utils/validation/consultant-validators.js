/**
 * @file Consultant Validators
 * @description Validation schemas for consultant-related operations
 * @version 2.0.0
 */

const Joi = require('joi');

/**
 * Common validation patterns
 */
const patterns = {
  employeeId: /^EMP-\d{6}$/,
  email: /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/,
  phone: /^[+]?[(]?[0-9]{3}[)]?[-\s.]?[0-9]{3}[-\s.]?[0-9]{4,6}$/,
  objectId: /^[0-9a-fA-F]{24}$/
};

/**
 * Common field schemas
 */
const commonFields = {
  objectId: Joi.string().pattern(patterns.objectId).required(),
  objectIdOptional: Joi.string().pattern(patterns.objectId),
  email: Joi.string().email().lowercase().trim(),
  phone: Joi.string().pattern(patterns.phone),
  date: Joi.date().iso(),
  percentage: Joi.number().min(0).max(100),
  currency: Joi.string().length(3).uppercase().default('USD'),
  rating: Joi.number().min(1).max(5)
};

/**
 * Create consultant validation schema
 */
const createConsultantSchema = Joi.object({
  body: Joi.object({
    userId: commonFields.objectId,
    
    personalInfo: Joi.object({
      firstName: Joi.string().trim().max(50).required(),
      lastName: Joi.string().trim().max(50).required(),
      middleName: Joi.string().trim().max(50),
      preferredName: Joi.string().trim().max(100),
      dateOfBirth: Joi.date().iso().max('now').required(),
      gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say'),
      nationality: Joi.string().max(100),
      languages: Joi.array().items(Joi.object({
        language: Joi.string().required(),
        proficiency: Joi.string().valid('native', 'fluent', 'advanced', 'intermediate', 'basic').required()
      }))
    }).required(),
    
    contactInfo: Joi.object({
      email: Joi.object({
        work: commonFields.email.required(),
        personal: commonFields.email
      }).required(),
      phone: Joi.object({
        work: commonFields.phone,
        mobile: commonFields.phone.required(),
        emergency: Joi.object({
          number: commonFields.phone.required(),
          relationship: Joi.string().required(),
          name: Joi.string().required()
        })
      }).required(),
      address: Joi.object({
        current: Joi.object({
          street: Joi.string().max(200),
          city: Joi.string().max(100).required(),
          state: Joi.string().max(100),
          country: Joi.string().max(100).required(),
          postalCode: Joi.string().max(20)
        }).required(),
        permanent: Joi.object({
          street: Joi.string().max(200),
          city: Joi.string().max(100),
          state: Joi.string().max(100),
          country: Joi.string().max(100),
          postalCode: Joi.string().max(20)
        })
      }).required(),
      timezone: Joi.string().default('America/New_York')
    }).required(),
    
    professional: Joi.object({
      role: Joi.string().valid(
        'junior_consultant', 'consultant', 'senior_consultant', 'principal_consultant',
        'manager', 'senior_manager', 'director', 'partner'
      ).required(),
      level: Joi.string().valid('entry', 'mid', 'senior', 'lead', 'principal', 'executive').required(),
      specialization: Joi.array().items(Joi.string().valid(
        'strategy', 'operations', 'technology', 'finance', 'hr', 'marketing',
        'sales', 'supply_chain', 'risk', 'change_management', 'data_analytics'
      )),
      department: Joi.string().valid(
        'consulting', 'advisory', 'implementation', 'technology', 'strategy', 'operations'
      ).required(),
      practiceArea: Joi.array().items(Joi.object({
        name: Joi.string().required(),
        isPrimary: Joi.boolean().default(false)
      })),
      industries: Joi.array().items(Joi.object({
        name: Joi.string().required(),
        yearsExperience: Joi.number().min(0).max(50),
        expertise: Joi.string().valid('basic', 'intermediate', 'advanced', 'expert')
      })),
      clearanceLevel: Joi.string().valid('none', 'public_trust', 'secret', 'top_secret', 'ts_sci'),
      travelPreference: Joi.object({
        willingToTravel: Joi.boolean().default(true),
        maxPercentage: commonFields.percentage,
        restrictions: Joi.array().items(Joi.string()),
        preferredLocations: Joi.array().items(Joi.string()),
        blackoutDates: Joi.array().items(Joi.object({
          startDate: commonFields.date.required(),
          endDate: commonFields.date.min(Joi.ref('startDate')).required(),
          reason: Joi.string()
        }))
      })
    }).required(),
    
    employment: Joi.object({
      startDate: commonFields.date.required(),
      probationEndDate: commonFields.date,
      confirmationDate: commonFields.date,
      type: Joi.string().valid('full_time', 'part_time', 'contract', 'intern').required(),
      status: Joi.string().valid('active', 'on_leave', 'notice_period', 'terminated', 'retired').default('active'),
      workLocation: Joi.string().valid('office', 'remote', 'hybrid', 'client_site'),
      reportingTo: Joi.object({
        primary: commonFields.objectId,
        secondary: commonFields.objectIdOptional,
        dotted: Joi.array().items(commonFields.objectIdOptional)
      }),
      team: Joi.object({
        current: commonFields.objectIdOptional,
        history: Joi.array().items(Joi.object({
          team: commonFields.objectId,
          startDate: commonFields.date.required(),
          endDate: commonFields.date,
          role: Joi.string()
        }))
      })
    }).required(),
    
    billing: Joi.object({
      standardRate: Joi.object({
        amount: Joi.number().min(0).required(),
        currency: commonFields.currency
      }).required(),
      rates: Joi.array().items(Joi.object({
        type: Joi.string().valid('standard', 'overtime', 'weekend', 'holiday', 'international').required(),
        amount: Joi.number().min(0).required(),
        currency: commonFields.currency,
        effectiveFrom: commonFields.date,
        effectiveTo: commonFields.date
      })),
      costToCompany: Joi.object({
        base: Joi.number().min(0),
        benefits: Joi.number().min(0),
        overhead: Joi.number().min(0),
        total: Joi.number().min(0),
        lastUpdated: commonFields.date
      }),
      utilization: Joi.object({
        target: commonFields.percentage.default(80),
        billableHoursTarget: Joi.number().min(0).default(1600),
        nonBillableAllowance: commonFields.percentage.default(20)
      })
    }).required()
  }).required()
});

/**
 * Update consultant validation schema
 */
const updateConsultantSchema = Joi.object({
  body: Joi.object({
    personalInfo: Joi.object({
      firstName: Joi.string().trim().max(50),
      lastName: Joi.string().trim().max(50),
      middleName: Joi.string().trim().max(50).allow(''),
      preferredName: Joi.string().trim().max(100),
      gender: Joi.string().valid('male', 'female', 'other', 'prefer_not_to_say'),
      nationality: Joi.string().max(100),
      languages: Joi.array().items(Joi.object({
        language: Joi.string().required(),
        proficiency: Joi.string().valid('native', 'fluent', 'advanced', 'intermediate', 'basic').required()
      }))
    }),
    
    contactInfo: Joi.object({
      email: Joi.object({
        personal: commonFields.email
      }),
      phone: Joi.object({
        work: commonFields.phone,
        mobile: commonFields.phone,
        emergency: Joi.object({
          number: commonFields.phone.required(),
          relationship: Joi.string().required(),
          name: Joi.string().required()
        })
      }),
      address: Joi.object({
        current: Joi.object({
          street: Joi.string().max(200),
          city: Joi.string().max(100),
          state: Joi.string().max(100),
          country: Joi.string().max(100),
          postalCode: Joi.string().max(20)
        }),
        permanent: Joi.object({
          street: Joi.string().max(200),
          city: Joi.string().max(100),
          state: Joi.string().max(100),
          country: Joi.string().max(100),
          postalCode: Joi.string().max(20)
        })
      }),
      timezone: Joi.string()
    }),
    
    professional: Joi.object({
      role: Joi.string().valid(
        'junior_consultant', 'consultant', 'senior_consultant', 'principal_consultant',
        'manager', 'senior_manager', 'director', 'partner'
      ),
      level: Joi.string().valid('entry', 'mid', 'senior', 'lead', 'principal', 'executive'),
      specialization: Joi.array().items(Joi.string().valid(
        'strategy', 'operations', 'technology', 'finance', 'hr', 'marketing',
        'sales', 'supply_chain', 'risk', 'change_management', 'data_analytics'
      )),
      department: Joi.string().valid(
        'consulting', 'advisory', 'implementation', 'technology', 'strategy', 'operations'
      ),
      practiceArea: Joi.array().items(Joi.object({
        name: Joi.string().required(),
        isPrimary: Joi.boolean()
      })),
      industries: Joi.array().items(Joi.object({
        name: Joi.string().required(),
        yearsExperience: Joi.number().min(0).max(50),
        expertise: Joi.string().valid('basic', 'intermediate', 'advanced', 'expert')
      })),
      clearanceLevel: Joi.string().valid('none', 'public_trust', 'secret', 'top_secret', 'ts_sci'),
      travelPreference: Joi.object({
        willingToTravel: Joi.boolean(),
        maxPercentage: commonFields.percentage,
        restrictions: Joi.array().items(Joi.string()),
        preferredLocations: Joi.array().items(Joi.string()),
        blackoutDates: Joi.array().items(Joi.object({
          startDate: commonFields.date.required(),
          endDate: commonFields.date.min(Joi.ref('startDate')).required(),
          reason: Joi.string()
        }))
      })
    }),
    
    employment: Joi.object({
      probationEndDate: commonFields.date,
      confirmationDate: commonFields.date,
      type: Joi.string().valid('full_time', 'part_time', 'contract', 'intern'),
      status: Joi.string().valid('active', 'on_leave', 'notice_period', 'terminated', 'retired'),
      workLocation: Joi.string().valid('office', 'remote', 'hybrid', 'client_site'),
      reportingTo: Joi.object({
        primary: commonFields.objectIdOptional,
        secondary: commonFields.objectIdOptional,
        dotted: Joi.array().items(commonFields.objectIdOptional)
      })
    }),
    
    billing: Joi.object({
      standardRate: Joi.object({
        amount: Joi.number().min(0),
        currency: commonFields.currency
      }),
      rates: Joi.array().items(Joi.object({
        type: Joi.string().valid('standard', 'overtime', 'weekend', 'holiday', 'international').required(),
        amount: Joi.number().min(0).required(),
        currency: commonFields.currency,
        effectiveFrom: commonFields.date,
        effectiveTo: commonFields.date
      })),
      utilization: Joi.object({
        target: commonFields.percentage,
        billableHoursTarget: Joi.number().min(0),
        nonBillableAllowance: commonFields.percentage
      })
    })
  }).min(1).required()
});

/**
 * Consultant ID parameter validation schema
 */
const consultantIdSchema = Joi.object({
  params: Joi.object({
    id: commonFields.objectId
  }).required()
});

/**
 * Query consultant validation schema
 */
const queryConsultantSchema = Joi.object({
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sort: Joi.string().default('-createdAt'),
    status: Joi.string().valid('active', 'inactive', 'all'),
    department: Joi.string(),
    role: Joi.string(),
    location: Joi.string(),
    skills: Joi.string(),
    minUtilization: Joi.number().min(0).max(100),
    maxUtilization: Joi.number().min(0).max(100),
    startDate: commonFields.date,
    endDate: commonFields.date,
    minAllocation: Joi.number().min(0).max(100)
  }).required()
});

/**
 * Search consultant validation schema
 */
const searchConsultantSchema = Joi.object({
  body: Joi.object({
    skills: Joi.array().items(Joi.string()).min(1),
    availability: Joi.object({
      startDate: commonFields.date.required(),
      endDate: commonFields.date.min(Joi.ref('startDate')).required(),
      minAllocation: commonFields.percentage.default(20)
    }),
    department: Joi.string(),
    role: Joi.string(),
    industries: Joi.array().items(Joi.string()),
    minRating: commonFields.rating,
    location: Joi.string(),
    clearance: Joi.string().valid('none', 'public_trust', 'secret', 'top_secret', 'ts_sci')
  }).required(),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sort: Joi.string().default('-availability.summary.utilizationPercentage')
  })
});

/**
 * Skill validation schema
 */
const skillSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().trim().required(),
    category: Joi.string().valid(
      'technical', 'functional', 'industry', 'soft_skills', 'tools', 'methodology', 'language'
    ).required(),
    level: Joi.number().integer().min(1).max(5).required(),
    yearsExperience: Joi.number().min(0).max(50),
    description: Joi.string().max(500),
    lastUsed: commonFields.date,
    projectsUsed: Joi.array().items(Joi.object({
      project: commonFields.objectId,
      usage: Joi.string().valid('primary', 'secondary', 'supporting')
    }))
  }).required()
});

/**
 * Certification validation schema
 */
const certificationSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().trim().required(),
    issuingOrganization: Joi.string().trim().required(),
    credentialId: Joi.string().trim(),
    category: Joi.string().valid(
      'technical', 'project_management', 'industry', 'methodology', 'security', 'compliance', 'other'
    ).required(),
    level: Joi.string().valid('foundation', 'associate', 'professional', 'expert', 'master'),
    issueDate: commonFields.date.required(),
    expiryDate: commonFields.date.min(Joi.ref('issueDate')),
    isActive: Joi.boolean().default(true),
    renewalRequired: Joi.boolean().default(false),
    continuingEducation: Joi.object({
      required: Joi.boolean().default(false),
      hoursRequired: Joi.number().min(0),
      hoursCompleted: Joi.number().min(0),
      deadline: commonFields.date
    }),
    verificationUrl: Joi.string().uri(),
    cost: Joi.object({
      exam: Joi.number().min(0),
      training: Joi.number().min(0),
      renewal: Joi.number().min(0),
      currency: commonFields.currency
    }),
    relatedSkills: Joi.array().items(Joi.string()),
    industryRecognition: Joi.string().valid('low', 'medium', 'high', 'very_high')
  }).required()
});

/**
 * Availability validation schema
 */
const availabilitySchema = Joi.object({
  body: Joi.object({
    currentAssignment: Joi.object({
      project: commonFields.objectId,
      client: commonFields.objectId,
      role: Joi.string(),
      allocation: commonFields.percentage.required(),
      startDate: commonFields.date.required(),
      endDate: commonFields.date,
      billable: Joi.boolean().default(true),
      location: Joi.string().valid('client_site', 'office', 'remote', 'hybrid')
    }),
    
    nextAvailable: commonFields.date,
    
    projects: Joi.array().items(Joi.object({
      project: commonFields.objectId.required(),
      client: commonFields.objectId.required(),
      allocation: commonFields.percentage.required(),
      startDate: commonFields.date.required(),
      endDate: commonFields.date,
      status: Joi.string().valid('tentative', 'confirmed', 'active', 'completed', 'cancelled').default('tentative'),
      billable: Joi.boolean().default(true),
      role: Joi.string(),
      responsibilities: Joi.array().items(Joi.string())
    })),
    
    preferences: Joi.object({
      minimumNotice: Joi.number().min(0).default(14),
      preferredAllocation: Joi.object({
        min: commonFields.percentage.default(80),
        max: commonFields.percentage.default(100)
      }),
      blockedClients: Joi.array().items(Joi.object({
        client: commonFields.objectId.required(),
        reason: Joi.string(),
        blockedUntil: commonFields.date
      })),
      preferredProjects: Joi.array().items(Joi.string()),
      workingHours: Joi.object({
        start: Joi.string().pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).default('09:00'),
        end: Joi.string().pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/).default('18:00'),
        timezone: Joi.string().default('America/New_York')
      })
    }),
    
    upcomingTimeOff: Joi.array().items(Joi.object({
      type: Joi.string().valid('vacation', 'sick', 'personal', 'training', 'conference').required(),
      startDate: commonFields.date.required(),
      endDate: commonFields.date.min(Joi.ref('startDate')).required(),
      approved: Joi.boolean().default(false),
      coverage: commonFields.objectIdOptional
    }))
  }).required()
});

/**
 * Performance review validation schema
 */
const performanceReviewSchema = Joi.object({
  body: Joi.object({
    period: Joi.string().valid(
      'quarterly', 'semi_annual', 'annual', 'project_end', 'probation'
    ).required(),
    year: Joi.number().integer().min(2020).max(2050).required(),
    quarter: Joi.when('period', {
      is: 'quarterly',
      then: Joi.number().integer().min(1).max(4).required(),
      otherwise: Joi.forbidden()
    }),
    startDate: commonFields.date.required(),
    endDate: commonFields.date.min(Joi.ref('startDate')).required(),
    
    ratings: Joi.object({
      overall: commonFields.rating.required(),
      technical: commonFields.rating,
      client: commonFields.rating,
      leadership: commonFields.rating,
      teamwork: commonFields.rating,
      communication: commonFields.rating,
      innovation: commonFields.rating,
      delivery: commonFields.rating
    }),
    
    metrics: Joi.object({
      utilization: commonFields.percentage,
      billableHours: Joi.number().min(0),
      revenueGenerated: Joi.number().min(0),
      clientSatisfaction: commonFields.rating,
      projectsCompleted: Joi.number().min(0),
      projectSuccessRate: commonFields.percentage,
      teamFeedbackScore: commonFields.rating
    }),
    
    feedback: Joi.object({
      strengths: Joi.array().items(Joi.string()),
      improvements: Joi.array().items(Joi.string()),
      achievements: Joi.array().items(Joi.string()),
      goals: Joi.array().items(Joi.string())
    }),
    
    outcomes: Joi.object({
      promotionRecommended: Joi.boolean(),
      salaryIncreasePercentage: Joi.number().min(0).max(100),
      bonusMultiplier: Joi.number().min(0).max(5),
      developmentPlan: Joi.boolean(),
      pipStatus: Joi.string().valid('none', 'monitoring', 'active', 'final_warning')
    })
  }).required()
});

module.exports = {
  createConsultantSchema,
  updateConsultantSchema,
  consultantIdSchema,
  queryConsultantSchema,
  searchConsultantSchema,
  skillSchema,
  certificationSchema,
  availabilitySchema,
  performanceReviewSchema
};