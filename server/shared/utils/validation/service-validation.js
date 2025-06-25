// server/core-business/services/validation/services-validation.js
/**
 * @file Services Validation Schemas
 * @description Validation schemas for service management endpoints
 * @version 3.0.0
 */

const Joi = require('joi');
const constants = require('../../../shared/config/constants');

/**
 * Common validation schemas
 */
const commonSchemas = {
  objectId: Joi.string()
    .pattern(constants.REGEX.MONGODB_ID)
    .message('Invalid ID format'),
  
  price: Joi.number()
    .min(0)
    .precision(2)
    .message('Price must be a positive number with up to 2 decimal places'),
  
  currency: Joi.string()
    .valid(...constants.BILLING.CURRENCIES_ENUM)
    .uppercase(),
  
  billingCycle: Joi.string()
    .valid('one_time', 'hourly', 'daily', 'weekly', 'monthly', 'quarterly', 'yearly', 'custom'),
  
  deliveryMethod: Joi.string()
    .valid('onsite', 'remote', 'hybrid', 'self_service'),
  
  serviceType: Joi.string()
    .valid('fixed_scope', 'time_and_materials', 'retainer', 'subscription', 'milestone_based'),
  
  serviceStatus: Joi.string()
    .valid('draft', 'pending_approval', 'active', 'inactive', 'deprecated', 'archived'),
  
  availabilityStatus: Joi.string()
    .valid('available', 'limited', 'booked', 'discontinued', 'coming_soon')
};

/**
 * Pricing schema
 */
const pricingSchema = Joi.object({
  basePrice: commonSchemas.price.required(),
  currency: commonSchemas.currency.default('USD'),
  billingCycle: commonSchemas.billingCycle.required(),
  customBillingDays: Joi.when('billingCycle', {
    is: 'custom',
    then: Joi.number().integer().min(1).max(365).required(),
    otherwise: Joi.forbidden()
  }),
  discounts: Joi.array().items(Joi.object({
    name: Joi.string().trim().max(100),
    type: Joi.string().valid('percentage', 'fixed').required(),
    value: Joi.number().min(0).required(),
    conditions: Joi.object({
      minQuantity: Joi.number().integer().min(1),
      minDuration: Joi.number().integer().min(1),
      customerType: Joi.array().items(Joi.string()),
      validFrom: Joi.date(),
      validUntil: Joi.date().greater(Joi.ref('validFrom'))
    }),
    active: Joi.boolean().default(true)
  })),
  taxable: Joi.boolean().default(true),
  taxRate: Joi.number().min(0).max(100)
});

/**
 * Deliverable schema
 */
const deliverableSchema = Joi.object({
  name: Joi.string().trim().required().max(200),
  description: Joi.string().trim().max(1000),
  type: Joi.string().valid('document', 'report', 'presentation', 'code', 'design', 'data', 'other').required(),
  format: Joi.string().max(50),
  estimatedDeliveryDays: Joi.number().integer().min(0),
  isRequired: Joi.boolean().default(true),
  order: Joi.number().integer().min(0).default(0)
});

/**
 * Requirement schema
 */
const requirementSchema = Joi.object({
  type: Joi.string().valid('skill', 'certification', 'experience', 'tool', 'resource', 'other').required(),
  name: Joi.string().trim().required().max(200),
  description: Joi.string().trim().max(500),
  level: Joi.string().valid('beginner', 'intermediate', 'advanced', 'expert'),
  isMandatory: Joi.boolean().default(true),
  alternatives: Joi.array().items(Joi.string().trim().max(200))
});

/**
 * SLA schema
 */
const slaSchema = Joi.object({
  responseTime: Joi.object({
    value: Joi.number().integer().min(1),
    unit: Joi.string().valid('minutes', 'hours', 'days').default('hours')
  }),
  resolutionTime: Joi.object({
    value: Joi.number().integer().min(1),
    unit: Joi.string().valid('hours', 'days', 'weeks').default('days')
  }),
  availability: Joi.object({
    percentage: Joi.number().min(0).max(100).default(99),
    businessHoursOnly: Joi.boolean().default(false)
  }),
  supportLevel: Joi.string().valid('basic', 'standard', 'premium', 'enterprise').default('standard'),
  penalties: Joi.array().items(Joi.object({
    condition: Joi.string().required(),
    penalty: Joi.string().required(),
    maxPenalty: Joi.number().min(0)
  }))
});

/**
 * Create service validation schema
 */
const createServiceSchema = {
  body: Joi.object({
    name: Joi.string()
      .trim()
      .required()
      .min(3)
      .max(100)
      .message('Service name must be between 3 and 100 characters'),
    
    slug: Joi.string()
      .trim()
      .lowercase()
      .pattern(/^[a-z0-9-]+$/)
      .message('Slug can only contain lowercase letters, numbers, and hyphens'),
    
    category: Joi.object({
      primary: Joi.string()
        .required()
        .valid('consulting', 'development', 'design', 'marketing', 'support', 'training', 'analytics', 'research', 'other'),
      secondary: Joi.array().items(Joi.string()),
      tags: Joi.array().items(Joi.string().trim().lowercase().max(50))
    }).required(),
    
    description: Joi.object({
      short: Joi.string().trim().required().max(200),
      full: Joi.string().trim().required().max(5000),
      highlights: Joi.array().items(Joi.string().trim().max(200)),
      targetAudience: Joi.string().trim().max(500)
    }).required(),
    
    type: commonSchemas.serviceType.required(),
    deliveryMethod: commonSchemas.deliveryMethod.required(),
    
    duration: Joi.object({
      estimated: Joi.object({
        min: Joi.number().integer().min(1),
        max: Joi.number().integer().min(Joi.ref('min')),
        unit: Joi.string().valid('hours', 'days', 'weeks', 'months').default('days')
      }),
      isFlexible: Joi.boolean().default(false)
    }),
    
    pricing: pricingSchema.required(),
    deliverables: Joi.array().items(deliverableSchema),
    
    requirements: Joi.object({
      provider: Joi.array().items(requirementSchema),
      client: Joi.array().items(requirementSchema)
    }),
    
    sla: slaSchema,
    
    team: Joi.object({
      minSize: Joi.number().integer().min(1).default(1),
      maxSize: Joi.number().integer().min(Joi.ref('minSize')),
      roles: Joi.array().items(Joi.object({
        role: Joi.string().required(),
        count: Joi.number().integer().min(1).default(1),
        level: Joi.string().valid('junior', 'mid', 'senior', 'lead', 'expert'),
        responsibilities: Joi.array().items(Joi.string()),
        isOptional: Joi.boolean().default(false)
      }))
    }),
    
    process: Joi.object({
      methodology: Joi.string().valid('agile', 'waterfall', 'hybrid', 'lean', 'custom'),
      phases: Joi.array().items(Joi.object({
        name: Joi.string().required(),
        description: Joi.string(),
        duration: Joi.object({
          estimated: Joi.number(),
          unit: Joi.string()
        }),
        deliverables: Joi.array().items(Joi.string()),
        order: Joi.number().integer()
      })),
      qualityChecks: Joi.array().items(Joi.object({
        name: Joi.string(),
        description: Joi.string(),
        frequency: Joi.string(),
        responsible: Joi.string()
      }))
    }),
    
    availability: Joi.object({
      status: commonSchemas.availabilityStatus.default('available'),
      capacity: Joi.object({
        current: Joi.number().integer().min(0).default(0),
        maximum: Joi.number().integer().min(0),
        unit: Joi.string()
      }),
      leadTime: Joi.object({
        value: Joi.number().integer().min(0),
        unit: Joi.string().valid('days', 'weeks', 'months')
      }),
      blackoutDates: Joi.array().items(Joi.object({
        startDate: Joi.date().required(),
        endDate: Joi.date().min(Joi.ref('startDate')).required(),
        reason: Joi.string()
      }))
    }),
    
    relatedServices: Joi.array().items(Joi.object({
      service: commonSchemas.objectId,
      type: Joi.string().valid('prerequisite', 'complement', 'upgrade', 'alternative'),
      description: Joi.string()
    })),
    
    documents: Joi.array().items(Joi.object({
      type: Joi.string().valid('brochure', 'proposal_template', 'contract_template', 'sow_template', 'case_study', 'whitepaper', 'other'),
      name: Joi.string(),
      description: Joi.string(),
      url: Joi.string().uri(),
      version: Joi.string(),
      isPublic: Joi.boolean().default(false)
    })),
    
    compliance: Joi.object({
      certifications: Joi.array().items(Joi.object({
        name: Joi.string(),
        issuer: Joi.string(),
        certificateNumber: Joi.string(),
        validFrom: Joi.date(),
        validUntil: Joi.date().greater(Joi.ref('validFrom')),
        documentUrl: Joi.string().uri()
      })),
      standards: Joi.array().items(Joi.string()),
      regulations: Joi.array().items(Joi.string()),
      dataHandling: Joi.object({
        classification: Joi.string().valid('public', 'internal', 'confidential', 'restricted'),
        retention: Joi.object({
          period: Joi.number().integer().min(1),
          unit: Joi.string()
        }),
        encryption: Joi.boolean(),
        gdprCompliant: Joi.boolean()
      })
    }),
    
    metadata: Joi.object({
      customFields: Joi.object(),
      internalNotes: Joi.array().items(Joi.object({
        note: Joi.string(),
        type: Joi.string().valid('general', 'technical', 'business', 'risk', 'improvement')
      }))
    }),
    
    organization: commonSchemas.objectId
  })
};

/**
 * Update service validation schema
 */
const updateServiceSchema = {
  body: Joi.object({
    name: Joi.string().trim().min(3).max(100),
    slug: Joi.string().trim().lowercase().pattern(/^[a-z0-9-]+$/),
    category: Joi.object({
      primary: Joi.string().valid('consulting', 'development', 'design', 'marketing', 'support', 'training', 'analytics', 'research', 'other'),
      secondary: Joi.array().items(Joi.string()),
      tags: Joi.array().items(Joi.string().trim().lowercase().max(50))
    }),
    description: Joi.object({
      short: Joi.string().trim().max(200),
      full: Joi.string().trim().max(5000),
      highlights: Joi.array().items(Joi.string().trim().max(200)),
      targetAudience: Joi.string().trim().max(500)
    }),
    type: commonSchemas.serviceType,
    deliveryMethod: commonSchemas.deliveryMethod,
    duration: Joi.object({
      estimated: Joi.object({
        min: Joi.number().integer().min(1),
        max: Joi.number().integer().min(Joi.ref('min')),
        unit: Joi.string().valid('hours', 'days', 'weeks', 'months')
      }),
      isFlexible: Joi.boolean()
    }),
    pricing: pricingSchema,
    deliverables: Joi.array().items(deliverableSchema),
    requirements: Joi.object({
      provider: Joi.array().items(requirementSchema),
      client: Joi.array().items(requirementSchema)
    }),
    sla: slaSchema,
    team: Joi.object({
      minSize: Joi.number().integer().min(1),
      maxSize: Joi.number().integer().min(Joi.ref('minSize')),
      roles: Joi.array().items(Joi.object({
        role: Joi.string().required(),
        count: Joi.number().integer().min(1),
        level: Joi.string().valid('junior', 'mid', 'senior', 'lead', 'expert'),
        responsibilities: Joi.array().items(Joi.string()),
        isOptional: Joi.boolean()
      }))
    }),
    process: Joi.object({
      methodology: Joi.string().valid('agile', 'waterfall', 'hybrid', 'lean', 'custom'),
      phases: Joi.array().items(Joi.object({
        name: Joi.string().required(),
        description: Joi.string(),
        duration: Joi.object({
          estimated: Joi.number(),
          unit: Joi.string()
        }),
        deliverables: Joi.array().items(Joi.string()),
        order: Joi.number().integer()
      })),
      qualityChecks: Joi.array().items(Joi.object({
        name: Joi.string(),
        description: Joi.string(),
        frequency: Joi.string(),
        responsible: Joi.string()
      }))
    }),
    availability: Joi.object({
      status: commonSchemas.availabilityStatus,
      capacity: Joi.object({
        current: Joi.number().integer().min(0),
        maximum: Joi.number().integer().min(0),
        unit: Joi.string()
      }),
      leadTime: Joi.object({
        value: Joi.number().integer().min(0),
        unit: Joi.string().valid('days', 'weeks', 'months')
      }),
      blackoutDates: Joi.array().items(Joi.object({
        startDate: Joi.date().required(),
        endDate: Joi.date().min(Joi.ref('startDate')).required(),
        reason: Joi.string()
      }))
    }),
    relatedServices: Joi.array().items(Joi.object({
      service: commonSchemas.objectId,
      type: Joi.string().valid('prerequisite', 'complement', 'upgrade', 'alternative'),
      description: Joi.string()
    })),
    documents: Joi.array().items(Joi.object({
      type: Joi.string().valid('brochure', 'proposal_template', 'contract_template', 'sow_template', 'case_study', 'whitepaper', 'other'),
      name: Joi.string(),
      description: Joi.string(),
      url: Joi.string().uri(),
      version: Joi.string(),
      isPublic: Joi.boolean()
    })),
    compliance: Joi.object({
      certifications: Joi.array().items(Joi.object({
        name: Joi.string(),
        issuer: Joi.string(),
        certificateNumber: Joi.string(),
        validFrom: Joi.date(),
        validUntil: Joi.date().greater(Joi.ref('validFrom')),
        documentUrl: Joi.string().uri()
      })),
      standards: Joi.array().items(Joi.string()),
      regulations: Joi.array().items(Joi.string()),
      dataHandling: Joi.object({
        classification: Joi.string().valid('public', 'internal', 'confidential', 'restricted'),
        retention: Joi.object({
          period: Joi.number().integer().min(1),
          unit: Joi.string()
        }),
        encryption: Joi.boolean(),
        gdprCompliant: Joi.boolean()
      })
    }),
    status: commonSchemas.serviceStatus,
    managers: Joi.array().items(commonSchemas.objectId)
  }).min(1)
};

/**
 * List services validation schema
 */
const listServicesSchema = {
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(constants.API.PAGINATION.MAX_LIMIT).default(20),
    sort: Joi.string().default('-createdAt'),
    organization: commonSchemas.objectId,
    category: Joi.string(),
    type: commonSchemas.serviceType,
    deliveryMethod: commonSchemas.deliveryMethod,
    status: commonSchemas.serviceStatus,
    availability: commonSchemas.availabilityStatus,
    search: Joi.string().trim().min(2).max(100),
    minPrice: Joi.number().min(0),
    maxPrice: Joi.number().min(0).greater(Joi.ref('minPrice')),
    populate: Joi.boolean().default(true)
  })
};

/**
 * Calculate price validation schema
 */
const calculatePriceSchema = {
  body: Joi.object({
    quantity: Joi.number().integer().min(1).default(1),
    duration: Joi.number().min(1).default(1),
    customerType: Joi.string(),
    date: Joi.date(),
    additionalFees: Joi.array().items(Joi.object({
      name: Joi.string().required(),
      amount: Joi.number().min(0).required(),
      description: Joi.string()
    }))
  })
};

/**
 * Review validation schema
 */
const reviewSchema = {
  body: Joi.object({
    projectId: commonSchemas.objectId,
    rating: Joi.number().integer().min(1).max(5).required(),
    positive: Joi.string().trim().max(1000),
    improvement: Joi.string().trim().max(1000),
    recommendation: Joi.boolean()
  })
};

/**
 * Availability validation schema
 */
const availabilitySchema = {
  body: Joi.object({
    status: commonSchemas.availabilityStatus.required(),
    capacity: Joi.number().integer().min(0),
    blackoutDates: Joi.array().items(Joi.object({
      startDate: Joi.date().required(),
      endDate: Joi.date().min(Joi.ref('startDate')).required(),
      reason: Joi.string().max(200)
    }))
  })
};

/**
 * Clone service validation schema
 */
const cloneServiceSchema = {
  body: Joi.object({
    name: Joi.string().trim().min(3).max(100),
    organization: commonSchemas.objectId
  })
};

/**
 * Archive service validation schema
 */
const archiveServiceSchema = {
  body: Joi.object({
    reason: Joi.string().trim().required().min(10).max(500)
  })
};

/**
 * Check requirements validation schema
 */
const checkRequirementsSchema = {
  body: Joi.object({
    provider: Joi.object().pattern(Joi.string(), Joi.array().items(Joi.string())),
    client: Joi.object().pattern(Joi.string(), Joi.array().items(Joi.string()))
  })
};

/**
 * Export services validation schema
 */
const exportServicesSchema = {
  query: Joi.object({
    organization: commonSchemas.objectId,
    status: commonSchemas.serviceStatus,
    category: Joi.string(),
    dateFrom: Joi.date(),
    dateTo: Joi.date().greater(Joi.ref('dateFrom')),
    format: Joi.string().valid('csv', 'json').default('csv')
  })
};

module.exports = {
  createServiceSchema,
  updateServiceSchema,
  listServicesSchema,
  calculatePriceSchema,
  reviewSchema,
  availabilitySchema,
  cloneServiceSchema,
  archiveServiceSchema,
  checkRequirementsSchema,
  exportServicesSchema
};