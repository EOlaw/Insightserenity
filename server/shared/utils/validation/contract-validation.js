// server/shared/validation/contract-validation.js
/**
 * @file Contract Validation Schemas
 * @description Joi validation schemas for contract-related operations
 * @version 3.0.0
 */

const Joi = require('joi');

/**
 * Common validation patterns
 */
const patterns = {
  objectId: Joi.string().regex(/^[0-9a-fA-F]{24}$/).message('Invalid ObjectId format'),
  contractNumber: Joi.string().regex(/^[A-Z]{2,3}-\d{4}-\d{4}$/).message('Invalid contract number format'),
  currency: Joi.string().length(3).uppercase().message('Currency must be 3-letter ISO code'),
  percentage: Joi.number().min(0).max(100),
  positiveNumber: Joi.number().positive(),
  email: Joi.string().email().lowercase(),
  url: Joi.string().uri(),
  date: Joi.date().iso(),
  futureDate: Joi.date().iso().greater('now'),
  phoneNumber: Joi.string().regex(/^\+?[1-9]\d{1,14}$/),
  contractType: Joi.string().valid(
    'service_agreement',
    'master_service_agreement',
    'statement_of_work',
    'non_disclosure_agreement',
    'purchase_order',
    'license_agreement',
    'maintenance_agreement',
    'consulting_agreement',
    'partnership_agreement',
    'subcontractor_agreement'
  ),
  contractStatus: Joi.string().valid(
    'draft',
    'pending_approval',
    'approved',
    'active',
    'suspended',
    'completed',
    'terminated',
    'expired',
    'cancelled'
  ),
  paymentTerms: Joi.string().valid(
    'net_30',
    'net_45',
    'net_60',
    'net_90',
    'due_on_receipt',
    'milestone_based',
    'custom'
  )
};

/**
 * Signatory sub-schema
 */
const signatorySchema = Joi.object({
  user: patterns.objectId,
  name: Joi.string().required(),
  title: Joi.string().required(),
  email: patterns.email.required(),
  phone: patterns.phoneNumber,
  isRequired: Joi.boolean().default(true),
  order: Joi.number().integer().min(1)
});

/**
 * Payment schedule item schema
 */
const paymentScheduleSchema = Joi.object({
  milestone: Joi.string().required(),
  description: Joi.string(),
  amount: patterns.positiveNumber.required(),
  percentage: patterns.percentage,
  dueDate: patterns.date.required(),
  invoiceRequired: Joi.boolean().default(true),
  status: Joi.string().valid('pending', 'invoiced', 'paid', 'overdue').default('pending')
});

/**
 * Deliverable schema
 */
const deliverableSchema = Joi.object({
  title: Joi.string().required(),
  description: Joi.string().required(),
  type: Joi.string().valid(
    'document', 'software', 'report', 'presentation', 
    'training', 'consultation', 'other'
  ),
  dueDate: patterns.date,
  acceptanceCriteria: Joi.array().items(Joi.string()),
  associatedMilestone: Joi.string(),
  value: patterns.positiveNumber
});

/**
 * Amendment schema
 */
const amendmentSchema = Joi.object({
  title: Joi.string().required(),
  description: Joi.string().required(),
  effectiveDate: patterns.date.required(),
  changes: Joi.object({
    timeline: Joi.object({
      newEndDate: patterns.date,
      extensionDays: Joi.number().integer()
    }),
    financial: Joi.object({
      additionalValue: Joi.number(),
      revisedTotal: patterns.positiveNumber,
      paymentTermsChange: Joi.string()
    }),
    scope: Joi.object({
      additions: Joi.array().items(Joi.string()),
      removals: Joi.array().items(Joi.string()),
      modifications: Joi.array().items(Joi.string())
    }),
    deliverables: Joi.array().items(deliverableSchema),
    other: Joi.string()
  }).required(),
  justification: Joi.string().required(),
  requestedBy: patterns.objectId,
  approvers: Joi.array().items(patterns.objectId)
});

/**
 * Create contract validation schema
 */
const createContractSchema = Joi.object({
  body: Joi.object({
    // Basic Information
    title: Joi.string().min(5).max(200).required(),
    type: patterns.contractType.required(),
    description: Joi.string().max(2000),
    
    // Client Information
    client: patterns.objectId.required(),
    clientContacts: Joi.array().items(patterns.objectId),
    
    // Organization (optional for platform contracts)
    organization: patterns.objectId,
    
    // Timeline
    timeline: Joi.object({
      startDate: patterns.date.required(),
      endDate: patterns.date.min(Joi.ref('startDate')).required(),
      executionDate: patterns.date,
      effectiveDate: patterns.date
    }).required(),
    
    // Financial Information
    financial: Joi.object({
      contractValue: patterns.positiveNumber.required(),
      currency: patterns.currency.default('USD'),
      paymentTerms: patterns.paymentTerms.required(),
      customPaymentTerms: Joi.string().when('paymentTerms', {
        is: 'custom',
        then: Joi.required()
      }),
      paymentSchedule: Joi.array().items(paymentScheduleSchema),
      retainerAmount: patterns.positiveNumber,
      discounts: Joi.array().items(Joi.object({
        type: Joi.string().valid('percentage', 'fixed'),
        value: patterns.positiveNumber,
        description: Joi.string()
      })),
      taxes: Joi.array().items(Joi.object({
        type: Joi.string().required(),
        rate: patterns.percentage,
        amount: patterns.positiveNumber
      }))
    }).required(),
    
    // Signatories
    signatories: Joi.object({
      internal: Joi.array().items(signatorySchema).min(1).required(),
      external: Joi.array().items(signatorySchema).min(1).required()
    }).required(),
    
    // Terms and Conditions
    terms: Joi.object({
      paymentTerms: Joi.string(),
      deliveryTerms: Joi.string(),
      intellectualProperty: Joi.string(),
      confidentiality: Joi.string(),
      liability: Joi.string(),
      termination: Joi.string(),
      disputeResolution: Joi.string(),
      governingLaw: Joi.string(),
      customTerms: Joi.array().items(Joi.object({
        title: Joi.string().required(),
        content: Joi.string().required()
      }))
    }),
    
    // Deliverables
    deliverables: Joi.array().items(deliverableSchema),
    
    // Renewal Information
    renewal: Joi.object({
      isRenewable: Joi.boolean().default(false),
      autoRenew: Joi.boolean().default(false),
      renewalPeriod: Joi.string().valid('monthly', 'quarterly', 'annually', 'custom'),
      customRenewalPeriod: Joi.string().when('renewalPeriod', {
        is: 'custom',
        then: Joi.required()
      }),
      renewalNotice: Joi.number().integer().min(1),
      renewalTerms: Joi.string(),
      priceAdjustment: Joi.object({
        type: Joi.string().valid('percentage', 'fixed', 'index'),
        value: Joi.number()
      })
    }),
    
    // Termination Conditions
    termination: Joi.object({
      noticePeriod: Joi.number().integer().min(0).default(30),
      earlyTerminationAllowed: Joi.boolean().default(true),
      earlyTerminationFee: patterns.positiveNumber,
      terminationConditions: Joi.array().items(Joi.string())
    }),
    
    // Settings
    settings: Joi.object({
      requiresLegalReview: Joi.boolean().default(false),
      requiresFinanceApproval: Joi.boolean().default(true),
      autoCreateProjects: Joi.boolean().default(false),
      enableAutomatedReminders: Joi.boolean().default(true),
      reminderDays: Joi.array().items(Joi.number().integer())
    }),
    
    // Document Templates
    documentTemplates: Joi.object({
      contract: Joi.string(),
      amendment: Joi.string(),
      invoice: Joi.string()
    }),
    
    // Metadata
    notes: Joi.string().max(5000),
    tags: Joi.array().items(Joi.string().max(50)),
    customFields: Joi.object()
  }).required()
});

/**
 * Update contract validation schema
 */
const updateContractSchema = Joi.object({
  body: Joi.object({
    title: Joi.string().min(5).max(200),
    description: Joi.string().max(2000),
    timeline: Joi.object({
      startDate: patterns.date,
      endDate: patterns.date,
      executionDate: patterns.date,
      effectiveDate: patterns.date
    }),
    financial: Joi.object({
      contractValue: patterns.positiveNumber,
      currency: patterns.currency,
      paymentTerms: patterns.paymentTerms,
      customPaymentTerms: Joi.string(),
      paymentSchedule: Joi.array().items(paymentScheduleSchema),
      retainerAmount: patterns.positiveNumber
    }),
    signatories: Joi.object({
      internal: Joi.array().items(signatorySchema),
      external: Joi.array().items(signatorySchema)
    }),
    terms: Joi.object({
      paymentTerms: Joi.string(),
      deliveryTerms: Joi.string(),
      intellectualProperty: Joi.string(),
      confidentiality: Joi.string(),
      liability: Joi.string(),
      termination: Joi.string(),
      disputeResolution: Joi.string(),
      governingLaw: Joi.string()
    }),
    deliverables: Joi.array().items(deliverableSchema),
    renewal: Joi.object({
      isRenewable: Joi.boolean(),
      autoRenew: Joi.boolean(),
      renewalPeriod: Joi.string(),
      renewalNotice: Joi.number().integer().min(1),
      renewalTerms: Joi.string()
    }),
    notes: Joi.string().max(5000),
    tags: Joi.array().items(Joi.string().max(50)),
    customFields: Joi.object(),
    revisionComment: Joi.string().max(500)
  }).min(1).required()
});

/**
 * Update contract status validation schema
 */
const updateContractStatusSchema = Joi.object({
  body: Joi.object({
    status: patterns.contractStatus.required(),
    reason: Joi.string().max(500),
    comment: Joi.string().max(1000),
    effectiveDate: patterns.date
  }).required()
});

/**
 * List contracts query validation schema
 */
const listContractsSchema = Joi.object({
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
    sort: Joi.string().default('-createdAt'),
    status: Joi.string(), // comma-separated list
    type: Joi.string(), // comma-separated list
    client: patterns.objectId,
    search: Joi.string().max(100),
    startDate: patterns.date,
    endDate: patterns.date,
    minValue: patterns.positiveNumber,
    maxValue: patterns.positiveNumber,
    tags: Joi.string(), // comma-separated list
    includeExpired: Joi.boolean(),
    includeAmendments: Joi.boolean(),
    includeDocuments: Joi.boolean(),
    includeProjects: Joi.boolean()
  })
});

/**
 * Contract ID parameter validation
 */
const contractIdSchema = Joi.object({
  params: Joi.object({
    id: patterns.objectId.required()
  }).required()
});

/**
 * Add amendment validation schema
 */
const addAmendmentSchema = Joi.object({
  body: amendmentSchema.required()
});

/**
 * Update amendment status validation schema
 */
const updateAmendmentStatusSchema = Joi.object({
  params: Joi.object({
    id: patterns.objectId.required(),
    amendmentId: patterns.objectId.required()
  }).required(),
  body: Joi.object({
    status: Joi.string().valid('draft', 'under_review', 'approved', 'rejected').required(),
    reason: Joi.string().max(500),
    comments: Joi.string().max(1000)
  }).required()
});

/**
 * Generate document validation schema
 */
const generateDocumentSchema = Joi.object({
  body: Joi.object({
    template: Joi.string(),
    includeAnnexes: Joi.boolean().default(true),
    format: Joi.string().valid('pdf', 'docx').default('pdf'),
    watermark: Joi.boolean(),
    language: Joi.string().default('en')
  })
});

/**
 * Upload document validation schema
 */
const uploadDocumentSchema = Joi.object({
  body: Joi.object({
    title: Joi.string().max(200).required(),
    type: Joi.string().valid(
      'contract', 'amendment', 'annex', 'correspondence', 
      'invoice', 'receipt', 'report', 'other'
    ).required(),
    description: Joi.string().max(500),
    version: Joi.string(),
    confidential: Joi.boolean().default(false)
  }).required()
});

/**
 * Sign contract validation schema
 */
const signContractSchema = Joi.object({
  body: Joi.object({
    signatureData: Joi.string().required(), // Base64 encoded signature or digital signature data
    signatureType: Joi.string().valid('electronic', 'digital', 'drawn').default('electronic'),
    agreementText: Joi.string(),
    consentToElectronicSignature: Joi.boolean().isValid(true).required()
  }).required()
});

/**
 * Renew contract validation schema
 */
const renewContractSchema = Joi.object({
  body: Joi.object({
    timeline: Joi.object({
      startDate: patterns.futureDate.required(),
      endDate: patterns.date.min(Joi.ref('startDate')).required()
    }).required(),
    financial: Joi.object({
      contractValue: patterns.positiveNumber,
      priceAdjustment: Joi.object({
        type: Joi.string().valid('percentage', 'fixed'),
        value: Joi.number().required()
      }),
      maintainPaymentSchedule: Joi.boolean().default(true)
    }),
    modifiedTerms: Joi.object({
      summary: Joi.string().max(1000),
      details: Joi.array().items(Joi.object({
        clause: Joi.string(),
        modification: Joi.string()
      }))
    }),
    notes: Joi.string().max(1000)
  }).required()
});

/**
 * Export contracts validation schema
 */
const exportContractsSchema = Joi.object({
  query: Joi.object({
    format: Joi.string().valid('csv', 'excel', 'pdf').default('csv'),
    status: Joi.string(), // comma-separated
    type: Joi.string(), // comma-separated
    startDate: patterns.date,
    endDate: patterns.date,
    fields: Joi.string(), // comma-separated list of fields to export
    includeFinancial: Joi.boolean().default(true),
    includeConfidential: Joi.boolean().default(false)
  })
});

/**
 * Analytics query validation schema
 */
const analyticsQuerySchema = Joi.object({
  query: Joi.object({
    startDate: patterns.date,
    endDate: patterns.date,
    groupBy: Joi.string().valid('day', 'week', 'month', 'quarter', 'year').default('month'),
    metrics: Joi.string().valid('all', 'count', 'value', 'status', 'type').default('all'),
    compareWith: Joi.string().valid('previous_period', 'previous_year'),
    includeForecasts: Joi.boolean().default(false)
  })
});

/**
 * Search contracts validation schema
 */
const searchContractsSchema = Joi.object({
  body: Joi.object({
    query: Joi.string().max(200),
    filters: Joi.object({
      status: Joi.array().items(patterns.contractStatus),
      type: Joi.array().items(patterns.contractType),
      clients: Joi.array().items(patterns.objectId),
      valueRange: Joi.object({
        min: patterns.positiveNumber,
        max: patterns.positiveNumber
      }),
      dateRange: Joi.object({
        field: Joi.string().valid('created', 'start', 'end', 'executed'),
        from: patterns.date,
        to: patterns.date
      }),
      tags: Joi.array().items(Joi.string()),
      hasAmendments: Joi.boolean(),
      isRenewable: Joi.boolean(),
      assignedTo: Joi.array().items(patterns.objectId)
    }),
    sort: Joi.object({
      field: Joi.string().default('relevance'),
      order: Joi.string().valid('asc', 'desc').default('desc')
    }),
    pagination: Joi.object({
      page: Joi.number().integer().min(1).default(1),
      limit: Joi.number().integer().min(1).max(100).default(20)
    })
  }).required()
});

/**
 * Bulk update validation schema
 */
const bulkUpdateSchema = Joi.object({
  body: Joi.object({
    contractIds: Joi.array().items(patterns.objectId).min(1).max(100).required(),
    updates: Joi.object({
      status: patterns.contractStatus,
      tags: Joi.object({
        add: Joi.array().items(Joi.string()),
        remove: Joi.array().items(Joi.string())
      }),
      assignedTo: patterns.objectId,
      customFields: Joi.object()
    }).min(1).required(),
    reason: Joi.string().max(500)
  }).required()
});

/**
 * Contract reminder validation schema
 */
const contractReminderSchema = Joi.object({
  body: Joi.object({
    type: Joi.string().valid(
      'renewal', 'expiry', 'payment', 'milestone', 
      'review', 'custom'
    ).required(),
    reminderDate: patterns.futureDate.required(),
    recipients: Joi.array().items(patterns.objectId).min(1).required(),
    message: Joi.string().max(1000),
    recurring: Joi.boolean().default(false),
    recurringInterval: Joi.string().valid('daily', 'weekly', 'monthly').when('recurring', {
      is: true,
      then: Joi.required()
    }),
    channels: Joi.array().items(
      Joi.string().valid('email', 'sms', 'in_app')
    ).default(['email', 'in_app'])
  }).required()
});

module.exports = {
  // Create/Update schemas
  createContractSchema,
  updateContractSchema,
  updateContractStatusSchema,
  
  // Query schemas
  listContractsSchema,
  contractIdSchema,
  searchContractsSchema,
  exportContractsSchema,
  analyticsQuerySchema,
  
  // Amendment schemas
  addAmendmentSchema,
  updateAmendmentStatusSchema,
  
  // Document schemas
  generateDocumentSchema,
  uploadDocumentSchema,
  
  // Signature schemas
  signContractSchema,
  
  // Lifecycle schemas
  renewContractSchema,
  
  // Bulk operation schemas
  bulkUpdateSchema,
  
  // Reminder schemas
  contractReminderSchema,
  
  // Exported patterns for reuse
  patterns
};