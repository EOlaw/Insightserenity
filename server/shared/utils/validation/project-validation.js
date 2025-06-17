/**
 * @file Project Validation Schemas
 * @description Request validation schemas for project endpoints
 * @version 2.0.0
 */

const Joi = require('joi');

/**
 * Common validation patterns
 */
const patterns = {
  objectId: Joi.string().regex(/^[0-9a-fA-F]{24}$/),
  projectCode: Joi.string().uppercase().regex(/^[A-Z0-9-]{3,20}$/),
  percentage: Joi.number().min(0).max(100),
  positiveNumber: Joi.number().positive(),
  currency: Joi.string().length(3).uppercase(),
  dateRange: Joi.object({
    start: Joi.date(),
    end: Joi.date().greater(Joi.ref('start'))
  })
};

/**
 * Team member schema
 */
const teamMemberDataSchema = Joi.object({
  consultant: patterns.objectId.required(),
  role: Joi.string().valid(
    'project_manager', 'lead_consultant', 'senior_consultant', 
    'consultant', 'analyst', 'specialist', 'advisor'
  ).required(),
  allocation: Joi.object({
    percentage: patterns.percentage.required(),
    hoursPerWeek: Joi.number().min(0).max(60),
    startDate: Joi.date().required(),
    endDate: Joi.date().greater(Joi.ref('startDate'))
  }).required(),
  billable: Joi.boolean(),
  hourlyRate: Joi.object({
    amount: patterns.positiveNumber,
    currency: patterns.currency
  }),
  responsibilities: Joi.array().items(Joi.string()),
  skills: Joi.array().items(Joi.string())
});

/**
 * Milestone schema
 */
const milestoneDataSchema = Joi.object({
  name: Joi.string().required(),
  description: Joi.string(),
  type: Joi.string().valid(
    'deliverable', 'payment', 'review', 'approval', 'phase_completion'
  ).required(),
  phase: Joi.string(),
  plannedDate: Joi.date().required(),
  dependencies: Joi.array().items(Joi.object({
    milestone: patterns.objectId,
    type: Joi.string().valid(
      'finish_to_start', 'start_to_start', 
      'finish_to_finish', 'start_to_finish'
    )
  })),
  payment: Joi.object({
    amount: patterns.positiveNumber,
    currency: patterns.currency
  }),
  assignedTo: Joi.array().items(patterns.objectId)
});

/**
 * Risk schema
 */
const riskDataSchema = Joi.object({
  title: Joi.string().required(),
  description: Joi.string().required(),
  category: Joi.string().valid(
    'technical', 'financial', 'operational', 
    'strategic', 'compliance', 'reputational'
  ).required(),
  probability: Joi.string().valid(
    'very_low', 'low', 'medium', 'high', 'very_high'
  ).required(),
  impact: Joi.string().valid(
    'negligible', 'minor', 'moderate', 'major', 'severe'
  ).required(),
  mitigation: Joi.object({
    strategy: Joi.string(),
    actions: Joi.array().items(Joi.object({
      description: Joi.string(),
      assignedTo: patterns.objectId,
      dueDate: Joi.date()
    })),
    contingencyPlan: Joi.string()
  })
});

/**
 * Create project validation schema
 */
const createProjectSchema = Joi.object({
  body: Joi.object({
    // Core Information
    name: Joi.string().min(3).max(200).required(),
    code: patterns.projectCode,
    description: Joi.object({
      brief: Joi.string().max(500).required(),
      detailed: Joi.string().max(5000),
      objectives: Joi.array().items(Joi.string()),
      scope: Joi.string(),
      outOfScope: Joi.array().items(Joi.string()),
      assumptions: Joi.array().items(Joi.string()),
      constraints: Joi.array().items(Joi.string())
    }).required(),
    
    // Client and Contract
    client: patterns.objectId.required(),
    clientContact: Joi.object({
      primary: patterns.objectId,
      additional: Joi.array().items(patterns.objectId)
    }),
    contract: patterns.objectId,
    proposal: patterns.objectId,
    
    // Classification
    type: Joi.string().valid(
      'strategy', 'implementation', 'transformation', 'assessment', 
      'training', 'support', 'research', 'other'
    ).required(),
    category: Joi.string().valid(
      'fixed_fee', 'time_and_materials', 'retainer', 
      'milestone_based', 'hybrid'
    ),
    priority: Joi.string().valid('low', 'medium', 'high', 'critical'),
    complexity: Joi.string().valid('simple', 'moderate', 'complex', 'highly_complex'),
    industry: Joi.string(),
    technologies: Joi.array().items(Joi.string()),
    methodologies: Joi.array().items(Joi.string().valid(
      'agile', 'waterfall', 'hybrid', 'scrum', 'kanban', 'prince2', 'custom'
    )),
    
    // Timeline
    timeline: Joi.object({
      estimatedStartDate: Joi.date().required(),
      estimatedEndDate: Joi.date().greater(Joi.ref('estimatedStartDate')).required(),
      actualStartDate: Joi.date(),
      actualEndDate: Joi.date()
    }).required(),
    
    // Team
    team: Joi.object({
      projectManager: patterns.objectId,
      sponsor: Joi.object({
        internal: patterns.objectId,
        client: Joi.string()
      }),
      members: Joi.array().items(teamMemberDataSchema)
    }),
    
    // Financial
    financial: Joi.object({
      budget: Joi.object({
        total: Joi.object({
          amount: patterns.positiveNumber.required(),
          currency: patterns.currency
        }).required(),
        contingency: Joi.object({
          percentage: patterns.percentage,
          amount: patterns.positiveNumber
        })
      }).required(),
      billing: Joi.object({
        method: Joi.string().valid(
          'fixed_fee', 'hourly', 'daily', 'milestone', 
          'monthly_retainer', 'mixed'
        ),
        frequency: Joi.string().valid(
          'upon_completion', 'milestone', 'monthly', 
          'bi_weekly', 'weekly'
        ),
        terms: Joi.string(),
        specialTerms: Joi.string()
      })
    }).required(),
    
    // Milestones
    milestones: Joi.array().items(milestoneDataSchema),
    
    // Tags and Custom Fields
    tags: Joi.array().items(Joi.string()),
    customFields: Joi.object()
  })
});

/**
 * Update project validation schema
 */
const updateProjectSchema = Joi.object({
  body: createProjectSchema.extract('body').fork(
    ['name', 'description', 'client', 'type', 'timeline', 'financial'],
    (schema) => schema.optional()
  )
});

/**
 * Query projects validation schema
 */
const queryProjectSchema = Joi.object({
  query: Joi.object({
    page: Joi.number().integer().min(1),
    limit: Joi.number().integer().min(1).max(100),
    sortBy: Joi.string().valid(
      'createdAt', 'updatedAt', 'name', 'code', 
      'timeline.estimatedStartDate', 'timeline.estimatedEndDate',
      'financial.budget.total.amount', 'priority'
    ),
    sortOrder: Joi.string().valid('asc', 'desc'),
    search: Joi.string(),
    status: Joi.alternatives().try(
      Joi.string(),
      Joi.array().items(Joi.string())
    ),
    client: patterns.objectId,
    projectManager: patterns.objectId,
    type: Joi.string(),
    priority: Joi.string().valid('low', 'medium', 'high', 'critical'),
    tags: Joi.string(), // comma-separated
    startDateFrom: Joi.date(),
    startDateTo: Joi.date(),
    budgetMin: patterns.positiveNumber,
    budgetMax: patterns.positiveNumber,
    healthScoreMin: Joi.number().min(0).max(100),
    isDelayed: Joi.boolean(),
    isOverBudget: Joi.boolean(),
    includeArchived: Joi.boolean()
  })
});

/**
 * Project ID parameter validation
 */
const projectIdSchema = Joi.object({
  params: Joi.object({
    id: patterns.objectId.required()
  })
});

/**
 * Update project status validation
 */
const updateProjectStatusSchema = Joi.object({
  body: Joi.object({
    status: Joi.string().valid(
      'draft', 'pending_approval', 'approved', 'active', 
      'on_hold', 'completed', 'cancelled', 'archived'
    ).required(),
    reason: Joi.string(),
    holdReason: Joi.string().when('status', {
      is: 'on_hold',
      then: Joi.required()
    }),
    cancellationReason: Joi.string().when('status', {
      is: 'cancelled',
      then: Joi.required()
    })
  })
});

/**
 * Team member validation
 */
const teamMemberSchema = Joi.object({
  body: teamMemberDataSchema
});

/**
 * Milestone update validation
 */
const milestoneUpdateSchema = Joi.object({
  body: milestoneDataSchema.keys({
    status: Joi.string().valid(
      'pending', 'in_progress', 'completed', 'delayed', 'cancelled'
    ),
    completion: patterns.percentage,
    actualDate: Joi.date(),
    blockers: Joi.array().items(Joi.object({
      description: Joi.string(),
      severity: Joi.string().valid('low', 'medium', 'high', 'critical')
    })),
    comments: Joi.array().items(Joi.object({
      content: Joi.string()
    }))
  })
});

/**
 * Risk validation
 */
const riskSchema = Joi.object({
  body: riskDataSchema.keys({
    status: Joi.string().valid(
      'identified', 'analyzing', 'mitigating', 'monitoring', 'closed'
    )
  })
});

/**
 * Issue validation
 */
const issueSchema = Joi.object({
  body: Joi.object({
    title: Joi.string().required(),
    description: Joi.string().required(),
    type: Joi.string().valid(
      'bug', 'blocker', 'requirement_change', 
      'resource', 'technical', 'process'
    ).required(),
    severity: Joi.string().valid('low', 'medium', 'high', 'critical').required(),
    status: Joi.string().valid(
      'open', 'investigating', 'in_progress', 
      'resolved', 'closed', 'wont_fix'
    ),
    assignedTo: patterns.objectId,
    resolution: Joi.object({
      description: Joi.string()
    }),
    impactAnalysis: Joi.string(),
    workaround: Joi.string(),
    relatedRisks: Joi.array().items(patterns.objectId),
    attachments: Joi.array().items(Joi.object({
      name: Joi.string(),
      url: Joi.string()
    }))
  })
});

/**
 * Change request validation
 */
const changeRequestSchema = Joi.object({
  body: Joi.object({
    title: Joi.string().required(),
    description: Joi.string().required(),
    type: Joi.string().valid(
      'scope', 'timeline', 'budget', 'resource', 'technical', 'other'
    ).required(),
    impact: Joi.object({
      scope: Joi.string(),
      timeline: Joi.object({
        days: Joi.number(),
        description: Joi.string()
      }),
      budget: Joi.object({
        amount: patterns.positiveNumber,
        currency: patterns.currency,
        description: Joi.string()
      }),
      resources: Joi.string(),
      risks: Joi.array().items(Joi.string())
    }),
    justification: Joi.string().required(),
    priority: Joi.string().valid('low', 'medium', 'high', 'critical'),
    reviewers: Joi.array().items(Joi.object({
      reviewer: patterns.objectId.required(),
      role: Joi.string()
    })),
    implementationPlan: Joi.string()
  })
});

/**
 * Change request review validation
 */
const changeRequestReviewSchema = Joi.object({
  body: Joi.object({
    decision: Joi.string().valid(
      'approved', 'rejected', 'needs_info'
    ).required(),
    comments: Joi.string()
  })
});

/**
 * Deliverable validation
 */
const deliverableSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().required(),
    description: Joi.string(),
    type: Joi.string().valid(
      'document', 'presentation', 'software', 
      'report', 'training', 'workshop', 'other'
    ),
    dueDate: Joi.date(),
    status: Joi.string().valid(
      'pending', 'in_progress', 'submitted', 
      'under_review', 'approved', 'rejected'
    ),
    assignedTo: Joi.array().items(patterns.objectId),
    acceptanceCriteria: Joi.array().items(Joi.string()),
    dependencies: Joi.array().items(patterns.objectId)
  })
});

/**
 * Communication log validation
 */
const communicationLogSchema = Joi.object({
  body: Joi.object({
    type: Joi.string().valid(
      'meeting', 'email', 'call', 'presentation', 'report', 'other'
    ).required(),
    subject: Joi.string().required(),
    date: Joi.date().required(),
    duration: Joi.number().min(0),
    participants: Joi.array().items(Joi.object({
      person: patterns.objectId,
      external: Joi.object({
        name: Joi.string(),
        email: Joi.string().email(),
        organization: Joi.string(),
        role: Joi.string()
      })
    })),
    summary: Joi.string(),
    keyDecisions: Joi.array().items(Joi.string()),
    actionItems: Joi.array().items(Joi.object({
      description: Joi.string(),
      assignedTo: patterns.objectId,
      dueDate: Joi.date()
    })),
    visibility: Joi.string().valid('internal', 'client_visible', 'public')
  })
});

/**
 * Lesson learned validation
 */
const lessonLearnedSchema = Joi.object({
  body: Joi.object({
    category: Joi.string().valid(
      'process', 'technical', 'communication', 'resource', 'other'
    ).required(),
    description: Joi.string().required(),
    impact: Joi.string().valid('positive', 'negative', 'neutral').required(),
    recommendation: Joi.string(),
    applicableToFutureProjects: Joi.boolean()
  })
});

/**
 * Export project validation
 */
const exportProjectSchema = Joi.object({
  query: Joi.object({
    format: Joi.string().valid('json', 'pdf', 'xlsx'),
    sections: Joi.string() // comma-separated list
  })
});

/**
 * Project statistics query validation
 */
const projectStatsQuerySchema = Joi.object({
  query: Joi.object({
    clientId: patterns.objectId,
    dateFrom: Joi.date(),
    dateTo: Joi.date(),
    groupBy: Joi.string().valid('status', 'type', 'priority', 'client', 'month')
  })
});

module.exports = {
  createProjectSchema,
  updateProjectSchema,
  queryProjectSchema,
  projectIdSchema,
  updateProjectStatusSchema,
  teamMemberSchema,
  milestoneUpdateSchema,
  riskSchema,
  issueSchema,
  changeRequestSchema,
  changeRequestReviewSchema,
  deliverableSchema,
  communicationLogSchema,
  lessonLearnedSchema,
  exportProjectSchema,
  projectStatsQuerySchema
};