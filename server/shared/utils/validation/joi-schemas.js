// /server/shared/utils/validation/joi-schemas.js

/**
 * @file Common Joi Validation Schemas
 * @description Reusable validation schemas for the platform
 * @version 1.0.0
 */

const Joi = require('joi');

const constants = require('../../config/constants');

/**
 * Common field validations
 */
const common = {
  // MongoDB ObjectId
  objectId: Joi.string()
    .pattern(constants.REGEX.MONGODB_ID)
    .message('Invalid ID format'),
  
  // UUID
  uuid: Joi.string()
    .pattern(constants.REGEX.UUID)
    .message('Invalid UUID format'),
  
  // Email
  email: Joi.string()
    .email({ tlds: { allow: true } })
    .max(254)
    .lowercase()
    .trim()
    .required(),
  
  // Username
  username: Joi.string()
    .pattern(constants.REGEX.USERNAME)
    .min(3)
    .max(30)
    .lowercase()
    .trim()
    .message('Username must be 3-30 characters and contain only letters, numbers, dots, underscores, and hyphens'),
  
  // Password
  password: Joi.string()
    .min(constants.AUTH.PASSWORD.MIN_LENGTH)
    .max(constants.AUTH.PASSWORD.MAX_LENGTH)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .message('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  // Phone number
  phone: Joi.string()
    .pattern(constants.REGEX.PHONE)
    .message('Invalid phone number format'),
  
  // URL
  url: Joi.string()
    .uri({ scheme: ['http', 'https'] })
    .max(2048),
  
  // Slug
  slug: Joi.string()
    .pattern(constants.REGEX.SLUG)
    .min(3)
    .max(100)
    .lowercase()
    .trim()
    .message('Slug must contain only lowercase letters, numbers, and hyphens'),
  
  // Date
  date: Joi.date().iso(),
  
  // Boolean
  boolean: Joi.boolean(),
  
  // Pagination
  page: Joi.number()
    .integer()
    .min(1)
    .default(constants.API.PAGINATION.DEFAULT_PAGE),
  
  limit: Joi.number()
    .integer()
    .min(constants.API.PAGINATION.MIN_LIMIT)
    .max(constants.API.PAGINATION.MAX_LIMIT)
    .default(constants.API.PAGINATION.DEFAULT_LIMIT),
  
  // Sort
  sortBy: Joi.string()
    .valid('createdAt', 'updatedAt', 'name', 'email', 'status')
    .default('createdAt'),
  
  sortOrder: Joi.string()
    .valid('asc', 'desc', '1', '-1')
    .default('desc'),
  
  // Status
  status: Joi.string()
    .valid(...Object.values(constants.USER_STATUS)),
  
  // Role
  role: Joi.string()
    .valid(
      ...Object.values(constants.ROLES.PLATFORM),
      ...Object.values(constants.ROLES.CORE_BUSINESS),
      ...Object.values(constants.ROLES.ORGANIZATION),
      ...Object.values(constants.ROLES.RECRUITMENT)
    )
};

/**
 * User schemas
 */
const user = {
  // User registration
  register: Joi.object({
    email: common.email,
    password: common.password,
    confirmPassword: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({ 'any.only': 'Passwords do not match' }),
    firstName: Joi.string().min(2).max(50).trim().required(),
    lastName: Joi.string().min(2).max(50).trim().required(),
    username: common.username.optional(),
    phone: common.phone.optional(),
    acceptTerms: Joi.boolean().valid(true).required(),
    organizationInviteCode: Joi.string().optional()
  }),
  
  // User login
  login: Joi.object({
    email: common.email,
    password: Joi.string().required(),
    rememberMe: common.boolean.optional(),
    deviceId: Joi.string().optional(),
    twoFactorCode: Joi.string().length(6).optional()
  }),
  
  // Update profile
  updateProfile: Joi.object({
    firstName: Joi.string().min(2).max(50).trim(),
    lastName: Joi.string().min(2).max(50).trim(),
    username: common.username,
    phone: common.phone,
    bio: Joi.string().max(500),
    avatar: common.url,
    timezone: Joi.string(),
    language: Joi.string().valid('en', 'es', 'fr', 'de', 'pt', 'zh'),
    notifications: Joi.object({
      email: common.boolean,
      sms: common.boolean,
      push: common.boolean
    })
  }),
  
  // Change password
  changePassword: Joi.object({
    currentPassword: Joi.string().required(),
    newPassword: common.password,
    confirmPassword: Joi.string()
      .valid(Joi.ref('newPassword'))
      .required()
      .messages({ 'any.only': 'Passwords do not match' })
  }),
  
  // Reset password
  resetPassword: Joi.object({
    token: Joi.string().required(),
    password: common.password,
    confirmPassword: Joi.string()
      .valid(Joi.ref('password'))
      .required()
      .messages({ 'any.only': 'Passwords do not match' })
  })
};

/**
 * Organization schemas
 */
const organization = {
  // Create organization
  create: Joi.object({
    name: Joi.string().min(2).max(100).trim().required(),
    slug: common.slug.required(),
    type: Joi.string()
      .valid(...Object.values(constants.ORGANIZATION.TYPES))
      .required(),
    description: Joi.string().max(500),
    website: common.url,
    email: common.email,
    phone: common.phone,
    address: Joi.object({
      street: Joi.string().max(100),
      city: Joi.string().max(50),
      state: Joi.string().max(50),
      country: Joi.string().length(2), // ISO country code
      postalCode: Joi.string().max(20)
    }),
    size: Joi.string()
      .valid(...Object.values(constants.ORGANIZATION.SIZE_RANGES)),
    industry: Joi.string().max(50),
    subscription: Joi.string()
      .valid(...Object.values(constants.ORGANIZATION.SUBSCRIPTION_TIERS))
      .default(constants.ORGANIZATION.SUBSCRIPTION_TIERS.TRIAL)
  }),
  
  // Update organization
  update: Joi.object({
    name: Joi.string().min(2).max(100).trim(),
    description: Joi.string().max(500),
    website: common.url,
    email: common.email,
    phone: common.phone,
    address: Joi.object({
      street: Joi.string().max(100),
      city: Joi.string().max(50),
      state: Joi.string().max(50),
      country: Joi.string().length(2),
      postalCode: Joi.string().max(20)
    }),
    size: Joi.string()
      .valid(...Object.values(constants.ORGANIZATION.SIZE_RANGES)),
    industry: Joi.string().max(50),
    settings: Joi.object({
      theme: Joi.string().valid('light', 'dark', 'auto'),
      language: Joi.string().valid('en', 'es', 'fr', 'de', 'pt', 'zh'),
      timezone: Joi.string(),
      features: Joi.object()
    })
  }),
  
  // Invite member
  inviteMember: Joi.object({
    email: common.email,
    role: Joi.string()
      .valid(...Object.values(constants.ROLES.ORGANIZATION))
      .required(),
    message: Joi.string().max(500),
    permissions: Joi.array().items(Joi.string()),
    expiresIn: Joi.number().integer().min(1).max(30).default(7) // days
  })
};

/**
 * Recruitment schemas
 */
const recruitment = {
  // Create job
  createJob: Joi.object({
    title: Joi.string().min(3).max(100).trim().required(),
    description: Joi.string().min(50).max(5000).required(),
    requirements: Joi.array().items(Joi.string()).min(1).required(),
    responsibilities: Joi.array().items(Joi.string()).min(1).required(),
    location: Joi.object({
      type: Joi.string().valid('onsite', 'remote', 'hybrid').required(),
      city: Joi.when('type', {
        is: Joi.not('remote'),
        then: Joi.string().required(),
        otherwise: Joi.optional()
      }),
      state: Joi.string(),
      country: Joi.string().length(2).required()
    }).required(),
    salary: Joi.object({
      min: Joi.number().positive(),
      max: Joi.number().positive().greater(Joi.ref('min')),
      currency: Joi.string().length(3).default('USD'),
      period: Joi.string().valid('hourly', 'monthly', 'yearly').default('yearly')
    }),
    type: Joi.string().valid('full-time', 'part-time', 'contract', 'internship').required(),
    category: Joi.string().required(),
    tags: Joi.array().items(Joi.string()).max(10),
    applicationDeadline: common.date.min('now'),
    status: Joi.string()
      .valid(...Object.values(constants.RECRUITMENT.JOB_STATUS))
      .default(constants.RECRUITMENT.JOB_STATUS.DRAFT)
  }),
  
  // Submit application
  submitApplication: Joi.object({
    jobId: common.objectId.required(),
    resume: Joi.object({
      url: common.url.required(),
      filename: Joi.string().required(),
      size: Joi.number().max(constants.FILE_UPLOAD.MAX_SIZE.DOCUMENT).required()
    }).required(),
    coverLetter: Joi.string().max(2000),
    portfolio: common.url,
    expectedSalary: Joi.object({
      amount: Joi.number().positive().required(),
      currency: Joi.string().length(3).default('USD'),
      period: Joi.string().valid('hourly', 'monthly', 'yearly').default('yearly')
    }),
    availability: common.date.min('now'),
    answers: Joi.array().items(Joi.object({
      questionId: common.objectId.required(),
      answer: Joi.string().max(500).required()
    }))
  }),
  
  // Update application status
  updateApplicationStatus: Joi.object({
    status: Joi.string()
      .valid(...Object.values(constants.RECRUITMENT.APPLICATION_STATUS))
      .required(),
    notes: Joi.string().max(1000),
    nextSteps: Joi.string().max(500),
    interviewDate: common.date.when('status', {
      is: constants.RECRUITMENT.APPLICATION_STATUS.INTERVIEW_SCHEDULED,
      then: Joi.required(),
      otherwise: Joi.optional()
    })
  })
};

/**
 * Billing schemas
 */
const billing = {
  // Create subscription
  createSubscription: Joi.object({
    tier: Joi.string()
      .valid(...Object.values(constants.ORGANIZATION.SUBSCRIPTION_TIERS))
      .required(),
    billingCycle: Joi.string().valid('monthly', 'yearly').required(),
    paymentMethodId: Joi.string().required(),
    couponCode: Joi.string().optional()
  }),
  
  // Update payment method
  updatePaymentMethod: Joi.object({
    paymentMethodId: Joi.string().required(),
    setAsDefault: common.boolean.default(true)
  })
};

/**
 * Query parameter schemas
 */
const query = {
  // Pagination
  pagination: Joi.object({
    page: common.page,
    limit: common.limit,
    sortBy: common.sortBy,
    sortOrder: common.sortOrder
  }),
  
  // Search
  search: Joi.object({
    q: Joi.string().min(1).max(100).trim(),
    fields: Joi.array().items(Joi.string()),
    exact: common.boolean.default(false)
  }),
  
  // Date range
  dateRange: Joi.object({
    startDate: common.date,
    endDate: common.date.min(Joi.ref('startDate'))
  }),
  
  // Filters
  filters: Joi.object({
    status: Joi.alternatives().try(
      Joi.string(),
      Joi.array().items(Joi.string())
    ),
    type: Joi.alternatives().try(
      Joi.string(),
      Joi.array().items(Joi.string())
    ),
    tags: Joi.array().items(Joi.string()),
    organizationId: common.objectId,
    userId: common.objectId
  })
};

/**
 * File upload schemas
 */
const file = {
  // Single file upload
  single: Joi.object({
    fieldname: Joi.string().required(),
    originalname: Joi.string().required(),
    encoding: Joi.string().required(),
    mimetype: Joi.string().required(),
    size: Joi.number().max(constants.FILE_UPLOAD.MAX_SIZE.DEFAULT).required(),
    buffer: Joi.binary().when('storage', {
      is: 'memory',
      then: Joi.required(),
      otherwise: Joi.optional()
    }),
    path: Joi.string().when('storage', {
      is: 'disk',
      then: Joi.required(),
      otherwise: Joi.optional()
    })
  }),
  
  // Multiple file upload
  multiple: Joi.array().items(
    Joi.object({
      fieldname: Joi.string().required(),
      originalname: Joi.string().required(),
      encoding: Joi.string().required(),
      mimetype: Joi.string().required(),
      size: Joi.number().required()
    })
  ).max(10)
};

module.exports = {
  common,
  user,
  organization,
  recruitment,
  billing,
  query,
  file,
  
  // Utility function to validate
  validate: (schema, data, options = {}) => {
    const defaultOptions = {
      abortEarly: false,
      stripUnknown: true,
      convert: true,
      ...options
    };
    
    return schema.validate(data, defaultOptions);
  }
};