// server/admin/organization-management/validation/subscription-validation.js
/**
 * @file Subscription Validation
 * @description Validation schemas for subscription and billing management operations
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');
const moment = require('moment');

// Constants
const constants = require('../../../shared/config/constants');

// Custom validators
const customValidators = {
  objectId: (value, helpers) => {
    if (!mongoose.isValidObjectId(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  currency: (value, helpers) => {
    const validCurrencies = ['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'CNY', 'INR'];
    if (!validCurrencies.includes(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  creditCard: (value, helpers) => {
    // Basic credit card validation (Luhn algorithm)
    const sanitized = value.replace(/\s/g, '');
    if (!/^\d{13,19}$/.test(sanitized)) {
      return helpers.error('string.creditCard');
    }
    
    let sum = 0;
    let isEven = false;
    
    for (let i = sanitized.length - 1; i >= 0; i--) {
      let digit = parseInt(sanitized[i], 10);
      
      if (isEven) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }
      
      sum += digit;
      isEven = !isEven;
    }
    
    if (sum % 10 !== 0) {
      return helpers.error('string.creditCard');
    }
    
    return sanitized;
  },
  
  futureDate: (value, helpers) => {
    if (moment(value).isSameOrBefore(moment())) {
      return helpers.error('date.future');
    }
    return value;
  },
  
  billingCycle: (value, helpers) => {
    const validCycles = Object.values(constants.BILLING.SUBSCRIPTION_BILLING_CYCLES);
    if (!validCycles.includes(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  }
};

/**
 * Plan change validation
 */
const validatePlanChange = (data) => {
  const schema = Joi.object({
    planId: Joi.string()
      .custom(customValidators.objectId)
      .required()
      .messages({
        'any.invalid': 'Invalid plan ID format',
        'any.required': 'Target plan ID is required'
      }),
    
    // Change details
    reason: Joi.string()
      .min(10)
      .max(500)
      .required()
      .messages({
        'string.min': 'Reason must be at least 10 characters',
        'any.required': 'Reason for plan change is required'
      }),
    
    // Billing options
    prorate: Joi.boolean().default(true),
    
    effectiveDate: Joi.alternatives()
      .try(
        Joi.string().valid('immediate', 'next_billing_cycle'),
        Joi.date().custom(customValidators.futureDate)
      )
      .default('immediate')
      .messages({
        'date.future': 'Effective date must be in the future'
      }),
    
    changeBillingCycle: Joi.boolean().default(false),
    
    newBillingCycle: Joi.when('changeBillingCycle', {
      is: true,
      then: Joi.string()
        .custom(customValidators.billingCycle)
        .required()
        .messages({
          'any.required': 'New billing cycle is required when changing billing cycle'
        })
    }),
    
    // Payment handling
    chargeImmediately: Joi.boolean().default(true),
    
    paymentMethod: Joi.when('chargeImmediately', {
      is: true,
      then: Joi.string().valid('default', 'invoice', 'credit').default('default')
    }),
    
    // Credits and discounts
    applyCredits: Joi.boolean().default(true),
    preserveDiscounts: Joi.boolean().default(false),
    
    // Custom pricing (requires special permission)
    customPricing: Joi.object({
      amount: Joi.number().min(0).required(),
      currency: Joi.string().custom(customValidators.currency).default('USD'),
      description: Joi.string().max(200).required()
    }).optional(),
    
    // Admin options
    allowDowngrade: Joi.boolean().default(false),
    skipValidation: Joi.boolean().default(false),
    skipProration: Joi.boolean().default(false),
    overrideFrequencyLimit: Joi.boolean().default(false),
    
    // Notifications
    notifyCustomer: Joi.boolean().default(true),
    customNotificationMessage: Joi.string().max(500).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Subscription cancellation validation
 */
const validateSubscriptionCancel = (data) => {
  const schema = Joi.object({
    // Cancellation type
    immediate: Joi.boolean().default(false),
    
    // Cancellation details
    reason: Joi.object({
      category: Joi.string()
        .valid(
          'too_expensive',
          'missing_features',
          'not_using',
          'switching_competitor',
          'technical_issues',
          'customer_service',
          'temporary_pause',
          'other'
        )
        .required(),
      
      description: Joi.string()
        .min(10)
        .max(1000)
        .required()
        .messages({
          'string.min': 'Cancellation reason must be at least 10 characters'
        }),
      
      competitor: Joi.when('category', {
        is: 'switching_competitor',
        then: Joi.string().max(100).optional()
      }),
      
      missingFeatures: Joi.when('category', {
        is: 'missing_features',
        then: Joi.array().items(Joi.string()).optional()
      })
    }).required(),
    
    // Feedback
    feedback: Joi.object({
      satisfaction: Joi.number().integer().min(1).max(5).optional(),
      recommendation: Joi.number().integer().min(0).max(10).optional(),
      comments: Joi.string().max(2000).optional()
    }).optional(),
    
    // Refund options
    issueRefund: Joi.boolean().default(false),
    
    refundAmount: Joi.when('issueRefund', {
      is: true,
      then: Joi.number().min(0).optional()
    }),
    
    refundReason: Joi.when('issueRefund', {
      is: true,
      then: Joi.string().max(500).required()
    }),
    
    // Retention offer
    retentionOffer: Joi.object({
      type: Joi.string().valid('discount', 'credit', 'plan_change', 'pause').required(),
      discountPercentage: Joi.when('type', {
        is: 'discount',
        then: Joi.number().min(5).max(100).required()
      }),
      creditAmount: Joi.when('type', {
        is: 'credit',
        then: Joi.number().min(0).required()
      }),
      pauseDuration: Joi.when('type', {
        is: 'pause',
        then: Joi.number().integer().min(1).max(90).required() // Days
      }),
      description: Joi.string().max(500).optional()
    }).optional(),
    
    // Options
    preserveData: Joi.boolean().default(true),
    allowReactivation: Joi.boolean().default(true),
    skipExitSurvey: Joi.boolean().default(false),
    
    // Admin options
    skipNotifications: Joi.boolean().default(false),
    allowWithBalance: Joi.boolean().default(false),
    overrideCommitment: Joi.boolean().default(false)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Subscription reactivation validation
 */
const validateReactivation = (data) => {
  const schema = Joi.object({
    // Reactivation options
    planId: Joi.string()
      .custom(customValidators.objectId)
      .optional()
      .messages({
        'any.invalid': 'Invalid plan ID format'
      }),
    
    reason: Joi.string()
      .min(10)
      .max(500)
      .optional(),
    
    // Promotional offers
    applyPromotion: Joi.boolean().default(false),
    
    promotion: Joi.when('applyPromotion', {
      is: true,
      then: Joi.object({
        type: Joi.string().valid('discount', 'trial_extension', 'credit').required(),
        value: Joi.number().min(0).required(),
        duration: Joi.string().valid('once', 'repeating', 'forever').default('once'),
        durationInMonths: Joi.when('duration', {
          is: 'repeating',
          then: Joi.number().integer().min(1).max(12).required()
        }),
        code: Joi.string().max(50).optional()
      }).required()
    }),
    
    // Billing options
    billingCycle: Joi.string()
      .custom(customValidators.billingCycle)
      .optional(),
    
    startDate: Joi.date()
      .min('now')
      .default(() => new Date())
      .messages({
        'date.min': 'Start date cannot be in the past'
      }),
    
    // Payment
    paymentMethod: Joi.string().valid('default', 'new', 'invoice').default('default'),
    
    newPaymentMethod: Joi.when('paymentMethod', {
      is: 'new',
      then: Joi.object({
        type: Joi.string().valid('card', 'bank_account', 'paypal').required(),
        token: Joi.string().required() // Payment processor token
      }).required()
    }),
    
    // Options
    waiveFees: Joi.boolean().default(false),
    restorePreviousSettings: Joi.boolean().default(true),
    skipTrialIfUsed: Joi.boolean().default(true)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Discount application validation
 */
const validateDiscount = (data) => {
  const schema = Joi.object({
    type: Joi.string()
      .valid('percentage', 'fixed', 'trial_extension', 'volume', 'loyalty')
      .required()
      .messages({
        'any.required': 'Discount type is required'
      }),
    
    value: Joi.number()
      .when('type', {
        is: 'percentage',
        then: Joi.number().min(0).max(100).required(),
        otherwise: Joi.number().min(0).required()
      })
      .messages({
        'number.max': 'Percentage discount cannot exceed 100%'
      }),
    
    duration: Joi.string()
      .valid('once', 'repeating', 'forever')
      .required()
      .messages({
        'any.required': 'Discount duration is required'
      }),
    
    durationInMonths: Joi.when('duration', {
      is: 'repeating',
      then: Joi.number()
        .integer()
        .min(1)
        .max(36)
        .required()
        .messages({
          'any.required': 'Duration in months is required for repeating discounts',
          'number.max': 'Repeating discounts cannot exceed 36 months'
        })
    }),
    
    description: Joi.string()
      .min(10)
      .max(200)
      .required()
      .messages({
        'string.min': 'Discount description must be at least 10 characters',
        'any.required': 'Discount description is required'
      }),
    
    // Discount conditions
    conditions: Joi.object({
      minAmount: Joi.number().min(0).optional(),
      minUsers: Joi.number().integer().min(1).optional(),
      requiredPlan: Joi.string().optional(),
      validUntil: Joi.date().greater('now').optional()
    }).optional(),
    
    // Application options
    startsAt: Joi.date()
      .min('now')
      .default(() => new Date()),
    
    endsAt: Joi.date()
      .greater(Joi.ref('startsAt'))
      .optional()
      .messages({
        'date.greater': 'End date must be after start date'
      }),
    
    stackable: Joi.boolean().default(false),
    applyToExistingCharges: Joi.boolean().default(false),
    
    // Coupon code
    couponCode: Joi.string()
      .uppercase()
      .alphanum()
      .min(4)
      .max(20)
      .optional()
      .messages({
        'string.alphanum': 'Coupon code must contain only letters and numbers'
      }),
    
    maxRedemptions: Joi.number()
      .integer()
      .min(1)
      .optional(),
    
    // Admin metadata
    approvedBy: Joi.string().max(200).optional(),
    internalNotes: Joi.string().max(500).optional(),
    category: Joi.string()
      .valid('retention', 'acquisition', 'loyalty', 'compensation', 'promotional')
      .default('promotional')
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Credit application validation
 */
const validateCredit = (data) => {
  const schema = Joi.object({
    amount: Joi.number()
      .positive()
      .required()
      .messages({
        'number.positive': 'Credit amount must be positive',
        'any.required': 'Credit amount is required'
      }),
    
    currency: Joi.string()
      .custom(customValidators.currency)
      .default('USD'),
    
    reason: Joi.string()
      .valid(
        'goodwill',
        'service_issue',
        'pricing_error',
        'promotional',
        'retention',
        'compensation',
        'referral',
        'other'
      )
      .required()
      .messages({
        'any.required': 'Credit reason is required'
      }),
    
    description: Joi.string()
      .min(10)
      .max(500)
      .required()
      .messages({
        'string.min': 'Credit description must be at least 10 characters',
        'any.required': 'Credit description is required'
      }),
    
    // Credit options
    expiresAt: Joi.date()
      .greater('now')
      .optional()
      .messages({
        'date.greater': 'Expiration date must be in the future'
      }),
    
    applicableCharges: Joi.array()
      .items(Joi.string().valid(
        'subscription',
        'usage',
        'addons',
        'support',
        'all'
      ))
      .default(['all']),
    
    // Usage restrictions
    restrictions: Joi.object({
      minInvoiceAmount: Joi.number().min(0).optional(),
      maxUsagePerInvoice: Joi.number().min(0).optional(),
      specificPlans: Joi.array().items(Joi.string()).optional(),
      excludedCharges: Joi.array().items(Joi.string()).optional()
    }).optional(),
    
    // Auto-apply settings
    autoApply: Joi.boolean().default(true),
    priority: Joi.number().integer().min(1).max(10).default(5),
    
    // Admin options
    requiresApproval: Joi.boolean().default(false),
    
    approvalDetails: Joi.when('requiresApproval', {
      is: true,
      then: Joi.object({
        approver: Joi.string().email().required(),
        approvalNotes: Joi.string().max(500).optional(),
        approvalDeadline: Joi.date().greater('now').optional()
      }).required()
    }),
    
    // Tracking
    campaignId: Joi.string().max(50).optional(),
    sourceId: Joi.string().max(50).optional(),
    
    // Notifications
    notifyCustomer: Joi.boolean().default(true),
    customMessage: Joi.string().max(500).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Refund request validation
 */
const validateRefund = (data) => {
  const schema = Joi.object({
    paymentId: Joi.string()
      .custom(customValidators.objectId)
      .required()
      .messages({
        'any.invalid': 'Invalid payment ID format',
        'any.required': 'Payment ID is required'
      }),
    
    amount: Joi.number()
      .positive()
      .required()
      .messages({
        'number.positive': 'Refund amount must be positive',
        'any.required': 'Refund amount is required'
      }),
    
    reason: Joi.string()
      .valid(
        'duplicate',
        'fraudulent',
        'requested_by_customer',
        'service_issue',
        'pricing_error',
        'goodwill',
        'other'
      )
      .required()
      .messages({
        'any.required': 'Refund reason is required'
      }),
    
    description: Joi.string()
      .min(10)
      .max(1000)
      .required()
      .messages({
        'string.min': 'Refund description must be at least 10 characters',
        'any.required': 'Refund description is required'
      }),
    
    // Refund options
    issueAsCredit: Joi.boolean().default(false),
    
    refundMethod: Joi.when('issueAsCredit', {
      is: false,
      then: Joi.string()
        .valid('original_payment_method', 'bank_transfer', 'check')
        .default('original_payment_method')
    }),
    
    // Additional details for specific reasons
    duplicatePaymentId: Joi.when('reason', {
      is: 'duplicate',
      then: Joi.string().custom(customValidators.objectId).required()
    }),
    
    serviceIssueDetails: Joi.when('reason', {
      is: 'service_issue',
      then: Joi.object({
        ticketId: Joi.string().optional(),
        impactedServices: Joi.array().items(Joi.string()).optional(),
        downtimeHours: Joi.number().min(0).optional()
      }).required()
    }),
    
    // Processing options
    processImmediately: Joi.boolean().default(true),
    
    scheduledDate: Joi.when('processImmediately', {
      is: false,
      then: Joi.date().greater('now').required()
    }),
    
    // Accounting
    accountingNotes: Joi.string().max(500).optional(),
    adjustRevenue: Joi.boolean().default(true),
    
    // Internal metadata
    metadata: Joi.object({
      requestedBy: Joi.string().max(200).optional(),
      ticketNumber: Joi.string().max(50).optional(),
      approvalReference: Joi.string().max(100).optional()
    }).optional(),
    
    // Compliance
    requiresReview: Joi.boolean().default(false),
    complianceNotes: Joi.string().max(500).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Billing override validation
 */
const validateBillingOverride = (data) => {
  const schema = Joi.object({
    // Custom pricing
    customPricing: Joi.object({
      amount: Joi.number().min(0).required(),
      currency: Joi.string().custom(customValidators.currency).default('USD'),
      interval: Joi.string().custom(customValidators.billingCycle).required()
    }).optional(),
    
    // Billing cycle override
    billingCycleOverride: Joi.string()
      .custom(customValidators.billingCycle)
      .optional(),
    
    // Payment terms
    paymentTerms: Joi.string()
      .valid('immediate', 'net15', 'net30', 'net60', 'custom')
      .optional(),
    
    customPaymentTerms: Joi.when('paymentTerms', {
      is: 'custom',
      then: Joi.object({
        days: Joi.number().integer().min(1).max(365).required(),
        description: Joi.string().max(200).required()
      }).required()
    }),
    
    // Invoicing override
    invoicing: Joi.object({
      autoGenerate: Joi.boolean().optional(),
      consolidate: Joi.boolean().optional(),
      frequency: Joi.string().valid('monthly', 'quarterly', 'annually').optional(),
      deliveryMethod: Joi.string().valid('email', 'mail', 'both').optional(),
      customRecipients: Joi.array().items(Joi.string().email()).optional()
    }).optional(),
    
    // Exemptions
    exemptions: Joi.array()
      .items(Joi.string().valid(
        'late_fees',
        'setup_fees',
        'overage_charges',
        'taxes',
        'processing_fees'
      ))
      .optional(),
    
    // Contract terms
    contractTerms: Joi.object({
      startDate: Joi.date().required(),
      endDate: Joi.date().greater(Joi.ref('startDate')).required(),
      autoRenew: Joi.boolean().default(false),
      renewalTerms: Joi.when('autoRenew', {
        is: true,
        then: Joi.object({
          duration: Joi.number().integer().min(1).max(60).required(), // Months
          priceIncrease: Joi.number().min(0).max(100).optional() // Percentage
        }).required()
      }),
      earlyTerminationFee: Joi.number().min(0).optional()
    }).optional(),
    
    // Volume discounts
    volumeDiscounts: Joi.array().items(
      Joi.object({
        threshold: Joi.number().integer().min(1).required(),
        discountPercentage: Joi.number().min(0).max(100).required(),
        appliesToAdditionalOnly: Joi.boolean().default(false)
      })
    ).optional(),
    
    // Override metadata
    reason: Joi.string()
      .min(20)
      .max(500)
      .required()
      .messages({
        'string.min': 'Override reason must be at least 20 characters',
        'any.required': 'Override reason is required'
      }),
    
    approvedBy: Joi.string()
      .max(200)
      .required()
      .messages({
        'any.required': 'Approval information is required'
      }),
    
    expiresAt: Joi.date()
      .greater('now')
      .optional(),
    
    // Documentation
    contractId: Joi.string().max(100).optional(),
    salesforceId: Joi.string().max(50).optional(),
    internalNotes: Joi.string().max(2000).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Payment method update validation
 */
const validatePaymentMethodUpdate = (data) => {
  const schema = Joi.object({
    type: Joi.string()
      .valid('card', 'bank_account', 'paypal', 'invoice')
      .required()
      .messages({
        'any.required': 'Payment method type is required'
      }),
    
    // Card details
    card: Joi.when('type', {
      is: 'card',
      then: Joi.object({
        token: Joi.string().required(), // Payment processor token
        last4: Joi.string().length(4).pattern(/^\d+$/).optional(),
        brand: Joi.string().valid('visa', 'mastercard', 'amex', 'discover').optional(),
        expiryMonth: Joi.number().integer().min(1).max(12).optional(),
        expiryYear: Joi.number().integer().min(new Date().getFullYear()).optional(),
        holderName: Joi.string().max(200).optional()
      }).required()
    }),
    
    // Bank account details
    bankAccount: Joi.when('type', {
      is: 'bank_account',
      then: Joi.object({
        token: Joi.string().required(),
        accountType: Joi.string().valid('checking', 'savings').required(),
        last4: Joi.string().length(4).pattern(/^\d+$/).optional(),
        bankName: Joi.string().max(100).optional(),
        accountHolderName: Joi.string().max(200).optional()
      }).required()
    }),
    
    // PayPal details
    paypal: Joi.when('type', {
      is: 'paypal',
      then: Joi.object({
        token: Joi.string().required(),
        email: Joi.string().email().optional(),
        payerId: Joi.string().optional()
      }).required()
    }),
    
    // Billing address
    billingAddress: Joi.object({
      line1: Joi.string().max(200).required(),
      line2: Joi.string().max(200).optional(),
      city: Joi.string().max(100).required(),
      state: Joi.string().max(100).optional(),
      postalCode: Joi.string().max(20).required(),
      country: Joi.string().length(2).uppercase().required()
    }).optional(),
    
    // Options
    setAsDefault: Joi.boolean().default(true),
    verifyBeforeUse: Joi.boolean().default(true),
    allowFutureCharges: Joi.boolean().default(true),
    
    // Backup payment method
    backupMethodId: Joi.string()
      .custom(customValidators.objectId)
      .optional(),
    
    // Metadata
    metadata: Joi.object().pattern(
      Joi.string(),
      Joi.string()
    ).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Bulk subscription update validation
 */
const validateBulkSubscriptionUpdate = (data) => {
  const schema = Joi.object({
    organizationIds: Joi.array()
      .items(Joi.string().custom(customValidators.objectId))
      .min(1)
      .max(100)
      .required()
      .messages({
        'array.min': 'At least one organization ID is required',
        'array.max': 'Maximum 100 subscriptions can be updated at once'
      }),
    
    updates: Joi.object({
      // Plan changes
      planId: Joi.string().custom(customValidators.objectId).optional(),
      
      // Discounts
      applyDiscount: Joi.object({
        type: Joi.string().valid('percentage', 'fixed').required(),
        value: Joi.number().positive().required(),
        duration: Joi.string().valid('once', 'repeating', 'forever').required(),
        durationInMonths: Joi.when('duration', {
          is: 'repeating',
          then: Joi.number().integer().min(1).max(12).required()
        })
      }).optional(),
      
      // Billing cycle
      billingCycle: Joi.string().custom(customValidators.billingCycle).optional(),
      
      // Payment terms
      paymentTerms: Joi.string().valid('immediate', 'net15', 'net30', 'net60').optional(),
      
      // Status changes
      pauseSubscription: Joi.boolean().optional(),
      resumeSubscription: Joi.boolean().optional()
    }).min(1).required(),
    
    // Bulk options
    skipFailures: Joi.boolean().default(false),
    applyProration: Joi.boolean().default(true),
    effectiveDate: Joi.date().min('now').default(() => new Date()),
    
    // Processing
    batchSize: Joi.number().integer().min(1).max(20).default(10),
    delayBetweenBatches: Joi.number().integer().min(100).max(5000).default(500),
    
    // Notifications
    notifyUsers: Joi.boolean().default(true),
    notificationTemplate: Joi.string().max(50).optional(),
    
    // Reason
    reason: Joi.string()
      .min(10)
      .max(500)
      .required()
      .messages({
        'string.min': 'Bulk update reason must be at least 10 characters',
        'any.required': 'Bulk update reason is required'
      })
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Trial extension validation
 */
const validateTrialExtension = (data) => {
  const schema = Joi.object({
    days: Joi.number()
      .integer()
      .min(1)
      .max(30)
      .required()
      .messages({
        'number.min': 'Trial extension must be at least 1 day',
        'number.max': 'Trial extension cannot exceed 30 days',
        'any.required': 'Number of days is required'
      }),
    
    reason: Joi.string()
      .min(10)
      .max(500)
      .required()
      .messages({
        'string.min': 'Extension reason must be at least 10 characters',
        'any.required': 'Extension reason is required'
      }),
    
    // Options
    notifyCustomer: Joi.boolean().default(true),
    allowOnlyOnce: Joi.boolean().default(true),
    requireConversion: Joi.boolean().default(false),
    
    // Conditions
    conditions: Joi.object({
      completedOnboarding: Joi.boolean().optional(),
      addedPaymentMethod: Joi.boolean().optional(),
      minimumActivity: Joi.number().min(0).optional()
    }).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

module.exports = {
  validatePlanChange,
  validateSubscriptionCancel,
  validateReactivation,
  validateDiscount,
  validateCredit,
  validateRefund,
  validateBillingOverride,
  validatePaymentMethodUpdate,
  validateBulkSubscriptionUpdate,
  validateTrialExtension
};