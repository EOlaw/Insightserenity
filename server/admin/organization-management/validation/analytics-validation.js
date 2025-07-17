// server/admin/organization-management/validation/analytics-validation.js
/**
 * @file Analytics Validation
 * @description Validation schemas for analytics and reporting operations
 * @version 1.0.0
 */

const Joi = require('joi');
const mongoose = require('mongoose');
const moment = require('moment');

// Custom validators
const customValidators = {
  objectId: (value, helpers) => {
    if (!mongoose.isValidObjectId(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  dateRange: (value, helpers) => {
    const { start, end } = value;
    if (moment(start).isAfter(moment(end))) {
      return helpers.error('dateRange.invalid');
    }
    return value;
  },
  
  metricName: (value, helpers) => {
    const validMetrics = [
      'dailyActiveUsers',
      'weeklyActiveUsers',
      'monthlyActiveUsers',
      'sessionDuration',
      'pageViews',
      'apiCalls',
      'errorRate',
      'responseTime',
      'revenue',
      'churnRate',
      'retentionRate',
      'conversionRate',
      'customerLifetimeValue',
      'averageOrderValue',
      'netPromoterScore'
    ];
    
    if (!validMetrics.includes(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  aggregationPeriod: (value, helpers) => {
    const validPeriods = ['minute', 'hour', 'day', 'week', 'month', 'quarter', 'year'];
    if (!validPeriods.includes(value)) {
      return helpers.error('any.invalid');
    }
    return value;
  },
  
  timezone: (value, helpers) => {
    try {
      const validTimezones = Intl.supportedValuesOf('timeZone');
      if (!validTimezones.includes(value)) {
        return helpers.error('any.invalid');
      }
      return value;
    } catch {
      // Fallback for older Node versions
      return value;
    }
  }
};

// Custom error messages
const messages = {
  'dateRange.invalid': 'Start date must be before end date'
};

/**
 * Analytics query validation
 */
const validateAnalyticsQuery = (data) => {
  const schema = Joi.object({
    // Time period
    period: Joi.string()
      .valid('hour', 'day', 'week', 'month', 'quarter', 'year', 'custom')
      .default('month'),
    
    // Custom date range
    startDate: Joi.when('period', {
      is: 'custom',
      then: Joi.date().required(),
      otherwise: Joi.date().optional()
    }),
    
    endDate: Joi.when('period', {
      is: 'custom',
      then: Joi.date().greater(Joi.ref('startDate')).required(),
      otherwise: Joi.date().optional()
    }),
    
    // Metrics selection
    metrics: Joi.array()
      .items(Joi.string().custom(customValidators.metricName))
      .min(1)
      .max(20)
      .optional(),
    
    // Grouping and aggregation
    groupBy: Joi.array()
      .items(Joi.string().valid(
        'hour',
        'day',
        'week',
        'month',
        'plan',
        'country',
        'industry',
        'userType',
        'device',
        'browser'
      ))
      .max(3)
      .optional(),
    
    aggregation: Joi.string()
      .valid('sum', 'average', 'min', 'max', 'count', 'unique')
      .default('average'),
    
    // Filters
    filters: Joi.object({
      plan: Joi.array().items(Joi.string()).optional(),
      country: Joi.array().items(Joi.string().length(2).uppercase()).optional(),
      industry: Joi.array().items(Joi.string()).optional(),
      minRevenue: Joi.number().min(0).optional(),
      maxRevenue: Joi.number().greater(Joi.ref('minRevenue')).optional(),
      activeOnly: Joi.boolean().optional()
    }).optional(),
    
    // Comparison
    compareWith: Joi.string()
      .valid('previous_period', 'previous_year', 'custom_period')
      .optional(),
    
    comparisonStartDate: Joi.when('compareWith', {
      is: 'custom_period',
      then: Joi.date().required()
    }),
    
    comparisonEndDate: Joi.when('compareWith', {
      is: 'custom_period',
      then: Joi.date().greater(Joi.ref('comparisonStartDate')).required()
    }),
    
    // Display options
    includePercentChange: Joi.boolean().default(true),
    includeTrends: Joi.boolean().default(true),
    includeForecasts: Joi.boolean().default(false),
    
    // Performance options
    sampleSize: Joi.when('period', {
      is: Joi.valid('year', 'custom'),
      then: Joi.number().integer().min(1000).max(100000).optional()
    }),
    
    forceRefresh: Joi.boolean().default(false),
    timezone: Joi.string().custom(customValidators.timezone).default('UTC')
  }).custom((value, helpers) => {
    // Additional validation for date ranges
    if (value.startDate && value.endDate) {
      const daysDiff = moment(value.endDate).diff(moment(value.startDate), 'days');
      if (daysDiff > 365) {
        return helpers.error('any.invalid', {
          message: 'Date range cannot exceed 365 days'
        });
      }
    }
    return value;
  });
  
  return schema.validate(data, { abortEarly: false, messages });
};

/**
 * Report configuration validation
 */
const validateReportConfig = (data) => {
  const schema = Joi.object({
    type: Joi.string()
      .valid(
        'executive_summary',
        'usage_report',
        'financial_report',
        'engagement_report',
        'health_report',
        'compliance_report',
        'custom'
      )
      .required()
      .messages({
        'any.required': 'Report type is required'
      }),
    
    // Report period
    period: Joi.object({
      type: Joi.string()
        .valid('day', 'week', 'month', 'quarter', 'year', 'custom')
        .required(),
      
      start: Joi.when('type', {
        is: 'custom',
        then: Joi.date().required()
      }),
      
      end: Joi.when('type', {
        is: 'custom',
        then: Joi.date().greater(Joi.ref('start')).required()
      })
    }).required(),
    
    // Report sections (for custom reports)
    sections: Joi.when('type', {
      is: 'custom',
      then: Joi.array()
        .items(Joi.string().valid(
          'summary',
          'kpis',
          'trends',
          'user_analytics',
          'revenue_analytics',
          'usage_analytics',
          'performance_metrics',
          'security_audit',
          'recommendations'
        ))
        .min(1)
        .required()
    }),
    
    // Data options
    includeCharts: Joi.boolean().default(true),
    includeRawData: Joi.boolean().default(false),
    includeBenchmarks: Joi.boolean().default(true),
    includeProjections: Joi.boolean().default(false),
    
    // Comparison options
    compareWithPrevious: Joi.boolean().default(true),
    
    comparisonPeriods: Joi.when('compareWithPrevious', {
      is: true,
      then: Joi.number().integer().min(1).max(12).default(1)
    }),
    
    // Formatting
    format: Joi.string()
      .valid('json', 'pdf', 'excel', 'csv', 'html')
      .default('json'),
    
    formatting: Joi.object({
      dateFormat: Joi.string().default('YYYY-MM-DD'),
      timeFormat: Joi.string().default('HH:mm:ss'),
      numberFormat: Joi.string().valid('standard', 'currency', 'percentage').default('standard'),
      currencyCode: Joi.when('numberFormat', {
        is: 'currency',
        then: Joi.string().length(3).uppercase().default('USD')
      }),
      decimals: Joi.number().integer().min(0).max(4).default(2),
      thousandsSeparator: Joi.boolean().default(true)
    }).optional(),
    
    // Branding (for PDF/HTML)
    branding: Joi.when('format', {
      is: Joi.valid('pdf', 'html'),
      then: Joi.object({
        logo: Joi.string().uri().optional(),
        primaryColor: Joi.string().pattern(/^#[0-9A-F]{6}$/i).optional(),
        companyName: Joi.string().max(100).optional(),
        reportTitle: Joi.string().max(200).optional(),
        footer: Joi.string().max(500).optional()
      }).optional()
    }),
    
    // Export options
    export: Joi.boolean().default(false),
    
    exportOptions: Joi.when('export', {
      is: true,
      then: Joi.object({
        filename: Joi.string().max(100).optional(),
        compress: Joi.boolean().default(false),
        encrypt: Joi.boolean().default(false),
        password: Joi.when('encrypt', {
          is: true,
          then: Joi.string().min(8).required()
        }),
        expiresIn: Joi.number().integer().min(1).max(168).optional() // Hours
      }).optional()
    }),
    
    // Delivery options
    delivery: Joi.object({
      method: Joi.string().valid('download', 'email', 'webhook').default('download'),
      
      email: Joi.when('method', {
        is: 'email',
        then: Joi.object({
          recipients: Joi.array().items(Joi.string().email()).min(1).required(),
          subject: Joi.string().max(200).optional(),
          message: Joi.string().max(1000).optional()
        }).required()
      }),
      
      webhook: Joi.when('method', {
        is: 'webhook',
        then: Joi.object({
          url: Joi.string().uri().required(),
          headers: Joi.object().pattern(Joi.string(), Joi.string()).optional(),
          retries: Joi.number().integer().min(0).max(3).default(1)
        }).required()
      })
    }).optional(),
    
    // Schedule options
    schedule: Joi.object({
      frequency: Joi.string()
        .valid('once', 'daily', 'weekly', 'monthly', 'quarterly')
        .required(),
      
      time: Joi.string()
        .pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/)
        .default('09:00'),
      
      dayOfWeek: Joi.when('frequency', {
        is: 'weekly',
        then: Joi.number().integer().min(0).max(6).required() // 0 = Sunday
      }),
      
      dayOfMonth: Joi.when('frequency', {
        is: 'monthly',
        then: Joi.number().integer().min(1).max(31).required()
      }),
      
      timezone: Joi.string().custom(customValidators.timezone).default('UTC'),
      
      endDate: Joi.date().greater('now').optional()
    }).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Organization comparison validation
 */
const validateComparisonQuery = (data) => {
  const schema = Joi.object({
    organizationIds: Joi.array()
      .items(Joi.string().custom(customValidators.objectId))
      .min(2)
      .max(10)
      .required()
      .messages({
        'array.min': 'At least 2 organizations required for comparison',
        'array.max': 'Maximum 10 organizations can be compared',
        'any.required': 'Organization IDs are required'
      }),
    
    config: Joi.object({
      period: Joi.string()
        .valid('day', 'week', 'month', 'quarter', 'year', 'custom')
        .default('month'),
      
      startDate: Joi.when('period', {
        is: 'custom',
        then: Joi.date().required()
      }),
      
      endDate: Joi.when('period', {
        is: 'custom',
        then: Joi.date().greater(Joi.ref('startDate')).required()
      }),
      
      metrics: Joi.array()
        .items(Joi.string().custom(customValidators.metricName))
        .min(1)
        .max(10)
        .default(['revenue', 'activeUsers', 'churnRate']),
      
      // Comparison options
      normalizeBySize: Joi.boolean().default(true),
      includeIndustryBenchmarks: Joi.boolean().default(false),
      includeGrowthRates: Joi.boolean().default(true),
      
      // Grouping
      groupBy: Joi.string()
        .valid('none', 'plan', 'industry', 'size', 'age')
        .default('none'),
      
      // Display options
      chartType: Joi.string()
        .valid('bar', 'line', 'radar', 'scatter')
        .default('bar'),
      
      showRankings: Joi.boolean().default(true),
      showPercentiles: Joi.boolean().default(true),
      highlightOutliers: Joi.boolean().default(true)
    }).default()
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Growth analytics validation
 */
const validateGrowthQuery = (data) => {
  const schema = Joi.object({
    periods: Joi.number()
      .integer()
      .min(1)
      .max(24)
      .default(12)
      .messages({
        'number.max': 'Maximum 24 periods allowed'
      }),
    
    periodType: Joi.string()
      .valid('day', 'week', 'month', 'quarter', 'year')
      .default('month'),
    
    metrics: Joi.array()
      .items(Joi.string().valid(
        'users',
        'revenue',
        'usage',
        'projects',
        'retention',
        'expansion'
      ))
      .default(['users', 'revenue']),
    
    // Analysis options
    includeForecasts: Joi.boolean().default(false),
    
    forecastPeriods: Joi.when('includeForecasts', {
      is: true,
      then: Joi.number().integer().min(1).max(12).default(3)
    }),
    
    includeCohorts: Joi.boolean().default(false),
    
    cohortOptions: Joi.when('includeCohorts', {
      is: true,
      then: Joi.object({
        type: Joi.string().valid('signup', 'first_purchase', 'plan_upgrade').default('signup'),
        segments: Joi.array().items(Joi.string()).optional()
      }).optional()
    }),
    
    // Trend analysis
    trendAnalysis: Joi.object({
      method: Joi.string().valid('linear', 'exponential', 'polynomial').default('linear'),
      confidenceInterval: Joi.number().min(0.8).max(0.99).default(0.95),
      seasonalAdjustment: Joi.boolean().default(true)
    }).optional(),
    
    // Benchmarking
    includeBenchmarks: Joi.boolean().default(false),
    
    benchmarkSource: Joi.when('includeBenchmarks', {
      is: true,
      then: Joi.string().valid('industry', 'plan_tier', 'company_size').default('industry')
    })
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Performance query validation
 */
const validatePerformanceQuery = (data) => {
  const schema = Joi.object({
    period: Joi.string()
      .valid('hour', 'day', 'week', 'month')
      .default('day'),
    
    startDate: Joi.date().optional(),
    endDate: Joi.date().when('startDate', {
      is: Joi.exist(),
      then: Joi.date().greater(Joi.ref('startDate')).required()
    }),
    
    // Metrics selection
    categories: Joi.array()
      .items(Joi.string().valid(
        'api',
        'system',
        'database',
        'user_experience',
        'reliability',
        'scalability'
      ))
      .default(['api', 'system', 'user_experience']),
    
    // Granularity
    granularity: Joi.string()
      .valid('minute', 'hour', 'day')
      .default('hour'),
    
    // Percentiles
    percentiles: Joi.array()
      .items(Joi.number().min(0).max(100))
      .default([50, 90, 95, 99]),
    
    // Thresholds
    slaThresholds: Joi.object({
      responseTime: Joi.number().positive().default(1000), // ms
      uptime: Joi.number().min(0).max(100).default(99.9), // percentage
      errorRate: Joi.number().min(0).max(100).default(1) // percentage
    }).optional(),
    
    // Filtering
    filters: Joi.object({
      endpoints: Joi.array().items(Joi.string()).optional(),
      services: Joi.array().items(Joi.string()).optional(),
      excludeHealthChecks: Joi.boolean().default(true),
      minSampleSize: Joi.number().integer().min(1).default(10)
    }).optional(),
    
    // Analysis options
    includeAnomalies: Joi.boolean().default(true),
    
    anomalyDetection: Joi.when('includeAnomalies', {
      is: true,
      then: Joi.object({
        method: Joi.string().valid('zscore', 'isolation_forest', 'lstm').default('zscore'),
        sensitivity: Joi.number().min(0).max(1).default(0.8),
        lookbackPeriods: Joi.number().integer().min(1).default(7)
      }).optional()
    })
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Predictive analytics validation
 */
const validatePredictiveQuery = (data) => {
  const schema = Joi.object({
    metrics: Joi.array()
      .items(Joi.string().valid(
        'revenue',
        'users',
        'churn',
        'usage',
        'conversion'
      ))
      .min(1)
      .required()
      .messages({
        'array.min': 'At least one metric is required for prediction'
      }),
    
    historicalPeriods: Joi.number()
      .integer()
      .min(6)
      .max(36)
      .default(12)
      .messages({
        'number.min': 'At least 6 historical periods required for accurate predictions'
      }),
    
    forecastPeriods: Joi.number()
      .integer()
      .min(1)
      .max(12)
      .default(3),
    
    // Model configuration
    models: Joi.array()
      .items(Joi.string().valid(
        'arima',
        'prophet',
        'linear_regression',
        'random_forest',
        'neural_network'
      ))
      .default(['arima', 'prophet']),
    
    // Feature engineering
    features: Joi.object({
      includeSeasonality: Joi.boolean().default(true),
      includeTrends: Joi.boolean().default(true),
      includeExternalFactors: Joi.boolean().default(false),
      
      externalFactors: Joi.when('includeExternalFactors', {
        is: true,
        then: Joi.array().items(Joi.string().valid(
          'holidays',
          'marketing_campaigns',
          'economic_indicators',
          'competitor_actions'
        )).optional()
      })
    }).optional(),
    
    // Confidence and validation
    confidenceLevel: Joi.number()
      .min(0.8)
      .max(0.99)
      .default(0.95),
    
    validationMethod: Joi.string()
      .valid('holdout', 'cross_validation', 'time_series_split')
      .default('time_series_split'),
    
    // Scenario analysis
    scenarios: Joi.array().items(
      Joi.object({
        name: Joi.string().required(),
        adjustments: Joi.object().pattern(
          Joi.string(),
          Joi.number()
        ).required()
      })
    ).optional(),
    
    // Output options
    includeConfidenceIntervals: Joi.boolean().default(true),
    includeFeatureImportance: Joi.boolean().default(true),
    includeModelComparison: Joi.boolean().default(true)
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Custom event tracking validation
 */
const validateCustomEvent = (data) => {
  const schema = Joi.object({
    category: Joi.string()
      .valid(
        'user_action',
        'system_event',
        'business_event',
        'integration_event',
        'custom'
      )
      .required()
      .messages({
        'any.required': 'Event category is required'
      }),
    
    action: Joi.string()
      .min(3)
      .max(50)
      .required()
      .messages({
        'string.min': 'Event action must be at least 3 characters',
        'any.required': 'Event action is required'
      }),
    
    label: Joi.string()
      .max(100)
      .optional(),
    
    value: Joi.number()
      .optional(),
    
    metadata: Joi.object()
      .pattern(Joi.string(), Joi.any())
      .max(20)
      .optional()
      .messages({
        'object.max': 'Maximum 20 metadata fields allowed'
      }),
    
    // Event properties
    timestamp: Joi.date()
      .max('now')
      .default(() => new Date()),
    
    userId: Joi.string()
      .custom(customValidators.objectId)
      .optional(),
    
    sessionId: Joi.string()
      .optional(),
    
    // Context
    context: Joi.object({
      page: Joi.string().uri().optional(),
      referrer: Joi.string().uri().optional(),
      userAgent: Joi.string().optional(),
      ipAddress: Joi.string().ip().optional(),
      device: Joi.object({
        type: Joi.string().valid('desktop', 'mobile', 'tablet').optional(),
        os: Joi.string().optional(),
        browser: Joi.string().optional()
      }).optional()
    }).optional(),
    
    // Processing options
    updateMetrics: Joi.boolean().default(true),
    triggerWebhooks: Joi.boolean().default(false),
    
    webhookConfig: Joi.when('triggerWebhooks', {
      is: true,
      then: Joi.object({
        url: Joi.string().uri().required(),
        events: Joi.array().items(Joi.string()).optional()
      }).required()
    })
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Analytics export validation
 */
const validateAnalyticsExport = (data) => {
  const schema = Joi.object({
    type: Joi.string()
      .valid('raw_data', 'aggregated', 'report')
      .required(),
    
    // Data selection
    dataRange: Joi.object({
      start: Joi.date().required(),
      end: Joi.date().greater(Joi.ref('start')).required()
    }).custom(customValidators.dateRange).required(),
    
    // For raw data export
    tables: Joi.when('type', {
      is: 'raw_data',
      then: Joi.array()
        .items(Joi.string().valid(
          'users',
          'sessions',
          'events',
          'pageviews',
          'transactions',
          'errors'
        ))
        .min(1)
        .required()
    }),
    
    // For aggregated data
    aggregations: Joi.when('type', {
      is: 'aggregated',
      then: Joi.array().items(
        Joi.object({
          metric: Joi.string().custom(customValidators.metricName).required(),
          aggregation: Joi.string().valid('sum', 'avg', 'min', 'max', 'count').required(),
          groupBy: Joi.array().items(Joi.string()).optional()
        })
      ).required()
    }),
    
    // Format options
    format: Joi.string()
      .valid('csv', 'json', 'parquet', 'excel')
      .default('csv'),
    
    compression: Joi.string()
      .valid('none', 'gzip', 'zip')
      .default('none'),
    
    // Field selection
    fields: Joi.array()
      .items(Joi.string())
      .optional(),
    
    excludeFields: Joi.array()
      .items(Joi.string())
      .optional(),
    
    // Privacy options
    anonymize: Joi.boolean().default(false),
    
    anonymizationOptions: Joi.when('anonymize', {
      is: true,
      then: Joi.object({
        method: Joi.string().valid('hash', 'random', 'generalize').default('hash'),
        fields: Joi.array().items(Joi.string()).default(['email', 'name', 'phone'])
      }).optional()
    }),
    
    // Large export options
    splitFiles: Joi.boolean().default(false),
    
    splitOptions: Joi.when('splitFiles', {
      is: true,
      then: Joi.object({
        maxSizeMB: Joi.number().min(10).max(1000).default(100),
        maxRows: Joi.number().integer().min(1000).optional()
      }).optional()
    })
  });
  
  return schema.validate(data, { abortEarly: false });
};

/**
 * Report schedule validation
 */
const validateReportSchedule = (data) => {
  const schema = Joi.object({
    name: Joi.string()
      .min(3)
      .max(100)
      .required()
      .messages({
        'string.min': 'Schedule name must be at least 3 characters',
        'any.required': 'Schedule name is required'
      }),
    
    description: Joi.string()
      .max(500)
      .optional(),
    
    // Report configuration
    reportConfig: Joi.object().required(), // Would be validated by validateReportConfig
    
    // Schedule configuration
    schedule: Joi.object({
      frequency: Joi.string()
        .valid('daily', 'weekly', 'monthly', 'quarterly', 'custom')
        .required(),
      
      customCron: Joi.when('frequency', {
        is: 'custom',
        then: Joi.string().required() // Cron expression
      }),
      
      time: Joi.when('frequency', {
        is: Joi.valid('daily', 'weekly', 'monthly'),
        then: Joi.string()
          .pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/)
          .required()
      }),
      
      dayOfWeek: Joi.when('frequency', {
        is: 'weekly',
        then: Joi.number().integer().min(0).max(6).required()
      }),
      
      dayOfMonth: Joi.when('frequency', {
        is: 'monthly',
        then: Joi.number().integer().min(1).max(31).required()
      }),
      
      timezone: Joi.string().custom(customValidators.timezone).required()
    }).required(),
    
    // Recipients
    recipients: Joi.array()
      .items(Joi.object({
        type: Joi.string().valid('email', 'webhook', 'slack').required(),
        
        email: Joi.when('type', {
          is: 'email',
          then: Joi.string().email().required()
        }),
        
        webhook: Joi.when('type', {
          is: 'webhook',
          then: Joi.object({
            url: Joi.string().uri().required(),
            headers: Joi.object().optional()
          }).required()
        }),
        
        slack: Joi.when('type', {
          is: 'slack',
          then: Joi.object({
            channel: Joi.string().required(),
            webhookUrl: Joi.string().uri().required()
          }).required()
        })
      }))
      .min(1)
      .required(),
    
    // Options
    enabled: Joi.boolean().default(true),
    
    retryOnFailure: Joi.boolean().default(true),
    
    retryConfig: Joi.when('retryOnFailure', {
      is: true,
      then: Joi.object({
        maxRetries: Joi.number().integer().min(1).max(5).default(3),
        retryDelayMinutes: Joi.number().integer().min(1).max(60).default(15)
      }).optional()
    }),
    
    // Validity
    startDate: Joi.date()
      .min('now')
      .default(() => new Date()),
    
    endDate: Joi.date()
      .greater(Joi.ref('startDate'))
      .optional(),
    
    // Filters
    organizationFilters: Joi.object({
      ids: Joi.array().items(Joi.string().custom(customValidators.objectId)).optional(),
      plans: Joi.array().items(Joi.string()).optional(),
      tags: Joi.array().items(Joi.string()).optional()
    }).optional()
  });
  
  return schema.validate(data, { abortEarly: false });
};

module.exports = {
  validateAnalyticsQuery,
  validateReportConfig,
  validateComparisonQuery,
  validateGrowthQuery,
  validatePerformanceQuery,
  validatePredictiveQuery,
  validateCustomEvent,
  validateAnalyticsExport,
  validateReportSchedule
};