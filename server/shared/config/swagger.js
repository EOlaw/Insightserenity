// /server/shared/config/swagger.js

/**
 * @file Swagger/OpenAPI Configuration
 * @description API documentation configuration for the Insightserenity platform
 * @version 3.0.0
 */

const swaggerJsdoc = require('swagger-jsdoc');

const constants = require('./constants');

/**
 * Base Swagger configuration
 */
const baseConfig = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: constants.APP.NAME + ' API',
      version: constants.APP.VERSION,
      description: 'Comprehensive API documentation for the Insightserenity multi-tenant platform',
      termsOfService: 'https://insightserenity.com/terms',
      contact: {
        name: 'API Support',
        url: 'https://insightserenity.com/support',
        email: constants.APP.SUPPORT_EMAIL
      },
      license: {
        name: 'Proprietary',
        url: 'https://insightserenity.com/license'
      }
    },
    servers: [
      {
        url: 'https://api.insightserenity.com/v2',
        description: 'Production server',
        variables: {
          version: {
            default: 'v2',
            enum: ['v1', 'v2'],
            description: 'API version'
          }
        }
      },
      {
        url: 'https://staging-api.insightserenity.com/v2',
        description: 'Staging server'
      },
      {
        url: 'http://localhost:3001/api/v2',
        description: 'Development server'
      }
    ],
    externalDocs: {
      description: 'Find more info',
      url: 'https://docs.insightserenity.com'
    }
  },
  apis: []
};

/**
 * Security schemes configuration
 */
const securitySchemes = {
  bearerAuth: {
    type: 'http',
    scheme: 'bearer',
    bearerFormat: 'JWT',
    description: 'JWT authorization header using the Bearer scheme'
  },
  apiKeyAuth: {
    type: 'apiKey',
    in: 'header',
    name: 'X-API-Key',
    description: 'API key for external service authentication'
  },
  oauth2: {
    type: 'oauth2',
    flows: {
      authorizationCode: {
        authorizationUrl: 'https://auth.insightserenity.com/oauth/authorize',
        tokenUrl: 'https://auth.insightserenity.com/oauth/token',
        refreshUrl: 'https://auth.insightserenity.com/oauth/refresh',
        scopes: {
          'read:profile': 'Read user profile',
          'write:profile': 'Modify user profile',
          'read:organizations': 'Read organization data',
          'write:organizations': 'Modify organization data',
          'read:recruitment': 'Read recruitment data',
          'write:recruitment': 'Modify recruitment data',
          'admin': 'Admin access'
        }
      }
    }
  },
  cookieAuth: {
    type: 'apiKey',
    in: 'cookie',
    name: 'session',
    description: 'Session cookie authentication'
  }
};

/**
 * Common schemas configuration
 */
const commonSchemas = {
  Error: {
    type: 'object',
    properties: {
      success: {
        type: 'boolean',
        example: false
      },
      error: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: 'An error occurred'
          },
          code: {
            type: 'string',
            example: 'E1000'
          },
          details: {
            type: 'array',
            items: {
              type: 'object'
            }
          }
        }
      },
      timestamp: {
        type: 'string',
        format: 'date-time'
      }
    }
  },
  
  Pagination: {
    type: 'object',
    properties: {
      page: {
        type: 'integer',
        minimum: 1,
        example: 1
      },
      limit: {
        type: 'integer',
        minimum: 1,
        maximum: 100,
        example: 20
      },
      total: {
        type: 'integer',
        example: 100
      },
      totalPages: {
        type: 'integer',
        example: 5
      }
    }
  },
  
  Success: {
    type: 'object',
    properties: {
      success: {
        type: 'boolean',
        example: true
      },
      message: {
        type: 'string',
        example: 'Operation completed successfully'
      }
    }
  },
  
  Timestamps: {
    type: 'object',
    properties: {
      createdAt: {
        type: 'string',
        format: 'date-time'
      },
      updatedAt: {
        type: 'string',
        format: 'date-time'
      }
    }
  }
};

/**
 * Create Swagger configuration for specific API modules
 */
const createSwaggerConfig = (module, options = {}) => {
  const moduleConfigs = {
    auth: {
      tags: [
        {
          name: 'Authentication',
          description: 'User authentication and authorization'
        }
      ],
      paths: [
        './server/shared/auth/routes/*.js',
        './server/shared/auth/controllers/*.js'
      ]
    },
    
    users: {
      tags: [
        {
          name: 'Users',
          description: 'User management operations'
        }
      ],
      paths: [
        './server/shared/users/routes/*.js',
        './server/shared/users/controllers/*.js'
      ]
    },
    
    organizations: {
      tags: [
        {
          name: 'Organizations',
          description: 'Organization management'
        }
      ],
      paths: [
        './server/hosted-organizations/organizations/routes/*.js',
        './server/hosted-organizations/organizations/controllers/*.js'
      ]
    },
    
    recruitment: {
      tags: [
        {
          name: 'Recruitment',
          description: 'Recruitment platform operations'
        },
        {
          name: 'Jobs',
          description: 'Job posting and management'
        },
        {
          name: 'Candidates',
          description: 'Candidate management'
        },
        {
          name: 'Applications',
          description: 'Job application management'
        }
      ],
      paths: [
        './server/recruitment-services/*/routes/*.js',
        './server/recruitment-services/*/controllers/*.js'
      ]
    },
    
    billing: {
      tags: [
        {
          name: 'Billing',
          description: 'Billing and subscription management'
        }
      ],
      paths: [
        './server/shared/billing/routes/*.js',
        './server/shared/billing/controllers/*.js'
      ]
    },
    
    admin: {
      tags: [
        {
          name: 'Admin',
          description: 'Platform administration'
        }
      ],
      paths: [
        './server/admin/*/routes/*.js',
        './server/admin/*/controllers/*.js'
      ]
    }
  };
  
  const moduleConfig = moduleConfigs[module] || { tags: [], paths: [] };
  
  return {
    ...baseConfig,
    definition: {
      ...baseConfig.definition,
      tags: moduleConfig.tags,
      components: {
        securitySchemes,
        schemas: {
          ...commonSchemas,
          ...options.schemas
        }
      },
      security: options.security || [
        { bearerAuth: [] }
      ]
    },
    apis: moduleConfig.paths
  };
};

/**
 * Swagger UI options
 */
const swaggerUiOptions = {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'Insightserenity API Documentation',
  customfavIcon: '/favicon.ico',
  swaggerOptions: {
    persistAuthorization: true,
    displayRequestDuration: true,
    docExpansion: 'none',
    filter: true,
    showExtensions: true,
    showCommonExtensions: true,
    displayOperationId: false,
    defaultModelsExpandDepth: 1,
    defaultModelExpandDepth: 1,
    tryItOutEnabled: process.env.NODE_ENV !== 'production',
    validatorUrl: null,
    supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
    onComplete: () => {
      console.log('Swagger UI loaded');
    }
  }
};

/**
 * Generate Swagger specs for all modules
 */
const generateAllSpecs = () => {
  const modules = ['auth', 'users', 'organizations', 'recruitment', 'billing', 'admin'];
  const specs = {};
  
  modules.forEach(module => {
    const config = createSwaggerConfig(module);
    specs[module] = swaggerJsdoc(config);
  });
  
  return specs;
};

/**
 * Combined API documentation
 */
const combinedSwaggerConfig = {
  ...baseConfig,
  definition: {
    ...baseConfig.definition,
    tags: [
      {
        name: 'Authentication',
        description: 'User authentication and authorization'
      },
      {
        name: 'Users',
        description: 'User management operations'
      },
      {
        name: 'Organizations',
        description: 'Organization management'
      },
      {
        name: 'Core Business',
        description: 'Insightserenity consultancy operations'
      },
      {
        name: 'Recruitment',
        description: 'Recruitment platform operations'
      },
      {
        name: 'Billing',
        description: 'Billing and subscription management'
      },
      {
        name: 'Notifications',
        description: 'Notification management'
      },
      {
        name: 'Analytics',
        description: 'Analytics and reporting'
      },
      {
        name: 'Admin',
        description: 'Platform administration'
      },
      {
        name: 'Webhooks',
        description: 'Webhook management'
      }
    ],
    components: {
      securitySchemes,
      schemas: commonSchemas
    },
    security: [
      { bearerAuth: [] }
    ]
  },
  apis: [
    './server/shared/*/routes/*.js',
    './server/shared/*/controllers/*.js',
    './server/core-business/*/routes/*.js',
    './server/core-business/*/controllers/*.js',
    './server/hosted-organizations/*/routes/*.js',
    './server/hosted-organizations/*/controllers/*.js',
    './server/recruitment-services/*/routes/*.js',
    './server/recruitment-services/*/controllers/*.js',
    './server/admin/*/routes/*.js',
    './server/admin/*/controllers/*.js',
    './server/external-apis/*/routes/*.js'
  ]
};

module.exports = {
  baseConfig,
  createSwaggerConfig,
  swaggerUiOptions,
  generateAllSpecs,
  combinedSwaggerConfig,
  commonSchemas,
  securitySchemes
};