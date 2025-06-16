// /server/shared/utils/constants/api-versions.js

/**
 * @file API Versions
 * @description API versioning constants and configuration
 * @version 1.0.0
 */

module.exports = {
  /**
   * Version definitions
   */
  VERSIONS: {
    V1: {
      version: 'v1',
      number: '1.0.0',
      status: 'deprecated',
      deprecatedDate: '2024-01-01',
      sunsetDate: '2025-06-01',
      basePath: '/api/v1',
      features: [
        'basic-auth',
        'user-management',
        'organization-basics',
        'simple-billing'
      ]
    },
    
    V2: {
      version: 'v2',
      number: '2.0.0',
      status: 'current',
      releasedDate: '2024-01-01',
      basePath: '/api/v2',
      features: [
        'oauth2',
        'advanced-user-management',
        'multi-tenant-organizations',
        'recruitment-platform',
        'webhooks',
        'real-time-updates',
        'advanced-analytics',
        'api-keys',
        'rate-limiting'
      ]
    },
    
    V3: {
      version: 'v3',
      number: '3.0.0',
      status: 'beta',
      plannedRelease: '2025-09-01',
      basePath: '/api/v3',
      features: [
        'graphql-support',
        'ai-integration',
        'blockchain-verification',
        'advanced-automation',
        'federated-authentication'
      ]
    }
  },
  
  /**
   * Current version settings
   */
  CURRENT: 'v2',
  DEFAULT: 'v2',
  MINIMUM_SUPPORTED: 'v1',
  BETA: 'v3',
  
  /**
   * Deprecated versions
   */
  DEPRECATED: ['v1'],
  
  /**
   * Version-specific settings
   */
  SETTINGS: {
    v1: {
      maxPageSize: 50,
      defaultPageSize: 10,
      maxRequestSize: '5mb',
      timeout: 30000,
      rateLimits: {
        anonymous: 50,
        authenticated: 200,
        premium: 500
      }
    },
    
    v2: {
      maxPageSize: 100,
      defaultPageSize: 20,
      maxRequestSize: '10mb',
      timeout: 60000,
      rateLimits: {
        anonymous: 100,
        authenticated: 1000,
        premium: 5000,
        enterprise: 10000
      },
      features: {
        pagination: 'cursor-based',
        filtering: 'advanced',
        sorting: 'multi-field',
        includes: 'nested',
        fields: 'sparse'
      }
    },
    
    v3: {
      maxPageSize: 200,
      defaultPageSize: 50,
      maxRequestSize: '50mb',
      timeout: 120000,
      rateLimits: {
        anonymous: 100,
        authenticated: 2000,
        premium: 10000,
        enterprise: 50000
      },
      features: {
        pagination: 'cursor-based',
        filtering: 'graphql',
        sorting: 'ai-optimized',
        includes: 'graph-based',
        fields: 'dynamic'
      }
    }
  },
  
  /**
   * Version compatibility matrix
   */
  COMPATIBILITY: {
    v1: {
      backwardCompatible: [],
      forwardCompatible: ['v2']
    },
    v2: {
      backwardCompatible: ['v1'],
      forwardCompatible: ['v3']
    },
    v3: {
      backwardCompatible: ['v2'],
      forwardCompatible: []
    }
  },
  
  /**
   * Breaking changes by version
   */
  BREAKING_CHANGES: {
    v2: [
      {
        change: 'Authentication method changed from Basic to OAuth2',
        migration: 'Use OAuth2 flow or API keys instead of Basic auth'
      },
      {
        change: 'User ID format changed from sequential to UUID',
        migration: 'Update stored user IDs to new format'
      },
      {
        change: 'Pagination changed from page-based to cursor-based',
        migration: 'Use cursor parameter instead of page number'
      },
      {
        change: 'Error response format standardized',
        migration: 'Update error handling to use new format'
      }
    ],
    
    v3: [
      {
        change: 'REST endpoints supplemented with GraphQL',
        migration: 'Optionally migrate to GraphQL for complex queries'
      },
      {
        change: 'Webhook payload structure updated',
        migration: 'Update webhook handlers for new payload format'
      }
    ]
  },
  
  /**
   * Deprecation warnings
   */
  DEPRECATION_WARNINGS: {
    v1: {
      message: 'API v1 is deprecated and will be removed on June 1, 2025',
      alternatives: ['v2'],
      migrationGuide: 'https://docs.insightserenity.com/api/migration/v1-to-v2'
    }
  },
  
  /**
   * Version-specific endpoints
   */
  ENDPOINTS: {
    v1: {
      auth: {
        login: '/auth/login',
        logout: '/auth/logout',
        refresh: '/auth/refresh'
      },
      users: {
        list: '/users',
        get: '/users/:id',
        create: '/users',
        update: '/users/:id',
        delete: '/users/:id'
      }
    },
    
    v2: {
      auth: {
        login: '/auth/login',
        logout: '/auth/logout',
        refresh: '/auth/token/refresh',
        oauth: '/auth/oauth/:provider',
        twoFactor: '/auth/2fa'
      },
      users: {
        list: '/users',
        get: '/users/:id',
        create: '/users',
        update: '/users/:id',
        delete: '/users/:id',
        profile: '/users/:id/profile',
        preferences: '/users/:id/preferences'
      },
      organizations: {
        list: '/organizations',
        get: '/organizations/:id',
        create: '/organizations',
        update: '/organizations/:id',
        delete: '/organizations/:id',
        members: '/organizations/:id/members'
      },
      recruitment: {
        jobs: '/recruitment/jobs',
        applications: '/recruitment/applications',
        candidates: '/recruitment/candidates'
      }
    },
    
    v3: {
      graphql: '/graphql',
      rest: {
        // Same as v2 with additions
      }
    }
  },
  
  /**
   * Version negotiation headers
   */
  HEADERS: {
    VERSION: 'X-API-Version',
    DEPRECATED: 'X-API-Deprecated',
    SUNSET: 'X-API-Sunset-Date',
    MIGRATION: 'X-API-Migration-Guide'
  },
  
  /**
   * Helper functions
   */
  
  /**
   * Get version info
   * @param {string} version - Version string
   * @returns {Object|null} Version information
   */
  getVersion(version) {
    return this.VERSIONS[version.toUpperCase()] || null;
  },
  
  /**
   * Check if version is supported
   * @param {string} version - Version to check
   * @returns {boolean} Is supported
   */
  isSupported(version) {
    const versionInfo = this.getVersion(version);
    return versionInfo && versionInfo.status !== 'deprecated';
  },
  
  /**
   * Check if version is deprecated
   * @param {string} version - Version to check
   * @returns {boolean} Is deprecated
   */
  isDeprecated(version) {
    return this.DEPRECATED.includes(version);
  },
  
  /**
   * Get version settings
   * @param {string} version - Version string
   * @returns {Object} Version settings
   */
  getSettings(version) {
    return this.SETTINGS[version] || this.SETTINGS[this.DEFAULT];
  },
  
  /**
   * Get rate limit for version and tier
   * @param {string} version - API version
   * @param {string} tier - User tier
   * @returns {number} Rate limit
   */
  getRateLimit(version, tier) {
    const settings = this.getSettings(version);
    return settings.rateLimits[tier] || settings.rateLimits.authenticated;
  },
  
  /**
   * Check version compatibility
   * @param {string} from - Source version
   * @param {string} to - Target version
   * @returns {boolean} Are compatible
   */
  areCompatible(from, to) {
    const compatibility = this.COMPATIBILITY[from];
    if (!compatibility) return false;
    
    return compatibility.backwardCompatible.includes(to) ||
           compatibility.forwardCompatible.includes(to);
  },
  
  /**
   * Get breaking changes between versions
   * @param {string} from - Source version
   * @param {string} to - Target version
   * @returns {Array} Breaking changes
   */
  getBreakingChanges(from, to) {
    const changes = [];
    
    // Get all versions between from and to
    const versions = Object.keys(this.VERSIONS);
    const fromIndex = versions.indexOf(from);
    const toIndex = versions.indexOf(to);
    
    if (fromIndex === -1 || toIndex === -1 || fromIndex >= toIndex) {
      return changes;
    }
    
    // Collect breaking changes for each version upgrade
    for (let i = fromIndex + 1; i <= toIndex; i++) {
      const version = versions[i];
      if (this.BREAKING_CHANGES[version]) {
        changes.push(...this.BREAKING_CHANGES[version]);
      }
    }
    
    return changes;
  },
  
  /**
   * Get deprecation warning for version
   * @param {string} version - Version to check
   * @returns {Object|null} Deprecation warning
   */
  getDeprecationWarning(version) {
    return this.DEPRECATION_WARNINGS[version] || null;
  },
  
  /**
   * Format version for URL
   * @param {string} version - Version string
   * @returns {string} Formatted version
   */
  formatForUrl(version) {
    return version.startsWith('v') ? version : `v${version}`;
  },
  
  /**
   * Extract version from URL
   * @param {string} url - URL string
   * @returns {string|null} Version
   */
  extractFromUrl(url) {
    const match = url.match(/\/api\/(v\d+)\//);
    return match ? match[1] : null;
  },
  
  /**
   * Get version from request
   * @param {Object} req - Express request
   * @returns {string} API version
   */
  getFromRequest(req) {
    // Check header first
    const headerVersion = req.get(this.HEADERS.VERSION);
    if (headerVersion) {
      return this.formatForUrl(headerVersion);
    }
    
    // Check URL
    const urlVersion = this.extractFromUrl(req.originalUrl);
    if (urlVersion) {
      return urlVersion;
    }
    
    // Check query parameter
    if (req.query.version) {
      return this.formatForUrl(req.query.version);
    }
    
    // Return default
    return this.DEFAULT;
  }
};