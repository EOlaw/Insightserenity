/**
 * @file Audit Helpers
 * @description Utility functions for audit logging system
 * @version 1.0.0
 */

const geoip = require('geoip-lite');
const UAParser = require('ua-parser-js');
const logger = require('../../utils/logger');

/**
 * Calculate risk score for an event
 * @param {Object} eventData - Event data
 * @returns {number} Risk score (0-100)
 */
function calculateRiskScore(eventData) {
  let score = 0;
  
  // Base risk by event type
  const eventRiskMap = {
    'login_failed': 15,
    'permission_denied': 20,
    'unauthorized_access': 30,
    'data_deletion': 25,
    'bulk_operation': 15,
    'configuration_change': 20,
    'security_alert': 40,
    'suspicious_activity': 35
  };
  
  const baseRisk = eventRiskMap[eventData.type] || 0;
  score += baseRisk;
  
  // Time-based risk factors
  const hour = new Date().getHours();
  const dayOfWeek = new Date().getDay();
  
  // After hours (10 PM - 6 AM)
  if (hour < 6 || hour >= 22) {
    score += 10;
  }
  
  // Weekend activity
  if (dayOfWeek === 0 || dayOfWeek === 6) {
    score += 5;
  }
  
  // Location-based risk
  if (eventData.ipAddress) {
    const locationRisk = calculateLocationRisk(eventData.ipAddress);
    score += locationRisk;
  }
  
  // Velocity-based risk (multiple events in short time)
  if (eventData.eventCount > 10 && eventData.timeWindow < 60) {
    score += 15;
  }
  
  // Failed attempts
  if (eventData.failedAttempts > 3) {
    score += eventData.failedAttempts * 5;
  }
  
  // Sensitive data access
  if (eventData.sensitiveData || eventData.targetType === 'payment_method') {
    score += 20;
  }
  
  // Privilege escalation attempts
  if (eventData.privilegeEscalation) {
    score += 30;
  }
  
  return Math.min(score, 100);
}

/**
 * Calculate location-based risk
 * @param {string} ipAddress - IP address
 * @returns {number} Location risk score
 */
function calculateLocationRisk(ipAddress) {
  try {
    const geo = geoip.lookup(ipAddress);
    if (!geo) return 10; // Unknown location
    
    // High-risk countries (example list - customize based on your needs)
    const highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
    const mediumRiskCountries = ['BR', 'IN', 'NG', 'PK'];
    
    if (highRiskCountries.includes(geo.country)) {
      return 25;
    } else if (mediumRiskCountries.includes(geo.country)) {
      return 15;
    }
    
    return 0;
  } catch (error) {
    logger.debug('Failed to calculate location risk', { error: error.message });
    return 5;
  }
}

/**
 * Detect anomalies in user behavior
 * @param {Object} eventData - Current event data
 * @param {Object} repository - Audit repository instance
 * @returns {Promise<Array>} Detected anomalies
 */
async function detectAnomalies(eventData, repository) {
  const anomalies = [];
  
  try {
    // Get user's recent activity
    const recentActivity = await repository.query({
      userId: eventData.userId,
      startDate: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
    }, { limit: 100 });
    
    if (recentActivity.results.length === 0) {
      return anomalies;
    }
    
    // Analyze patterns
    const patterns = analyzeActivityPatterns(recentActivity.results);
    
    // Check for unusual login location
    if (eventData.ipAddress && patterns.locations.length > 0) {
      const currentGeo = geoip.lookup(eventData.ipAddress);
      const isNewLocation = !patterns.locations.some(loc => 
        loc.country === currentGeo?.country && 
        loc.city === currentGeo?.city
      );
      
      if (isNewLocation) {
        anomalies.push('new_location');
      }
    }
    
    // Check for unusual time
    const currentHour = new Date().getHours();
    if (!patterns.activeHours.includes(currentHour)) {
      anomalies.push('unusual_time');
    }
    
    // Check for unusual user agent
    if (eventData.userAgent && patterns.userAgents.length > 0) {
      const parser = new UAParser(eventData.userAgent);
      const currentUA = parser.getResult();
      
      const isNewDevice = !patterns.userAgents.some(ua => 
        ua.browser === currentUA.browser.name &&
        ua.os === currentUA.os.name
      );
      
      if (isNewDevice) {
        anomalies.push('new_device');
      }
    }
    
    // Check for rapid succession of events
    const recentCount = recentActivity.results.filter(event => 
      new Date(event.timestamp) > new Date(Date.now() - 5 * 60 * 1000)
    ).length;
    
    if (recentCount > 20) {
      anomalies.push('rapid_activity');
    }
    
    // Check for access pattern changes
    if (eventData.targetType && patterns.accessedResources.length > 0) {
      const isNewResourceType = !patterns.accessedResources.includes(eventData.targetType);
      if (isNewResourceType) {
        anomalies.push('new_resource_type');
      }
    }
    
  } catch (error) {
    logger.error('Failed to detect anomalies', {
      error: error.message,
      userId: eventData.userId
    });
  }
  
  return anomalies;
}

/**
 * Analyze activity patterns from audit logs
 * @param {Array} auditLogs - Recent audit logs
 * @returns {Object} Activity patterns
 */
function analyzeActivityPatterns(auditLogs) {
  const patterns = {
    locations: [],
    activeHours: [],
    userAgents: [],
    accessedResources: [],
    failureRate: 0,
    averageEventsPerHour: 0
  };
  
  const locationSet = new Set();
  const hourSet = new Set();
  const userAgentSet = new Set();
  const resourceSet = new Set();
  
  let failures = 0;
  
  auditLogs.forEach(log => {
    // Collect locations
    if (log.actor.ipAddress) {
      const geo = geoip.lookup(log.actor.ipAddress);
      if (geo) {
        const locationKey = `${geo.country}-${geo.city}`;
        if (!locationSet.has(locationKey)) {
          locationSet.add(locationKey);
          patterns.locations.push({
            country: geo.country,
            city: geo.city,
            region: geo.region
          });
        }
      }
    }
    
    // Collect active hours
    const hour = new Date(log.timestamp).getHours();
    hourSet.add(hour);
    
    // Collect user agents
    if (log.actor.userAgent) {
      const parser = new UAParser(log.actor.userAgent);
      const ua = parser.getResult();
      const uaKey = `${ua.browser.name}-${ua.os.name}`;
      
      if (!userAgentSet.has(uaKey)) {
        userAgentSet.add(uaKey);
        patterns.userAgents.push({
          browser: ua.browser.name,
          os: ua.os.name,
          device: ua.device.type || 'desktop'
        });
      }
    }
    
    // Collect accessed resources
    if (log.target?.type) {
      resourceSet.add(log.target.type);
    }
    
    // Count failures
    if (log.event.result === 'failure') {
      failures++;
    }
  });
  
  patterns.activeHours = Array.from(hourSet).sort((a, b) => a - b);
  patterns.accessedResources = Array.from(resourceSet);
  patterns.failureRate = auditLogs.length > 0 ? (failures / auditLogs.length) * 100 : 0;
  
  // Calculate events per hour
  if (auditLogs.length > 0) {
    const timeSpan = new Date(auditLogs[0].timestamp) - new Date(auditLogs[auditLogs.length - 1].timestamp);
    const hours = timeSpan / (1000 * 60 * 60);
    patterns.averageEventsPerHour = hours > 0 ? auditLogs.length / hours : auditLogs.length;
  }
  
  return patterns;
}

/**
 * Format IP address for display
 * @param {string} ip - IP address
 * @returns {string} Formatted IP address
 */
function formatIpAddress(ip) {
  if (!ip) return 'Unknown';
  
  // Handle IPv6 mapped IPv4 addresses
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  
  return ip;
}

/**
 * Parse user agent string
 * @param {string} userAgent - User agent string
 * @returns {Object} Parsed user agent info
 */
function parseUserAgent(userAgent) {
  if (!userAgent) {
    return {
      browser: 'Unknown',
      os: 'Unknown',
      device: 'Unknown'
    };
  }
  
  const parser = new UAParser(userAgent);
  const result = parser.getResult();
  
  return {
    browser: `${result.browser.name || 'Unknown'} ${result.browser.version || ''}`.trim(),
    os: `${result.os.name || 'Unknown'} ${result.os.version || ''}`.trim(),
    device: result.device.type || 'desktop',
    isBot: /bot|crawler|spider|scraper/i.test(userAgent)
  };
}

/**
 * Get geolocation from IP address
 * @param {string} ipAddress - IP address
 * @returns {Object} Location information
 */
function getGeolocation(ipAddress) {
  if (!ipAddress) {
    return {
      country: 'Unknown',
      city: 'Unknown',
      region: 'Unknown',
      timezone: 'Unknown'
    };
  }
  
  const geo = geoip.lookup(ipAddress);
  
  if (!geo) {
    return {
      country: 'Unknown',
      city: 'Unknown',
      region: 'Unknown',
      timezone: 'Unknown'
    };
  }
  
  return {
    country: geo.country,
    city: geo.city || 'Unknown',
    region: geo.region || 'Unknown',
    timezone: geo.timezone || 'Unknown',
    coordinates: geo.ll ? {
      latitude: geo.ll[0],
      longitude: geo.ll[1]
    } : null
  };
}

/**
 * Mask sensitive data in audit logs
 * @param {*} data - Data to mask
 * @param {Array<string>} fieldsToMask - Fields to mask
 * @returns {*} Masked data
 */
function maskSensitiveData(data, fieldsToMask = []) {
  if (!data || typeof data !== 'object') {
    return data;
  }
  
  const defaultSensitiveFields = [
    'password',
    'token',
    'secret',
    'key',
    'authorization',
    'cookie',
    'ssn',
    'creditCard',
    'cvv'
  ];
  
  const allFieldsToMask = [...defaultSensitiveFields, ...fieldsToMask];
  
  const masked = Array.isArray(data) ? [...data] : { ...data };
  
  function maskValue(value) {
    if (typeof value === 'string') {
      if (value.length <= 4) {
        return '****';
      }
      return value.substring(0, 2) + '*'.repeat(value.length - 4) + value.substring(value.length - 2);
    }
    return '****';
  }
  
  function maskObject(obj) {
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const lowerKey = key.toLowerCase();
        
        if (allFieldsToMask.some(field => lowerKey.includes(field.toLowerCase()))) {
          obj[key] = maskValue(obj[key]);
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          maskObject(obj[key]);
        }
      }
    }
  }
  
  if (Array.isArray(masked)) {
    masked.forEach(item => {
      if (typeof item === 'object' && item !== null) {
        maskObject(item);
      }
    });
  } else {
    maskObject(masked);
  }
  
  return masked;
}

/**
 * Generate audit event description
 * @param {Object} auditEvent - Audit event
 * @returns {string} Human-readable description
 */
function generateEventDescription(auditEvent) {
  const { event, actor, target } = auditEvent;
  
  const actorName = actor.email || actor.userId || 'Unknown user';
  const action = event.action.replace(/_/g, ' ');
  
  let description = `${actorName} ${action}`;
  
  if (target && target.type && target.id) {
    description += ` ${target.type} ${target.id}`;
  }
  
  if (event.result !== 'success') {
    description += ` (${event.result})`;
  }
  
  return description;
}

/**
 * Calculate statistics from audit logs
 * @param {Array} auditLogs - Audit logs
 * @returns {Object} Statistics
 */
function calculateAuditStatistics(auditLogs) {
  const stats = {
    total: auditLogs.length,
    byCategory: {},
    bySeverity: {},
    byResult: {},
    byHour: {},
    topUsers: [],
    topActions: [],
    averageRiskScore: 0,
    peakHours: []
  };
  
  const userCounts = {};
  const actionCounts = {};
  let totalRiskScore = 0;
  
  auditLogs.forEach(log => {
    // Category counts
    stats.byCategory[log.event.category] = (stats.byCategory[log.event.category] || 0) + 1;
    
    // Severity counts
    stats.bySeverity[log.event.severity] = (stats.bySeverity[log.event.severity] || 0) + 1;
    
    // Result counts
    stats.byResult[log.event.result] = (stats.byResult[log.event.result] || 0) + 1;
    
    // Hour distribution
    const hour = new Date(log.timestamp).getHours();
    stats.byHour[hour] = (stats.byHour[hour] || 0) + 1;
    
    // User counts
    const userId = log.actor.email || log.actor.userId;
    userCounts[userId] = (userCounts[userId] || 0) + 1;
    
    // Action counts
    actionCounts[log.event.action] = (actionCounts[log.event.action] || 0) + 1;
    
    // Risk score
    if (log.security?.risk?.score) {
      totalRiskScore += log.security.risk.score;
    }
  });
  
  // Calculate averages and top items
  stats.averageRiskScore = stats.total > 0 ? totalRiskScore / stats.total : 0;
  
  // Top users
  stats.topUsers = Object.entries(userCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([user, count]) => ({ user, count }));
  
  // Top actions
  stats.topActions = Object.entries(actionCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([action, count]) => ({ action, count }));
  
  // Peak hours
  const hourEntries = Object.entries(stats.byHour)
    .sort((a, b) => b[1] - a[1]);
  
  stats.peakHours = hourEntries
    .slice(0, 3)
    .map(([hour, count]) => ({ hour: parseInt(hour), count }));
  
  return stats;
}

/**
 * Validate audit event structure
 * @param {Object} event - Audit event
 * @returns {Object} Validation result
 */
function validateAuditEvent(event) {
  const errors = [];
  const warnings = [];
  
  // Required fields
  if (!event.event?.action) {
    errors.push('Missing required field: event.action');
  }
  
  if (!event.actor?.userId && !event.systemGenerated) {
    errors.push('Missing required field: actor.userId (or mark as systemGenerated)');
  }
  
  // Validate enums
  const validCategories = ['authentication', 'authorization', 'data_access', 'data_modification', 
                          'configuration', 'security', 'compliance', 'system'];
  if (event.event?.category && !validCategories.includes(event.event.category)) {
    warnings.push(`Invalid category: ${event.event.category}`);
  }
  
  const validResults = ['success', 'failure', 'error', 'blocked'];
  if (event.event?.result && !validResults.includes(event.event.result)) {
    warnings.push(`Invalid result: ${event.event.result}`);
  }
  
  const validSeverities = ['low', 'medium', 'high', 'critical'];
  if (event.event?.severity && !validSeverities.includes(event.event.severity)) {
    warnings.push(`Invalid severity: ${event.event.severity}`);
  }
  
  // Validate data types
  if (event.security?.risk?.score !== undefined) {
    const score = event.security.risk.score;
    if (typeof score !== 'number' || score < 0 || score > 100) {
      warnings.push('Risk score must be a number between 0 and 100');
    }
  }
  
  if (event.timestamp && !(event.timestamp instanceof Date)) {
    try {
      new Date(event.timestamp);
    } catch (e) {
      errors.push('Invalid timestamp format');
    }
  }
  
  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}

module.exports = {
  calculateRiskScore,
  calculateLocationRisk,
  detectAnomalies,
  analyzeActivityPatterns,
  formatIpAddress,
  parseUserAgent,
  getGeolocation,
  maskSensitiveData,
  generateEventDescription,
  calculateAuditStatistics,
  validateAuditEvent
};