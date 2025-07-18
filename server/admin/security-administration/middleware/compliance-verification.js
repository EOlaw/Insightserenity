// server/admin/security-administration/middleware/compliance-verification.js
/**
 * @file Compliance Verification Middleware
 * @description Middleware for ensuring compliance requirements are met
 * @version 1.0.0
 */

const { ForbiddenError, UnauthorizedError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminActivityTracker = require('../../../shared/admin/utils/admin-activity-tracker');
const CacheService = require('../../../shared/utils/cache-service');
const ComplianceStandard = require('../../../shared/security/models/compliance-standard-model');
const AuditLog = require('../../../shared/security/models/audit-log-model');

/**
 * Compliance Verification Middleware Class
 * @class ComplianceVerificationMiddleware
 */
class ComplianceVerificationMiddleware {
  /**
   * Verify compliance requirements for data access
   */
  static verifyDataAccessCompliance = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      if (!adminUser) {
        throw new UnauthorizedError('Authentication required');
      }

      // Check data classification
      const dataClassification = req.headers['x-data-classification'] || 'internal';
      
      // Verify user has appropriate clearance
      if (dataClassification === 'confidential' && !adminUser.permissions?.includes(AdminPermissions.COMPLIANCE.ACCESS_CONFIDENTIAL)) {
        await this.logComplianceViolation(adminUser, 'unauthorized_data_access', {
          classification: dataClassification,
          path: req.path
        });
        
        throw new ForbiddenError('Insufficient clearance for confidential data');
      }

      // Check if data access logging is required
      if (this.requiresAccessLogging(req)) {
        await this.logDataAccess(adminUser, req);
      }

      // Verify data residency compliance
      const residencyCompliant = await this.verifyDataResidency(req);
      if (!residencyCompliant) {
        throw new ForbiddenError('Data residency requirements not met');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Verify GDPR compliance
   */
  static verifyGDPRCompliance = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Check if GDPR applies
      if (!await this.isGDPRApplicable(req)) {
        return next();
      }

      // Verify lawful basis for processing
      if (this.isPersonalDataOperation(req)) {
        const hasLawfulBasis = await this.verifyLawfulBasis(req);
        if (!hasLawfulBasis) {
          await this.logComplianceViolation(adminUser, 'gdpr_no_lawful_basis', {
            operation: req.method,
            path: req.path
          });
          
          throw new ForbiddenError('No lawful basis for processing personal data');
        }
      }

      // Check data minimization
      if (req.method === 'GET' && req.query.includeAll) {
        await this.logComplianceViolation(adminUser, 'gdpr_data_minimization', {
          path: req.path,
          query: req.query
        });
        
        delete req.query.includeAll;
        req.query.fields = this.getMinimalFields(req.path);
      }

      // Verify consent for marketing operations
      if (this.isMarketingOperation(req)) {
        const hasConsent = await this.verifyMarketingConsent(req);
        if (!hasConsent) {
          throw new ForbiddenError('Marketing consent required');
        }
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Verify HIPAA compliance
   */
  static verifyHIPAACompliance = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Check if HIPAA applies
      if (!await this.isHIPAAApplicable(req)) {
        return next();
      }

      // Verify user has HIPAA training
      const hasTraining = await this.verifyHIPAATraining(adminUser);
      if (!hasTraining) {
        throw new ForbiddenError('HIPAA training certification required');
      }

      // Check for PHI access
      if (this.isPHIOperation(req)) {
        // Verify minimum necessary standard
        if (!this.meetsMinimumNecessary(req)) {
          await this.logComplianceViolation(adminUser, 'hipaa_minimum_necessary', {
            operation: req.method,
            path: req.path
          });
          
          throw new ForbiddenError('Request violates HIPAA minimum necessary standard');
        }

        // Log PHI access
        await this.logPHIAccess(adminUser, req);
      }

      // Verify encryption for PHI transmission
      if (!req.secure && this.containsPHI(req)) {
        throw new ForbiddenError('PHI must be transmitted over secure connection');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Verify PCI DSS compliance
   */
  static verifyPCIDSSCompliance = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Check if PCI DSS applies
      if (!this.isPCIDSSApplicable(req)) {
        return next();
      }

      // Verify PCI compliance level
      const complianceLevel = await this.getPCIComplianceLevel(adminUser.organizationId);
      
      // Check cardholder data access
      if (this.isCardholderDataOperation(req)) {
        // Verify user has PCI authorization
        if (!adminUser.permissions?.includes(AdminPermissions.COMPLIANCE.ACCESS_CARDHOLDER_DATA)) {
          await this.logComplianceViolation(adminUser, 'pci_unauthorized_access', {
            path: req.path
          });
          
          throw new ForbiddenError('Not authorized to access cardholder data');
        }

        // Ensure no storage of sensitive authentication data
        if (req.method === 'POST' || req.method === 'PUT') {
          this.sanitizeCardholderData(req);
        }

        // Log cardholder data access
        await this.logCardholderDataAccess(adminUser, req);
      }

      // Verify secure transmission
      if (!req.secure && this.containsCardData(req)) {
        throw new ForbiddenError('Cardholder data must be transmitted securely');
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Verify SOC 2 compliance
   */
  static verifySOC2Compliance = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Check if SOC 2 applies
      if (!await this.isSOC2Applicable(req)) {
        return next();
      }

      // Verify trust service criteria
      const criteria = await this.getApplicableTrustCriteria(req);
      
      for (const criterion of criteria) {
        const compliant = await this.verifyTrustCriterion(criterion, req, adminUser);
        
        if (!compliant) {
          await this.logComplianceViolation(adminUser, 'soc2_criterion_violation', {
            criterion,
            path: req.path
          });
          
          throw new ForbiddenError(`SOC 2 ${criterion} criterion not met`);
        }
      }

      // Log for SOC 2 audit trail
      await this.logSOC2Activity(adminUser, req);

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Verify data retention compliance
   */
  static verifyDataRetentionCompliance = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Check if operation affects data retention
      if (!this.affectsDataRetention(req)) {
        return next();
      }

      // Get applicable retention policies
      const policies = await this.getRetentionPolicies(adminUser.organizationId);
      
      // Verify deletion requests
      if (req.method === 'DELETE') {
        const canDelete = await this.verifyDeletionCompliance(req, policies);
        
        if (!canDelete.allowed) {
          await this.logComplianceViolation(adminUser, 'retention_policy_violation', {
            reason: canDelete.reason,
            path: req.path
          });
          
          throw new ForbiddenError(canDelete.reason || 'Deletion violates retention policy');
        }
      }

      // Verify data export includes retention metadata
      if (req.path.includes('/export')) {
        req.includeRetentionMetadata = true;
      }

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Verify audit requirements
   */
  static verifyAuditRequirements = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Determine audit level required
      const auditLevel = this.determineAuditLevel(req);
      
      // High-risk operations require additional verification
      if (auditLevel === 'critical') {
        // Require reason for critical operations
        if (!req.body.reason || req.body.reason.length < 20) {
          throw new ValidationError('Detailed reason required for critical operations (min 20 characters)');
        }

        // Require approval for certain operations
        if (this.requiresApproval(req)) {
          const hasApproval = await this.verifyApproval(req, adminUser);
          if (!hasApproval) {
            throw new ForbiddenError('Operation requires approval from another administrator');
          }
        }
      }

      // Ensure audit data integrity
      req.auditMetadata = {
        level: auditLevel,
        complianceStandards: await this.getApplicableStandards(adminUser.organizationId),
        timestamp: new Date(),
        sessionId: req.sessionID,
        correlationId: req.id
      };

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Verify cross-border data transfer compliance
   */
  static verifyCrossBorderCompliance = async (req, res, next) => {
    try {
      const adminUser = req.adminUser;
      
      // Check if operation involves cross-border transfer
      if (!this.involvesCrossBorderTransfer(req)) {
        return next();
      }

      // Get source and destination jurisdictions
      const transfer = await this.getTransferDetails(req);
      
      // Verify transfer is allowed
      const transferAllowed = await this.verifyTransferCompliance(transfer);
      
      if (!transferAllowed.allowed) {
        await this.logComplianceViolation(adminUser, 'cross_border_violation', {
          source: transfer.source,
          destination: transfer.destination,
          reason: transferAllowed.reason
        });
        
        throw new ForbiddenError(transferAllowed.reason || 'Cross-border data transfer not permitted');
      }

      // Add transfer safeguards
      req.transferSafeguards = transferAllowed.requiredSafeguards;

      next();
    } catch (error) {
      next(error);
    }
  };

  /**
   * Track compliance metrics
   */
  static trackComplianceMetrics = async (req, res, next) => {
    try {
      const startTime = Date.now();
      
      // Track response
      res.on('finish', async () => {
        const duration = Date.now() - startTime;
        
        await this.recordComplianceMetrics({
          path: req.path,
          method: req.method,
          statusCode: res.statusCode,
          duration,
          adminUser: req.adminUser?.id,
          complianceChecks: req.complianceChecks || [],
          violations: req.complianceViolations || []
        });
      });

      next();
    } catch (error) {
      next(error);
    }
  };

  // Helper methods

  /**
   * Log compliance violation
   * @private
   */
  static async logComplianceViolation(adminUser, violationType, details) {
    try {
      await AuditLog.create({
        userId: adminUser.id,
        organizationId: adminUser.organizationId,
        eventType: `compliance.violation.${violationType}`,
        severity: 'high',
        category: 'COMPLIANCE',
        details: {
          violationType,
          ...details,
          description: `Compliance violation detected: ${violationType}`
        },
        metadata: {
          ipAddress: adminUser.lastIP,
          userAgent: adminUser.lastUserAgent
        },
        compliance: {
          violation: true,
          violationType,
          standards: await this.getViolatedStandards(violationType)
        },
        timestamp: new Date()
      });

      // Track violation
      const key = `compliance:violations:${adminUser.organizationId || 'platform'}`;
      await CacheService.hincrby(key, violationType, 1);
      await CacheService.expire(key, 86400); // 24 hours
    } catch (error) {
      logger.error('Error logging compliance violation', {
        error: error.message,
        violationType,
        userId: adminUser.id
      });
    }
  }

  /**
   * Get violated standards
   * @private
   */
  static async getViolatedStandards(violationType) {
    const violationMap = {
      'gdpr_no_lawful_basis': ['GDPR'],
      'gdpr_data_minimization': ['GDPR'],
      'hipaa_minimum_necessary': ['HIPAA'],
      'pci_unauthorized_access': ['PCI-DSS'],
      'soc2_criterion_violation': ['SOC2'],
      'retention_policy_violation': ['GDPR', 'HIPAA'],
      'cross_border_violation': ['GDPR', 'APEC']
    };

    return violationMap[violationType] || [];
  }

  /**
   * Check if data access logging is required
   * @private
   */
  static requiresAccessLogging(req) {
    const sensitiveEndpoints = [
      '/users',
      '/organizations',
      '/payments',
      '/audit',
      '/compliance'
    ];

    return sensitiveEndpoints.some(endpoint => req.path.includes(endpoint));
  }

  /**
   * Log data access
   * @private
   */
  static async logDataAccess(adminUser, req) {
    try {
      await AuditLog.create({
        userId: adminUser.id,
        organizationId: adminUser.organizationId,
        eventType: 'data.access',
        severity: 'low',
        category: 'DATA_ACCESS',
        details: {
          path: req.path,
          method: req.method,
          query: req.query,
          dataType: this.getDataType(req.path)
        },
        metadata: {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        },
        compliance: {
          logged: true,
          standards: ['SOC2', 'ISO27001']
        },
        timestamp: new Date()
      });
    } catch (error) {
      logger.error('Error logging data access', {
        error: error.message,
        userId: adminUser.id,
        path: req.path
      });
    }
  }

  /**
   * Get data type from path
   * @private
   */
  static getDataType(path) {
    if (path.includes('/users')) return 'user_data';
    if (path.includes('/organizations')) return 'organization_data';
    if (path.includes('/payments')) return 'payment_data';
    if (path.includes('/audit')) return 'audit_data';
    return 'general_data';
  }

  /**
   * Verify data residency
   * @private
   */
  static async verifyDataResidency(req) {
    try {
      // Check if organization has residency requirements
      if (!req.adminUser?.organizationId) {
        return true;
      }

      const cacheKey = `residency:${req.adminUser.organizationId}`;
      const requirements = await CacheService.get(cacheKey);
      
      if (!requirements) {
        return true;
      }

      // Verify request complies with residency
      const requestRegion = req.headers['x-region'] || process.env.DEFAULT_REGION;
      return requirements.allowedRegions.includes(requestRegion);
    } catch (error) {
      logger.error('Error verifying data residency', {
        error: error.message,
        path: req.path
      });
      return true; // Fail open for now
    }
  }

  /**
   * Check if GDPR applies
   * @private
   */
  static async isGDPRApplicable(req) {
    try {
      if (!req.adminUser?.organizationId) {
        return false;
      }

      const cacheKey = `compliance:gdpr:${req.adminUser.organizationId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached !== null) {
        return cached;
      }

      // Check organization settings
      const settings = await this.getOrganizationCompliance(req.adminUser.organizationId);
      const applicable = settings.standards?.includes('GDPR') || settings.region === 'EU';
      
      await CacheService.set(cacheKey, applicable, 3600);
      return applicable;
    } catch (error) {
      return false;
    }
  }

  /**
   * Check if operation involves personal data
   * @private
   */
  static isPersonalDataOperation(req) {
    const personalDataPaths = [
      '/users',
      '/profiles',
      '/contacts',
      '/communications'
    ];

    return personalDataPaths.some(path => req.path.includes(path));
  }

  /**
   * Verify lawful basis for processing
   * @private
   */
  static async verifyLawfulBasis(req) {
    // Simplified check - in production would be more complex
    const lawfulBases = [
      'consent',
      'contract',
      'legal_obligation',
      'vital_interests',
      'public_task',
      'legitimate_interests'
    ];

    // Check if operation has declared lawful basis
    const basis = req.headers['x-lawful-basis'] || req.body.lawfulBasis;
    return lawfulBases.includes(basis);
  }

  /**
   * Get minimal fields for data minimization
   * @private
   */
  static getMinimalFields(path) {
    const fieldMap = {
      '/users': 'id,email,name,status',
      '/organizations': 'id,name,plan,status',
      '/audit': 'id,eventType,timestamp,severity'
    };

    for (const [pathPattern, fields] of Object.entries(fieldMap)) {
      if (path.includes(pathPattern)) {
        return fields;
      }
    }

    return null;
  }

  /**
   * Check if operation is marketing related
   * @private
   */
  static isMarketingOperation(req) {
    return req.path.includes('/marketing') || 
           req.path.includes('/campaigns') ||
           req.path.includes('/communications/bulk');
  }

  /**
   * Verify marketing consent
   * @private
   */
  static async verifyMarketingConsent(req) {
    // In production, would check actual consent records
    return req.body.hasMarketingConsent === true;
  }

  /**
   * Check if HIPAA applies
   * @private
   */
  static async isHIPAAApplicable(req) {
    try {
      if (!req.adminUser?.organizationId) {
        return false;
      }

      const settings = await this.getOrganizationCompliance(req.adminUser.organizationId);
      return settings.standards?.includes('HIPAA') || settings.industry === 'healthcare';
    } catch (error) {
      return false;
    }
  }

  /**
   * Verify HIPAA training
   * @private
   */
  static async verifyHIPAATraining(adminUser) {
    try {
      const cacheKey = `training:hipaa:${adminUser.id}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached !== null) {
        return cached;
      }

      // Check training records
      const hasTraining = adminUser.certifications?.includes('HIPAA') || false;
      
      await CacheService.set(cacheKey, hasTraining, 86400); // 24 hours
      return hasTraining;
    } catch (error) {
      return false;
    }
  }

  /**
   * Check if operation involves PHI
   * @private
   */
  static isPHIOperation(req) {
    const phiPaths = [
      '/patients',
      '/medical-records',
      '/health-data',
      '/prescriptions'
    ];

    return phiPaths.some(path => req.path.includes(path));
  }

  /**
   * Check minimum necessary standard
   * @private
   */
  static meetsMinimumNecessary(req) {
    // Check if request is scoped appropriately
    if (req.query.includeAll || req.query.fields === '*') {
      return false;
    }

    // Check if user has legitimate need
    return true;
  }

  /**
   * Log PHI access
   * @private
   */
  static async logPHIAccess(adminUser, req) {
    try {
      await AuditLog.create({
        userId: adminUser.id,
        organizationId: adminUser.organizationId,
        eventType: 'phi.access',
        severity: 'medium',
        category: 'PHI_ACCESS',
        details: {
          path: req.path,
          method: req.method,
          purpose: req.headers['x-access-purpose'] || 'not specified'
        },
        metadata: {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        },
        compliance: {
          standard: 'HIPAA',
          logged: true
        },
        timestamp: new Date()
      });
    } catch (error) {
      logger.error('Error logging PHI access', {
        error: error.message,
        userId: adminUser.id
      });
    }
  }

  /**
   * Check if request contains PHI
   * @private
   */
  static containsPHI(req) {
    // Check request body and params for PHI indicators
    const phiFields = [
      'ssn',
      'medicalRecordNumber',
      'healthPlan',
      'diagnosis',
      'treatment'
    ];

    const data = { ...req.body, ...req.query };
    return phiFields.some(field => data.hasOwnProperty(field));
  }

  /**
   * Check if PCI DSS applies
   * @private
   */
  static isPCIDSSApplicable(req) {
    return req.path.includes('/payments') || 
           req.path.includes('/cards') ||
           req.path.includes('/transactions');
  }

  /**
   * Get PCI compliance level
   * @private
   */
  static async getPCIComplianceLevel(organizationId) {
    try {
      const cacheKey = `compliance:pci:level:${organizationId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached) {
        return cached;
      }

      // In production, would check actual compliance level
      const level = 'Level 2'; // Default level
      
      await CacheService.set(cacheKey, level, 3600);
      return level;
    } catch (error) {
      return 'Level 4';
    }
  }

  /**
   * Check if operation involves cardholder data
   * @private
   */
  static isCardholderDataOperation(req) {
    return req.path.includes('/cards') || 
           (req.body && (req.body.cardNumber || req.body.cvv));
  }

  /**
   * Sanitize cardholder data
   * @private
   */
  static sanitizeCardholderData(req) {
    // Remove sensitive authentication data
    if (req.body.cvv) {
      delete req.body.cvv;
    }
    
    if (req.body.pin) {
      delete req.body.pin;
    }

    // Mask card number
    if (req.body.cardNumber) {
      req.body.cardNumber = this.maskCardNumber(req.body.cardNumber);
    }
  }

  /**
   * Mask card number
   * @private
   */
  static maskCardNumber(cardNumber) {
    const cleaned = cardNumber.replace(/\D/g, '');
    if (cleaned.length < 12) return cardNumber;
    
    const first6 = cleaned.substring(0, 6);
    const last4 = cleaned.substring(cleaned.length - 4);
    const masked = '*'.repeat(cleaned.length - 10);
    
    return `${first6}${masked}${last4}`;
  }

  /**
   * Log cardholder data access
   * @private
   */
  static async logCardholderDataAccess(adminUser, req) {
    try {
      await AuditLog.create({
        userId: adminUser.id,
        organizationId: adminUser.organizationId,
        eventType: 'cardholder_data.access',
        severity: 'high',
        category: 'PCI_DSS',
        details: {
          path: req.path,
          method: req.method,
          dataType: 'cardholder_data'
        },
        metadata: {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        },
        compliance: {
          standard: 'PCI-DSS',
          logged: true
        },
        timestamp: new Date()
      });
    } catch (error) {
      logger.error('Error logging cardholder data access', {
        error: error.message,
        userId: adminUser.id
      });
    }
  }

  /**
   * Check if request contains card data
   * @private
   */
  static containsCardData(req) {
    const cardFields = ['cardNumber', 'expiryDate', 'cvv', 'cardholderName'];
    const data = { ...req.body, ...req.query };
    
    return cardFields.some(field => data.hasOwnProperty(field));
  }

  /**
   * Check if SOC 2 applies
   * @private
   */
  static async isSOC2Applicable(req) {
    try {
      if (!req.adminUser?.organizationId) {
        return false;
      }

      const settings = await this.getOrganizationCompliance(req.adminUser.organizationId);
      return settings.standards?.includes('SOC2');
    } catch (error) {
      return false;
    }
  }

  /**
   * Get applicable trust criteria
   * @private
   */
  static async getApplicableTrustCriteria(req) {
    // SOC 2 Trust Service Criteria
    const criteria = ['security'];

    // Add criteria based on operation
    if (req.path.includes('/availability')) {
      criteria.push('availability');
    }
    
    if (this.isPersonalDataOperation(req)) {
      criteria.push('confidentiality', 'privacy');
    }
    
    if (req.method !== 'GET') {
      criteria.push('processing_integrity');
    }

    return criteria;
  }

  /**
   * Verify trust criterion
   * @private
   */
  static async verifyTrustCriterion(criterion, req, adminUser) {
    switch (criterion) {
      case 'security':
        return req.secure && adminUser.mfaEnabled;
      
      case 'availability':
        return await this.checkServiceAvailability();
      
      case 'confidentiality':
        return await this.verifyConfidentialityControls(req);
      
      case 'privacy':
        return await this.verifyPrivacyControls(req);
      
      case 'processing_integrity':
        return await this.verifyProcessingIntegrity(req);
      
      default:
        return true;
    }
  }

  /**
   * Log SOC 2 activity
   * @private
   */
  static async logSOC2Activity(adminUser, req) {
    try {
      await AuditLog.create({
        userId: adminUser.id,
        organizationId: adminUser.organizationId,
        eventType: 'soc2.activity',
        severity: 'low',
        category: 'SOC2_COMPLIANCE',
        details: {
          path: req.path,
          method: req.method,
          criteria: await this.getApplicableTrustCriteria(req)
        },
        metadata: {
          ipAddress: req.ip,
          userAgent: req.headers['user-agent']
        },
        compliance: {
          standard: 'SOC2',
          logged: true
        },
        timestamp: new Date()
      });
    } catch (error) {
      logger.error('Error logging SOC 2 activity', {
        error: error.message,
        userId: adminUser.id
      });
    }
  }

  /**
   * Check if operation affects data retention
   * @private
   */
  static affectsDataRetention(req) {
    return req.method === 'DELETE' || 
           req.path.includes('/archive') ||
           req.path.includes('/retention');
  }

  /**
   * Get retention policies
   * @private
   */
  static async getRetentionPolicies(organizationId) {
    try {
      const cacheKey = `retention:policies:${organizationId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached) {
        return cached;
      }

      // Default retention policies
      const policies = {
        audit_logs: { days: 2555, standard: 'SOC2' }, // 7 years
        user_data: { days: 1095, standard: 'GDPR' }, // 3 years
        payment_data: { days: 2555, standard: 'PCI-DSS' } // 7 years
      };

      await CacheService.set(cacheKey, policies, 3600);
      return policies;
    } catch (error) {
      return {};
    }
  }

  /**
   * Verify deletion compliance
   * @private
   */
  static async verifyDeletionCompliance(req, policies) {
    // Extract resource type from path
    const resourceType = this.getResourceType(req.path);
    const policy = policies[resourceType];

    if (!policy) {
      return { allowed: true };
    }

    // Check if data is under retention
    const resourceAge = await this.getResourceAge(req.params.id);
    if (resourceAge < policy.days * 24 * 60 * 60 * 1000) {
      return {
        allowed: false,
        reason: `Data must be retained for ${policy.days} days per ${policy.standard}`
      };
    }

    // Check for legal holds
    const hasLegalHold = await this.checkLegalHold(req.params.id);
    if (hasLegalHold) {
      return {
        allowed: false,
        reason: 'Data is under legal hold'
      };
    }

    return { allowed: true };
  }

  /**
   * Get resource type from path
   * @private
   */
  static getResourceType(path) {
    if (path.includes('/audit')) return 'audit_logs';
    if (path.includes('/users')) return 'user_data';
    if (path.includes('/payments')) return 'payment_data';
    return 'general_data';
  }

  /**
   * Get resource age
   * @private
   */
  static async getResourceAge(resourceId) {
    // In production, would check actual resource age
    return 30 * 24 * 60 * 60 * 1000; // 30 days
  }

  /**
   * Check legal hold
   * @private
   */
  static async checkLegalHold(resourceId) {
    try {
      const cacheKey = `legal_hold:${resourceId}`;
      const hold = await CacheService.get(cacheKey);
      return !!hold;
    } catch (error) {
      return false;
    }
  }

  /**
   * Determine audit level
   * @private
   */
  static determineAuditLevel(req) {
    // Critical operations
    if (req.path.includes('/security') || 
        req.path.includes('/encryption') ||
        req.path.includes('/compliance')) {
      return 'critical';
    }

    // High risk operations
    if (req.method === 'DELETE' || 
        req.path.includes('/bulk') ||
        req.path.includes('/export')) {
      return 'high';
    }

    // Modifications
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Check if operation requires approval
   * @private
   */
  static requiresApproval(req) {
    const approvalRequired = [
      '/security/encryption/rotate',
      '/compliance/standards/delete',
      '/audit/purge'
    ];

    return approvalRequired.some(path => req.path.includes(path));
  }

  /**
   * Verify approval
   * @private
   */
  static async verifyApproval(req, adminUser) {
    try {
      const approvalToken = req.headers['x-approval-token'] || req.body.approvalToken;
      
      if (!approvalToken) {
        return false;
      }

      const cacheKey = `approval:${approvalToken}`;
      const approval = await CacheService.get(cacheKey);
      
      if (!approval) {
        return false;
      }

      // Verify approval is for this operation
      return approval.operation === req.path && 
             approval.approvedBy !== adminUser.id;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get applicable compliance standards
   * @private
   */
  static async getApplicableStandards(organizationId) {
    try {
      const settings = await this.getOrganizationCompliance(organizationId);
      return settings.standards || [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Check if operation involves cross-border transfer
   * @private
   */
  static involvesCrossBorderTransfer(req) {
    return req.headers['x-destination-region'] && 
           req.headers['x-destination-region'] !== process.env.DEFAULT_REGION;
  }

  /**
   * Get transfer details
   * @private
   */
  static async getTransferDetails(req) {
    return {
      source: process.env.DEFAULT_REGION || 'US',
      destination: req.headers['x-destination-region'],
      dataType: this.getDataType(req.path),
      volume: req.headers['content-length'] || 0
    };
  }

  /**
   * Verify transfer compliance
   * @private
   */
  static async verifyTransferCompliance(transfer) {
    // Simplified transfer rules
    const allowedTransfers = {
      'US': ['US', 'CA', 'UK', 'EU'],
      'EU': ['EU', 'UK', 'CH'],
      'UK': ['UK', 'EU', 'US'],
      'CA': ['CA', 'US']
    };

    const allowed = allowedTransfers[transfer.source]?.includes(transfer.destination);

    if (!allowed) {
      return {
        allowed: false,
        reason: `Data transfer from ${transfer.source} to ${transfer.destination} not permitted`
      };
    }

    // Determine required safeguards
    const safeguards = [];
    if (transfer.source !== transfer.destination) {
      safeguards.push('encryption', 'contractual_clauses');
    }

    return {
      allowed: true,
      requiredSafeguards: safeguards
    };
  }

  /**
   * Record compliance metrics
   * @private
   */
  static async recordComplianceMetrics(metrics) {
    try {
      const key = `compliance:metrics:${new Date().toISOString().split('T')[0]}`;
      
      await CacheService.hincrby(key, 'total_requests', 1);
      await CacheService.hincrby(key, `status_${metrics.statusCode}`, 1);
      
      if (metrics.violations.length > 0) {
        await CacheService.hincrby(key, 'violations', metrics.violations.length);
      }

      await CacheService.expire(key, 86400 * 30); // 30 days
    } catch (error) {
      // Silent fail for metrics
    }
  }

  /**
   * Get organization compliance settings
   * @private
   */
  static async getOrganizationCompliance(organizationId) {
    try {
      const cacheKey = `org:compliance:${organizationId}`;
      const cached = await CacheService.get(cacheKey);
      
      if (cached) {
        return cached;
      }

      // Default compliance settings
      const settings = {
        standards: ['SOC2'],
        region: 'US',
        industry: 'technology'
      };

      await CacheService.set(cacheKey, settings, 3600);
      return settings;
    } catch (error) {
      return {};
    }
  }

  /**
   * Check service availability
   * @private
   */
  static async checkServiceAvailability() {
    // In production, would check actual service health
    return true;
  }

  /**
   * Verify confidentiality controls
   * @private
   */
  static async verifyConfidentialityControls(req) {
    return req.secure && !req.query.includeConfidential;
  }

  /**
   * Verify privacy controls
   * @private
   */
  static async verifyPrivacyControls(req) {
    return !req.query.includePersonal || req.headers['x-privacy-consent'] === 'true';
  }

  /**
   * Verify processing integrity
   * @private
   */
  static async verifyProcessingIntegrity(req) {
    // Check for data validation
    return req.body && Object.keys(req.body).length > 0;
  }
}

module.exports = ComplianceVerificationMiddleware;