/**
 * @file Audit Compliance Service
 * @description Handles compliance mapping and reporting for audit logs
 * @version 1.0.0
 */

const AuditRepository = require('../repositories/audit-repository');
const logger = require('../../utils/logger');

/**
 * Audit Compliance Service Class
 * @class AuditComplianceService
 */
class AuditComplianceService {
  constructor() {
    this.repository = new AuditRepository();
    
    // Compliance regulation mappings
    this.complianceMap = {
      GDPR: {
        events: ['data_access', 'data_modification', 'data_deletion', 'consent', 'personal_data'],
        retentionDays: 1095, // 3 years
        controls: ['data_protection', 'user_rights', 'consent_management', 'data_portability']
      },
      HIPAA: {
        events: ['health_data_access', 'health_data_modification', 'authentication', 'phi_access'],
        retentionDays: 2190, // 6 years
        controls: ['access_control', 'encryption', 'audit_controls', 'integrity']
      },
      PCI_DSS: {
        events: ['payment_data_access', 'payment_method_modification', 'authentication', 'cardholder_data'],
        retentionDays: 730, // 2 years
        controls: ['payment_security', 'encryption', 'access_control', 'monitoring']
      },
      SOC2: {
        events: ['access_control', 'data_security', 'availability', 'confidentiality', 'privacy'],
        retentionDays: 1095, // 3 years
        controls: ['security_monitoring', 'access_management', 'change_control', 'risk_assessment']
      },
      ISO27001: {
        events: ['information_security', 'risk_management', 'incident_management', 'access_control'],
        retentionDays: 1095, // 3 years
        controls: ['isms_controls', 'risk_treatment', 'security_objectives', 'continuous_improvement']
      }
    };
    
    // Event type to regulation mapping
    this.eventRegulationMap = {
      // GDPR events
      'user_data_accessed': ['GDPR'],
      'user_data_modified': ['GDPR'],
      'user_data_deleted': ['GDPR'],
      'consent_granted': ['GDPR'],
      'consent_revoked': ['GDPR'],
      'data_exported': ['GDPR'],
      'right_to_be_forgotten': ['GDPR'],
      
      // HIPAA events
      'patient_record_accessed': ['HIPAA'],
      'patient_record_modified': ['HIPAA'],
      'health_data_shared': ['HIPAA'],
      'phi_downloaded': ['HIPAA'],
      
      // PCI-DSS events
      'payment_processed': ['PCI_DSS'],
      'card_data_accessed': ['PCI_DSS'],
      'payment_method_added': ['PCI_DSS'],
      'payment_method_removed': ['PCI_DSS'],
      
      // Multiple regulations
      'authentication_failed': ['GDPR', 'HIPAA', 'PCI_DSS', 'SOC2'],
      'user_login': ['GDPR', 'HIPAA', 'PCI_DSS', 'SOC2'],
      'unauthorized_access': ['GDPR', 'HIPAA', 'PCI_DSS', 'SOC2', 'ISO27001']
    };
  }
  
  /**
   * Map compliance requirements for an event
   * @param {Object} eventData - Event data
   * @returns {Object} Compliance information
   */
  mapCompliance(eventData) {
    const regulations = new Set();
    const controls = new Set();
    const violations = [];
    
    // Check event type mapping
    const eventRegulations = this.eventRegulationMap[eventData.type] || [];
    eventRegulations.forEach(reg => regulations.add(reg));
    
    // Check for specific compliance indicators
    if (this.isPersonalDataEvent(eventData)) {
      regulations.add('GDPR');
      controls.add('data_protection');
    }
    
    if (this.isHealthDataEvent(eventData)) {
      regulations.add('HIPAA');
      controls.add('phi_protection');
    }
    
    if (this.isPaymentDataEvent(eventData)) {
      regulations.add('PCI_DSS');
      controls.add('payment_security');
    }
    
    // Add controls based on regulations
    regulations.forEach(reg => {
      if (this.complianceMap[reg]) {
        this.complianceMap[reg].controls.forEach(control => controls.add(control));
      }
    });
    
    // Check for violations
    const detectedViolations = this.detectViolations(eventData, Array.from(regulations));
    violations.push(...detectedViolations);
    
    return {
      regulations: Array.from(regulations),
      controls: Array.from(controls),
      violations
    };
  }
  
  /**
   * Check if event involves personal data
   * @private
   * @param {Object} eventData - Event data
   * @returns {boolean} Is personal data event
   */
  isPersonalDataEvent(eventData) {
    const personalDataIndicators = [
      'personal_data',
      'user_profile',
      'email',
      'name',
      'address',
      'phone',
      'ssn',
      'identity'
    ];
    
    const eventString = JSON.stringify(eventData).toLowerCase();
    return personalDataIndicators.some(indicator => eventString.includes(indicator));
  }
  
  /**
   * Check if event involves health data
   * @private
   * @param {Object} eventData - Event data
   * @returns {boolean} Is health data event
   */
  isHealthDataEvent(eventData) {
    const healthDataIndicators = [
      'health',
      'medical',
      'patient',
      'diagnosis',
      'treatment',
      'prescription',
      'phi'
    ];
    
    const eventString = JSON.stringify(eventData).toLowerCase();
    return healthDataIndicators.some(indicator => eventString.includes(indicator));
  }
  
  /**
   * Check if event involves payment data
   * @private
   * @param {Object} eventData - Event data
   * @returns {boolean} Is payment data event
   */
  isPaymentDataEvent(eventData) {
    const paymentDataIndicators = [
      'payment',
      'card',
      'credit',
      'debit',
      'account_number',
      'routing_number',
      'cvv',
      'billing'
    ];
    
    const eventString = JSON.stringify(eventData).toLowerCase();
    return paymentDataIndicators.some(indicator => eventString.includes(indicator));
  }
  
  /**
   * Detect compliance violations
   * @private
   * @param {Object} eventData - Event data
   * @param {Array<string>} regulations - Applicable regulations
   * @returns {Array<string>} Detected violations
   */
  detectViolations(eventData, regulations) {
    const violations = [];
    
    // GDPR violations
    if (regulations.includes('GDPR')) {
      if (eventData.type === 'data_accessed' && !eventData.legalBasis) {
        violations.push('gdpr_no_legal_basis');
      }
      if (eventData.type === 'consent_override') {
        violations.push('gdpr_consent_violation');
      }
      if (eventData.dataRetentionExceeded) {
        violations.push('gdpr_retention_exceeded');
      }
    }
    
    // HIPAA violations
    if (regulations.includes('HIPAA')) {
      if (eventData.type === 'phi_accessed' && !eventData.minimumNecessary) {
        violations.push('hipaa_minimum_necessary');
      }
      if (eventData.unauthorizedDisclosure) {
        violations.push('hipaa_unauthorized_disclosure');
      }
    }
    
    // PCI-DSS violations
    if (regulations.includes('PCI_DSS')) {
      if (eventData.unencryptedCardData) {
        violations.push('pci_unencrypted_data');
      }
      if (eventData.storedCVV) {
        violations.push('pci_stored_cvv');
      }
    }
    
    // General violations
    if (eventData.result === 'blocked' && eventData.reason === 'compliance') {
      violations.push('compliance_block');
    }
    
    return violations;
  }
  
  /**
   * Generate compliance report
   * @param {string} regulation - Regulation type
   * @param {Date} startDate - Report start date
   * @param {Date} endDate - Report end date
   * @returns {Promise<Object>} Compliance report
   */
  async generateReport(regulation, startDate, endDate) {
    try {
      if (!this.complianceMap[regulation]) {
        throw new Error(`Unknown regulation: ${regulation}`);
      }
      
      const filters = {
        regulations: [regulation],
        startDate,
        endDate
      };
      
      const { results: events } = await this.repository.query(filters, {
        limit: 10000, // Higher limit for reports
        decrypt: true
      });
      
      const report = {
        regulation,
        period: {
          startDate,
          endDate,
          days: Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24))
        },
        generated: new Date(),
        summary: {
          totalEvents: events.length,
          byCategory: {},
          bySeverity: {},
          byResult: {},
          violations: 0,
          controls: new Set()
        },
        details: {
          events: [],
          violations: [],
          recommendations: []
        },
        compliance: {
          score: 0,
          status: 'unknown',
          gaps: []
        }
      };
      
      // Analyze events
      events.forEach(event => {
        // Category breakdown
        report.summary.byCategory[event.event.category] = 
          (report.summary.byCategory[event.event.category] || 0) + 1;
        
        // Severity breakdown
        report.summary.bySeverity[event.event.severity] = 
          (report.summary.bySeverity[event.event.severity] || 0) + 1;
        
        // Result breakdown
        report.summary.byResult[event.event.result] = 
          (report.summary.byResult[event.event.result] || 0) + 1;
        
        // Track violations
        if (event.security.compliance.violations?.length > 0) {
          report.summary.violations += event.security.compliance.violations.length;
          report.details.violations.push({
            eventId: event.eventId,
            timestamp: event.timestamp,
            violations: event.security.compliance.violations,
            actor: event.actor.email || event.actor.userId,
            action: event.event.action
          });
        }
        
        // Track controls
        event.security.compliance.controls?.forEach(control => {
          report.summary.controls.add(control);
        });
        
        // Add event details
        report.details.events.push({
          timestamp: event.timestamp,
          action: event.event.action,
          actor: event.actor.email || event.actor.userId,
          target: `${event.target.type}:${event.target.id}`,
          result: event.event.result,
          risk: event.security.risk.score
        });
      });
      
      // Convert controls Set to Array
      report.summary.controls = Array.from(report.summary.controls);
      
      // Calculate compliance score
      report.compliance = this.calculateComplianceScore(report, regulation);
      
      // Generate recommendations
      report.details.recommendations = this.generateRecommendations(report, regulation);
      
      return report;
    } catch (error) {
      logger.error('Failed to generate compliance report', {
        error: error.message,
        regulation,
        period: { startDate, endDate }
      });
      throw error;
    }
  }
  
  /**
   * Calculate compliance score
   * @private
   * @param {Object} report - Report data
   * @param {string} regulation - Regulation type
   * @returns {Object} Compliance score and status
   */
  calculateComplianceScore(report, regulation) {
    let score = 100;
    const gaps = [];
    
    // Deduct for violations
    score -= report.summary.violations * 5;
    if (report.summary.violations > 0) {
      gaps.push(`${report.summary.violations} compliance violations detected`);
    }
    
    // Check required controls
    const requiredControls = this.complianceMap[regulation].controls;
    const missingControls = requiredControls.filter(
      control => !report.summary.controls.includes(control)
    );
    
    if (missingControls.length > 0) {
      score -= missingControls.length * 10;
      gaps.push(`Missing controls: ${missingControls.join(', ')}`);
    }
    
    // Check failure rate
    const totalEvents = report.summary.totalEvents;
    const failures = report.summary.byResult.failure || 0;
    const failureRate = totalEvents > 0 ? (failures / totalEvents) * 100 : 0;
    
    if (failureRate > 5) {
      score -= Math.min(failureRate, 20);
      gaps.push(`High failure rate: ${failureRate.toFixed(2)}%`);
    }
    
    // Determine status
    let status;
    if (score >= 90) status = 'compliant';
    else if (score >= 70) status = 'partially_compliant';
    else if (score >= 50) status = 'non_compliant';
    else status = 'critical';
    
    return {
      score: Math.max(0, score),
      status,
      gaps
    };
  }
  
  /**
   * Generate recommendations
   * @private
   * @param {Object} report - Report data
   * @param {string} regulation - Regulation type
   * @returns {Array<Object>} Recommendations
   */
  generateRecommendations(report, regulation) {
    const recommendations = [];
    
    // Violation-based recommendations
    if (report.summary.violations > 0) {
      recommendations.push({
        priority: 'high',
        category: 'violations',
        recommendation: 'Address compliance violations immediately',
        details: `${report.summary.violations} violations detected that require immediate attention`
      });
    }
    
    // Control-based recommendations
    const requiredControls = this.complianceMap[regulation].controls;
    const missingControls = requiredControls.filter(
      control => !report.summary.controls.includes(control)
    );
    
    if (missingControls.length > 0) {
      recommendations.push({
        priority: 'high',
        category: 'controls',
        recommendation: 'Implement missing security controls',
        details: `Missing controls: ${missingControls.join(', ')}`
      });
    }
    
    // Failure rate recommendations
    const totalEvents = report.summary.totalEvents;
    const failures = report.summary.byResult.failure || 0;
    const failureRate = totalEvents > 0 ? (failures / totalEvents) * 100 : 0;
    
    if (failureRate > 5) {
      recommendations.push({
        priority: 'medium',
        category: 'reliability',
        recommendation: 'Investigate and reduce failure rate',
        details: `Current failure rate of ${failureRate.toFixed(2)}% exceeds acceptable threshold`
      });
    }
    
    // Security recommendations
    const criticalEvents = report.summary.bySeverity.critical || 0;
    const highEvents = report.summary.bySeverity.high || 0;
    
    if (criticalEvents > 0 || highEvents > 10) {
      recommendations.push({
        priority: 'high',
        category: 'security',
        recommendation: 'Review and address high-severity security events',
        details: `${criticalEvents} critical and ${highEvents} high severity events detected`
      });
    }
    
    // Regulation-specific recommendations
    if (regulation === 'GDPR' && !report.summary.controls.includes('consent_management')) {
      recommendations.push({
        priority: 'high',
        category: 'gdpr',
        recommendation: 'Implement consent management system',
        details: 'GDPR requires explicit consent tracking and management'
      });
    }
    
    if (regulation === 'PCI_DSS' && !report.summary.controls.includes('encryption')) {
      recommendations.push({
        priority: 'critical',
        category: 'pci',
        recommendation: 'Implement end-to-end encryption for cardholder data',
        details: 'PCI-DSS requires encryption of cardholder data at rest and in transit'
      });
    }
    
    return recommendations;
  }
  
  /**
   * Get retention requirements for regulation
   * @param {string} regulation - Regulation type
   * @returns {Object} Retention requirements
   */
  getRetentionRequirements(regulation) {
    const config = this.complianceMap[regulation];
    if (!config) {
      return { days: 90, policy: 'standard' };
    }
    
    return {
      days: config.retentionDays,
      policy: regulation.toLowerCase(),
      description: `${regulation} requires ${config.retentionDays} days retention`
    };
  }
  
  /**
   * Validate compliance for an event
   * @param {Object} eventData - Event data
   * @returns {Object} Validation result
   */
  validateCompliance(eventData) {
    const complianceInfo = this.mapCompliance(eventData);
    const violations = complianceInfo.violations || [];
    
    return {
      isCompliant: violations.length === 0,
      regulations: complianceInfo.regulations,
      controls: complianceInfo.controls,
      violations,
      recommendations: violations.length > 0 ? 
        [`Address violations: ${violations.join(', ')}`] : 
        []
    };
  }
}

module.exports = AuditComplianceService;