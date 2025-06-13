// server/shared/billing/services/tax-service.js
/**
 * @file Tax Service
 * @description Service for handling tax calculations and compliance
 * @version 3.0.0
 */

const logger = require('../../utils/logger');
const { ValidationError } = require('../../utils/app-error');
const CacheService = require('../../utils/cache-service');
const config = require('../../config');

// Tax rate database (simplified - in production, use a tax API service)
const TAX_RATES = {
  US: {
    default: 0,
    states: {
      CA: 0.0725,
      NY: 0.08,
      TX: 0.0625,
      FL: 0.06,
      WA: 0.065,
      IL: 0.0625,
      PA: 0.06,
      OH: 0.0575,
      GA: 0.04,
      NC: 0.0475,
      MI: 0.06,
      NJ: 0.06625,
      VA: 0.053,
      MA: 0.0625,
      AZ: 0.056,
      IN: 0.07,
      TN: 0.07,
      MO: 0.04225,
      MD: 0.06,
      WI: 0.05,
      MN: 0.06875,
      CO: 0.029,
      AL: 0.04,
      SC: 0.06,
      LA: 0.0445,
      KY: 0.06,
      OR: 0,
      OK: 0.045,
      CT: 0.0635,
      UT: 0.0485,
      IA: 0.06,
      NV: 0.0685,
      AR: 0.065,
      MS: 0.07,
      KS: 0.065,
      NM: 0.05125,
      NE: 0.055,
      ID: 0.06,
      WV: 0.06,
      HI: 0.04,
      NH: 0,
      ME: 0.055,
      MT: 0,
      RI: 0.07,
      DE: 0,
      SD: 0.045,
      ND: 0.05,
      AK: 0,
      VT: 0.06,
      WY: 0.04
    }
  },
  CA: {
    default: 0.05,
    provinces: {
      ON: 0.13,
      QC: 0.14975,
      BC: 0.12,
      AB: 0.05,
      MB: 0.12,
      SK: 0.11,
      NS: 0.15,
      NB: 0.15,
      NL: 0.15,
      PE: 0.15,
      NT: 0.05,
      YT: 0.05,
      NU: 0.05
    }
  },
  GB: {
    default: 0.20,
    reduced: 0.05,
    zero: 0
  },
  EU: {
    default: 0.21,
    countries: {
      DE: 0.19,
      FR: 0.20,
      IT: 0.22,
      ES: 0.21,
      NL: 0.21,
      BE: 0.21,
      PL: 0.23,
      SE: 0.25,
      DK: 0.25,
      FI: 0.24,
      AT: 0.20,
      PT: 0.23,
      GR: 0.24,
      CZ: 0.21,
      HU: 0.27,
      RO: 0.19,
      BG: 0.20,
      HR: 0.25,
      SK: 0.20,
      SI: 0.22,
      LT: 0.21,
      LV: 0.21,
      EE: 0.20,
      CY: 0.19,
      LU: 0.17,
      MT: 0.18,
      IE: 0.23
    }
  },
  AU: {
    default: 0.10
  }
};

// Tax-exempt categories
const TAX_EXEMPT_CATEGORIES = {
  NONPROFIT: 'nonprofit',
  EDUCATIONAL: 'educational',
  GOVERNMENT: 'government',
  RESELLER: 'reseller',
  DIPLOMATIC: 'diplomatic'
};

// Service types subject to different tax treatments
const SERVICE_TAX_CATEGORIES = {
  DIGITAL_SERVICE: 'digital_service',
  PROFESSIONAL_SERVICE: 'professional_service',
  SUBSCRIPTION: 'subscription',
  CONSULTING: 'consulting',
  SAAS: 'saas'
};

/**
 * Tax Service Class
 * @class TaxService
 */
class TaxService {
  /**
   * Calculate tax for a transaction
   * @param {Object} taxData - Tax calculation data
   * @returns {Promise<Number>} Tax amount
   */
  static async calculateTax(taxData) {
    try {
      const {
        amount,
        userId,
        organizationId,
        type = 'subscription',
        location,
        taxExempt = false,
        taxExemptionReason
      } = taxData;
      
      // Check if tax exempt
      if (taxExempt && this.isValidTaxExemption(taxExemptionReason)) {
        return 0;
      }
      
      // Get location data
      const taxLocation = location || await this.getUserLocation(userId);
      
      if (!taxLocation || !taxLocation.country) {
        logger.warn('No location data for tax calculation', { userId });
        return 0;
      }
      
      // Get applicable tax rate
      const taxRate = await this.getTaxRate(taxLocation, type);
      
      // Calculate tax amount
      const taxAmount = amount * taxRate;
      
      // Log tax calculation for audit
      await this.logTaxCalculation({
        userId,
        organizationId,
        amount,
        taxRate,
        taxAmount,
        location: taxLocation,
        type,
        taxExempt
      });
      
      return Math.round(taxAmount * 100) / 100; // Round to 2 decimal places
      
    } catch (error) {
      logger.error('Calculate tax error', { error });
      throw error;
    }
  }
  
  /**
   * Get tax rate for location and service type
   * @param {Object} location - Location data
   * @param {string} serviceType - Type of service
   * @returns {Promise<Number>} Tax rate
   */
  static async getTaxRate(location, serviceType) {
    try {
      const cacheKey = `tax_rate:${location.country}:${location.state}:${serviceType}`;
      
      // Check cache
      const cachedRate = await CacheService.get(cacheKey);
      if (cachedRate !== null) {
        return cachedRate;
      }
      
      let taxRate = 0;
      
      // US tax rates
      if (location.country === 'US') {
        if (location.state && TAX_RATES.US.states[location.state]) {
          taxRate = TAX_RATES.US.states[location.state];
        } else {
          taxRate = TAX_RATES.US.default;
        }
        
        // Add local taxes if applicable
        if (location.city) {
          taxRate += await this.getLocalTaxRate(location);
        }
      }
      
      // Canadian tax rates
      else if (location.country === 'CA') {
        if (location.province && TAX_RATES.CA.provinces[location.province]) {
          taxRate = TAX_RATES.CA.provinces[location.province];
        } else {
          taxRate = TAX_RATES.CA.default;
        }
      }
      
      // UK tax rates
      else if (location.country === 'GB') {
        // Different rates for different service types
        if (serviceType === SERVICE_TAX_CATEGORIES.DIGITAL_SERVICE) {
          taxRate = TAX_RATES.GB.default;
        } else if (serviceType === SERVICE_TAX_CATEGORIES.EDUCATIONAL) {
          taxRate = TAX_RATES.GB.zero;
        } else {
          taxRate = TAX_RATES.GB.default;
        }
      }
      
      // EU tax rates
      else if (this.isEUCountry(location.country)) {
        if (TAX_RATES.EU.countries[location.country]) {
          taxRate = TAX_RATES.EU.countries[location.country];
        } else {
          taxRate = TAX_RATES.EU.default;
        }
        
        // Apply MOSS rules for digital services
        if (serviceType === SERVICE_TAX_CATEGORIES.DIGITAL_SERVICE) {
          taxRate = await this.getMOSSTaxRate(location);
        }
      }
      
      // Australian tax rates
      else if (location.country === 'AU') {
        taxRate = TAX_RATES.AU.default;
      }
      
      // Cache the rate
      await CacheService.set(cacheKey, taxRate, 86400); // Cache for 24 hours
      
      return taxRate;
      
    } catch (error) {
      logger.error('Get tax rate error', { error, location });
      return 0; // Default to no tax on error
    }
  }
  
  /**
   * Get local tax rate (US cities/counties)
   * @param {Object} location - Location data
   * @returns {Promise<Number>} Local tax rate
   */
  static async getLocalTaxRate(location) {
    // In production, this would integrate with a tax API service
    // For now, return a simplified rate
    const localRates = {
      'New York City': 0.045,
      'Los Angeles': 0.0125,
      'Chicago': 0.0125,
      'Houston': 0.0125,
      'Phoenix': 0.027,
      'Philadelphia': 0.02,
      'San Antonio': 0.0125,
      'San Diego': 0.0075,
      'Dallas': 0.0125,
      'San Jose': 0.0125
    };
    
    return localRates[location.city] || 0;
  }
  
  /**
   * Check if country is in EU
   * @param {string} countryCode - ISO country code
   * @returns {boolean} Is EU country
   */
  static isEUCountry(countryCode) {
    return Object.keys(TAX_RATES.EU.countries).includes(countryCode);
  }
  
  /**
   * Get MOSS tax rate for EU digital services
   * @param {Object} location - Location data
   * @returns {Promise<Number>} MOSS tax rate
   */
  static async getMOSSTaxRate(location) {
    // Mini One Stop Shop (MOSS) rules for EU digital services
    // Tax is charged at the rate of the customer's country
    return TAX_RATES.EU.countries[location.country] || TAX_RATES.EU.default;
  }
  
  /**
   * Validate tax exemption
   * @param {string} reason - Tax exemption reason
   * @returns {boolean} Is valid exemption
   */
  static isValidTaxExemption(reason) {
    return Object.values(TAX_EXEMPT_CATEGORIES).includes(reason);
  }
  
  /**
   * Get user location for tax purposes
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Location data
   */
  static async getUserLocation(userId) {
    try {
      const User = require('../../users/models/user-model');
      const user = await User.findById(userId).select('contact.address billingAddress');
      
      if (!user) {
        return null;
      }
      
      const address = user.billingAddress || user.contact?.address;
      
      if (!address) {
        return null;
      }
      
      return {
        country: address.country,
        state: address.state,
        province: address.state, // For Canada
        city: address.city,
        postalCode: address.postalCode
      };
      
    } catch (error) {
      logger.error('Get user location error', { error, userId });
      return null;
    }
  }
  
  /**
   * Calculate tax breakdown
   * @param {Object} taxData - Tax calculation data
   * @returns {Promise<Object>} Tax breakdown
   */
  static async calculateTaxBreakdown(taxData) {
    try {
      const location = taxData.location || await this.getUserLocation(taxData.userId);
      const baseRate = await this.getTaxRate(location, taxData.type);
      const localRate = location?.city ? await this.getLocalTaxRate(location) : 0;
      
      const breakdown = {
        subtotal: taxData.amount,
        taxRate: baseRate + localRate,
        stateTax: {
          rate: baseRate,
          amount: taxData.amount * baseRate
        },
        localTax: {
          rate: localRate,
          amount: taxData.amount * localRate
        },
        totalTax: taxData.amount * (baseRate + localRate),
        total: taxData.amount + (taxData.amount * (baseRate + localRate)),
        jurisdiction: {
          country: location?.country,
          state: location?.state,
          city: location?.city
        }
      };
      
      return breakdown;
      
    } catch (error) {
      logger.error('Calculate tax breakdown error', { error });
      throw error;
    }
  }
  
  /**
   * Generate tax invoice data
   * @param {Object} invoice - Invoice object
   * @returns {Promise<Object>} Tax invoice data
   */
  static async generateTaxInvoiceData(invoice) {
    try {
      const taxData = {
        invoiceNumber: invoice.invoiceNumber,
        date: invoice.dates.issued,
        seller: {
          name: config.company.legalName || 'Insightserenity Inc.',
          address: config.company.address,
          taxId: config.company.taxId,
          vatNumber: config.company.vatNumber
        },
        buyer: {
          name: invoice.billingInfo.company?.name || invoice.billingInfo.customer.name,
          address: invoice.billingInfo.address,
          taxId: invoice.billingInfo.company?.taxId,
          vatNumber: invoice.billingInfo.company?.vatNumber
        },
        items: invoice.items.map(item => ({
          description: item.name,
          quantity: item.quantity.amount,
          rate: item.rate.amount,
          amount: item.amount,
          taxRate: item.tax?.rate || 0,
          taxAmount: item.tax?.amount || 0,
          total: item.total
        })),
        taxSummary: {
          subtotal: invoice.financials.subtotal,
          taxAmount: invoice.financials.tax.total,
          total: invoice.financials.total
        }
      };
      
      return taxData;
      
    } catch (error) {
      logger.error('Generate tax invoice data error', { error });
      throw error;
    }
  }
  
  /**
   * Validate tax number
   * @param {string} taxNumber - Tax identification number
   * @param {string} country - Country code
   * @returns {Promise<Object>} Validation result
   */
  static async validateTaxNumber(taxNumber, country) {
    try {
      // Basic validation patterns
      const patterns = {
        US: /^\d{2}-\d{7}$/, // EIN format
        CA: /^\d{9}(RT\d{4})?$/, // BN format
        GB: /^GB\d{9}$|^GB\d{12}$|^GBGD\d{3}$|^GBHA\d{3}$/, // VAT format
        EU: /^[A-Z]{2}\d{8,12}$/ // General EU VAT format
      };
      
      let isValid = false;
      let format = null;
      
      if (country === 'US' && patterns.US.test(taxNumber)) {
        isValid = true;
        format = 'EIN';
      } else if (country === 'CA' && patterns.CA.test(taxNumber)) {
        isValid = true;
        format = 'BN';
      } else if (country === 'GB' && patterns.GB.test(taxNumber)) {
        isValid = true;
        format = 'VAT';
      } else if (this.isEUCountry(country) && patterns.EU.test(taxNumber)) {
        isValid = true;
        format = 'VAT';
      }
      
      // In production, integrate with VIES or similar service for real validation
      
      return {
        valid: isValid,
        format,
        country,
        number: taxNumber
      };
      
    } catch (error) {
      logger.error('Validate tax number error', { error });
      return { valid: false, error: error.message };
    }
  }
  
  /**
   * Log tax calculation for audit
   * @param {Object} calculationData - Tax calculation data
   * @returns {Promise<void>}
   */
  static async logTaxCalculation(calculationData) {
    try {
      // In production, this would store in a dedicated audit table
      logger.info('Tax calculation', {
        ...calculationData,
        timestamp: new Date(),
        calculationId: `TAX_CALC_${Date.now()}`
      });
      
    } catch (error) {
      logger.error('Log tax calculation error', { error });
    }
  }
  
  /**
   * Get tax report data
   * @param {Object} filters - Report filters
   * @returns {Promise<Object>} Tax report data
   */
  static async getTaxReport(filters) {
    try {
      const Invoice = require('../models/invoice-model');
      
      const invoices = await Invoice.find({
        status: 'paid',
        'dates.paid': {
          $gte: filters.startDate,
          $lte: filters.endDate
        }
      });
      
      const report = {
        period: {
          start: filters.startDate,
          end: filters.endDate
        },
        summary: {
          totalSales: 0,
          totalTax: 0,
          count: invoices.length
        },
        byJurisdiction: {},
        byType: {}
      };
      
      invoices.forEach(invoice => {
        report.summary.totalSales += invoice.financials.subtotal;
        report.summary.totalTax += invoice.financials.tax.total;
        
        // Group by jurisdiction
        const jurisdiction = invoice.billingInfo.address.state || invoice.billingInfo.address.country;
        if (!report.byJurisdiction[jurisdiction]) {
          report.byJurisdiction[jurisdiction] = {
            sales: 0,
            tax: 0,
            count: 0
          };
        }
        report.byJurisdiction[jurisdiction].sales += invoice.financials.subtotal;
        report.byJurisdiction[jurisdiction].tax += invoice.financials.tax.total;
        report.byJurisdiction[jurisdiction].count++;
        
        // Group by type
        if (!report.byType[invoice.type]) {
          report.byType[invoice.type] = {
            sales: 0,
            tax: 0,
            count: 0
          };
        }
        report.byType[invoice.type].sales += invoice.financials.subtotal;
        report.byType[invoice.type].tax += invoice.financials.tax.total;
        report.byType[invoice.type].count++;
      });
      
      return report;
      
    } catch (error) {
      logger.error('Get tax report error', { error });
      throw error;
    }
  }
}

module.exports = TaxService;