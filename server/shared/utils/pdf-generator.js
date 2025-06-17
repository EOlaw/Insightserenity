/**
 * @file PDF Generator Utility
 * @description Utility for generating PDF documents from templates and data
 * @version 2.0.0
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const handlebars = require('handlebars');
const puppeteer = require('puppeteer');
const logger = require('./logger');

/**
 * PDF Generator Class
 */
class PDFGenerator {
  constructor() {
    this.templatesPath = path.join(__dirname, '../../templates/pdf');
    this.assetsPath = path.join(__dirname, '../../assets');
    this.registerHelpers();
  }

  /**
   * Register Handlebars helpers for template processing
   */
  registerHelpers() {
    // Format date helper
    handlebars.registerHelper('formatDate', (date, format = 'MMM DD, YYYY') => {
      if (!date) return '';
      const d = new Date(date);
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      
      if (format === 'MMM DD, YYYY') {
        return `${months[d.getMonth()]} ${d.getDate()}, ${d.getFullYear()}`;
      } else if (format === 'MM/DD/YYYY') {
        return `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getDate().toString().padStart(2, '0')}/${d.getFullYear()}`;
      }
      return d.toLocaleDateString();
    });

    // Format currency helper
    handlebars.registerHelper('formatCurrency', (amount, currency = 'USD') => {
      if (!amount) return '$0.00';
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency
      }).format(amount);
    });

    // Format percentage helper
    handlebars.registerHelper('formatPercentage', (value) => {
      if (value === null || value === undefined) return '0%';
      return `${Math.round(value)}%`;
    });

    // Conditional helper
    handlebars.registerHelper('ifEquals', function(arg1, arg2, options) {
      return (arg1 == arg2) ? options.fn(this) : options.inverse(this);
    });

    // Array join helper
    handlebars.registerHelper('join', (array, separator = ', ') => {
      if (!Array.isArray(array)) return '';
      return array.join(separator);
    });

    // Rating stars helper
    handlebars.registerHelper('ratingStars', (rating) => {
      if (!rating) return '';
      const fullStars = Math.floor(rating);
      const halfStar = rating % 1 >= 0.5 ? 1 : 0;
      const emptyStars = 5 - fullStars - halfStar;
      
      let stars = '★'.repeat(fullStars);
      if (halfStar) stars += '☆';
      stars += '☆'.repeat(emptyStars);
      
      return stars;
    });
  }

  /**
   * Generate PDF from template
   * @param {string} templateName - Name of the template to use
   * @param {Object} data - Data to populate in the template
   * @param {Object} options - PDF generation options
   * @returns {Promise<Buffer>} - PDF buffer
   */
  async generatePDF(templateName, data, options = {}) {
    try {
      const method = options.method || 'puppeteer'; // 'pdfkit' or 'puppeteer'
      
      if (method === 'pdfkit') {
        return await this.generateWithPDFKit(templateName, data, options);
      } else {
        return await this.generateWithPuppeteer(templateName, data, options);
      }
    } catch (error) {
      logger.error('PDF generation failed:', error);
      throw error;
    }
  }

  /**
   * Generate PDF using PDFKit (programmatic approach)
   * @private
   */
  async generateWithPDFKit(templateName, data, options) {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({
          size: options.size || 'A4',
          margins: options.margins || {
            top: 50,
            bottom: 50,
            left: 50,
            right: 50
          }
        });

        const chunks = [];
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));

        // Apply template-specific rendering
        switch (templateName) {
          case 'consultant-profile':
            this.renderConsultantProfile(doc, data);
            break;
          case 'performance-review':
            this.renderPerformanceReview(doc, data);
            break;
          case 'project-report':
            this.renderProjectReport(doc, data);
            break;
          case 'invoice':
            this.renderInvoice(doc, data);
            break;
          default:
            this.renderGenericDocument(doc, data);
        }

        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Generate PDF using Puppeteer (HTML to PDF)
   * @private
   */
  async generateWithPuppeteer(templateName, data, options) {
    const templatePath = path.join(this.templatesPath, `${templateName}.hbs`);
    
    if (!fs.existsSync(templatePath)) {
      throw new Error(`Template ${templateName} not found`);
    }

    // Read and compile template
    const templateContent = fs.readFileSync(templatePath, 'utf8');
    const template = handlebars.compile(templateContent);
    const html = template(data);

    // Add CSS
    const cssPath = path.join(this.templatesPath, 'styles.css');
    const css = fs.existsSync(cssPath) ? fs.readFileSync(cssPath, 'utf8') : '';
    const fullHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <style>${css}</style>
        </head>
        <body>
          ${html}
        </body>
      </html>
    `;

    // Launch puppeteer
    const browser = await puppeteer.launch({
      headless: 'new',
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    try {
      const page = await browser.newPage();
      await page.setContent(fullHtml, { waitUntil: 'networkidle0' });

      const pdfBuffer = await page.pdf({
        format: options.format || 'A4',
        printBackground: true,
        margin: options.margins || {
          top: '50px',
          right: '50px',
          bottom: '50px',
          left: '50px'
        },
        displayHeaderFooter: options.headerFooter !== false,
        headerTemplate: options.headerTemplate || this.getDefaultHeader(data),
        footerTemplate: options.footerTemplate || this.getDefaultFooter(data)
      });

      return pdfBuffer;
    } finally {
      await browser.close();
    }
  }

  /**
   * Render consultant profile using PDFKit
   * @private
   */
  renderConsultantProfile(doc, data) {
    const { personalInfo, professional, skills, certifications, experience, education, performance } = data;

    // Add company logo
    const logoPath = path.join(this.assetsPath, 'logo.png');
    if (fs.existsSync(logoPath)) {
      doc.image(logoPath, 50, 45, { width: 100 });
    }

    // Title
    doc.fontSize(24)
       .font('Helvetica-Bold')
       .text('Consultant Profile', 200, 50);

    // Personal Information Section
    doc.fontSize(18)
       .font('Helvetica-Bold')
       .text('Personal Information', 50, 150);

    doc.fontSize(12)
       .font('Helvetica')
       .text(`Name: ${personalInfo.name}`, 50, 180)
       .text(`Email: ${personalInfo.email}`, 50, 200)
       .text(`Phone: ${personalInfo.phone}`, 50, 220)
       .text(`Location: ${personalInfo.location}`, 50, 240);

    // Professional Summary
    doc.fontSize(18)
       .font('Helvetica-Bold')
       .text('Professional Summary', 50, 280);

    doc.fontSize(12)
       .font('Helvetica')
       .text(`Role: ${professional.role}`, 50, 310)
       .text(`Department: ${professional.department}`, 50, 330)
       .text(`Level: ${professional.level}`, 50, 350)
       .text(`Specializations: ${professional.specialization.join(', ')}`, 50, 370);

    // Skills Section
    if (skills && skills.length > 0) {
      doc.addPage();
      doc.fontSize(18)
         .font('Helvetica-Bold')
         .text('Skills & Competencies', 50, 50);

      let yPosition = 80;
      skills.forEach(skill => {
        doc.fontSize(12)
           .font('Helvetica-Bold')
           .text(`${skill.name} (${skill.category})`, 50, yPosition);
        
        doc.fontSize(10)
           .font('Helvetica')
           .text(`Level: ${skill.level}/5 | Experience: ${skill.yearsExperience} years`, 70, yPosition + 15);
        
        yPosition += 40;
        
        if (yPosition > 700) {
          doc.addPage();
          yPosition = 50;
        }
      });
    }

    // Certifications Section
    if (certifications && certifications.length > 0) {
      doc.addPage();
      doc.fontSize(18)
         .font('Helvetica-Bold')
         .text('Certifications', 50, 50);

      let yPosition = 80;
      certifications.forEach(cert => {
        doc.fontSize(12)
           .font('Helvetica-Bold')
           .text(cert.name, 50, yPosition);
        
        doc.fontSize(10)
           .font('Helvetica')
           .text(`${cert.issuingOrganization} | Issued: ${new Date(cert.issueDate).toLocaleDateString()}`, 70, yPosition + 15);
        
        if (cert.expiryDate) {
          doc.text(`Expires: ${new Date(cert.expiryDate).toLocaleDateString()}`, 70, yPosition + 30);
        }
        
        yPosition += 50;
        
        if (yPosition > 700) {
          doc.addPage();
          yPosition = 50;
        }
      });
    }

    // Experience Section
    if (experience && experience.previous && experience.previous.length > 0) {
      doc.addPage();
      doc.fontSize(18)
         .font('Helvetica-Bold')
         .text('Professional Experience', 50, 50);

      let yPosition = 80;
      experience.previous.forEach(exp => {
        doc.fontSize(14)
           .font('Helvetica-Bold')
           .text(`${exp.role} at ${exp.company}`, 50, yPosition);
        
        doc.fontSize(10)
           .font('Helvetica')
           .text(`${new Date(exp.startDate).toLocaleDateString()} - ${exp.endDate ? new Date(exp.endDate).toLocaleDateString() : 'Present'}`, 50, yPosition + 18);
        
        if (exp.description) {
          doc.fontSize(11)
             .text(exp.description, 50, yPosition + 35, { width: 500 });
          yPosition += 35 + (exp.description.length / 80) * 15;
        }
        
        yPosition += 40;
        
        if (yPosition > 650) {
          doc.addPage();
          yPosition = 50;
        }
      });
    }

    // Performance Summary
    if (performance) {
      doc.fontSize(18)
         .font('Helvetica-Bold')
         .text('Performance Rating', 50, yPosition + 30);

      doc.fontSize(12)
         .font('Helvetica')
         .text(`Current Rating: ${performance}/5`, 50, yPosition + 60);
    }
  }

  /**
   * Render performance review using PDFKit
   * @private
   */
  renderPerformanceReview(doc, data) {
    // Header
    doc.fontSize(20)
       .font('Helvetica-Bold')
       .text('Performance Review', 50, 50, { align: 'center' });

    doc.fontSize(14)
       .font('Helvetica')
       .text(`Period: ${data.period} ${data.year}`, 50, 90, { align: 'center' });

    // Employee Information
    doc.fontSize(12)
       .text(`Employee: ${data.employeeName}`, 50, 130)
       .text(`Role: ${data.role}`, 50, 150)
       .text(`Department: ${data.department}`, 50, 170)
       .text(`Review Date: ${new Date(data.reviewDate).toLocaleDateString()}`, 50, 190);

    // Ratings Section
    doc.fontSize(16)
       .font('Helvetica-Bold')
       .text('Performance Ratings', 50, 230);

    let yPosition = 260;
    Object.entries(data.ratings).forEach(([category, rating]) => {
      doc.fontSize(12)
         .font('Helvetica')
         .text(`${category.charAt(0).toUpperCase() + category.slice(1)}:`, 50, yPosition)
         .text(`${rating}/5`, 400, yPosition);
      yPosition += 25;
    });

    // Goals and Achievements
    if (data.achievements && data.achievements.length > 0) {
      doc.addPage();
      doc.fontSize(16)
         .font('Helvetica-Bold')
         .text('Key Achievements', 50, 50);

      yPosition = 80;
      data.achievements.forEach((achievement, index) => {
        doc.fontSize(12)
           .font('Helvetica')
           .text(`${index + 1}. ${achievement}`, 50, yPosition, { width: 500 });
        yPosition += 30;
      });
    }

    // Development Areas
    if (data.developmentAreas && data.developmentAreas.length > 0) {
      doc.fontSize(16)
         .font('Helvetica-Bold')
         .text('Development Areas', 50, yPosition + 30);

      yPosition += 60;
      data.developmentAreas.forEach((area, index) => {
        doc.fontSize(12)
           .font('Helvetica')
           .text(`${index + 1}. ${area}`, 50, yPosition, { width: 500 });
        yPosition += 30;
      });
    }
  }

  /**
   * Render project report using PDFKit
   * @private
   */
  renderProjectReport(doc, data) {
    // Title Page
    doc.fontSize(28)
       .font('Helvetica-Bold')
       .text(data.projectName, 50, 200, { align: 'center' });

    doc.fontSize(16)
       .font('Helvetica')
       .text('Project Status Report', 50, 250, { align: 'center' })
       .text(new Date().toLocaleDateString(), 50, 280, { align: 'center' });

    // Executive Summary
    doc.addPage();
    doc.fontSize(20)
       .font('Helvetica-Bold')
       .text('Executive Summary', 50, 50);

    doc.fontSize(12)
       .font('Helvetica')
       .text(`Project Status: ${data.status}`, 50, 90)
       .text(`Health Score: ${data.healthScore}/100`, 50, 110)
       .text(`Progress: ${data.progress}%`, 50, 130)
       .text(`Budget Utilization: ${data.budgetUtilization}%`, 50, 150);

    // Timeline
    doc.fontSize(16)
       .font('Helvetica-Bold')
       .text('Timeline', 50, 200);

    doc.fontSize(12)
       .font('Helvetica')
       .text(`Start Date: ${new Date(data.timeline.startDate).toLocaleDateString()}`, 50, 230)
       .text(`End Date: ${new Date(data.timeline.endDate).toLocaleDateString()}`, 50, 250)
       .text(`Days Remaining: ${data.timeline.daysRemaining}`, 50, 270);

    // Milestones
    if (data.milestones && data.milestones.upcoming && data.milestones.upcoming.length > 0) {
      doc.fontSize(16)
         .font('Helvetica-Bold')
         .text('Upcoming Milestones', 50, 320);

      let yPosition = 350;
      data.milestones.upcoming.forEach(milestone => {
        doc.fontSize(12)
           .font('Helvetica')
           .text(`${milestone.name}: ${new Date(milestone.date).toLocaleDateString()}`, 50, yPosition);
        yPosition += 25;
      });
    }

    // Risks and Issues
    doc.addPage();
    doc.fontSize(16)
       .font('Helvetica-Bold')
       .text('Risk Summary', 50, 50);

    doc.fontSize(12)
       .font('Helvetica')
       .text(`High Priority Risks: ${data.risks.high}`, 50, 80)
       .text(`Medium Priority Risks: ${data.risks.medium}`, 50, 100)
       .text(`Low Priority Risks: ${data.risks.low}`, 50, 120);

    doc.fontSize(16)
       .font('Helvetica-Bold')
       .text('Issue Summary', 50, 160);

    doc.fontSize(12)
       .font('Helvetica')
       .text(`Open Issues: ${data.issues.open}`, 50, 190)
       .text(`Critical Issues: ${data.issues.critical}`, 50, 210);
  }

  /**
   * Render invoice using PDFKit
   * @private
   */
  renderInvoice(doc, data) {
    // Invoice Header
    doc.fontSize(24)
       .font('Helvetica-Bold')
       .text('INVOICE', 400, 50);

    doc.fontSize(12)
       .font('Helvetica')
       .text(`Invoice #: ${data.invoiceNumber}`, 400, 90)
       .text(`Date: ${new Date(data.date).toLocaleDateString()}`, 400, 110)
       .text(`Due Date: ${new Date(data.dueDate).toLocaleDateString()}`, 400, 130);

    // Company Information
    doc.fontSize(14)
       .font('Helvetica-Bold')
       .text(data.company.name, 50, 50);

    doc.fontSize(10)
       .font('Helvetica')
       .text(data.company.address.street, 50, 70)
       .text(`${data.company.address.city}, ${data.company.address.state} ${data.company.address.zip}`, 50, 85)
       .text(`Phone: ${data.company.phone}`, 50, 100)
       .text(`Email: ${data.company.email}`, 50, 115);

    // Bill To
    doc.fontSize(14)
       .font('Helvetica-Bold')
       .text('Bill To:', 50, 160);

    doc.fontSize(10)
       .font('Helvetica')
       .text(data.client.name, 50, 180)
       .text(data.client.address.street, 50, 195)
       .text(`${data.client.address.city}, ${data.client.address.state} ${data.client.address.zip}`, 50, 210);

    // Line Items Table
    doc.fontSize(12)
       .font('Helvetica-Bold');

    // Table headers
    doc.text('Description', 50, 260)
       .text('Hours', 300, 260)
       .text('Rate', 380, 260)
       .text('Amount', 460, 260);

    // Draw line
    doc.moveTo(50, 280)
       .lineTo(550, 280)
       .stroke();

    // Line items
    let yPosition = 300;
    let subtotal = 0;

    data.lineItems.forEach(item => {
      doc.fontSize(10)
         .font('Helvetica')
         .text(item.description, 50, yPosition, { width: 240 })
         .text(item.hours.toString(), 300, yPosition)
         .text(`$${item.rate.toFixed(2)}`, 380, yPosition)
         .text(`$${(item.hours * item.rate).toFixed(2)}`, 460, yPosition);
      
      subtotal += item.hours * item.rate;
      yPosition += 30;
    });

    // Totals
    doc.moveTo(50, yPosition)
       .lineTo(550, yPosition)
       .stroke();

    yPosition += 20;

    doc.fontSize(12)
       .font('Helvetica-Bold')
       .text('Subtotal:', 380, yPosition)
       .text(`$${subtotal.toFixed(2)}`, 460, yPosition);

    if (data.tax) {
      yPosition += 20;
      const taxAmount = subtotal * data.tax.rate;
      doc.text(`Tax (${data.tax.rate * 100}%):`, 380, yPosition)
         .text(`$${taxAmount.toFixed(2)}`, 460, yPosition);
      subtotal += taxAmount;
    }

    yPosition += 25;
    doc.fontSize(14)
       .text('Total:', 380, yPosition)
       .text(`$${subtotal.toFixed(2)}`, 460, yPosition);

    // Payment Terms
    if (data.terms) {
      doc.fontSize(10)
         .font('Helvetica')
         .text('Payment Terms:', 50, yPosition + 60)
         .text(data.terms, 50, yPosition + 75, { width: 300 });
    }
  }

  /**
   * Render generic document
   * @private
   */
  renderGenericDocument(doc, data) {
    // Title
    if (data.title) {
      doc.fontSize(24)
         .font('Helvetica-Bold')
         .text(data.title, 50, 50, { align: 'center' });
    }

    // Subtitle
    if (data.subtitle) {
      doc.fontSize(16)
         .font('Helvetica')
         .text(data.subtitle, 50, 90, { align: 'center' });
    }

    // Content sections
    let yPosition = 150;
    
    if (data.sections) {
      data.sections.forEach(section => {
        if (yPosition > 650) {
          doc.addPage();
          yPosition = 50;
        }

        // Section title
        if (section.title) {
          doc.fontSize(18)
             .font('Helvetica-Bold')
             .text(section.title, 50, yPosition);
          yPosition += 30;
        }

        // Section content
        if (section.content) {
          doc.fontSize(12)
             .font('Helvetica')
             .text(section.content, 50, yPosition, { width: 500 });
          yPosition += (section.content.length / 80) * 15 + 30;
        }

        // Section list items
        if (section.items && Array.isArray(section.items)) {
          section.items.forEach(item => {
            doc.fontSize(11)
               .font('Helvetica')
               .text(`• ${item}`, 70, yPosition, { width: 480 });
            yPosition += 25;
          });
        }

        yPosition += 20;
      });
    }
  }

  /**
   * Get default header template
   * @private
   */
  getDefaultHeader(data) {
    return `
      <div style="font-size: 10px; color: #666; width: 100%; text-align: center; padding-top: 20px;">
        ${data.headerText || ''}
      </div>
    `;
  }

  /**
   * Get default footer template
   * @private
   */
  getDefaultFooter(data) {
    return `
      <div style="font-size: 10px; color: #666; width: 100%; text-align: center; padding-bottom: 20px;">
        <span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
        ${data.footerText ? ` | ${data.footerText}` : ''}
      </div>
    `;
  }
}

// Create singleton instance
const pdfGenerator = new PDFGenerator();

/**
 * Export generatePDF function
 */
module.exports = {
  generatePDF: (templateName, data, options) => pdfGenerator.generatePDF(templateName, data, options),
  PDFGenerator
};