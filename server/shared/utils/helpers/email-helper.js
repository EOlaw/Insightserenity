// /server/shared/utils/helpers/email-helper.js

/**
 * @file Email Helper
 * @description Email sending utilities with template support
 * @version 1.0.0
 */

const nodemailer = require('nodemailer');
const handlebars = require('handlebars');

const fs = require('fs').promises;
const path = require('path');

const juice = require('juice');

const config = require('../../config');
const { AppError } = require('../app-error');
const logger = require('../logger');

/**
 * Email Helper Class
 */
class EmailHelper {
  constructor() {
    this.transporter = null;
    this.templates = new Map();
    this.defaultFrom = config.email.defaultFrom || 'noreply@insightserenity.com';
    this.templateDir = path.join(__dirname, '../../../../templates/emails');
    this.initializeTransporter();
    this.registerHelpers();
  }
  
  /**
   * Initialize email transporter
   */
  initializeTransporter() {
    try {
      if (process.env.NODE_ENV === 'test') {
        // Use test account for testing
        this.transporter = nodemailer.createTransport({
          host: 'smtp.ethereal.email',
          port: 587,
          auth: {
            user: 'test@ethereal.email',
            pass: 'test'
          }
        });
      } else if (config.email.service === 'sendgrid') {
        // SendGrid configuration
        this.transporter = nodemailer.createTransporter({
          host: 'smtp.sendgrid.net',
          port: 587,
          auth: {
            user: 'apikey',
            pass: config.email.sendgridApiKey
          }
        });
      } else if (config.email.service === 'ses') {
        // AWS SES configuration
        const aws = require('@aws-sdk/client-ses');
        const { defaultProvider } = require('@aws-sdk/credential-provider-node');
        
        this.transporter = nodemailer.createTransporter({
          SES: {
            ses: new aws.SES({
              region: config.email.awsRegion || 'us-east-1',
              credentials: defaultProvider()
            }),
            aws
          }
        });
      } else {
        // SMTP configuration
        this.transporter = nodemailer.createTransporter({
          host: config.email.smtp.host,
          port: config.email.smtp.port,
          secure: config.email.smtp.secure,
          auth: {
            user: config.email.smtp.user,
            pass: config.email.smtp.pass
          }
        });
      }
      
      // Verify transporter
      this.transporter.verify((error) => {
        if (error) {
          logger.error('Email transporter verification failed:', error);
        } else {
          logger.info('Email transporter ready');
        }
      });
    } catch (error) {
      logger.error('Failed to initialize email transporter:', error);
    }
  }
  
  /**
   * Register Handlebars helpers
   */
  registerHelpers() {
    // Date formatting helper
    handlebars.registerHelper('formatDate', (date, format) => {
      const moment = require('moment');
      return moment(date).format(format || 'MMMM D, YYYY');
    });
    
    // Currency formatting helper
    handlebars.registerHelper('formatCurrency', (amount, currency = 'USD') => {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency
      }).format(amount);
    });
    
    // Conditional helper
    handlebars.registerHelper('ifEquals', function(arg1, arg2, options) {
      return arg1 === arg2 ? options.fn(this) : options.inverse(this);
    });
    
    // URL helper
    handlebars.registerHelper('url', (path) => {
      const baseUrl = config.app.url || 'https://insightserenity.com';
      return `${baseUrl}${path}`;
    });
  }
  
  /**
   * Load email template
   * @param {string} templateName - Template name
   * @returns {Promise<Function>} Compiled template
   */
  async loadTemplate(templateName) {
    // Check cache
    if (this.templates.has(templateName)) {
      return this.templates.get(templateName);
    }
    
    try {
      // Load template file
      const templatePath = path.join(this.templateDir, `${templateName}.hbs`);
      const templateContent = await fs.readFile(templatePath, 'utf-8');
      
      // Load layout if exists
      let layoutContent = '';
      try {
        const layoutPath = path.join(this.templateDir, 'layouts', 'default.hbs');
        layoutContent = await fs.readFile(layoutPath, 'utf-8');
      } catch (error) {
        // No layout file, use template as is
      }
      
      // Compile template
      let compiledTemplate;
      if (layoutContent) {
        handlebars.registerPartial('content', templateContent);
        compiledTemplate = handlebars.compile(layoutContent);
      } else {
        compiledTemplate = handlebars.compile(templateContent);
      }
      
      // Cache compiled template
      this.templates.set(templateName, compiledTemplate);
      
      return compiledTemplate;
    } catch (error) {
      logger.error(`Failed to load email template ${templateName}:`, error);
      throw new AppError(`Email template ${templateName} not found`, 500);
    }
  }
  
  /**
   * Send email
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async send(options) {
    try {
      const {
        to,
        cc,
        bcc,
        from = this.defaultFrom,
        subject,
        text,
        html,
        attachments,
        replyTo,
        headers = {}
      } = options;
      
      // Validate recipients
      if (!to) {
        throw new AppError('Email recipient is required', 400);
      }
      
      // Prepare email options
      const mailOptions = {
        from,
        to: Array.isArray(to) ? to.join(', ') : to,
        subject,
        text,
        html,
        attachments,
        replyTo,
        headers: {
          'X-Mailer': 'Insightserenity Platform',
          'X-Priority': '3',
          ...headers
        }
      };
      
      if (cc) mailOptions.cc = Array.isArray(cc) ? cc.join(', ') : cc;
      if (bcc) mailOptions.bcc = Array.isArray(bcc) ? bcc.join(', ') : bcc;
      
      // Add tracking pixel if enabled
      if (config.email.tracking && html) {
        const trackingId = this.generateTrackingId();
        const trackingPixel = `<img src="${config.app.url}/api/email/track/${trackingId}" width="1" height="1" />`;
        mailOptions.html = html.replace('</body>', `${trackingPixel}</body>`);
      }
      
      // Send email
      const result = await this.transporter.sendMail(mailOptions);
      
      // Log email sent
      logger.info('Email sent successfully', {
        messageId: result.messageId,
        to: mailOptions.to,
        subject: mailOptions.subject
      });
      
      return {
        success: true,
        messageId: result.messageId,
        preview: nodemailer.getTestMessageUrl(result)
      };
    } catch (error) {
      logger.error('Failed to send email:', error);
      throw new AppError('Failed to send email', 500);
    }
  }
  
  /**
   * Send templated email
   * @param {string} templateName - Template name
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async sendTemplate(templateName, options) {
    try {
      const { data = {}, ...emailOptions } = options;
      
      // Load and compile template
      const template = await this.loadTemplate(templateName);
      
      // Add default data
      const templateData = {
        appName: config.app.name,
        appUrl: config.app.url,
        currentYear: new Date().getFullYear(),
        ...data
      };
      
      // Generate HTML
      let html = template(templateData);
      
      // Inline CSS
      html = juice(html);
      
      // Generate text version
      const text = this.htmlToText(html);
      
      // Send email
      return this.send({
        ...emailOptions,
        html,
        text
      });
    } catch (error) {
      logger.error(`Failed to send templated email ${templateName}:`, error);
      throw error;
    }
  }
  
  /**
   * Send bulk emails
   * @param {Array} recipients - Array of recipient options
   * @param {Object} options - Common email options
   * @returns {Promise<Array>} Send results
   */
  async sendBulk(recipients, options) {
    const results = [];
    const batchSize = config.email.bulkBatchSize || 50;
    
    // Process in batches
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      const batchResults = await Promise.allSettled(
        batch.map(recipient => {
          const emailOptions = {
            ...options,
            to: recipient.email || recipient,
            data: {
              ...options.data,
              ...(recipient.data || {})
            }
          };
          
          if (options.template) {
            return this.sendTemplate(options.template, emailOptions);
          }
          return this.send(emailOptions);
        })
      );
      
      results.push(...batchResults);
      
      // Rate limiting delay
      if (i + batchSize < recipients.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    // Log results
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;
    
    logger.info('Bulk email send completed', {
      total: recipients.length,
      successful,
      failed
    });
    
    return results;
  }
  
  /**
   * Queue email for sending
   * @param {Object} options - Email options
   * @returns {Promise<string>} Job ID
   */
  async queue(options) {
    const QueueHelper = require('./queue-helper');
    const emailQueue = QueueHelper.getQueue('email');
    
    const job = await emailQueue.add('send-email', options, {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000
      },
      removeOnComplete: true,
      removeOnFail: false
    });
    
    return job.id;
  }
  
  /**
   * Convert HTML to text
   * @param {string} html - HTML content
   * @returns {string} Text content
   */
  htmlToText(html) {
    const htmlToText = require('html-to-text');
    
    return htmlToText.convert(html, {
      wordwrap: 130,
      selectors: [
        { selector: 'a', options: { hideLinkHrefIfSameAsText: true } },
        { selector: 'img', format: 'skip' }
      ]
    });
  }
  
  /**
   * Generate tracking ID
   * @returns {string} Tracking ID
   */
  generateTrackingId() {
    const crypto = require('crypto');
    return crypto.randomBytes(16).toString('hex');
  }
  
  /**
   * Validate email address
   * @param {string} email - Email address
   * @returns {boolean} Is valid
   */
  static isValidEmail(email) {
    const validator = require('validator');
    return validator.isEmail(email);
  }
  
  /**
   * Send common emails
   */
  async sendWelcomeEmail(user) {
    return this.sendTemplate('welcome', {
      to: user.email,
      subject: 'Welcome to Insightserenity',
      data: {
        name: user.firstName,
        activationUrl: `${config.app.url}/activate/${user.activationToken}`
      }
    });
  }
  
  async sendPasswordResetEmail(user, resetToken) {
    return this.sendTemplate('password-reset', {
      to: user.email,
      subject: 'Reset Your Password',
      data: {
        name: user.firstName,
        resetUrl: `${config.app.url}/reset-password/${resetToken}`,
        expiresIn: '2 hours'
      }
    });
  }
  
  async sendInvitationEmail(invitation) {
    return this.sendTemplate('invitation', {
      to: invitation.email,
      subject: `You're invited to join ${invitation.organizationName}`,
      data: {
        organizationName: invitation.organizationName,
        inviterName: invitation.inviterName,
        role: invitation.role,
        acceptUrl: `${config.app.url}/accept-invitation/${invitation.token}`,
        expiresIn: `${invitation.expiresInDays} days`
      }
    });
  }
  
  async sendNotificationEmail(notification) {
    return this.sendTemplate('notification', {
      to: notification.recipient,
      subject: notification.subject,
      data: {
        title: notification.title,
        message: notification.message,
        actionUrl: notification.actionUrl,
        actionText: notification.actionText || 'View Details'
      }
    });
  }
}

// Create singleton instance
const emailHelper = new EmailHelper();

module.exports = emailHelper;