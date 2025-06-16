// /server/shared/services/email-service.js

/**
 * @file Email Service
 * @description Comprehensive email sending service with multiple providers
 * @version 1.0.0
 */

const nodemailer = require('nodemailer');
const sgMail = require('@sendgrid/mail');
const ses = require('@aws-sdk/client-ses');
const mailgun = require('mailgun-js');
const logger = require('../utils/logger');
const config = require('../config');
const emailHelper = require('../utils/helpers/email-helper');
const queueHelper = require('../utils/helpers/queue-helper');
const { AppError } = require('../utils/app-error');

/**
 * Email Service Class
 */
class EmailService {
  constructor() {
    this.provider = config.email.provider || 'smtp';
    this.from = config.email.defaultFrom;
    this.replyTo = config.email.replyTo;
    this.templates = new Map();
    
    this.initializeProvider();
  }
  
  /**
   * Initialize email provider
   */
  initializeProvider() {
    try {
      switch (this.provider) {
        case 'sendgrid':
          this.initializeSendGrid();
          break;
        case 'ses':
          this.initializeSES();
          break;
        case 'mailgun':
          this.initializeMailgun();
          break;
        case 'smtp':
        default:
          this.initializeSMTP();
      }
      
      logger.info(`Email service initialized with provider: ${this.provider}`);
    } catch (error) {
      logger.error('Failed to initialize email service:', error);
      throw new AppError('Email service initialization failed', 500);
    }
  }
  
  /**
   * Initialize SendGrid
   */
  initializeSendGrid() {
    if (!config.email.sendgrid.apiKey) {
      throw new Error('SendGrid API key not configured');
    }
    
    sgMail.setApiKey(config.email.sendgrid.apiKey);
    this.sendgridClient = sgMail;
  }
  
  /**
   * Initialize AWS SES
   */
  initializeSES() {
    const { defaultProvider } = require('@aws-sdk/credential-provider-node');
    
    this.sesClient = new ses.SES({
      region: config.email.ses.region || 'us-east-1',
      credentials: defaultProvider()
    });
  }
  
  /**
   * Initialize Mailgun
   */
  initializeMailgun() {
    if (!config.email.mailgun.apiKey || !config.email.mailgun.domain) {
      throw new Error('Mailgun configuration incomplete');
    }
    
    this.mailgunClient = mailgun({
      apiKey: config.email.mailgun.apiKey,
      domain: config.email.mailgun.domain,
      host: config.email.mailgun.host || 'api.mailgun.net'
    });
  }
  
  /**
   * Initialize SMTP
   */
  initializeSMTP() {
    this.transporter = nodemailer.createTransporter({
      host: config.email.smtp.host,
      port: config.email.smtp.port,
      secure: config.email.smtp.secure,
      auth: {
        user: config.email.smtp.user,
        pass: config.email.smtp.pass
      },
      pool: true,
      maxConnections: config.email.smtp.maxConnections || 5,
      maxMessages: config.email.smtp.maxMessages || 100
    });
    
    // Verify connection
    this.transporter.verify((error) => {
      if (error) {
        logger.error('SMTP connection verification failed:', error);
      } else {
        logger.info('SMTP server ready to send emails');
      }
    });
  }
  
  /**
   * Send email using configured provider
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async send(options) {
    try {
      // Prepare email data
      const emailData = this.prepareEmailData(options);
      
      // Validate email data
      this.validateEmailData(emailData);
      
      // Send based on provider
      let result;
      switch (this.provider) {
        case 'sendgrid':
          result = await this.sendViaSendGrid(emailData);
          break;
        case 'ses':
          result = await this.sendViaSES(emailData);
          break;
        case 'mailgun':
          result = await this.sendViaMailgun(emailData);
          break;
        case 'smtp':
        default:
          result = await this.sendViaSMTP(emailData);
      }
      
      // Log success
      this.logEmailSent(emailData, result);
      
      return result;
    } catch (error) {
      logger.error('Email send failed:', error);
      throw new AppError('Failed to send email', 500);
    }
  }
  
  /**
   * Send via SendGrid
   */
  async sendViaSendGrid(emailData) {
    const msg = {
      to: emailData.to,
      from: emailData.from,
      subject: emailData.subject,
      text: emailData.text,
      html: emailData.html,
      ...(emailData.cc && { cc: emailData.cc }),
      ...(emailData.bcc && { bcc: emailData.bcc }),
      ...(emailData.replyTo && { replyTo: emailData.replyTo }),
      ...(emailData.attachments && {
        attachments: emailData.attachments.map(att => ({
          content: att.content.toString('base64'),
          filename: att.filename,
          type: att.contentType,
          disposition: att.disposition || 'attachment'
        }))
      }),
      ...(emailData.templateId && { templateId: emailData.templateId }),
      ...(emailData.dynamicTemplateData && { 
        dynamicTemplateData: emailData.dynamicTemplateData 
      }),
      trackingSettings: {
        clickTracking: { enable: config.email.tracking.clicks },
        openTracking: { enable: config.email.tracking.opens }
      }
    };
    
    const [response] = await this.sendgridClient.send(msg);
    
    return {
      messageId: response.headers['x-message-id'],
      status: response.statusCode,
      provider: 'sendgrid'
    };
  }
  
  /**
   * Send via AWS SES
   */
  async sendViaSES(emailData) {
    const params = {
      Source: emailData.from,
      Destination: {
        ToAddresses: Array.isArray(emailData.to) ? emailData.to : [emailData.to],
        ...(emailData.cc && { 
          CcAddresses: Array.isArray(emailData.cc) ? emailData.cc : [emailData.cc] 
        }),
        ...(emailData.bcc && { 
          BccAddresses: Array.isArray(emailData.bcc) ? emailData.bcc : [emailData.bcc] 
        })
      },
      Message: {
        Subject: {
          Data: emailData.subject,
          Charset: 'UTF-8'
        },
        Body: {
          ...(emailData.text && {
            Text: {
              Data: emailData.text,
              Charset: 'UTF-8'
            }
          }),
          ...(emailData.html && {
            Html: {
              Data: emailData.html,
              Charset: 'UTF-8'
            }
          })
        }
      },
      ...(emailData.replyTo && {
        ReplyToAddresses: Array.isArray(emailData.replyTo) ? 
          emailData.replyTo : [emailData.replyTo]
      })
    };
    
    const command = new ses.SendEmailCommand(params);
    const response = await this.sesClient.send(command);
    
    return {
      messageId: response.MessageId,
      status: 200,
      provider: 'ses'
    };
  }
  
  /**
   * Send via Mailgun
   */
  async sendViaMailgun(emailData) {
    const data = {
      from: emailData.from,
      to: Array.isArray(emailData.to) ? emailData.to.join(',') : emailData.to,
      subject: emailData.subject,
      text: emailData.text,
      html: emailData.html,
      ...(emailData.cc && { cc: Array.isArray(emailData.cc) ? emailData.cc.join(',') : emailData.cc }),
      ...(emailData.bcc && { bcc: Array.isArray(emailData.bcc) ? emailData.bcc.join(',') : emailData.bcc }),
      ...(emailData.replyTo && { 'h:Reply-To': emailData.replyTo }),
      ...(emailData.attachments && { attachment: emailData.attachments }),
      ...(config.email.tracking.opens && { 'o:tracking-opens': 'yes' }),
      ...(config.email.tracking.clicks && { 'o:tracking-clicks': 'yes' })
    };
    
    const response = await new Promise((resolve, reject) => {
      this.mailgunClient.messages().send(data, (error, body) => {
        if (error) reject(error);
        else resolve(body);
      });
    });
    
    return {
      messageId: response.id,
      status: 200,
      provider: 'mailgun'
    };
  }
  
  /**
   * Send via SMTP
   */
  async sendViaSMTP(emailData) {
    const mailOptions = {
      from: emailData.from,
      to: emailData.to,
      subject: emailData.subject,
      text: emailData.text,
      html: emailData.html,
      ...(emailData.cc && { cc: emailData.cc }),
      ...(emailData.bcc && { bcc: emailData.bcc }),
      ...(emailData.replyTo && { replyTo: emailData.replyTo }),
      ...(emailData.attachments && { attachments: emailData.attachments }),
      headers: {
        'X-Mailer': 'Insightserenity Platform',
        'X-Priority': emailData.priority || '3',
        ...(emailData.headers || {})
      }
    };
    
    const result = await this.transporter.sendMail(mailOptions);
    
    return {
      messageId: result.messageId,
      status: 250,
      provider: 'smtp',
      accepted: result.accepted,
      rejected: result.rejected,
      preview: nodemailer.getTestMessageUrl(result)
    };
  }
  
  /**
   * Send templated email
   * @param {string} templateName - Template name
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async sendTemplate(templateName, options) {
    try {
      // If using SendGrid dynamic templates
      if (this.provider === 'sendgrid' && config.email.sendgrid.templates[templateName]) {
        return this.send({
          ...options,
          templateId: config.email.sendgrid.templates[templateName],
          dynamicTemplateData: options.data
        });
      }
      
      // Otherwise use local templates
      return emailHelper.sendTemplate(templateName, options);
    } catch (error) {
      logger.error(`Failed to send templated email ${templateName}:`, error);
      throw error;
    }
  }
  
  /**
   * Send bulk emails
   * @param {Array} recipients - Array of recipient configurations
   * @param {Object} commonOptions - Common email options
   * @returns {Promise<Object>} Bulk send results
   */
  async sendBulk(recipients, commonOptions) {
    const batchSize = config.email.bulkBatchSize || 50;
    const results = {
      successful: 0,
      failed: 0,
      errors: []
    };
    
    // Process in batches
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
      // Queue batch for processing
      const jobs = batch.map(recipient => {
        const emailOptions = {
          ...commonOptions,
          to: recipient.email,
          data: {
            ...commonOptions.data,
            ...recipient.data
          }
        };
        
        return queueHelper.addJob('email', 'send-email', emailOptions);
      });
      
      // Wait for batch to complete
      const batchResults = await Promise.allSettled(jobs);
      
      batchResults.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          results.successful++;
        } else {
          results.failed++;
          results.errors.push({
            recipient: batch[index].email,
            error: result.reason.message
          });
        }
      });
      
      // Rate limiting between batches
      if (i + batchSize < recipients.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    logger.info('Bulk email send completed', results);
    return results;
  }
  
  /**
   * Queue email for sending
   * @param {Object} options - Email options
   * @returns {Promise<string>} Job ID
   */
  async queue(options) {
    return queueHelper.addJob('email', 'send-email', options, {
      priority: options.priority || 3,
      delay: options.delay || 0,
      attempts: options.attempts || 3
    });
  }
  
  /**
   * Prepare email data
   */
  prepareEmailData(options) {
    return {
      from: options.from || this.from,
      to: options.to,
      cc: options.cc,
      bcc: options.bcc,
      replyTo: options.replyTo || this.replyTo,
      subject: options.subject,
      text: options.text,
      html: options.html,
      attachments: options.attachments,
      headers: options.headers,
      priority: options.priority,
      templateId: options.templateId,
      dynamicTemplateData: options.data,
      metadata: {
        userId: options.userId,
        organizationId: options.organizationId,
        category: options.category,
        tags: options.tags
      }
    };
  }
  
  /**
   * Validate email data
   */
  validateEmailData(emailData) {
    if (!emailData.to) {
      throw new AppError('Email recipient is required', 400);
    }
    
    if (!emailData.subject) {
      throw new AppError('Email subject is required', 400);
    }
    
    if (!emailData.text && !emailData.html && !emailData.templateId) {
      throw new AppError('Email content is required', 400);
    }
    
    // Validate email addresses
    const validateEmail = (email) => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailRegex.test(email);
    };
    
    const emails = [
      ...(Array.isArray(emailData.to) ? emailData.to : [emailData.to]),
      ...(emailData.cc ? (Array.isArray(emailData.cc) ? emailData.cc : [emailData.cc]) : []),
      ...(emailData.bcc ? (Array.isArray(emailData.bcc) ? emailData.bcc : [emailData.bcc]) : [])
    ];
    
    const invalidEmails = emails.filter(email => !validateEmail(email));
    if (invalidEmails.length > 0) {
      throw new AppError(`Invalid email addresses: ${invalidEmails.join(', ')}`, 400);
    }
  }
  
  /**
   * Log email sent
   */
  logEmailSent(emailData, result) {
    logger.info('Email sent successfully', {
      messageId: result.messageId,
      provider: result.provider,
      to: emailData.to,
      subject: emailData.subject,
      category: emailData.metadata?.category,
      userId: emailData.metadata?.userId,
      organizationId: emailData.metadata?.organizationId
    });
  }
  
  /**
   * Email templates
   */
  async sendWelcomeEmail(user) {
    return this.sendTemplate('welcome', {
      to: user.email,
      subject: 'Welcome to Insightserenity',
      data: {
        name: user.firstName,
        email: user.email,
        activationUrl: `${config.app.url}/activate/${user.activationToken}`
      },
      userId: user.id,
      category: 'account'
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
      },
      userId: user.id,
      category: 'security',
      priority: 1
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
        message: invitation.message,
        acceptUrl: `${config.app.url}/invitations/${invitation.token}`,
        expiresIn: `${invitation.expiresInDays} days`
      },
      organizationId: invitation.organizationId,
      category: 'invitation'
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
        actionText: notification.actionText || 'View Details',
        type: notification.type
      },
      userId: notification.userId,
      organizationId: notification.organizationId,
      category: 'notification'
    });
  }
  
  async sendReportEmail(report) {
    return this.sendTemplate('report', {
      to: report.recipient,
      subject: `${report.type} Report - ${report.period}`,
      data: {
        reportType: report.type,
        period: report.period,
        summary: report.summary,
        downloadUrl: report.downloadUrl,
        expiresIn: '7 days'
      },
      attachments: report.attachments,
      userId: report.userId,
      organizationId: report.organizationId,
      category: 'report'
    });
  }
}

// Create singleton instance
const emailService = new EmailService();

module.exports = emailService;