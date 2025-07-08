// /server/shared/services/email-service.js

/**
 * @file Email Service
 * @description Comprehensive email sending service with multiple providers and enhanced security
 * @version 1.2.0
 * @updated Fixed configuration issues and Gmail SMTP integration
 */

const nodemailer = require('nodemailer');
const { AppError } = require('../utils/app-error');
const logger = require('../utils/logger');

// Safe imports with fallbacks for optional dependencies
let sgMail = null;
let ses = null;
let Mailgun = null;
let config = null;
let emailHelper = null;
let queueHelper = null;

try {
  sgMail = require('@sendgrid/mail');
} catch (error) {
  logger.debug('SendGrid package not available', { package: '@sendgrid/mail' });
}

try {
  ses = require('@aws-sdk/client-ses');
} catch (error) {
  logger.debug('AWS SES package not available', { package: '@aws-sdk/client-ses' });
}

try {
  Mailgun = require('mailgun.js');
} catch (error) {
  logger.debug('Mailgun package not available', { package: 'mailgun.js' });
}

try {
  config = require('../config/config');
} catch (error) {
  logger.warn('Config not available, using defaults');
  config = {
    email: {
      provider: 'smtp',
      from: 'noreply@localhost',
      smtp: {
        host: 'localhost',
        port: 587,
        secure: false,
        user: '',
        pass: ''
      }
    },
    app: {
      url: 'http://localhost:3000',
      env: 'development'
    }
  };
}

try {
  emailHelper = require('../utils/helpers/email-helper');
} catch (error) {
  logger.debug('Email helper not available');
  emailHelper = { sendTemplate: () => Promise.reject(new Error('Email helper not configured')) };
}

try {
  queueHelper = require('../utils/helpers/queue-helper');
} catch (error) {
  logger.debug('Queue helper not available');
  queueHelper = { addJob: () => Promise.reject(new Error('Queue helper not configured')) };
}

/**
 * Email Service Class
 */
class EmailService {
  constructor() {
    this.provider = this.determineAvailableProvider();
    // Fixed: Use correct config path for email from address
    this.from = config.email?.from || config.email?.defaultFrom || 'noreply@insightserenity.com';
    this.replyTo = config.email?.replyTo;
    this.templates = new Map();
    
    this.initializeProvider();
  }
  
  /**
   * Determine which email provider is available and configured
   */
  determineAvailableProvider() {
    const requestedProvider = config.email?.provider || 'smtp';
    
    switch (requestedProvider) {
      case 'sendgrid':
        if (sgMail && config.email?.sendgrid?.apiKey) {
          return 'sendgrid';
        }
        logger.warn('SendGrid requested but not available, falling back to SMTP');
        break;
      case 'ses':
        if (ses && config.email?.ses) {
          return 'ses';
        }
        logger.warn('AWS SES requested but not available, falling back to SMTP');
        break;
      case 'mailgun':
        if (Mailgun && config.email?.mailgun?.apiKey) {
          return 'mailgun';
        }
        logger.warn('Mailgun requested but not available, falling back to SMTP');
        break;
    }
    
    return 'smtp';
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
      
      logger.info('Email service initialized successfully', { 
        provider: this.provider,
        from: this.from
      });
    } catch (error) {
      logger.error('Failed to initialize email service', { error: error.message });
      
      if (this.provider !== 'smtp') {
        logger.warn('Falling back to SMTP provider');
        this.provider = 'smtp';
        this.initializeSMTP();
      } else {
        throw new AppError('Email service initialization failed completely', 500);
      }
    }
  }
  
  /**
   * Initialize SendGrid
   */
  initializeSendGrid() {
    if (!sgMail) {
      throw new Error('SendGrid package not installed');
    }
    
    if (!config.email?.sendgrid?.apiKey) {
      throw new Error('SendGrid API key not configured');
    }
    
    sgMail.setApiKey(config.email.sendgrid.apiKey);
    this.sendgridClient = sgMail;
    logger.info('SendGrid initialized successfully');
  }
  
  /**
   * Initialize AWS SES
   */
  initializeSES() {
    if (!ses) {
      throw new Error('AWS SES package not installed');
    }
    
    const { defaultProvider } = require('@aws-sdk/credential-provider-node');
    
    this.sesClient = new ses.SES({
      region: config.email?.ses?.region || 'us-east-1',
      credentials: defaultProvider()
    });
    
    logger.info('AWS SES initialized successfully');
  }
  
  /**
   * Initialize Mailgun with the secure mailgun.js package
   */
  initializeMailgun() {
    if (!Mailgun) {
      throw new Error('Mailgun package not installed. Install with: npm install mailgun.js');
    }
    
    if (!config.email?.mailgun?.apiKey || !config.email?.mailgun?.domain) {
      throw new Error('Mailgun configuration incomplete - API key and domain required');
    }
    
    const mailgun = new Mailgun({});
    
    this.mailgunClient = mailgun.client({
      username: 'api',
      key: config.email.mailgun.apiKey,
      url: config.email.mailgun.host || 'https://api.mailgun.net'
    });
    
    this.mailgunDomain = config.email.mailgun.domain;
    
    logger.info('Mailgun initialized successfully', { 
      domain: this.mailgunDomain,
      host: config.email.mailgun.host || 'https://api.mailgun.net'
    });
  }
  
  /**
   * Initialize SMTP with enhanced Gmail compatibility
   */
  initializeSMTP() {
    const smtpConfig = config.email?.smtp || {
      host: 'localhost',
      port: 587,
      secure: false,
      user: '',
      pass: ''
    };
    
    // Validate SMTP credentials
    if (!smtpConfig.user || !smtpConfig.pass) {
      logger.warn('SMTP credentials not configured - email sending will fail', {
        hasUser: !!smtpConfig.user,
        hasPass: !!smtpConfig.pass,
        host: smtpConfig.host
      });
    }
    
    // Enhanced configuration for Gmail compatibility
    const transporterConfig = {
      host: smtpConfig.host,
      port: smtpConfig.port,
      secure: smtpConfig.secure, // true for 465, false for other ports
      auth: smtpConfig.user && smtpConfig.pass ? {
        user: smtpConfig.user,
        pass: smtpConfig.pass
      } : undefined,
      pool: true,
      maxConnections: smtpConfig.maxConnections || 5,
      maxMessages: smtpConfig.maxMessages || 100,
      // Enhanced TLS configuration for Gmail
      tls: {
        rejectUnauthorized: smtpConfig.tls?.rejectUnauthorized !== false,
        ciphers: 'SSLv3'
      },
      // Additional options for better compatibility
      connectionTimeout: 60000, // 60 seconds
      greetingTimeout: 30000,    // 30 seconds
      socketTimeout: 60000,      // 60 seconds
      // Debug options for development
      debug: config.app?.env === 'development',
      logger: config.app?.env === 'development'
    };

    this.transporter = nodemailer.createTransport(transporterConfig);
    
    // Always verify connection for better debugging
    this.transporter.verify((error) => {
      if (error) {
        logger.error('SMTP connection verification failed', { 
          error: error.message,
          code: error.code,
          command: error.command,
          host: smtpConfig.host,
          port: smtpConfig.port,
          user: smtpConfig.user ? `${smtpConfig.user.substring(0, 3)}***` : 'not configured',
          secure: smtpConfig.secure
        });
      } else {
        logger.info('SMTP server ready to send emails', {
          host: smtpConfig.host,
          port: smtpConfig.port,
          secure: smtpConfig.secure,
          from: this.from
        });
      }
    });
    
    logger.info('SMTP initialized successfully', { 
      host: smtpConfig.host, 
      port: smtpConfig.port,
      secure: smtpConfig.secure,
      from: this.from
    });
  }
  
  /**
   * Send email using configured provider with enhanced error handling
   * @param {Object} options - Email options
   * @returns {Promise<Object>} Send result
   */
  async send(options) {
    try {
      // Validate transporter exists
      if (this.provider === 'smtp' && !this.transporter) {
        throw new Error('SMTP transporter not initialized');
      }

      const emailData = this.prepareEmailData(options);
      this.validateEmailData(emailData);
      
      logger.info('Attempting to send email', {
        to: emailData.to,
        subject: emailData.subject,
        from: emailData.from,
        provider: this.provider,
        hasHTML: !!emailData.html,
        hasText: !!emailData.text
      });

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
      
      this.logEmailSent(emailData, result);
      return result;
    } catch (error) {
      logger.error('Email send failed', { 
        error: error.message,
        code: error.code,
        command: error.command,
        stack: config.app?.env === 'development' ? error.stack : undefined,
        provider: this.provider,
        to: options.to,
        subject: options.subject
      });
      throw new AppError(`Failed to send email: ${error.message}`, 500);
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
        clickTracking: { enable: config.email?.tracking?.clicks || false },
        openTracking: { enable: config.email?.tracking?.opens || false }
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
   * Send via Mailgun using the secure mailgun.js package
   */
  async sendViaMailgun(emailData) {
    const messageData = {
      from: emailData.from,
      to: Array.isArray(emailData.to) ? emailData.to : [emailData.to],
      subject: emailData.subject,
      text: emailData.text,
      html: emailData.html,
      ...(emailData.cc && { cc: Array.isArray(emailData.cc) ? emailData.cc : [emailData.cc] }),
      ...(emailData.bcc && { bcc: Array.isArray(emailData.bcc) ? emailData.bcc : [emailData.bcc] }),
      ...(emailData.replyTo && { 'h:Reply-To': emailData.replyTo }),
      ...(config.email?.tracking?.opens && { 'o:tracking-opens': 'yes' }),
      ...(config.email?.tracking?.clicks && { 'o:tracking-clicks': 'yes' })
    };
    
    if (emailData.attachments && emailData.attachments.length > 0) {
      messageData.attachment = emailData.attachments.map(att => ({
        filename: att.filename,
        data: att.content
      }));
    }
    
    const response = await this.mailgunClient.messages.create(this.mailgunDomain, messageData);
    
    return {
      messageId: response.id,
      status: 200,
      provider: 'mailgun',
      message: response.message
    };
  }
  
  /**
   * Send via SMTP with enhanced error handling and logging
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
        'X-Mailer': 'InsightSerenity Platform',
        'X-Priority': emailData.priority || '3',
        ...(emailData.headers || {})
      }
    };
    
    logger.info('Sending via SMTP', {
      to: mailOptions.to,
      from: mailOptions.from,
      subject: mailOptions.subject,
      hasAttachments: !!(emailData.attachments && emailData.attachments.length > 0)
    });

    try {
      const result = await this.transporter.sendMail(mailOptions);
      
      logger.info('SMTP send successful', {
        messageId: result.messageId,
        accepted: result.accepted,
        rejected: result.rejected,
        response: result.response
      });

      return {
        messageId: result.messageId,
        status: 250,
        provider: 'smtp',
        accepted: result.accepted,
        rejected: result.rejected,
        response: result.response,
        preview: nodemailer.getTestMessageUrl(result)
      };
    } catch (error) {
      logger.error('SMTP send error details', {
        error: error.message,
        code: error.code,
        command: error.command,
        response: error.response,
        responseCode: error.responseCode
      });
      throw error;
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
      if (this.provider === 'sendgrid' && config.email?.sendgrid?.templates?.[templateName]) {
        return this.send({
          ...options,
          templateId: config.email.sendgrid.templates[templateName],
          dynamicTemplateData: options.data
        });
      }
      
      return emailHelper.sendTemplate(templateName, options);
    } catch (error) {
      logger.error('Failed to send templated email', { 
        template: templateName, 
        error: error.message 
      });
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
    const batchSize = config.email?.bulkBatchSize || 50;
    const results = {
      successful: 0,
      failed: 0,
      errors: []
    };
    
    for (let i = 0; i < recipients.length; i += batchSize) {
      const batch = recipients.slice(i, i + batchSize);
      
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
   * Prepare email data with proper validation
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
   * Validate email data with comprehensive checks
   */
  validateEmailData(emailData) {
    if (!emailData.to) {
      throw new AppError('Email recipient is required', 400);
    }
    
    if (!emailData.subject) {
      throw new AppError('Email subject is required', 400);
    }
    
    if (!emailData.text && !emailData.html && !emailData.templateId) {
      throw new AppError('Email content is required (text, html, or templateId)', 400);
    }
    
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
   * Log email sent with enhanced information
   */
  logEmailSent(emailData, result) {
    logger.info('Email sent successfully', {
      messageId: result.messageId,
      provider: result.provider,
      status: result.status,
      to: emailData.to,
      subject: emailData.subject,
      category: emailData.metadata?.category,
      userId: emailData.metadata?.userId,
      organizationId: emailData.metadata?.organizationId,
      timestamp: new Date().toISOString()
    });
  }
  
  /**
   * Test email configuration with comprehensive diagnostics
   */
  async testConnection() {
    try {
      logger.info('Testing email service connection', { provider: this.provider });
      
      if (this.provider === 'smtp' && this.transporter) {
        logger.info('Testing SMTP connection...');
        await this.transporter.verify();
        logger.info('SMTP connection test successful');
        return { 
          success: true, 
          provider: this.provider,
          details: {
            host: config.email?.smtp?.host,
            port: config.email?.smtp?.port,
            secure: config.email?.smtp?.secure,
            from: this.from
          }
        };
      }
      
      if (this.provider === 'mailgun' && this.mailgunClient) {
        const domainInfo = await this.mailgunClient.domains.get(this.mailgunDomain);
        return { 
          success: true, 
          provider: this.provider, 
          domain: domainInfo.domain?.name 
        };
      }
      
      return { success: true, provider: this.provider };
    } catch (error) {
      logger.error('Email service test failed', { 
        error: error.message,
        code: error.code,
        provider: this.provider,
        details: error.command || 'Unknown error'
      });
      return { 
        success: false, 
        error: error.message, 
        provider: this.provider,
        code: error.code
      };
    }
  }
  
  /**
   * Pre-built email templates for common use cases
   */
  async sendWelcomeEmail(user) {
    const welcomeHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Welcome to InsightSerenity</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to InsightSerenity!</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333;">Hello ${user.firstName},</h2>
          <p>Welcome to InsightSerenity! We're excited to have you on board.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${config.app?.url || 'http://localhost:3000'}/activate/${user.activationToken}" 
               style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
              Activate Your Account
            </a>
          </div>
          <p style="font-size: 14px; color: #666;">
            If you have any questions, feel free to contact our support team.
          </p>
        </div>
      </body>
      </html>
    `;

    return this.send({
      to: user.email,
      subject: 'Welcome to InsightSerenity',
      html: welcomeHTML,
      text: `Hello ${user.firstName},\n\nWelcome to InsightSerenity! Please activate your account by visiting: ${config.app?.url || 'http://localhost:3000'}/activate/${user.activationToken}`,
      userId: user.id,
      category: 'account'
    });
  }
  
  async sendPasswordResetEmail(user, resetToken) {
    const resetHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>Reset Your Password</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: #f44336; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Password Reset Request</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333;">Hello ${user.firstName},</h2>
          <p>You requested a password reset. Click the button below to reset your password:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${config.app?.url || 'http://localhost:3000'}/reset-password/${resetToken}" 
               style="background: #f44336; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">
              Reset Password
            </a>
          </div>
          <p style="font-size: 14px; color: #666;">
            This link will expire in 2 hours. If you didn't request this reset, please ignore this email.
          </p>
        </div>
      </body>
      </html>
    `;

    return this.send({
      to: user.email,
      subject: 'Reset Your Password',
      html: resetHTML,
      text: `Hello ${user.firstName},\n\nYou requested a password reset. Visit this link to reset your password: ${config.app?.url || 'http://localhost:3000'}/reset-password/${resetToken}\n\nThis link expires in 2 hours.`,
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
        acceptUrl: `${config.app?.url || 'http://localhost:3000'}/invitations/${invitation.token}`,
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