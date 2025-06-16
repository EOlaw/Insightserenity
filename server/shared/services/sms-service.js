// /server/shared/services/sms-service.js

/**
 * @file SMS Service
 * @description SMS notification service with multiple providers
 * @version 1.0.0
 */

const { SNSClient, PublishCommand } = require('@aws-sdk/client-sns');
const axios = require('axios');
const twilio = require('twilio');

const config = require('../config');
const { AppError } = require('../utils/app-error');
const queueHelper = require('../utils/helpers/queue-helper');
const logger = require('../utils/logger');
const { validatePhoneNumber } = require('../utils/validation/custom-validators');

/**
 * SMS Service Class
 */
class SMSService {
  constructor() {
    this.provider = config.sms.provider || 'twilio';
    this.from = config.sms.defaultFrom;
    this.templates = new Map();
    
    this.initializeProvider();
    this.loadTemplates();
  }
  
  /**
   * Initialize SMS provider
   */
  initializeProvider() {
    try {
      switch (this.provider) {
        case 'twilio':
          this.initializeTwilio();
          break;
        case 'sns':
          this.initializeSNS();
          break;
        case 'messagebird':
          this.initializeMessageBird();
          break;
        case 'nexmo':
          this.initializeNexmo();
          break;
        default:
          throw new Error(`Unsupported SMS provider: ${this.provider}`);
      }
      
      logger.info(`SMS service initialized with provider: ${this.provider}`);
    } catch (error) {
      logger.error('Failed to initialize SMS service:', error);
      throw new AppError('SMS service initialization failed', 500);
    }
  }
  
  /**
   * Initialize Twilio
   */
  initializeTwilio() {
    if (!config.sms.twilio.accountSid || !config.sms.twilio.authToken) {
      throw new Error('Twilio credentials not configured');
    }
    
    this.twilioClient = twilio(
      config.sms.twilio.accountSid,
      config.sms.twilio.authToken
    );
    
    // Set default from number
    if (!this.from && config.sms.twilio.phoneNumber) {
      this.from = config.sms.twilio.phoneNumber;
    }
  }
  
  /**
   * Initialize AWS SNS
   */
  initializeSNS() {
    const { defaultProvider } = require('@aws-sdk/credential-provider-node');
    
    this.snsClient = new SNSClient({
      region: config.sms.sns.region || 'us-east-1',
      credentials: defaultProvider()
    });
  }
  
  /**
   * Initialize MessageBird
   */
  initializeMessageBird() {
    if (!config.sms.messagebird.accessKey) {
      throw new Error('MessageBird access key not configured');
    }
    
    this.messagebirdClient = require('messagebird')(config.sms.messagebird.accessKey);
  }
  
  /**
   * Initialize Nexmo (Vonage)
   */
  initializeNexmo() {
    if (!config.sms.nexmo.apiKey || !config.sms.nexmo.apiSecret) {
      throw new Error('Nexmo credentials not configured');
    }
    
    const Nexmo = require('nexmo');
    this.nexmoClient = new Nexmo({
      apiKey: config.sms.nexmo.apiKey,
      apiSecret: config.sms.nexmo.apiSecret
    });
  }
  
  /**
   * Load SMS templates
   */
  loadTemplates() {
    // Welcome message
    this.templates.set('welcome', {
      text: 'Welcome to Insightserenity, {{name}}! Your account has been created successfully.',
      maxLength: 160
    });
    
    // Verification code
    this.templates.set('verification', {
      text: 'Your Insightserenity verification code is: {{code}}. Valid for {{minutes}} minutes.',
      maxLength: 160
    });
    
    // Password reset
    this.templates.set('passwordReset', {
      text: 'Reset your Insightserenity password: {{link}}. Valid for 2 hours.',
      maxLength: 160
    });
    
    // Two-factor authentication
    this.templates.set('twoFactor', {
      text: 'Your Insightserenity 2FA code: {{code}}. Do not share this code.',
      maxLength: 160
    });
    
    // Appointment reminder
    this.templates.set('appointment', {
      text: 'Reminder: {{type}} appointment on {{date}} at {{time}}. Reply CONFIRM or CANCEL.',
      maxLength: 160
    });
    
    // Custom notification
    this.templates.set('notification', {
      text: '{{message}}',
      maxLength: 160
    });
  }
  
  /**
   * Send SMS
   * @param {Object} options - SMS options
   * @returns {Promise<Object>} Send result
   */
  async send(options) {
    try {
      // Prepare SMS data
      const smsData = this.prepareSMSData(options);
      
      // Validate SMS data
      await this.validateSMSData(smsData);
      
      // Check for opt-out
      if (await this.isOptedOut(smsData.to)) {
        throw new AppError('Recipient has opted out of SMS notifications', 400);
      }
      
      // Send based on provider
      let result;
      switch (this.provider) {
        case 'twilio':
          result = await this.sendViaTwilio(smsData);
          break;
        case 'sns':
          result = await this.sendViaSNS(smsData);
          break;
        case 'messagebird':
          result = await this.sendViaMessageBird(smsData);
          break;
        case 'nexmo':
          result = await this.sendViaNexmo(smsData);
          break;
        default:
          throw new Error(`Unsupported provider: ${this.provider}`);
      }
      
      // Log success
      await this.logSMSSent(smsData, result);
      
      return result;
    } catch (error) {
      logger.error('SMS send failed:', error);
      throw error instanceof AppError ? error : new AppError('Failed to send SMS', 500);
    }
  }
  
  /**
   * Send via Twilio
   */
  async sendViaTwilio(smsData) {
    const message = await this.twilioClient.messages.create({
      body: smsData.message,
      from: smsData.from,
      to: smsData.to,
      ...(smsData.mediaUrl && { mediaUrl: [smsData.mediaUrl] }),
      ...(smsData.statusCallback && { statusCallback: smsData.statusCallback })
    });
    
    return {
      messageId: message.sid,
      status: message.status,
      provider: 'twilio',
      price: message.price,
      priceUnit: message.priceUnit
    };
  }
  
  /**
   * Send via AWS SNS
   */
  async sendViaSNS(smsData) {
    const params = {
      Message: smsData.message,
      PhoneNumber: smsData.to,
      MessageAttributes: {
        'AWS.SNS.SMS.SenderID': {
          DataType: 'String',
          StringValue: smsData.senderId || 'Insightserenity'
        },
        'AWS.SNS.SMS.SMSType': {
          DataType: 'String',
          StringValue: smsData.type || 'Transactional'
        }
      }
    };
    
    const command = new PublishCommand(params);
    const response = await this.snsClient.send(command);
    
    return {
      messageId: response.MessageId,
      status: 'sent',
      provider: 'sns'
    };
  }
  
  /**
   * Send via MessageBird
   */
  async sendViaMessageBird(smsData) {
    return new Promise((resolve, reject) => {
      this.messagebirdClient.messages.create({
        originator: smsData.from || 'Insightserenity',
        recipients: [smsData.to],
        body: smsData.message
      }, (err, response) => {
        if (err) {
          reject(err);
        } else {
          resolve({
            messageId: response.id,
            status: response.recipients.items[0].status,
            provider: 'messagebird'
          });
        }
      });
    });
  }
  
  /**
   * Send via Nexmo
   */
  async sendViaNexmo(smsData) {
    return new Promise((resolve, reject) => {
      this.nexmoClient.message.sendSms(
        smsData.from || 'Insightserenity',
        smsData.to,
        smsData.message,
        {},
        (err, response) => {
          if (err) {
            reject(err);
          } else {
            const message = response.messages[0];
            if (message.status === '0') {
              resolve({
                messageId: message['message-id'],
                status: 'sent',
                provider: 'nexmo',
                remainingBalance: response['remaining-balance']
              });
            } else {
              reject(new Error(`Nexmo error: ${message['error-text']}`));
            }
          }
        }
      );
    });
  }
  
  /**
   * Send templated SMS
   * @param {string} templateName - Template name
   * @param {Object} options - SMS options
   * @returns {Promise<Object>} Send result
   */
  async sendTemplate(templateName, options) {
    const template = this.templates.get(templateName);
    if (!template) {
      throw new AppError(`SMS template '${templateName}' not found`, 400);
    }
    
    // Replace template variables
    let message = template.text;
    if (options.data) {
      Object.entries(options.data).forEach(([key, value]) => {
        message = message.replace(new RegExp(`{{${key}}}`, 'g'), value);
      });
    }
    
    // Check message length
    if (message.length > template.maxLength) {
      logger.warn(`SMS message exceeds maximum length for template ${templateName}`);
    }
    
    return this.send({
      ...options,
      message,
      template: templateName
    });
  }
  
  /**
   * Send bulk SMS
   * @param {Array} recipients - Array of recipient configurations
   * @param {Object} commonOptions - Common SMS options
   * @returns {Promise<Object>} Bulk send results
   */
  async sendBulk(recipients, commonOptions) {
    const batchSize = config.sms.bulkBatchSize || 100;
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
        const smsOptions = {
          ...commonOptions,
          to: recipient.phone,
          data: {
            ...commonOptions.data,
            ...recipient.data
          }
        };
        
        return queueHelper.addJob('sms', 'send-sms', smsOptions);
      });
      
      // Wait for batch to complete
      const batchResults = await Promise.allSettled(jobs);
      
      batchResults.forEach((result, index) => {
        if (result.status === 'fulfilled') {
          results.successful++;
        } else {
          results.failed++;
          results.errors.push({
            recipient: batch[index].phone,
            error: result.reason.message
          });
        }
      });
      
      // Rate limiting between batches
      if (i + batchSize < recipients.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    logger.info('Bulk SMS send completed', results);
    return results;
  }
  
  /**
   * Prepare SMS data
   */
  prepareSMSData(options) {
    return {
      to: options.to,
      from: options.from || this.from,
      message: options.message,
      type: options.type || 'transactional',
      senderId: options.senderId,
      mediaUrl: options.mediaUrl,
      statusCallback: options.statusCallback,
      template: options.template,
      metadata: {
        userId: options.userId,
        organizationId: options.organizationId,
        category: options.category,
        reference: options.reference
      }
    };
  }
  
  /**
   * Validate SMS data
   */
  async validateSMSData(smsData) {
    // Validate recipient
    if (!smsData.to) {
      throw new AppError('SMS recipient is required', 400);
    }
    
    const phoneValidation = validatePhoneNumber(smsData.to);
    if (!phoneValidation.valid) {
      throw new AppError(phoneValidation.message, 400);
    }
    
    // Validate message
    if (!smsData.message) {
      throw new AppError('SMS message is required', 400);
    }
    
    // Check message length
    const maxLength = config.sms.maxLength || 1600;
    if (smsData.message.length > maxLength) {
      throw new AppError(`SMS message exceeds maximum length of ${maxLength} characters`, 400);
    }
    
    // Validate from number if provided
    if (smsData.from && this.provider === 'twilio') {
      // Verify from number is registered with Twilio
      // This would require additional Twilio API calls
    }
  }
  
  /**
   * Check if recipient has opted out
   */
  async isOptedOut(phoneNumber) {
    // Check opt-out database/cache
    // This would be implemented based on your opt-out management system
    return false;
  }
  
  /**
   * Log SMS sent
   */
  async logSMSSent(smsData, result) {
    const logEntry = {
      messageId: result.messageId,
      provider: result.provider,
      to: smsData.to,
      from: smsData.from,
      template: smsData.template,
      category: smsData.metadata?.category,
      userId: smsData.metadata?.userId,
      organizationId: smsData.metadata?.organizationId,
      status: result.status,
      cost: result.price,
      timestamp: new Date().toISOString()
    };
    
    logger.info('SMS sent successfully', logEntry);
    
    // Store in database for tracking
    // await SMSLog.create(logEntry);
  }
  
  /**
   * Handle SMS webhook
   */
  async handleWebhook(provider, data) {
    switch (provider) {
      case 'twilio':
        return this.handleTwilioWebhook(data);
      case 'sns':
        return this.handleSNSWebhook(data);
      default:
        throw new AppError('Unknown webhook provider', 400);
    }
  }
  
  /**
   * Handle Twilio webhook
   */
  async handleTwilioWebhook(data) {
    const { MessageSid, MessageStatus, ErrorCode, ErrorMessage } = data;
    
    logger.info('Twilio webhook received', {
      messageId: MessageSid,
      status: MessageStatus,
      errorCode: ErrorCode,
      errorMessage: ErrorMessage
    });
    
    // Update message status in database
    // await SMSLog.updateStatus(MessageSid, MessageStatus);
    
    // Handle specific statuses
    if (MessageStatus === 'failed' || MessageStatus === 'undelivered') {
      logger.error('SMS delivery failed', {
        messageId: MessageSid,
        errorCode: ErrorCode,
        errorMessage: ErrorMessage
      });
    }
  }
  
  /**
   * Handle SNS webhook
   */
  async handleSNSWebhook(data) {
    // Parse SNS message
    const message = JSON.parse(data.Message);
    
    logger.info('SNS webhook received', {
      messageId: message.MessageId,
      status: message.Status,
      phoneNumber: message.PhoneNumber
    });
    
    // Update message status
    // await SMSLog.updateStatus(message.MessageId, message.Status);
  }
  
  /**
   * Send verification code
   */
  async sendVerificationCode(phoneNumber, code, expiryMinutes = 10) {
    return this.sendTemplate('verification', {
      to: phoneNumber,
      data: {
        code,
        minutes: expiryMinutes
      },
      type: 'transactional',
      category: 'verification'
    });
  }
  
  /**
   * Send two-factor authentication code
   */
  async send2FACode(phoneNumber, code, userId) {
    return this.sendTemplate('twoFactor', {
      to: phoneNumber,
      data: { code },
      type: 'transactional',
      category: '2fa',
      userId
    });
  }
  
  /**
   * Send appointment reminder
   */
  async sendAppointmentReminder(appointment) {
    return this.sendTemplate('appointment', {
      to: appointment.phoneNumber,
      data: {
        type: appointment.type,
        date: appointment.date,
        time: appointment.time
      },
      type: 'transactional',
      category: 'reminder',
      userId: appointment.userId,
      reference: appointment.id
    });
  }
  
  /**
   * Queue SMS for sending
   */
  async queue(options) {
    return queueHelper.addJob('sms', 'send-sms', options, {
      priority: options.priority || 3,
      delay: options.delay || 0,
      attempts: options.attempts || 3
    });
  }
  
  /**
   * Get SMS status
   */
  async getStatus(messageId) {
    switch (this.provider) {
      case 'twilio':
        const message = await this.twilioClient.messages(messageId).fetch();
        return {
          status: message.status,
          errorCode: message.errorCode,
          errorMessage: message.errorMessage,
          dateSent: message.dateSent,
          price: message.price
        };
      default:
        throw new AppError('Status check not supported for this provider', 400);
    }
  }
  
  /**
   * Calculate SMS segments
   */
  calculateSegments(message) {
    const length = message.length;
    const hasUnicode = /[^\x00-\x7F]/.test(message);
    
    if (hasUnicode) {
      // Unicode messages
      return length <= 70 ? 1 : Math.ceil(length / 67);
    } else {
      // GSM 7-bit messages
      return length <= 160 ? 1 : Math.ceil(length / 153);
    }
  }
}

// Create singleton instance
const smsService = new SMSService();

module.exports = smsService;