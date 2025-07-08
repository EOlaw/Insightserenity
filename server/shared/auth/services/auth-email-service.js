/**
 * @file Authentication Email Service
 * @description Handles all authentication-related email communications
 * @version 1.0.0
 */

const config = require('../../config/config');
const EmailService = require('../../services/email-service');
const logger = require('../../utils/logger');

/**
 * Authentication Email Service Class
 * Manages all email communications related to authentication flows
 */
class AuthEmailService {
  
  /**
   * Send email verification message
   * @param {Object} user - User object
   * @param {string} token - Verification token
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Send result
   */
  static async sendVerificationEmail(user, token, context) {
    try {
      // Construct verification URL using correct config path
      const verificationUrl = `${config.frontend?.verifyEmailUrl || config.client?.url || 'http://localhost:3000/verify-email'}?token=${token}`;
      
      // ENHANCED DEVELOPMENT LOGGING
      if (config.app.env === 'development') {
        console.log('\n🔓 =================== EMAIL VERIFICATION TOKEN (DEVELOPMENT) ===================');
        console.log(`📧 To: ${user.email}`);
        console.log(`👤 User: ${user.firstName} ${user.lastName}`);
        console.log(`🆔 User ID: ${user._id}`);
        console.log(`🔑 Verification Token: ${token}`);
        console.log(`🔗 Verification URL: ${verificationUrl}`);
        console.log(`⏰ Expires: 24 hours from now`);
        console.log(`📅 Created: ${new Date().toISOString()}`);
        console.log('================================================================================\n');
        
        logger.info('🔓 EMAIL VERIFICATION TOKEN (DEVELOPMENT)', {
          userId: user._id,
          email: user.email,
          firstName: user.firstName,
          fullToken: token,
          verificationUrl,
          note: 'Full token logged for development purposes only'
        });
      }

      // Prepare email content
      const emailData = {
        to: user.email,
        subject: 'Verify your email address',
        html: this.generateVerificationEmailHTML(user.firstName, verificationUrl),
        text: this.generateVerificationEmailText(user.firstName, verificationUrl),
        category: 'verification',
        userId: user._id
      };

      // Try to send email using the email service
      try {
        logger.info('Attempting to send verification email via email service', {
          to: user.email,
          userId: user._id,
          subject: emailData.subject
        });

        const result = await EmailService.send(emailData);
        
        logger.info('Verification email sent successfully', {
          to: user.email,
          userId: user._id,
          messageId: result.messageId,
          provider: result.provider
        });

        return {
          success: true,
          messageId: result.messageId,
          provider: result.provider
        };

      } catch (emailError) {
        // Log email error but don't fail registration
        logger.error('Failed to send verification email', {
          error: emailError.message,
          userId: user._id,
          email: user.email,
          errorCode: emailError.code
        });

        // Development fallback logging
        if (config.app.env === 'development') {
          console.log('📧 VERIFICATION EMAIL FAILED - Fallback Information:');
          console.log(`   To: ${user.email}`);
          console.log(`   Subject: ${emailData.subject}`);
          console.log(`   Verification URL: ${verificationUrl}`);
          console.log(`   Full Token: ${token}`);
          console.log(`   Error: ${emailError.message}`);
        }

        // Log fallback information for production
        logger.info('Verification email fallback - registration completed without email', {
          userId: user._id,
          email: user.email,
          verificationUrl,
          token: config.app.env === 'development' ? token : token.substring(0, 8) + '...',
          error: emailError.message,
          note: 'User can verify manually using URL if needed'
        });

        return {
          success: false,
          error: emailError.message,
          fallbackUrl: verificationUrl
        };
      }
      
    } catch (error) {
      logger.error('Critical error in sendVerificationEmail', {
        error: error.message,
        stack: error.stack,
        userId: user._id,
        email: user.email
      });
      throw error;
    }
  }

  /**
   * Send email verification success notification
   * @param {Object} user - User object
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Send result
   */
  static async sendVerificationSuccessEmail(user, context) {
    try {
      const loginUrl = `${config.frontend?.loginUrl || config.client?.url || 'http://localhost:3000/login'}`;
      
      const emailData = {
        to: user.email,
        subject: 'Email verified successfully - Welcome to InsightSerenity!',
        html: this.generateVerificationSuccessHTML(user.firstName, loginUrl),
        text: this.generateVerificationSuccessText(user.firstName, loginUrl),
        category: 'verification_success',
        userId: user._id
      };

      const result = await EmailService.send(emailData);
      
      logger.info('Verification success email sent', {
        to: user.email,
        userId: user._id,
        messageId: result.messageId
      });

      return {
        success: true,
        messageId: result.messageId,
        provider: result.provider
      };

    } catch (error) {
      logger.error('Failed to send verification success email', {
        error: error.message,
        userId: user._id,
        email: user.email
      });
      
      // Don't throw error as this is a nice-to-have notification
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send password reset email
   * @param {Object} user - User object
   * @param {string} token - Reset token
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Send result
   */
  static async sendPasswordResetEmail(user, token, context) {
    try {
      const resetUrl = `${config.frontend?.resetPasswordUrl || config.client?.url || 'http://localhost:3000/reset-password'}?token=${token}`;
      
      // Development logging
      if (config.app.env === 'development') {
        logger.info('🔑 PASSWORD RESET TOKEN (DEVELOPMENT)', {
          userId: user._id,
          email: user.email,
          resetUrl,
          token,
          ip: context.ip
        });
      }
      
      const emailData = {
        to: user.email,
        subject: 'Reset your password - InsightSerenity',
        html: this.generatePasswordResetHTML(user.firstName, resetUrl, context.ip),
        text: this.generatePasswordResetText(user.firstName, resetUrl),
        category: 'password_reset',
        userId: user._id,
        priority: 1 // High priority for security emails
      };

      const result = await EmailService.send(emailData);
      
      logger.info('Password reset email sent successfully', {
        to: user.email,
        userId: user._id,
        messageId: result.messageId,
        resetUrl
      });

      return {
        success: true,
        messageId: result.messageId,
        provider: result.provider
      };
      
    } catch (error) {
      logger.error('Failed to send password reset email', {
        error: error.message,
        userId: user._id,
        email: user.email,
        ip: context.ip
      });
      
      // Development fallback
      if (config.app.env === 'development') {
        console.log('📧 PASSWORD RESET EMAIL FAILED - Token for manual reset:');
        console.log(`   User: ${user.email}`);
        console.log(`   Token: ${token}`);
        console.log(`   Reset URL: ${resetUrl}`);
      }
      
      throw error;
    }
  }

  /**
   * Send password changed notification
   * @param {Object} user - User object
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Send result
   */
  static async sendPasswordChangedEmail(user, context) {
    try {
      const loginUrl = `${config.frontend?.loginUrl || config.client?.url || 'http://localhost:3000/login'}`;
      const supportEmail = config.email?.supportEmail || 'support@insightserenity.com';
      
      const emailData = {
        to: user.email,
        subject: 'Your password has been changed - InsightSerenity',
        html: this.generatePasswordChangedHTML(user.firstName, loginUrl, supportEmail, context),
        text: this.generatePasswordChangedText(user.firstName, loginUrl, supportEmail, context),
        category: 'password_changed',
        userId: user._id,
        priority: 1 // High priority for security notifications
      };

      const result = await EmailService.send(emailData);
      
      logger.info('Password changed email sent successfully', {
        to: user.email,
        userId: user._id,
        messageId: result.messageId
      });

      return {
        success: true,
        messageId: result.messageId,
        provider: result.provider
      };
      
    } catch (error) {
      logger.error('Failed to send password changed email', {
        error: error.message,
        userId: user._id,
        email: user.email,
        ip: context.ip
      });
      
      // Don't throw error as password change already succeeded
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send MFA setup success notification
   * @param {Object} user - User object
   * @param {string} method - MFA method that was set up
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Send result
   */
  static async sendMfaEnabledEmail(user, method, context) {
    try {
      const emailData = {
        to: user.email,
        subject: 'Two-factor authentication enabled - InsightSerenity',
        html: this.generateMfaEnabledHTML(user.firstName, method),
        text: this.generateMfaEnabledText(user.firstName, method),
        category: 'mfa_enabled',
        userId: user._id,
        priority: 1
      };

      const result = await EmailService.send(emailData);
      
      logger.info('MFA enabled email sent successfully', {
        to: user.email,
        userId: user._id,
        method,
        messageId: result.messageId
      });

      return {
        success: true,
        messageId: result.messageId,
        provider: result.provider
      };
      
    } catch (error) {
      logger.error('Failed to send MFA enabled email', {
        error: error.message,
        userId: user._id,
        email: user.email,
        method
      });
      
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Send suspicious login attempt notification
   * @param {Object} user - User object
   * @param {Object} loginAttempt - Login attempt details
   * @param {Object} context - Request context
   * @returns {Promise<Object>} Send result
   */
  static async sendSuspiciousLoginEmail(user, loginAttempt, context) {
    try {
      const emailData = {
        to: user.email,
        subject: 'Suspicious login attempt detected - InsightSerenity',
        html: this.generateSuspiciousLoginHTML(user.firstName, loginAttempt),
        text: this.generateSuspiciousLoginText(user.firstName, loginAttempt),
        category: 'security_alert',
        userId: user._id,
        priority: 1
      };

      const result = await EmailService.send(emailData);
      
      logger.info('Suspicious login email sent successfully', {
        to: user.email,
        userId: user._id,
        messageId: result.messageId,
        loginAttempt: {
          ip: loginAttempt.ip,
          location: loginAttempt.location,
          timestamp: loginAttempt.timestamp
        }
      });

      return {
        success: true,
        messageId: result.messageId,
        provider: result.provider
      };
      
    } catch (error) {
      logger.error('Failed to send suspicious login email', {
        error: error.message,
        userId: user._id,
        email: user.email
      });
      
      return {
        success: false,
        error: error.message
      };
    }
  }

  // ==================== EMAIL TEMPLATE GENERATORS ====================

  /**
   * Generate HTML content for verification email
   * @param {string} firstName - User's first name
   * @param {string} verificationUrl - Verification URL
   * @returns {string} HTML content
   */
  static generateVerificationEmailHTML(firstName, verificationUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verify Your Email</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to InsightSerenity!</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333; margin-bottom: 20px;">Hi ${firstName},</h2>
          <p style="font-size: 16px; margin-bottom: 20px;">
            Thank you for joining InsightSerenity! To complete your registration and secure your account, 
            please verify your email address by clicking the button below.
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" 
               style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 5px; 
                      font-weight: bold; 
                      display: inline-block;
                      font-size: 16px;">
              Verify Email Address
            </a>
          </div>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="${verificationUrl}" style="color: #667eea; word-break: break-all;">${verificationUrl}</a>
          </p>
          <p style="font-size: 14px; color: #666; margin-top: 20px;">
            This verification link will expire in 24 hours for security reasons.
          </p>
          <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
          <p style="font-size: 12px; color: #888; text-align: center;">
            If you didn't create an account with InsightSerenity, please ignore this email.
          </p>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate plain text content for verification email
   * @param {string} firstName - User's first name
   * @param {string} verificationUrl - Verification URL
   * @returns {string} Plain text content
   */
  static generateVerificationEmailText(firstName, verificationUrl) {
    return `
Hi ${firstName},

Welcome to InsightSerenity!

Thank you for joining us. To complete your registration and secure your account, please verify your email address by visiting this link:

${verificationUrl}

This verification link will expire in 24 hours for security reasons.

If you didn't create an account with InsightSerenity, please ignore this email.

Best regards,
The InsightSerenity Team
    `.trim();
  }

  /**
   * Generate HTML content for verification success email
   * @param {string} firstName - User's first name
   * @param {string} loginUrl - Login URL
   * @returns {string} HTML content
   */
  static generateVerificationSuccessHTML(firstName, loginUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verified Successfully</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">🎉 Email Verified!</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333; margin-bottom: 20px;">Congratulations ${firstName}!</h2>
          <p style="font-size: 16px; margin-bottom: 20px;">
            Your email address has been successfully verified. Your InsightSerenity account is now active and ready to use.
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${loginUrl}" 
               style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 5px; 
                      font-weight: bold; 
                      display: inline-block;
                      font-size: 16px;">
              Login to Your Account
            </a>
          </div>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            You can now access all features of your InsightSerenity account. If you have any questions, our support team is here to help.
          </p>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate plain text content for verification success email
   * @param {string} firstName - User's first name
   * @param {string} loginUrl - Login URL
   * @returns {string} Plain text content
   */
  static generateVerificationSuccessText(firstName, loginUrl) {
    return `
Congratulations ${firstName}!

Your email address has been successfully verified. Your InsightSerenity account is now active and ready to use.

Login to your account: ${loginUrl}

You can now access all features of your InsightSerenity account. If you have any questions, our support team is here to help.

Best regards,
The InsightSerenity Team
    `.trim();
  }

  /**
   * Generate HTML content for password reset email
   * @param {string} firstName - User's first name
   * @param {string} resetUrl - Password reset URL
   * @param {string} ip - Request IP address
   * @returns {string} HTML content
   */
  static generatePasswordResetHTML(firstName, resetUrl, ip) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">🔐 Password Reset Request</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333; margin-bottom: 20px;">Hello ${firstName},</h2>
          <p style="font-size: 16px; margin-bottom: 20px;">
            We received a request to reset your password for your InsightSerenity account. Click the button below to create a new password.
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" 
               style="background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 5px; 
                      font-weight: bold; 
                      display: inline-block;
                      font-size: 16px;">
              Reset Password
            </a>
          </div>
          <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #856404;">
              <strong>Security Notice:</strong> This request originated from IP address ${ip}. 
              If you didn't request this reset, please ignore this email and consider changing your password.
            </p>
          </div>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            This password reset link will expire in 1 hour for security reasons.
            If you continue to have issues, please contact our support team.
          </p>
          <hr style="border: none; border-top: 1px solid #ddd; margin: 30px 0;">
          <p style="font-size: 12px; color: #888; text-align: center;">
            If you didn't request this password reset, please ignore this email. Your password will not be changed.
          </p>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate plain text content for password reset email
   * @param {string} firstName - User's first name
   * @param {string} resetUrl - Password reset URL
   * @returns {string} Plain text content
   */
  static generatePasswordResetText(firstName, resetUrl) {
    return `
Hello ${firstName},

We received a request to reset your password for your InsightSerenity account.

Reset your password by visiting this link: ${resetUrl}

This password reset link will expire in 1 hour for security reasons.

If you didn't request this password reset, please ignore this email. Your password will not be changed.

If you continue to have issues, please contact our support team.

Best regards,
The InsightSerenity Team
    `.trim();
  }

  /**
   * Generate HTML content for password changed email
   * @param {string} firstName - User's first name
   * @param {string} loginUrl - Login URL
   * @param {string} supportEmail - Support email address
   * @param {Object} context - Request context
   * @returns {string} HTML content
   */
  static generatePasswordChangedHTML(firstName, loginUrl, supportEmail, context) {
    const timestamp = new Date().toLocaleString();
    
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Changed Successfully</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">✅ Password Changed</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333; margin-bottom: 20px;">Hello ${firstName},</h2>
          <p style="font-size: 16px; margin-bottom: 20px;">
            Your InsightSerenity account password has been successfully changed.
          </p>
          <div style="background: #d1ecf1; border: 1px solid #b8daff; border-radius: 5px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #0c5460;">
              <strong>Change Details:</strong><br>
              Time: ${timestamp}<br>
              IP Address: ${context.ip || 'Unknown'}
            </p>
          </div>
          <p style="font-size: 16px; margin-bottom: 20px;">
            You can now use your new password to access your account.
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${loginUrl}" 
               style="background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 5px; 
                      font-weight: bold; 
                      display: inline-block;
                      font-size: 16px;">
              Login to Your Account
            </a>
          </div>
          <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #856404;">
              <strong>Security Notice:</strong> If you didn't make this change, please contact our support team immediately at ${supportEmail}
            </p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate plain text content for password changed email
   * @param {string} firstName - User's first name
   * @param {string} loginUrl - Login URL
   * @param {string} supportEmail - Support email address
   * @param {Object} context - Request context
   * @returns {string} Plain text content
   */
  static generatePasswordChangedText(firstName, loginUrl, supportEmail, context) {
    const timestamp = new Date().toLocaleString();
    
    return `
Hello ${firstName},

Your InsightSerenity account password has been successfully changed.

Change Details:
Time: ${timestamp}
IP Address: ${context.ip || 'Unknown'}

You can now use your new password to access your account: ${loginUrl}

SECURITY NOTICE: If you didn't make this change, please contact our support team immediately at ${supportEmail}

Best regards,
The InsightSerenity Team
    `.trim();
  }

  /**
   * Generate HTML content for MFA enabled email
   * @param {string} firstName - User's first name
   * @param {string} method - MFA method
   * @returns {string} HTML content
   */
  static generateMfaEnabledHTML(firstName, method) {
    const methodLabels = {
      totp: 'Authenticator App (TOTP)',
      sms: 'SMS Text Message',
      email: 'Email Code',
      backup_codes: 'Backup Codes'
    };
    
    const methodLabel = methodLabels[method] || method.toUpperCase();
    
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Two-Factor Authentication Enabled</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #6f42c1 0%, #e83e8c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">🔐 MFA Enabled</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333; margin-bottom: 20px;">Hello ${firstName},</h2>
          <p style="font-size: 16px; margin-bottom: 20px;">
            Two-factor authentication has been successfully enabled on your InsightSerenity account using <strong>${methodLabel}</strong>.
          </p>
          <div style="background: #d1ecf1; border: 1px solid #b8daff; border-radius: 5px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #0c5460;">
              <strong>Enhanced Security:</strong> Your account is now protected with an additional layer of security. 
              You'll need to provide a verification code when logging in from new devices.
            </p>
          </div>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            If you didn't enable this feature, please contact our support team immediately.
          </p>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate plain text content for MFA enabled email
   * @param {string} firstName - User's first name
   * @param {string} method - MFA method
   * @returns {string} Plain text content
   */
  static generateMfaEnabledText(firstName, method) {
    const methodLabels = {
      totp: 'Authenticator App (TOTP)',
      sms: 'SMS Text Message',
      email: 'Email Code',
      backup_codes: 'Backup Codes'
    };
    
    const methodLabel = methodLabels[method] || method.toUpperCase();
    
    return `
Hello ${firstName},

Two-factor authentication has been successfully enabled on your InsightSerenity account using ${methodLabel}.

Your account is now protected with an additional layer of security. You'll need to provide a verification code when logging in from new devices.

If you didn't enable this feature, please contact our support team immediately.

Best regards,
The InsightSerenity Team
    `.trim();
  }

  /**
   * Generate HTML content for suspicious login email
   * @param {string} firstName - User's first name
   * @param {Object} loginAttempt - Login attempt details
   * @returns {string} HTML content
   */
  static generateSuspiciousLoginHTML(firstName, loginAttempt) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Suspicious Login Attempt</title>
      </head>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #dc3545 0%, #fd7e14 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">⚠️ Security Alert</h1>
        </div>
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #ddd;">
          <h2 style="color: #333; margin-bottom: 20px;">Hello ${firstName},</h2>
          <p style="font-size: 16px; margin-bottom: 20px;">
            We detected a suspicious login attempt on your InsightSerenity account that was blocked for your security.
          </p>
          <div style="background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 5px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #721c24;">
              <strong>Attempt Details:</strong><br>
              Time: ${loginAttempt.timestamp}<br>
              IP Address: ${loginAttempt.ip}<br>
              Location: ${loginAttempt.location || 'Unknown'}<br>
              Device: ${loginAttempt.device || 'Unknown'}
            </p>
          </div>
          <p style="font-size: 16px; margin-bottom: 20px;">
            If this was you, please try logging in again. If this wasn't you, your account is secure and no action is needed.
          </p>
          <p style="font-size: 14px; color: #666; margin-top: 30px;">
            To enhance your account security, consider enabling two-factor authentication in your account settings.
          </p>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate plain text content for suspicious login email
   * @param {string} firstName - User's first name
   * @param {Object} loginAttempt - Login attempt details
   * @returns {string} Plain text content
   */
  static generateSuspiciousLoginText(firstName, loginAttempt) {
    return `
Hello ${firstName},

We detected a suspicious login attempt on your InsightSerenity account that was blocked for your security.

Attempt Details:
Time: ${loginAttempt.timestamp}
IP Address: ${loginAttempt.ip}
Location: ${loginAttempt.location || 'Unknown'}
Device: ${loginAttempt.device || 'Unknown'}

If this was you, please try logging in again. If this wasn't you, your account is secure and no action is needed.

To enhance your account security, consider enabling two-factor authentication in your account settings.

Best regards,
The InsightSerenity Team
    `.trim();
  }
}

module.exports = AuthEmailService;