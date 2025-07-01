/**
 * @file Subscription Validation Middleware
 * @description Middleware for validating subscription status and access in hosted organizations
 * @version 1.0.0
 */

const logger = require('../../utils/logger');
const { AppError } = require('../../utils/app-error');
const OrganizationTenantService = require('../../../organization-tenants/services/organization-tenant-service');
const { TENANT_CONSTANTS } = require('../../../organization-tenants/constants/tenant-constants');

/**
 * Validate subscription status and access
 * @param {Object} options - Validation options
 * @param {Array} options.requiredPlans - Array of required plan types
 * @param {Array} options.requiredFeatures - Array of required features
 * @param {boolean} options.allowTrial - Whether to allow trial subscriptions (default: true)
 * @param {boolean} options.allowGracePeriod - Whether to allow grace period access (default: false)
 * @param {number} options.gracePeriodDays - Grace period days for expired subscriptions (default: 7)
 * @returns {Function} Express middleware function
 */
const validateSubscription = (options = {}) => {
  const {
    requiredPlans = [],
    requiredFeatures = [],
    allowTrial = true,
    allowGracePeriod = false,
    gracePeriodDays = 7
  } = options;

  return async (req, res, next) => {
    try {
      // Skip validation for certain conditions
      if (shouldSkipSubscriptionValidation(req)) {
        return next();
      }

      // Ensure tenant context exists
      if (!req.tenant) {
        logger.warn('Subscription validation requires tenant context', {
          path: req.path,
          method: req.method,
          userId: req.user?._id
        });
        return next();
      }

      const tenant = req.tenant;
      const subscription = tenant.subscription;

      if (!subscription) {
        logger.warn('No subscription found for tenant', {
          tenantId: tenant._id,
          path: req.path,
          method: req.method
        });
        
        const error = new AppError('No subscription found', 402);
        error.type = 'SubscriptionRequired';
        return next(error);
      }

      // Validate subscription status
      const statusValidation = validateSubscriptionStatus(subscription, { 
        allowTrial, 
        allowGracePeriod, 
        gracePeriodDays 
      });

      if (!statusValidation.valid) {
        logger.warn('Invalid subscription status', {
          tenantId: tenant._id,
          status: subscription.status,
          reason: statusValidation.reason,
          path: req.path,
          method: req.method
        });

        const error = new AppError(statusValidation.message, statusValidation.statusCode);
        error.type = statusValidation.errorType;
        error.subscription = {
          status: subscription.status,
          plan: subscription.plan,
          expiresAt: subscription.expiresAt
        };
        return next(error);
      }

      // Validate required plans
      if (requiredPlans.length > 0) {
        const planValidation = validateRequiredPlans(subscription, requiredPlans);
        
        if (!planValidation.valid) {
          logger.warn('Plan requirement not met', {
            tenantId: tenant._id,
            currentPlan: subscription.plan,
            requiredPlans,
            path: req.path,
            method: req.method
          });

          const error = new AppError(planValidation.message, 402);
          error.type = 'PlanUpgradeRequired';
          error.subscription = {
            currentPlan: subscription.plan,
            requiredPlans
          };
          return next(error);
        }
      }

      // Validate required features
      if (requiredFeatures.length > 0) {
        const featureValidation = validateRequiredFeatures(tenant, requiredFeatures);
        
        if (!featureValidation.valid) {
          logger.warn('Feature requirement not met', {
            tenantId: tenant._id,
            plan: subscription.plan,
            requiredFeatures,
            availableFeatures: featureValidation.availableFeatures,
            path: req.path,
            method: req.method
          });

          const error = new AppError(featureValidation.message, 403);
          error.type = 'FeatureNotAvailable';
          error.features = {
            required: requiredFeatures,
            available: featureValidation.availableFeatures,
            missing: featureValidation.missingFeatures
          };
          return next(error);
        }
      }

      // Add subscription info to request for downstream middleware
      req.subscriptionInfo = {
        valid: true,
        status: subscription.status,
        plan: subscription.plan,
        features: getAvailableFeatures(tenant),
        expiresAt: subscription.expiresAt,
        isInGracePeriod: statusValidation.isInGracePeriod
      };

      logger.debug('Subscription validation passed', {
        tenantId: tenant._id,
        status: subscription.status,
        plan: subscription.plan,
        path: req.path,
        method: req.method
      });

      next();

    } catch (error) {
      logger.error('Subscription validation error', {
        error: error.message,
        stack: error.stack,
        tenantId: req.tenant?._id,
        path: req.path,
        method: req.method
      });
      next(error);
    }
  };
};

/**
 * Validate subscription status
 * @param {Object} subscription - Subscription object
 * @param {Object} options - Validation options
 * @returns {Object} Validation result
 */
function validateSubscriptionStatus(subscription, options) {
  const { allowTrial, allowGracePeriod, gracePeriodDays } = options;
  const now = new Date();

  switch (subscription.status) {
    case TENANT_CONSTANTS.SUBSCRIPTION_STATUS.ACTIVE:
      if (subscription.expiresAt && subscription.expiresAt <= now) {
        if (allowGracePeriod) {
          const gracePeriodEnd = new Date(subscription.expiresAt);
          gracePeriodEnd.setDate(gracePeriodEnd.getDate() + gracePeriodDays);
          
          if (now <= gracePeriodEnd) {
            return {
              valid: true,
              isInGracePeriod: true,
              reason: 'grace_period'
            };
          }
        }
        
        return {
          valid: false,
          reason: 'expired',
          message: 'Subscription has expired',
          statusCode: 402,
          errorType: 'SubscriptionExpired'
        };
      }
      return { valid: true };

    case TENANT_CONSTANTS.SUBSCRIPTION_STATUS.TRIAL:
      if (!allowTrial) {
        return {
          valid: false,
          reason: 'trial_not_allowed',
          message: 'Trial subscriptions are not allowed for this operation',
          statusCode: 402,
          errorType: 'TrialNotAllowed'
        };
      }
      
      if (subscription.trialEndsAt && subscription.trialEndsAt <= now) {
        return {
          valid: false,
          reason: 'trial_expired',
          message: 'Trial subscription has expired',
          statusCode: 402,
          errorType: 'TrialExpired'
        };
      }
      return { valid: true };

    case TENANT_CONSTANTS.SUBSCRIPTION_STATUS.PAST_DUE:
      if (allowGracePeriod) {
        const gracePeriodEnd = new Date(subscription.lastPaymentDate || subscription.createdAt);
        gracePeriodEnd.setDate(gracePeriodEnd.getDate() + gracePeriodDays);
        
        if (now <= gracePeriodEnd) {
          return {
            valid: true,
            isInGracePeriod: true,
            reason: 'payment_grace_period'
          };
        }
      }
      
      return {
        valid: false,
        reason: 'payment_overdue',
        message: 'Subscription payment is overdue',
        statusCode: 402,
        errorType: 'PaymentOverdue'
      };

    case TENANT_CONSTANTS.SUBSCRIPTION_STATUS.CANCELLED:
      return {
        valid: false,
        reason: 'cancelled',
        message: 'Subscription has been cancelled',
        statusCode: 402,
        errorType: 'SubscriptionCancelled'
      };

    case TENANT_CONSTANTS.SUBSCRIPTION_STATUS.SUSPENDED:
      return {
        valid: false,
        reason: 'suspended',
        message: 'Subscription has been suspended',
        statusCode: 403,
        errorType: 'SubscriptionSuspended'
      };

    default:
      return {
        valid: false,
        reason: 'unknown_status',
        message: 'Unknown subscription status',
        statusCode: 500,
        errorType: 'UnknownSubscriptionStatus'
      };
  }
}

/**
 * Validate required plans
 * @param {Object} subscription - Subscription object
 * @param {Array} requiredPlans - Required plan types
 * @returns {Object} Validation result
 */
function validateRequiredPlans(subscription, requiredPlans) {
  if (requiredPlans.includes(subscription.plan)) {
    return { valid: true };
  }

  // Check if current plan is higher tier than required
  const planHierarchy = ['starter', 'professional', 'business', 'enterprise'];
  const currentPlanIndex = planHierarchy.indexOf(subscription.plan);
  const requiredPlanIndices = requiredPlans.map(plan => planHierarchy.indexOf(plan));
  const minRequiredIndex = Math.min(...requiredPlanIndices);

  if (currentPlanIndex >= minRequiredIndex && currentPlanIndex !== -1) {
    return { valid: true };
  }

  return {
    valid: false,
    message: `This feature requires one of the following plans: ${requiredPlans.join(', ')}`
  };
}

/**
 * Validate required features
 * @param {Object} tenant - Tenant object
 * @param {Array} requiredFeatures - Required features
 * @returns {Object} Validation result
 */
function validateRequiredFeatures(tenant, requiredFeatures) {
  const availableFeatures = getAvailableFeatures(tenant);
  const missingFeatures = requiredFeatures.filter(feature => !availableFeatures.includes(feature));

  if (missingFeatures.length === 0) {
    return { valid: true, availableFeatures };
  }

  return {
    valid: false,
    availableFeatures,
    missingFeatures,
    message: `This operation requires the following features: ${missingFeatures.join(', ')}`
  };
}

/**
 * Get available features for tenant
 * @param {Object} tenant - Tenant object
 * @returns {Array} Available features
 */
function getAvailableFeatures(tenant) {
  const planFeatures = {
    starter: ['basic_analytics', 'email_support', 'standard_integrations'],
    professional: ['basic_analytics', 'email_support', 'standard_integrations', 'advanced_analytics', 'priority_support', 'custom_branding'],
    business: ['basic_analytics', 'email_support', 'standard_integrations', 'advanced_analytics', 'priority_support', 'custom_branding', 'api_access', 'webhook_integrations', 'sso'],
    enterprise: ['basic_analytics', 'email_support', 'standard_integrations', 'advanced_analytics', 'priority_support', 'custom_branding', 'api_access', 'webhook_integrations', 'sso', 'dedicated_support', 'custom_integrations', 'advanced_security']
  };

  const planBaseFeatures = planFeatures[tenant.subscription?.plan] || planFeatures.starter;
  const tenantSpecificFeatures = tenant.features || [];

  return [...new Set([...planBaseFeatures, ...tenantSpecificFeatures])];
}

/**
 * Check if subscription validation should be skipped
 * @param {Object} req - Express request object
 * @returns {boolean} Whether to skip validation
 */
function shouldSkipSubscriptionValidation(req) {
  // Skip for health checks and internal routes
  const skipPaths = ['/health', '/ping', '/metrics', '/admin'];
  if (skipPaths.some(path => req.path.startsWith(path))) {
    return true;
  }

  // Skip for platform admin users
  if (req.user?.roles?.includes('super_admin') || req.user?.roles?.includes('admin')) {
    return true;
  }

  // Skip for authentication routes
  const authPaths = ['/auth', '/login', '/register', '/verify'];
  if (authPaths.some(path => req.path.startsWith(path))) {
    return true;
  }

  return false;
}

// Pre-configured middleware for common validation scenarios
const requireActiveSubscription = validateSubscription({
  allowTrial: true,
  allowGracePeriod: false
});

const requirePaidSubscription = validateSubscription({
  allowTrial: false,
  allowGracePeriod: true,
  gracePeriodDays: 7
});

const requireBusinessPlan = validateSubscription({
  requiredPlans: ['business', 'enterprise'],
  allowTrial: false
});

const requireEnterprisePlan = validateSubscription({
  requiredPlans: ['enterprise'],
  allowTrial: false
});

const requireAPIAccess = validateSubscription({
  requiredFeatures: ['api_access'],
  allowTrial: false
});

module.exports = {
  validateSubscription,
  requireActiveSubscription,
  requirePaidSubscription,
  requireBusinessPlan,
  requireEnterprisePlan,
  requireAPIAccess,
  validateSubscriptionStatus,
  validateRequiredPlans,
  validateRequiredFeatures,
  getAvailableFeatures,
  shouldSkipSubscriptionValidation
};