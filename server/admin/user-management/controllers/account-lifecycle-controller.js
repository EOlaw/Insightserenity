// server/admin/user-management/controllers/account-lifecycle-controller.js
/**
 * @file Account Lifecycle Controller
 * @description Controller for handling account lifecycle management operations
 * @version 1.0.0
 */

// Services
const AccountLifecycleService = require('../services/account-lifecycle-service');
const AdminHelpers = require('../../../shared/admin/utils/admin-helpers');

// Utilities
const { asyncHandler } = require('../../../shared/utils/async-handler');
const { AppError, ValidationError } = require('../../../shared/utils/app-error');
const logger = require('../../../shared/utils/logger');
const { sanitizeQuery, sanitizeBody } = require('../../../shared/utils/sanitizers');
const ResponseFormatter = require('../../../shared/utils/response-formatter');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');
const AdminLimits = require('../../../shared/admin/constants/admin-limits');

/**
 * Account Lifecycle Controller Class
 */
class AccountLifecycleController {
  /**
   * Get account lifecycle overview
   * @route GET /api/admin/users/lifecycle/overview
   */
  getLifecycleOverview = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate time range
    const allowedTimeRanges = ['last24h', 'last7d', 'last30d', 'last90d', 'last365d'];
    const timeRange = queryParams.timeRange || 'last30d';
    
    if (!allowedTimeRanges.includes(timeRange)) {
      throw new ValidationError(`Invalid time range. Allowed values: ${allowedTimeRanges.join(', ')}`);
    }

    // Validate organization ID if provided
    if (queryParams.organizationId && !AdminHelpers.isValidObjectId(queryParams.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    const options = {
      timeRange,
      organizationId: queryParams.organizationId,
      skipCache: queryParams.skipCache === 'true'
    };

    // Get lifecycle overview
    const overview = await AccountLifecycleService.getLifecycleOverview(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(overview, 'Lifecycle overview retrieved successfully')
    );
  });

  /**
   * Configure lifecycle policies
   * @route POST /api/admin/users/lifecycle/policies
   */
  configureLifecyclePolicies = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const policyData = sanitizeBody(req.body);

    // Validate organization ID if provided
    if (policyData.organizationId && !AdminHelpers.isValidObjectId(policyData.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    // Validate policies object
    if (!policyData.policies || typeof policyData.policies !== 'object') {
      throw new ValidationError('Policies configuration is required');
    }

    // Validate specific policy values
    const policies = policyData.policies;

    if (policies.inactivityWarning !== undefined) {
      const days = parseInt(policies.inactivityWarning);
      if (isNaN(days) || days < 1 || days > 365) {
        throw new ValidationError('Inactivity warning must be between 1 and 365 days');
      }
      policies.inactivityWarning = days;
    }

    if (policies.inactivitySuspension !== undefined) {
      const days = parseInt(policies.inactivitySuspension);
      if (isNaN(days) || days < 1 || days > 730) {
        throw new ValidationError('Inactivity suspension must be between 1 and 730 days');
      }
      if (policies.inactivityWarning && days <= policies.inactivityWarning) {
        throw new ValidationError('Inactivity suspension must be greater than inactivity warning');
      }
      policies.inactivitySuspension = days;
    }

    if (policies.inactivityDeletion !== undefined) {
      const days = parseInt(policies.inactivityDeletion);
      if (isNaN(days) || days < 30 || days > 1825) {
        throw new ValidationError('Inactivity deletion must be between 30 and 1825 days (5 years)');
      }
      if (policies.inactivitySuspension && days <= policies.inactivitySuspension) {
        throw new ValidationError('Inactivity deletion must be greater than inactivity suspension');
      }
      policies.inactivityDeletion = days;
    }

    if (policies.trialExpiration !== undefined) {
      const days = parseInt(policies.trialExpiration);
      if (isNaN(days) || days < 1 || days > 90) {
        throw new ValidationError('Trial expiration must be between 1 and 90 days');
      }
      policies.trialExpiration = days;
    }

    if (policies.passwordExpiration !== undefined) {
      const days = parseInt(policies.passwordExpiration);
      if (isNaN(days) || days < 0 || days > 365) {
        throw new ValidationError('Password expiration must be between 0 (disabled) and 365 days');
      }
      policies.passwordExpiration = days;
    }

    if (policies.sessionTimeout !== undefined) {
      const hours = parseInt(policies.sessionTimeout);
      if (isNaN(hours) || hours < 1 || hours > 720) {
        throw new ValidationError('Session timeout must be between 1 and 720 hours (30 days)');
      }
      policies.sessionTimeout = hours;
    }

    if (policies.dataRetention !== undefined) {
      const days = parseInt(policies.dataRetention);
      if (isNaN(days) || days < 365 || days > 3650) {
        throw new ValidationError('Data retention must be between 365 and 3650 days (1-10 years)');
      }
      policies.dataRetention = days;
    }

    // Validate effective date if provided
    if (policyData.effectiveDate) {
      const effectiveDate = new Date(policyData.effectiveDate);
      if (isNaN(effectiveDate.getTime())) {
        throw new ValidationError('Invalid effective date format');
      }
      policyData.effectiveDate = effectiveDate;
    }

    // Configure policies
    const result = await AccountLifecycleService.configureLifecyclePolicies(adminUser, policyData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Lifecycle policies configured successfully')
    );
  });

  /**
   * Transition account lifecycle stage
   * @route POST /api/admin/users/:userId/lifecycle/transition
   */
  transitionAccountLifecycle = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    const transitionData = sanitizeBody(req.body);

    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    // Validate target stage
    const allowedStages = [
      'onboarding',
      'active',
      'inactive',
      'at_risk',
      'churned',
      'reactivated',
      'suspended',
      'deleted'
    ];
    
    if (!transitionData.targetStage || !allowedStages.includes(transitionData.targetStage)) {
      throw new ValidationError(`Invalid target stage. Allowed values: ${allowedStages.join(', ')}`);
    }

    // Validate reason
    if (!transitionData.reason || transitionData.reason.trim().length < 10) {
      throw new ValidationError('Transition reason required (minimum 10 characters)');
    }

    // Prevent certain self-transitions
    if (userId === adminUser.id && ['suspended', 'deleted', 'churned'].includes(transitionData.targetStage)) {
      throw new ValidationError('Cannot transition your own account to this stage');
    }

    // Execute transition
    const result = await AccountLifecycleService.transitionAccountLifecycle(adminUser, userId, transitionData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Account lifecycle transitioned successfully')
    );
  });

  /**
   * Reactivate user account
   * @route POST /api/admin/users/:userId/lifecycle/reactivate
   */
  reactivateAccount = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { userId } = req.params;
    const reactivationData = sanitizeBody(req.body);

    // Validate user ID
    if (!AdminHelpers.isValidObjectId(userId)) {
      throw new ValidationError('Invalid user ID');
    }

    // Validate reason
    if (!reactivationData.reason || reactivationData.reason.trim().length < 10) {
      throw new ValidationError('Reactivation reason required (minimum 10 characters)');
    }

    // Validate trial extension if provided
    if (reactivationData.extendTrial && reactivationData.trialDays !== undefined) {
      const trialDays = parseInt(reactivationData.trialDays);
      if (isNaN(trialDays) || trialDays < 1 || trialDays > 90) {
        throw new ValidationError('Trial extension must be between 1 and 90 days');
      }
      reactivationData.trialDays = trialDays;
    }

    // Validate incentive details if provided
    if (reactivationData.offerIncentive && !reactivationData.incentiveDetails) {
      throw new ValidationError('Incentive details are required when offering incentive');
    }

    if (reactivationData.incentiveDetails) {
      const incentive = reactivationData.incentiveDetails;
      
      if (!incentive.type || !['discount', 'credit', 'free_period', 'upgrade'].includes(incentive.type)) {
        throw new ValidationError('Invalid incentive type');
      }

      if (incentive.type === 'discount' && (!incentive.percentage || incentive.percentage < 1 || incentive.percentage > 100)) {
        throw new ValidationError('Discount percentage must be between 1 and 100');
      }

      if (incentive.type === 'credit' && (!incentive.amount || incentive.amount < 1)) {
        throw new ValidationError('Credit amount must be greater than 0');
      }

      if (incentive.type === 'free_period' && (!incentive.days || incentive.days < 1 || incentive.days > 365)) {
        throw new ValidationError('Free period must be between 1 and 365 days');
      }

      if (incentive.type === 'upgrade' && !incentive.targetPlan) {
        throw new ValidationError('Target plan is required for upgrade incentive');
      }
    }

    // Reactivate account
    const result = await AccountLifecycleService.reactivateAccount(adminUser, userId, reactivationData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Account reactivated successfully')
    );
  });

  /**
   * Schedule account deletion
   * @route POST /api/admin/users/lifecycle/schedule-deletion
   */
  scheduleAccountDeletion = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const deletionData = sanitizeBody(req.body);

    // Validate input
    if (!deletionData.userIds && !deletionData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (deletionData.userIds) {
      if (!Array.isArray(deletionData.userIds)) {
        throw new ValidationError('userIds must be an array');
      }

      // Validate user IDs
      const invalidIds = deletionData.userIds.filter(id => !AdminHelpers.isValidObjectId(id));
      if (invalidIds.length > 0) {
        throw new ValidationError(`Invalid user IDs: ${invalidIds.join(', ')}`);
      }

      // Check limit
      if (deletionData.userIds.length > AdminLimits.LIFECYCLE.MAX_SCHEDULED_DELETIONS) {
        throw new ValidationError(`Cannot schedule deletion for more than ${AdminLimits.LIFECYCLE.MAX_SCHEDULED_DELETIONS} users at once`);
      }

      // Prevent self-deletion
      if (deletionData.userIds.includes(adminUser.id)) {
        throw new ValidationError('Cannot schedule deletion of your own account');
      }
    }

    // Validate deletion date
    if (!deletionData.deletionDate) {
      throw new ValidationError('Deletion date is required');
    }

    const deletionDate = new Date(deletionData.deletionDate);
    if (isNaN(deletionDate.getTime())) {
      throw new ValidationError('Invalid deletion date format');
    }

    const minDate = new Date();
    minDate.setDate(minDate.getDate() + 7); // Minimum 7 days in future
    
    const maxDate = new Date();
    maxDate.setDate(maxDate.getDate() + 365); // Maximum 1 year in future

    if (deletionDate < minDate || deletionDate > maxDate) {
      throw new ValidationError('Deletion date must be between 7 days and 1 year from now');
    }

    // Validate deletion type
    if (deletionData.deletionType && !['soft', 'hard'].includes(deletionData.deletionType)) {
      throw new ValidationError('Invalid deletion type. Allowed values: soft, hard');
    }

    // Validate reason
    if (!deletionData.reason || deletionData.reason.trim().length < 20) {
      throw new ValidationError('Deletion reason required (minimum 20 characters)');
    }

    // Validate notification lead time
    if (deletionData.notificationLeadTime !== undefined) {
      const leadTime = parseInt(deletionData.notificationLeadTime);
      if (isNaN(leadTime) || leadTime < 1 || leadTime > 90) {
        throw new ValidationError('Notification lead time must be between 1 and 90 days');
      }
      deletionData.notificationLeadTime = leadTime;
    }

    // Schedule deletion
    const result = await AccountLifecycleService.scheduleAccountDeletion(adminUser, deletionData);

    res.status(202).json(
      ResponseFormatter.success(result, 'Account deletion scheduled successfully')
    );
  });

  /**
   * Get lifecycle automation rules
   * @route GET /api/admin/users/lifecycle/automation-rules
   */
  getLifecycleAutomationRules = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate organization ID if provided
    if (queryParams.organizationId && !AdminHelpers.isValidObjectId(queryParams.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    // Validate rule type if provided
    const allowedRuleTypes = [
      'inactivity_warning',
      'inactivity_suspension',
      'trial_expiration',
      'password_expiration',
      'at_risk_detection',
      'reactivation_campaign'
    ];
    
    if (queryParams.ruleType && !allowedRuleTypes.includes(queryParams.ruleType)) {
      throw new ValidationError(`Invalid rule type. Allowed values: ${allowedRuleTypes.join(', ')}`);
    }

    const options = {
      organizationId: queryParams.organizationId,
      ruleType: queryParams.ruleType,
      isActive: queryParams.isActive ? queryParams.isActive === 'true' : null
    };

    // Get automation rules
    const rules = await AccountLifecycleService.getLifecycleAutomationRules(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(rules, 'Lifecycle automation rules retrieved successfully')
    );
  });

  /**
   * Create lifecycle automation rule
   * @route POST /api/admin/users/lifecycle/automation-rules
   */
  createLifecycleAutomationRule = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const ruleData = sanitizeBody(req.body);

    // Validate required fields
    if (!ruleData.name || ruleData.name.trim().length < 3) {
      throw new ValidationError('Rule name is required (minimum 3 characters)');
    }

    if (ruleData.name.length > 100) {
      throw new ValidationError('Rule name cannot exceed 100 characters');
    }

    if (!ruleData.trigger || typeof ruleData.trigger !== 'object') {
      throw new ValidationError('Rule trigger configuration is required');
    }

    if (!ruleData.actions || !Array.isArray(ruleData.actions) || ruleData.actions.length === 0) {
      throw new ValidationError('At least one action is required');
    }

    // Validate trigger
    const allowedTriggerTypes = [
      'time_based',
      'event_based',
      'condition_based',
      'manual'
    ];
    
    if (!ruleData.trigger.type || !allowedTriggerTypes.includes(ruleData.trigger.type)) {
      throw new ValidationError(`Invalid trigger type. Allowed values: ${allowedTriggerTypes.join(', ')}`);
    }

    // Validate trigger configuration based on type
    if (ruleData.trigger.type === 'time_based') {
      if (!ruleData.trigger.schedule || typeof ruleData.trigger.schedule !== 'object') {
        throw new ValidationError('Schedule configuration is required for time-based triggers');
      }

      const allowedFrequencies = ['once', 'hourly', 'daily', 'weekly', 'monthly'];
      if (!allowedFrequencies.includes(ruleData.trigger.schedule.frequency)) {
        throw new ValidationError(`Invalid schedule frequency. Allowed values: ${allowedFrequencies.join(', ')}`);
      }
    }

    if (ruleData.trigger.type === 'event_based') {
      if (!ruleData.trigger.event || typeof ruleData.trigger.event !== 'string') {
        throw new ValidationError('Event name is required for event-based triggers');
      }
    }

    if (ruleData.trigger.type === 'condition_based') {
      if (!ruleData.trigger.conditions || !Array.isArray(ruleData.trigger.conditions)) {
        throw new ValidationError('Conditions array is required for condition-based triggers');
      }
    }

    // Validate conditions if provided
    if (ruleData.conditions && Array.isArray(ruleData.conditions)) {
      if (ruleData.conditions.length > AdminLimits.LIFECYCLE.MAX_CONDITIONS_PER_RULE) {
        throw new ValidationError(`Cannot exceed ${AdminLimits.LIFECYCLE.MAX_CONDITIONS_PER_RULE} conditions per rule`);
      }

      ruleData.conditions.forEach((condition, index) => {
        if (!condition.field || !condition.operator || condition.value === undefined) {
          throw new ValidationError(`Invalid condition at index ${index}: field, operator, and value are required`);
        }

        const allowedOperators = ['equals', 'not_equals', 'greater_than', 'less_than', 'contains', 'not_contains', 'in', 'not_in'];
        if (!allowedOperators.includes(condition.operator)) {
          throw new ValidationError(`Invalid operator at condition ${index}. Allowed values: ${allowedOperators.join(', ')}`);
        }
      });
    }

    // Validate actions
    if (ruleData.actions.length > AdminLimits.LIFECYCLE.MAX_ACTIONS_PER_RULE) {
      throw new ValidationError(`Cannot exceed ${AdminLimits.LIFECYCLE.MAX_ACTIONS_PER_RULE} actions per rule`);
    }

    const allowedActionTypes = [
      'send_email',
      'send_notification',
      'change_status',
      'change_lifecycle_stage',
      'add_tag',
      'remove_tag',
      'trigger_webhook',
      'create_task',
      'update_field'
    ];

    ruleData.actions.forEach((action, index) => {
      if (!action.type || !allowedActionTypes.includes(action.type)) {
        throw new ValidationError(`Invalid action type at index ${index}. Allowed values: ${allowedActionTypes.join(', ')}`);
      }

      if (!action.config || typeof action.config !== 'object') {
        throw new ValidationError(`Action configuration is required at index ${index}`);
      }
    });

    // Validate priority
    if (ruleData.priority !== undefined) {
      const priority = parseInt(ruleData.priority);
      if (isNaN(priority) || priority < 1 || priority > 100) {
        throw new ValidationError('Priority must be between 1 and 100');
      }
      ruleData.priority = priority;
    }

    // Validate organization ID if provided
    if (ruleData.organizationId && !AdminHelpers.isValidObjectId(ruleData.organizationId)) {
      throw new ValidationError('Invalid organization ID');
    }

    // Create rule
    const result = await AccountLifecycleService.createLifecycleAutomationRule(adminUser, ruleData);

    res.status(201).json(
      ResponseFormatter.success(result, 'Lifecycle automation rule created successfully')
    );
  });

  /**
   * Update lifecycle automation rule
   * @route PUT /api/admin/users/lifecycle/automation-rules/:ruleId
   */
  updateLifecycleAutomationRule = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { ruleId } = req.params;
    const updateData = sanitizeBody(req.body);

    // Validate rule ID
    if (!ruleId || !AdminHelpers.isValidUUID(ruleId)) {
      throw new ValidationError('Invalid rule ID');
    }

    // Validate update data (similar to create but all fields optional)
    if (updateData.name !== undefined) {
      if (updateData.name.trim().length < 3) {
        throw new ValidationError('Rule name must be at least 3 characters');
      }
      if (updateData.name.length > 100) {
        throw new ValidationError('Rule name cannot exceed 100 characters');
      }
    }

    // Additional validations for other fields...

    // Update rule
    const result = await AccountLifecycleService.updateLifecycleAutomationRule(adminUser, ruleId, updateData);

    res.status(200).json(
      ResponseFormatter.success(result, 'Lifecycle automation rule updated successfully')
    );
  });

  /**
   * Delete lifecycle automation rule
   * @route DELETE /api/admin/users/lifecycle/automation-rules/:ruleId
   */
  deleteLifecycleAutomationRule = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const { ruleId } = req.params;

    // Validate rule ID
    if (!ruleId || !AdminHelpers.isValidUUID(ruleId)) {
      throw new ValidationError('Invalid rule ID');
    }

    // Delete rule
    const result = await AccountLifecycleService.deleteLifecycleAutomationRule(adminUser, ruleId);

    res.status(200).json(
      ResponseFormatter.success(result, 'Lifecycle automation rule deleted successfully')
    );
  });

  /**
   * Get account retention analysis
   * @route GET /api/admin/users/lifecycle/retention-analysis
   */
  getAccountRetentionAnalysis = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate date range
    const startDate = queryParams.startDate ? new Date(queryParams.startDate) : new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
    const endDate = queryParams.endDate ? new Date(queryParams.endDate) : new Date();

    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      throw new ValidationError('Invalid date format');
    }

    if (startDate >= endDate) {
      throw new ValidationError('Start date must be before end date');
    }

    // Validate cohort size
    const allowedCohortSizes = ['day', 'week', 'month', 'quarter'];
    const cohortSize = queryParams.cohortSize || 'month';
    
    if (!allowedCohortSizes.includes(cohortSize)) {
      throw new ValidationError(`Invalid cohort size. Allowed values: ${allowedCohortSizes.join(', ')}`);
    }

    // Validate segment by if provided
    const allowedSegments = ['lifecycle_stage', 'organization', 'plan', 'acquisition_source'];
    if (queryParams.segmentBy && !allowedSegments.includes(queryParams.segmentBy)) {
      throw new ValidationError(`Invalid segment. Allowed values: ${allowedSegments.join(', ')}`);
    }

    const options = {
      startDate: startDate.toISOString(),
      endDate: endDate.toISOString(),
      cohortSize,
      segmentBy: queryParams.segmentBy,
      includeChurnPrediction: queryParams.includeChurnPrediction !== 'false'
    };

    // Get retention analysis
    const analysis = await AccountLifecycleService.getAccountRetentionAnalysis(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(analysis, 'Account retention analysis retrieved successfully')
    );
  });

  /**
   * Get at-risk accounts
   * @route GET /api/admin/users/lifecycle/at-risk
   */
  getAtRiskAccounts = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate risk threshold
    const riskThreshold = queryParams.riskThreshold ? parseFloat(queryParams.riskThreshold) : 0.5;
    if (isNaN(riskThreshold) || riskThreshold < 0 || riskThreshold > 1) {
      throw new ValidationError('Risk threshold must be between 0 and 1');
    }

    // Validate sort options
    const allowedSortFields = ['riskScore', 'lastActiveAt', 'createdAt', 'lifetimeValue'];
    const sortBy = queryParams.sortBy || 'riskScore';
    
    if (!allowedSortFields.includes(sortBy)) {
      throw new ValidationError(`Invalid sort field. Allowed values: ${allowedSortFields.join(', ')}`);
    }

    const options = {
      page: parseInt(queryParams.page) || 1,
      limit: Math.min(parseInt(queryParams.limit) || 20, AdminLimits.PAGINATION.MAX_LIMIT),
      riskThreshold,
      riskFactors: queryParams.riskFactors ? queryParams.riskFactors.split(',').map(f => f.trim()) : null,
      organizationId: queryParams.organizationId,
      sortBy,
      sortOrder: queryParams.sortOrder || 'desc',
      includeRecommendations: queryParams.includeRecommendations !== 'false'
    };

    // Get at-risk accounts
    const result = await AccountLifecycleService.getAtRiskAccounts(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(result, 'At-risk accounts retrieved successfully')
    );
  });

  /**
   * Get lifecycle events history
   * @route GET /api/admin/users/lifecycle/events
   */
  getLifecycleEvents = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate event types if provided
    const allowedEventTypes = [
      'stage_transition',
      'reactivation',
      'suspension',
      'deletion_scheduled',
      'deletion_cancelled',
      'policy_applied',
      'automation_triggered'
    ];
    
    if (queryParams.eventTypes) {
      const requestedTypes = queryParams.eventTypes.split(',').map(t => t.trim());
      const invalidTypes = requestedTypes.filter(t => !allowedEventTypes.includes(t));
      
      if (invalidTypes.length > 0) {
        throw new ValidationError(`Invalid event types: ${invalidTypes.join(', ')}`);
      }
    }

    // Validate user ID if provided
    if (queryParams.userId && !AdminHelpers.isValidObjectId(queryParams.userId)) {
      throw new ValidationError('Invalid user ID');
    }

    const options = {
      page: parseInt(queryParams.page) || 1,
      limit: Math.min(parseInt(queryParams.limit) || 20, AdminLimits.PAGINATION.MAX_LIMIT),
      userId: queryParams.userId,
      eventTypes: queryParams.eventTypes ? queryParams.eventTypes.split(',').map(t => t.trim()) : null,
      startDate: queryParams.startDate,
      endDate: queryParams.endDate,
      sortBy: queryParams.sortBy || 'timestamp',
      sortOrder: queryParams.sortOrder || 'desc'
    };

    // Get lifecycle events
    const events = await AccountLifecycleService.getLifecycleEvents(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(events, 'Lifecycle events retrieved successfully')
    );
  });

  /**
   * Execute lifecycle action manually
   * @route POST /api/admin/users/lifecycle/execute-action
   */
  executeLifecycleAction = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const actionData = sanitizeBody(req.body);

    // Validate action type
    const allowedActions = [
      'send_inactivity_warning',
      'apply_retention_campaign',
      'trigger_reactivation_sequence',
      'process_scheduled_deletions',
      'update_lifecycle_stages',
      'generate_at_risk_report'
    ];
    
    if (!actionData.action || !allowedActions.includes(actionData.action)) {
      throw new ValidationError(`Invalid action. Allowed values: ${allowedActions.join(', ')}`);
    }

    // Validate target users or filters
    if (!actionData.userIds && !actionData.filters) {
      throw new ValidationError('Either userIds or filters must be provided');
    }

    if (actionData.userIds) {
      if (!Array.isArray(actionData.userIds)) {
        throw new ValidationError('userIds must be an array');
      }

      const invalidIds = actionData.userIds.filter(id => !AdminHelpers.isValidObjectId(id));
      if (invalidIds.length > 0) {
        throw new ValidationError(`Invalid user IDs: ${invalidIds.join(', ')}`);
      }
    }

    // Validate reason
    if (!actionData.reason || actionData.reason.trim().length < 10) {
      throw new ValidationError('Action reason required (minimum 10 characters)');
    }

    // Execute action
    const result = await AccountLifecycleService.executeLifecycleAction(adminUser, actionData);

    res.status(202).json(
      ResponseFormatter.success(result, 'Lifecycle action initiated successfully')
    );
  });

  /**
   * Get lifecycle recommendations
   * @route GET /api/admin/users/lifecycle/recommendations
   */
  getLifecycleRecommendations = asyncHandler(async (req, res) => {
    const adminUser = req.adminUser;
    const queryParams = sanitizeQuery(req.query);

    // Validate recommendation types if provided
    const allowedTypes = [
      'retention',
      'reactivation',
      'engagement',
      'risk_mitigation',
      'policy_optimization'
    ];
    
    let recommendationTypes = null;
    if (queryParams.types) {
      recommendationTypes = queryParams.types.split(',').map(t => t.trim());
      const invalidTypes = recommendationTypes.filter(t => !allowedTypes.includes(t));
      
      if (invalidTypes.length > 0) {
        throw new ValidationError(`Invalid recommendation types: ${invalidTypes.join(', ')}`);
      }
    }

    const options = {
      types: recommendationTypes,
      organizationId: queryParams.organizationId,
      maxRecommendations: parseInt(queryParams.maxRecommendations) || 10,
      minConfidence: parseFloat(queryParams.minConfidence) || 0.7
    };

    // Validate max recommendations
    if (options.maxRecommendations < 1 || options.maxRecommendations > 50) {
      throw new ValidationError('Max recommendations must be between 1 and 50');
    }

    // Validate confidence threshold
    if (isNaN(options.minConfidence) || options.minConfidence < 0 || options.minConfidence > 1) {
      throw new ValidationError('Minimum confidence must be between 0 and 1');
    }

    // Get recommendations
    const recommendations = await AccountLifecycleService.getLifecycleRecommendations(adminUser, options);

    res.status(200).json(
      ResponseFormatter.success(recommendations, 'Lifecycle recommendations retrieved successfully')
    );
  });
}

module.exports = new AccountLifecycleController();