// server/admin/super-admin/routes/emergency-access-routes.js
/**
 * @file Emergency Access Routes
 * @description Route definitions for emergency access and critical system operations
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const EmergencyAccessController = require('../controllers/emergency-access-controller');

// Middleware
const { authenticate } = require('../../../shared/middleware/auth');
const { authorize } = require('../../../shared/middleware/authorization');
const SuperAdminOnly = require('../middleware/super-admin-only');
const CriticalOperation = require('../middleware/critical-operation');
const EmergencyBypass = require('../middleware/emergency-bypass');
const { validateRequest } = require('../../../shared/middleware/validate-request');
const { rateLimiter } = require('../../../shared/middleware/rate-limiter');
const { auditLog } = require('../../../shared/middleware/audit-logger');
const { sanitize } = require('../../../shared/middleware/sanitizer');
const { cache } = require('../../../shared/middleware/cache');
const { requireVideoAuth } = require('../../../shared/middleware/video-auth');
const { alertSecurityTeam } = require('../../../shared/middleware/security-alert');

// Validation
const EmergencyAccessValidation = require('../validation/emergency-access-validation');

// Constants
const AdminPermissions = require('../../../shared/admin/constants/admin-permissions');

/**
 * Emergency Access Routes
 * Base path: /api/admin/super-admin/emergency-access
 */

// Apply authentication to all routes
router.use(authenticate);

// Apply super admin only middleware to all routes
router.use(SuperAdminOnly.enforce({
  requireMFA: true,
  requireActiveSession: true,
  checkIPWhitelist: true,
  auditAccess: true,
  allowEmergencyAccess: true,
  customPermission: AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS
}));

// Apply emergency bypass check
router.use(EmergencyBypass.check({
  allowedTypes: ['FULL_OVERRIDE', 'SYSTEM_LOCKS'],
  requireActiveEmergencyAccess: true,
  monitorActions: true,
  alertOnUse: true
}));

/**
 * Emergency Access Request Routes
 */

/**
 * @route   POST /api/admin/super-admin/emergency-access/request
 * @desc    Request emergency access
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/request',
  rateLimiter('emergency_request', { max: 3, window: 3600, skipSuccessfulRequests: false }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'request'),
  CriticalOperation.protect('emergency.access.grant', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(EmergencyAccessValidation.requestAccess, 'body'),
  sanitize(['body.reason']),
  alertSecurityTeam('emergency_access_requested'),
  auditLog('emergency.access.requested', { critical: true, alert: true }),
  EmergencyAccessController.requestEmergencyAccess
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/:requestId/activate
 * @desc    Activate emergency access with authentication codes
 * @access  Super Admin
 */
router.post(
  '/:requestId/activate',
  rateLimiter('emergency_activate', { max: 5, window: 300, skipSuccessfulRequests: false }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'activate'),
  validateRequest(EmergencyAccessValidation.activateAccess),
  alertSecurityTeam('emergency_access_activated'),
  auditLog('emergency.access.activated', { critical: true, alert: true }),
  EmergencyAccessController.activateEmergencyAccess
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/:requestId/revoke
 * @desc    Revoke active emergency access
 * @access  Super Admin
 */
router.post(
  '/:requestId/revoke',
  rateLimiter('emergency_revoke', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'revoke'),
  validateRequest(EmergencyAccessValidation.revokeAccess),
  alertSecurityTeam('emergency_access_revoked'),
  auditLog('emergency.access.revoked', { critical: true }),
  EmergencyAccessController.revokeEmergencyAccess
);

/**
 * @route   GET /api/admin/super-admin/emergency-access/active
 * @desc    Get active emergency access sessions
 * @access  Super Admin
 */
router.get(
  '/active',
  rateLimiter('emergency_active', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'read'),
  cache({ ttl: 60, key: 'active_emergency_sessions' }),
  auditLog('emergency.sessions.viewed'),
  EmergencyAccessController.getActiveEmergencySessions
);

/**
 * @route   GET /api/admin/super-admin/emergency-access/statistics
 * @desc    Get emergency access statistics
 * @access  Super Admin
 */
router.get(
  '/statistics',
  rateLimiter('emergency_stats', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'read'),
  cache({ ttl: 300, key: 'emergency_statistics' }),
  auditLog('emergency.statistics.accessed'),
  EmergencyAccessController.getEmergencyAccessStatistics
);

/**
 * Break Glass Access Routes
 */

/**
 * @route   POST /api/admin/super-admin/emergency-access/break-glass
 * @desc    Activate break glass emergency access
 * @access  Super Admin + Critical Operation + Video Auth
 */
router.post(
  '/break-glass',
  rateLimiter('break_glass', { max: 1, window: 86400, skipSuccessfulRequests: false }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'break_glass'),
  requireVideoAuth({ required: true, biometrics: ['face', 'voice'] }),
  CriticalOperation.protect('emergency.bypass.activate', {
    requireDualAuth: true,
    requireVideoAuth: true,
    notifyAllAdmins: true
  }),
  validateRequest(EmergencyAccessValidation.breakGlass, 'body'),
  alertSecurityTeam('break_glass_activated', { priority: 'critical' }),
  auditLog('emergency.break.glass.activated', { critical: true, alert: true }),
  EmergencyAccessController.createBreakGlassAccess
);

/**
 * System Bypass Routes
 */

/**
 * @route   POST /api/admin/super-admin/emergency-access/bypass
 * @desc    Execute system bypass
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/bypass',
  rateLimiter('system_bypass', { max: 5, window: 3600, skipSuccessfulRequests: false }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'bypass'),
  CriticalOperation.protect('emergency.bypass.activate', {
    requireDualAuth: false,
    recordDetailed: true
  }),
  validateRequest(EmergencyAccessValidation.systemBypass, 'body'),
  alertSecurityTeam('system_bypass_executed'),
  auditLog('emergency.bypass.executed', { critical: true, alert: true }),
  EmergencyAccessController.executeSystemBypass
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/unlock
 * @desc    Unlock system resources
 * @access  Super Admin
 */
router.post(
  '/unlock',
  rateLimiter('system_unlock', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'unlock'),
  validateRequest(EmergencyAccessValidation.unlockResources, 'body'),
  auditLog('emergency.resources.unlocked', { critical: false }),
  EmergencyAccessController.unlockSystemResources
);

/**
 * Emergency Audit and Reporting Routes
 */

/**
 * @route   GET /api/admin/super-admin/emergency-access/:requestId/audit
 * @desc    Get emergency access audit trail
 * @access  Super Admin
 */
router.get(
  '/:requestId/audit',
  rateLimiter('emergency_audit', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'audit'),
  cache({ ttl: 300, key: req => `emergency_audit_${req.params.requestId}` }),
  auditLog('emergency.audit.accessed'),
  EmergencyAccessController.getEmergencyAccessAuditTrail
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/reports/generate
 * @desc    Generate emergency access report
 * @access  Super Admin
 */
router.post(
  '/reports/generate',
  rateLimiter('emergency_report', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'report'),
  validateRequest(EmergencyAccessValidation.generateReport, 'body'),
  auditLog('emergency.report.generated'),
  EmergencyAccessController.generateEmergencyAccessReport
);

/**
 * Emergency Testing and Simulation Routes
 */

/**
 * @route   POST /api/admin/super-admin/emergency-access/test
 * @desc    Test emergency procedures
 * @access  Super Admin
 */
router.post(
  '/test',
  rateLimiter('emergency_test', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'test'),
  validateRequest(EmergencyAccessValidation.testProcedures, 'body'),
  auditLog('emergency.procedures.tested'),
  EmergencyAccessController.testEmergencyProcedures
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/simulate
 * @desc    Simulate emergency scenario
 * @access  Super Admin
 */
router.post(
  '/simulate',
  rateLimiter('emergency_simulate', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'simulate'),
  validateRequest(EmergencyAccessValidation.simulateScenario, 'body'),
  auditLog('emergency.scenario.simulated'),
  EmergencyAccessController.simulateEmergencyScenario
);

/**
 * Emergency Configuration Routes
 */

/**
 * @route   PUT /api/admin/super-admin/emergency-access/contacts
 * @desc    Configure emergency contacts
 * @access  Super Admin
 */
router.put(
  '/contacts',
  rateLimiter('emergency_contacts', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'configure'),
  validateRequest(EmergencyAccessValidation.configureContacts, 'body'),
  auditLog('emergency.contacts.configured'),
  EmergencyAccessController.configureEmergencyContacts
);

/**
 * @route   GET /api/admin/super-admin/emergency-access/protocols
 * @desc    Get emergency protocols
 * @access  Super Admin
 */
router.get(
  '/protocols',
  rateLimiter('emergency_protocols', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'read'),
  cache({ ttl: 600, key: 'emergency_protocols' }),
  auditLog('emergency.protocols.accessed'),
  EmergencyAccessController.getEmergencyProtocols
);

/**
 * @route   PUT /api/admin/super-admin/emergency-access/protocols/:protocolId
 * @desc    Update emergency protocol
 * @access  Super Admin
 */
router.put(
  '/protocols/:protocolId',
  rateLimiter('emergency_protocol_update', { max: 10, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'update'),
  validateRequest(EmergencyAccessValidation.updateProtocol),
  auditLog('emergency.protocol.updated'),
  EmergencyAccessController.updateEmergencyProtocol
);

/**
 * Emergency Review and Approval Routes
 */

/**
 * @route   POST /api/admin/super-admin/emergency-access/:requestId/review
 * @desc    Review emergency access request
 * @access  Super Admin
 */
router.post(
  '/:requestId/review',
  rateLimiter('emergency_review', { max: 20, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'review'),
  validateRequest(EmergencyAccessValidation.reviewRequest),
  auditLog('emergency.request.reviewed', { critical: true }),
  EmergencyAccessController.reviewEmergencyAccessRequest
);

/**
 * System Recovery Routes
 */

/**
 * @route   GET /api/admin/super-admin/emergency-access/recovery-options
 * @desc    Get system recovery options
 * @access  Super Admin
 */
router.get(
  '/recovery-options',
  rateLimiter('recovery_options', { max: 20, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'recovery'),
  cache({ ttl: 300, key: 'recovery_options' }),
  auditLog('emergency.recovery.options.accessed'),
  EmergencyAccessController.getSystemRecoveryOptions
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/recovery/execute
 * @desc    Execute recovery procedure
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/recovery/execute',
  rateLimiter('recovery_execute', { max: 3, window: 3600, skipSuccessfulRequests: false }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'recovery'),
  CriticalOperation.protect('system.recovery.execute', {
    requireDualAuth: true,
    requireVideoAuth: req => req.body.recoveryType === 'full_system_restore',
    notifyAllAdmins: true
  }),
  validateRequest(EmergencyAccessValidation.executeRecovery, 'body'),
  alertSecurityTeam('system_recovery_initiated', { priority: 'critical' }),
  auditLog('emergency.recovery.executed', { critical: true, alert: true }),
  EmergencyAccessController.executeRecoveryProcedure
);

/**
 * Emergency Session Management Routes
 */

/**
 * @route   GET /api/admin/super-admin/emergency-access/sessions
 * @desc    List all emergency sessions (active and historical)
 * @access  Super Admin
 */
router.get(
  '/sessions',
  rateLimiter('emergency_sessions', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'read'),
  cache({ ttl: 300, key: 'emergency_sessions' }),
  auditLog('emergency.sessions.listed'),
  EmergencyAccessController.listEmergencySessions
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/sessions/:sessionId/extend
 * @desc    Extend emergency access session
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/sessions/:sessionId/extend',
  rateLimiter('emergency_extend', { max: 5, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'extend'),
  CriticalOperation.protect('emergency.session.extend', {
    requireDualAuth: true,
    recordDetailed: true
  }),
  alertSecurityTeam('emergency_session_extended'),
  auditLog('emergency.session.extended', { critical: true }),
  EmergencyAccessController.extendEmergencySession
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/sessions/:sessionId/handover
 * @desc    Handover emergency access to another admin
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/sessions/:sessionId/handover',
  rateLimiter('emergency_handover', { max: 3, window: 3600 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'handover'),
  CriticalOperation.protect('emergency.session.handover', {
    requireDualAuth: true,
    notifyAllAdmins: true
  }),
  alertSecurityTeam('emergency_session_handover'),
  auditLog('emergency.session.handover', { critical: true, alert: true }),
  EmergencyAccessController.handoverEmergencySession
);

/**
 * Emergency Bypass Management Routes
 */

/**
 * @route   POST /api/admin/super-admin/emergency-access/bypass/create
 * @desc    Create emergency bypass token
 * @access  Super Admin + Critical Operation
 */
router.post(
  '/bypass/create',
  rateLimiter('bypass_create', { max: 5, window: 3600, skipSuccessfulRequests: false }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'bypass'),
  EmergencyBypass.create({
    requireJustification: true,
    autoExpire: true,
    notifySecurityTeam: true
  }),
  auditLog('emergency.bypass.created', { critical: true, alert: true }),
  EmergencyAccessController.createBypassToken
);

/**
 * @route   POST /api/admin/super-admin/emergency-access/bypass/:bypassId/revoke
 * @desc    Revoke emergency bypass
 * @access  Super Admin
 */
router.post(
  '/bypass/:bypassId/revoke',
  rateLimiter('bypass_revoke', { max: 10, window: 300 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'revoke'),
  auditLog('emergency.bypass.revoked', { critical: true }),
  EmergencyAccessController.revokeBypass
);

/**
 * @route   GET /api/admin/super-admin/emergency-access/bypass/active
 * @desc    List active bypasses
 * @access  Super Admin
 */
router.get(
  '/bypass/active',
  rateLimiter('bypass_list', { max: 30, window: 60 }),
  authorize(AdminPermissions.SUPER_ADMIN.EMERGENCY_ACCESS, 'read'),
  cache({ ttl: 60, key: 'active_bypasses' }),
  auditLog('emergency.bypasses.listed'),
  EmergencyAccessController.listActiveBypasses
);

/**
 * Error handling middleware for emergency access routes
 */
router.use((error, req, res, next) => {
  // Log all emergency access errors as critical
  logger.critical('Emergency access route error', {
    error: error.message,
    path: req.path,
    method: req.method,
    user: req.user?.id,
    requestId: req.params?.requestId,
    emergencyAccess: req.emergencyAccess,
    stack: error.stack
  });

  // Alert security team on any emergency access errors
  SecurityService.alertSecurityTeam({
    event: 'emergency_access_error',
    severity: 'critical',
    error: error.message,
    user: req.user?.email,
    path: req.path
  }).catch(err => logger.error('Failed to alert security team', err));

  next(error);
});

module.exports = router;