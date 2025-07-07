const express = require('express');
const RoleConversionController = require('../controllers/role-conversion-controller');
const { authenticate } = require('../../middleware/auth/auth-middleware')
const { restrictTo } = require('../../middleware/auth/authorization-middleware');
const PermissionMiddleware = require('../../middleware/auth/permission-middleware');

const router = express.Router();

// All routes require authentication
router.use(authenticate());

// Prospect to client upgrade
router.post('/upgrade-to-client',
  restrictTo('prospect'),
  RoleConversionController.upgradeToClient
);

// Admin role management
router.post('/admin/change-user-role',
  restrictTo('super_admin', 'platform_admin'),
  PermissionMiddleware.require('users.manage'),
  RoleConversionController.adminChangeUserRole
);

// Get upgrade options for current user
router.get('/upgrade-options',
  RoleConversionController.getUpgradeOptions
);

module.exports = router;