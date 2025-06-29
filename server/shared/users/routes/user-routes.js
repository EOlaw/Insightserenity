// server/shared/users/routes/user-routes.js
/**
 * @file User Routes
 * @description API routes for user operations
 * @version 3.0.0
 */

// Commented middlewares only (except authenticate)
const express = require('express');
const router = express.Router();
// const { body, query, param } = require('express-validator');

const { authenticate /*, authorize */ } = require('../../middleware/auth/auth-middleware');
// const { rateLimiter } = require('../../utils/rate-limiter');
// const { uploadSingle } = require('../../utils/file-upload-middleware');
// const { validateRequest } = require('../../utils/validation/validator');
const UserController = require('../controllers/user-controller');
const fileHelper = require('../../utils/helpers/file-helper');


router.get('/me',
  authenticate(),
  UserController.getMe
);

router.put('/me',
  authenticate(),
  // rateLimiter('userUpdate', { max: 10, windowMs: 15 * 60 * 1000 }),
  // [
  //   body('firstName').optional().trim().notEmpty().isLength({ max: 50 }),
  //   body('lastName').optional().trim().notEmpty().isLength({ max: 50 }),
  //   body('middleName').optional().trim().isLength({ max: 50 }),
  //   body('username').optional().trim().isLength({ min: 3, max: 30 })
  //     .matches(/^[a-z0-9_-]+$/),
  //   body('contact.phone.number').optional().isMobilePhone(),
  //   body('contact.address').optional().isObject()
  // ],
  // validateRequest,
  UserController.updateMe
);

router.put('/me/profile',
  authenticate(),
  // rateLimiter('userUpdate', { max: 10, windowMs: 15 * 60 * 1000 }),
  // [
  //   body('displayName').optional().trim().isLength({ max: 100 }),
  //   body('bio.short').optional().trim().isLength({ max: 160 }),
  //   ...
  // ],
  // validateRequest,
  UserController.updateMyProfile
);

router.post('/me/avatar',
  authenticate(),
  fileHelper.upload.image('avatar', {
    folder: 'avatars',
    maxSize: 5 * 1024 * 1024, // 5MB to match the original code
    // allowedTypes: ['image/jpeg', 'image/png', 'image/webp']
  }),
  UserController.updateMyAvatar
);

router.delete('/me/avatar',
  authenticate(),
  UserController.removeMyAvatar
);

router.put('/me/preferences',
  authenticate(),
  // [
  //   body('language').optional().isString(),
  //   ...
  // ],
  // validateRequest,
  UserController.updateMyPreferences
);

router.get('/me/statistics',
  authenticate(),
  UserController.getMyStatistics
);

router.get('/me/export',
  authenticate(),
  // rateLimiter('dataExport', { max: 2, windowMs: 24 * 60 * 60 * 1000 }),
  UserController.exportMyData
);

router.put('/me/skills',
  authenticate(),
  // [
  //   body('skills').isArray(),
  //   ...
  // ],
  // validateRequest,
  UserController.updateMySkills
);

router.put('/me/experience',
  authenticate(),
  // [
  //   body('experience').isArray(),
  //   ...
  // ],
  // validateRequest,
  UserController.updateMyExperience
);

router.put('/me/education',
  authenticate(),
  // [
  //   body('education').isArray(),
  //   ...
  // ],
  // validateRequest,
  UserController.updateMyEducation
);

router.post('/me/switch-organization',
  authenticate(),
  // [
  //   body('organizationId').isMongoId()
  // ],
  // validateRequest,
  UserController.switchOrganization
);

router.get('/:userId/organizations',
  authenticate(),
  // [
  //   param('userId').isMongoId()
  // ],
  // validateRequest,
  UserController.getUserOrganizations
);

router.post('/:userId/organizations',
  authenticate(),
  // authorize('organizations.members.add'),
  // [
  //   param('userId').isMongoId(),
  //   ...
  // ],
  // validateRequest,
  UserController.addUserToOrganization
);

router.delete('/:userId/organizations/:organizationId',
  authenticate(),
  // authorize('organizations.members.remove'),
  // [
  //   param('userId').isMongoId(),
  //   param('organizationId').isMongoId()
  // ],
  // validateRequest,
  UserController.removeUserFromOrganization
);

router.get('/search',
  authenticate(),
  // rateLimiter('search', { max: 30, windowMs: 60 * 1000 }),
  // [
  //   query('q').optional().trim(),
  //   ...
  // ],
  // validateRequest,
  UserController.searchUsers
);

router.get('/',
  authenticate(),
  // authorize('users.view.all'),
  // [
  //   query('page').optional().isInt(),
  //   ...
  // ],
  // validateRequest,
  UserController.getAllUsers
);

router.post('/',
  authenticate(),
  // authorize('users.create'),
  // rateLimiter('adminAction', { max: 20, windowMs: 15 * 60 * 1000 }),
  // [
  //   body('email').isEmail(),
  //   ...
  // ],
  // validateRequest,
  UserController.createUser
);

router.get('/:userId',
  authenticate(),
  // [
  //   param('userId').isMongoId(),
  //   ...
  // ],
  // validateRequest,
  UserController.getUserById
);

router.put('/:userId',
  authenticate(),
  // authorize('users.update'),
  // rateLimiter('adminAction', { max: 20, windowMs: 15 * 60 * 1000 }),
  // [
  //   param('userId').isMongoId()
  // ],
  // validateRequest,
  UserController.updateUser
);

router.delete('/:userId',
  authenticate(),
  // authorize('users.delete'),
  // rateLimiter('adminAction', { max: 10, windowMs: 15 * 60 * 1000 }),
  // [
  //   param('userId').isMongoId()
  // ],
  // validateRequest,
  UserController.deleteUser
);

router.put('/bulk',
  authenticate(),
  // authorize('users.bulk.update'),
  // rateLimiter('adminAction', { max: 5, windowMs: 15 * 60 * 1000 }),
  // [
  //   body('userIds').isArray().notEmpty(),
  //   ...
  // ],
  // validateRequest,
  UserController.bulkUpdateUsers
);

router.get('/:userId/statistics',
  authenticate(),
  // [
  //   param('userId').isMongoId()
  // ],
  // validateRequest,
  UserController.getUserStatistics
);

router.get('/:userId/activity',
  authenticate(),
  // [
  //   param('userId').isMongoId(),
  //   ...
  // ],
  // validateRequest,
  UserController.getUserActivity
);

router.post('/:userId/verify-email',
  authenticate(),
  // authorize('users.verify'),
  // [
  //   param('userId').isMongoId()
  // ],
  // validateRequest,
  UserController.verifyUserEmail
);

router.post('/:userId/suspend',
  authenticate(),
  // authorize('users.suspend'),
  // rateLimiter('adminAction', { max: 10, windowMs: 15 * 60 * 1000 }),
  // [
  //   param('userId').isMongoId(),
  //   ...
  // ],
  // validateRequest,
  UserController.suspendUser
);

router.post('/:userId/reactivate',
  authenticate(),
  // authorize('users.reactivate'),
  // [
  //   param('userId').isMongoId()
  // ],
  // validateRequest,
  UserController.reactivateUser
);

module.exports = router;
// This code is a simplified version of the original user routes, with commented-out middlewares and validation for clarity.
// It includes routes for user profile management, organization management, user search, and administrative actions.