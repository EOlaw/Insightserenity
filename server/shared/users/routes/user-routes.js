// server/shared/users/routes/user-routes.js
/**
 * @file User Routes
 * @description API routes for user operations
 * @version 3.0.0
 */

// const express = require('express');

// const router = express.Router();
// const { body, query, param } = require('express-validator');

// const { authenticate, authorize } = require('../../middleware/auth/auth-middleware');
// const { rateLimiter } = require('../../utils/rate-limiter');
// const { uploadSingle } = require('../../utils/file-upload-middleware');
// const { validateRequest } = require('../../utils/validation/validator');
// const UserController = require('../controllers/user-controller');


// /**
//  * User Routes Configuration
//  */

// // ===========================
// // Current User Routes (Me)
// // ===========================

// /**
//  * @route   GET /api/users/me
//  * @desc    Get current user profile
//  * @access  Private
//  */
// router.get('/me',
//   authenticate(),
//   UserController.getMe
// );

// /**
//  * @route   PUT /api/users/me
//  * @desc    Update current user basic info
//  * @access  Private
//  */
// router.put('/me',
//   authenticate(),
//   rateLimiter('userUpdate', { max: 10, windowMs: 15 * 60 * 1000 }),
//   [
//     body('firstName').optional().trim().notEmpty().isLength({ max: 50 }),
//     body('lastName').optional().trim().notEmpty().isLength({ max: 50 }),
//     body('middleName').optional().trim().isLength({ max: 50 }),
//     body('username').optional().trim().isLength({ min: 3, max: 30 })
//       .matches(/^[a-z0-9_-]+$/).withMessage('Username can only contain lowercase letters, numbers, hyphens, and underscores'),
//     body('contact.phone.number').optional().isMobilePhone(),
//     body('contact.address').optional().isObject()
//   ],
//   validateRequest,
//   UserController.updateMe
// );

// /**
//  * @route   PUT /api/users/me/profile
//  * @desc    Update current user profile details
//  * @access  Private
//  */
// router.put('/me/profile',
//   authenticate(),
//   rateLimiter('userUpdate', { max: 10, windowMs: 15 * 60 * 1000 }),
//   [
//     body('displayName').optional().trim().isLength({ max: 100 }),
//     body('bio.short').optional().trim().isLength({ max: 160 }),
//     body('bio.full').optional().trim().isLength({ max: 2000 }),
//     body('title').optional().trim().isLength({ max: 100 }),
//     body('department').optional().trim().isLength({ max: 100 }),
//     body('location').optional().trim().isLength({ max: 100 }),
//     body('timezone').optional().isIn(Intl.supportedValuesOf('timeZone')),
//     body('dateOfBirth').optional().isISO8601().custom((value) => {
//       const age = Math.floor((new Date() - new Date(value)) / (365.25 * 24 * 60 * 60 * 1000));
//       if (age < 16 || age > 120) {
//         throw new Error('User must be between 16 and 120 years old');
//       }
//       return true;
//     }),
//     body('gender').optional().isIn(['male', 'female', 'other', 'prefer_not_to_say']),
//     body('languages').optional().isArray(),
//     body('socialLinks').optional().isObject()
//   ],
//   validateRequest,
//   UserController.updateMyProfile
// );

// /**
//  * @route   POST /api/users/me/avatar
//  * @desc    Upload/update user avatar
//  * @access  Private
//  */
// router.post('/me/avatar',
//   authenticate(),
//   rateLimiter('fileUpload', { max: 5, windowMs: 15 * 60 * 1000 }),
//   // uploadSingle('avatar', {
//   //   allowedTypes: ['image/jpeg', 'image/png', 'image/webp'],
//   //   maxSize: 5 * 1024 * 1024 // 5MB
//   // }),
//   UserController.updateMyAvatar
// );

// /**
//  * @route   DELETE /api/users/me/avatar
//  * @desc    Remove user avatar
//  * @access  Private
//  */
// router.delete('/me/avatar',
//   authenticate(),
//   UserController.removeMyAvatar
// );

// /**
//  * @route   PUT /api/users/me/preferences
//  * @desc    Update user preferences
//  * @access  Private
//  */
// router.put('/me/preferences',
//   authenticate(),
//   [
//     body('language').optional().isString(),
//     body('timezone').optional().isIn(Intl.supportedValuesOf('timeZone')),
//     body('dateFormat').optional().isString(),
//     body('timeFormat').optional().isIn(['12h', '24h']),
//     body('currency').optional().isISO4217(),
//     body('theme').optional().isIn(['light', 'dark', 'auto']),
//     body('emailNotifications').optional().isObject(),
//     body('pushNotifications').optional().isObject(),
//     body('privacy').optional().isObject(),
//     body('accessibility').optional().isObject()
//   ],
//   validateRequest,
//   UserController.updateMyPreferences
// );

// /**
//  * @route   GET /api/users/me/statistics
//  * @desc    Get current user statistics
//  * @access  Private
//  */
// router.get('/me/statistics',
//   authenticate(),
//   UserController.getMyStatistics
// );

// /**
//  * @route   GET /api/users/me/export
//  * @desc    Export current user data (GDPR)
//  * @access  Private
//  */
// router.get('/me/export',
//   authenticate(),
//   rateLimiter('dataExport', { max: 2, windowMs: 24 * 60 * 60 * 1000 }), // 2 per day
//   UserController.exportMyData
// );

// // ===========================
// // Professional Profile Routes
// // ===========================

// /**
//  * @route   PUT /api/users/me/skills
//  * @desc    Update user skills
//  * @access  Private
//  */
// router.put('/me/skills',
//   authenticate(),
//   [
//     body('skills').isArray(),
//     body('skills.*.name').notEmpty().trim(),
//     body('skills.*.category').optional().trim(),
//     body('skills.*.level').optional().isIn(['beginner', 'intermediate', 'advanced', 'expert']),
//     body('skills.*.yearsOfExperience').optional().isInt({ min: 0, max: 50 })
//   ],
//   validateRequest,
//   UserController.updateMySkills
// );

// /**
//  * @route   PUT /api/users/me/experience
//  * @desc    Update work experience
//  * @access  Private
//  */
// router.put('/me/experience',
//   authenticate(),
//   [
//     body('experience').isArray(),
//     body('experience.*.company').notEmpty().trim(),
//     body('experience.*.title').notEmpty().trim(),
//     body('experience.*.location').optional().trim(),
//     body('experience.*.startDate').isISO8601(),
//     body('experience.*.endDate').optional().isISO8601(),
//     body('experience.*.current').optional().isBoolean(),
//     body('experience.*.description').optional().trim().isLength({ max: 2000 }),
//     body('experience.*.achievements').optional().isArray()
//   ],
//   validateRequest,
//   UserController.updateMyExperience
// );

// /**
//  * @route   PUT /api/users/me/education
//  * @desc    Update education history
//  * @access  Private
//  */
// router.put('/me/education',
//   authenticate(),
//   [
//     body('education').isArray(),
//     body('education.*.institution').notEmpty().trim(),
//     body('education.*.degree').notEmpty().trim(),
//     body('education.*.fieldOfStudy').optional().trim(),
//     body('education.*.startDate').isISO8601(),
//     body('education.*.endDate').optional().isISO8601(),
//     body('education.*.grade').optional().trim(),
//     body('education.*.activities').optional().trim(),
//     body('education.*.description').optional().trim().isLength({ max: 1000 })
//   ],
//   validateRequest,
//   UserController.updateMyEducation
// );

// // ===========================
// // Organization Routes
// // ===========================

// /**
//  * @route   POST /api/users/me/switch-organization
//  * @desc    Switch current organization
//  * @access  Private
//  */
// router.post('/me/switch-organization',
//   authenticate(),
//   [
//     body('organizationId').isMongoId().withMessage('Valid organization ID required')
//   ],
//   validateRequest,
//   UserController.switchOrganization
// );

// /**
//  * @route   GET /api/users/:userId/organizations
//  * @desc    Get user's organizations
//  * @access  Private
//  */
// router.get('/:userId/organizations',
//   authenticate(),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required')
//   ],
//   validateRequest,
//   UserController.getUserOrganizations
// );

// /**
//  * @route   POST /api/users/:userId/organizations
//  * @desc    Add user to organization
//  * @access  Private (Organization Admin)
//  */
// router.post('/:userId/organizations',
//   authenticate(),
//   authorize('organizations.members.add'),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required'),
//     body('organizationId').isMongoId().withMessage('Valid organization ID required'),
//     body('role').notEmpty().trim(),
//     body('department').optional().trim()
//   ],
//   validateRequest,
//   UserController.addUserToOrganization
// );

// /**
//  * @route   DELETE /api/users/:userId/organizations/:organizationId
//  * @desc    Remove user from organization
//  * @access  Private (Organization Admin)
//  */
// router.delete('/:userId/organizations/:organizationId',
//   authenticate(),
//   authorize('organizations.members.remove'),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required'),
//     param('organizationId').isMongoId().withMessage('Valid organization ID required')
//   ],
//   validateRequest,
//   UserController.removeUserFromOrganization
// );

// // ===========================
// // User Search and Discovery
// // ===========================

// /**
//  * @route   GET /api/users/search
//  * @desc    Search users
//  * @access  Private
//  */
// router.get('/search',
//   authenticate(),
//   rateLimiter('search', { max: 30, windowMs: 60 * 1000 }), // 30 per minute
//   [
//     query('q').optional().trim(),
//     query('userType').optional().isString(),
//     query('role').optional().isString(),
//     query('organizationId').optional().isMongoId(),
//     query('status').optional().isIn(['active', 'inactive', 'suspended']),
//     query('skills').optional().isString(),
//     query('location').optional().isString(),
//     query('activelyLooking').optional().isBoolean(),
//     query('page').optional().isInt({ min: 1 }).toInt(),
//     query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
//     query('sort').optional().isString()
//   ],
//   validateRequest,
//   UserController.searchUsers
// );

// // ===========================
// // User Management (Admin)
// // ===========================

// /**
//  * @route   GET /api/users
//  * @desc    Get all users (admin)
//  * @access  Private (Admin)
//  */
// router.get('/',
//   authenticate(),
//   authorize('users.view.all'),
//   [
//     query('page').optional().isInt({ min: 1 }).toInt(),
//     query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
//     query('sort').optional().isString(),
//     query('status').optional().isString(),
//     query('userType').optional().isString(),
//     query('role').optional().isString(),
//     query('organizationId').optional().isMongoId()
//   ],
//   validateRequest,
//   UserController.getAllUsers
// );

// /**
//  * @route   POST /api/users
//  * @desc    Create new user (admin)
//  * @access  Private (Admin)
//  */
// router.post('/',
//   authenticate(),
//   authorize('users.create'),
//   rateLimiter('adminAction', { max: 20, windowMs: 15 * 60 * 1000 }),
//   [
//     body('email').isEmail().normalizeEmail(),
//     body('firstName').trim().notEmpty().isLength({ max: 50 }),
//     body('lastName').trim().notEmpty().isLength({ max: 50 }),
//     body('userType').isIn(['core_consultant', 'hosted_org_user', 'job_seeker', 'recruitment_partner']),
//     body('role.primary').notEmpty(),
//     body('password').optional().isLength({ min: 12 }),
//     body('sendWelcomeEmail').optional().isBoolean()
//   ],
//   validateRequest,
//   UserController.createUser
// );

// /**
//  * @route   GET /api/users/:userId
//  * @desc    Get user by ID
//  * @access  Private
//  */
// router.get('/:userId',
//   authenticate(),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required'),
//     query('fields').optional().isString()
//   ],
//   validateRequest,
//   UserController.getUserById
// );

// /**
//  * @route   PUT /api/users/:userId
//  * @desc    Update user (admin)
//  * @access  Private (Admin)
//  */
// router.put('/:userId',
//   authenticate(),
//   authorize('users.update'),
//   rateLimiter('adminAction', { max: 20, windowMs: 15 * 60 * 1000 }),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required')
//   ],
//   validateRequest,
//   UserController.updateUser
// );

// /**
//  * @route   DELETE /api/users/:userId
//  * @desc    Delete user (admin)
//  * @access  Private (Admin)
//  */
// router.delete('/:userId',
//   authenticate(),
//   authorize('users.delete'),
//   rateLimiter('adminAction', { max: 10, windowMs: 15 * 60 * 1000 }),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required')
//   ],
//   validateRequest,
//   UserController.deleteUser
// );

// /**
//  * @route   PUT /api/users/bulk
//  * @desc    Bulk update users (admin)
//  * @access  Private (Admin)
//  */
// router.put('/bulk',
//   authenticate(),
//   authorize('users.bulk.update'),
//   rateLimiter('adminAction', { max: 5, windowMs: 15 * 60 * 1000 }),
//   [
//     body('userIds').isArray().notEmpty(),
//     body('userIds.*').isMongoId(),
//     body('updateData').isObject().notEmpty()
//   ],
//   validateRequest,
//   UserController.bulkUpdateUsers
// );

// // ===========================
// // User Statistics and Activity
// // ===========================

// /**
//  * @route   GET /api/users/:userId/statistics
//  * @desc    Get user statistics
//  * @access  Private
//  */
// router.get('/:userId/statistics',
//   authenticate(),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required')
//   ],
//   validateRequest,
//   UserController.getUserStatistics
// );

// /**
//  * @route   GET /api/users/:userId/activity
//  * @desc    Get user activity log
//  * @access  Private (Admin or Self)
//  */
// router.get('/:userId/activity',
//   authenticate(),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required'),
//     query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
//     query('offset').optional().isInt({ min: 0 }).toInt()
//   ],
//   validateRequest,
//   UserController.getUserActivity
// );

// // ===========================
// // User Account Management
// // ===========================

// /**
//  * @route   POST /api/users/:userId/verify-email
//  * @desc    Verify user email (admin)
//  * @access  Private (Admin)
//  */
// router.post('/:userId/verify-email',
//   authenticate(),
//   authorize('users.verify'),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required')
//   ],
//   validateRequest,
//   UserController.verifyUserEmail
// );

// /**
//  * @route   POST /api/users/:userId/suspend
//  * @desc    Suspend user account
//  * @access  Private (Admin)
//  */
// router.post('/:userId/suspend',
//   authenticate(),
//   authorize('users.suspend'),
//   rateLimiter('adminAction', { max: 10, windowMs: 15 * 60 * 1000 }),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required'),
//     body('reason').trim().notEmpty(),
//     body('duration').optional().isInt({ min: 1 }) // Days
//   ],
//   validateRequest,
//   UserController.suspendUser
// );

// /**
//  * @route   POST /api/users/:userId/reactivate
//  * @desc    Reactivate suspended user
//  * @access  Private (Admin)
//  */
// router.post('/:userId/reactivate',
//   authenticate(),
//   authorize('users.reactivate'),
//   [
//     param('userId').isMongoId().withMessage('Valid user ID required')
//   ],
//   validateRequest,
//   UserController.reactivateUser
// );

// // ===========================
// // Export Router
// // ===========================

// module.exports = router;

// Commented middlewares only (except authenticate)
const express = require('express');
const router = express.Router();
// const { body, query, param } = require('express-validator');

const { authenticate /*, authorize */ } = require('../../middleware/auth/auth-middleware');
// const { rateLimiter } = require('../../utils/rate-limiter');
// const { uploadSingle } = require('../../utils/file-upload-middleware');
// const { validateRequest } = require('../../utils/validation/validator');
const UserController = require('../controllers/user-controller');

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
  // rateLimiter('fileUpload', { max: 5, windowMs: 15 * 60 * 1000 }),
  // uploadSingle('avatar', { allowedTypes: [...], maxSize: ... }),
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