// server/core-business/reports/routes/reports-routes.js
/**
 * @file Reports Routes
 * @description API routes for reports management
 * @version 3.0.0
 */

const express = require('express');
const router = express.Router();

// Controllers
const ReportsController = require('../controllers/reports-controller');

// Middleware
const { authenticate } = require('../../../shared/middleware/auth/auth-middleware');
const { authorize } = require('../../../shared/middleware/auth/permission-middleware');
const { validateRequest } = require('../../../shared/middleware/request-validator');
const { rateLimiter } = require('../../../shared/utils/rate-limiter');
const fileHelper = require('../../../shared/utils/helpers/file-helper');

// Validation schemas
const {
  createReportSchema,
  updateReportSchema,
  listReportsSchema,
  executeReportSchema,
  exportReportSchema,
  shareReportSchema,
  cloneReportSchema,
  scheduleReportSchema,
  testQuerySchema,
  bulkOperationSchema,
  reportIdSchema,
  executionIdSchema,
  templateSchema,
  statisticsQuerySchema,
  activityLogSchema,
  accessLogSchema,
  updateAccessSchema
} = require('../validation/reports-validation');

/**
 * Apply authentication to all routes
 */
router.use(authenticate());

/**
 * Report CRUD Operations
 */

// List reports
router.get('/',
  authorize(['report.read', 'report.admin']),
  validateRequest(listReportsSchema),
  rateLimiter('reports-list', { max: 100, windowMs: 60 * 1000 }), // 100 requests per minute
  ReportsController.listReports
);

// Get report statistics
router.get('/statistics',
  authorize(['report.read', 'report.admin', 'manager', 'admin']),
  validateRequest(statisticsQuerySchema),
  rateLimiter('reports-stats', { max: 30, windowMs: 60 * 1000 }),
  ReportsController.getStatistics
);

// Get report templates
router.get('/templates',
  authorize(['report.create', 'report.admin']),
  rateLimiter('reports-templates', { max: 50, windowMs: 60 * 1000 }),
  ReportsController.getTemplates
);

// Test report query (Admin only)
router.post('/test-query',
  authorize(['report.admin', 'admin']),
  validateRequest(testQuerySchema),
  rateLimiter('reports-test-query', { max: 10, windowMs: 60 * 1000 }),
  ReportsController.testQuery
);

// Create report from template
router.post('/from-template',
  authorize(['report.create', 'report.admin']),
  validateRequest(templateSchema),
  rateLimiter('reports-create', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  ReportsController.createFromTemplate
);

// Bulk operations (Admin only)
router.post('/bulk',
  authorize(['report.admin', 'admin']),
  validateRequest(bulkOperationSchema),
  rateLimiter('reports-bulk', { max: 5, windowMs: 60 * 60 * 1000 }), // 5 per hour
  ReportsController.bulkOperation
);

// Create new report
router.post('/',
  authorize(['report.create', 'report.admin']),
  validateRequest(createReportSchema),
  rateLimiter('reports-create', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  ReportsController.createReport
);

// Get specific report
router.get('/:reportId',
  authorize(['report.read', 'report.admin']),
  validateRequest(reportIdSchema),
  rateLimiter('reports-read', { max: 200, windowMs: 60 * 1000 }), // 200 per minute
  ReportsController.getReport
);

// Update report
router.put('/:reportId',
  authorize(['report.update', 'report.admin']),
  validateRequest(updateReportSchema),
  rateLimiter('reports-update', { max: 50, windowMs: 60 * 1000 }),
  ReportsController.updateReport
);

// Delete report
router.delete('/:reportId',
  authorize(['report.delete', 'report.admin']),
  validateRequest(reportIdSchema),
  rateLimiter('reports-delete', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  ReportsController.deleteReport
);

/**
 * Report Execution Routes
 */

// Execute report
router.post('/:reportId/execute',
  authorize(['report.run', 'report.read', 'report.admin']),
  validateRequest(executeReportSchema),
  rateLimiter('reports-execute', { max: 30, windowMs: 60 * 1000 }), // 30 per minute
  ReportsController.executeReport
);

// Get execution status
router.get('/:reportId/executions/:executionId',
  authorize(['report.read', 'report.admin']),
  validateRequest(executionIdSchema),
  rateLimiter('reports-execution-status', { max: 100, windowMs: 60 * 1000 }),
  ReportsController.getExecutionStatus
);

/**
 * Report Export Routes
 */

// Export report
router.post('/:reportId/export',
  authorize(['report.export', 'report.read', 'report.admin']),
  validateRequest(exportReportSchema),
  rateLimiter('reports-export', { max: 20, windowMs: 60 * 60 * 1000 }), // 20 per hour
  ReportsController.exportReport
);

/**
 * Report Sharing Routes
 */

// Share report
router.post('/:reportId/share',
  authorize(['report.share', 'report.admin']),
  validateRequest(shareReportSchema),
  rateLimiter('reports-share', { max: 30, windowMs: 60 * 60 * 1000 }), // 30 per hour
  ReportsController.shareReport
);

// Unshare report
router.delete('/:reportId/share/:userId',
  authorize(['report.share', 'report.admin']),
  rateLimiter('reports-unshare', { max: 30, windowMs: 60 * 60 * 1000 }),
  ReportsController.unshareReport
);

/**
 * Report Clone Routes
 */

// Clone report
router.post('/:reportId/clone',
  authorize(['report.create', 'report.admin']),
  validateRequest(cloneReportSchema),
  rateLimiter('reports-clone', { max: 10, windowMs: 60 * 60 * 1000 }), // 10 per hour
  ReportsController.cloneReport
);

/**
 * Report Schedule Routes
 */

// Update report schedule
router.put('/:reportId/schedule',
  authorize(['report.schedule', 'report.admin']),
  validateRequest(scheduleReportSchema),
  rateLimiter('reports-schedule', { max: 20, windowMs: 60 * 60 * 1000 }),
  ReportsController.updateSchedule
);

/**
 * Report Activity and Logging Routes
 */

// Get report activity log
router.get('/:reportId/activity',
  authorize(['report.read', 'report.admin']),
  validateRequest(activityLogSchema),
  rateLimiter('reports-activity', { max: 50, windowMs: 60 * 1000 }),
  ReportsController.getActivityLog
);

// Get report access log
router.get('/:reportId/access-log',
  authorize(['report.admin', 'admin']),
  validateRequest(accessLogSchema),
  rateLimiter('reports-access-log', { max: 30, windowMs: 60 * 1000 }),
  ReportsController.getAccessLog
);

/**
 * Report Access Control Routes
 */

// Update report access control
router.put('/:reportId/access',
  authorize(['report.admin', 'admin']),
  validateRequest(updateAccessSchema),
  rateLimiter('reports-access', { max: 20, windowMs: 60 * 60 * 1000 }),
  ReportsController.updateAccess
);

/**
 * Public Report Routes (No authentication required but with restrictions)
 */

// Get public report (requires token)
router.get('/public/:slug',
  rateLimiter('reports-public', { max: 50, windowMs: 60 * 1000 }),
  async (req, res, next) => {
    const { slug } = req.params;
    const { token } = req.query;
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: {
          message: 'Access token required',
          code: 'TOKEN_REQUIRED'
        }
      });
    }
    
    // Verify public access token
    try {
      const report = await Report.findOne({ 
        slug, 
        'sharing.isPublic': true,
        'sharing.publicToken': token 
      });
      
      if (!report) {
        return res.status(404).json({
          success: false,
          error: {
            message: 'Report not found or invalid token',
            code: 'INVALID_ACCESS'
          }
        });
      }
      
      // Add report to request for controller
      req.publicReport = report;
      next();
    } catch (error) {
      next(error);
    }
  },
  async (req, res) => {
    const report = req.publicReport;
    
    // Return limited report data for public access
    const publicData = {
      reportId: report.reportId,
      name: report.name,
      description: report.description,
      type: report.type,
      category: report.category,
      visualizations: report.visualizations,
      lastRunAt: report.analytics.lastRunAt
    };
    
    responseHandler.success(res, { report: publicData }, 'Public report retrieved');
  }
);

/**
 * Health Check
 */
router.get('/health',
  (req, res) => {
    res.status(200).json({ 
      status: 'ok', 
      service: 'reports',
      timestamp: new Date().toISOString()
    });
  }
);

/**
 * Error handling middleware for this router
 */
router.use((error, req, res, next) => {
  logger.error('Reports route error', {
    error: error.message,
    stack: error.stack,
    path: req.path,
    method: req.method,
    userId: req.user?._id
  });
  
  // Pass to global error handler
  next(error);
});

module.exports = router;