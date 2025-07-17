/**
 * @file Core Business Module App
 * @description Express application for core business operations
 * @version 2.0.0
 */

const express = require('express');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');

// Import shared configuration
const config = require('../shared/config/config');
const logger = require('../shared/utils/logger');

// Create module app
const app = express();

// Module-specific middleware
app.use(helmet({
    contentSecurityPolicy: config.security.contentSecurityPolicy || {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"]
        }
    }
}));

app.use(compression());
app.use(mongoSanitize());
app.use(express.json({ limit: config.app.requestLimit || '10mb' }));
app.use(express.urlencoded({ extended: true, limit: config.app.requestLimit || '10mb' }));

// Import route modules
// const clientRoutes = require('./clients/routes/client-routes');
// const consultantRoutes = require('./consultants/routes/consultant-routes');
// const projectRoutes = require('./projects/routes/project-routes');
// const teamRoutes = require('./teams/routes/team-routes');
// const serviceRoutes = require('./services/routes/service-routes');
// const proposalRoutes = require('./proposals/routes/proposal-routes');
// const contractRoutes = require('./contracts/routes/contract-routes');
// const deliverableRoutes = require('./deliverables/routes/deliverable-routes');
// const timesheetRoutes = require('./timesheets/routes/timesheet-routes');
// const expenseRoutes = require('./expenses/routes/expense-routes');
// const invoiceRoutes = require('./invoices/routes/invoice-routes');
// const reportRoutes = require('./reports/routes/report-routes');
// const knowledgeRoutes = require('./knowledge/routes/knowledge-routes');
// const trainingRoutes = require('./training/routes/training-routes');

// Core business middleware
// const { checkBusinessContext } = require('../shared/middleware/business-context');
// const { enforceBusinessRules } = require('./middleware/business-rules');
// const { auditLog } = require('../shared/middleware/audit-middleware');

// Apply business context middleware
// app.use(checkBusinessContext);

// Health check for this module
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        module: 'core-business',
        timestamp: new Date().toISOString(),
        environment: config.app.env,
        version: config.app.version,
        services: {
            consultants: 'active',
            projects: 'active',
            teams: 'active',
            services: 'active',
            clients: 'active',
            financial: 'active',
            knowledge: 'active'
        }
    });
});

// Log module initialization
logger.info('Core Business module initialized', {
    environment: config.app.env,
    requestLimit: config.app.requestLimit
});

/**
 * Mount routes in logical order
 * Order matters for middleware application and route precedence
 */

// // 1. Consultant Management (Foundation of consultancy business)
// app.use('/consultants', consultantRoutes);

// 2. Client Management (Who we serve)
// app.use('/clients', clientRoutes);

// // 3. Service Catalog (What we offer)
// app.use('/services', serviceRoutes);

// // 4. Team Management (How we organize)
// app.use('/teams', teamRoutes);

// // 5. Project Management (Core operations)
// app.use('/projects', projectRoutes);

// // 6. Proposal Management (Business development)
// app.use('/proposals', proposalRoutes);

// // 7. Contract Management (Legal framework)
// app.use('/contracts', contractRoutes);

// // 8. Deliverable Management (Work products)
// app.use('/deliverables', deliverableRoutes);

// // 9. Time & Expense Tracking (Resource management)
// app.use('/timesheets', timesheetRoutes);
// app.use('/expenses', expenseRoutes);

// // 10. Financial Management (Billing & invoicing)
// app.use('/invoices', invoiceRoutes);

// // 11. Reporting & Analytics (Business intelligence)
// app.use('/reports', reportRoutes);

// // 12. Knowledge Management (Intellectual capital)
// app.use('/knowledge', knowledgeRoutes);

// // 13. Training & Development (Capability building)
// app.use('/training', trainingRoutes);

// Apply audit logging to all routes
// app.use(auditLog('core-business'));

// Business rules enforcement
// app.use(enforceBusinessRules);

// Module-specific error handling
app.use((err, req, res, next) => {
    if (err.type === 'BusinessRuleViolation') {
        return res.status(422).json({
            status: 'error',
            type: 'business_rule_violation',
            message: err.message,
            rule: err.rule,
            context: err.context
        });
    }
    
    if (err.type === 'ResourceConflict') {
        return res.status(409).json({
            status: 'error',
            type: 'resource_conflict',
            message: err.message,
            conflicts: err.conflicts
        });
    }
    
    next(err);
});

// 404 handler for this module
app.use('*', (req, res) => {
    res.status(404).json({
        status: 'error',
        module: 'core-business',
        message: `Core business route ${req.originalUrl} not found`,
        availableEndpoints: [
            '/consultants',
            '/clients',
            '/services',
            '/teams',
            '/projects',
            '/proposals',
            '/contracts',
            '/deliverables',
            '/timesheets',
            '/expenses',
            '/invoices',
            '/reports',
            '/knowledge',
            '/training'
        ]
    });
});

module.exports = app;