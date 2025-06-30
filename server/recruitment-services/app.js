/**
 * @file Recruitment Services Module App
 * @description Express application for recruitment and talent acquisition services
 * @version 2.0.0
 */

const express = require('express');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const fileUpload = require('express-fileupload');

// Import shared configuration
const config = require('../shared/config/config');
const logger = require('../shared/utils/logger');

// Create module app
const app = express();

// Module-specific middleware
app.use(helmet(config.security.helmet || {}));
app.use(compression());
app.use(mongoSanitize());
app.use(express.json({ limit: config.recruitment?.requestLimit || '25mb' })); // Higher limit for resume uploads
app.use(express.urlencoded({ extended: true, limit: config.recruitment?.requestLimit || '25mb' }));

// File upload configuration for resumes and documents
app.use(fileUpload({
    limits: { fileSize: config.recruitment?.maxFileSize || 10 * 1024 * 1024 }, // 10MB default
    abortOnLimit: true,
    createParentPath: true,
    useTempFiles: config.recruitment?.useTempFiles !== false,
    tempFileDir: config.recruitment?.tempDir || '/tmp/',
    preserveExtension: true,
    safeFileNames: true,
    parseNested: true
}));

// Import route modules
const jobRoutes = require('./jobs/routes/job-routes');
const candidateRoutes = require('./candidates/routes/candidate-routes');
const applicationRoutes = require('./applications/routes/application-routes');
const interviewRoutes = require('./interviews/routes/interview-routes');
const assessmentRoutes = require('./assessments/routes/assessment-routes');
const talentPoolRoutes = require('./talent-pool/routes/talent-pool-routes');
const recruitmentAgencyRoutes = require('./agencies/routes/agency-routes');
const referralRoutes = require('./referrals/routes/referral-routes');
const onboardingRoutes = require('./onboarding/routes/onboarding-routes');
const recruitmentReportRoutes = require('./reports/routes/recruitment-report-routes');
const jobBoardRoutes = require('./job-boards/routes/job-board-routes');
const employerBrandingRoutes = require('./employer-branding/routes/employer-branding-routes');
const careerSiteRoutes = require('./career-site/routes/career-site-routes');
const recruitmentAutomationRoutes = require('./automation/routes/automation-routes');

// Recruitment-specific middleware
const { validateRecruiter } = require('./middleware/recruiter-validation');
const { checkJobPostingLimits } = require('./middleware/job-posting-limits');
const { sanitizeResumeData } = require('./middleware/resume-sanitization');
const { trackRecruitmentMetrics } = require('./middleware/recruitment-metrics');
const { enforceGDPR } = require('./middleware/gdpr-compliance');

// Apply GDPR compliance for candidate data
app.use(enforceGDPR);

// Health check for recruitment services
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        module: 'recruitment-services',
        timestamp: new Date().toISOString(),
        environment: config.app.env,
        version: config.app.version,
        gdprCompliant: config.recruitment?.gdprEnabled || true,
        services: {
            jobs: 'active',
            candidates: 'active',
            applications: 'active',
            interviews: 'active',
            assessments: 'active',
            talentPool: 'active',
            agencies: 'active',
            automation: 'active'
        }
    });
});

// Log module initialization
logger.info('Recruitment Services module initialized', {
    environment: config.app.env,
    maxFileSize: config.recruitment?.maxFileSize,
    gdprEnabled: config.recruitment?.gdprEnabled
});

/**
 * Public routes (no authentication required)
 */

// Career site and job listings (public access)
app.use('/career-site', careerSiteRoutes);
app.use('/public/jobs', jobRoutes.publicRoutes);

/**
 * Protected routes (authentication required)
 * Ordered by recruitment workflow
 */

// 1. Employer Branding (Foundation for attraction)
app.use('/employer-branding', validateRecruiter, employerBrandingRoutes);

// 2. Job Management (Create positions)
app.use('/jobs', validateRecruiter, checkJobPostingLimits, jobRoutes);

// 3. Job Board Integrations (Distribute jobs)
app.use('/job-boards', validateRecruiter, jobBoardRoutes);

// 4. Candidate Management (Manage talent)
app.use('/candidates', validateRecruiter, sanitizeResumeData, candidateRoutes);

// 5. Application Management (Process applications)
app.use('/applications', validateRecruiter, applicationRoutes);

// 6. Interview Management (Evaluate candidates)
app.use('/interviews', validateRecruiter, interviewRoutes);

// 7. Assessment Management (Test candidates)
app.use('/assessments', validateRecruiter, assessmentRoutes);

// 8. Talent Pool (Build pipeline)
app.use('/talent-pool', validateRecruiter, talentPoolRoutes);

// 9. Referral Program (Employee referrals)
app.use('/referrals', referralRoutes);

// 10. Agency Management (External recruiters)
app.use('/agencies', validateRecruiter, recruitmentAgencyRoutes);

// 11. Onboarding (New hire process)
app.use('/onboarding', validateRecruiter, onboardingRoutes);

// 12. Recruitment Automation (ATS features)
app.use('/automation', validateRecruiter, recruitmentAutomationRoutes);

// 13. Reporting & Analytics (Recruitment metrics)
app.use('/reports', validateRecruiter, recruitmentReportRoutes);

// Apply recruitment metrics tracking
app.use(trackRecruitmentMetrics);

// Module-specific error handling
app.use((err, req, res, next) => {
    if (err.type === 'JobPostingLimitExceeded') {
        return res.status(429).json({
            status: 'error',
            type: 'job_posting_limit_exceeded',
            message: 'Job posting limit reached for your subscription',
            code: 'JOB_LIMIT_EXCEEDED',
            limit: err.limit,
            current: err.current,
            upgradeUrl: '/billing/upgrade'
        });
    }
    
    if (err.type === 'CandidateDataPrivacy') {
        return res.status(403).json({
            status: 'error',
            type: 'data_privacy_violation',
            message: 'Cannot access candidate data due to privacy settings',
            code: 'PRIVACY_VIOLATION',
            gdprInfo: err.gdprInfo
        });
    }
    
    if (err.type === 'InvalidResumeFormat') {
        return res.status(400).json({
            status: 'error',
            type: 'invalid_resume_format',
            message: 'Resume format not supported',
            code: 'INVALID_RESUME',
            supportedFormats: ['.pdf', '.doc', '.docx', '.txt']
        });
    }
    
    if (err.type === 'DuplicateApplication') {
        return res.status(409).json({
            status: 'error',
            type: 'duplicate_application',
            message: 'Candidate has already applied for this position',
            code: 'DUPLICATE_APP',
            existingApplicationId: err.applicationId
        });
    }
    
    next(err);
});

// 404 handler for this module
app.use('*', (req, res) => {
    res.status(404).json({
        status: 'error',
        module: 'recruitment-services',
        message: `Recruitment service route ${req.originalUrl} not found`,
        availableEndpoints: [
            '/career-site',
            '/jobs',
            '/job-boards',
            '/candidates',
            '/applications',
            '/interviews',
            '/assessments',
            '/talent-pool',
            '/referrals',
            '/agencies',
            '/onboarding',
            '/automation',
            '/reports',
            '/employer-branding'
        ]
    });
});

module.exports = app;