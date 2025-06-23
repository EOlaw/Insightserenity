/**
 * @file Configuration Module
 * @description Centralized configuration management for the application
 * @version 3.0.0
 */

const path = require('path');

const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Helper function to parse boolean environment variables
const parseBoolean = (value, defaultValue = false) => {
    if (value === undefined || value === null) return defaultValue;
    if (typeof value === 'boolean') return value;
    return value.toLowerCase() === 'true';
};

// Helper function to parse array from comma-separated string
const parseArray = (value, defaultValue = []) => {
    if (!value) return defaultValue;
    return value.split(',').map(item => item.trim()).filter(Boolean);
};

// Helper function to get environment variable with default (ROBUST VERSION)
const getEnv = (key, defaultValue = '') => {
    const value = process.env[key];
    if (value === undefined || value === null || value === '') {
        return defaultValue;
    }
    return value;
};

// Helper function to get required environment variable (SAFER VERSION)
const getRequiredEnv = (key) => {
    const value = process.env[key];
    if (!value || value.trim() === '') {
        // console.warn(`⚠️  Required environment variable ${key} is not set or empty`);
        return ''; // Return empty string instead of throwing
    }
    return value;
};

/**
 * Application configuration object
 */
const config = {
    // Application settings
    app: {
        name: getEnv('APP_NAME', 'InsightSerenity'),
        env: getEnv('NODE_ENV', 'development'),
        port: parseInt(getEnv('PORT', '5001'), 10),
        host: getEnv('APP_HOST', 'localhost'),
        url: getEnv('APP_URL', 'https://localhost:5001'),
        apiPrefix: getEnv('API_PREFIX', '/api'),
        apiVersion: getEnv('API_VERSION', 'v1'),
        version: getEnv('NPM_PACKAGE_VERSION', '3.0.0'),
        uploadLimit: getEnv('UPLOAD_LIMIT', '10mb'),
        trustProxy: parseBoolean(getEnv('TRUST_PROXY', 'true'))
    },

    // ADD THIS SERVER SECTION:
    server: {
        name: getEnv('APP_NAME', 'InsightSerenity'),
        isProduction: getEnv('NODE_ENV', 'development') === 'production',
        isDevelopment: getEnv('NODE_ENV', 'development') === 'development',
        host: getEnv('APP_HOST', 'localhost'),
        port: parseInt(getEnv('PORT', '5001'), 10),
        url: getEnv('APP_URL', 'https://localhost:5001'),
        protocol: getEnv('APP_URL', 'https://localhost:5001').startsWith('https') ? 'https' : 'http'
    },

    // Client configuration (for auth controller compatibility)
    client: {
        url: getEnv('CLIENT_URL', 'http://localhost:5001')
    },

    // Domain configuration
    domain: {
        primary: getEnv('DOMAIN', 'localhost'),
        clientUrl: getEnv('CLIENT_URL', 'http://localhost:5001')
    },

    // Database configuration
    database: {
        uri: getEnv('MONGODB_URI') || getEnv('DB_URL_INSIGHTSERENITY'),
        options: {
            maxPoolSize: parseInt(getEnv('DB_POOL_SIZE', '10'), 10),
            serverSelectionTimeoutMS: parseInt(getEnv('DB_TIMEOUT', '30000'), 10),
            socketTimeoutMS: parseInt(getEnv('DB_SOCKET_TIMEOUT', '60000'), 10),
            heartbeatFrequencyMS: parseInt(getEnv('DB_HEARTBEAT_FREQUENCY', '30000'), 10),
            maxIdleTimeMS: parseInt(getEnv('DB_MAX_IDLE_TIME', '30000'), 10),
            family: 4
        },
        encryptionKey: getEnv('DB_ENCRYPTION_KEY', 'your-encryption-key-replace-in-production')
    },

    // Authentication configuration
    auth: {
        // Token configuration  
        accessToken: {
            secret: getEnv('ACCESS_TOKEN_SECRET') || getEnv('JWT_SECRET'),
            expiresIn: getEnv('ACCESS_TOKEN_EXPIRES_IN', '15m'),
            issuer: getEnv('ACCESS_TOKEN_ISSUER', 'InsightSerenity'),
            audience: getEnv('ACCESS_TOKEN_AUDIENCE', 'InsightSerenity-Users')
        },
        refreshToken: {
            secret: getEnv('REFRESH_TOKEN_SECRET') || getEnv('JWT_REFRESH_SECRET'),
            expiresIn: getEnv('REFRESH_TOKEN_EXPIRES_IN', '7d'),
            issuer: getEnv('REFRESH_TOKEN_ISSUER', 'InsightSerenity'),
            audience: getEnv('REFRESH_TOKEN_AUDIENCE', 'InsightSerenity-Users')
        },
        
        // CRITICAL: Direct legacy properties (ensuring they have values)
        jwtSecret: getEnv('ACCESS_TOKEN_SECRET') || getEnv('JWT_SECRET') || 'fallback-secret-development-only',
        jwtRefreshSecret: getEnv('REFRESH_TOKEN_SECRET') || getEnv('JWT_REFRESH_SECRET') || 'fallback-refresh-secret-development-only',
        accessTokenExpiry: getEnv('ACCESS_TOKEN_EXPIRES_IN', '15m'),
        refreshTokenExpiry: getEnv('REFRESH_TOKEN_EXPIRES_IN', '7d'),
        
        // Session durations (CRITICAL - These were missing and causing your error)
        sessionDuration: parseInt(getEnv('AUTH_SESSION_DURATION', '86400000'), 10), // 24 hours in milliseconds
        rememberMeDuration: parseInt(getEnv('AUTH_REMEMBER_ME_DURATION', '2592000000'), 10), // 30 days in milliseconds
        
        // JWT configuration
        jwt: {
            algorithm: getEnv('JWT_ALGORITHM', 'HS256'),
            issuer: getEnv('JWT_ISSUER', 'InsightSerenity'),
            audience: getEnv('JWT_AUDIENCE', 'InsightSerenity-Users')
        },
        
        // Password policy
        passwordPolicy: {
            minLength: parseInt(getEnv('PASSWORD_MIN_LENGTH', '12'), 10),
            maxLength: parseInt(getEnv('PASSWORD_MAX_LENGTH', '128'), 10),
            requireUppercase: parseBoolean(getEnv('PASSWORD_REQUIRE_UPPERCASE', 'true')),
            requireLowercase: parseBoolean(getEnv('PASSWORD_REQUIRE_LOWERCASE', 'true')),
            requireNumbers: parseBoolean(getEnv('PASSWORD_REQUIRE_NUMBERS', 'true')),
            requireSpecialChars: parseBoolean(getEnv('PASSWORD_REQUIRE_SPECIAL_CHARS', 'true')),
            preventReuse: parseInt(getEnv('PASSWORD_PREVENT_REUSE', '5'), 10),
            maxAge: parseInt(getEnv('PASSWORD_MAX_AGE', '7776000000'), 10) // 90 days
        },
        
        // Security settings
        saltRounds: parseInt(getEnv('SALT_ROUNDS', '12'), 10),
        maxLoginAttempts: parseInt(getEnv('MAX_LOGIN_ATTEMPTS', '5'), 10),
        lockoutDuration: parseInt(getEnv('LOCKOUT_DURATION', '900000'), 10), // 15 minutes
        
        // Email verification
        requireEmailVerification: parseBoolean(getEnv('REQUIRE_EMAIL_VERIFICATION', 'true')),
        emailVerificationExpiry: parseInt(getEnv('EMAIL_VERIFICATION_EXPIRY', '86400000'), 10), // 24 hours
        
        // Password reset
        passwordResetExpiry: parseInt(getEnv('PASSWORD_RESET_EXPIRY', '3600000'), 10), // 1 hour
        
        // Two-factor authentication
        twoFactor: {
            enabled: parseBoolean(getEnv('TWO_FACTOR_ENABLED', 'true')),
            issuer: getEnv('TWO_FACTOR_ISSUER', 'InsightSerenity'),
            window: parseInt(getEnv('TWO_FACTOR_WINDOW', '2'), 10),
            backupCodesCount: parseInt(getEnv('TWO_FACTOR_BACKUP_CODES', '8'), 10)
        },
        
        // Device trust
        trustedDeviceExpiry: parseInt(getEnv('TRUSTED_DEVICE_EXPIRY', '2592000000'), 10), // 30 days
        
        // Rate limiting for auth endpoints
        rateLimit: {
            login: {
                windowMs: parseInt(getEnv('AUTH_RATE_LIMIT_WINDOW', '900000'), 10), // 15 minutes
                max: parseInt(getEnv('AUTH_RATE_LIMIT_MAX', '5'), 10)
            },
            passwordReset: {
                windowMs: parseInt(getEnv('PASSWORD_RESET_RATE_LIMIT_WINDOW', '3600000'), 10), // 1 hour
                max: parseInt(getEnv('PASSWORD_RESET_RATE_LIMIT_MAX', '3'), 10)
            }
        }
    },

    // Session configuration
    session: {
        secret: getEnv('SESSION_SECRET'),
        name: getEnv('SESSION_NAME', 'insightserenity.sid'),
        resave: parseBoolean(getEnv('SESSION_RESAVE', 'false')),
        saveUninitialized: parseBoolean(getEnv('SESSION_SAVE_UNINITIALIZED', 'false')),
        rolling: parseBoolean(getEnv('SESSION_ROLLING', 'true')),
        proxy: parseBoolean(getEnv('SESSION_PROXY', 'true')),
        cookie: {
            secure: parseBoolean(getEnv('SESSION_SECURE', 'false')),
            httpOnly: parseBoolean(getEnv('SESSION_HTTP_ONLY', 'true')),
            maxAge: parseInt(getEnv('SESSION_MAX_AGE', '86400000'), 10),
            sameSite: getEnv('SESSION_SAME_SITE', 'lax')
        },
        store: getEnv('SESSION_STORE', 'mongodb'),
        idleTimeout: parseInt(getEnv('SESSION_IDLE_TIMEOUT', '1800000'), 10),
        absoluteTimeout: parseInt(getEnv('SESSION_ABSOLUTE_TIMEOUT', '28800000'), 10),
        rotationMinutes: parseInt(getEnv('SESSION_ROTATION_MINUTES', '60'), 10),
        useSessions: parseBoolean(getEnv('USE_SESSIONS', 'true'))
    },

    // Security configuration
    security: {
        cookieSecret: getEnv('COOKIE_SECRET'),
        encryption: {
            algorithm: getEnv('ENCRYPTION_ALGORITHM', 'aes-256-gcm'),
            keyLength: parseInt(getEnv('ENCRYPTION_KEY_LENGTH', '32'), 10),
            ivLength: parseInt(getEnv('ENCRYPTION_IV_LENGTH', '16'), 10),
            tagLength: parseInt(getEnv('ENCRYPTION_TAG_LENGTH', '16'), 10),
            saltLength: parseInt(getEnv('ENCRYPTION_SALT_LENGTH', '64'), 10),
            iterations: parseInt(getEnv('ENCRYPTION_ITERATIONS', '100000'), 10)
        },
        ssl: {
            enabled: parseBoolean(getEnv('USE_HTTPS', 'false')),
            keyPath: getEnv('SSL_KEY_PATH', 'localhost-key.pem'),
            certPath: getEnv('SSL_CERT_PATH', 'localhost.pem'),
            ca: getEnv('SSL_CA_PATH'),
            rejectUnauthorized: parseBoolean(getEnv('SSL_REJECT_UNAUTHORIZED', 'false'))
        },
        cors: {
            enabled: parseBoolean(getEnv('CORS_ENABLED', 'true')),
            origins: parseArray(getEnv('CORS_ORIGINS', 'http://localhost:3000')),
            methods: parseArray(getEnv('CORS_METHODS', 'GET,POST,PUT,DELETE,PATCH,OPTIONS')),
            allowedHeaders: parseArray(getEnv('CORS_HEADERS', 'Content-Type,Authorization,X-Requested-With,X-CSRF-Token,Accept,Origin')),
            exposedHeaders: parseArray(getEnv('CORS_EXPOSED_HEADERS', 'X-Total-Count,X-Page-Count,X-Page,X-Per-Page')),
            allowCredentials: parseBoolean(getEnv('CORS_CREDENTIALS', 'true')),
            maxAge: parseInt(getEnv('CORS_MAX_AGE', '86400'), 10),
            preflightContinue: parseBoolean(getEnv('CORS_PREFLIGHT_CONTINUE', 'false')),
            optionsSuccessStatus: parseInt(getEnv('CORS_OPTIONS_STATUS', '204'), 10)
        },
        helmet: {
            enabled: parseBoolean(getEnv('HELMET_ENABLED', 'true')),
            contentSecurityPolicy: parseBoolean(getEnv('HELMET_COEP', 'false'))
        },
        rateLimit: {
            enabled: parseBoolean(getEnv('RATE_LIMIT_ENABLED', 'true')),
            windowMs: parseInt(getEnv('RATE_LIMIT_WINDOW_MS', '900000'), 10),
            max: parseInt(getEnv('RATE_LIMIT_MAX_REQUESTS', '100'), 10),
            message: getEnv('RATE_LIMIT_MESSAGE', 'Too many requests from this IP, please try again later.'),
            standardHeaders: parseBoolean(getEnv('RATE_LIMIT_STANDARD_HEADERS', 'true')),
            legacyHeaders: parseBoolean(getEnv('RATE_LIMIT_LEGACY_HEADERS', 'false')),
            skipSuccessful: parseBoolean(getEnv('RATE_LIMIT_SKIP_SUCCESSFUL', 'false')),
            skipFailed: parseBoolean(getEnv('RATE_LIMIT_SKIP_FAILED', 'false'))
        },
        sanitize: {
            enabled: parseBoolean(getEnv('SANITIZE_ENABLED', 'true')),
            replaceWith: getEnv('SANITIZE_REPLACE_WITH', '_')
        },
        session: {
            enabled: parseBoolean(getEnv('SESSION_ENABLED', 'true')),
            secret: getEnv('SESSION_SECRET', 'your_default_session_secret'),
            resave: parseBoolean(getEnv('SESSION_RESAVE', 'false')),
            saveUninitialized: parseBoolean(getEnv('SESSION_SAVE_UNINITIALIZED', 'false')),
            cookie: {
                secure: parseBoolean(getEnv('SESSION_COOKIE_SECURE', 'false')),
                httpOnly: parseBoolean(getEnv('SESSION_COOKIE_HTTP_ONLY', 'true')),
                maxAge: parseInt(getEnv('SESSION_COOKIE_MAX_AGE', '3600000'), 10) // 1 hour default
            }
        }
    },

    // Redis configuration (optional)
    redis: {
        enabled: parseBoolean(getEnv('REDIS_ENABLED', 'false')),
        host: getEnv('REDIS_HOST', 'localhost'),
        port: parseInt(getEnv('REDIS_PORT', '6379'), 10),
        password: getEnv('REDIS_PASSWORD', ''),
        db: parseInt(getEnv('REDIS_DB', '0'), 10),
        ttl: parseInt(getEnv('REDIS_TTL', '86400'), 10),
        keyPrefix: getEnv('REDIS_KEY_PREFIX', 'insightserenity:')
    },

    // Email configuration
    email: {
        encryptionKey: getEnv('EMAIL_ENCRYPTION_KEY'),
        from: getEnv('EMAIL_FROM', 'noreply@insightserenity.com'),
        provider: getEnv('EMAIL_PROVIDER', 'smtp'),
        supportEmail: getEnv('SUPPORT_EMAIL', 'support@insightserenity.com'),
        smtp: {
            host: getEnv('SMTP_HOST', 'smtp.gmail.com'),
            port: parseInt(getEnv('SMTP_PORT', '587'), 10),
            secure: parseBoolean(getEnv('SMTP_SECURE', 'false')),
            user: getEnv('SMTP_USER'),
            pass: getEnv('SMTP_PASS'),
            tls: {
                rejectUnauthorized: parseBoolean(getEnv('SMTP_TLS_REJECT_UNAUTHORIZED', 'true'))
            }
        }
    },

    // File storage configuration
    storage: {
        provider: getEnv('STORAGE_PROVIDER', 'local'),
        uploadsDir: getEnv('UPLOADS_DIR', 'uploads'),
        fileBaseUrl: getEnv('FILE_BASE_URL', '/uploads'),
        maxFileSize: parseInt(getEnv('MAX_FILE_SIZE', '10485760'), 10),
        allowedMimeTypes: parseArray(getEnv('ALLOWED_MIME_TYPES', 'image/jpeg,image/png,image/gif,image/webp,application/pdf')),
        createUploadDirs: parseBoolean(getEnv('CREATE_UPLOAD_DIRS', 'true'))
    },

    // OAuth configuration
    oauth: {
        github: {
            enabled: parseBoolean(getEnv('GITHUB_OAUTH_ENABLED', 'false')),
            clientId: getEnv('GITHUB_CLIENT_ID'),
            clientSecret: getEnv('GITHUB_CLIENT_SECRET'),
            callbackUrl: getEnv('GITHUB_CALLBACK_URL', 'https://localhost:5001/api/auth/github/callback'),
            scope: parseArray(getEnv('GITHUB_SCOPE', 'user:email,read:user'))
        },
        google: {
            enabled: parseBoolean(getEnv('GOOGLE_OAUTH_ENABLED', 'false')),
            clientId: getEnv('GOOGLE_CLIENT_ID'),
            clientSecret: getEnv('GOOGLE_CLIENT_SECRET'),
            callbackUrl: getEnv('GOOGLE_CALLBACK_URL', 'https://localhost:5001/api/auth/google/callback'),
            scope: parseArray(getEnv('GOOGLE_SCOPE', 'profile,email'))
        },
        linkedin: {
            enabled: parseBoolean(getEnv('LINKEDIN_OAUTH_ENABLED', 'false')),
            clientId: getEnv('LINKEDIN_CLIENT_ID'),
            clientSecret: getEnv('LINKEDIN_CLIENT_SECRET'),
            callbackUrl: getEnv('LINKEDIN_CALLBACK_URL', 'https://localhost:5001/api/auth/linkedin/callback'),
            scope: parseArray(getEnv('LINKEDIN_SCOPE', 'r_emailaddress,r_liteprofile'))
        }
    },

    // Passkey/WebAuthn configuration
    passkey: {
        enabled: parseBoolean(getEnv('PASSKEY_ENABLED', 'true')),
        rpName: getEnv('PASSKEY_RP_NAME', 'InsightSerenity'),
        rpId: getEnv('PASSKEY_RP_ID', 'localhost'),
        origin: getEnv('PASSKEY_ORIGIN', 'https://localhost:5001'),
        attestation: getEnv('PASSKEY_ATTESTATION', 'none'),
        userVerification: getEnv('PASSKEY_USER_VERIFICATION', 'required'),
        timeout: parseInt(getEnv('PASSKEY_TIMEOUT', '60000'), 10),
        authenticatorAttachment: getEnv('PASSKEY_AUTHENTICATOR_ATTACHMENT', 'platform')
    },

    // Organization/Multi-tenancy settings
    organization: {
        multiTenancyEnabled: parseBoolean(getEnv('MULTI_TENANCY_ENABLED', 'true')),
        requireOrgLogin: parseBoolean(getEnv('REQUIRE_ORG_LOGIN', 'false')),
        allowPersonalAccounts: parseBoolean(getEnv('ALLOW_PERSONAL_ACCOUNTS', 'true')),
        defaultRole: getEnv('DEFAULT_ORG_ROLE', 'member'),
        invitationExpiry: parseInt(getEnv('ORG_INVITATION_EXPIRY', '604800000'), 10),
        maxOrgsPerUser: parseInt(getEnv('MAX_ORGS_PER_USER', '10'), 10),
        restrictOneOrgPerUser: parseBoolean(getEnv('RESTRICT_ONE_ORG_PER_USER', 'false'))
    },

    // Payment configuration
    payment: {
        provider: getEnv('PAYMENT_PROVIDER', 'stripe'),
        stripe: {
            secretKey: getEnv('STRIPE_SECRET_KEY'),
            publicKey: getEnv('STRIPE_PUBLIC_KEY'),
            webhookSecret: getEnv('STRIPE_WEBHOOK_SECRET'),
            apiVersion: getEnv('STRIPE_API_VERSION', '2023-10-16'),
            currency: getEnv('STRIPE_CURRENCY', 'usd')
        }
    },

    // Consultant API Integration
    consultantApi: {
        url: getEnv('CONSULTANT_API_URL', 'https://api.yourpartnerplatform.com'),
        key: getEnv('CONSULTANT_API_KEY'),
        timeout: parseInt(getEnv('CONSULTANT_API_TIMEOUT', '10000'), 10),
        retries: parseInt(getEnv('CONSULTANT_API_RETRIES', '3'), 10),
        retryDelay: parseInt(getEnv('CONSULTANT_API_RETRY_DELAY', '1000'), 10)
    },

    // Frontend URLs
    frontend: {
        url: getEnv('FRONTEND_URL', 'http://localhost:3000'),
        loginUrl: getEnv('FRONTEND_LOGIN_URL', 'http://localhost:3000/login'),
        resetPasswordUrl: getEnv('FRONTEND_RESET_PASSWORD_URL', 'http://localhost:3000/reset-password'),
        verifyEmailUrl: getEnv('FRONTEND_VERIFY_EMAIL_URL', 'http://localhost:3000/verify-email'),
        dashboardUrl: getEnv('FRONTEND_DASHBOARD_URL', 'http://localhost:3000/dashboard')
    },

    // Logging configuration
    logging: {
        enabled: parseBoolean(getEnv('LOGGING_ENABLED', 'true')),
        level: getEnv('LOG_LEVEL', 'info'),
        format: getEnv('LOG_FORMAT', 'json'),
        colorize: parseBoolean(getEnv('LOG_COLORIZE', 'true')),
        file: {
            enabled: parseBoolean(getEnv('LOG_FILE_ENABLED', 'false')),
            path: getEnv('LOG_FILE_PATH', 'logs'),
            name: getEnv('LOG_FILE_NAME', 'app-%DATE%.log'),
            maxSize: getEnv('LOG_FILE_MAX_SIZE', '10m'),
            maxFiles: getEnv('LOG_FILE_MAX_FILES', '7d'),
            zipped: parseBoolean(getEnv('LOG_FILE_ZIPPED', 'true'))
        },
        remote: {
            enabled: parseBoolean(getEnv('LOG_REMOTE_ENABLED', 'false')),
            service: getEnv('LOG_REMOTE_SERVICE', 'sentry'),
            dsn: getEnv('LOG_REMOTE_DSN')
        }
    },

    // Feature flags
    features: {
        registration: parseBoolean(getEnv('FEATURE_REGISTRATION', 'true')),
        socialLogin: parseBoolean(getEnv('FEATURE_SOCIAL_LOGIN', 'true')),
        twoFactorAuth: parseBoolean(getEnv('FEATURE_2FA', 'true')),
        passkeys: parseBoolean(getEnv('FEATURE_PASSKEYS', 'true')),
        organizations: parseBoolean(getEnv('FEATURE_ORGANIZATIONS', 'true')),
        payments: parseBoolean(getEnv('FEATURE_PAYMENTS', 'true')),
        api: parseBoolean(getEnv('FEATURE_API', 'true')),
        webhooks: parseBoolean(getEnv('FEATURE_WEBHOOKS', 'false'))
    },

    // Test environment settings
    test: {
        port: parseInt(getEnv('TEST_PORT', '3001'), 10),
        mongodbUri: getEnv('TEST_MONGODB_URI', 'mongodb://localhost:27017/insightserenity-test')
    }
};

// Validate required configuration in production
if (config.app.env === 'production') {
    const requiredConfigs = [
        'database.uri',
        'auth.accessToken.secret',
        'auth.refreshToken.secret',
        'session.secret',
        'security.cookieSecret',
        'email.encryptionKey'
    ];

    requiredConfigs.forEach(configPath => {
        const value = configPath.split('.').reduce((obj, key) => obj?.[key], config);
        if (!value) {
            throw new Error(`Required configuration ${configPath} is not set for production environment`);
        }
    });
}

// ==============================================
// DEBUG: Log authentication configuration values
// ==============================================
// console.log('🔍 DEBUG: Authentication Config Values:');
// console.log('ACCESS_TOKEN_SECRET from env:', process.env.ACCESS_TOKEN_SECRET?.substring(0, 20) + '...');
// console.log('REFRESH_TOKEN_SECRET from env:', process.env.REFRESH_TOKEN_SECRET?.substring(0, 20) + '...');
// console.log('JWT_SECRET from env:', process.env.JWT_SECRET?.substring(0, 20) + '...');
// console.log('JWT_REFRESH_SECRET from env:', process.env.JWT_REFRESH_SECRET?.substring(0, 20) + '...');

// console.log('🔍 config.auth.jwtSecret:', config.auth.jwtSecret?.substring(0, 20) + '...');
// console.log('🔍 config.auth.jwtRefreshSecret:', config.auth.jwtRefreshSecret?.substring(0, 20) + '...');
// console.log('🔍 config.auth.accessTokenExpiry:', config.auth.accessTokenExpiry);
// console.log('🔍 config.auth.refreshTokenExpiry:', config.auth.refreshTokenExpiry);
console.log('==============================================');

// Freeze configuration to prevent modifications
Object.freeze(config);

module.exports = config;