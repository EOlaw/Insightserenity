// /server/shared/auth/middleware/auth-middleware.js

const jwt = require('jsonwebtoken');
const passport = require('passport');
const { RateLimiterRedis } = require('rate-limiter-flexible');

const AuthModel = require('../../auth/models/auth-model');
const redis = require('../../config/redis');
const User = require('../../users/models/user-model');
const { AppError } = require('../../utils/app-error');
const { asyncHandler } = require('../../utils/async-handler');
const logger = require('../../utils/logger');

/**
 * Core authentication middleware using Passport.js
 */
const authenticate = (strategy = 'jwt') => {
  return (req, res, next) => {
    passport.authenticate(strategy, { session: false }, (err, user, info) => {
      if (err) {
        return next(new AppError('Authentication error', 500));
      }
      
      if (!user) {
        return next(new AppError(info?.message || 'Authentication failed', 401));
      }
      
      req.user = user;
      next();
    })(req, res, next);
  };
};

/**
 * Require authentication - stricter version of verifyToken
 * Ensures user is authenticated and has valid session
 */
const requireAuth = asyncHandler(async (req, res, next) => {
  // First verify the token
  await verifyToken(req, res, async (error) => {
    if (error) {
      return next(error);
    }
    
    // Additional checks for authenticated users
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }
    
    // Check if user account is verified (if email verification is enabled)
    if (process.env.REQUIRE_EMAIL_VERIFICATION === 'true' && !req.user.emailVerified) {
      return next(new AppError('Please verify your email address to continue', 403));
    }
    
    // Check if user has completed profile setup (optional)
    if (req.user.profileStatus === 'incomplete') {
      // Allow access to profile completion routes
      const allowedPaths = ['/api/v1/users/profile', '/api/v1/auth/logout'];
      if (!allowedPaths.some(path => req.path.startsWith(path))) {
        return res.status(403).json({
          status: 'error',
          message: 'Please complete your profile setup',
          redirectTo: '/profile/setup'
        });
      }
    }
    
    // Check if password reset is required
    if (req.user.requirePasswordChange) {
      const allowedPaths = ['/api/v1/auth/change-password', '/api/v1/auth/logout'];
      if (!allowedPaths.some(path => req.path.startsWith(path))) {
        return res.status(403).json({
          status: 'error',
          message: 'Password change required',
          redirectTo: '/auth/change-password'
        });
      }
    }
    
    // Update last activity
    req.user.lastActivity = new Date();
    await req.user.save({ validateBeforeSave: false });
    
    next();
  });
});

/**
 * Verify JWT token middleware
 */
const verifyToken = asyncHandler(async (req, res, next) => {
  let token;
  
  // Extract token from Authorization header or cookies
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  
  if (!token) {
    return next(new AppError('Please log in to access this resource', 401));
  }
  
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if token exists in blacklist (for logout functionality)
    const isBlacklisted = await AuthModel.isTokenBlacklisted(token);
    if (isBlacklisted) {
      return next(new AppError('Token has been invalidated', 401));
    }
    
    // Check if user still exists
    const user = await User.findById(decoded.id).select('+active');
    if (!user) {
      return next(new AppError('User no longer exists', 401));
    }
    
    // Check if user is active
    if (!user.active) {
      return next(new AppError('Account has been deactivated', 401));
    }
    
    // Check if user changed password after token was issued
    if (user.passwordChangedAfter(decoded.iat)) {
      return next(new AppError('Password recently changed. Please log in again', 401));
    }
    
    // Grant access to protected route
    req.user = user;
    req.token = token;
    res.locals.user = user;
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return next(new AppError('Invalid token', 401));
    } else if (error.name === 'TokenExpiredError') {
      return next(new AppError('Token has expired', 401));
    }
    return next(new AppError('Token verification failed', 401));
  }
});

/**
 * Role-based access control middleware
 */
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }
    
    // Check if user has any of the allowed roles
    const userRoles = Array.isArray(req.user.roles) ? req.user.roles : [req.user.role];
    const hasPermission = roles.some(role => userRoles.includes(role));
    
    if (!hasPermission) {
      return next(new AppError('You do not have permission to perform this action', 403));
    }
    
    next();
  };
};

/**
 * Organization-based access control
 */
const restrictToOrganization = asyncHandler(async (req, res, next) => {
  const organizationId = req.params.organizationId || req.body.organizationId;
  
  if (!organizationId) {
    return next(new AppError('Organization ID is required', 400));
  }
  
  // Super admins have access to all organizations
  if (req.user.roles.includes('super-admin')) {
    return next();
  }
  
  // Check if user belongs to the organization
  const hasAccess = req.user.organizations.some(
    org => org.organizationId.toString() === organizationId && org.active
  );
  
  if (!hasAccess) {
    return next(new AppError('Access denied to this organization', 403));
  }
  
  // Set organization context
  req.organizationId = organizationId;
  const userOrg = req.user.organizations.find(
    org => org.organizationId.toString() === organizationId
  );
  req.organizationRole = userOrg.role;
  
  next();
});

/**
 * API key authentication for external services
 */
const authenticateApiKey = asyncHandler(async (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.apiKey;
  
  if (!apiKey) {
    return next(new AppError('API key is required', 401));
  }
  
  // Validate API key
  const apiKeyData = await AuthModel.validateApiKey(apiKey);
  if (!apiKeyData) {
    return next(new AppError('Invalid API key', 401));
  }
  
  // Check if API key is active
  if (!apiKeyData.active) {
    return next(new AppError('API key has been deactivated', 401));
  }
  
  // Check rate limits for API key
  if (apiKeyData.rateLimit) {
    const rateLimiter = new RateLimiterRedis({
      storeClient: redis,
      keyPrefix: `api_limit_${apiKeyData._id}`,
      points: apiKeyData.rateLimit.requests,
      duration: apiKeyData.rateLimit.window, // in seconds
    });
    
    try {
      await rateLimiter.consume(apiKeyData._id);
    } catch (rateLimiterRes) {
      return next(new AppError('API rate limit exceeded', 429));
    }
  }
  
  // Set API key context
  req.apiKey = apiKeyData;
  req.isApiRequest = true;
  
  // Log API usage
  await AuthModel.logApiUsage(apiKeyData._id, {
    endpoint: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('user-agent'),
  });
  
  next();
});

/**
 * Two-factor authentication verification
 */
const verify2FA = asyncHandler(async (req, res, next) => {
  if (!req.user.twoFactorEnabled) {
    return next();
  }
  
  const { twoFactorCode } = req.body;
  
  if (!twoFactorCode) {
    return res.status(403).json({
      status: 'error',
      message: 'Two-factor authentication code required',
      requires2FA: true,
    });
  }
  
  const isValid = await AuthModel.verify2FACode(req.user._id, twoFactorCode);
  
  if (!isValid) {
    return next(new AppError('Invalid two-factor authentication code', 401));
  }
  
  next();
});

/**
 * Session validation middleware
 */
const validateSession = asyncHandler(async (req, res, next) => {
  if (!req.session || !req.session.userId) {
    return next(new AppError('No active session', 401));
  }
  
  // Validate session in database
  const session = await AuthModel.getActiveSession(req.session.id);
  if (!session) {
    req.session.destroy();
    return next(new AppError('Session expired or invalid', 401));
  }
  
  // Update session activity
  await AuthModel.updateSessionActivity(req.session.id);
  
  // Load user if not already loaded
  if (!req.user) {
    req.user = await User.findById(req.session.userId).select('+active');
    if (!req.user || !req.user.active) {
      req.session.destroy();
      return next(new AppError('User not found or inactive', 401));
    }
  }
  
  next();
});

/**
 * Optional authentication - doesn't fail if no token
 */
const optionalAuth = async (req, res, next) => {
  let token;
  
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  
  if (!token) {
    return next();
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('+active');
    
    if (user && user.active) {
      req.user = user;
      res.locals.user = user;
    }
  } catch (error) {
    // Silent fail - user remains unauthenticated
    logger.debug('Optional auth failed:', error.message);
  }
  
  next();
};

/**
 * Refresh token validation
 */
const validateRefreshToken = asyncHandler(async (req, res, next) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return next(new AppError('Refresh token is required', 400));
  }
  
  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Check if refresh token exists in database
    const tokenData = await AuthModel.getRefreshToken(refreshToken);
    if (!tokenData) {
      return next(new AppError('Invalid refresh token', 401));
    }
    
    // Check if user still exists and is active
    const user = await User.findById(decoded.id).select('+active');
    if (!user || !user.active) {
      await AuthModel.revokeRefreshToken(refreshToken);
      return next(new AppError('User not found or inactive', 401));
    }
    
    req.user = user;
    req.refreshToken = refreshToken;
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      await AuthModel.revokeRefreshToken(refreshToken);
      return next(new AppError('Refresh token has expired', 401));
    }
    return next(new AppError('Invalid refresh token', 401));
  }
});

/**
 * IP whitelist middleware
 */
const ipWhitelist = (allowedIPs = []) => {
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (allowedIPs.length === 0 || allowedIPs.includes(clientIP)) {
      return next();
    }
    
    logger.warn(`Unauthorized IP access attempt: ${clientIP}`);
    return next(new AppError('Access denied from this IP address', 403));
  };
};

/**
 * CORS credentials check for authenticated routes
 */
const checkCorsCredentials = (req, res, next) => {
  const origin = req.get('origin');
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [];
  
  if (origin && !allowedOrigins.includes(origin)) {
    return next(new AppError('CORS policy violation', 403));
  }
  
  next();
};

module.exports = {
  authenticate,
  requireAuth,
  verifyToken,
  restrictTo,
  restrictToOrganization,
  authenticateApiKey,
  verify2FA,
  validateSession,
  optionalAuth,
  validateRefreshToken,
  ipWhitelist,
  checkCorsCredentials,
};