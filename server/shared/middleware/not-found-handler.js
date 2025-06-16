// /server/shared/middleware/not-found-handler.js

const { AppError } = require('../utils/app-error');
const errorCodes = require('../utils/constants/error-codes');

/**
 * Not Found Middleware
 * Handles 404 errors for unmatched routes
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function notFoundHandler(req, res, next) {
  const message = `Cannot ${req.method} ${req.originalUrl || 'unknown route'}`;
  const error = new AppError(
    message,
    404,
    errorCodes.BUSINESS.RESOURCE_NOT_FOUND
  );
  next(error);
}

module.exports = notFoundHandler;
