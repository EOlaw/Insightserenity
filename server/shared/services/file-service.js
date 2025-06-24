// server/shared/services/file-service.js

/**
 * @file File Service
 * @description High-level file service providing unified interface for file operations
 * @version 1.0.0
 */

const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

const fileHelper = require('../utils/helpers/file-helper');
const config = require('../config/config');
const constants = require('../config/constants');
const { AppError } = require('../utils/app-error');
const logger = require('../utils/logger');

/**
 * FileService Class
 * Provides high-level file operations with standardized interface
 */
class FileService {
  
  /**
   * Upload and process image file
   * @param {Object} file - Multer file object
   * @param {Object} options - Upload and processing options
   * @returns {Promise<Object>} Upload result with url and publicId
   */
  static async uploadImage(file, options = {}) {
    try {
      const {
        folder = 'images',
        transformation = {},
        generateThumbnail = false,
        quality = 85
      } = options;

      // Validate file
      if (!file) {
        throw new AppError('No file provided', 400);
      }

      // Validate image type
      const allowedTypes = constants.FILE.ALLOWED_TYPES.IMAGE;
      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid image type', 400);
      }

      // Validate file size
      const maxSize = constants.FILE.MAX_SIZES.IMAGE;
      if (file.size > maxSize) {
        throw new AppError('File size exceeds limit', 400);
      }

      // Generate unique filename (not including folder in publicId for this case)
      const timestamp = Date.now();
      const randomString = crypto.randomBytes(8).toString('hex');
      const extension = path.extname(file.originalname).toLowerCase();
      const baseName = path.basename(file.originalname, extension)
        .replace(/[^a-zA-Z0-9]/g, '-')
        .toLowerCase()
        .substring(0, 30);
      
      const finalFileName = `${timestamp}-${randomString}-${baseName}${extension}`;
      
      // Determine upload directory and create folder structure
      const uploadDir = config.storage?.localPath || path.join(__dirname, '../../../uploads');
      const folderPath = path.join(uploadDir, folder);
      await fs.mkdir(folderPath, { recursive: true });

      // Process image if transformations are specified
      let sourceFilePath = file.path;
      let processedFilePath = null;
      
      if (transformation.width || transformation.height) {
        const processOptions = {
          width: transformation.width,
          height: transformation.height,
          quality: quality,
          fit: transformation.crop === 'fill' ? 'cover' : 'inside',
          position: transformation.gravity === 'face' ? 'attention' : 'center'
        };

        const processResult = await fileHelper.processImage(file.path, processOptions);
        processedFilePath = processResult.path;
        sourceFilePath = processedFilePath;
      }

      // Generate final file path
      const finalPath = path.join(folderPath, finalFileName);

      // Copy/move processed file to final location
      try {
        if (processedFilePath && processedFilePath !== file.path) {
          // If we processed the image, move the processed file
          await fs.rename(sourceFilePath, finalPath);
        } else {
          // If no processing, copy the original file
          await fs.copyFile(file.path, finalPath);
        }
      } catch (moveError) {
        // If rename fails, try copy and delete
        await fs.copyFile(sourceFilePath, finalPath);
        if (processedFilePath && processedFilePath !== file.path) {
          await fs.unlink(sourceFilePath).catch(() => {});
        }
      }

      // Clean up original uploaded file if it's different from final
      if (file.path !== finalPath) {
        await fs.unlink(file.path).catch(() => {});
      }

      // Generate public ID for external reference
      const publicId = `${folder}/${finalFileName}`;

      // Generate URL based on storage type
      let url;
      if (config.storage?.type === 's3') {
        // Upload to S3 if configured
        const s3Result = await fileHelper.uploadToS3(finalPath, publicId);
        url = s3Result.url;
        
        // Clean up local file after S3 upload
        await fs.unlink(finalPath).catch(() => {});
      } else {
        // Generate local URL
        const baseUrl = config.app?.baseUrl || `http://localhost:${config.app?.port || 5001}`;
        url = `${baseUrl}/uploads/${publicId}`;
      }

      // Generate thumbnail if requested
      let thumbnailUrl = null;
      if (generateThumbnail) {
        const thumbnailResult = await this.generateThumbnail(file, folder, finalFileName);
        thumbnailUrl = thumbnailResult.url;
      }

      logger.info('Image uploaded successfully', {
        publicId,
        originalName: file.originalname,
        size: file.size,
        folder,
        url
      });

      return {
        url,
        publicId,
        thumbnailUrl,
        filename: file.originalname,
        size: file.size,
        mimetype: file.mimetype,
        folder
      };

    } catch (error) {
      logger.error('Image upload failed', { error: error.message, file: file?.originalname });
      throw new AppError(`Image upload failed: ${error.message}`, 500);
    }
  }

  /**
   * Upload document file
   * @param {Object} file - Multer file object
   * @param {Object} options - Upload options
   * @returns {Promise<Object>} Upload result
   */
  static async uploadDocument(file, options = {}) {
    try {
      const { folder = 'documents' } = options;

      // Validate file
      if (!file) {
        throw new AppError('No file provided', 400);
      }

      // Validate document type
      const allowedTypes = constants.FILE.ALLOWED_TYPES.DOCUMENT;
      if (!allowedTypes.includes(file.mimetype)) {
        throw new AppError('Invalid document type', 400);
      }

      // Validate file size
      const maxSize = constants.FILE.MAX_SIZES.DOCUMENT;
      if (file.size > maxSize) {
        throw new AppError('File size exceeds limit', 400);
      }

      // Generate unique public ID
      const publicId = this.generatePublicId(file.originalname, folder);
      
      // Determine file path
      const uploadDir = config.storage?.localPath || path.join(__dirname, '../../../uploads');
      const folderPath = path.join(uploadDir, folder);
      await fs.mkdir(folderPath, { recursive: true });

      // Generate final file path
      const extension = path.extname(file.originalname).toLowerCase();
      const finalFileName = `${publicId}${extension}`;
      const finalPath = path.join(folderPath, finalFileName);

      // Move file to final location
      await fs.rename(file.path, finalPath);

      // Generate URL
      let url;
      if (config.storage?.type === 's3') {
        const s3Key = `${folder}/${finalFileName}`;
        const s3Result = await fileHelper.uploadToS3(finalPath, s3Key);
        url = s3Result.url;
        await fs.unlink(finalPath).catch(() => {});
      } else {
        const baseUrl = config.app?.baseUrl || `http://localhost:${config.app?.port || 5001}`;
        url = `${baseUrl}/uploads/${folder}/${finalFileName}`;
      }

      return {
        url,
        publicId,
        filename: file.originalname,
        size: file.size,
        mimetype: file.mimetype,
        folder
      };

    } catch (error) {
      logger.error('Document upload failed', { error: error.message, file: file?.originalname });
      throw new AppError(`Document upload failed: ${error.message}`, 500);
    }
  }

  /**
   * Delete file by public ID
   * @param {string} publicId - File public ID
   * @returns {Promise<boolean>} Success status
   */
  static async deleteFile(publicId) {
    try {
      if (!publicId) {
        logger.warn('Delete file called with empty publicId');
        return false;
      }

      // Extract folder and filename from publicId
      const parts = publicId.split('/');
      const folder = parts.length > 1 ? parts[0] : 'images';
      const filename = parts.length > 1 ? parts.slice(1).join('/') : parts[0];

      if (config.storage?.type === 's3') {
        // Delete from S3
        const s3Key = `${folder}/${filename}`;
        await fileHelper.deleteFile(s3Key, 's3');
      } else {
        // Delete local file
        const uploadDir = config.storage?.localPath || path.join(__dirname, '../../../uploads');
        const filePath = path.join(uploadDir, folder, filename);
        await fileHelper.deleteFile(filePath, 'local');
      }

      logger.info('File deleted successfully', { publicId });
      return true;

    } catch (error) {
      logger.error('File deletion failed', { error: error.message, publicId });
      return false;
    }
  }

  /**
   * Generate thumbnail for image
   * @param {Object} file - Original file
   * @param {string} folder - Folder name
   * @param {string} fileName - Base filename
   * @returns {Promise<Object>} Thumbnail result
   */
  static async generateThumbnail(file, folder, fileName) {
    try {
      const thumbnailOptions = {
        width: 200,
        height: 200,
        quality: 80,
        thumbnail: true
      };

      const thumbnailResult = await fileHelper.processImage(file.path, thumbnailOptions);
      
      // Move thumbnail to proper location
      const uploadDir = config.storage?.localPath || path.join(__dirname, '../../../uploads');
      const thumbnailFolder = path.join(uploadDir, folder, 'thumbnails');
      await fs.mkdir(thumbnailFolder, { recursive: true });

      const extension = path.extname(fileName);
      const baseName = path.basename(fileName, extension);
      const thumbnailFileName = `${baseName}_thumb${extension}`;
      const thumbnailPath = path.join(thumbnailFolder, thumbnailFileName);

      // Copy thumbnail to final location
      try {
        await fs.rename(thumbnailResult.thumbnailPath, thumbnailPath);
      } catch (error) {
        await fs.copyFile(thumbnailResult.thumbnailPath, thumbnailPath);
        await fs.unlink(thumbnailResult.thumbnailPath).catch(() => {});
      }

      // Generate thumbnail URL
      let thumbnailUrl;
      if (config.storage?.type === 's3') {
        const s3Key = `${folder}/thumbnails/${thumbnailFileName}`;
        const s3Result = await fileHelper.uploadToS3(thumbnailPath, s3Key);
        thumbnailUrl = s3Result.url;
        await fs.unlink(thumbnailPath).catch(() => {});
      } else {
        const baseUrl = config.app?.baseUrl || `http://localhost:${config.app?.port || 5001}`;
        thumbnailUrl = `${baseUrl}/uploads/${folder}/thumbnails/${thumbnailFileName}`;
      }

      return { url: thumbnailUrl };

    } catch (error) {
      logger.error('Thumbnail generation failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Generate unique public ID
   * @param {string} originalName - Original file name
   * @param {string} folder - Folder name
   * @returns {string} Public ID
   */
  static generatePublicId(originalName, folder) {
    const timestamp = Date.now();
    const randomString = crypto.randomBytes(8).toString('hex');
    const baseName = path.basename(originalName, path.extname(originalName))
      .replace(/[^a-zA-Z0-9]/g, '-')
      .toLowerCase()
      .substring(0, 30);
    
    return `${folder}/${timestamp}-${randomString}-${baseName}`;
  }

  /**
   * Get file metadata
   * @param {string} publicId - File public ID
   * @returns {Promise<Object>} File metadata
   */
  static async getFileMetadata(publicId) {
    try {
      const parts = publicId.split('/');
      const folder = parts.length > 1 ? parts[0] : 'images';
      const filename = parts.length > 1 ? parts.slice(1).join('/') : parts[0];

      const uploadDir = config.storage?.localPath || path.join(__dirname, '../../../uploads');
      const filePath = path.join(uploadDir, folder, filename);

      return await fileHelper.getFileMetadata(filePath);

    } catch (error) {
      logger.error('Failed to get file metadata', { error: error.message, publicId });
      throw new AppError('Failed to get file metadata', 500);
    }
  }

  /**
   * Cleanup temporary files
   * @param {number} maxAge - Maximum age in hours
   * @returns {Promise<number>} Number of files cleaned
   */
  static async cleanupTempFiles(maxAge = 24) {
    return await fileHelper.cleanupTempFiles(maxAge);
  }
}

module.exports = FileService;