// /server/shared/utils/helpers/file-helper.js

/**
 * @file File Helper
 * @description File upload and processing utilities
 * @version 1.0.0
 */

const multer = require('multer');
const sharp = require('sharp');
const ffmpeg = require('fluent-ffmpeg');

const fs = require('fs').promises;
const crypto = require('crypto');
const path = require('path');

const { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const mime = require('mime-types');

const config = require('../../config/config');
const constants = require('../../config/constants');
const { AppError } = require('../app-error');
const logger = require('../logger');

/**
 * File Helper Class
 */
class FileHelper {
  constructor() {
    this.uploadDir = config.storage.localPath || path.join(__dirname, '../../../../uploads');
    this.tempDir = path.join(this.uploadDir, 'temp');
    this.storageType = config.storage.type || 'local'; // 'local' or 's3'
    
    // Initialize S3 client if needed
    if (this.storageType === 's3') {
      this.s3Client = new S3Client({
        region: config.storage.s3.region,
        credentials: {
          accessKeyId: config.storage.s3.accessKeyId,
          secretAccessKey: config.storage.s3.secretAccessKey
        }
      });
      this.s3Bucket = config.storage.s3.bucket;
    }
    
    // Ensure directories exist
    this.ensureDirectories();
  }
  
  /**
   * Ensure upload directories exist
   */
  async ensureDirectories() {
    try {
      await fs.mkdir(this.uploadDir, { recursive: true });
      await fs.mkdir(this.tempDir, { recursive: true });
      await fs.mkdir(path.join(this.uploadDir, 'images'), { recursive: true });
      await fs.mkdir(path.join(this.uploadDir, 'documents'), { recursive: true });
      await fs.mkdir(path.join(this.uploadDir, 'videos'), { recursive: true });
      await fs.mkdir(path.join(this.uploadDir, 'avatars'), { recursive: true });
    } catch (error) {
      logger.error('Failed to create upload directories:', error);
    }
  }
  
  /**
   * Create multer storage configuration
   * @param {Object} options - Storage options
   * @returns {Object} Multer storage config
   */
  createStorage(options = {}) {
    return multer.diskStorage({
      destination: async (req, file, cb) => {
        let folder = 'temp';
        
        if (options.folder) {
          folder = options.folder;
        } else if (file.mimetype.startsWith('image/')) {
          folder = 'images';
        } else if (file.mimetype.startsWith('video/')) {
          folder = 'videos';
        } else {
          folder = 'documents';
        }
        
        const destPath = path.join(this.uploadDir, folder);
        await fs.mkdir(destPath, { recursive: true });
        cb(null, destPath);
      },
      
      filename: (req, file, cb) => {
        const uniqueName = this.generateUniqueFilename(file.originalname);
        cb(null, uniqueName);
      }
    });
  }
  
  /**
   * Create multer upload middleware
   * @param {Object} options - Upload options
   * @returns {Object} Multer instance
   */
  createUploadMiddleware(options = {}) {
    const {
      maxSize = constants.FILE_UPLOAD.MAX_SIZE.DEFAULT,
      allowedTypes = [],
      maxFiles = 1,
      folder = 'temp'
    } = options;
    
    return multer({
      storage: this.createStorage({ folder }),
      limits: {
        fileSize: maxSize,
        files: maxFiles
      },
      fileFilter: (req, file, cb) => {
        // Check file type
        if (allowedTypes.length > 0) {
          const mimeType = file.mimetype;
          const extension = path.extname(file.originalname).toLowerCase();
          
          const isAllowedMime = allowedTypes.some(type => {
            if (type.includes('*')) {
              return mimeType.startsWith(type.replace('*', ''));
            }
            return mimeType === type;
          });
          
          const isAllowedExt = constants.FILE_UPLOAD.ALLOWED_EXTENSIONS.IMAGE.includes(extension) ||
                               constants.FILE_UPLOAD.ALLOWED_EXTENSIONS.DOCUMENT.includes(extension) ||
                               constants.FILE_UPLOAD.ALLOWED_EXTENSIONS.VIDEO.includes(extension);
          
          if (!isAllowedMime || !isAllowedExt) {
            return cb(new AppError('File type not allowed', 400));
          }
        }
        
        cb(null, true);
      }
    });
  }
  
  /**
   * Generate unique filename
   * @param {string} originalName - Original filename
   * @returns {string} Unique filename
   */
  generateUniqueFilename(originalName) {
    const timestamp = Date.now();
    const random = crypto.randomBytes(8).toString('hex');
    const extension = path.extname(originalName).toLowerCase();
    const safeName = path.basename(originalName, extension)
      .replace(/[^a-zA-Z0-9]/g, '-')
      .substring(0, 50);
    
    return `${safeName}-${timestamp}-${random}${extension}`;
  }
  
  /**
   * Process uploaded image
   * @param {string} filePath - File path
   * @param {Object} options - Processing options
   * @returns {Promise<Object>} Processing result
   */
  async processImage(filePath, options = {}) {
    try {
      const {
        width,
        height,
        quality = 85,
        format,
        thumbnail = false,
        watermark = false
      } = options;
      
      // Get image metadata
      const metadata = await sharp(filePath).metadata();
      
      // Create processing pipeline
      let pipeline = sharp(filePath);
      
      // Resize if dimensions specified
      if (width || height) {
        pipeline = pipeline.resize(width, height, {
          fit: options.fit || 'cover',
          position: options.position || 'center'
        });
      }
      
      // Convert format if specified
      if (format) {
        pipeline = pipeline.toFormat(format, { quality });
      } else {
        // Auto-optimize based on format
        if (metadata.format === 'jpeg' || metadata.format === 'jpg') {
          pipeline = pipeline.jpeg({ quality, progressive: true });
        } else if (metadata.format === 'png') {
          pipeline = pipeline.png({ compressionLevel: 9 });
        } else if (metadata.format === 'webp') {
          pipeline = pipeline.webp({ quality });
        }
      }
      
      // Add watermark if requested
      if (watermark && config.storage.watermarkPath) {
        pipeline = pipeline.composite([{
          input: config.storage.watermarkPath,
          gravity: 'southeast',
          blend: 'over'
        }]);
      }
      
      // Generate output filename
      const outputPath = filePath.replace(
        path.extname(filePath),
        `-processed${format ? `.${format}` : path.extname(filePath)}`
      );
      
      // Process and save
      await pipeline.toFile(outputPath);
      
      // Generate thumbnail if requested
      let thumbnailPath = null;
      if (thumbnail) {
        thumbnailPath = filePath.replace(
          path.extname(filePath),
          `-thumb${path.extname(filePath)}`
        );
        
        await sharp(filePath)
          .resize(200, 200, { fit: 'cover' })
          .toFile(thumbnailPath);
      }
      
      // Get file stats
      const stats = await fs.stat(outputPath);
      
      return {
        path: outputPath,
        thumbnailPath,
        size: stats.size,
        metadata: {
          width: metadata.width,
          height: metadata.height,
          format: metadata.format,
          space: metadata.space,
          channels: metadata.channels,
          density: metadata.density
        }
      };
    } catch (error) {
      logger.error('Image processing failed:', error);
      throw new AppError('Failed to process image', 500);
    }
  }
  
  /**
   * Process uploaded video
   * @param {string} filePath - File path
   * @param {Object} options - Processing options
   * @returns {Promise<Object>} Processing result
   */
  async processVideo(filePath, options = {}) {
    return new Promise((resolve, reject) => {
      const {
        width,
        height,
        bitrate = '1000k',
        format = 'mp4',
        thumbnail = true
      } = options;
      
      const outputPath = filePath.replace(
        path.extname(filePath),
        `-processed.${format}`
      );
      
      // Create ffmpeg command
      let command = ffmpeg(filePath);
      
      // Set video codec
      command = command.videoCodec(format === 'mp4' ? 'libx264' : 'libvpx');
      
      // Set dimensions if specified
      if (width || height) {
        command = command.size(`${width || '?'}x${height || '?'}`);
      }
      
      // Set bitrate
      command = command.videoBitrate(bitrate);
      
      // Set audio codec
      command = command.audioCodec('aac');
      
      // Process video
      command
        .output(outputPath)
        .on('end', async () => {
          const result = {
            path: outputPath,
            thumbnailPath: null
          };
          
          // Generate thumbnail if requested
          if (thumbnail) {
            const thumbnailPath = filePath.replace(
              path.extname(filePath),
              '-thumb.jpg'
            );
            
            await new Promise((thumbResolve, thumbReject) => {
              ffmpeg(filePath)
                .screenshots({
                  timestamps: ['50%'],
                  filename: path.basename(thumbnailPath),
                  folder: path.dirname(thumbnailPath),
                  size: '320x240'
                })
                .on('end', () => {
                  result.thumbnailPath = thumbnailPath;
                  thumbResolve();
                })
                .on('error', thumbReject);
            });
          }
          
          // Get video metadata
          ffmpeg.ffprobe(outputPath, (err, metadata) => {
            if (err) {
              reject(err);
            } else {
              result.metadata = {
                duration: metadata.format.duration,
                bitrate: metadata.format.bit_rate,
                size: metadata.format.size,
                format: metadata.format.format_name
              };
              resolve(result);
            }
          });
        })
        .on('error', reject)
        .run();
    });
  }
  
  /**
   * Upload file to S3
   * @param {string} filePath - Local file path
   * @param {string} s3Key - S3 object key
   * @param {Object} options - Upload options
   * @returns {Promise<Object>} Upload result
   */
  async uploadToS3(filePath, s3Key, options = {}) {
    try {
      const fileContent = await fs.readFile(filePath);
      const contentType = mime.lookup(filePath) || 'application/octet-stream';
      
      const uploadParams = {
        Bucket: this.s3Bucket,
        Key: s3Key,
        Body: fileContent,
        ContentType: contentType,
        ...options
      };
      
      // Add cache control for static assets
      if (contentType.startsWith('image/') || contentType.startsWith('video/')) {
        uploadParams.CacheControl = 'public, max-age=31536000';
      }
      
      const command = new PutObjectCommand(uploadParams);
      await this.s3Client.send(command);
      
      // Generate URL
      const url = `https://${this.s3Bucket}.s3.${config.storage.s3.region}.amazonaws.com/${s3Key}`;
      
      return {
        key: s3Key,
        url,
        bucket: this.s3Bucket
      };
    } catch (error) {
      logger.error('S3 upload failed:', error);
      throw new AppError('Failed to upload file to S3', 500);
    }
  }
  
  /**
   * Generate signed URL for S3 object
   * @param {string} s3Key - S3 object key
   * @param {number} expiresIn - Expiration time in seconds
   * @returns {Promise<string>} Signed URL
   */
  async getSignedUrl(s3Key, expiresIn = 3600) {
    try {
      const command = new GetObjectCommand({
        Bucket: this.s3Bucket,
        Key: s3Key
      });
      
      return await getSignedUrl(this.s3Client, command, { expiresIn });
    } catch (error) {
      logger.error('Failed to generate signed URL:', error);
      throw new AppError('Failed to generate signed URL', 500);
    }
  }
  
  /**
   * Delete file
   * @param {string} filePath - File path or S3 key
   * @param {string} type - Storage type ('local' or 's3')
   * @returns {Promise<boolean>} Success status
   */
  async deleteFile(filePath, type = this.storageType) {
    try {
      if (type === 's3') {
        const command = new DeleteObjectCommand({
          Bucket: this.s3Bucket,
          Key: filePath
        });
        await this.s3Client.send(command);
      } else {
        await fs.unlink(filePath);
      }
      
      return true;
    } catch (error) {
      logger.error('Failed to delete file:', error);
      return false;
    }
  }
  
  /**
   * Clean up old temporary files
   * @param {number} maxAge - Maximum age in hours
   * @returns {Promise<number>} Number of files deleted
   */
  async cleanupTempFiles(maxAge = 24) {
    try {
      const files = await fs.readdir(this.tempDir);
      const now = Date.now();
      const maxAgeMs = maxAge * 60 * 60 * 1000;
      let deletedCount = 0;
      
      for (const file of files) {
        const filePath = path.join(this.tempDir, file);
        const stats = await fs.stat(filePath);
        
        if (now - stats.mtime.getTime() > maxAgeMs) {
          await fs.unlink(filePath);
          deletedCount++;
        }
      }
      
      logger.info(`Cleaned up ${deletedCount} temporary files`);
      return deletedCount;
    } catch (error) {
      logger.error('Temp file cleanup failed:', error);
      return 0;
    }
  }
  
  /**
   * Get file metadata
   * @param {string} filePath - File path
   * @returns {Promise<Object>} File metadata
   */
  async getFileMetadata(filePath) {
    try {
      const stats = await fs.stat(filePath);
      const mimeType = mime.lookup(filePath);
      
      const metadata = {
        name: path.basename(filePath),
        size: stats.size,
        mimeType,
        createdAt: stats.birthtime,
        modifiedAt: stats.mtime
      };
      
      // Add image-specific metadata
      if (mimeType && mimeType.startsWith('image/')) {
        try {
          const imageMetadata = await sharp(filePath).metadata();
          metadata.dimensions = {
            width: imageMetadata.width,
            height: imageMetadata.height
          };
          metadata.format = imageMetadata.format;
        } catch (error) {
          // Not an image or sharp failed
        }
      }
      
      return metadata;
    } catch (error) {
      logger.error('Failed to get file metadata:', error);
      throw new AppError('Failed to get file metadata', 500);
    }
  }
  
  /**
   * Create upload handlers for different file types
   */
  get upload() {
    return {
      single: (fieldName, options = {}) => {
        const middleware = this.createUploadMiddleware(options);
        return middleware.single(fieldName);
      },
      
      multiple: (fieldName, maxCount = 10, options = {}) => {
        const middleware = this.createUploadMiddleware({ ...options, maxFiles: maxCount });
        return middleware.array(fieldName, maxCount);
      },
      
      fields: (fields, options = {}) => {
        const middleware = this.createUploadMiddleware(options);
        return middleware.fields(fields);
      },
      
      image: (fieldName, options = {}) => {
        return this.upload.single(fieldName, {
          ...options,
          allowedTypes: constants.FILE_UPLOAD.ALLOWED_TYPES.IMAGE,
          maxSize: options.maxSize || constants.FILE_UPLOAD.MAX_SIZE.IMAGE
        });
      },
      
      document: (fieldName, options = {}) => {
        return this.upload.single(fieldName, {
          ...options,
          allowedTypes: constants.FILE_UPLOAD.ALLOWED_TYPES.DOCUMENT,
          maxSize: options.maxSize || constants.FILE_UPLOAD.MAX_SIZE.DOCUMENT
        });
      },
      
      video: (fieldName, options = {}) => {
        return this.upload.single(fieldName, {
          ...options,
          allowedTypes: constants.FILE_UPLOAD.ALLOWED_TYPES.VIDEO,
          maxSize: options.maxSize || constants.FILE_UPLOAD.MAX_SIZE.VIDEO
        });
      }
    };
  }
}

// Create singleton instance
const fileHelper = new FileHelper();

module.exports = fileHelper;