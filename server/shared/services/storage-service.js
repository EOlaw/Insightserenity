// /server/shared/services/storage-service.js

/**
 * @file Storage Service
 * @description File storage service with S3, Google Cloud Storage, and local storage support
 * @version 1.0.0
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');
const { 
  S3Client, 
  PutObjectCommand, 
  GetObjectCommand, 
  DeleteObjectCommand,
  HeadObjectCommand,
  CopyObjectCommand,
  ListObjectsV2Command
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { Storage } = require('@google-cloud/storage');
const logger = require('../utils/logger');
const config = require('../config');
const fileHelper = require('../utils/helpers/file-helper');
const { AppError } = require('../utils/app-error');

/**
 * Storage Service Class
 */
class StorageService {
  constructor() {
    this.provider = config.storage.provider || 'local';
    this.bucket = config.storage.bucket;
    this.region = config.storage.region;
    this.cdnUrl = config.storage.cdnUrl;
    
    this.initializeProvider();
  }
  
  /**
   * Initialize storage provider
   */
  initializeProvider() {
    try {
      switch (this.provider) {
        case 's3':
          this.initializeS3();
          break;
        case 'gcs':
          this.initializeGCS();
          break;
        case 'azure':
          this.initializeAzure();
          break;
        case 'local':
        default:
          this.initializeLocal();
      }
      
      logger.info(`Storage service initialized with provider: ${this.provider}`);
    } catch (error) {
      logger.error('Failed to initialize storage service:', error);
      throw new AppError('Storage service initialization failed', 500);
    }
  }
  
  /**
   * Initialize AWS S3
   */
  initializeS3() {
    this.s3Client = new S3Client({
      region: this.region,
      credentials: {
        accessKeyId: config.storage.s3.accessKeyId,
        secretAccessKey: config.storage.s3.secretAccessKey
      }
    });
  }
  
  /**
   * Initialize Google Cloud Storage
   */
  initializeGCS() {
    this.gcsClient = new Storage({
      projectId: config.storage.gcs.projectId,
      keyFilename: config.storage.gcs.keyFilename
    });
    
    this.gcsBucket = this.gcsClient.bucket(this.bucket);
  }
  
  /**
   * Initialize Azure Blob Storage
   */
  initializeAzure() {
    const { BlobServiceClient } = require('@azure/storage-blob');
    
    this.azureClient = BlobServiceClient.fromConnectionString(
      config.storage.azure.connectionString
    );
    
    this.azureContainer = this.azureClient.getContainerClient(this.bucket);
  }
  
  /**
   * Initialize local storage
   */
  initializeLocal() {
    this.localBasePath = config.storage.localPath || path.join(__dirname, '../../../uploads');
    this.ensureLocalDirectories();
  }
  
  /**
   * Ensure local directories exist
   */
  async ensureLocalDirectories() {
    const directories = [
      this.localBasePath,
      path.join(this.localBasePath, 'images'),
      path.join(this.localBasePath, 'documents'),
      path.join(this.localBasePath, 'videos'),
      path.join(this.localBasePath, 'temp')
    ];
    
    for (const dir of directories) {
      await fs.mkdir(dir, { recursive: true });
    }
  }
  
  /**
   * Upload file
   * @param {Object} file - File object
   * @param {Object} options - Upload options
   * @returns {Promise<Object>} Upload result
   */
  async upload(file, options = {}) {
    try {
      const {
        folder = 'general',
        filename,
        contentType,
        metadata = {},
        acl = 'private',
        processImage = false,
        generateThumbnail = false
      } = options;
      
      // Generate file key
      const fileKey = this.generateFileKey(file, folder, filename);
      
      // Process image if requested
      let processedFile = file;
      let thumbnailKey = null;
      
      if (processImage && this.isImage(file)) {
        processedFile = await this.processImageFile(file, options);
        
        if (generateThumbnail) {
          const thumbnail = await this.generateThumbnailFile(file, options);
          thumbnailKey = this.generateFileKey(thumbnail, `${folder}/thumbnails`, `thumb_${filename}`);
          await this.uploadToProvider(thumbnail, thumbnailKey, {
            contentType: thumbnail.mimetype,
            metadata: { ...metadata, type: 'thumbnail' },
            acl
          });
        }
      }
      
      // Upload to provider
      const result = await this.uploadToProvider(processedFile, fileKey, {
        contentType: contentType || processedFile.mimetype,
        metadata,
        acl
      });
      
      // Add additional information
      result.filename = processedFile.originalname;
      result.size = processedFile.size;
      result.mimetype = processedFile.mimetype;
      result.thumbnailUrl = thumbnailKey ? this.getUrl(thumbnailKey) : null;
      
      return result;
    } catch (error) {
      logger.error('File upload failed:', error);
      throw new AppError('Failed to upload file', 500);
    }
  }
  
  /**
   * Upload to specific provider
   */
  async uploadToProvider(file, key, options) {
    switch (this.provider) {
      case 's3':
        return this.uploadToS3(file, key, options);
      case 'gcs':
        return this.uploadToGCS(file, key, options);
      case 'azure':
        return this.uploadToAzure(file, key, options);
      case 'local':
      default:
        return this.uploadToLocal(file, key, options);
    }
  }
  
  /**
   * Upload to S3
   */
  async uploadToS3(file, key, options) {
    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: file.buffer || await fs.readFile(file.path),
      ContentType: options.contentType,
      Metadata: options.metadata,
      ACL: options.acl,
      CacheControl: this.getCacheControl(options.contentType),
      ...(options.serverSideEncryption && {
        ServerSideEncryption: 'AES256'
      })
    });
    
    await this.s3Client.send(command);
    
    return {
      key,
      url: this.getUrl(key),
      provider: 's3',
      bucket: this.bucket
    };
  }
  
  /**
   * Upload to Google Cloud Storage
   */
  async uploadToGCS(file, key, options) {
    const blob = this.gcsBucket.file(key);
    
    const stream = blob.createWriteStream({
      metadata: {
        contentType: options.contentType,
        metadata: options.metadata,
        cacheControl: this.getCacheControl(options.contentType)
      },
      resumable: false
    });
    
    return new Promise((resolve, reject) => {
      stream.on('error', reject);
      stream.on('finish', () => {
        if (options.acl === 'public-read') {
          blob.makePublic();
        }
        
        resolve({
          key,
          url: this.getUrl(key),
          provider: 'gcs',
          bucket: this.bucket
        });
      });
      
      if (file.buffer) {
        stream.end(file.buffer);
      } else {
        fs.createReadStream(file.path).pipe(stream);
      }
    });
  }
  
  /**
   * Upload to Azure
   */
  async uploadToAzure(file, key, options) {
    const blockBlobClient = this.azureContainer.getBlockBlobClient(key);
    
    const uploadOptions = {
      blobHTTPHeaders: {
        blobContentType: options.contentType,
        blobCacheControl: this.getCacheControl(options.contentType)
      },
      metadata: options.metadata
    };
    
    if (file.buffer) {
      await blockBlobClient.upload(file.buffer, file.buffer.length, uploadOptions);
    } else {
      await blockBlobClient.uploadFile(file.path, uploadOptions);
    }
    
    return {
      key,
      url: this.getUrl(key),
      provider: 'azure',
      container: this.bucket
    };
  }
  
  /**
   * Upload to local storage
   */
  async uploadToLocal(file, key, options) {
    const filePath = path.join(this.localBasePath, key);
    const dir = path.dirname(filePath);
    
    // Ensure directory exists
    await fs.mkdir(dir, { recursive: true });
    
    // Write file
    if (file.buffer) {
      await fs.writeFile(filePath, file.buffer);
    } else {
      await fs.copyFile(file.path, filePath);
    }
    
    // Store metadata
    const metadataPath = `${filePath}.meta.json`;
    await fs.writeFile(metadataPath, JSON.stringify({
      contentType: options.contentType,
      metadata: options.metadata,
      uploadedAt: new Date().toISOString()
    }));
    
    return {
      key,
      url: this.getUrl(key),
      provider: 'local',
      path: filePath
    };
  }
  
  /**
   * Get file URL
   */
  getUrl(key) {
    if (this.cdnUrl) {
      return `${this.cdnUrl}/${key}`;
    }
    
    switch (this.provider) {
      case 's3':
        return `https://${this.bucket}.s3.${this.region}.amazonaws.com/${key}`;
      case 'gcs':
        return `https://storage.googleapis.com/${this.bucket}/${key}`;
      case 'azure':
        return `https://${config.storage.azure.accountName}.blob.core.windows.net/${this.bucket}/${key}`;
      case 'local':
      default:
        return `/uploads/${key}`;
    }
  }
  
  /**
   * Get signed URL for private files
   */
  async getSignedUrl(key, expiresIn = 3600) {
    switch (this.provider) {
      case 's3':
        return this.getS3SignedUrl(key, expiresIn);
      case 'gcs':
        return this.getGCSSignedUrl(key, expiresIn);
      case 'azure':
        return this.getAzureSignedUrl(key, expiresIn);
      case 'local':
      default:
        return this.getLocalSignedUrl(key, expiresIn);
    }
  }
  
  /**
   * Get S3 signed URL
   */
  async getS3SignedUrl(key, expiresIn) {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key
    });
    
    return getSignedUrl(this.s3Client, command, { expiresIn });
  }
  
  /**
   * Get GCS signed URL
   */
  async getGCSSignedUrl(key, expiresIn) {
    const [url] = await this.gcsBucket.file(key).getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: Date.now() + expiresIn * 1000
    });
    
    return url;
  }
  
  /**
   * Get Azure signed URL
   */
  async getAzureSignedUrl(key, expiresIn) {
    const { generateBlobSASQueryParameters, BlobSASPermissions } = require('@azure/storage-blob');
    
    const sasOptions = {
      containerName: this.bucket,
      blobName: key,
      permissions: BlobSASPermissions.parse('r'),
      startsOn: new Date(),
      expiresOn: new Date(Date.now() + expiresIn * 1000)
    };
    
    const sasToken = generateBlobSASQueryParameters(
      sasOptions,
      config.storage.azure.sharedKeyCredential
    ).toString();
    
    return `${this.getUrl(key)}?${sasToken}`;
  }
  
  /**
   * Get local signed URL (using JWT)
   */
  async getLocalSignedUrl(key, expiresIn) {
    const jwt = require('jsonwebtoken');
    
    const token = jwt.sign(
      { key, type: 'file-access' },
      config.auth.jwtSecret,
      { expiresIn }
    );
    
    return `/api/files/signed/${encodeURIComponent(key)}?token=${token}`;
  }
  
  /**
   * Download file
   */
  async download(key) {
    switch (this.provider) {
      case 's3':
        return this.downloadFromS3(key);
      case 'gcs':
        return this.downloadFromGCS(key);
      case 'azure':
        return this.downloadFromAzure(key);
      case 'local':
      default:
        return this.downloadFromLocal(key);
    }
  }
  
  /**
   * Download from S3
   */
  async downloadFromS3(key) {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key
    });
    
    const response = await this.s3Client.send(command);
    
    return {
      stream: response.Body,
      contentType: response.ContentType,
      contentLength: response.ContentLength,
      metadata: response.Metadata
    };
  }
  
  /**
   * Delete file
   */
  async delete(key) {
    try {
      switch (this.provider) {
        case 's3':
          await this.deleteFromS3(key);
          break;
        case 'gcs':
          await this.deleteFromGCS(key);
          break;
        case 'azure':
          await this.deleteFromAzure(key);
          break;
        case 'local':
        default:
          await this.deleteFromLocal(key);
      }
      
      logger.info('File deleted successfully', { key, provider: this.provider });
      return true;
    } catch (error) {
      logger.error('File deletion failed:', error);
      throw new AppError('Failed to delete file', 500);
    }
  }
  
  /**
   * Delete from S3
   */
  async deleteFromS3(key) {
    const command = new DeleteObjectCommand({
      Bucket: this.bucket,
      Key: key
    });
    
    await this.s3Client.send(command);
  }
  
  /**
   * Delete from local storage
   */
  async deleteFromLocal(key) {
    const filePath = path.join(this.localBasePath, key);
    await fs.unlink(filePath);
    
    // Delete metadata if exists
    try {
      await fs.unlink(`${filePath}.meta.json`);
    } catch (error) {
      // Ignore if metadata doesn't exist
    }
  }
  
  /**
   * Copy file
   */
  async copy(sourceKey, destinationKey) {
    switch (this.provider) {
      case 's3':
        return this.copyInS3(sourceKey, destinationKey);
      case 'local':
      default:
        return this.copyInLocal(sourceKey, destinationKey);
    }
  }
  
  /**
   * Copy in S3
   */
  async copyInS3(sourceKey, destinationKey) {
    const command = new CopyObjectCommand({
      Bucket: this.bucket,
      CopySource: `${this.bucket}/${sourceKey}`,
      Key: destinationKey
    });
    
    await this.s3Client.send(command);
    
    return {
      key: destinationKey,
      url: this.getUrl(destinationKey)
    };
  }
  
  /**
   * List files
   */
  async list(prefix, options = {}) {
    switch (this.provider) {
      case 's3':
        return this.listFromS3(prefix, options);
      case 'local':
      default:
        return this.listFromLocal(prefix, options);
    }
  }
  
  /**
   * List from S3
   */
  async listFromS3(prefix, options) {
    const command = new ListObjectsV2Command({
      Bucket: this.bucket,
      Prefix: prefix,
      MaxKeys: options.limit || 1000,
      ContinuationToken: options.continuationToken
    });
    
    const response = await this.s3Client.send(command);
    
    return {
      files: response.Contents?.map(item => ({
        key: item.Key,
        size: item.Size,
        lastModified: item.LastModified,
        etag: item.ETag
      })) || [],
      isTruncated: response.IsTruncated,
      continuationToken: response.NextContinuationToken
    };
  }
  
  /**
   * Check if file exists
   */
  async exists(key) {
    try {
      switch (this.provider) {
        case 's3':
          const command = new HeadObjectCommand({
            Bucket: this.bucket,
            Key: key
          });
          await this.s3Client.send(command);
          return true;
        case 'local':
        default:
          const filePath = path.join(this.localBasePath, key);
          await fs.access(filePath);
          return true;
      }
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Generate file key
   */
  generateFileKey(file, folder, customName) {
    const timestamp = Date.now();
    const randomString = crypto.randomBytes(8).toString('hex');
    const extension = path.extname(file.originalname || file.name);
    const basename = customName || 
                    path.basename(file.originalname || file.name, extension)
                      .replace(/[^a-zA-Z0-9]/g, '-')
                      .toLowerCase();
    
    return `${folder}/${timestamp}-${randomString}-${basename}${extension}`;
  }
  
  /**
   * Check if file is image
   */
  isImage(file) {
    const imageMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    return imageMimeTypes.includes(file.mimetype);
  }
  
  /**
   * Process image file
   */
  async processImageFile(file, options = {}) {
    const {
      width,
      height,
      quality = 85,
      format,
      fit = 'cover'
    } = options;
    
    let sharpInstance = sharp(file.buffer || file.path);
    
    if (width || height) {
      sharpInstance = sharpInstance.resize(width, height, { fit });
    }
    
    if (format) {
      sharpInstance = sharpInstance.toFormat(format, { quality });
    }
    
    const buffer = await sharpInstance.toBuffer();
    
    return {
      ...file,
      buffer,
      size: buffer.length
    };
  }
  
  /**
   * Generate thumbnail
   */
  async generateThumbnailFile(file, options = {}) {
    const {
      width = 200,
      height = 200,
      quality = 80
    } = options;
    
    const buffer = await sharp(file.buffer || file.path)
      .resize(width, height, { fit: 'cover' })
      .jpeg({ quality })
      .toBuffer();
    
    return {
      ...file,
      buffer,
      size: buffer.length,
      originalname: `thumb_${file.originalname}`,
      mimetype: 'image/jpeg'
    };
  }
  
  /**
   * Get cache control header
   */
  getCacheControl(contentType) {
    if (contentType?.startsWith('image/')) {
      return 'public, max-age=31536000'; // 1 year
    }
    
    if (contentType?.startsWith('video/')) {
      return 'public, max-age=604800'; // 1 week
    }
    
    return 'private, max-age=3600'; // 1 hour
  }
}

// Create singleton instance
const storageService = new StorageService();

module.exports = storageService;