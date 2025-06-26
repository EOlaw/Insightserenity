// server/core-business/reports/models/schemas/report-export-schema.js
/**
 * @file Report Export Schema
 * @description Schema for report export configuration
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Report Export Schema
 */
const reportExportSchema = new Schema({
  // Export Formats
  formats: [{
    type: {
      type: String,
      enum: ['pdf', 'excel', 'csv', 'json', 'xml', 'html', 'powerpoint', 'word'],
      required: true
    },
    
    enabled: {
      type: Boolean,
      default: true
    },
    
    // Format-specific Configuration
    config: {
      // PDF Configuration
      pdf: {
        pageSize: {
          type: String,
          enum: ['A4', 'A3', 'Letter', 'Legal', 'Tabloid'],
          default: 'A4'
        },
        orientation: {
          type: String,
          enum: ['portrait', 'landscape'],
          default: 'portrait'
        },
        margins: {
          top: { type: Number, default: 10 },
          right: { type: Number, default: 10 },
          bottom: { type: Number, default: 10 },
          left: { type: Number, default: 10 }
        },
        includeHeader: {
          type: Boolean,
          default: true
        },
        includeFooter: {
          type: Boolean,
          default: true
        },
        includePageNumbers: {
          type: Boolean,
          default: true
        },
        includeTimestamp: {
          type: Boolean,
          default: true
        },
        includeTOC: {
          type: Boolean,
          default: false
        },
        compression: {
          type: Boolean,
          default: true
        },
        encryption: {
          enabled: Boolean,
          password: String,
          permissions: {
            printing: Boolean,
            copying: Boolean,
            modifying: Boolean
          }
        }
      },
      
      // Excel Configuration
      excel: {
        format: {
          type: String,
          enum: ['xlsx', 'xls'],
          default: 'xlsx'
        },
        includeFormulas: {
          type: Boolean,
          default: true
        },
        includePivotTables: {
          type: Boolean,
          default: true
        },
        includeCharts: {
          type: Boolean,
          default: true
        },
        sheetsConfig: [{
          name: String,
          data: String, // Reference to visualization
          includeFilters: Boolean,
          freezePanes: {
            row: Number,
            column: Number
          },
          protection: {
            enabled: Boolean,
            password: String
          }
        }],
        styling: {
          theme: String,
          headerStyle: Schema.Types.Mixed,
          dataStyle: Schema.Types.Mixed,
          alternateRows: Boolean
        }
      },
      
      // CSV Configuration
      csv: {
        delimiter: {
          type: String,
          default: ','
        },
        quoteCharacter: {
          type: String,
          default: '"'
        },
        escapeCharacter: {
          type: String,
          default: '"'
        },
        includeHeaders: {
          type: Boolean,
          default: true
        },
        encoding: {
          type: String,
          enum: ['utf-8', 'utf-16', 'ascii', 'iso-8859-1'],
          default: 'utf-8'
        },
        lineTerminator: {
          type: String,
          enum: ['\\n', '\\r\\n'],
          default: '\\n'
        },
        nullValue: {
          type: String,
          default: ''
        }
      },
      
      // JSON Configuration
      json: {
        pretty: {
          type: Boolean,
          default: true
        },
        indent: {
          type: Number,
          default: 2
        },
        includeMetadata: {
          type: Boolean,
          default: false
        },
        structure: {
          type: String,
          enum: ['flat', 'nested', 'normalized'],
          default: 'flat'
        },
        dateFormat: {
          type: String,
          default: 'ISO8601'
        }
      },
      
      // HTML Configuration
      html: {
        template: String,
        includeCSS: {
          type: Boolean,
          default: true
        },
        includeJS: {
          type: Boolean,
          default: true
        },
        responsive: {
          type: Boolean,
          default: true
        },
        embedImages: {
          type: Boolean,
          default: true
        },
        minify: {
          type: Boolean,
          default: false
        }
      }
    }
  }],
  
  // Export Options
  options: {
    // Data Options
    includeAllData: {
      type: Boolean,
      default: false
    },
    
    maxRows: {
      type: Number,
      default: 50000
    },
    
    sampling: {
      enabled: Boolean,
      method: {
        type: String,
        enum: ['random', 'systematic', 'stratified']
      },
      size: Number,
      seed: Number
    },
    
    // Content Options
    includeVisualizations: {
      type: Boolean,
      default: true
    },
    
    includeRawData: {
      type: Boolean,
      default: true
    },
    
    includeSummary: {
      type: Boolean,
      default: true
    },
    
    includeFilters: {
      type: Boolean,
      default: true
    },
    
    includeParameters: {
      type: Boolean,
      default: true
    },
    
    includeMetadata: {
      type: Boolean,
      default: false
    },
    
    // Formatting Options
    dateFormat: {
      type: String,
      default: 'YYYY-MM-DD'
    },
    
    numberFormat: {
      thousandsSeparator: {
        type: String,
        default: ','
      },
      decimalSeparator: {
        type: String,
        default: '.'
      },
      decimalPlaces: Number,
      useScientificNotation: Boolean
    },
    
    currencyFormat: {
      symbol: String,
      position: {
        type: String,
        enum: ['before', 'after'],
        default: 'before'
      },
      decimalPlaces: {
        type: Number,
        default: 2
      }
    },
    
    nullHandling: {
      displayValue: {
        type: String,
        default: 'N/A'
      },
      exportValue: Schema.Types.Mixed
    }
  },
  
  // Template Configuration
  templates: [{
    name: String,
    format: String,
    isDefault: Boolean,
    template: {
      type: {
        type: String,
        enum: ['builtin', 'custom', 'external']
      },
      
      builtin: {
        name: String,
        version: String
      },
      
      custom: {
        content: String,
        engine: {
          type: String,
          enum: ['handlebars', 'mustache', 'ejs', 'pug']
        },
        helpers: Schema.Types.Mixed,
        partials: Schema.Types.Mixed
      },
      
      external: {
        url: String,
        method: String,
        headers: Schema.Types.Mixed,
        authentication: Schema.Types.Mixed
      }
    },
    
    sections: [{
      type: {
        type: String,
        enum: ['header', 'cover', 'toc', 'summary', 'content', 'appendix', 'footer']
      },
      enabled: Boolean,
      template: String,
      data: Schema.Types.Mixed
    }],
    
    styling: {
      css: String,
      theme: String,
      fonts: [String],
      colors: Schema.Types.Mixed
    }
  }],
  
  // Compression and Packaging
  compression: {
    enabled: {
      type: Boolean,
      default: false
    },
    
    format: {
      type: String,
      enum: ['zip', 'gzip', '7z', 'tar'],
      default: 'zip'
    },
    
    level: {
      type: Number,
      min: 1,
      max: 9,
      default: 6
    },
    
    includeMultipleFormats: Boolean,
    
    structure: {
      createFolder: Boolean,
      folderName: String,
      includeReadme: Boolean,
      includeMetadata: Boolean
    }
  },
  
  // Security and Watermarking
  security: {
    watermark: {
      enabled: Boolean,
      text: String,
      image: String,
      position: {
        type: String,
        enum: ['center', 'top-left', 'top-right', 'bottom-left', 'bottom-right', 'diagonal'],
        default: 'center'
      },
      opacity: {
        type: Number,
        min: 0,
        max: 1,
        default: 0.3
      },
      rotation: Number
    },
    
    encryption: {
      enabled: Boolean,
      algorithm: {
        type: String,
        enum: ['AES-256', 'AES-128', 'RSA'],
        default: 'AES-256'
      },
      passwordRequired: Boolean,
      certificateRequired: Boolean
    },
    
    digitalSignature: {
      enabled: Boolean,
      certificate: String,
      timestampServer: String
    },
    
    restrictions: {
      expiryDate: Date,
      maxDownloads: Number,
      ipWhitelist: [String],
      requireAuthentication: Boolean
    }
  },
  
  // Post-processing
  postProcessing: [{
    type: {
      type: String,
      enum: ['script', 'webhook', 'function']
    },
    
    enabled: Boolean,
    
    script: {
      language: {
        type: String,
        enum: ['javascript', 'python', 'shell']
      },
      code: String,
      timeout: Number
    },
    
    webhook: {
      url: String,
      method: String,
      headers: Schema.Types.Mixed,
      retries: Number
    },
    
    function: {
      name: String,
      parameters: Schema.Types.Mixed
    },
    
    onError: {
      type: String,
      enum: ['fail', 'continue', 'retry'],
      default: 'fail'
    }
  }],
  
  // Storage Configuration
  storage: {
    temporary: {
      provider: {
        type: String,
        enum: ['local', 's3', 'azure', 'gcs'],
        default: 'local'
      },
      
      retention: {
        duration: {
          type: Number,
          default: 24 // hours
        },
        cleanupEnabled: {
          type: Boolean,
          default: true
        }
      },
      
      path: String,
      
      s3: {
        bucket: String,
        region: String,
        prefix: String
      },
      
      azure: {
        container: String,
        accountName: String
      },
      
      gcs: {
        bucket: String,
        projectId: String
      }
    },
    
    permanent: {
      enabled: Boolean,
      provider: String,
      config: Schema.Types.Mixed
    }
  },
  
  // Performance Configuration
  performance: {
    streaming: {
      enabled: {
        type: Boolean,
        default: true
      },
      chunkSize: {
        type: Number,
        default: 1024 * 1024 // 1MB
      }
    },
    
    parallel: {
      enabled: Boolean,
      maxWorkers: Number
    },
    
    caching: {
      enabled: Boolean,
      duration: Number
    },
    
    optimization: {
      imageCompression: Boolean,
      fontSubsetting: Boolean,
      dataDeduplication: Boolean
    }
  },
  
  // Metadata
  defaultFormat: {
    type: String,
    enum: ['pdf', 'excel', 'csv', 'json'],
    default: 'pdf'
  },
  
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  _id: false,
  timestamps: true
});

module.exports = { reportExportSchema };