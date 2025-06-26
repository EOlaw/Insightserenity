// server/core-business/reports/models/schemas/report-visualization-schema.js
/**
 * @file Report Visualization Schema
 * @description Schema for report visualization configuration
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Report Visualization Schema
 */
const reportVisualizationSchema = new Schema({
  // Visualization Identification
  id: {
    type: String,
    required: true
  },
  
  name: {
    type: String,
    required: true,
    trim: true
  },
  
  title: {
    type: String,
    required: true
  },
  
  subtitle: String,
  
  description: String,
  
  // Visualization Type
  type: {
    type: String,
    required: true,
    enum: [
      // Charts
      'line',
      'bar',
      'column',
      'area',
      'pie',
      'donut',
      'scatter',
      'bubble',
      'heatmap',
      'treemap',
      'sunburst',
      'sankey',
      'gauge',
      'radar',
      'funnel',
      'waterfall',
      'boxplot',
      'candlestick',
      
      // Tables
      'table',
      'pivotTable',
      'dataGrid',
      
      // Metrics
      'metric',
      'scorecard',
      'kpi',
      'progress',
      
      // Maps
      'geoMap',
      'choropleth',
      
      // Others
      'text',
      'image',
      'custom'
    ]
  },
  
  // Data Configuration
  dataSource: {
    name: String, // Reference to data source
    query: Schema.Types.Mixed,
    aggregation: Schema.Types.Mixed,
    filters: [Schema.Types.Mixed]
  },
  
  // Chart Configuration
  chartConfig: {
    // Axes
    xAxis: {
      field: String,
      label: String,
      type: {
        type: String,
        enum: ['category', 'value', 'time', 'log']
      },
      format: String,
      min: Schema.Types.Mixed,
      max: Schema.Types.Mixed,
      interval: Schema.Types.Mixed,
      rotate: Number,
      show: {
        type: Boolean,
        default: true
      }
    },
    
    yAxis: [{
      field: String,
      label: String,
      type: {
        type: String,
        enum: ['value', 'category', 'time', 'log']
      },
      format: String,
      min: Schema.Types.Mixed,
      max: Schema.Types.Mixed,
      position: {
        type: String,
        enum: ['left', 'right']
      },
      show: {
        type: Boolean,
        default: true
      }
    }],
    
    // Series
    series: [{
      name: String,
      field: String,
      type: String, // Override chart type for mixed charts
      aggregation: {
        type: String,
        enum: ['sum', 'avg', 'min', 'max', 'count', 'distinct']
      },
      color: String,
      stack: String,
      yAxisIndex: Number,
      dataLabels: {
        show: Boolean,
        format: String,
        position: String
      }
    }],
    
    // Additional dimensions
    groupBy: String,
    splitBy: String,
    sizeBy: String, // For bubble charts
    colorBy: String,
    
    // Chart-specific options
    pieConfig: {
      innerRadius: Number, // For donut
      startAngle: Number,
      endAngle: Number,
      showLabels: Boolean,
      showPercentage: Boolean
    },
    
    mapConfig: {
      region: String,
      geoField: String,
      valueField: String,
      colorScale: [String],
      zoom: {
        enabled: Boolean,
        level: Number
      }
    }
  },
  
  // Table Configuration
  tableConfig: {
    columns: [{
      field: String,
      header: String,
      width: Schema.Types.Mixed,
      align: {
        type: String,
        enum: ['left', 'center', 'right']
      },
      format: {
        type: String,
        pattern: String
      },
      sortable: {
        type: Boolean,
        default: true
      },
      filterable: {
        type: Boolean,
        default: true
      },
      frozen: Boolean,
      hidden: Boolean,
      aggregation: String,
      cellRenderer: String,
      headerStyle: Schema.Types.Mixed,
      cellStyle: Schema.Types.Mixed
    }],
    
    rowGrouping: {
      enabled: Boolean,
      fields: [String],
      aggregations: Schema.Types.Mixed
    },
    
    pagination: {
      enabled: {
        type: Boolean,
        default: true
      },
      pageSize: {
        type: Number,
        default: 20
      },
      pageSizes: [Number]
    },
    
    totals: {
      show: Boolean,
      position: {
        type: String,
        enum: ['top', 'bottom']
      },
      fields: [String]
    },
    
    export: {
      enabled: {
        type: Boolean,
        default: true
      },
      formats: [{
        type: String,
        enum: ['csv', 'excel', 'pdf']
      }]
    }
  },
  
  // Metric Configuration
  metricConfig: {
    value: {
      field: String,
      aggregation: String,
      format: String,
      prefix: String,
      suffix: String
    },
    
    comparison: {
      enabled: Boolean,
      type: {
        type: String,
        enum: ['previous_period', 'target', 'custom']
      },
      field: String,
      value: Schema.Types.Mixed,
      format: String,
      showAs: {
        type: String,
        enum: ['value', 'percentage', 'both']
      }
    },
    
    trend: {
      show: Boolean,
      field: String,
      periods: Number,
      type: {
        type: String,
        enum: ['line', 'area', 'bar']
      }
    },
    
    thresholds: [{
      value: Number,
      color: String,
      label: String,
      operator: {
        type: String,
        enum: ['gt', 'gte', 'lt', 'lte', 'between']
      }
    }],
    
    icon: {
      show: Boolean,
      type: String,
      position: {
        type: String,
        enum: ['left', 'right', 'top']
      }
    }
  },
  
  // Style Configuration
  style: {
    // Layout
    height: Schema.Types.Mixed,
    width: Schema.Types.Mixed,
    minHeight: Number,
    maxHeight: Number,
    aspectRatio: String,
    
    // Colors
    colorScheme: {
      type: String,
      enum: ['default', 'monochrome', 'gradient', 'custom']
    },
    colors: [String],
    backgroundColor: String,
    
    // Typography
    font: {
      family: String,
      size: {
        title: Number,
        subtitle: Number,
        label: Number,
        value: Number
      }
    },
    
    // Borders and spacing
    border: {
      show: Boolean,
      color: String,
      width: Number,
      radius: Number
    },
    
    padding: {
      top: Number,
      right: Number,
      bottom: Number,
      left: Number
    },
    
    // Shadows
    shadow: {
      enabled: Boolean,
      type: {
        type: String,
        enum: ['small', 'medium', 'large']
      }
    }
  },
  
  // Interactivity
  interactions: {
    // Click actions
    onClick: {
      enabled: Boolean,
      action: {
        type: String,
        enum: ['drillDown', 'filter', 'navigate', 'custom']
      },
      target: String,
      parameters: Schema.Types.Mixed
    },
    
    // Hover
    tooltip: {
      enabled: {
        type: Boolean,
        default: true
      },
      format: String,
      fields: [String],
      customContent: String
    },
    
    // Selection
    selection: {
      enabled: Boolean,
      mode: {
        type: String,
        enum: ['single', 'multiple']
      },
      action: String
    },
    
    // Zoom and pan
    zoom: {
      enabled: Boolean,
      type: {
        type: String,
        enum: ['x', 'y', 'xy']
      }
    },
    
    // Export
    export: {
      enabled: Boolean,
      formats: [{
        type: String,
        enum: ['png', 'jpg', 'svg', 'pdf']
      }]
    }
  },
  
  // Animation
  animation: {
    enabled: {
      type: Boolean,
      default: true
    },
    duration: {
      type: Number,
      default: 1000
    },
    easing: {
      type: String,
      enum: ['linear', 'easeIn', 'easeOut', 'easeInOut'],
      default: 'easeOut'
    },
    delay: Number
  },
  
  // Responsive Configuration
  responsive: {
    enabled: {
      type: Boolean,
      default: true
    },
    breakpoints: [{
      maxWidth: Number,
      config: Schema.Types.Mixed
    }],
    maintainAspectRatio: Boolean
  },
  
  // Legend Configuration
  legend: {
    show: {
      type: Boolean,
      default: true
    },
    position: {
      type: String,
      enum: ['top', 'bottom', 'left', 'right'],
      default: 'bottom'
    },
    align: {
      type: String,
      enum: ['start', 'center', 'end'],
      default: 'center'
    },
    orientation: {
      type: String,
      enum: ['horizontal', 'vertical'],
      default: 'horizontal'
    }
  },
  
  // Custom Configuration
  customConfig: Schema.Types.Mixed,
  
  // Dependencies
  dependencies: [{
    visualization: String,
    type: {
      type: String,
      enum: ['data', 'filter', 'parameter']
    },
    mapping: Schema.Types.Mixed
  }],
  
  // Metadata
  order: {
    type: Number,
    default: 0
  },
  
  tags: [String],
  
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  _id: false,
  timestamps: true
});

module.exports = { reportVisualizationSchema };