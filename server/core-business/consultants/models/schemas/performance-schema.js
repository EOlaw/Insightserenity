/**
 * @file Performance Schema
 * @description Schema for consultant performance reviews and metrics
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const performanceSchema = new Schema({
  reviews: [{
    period: {
      type: String,
      required: true,
      enum: ['quarterly', 'semi_annual', 'annual', 'project_end', 'probation']
    },
    year: { type: Number, required: true },
    quarter: Number,
    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    
    ratings: {
      overall: { type: Number, min: 1, max: 5, required: true },
      technical: { type: Number, min: 1, max: 5 },
      client: { type: Number, min: 1, max: 5 },
      leadership: { type: Number, min: 1, max: 5 },
      teamwork: { type: Number, min: 1, max: 5 },
      communication: { type: Number, min: 1, max: 5 },
      innovation: { type: Number, min: 1, max: 5 },
      delivery: { type: Number, min: 1, max: 5 }
    },
    
    metrics: {
      utilization: Number,
      billableHours: Number,
      revenueGenerated: Number,
      clientSatisfaction: Number,
      projectsCompleted: Number,
      projectSuccessRate: Number,
      teamFeedbackScore: Number
    },
    
    feedback: {
      strengths: [String],
      improvements: [String],
      achievements: [String],
      goals: [String]
    },
    
    reviewer: {
      primary: { type: Schema.Types.ObjectId, ref: 'User', required: true },
      secondary: { type: Schema.Types.ObjectId, ref: 'User' },
      reviewDate: Date
    },
    
    selfAssessment: {
      submitted: { type: Boolean, default: false },
      submittedDate: Date,
      highlights: String,
      challenges: String,
      goalsAchieved: [String],
      developmentNeeds: [String]
    },
    
    threeSixtyFeedback: [{
      respondent: { type: Schema.Types.ObjectId, ref: 'User' },
      relationship: {
        type: String,
        enum: ['manager', 'peer', 'subordinate', 'client', 'other']
      },
      submitted: { type: Boolean, default: false },
      ratings: {
        overall: { type: Number, min: 1, max: 5 },
        competencies: Schema.Types.Mixed
      },
      comments: String
    }],
    
    calibration: {
      conducted: { type: Boolean, default: false },
      date: Date,
      finalRating: { type: Number, min: 1, max: 5 },
      adjustmentReason: String,
      participants: [{ type: Schema.Types.ObjectId, ref: 'User' }]
    },
    
    outcomes: {
      promotionRecommended: { type: Boolean, default: false },
      salaryIncreasePercentage: Number,
      bonusMultiplier: Number,
      developmentPlan: Boolean,
      pipStatus: {
        type: String,
        enum: ['none', 'monitoring', 'active', 'final_warning']
      }
    },
    
    status: {
      type: String,
      enum: ['not_started', 'self_assessment', 'manager_review', 'calibration', 'completed', 'acknowledged'],
      default: 'not_started'
    },
    
    acknowledgedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    acknowledgedDate: Date
  }],
  
  currentRating: {
    overall: { type: Number, min: 1, max: 5 },
    trend: {
      type: String,
      enum: ['improving', 'stable', 'declining']
    },
    lastUpdated: Date
  },
  
  goals: [{
    title: { type: String, required: true },
    description: String,
    category: {
      type: String,
      enum: ['performance', 'development', 'career', 'certification', 'skill']
    },
    targetDate: { type: Date, required: true },
    weight: { type: Number, min: 0, max: 100 },
    status: {
      type: String,
      enum: ['not_started', 'in_progress', 'at_risk', 'completed', 'cancelled'],
      default: 'not_started'
    },
    progress: { type: Number, min: 0, max: 100, default: 0 },
    milestones: [{
      description: String,
      dueDate: Date,
      completed: { type: Boolean, default: false },
      completedDate: Date
    }],
    actualCompletion: Date,
    outcome: String,
    impactAssessment: String
  }],
  
  recognition: [{
    type: {
      type: String,
      enum: ['award', 'spot_bonus', 'client_praise', 'peer_nomination', 'certification', 'publication']
    },
    title: String,
    description: String,
    date: { type: Date, default: Date.now },
    nominator: { type: Schema.Types.ObjectId, ref: 'User' },
    value: {
      monetary: Number,
      points: Number
    },
    visibility: {
      type: String,
      enum: ['private', 'team', 'department', 'company', 'public'],
      default: 'team'
    }
  }],
  
  developmentNeeds: [{
    area: String,
    priority: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical']
    },
    identifiedDate: Date,
    targetDate: Date,
    plan: String,
    resources: [String],
    progress: {
      type: String,
      enum: ['identified', 'planned', 'in_progress', 'completed']
    }
  }],
  
  metrics: {
    lifetime: {
      projectsCompleted: { type: Number, default: 0 },
      clientsServed: { type: Number, default: 0 },
      revenueGenerated: { type: Number, default: 0 },
      averageRating: { type: Number, min: 1, max: 5 },
      promotions: { type: Number, default: 0 }
    },
    annual: {
      year: Number,
      utilization: Number,
      billableHours: Number,
      revenueGenerated: Number,
      clientSatisfaction: Number,
      internalContribution: Number
    }
  }
}, { _id: false });

module.exports = performanceSchema;