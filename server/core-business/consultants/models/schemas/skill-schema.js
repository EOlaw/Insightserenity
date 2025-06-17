/**
 * @file Skill Schema
 * @description Schema for consultant skills and competencies
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const skillSchema = new Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    required: true,
    enum: ['technical', 'functional', 'industry', 'soft_skills', 'tools', 'methodology', 'language']
  },
  level: {
    type: Number,
    required: true,
    min: 1,
    max: 5,
    description: '1=Basic, 2=Intermediate, 3=Advanced, 4=Expert, 5=Master'
  },
  yearsExperience: {
    type: Number,
    min: 0,
    max: 50
  },
  description: String,
  verified: {
    type: Boolean,
    default: false
  },
  verifiedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  verifiedDate: Date,
  lastUsed: Date,
  lastAssessed: Date,
  assessmentScore: {
    type: Number,
    min: 0,
    max: 100
  },
  projectsUsed: [{
    project: { type: Schema.Types.ObjectId, ref: 'Project' },
    usage: {
      type: String,
      enum: ['primary', 'secondary', 'supporting']
    }
  }],
  endorsements: [{
    endorser: { type: Schema.Types.ObjectId, ref: 'User' },
    date: { type: Date, default: Date.now },
    comment: String
  }],
  trainingCompleted: [{
    name: String,
    provider: String,
    date: Date,
    certificateUrl: String
  }]
}, { _id: true, timestamps: true });

module.exports = skillSchema;