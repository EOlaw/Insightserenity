/**
 * @file Experience Schema
 * @description Schema for professional experience and work history
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const experienceSchema = new Schema({
  company: {
    type: String,
    required: true,
    trim: true
  },
  role: {
    type: String,
    required: true,
    trim: true
  },
  level: {
    type: String,
    enum: ['intern', 'entry', 'mid', 'senior', 'lead', 'principal', 'executive']
  },
  type: {
    type: String,
    enum: ['full_time', 'part_time', 'contract', 'freelance', 'internship'],
    default: 'full_time'
  },
  location: {
    city: String,
    state: String,
    country: String,
    remote: { type: Boolean, default: false }
  },
  startDate: {
    type: Date,
    required: true
  },
  endDate: Date,
  isCurrent: {
    type: Boolean,
    default: false
  },
  industry: {
    type: String,
    enum: ['technology', 'finance', 'healthcare', 'retail', 'manufacturing', 'energy', 
            'telecommunications', 'media', 'education', 'government', 'nonprofit', 'other']
  },
  description: {
    type: String,
    maxlength: 2000
  },
  responsibilities: [String],
  achievements: [{
    description: String,
    impact: String,
    metrics: String
  }],
  technologies: [String],
  methodologies: [String],
  teamSize: {
    direct: Number,
    total: Number
  },
  budget: {
    managed: Number,
    currency: { type: String, default: 'USD' }
  },
  clients: [{
    name: String,
    industry: String,
    projectValue: Number
  }],
  projects: [{
    name: String,
    role: String,
    duration: Number, // in months
    teamSize: Number,
    technologies: [String],
    outcome: String
  }],
  reportingTo: {
    name: String,
    title: String,
    linkedIn: String
  },
  references: [{
    name: String,
    title: String,
    relationship: String,
    email: String,
    phone: String,
    canContact: { type: Boolean, default: false }
  }],
  reasonForLeaving: String,
  eligibleForRehire: {
    type: Boolean,
    default: true
  }
}, { _id: true, timestamps: true });

module.exports = experienceSchema;