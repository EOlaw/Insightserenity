// server/core-business/proposals/models/schemas/proposal-terms-schema.js
/**
 * @file Proposal Terms Schema
 * @description Schema definition for proposal terms and conditions
 * @version 3.0.0
 */

const mongoose = require('mongoose');
const { Schema } = mongoose;

/**
 * Proposal Terms Schema
 */
const proposalTermsSchema = new Schema({
  standard: {
    useStandard: {
      type: Boolean,
      default: true
    },
    version: String,
    lastUpdated: Date
  },
  
  custom: [{
    section: {
      type: String,
      required: true
    },
    title: String,
    content: {
      type: String,
      required: true
    },
    order: Number,
    isMandatory: {
      type: Boolean,
      default: true
    }
  }],
  
  intellectual_property: {
    ownership: {
      type: String,
      enum: ['client', 'provider', 'shared', 'custom'],
      default: 'client'
    },
    transferUpon: {
      type: String,
      enum: ['payment', 'completion', 'acceptance', 'custom'],
      default: 'payment'
    },
    exceptions: [String],
    customTerms: String
  },
  
  confidentiality: {
    duration: {
      value: Number,
      unit: {
        type: String,
        enum: ['months', 'years', 'perpetual'],
        default: 'years'
      }
    },
    scope: [String],
    exceptions: [String]
  },
  
  liability: {
    limitation: {
      type: String,
      enum: ['contract_value', 'fees_paid', 'unlimited', 'custom'],
      default: 'contract_value'
    },
    multiplier: {
      type: Number,
      default: 1
    },
    exclusions: [String],
    indemnification: {
      byProvider: [String],
      byClient: [String]
    }
  },
  
  termination: {
    notice: {
      value: Number,
      unit: {
        type: String,
        enum: ['days', 'weeks', 'months'],
        default: 'days'
      }
    },
    forCause: {
      reasons: [String],
      remedyPeriod: {
        value: Number,
        unit: String
      }
    },
    forConvenience: {
      allowed: {
        type: Boolean,
        default: true
      },
      compensationTerms: String
    },
    effectOfTermination: [String]
  },
  
  warranties: {
    provider: [String],
    duration: {
      value: Number,
      unit: {
        type: String,
        enum: ['days', 'months', 'years'],
        default: 'months'
      }
    },
    remedies: [String],
    disclaimers: [String]
  },
  
  dispute_resolution: {
    method: {
      type: String,
      enum: ['negotiation', 'mediation', 'arbitration', 'litigation', 'escalation'],
      default: 'negotiation'
    },
    escalation: [{
      level: Number,
      method: String,
      timeframe: {
        value: Number,
        unit: String
      }
    }],
    governing_law: String,
    jurisdiction: String,
    venue: String
  },
  
  change_management: {
    process: {
      type: String,
      enum: ['written_approval', 'change_order', 'amendment', 'email_approval'],
      default: 'change_order'
    },
    approvalRequired: {
      provider: [String],
      client: [String]
    },
    costThreshold: Number,
    timeThreshold: {
      value: Number,
      unit: String
    }
  },
  
  force_majeure: {
    events: [String],
    notification: {
      value: Number,
      unit: String
    },
    mitigation: String,
    termination: {
      allowed: Boolean,
      after: {
        value: Number,
        unit: String
      }
    }
  },
  
  acceptance: {
    criteria: [String],
    process: String,
    timeline: {
      value: Number,
      unit: String
    },
    deemedAcceptance: {
      enabled: Boolean,
      after: {
        value: Number,
        unit: String
      }
    }
  },
  
  additional: [{
    title: String,
    content: String,
    category: String
  }],
  
  signatures: {
    required: {
      type: Boolean,
      default: true
    },
    electronic: {
      allowed: {
        type: Boolean,
        default: true
      },
      providers: ['docusign', 'hellosign', 'adobesign', 'other']
    },
    signatories: [{
      role: {
        type: String,
        enum: ['provider', 'client', 'witness', 'legal'],
        required: true
      },
      name: String,
      title: String,
      email: String,
      isRequired: {
        type: Boolean,
        default: true
      }
    }]
  }
}, {
  _id: false
});

module.exports = { proposalTermsSchema };