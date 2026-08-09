const mongoose = require('mongoose');

const incidentSchema = new mongoose.Schema({
  incidentId: {
    type: String,
    required: true,
    unique: true,
  },
  title: {
    type: String,
    required: true,
  },
  severity: {
    type: Number,
    min: 1,
    max: 4,
    default: 2,
  },
  status: {
    type: String,
    enum: ['open', 'investigating', 'monitoring', 'resolved', 'false_positive'],
    default: 'open',
  },
  triageScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
  },
  attackType: {
    type: String,
    default: 'Unknown',
  },
  sourceIp: {
    type: String,
    default: 'Unknown',
  },
  targetDevice: {
    type: String,
    default: 'Unknown',
  },
  targetIp: {
    type: String,
    default: 'Unknown',
  },
  isAnomaly: {
    type: Boolean,
    default: false,
  },
  blastRadius: {
    type: Number,
    default: 0,
  },
  analystAction: {
    type: String,
    enum: ['block', 'investigate', 'monitor', 'false_positive', 'lockdown', 'auto_block', 'auto_close', null],
    default: null,
  },
  analystId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
  },
  notes: {
    type: String,
    default: '',
  },
  ruleLevel: {
    type: Number,
    default: 0,
  },
  ruleDescription: {
    type: String,
    default: '',
  },
  resolvedAt: {
    type: Date,
    default: null,
  },
  reportPath: {
    type: String,
    default: null,
  },
}, { timestamps: true });

module.exports = mongoose.model('Incident', incidentSchema);
