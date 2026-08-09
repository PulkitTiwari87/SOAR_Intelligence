const express = require('express');
const { verifyToken } = require('../middleware/auth');
const AuditLog = require('../models/AuditLog');

const router = express.Router();

// GET /api/system/health — System health summary
router.get('/health', verifyToken, async (req, res) => {
  // Mock container status for project demo
  const containers = [
    { name: 'wazuh.manager', status: 'running', port: 55000, uptime: '72h' },
    { name: 'wazuh.indexer', status: 'running', port: 9200, uptime: '72h' },
    { name: 'wazuh.dashboard', status: 'running', port: 443, uptime: '72h' },
    { name: 'thehive', status: 'running', port: 9000, uptime: '72h' },
    { name: 'cortex', status: 'running', port: 9001, uptime: '72h' },
    { name: 'elasticsearch', status: 'running', port: 9201, uptime: '72h' },
    { name: 'cassandra', status: 'running', port: 9042, uptime: '72h' },
    { name: 'misp', status: 'running', port: 8080, uptime: '72h' },
  ];

  res.json({
    status: 'healthy',
    containers,
    aiModels: {
      triage: { loaded: true, version: 'v2.0', accuracy: 99.94 },
      phishing: { loaded: true, version: 'v1.0', accuracy: 85.0 },
      anomaly: { loaded: true, version: 'v1.0', accuracy: 92.0 },
    },
    timestamp: new Date().toISOString(),
  });
});

// GET /api/system/audit — Audit log (analyst only access in frontend)
router.get('/audit', verifyToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;

    const total = await AuditLog.countDocuments();
    const logs = await AuditLog.find()
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      logs,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
