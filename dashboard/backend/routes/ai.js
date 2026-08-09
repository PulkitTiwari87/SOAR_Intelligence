const express = require('express');
const { verifyToken, requireRole } = require('../middleware/auth');
const { runPythonExpr } = require('../services/pythonBridge');

const router = express.Router();

// POST /api/ai/triage — Run ML Triage on alert features
router.post('/triage', verifyToken, async (req, res) => {
  try {
    const features = req.body;
    const code = `
import sys, json, os
sys.path.insert(0, os.environ.get('PYTHONPATH', '.'))
from ai.triage.ml_triage_analyzer import predict_threat
result = predict_threat(${JSON.stringify(features)})
print(json.dumps(result))
`;
    const result = await runPythonExpr(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ai/phishing — Analyze email text
router.post('/phishing', verifyToken, async (req, res) => {
  try {
    const { emailText } = req.body;
    if (!emailText) {
      return res.status(400).json({ error: 'emailText is required.' });
    }
    // Escape the email text for Python
    const escaped = emailText.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
    const code = `
import sys, json, os
sys.path.insert(0, os.environ.get('PYTHONPATH', '.'))
from ai.phishing.nlp_phishing_parser import analyze_email
result = analyze_email("${escaped}")
print(json.dumps(result))
`;
    const result = await runPythonExpr(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ai/anomaly — Run anomaly detection on metrics
router.post('/anomaly', verifyToken, async (req, res) => {
  try {
    const metrics = req.body;
    const code = `
import sys, json, os
sys.path.insert(0, os.environ.get('PYTHONPATH', '.'))
from ai.anomaly.isolation_forest_detector import detect_anomaly
result = detect_anomaly(${JSON.stringify(metrics)})
print(json.dumps(result))
`;
    const result = await runPythonExpr(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/ai/certificate — Check SSL/TLS certificate
router.post('/certificate', verifyToken, async (req, res) => {
  try {
    let { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required.' });

    // Extract hostname
    let hostname = url.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];

    const code = `
import ssl, socket, json, sys, certifi
from datetime import datetime
def get_cert(hostname):
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get('notAfter')
                expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days = (expires - datetime.utcnow()).days
                return {
                    "valid": True, "hostname": hostname,
                    "subject": dict(x[0] for x in cert.get('subject')).get('commonName'),
                    "issuer": dict(x[0] for x in cert.get('issuer')).get('commonName'),
                    "expires": not_after, "days_left": days,
                    "protocol": ssock.version(), "expired": days < 0
                }
    except Exception as e: 
        return {"valid": False, "error": str(e)}
print(json.dumps(get_cert("${hostname}")))
`;
    const result = await runPythonExpr(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/ai/stats — Get self-learning stats
router.get('/stats', verifyToken, async (req, res) => {
  try {
    const code = `
import sys, json, os
sys.path.insert(0, os.environ.get('PYTHONPATH', '.'))
from ai.feedback_loop import get_learning_stats
stats = get_learning_stats()
print(json.dumps(stats, default=str))
`;
    const result = await runPythonExpr(code);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
