const express = require('express');
const https = require('https');
const http = require('http');
const { verifyToken } = require('../middleware/auth');

const router = express.Router();

// ─── Helper: Make HTTP/HTTPS request ───
function apiRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const proto = options.protocol === 'https:' ? https : http;
    const req = proto.request({
      ...options,
      rejectUnauthorized: false, // self-signed certs
      timeout: 8000,
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });
    req.on('error', err => reject(err));
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    if (postData) req.write(postData);
    req.end();
  });
}

// ─── Wazuh API config ───
const WAZUH_API = {
  host: 'localhost',
  port: 55000,
  protocol: 'https:',
  auth: 'wazuh-wui:MyS3cr37P450r.*-', // Actual API user from docker-compose
  altAuth: 'wazuh:wazuh',           // Fallback
};

// ─── TheHive config ───
const THEHIVE_API = {
  host: 'localhost',
  port: 9000,
  protocol: 'http:',
};

// ─── Cortex config ───
const CORTEX_API = {
  host: 'localhost',
  port: 9001,
  protocol: 'http:',
};

// ─── MISP config ───
const MISP_API = {
  host: 'localhost',
  port: 8080,
  protocol: 'http:',
};

// ─── Redis config (Internal) ───
const REDIS_API = {
  host: 'localhost',
  port: 6379,
  protocol: 'http:',
};

// ─── GET Wazuh JWT Token ───
async function getWazuhToken() {
  const auths = [WAZUH_API.auth, WAZUH_API.altAuth];
  for (const auth of auths) {
    try {
      const result = await apiRequest({
        hostname: WAZUH_API.host,
        port: WAZUH_API.port,
        protocol: WAZUH_API.protocol,
        path: '/security/user/authenticate',
        method: 'POST',
        headers: {
          'Authorization': 'Basic ' + Buffer.from(auth).toString('base64'),
          'Content-Type': 'application/json',
        },
      });
      if (result.status === 200 && result.data?.data?.token) {
        return result.data.data.token;
      }
    } catch { /* try next auth */ }
  }
  return null;
}

// ═══════════════════════════════════════════════
// GET /api/soar/overview — Unified SOAR overview
// ═══════════════════════════════════════════════
router.get('/overview', verifyToken, async (req, res) => {
  const overview = {
    wazuh: { status: 'offline', agents: [], alerts: [], totalAlerts: 0, manager: {} },
    thehive: { status: 'offline', cases: [], alerts: [], stats: {} },
    cortex: { status: 'offline', analyzers: [], jobs: [] },
    misp: { status: 'offline', events: 0, status_msg: 'Unreachable' },
    redis: { status: 'offline', memory: '0B', status_msg: 'Disconnected' },
    timestamp: new Date().toISOString(),
  };

  // ─── 1. Wazuh Data ───
  try {
    const token = await getWazuhToken();
    if (token) {
      const headers = { Authorization: `Bearer ${token}` };

      // Manager info
      const managerRes = await apiRequest({
        hostname: WAZUH_API.host, port: WAZUH_API.port, protocol: WAZUH_API.protocol,
        path: '/', method: 'GET', headers,
      });
      overview.wazuh.manager = managerRes.data?.data || {};

      // Agents list
      const agentsRes = await apiRequest({
        hostname: WAZUH_API.host, port: WAZUH_API.port, protocol: WAZUH_API.protocol,
        path: '/agents?pretty=true&sort=-dateAdd', method: 'GET', headers,
      });
      overview.wazuh.agents = (agentsRes.data?.data?.affected_items || []).map(a => ({
        id: a.id,
        name: a.name,
        ip: a.ip,
        status: a.status,
        os: a.os?.name ? `${a.os.name} ${a.os.version || ''}`.trim() : 'Unknown',
        version: a.version,
        lastKeepAlive: a.lastKeepAlive,
        dateAdd: a.dateAdd,
      }));

      // Alerts (from Wazuh Indexer via Wazuh API)
      try {
        const alertsRes = await apiRequest({
          hostname: WAZUH_API.host, port: WAZUH_API.port, protocol: WAZUH_API.protocol,
          path: '/manager/logs?limit=100&sort=-timestamp', method: 'GET', headers,
        });
        // This gives manager logs, not alerts. Let's get alerts from indexer directly.
      } catch {}

      overview.wazuh.status = 'online';
    }
  } catch (err) {
    console.error('[SOAR] Wazuh connection error:', err.message);
  }

  // ─── Wazuh Indexer: Get actual alerts directly ───
  try {
    const indexerRes = await apiRequest({
      hostname: 'localhost', port: 9200, protocol: 'https:',
      path: '/wazuh-alerts-*/_search?size=50&sort=timestamp:desc',
      method: 'GET',
      headers: {
        'Authorization': 'Basic ' + Buffer.from('admin:admin').toString('base64'),
        'Content-Type': 'application/json',
      },
    });
    if (indexerRes.status === 200 && indexerRes.data?.hits?.hits) {
      overview.wazuh.alerts = indexerRes.data.hits.hits.map(h => {
        const s = h._source;
        return {
          id: s.id || h._id,
          timestamp: s.timestamp,
          agentName: s.agent?.name || 'Unknown',
          agentId: s.agent?.id || '000',
          agentIp: s.agent?.ip || '',
          ruleId: s.rule?.id || '',
          ruleLevel: s.rule?.level || 0,
          ruleDescription: s.rule?.description || '',
          ruleGroups: s.rule?.groups || [],
          mitre: s.rule?.mitre || {},
          srcIp: s.data?.srcip || s.data?.src_ip || s.data?.src || s.data?.origin || s.agent?.ip || '',
          dstIp: s.data?.dstip || s.data?.dst_ip || s.data?.dst || '',
          fullLog: s.full_log || '',
          location: s.location || '',
        };
      });
      overview.wazuh.totalAlerts = indexerRes.data.hits.total?.value || indexerRes.data.hits.hits.length;

      // If indexer has data, Wazuh pipeline is working
      overview.wazuh.status = 'online';

      // Extract unique agents from alerts if API didn't provide them
      if (overview.wazuh.agents.length === 0) {
        const agentMap = {};
        overview.wazuh.alerts.forEach(a => {
          if (a.agentId && a.agentId !== '000' && !agentMap[a.agentId]) {
            agentMap[a.agentId] = {
              id: a.agentId, name: a.agentName, ip: a.agentIp,
              status: 'active', os: 'Linux', version: 'v4.9.0',
            };
          }
        });
        overview.wazuh.agents = Object.values(agentMap);
        // Always include manager
        overview.wazuh.agents.unshift({
          id: '000', name: 'wazuh.manager', ip: '127.0.0.1',
          status: 'active', os: 'Server', version: 'v4.9.0',
        });
      }
    }
  } catch (err) {
    console.error('[SOAR] Indexer error:', err.message);
  }

  // ─── 2. TheHive Data ───
  try {
    // Check TheHive status
    const hiveStatus = await apiRequest({
      hostname: THEHIVE_API.host, port: THEHIVE_API.port, protocol: THEHIVE_API.protocol,
      path: '/api/status', method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (hiveStatus.status === 200) {
      overview.thehive.status = 'online';
      overview.thehive.stats = hiveStatus.data || {};

      // Try to get cases (may need API key)
      try {
        const casesRes = await apiRequest({
          hostname: THEHIVE_API.host, port: THEHIVE_API.port, protocol: THEHIVE_API.protocol,
          path: '/api/case?range=0-20&sort=-createdAt', method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer soar-api-key-2026',
          },
        });
        if (Array.isArray(casesRes.data)) {
          overview.thehive.cases = casesRes.data.map(c => ({
            id: c._id || c.id,
            caseId: c.caseId,
            title: c.title,
            severity: c.severity,
            status: c.status,
            tlp: c.tlp,
            pap: c.pap,
            owner: c.owner,
            createdAt: c.createdAt ? new Date(c.createdAt).toISOString() : '',
            tags: c.tags || [],
          }));
        }
      } catch {}

      // Get TheHive alerts
      try {
        const alertsRes = await apiRequest({
          hostname: THEHIVE_API.host, port: THEHIVE_API.port, protocol: THEHIVE_API.protocol,
          path: '/api/alert?range=0-20&sort=-createdAt', method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer soar-api-key-2026',
          },
        });
        if (Array.isArray(alertsRes.data)) {
          overview.thehive.alerts = alertsRes.data.map(a => ({
            id: a._id || a.id,
            title: a.title,
            severity: a.severity,
            status: a.status,
            source: a.source,
            type: a.type,
            createdAt: a.createdAt ? new Date(a.createdAt).toISOString() : '',
          }));
        }
      } catch {}
    }
  } catch (err) {
    overview.thehive.status = 'offline';
    console.error('[SOAR] TheHive connection error:', err.message);
  }

  // ─── 3. Cortex Data ───
  try {
    const cortexStatus = await apiRequest({
      hostname: CORTEX_API.host, port: CORTEX_API.port, protocol: CORTEX_API.protocol,
      path: '/api/status', method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });
    if (cortexStatus.status === 200) {
      overview.cortex.status = 'online';

      // Get analyzers
      try {
        const analyzersRes = await apiRequest({
          hostname: CORTEX_API.host, port: CORTEX_API.port, protocol: CORTEX_API.protocol,
          path: '/api/analyzer', method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer cortex-api-key-2026',
          },
        });
        if (Array.isArray(analyzersRes.data)) {
          overview.cortex.analyzers = analyzersRes.data.map(a => ({
            id: a.id,
            name: a.name,
            version: a.version,
            dataTypeList: a.dataTypeList || [],
          }));
        }
      } catch {}

      // Get recent jobs
      try {
        const jobsRes = await apiRequest({
          hostname: CORTEX_API.host, port: CORTEX_API.port, protocol: CORTEX_API.protocol,
          path: '/api/job?range=0-20&sort=-createdAt', method: 'GET',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer cortex-api-key-2026',
          },
        });
        if (Array.isArray(jobsRes.data)) {
          overview.cortex.jobs = jobsRes.data.map(j => ({
            id: j.id,
            analyzerName: j.analyzerName,
            status: j.status,
            createdAt: j.createdAt ? new Date(j.createdAt).toISOString() : '',
          }));
        }
      } catch {}
    }
  } catch (err) {
    overview.cortex.status = 'offline';
    console.error('[SOAR] Cortex connection error:', err.message);
  }

  // ─── 4. MISP Data ───
  try {
    const { execSync } = require('child_process');
    // Fallback: Check if container is running
    const containerStatus = execSync('docker inspect -f "{{.State.Status}}" misp').toString().trim();
    
    overview.misp.status = containerStatus === 'running' ? 'online' : 'offline';
    overview.misp.status_msg = containerStatus === 'running' ? 'Running' : 'Stopped';

    // Attempt API check for event count
    try {
      const mispRes = await apiRequest({
        hostname: MISP_API.host, port: MISP_API.port, protocol: MISP_API.protocol,
        path: '/events/index.json', method: 'GET',
        headers: { 'Accept': 'application/json' },
      });
      if (mispRes.status === 200 && Array.isArray(mispRes.data)) {
        overview.misp.events = mispRes.data.length;
      }
    } catch {}
  } catch (err) {
    overview.misp.status = 'offline';
  }

  // ─── 5. Redis Data ───
  try {
    const { execSync } = require('child_process');
    const redisPing = execSync('docker exec misp-redis redis-cli ping').toString().trim();
    if (redisPing === 'PONG') {
      overview.redis.status = 'online';
      overview.redis.status_msg = 'Active';
      try {
        const redisInfo = execSync('docker exec misp-redis redis-cli info memory | grep used_memory_human').toString().trim();
        overview.redis.memory = redisInfo.split(':')[1] || 'Unknown';
      } catch {}
    }
  } catch (err) {
    overview.redis.status = 'offline';
  }

  res.json(overview);
});

// ═══════════════════════════════════════════════
// GET /api/soar/alerts — Get Wazuh alerts from indexer
// ═══════════════════════════════════════════════
router.get('/alerts', verifyToken, async (req, res) => {
  try {
    const size = parseInt(req.query.limit) || 100;
    const level = parseInt(req.query.level) || 0;

    let query = { match_all: {} };
    if (level > 0) {
      query = { range: { 'rule.level': { gte: level } } };
    }

    const body = JSON.stringify({
      size,
      sort: [{ timestamp: { order: 'desc' } }],
      query,
    });

    const result = await apiRequest({
      hostname: 'localhost', port: 9200, protocol: 'https:',
      path: '/wazuh-alerts-*/_search',
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from('admin:admin').toString('base64'),
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, body);

    if (result.status === 200 && result.data?.hits?.hits) {
      const alerts = result.data.hits.hits.map(h => {
        const s = h._source;
        return {
          id: s.id || h._id,
          timestamp: s.timestamp,
          agent: s.agent || {},
          rule: s.rule || {},
          data: s.data || {},
          mitre: s.rule?.mitre || {},
          fullLog: s.full_log || '',
          location: s.location || '',
        };
      });
      res.json({
        total: result.data.hits.total?.value || alerts.length,
        alerts,
      });
    } else {
      res.json({ total: 0, alerts: [] });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════
// GET /api/soar/agents — Get Wazuh agents
// ═══════════════════════════════════════════════
router.get('/agents', verifyToken, async (req, res) => {
  try {
    const token = await getWazuhToken();
    if (!token) return res.json({ agents: [] });

    const result = await apiRequest({
      hostname: WAZUH_API.host, port: WAZUH_API.port, protocol: WAZUH_API.protocol,
      path: '/agents?pretty=true', method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const agents = (result.data?.data?.affected_items || []).map(a => ({
      id: a.id,
      name: a.name,
      ip: a.ip,
      status: a.status,
      os: a.os?.name ? `${a.os.name} ${a.os.version || ''}`.trim() : 'Unknown',
      version: a.version,
      lastKeepAlive: a.lastKeepAlive,
    }));

    res.json({ agents });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ═══════════════════════════════════════════════
// POST /api/soar/initialize — Run Make Live script
// ═══════════════════════════════════════════════
router.post('/initialize', verifyToken, async (req, res) => {
  try {
    const { exec } = require('child_process');
    const scriptPath = require('path').join(__dirname, '../../../scripts/make_live.sh');
    
    exec(`bash ${scriptPath}`, (error, stdout, stderr) => {
      if (error) {
        console.error(`[SOAR Init Error]: ${error.message}`);
        return res.status(500).json({ error: error.message });
      }
      res.json({ success: true, output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
