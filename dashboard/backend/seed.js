/**
 * Seed script: Creates default admin account and demo incidents.
 * Run with: node seed.js
 */
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');
const Incident = require('./models/Incident');

const DEMO_INCIDENTS = [
  {
    incidentId: 'IR-2026-001',
    title: 'SSH Brute Force from APT28 IP',
    severity: 4,
    status: 'resolved',
    triageScore: 95.2,
    attackType: 'Brute Force',
    sourceIp: '91.219.236.222',
    targetDevice: 'kali-vm-01',
    targetIp: '192.168.64.9',
    isAnomaly: false,
    blastRadius: 2,
    analystAction: 'auto_block',
    ruleLevel: 12,
    ruleDescription: 'Multiple SSH authentication failures from external IP',
    resolvedAt: new Date(Date.now() - 86400000),
  },
  {
    incidentId: 'IR-2026-002',
    title: 'Suspicious Data Exfiltration at 3AM',
    severity: 3,
    status: 'open',
    triageScore: 72.8,
    attackType: 'Data Exfiltration',
    sourceIp: '192.168.64.10',
    targetDevice: 'web-server-01',
    targetIp: '192.168.64.10',
    isAnomaly: true,
    blastRadius: 5,
    analystAction: null,
    ruleLevel: 10,
    ruleDescription: 'Unusual outbound data transfer during non-business hours',
  },
  {
    incidentId: 'IR-2026-003',
    title: 'Port Scan Detected from External IP',
    severity: 2,
    status: 'resolved',
    triageScore: 88.4,
    attackType: 'Port Scanning',
    sourceIp: '185.220.101.44',
    targetDevice: 'kali-vm-01',
    targetIp: '192.168.64.9',
    isAnomaly: false,
    blastRadius: 1,
    analystAction: 'block',
    ruleLevel: 8,
    ruleDescription: 'Nmap port scan detected on multiple ports',
    resolvedAt: new Date(Date.now() - 172800000),
  },
  {
    incidentId: 'IR-2026-004',
    title: 'Potential Ransomware Activity — File Encryption',
    severity: 4,
    status: 'open',
    triageScore: 67.3,
    attackType: 'Ransomware',
    sourceIp: '10.0.0.55',
    targetDevice: 'file-server-01',
    targetIp: '192.168.64.12',
    isAnomaly: true,
    blastRadius: 8,
    analystAction: null,
    ruleLevel: 14,
    ruleDescription: 'Mass file modification with encryption patterns detected',
  },
  {
    incidentId: 'IR-2026-005',
    title: 'DNS Tunneling Communication Detected',
    severity: 3,
    status: 'investigating',
    triageScore: 61.5,
    attackType: 'DNS Tunneling',
    sourceIp: '192.168.64.11',
    targetDevice: 'workstation-03',
    targetIp: '192.168.64.11',
    isAnomaly: true,
    blastRadius: 3,
    analystAction: 'investigate',
    ruleLevel: 11,
    ruleDescription: 'Abnormal DNS query volume with encoded subdomains',
  },
  {
    incidentId: 'IR-2026-006',
    title: 'Routine Login Spike — False Positive',
    severity: 1,
    status: 'false_positive',
    triageScore: 22.1,
    attackType: 'Normal Activity',
    sourceIp: '192.168.64.5',
    targetDevice: 'kali-vm-01',
    targetIp: '192.168.64.9',
    isAnomaly: false,
    blastRadius: 0,
    analystAction: 'auto_close',
    ruleLevel: 3,
    ruleDescription: 'Multiple login attempts from internal IP during business hours',
    resolvedAt: new Date(Date.now() - 259200000),
  },
  {
    incidentId: 'IR-2026-007',
    title: 'Credential Stuffing Attack on Web Portal',
    severity: 3,
    status: 'resolved',
    triageScore: 91.7,
    attackType: 'Credential Stuffing',
    sourceIp: '45.33.49.119',
    targetDevice: 'web-server-01',
    targetIp: '192.168.64.10',
    isAnomaly: false,
    blastRadius: 2,
    analystAction: 'auto_block',
    ruleLevel: 11,
    ruleDescription: 'Automated login attempts with breached credential patterns',
    resolvedAt: new Date(Date.now() - 43200000),
  },
  {
    incidentId: 'IR-2026-008',
    title: 'Reverse Shell Callback Attempt',
    severity: 4,
    status: 'open',
    triageScore: 78.9,
    attackType: 'Reverse Shell',
    sourceIp: '192.168.64.9',
    targetDevice: 'kali-vm-01',
    targetIp: '192.168.64.9',
    isAnomaly: true,
    blastRadius: 4,
    analystAction: null,
    ruleLevel: 13,
    ruleDescription: 'Outbound connection to known C2 infrastructure detected',
  },
];

async function seed() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('  ✓ Connected to MongoDB');

    // Seed admin user
    const existing = await User.findOne({ username: 'admin' });
    if (!existing) {
      const admin = new User({
        username: 'admin',
        passwordHash: 'soar2026',
        role: 'analyst',
      });
      await admin.save();
      console.log('  ✓ Created admin user (admin / soar2026)');
    } else {
      console.log('  ⊘ Admin user already exists');
    }

    // Seed regular user
    const existingUser = await User.findOne({ username: 'viewer' });
    if (!existingUser) {
      const viewer = new User({
        username: 'viewer',
        passwordHash: 'viewer2026',
        role: 'user',
      });
      await viewer.save();
      console.log('  ✓ Created viewer user (viewer / viewer2026)');
    } else {
      console.log('  ⊘ Viewer user already exists');
    }

    // Seed demo incidents
    for (const inc of DEMO_INCIDENTS) {
      const exists = await Incident.findOne({ incidentId: inc.incidentId });
      if (!exists) {
        await Incident.create(inc);
        console.log(`  ✓ Created incident ${inc.incidentId}`);
      }
    }

    console.log('\n  ✅ Seed complete!\n');
    process.exit(0);
  } catch (err) {
    console.error('  ✗ Seed failed:', err.message);
    process.exit(1);
  }
}

seed();
