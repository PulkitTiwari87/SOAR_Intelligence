const mongoose = require('mongoose');
const Incident = require('./models/Incident');

async function simulateAttacks() {
  await mongoose.connect('mongodb://localhost/soar_dashboard');
  
  const attack1 = new Incident({
    incidentId: 'INC-DEMO-' + Math.floor(Math.random() * 10000),
    title: 'Multiple Failed SSH Logins (Brute Force)',
    severity: 3,
    status: 'open',
    triageScore: 88,
    attackType: 'SSH Brute Force',
    sourceIp: '192.168.1.105',
    targetDevice: 'Kali-VM',
    targetIp: '192.168.64.4',
    isAnomaly: true,
    blastRadius: 2,
    ruleLevel: 10,
    ruleDescription: 'sshd: authentication failed from a malicious IP',
  });

  const attack2 = new Incident({
    incidentId: 'INC-DEMO-' + Math.floor(Math.random() * 10000),
    title: 'Suspicious Binary Execution (Possible Malware)',
    severity: 4,
    status: 'investigating',
    triageScore: 95,
    attackType: 'Malware Execution',
    sourceIp: '10.0.2.15',
    targetDevice: 'Kali-VM',
    targetIp: '192.168.64.4',
    isAnomaly: true,
    blastRadius: 5,
    ruleLevel: 12,
    ruleDescription: 'File added to system directory and executed',
  });

  await attack1.save();
  await attack2.save();
  console.log('Successfully injected 2 live demo attacks into the dashboard portal.');
  process.exit(0);
}

simulateAttacks();
