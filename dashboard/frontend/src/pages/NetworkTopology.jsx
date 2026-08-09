import { Network as NetworkIcon } from 'lucide-react';

const NODES = [
  { id: 'wazuh', label: 'Wazuh Manager', type: 'core', x: 50, y: 30 },
  { id: 'thehive', label: 'TheHive', type: 'core', x: 30, y: 60 },
  { id: 'cortex', label: 'Cortex', type: 'core', x: 70, y: 60 },
  { id: 'misp', label: 'MISP', type: 'intel', x: 85, y: 35 },
  { id: 'kali', label: 'Kali VM', type: 'agent', x: 15, y: 35 },
  { id: 'web', label: 'Web Server', type: 'agent', x: 50, y: 85 },
  { id: 'elastic', label: 'Elasticsearch', type: 'data', x: 50, y: 55 },
];

const EDGES = [
  { from: 'kali', to: 'wazuh', label: 'Logs' },
  { from: 'wazuh', to: 'thehive', label: 'Alerts' },
  { from: 'thehive', to: 'cortex', label: 'Analyze' },
  { from: 'cortex', to: 'misp', label: 'Intel' },
  { from: 'cortex', to: 'wazuh', label: 'Response' },
  { from: 'thehive', to: 'elastic', label: 'Store' },
  { from: 'web', to: 'wazuh', label: 'Logs' },
];

const typeColors = { core: '#3b82f6', agent: '#22c55e', intel: '#f59e0b', data: '#8b5cf6' };

export default function NetworkTopology() {
  return (
    <div className="page-container">
      <div className="page-header">
        <h1><NetworkIcon size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />Network Topology</h1>
        <p>SOAR infrastructure visualization and data flow mapping</p>
      </div>

      <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
        <svg viewBox="0 0 100 100" style={{ width: '100%', height: '500px', background: 'var(--bg-secondary)' }}>
          {/* Edges */}
          {EDGES.map((e, i) => {
            const from = NODES.find(n => n.id === e.from);
            const to = NODES.find(n => n.id === e.to);
            return (
              <g key={i}>
                <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke="var(--border-hover)" strokeWidth="0.3" strokeDasharray="1,0.5" />
                <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 1} fill="var(--text-muted)" fontSize="1.8" textAnchor="middle">{e.label}</text>
              </g>
            );
          })}
          {/* Nodes */}
          {NODES.map(n => (
            <g key={n.id}>
              <circle cx={n.x} cy={n.y} r="4" fill={typeColors[n.type]} opacity="0.15" />
              <circle cx={n.x} cy={n.y} r="2.5" fill={typeColors[n.type]} stroke={typeColors[n.type]} strokeWidth="0.3">
                <animate attributeName="r" values="2.5;2.8;2.5" dur="3s" repeatCount="indefinite" />
              </circle>
              <text x={n.x} y={n.y + 6} fill="var(--text-primary)" fontSize="2.2" textAnchor="middle" fontWeight="600">{n.label}</text>
            </g>
          ))}
        </svg>
      </div>

      <div className="grid-4" style={{ marginTop: '16px' }}>
        {Object.entries(typeColors).map(([type, color]) => (
          <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
            <div style={{ width: '12px', height: '12px', borderRadius: '50%', background: color }} />
            <span style={{ textTransform: 'capitalize', color: 'var(--text-secondary)' }}>{type}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
