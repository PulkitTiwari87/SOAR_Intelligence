import { API_URL } from '../config';
import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  Shield, ShieldAlert, Activity, Radio, Server, AlertTriangle,
  RefreshCw, ChevronDown, ChevronUp, ExternalLink, Wifi, WifiOff,
  Clock, Zap, Bug, Eye, Brain, Layers, Network
} from 'lucide-react';

const API = API_URL;

const SEVERITY_MAP = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' };
const SEVERITY_COLORS = { 1: '#22c55e', 2: '#f59e0b', 3: '#f97316', 4: '#ef4444' };

function StatusBadge({ status }) {
  const colors = {
    online: { bg: 'rgba(34,197,94,0.15)', color: '#22c55e', label: '● Online' },
    active: { bg: 'rgba(34,197,94,0.15)', color: '#22c55e', label: '● Active' },
    offline: { bg: 'rgba(239,68,68,0.15)', color: '#ef4444', label: '● Offline' },
    disconnected: { bg: 'rgba(239,68,68,0.15)', color: '#ef4444', label: '● Disconnected' },
    pending: { bg: 'rgba(245,158,11,0.15)', color: '#f59e0b', label: '● Pending' },
    never_connected: { bg: 'rgba(107,114,128,0.15)', color: '#6b7280', label: '● Never Connected' },
  };
  const c = colors[status] || colors.offline;
  return (
    <span style={{
      padding: '4px 10px', borderRadius: '20px', fontSize: '0.75rem', fontWeight: 600,
      background: c.bg, color: c.color, whiteSpace: 'nowrap',
    }}>{c.label}</span>
  );
}

function RuleLevelBadge({ level }) {
  let color = '#22c55e';
  if (level >= 12) color = '#ef4444';
  else if (level >= 8) color = '#f97316';
  else if (level >= 5) color = '#f59e0b';
  return (
    <span style={{
      padding: '2px 8px', borderRadius: '12px', fontSize: '0.7rem', fontWeight: 700,
      background: `${color}20`, color, border: `1px solid ${color}40`,
    }}>Level {level}</span>
  );
}

function MitreBadge({ id, technique }) {
  if (!id) return null;
  const ids = Array.isArray(id) ? id : [id];
  return ids.map(t => (
    <span key={t} title={technique} style={{
      padding: '2px 6px', borderRadius: '4px', fontSize: '0.65rem', fontWeight: 600,
      background: 'rgba(139,92,246,0.15)', color: '#8b5cf6', border: '1px solid rgba(139,92,246,0.3)',
      marginRight: '4px',
    }}>{t}</span>
  ));
}

function PlatformCard({ icon: Icon, name, status, color, stats, link }) {
  return (
    <div className="card" style={{
      padding: '20px', borderLeft: `3px solid ${color}`, position: 'relative', overflow: 'hidden',
    }}>
      <div style={{ position: 'absolute', top: '12px', right: '16px' }}>
        <StatusBadge status={status} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
        <div style={{
          width: '44px', height: '44px', borderRadius: '12px',
          background: `linear-gradient(135deg, ${color}30, ${color}10)`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: `1px solid ${color}40`,
        }}>
          <Icon size={22} style={{ color }} />
        </div>
        <div>
          <h3 style={{ margin: 0, fontSize: '1.1rem' }}>{name}</h3>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {status === 'online' || status === 'active' ? 'Connected' : 'Unreachable'}
          </span>
        </div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
        {stats.map(s => (
          <div key={s.label} style={{
            padding: '8px 12px', borderRadius: '8px',
            background: 'rgba(255,255,255,0.03)', border: '1px solid var(--glass-border)',
          }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '2px' }}>{s.label}</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700, color: s.color || 'var(--text-primary)' }}>{s.value}</div>
          </div>
        ))}
      </div>
      {link && (
        <a href={link} target="_blank" rel="noreferrer" style={{
          display: 'flex', alignItems: 'center', gap: '6px', marginTop: '12px',
          fontSize: '0.8rem', color, textDecoration: 'none', opacity: 0.8,
        }}>
          Open Dashboard <ExternalLink size={12} />
        </a>
      )}
    </div>
  );
}

export default function SOARIntegration() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [levelFilter, setLevelFilter] = useState(0);
  const [lastRefresh, setLastRefresh] = useState(null);

  const fetchData = useCallback(async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
    try {
      const token = localStorage.getItem('soar_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await axios.get(`${API}/soar/overview`, { headers });
      setData(res.data);
      setLastRefresh(new Date());
    } catch (err) {
      console.error('SOAR fetch error:', err);
    }
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Auto-refresh every 30s
  useEffect(() => {
    const interval = setInterval(() => fetchData(), 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  if (loading) return <div className="loading-container"><div className="spinner" /><span>Connecting to SOAR platforms...</span></div>;

  const wazuh = data?.wazuh || {};
  const thehive = data?.thehive || {};
  const cortex = data?.cortex || {};
  const misp = data?.misp || {};
  const redis = data?.redis || {};

  const activeAgents = (wazuh.agents || []).filter(a => a.status === 'active').length;
  const criticalAlerts = (wazuh.alerts || []).filter(a => a.ruleLevel >= 10).length;
  const highAlerts = (wazuh.alerts || []).filter(a => a.ruleLevel >= 7 && a.ruleLevel < 10).length;

  const filteredAlerts = levelFilter > 0
    ? (wazuh.alerts || []).filter(a => a.ruleLevel >= levelFilter)
    : (wazuh.alerts || []);

  const handleMakeLive = async () => {
    if (!window.confirm('This will initialize TheHive, Cortex and restart the backend. Continue?')) return;
    setRefreshing(true);
    try {
      const token = localStorage.getItem('soar_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      await axios.post(`${API}/soar/initialize`, {}, { headers });
      alert('SOAR initialized successfully! Refreshing data...');
      fetchData();
    } catch (err) {
      alert('Initialization failed: ' + (err.response?.data?.error || err.message));
    }
    setRefreshing(false);
  };

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1><Layers size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />SOAR Integration Hub</h1>
          <p>Unified view — Wazuh • TheHive • Cortex • MISP • Redis — Live threat intelligence</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {lastRefresh && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            className="btn btn-warning"
            onClick={handleMakeLive}
            disabled={refreshing}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Zap size={16} />
            One-Click Live
          </button>
          <button
            className="btn btn-primary"
            onClick={() => fetchData(true)}
            disabled={refreshing}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={16} className={refreshing ? 'spin-icon' : ''} />
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Platform Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px', marginBottom: '24px' }}>
        <PlatformCard
          icon={Shield} name="Wazuh Manager" status={wazuh.status || 'offline'} color="#3b82f6"
          link="https://localhost:443"
          stats={[
            { label: 'Total Alerts', value: wazuh.totalAlerts || 0, color: '#3b82f6' },
            { label: 'Active Agents', value: activeAgents, color: '#22c55e' },
            { label: 'Critical', value: criticalAlerts, color: '#ef4444' },
            { label: 'High', value: highAlerts, color: '#f97316' },
          ]}
        />
        <PlatformCard
          icon={Bug} name="TheHive" status={thehive.status || 'offline'} color="#f59e0b"
          link="http://localhost:9000"
          stats={[
            { label: 'Cases', value: thehive.cases?.length || 0, color: '#f59e0b' },
            { label: 'Alerts', value: thehive.alerts?.length || 0 },
            { label: 'Status', value: thehive.status === 'online' ? 'Ready' : 'Down' },
            { label: 'Version', value: thehive.stats?.versions?.TheHive || '—' },
          ]}
        />
        <PlatformCard
          icon={Brain} name="Cortex" status={cortex.status || 'offline'} color="#8b5cf6"
          link="http://localhost:9001"
          stats={[
            { label: 'Analyzers', value: cortex.analyzers?.length || 0, color: '#8b5cf6' },
            { label: 'Jobs', value: cortex.jobs?.length || 0 },
            { label: 'Status', value: cortex.status === 'online' ? 'Ready' : 'Down' },
            { label: 'Engine', value: cortex.status === 'online' ? 'Active' : '—' },
          ]}
        />
        <PlatformCard
          icon={Activity} name="MISP Platform" status={misp.status || 'offline'} color="#ef4444"
          link="http://localhost:8080"
          stats={[
            { label: 'Events', value: misp.events || 0, color: '#ef4444' },
            { label: 'Status', value: misp.status_msg || 'Unreachable' },
            { label: 'Type', value: 'Threat Intel' },
            { label: 'User', value: 'admin' },
          ]}
        />
        <PlatformCard
          icon={Radio} name="Redis Cache" status={redis.status || 'offline'} color="#22c55e"
          stats={[
            { label: 'Memory', value: redis.memory || '0B', color: '#22c55e' },
            { label: 'Status', value: redis.status_msg || 'Disconnected' },
            { label: 'Node', value: 'misp-redis' },
            { label: 'Port', value: '6379' },
          ]}
        />
      </div>

      {/* Agents Section */}
      {wazuh.agents?.length > 0 && (
        <div className="card" style={{ marginBottom: '24px' }}>
          <h3 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={18} /> Monitored Agents ({wazuh.agents.length})
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '12px' }}>
            {wazuh.agents.map(agent => (
              <div key={agent.id} style={{
                padding: '14px 16px', borderRadius: '10px',
                background: 'rgba(255,255,255,0.02)', border: '1px solid var(--glass-border)',
                display: 'flex', alignItems: 'center', gap: '12px',
              }}>
                <div style={{
                  width: '36px', height: '36px', borderRadius: '10px',
                  background: agent.status === 'active' ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  {agent.status === 'active' ? <Wifi size={18} color="#22c55e" /> : <WifiOff size={18} color="#ef4444" />}
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>
                    {agent.name} <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 400 }}>#{agent.id}</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {agent.ip} • {agent.os}
                  </div>
                </div>
                <StatusBadge status={agent.status} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Live Alerts Section */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
          <h3 className="section-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={18} style={{ color: '#ef4444' }} />
            Live Security Alerts ({filteredAlerts.length})
          </h3>
          <div style={{ display: 'flex', gap: '6px' }}>
            {[
              { label: 'All', value: 0 },
              { label: 'Level 5+', value: 5 },
              { label: 'Level 8+', value: 8 },
              { label: 'Level 10+', value: 10 },
              { label: 'Level 12+', value: 12 },
            ].map(f => (
              <button key={f.value}
                onClick={() => setLevelFilter(f.value)}
                style={{
                  padding: '4px 12px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: 600,
                  cursor: 'pointer', border: '1px solid',
                  background: levelFilter === f.value ? 'rgba(59,130,246,0.2)' : 'transparent',
                  color: levelFilter === f.value ? '#3b82f6' : 'var(--text-muted)',
                  borderColor: levelFilter === f.value ? 'rgba(59,130,246,0.4)' : 'var(--glass-border)',
                }}>
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {filteredAlerts.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            <ShieldAlert size={40} style={{ opacity: 0.3, marginBottom: '8px' }} />
            <p>No alerts matching this filter</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {filteredAlerts.map((alert, idx) => {
              const isExpanded = expandedAlert === idx;
              return (
                <div key={idx} style={{
                  borderRadius: '8px', border: '1px solid var(--glass-border)',
                  background: isExpanded ? 'rgba(255,255,255,0.04)' : 'rgba(255,255,255,0.01)',
                  transition: 'all 0.2s ease', overflow: 'hidden',
                }}>
                  <div
                    onClick={() => setExpandedAlert(isExpanded ? null : idx)}
                    style={{
                      padding: '12px 16px', cursor: 'pointer',
                      display: 'grid', gridTemplateColumns: '140px 60px 1fr auto 60px',
                      alignItems: 'center', gap: '12px',
                    }}
                  >
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '—'}
                    </span>
                    <RuleLevelBadge level={alert.ruleLevel} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: '0.85rem', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {alert.ruleDescription || 'Unknown alert'}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        Agent: {alert.agentName} ({alert.agentId}) • Rule: {alert.ruleId}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      {alert.srcIp && (
                        <span style={{
                          padding: '2px 8px', borderRadius: '4px', background: 'rgba(59,130,246,0.1)',
                          color: '#3b82f6', fontSize: '0.75rem', fontWeight: 600, fontFamily: 'monospace',
                          border: '1px solid rgba(59,130,246,0.2)', display: 'flex', alignItems: 'center', gap: '4px'
                        }}>
                          <Network size={12} /> {alert.srcIp}
                        </span>
                      )}
                      {alert.mitre?.id && <MitreBadge id={alert.mitre.id} technique={alert.mitre.technique?.[0]} />}
                    </div>
                    {isExpanded ? <ChevronUp size={16} color="var(--text-muted)" /> : <ChevronDown size={16} color="var(--text-muted)" />}
                  </div>
                  {isExpanded && (
                    <div style={{
                      padding: '0 16px 14px', borderTop: '1px solid var(--glass-border)',
                      paddingTop: '12px',
                    }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '12px' }}>
                        <div><span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Agent IP</span><div style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{alert.agentIp || '—'}</div></div>
                        <div><span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Source IP</span><div style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{alert.srcIp || '—'}</div></div>
                        <div><span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Location</span><div style={{ fontSize: '0.85rem' }}>{alert.location || '—'}</div></div>
                      </div>
                      {alert.mitre?.tactic && (
                        <div style={{ marginBottom: '10px' }}>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>MITRE ATT&CK</span>
                          <div style={{ fontSize: '0.85rem', display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '4px' }}>
                            {(Array.isArray(alert.mitre.tactic) ? alert.mitre.tactic : [alert.mitre.tactic]).map(t => (
                              <span key={t} style={{ padding: '2px 8px', borderRadius: '4px', background: 'rgba(249,115,22,0.12)', color: '#f97316', fontSize: '0.7rem', fontWeight: 600 }}>{t}</span>
                            ))}
                          </div>
                        </div>
                      )}
                      <div>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Full Log</span>
                        <div style={{
                          fontFamily: 'monospace', fontSize: '0.78rem', padding: '10px 14px',
                          background: 'rgba(0,0,0,0.3)', borderRadius: '6px', marginTop: '4px',
                          whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: '120px', overflowY: 'auto',
                          color: 'var(--text-secondary)', lineHeight: 1.5,
                        }}>
                          {alert.fullLog || 'No log data available'}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
