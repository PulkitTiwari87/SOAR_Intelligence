import { API_URL } from '../config';
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { AlertTriangle, ShieldCheck, ShieldOff, Clock, Activity, Zap, Scan } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';

const API = API_URL;

const SEVERITY_COLORS = ['#22c55e', '#f59e0b', '#f97316', '#ef4444'];

export default function CommandCenter() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, incidentsRes] = await Promise.all([
          axios.get(`${API}/incidents/stats`),
          axios.get(`${API}/incidents?limit=10`),
        ]);
        setStats(statsRes.data);
        setIncidents(incidentsRes.data.incidents);
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
      }
      setLoading(false);
    };
    fetchData();
  }, []);

  if (loading) return <div className="loading-container"><div className="spinner" /><span>Loading dashboard...</span></div>;

  const threatLevel = stats ? Math.min(100, Math.round((stats.open / Math.max(stats.total, 1)) * 100 + stats.avgTriageScore * 0.3)) : 0;
  const threatColor = threatLevel > 70 ? '#ef4444' : threatLevel > 40 ? '#f59e0b' : '#22c55e';
  const threatLabel = threatLevel > 70 ? 'CRITICAL' : threatLevel > 40 ? 'ELEVATED' : 'LOW';

  const pieData = stats?.attackDistribution?.map(a => ({ name: a.type, value: a.count })) || [];
  const severityData = stats ? [
    { name: 'Low', value: stats.severity.low, fill: '#22c55e' },
    { name: 'Medium', value: stats.severity.medium, fill: '#f59e0b' },
    { name: 'High', value: stats.severity.high, fill: '#f97316' },
    { name: 'Critical', value: stats.severity.critical, fill: '#ef4444' },
  ] : [];

  return (
    <div className="page-container">
      <div className="page-header">
        <h1>Command Center</h1>
        <p>Real-time security operations overview</p>
      </div>

      {/* Quick Actions */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        <button className="btn btn-primary" onClick={() => navigate('/vulnerabilities')}>
          <Scan size={18} /> Run Vulnerability Scan
        </button>
        <button className="btn btn-ghost" onClick={() => navigate('/ai-intelligence')}>
          <Zap size={18} /> AI Threat Analysis
        </button>
      </div>

      {/* Stat Cards */}
      <div className="grid-4" style={{ marginBottom: '24px' }}>

        <div className="stat-card blue">
          <div className="stat-icon blue"><AlertTriangle size={24} /></div>
          <div className="stat-info">
            <h3>Total Alerts</h3>
            <div className="stat-value">{stats?.total || 0}</div>
          </div>
        </div>
        <div className="stat-card red">
          <div className="stat-icon red"><ShieldOff size={24} /></div>
          <div className="stat-info">
            <h3>Open Cases</h3>
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats?.open || 0}</div>
          </div>
        </div>
        <div className="stat-card green">
          <div className="stat-icon green"><ShieldCheck size={24} /></div>
          <div className="stat-info">
            <h3>Blocked IPs</h3>
            <div className="stat-value" style={{ color: 'var(--success)' }}>{stats?.blockedIps || 0}</div>
          </div>
        </div>
        <div className="stat-card yellow">
          <div className="stat-icon yellow"><Clock size={24} /></div>
          <div className="stat-info">
            <h3>Avg Response</h3>
            <div className="stat-value">{stats?.mttr || 0}<span style={{ fontSize: '0.9rem', fontWeight: 400 }}>s</span></div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid-3" style={{ marginBottom: '24px' }}>
        {/* Threat Gauge */}
        <div className="card">
          <h3 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Zap size={18} style={{ color: threatColor }} /> Threat Level
          </h3>
          <div className="threat-gauge">
            <svg className="gauge-svg" viewBox="0 0 200 120">
              <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="var(--border)" strokeWidth="12" strokeLinecap="round" />
              <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke={threatColor} strokeWidth="12" strokeLinecap="round"
                strokeDasharray={`${threatLevel * 2.5} 250`} style={{ transition: 'stroke-dasharray 1s ease', filter: `drop-shadow(0 0 6px ${threatColor}40)` }} />
              <text x="100" y="85" textAnchor="middle" fill={threatColor} fontSize="28" fontWeight="700">{threatLevel}</text>
              <text x="100" y="105" textAnchor="middle" fill="var(--text-muted)" fontSize="11">/100</text>
            </svg>
            <div className="gauge-label" style={{ color: threatColor }}>{threatLabel}</div>
          </div>
        </div>

        {/* Attack Distribution */}
        <div className="card">
          <h3 className="section-title">Attack Distribution</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%"
                  outerRadius={80} innerRadius={40} paddingAngle={3} strokeWidth={0}>
                  {pieData.map((_, i) => (
                    <Cell key={i} fill={['#3b82f6', '#ef4444', '#f59e0b', '#22c55e', '#8b5cf6', '#06b6d4', '#f97316', '#ec4899', '#14b8a6', '#a855f7'][i % 10]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '60px 0' }}>No data yet</p>}
        </div>

        {/* Severity Breakdown */}
        <div className="card">
          <h3 className="section-title">Severity Breakdown</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={severityData} layout="vertical">
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={70} tick={{ fill: 'var(--text-secondary)', fontSize: 12 }} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }} />
              <Bar dataKey="value" radius={[0, 6, 6, 0]} barSize={20}>
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Incidents Table */}
      <div className="card">
        <h3 className="section-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={18} /> Recent Incidents
        </h3>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Triage Score</th>
                <th>Source IP</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map(inc => (
                <tr key={inc._id}>
                  <td style={{ fontFamily: 'monospace', color: 'var(--accent)' }}>{inc.incidentId}</td>
                  <td>{inc.title}</td>
                  <td><span className={`badge badge-${['', 'low', 'medium', 'high', 'critical'][inc.severity]}`}>
                    {['', 'Low', 'Medium', 'High', 'Critical'][inc.severity]}
                  </span></td>
                  <td><span className={`badge badge-${inc.status}`}>{inc.status.replace('_', ' ')}</span></td>
                  <td style={{ fontWeight: 600, color: inc.triageScore >= 90 ? 'var(--danger)' : inc.triageScore >= 50 ? 'var(--warning)' : 'var(--success)' }}>
                    {inc.triageScore}%
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{inc.sourceIp}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                    {new Date(inc.createdAt).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
