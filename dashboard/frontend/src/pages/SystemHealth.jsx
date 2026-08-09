import { API_URL } from '../config';
import { useState, useEffect } from 'react';
import axios from 'axios';
import { Activity, CheckCircle, XCircle } from 'lucide-react';

const API = API_URL;

export default function SystemHealth() {
  const [health, setHealth] = useState(null);
  useEffect(() => {
    axios.get(`${API}/system/health`).then(r => setHealth(r.data)).catch(() => {});
  }, []);

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><Activity size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />System Health</h1>
        <p>Docker container status and AI model health monitoring</p>
      </div>

      <div className="grid-4" style={{ marginBottom: '24px' }}>
        {(health?.containers || []).map(c => (
          <div key={c.name} className="card" style={{ textAlign: 'center', padding: '20px' }}>
            {c.status === 'running' ?
              <CheckCircle size={28} style={{ color: 'var(--success)', marginBottom: '8px' }} /> :
              <XCircle size={28} style={{ color: 'var(--danger)', marginBottom: '8px' }} />
            }
            <div style={{ fontWeight: 600, fontSize: '0.95rem', marginBottom: '4px' }}>{c.name}</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Port: {c.port}</div>
            <span className={`badge ${c.status === 'running' ? 'badge-resolved' : 'badge-open'}`} style={{ marginTop: '8px' }}>
              {c.status}
            </span>
          </div>
        ))}
      </div>

      <div className="card">
        <h3 className="section-title">AI Model Status</h3>
        <div className="grid-3">
          {health?.aiModels && Object.entries(health.aiModels).map(([name, info]) => (
            <div key={name} className="stat-card green">
              <div className="stat-info">
                <h3>{name}</h3>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  {info.version} • {info.accuracy}% accuracy
                </div>
              </div>
              <span className="badge badge-resolved">{info.loaded ? 'Loaded' : 'Not Loaded'}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
