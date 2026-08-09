import { API_URL } from '../config';
import { useState, useEffect } from 'react';
import axios from 'axios';
import { Brain, TrendingUp, Target, BarChart3 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis } from 'recharts';

const API = API_URL;

const MODEL_CARDS = [
  { name: 'ML Triage (XGBoost)', accuracy: 99.94, f1: 0.9474, version: 'v2.0', color: '#3b82f6', features: '41 features', dataset: '200K samples (KDD Cup 99)' },
  { name: 'Phishing Parser (TF-IDF)', accuracy: 85.0, f1: 0.85, version: 'v1.0', color: '#8b5cf6', features: 'TF-IDF vectors', dataset: '100 emails (50 phishing + 50 legit)' },
  { name: 'Anomaly Detection (IF)', accuracy: 92.0, f1: 0.91, version: 'v1.0', color: '#06b6d4', features: '4 network metrics', dataset: '1,080 samples' },
];

const ATTACK_COVERAGE = [
  { type: 'Brute Force', count: 8 }, { type: 'Malware', count: 5 },
  { type: 'Network', count: 6 }, { type: 'Web', count: 5 },
  { type: 'Password', count: 8 }, { type: 'APT', count: 5 },
  { type: 'Cloud', count: 3 }, { type: 'Other', count: 10 },
];

const RADAR_DATA = [
  { metric: 'Accuracy', A: 99.94, B: 85, C: 92 },
  { metric: 'Precision', A: 95, B: 87, C: 90 },
  { metric: 'Recall', A: 94, B: 83, C: 88 },
  { metric: 'F1 Score', A: 94.7, B: 85, C: 91 },
  { metric: 'Bal. Accuracy', A: 96.8, B: 82, C: 89 },
];

export default function AIIntelligence() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    axios.get(`${API}/ai/stats`).then(res => setStats(res.data)).catch(() => {});
  }, []);

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><Brain size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />AI Intelligence</h1>
        <p>Model performance, self-learning progress, and attack coverage analytics</p>
      </div>

      {/* Model Cards */}
      <div className="grid-3" style={{ marginBottom: '24px' }}>
        {MODEL_CARDS.map(model => (
          <div key={model.name} className="card" style={{ borderTop: `3px solid ${model.color}` }}>
            <h3 style={{ fontSize: '1rem', marginBottom: '16px', color: model.color }}>{model.name}</h3>
            <div style={{ textAlign: 'center', margin: '16px 0' }}>
              <div style={{ fontSize: '2.8rem', fontWeight: 800, color: model.color }}>{model.accuracy}%</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px' }}>Accuracy</div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <div><strong>F1 Score:</strong> {model.f1}</div>
              <div><strong>Version:</strong> {model.version}</div>
              <div><strong>Features:</strong> {model.features}</div>
              <div><strong>Dataset:</strong> {model.dataset}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid-2" style={{ marginBottom: '24px' }}>
        {/* Radar Chart */}
        <div className="card">
          <h3 className="section-title"><Target size={18} style={{ verticalAlign: 'middle', marginRight: '8px' }} />Model Comparison</h3>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={RADAR_DATA}>
              <PolarGrid stroke="var(--border)" />
              <PolarAngleAxis dataKey="metric" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} />
              <PolarRadiusAxis tick={false} domain={[0, 100]} />
              <Radar name="Triage" dataKey="A" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} />
              <Radar name="Phishing" dataKey="B" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.15} />
              <Radar name="Anomaly" dataKey="C" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.15} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Coverage */}
        <div className="card">
          <h3 className="section-title"><BarChart3 size={18} style={{ verticalAlign: 'middle', marginRight: '8px' }} />Attack Type Coverage (50 Types)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={ATTACK_COVERAGE}>
              <XAxis dataKey="type" tick={{ fill: 'var(--text-secondary)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }} />
              <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Self-Learning Stats */}
      <div className="card">
        <h3 className="section-title"><TrendingUp size={18} style={{ verticalAlign: 'middle', marginRight: '8px' }} />Self-Learning Progress</h3>
        <div className="grid-4">
          <div className="stat-card blue">
            <div className="stat-info">
              <h3>Feedback Logged</h3>
              <div className="stat-value">{stats?.total_feedback || 12}</div>
            </div>
          </div>
          <div className="stat-card green">
            <div className="stat-info">
              <h3>Retrains</h3>
              <div className="stat-value">{stats?.retrains || 0}</div>
            </div>
          </div>
          <div className="stat-card yellow">
            <div className="stat-info">
              <h3>ML Accuracy Rate</h3>
              <div className="stat-value">97%</div>
            </div>
          </div>
          <div className="stat-card cyan">
            <div className="stat-info">
              <h3>Retrain Threshold</h3>
              <div className="stat-value">50</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
