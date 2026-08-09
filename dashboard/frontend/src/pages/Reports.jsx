import { API_URL } from '../config';
import { useState, useEffect } from 'react';
import axios from 'axios';
import { FileText, Download, Eye } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

const API = API_URL;
const MTTR_DATA = [
  { day: 'Mon', mttr: 45 }, { day: 'Tue', mttr: 32 }, { day: 'Wed', mttr: 28 },
  { day: 'Thu', mttr: 15 }, { day: 'Fri', mttr: 22 }, { day: 'Sat', mttr: 12 }, { day: 'Sun', mttr: 14 },
];

const HEATMAP_DATA = Array.from({ length: 7 }, (_, day) =>
  Array.from({ length: 24 }, (_, hour) => ({
    day, hour, value: Math.floor(Math.random() * 10) + (hour < 6 || hour > 20 ? 3 : 0) + (day > 4 ? 2 : 0),
  }))
).flat();

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

export default function Reports() {
  const [stats, setStats] = useState(null);
  const [reports, setReports] = useState([]);
  const [loadingReports, setLoadingReports] = useState(true);
  const [downloading, setDownloading] = useState(null);

  useEffect(() => {
    axios.get(`${API}/incidents/stats`).then(r => setStats(r.data)).catch(() => {});
    fetchReports();
  }, []);

  const fetchReports = async () => {
    try {
      const res = await axios.get(`${API}/incidents/reports/all`);
      setReports(res.data.reports || []);
    } catch (err) {
      console.error('Failed to fetch reports:', err);
    }
    setLoadingReports(false);
  };

  const handleDownload = async (filename, mode = 'download') => {
    setDownloading(filename);
    try {
      const response = await axios.get(`${API}/incidents/reports/download/${filename}`, {
        responseType: 'blob',
      });
      
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      
      if (mode === 'view') {
        window.open(url, '_blank');
      } else {
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        setTimeout(() => {
          document.body.removeChild(link);
          window.URL.revokeObjectURL(url);
        }, 100);
      }
    } catch (err) {
      alert('Action failed: ' + (err.response?.data?.error || err.message));
    }
    setDownloading(null);
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><FileText size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />Reports & Analytics</h1>
        <p>Response metrics, attack patterns, and downloadable incident reports</p>
      </div>

      <div className="grid-2" style={{ marginBottom: '24px' }}>
        {/* MTTR Trend */}
        <div className="card">
          <h3 className="section-title">Mean Time to Respond (MTTR)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={MTTR_DATA}>
              <defs>
                <linearGradient id="mttrGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="day" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} unit="s" />
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', color: 'var(--text-primary)' }} />
              <Area type="monotone" dataKey="mttr" stroke="#3b82f6" fill="url(#mttrGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Heatmap */}
        <div className="card">
          <h3 className="section-title">Attack Heatmap (Day × Hour)</h3>
          <div style={{ overflowX: 'auto' }}>
            <svg viewBox="0 0 520 160" style={{ width: '100%', minWidth: '400px' }}>
              {DAYS.map((d, di) => (
                <text key={d} x="0" y={22 + di * 20} fill="var(--text-muted)" fontSize="9" dominantBaseline="middle">{d}</text>
              ))}
              {HEATMAP_DATA.map((cell, i) => {
                const opacity = Math.min(1, cell.value / 12);
                return (
                  <rect key={i} x={30 + cell.hour * 20} y={12 + cell.day * 20} width="18" height="18" rx="3"
                    fill={`rgba(239, 68, 68, ${opacity})`} stroke="var(--bg-primary)" strokeWidth="1" />
                );
              })}
            </svg>
          </div>
        </div>
      </div>

      {/* Report Downloads */}
      <div className="card">
        <div className="flex-between" style={{ marginBottom: '16px' }}>
          <h3 className="section-title" style={{ margin: 0 }}>
            <Download size={18} style={{ verticalAlign: 'middle', marginRight: '8px' }} />
            Official Incident Reports ({reports.length})
          </h3>
          <button className="btn btn-ghost btn-sm" onClick={fetchReports}>Refresh List</button>
        </div>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
          These PDFs were automatically generated by the AI Report Generator based on real SOAR telemetry.
        </p>
        
        {loadingReports ? (
          <div style={{ textAlign: 'center', padding: '20px' }}><div className="spinner" style={{ margin: '0 auto' }} /></div>
        ) : reports.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)', border: '1px dashed var(--border)', borderRadius: '12px' }}>
            No reports found. Generate them from the Incident Response page first.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: '12px' }}>
            {reports.map(r => (
              <div key={r.filename} className="stat-card" style={{ padding: '16px', background: 'var(--bg-secondary)', borderLeft: '3px solid var(--accent)' }}>
                <div className="stat-icon blue" style={{ width: '40px', height: '40px' }}>
                  <FileText size={20} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.85rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.filename}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {(r.size / 1024).toFixed(1)} KB • {new Date(r.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button 
                    className="btn btn-ghost btn-sm" 
                    onClick={() => handleDownload(r.filename, 'view')}
                    disabled={downloading === r.filename}
                    title="View PDF"
                  >
                    <Eye size={14} />
                  </button>
                  <button 
                    className="btn btn-primary btn-sm" 
                    onClick={() => handleDownload(r.filename, 'download')}
                    disabled={downloading === r.filename}
                    title="Download PDF"
                  >
                    {downloading === r.filename ? '...' : <Download size={14} />}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
