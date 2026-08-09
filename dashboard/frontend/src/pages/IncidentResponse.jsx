import { API_URL } from '../config';
import { useState, useEffect } from 'react';
import axios from 'axios';
import { ShieldAlert, Ban, Search, Eye, CheckCircle, AlertOctagon, FileText, Download, Loader, RefreshCw, Clock } from 'lucide-react';

const API = API_URL;

export default function IncidentResponse() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);
  const [reportLoading, setReportLoading] = useState(null);
  const [reportReady, setReportReady] = useState({});

  const [syncing, setSyncing] = useState(false);

  const fetchIncidents = async () => {
    try {
      const res = await axios.get(`${API}/incidents?limit=50`);
      setIncidents(res.data.incidents);
      // Track which incidents already have reports
      const ready = {};
      res.data.incidents.forEach(inc => {
        if (inc.reportPath) ready[inc._id] = true;
      });
      setReportReady(prev => ({ ...prev, ...ready }));
    } catch (err) { console.error(err); }
    setLoading(false);
  };

  useEffect(() => { fetchIncidents(); }, []);

  const handleSyncWazuh = async () => {
    setSyncing(true);
    try {
      const res = await axios.post(`${API}/incidents/sync-wazuh`);
      alert(`Successfully synced ${res.data.synced} new attacks from Wazuh!`);
      await fetchIncidents();
    } catch (err) {
      alert('Sync failed: ' + (err.response?.data?.error || err.message));
    }
    setSyncing(false);
  };

  const handleAction = async (id, action) => {
    setActionLoading(id);
    try {
      await axios.patch(`${API}/incidents/${id}/action`, { action });
      await fetchIncidents();
    } catch (err) {
      alert('Action failed: ' + (err.response?.data?.error || err.message));
    }
    setActionLoading(null);
  };

  const handleGenerateReport = async (id) => {
    setReportLoading(id);
    try {
      const res = await axios.post(`${API}/incidents/${id}/report`);
      if (res.data.success) {
        setReportReady(prev => ({ ...prev, [id]: true }));
      }
    } catch (err) {
      alert('Report generation failed: ' + (err.response?.data?.error || err.message));
    }
    setReportLoading(null);
  };

  const handleDownloadReport = async (id, incidentId, mode = 'download') => {
    try {
      console.log(`[SOAR] Fetching report for ${incidentId} (mode: ${mode})...`);
      const response = await axios.get(`${API}/incidents/${id}/report/download`, {
        responseType: 'blob',
      });
      
      const blob = new Blob([response.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      
      if (mode === 'view') {
        window.open(url, '_blank');
      } else {
        const link = document.createElement('a');
        link.href = url;
        link.download = `${incidentId}.pdf`;
        document.body.appendChild(link);
        link.click();
        
        setTimeout(() => {
          document.body.removeChild(link);
          window.URL.revokeObjectURL(url);
        }, 100);
      }
    } catch (err) {
      console.error('[SOAR] Report action error:', err);
      alert('Action failed: ' + (err.response?.data?.error || 'Report not found or server error.'));
    }
  };

  if (loading) return <div className="loading-container"><div className="spinner" /><span>Loading incidents...</span></div>;

  const openIncidents = incidents.filter(i => i.status === 'open');
  const otherIncidents = incidents.filter(i => i.status !== 'open');

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1><ShieldAlert size={28} style={{ verticalAlign: 'middle', marginRight: '10px' }} />Incident Response</h1>
          <p>Review and respond to security incidents requiring human analysis</p>
        </div>
        <button
          className="btn btn-warning"
          onClick={handleSyncWazuh}
          disabled={syncing}
          style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
        >
          <RefreshCw size={18} className={syncing ? 'spin-icon' : ''} />
          {syncing ? 'Syncing...' : 'Sync Live Attacks'}
        </button>
      </div>

      {/* Pending Review */}
      <h2 className="section-title" style={{ color: 'var(--danger)' }}>
        <AlertOctagon size={18} style={{ verticalAlign: 'middle', marginRight: '8px' }} />
        Pending Review ({openIncidents.length})
      </h2>

      {openIncidents.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '48px', marginBottom: '24px' }}>
          <CheckCircle size={40} style={{ color: 'var(--success)', marginBottom: '12px' }} />
          <p style={{ color: 'var(--text-secondary)' }}>No incidents pending review. All clear!</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '32px' }}>
          {openIncidents.map(inc => (
            <div key={inc._id} className="card" style={{ padding: '20px' }}>
              <div className="flex-between" style={{ marginBottom: '16px' }}>
                <div>
                  <span style={{ fontFamily: 'monospace', color: 'var(--accent)', marginRight: '12px' }}>{inc.incidentId}</span>
                  <strong>{inc.title}</strong>
                </div>
                <div className="flex-gap">
                  <span className={`badge badge-${['', 'low', 'medium', 'high', 'critical'][inc.severity]}`}>
                    {['', 'Low', 'Medium', 'High', 'Critical'][inc.severity]}
                  </span>
                  <span style={{ fontWeight: 700, color: inc.triageScore >= 90 ? 'var(--danger)' : 'var(--warning)' }}>
                    {inc.triageScore}%
                  </span>
                </div>
              </div>

              <div className="grid-5" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                <div><strong>Source:</strong> {inc.sourceIp}</div>
                <div><strong>Target:</strong> {inc.targetDevice}</div>
                <div><strong>Attack:</strong> {inc.attackType}</div>
                <div><strong>Blast Radius:</strong> {inc.blastRadius} hosts</div>
                <div style={{ color: 'var(--accent)', fontWeight: 600 }}>
                  <Clock size={14} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                  {new Date(inc.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </div>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                <div className="action-buttons">
                  <button className="btn btn-danger btn-sm" onClick={() => handleAction(inc._id, 'block')}
                    disabled={actionLoading === inc._id}>
                    <Ban size={14} /> Block & Isolate
                  </button>
                  <button className="btn btn-warning btn-sm" onClick={() => handleAction(inc._id, 'investigate')}
                    disabled={actionLoading === inc._id}>
                    <Search size={14} /> Investigate
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={() => handleAction(inc._id, 'monitor')}
                    disabled={actionLoading === inc._id}>
                    <Eye size={14} /> Monitor
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={() => handleAction(inc._id, 'false_positive')}
                    disabled={actionLoading === inc._id}>
                    <CheckCircle size={14} /> False Positive
                  </button>
                  <button className="btn btn-danger btn-sm" onClick={() => handleAction(inc._id, 'lockdown')}
                    disabled={actionLoading === inc._id} style={{ background: '#7c2d12' }}>
                    <AlertOctagon size={14} /> Full Lockdown
                  </button>
                </div>

                {/* Report Buttons */}
                <div className="action-buttons">
                  <button
                    className="btn btn-sm"
                    style={{ background: 'rgba(139, 92, 246, 0.15)', color: '#8b5cf6', border: '1px solid rgba(139, 92, 246, 0.3)' }}
                    onClick={() => handleGenerateReport(inc._id)}
                    disabled={reportLoading === inc._id}
                  >
                    {reportLoading === inc._id ? <><Loader size={14} className="spin-icon" /> Generating...</> : <><FileText size={14} /> Generate Report</>}
                  </button>
                  {reportReady[inc._id] && (
                    <button
                      className="btn btn-sm"
                      style={{ background: 'rgba(139, 92, 246, 0.15)', color: '#8b5cf6', border: '1px solid rgba(139, 92, 246, 0.3)' }}
                      onClick={() => handleDownloadReport(inc._id, inc.incidentId, 'view')}
                      title="View Report"
                    >
                      <Eye size={14} /> View
                    </button>
                  )}
                  {reportReady[inc._id] && (
                    <button
                      className="btn btn-sm"
                      style={{ background: 'rgba(34, 197, 94, 0.15)', color: '#22c55e', border: '1px solid rgba(34, 197, 94, 0.3)' }}
                      onClick={() => handleDownloadReport(inc._id, inc.incidentId, 'download')}
                      title="Download PDF"
                    >
                      <Download size={14} /> Download
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Resolved / Other */}
      <h2 className="section-title">All Incidents ({otherIncidents.length})</h2>
      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr><th>ID</th><th>Title</th><th>Status</th><th>Action</th><th>Score</th><th>Time</th><th>Report</th></tr>
            </thead>
            <tbody>
              {otherIncidents.map(inc => (
                <tr key={inc._id}>
                  <td style={{ fontFamily: 'monospace', color: 'var(--accent)' }}>{inc.incidentId}</td>
                  <td>{inc.title}</td>
                  <td><span className={`badge badge-${inc.status}`}>{inc.status.replace('_', ' ')}</span></td>
                  <td style={{ textTransform: 'capitalize' }}>{inc.analystAction?.replace('_', ' ') || '—'}</td>
                  <td style={{ fontWeight: 600 }}>{inc.triageScore}%</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{new Date(inc.createdAt).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button
                        className="btn btn-sm"
                        style={{ padding: '4px 10px', background: 'rgba(139, 92, 246, 0.12)', color: '#8b5cf6', border: '1px solid rgba(139, 92, 246, 0.25)', fontSize: '0.75rem' }}
                        onClick={() => handleGenerateReport(inc._id)}
                        disabled={reportLoading === inc._id}
                        title="Generate PDF Report"
                      >
                        {reportLoading === inc._id ? <Loader size={12} className="spin-icon" /> : <FileText size={12} />}
                      </button>
                      <button
                        className="btn btn-sm"
                        style={{ padding: '4px 10px', background: 'rgba(139, 92, 246, 0.12)', color: '#8b5cf6', border: '1px solid rgba(139, 92, 246, 0.25)', fontSize: '0.75rem' }}
                        onClick={() => handleDownloadReport(inc._id, inc.incidentId, 'view')}
                        title="View PDF Report"
                      >
                        <Eye size={12} />
                      </button>
                      <button
                        className="btn btn-sm"
                        style={{ padding: '4px 10px', background: 'rgba(34, 197, 94, 0.12)', color: '#22c55e', border: '1px solid rgba(34, 197, 94, 0.25)', fontSize: '0.75rem' }}
                        onClick={() => handleDownloadReport(inc._id, inc.incidentId, 'download')}
                        title="Download PDF Report"
                      >
                        <Download size={12} />
                      </button>
                    </div>
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
