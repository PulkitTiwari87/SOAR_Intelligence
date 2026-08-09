import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { Bell, AlertTriangle, ShieldAlert, Clock, ChevronRight, X, Siren } from 'lucide-react';
import { API_URL } from '../config';

const API = API_URL;
const POLL_INTERVAL = 30000; // 30 seconds

export default function NotificationBell() {
  const { user, isAnalyst } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [prevCount, setPrevCount] = useState(0);
  const [pulse, setPulse] = useState(false);
  const [toastVisible, setToastVisible] = useState(false);
  const [toastDismissed, setToastDismissed] = useState(false);
  const panelRef = useRef(null);

  // Fetch open incidents that need human intervention
  const fetchAlerts = async () => {
    if (!user) return;
    try {
      const res = await axios.get(`${API}/incidents?limit=50`);
      const openIncidents = res.data.incidents.filter(
        inc => inc.status === 'open' || inc.status === 'investigating'
      );
      setAlerts(openIncidents);

      // Trigger pulse animation when new alerts come in
      if (openIncidents.length > prevCount && prevCount > 0) {
        setPulse(true);
        setTimeout(() => setPulse(false), 3000);
      }

      // Show toast for critical alerts (only for analyst, only once per session until dismissed)
      const criticals = openIncidents.filter(inc => inc.severity >= 3 && inc.status === 'open');
      if (criticals.length > 0 && isAnalyst && !toastDismissed) {
        setToastVisible(true);
      }

      setPrevCount(openIncidents.length);
    } catch (err) {
      console.error('Notification fetch error:', err);
    }
  };

  // Initial fetch + polling
  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [user]);

  // Click outside to close dropdown
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleAlertClick = (inc) => {
    setOpen(false);
    navigate('/incidents');
  };

  const dismissToast = () => {
    setToastVisible(false);
    setToastDismissed(true);
  };

  const criticalAlerts = alerts.filter(a => a.severity >= 3 && a.status === 'open');
  const pendingCount = alerts.filter(a => a.status === 'open').length;

  const getSeverityColor = (sev) => {
    if (sev === 4) return 'var(--danger)';
    if (sev === 3) return '#f97316';
    if (sev === 2) return 'var(--warning)';
    return 'var(--success)';
  };

  const getSeverityLabel = (sev) => ['', 'Low', 'Medium', 'High', 'Critical'][sev] || 'Unknown';

  const getTimeAgo = (date) => {
    const seconds = Math.floor((new Date() - new Date(date)) / 1000);
    if (seconds < 60) return 'Just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  return (
    <>
      {/* ─── CRITICAL ALERT TOAST BANNER ─── */}
      {toastVisible && criticalAlerts.length > 0 && (
        <div className="alert-toast" style={{
          position: 'fixed',
          top: 'calc(var(--navbar-height) + 8px)',
          left: 'calc(var(--sidebar-width) + 20px)',
          right: '20px',
          zIndex: 1000,
          animation: 'slideDown 0.4s ease',
        }}>
          <div style={{
            background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(239, 68, 68, 0.08) 100%)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: 'var(--radius-lg)',
            padding: '14px 20px',
            display: 'flex',
            alignItems: 'center',
            gap: '14px',
            backdropFilter: 'blur(12px)',
            boxShadow: '0 4px 24px rgba(239, 68, 68, 0.2)',
          }}>
            <div className="alert-toast-icon">
              <Siren size={22} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--danger)', marginBottom: '2px' }}>
                ⚠ Human Intervention Required
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                {criticalAlerts.length} critical incident{criticalAlerts.length > 1 ? 's' : ''} pending review
                — <strong>{criticalAlerts[0]?.title}</strong>
                {criticalAlerts.length > 1 && ` and ${criticalAlerts.length - 1} more`}
              </div>
            </div>
            <button
              className="btn btn-danger btn-sm"
              onClick={() => { dismissToast(); navigate('/incidents'); }}
              style={{ whiteSpace: 'nowrap' }}
            >
              <ShieldAlert size={14} /> Review Now
            </button>
            <button
              onClick={dismissToast}
              style={{
                background: 'none', border: 'none', cursor: 'pointer',
                color: 'var(--text-muted)', padding: '4px',
              }}
            >
              <X size={16} />
            </button>
          </div>
        </div>
      )}

      {/* ─── BELL ICON ─── */}
      <div ref={panelRef} style={{ position: 'relative' }}>
        <button
          onClick={() => setOpen(!open)}
          className={`notification-bell ${pulse ? 'pulse' : ''}`}
          style={{
            position: 'relative',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: pendingCount > 0 ? 'var(--text-primary)' : 'var(--text-muted)',
            padding: '8px',
            borderRadius: 'var(--radius-md)',
            transition: 'all 150ms ease',
          }}
          title={`${pendingCount} incident${pendingCount !== 1 ? 's' : ''} pending review`}
        >
          <Bell size={20} />
          {pendingCount > 0 && (
            <span style={{
              position: 'absolute', top: '2px', right: '2px',
              width: '18px', height: '18px',
              background: 'var(--danger)',
              color: 'white',
              borderRadius: '50%',
              fontSize: '0.65rem',
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 8px var(--danger-glow)',
              animation: pendingCount > 0 ? 'badgePulse 2s ease-in-out infinite' : 'none',
            }}>
              {pendingCount > 9 ? '9+' : pendingCount}
            </span>
          )}
        </button>

        {/* ─── DROPDOWN PANEL ─── */}
        {open && (
          <div style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            right: 0,
            width: '400px',
            background: 'var(--bg-card)',
            border: '1px solid var(--glass-border)',
            borderRadius: 'var(--radius-lg)',
            boxShadow: 'var(--shadow-lg)',
            zIndex: 500,
            overflow: 'hidden',
            animation: 'fadeIn 0.2s ease',
          }}>
            {/* Header */}
            <div style={{
              padding: '14px 18px',
              borderBottom: '1px solid var(--glass-border)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}>
              <div style={{ fontWeight: 700, fontSize: '0.95rem' }}>
                <AlertTriangle size={16} style={{ verticalAlign: 'middle', marginRight: '6px', color: 'var(--warning)' }} />
                Alerts Requiring Action
              </div>
              <span className="badge badge-open">{pendingCount} pending</span>
            </div>

            {/* Alert List */}
            <div style={{ maxHeight: '360px', overflowY: 'auto' }}>
              {alerts.length === 0 ? (
                <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Bell size={28} style={{ opacity: 0.3, marginBottom: '8px' }} />
                  <p>No alerts pending</p>
                </div>
              ) : (
                alerts.filter(a => a.status === 'open').map(inc => (
                  <div
                    key={inc._id}
                    onClick={() => handleAlertClick(inc)}
                    style={{
                      padding: '12px 18px',
                      borderBottom: '1px solid var(--glass-border)',
                      cursor: 'pointer',
                      transition: 'background 150ms ease',
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '12px',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-card-hover)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    {/* Severity dot */}
                    <div style={{
                      width: '10px', height: '10px', borderRadius: '50%',
                      background: getSeverityColor(inc.severity),
                      boxShadow: inc.severity >= 3 ? `0 0 8px ${getSeverityColor(inc.severity)}40` : 'none',
                      flexShrink: 0, marginTop: '5px',
                    }} />

                    {/* Content */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontWeight: 600, fontSize: '0.85rem', marginBottom: '3px',
                        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                      }}>
                        {inc.title}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                        <span style={{ color: getSeverityColor(inc.severity), fontWeight: 600 }}>
                          {getSeverityLabel(inc.severity)}
                        </span>
                        <span>{inc.incidentId}</span>
                        <span>{inc.attackType}</span>
                      </div>
                    </div>

                    {/* Time + arrow */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                        <Clock size={10} style={{ verticalAlign: 'middle', marginRight: '2px' }} />
                        {getTimeAgo(inc.createdAt)}
                      </span>
                      <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
                    </div>
                  </div>
                ))
              )}

              {/* Investigating alerts */}
              {alerts.filter(a => a.status === 'investigating').length > 0 && (
                <>
                  <div style={{
                    padding: '8px 18px', fontSize: '0.7rem', fontWeight: 600,
                    color: 'var(--warning)', textTransform: 'uppercase', letterSpacing: '0.5px',
                    background: 'var(--bg-secondary)',
                  }}>
                    Under Investigation
                  </div>
                  {alerts.filter(a => a.status === 'investigating').map(inc => (
                    <div
                      key={inc._id}
                      onClick={() => handleAlertClick(inc)}
                      style={{
                        padding: '10px 18px',
                        borderBottom: '1px solid var(--glass-border)',
                        cursor: 'pointer',
                        transition: 'background 150ms ease',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '10px',
                        opacity: 0.8,
                      }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-card-hover)'; e.currentTarget.style.opacity = '1'; }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.opacity = '0.8'; }}
                    >
                      <div style={{
                        width: '8px', height: '8px', borderRadius: '50%',
                        background: 'var(--warning)', flexShrink: 0,
                      }} />
                      <div style={{ flex: 1, fontSize: '0.82rem' }}>{inc.title}</div>
                      <span className="badge badge-investigating" style={{ fontSize: '0.65rem' }}>investigating</span>
                    </div>
                  ))}
                </>
              )}
            </div>

            {/* Footer */}
            {alerts.length > 0 && (
              <div
                onClick={() => { setOpen(false); navigate('/incidents'); }}
                style={{
                  padding: '12px 18px',
                  borderTop: '1px solid var(--glass-border)',
                  textAlign: 'center',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  color: 'var(--accent)',
                  cursor: 'pointer',
                  transition: 'background 150ms ease',
                }}
                onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-card-hover)'}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                View All in Incident Response →
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
