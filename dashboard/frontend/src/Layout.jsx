import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity, Bell, Brain, Building2, ChevronRight,
  ClipboardCheck, LayoutDashboard, LogOut,
  Menu, Server, ShieldAlert, ShieldCheck, Workflow, Radar,
} from 'lucide-react';
import { api } from './api';
import { useAuth } from './auth';
import { fmtDuration } from './ui';

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert, countKey: 'incidents' },
  { to: '/approvals', label: 'Approvals', icon: ClipboardCheck, countKey: 'approvals' },
  { to: '/intel', label: 'Threat Intel', icon: Radar },
  { to: '/assets', label: 'Assets', icon: Building2 },
  { to: '/playbooks', label: 'Playbooks', icon: Workflow },
  { to: '/ai', label: 'AI & Analysis', icon: Brain },
  { to: '/system', label: 'System', icon: Server },
  { to: '/admin', label: 'Admin', icon: ShieldCheck },
];

function useNavCounts() {
  const [counts, setCounts] = useState({ incidents: 0, approvals: 0 });
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const [inc, app] = await Promise.all([
        api.get('/incidents?status=open&limit=1').catch(() => null),
        api.get('/approvals?status=pending').catch(() => null),
      ]);
      if (!alive) return;
      setCounts({
        incidents: inc?.data?.pagination?.total ?? 0,
        approvals: app?.data?.approvals?.length ?? 0,
      });
    };
    tick();
    const id = setInterval(tick, 30000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  return counts;
}

function useSystemHealth() {
  const [health, setHealth] = useState(null);
  useEffect(() => {
    let alive = true;
    const tick = () => api.get('/system/health')
      .then((r) => alive && setHealth(r.data))
      .catch(() => alive && setHealth(null));
    tick();
    const id = setInterval(tick, 30000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  return health;
}

function Clock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => { const id = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(id); }, []);
  const t = now.toISOString();
  return (
    <span className="topbar-clock-block">
      <span className="topbar-clock-time">{t.slice(11, 19)}</span>
      <span className="topbar-clock-utc">UTC</span>
    </span>
  );
}

/* Breadcrumb segments: derive from pathname */
function useBreadcrumbs(location) {
  const parts = location.pathname.split('/').filter(Boolean);
  // SOAR Intelligence / Segment / Segment
  const crumbs = [{ label: 'SOAR INTELLIGENCE', to: '/' }];
  const seg1 = parts[0];
  const nav = NAV.find((n) => n.to === '/' + (seg1 || ''));
  if (nav && seg1) crumbs.push({ label: nav.label.toUpperCase(), to: nav.to });
  if (parts[1]) crumbs.push({ label: parts[1].toUpperCase(), to: null });
  return crumbs;
}

/* Derive current incident number from path /incidents/:id */
function useCurrentIncident(location) {
  const m = location.pathname.match(/^\/incidents\/(.+)$/);
  return m ? m[1] : null;
}

export default function Layout() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const health = useSystemHealth();
  const counts = useNavCounts();
  const breadcrumbs = useBreadcrumbs(location);
  const incident = useCurrentIncident(location);
  const isHealthy = health?.status === 'healthy';

  return (
    <div className="app-layout">
      {/* ── SIDEBAR ── */}
      <aside className={`sidebar ${open ? 'open' : ''}`} aria-label="Main navigation">

        {/* Brand */}
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">
            <Activity size={14} color="var(--accent)" />
          </div>
          <span className="sidebar-brand-name">SOAR INTELLIGENCE</span>
        </div>

        {/* Active incident context if applicable */}
        {incident && (
          <div className="sidebar-incident-ctx">
            <span className="sidebar-incident-dot critical" />
            <span className="sidebar-incident-label">{incident}</span>
          </div>
        )}

        {/* Navigation */}
        <nav>
          {NAV.map(({ to, label, icon: Icon, end, countKey }) => {
            const cnt = countKey ? counts[countKey] : 0;
            return (
              <NavLink
                key={to} to={to} end={end}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                onClick={() => setOpen(false)}
              >
                <Icon size={15} />
                <span className="nav-label">{label}</span>
                {cnt > 0 && <span className="nav-count">{cnt}</span>}
              </NavLink>
            );
          })}
        </nav>

        {/* Bottom section */}
        <div className="sidebar-bottom">
          {/* Node status */}
          <div className="sidebar-node-status">
            <div className="sidebar-node-left">
              <span className={`sidebar-status-dot ${isHealthy ? 'ok' : health ? 'bad' : ''}`} aria-hidden="true" />
              <span className="sidebar-node-name">{health ? `${health.status} · ${health.environment}` : 'connecting…'}</span>
            </div>
          </div>

          {/* User info */}
          <div className="sidebar-user">
            <div className="sidebar-user-avatar">{user.username.slice(0, 2).toUpperCase()}</div>
            <div className="sidebar-user-info">
              <span className="sidebar-user-name">{user.username}</span>
              <span className="sidebar-user-role">{user.role.replace('_', ' ')}</span>
            </div>
            <button className="btn btn-ghost btn-icon" onClick={logout} aria-label="Sign out" title="Sign out">
              <LogOut size={13} />
            </button>
          </div>
        </div>
      </aside>

      {/* ── MAIN CONTENT ── */}
      <div className="main-content">

        {/* ── TOPBAR ── */}
        <header className="topbar" role="banner">
          <button className="btn btn-ghost btn-icon menu-btn" onClick={() => setOpen(!open)} aria-label="Toggle navigation">
            <Menu size={16} />
          </button>

          {/* Breadcrumb */}
          <nav className="topbar-breadcrumb" aria-label="Breadcrumb">
            {breadcrumbs.map((c, i) => (
              <span key={i} className="topbar-breadcrumb-seg">
                {i > 0 && <ChevronRight size={11} className="topbar-breadcrumb-sep" />}
                <span className={i === breadcrumbs.length - 1 ? 'topbar-breadcrumb-active' : 'topbar-breadcrumb-dim'}>
                  {c.label}
                </span>
              </span>
            ))}
            {/* Incident badge in breadcrumb */}
            {incident && (
              <>
                <ChevronRight size={11} className="topbar-breadcrumb-sep" />
                <span className="topbar-incident-chip">{incident}</span>
              </>
            )}
          </nav>

          {/* Spacer */}
          <div style={{ flex: 1 }} />

          {/* Clock */}
          <Clock />

          {/* Notifications: real pending-approvals count, click navigates there */}
          <button
            className="topbar-icon-btn"
            onClick={() => navigate('/approvals')}
            aria-label={`${counts.approvals} pending approvals`}
            title="Pending approvals"
          >
            <Bell size={14} />
            {counts.approvals > 0 && <span className="badge badge-critical" style={{ marginLeft: 4 }}>{counts.approvals}</span>}
          </button>

          <span style={{ color: 'var(--text-secondary)', fontSize: 13 }}>{user.username}</span>
          <span className="badge badge-info">{user.role.replace('_', ' ').toLowerCase()}</span>
          <button className="btn btn-ghost btn-icon" onClick={logout} aria-label="Sign out" title="Sign out">
            <LogOut size={14} />
          </button>
        </header>

        {/* Page */}
        <Outlet />

        {/* ── STATUS FOOTER ── */}
        <footer className="status-footer">
          <span className={`sidebar-status-dot ${isHealthy ? 'ok' : health ? 'bad' : ''}`} aria-hidden="true" />
          {health ? (
            <span>
              status: <strong>{health.status}</strong>
              <span className="status-footer-sep">·</span>
              env: {health.environment}
              <span className="status-footer-sep">·</span>
              uptime: {fmtDuration(health.uptime_seconds)}
              <span className="status-footer-sep">·</span>
              db: {health.database?.ok ? 'ok' : 'error'}
            </span>
          ) : <span>Connecting to API…</span>}
        </footer>
      </div>
    </div>
  );
}
