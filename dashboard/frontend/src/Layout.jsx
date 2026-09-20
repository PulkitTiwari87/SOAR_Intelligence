import { useEffect, useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { Activity, Bell, Brain, Building2, ClipboardCheck, LayoutDashboard, LogOut, Menu, Server, ShieldAlert, ShieldCheck, Workflow, Radar } from 'lucide-react';
import { api } from './api';
import { useAuth } from './auth';

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/approvals', label: 'Approvals', icon: ClipboardCheck },
  { to: '/intel', label: 'Threat Intel', icon: Radar },
  { to: '/assets', label: 'Assets', icon: Building2 },
  { to: '/playbooks', label: 'Playbooks', icon: Workflow },
  { to: '/ai', label: 'AI & Analysis', icon: Brain },
  { to: '/system', label: 'System', icon: Server },
  { to: '/admin', label: 'Admin', icon: ShieldCheck },
];

function PendingApprovals() {
  const [n, setN] = useState(0);
  const navigate = useNavigate();
  useEffect(() => {
    let alive = true;
    const tick = () => api.get('/approvals?status=pending').then((r) => alive && setN(r.data.approvals.length)).catch(() => {});
    tick();
    const id = setInterval(tick, 30000);
    return () => { alive = false; clearInterval(id); };
  }, []);
  return (
    <button className="btn btn-ghost btn-sm" onClick={() => navigate('/approvals')} title="Pending approvals" aria-label={`${n} pending approvals`}>
      <Bell size={16} /> {n > 0 && <span className="badge badge-critical">{n}</span>}
    </button>
  );
}

export default function Layout() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  return (
    <div className="app-layout">
      <aside className={`sidebar ${open ? 'open' : ''}`} aria-label="Main navigation">
        <div className="sidebar-brand"><Activity size={22} color="var(--accent)" /> <span>SOAR Intelligence</span></div>
        <nav>
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} onClick={() => setOpen(false)}>
              <Icon size={18} /> {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="main-content">
        <header className="topbar">
          <button className="btn btn-ghost btn-sm menu-btn" onClick={() => setOpen(!open)} aria-label="Toggle navigation"><Menu size={18} /></button>
          <div style={{ flex: 1 }} />
          <PendingApprovals />
          <span style={{ color: 'var(--text-secondary)' }}>{user.username}</span>
          <span className="badge badge-info">{user.role.replace('_', ' ').toLowerCase()}</span>
          <button className="btn btn-ghost btn-sm" onClick={logout} aria-label="Sign out"><LogOut size={16} /></button>
        </header>
        <Outlet />
      </div>
    </div>
  );
}
