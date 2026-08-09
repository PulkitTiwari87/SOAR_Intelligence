import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard, ShieldAlert, Brain, Fish, Scan,
  Network, FileText, Activity, ClipboardList, Shield, Layers, Settings as SettingsIcon
} from 'lucide-react';

const navItems = [
  { path: '/dashboard', label: 'Command Center', icon: LayoutDashboard },
  { path: '/soar', label: 'SOAR Integration', icon: Layers },
  { path: '/incidents', label: 'Incident Response', icon: ShieldAlert, analystOnly: true },
  { path: '/ai-intelligence', label: 'AI Intelligence', icon: Brain },
  { path: '/phishing', label: 'Phishing Analyzer', icon: Fish },
  { path: '/vulnerabilities', label: 'Vulnerability Scanner', icon: Scan },
  { path: '/network', label: 'Network Topology', icon: Network, analystOnly: true },
  { path: '/reports', label: 'Reports & Analytics', icon: FileText },
  { path: '/system', label: 'System Health', icon: Activity },
  { path: '/audit', label: 'Audit Log', icon: ClipboardList, analystOnly: true },
  { path: '/settings', label: 'Settings', icon: SettingsIcon },
];

export default function Sidebar() {
  const { isAnalyst } = useAuth();

  const filteredItems = navItems.filter(item => !item.analystOnly || isAnalyst);

  return (
    <aside style={{
      position: 'fixed', left: 0, top: 0, bottom: 0,
      width: 'var(--sidebar-width)', background: 'var(--bg-sidebar)',
      borderRight: '1px solid var(--glass-border)',
      display: 'flex', flexDirection: 'column', zIndex: 200,
      overflowY: 'auto',
    }}>
      {/* Logo */}
      <div style={{
        padding: '20px 24px', display: 'flex', alignItems: 'center', gap: '12px',
        borderBottom: '1px solid var(--glass-border)',
      }}>
        <div style={{
          width: '40px', height: '40px', borderRadius: 'var(--radius-md)',
          background: 'linear-gradient(135deg, var(--accent), #8b5cf6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Shield size={22} color="white" />
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: '1.1rem' }}>SOAR</div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', letterSpacing: '1px' }}>AI DASHBOARD</div>
        </div>
      </div>

      {/* Nav Items */}
      <nav style={{ padding: '12px 10px', flex: 1 }}>
        {filteredItems.map(({ path, label, icon: Icon }) => (
          <NavLink
            key={path}
            to={path}
            style={({ isActive }) => ({
              display: 'flex', alignItems: 'center', gap: '12px',
              padding: '11px 16px', borderRadius: 'var(--radius-md)',
              color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
              background: isActive ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
              fontWeight: isActive ? 600 : 400, fontSize: '0.9rem',
              transition: 'all 150ms ease', textDecoration: 'none',
              marginBottom: '2px',
            })}
            onMouseEnter={e => {
              if (!e.currentTarget.classList.contains('active')) {
                e.currentTarget.style.background = 'var(--bg-card-hover)';
                e.currentTarget.style.color = 'var(--text-primary)';
              }
            }}
            onMouseLeave={e => {
              if (!e.currentTarget.classList.contains('active')) {
                e.currentTarget.style.background = 'transparent';
                e.currentTarget.style.color = 'var(--text-secondary)';
              }
            }}
          >
            <Icon size={18} />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div style={{
        padding: '16px 24px', borderTop: '1px solid var(--glass-border)',
        fontSize: '0.7rem', color: 'var(--text-muted)', textAlign: 'center',
      }}>
        SOAR v2.0 • AI-Powered
      </div>
    </aside>
  );
}
