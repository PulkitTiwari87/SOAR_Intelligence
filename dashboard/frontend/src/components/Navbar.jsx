import { useAuth } from '../context/AuthContext';
import { Shield, LogOut, User } from 'lucide-react';
import NotificationBell from './NotificationBell';

export default function Navbar() {
  const { user, logout, isAnalyst } = useAuth();

  return (
    <nav style={{
      position: 'fixed', top: 0, left: 'var(--sidebar-width)', right: 0,
      height: 'var(--navbar-height)', background: 'var(--glass-bg)',
      borderBottom: '1px solid var(--glass-border)', backdropFilter: 'blur(20px)',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 32px', zIndex: 100,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <Shield size={22} style={{ color: 'var(--accent)' }} />
        <span style={{ fontWeight: 700, fontSize: '1.1rem' }}>SOAR Command Center</span>
      </div>

      {user && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {/* Notification Bell (analyst only) */}
          {isAnalyst && <NotificationBell />}

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <User size={16} style={{ color: 'var(--text-secondary)' }} />
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>{user.username}</span>
            <span className={`badge badge-${user.role}`}>{user.role}</span>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={logout}>
            <LogOut size={16} /> Logout
          </button>
        </div>
      )}
    </nav>
  );
}
